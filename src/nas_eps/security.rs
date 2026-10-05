/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! EPS NAS security envelope — integrity protection and ciphering.
//!
//! This module provides [`NasSecurityContext`] which wraps EPS NAS keys and
//! algorithms to protect outbound messages and unprotect (verify + decipher)
//! inbound messages per TS 33.401 §8 and TS 24.301 §4.4. It also computes the
//! short MAC of a SERVICE REQUEST, protects EMM TRANSPORT, and ciphers only
//! the container of a CONTROL PLANE SERVICE REQUEST.
//!
//! Requires the `security` feature flag:
//! ```toml
//! oxirush-nas = { version = "0.4", features = ["security"] }
//! ```
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::nas_eps::security::{Direction, NasSecurityContext};
//! use oxirush_nas::nas_eps::{
//!     CipheringAlgorithm, IntegrityAlgorithm, NasEpsMessage, NasEpsSecurityHeaderType,
//! };
//!
//! let mut tx = NasSecurityContext::from_fresh_keys([0x11; 16], [0x22; 16], IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
//! let mut rx = NasSecurityContext::from_fresh_keys([0x11; 16], [0x22; 16], IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
//! // ESM INFORMATION RESPONSE with PTI 1.
//! let message = NasEpsMessage::from_bytes(&[0x02, 0x01, 0xda]).unwrap();
//!
//! // Protect (integrity + cipher)
//! let wire = tx.protect(&message, NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered, Direction::Uplink).unwrap();
//!
//! // Unprotect (verify MAC + decipher + decode)
//! let (decoded, _) = rx.unprotect(&wire, Direction::Uplink).unwrap();
//! assert_eq!(decoded, message);
//! ```

use crate::common::{NasError, Result};
use crate::nas_eps::message_types::{EPS_EMM_PROTOCOL_DISCRIMINATOR, NasEpsSecurityHeaderType};
use std::convert::TryFrom;

pub use crate::common::{Direction, estimate_nas_count};
use crate::nas_eps::ie::{CipheringAlgorithm, IntegrityAlgorithm};
use crate::nas_eps::messages::{
    EPS_SECURITY_HEADER_LEN, NasEmmMessage, NasEmmTransport, NasEpsMessage, NasEsmMessage,
    NasServiceRequest, decode_nas_eps_message, decode_nas_eps_message_with_direction,
    encode_nas_eps_message, received_emm_data_container_is_valid, valid_emm_data_container,
};
use oxirush_security::nas_eps as eps;

/// Cipher the value of the sole container in a CONTROL PLANE SERVICE REQUEST.
fn cipher_control_plane_container(
    payload: &mut Vec<u8>,
    key: &[u8; 16],
    count: u32,
    direction: Direction,
    algo_id: u8,
) -> Result<()> {
    let mut message = decode_nas_eps_message(payload)?;
    let NasEpsMessage::Emm(_, NasEmmMessage::ControlPlaneServiceRequest(request)) = &mut message
    else {
        return Err(NasError::DecodingError(
            "Partial EPS ciphering requires CONTROL PLANE SERVICE REQUEST".into(),
        ));
    };
    match (
        &mut request.esm_message_container,
        &mut request.nas_message_container,
    ) {
        (Some(container), None) => {
            eps::nas_cipher(key, count, direction.as_u8(), &mut container.value, algo_id)
        }
        (None, Some(container)) => {
            eps::nas_cipher(key, count, direction.as_u8(), &mut container.value, algo_id)
        }
        _ => {
            return Err(NasError::DecodingError(
                "Partial EPS ciphering requires exactly one message container".into(),
            ));
        }
    }
    *payload = encode_nas_eps_message(&message)?;
    Ok(())
}

fn validate_sht_message(
    sht: NasEpsSecurityHeaderType,
    message: &NasEpsMessage,
    direction: Direction,
) -> Result<()> {
    if !matches!(message, NasEpsMessage::Emm(..) | NasEpsMessage::Esm(..)) {
        return Err(NasError::EncodingError(
            "EPS security envelope requires a plain EMM or ESM message".into(),
        ));
    }
    if let NasEpsMessage::Emm(_, inner) = message {
        // TS 24.301 Chapter 8 assigns a sending side to each EMM message.
        let required_direction = match inner {
            NasEmmMessage::AttachComplete(_)
            | NasEmmMessage::AttachRequest(_)
            | NasEmmMessage::AuthenticationFailure(_)
            | NasEmmMessage::AuthenticationResponse(_)
            | NasEmmMessage::DetachRequestFromUe(_)
            | NasEmmMessage::ExtendedServiceRequest(_)
            | NasEmmMessage::GutiReallocationComplete(_)
            | NasEmmMessage::IdentityResponse(_)
            | NasEmmMessage::SecurityModeComplete(_)
            | NasEmmMessage::SecurityModeReject(_)
            | NasEmmMessage::TrackingAreaUpdateComplete(_)
            | NasEmmMessage::TrackingAreaUpdateRequest(_)
            | NasEmmMessage::UplinkNasTransport(_)
            | NasEmmMessage::UplinkGenericNasTransport(_)
            | NasEmmMessage::ControlPlaneServiceRequest(_) => Some(Direction::Uplink),
            NasEmmMessage::AttachAccept(_)
            | NasEmmMessage::AttachReject(_)
            | NasEmmMessage::AuthenticationReject(_)
            | NasEmmMessage::AuthenticationRequest(_)
            | NasEmmMessage::CsServiceNotification(_)
            | NasEmmMessage::DetachRequestToUe(_)
            | NasEmmMessage::DownlinkNasTransport(_)
            | NasEmmMessage::EmmInformation(_)
            | NasEmmMessage::GutiReallocationCommand(_)
            | NasEmmMessage::IdentityRequest(_)
            | NasEmmMessage::SecurityModeCommand(_)
            | NasEmmMessage::ServiceReject(_)
            | NasEmmMessage::TrackingAreaUpdateAccept(_)
            | NasEmmMessage::TrackingAreaUpdateReject(_)
            | NasEmmMessage::DownlinkGenericNasTransport(_)
            | NasEmmMessage::ServiceAccept(_) => Some(Direction::Downlink),
            NasEmmMessage::DetachAccept(_) | NasEmmMessage::EmmStatus(_) => None,
        };
        if required_direction.is_some_and(|required| required != direction) {
            return Err(NasError::EncodingError(
                "EPS EMM message direction does not match its message type".into(),
            ));
        }
        match inner {
            NasEmmMessage::SecurityModeCommand(_)
                if sht != NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext
                    || direction != Direction::Downlink =>
            {
                return Err(NasError::EncodingError(
                    "SECURITY MODE COMMAND requires downlink integrity protection with new context"
                        .into(),
                ));
            }
            NasEmmMessage::SecurityModeComplete(_)
                if sht != NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                    || direction != Direction::Uplink =>
            {
                return Err(NasError::EncodingError(
                    "SECURITY MODE COMPLETE requires uplink ciphering with new context".into(),
                ));
            }
            _ => {}
        }
    }
    if let NasEpsMessage::Esm(_, inner) = message {
        let required_direction = match inner {
            NasEsmMessage::ActivateDedicatedEpsBearerContextAccept(_)
            | NasEsmMessage::ActivateDedicatedEpsBearerContextReject(_)
            | NasEsmMessage::ActivateDefaultEpsBearerContextAccept(_)
            | NasEsmMessage::ActivateDefaultEpsBearerContextReject(_)
            | NasEsmMessage::BearerResourceAllocationRequest(_)
            | NasEsmMessage::BearerResourceModificationRequest(_)
            | NasEsmMessage::DeactivateEpsBearerContextAccept(_)
            | NasEsmMessage::EsmInformationResponse(_)
            | NasEsmMessage::ModifyEpsBearerContextAccept(_)
            | NasEsmMessage::ModifyEpsBearerContextReject(_)
            | NasEsmMessage::PdnConnectivityRequest(_)
            | NasEsmMessage::PdnDisconnectRequest(_)
            | NasEsmMessage::RemoteUeReport(_) => Some(Direction::Uplink),
            NasEsmMessage::ActivateDedicatedEpsBearerContextRequest(_)
            | NasEsmMessage::ActivateDefaultEpsBearerContextRequest(_)
            | NasEsmMessage::BearerResourceAllocationReject(_)
            | NasEsmMessage::BearerResourceModificationReject(_)
            | NasEsmMessage::DeactivateEpsBearerContextRequest(_)
            | NasEsmMessage::EsmInformationRequest(_)
            | NasEsmMessage::ModifyEpsBearerContextRequest(_)
            | NasEsmMessage::Notification(_)
            | NasEsmMessage::PdnConnectivityReject(_)
            | NasEsmMessage::PdnDisconnectReject(_)
            | NasEsmMessage::RemoteUeReportResponse(_) => Some(Direction::Downlink),
            NasEsmMessage::EsmDummyMessage(_)
            | NasEsmMessage::EsmStatus(_)
            | NasEsmMessage::EsmDataTransport(_) => None,
        };
        if required_direction.is_some_and(|required| required != direction) {
            return Err(NasError::EncodingError(
                "EPS ESM message direction does not match its message type".into(),
            ));
        }
    }
    if let NasEpsMessage::Emm(_, NasEmmMessage::ControlPlaneServiceRequest(request)) = message
        && sht
            != if request.esm_message_container.is_some() || request.nas_message_container.is_some()
            {
                NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered
            } else {
                NasEpsSecurityHeaderType::IntegrityProtected
            }
    {
        return Err(NasError::EncodingError(
            "CONTROL PLANE SERVICE REQUEST security header type does not match its container"
                .into(),
        ));
    }
    let valid = match sht {
        NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext => matches!(
            message,
            NasEpsMessage::Emm(_, NasEmmMessage::SecurityModeCommand(_))
        ),
        NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext => matches!(
            message,
            NasEpsMessage::Emm(_, NasEmmMessage::SecurityModeComplete(_))
        ),
        NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered => matches!(
            message,
            NasEpsMessage::Emm(_, NasEmmMessage::ControlPlaneServiceRequest(_))
        ),
        NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered => !matches!(
            message,
            NasEpsMessage::Emm(
                _,
                NasEmmMessage::AttachRequest(_) | NasEmmMessage::TrackingAreaUpdateRequest(_)
            )
        ),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(NasError::EncodingError(
            "EPS security header type does not match message type".into(),
        ))
    }
}

/// EPS NAS security context for integrity protection and ciphering.
///
/// The constant NAS bearer is zero per TS 33.401 &sect;8.1.1 and &sect;8.2.
/// Uplink and downlink COUNT values start at zero and advance after successful
/// protection or MAC verification.
///
/// Both COUNTs hold the next value to use or to expect. TS 24.301 §4.4.3.1
/// stores the sending-side COUNT (uplink in the UE, downlink in the MME)
/// the same way, but the receiving-side COUNT as the largest value received:
/// add one to that value when importing it and subtract one when exporting
/// it (USIM storage, S10 or N26 context transfer). Adjusting a sending-side
/// COUNT would reuse a COUNT with the same key. The eKSI of the context is
/// kept by the caller.
#[cfg_attr(test, derive(Clone))]
pub struct NasSecurityContext {
    /// EPS NAS integrity key.
    knas_int: [u8; 16],
    /// EPS NAS ciphering key.
    knas_enc: [u8; 16],
    /// Selected EIA algorithm.
    integrity_algo: IntegrityAlgorithm,
    /// Selected EEA algorithm.
    ciphering_algo: CipheringAlgorithm,
    /// Next uplink NAS COUNT.
    ul_count: u32,
    /// Next downlink NAS COUNT.
    dl_count: u32,
}

impl Drop for NasSecurityContext {
    /// Overwrite the NAS keys when the context is released.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.knas_int.zeroize();
        self.knas_enc.zeroize();
    }
}

impl NasSecurityContext {
    fn check_algorithms(&self) -> Result<()> {
        if self.integrity_algo as u8 > 3 || self.ciphering_algo as u8 > 3 {
            return Err(NasError::EncodingError(
                "Reserved EPS NAS security algorithm is not implemented".into(),
            ));
        }
        // EIA0 is only used for unauthenticated emergency sessions, which
        // select EEA0 (TS 33.401 §5.1.4.1 and §15).
        if self.integrity_algo == IntegrityAlgorithm::EIA0
            && self.ciphering_algo != CipheringAlgorithm::EEA0
        {
            return Err(NasError::EncodingError("EPS EIA0 requires EEA0".into()));
        }
        Ok(())
    }

    /// Create a context for genuinely fresh NAS keys with COUNT values at zero.
    ///
    /// Reusing the same keys with this constructor violates TS 33.401 §6.5;
    /// use [`Self::reselect_algorithms`] for an existing KASME.
    pub fn from_fresh_keys(
        knas_int: [u8; 16],
        knas_enc: [u8; 16],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Self {
        Self {
            knas_int,
            knas_enc,
            integrity_algo,
            ciphering_algo,
            ul_count: 0,
            dl_count: 0,
        }
    }

    /// Derive a fresh EPS NAS context from a newly established KASME.
    ///
    /// COUNT starts at zero. Calling this again for the same KASME would violate
    /// TS 33.401 §6.5; use [`Self::reselect_algorithms`] instead.
    pub fn from_fresh_kasme(
        kasme: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Self {
        let knas_int =
            zeroize::Zeroizing::new(eps::derive_nas_key(kasme, 0x02, integrity_algo as u8));
        let knas_enc =
            zeroize::Zeroizing::new(eps::derive_nas_key(kasme, 0x01, ciphering_algo as u8));
        Self::from_fresh_keys(
            oxirush_security::extract_128(&knas_int),
            oxirush_security::extract_128(&knas_enc),
            integrity_algo,
            ciphering_algo,
        )
    }

    /// Selected integrity algorithm.
    pub fn integrity_algorithm(&self) -> IntegrityAlgorithm {
        self.integrity_algo
    }

    /// Selected ciphering algorithm.
    pub fn ciphering_algorithm(&self) -> CipheringAlgorithm {
        self.ciphering_algo
    }

    /// Next uplink NAS COUNT to use or expect.
    pub fn uplink_count(&self) -> u32 {
        self.ul_count
    }

    /// Next downlink NAS COUNT to use or expect.
    pub fn downlink_count(&self) -> u32 {
        self.dl_count
    }

    /// Restore an EPS context and its next COUNT values from persistent state.
    ///
    /// The caller must supply the counts stored for this exact KASME. Passing
    /// zero for a KASME that has already protected traffic violates TS 33.401
    /// §6.5. A value of `0x0100_0000` represents an exhausted COUNT.
    pub fn restore_from_kasme(
        kasme: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
        ul_count: u32,
        dl_count: u32,
    ) -> Result<Self> {
        if ul_count > 0x0100_0000 || dl_count > 0x0100_0000 {
            return Err(NasError::EncodingError(
                "Persisted EPS NAS COUNT exceeds its representable state".into(),
            ));
        }
        let mut context = Self::from_fresh_kasme(kasme, integrity_algo, ciphering_algo);
        context.check_algorithms()?;
        context.ul_count = ul_count;
        context.dl_count = dl_count;
        Ok(context)
    }

    /// Re-derive NAS keys for a new algorithm selection under the same KASME.
    ///
    /// Both COUNTs are preserved, as required by TS 33.401 §§6.5, 7.2.5.2.2,
    /// 7.2.7, and 7.2.8.1.2.
    pub fn reselect_algorithms(
        &mut self,
        kasme: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<()> {
        use zeroize::Zeroize;

        let replacement = Self::from_fresh_kasme(kasme, integrity_algo, ciphering_algo);
        replacement.check_algorithms()?;
        self.knas_int.zeroize();
        self.knas_enc.zeroize();
        self.knas_int = replacement.knas_int;
        self.knas_enc = replacement.knas_enc;
        self.integrity_algo = integrity_algo;
        self.ciphering_algo = ciphering_algo;
        Ok(())
    }

    /// Map a 5GS KAMF to an EPS context for idle mobility.
    ///
    /// `ul_nas_count_used` is the 5GS COUNT used to protect the
    /// mobility-triggering message. The next uplink COUNT is one greater;
    /// the current downlink COUNT carries into the mapped EPS context.
    /// The mapped eKSI is negotiated by the enclosing mobility procedure.
    pub fn from_mapped_kasme_idle(
        kamf: &[u8; 32],
        ul_nas_count_used: u32,
        dl_nas_count: u32,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        if ul_nas_count_used >= 0x00ff_ffff || dl_nas_count > 0x00ff_ffff {
            return Err(NasError::EncodingError(
                "Mapped EPS NAS COUNT is exhausted".into(),
            ));
        }
        let kasme = zeroize::Zeroizing::new(oxirush_security::nas_5gs::derive_mapped_kasme_idle(
            kamf,
            ul_nas_count_used,
        ));
        let mut context = Self::from_fresh_kasme(&kasme, integrity_algo, ciphering_algo);
        context.ul_count = ul_nas_count_used + 1;
        context.dl_count = dl_nas_count;
        Ok(context)
    }

    /// Map a 5GS KAMF to an EPS context for connected handover.
    /// `dl_nas_count_used` derives the key; the next downlink COUNT is one greater.
    pub fn from_mapped_kasme_handover(
        kamf: &[u8; 32],
        ul_nas_count: u32,
        dl_nas_count_used: u32,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        if ul_nas_count > 0x00ff_ffff || dl_nas_count_used >= 0x00ff_ffff {
            return Err(NasError::EncodingError(
                "Mapped EPS NAS COUNT is exhausted".into(),
            ));
        }
        let kasme = zeroize::Zeroizing::new(
            oxirush_security::nas_5gs::derive_mapped_kasme_handover(kamf, dl_nas_count_used),
        );
        let mut context = Self::from_fresh_kasme(&kasme, integrity_algo, ciphering_algo);
        context.ul_count = ul_nas_count;
        context.dl_count = dl_nas_count_used + 1;
        Ok(context)
    }

    fn count(&self, direction: Direction) -> u32 {
        match direction {
            Direction::Uplink => self.ul_count,
            Direction::Downlink => self.dl_count,
        }
    }

    fn set_count(&mut self, direction: Direction, count: u32) {
        match direction {
            Direction::Uplink => self.ul_count = count,
            Direction::Downlink => self.dl_count = count,
        }
    }

    fn advance_count(&mut self, direction: Direction, count: u32) {
        let next = if self.integrity_algo == IntegrityAlgorithm::EIA0 {
            (count + 1) & 0x00ff_ffff
        } else {
            count + 1
        };
        self.set_count(direction, next);
    }

    /// Protect a short SERVICE REQUEST with the five-bit NAS SQN and 16-bit MAC.
    pub fn protect_service_request(&mut self, ksi: u8) -> Result<NasServiceRequest> {
        self.check_algorithms()?;
        if ksi >= 7 {
            return Err(NasError::EncodingError(
                "EPS NAS SERVICE REQUEST requires a current security context KSI".into(),
            ));
        }
        let count = self.ul_count;
        if count > 0x00ff_ffff {
            return Err(NasError::EncodingError("EPS NAS COUNT exhausted".into()));
        }
        let ksi_and_sequence_number = (ksi << 5) | (count as u8 & 0x1f);
        let mac = eps::service_request_short_mac(
            &self.knas_int,
            count,
            Direction::Uplink.as_u8(),
            ksi_and_sequence_number,
            self.integrity_algo as u8,
        );
        self.advance_count(Direction::Uplink, count);
        Ok(NasServiceRequest::new(ksi_and_sequence_number, mac))
    }

    /// Verify a short SERVICE REQUEST and advance the uplink COUNT.
    pub fn unprotect_service_request(&mut self, request: &NasServiceRequest) -> Result<()> {
        self.check_algorithms()?;
        if !(12..=15).contains(&request.security_header_type) {
            return Err(NasError::DecodingError(
                "Invalid EPS SERVICE REQUEST security header type".into(),
            ));
        }
        if request.ksi_and_sequence_number >> 5 == 7 {
            return Err(NasError::DecodingError(
                "EPS NAS SERVICE REQUEST has no current security context KSI".into(),
            ));
        }
        let mut count = crate::common::estimate_count_bits(
            self.ul_count,
            request.ksi_and_sequence_number & 0x1f,
            5,
        );
        if self.integrity_algo == IntegrityAlgorithm::EIA0 {
            count &= 0x00ff_ffff;
        }
        if self.integrity_algo != IntegrityAlgorithm::EIA0
            && (count < self.ul_count || count > 0x00ff_ffff)
        {
            return Err(NasError::DecodingError(
                "EPS NAS COUNT replay or exhaustion".into(),
            ));
        }
        let mac = eps::service_request_short_mac_with_header(
            &self.knas_int,
            count,
            Direction::Uplink.as_u8(),
            (request.security_header_type << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR,
            request.ksi_and_sequence_number,
            self.integrity_algo as u8,
        );
        if self.integrity_algo != IntegrityAlgorithm::EIA0
            && mac != request.message_authentication_code
        {
            return Err(NasError::IntegrityCheckFailed);
        }
        self.advance_count(Direction::Uplink, count);
        Ok(())
    }

    /// Compute the re-establishment NAS MAC for a 28-bit target E-UTRAN Cell
    /// Identifier and atomically consume the next uplink NAS COUNT.
    ///
    /// TS 33.401 §7.4.4 requires the UE to increment UL COUNT as though it
    /// had sent a NAS message. Keeping the calculation and advancement in one
    /// context operation prevents accidental COUNT reuse.
    pub fn protect_re_establishment(&mut self, target_cell_id: u32) -> Result<(u16, u16)> {
        self.check_algorithms()?;
        let count = self.ul_count;
        if count > 0x00ff_ffff {
            return Err(NasError::EncodingError("EPS NAS COUNT exhausted".into()));
        }
        if target_cell_id > 0x0fff_ffff {
            return Err(NasError::EncodingError(
                "E-UTRAN Cell Identifier must be 28 bits".into(),
            ));
        }
        let mac = eps::re_establishment_nas_mac(
            &self.knas_int,
            count,
            target_cell_id,
            self.integrity_algo as u8,
        );
        self.advance_count(Direction::Uplink, count);
        Ok(mac)
    }

    /// Verify a re-establishment request and return the downlink NAS MAC.
    ///
    /// `count_lsb` is the five-bit NAS COUNT value carried by the RRC
    /// connection re-establishment request. On a valid `ul_nas_mac`, the
    /// stored uplink COUNT advances exactly as for an authenticated NAS
    /// message. A failed MAC or invalid input leaves it unchanged.
    ///
    /// This is the network-side operation from TS 33.401 §7.4.4. The caller
    /// sends the returned `DL_NAS_MAC` through the target eNB.
    pub fn verify_re_establishment(
        &mut self,
        count_lsb: u8,
        ul_nas_mac: u16,
        target_cell_id: u32,
    ) -> Result<u16> {
        self.check_algorithms()?;
        if count_lsb > 0x1f {
            return Err(NasError::DecodingError(
                "Re-establishment NAS COUNT field must be five bits".into(),
            ));
        }
        if target_cell_id > 0x0fff_ffff {
            return Err(NasError::DecodingError(
                "E-UTRAN Cell Identifier must be 28 bits".into(),
            ));
        }

        let stored_count = self.ul_count;
        let mut count = crate::common::estimate_count_bits(stored_count, count_lsb, 5);
        if self.integrity_algo == IntegrityAlgorithm::EIA0 {
            count &= 0x00ff_ffff;
        } else if count < stored_count || count > 0x00ff_ffff {
            return Err(NasError::DecodingError(
                "EPS NAS COUNT replay or exhaustion".into(),
            ));
        }
        let (expected_ul_nas_mac, dl_nas_mac) = eps::re_establishment_nas_mac(
            &self.knas_int,
            count,
            target_cell_id,
            self.integrity_algo as u8,
        );
        if self.integrity_algo != IntegrityAlgorithm::EIA0 && ul_nas_mac != expected_ul_nas_mac {
            return Err(NasError::IntegrityCheckFailed);
        }
        self.advance_count(Direction::Uplink, count);
        Ok(dl_nas_mac)
    }

    /// Protect a plain EMM or ESM message.
    pub fn protect(
        &mut self,
        inner: &NasEpsMessage,
        sht: NasEpsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        let inner_bytes = encode_nas_eps_message(inner)?;
        self.protect_bytes(inner_bytes, sht, direction)
    }

    /// Protect an already encoded plain EMM or ESM message.
    pub fn protect_bytes(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: NasEpsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        self.check_algorithms()?;
        // Both DETACH REQUEST forms share one message type; the direction
        // selects the form to check.
        let inner = decode_nas_eps_message_with_direction(&inner_bytes, direction)?;
        if !matches!(inner, NasEpsMessage::Emm(..) | NasEpsMessage::Esm(..)) {
            return Err(NasError::EncodingError(
                "EPS security requires a plain EMM or ESM message".into(),
            ));
        }
        if !matches!(
            sht,
            NasEpsSecurityHeaderType::IntegrityProtected
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered
        ) {
            return Err(NasError::EncodingError(
                "Unsupported EPS security header type for protection".into(),
            ));
        }
        validate_sht_message(sht, &inner, direction)?;
        self.protect_envelope(inner_bytes, sht, direction)
    }

    /// Protect explicitly opaque or malformed inner bytes without codec checks.
    ///
    /// Only regular security headers 1 through 4 are supported; plain, partial,
    /// EMM TRANSPORT and short SERVICE REQUEST envelopes are rejected. The
    /// payload is not decoded or re-encoded, so its message direction and
    /// header pairing are deliberately unchecked. Existing keys and COUNT are
    /// used even for a new-context header; no keys are installed and no COUNT
    /// is reset. COUNT advances once after successful composition. Checked
    /// receivers may reject the authenticated inner payload.
    pub fn protect_opaque_payload(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: NasEpsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        self.check_algorithms()?;
        if !matches!(
            sht,
            NasEpsSecurityHeaderType::IntegrityProtected
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
        ) {
            return Err(NasError::EncodingError(
                "Opaque EPS protection requires a regular security header type".into(),
            ));
        }
        self.protect_envelope(inner_bytes, sht, direction)
    }

    fn protect_envelope(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: NasEpsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        let count = self.count(direction);
        if count > 0x00FF_FFFF {
            return Err(NasError::EncodingError("EPS NAS COUNT exhausted".into()));
        }
        let sequence_number = count as u8;
        let mut payload = inner_bytes;
        if matches!(
            sht,
            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
        ) {
            eps::nas_cipher(
                &self.knas_enc,
                count,
                direction.as_u8(),
                &mut payload,
                self.ciphering_algo as u8,
            );
        } else if sht == NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered {
            cipher_control_plane_container(
                &mut payload,
                &self.knas_enc,
                count,
                direction,
                self.ciphering_algo as u8,
            )?;
        }
        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sequence_number);
        mac_input.extend_from_slice(&payload);
        let mac = eps::nas_mac(
            &self.knas_int,
            count,
            direction.as_u8(),
            &mac_input,
            self.integrity_algo as u8,
        );
        let mut wire = Vec::with_capacity(EPS_SECURITY_HEADER_LEN + payload.len());
        wire.push(((sht as u8) << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR);
        wire.extend_from_slice(&mac.to_be_bytes());
        wire.push(sequence_number);
        wire.extend_from_slice(&payload);
        self.advance_count(direction, count);
        Ok(wire)
    }

    /// Protect the data container of an EMM TRANSPORT (TS 24.301 §4.4.5).
    /// The complete data container starts at octet 7 and is ciphered as a unit.
    pub fn protect_emm_transport(
        &mut self,
        data_container: Option<&[u8]>,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        self.check_algorithms()?;
        if data_container
            .is_some_and(|data| !valid_emm_data_container(data, direction == Direction::Downlink))
        {
            return Err(NasError::EncodingError(
                "Invalid EMM TRANSPORT data container".into(),
            ));
        }
        let count = self.count(direction);
        if count > 0x00ff_ffff {
            return Err(NasError::EncodingError("EPS NAS COUNT exhausted".into()));
        }
        let sequence_number = count as u8;
        let mut payload = data_container.map_or_else(Vec::new, <[u8]>::to_vec);
        eps::nas_cipher(
            &self.knas_enc,
            count,
            direction.as_u8(),
            &mut payload,
            self.ciphering_algo as u8,
        );
        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sequence_number);
        mac_input.extend_from_slice(&payload);
        let mac = eps::nas_mac(
            &self.knas_int,
            count,
            direction.as_u8(),
            &mac_input,
            self.integrity_algo as u8,
        );
        let mut wire = Vec::with_capacity(EPS_SECURITY_HEADER_LEN + payload.len());
        wire.push(0xb7);
        wire.extend_from_slice(&mac.to_be_bytes());
        wire.push(sequence_number);
        wire.extend_from_slice(&payload);
        self.advance_count(direction, count);
        Ok(wire)
    }

    /// Verify, decipher, and decode an inbound EPS NAS message.
    ///
    /// A MAC mismatch returns [`NasError::IntegrityCheckFailed`] and leaves
    /// the COUNTs unchanged. A receiver that must still process the message
    /// (TS 24.301 §4.4.4.3) can decode the PDU with
    /// [`decode_nas_eps_message`],
    /// which returns the unverified inner message when it is not ciphered.
    pub fn unprotect(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<(NasEpsMessage, NasEpsSecurityHeaderType)> {
        let (plain, sht) = self.unprotect_raw(data, direction)?;
        if sht == NasEpsSecurityHeaderType::EmmTransport {
            let mac = u32::from_be_bytes(data[1..5].try_into().expect("four MAC octets"));
            return Ok((
                NasEpsMessage::EmmTransport(if plain.is_empty() {
                    NasEmmTransport::new(mac, data[5])
                } else {
                    NasEmmTransport::new(mac, data[5]).set_data_container(plain)
                }),
                sht,
            ));
        }
        let message = decode_nas_eps_message_with_direction(&plain, direction)?;
        if !matches!(message, NasEpsMessage::Emm(..) | NasEpsMessage::Esm(..)) {
            return Err(NasError::DecodingError(
                "EPS security envelope has no plain EMM or ESM message".into(),
            ));
        }
        Ok((message, sht))
    }

    /// Verify and decipher an inbound PDU, returning its plain bytes.
    pub fn unprotect_raw(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<(Vec<u8>, NasEpsSecurityHeaderType)> {
        self.check_algorithms()?;
        if data.len() < EPS_SECURITY_HEADER_LEN {
            return Err(NasError::BufferTooShort);
        }
        if data[0] & 0x0F != EPS_EMM_PROTOCOL_DISCRIMINATOR {
            return Err(NasError::DecodingError(
                "Invalid EPS security protocol discriminator".into(),
            ));
        }
        let sht = NasEpsSecurityHeaderType::try_from(data[0] >> 4)?;
        if !matches!(
            sht,
            NasEpsSecurityHeaderType::IntegrityProtected
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered
                | NasEpsSecurityHeaderType::EmmTransport
        ) {
            return Err(NasError::DecodingError(
                "Unsupported EPS security header type for unprotection".into(),
            ));
        }
        let received_mac = u32::from_be_bytes(data[1..5].try_into().expect("four MAC octets"));
        let sequence_number = data[5];
        let payload = &data[EPS_SECURITY_HEADER_LEN..];
        let stored_count = self.count(direction);
        let mut count = crate::common::estimate_count(stored_count, sequence_number);
        if self.integrity_algo == IntegrityAlgorithm::EIA0 {
            count &= 0x00ff_ffff;
        }
        if self.integrity_algo != IntegrityAlgorithm::EIA0
            && (count < stored_count || count > 0x00FF_FFFF)
        {
            return Err(NasError::DecodingError(
                "EPS NAS COUNT replay or exhaustion".into(),
            ));
        }
        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sequence_number);
        mac_input.extend_from_slice(payload);
        let expected_mac = eps::nas_mac(
            &self.knas_int,
            count,
            direction.as_u8(),
            &mac_input,
            self.integrity_algo as u8,
        );
        if self.integrity_algo != IntegrityAlgorithm::EIA0 && received_mac != expected_mac {
            return Err(NasError::IntegrityCheckFailed);
        }
        // TS 24.301 §4.4.3.3 commits the received NAS COUNT after successful
        // integrity verification. Inner syntax and header-pairing checks must
        // not make an authenticated COUNT reusable.
        self.advance_count(direction, count);

        let mut plain = payload.to_vec();
        if matches!(
            sht,
            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                | NasEpsSecurityHeaderType::EmmTransport
        ) {
            eps::nas_cipher(
                &self.knas_enc,
                count,
                direction.as_u8(),
                &mut plain,
                self.ciphering_algo as u8,
            );
        } else if sht == NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered {
            cipher_control_plane_container(
                &mut plain,
                &self.knas_enc,
                count,
                direction,
                self.ciphering_algo as u8,
            )?;
        }
        if sht == NasEpsSecurityHeaderType::EmmTransport {
            if !plain.is_empty()
                && !received_emm_data_container_is_valid(&plain, direction == Direction::Downlink)
            {
                return Err(NasError::DecodingError(
                    "Invalid EMM TRANSPORT data container".into(),
                ));
            }
        } else {
            let inner = decode_nas_eps_message_with_direction(&plain, direction)?;
            validate_sht_message(sht, &inner, direction).map_err(|_| {
                NasError::DecodingError(
                    "EPS security header type does not match message type".into(),
                )
            })?;
        }
        Ok((plain, sht))
    }
}

#[cfg(all(test, feature = "security"))]
mod tests {
    use super::*;
    use crate::common::Validate;
    use crate::nas_eps::messages::{
        NasControlPlaneServiceRequest, NasEmmMessage, NasEmmStatus, NasEsmMessage,
        NasPdnConnectivityRequest, NasSecurityModeCommand, NasSecurityModeComplete,
    };
    use crate::nas_eps::types::{
        NasControlPlaneServiceType, NasEmmCause, NasEsmMessageContainer, NasKeySetIdentifier,
        NasMessageContainer, NasPdnType, NasReplayedUeSecurityCapabilities, NasRequestType,
        NasSelectedNasSecurityAlgorithms, NasSpareHalfOctet,
    };

    #[test]
    fn security_mode_requires_its_header_and_direction() {
        let command = NasEpsMessage::new_emm(NasEmmMessage::SecurityModeCommand(
            NasSecurityModeCommand::new(
                NasSelectedNasSecurityAlgorithms::new(0),
                NasKeySetIdentifier::new(0),
                NasSpareHalfOctet::new(0),
                NasReplayedUeSecurityCapabilities::new(vec![0; 2]),
            ),
        ));
        let complete = NasEpsMessage::new_emm(NasEmmMessage::SecurityModeComplete(
            NasSecurityModeComplete::new(),
        ));
        let cases = [
            (
                &command,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
            ),
            (
                &command,
                NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext,
                Direction::Uplink,
            ),
            (
                &complete,
                NasEpsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            ),
            (
                &complete,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext,
                Direction::Downlink,
            ),
        ];
        for (message, sht, direction) in cases {
            let mut context = context();
            assert!(context.protect(message, sht, direction).is_err());
            assert_eq!((context.ul_count, context.dl_count), (0, 0));
        }
        assert!(
            context()
                .protect(
                    &command,
                    NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext,
                    Direction::Downlink,
                )
                .is_ok()
        );
        assert!(
            context()
                .protect(
                    &complete,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext,
                    Direction::Uplink,
                )
                .is_ok()
        );
    }

    #[test]
    fn mapped_5gs_context_copies_counts_and_uses_mapped_key() {
        let kamf = core::array::from_fn(|i| i as u8);
        let kasme = oxirush_security::nas_5gs::derive_mapped_kasme_idle(&kamf, 0x1234);
        let expected = NasSecurityContext::from_fresh_kasme(
            &kasme,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        );
        let context = NasSecurityContext::from_mapped_kasme_idle(
            &kamf,
            0x1234,
            0x5678,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        )
        .unwrap();
        assert_eq!(context.knas_int, expected.knas_int);
        assert_eq!(context.knas_enc, expected.knas_enc);
        assert_eq!((context.ul_count, context.dl_count), (0x1235, 0x5678));
        let message = NasEpsMessage::new_emm(NasEmmMessage::EmmStatus(NasEmmStatus::new(
            NasEmmCause::new(3),
        )));
        let wire = context
            .clone()
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(wire, [0x27, 0x3b, 0xa8, 0xe0, 0xf4, 0x35, 0xbb, 0x27, 0x2e]);

        let handover = NasSecurityContext::from_mapped_kasme_handover(
            &kamf,
            0x1234,
            0x5678,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        )
        .unwrap();
        assert_ne!(handover.knas_int, context.knas_int);
        assert_eq!((handover.ul_count, handover.dl_count), (0x1234, 0x5679));
        let wire = handover
            .clone()
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
            )
            .unwrap();
        assert_eq!(wire, [0x27, 0x77, 0x6a, 0x52, 0xea, 0x79, 0x31, 0x21, 0x28]);
        assert!(
            NasSecurityContext::from_mapped_kasme_idle(
                &kamf,
                0x00ff_ffff,
                0,
                IntegrityAlgorithm::EIA2,
                CipheringAlgorithm::EEA2,
            )
            .is_err()
        );
        assert!(
            NasSecurityContext::from_mapped_kasme_handover(
                &kamf,
                0,
                0x00ff_ffff,
                IntegrityAlgorithm::EIA2,
                CipheringAlgorithm::EEA2,
            )
            .is_err()
        );
    }

    fn context() -> NasSecurityContext {
        NasSecurityContext::from_fresh_keys(
            [0x11; 16],
            [0x22; 16],
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        )
    }

    #[test]
    fn opaque_payload_preserves_malformed_bytes_and_authenticates_all_regular_headers() {
        let inner = vec![0x07, 0xff, 0x20, 0x02, 0xbb, 0xaa, 0x20, 0x01, 0xcc];
        for direction in [Direction::Uplink, Direction::Downlink] {
            for sht in [
                NasEpsSecurityHeaderType::IntegrityProtected,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext,
            ] {
                let mut sender = context();
                sender.set_count(direction, 0x1234);
                assert!(sender.protect_bytes(inner.clone(), sht, direction).is_err());
                assert_eq!(sender.count(direction), 0x1234);
                let mut receiver = sender.clone();
                let mut tampered_receiver = receiver.clone();
                let wire = sender
                    .protect_opaque_payload(inner.clone(), sht, direction)
                    .unwrap();
                let mut payload = inner.clone();
                if matches!(sht as u8, 2 | 4) {
                    eps::nas_cipher(&[0x22; 16], 0x1234, direction.as_u8(), &mut payload, 2);
                }
                assert_eq!(wire[0], ((sht as u8) << 4) | 7);
                assert_eq!(wire[5], 0x34);
                assert_eq!(&wire[6..], payload);
                let mac = eps::nas_mac(&[0x11; 16], 0x1234, direction.as_u8(), &wire[5..], 2);
                assert_eq!(&wire[1..5], mac.to_be_bytes());
                if matches!(sht as u8, 2 | 4) {
                    eps::nas_cipher(&[0x22; 16], 0x1234, direction.as_u8(), &mut payload, 2);
                }
                assert_eq!(payload, inner);
                assert_eq!(sender.count(direction), 0x1235);
                assert_eq!(
                    sender.count(if direction == Direction::Uplink {
                        Direction::Downlink
                    } else {
                        Direction::Uplink
                    }),
                    0
                );
                assert_eq!(sender.knas_int, [0x11; 16]);
                assert_eq!(sender.knas_enc, [0x22; 16]);
                let mut tampered = wire.clone();
                tampered[1] ^= 1;
                assert!(matches!(
                    tampered_receiver.unprotect_raw(&tampered, direction),
                    Err(NasError::IntegrityCheckFailed)
                ));
                assert_eq!(tampered_receiver.count(direction), 0x1234);
                assert!(matches!(
                    receiver.unprotect_raw(&wire, direction),
                    Err(NasError::UnknownMessageType(0xff))
                ));
                assert_eq!(receiver.count(direction), 0x1235);
            }
        }
    }

    #[test]
    fn opaque_payload_matches_checked_protection_without_relaxing_checked_headers_or_direction() {
        let inner = vec![0x07, 0x60, 0x03]; // EMM STATUS.
        let mut sender = context();
        let mut receiver = context();
        for sht in [
            NasEpsSecurityHeaderType::IntegrityProtected,
            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
        ] {
            let checked = sender
                .clone()
                .protect_bytes(inner.clone(), sht, Direction::Uplink)
                .unwrap();
            let opaque = sender
                .protect_opaque_payload(inner.clone(), sht, Direction::Uplink)
                .unwrap();
            assert_eq!(opaque, checked);
            assert_eq!(
                receiver.unprotect_raw(&opaque, Direction::Uplink).unwrap(),
                (inner.clone(), sht)
            );
        }
        assert!(
            sender
                .protect_bytes(
                    inner,
                    NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext,
                    Direction::Uplink
                )
                .is_err()
        );
        assert!(
            sender
                .protect_bytes(
                    vec![0x07, 0x5f, 0x03], // Uplink SECURITY MODE REJECT.
                    NasEpsSecurityHeaderType::IntegrityProtected,
                    Direction::Downlink
                )
                .is_err()
        );
        assert_eq!((sender.ul_count, sender.dl_count), (2, 0));
    }

    #[test]
    fn opaque_payload_rejects_envelope_errors_without_consuming_count() {
        let mut sender = context();
        let sht = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
        for unsupported in [
            NasEpsSecurityHeaderType::PlainNasMessage,
            NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered,
            NasEpsSecurityHeaderType::EmmTransport,
            NasEpsSecurityHeaderType::ServiceRequest,
        ] {
            assert!(
                sender
                    .protect_opaque_payload(vec![0xff], unsupported, Direction::Uplink)
                    .is_err()
            );
            assert_eq!(sender.ul_count, 0);
        }
        for (integrity, ciphering) in [
            (IntegrityAlgorithm::EIA7, CipheringAlgorithm::EEA2),
            (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA7),
            (IntegrityAlgorithm::EIA0, CipheringAlgorithm::EEA2),
        ] {
            sender.integrity_algo = integrity;
            sender.ciphering_algo = ciphering;
            assert!(
                sender
                    .protect_opaque_payload(vec![0xff], sht, Direction::Uplink)
                    .is_err()
            );
            assert_eq!(sender.ul_count, 0);
        }
        sender.integrity_algo = IntegrityAlgorithm::EIA2;
        sender.ciphering_algo = CipheringAlgorithm::EEA2;
        for direction in [Direction::Uplink, Direction::Downlink] {
            sender.set_count(direction, 0x00ff_ffff);
            let wire = sender
                .protect_opaque_payload(Vec::new(), sht, direction)
                .unwrap();
            assert_eq!(wire.len(), 6);
            assert_eq!(wire[5], 0xff);
            let mac = eps::nas_mac(&[0x11; 16], 0x00ff_ffff, direction.as_u8(), &wire[5..], 2);
            assert_eq!(&wire[1..5], mac.to_be_bytes());
            assert_eq!(sender.count(direction), 0x0100_0000);
            assert!(
                sender
                    .protect_opaque_payload(vec![0xff], sht, direction)
                    .is_err()
            );
            assert_eq!(sender.count(direction), 0x0100_0000);
        }
    }

    #[test]
    fn eps_ciphered_message_uses_zero_bearer_and_rejects_tampering() {
        let message = NasEpsMessage::new_emm(NasEmmMessage::EmmStatus(NasEmmStatus::new(
            NasEmmCause::new(3),
        )));
        let mut sender = context();
        let mut receiver = context();
        let wire = sender
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Uplink,
            )
            .unwrap();
        // Independently checked with AES-CTR and AES-CMAC using OpenSSL.
        assert_eq!(wire, [0x27, 0x2d, 0x20, 0x99, 0x94, 0x00, 0x32, 0xc6, 0x12]);
        let expected_mac = eps::nas_mac(&[0x11; 16], 0, 0, &wire[5..], 2);
        assert_eq!(&wire[1..5], expected_mac.to_be_bytes());
        let mut tampered = wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(receiver.unprotect(&tampered, Direction::Uplink).is_err());
        assert_eq!(receiver.ul_count, 0);
        let (decoded, sht) = receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(sht, NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered);
        assert_eq!(decoded, message);
        assert_eq!(receiver.ul_count, 1);
        assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
    }

    #[test]
    fn network_detach_that_also_parses_as_the_ue_form_is_protected() {
        // Detach type 1 with a forbidden TAI list: the body is also a valid
        // UE-originated DETACH REQUEST, so only the direction tells them apart.
        let plain = hex::decode(
            "0745011d200d5ab2594f09d78af9848bc8c934aef5f813475d1d03fdd4592d4febacfde0ed",
        )
        .unwrap();
        let message = decode_nas_eps_message_with_direction(&plain, Direction::Downlink).unwrap();
        assert!(matches!(
            message,
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestToUe(_))
        ));
        let sht = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
        let wire = context()
            .protect(&message, sht, Direction::Downlink)
            .unwrap();
        assert_eq!(
            context()
                .protect_bytes(plain, sht, Direction::Downlink)
                .unwrap(),
            wire
        );
        let (decoded, _) = context().unprotect(&wire, Direction::Downlink).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn independent_eps_count_boundary_vectors_and_replay() {
        let message = NasEpsMessage::new_emm(NasEmmMessage::EmmStatus(NasEmmStatus::new(
            NasEmmCause::new(3),
        )));
        for (count, expected) in [
            (
                0x0000_00ff,
                [0x27, 0xc2, 0x01, 0x2c, 0xe8, 0xff, 0x18, 0x4f, 0x79],
            ),
            (
                0x0000_0100,
                [0x27, 0x7e, 0x23, 0x56, 0x05, 0x00, 0x29, 0x9d, 0xc1],
            ),
            (
                0x00ff_fffe,
                [0x27, 0x21, 0x9b, 0x4b, 0xad, 0xfe, 0xe8, 0x30, 0xa2],
            ),
            (
                0x00ff_ffff,
                [0x27, 0x39, 0x47, 0xa1, 0x5d, 0xff, 0xe1, 0x29, 0x1c],
            ),
        ] {
            let mut sender = context();
            let mut receiver = context();
            sender.dl_count = count;
            receiver.dl_count = count;
            let wire = sender
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                    Direction::Downlink,
                )
                .unwrap();
            assert_eq!(wire, expected, "COUNT {count:#08x}");
            assert_eq!(sender.dl_count, count + 1);
            assert_eq!(
                receiver.unprotect(&wire, Direction::Downlink).unwrap().0,
                message
            );
            assert_eq!(receiver.dl_count, count + 1);
            assert!(receiver.unprotect(&wire, Direction::Downlink).is_err());
            if count == 0x00ff_ffff {
                assert!(
                    sender
                        .protect(
                            &message,
                            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                            Direction::Downlink,
                        )
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn eia0_requires_eea0() {
        let message = NasEpsMessage::new_emm(NasEmmMessage::EmmStatus(NasEmmStatus::new(
            NasEmmCause::new(3),
        )));
        let mut context = NasSecurityContext::from_fresh_keys(
            [0; 16],
            [0; 16],
            IntegrityAlgorithm::EIA0,
            CipheringAlgorithm::EEA2,
        );
        assert!(
            context
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtected,
                    Direction::Uplink
                )
                .is_err()
        );
        assert_eq!(context.ul_count, 0);
        assert!(
            context
                .unprotect(&[0x17, 0, 0, 0, 0, 0, 0x07, 0x60, 0x03], Direction::Uplink)
                .is_err()
        );
    }

    #[test]
    fn fresh_count_after_gap_is_accepted_and_replay_is_not() {
        // TS 24.301 §4.4.3.1: a lower sequence number means the overflow
        // counter advanced, independent of the current overflow value.
        let message = NasEpsMessage::new_emm(NasEmmMessage::EmmStatus(NasEmmStatus::new(
            NasEmmCause::new(3),
        )));
        for (receiver_next, sender_count) in [(0x05, 0x90), (0x0105, 0x0190), (0x01f0, 0x0202)] {
            let mut sender = context();
            let mut receiver = context();
            sender.ul_count = sender_count;
            receiver.ul_count = receiver_next;
            let wire = sender
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                    Direction::Uplink,
                )
                .unwrap();
            assert_eq!(
                receiver.unprotect(&wire, Direction::Uplink).unwrap().0,
                message
            );
            assert_eq!(receiver.ul_count, sender_count + 1);
            assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
            assert_eq!(receiver.ul_count, sender_count + 1);
        }

        // Five-bit SERVICE REQUEST sequence numbers after a gap of 17.
        let mut sender = context();
        let mut receiver = context();
        sender.ul_count = 49;
        receiver.ul_count = 32;
        let request = sender.protect_service_request(1).unwrap();
        receiver.unprotect_service_request(&request).unwrap();
        assert_eq!(receiver.ul_count, 50);
        assert!(receiver.unprotect_service_request(&request).is_err());
    }

    #[test]
    fn eps_integrity_only_esm_message_round_trips() {
        let message = NasEpsMessage::new_esm(
            NasEsmMessage::PdnConnectivityRequest(NasPdnConnectivityRequest::new(
                NasRequestType::new(1),
                NasPdnType::new(3),
            )),
            0,
            1,
        );
        let mut sender = context();
        let mut receiver = context();
        assert!(
            sender
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtected,
                    Direction::Downlink,
                )
                .is_err()
        );
        assert_eq!(sender.dl_count, 0);
        let wire = sender
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(wire[0], 0x17);
        let (decoded, _) = receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn eps_keys_derive_from_fresh_kasme() {
        let kasme = [0x42; 32];
        let context = NasSecurityContext::from_fresh_kasme(
            &kasme,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA1,
        );
        assert_eq!(
            context.knas_int,
            oxirush_security::extract_128(&eps::derive_nas_key(&kasme, 2, 2))
        );
        assert_eq!(
            context.knas_enc,
            oxirush_security::extract_128(&eps::derive_nas_key(&kasme, 1, 1))
        );
    }

    #[test]
    fn persisted_eps_context_and_algorithm_reselection_preserve_counts() {
        let kasme = [0x42; 32];
        let mut context = NasSecurityContext::restore_from_kasme(
            &kasme,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
            0x0012_3456,
            0x0000_abcd,
        )
        .unwrap();
        let old_keys = (context.knas_int, context.knas_enc);
        assert_eq!(context.uplink_count(), 0x0012_3456);
        assert_eq!(context.downlink_count(), 0x0000_abcd);

        context
            .reselect_algorithms(&kasme, IntegrityAlgorithm::EIA1, CipheringAlgorithm::EEA1)
            .unwrap();
        assert_eq!(context.integrity_algorithm(), IntegrityAlgorithm::EIA1);
        assert_eq!(context.ciphering_algorithm(), CipheringAlgorithm::EEA1);
        assert_eq!(context.uplink_count(), 0x0012_3456);
        assert_eq!(context.downlink_count(), 0x0000_abcd);
        assert_ne!((context.knas_int, context.knas_enc), old_keys);

        assert!(
            NasSecurityContext::restore_from_kasme(
                &kasme,
                IntegrityAlgorithm::EIA2,
                CipheringAlgorithm::EEA2,
                0x0100_0001,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn eps_service_request_short_mac_and_replay() {
        let mut sender = context();
        let mut receiver = context();
        sender.ul_count = 31;
        receiver.ul_count = 31;
        let request = sender.protect_service_request(3).unwrap();
        assert_eq!(request.ksi_and_sequence_number, 0x7f);
        assert_eq!(
            request.message_authentication_code,
            eps::service_request_short_mac(&[0x11; 16], 31, 0, 0x7f, 2)
        );
        let wire = NasEpsMessage::ServiceRequest(request.clone())
            .to_bytes()
            .unwrap();
        assert_eq!(wire.len(), 4);
        let decoded = NasEpsMessage::from_bytes(&wire).unwrap();
        assert_eq!(decoded, NasEpsMessage::ServiceRequest(request.clone()));
        let mut tampered = request.clone();
        tampered.message_authentication_code ^= 1;
        assert!(receiver.unprotect_service_request(&tampered).is_err());
        assert_eq!(receiver.ul_count, 31);
        receiver.unprotect_service_request(&request).unwrap();
        assert_eq!(receiver.ul_count, 32);
        assert!(receiver.unprotect_service_request(&request).is_err());
        let next = sender.protect_service_request(3).unwrap();
        receiver.unprotect_service_request(&next).unwrap();
        assert_eq!(receiver.ul_count, 33);
    }

    #[test]
    fn re_establishment_mac_atomically_consumes_ul_count() {
        let mut context = context();
        context.ul_count = 7;
        let expected = eps::re_establishment_nas_mac(
            &context.knas_int,
            7,
            0x0123_4567,
            context.integrity_algo as u8,
        );
        assert_eq!(
            context.protect_re_establishment(0x0123_4567).unwrap(),
            expected
        );
        assert_eq!(context.ul_count, 8);
        assert!(context.protect_re_establishment(0x1000_0000).is_err());
        assert_eq!(context.ul_count, 8);

        context.ul_count = 0x00ff_ffff;
        assert!(context.protect_re_establishment(0x0123_4567).is_ok());
        assert_eq!(context.ul_count, 0x0100_0000);
        assert!(context.protect_re_establishment(0x0123_4567).is_err());
        assert_eq!(context.ul_count, 0x0100_0000);
    }

    #[test]
    fn re_establishment_verification_estimates_count_and_commits_atomically() {
        let mut receiver = context();
        receiver.ul_count = 7;
        let (ul_nas_mac, dl_nas_mac) = eps::re_establishment_nas_mac(
            &receiver.knas_int,
            7,
            0x0123_4567,
            receiver.integrity_algo as u8,
        );

        assert!(
            receiver
                .verify_re_establishment(7, ul_nas_mac ^ 1, 0x0123_4567)
                .is_err()
        );
        assert_eq!(receiver.ul_count, 7);
        assert_eq!(
            receiver
                .verify_re_establishment(7, ul_nas_mac, 0x0123_4567)
                .unwrap(),
            dl_nas_mac
        );
        assert_eq!(receiver.ul_count, 8);
        assert!(
            receiver
                .verify_re_establishment(7, ul_nas_mac, 0x0123_4567)
                .is_err()
        );
        assert_eq!(receiver.ul_count, 8);

        let mut after_gap = context();
        after_gap.ul_count = 8;
        let count = 39;
        let (ul_nas_mac, dl_nas_mac) = eps::re_establishment_nas_mac(
            &after_gap.knas_int,
            count,
            0x0123_4567,
            after_gap.integrity_algo as u8,
        );
        assert_eq!(
            after_gap
                .verify_re_establishment(7, ul_nas_mac, 0x0123_4567)
                .unwrap(),
            dl_nas_mac
        );
        assert_eq!(after_gap.ul_count, 40);
        assert!(
            after_gap
                .verify_re_establishment(0x20, 0, 0x0123_4567)
                .is_err()
        );
        assert_eq!(after_gap.ul_count, 40);
    }

    #[test]
    fn eps_partial_ciphering_preserves_clear_header_and_recovers_container() {
        for use_esm in [true, false] {
            let mut request = NasControlPlaneServiceRequest::new(
                NasControlPlaneServiceType::new(0),
                NasKeySetIdentifier::new(0),
            );
            if use_esm {
                request.esm_message_container =
                    Some(NasEsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]));
            } else {
                request.nas_message_container =
                    Some(NasMessageContainer::new(vec![0x11, 0x22, 0x33]));
            }
            let message =
                NasEpsMessage::new_emm(NasEmmMessage::ControlPlaneServiceRequest(request));
            let plain = message.to_bytes().unwrap();
            let mut sender = context();
            let mut receiver = context();
            assert!(
                sender
                    .protect(
                        &message,
                        NasEpsSecurityHeaderType::IntegrityProtected,
                        Direction::Uplink
                    )
                    .is_err()
            );
            assert!(
                sender
                    .protect(
                        &message,
                        NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                        Direction::Uplink
                    )
                    .is_err()
            );
            assert_eq!(sender.ul_count, 0);
            let mac = eps::nas_mac(
                &sender.knas_int,
                0,
                0,
                &[&[0], plain.as_slice()].concat(),
                2,
            );
            let mut wrong_sht = vec![0x17];
            wrong_sht.extend_from_slice(&mac.to_be_bytes());
            wrong_sht.push(0);
            wrong_sht.extend_from_slice(&plain);
            assert!(receiver.unprotect(&wrong_sht, Direction::Uplink).is_err());
            assert_eq!(receiver.ul_count, 1);
            let mut receiver = context();
            let wire = sender
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered,
                    Direction::Uplink,
                )
                .unwrap();
            assert_eq!(wire[0], 0x57);
            assert_eq!(&wire[6..9], &plain[..3]);
            assert_ne!(&wire[9..], &plain[3..]);
            let (decoded, sht) = receiver.unprotect(&wire, Direction::Uplink).unwrap();
            assert_eq!(
                sht,
                NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered
            );
            assert_eq!(decoded.to_bytes().unwrap(), plain);
            let mut tampered = wire;
            tampered[7] ^= 1;
            assert!(context().unprotect(&tampered, Direction::Uplink).is_err());
        }
    }

    #[test]
    fn control_plane_service_request_without_container_uses_integrity_only() {
        let message = NasEpsMessage::new_emm(NasEmmMessage::ControlPlaneServiceRequest(
            NasControlPlaneServiceRequest::new(
                NasControlPlaneServiceType::new(0),
                NasKeySetIdentifier::new(0),
            ),
        ));
        assert!(
            context()
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtected,
                    Direction::Downlink,
                )
                .is_err()
        );
        let plain = message.to_bytes().unwrap();
        let mut wrong_direction_wire = vec![0x17];
        let mac = eps::nas_mac(
            &[0x11; 16],
            0,
            Direction::Downlink.as_u8(),
            &[&[0], plain.as_slice()].concat(),
            2,
        );
        wrong_direction_wire.extend_from_slice(&mac.to_be_bytes());
        wrong_direction_wire.push(0);
        wrong_direction_wire.extend_from_slice(&plain);
        let mut wrong_direction_receiver = context();
        assert!(
            wrong_direction_receiver
                .unprotect_raw(&wrong_direction_wire, Direction::Downlink)
                .is_err()
        );
        assert_eq!(wrong_direction_receiver.dl_count, 1);
        let mut sender = context();
        for sht in [
            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
            NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered,
        ] {
            assert!(sender.protect(&message, sht, Direction::Uplink).is_err());
            assert_eq!(sender.ul_count, 0);
        }
        let wire = sender
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(&wire[6..], message.to_bytes().unwrap());
        let mut receiver = context();
        assert_eq!(
            receiver.unprotect(&wire, Direction::Uplink).unwrap().0,
            message
        );
    }

    #[test]
    fn emm_transport_ciphers_complete_container_and_accepts_absence() {
        let mut sender = context();
        let mut receiver = context();
        let mut raw_receiver = context();
        let wire = sender
            .protect_emm_transport(Some(&[0x01, 0xab]), Direction::Uplink)
            .unwrap();
        assert_eq!(wire[0], 0xb7);
        assert_eq!(
            raw_receiver
                .unprotect_raw(&wire, Direction::Uplink)
                .unwrap()
                .0,
            [0x01, 0xab]
        );
        let opaque = NasEpsMessage::from_bytes(&wire).unwrap();
        assert_eq!(opaque.to_bytes().unwrap(), wire);
        let (decoded, sht) = receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(sht, NasEpsSecurityHeaderType::EmmTransport);
        let NasEpsMessage::EmmTransport(transport) = decoded else {
            panic!("expected EMM TRANSPORT")
        };
        assert_eq!(transport.data_container.as_deref(), Some(&[0x01, 0xab][..]));
        assert!(NasEpsMessage::EmmTransport(transport).to_bytes().is_err());
        let empty_wire = sender
            .protect_emm_transport(None, Direction::Uplink)
            .unwrap();
        let (empty, _) = receiver.unprotect(&empty_wire, Direction::Uplink).unwrap();
        let NasEpsMessage::EmmTransport(empty) = empty else {
            panic!("expected EMM TRANSPORT")
        };
        assert!(empty.data_container.is_none());
        assert!(
            sender
                .protect_emm_transport(Some(&[]), Direction::Uplink)
                .is_err()
        );
        assert!(
            sender
                .protect_emm_transport(Some(&[0x79, 0xaa]), Direction::Uplink)
                .is_err()
        );
    }

    #[test]
    fn received_emm_transport_ignores_spare_bits() {
        // An SMS container with a spare bit set and a
        // downlink control-plane container with DDX bits (spare in that
        // direction) are accepted once the MAC verifies (TS 24.007 §11.1.4).
        for container in [[0x21, 0xaa], [0x09, 0xaa]] {
            let mut payload = container.to_vec();
            eps::nas_cipher(&[0x22; 16], 0, 1, &mut payload, 2);
            let mut mac_input = vec![0];
            mac_input.extend_from_slice(&payload);
            let mac = eps::nas_mac(&[0x11; 16], 0, 1, &mac_input, 2);
            let mut wire = vec![0xb7];
            wire.extend_from_slice(&mac.to_be_bytes());
            wire.extend_from_slice(&mac_input);
            let (plain, _) = context().unprotect_raw(&wire, Direction::Downlink).unwrap();
            assert_eq!(plain, container);
            // A sender still has to clear them.
            assert!(
                context()
                    .protect_emm_transport(Some(&container), Direction::Downlink)
                    .is_err()
            );
        }
    }

    #[test]
    fn eia0_skips_mac_and_replay_and_wraps_count() {
        let mut sender = NasSecurityContext::from_fresh_keys(
            [0; 16],
            [0; 16],
            IntegrityAlgorithm::EIA0,
            CipheringAlgorithm::EEA0,
        );
        let mut receiver = sender.clone();
        sender.ul_count = 0x00ff_ffff;
        receiver.ul_count = 0x00ff_ffff;
        let message = NasEpsMessage::new_emm(NasEmmMessage::EmmStatus(NasEmmStatus::new(
            NasEmmCause::new(3),
        )));
        let mut wire = sender
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(sender.ul_count, 0);
        wire[1..5].copy_from_slice(&[1, 2, 3, 4]);
        receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(receiver.ul_count, 0);
        receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(receiver.ul_count, 256);
    }

    #[test]
    fn valid_mac_over_invalid_inner_message_advances_count() {
        let key = [0x11; 16];
        let inner = [0xc7, 0, 0, 0];
        let mut mac_input = vec![0];
        mac_input.extend_from_slice(&inner);
        let mac = eps::nas_mac(&key, 0, Direction::Uplink.as_u8(), &mac_input, 2);
        let mut wire = vec![0x17];
        wire.extend_from_slice(&mac.to_be_bytes());
        wire.extend_from_slice(&mac_input);

        let mut raw_receiver = NasSecurityContext::from_fresh_keys(
            key,
            [0x22; 16],
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        );
        assert!(
            raw_receiver
                .unprotect_raw(&wire, Direction::Uplink)
                .is_err()
        );
        assert_eq!(raw_receiver.ul_count, 1);

        let mut receiver = raw_receiver.clone();
        assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
        assert_eq!(receiver.ul_count, 1);
    }

    #[test]
    fn service_request_without_security_context_ksi_is_rejected() {
        let mut receiver = context();
        let request = NasServiceRequest::new(0xe0, 0);
        assert!(receiver.unprotect_service_request(&request).is_err());
        assert_eq!(receiver.ul_count, 0);
        assert!(!NasEpsMessage::ServiceRequest(request).validate().is_empty());
    }

    #[test]
    fn service_request_uses_actual_received_first_octet() {
        let mut sender = context();
        let mut receiver = context();
        let mut request = sender.protect_service_request(1).unwrap();
        request.security_header_type = 13;
        request.message_authentication_code = eps::service_request_short_mac_with_header(
            &[0x11; 16],
            0,
            0,
            0xd7,
            request.ksi_and_sequence_number,
            2,
        );
        receiver.unprotect_service_request(&request).unwrap();
        request.security_header_type = 0;
        assert!(receiver.unprotect_service_request(&request).is_err());
    }
}
