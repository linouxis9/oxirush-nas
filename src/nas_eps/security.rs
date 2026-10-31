/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

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
//! oxirush-nas = { version = "0.5", features = ["security"] }
//! ```
//!
//! A context starts, is restored and changes its algorithms as the
//! [5GS context](crate::nas_5gs::security) does, from a KASME where that one
//! has a KAMF.
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::nas_eps::{
//!     CipheringAlgorithm, Direction, IntegrityAlgorithm, KAsme, NasCount, NasEpsMessage,
//!     NasEpsSecurityHeaderType, NasSecurityContext,
//! };
//!
//! // ATTACH REJECT, cause #3
//! let msg = NasEpsMessage::decode(&[0x07, 0x44, 0x03]).unwrap();
//!
//! // The two ends of one link: the same KASME and the same algorithms
//! let kasme = KAsme::new(&[0x11; 32]);
//! let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
//! let mut tx = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
//! let mut rx = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
//!
//! // Protect outbound: integrity and ciphering
//! let sht = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
//! let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();
//!
//! // Unprotect inbound: MAC check, deciphering and decoding
//! let verified = rx.unprotect(&protected, Direction::Downlink).unwrap();
//! assert_eq!(verified.message, msg);
//! assert_eq!(verified.security_header_type, sht);
//! assert_eq!(verified.count, NasCount::ZERO);
//! ```
//!
//! `protect` and `protect_bytes` validate the inner message. For negative tests,
//! `protect_opaque_payload` ciphers and integrity-protects any inner octets
//! under security header types 1 to 4.

use crate::common::{Core, Direction, Keys, NasError, NextCount, Result, System, wiped};
use crate::nas_eps::message_types::{EPS_EMM_PROTOCOL_DISCRIMINATOR, NasEpsSecurityHeaderType};
use crate::prelude::*;
use core::convert::TryFrom;
use core::fmt;

use crate::nas_eps::ie::{CipheringAlgorithm, IntegrityAlgorithm};
use crate::nas_eps::messages::{
    EPS_SECURITY_HEADER_LEN, NasEmmMessage, NasEmmTransport, NasEpsMessage, NasEsmMessage,
    NasServiceRequest, received_emm_data_container_is_valid, valid_emm_data_container,
};
use oxirush_security::NasCount;
use oxirush_security::nas_5gs::{KAmf, derive_mapped_kasme_handover, derive_mapped_kasme_idle};
use oxirush_security::nas_eps as eps;
use oxirush_security::nas_eps::{KAsme, KNasEnc, KNasInt};

/// The integrity algorithm of the security crate that a code of TS 24.301
/// §9.9.3.23 selects: the codes 4 to 7 are reserved, and no algorithm.
impl TryFrom<IntegrityAlgorithm> for oxirush_security::IntegrityAlgorithm {
    type Error = NasError;

    fn try_from(algorithm: IntegrityAlgorithm) -> Result<Self> {
        Self::try_from(algorithm as u8).map_err(|_| {
            NasError::SecurityRefused(format!(
                "{algorithm:?} is a reserved EPS integrity algorithm: no key and no code are computed with it"
            ))
        })
    }
}

/// The ciphering algorithm of the security crate that a code of TS 24.301
/// §9.9.3.23 selects: the codes 4 to 7 are reserved, and no algorithm.
impl TryFrom<CipheringAlgorithm> for oxirush_security::CipheringAlgorithm {
    type Error = NasError;

    fn try_from(algorithm: CipheringAlgorithm) -> Result<Self> {
        Self::try_from(algorithm as u8).map_err(|_| {
            NasError::SecurityRefused(format!(
                "{algorithm:?} is a reserved EPS ciphering algorithm: no key is derived and nothing is ciphered with it"
            ))
        })
    }
}

/// A message that a security context verified, and what it was verified
/// with.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct Verified<M> {
    /// The message under the security header: decoded, or its plain octets
    /// from `unprotect_raw`.
    pub message: M,
    /// The security header type that the message came under.
    pub security_header_type: NasEpsSecurityHeaderType,
    /// The NAS COUNT that the message authentication code was verified
    /// with: the uplink NAS COUNT of the message that K_eNB is derived with
    /// (TS 33.401 Annex A.3), for a message that starts the access stratum
    /// security.
    pub count: NasCount,
}

/// What `error` of the plain message `plain` is once the code of the
/// message was verified.
fn refused(error: NasError, plain: &[u8]) -> NasError {
    NasError::AuthenticMessageRefused {
        error: Box::new(error),
        plain: plain.into(),
    }
}

/// Cipher the value of the sole container in a CONTROL PLANE SERVICE REQUEST.
fn cipher_control_plane_container(
    payload: &mut Vec<u8>,
    key: &KNasEnc,
    count: NasCount,
    direction: Direction,
    algorithm: oxirush_security::CipheringAlgorithm,
) -> Result<()> {
    let mut message = NasEpsMessage::decode(payload)?;
    let NasEpsMessage::Emm(_, NasEmmMessage::ControlPlaneServiceRequest(request)) = &mut message
    else {
        return Err(NasError::DecodingError(
            "partial EPS ciphering requires CONTROL PLANE SERVICE REQUEST".into(),
        ));
    };
    match (
        &mut request.esm_message_container,
        &mut request.nas_message_container,
    ) {
        (Some(container), None) => eps::nas_cipher(
            key,
            count,
            direction.into(),
            &mut container.value,
            algorithm,
        ),
        (None, Some(container)) => eps::nas_cipher(
            key,
            count,
            direction.into(),
            &mut container.value,
            algorithm,
        ),
        _ => {
            return Err(NasError::DecodingError(
                "partial EPS ciphering requires exactly one message container".into(),
            ));
        }
    }
    *payload = message.encode()?;
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
            | NasEmmMessage::DetachRequestUeOriginating(_)
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
            | NasEmmMessage::DetachRequestUeTerminated(_)
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
                if sht != NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
                    || direction != Direction::Downlink =>
            {
                return Err(NasError::EncodingError(
                    "SECURITY MODE COMMAND requires downlink integrity protection with new context"
                        .into(),
                ));
            }
            NasEmmMessage::SecurityModeComplete(_)
                if sht != NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
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
                NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
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
        NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext => matches!(
            message,
            NasEpsMessage::Emm(_, NasEmmMessage::SecurityModeCommand(_))
        ),
        NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext => {
            matches!(
                message,
                NasEpsMessage::Emm(_, NasEmmMessage::SecurityModeComplete(_))
            )
        }
        NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage => matches!(
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
///
/// The keys are wiped when the context is dropped, by their own types, and
/// `Debug` shows the algorithms and the COUNTs without them.
#[cfg_attr(test, derive(Clone))]
pub struct NasSecurityContext {
    /// The keys, the algorithms and the COUNTs.
    core: Core<Eps>,
}

/// The system of the EPS contexts: KNASint and KNASenc of TS 33.401, the
/// codes of TS 24.301 §9.9.3.23, and one NAS connection, whose bearer is
/// zero (TS 33.401 §8.1.1 and §8.2).
pub(crate) enum Eps {}

impl System for Eps {
    type IntegrityKey = KNasInt;
    type CipheringKey = KNasEnc;
    type Integrity = IntegrityAlgorithm;
    type Ciphering = CipheringAlgorithm;
    type Connection = ();
    type Counts = [[NextCount; 2]; 1];
    const NAME: &'static str = "EPS";
    const NULL_INTEGRITY: IntegrityAlgorithm = IntegrityAlgorithm::EIA0;
    const NULL_CIPHERING: CipheringAlgorithm = CipheringAlgorithm::EEA0;

    fn place((): ()) -> usize {
        0
    }

    fn algorithms(
        integrity: IntegrityAlgorithm,
        ciphering: CipheringAlgorithm,
    ) -> Result<(
        oxirush_security::IntegrityAlgorithm,
        oxirush_security::CipheringAlgorithm,
    )> {
        Ok((integrity.try_into()?, ciphering.try_into()?))
    }

    fn bearer((): ()) -> oxirush_security::Bearer {
        oxirush_security::Bearer::ZERO
    }
}

/// Whether `inner` is a message that a context protects under `sht` in
/// `direction`: a plain EMM or ESM message, under a header type that
/// protects it.
fn check_protected(
    inner: &NasEpsMessage,
    sht: NasEpsSecurityHeaderType,
    direction: Direction,
) -> Result<()> {
    if !matches!(inner, NasEpsMessage::Emm(..) | NasEpsMessage::Esm(..)) {
        return Err(NasError::EncodingError(
            "EPS security requires a plain EMM or ESM message".into(),
        ));
    }
    if !matches!(
        sht,
        NasEpsSecurityHeaderType::IntegrityProtected
            | NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
            | NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
            | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
            | NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
    ) {
        return Err(NasError::SecurityRefused(format!(
            "{sht:?} is no header type that protects a message"
        )));
    }
    validate_sht_message(sht, inner, direction)
}

impl fmt::Debug for NasSecurityContext {
    /// The algorithms and the next NAS COUNTs, without the keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NasSecurityContext")
            .field("integrity_algorithm", &self.core.integrity_code)
            .field("ciphering_algorithm", &self.core.ciphering_code)
            .field("uplink_count", &self.nas_count(Direction::Uplink))
            .field("downlink_count", &self.nas_count(Direction::Downlink))
            .finish_non_exhaustive()
    }
}

impl NasSecurityContext {
    /// Create a context for genuinely fresh NAS keys with COUNT values at zero.
    ///
    /// Reusing the same keys with this constructor violates TS 33.401 §6.5;
    /// use [`Self::reselect_algorithms`] for an existing KASME. A reserved
    /// algorithm (the codes 4 to 7) and EIA0 with another cipher than EEA0
    /// are errors.
    pub fn from_fresh_keys(
        knas_int: &KNasInt,
        knas_enc: &KNasEnc,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        let keys = |_, _| Keys {
            integrity: knas_int.clone(),
            ciphering: knas_enc.clone(),
        };
        let core = Core::derived(integrity_algo, ciphering_algo, keys)?;
        Ok(Self { core })
    }

    /// Derive a fresh EPS NAS context from a newly established KASME.
    ///
    /// COUNT starts at zero. Calling this again for the same KASME would violate
    /// TS 33.401 §6.5; use [`Self::reselect_algorithms`] instead. The
    /// algorithms are checked as [`Self::from_fresh_keys`] checks them.
    pub fn from_fresh_kasme(
        kasme: &KAsme,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        let core = Core::derived(integrity_algo, ciphering_algo, |integrity, ciphering| {
            Keys {
                integrity: eps::derive_knas_int(kasme, integrity),
                ciphering: eps::derive_knas_enc(kasme, ciphering),
            }
        })?;
        Ok(Self { core })
    }

    /// Selected integrity algorithm.
    pub fn integrity_algorithm(&self) -> IntegrityAlgorithm {
        self.core.integrity_code
    }

    /// Selected ciphering algorithm.
    pub fn ciphering_algorithm(&self) -> CipheringAlgorithm {
        self.core.ciphering_code
    }

    /// Next NAS COUNT to use or expect for a direction: `None` when every
    /// COUNT of the direction was used, after which the context protects
    /// nothing more in it.
    pub fn nas_count(&self, direction: Direction) -> Option<NasCount> {
        self.core.count(direction, ()).get()
    }

    /// Restore an EPS context and its next COUNT values from persistent state.
    ///
    /// The caller must supply the counts stored for this exact KASME, as
    /// [`Self::nas_count`] gave them: the uplink then the downlink COUNT,
    /// `None` for one that is exhausted. Passing zero for a KASME that has
    /// already protected traffic violates TS 33.401 §6.5.
    pub fn restore_from_kasme(
        kasme: &KAsme,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
        counts: (Option<NasCount>, Option<NasCount>),
    ) -> Result<Self> {
        let mut context = Self::from_fresh_kasme(kasme, integrity_algo, ciphering_algo)?;
        context.set_counts(counts.0, counts.1);
        Ok(context)
    }

    /// Give the context the next COUNTs `uplink` and `downlink`.
    fn set_counts(&mut self, uplink: Option<NasCount>, downlink: Option<NasCount>) {
        *self.core.count_mut(Direction::Uplink, ()) = NextCount::of(uplink);
        *self.core.count_mut(Direction::Downlink, ()) = NextCount::of(downlink);
    }

    /// Re-derive NAS keys for a new algorithm selection under the same KASME.
    ///
    /// Both COUNTs are preserved, as required by TS 33.401 §§6.5, 7.2.5.2.2,
    /// 7.2.7, and 7.2.8.1.2.
    pub fn reselect_algorithms(
        &mut self,
        kasme: &KAsme,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<()> {
        // A key that is replaced is wiped as it is dropped.
        let derive = |integrity, ciphering| Keys {
            integrity: eps::derive_knas_int(kasme, integrity),
            ciphering: eps::derive_knas_enc(kasme, ciphering),
        };
        self.core.reselect(integrity_algo, ciphering_algo, derive)
    }

    /// Map a 5GS KAMF to an EPS context for idle mobility.
    ///
    /// `ul_nas_count_used` is the 5GS COUNT used to protect the
    /// mobility-triggering message. The next uplink COUNT is one greater;
    /// the current downlink COUNT carries into the mapped EPS context.
    /// The mapped eKSI is negotiated by the enclosing mobility procedure.
    pub fn from_mapped_kasme_idle(
        kamf: &KAmf,
        ul_nas_count_used: NasCount,
        dl_nas_count: NasCount,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        // The mapped context goes on from the COUNT after the one that was
        // used, and there is none after the last.
        let ul_count = ul_nas_count_used
            .next()
            .map_err(|_| NasError::NasCountExhausted)?;
        let mut context = wiped(|| {
            let kasme = derive_mapped_kasme_idle(kamf, ul_nas_count_used);
            Self::from_fresh_kasme(&kasme, integrity_algo, ciphering_algo)
        })?;
        context.set_counts(Some(ul_count), Some(dl_nas_count));
        Ok(context)
    }

    /// Map a 5GS KAMF to an EPS context for connected handover.
    /// `dl_nas_count_used` derives the key; the next downlink COUNT is one greater.
    pub fn from_mapped_kasme_handover(
        kamf: &KAmf,
        ul_nas_count: NasCount,
        dl_nas_count_used: NasCount,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        let dl_count = dl_nas_count_used
            .next()
            .map_err(|_| NasError::NasCountExhausted)?;
        let mut context = wiped(|| {
            let kasme = derive_mapped_kasme_handover(kamf, dl_nas_count_used);
            Self::from_fresh_kasme(&kasme, integrity_algo, ciphering_algo)
        })?;
        context.set_counts(Some(ul_nas_count), Some(dl_count));
        Ok(context)
    }

    /// Protect a short SERVICE REQUEST with the five-bit NAS SQN and 16-bit MAC.
    pub fn protect_service_request(&mut self, ksi: u8) -> Result<NasServiceRequest> {
        if ksi >= 7 {
            return Err(NasError::EncodingError(
                "EPS NAS SERVICE REQUEST requires a current security context KSI".into(),
            ));
        }
        let count = self.core.count(Direction::Uplink, ()).to_send()?;
        let ksi_and_sequence_number = (ksi << 5) | (count.sequence_number() & 0x1f);
        let mac = eps::service_request_short_mac(
            &self.core.keys.integrity,
            count,
            Direction::Uplink.into(),
            ksi_and_sequence_number,
            self.core.integrity,
        );
        self.core.advance(Direction::Uplink, (), count);
        Ok(NasServiceRequest::new(ksi_and_sequence_number, mac))
    }

    /// Verify a short SERVICE REQUEST and advance the uplink COUNT. Returns
    /// the NAS COUNT that the request was verified with: K_eNB is derived
    /// with it (TS 33.401 Annex A.3).
    pub fn unprotect_service_request(&mut self, request: &NasServiceRequest) -> Result<NasCount> {
        if !(12..=15).contains(&request.security_header_type) {
            return Err(NasError::DecodingError(
                "invalid EPS SERVICE REQUEST security header type".into(),
            ));
        }
        if request.ksi_and_sequence_number >> 5 == 7 {
            return Err(NasError::DecodingError(
                "EPS NAS SERVICE REQUEST has no current security context KSI".into(),
            ));
        }
        let sequence_number = request.ksi_and_sequence_number & 0x1f;
        let lowest = self.core.count(Direction::Uplink, ());
        let count = lowest.received(sequence_number, 5, self.core.wraps())?;
        let mac = eps::service_request_short_mac_with_header(
            &self.core.keys.integrity,
            count,
            Direction::Uplink.into(),
            (request.security_header_type << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR,
            request.ksi_and_sequence_number,
            self.core.integrity,
        )
        .map_err(|error| NasError::DecodingError(error.to_string()))?;
        let received = request.message_authentication_code.to_be_bytes();
        self.core.check(&received, &mac.to_be_bytes())?;
        self.core.advance(Direction::Uplink, (), count);
        Ok(count)
    }

    /// Compute the re-establishment NAS MAC for a 28-bit target E-UTRAN Cell
    /// Identifier and atomically consume the next uplink NAS COUNT.
    ///
    /// TS 33.401 §7.4.4 requires the UE to increment UL COUNT as though it
    /// had sent a NAS message. Keeping the calculation and advancement in one
    /// context operation prevents accidental COUNT reuse.
    pub fn protect_re_establishment(&mut self, target_cell_id: u32) -> Result<(u16, u16)> {
        let count = self.core.count(Direction::Uplink, ()).to_send()?;
        let mac = eps::re_establishment_nas_mac(
            &self.core.keys.integrity,
            count,
            target_cell_id,
            self.core.integrity,
        )
        .map_err(|_| NasError::EncodingError("E-UTRAN Cell Identifier must be 28 bits".into()))?;
        self.core.advance(Direction::Uplink, (), count);
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
        if count_lsb > 0x1f {
            return Err(NasError::DecodingError(
                "re-establishment NAS COUNT field must be five bits".into(),
            ));
        }
        let lowest = self.core.count(Direction::Uplink, ());
        let count = lowest.received(count_lsb, 5, self.core.wraps())?;
        let (expected_ul_nas_mac, dl_nas_mac) = eps::re_establishment_nas_mac(
            &self.core.keys.integrity,
            count,
            target_cell_id,
            self.core.integrity,
        )
        .map_err(|_| NasError::DecodingError("E-UTRAN Cell Identifier must be 28 bits".into()))?;
        let (received, expected) = (ul_nas_mac.to_be_bytes(), expected_ul_nas_mac.to_be_bytes());
        self.core.check(&received, &expected)?;
        self.core.advance(Direction::Uplink, (), count);
        Ok(dl_nas_mac)
    }

    /// Protect a plain EMM or ESM message.
    pub fn protect(
        &mut self,
        inner: &NasEpsMessage,
        sht: NasEpsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        check_protected(inner, sht, direction)?;
        let inner_bytes = inner.encode()?;
        self.protect_envelope(inner_bytes, sht, direction)
    }

    /// Protect an already encoded plain EMM or ESM message.
    pub fn protect_bytes(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: NasEpsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        // Both DETACH REQUEST forms share one message type; the direction
        // selects the form to check.
        let inner = NasEpsMessage::decode_with_direction(&inner_bytes, direction)?;
        check_protected(&inner, sht, direction)?;
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
        if !matches!(
            sht,
            NasEpsSecurityHeaderType::IntegrityProtected
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
        ) {
            return Err(NasError::SecurityRefused(
                "opaque EPS protection takes a header type that protects".into(),
            ));
        }
        self.protect_envelope(inner_bytes, sht, direction)
    }

    /// The message under its security header `[SHT | PD | MAC | SN]`,
    /// ciphered for the header types that cipher, and with the container of
    /// a CONTROL PLANE SERVICE REQUEST ciphered alone for "partially
    /// ciphered" (TS 24.301 §4.4.5).
    fn protect_envelope(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: NasEpsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        let header = [((sht as u8) << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR];
        let cipher = |core: &Core<Eps>, count, payload: &mut Vec<u8>| match sht {
            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
            | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext => {
                core.cipher(count, (), direction, payload);
                Ok(())
            }
            NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage => {
                let (key, algorithm) = (&core.keys.ciphering, core.ciphering);
                cipher_control_plane_container(payload, key, count, direction, algorithm)
            }
            _ => Ok(()),
        };
        self.core.seal(&header, inner_bytes, direction, (), cipher)
    }

    /// Protect the data container of an EMM TRANSPORT (TS 24.301 §4.4.5).
    /// The complete data container starts at octet 7 and is ciphered as a unit.
    pub fn protect_emm_transport(
        &mut self,
        data_container: Option<&[u8]>,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        if data_container
            .is_some_and(|data| !valid_emm_data_container(data, direction == Direction::Downlink))
        {
            return Err(NasError::EncodingError(
                "invalid EMM TRANSPORT data container".into(),
            ));
        }
        // The complete data container is ciphered as one unit
        let payload = data_container.map_or_else(Vec::new, <[u8]>::to_vec);
        let cipher = |core: &Core<Eps>, count, payload: &mut Vec<u8>| {
            core.cipher(count, (), direction, payload);
            Ok(())
        };
        // The security header type 1011 of an EMM TRANSPORT
        self.core.seal(&[0xb7], payload, direction, (), cipher)
    }

    /// Verify, decipher, and decode an inbound EPS NAS message.
    ///
    /// The COUNT of the direction advances as soon as the MAC is verified:
    /// a message that is then refused for what it is, is
    /// [`NasError::AuthenticMessageRefused`], with its COUNT used and its
    /// plain octets, deciphered, which [`NasEpsMessage::answer_to_refused`]
    /// answers. A MAC mismatch returns [`NasError::IntegrityCheckFailed`] and leaves
    /// the COUNTs unchanged. A receiver that must still process the message
    /// (TS 24.301 §4.4.4.3) can decode the PDU with
    /// [`NasEpsMessage::decode`],
    /// which returns the unverified inner message when it is not ciphered.
    ///
    /// With EIA0 no MAC is checked and no message is refused as a replay
    /// (§4.4.3.2, TS 33.401 annex B.0): a message received again is taken
    /// with a COUNT higher than the stored one (§4.4.3.1). A SECURITY MODE
    /// COMMAND is verified by the context that it takes into use, which the
    /// caller makes (§5.4.3.3): the context in use, with its COUNTs, one of
    /// [`Self::restore_from_kasme`] for new algorithms under its KASME, or
    /// one of [`Self::from_fresh_kasme`] after an authentication.
    pub fn unprotect(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<Verified<NasEpsMessage>> {
        let (plain, message, security_header_type, count) =
            self.unprotect_checked(data, direction)?;
        let message = match (security_header_type, message) {
            (NasEpsSecurityHeaderType::SecurityHeaderForTheEmmTransportMessage, _) => {
                let mac = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                NasEpsMessage::EmmTransport(if plain.is_empty() {
                    NasEmmTransport::new(mac, data[5])
                } else {
                    NasEmmTransport::new(mac, data[5]).set_data_container(plain)
                })
            }
            (_, Some(message @ (NasEpsMessage::Emm(..) | NasEpsMessage::Esm(..)))) => message,
            _ => {
                return Err(refused(
                    NasError::DecodingError(
                        "EPS security envelope has no plain EMM or ESM message".into(),
                    ),
                    &plain,
                ));
            }
        };
        Ok(Verified {
            message,
            security_header_type,
            count,
        })
    }

    /// Verify and decipher an inbound PDU, returning its plain bytes.
    pub fn unprotect_raw(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<Verified<Vec<u8>>> {
        let (message, _, security_header_type, count) = self.unprotect_checked(data, direction)?;
        Ok(Verified {
            message,
            security_header_type,
            count,
        })
    }

    /// The plain octets of a protected PDU and the message they are, which
    /// is decoded once to check it: the data container of an EMM TRANSPORT
    /// is no message.
    fn unprotect_checked(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<(
        Vec<u8>,
        Option<NasEpsMessage>,
        NasEpsSecurityHeaderType,
        NasCount,
    )> {
        if data.len() < EPS_SECURITY_HEADER_LEN {
            return Err(NasError::BufferTooShort);
        }
        if data[0] & 0x0F != EPS_EMM_PROTOCOL_DISCRIMINATOR {
            return Err(NasError::DecodingError(
                "invalid EPS security protocol discriminator".into(),
            ));
        }
        let sht = NasEpsSecurityHeaderType::try_from(data[0] >> 4)?;
        if !matches!(
            sht,
            NasEpsSecurityHeaderType::IntegrityProtected
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
                | NasEpsSecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        ) {
            return Err(NasError::DecodingError(
                "unsupported EPS security header type for unprotection".into(),
            ));
        }
        let payload = &data[EPS_SECURITY_HEADER_LEN..];
        // TS 24.301 §4.4.3.3 commits the received NAS COUNT after successful
        // integrity verification. Inner syntax and header-pairing checks must
        // not make an authenticated COUNT reusable.
        let nas_count = self.core.open(data, 1, direction, ())?;

        let mut plain = payload.to_vec();
        if matches!(
            sht,
            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
                | NasEpsSecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        ) {
            self.core.cipher(nas_count, (), direction, &mut plain);
        } else if sht == NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
        {
            let (key, algorithm) = (&self.core.keys.ciphering, self.core.ciphering);
            cipher_control_plane_container(&mut plain, key, nas_count, direction, algorithm)
                .map_err(|error| refused(error, &plain))?;
        }
        if sht == NasEpsSecurityHeaderType::SecurityHeaderForTheEmmTransportMessage {
            if !plain.is_empty()
                && !received_emm_data_container_is_valid(&plain, direction == Direction::Downlink)
            {
                return Err(refused(
                    NasError::DecodingError("invalid EMM TRANSPORT data container".into()),
                    &plain,
                ));
            }
            return Ok((plain, None, sht, nas_count));
        }
        let inner = NasEpsMessage::decode_with_direction(&plain, direction)
            .map_err(|error| refused(error, &plain))?;
        validate_sht_message(sht, &inner, direction).map_err(|_| {
            let error = "EPS security header type does not match message type";
            refused(NasError::DecodingError(error.into()), &plain)
        })?;
        Ok((plain, Some(inner), sht, nas_count))
    }
}

#[cfg(test)]
impl NasSecurityContext {
    /// The next COUNT of a direction, as the context keeps it.
    fn count_ref(&self, direction: Direction) -> NextCount {
        self.core.count(direction, ())
    }

    /// The next COUNT of a direction, to set it.
    fn count_mut(&mut self, direction: Direction) -> &mut NextCount {
        self.core.count_mut(direction, ())
    }
}

#[cfg(all(test, feature = "security"))]
mod tests {
    use super::*;
    use oxirush_security::CipheringAlgorithm as Eea;
    use oxirush_security::IntegrityAlgorithm as Eia;

    /// A NAS COUNT of a message.
    fn count(count: u32) -> NasCount {
        NasCount::new(count).unwrap()
    }
    use crate::common::Validate;
    use crate::nas_eps::messages::{
        NasControlPlaneServiceRequest, NasEmmMessage, NasEmmStatus, NasPdnConnectivityRequest,
        NasSecurityModeCommand, NasSecurityModeComplete,
    };
    use crate::nas_eps::types::{
        NasControlPlaneServiceType, NasEmmCause, NasEsmMessageContainer, NasKeySetIdentifier,
        NasMessageContainer, NasPdnType, NasRequestType, NasSecurityAlgorithms,
        NasUeSecurityCapability,
    };

    #[test]
    fn security_mode_requires_its_header_and_direction() {
        let command = NasEpsMessage::new_emm(NasSecurityModeCommand::new(
            NasSecurityAlgorithms::new(0),
            NasKeySetIdentifier::new(0),
            NasUeSecurityCapability::new(vec![0; 2]),
        ));
        let complete = NasEpsMessage::new_emm(NasSecurityModeComplete::new());
        let cases = [
            (
                &command,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
            ),
            (
                &command,
                NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
                Direction::Uplink,
            ),
            (
                &complete,
                NasEpsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            ),
            (
                &complete,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
                Direction::Downlink,
            ),
        ];
        for (message, sht, direction) in cases {
            let mut context = context();
            assert!(context.protect(message, sht, direction).is_err());
            assert_eq!(
                (
                    context.count_ref(Direction::Uplink),
                    context.count_ref(Direction::Downlink)
                ),
                ((0).into(), (0).into())
            );
        }
        assert!(
            context()
                .protect(
                    &command,
                    NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
                    Direction::Downlink,
                )
                .is_ok()
        );
        assert!(
            context()
                .protect(
                    &complete,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
                    Direction::Uplink,
                )
                .is_ok()
        );
    }

    #[test]
    fn mapped_5gs_context_copies_counts_and_uses_mapped_key() {
        let kamf = KAmf::new(&core::array::from_fn(|i| i as u8));
        let kasme = derive_mapped_kasme_idle(&kamf, count(0x1234));
        let expected = NasSecurityContext::from_fresh_kasme(
            &kasme,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        )
        .unwrap();
        let context = NasSecurityContext::from_mapped_kasme_idle(
            &kamf,
            count(0x1234),
            count(0x5678),
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        )
        .unwrap();
        assert_eq!(context.core.keys.integrity, expected.core.keys.integrity);
        assert_eq!(context.core.keys.ciphering, expected.core.keys.ciphering);
        assert_eq!(
            (
                context.count_ref(Direction::Uplink),
                context.count_ref(Direction::Downlink)
            ),
            ((0x1235).into(), (0x5678).into())
        );
        let message = NasEpsMessage::new_emm(NasEmmStatus::new(NasEmmCause::new(3)));
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
            count(0x1234),
            count(0x5678),
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        )
        .unwrap();
        assert_ne!(handover.core.keys.integrity, context.core.keys.integrity);
        assert_eq!(
            (
                handover.count_ref(Direction::Uplink),
                handover.count_ref(Direction::Downlink)
            ),
            ((0x1234).into(), (0x5679).into())
        );
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
                NasCount::MAX,
                NasCount::ZERO,
                IntegrityAlgorithm::EIA2,
                CipheringAlgorithm::EEA2,
            )
            .is_err()
        );
        assert!(
            NasSecurityContext::from_mapped_kasme_handover(
                &kamf,
                NasCount::ZERO,
                NasCount::MAX,
                IntegrityAlgorithm::EIA2,
                CipheringAlgorithm::EEA2,
            )
            .is_err()
        );
    }

    fn context() -> NasSecurityContext {
        NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x11; 16]),
            &KNasEnc::new(&[0x22; 16]),
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        )
        .unwrap()
    }

    #[test]
    fn a_context_is_shown_without_its_keys_and_gives_the_count_it_verified_with() {
        let mut sender = context();
        *sender.count_mut(Direction::Uplink) = (0x0000_02fe).into();
        let mut receiver = sender.clone();
        let shown = format!("{receiver:?}");
        assert_eq!(
            shown,
            "NasSecurityContext { integrity_algorithm: EIA2, ciphering_algorithm: EEA2, \
             uplink_count: Some(NasCount(766)), downlink_count: Some(NasCount(0)), .. }"
        );
        // Neither a key nor one of its octets
        assert!(!shown.contains("11") && !shown.contains("22") && !shown.contains("17"));
        // What a UE costs: the place of the keys, the algorithms and two
        // COUNTs, and the two keys in the heap
        #[cfg(target_pointer_width = "64")]
        assert_eq!(core::mem::size_of::<NasSecurityContext>(), 24);
        assert_eq!(core::mem::size_of::<Keys<KNasInt, KNasEnc>>(), 32);

        // The COUNT of each message that is verified, across a wrap of the
        // sequence number
        let message = NasEpsMessage::new_emm(NasEmmStatus::new(NasEmmCause::new(3)));
        let sht = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
        for expected in [0x02fe, 0x02ff, 0x0300] {
            let wire = sender.protect(&message, sht, Direction::Uplink).unwrap();
            let verified = receiver.unprotect(&wire, Direction::Uplink).unwrap();
            assert_eq!(verified.count, count(expected));
            assert_eq!(verified.security_header_type, sht);
            assert_eq!(verified.message, message);
        }
        // A short SERVICE REQUEST carries five bits of it
        let request = sender.protect_service_request(1).unwrap();
        assert_eq!(
            receiver.unprotect_service_request(&request),
            Ok(count(0x0301))
        );
    }

    #[test]
    fn opaque_payload_preserves_malformed_bytes_and_authenticates_all_regular_headers() {
        let inner = vec![0x07, 0xff, 0x20, 0x02, 0xbb, 0xaa, 0x20, 0x01, 0xcc];
        for direction in [Direction::Uplink, Direction::Downlink] {
            for sht in [
                NasEpsSecurityHeaderType::IntegrityProtected,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
                NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
            ] {
                let mut sender = context();
                match direction {
                    Direction::Uplink => *sender.count_mut(Direction::Uplink) = (0x1234).into(),
                    Direction::Downlink => *sender.count_mut(Direction::Downlink) = (0x1234).into(),
                }
                assert!(sender.protect_bytes(inner.clone(), sht, direction).is_err());
                assert_eq!(sender.count_ref(direction), 0x1234);
                let mut receiver = sender.clone();
                let mut tampered_receiver = receiver.clone();
                let wire = sender
                    .protect_opaque_payload(inner.clone(), sht, direction)
                    .unwrap();
                let mut payload = inner.clone();
                if matches!(sht as u8, 2 | 4) {
                    eps::nas_cipher(
                        &KNasEnc::new(&[0x22; 16]),
                        count(0x1234),
                        direction.into(),
                        &mut payload,
                        Eea::EEA2,
                    );
                }
                assert_eq!(wire[0], ((sht as u8) << 4) | 7);
                assert_eq!(wire[5], 0x34);
                assert_eq!(&wire[6..], payload);
                let mac = eps::nas_mac(
                    &KNasInt::new(&[0x11; 16]),
                    count(0x1234),
                    direction.into(),
                    &wire[5..],
                    Eia::EIA2,
                );
                assert_eq!(&wire[1..5], mac.to_be_bytes());
                if matches!(sht as u8, 2 | 4) {
                    eps::nas_cipher(
                        &KNasEnc::new(&[0x22; 16]),
                        count(0x1234),
                        direction.into(),
                        &mut payload,
                        Eea::EEA2,
                    );
                }
                assert_eq!(payload, inner);
                assert_eq!(sender.count_ref(direction), 0x1235);
                assert_eq!(
                    sender.count_ref(if direction == Direction::Uplink {
                        Direction::Downlink
                    } else {
                        Direction::Uplink
                    }),
                    0
                );
                assert_eq!(sender.core.keys.integrity, [0x11; 16]);
                assert_eq!(sender.core.keys.ciphering, [0x22; 16]);
                let mut tampered = wire.clone();
                tampered[1] ^= 1;
                assert!(matches!(
                    tampered_receiver.unprotect_raw(&tampered, direction),
                    Err(NasError::IntegrityCheckFailed)
                ));
                assert_eq!(tampered_receiver.count_ref(direction), 0x1234);
                // The code is right and the message is refused for what it
                // is, with its COUNT used.
                assert_eq!(
                    receiver.unprotect_raw(&wire, direction),
                    Err(NasError::AuthenticMessageRefused {
                        error: Box::new(NasError::UnknownMessageType(0xff)),
                        plain: inner.clone().into(),
                    })
                );
                assert_eq!(receiver.count_ref(direction), 0x1235);
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
            let raw = receiver.unprotect_raw(&opaque, Direction::Uplink).unwrap();
            assert_eq!(
                (raw.message, raw.security_header_type),
                (inner.clone(), sht)
            );
        }
        assert!(
            sender
                .protect_bytes(
                    inner,
                    NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
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
        assert_eq!(
            (
                sender.count_ref(Direction::Uplink),
                sender.count_ref(Direction::Downlink)
            ),
            ((2).into(), (0).into())
        );
    }

    #[test]
    fn opaque_payload_rejects_envelope_errors_without_consuming_count() {
        let mut sender = context();
        let sht = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
        for unsupported in [
            NasEpsSecurityHeaderType::PlainNasMessageNotSecurityProtected,
            NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
            NasEpsSecurityHeaderType::SecurityHeaderForTheEmmTransportMessage,
            NasEpsSecurityHeaderType::SecurityHeaderForTheServiceRequestMessage,
        ] {
            assert!(
                sender
                    .protect_opaque_payload(vec![0xff], unsupported, Direction::Uplink)
                    .is_err()
            );
            assert_eq!(sender.count_ref(Direction::Uplink), 0);
        }
        // A reserved algorithm, and EIA0 with a cipher, make no context.
        for (integrity, ciphering) in [
            (IntegrityAlgorithm::EIA7, CipheringAlgorithm::EEA2),
            (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA7),
            (IntegrityAlgorithm::EIA0, CipheringAlgorithm::EEA2),
        ] {
            let context = NasSecurityContext::from_fresh_keys(
                &KNasInt::new(&[0x11; 16]),
                &KNasEnc::new(&[0x22; 16]),
                integrity,
                ciphering,
            );
            assert!(context.is_err(), "{integrity:?} {ciphering:?}");
            let kasme = KAsme::new(&[0x42; 32]);
            assert!(NasSecurityContext::from_fresh_kasme(&kasme, integrity, ciphering).is_err());
        }
        for direction in [Direction::Uplink, Direction::Downlink] {
            match direction {
                Direction::Uplink => *sender.count_mut(Direction::Uplink) = (0x00ff_ffff).into(),
                Direction::Downlink => {
                    *sender.count_mut(Direction::Downlink) = (0x00ff_ffff).into()
                }
            }
            let wire = sender
                .protect_opaque_payload(Vec::new(), sht, direction)
                .unwrap();
            assert_eq!(wire.len(), 6);
            assert_eq!(wire[5], 0xff);
            let mac = eps::nas_mac(
                &KNasInt::new(&[0x11; 16]),
                NasCount::MAX,
                direction.into(),
                &wire[5..],
                Eia::EIA2,
            );
            assert_eq!(&wire[1..5], mac.to_be_bytes());
            assert_eq!(sender.count_ref(direction), 0x0100_0000);
            // After the last COUNT the context protects and verifies nothing
            // more in the direction, and says so by a variant.
            assert_eq!(
                sender.protect_opaque_payload(vec![0xff], sht, direction),
                Err(NasError::NasCountExhausted)
            );
            assert_eq!(
                sender.unprotect_raw(&wire, direction),
                Err(NasError::NasCountExhausted)
            );
            assert_eq!(sender.count_ref(direction), 0x0100_0000);
        }
    }

    #[test]
    fn eps_ciphered_message_uses_zero_bearer_and_rejects_tampering() {
        let message = NasEpsMessage::new_emm(NasEmmStatus::new(NasEmmCause::new(3)));
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
        let expected_mac = eps::nas_mac(
            &KNasInt::new(&[0x11; 16]),
            NasCount::ZERO,
            Direction::Uplink.into(),
            &wire[5..],
            Eia::EIA2,
        );
        assert_eq!(&wire[1..5], expected_mac.to_be_bytes());
        let mut tampered = wire.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(receiver.unprotect(&tampered, Direction::Uplink).is_err());
        assert_eq!(receiver.count_ref(Direction::Uplink), 0);
        let Verified {
            message: decoded,
            security_header_type: sht,
            ..
        } = receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(sht, NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered);
        assert_eq!(decoded, message);
        assert_eq!(receiver.count_ref(Direction::Uplink), 1);
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
        let message = NasEpsMessage::decode_with_direction(&plain, Direction::Downlink).unwrap();
        assert!(matches!(
            message,
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestUeTerminated(_))
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
        let Verified {
            message: decoded, ..
        } = context().unprotect(&wire, Direction::Downlink).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn independent_eps_count_boundary_vectors_and_replay() {
        let message = NasEpsMessage::new_emm(NasEmmStatus::new(NasEmmCause::new(3)));
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
            *sender.count_mut(Direction::Downlink) = (count).into();
            *receiver.count_mut(Direction::Downlink) = (count).into();
            let wire = sender
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                    Direction::Downlink,
                )
                .unwrap();
            assert_eq!(wire, expected, "COUNT {count:#08x}");
            assert_eq!(sender.count_ref(Direction::Downlink), count + 1);
            assert_eq!(
                receiver
                    .unprotect(&wire, Direction::Downlink)
                    .unwrap()
                    .message,
                message
            );
            assert_eq!(receiver.count_ref(Direction::Downlink), count + 1);
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
        let context = |eea| {
            NasSecurityContext::from_fresh_keys(
                &KNasInt::new(&[0; 16]),
                &KNasEnc::new(&[0; 16]),
                IntegrityAlgorithm::EIA0,
                eea,
            )
        };
        assert!(context(CipheringAlgorithm::EEA2).is_err());
        let kasme = KAsme::new(&[0x42; 32]);
        let mut null = context(CipheringAlgorithm::EEA0).unwrap();
        assert!(
            null.reselect_algorithms(&kasme, IntegrityAlgorithm::EIA0, CipheringAlgorithm::EEA1)
                .is_err()
        );
        // A context that refuses its new algorithms keeps those it had.
        assert_eq!(null.ciphering_algorithm(), CipheringAlgorithm::EEA0);
        assert_eq!(null.count_ref(Direction::Uplink), 0);
    }

    #[test]
    fn fresh_count_after_gap_is_accepted_and_replay_is_not() {
        // TS 24.301 §4.4.3.1: a lower sequence number means the overflow
        // counter advanced, independent of the current overflow value.
        let message = NasEpsMessage::new_emm(NasEmmStatus::new(NasEmmCause::new(3)));
        for (receiver_next, sender_count) in [(0x05, 0x90), (0x0105, 0x0190), (0x01f0, 0x0202)] {
            let mut sender = context();
            let mut receiver = context();
            *sender.count_mut(Direction::Uplink) = (sender_count).into();
            *receiver.count_mut(Direction::Uplink) = (receiver_next).into();
            let wire = sender
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                    Direction::Uplink,
                )
                .unwrap();
            assert_eq!(
                receiver
                    .unprotect(&wire, Direction::Uplink)
                    .unwrap()
                    .message,
                message
            );
            assert_eq!(receiver.count_ref(Direction::Uplink), sender_count + 1);
            assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
            assert_eq!(receiver.count_ref(Direction::Uplink), sender_count + 1);
        }

        // Five-bit SERVICE REQUEST sequence numbers after a gap of 17.
        let mut sender = context();
        let mut receiver = context();
        *sender.count_mut(Direction::Uplink) = (49).into();
        *receiver.count_mut(Direction::Uplink) = (32).into();
        let request = sender.protect_service_request(1).unwrap();
        receiver.unprotect_service_request(&request).unwrap();
        assert_eq!(receiver.count_ref(Direction::Uplink), 50);
        assert!(receiver.unprotect_service_request(&request).is_err());
    }

    #[test]
    fn eps_integrity_only_esm_message_round_trips() {
        let message = NasEpsMessage::new_esm(
            NasPdnConnectivityRequest::new(NasRequestType::new(1), NasPdnType::new(3)),
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
        assert_eq!(sender.count_ref(Direction::Downlink), 0);
        let wire = sender
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(wire[0], 0x17);
        let Verified {
            message: decoded, ..
        } = receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn eps_keys_derive_from_fresh_kasme() {
        let kasme = KAsme::new(&[0x42; 32]);
        let context = NasSecurityContext::from_fresh_kasme(
            &kasme,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA1,
        )
        .unwrap();
        // TS 33.401 Annex A.7: FC 0x15, the algorithm type distinguisher (1
        // for NAS ciphering, 2 for NAS integrity) and the algorithm identity;
        // the key is the 128 least significant bits.
        use oxirush_security::kdf::{build_s, kdf};
        let derived = |kind: u8, identity: u8| {
            let s = build_s(0x15, &[&[kind], &[identity]]).unwrap();
            *oxirush_security::kdf::extract_128(&kdf(kasme.as_octets(), &s))
        };
        assert_eq!(context.core.keys.integrity, derived(2, 2));
        assert_eq!(context.core.keys.ciphering, derived(1, 1));
    }

    #[test]
    fn persisted_eps_context_and_algorithm_reselection_preserve_counts() {
        let kasme = KAsme::new(&[0x42; 32]);
        let mut context = NasSecurityContext::restore_from_kasme(
            &kasme,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
            (Some(count(0x0012_3456)), Some(count(0x0000_abcd))),
        )
        .unwrap();
        let old_keys = (
            context.core.keys.integrity.clone(),
            context.core.keys.ciphering.clone(),
        );
        assert_eq!(
            context.nas_count(Direction::Uplink),
            Some(count(0x0012_3456))
        );
        assert_eq!(
            context.nas_count(Direction::Downlink),
            Some(count(0x0000_abcd))
        );

        context
            .reselect_algorithms(&kasme, IntegrityAlgorithm::EIA1, CipheringAlgorithm::EEA1)
            .unwrap();
        assert_eq!(context.integrity_algorithm(), IntegrityAlgorithm::EIA1);
        assert_eq!(context.ciphering_algorithm(), CipheringAlgorithm::EEA1);
        assert_eq!(
            context.nas_count(Direction::Uplink),
            Some(count(0x0012_3456))
        );
        assert_eq!(
            context.nas_count(Direction::Downlink),
            Some(count(0x0000_abcd))
        );
        assert_ne!(
            (&context.core.keys.integrity, &context.core.keys.ciphering),
            (&old_keys.0, &old_keys.1)
        );

        // A direction whose COUNTs are all used is restored as such.
        let exhausted = NasSecurityContext::restore_from_kasme(
            &kasme,
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
            (None, Some(NasCount::ZERO)),
        )
        .unwrap();
        assert_eq!(exhausted.nas_count(Direction::Uplink), None);
        assert_eq!(
            exhausted.nas_count(Direction::Downlink),
            Some(NasCount::ZERO)
        );
    }

    #[test]
    fn eps_service_request_short_mac_and_replay() {
        let mut sender = context();
        let mut receiver = context();
        *sender.count_mut(Direction::Uplink) = (31).into();
        *receiver.count_mut(Direction::Uplink) = (31).into();
        let request = sender.protect_service_request(3).unwrap();
        assert_eq!(request.ksi_and_sequence_number, 0x7f);
        assert_eq!(
            request.message_authentication_code,
            eps::service_request_short_mac(
                &KNasInt::new(&[0x11; 16]),
                count(31),
                Direction::Uplink.into(),
                0x7f,
                Eia::EIA2
            )
        );
        let wire = NasEpsMessage::ServiceRequest(request.clone())
            .encode()
            .unwrap();
        assert_eq!(wire.len(), 4);
        let decoded = NasEpsMessage::decode(&wire).unwrap();
        assert_eq!(decoded, NasEpsMessage::ServiceRequest(request.clone()));
        let mut tampered = request.clone();
        tampered.message_authentication_code ^= 1;
        assert!(receiver.unprotect_service_request(&tampered).is_err());
        assert_eq!(receiver.count_ref(Direction::Uplink), 31);
        receiver.unprotect_service_request(&request).unwrap();
        assert_eq!(receiver.count_ref(Direction::Uplink), 32);
        assert!(receiver.unprotect_service_request(&request).is_err());
        let next = sender.protect_service_request(3).unwrap();
        receiver.unprotect_service_request(&next).unwrap();
        assert_eq!(receiver.count_ref(Direction::Uplink), 33);
    }

    #[test]
    fn re_establishment_mac_atomically_consumes_ul_count() {
        let mut context = context();
        *context.count_mut(Direction::Uplink) = (7).into();
        let expected = eps::re_establishment_nas_mac(
            &context.core.keys.integrity,
            count(7),
            0x0123_4567,
            Eia::EIA2,
        )
        .unwrap();
        assert_eq!(
            context.protect_re_establishment(0x0123_4567).unwrap(),
            expected
        );
        assert_eq!(context.count_ref(Direction::Uplink), 8);
        assert!(context.protect_re_establishment(0x1000_0000).is_err());
        assert_eq!(context.count_ref(Direction::Uplink), 8);

        *context.count_mut(Direction::Uplink) = (0x00ff_ffff).into();
        assert!(context.protect_re_establishment(0x0123_4567).is_ok());
        assert_eq!(context.count_ref(Direction::Uplink), 0x0100_0000);
        assert_eq!(
            context.protect_re_establishment(0x0123_4567),
            Err(NasError::NasCountExhausted)
        );
        assert_eq!(context.count_ref(Direction::Uplink), 0x0100_0000);
        assert_eq!(
            context.protect_service_request(1).map(|_| ()),
            Err(NasError::NasCountExhausted)
        );
    }

    #[test]
    fn re_establishment_verification_estimates_count_and_commits_atomically() {
        let mut receiver = context();
        *receiver.count_mut(Direction::Uplink) = (7).into();
        let (ul_nas_mac, dl_nas_mac) = eps::re_establishment_nas_mac(
            &receiver.core.keys.integrity,
            count(7),
            0x0123_4567,
            Eia::EIA2,
        )
        .unwrap();

        assert!(
            receiver
                .verify_re_establishment(7, ul_nas_mac ^ 1, 0x0123_4567)
                .is_err()
        );
        assert_eq!(receiver.count_ref(Direction::Uplink), 7);
        assert_eq!(
            receiver
                .verify_re_establishment(7, ul_nas_mac, 0x0123_4567)
                .unwrap(),
            dl_nas_mac
        );
        assert_eq!(receiver.count_ref(Direction::Uplink), 8);
        assert!(
            receiver
                .verify_re_establishment(7, ul_nas_mac, 0x0123_4567)
                .is_err()
        );
        assert_eq!(receiver.count_ref(Direction::Uplink), 8);

        let mut after_gap = context();
        *after_gap.count_mut(Direction::Uplink) = (8).into();
        let (ul_nas_mac, dl_nas_mac) = eps::re_establishment_nas_mac(
            &after_gap.core.keys.integrity,
            count(39),
            0x0123_4567,
            Eia::EIA2,
        )
        .unwrap();
        assert_eq!(
            after_gap
                .verify_re_establishment(7, ul_nas_mac, 0x0123_4567)
                .unwrap(),
            dl_nas_mac
        );
        assert_eq!(after_gap.count_ref(Direction::Uplink), 40);
        assert!(
            after_gap
                .verify_re_establishment(0x20, 0, 0x0123_4567)
                .is_err()
        );
        assert_eq!(after_gap.count_ref(Direction::Uplink), 40);
    }

    #[test]
    fn a_re_establishment_count_has_five_bits() {
        // The five bits 11111 are a COUNT, and a sixth bit is refused before
        // the code is looked at
        let mut receiver = context();
        *receiver.count_mut(Direction::Uplink) = (31).into();
        let (ul_nas_mac, dl_nas_mac) = eps::re_establishment_nas_mac(
            &receiver.core.keys.integrity,
            count(31),
            0x0123_4567,
            Eia::EIA2,
        )
        .unwrap();
        let error = receiver
            .verify_re_establishment(0x20, ul_nas_mac, 0x0123_4567)
            .unwrap_err();
        assert!(matches!(error, NasError::DecodingError(_)), "{error:?}");
        assert_eq!(
            receiver.verify_re_establishment(0x1f, ul_nas_mac, 0x0123_4567),
            Ok(dl_nas_mac)
        );
        assert_eq!(receiver.count_ref(Direction::Uplink), 32);
    }

    #[test]
    fn a_service_request_of_the_ksi_7_is_refused_with_its_code() {
        // KSI 7, "no key is available", has no context to verify with, even
        // under the code that the context computes
        let mut receiver = context();
        let ksi_and_sequence_number = 7 << 5;
        let mac = eps::service_request_short_mac_with_header(
            &receiver.core.keys.integrity,
            count(0),
            Direction::Uplink.into(),
            0xc7,
            ksi_and_sequence_number,
            Eia::EIA2,
        )
        .unwrap();
        let request = NasServiceRequest::new(ksi_and_sequence_number, mac);
        let error = receiver.unprotect_service_request(&request).unwrap_err();
        assert!(matches!(error, NasError::DecodingError(_)), "{error:?}");
        assert_eq!(receiver.count_ref(Direction::Uplink), 0);
        // The KSI 6 is one
        let ksi_and_sequence_number = 6 << 5;
        let mac = eps::service_request_short_mac_with_header(
            &receiver.core.keys.integrity,
            count(0),
            Direction::Uplink.into(),
            0xc7,
            ksi_and_sequence_number,
            Eia::EIA2,
        )
        .unwrap();
        let request = NasServiceRequest::new(ksi_and_sequence_number, mac);
        assert_eq!(receiver.unprotect_service_request(&request), Ok(count(0)));
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
            let message = NasEpsMessage::new_emm(request);
            let plain = message.encode().unwrap();
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
            assert_eq!(sender.count_ref(Direction::Uplink), 0);
            let mac = eps::nas_mac(
                &sender.core.keys.integrity,
                NasCount::ZERO,
                Direction::Uplink.into(),
                &[&[0], plain.as_slice()].concat(),
                Eia::EIA2,
            );
            let mut wrong_sht = vec![0x17];
            wrong_sht.extend_from_slice(&mac.to_be_bytes());
            wrong_sht.push(0);
            wrong_sht.extend_from_slice(&plain);
            assert!(receiver.unprotect(&wrong_sht, Direction::Uplink).is_err());
            assert_eq!(receiver.count_ref(Direction::Uplink), 1);
            let mut receiver = context();
            let wire = sender
                .protect(
                    &message,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
                    Direction::Uplink,
                )
                .unwrap();
            assert_eq!(wire[0], 0x57);
            assert_eq!(&wire[6..9], &plain[..3]);
            assert_ne!(&wire[9..], &plain[3..]);
            let Verified {
                message: decoded,
                security_header_type: sht,
                ..
            } = receiver.unprotect(&wire, Direction::Uplink).unwrap();
            assert_eq!(
                sht,
                NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
            );
            assert_eq!(decoded.encode().unwrap(), plain);
            let mut tampered = wire;
            tampered[7] ^= 1;
            assert!(context().unprotect(&tampered, Direction::Uplink).is_err());
        }
    }

    #[test]
    fn control_plane_service_request_without_container_uses_integrity_only() {
        let message = NasEpsMessage::new_emm(NasControlPlaneServiceRequest::new(
            NasControlPlaneServiceType::new(0),
            NasKeySetIdentifier::new(0),
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
        let plain = message.encode().unwrap();
        let mut wrong_direction_wire = vec![0x17];
        let mac = eps::nas_mac(
            &KNasInt::new(&[0x11; 16]),
            NasCount::ZERO,
            Direction::Downlink.into(),
            &[&[0], plain.as_slice()].concat(),
            Eia::EIA2,
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
        assert_eq!(wrong_direction_receiver.count_ref(Direction::Downlink), 1);
        let mut sender = context();
        for sht in [
            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
            NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
        ] {
            assert!(sender.protect(&message, sht, Direction::Uplink).is_err());
            assert_eq!(sender.count_ref(Direction::Uplink), 0);
        }
        let wire = sender
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(&wire[6..], message.encode().unwrap());
        let mut receiver = context();
        assert_eq!(
            receiver
                .unprotect(&wire, Direction::Uplink)
                .unwrap()
                .message,
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
                .message,
            [0x01, 0xab]
        );
        let opaque = NasEpsMessage::decode(&wire).unwrap();
        assert_eq!(opaque.encode().unwrap(), wire);
        let Verified {
            message: decoded,
            security_header_type: sht,
            ..
        } = receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(
            sht,
            NasEpsSecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        );
        let NasEpsMessage::EmmTransport(transport) = decoded else {
            panic!("expected EMM TRANSPORT")
        };
        assert_eq!(transport.data_container.as_deref(), Some(&[0x01, 0xab][..]));
        assert!(NasEpsMessage::EmmTransport(transport).encode().is_err());
        let empty_wire = sender
            .protect_emm_transport(None, Direction::Uplink)
            .unwrap();
        let Verified { message: empty, .. } =
            receiver.unprotect(&empty_wire, Direction::Uplink).unwrap();
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
            eps::nas_cipher(
                &KNasEnc::new(&[0x22; 16]),
                NasCount::ZERO,
                Direction::Downlink.into(),
                &mut payload,
                Eea::EEA2,
            );
            let mut mac_input = vec![0];
            mac_input.extend_from_slice(&payload);
            let mac = eps::nas_mac(
                &KNasInt::new(&[0x11; 16]),
                NasCount::ZERO,
                Direction::Downlink.into(),
                &mac_input,
                Eia::EIA2,
            );
            let mut wire = vec![0xb7];
            wire.extend_from_slice(&mac.to_be_bytes());
            wire.extend_from_slice(&mac_input);
            let Verified { message: plain, .. } =
                context().unprotect_raw(&wire, Direction::Downlink).unwrap();
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
            &KNasInt::new(&[0; 16]),
            &KNasEnc::new(&[0; 16]),
            IntegrityAlgorithm::EIA0,
            CipheringAlgorithm::EEA0,
        )
        .unwrap();
        let mut receiver = sender.clone();
        *sender.count_mut(Direction::Uplink) = (0x00ff_ffff).into();
        *receiver.count_mut(Direction::Uplink) = (0x00ff_ffff).into();
        let message = NasEpsMessage::new_emm(NasEmmStatus::new(NasEmmCause::new(3)));
        let mut wire = sender
            .protect(
                &message,
                NasEpsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(sender.count_ref(Direction::Uplink), 0);
        wire[1..5].copy_from_slice(&[1, 2, 3, 4]);
        receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(receiver.count_ref(Direction::Uplink), 0);
        receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(receiver.count_ref(Direction::Uplink), 256);
    }

    #[test]
    fn valid_mac_over_invalid_inner_message_advances_count() {
        let key = [0x11; 16];
        let inner = [0xc7, 0, 0, 0];
        let mut mac_input = vec![0];
        mac_input.extend_from_slice(&inner);
        let mac = eps::nas_mac(
            &KNasInt::new(&key),
            NasCount::ZERO,
            Direction::Uplink.into(),
            &mac_input,
            Eia::EIA2,
        );
        let mut wire = vec![0x17];
        wire.extend_from_slice(&mac.to_be_bytes());
        wire.extend_from_slice(&mac_input);

        let mut raw_receiver = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key),
            &KNasEnc::new(&[0x22; 16]),
            IntegrityAlgorithm::EIA2,
            CipheringAlgorithm::EEA2,
        )
        .unwrap();
        assert!(
            raw_receiver
                .unprotect_raw(&wire, Direction::Uplink)
                .is_err()
        );
        assert_eq!(raw_receiver.count_ref(Direction::Uplink), 1);

        let mut receiver = raw_receiver.clone();
        assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
        assert_eq!(receiver.count_ref(Direction::Uplink), 1);
    }

    #[test]
    fn service_request_without_security_context_ksi_is_rejected() {
        let mut receiver = context();
        let request = NasServiceRequest::new(0xe0, 0);
        assert!(receiver.unprotect_service_request(&request).is_err());
        assert_eq!(receiver.count_ref(Direction::Uplink), 0);
        assert!(!NasEpsMessage::ServiceRequest(request).validate().is_empty());
    }

    #[test]
    fn service_request_uses_actual_received_first_octet() {
        let mut sender = context();
        let mut receiver = context();
        let mut request = sender.protect_service_request(1).unwrap();
        request.security_header_type = 13;
        request.message_authentication_code = eps::service_request_short_mac_with_header(
            &KNasInt::new(&[0x11; 16]),
            NasCount::ZERO,
            Direction::Uplink.into(),
            0xd7,
            request.ksi_and_sequence_number,
            Eia::EIA2,
        )
        .unwrap();
        receiver.unprotect_service_request(&request).unwrap();
        request.security_header_type = 0;
        assert!(receiver.unprotect_service_request(&request).is_err());
    }
}
