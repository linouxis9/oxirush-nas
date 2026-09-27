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

//! NAS security envelope — integrity protection and ciphering.
//!
//! This module provides [`NasSecurityContext`] which wraps NAS keys and algorithms
//! to protect outbound messages and unprotect (verify + decipher) inbound messages
//! per TS 33.501 &sect;6.4.3.
//!
//! Requires the `security` feature flag:
//! ```toml
//! oxirush-nas = { version = "0.4", features = ["security"] }
//! ```
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::nas_5gs::security::{Direction, NasSecurityContext};
//! use oxirush_nas::nas_5gs::{
//!     CipheringAlgorithm, IntegrityAlgorithm, Nas5gsSecurityHeaderType, decode_nas_5gs_message,
//! };
//!
//! let mut tx = NasSecurityContext::from_fresh_keys([0x11; 16], [0x22; 16], IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
//! let mut rx = NasSecurityContext::from_fresh_keys([0x11; 16], [0x22; 16], IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
//! // REGISTRATION COMPLETE.
//! let message = decode_nas_5gs_message(&[0x7e, 0x00, 0x43]).unwrap();
//!
//! // Protect (integrity + cipher)
//! let wire = tx.protect(&message, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered, Direction::Uplink).unwrap();
//!
//! // Unprotect (verify MAC + decipher + decode)
//! let (decoded, _) = rx.unprotect(&wire, Direction::Uplink).unwrap();
//! assert_eq!(decoded, message);
//! ```

pub use crate::common::{Direction, estimate_nas_count};
use crate::nas_5gs::ie::{AccessTypeValue, CipheringAlgorithm, IntegrityAlgorithm};
use crate::nas_5gs::message_types::Nas5gsSecurityHeaderType;
use crate::nas_5gs::messages::{
    Nas5gmmMessage, Nas5gsMessage, decode_nas_5gs_message, encode_nas_5gs_message,
    validate_security_protected_inner_message,
};
use crate::nas_5gs::types::{EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, NasError, Result};
use oxirush_security::nas_5gs::{nas_cipher, nas_mac};

fn validate_message_direction(message: &Nas5gsMessage, direction: Direction) -> Result<()> {
    let Nas5gsMessage::Gmm(_, inner) = message else {
        return Ok(());
    };
    // TS 24.501 Chapter 8 assigns a sending side to each 5GMM message.
    let required_direction = match inner {
        Nas5gmmMessage::RegistrationRequest(_)
        | Nas5gmmMessage::RegistrationComplete(_)
        | Nas5gmmMessage::DeregistrationRequestFromUe(_)
        | Nas5gmmMessage::DeregistrationAcceptToUe(_)
        | Nas5gmmMessage::ConfigurationUpdateComplete(_)
        | Nas5gmmMessage::ServiceRequest(_)
        | Nas5gmmMessage::AuthenticationResponse(_)
        | Nas5gmmMessage::AuthenticationFailure(_)
        | Nas5gmmMessage::IdentityResponse(_)
        | Nas5gmmMessage::SecurityModeComplete(_)
        | Nas5gmmMessage::SecurityModeReject(_)
        | Nas5gmmMessage::NotificationResponse(_)
        | Nas5gmmMessage::UlNasTransport(_)
        | Nas5gmmMessage::ControlPlaneServiceRequest(_)
        | Nas5gmmMessage::NetworkSliceSpecificAuthenticationComplete(_)
        | Nas5gmmMessage::RelayKeyRequest(_)
        | Nas5gmmMessage::RelayAuthenticationResponse(_) => Some(Direction::Uplink),
        Nas5gmmMessage::RegistrationAccept(_)
        | Nas5gmmMessage::RegistrationReject(_)
        | Nas5gmmMessage::DeregistrationRequestToUe(_)
        | Nas5gmmMessage::DeregistrationAcceptFromUe(_)
        | Nas5gmmMessage::ServiceAccept(_)
        | Nas5gmmMessage::ServiceReject(_)
        | Nas5gmmMessage::ConfigurationUpdateCommand(_)
        | Nas5gmmMessage::AuthenticationRequest(_)
        | Nas5gmmMessage::AuthenticationReject(_)
        | Nas5gmmMessage::AuthenticationResult(_)
        | Nas5gmmMessage::IdentityRequest(_)
        | Nas5gmmMessage::SecurityModeCommand(_)
        | Nas5gmmMessage::Notification(_)
        | Nas5gmmMessage::DlNasTransport(_)
        | Nas5gmmMessage::NetworkSliceSpecificAuthenticationCommand(_)
        | Nas5gmmMessage::NetworkSliceSpecificAuthenticationResult(_)
        | Nas5gmmMessage::RelayKeyAccept(_)
        | Nas5gmmMessage::RelayKeyReject(_)
        | Nas5gmmMessage::RelayAuthenticationRequest(_) => Some(Direction::Downlink),
        Nas5gmmMessage::FGmmStatus(_) => None,
    };
    if required_direction.is_some_and(|required| required != direction) {
        return Err(NasError::EncodingError(format!(
            "{:?} requires {:?} direction",
            inner.message_type(),
            required_direction.expect("checked direction")
        )));
    }
    Ok(())
}

/// Access domain associated with NAS COUNT tracking.
///
/// TS 24.501 §4.4.3 keeps separate NAS COUNT pairs per access type when the
/// same NAS security context is used over both 3GPP and non-3GPP access.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NasCountAccessType {
    /// 3GPP access.
    #[default]
    ThreeGpp,
    /// Non-3GPP access.
    Non3Gpp,
}

impl TryFrom<AccessTypeValue> for NasCountAccessType {
    type Error = NasError;

    fn try_from(value: AccessTypeValue) -> Result<Self> {
        match value {
            AccessTypeValue::ThreeGpp => Ok(Self::ThreeGpp),
            AccessTypeValue::Non3Gpp => Ok(Self::Non3Gpp),
        }
    }
}

/// NAS security context for protect/unprotect operations.
///
/// Tracks separate uplink and downlink NAS COUNT values for 3GPP and
/// non-3GPP access. Use separate instances for transmitting and receiving
/// when testing a message round trip.
///
/// Every COUNT holds the next value to use or to expect. TS 24.501
/// §4.4.3.1 stores the sending-side COUNT (uplink in the UE, downlink in
/// the AMF) the same way, but the receiving-side COUNT as the largest value
/// received: add one to that value when importing it and subtract one when
/// exporting it. Adjusting a sending-side COUNT would reuse a COUNT with the
/// same key.
#[cfg_attr(test, derive(Clone))]
pub struct NasSecurityContext {
    /// 128-bit NAS integrity key (KNASint).
    knas_int: [u8; 16],
    /// 128-bit NAS ciphering key (KNASenc).
    knas_enc: [u8; 16],
    /// Integrity algorithm.
    integrity_algo: IntegrityAlgorithm,
    /// Ciphering algorithm.
    ciphering_algo: CipheringAlgorithm,
    /// Next uplink NAS COUNT to use (UE) or to expect (AMF).
    ul_count: u32,
    /// Next downlink NAS COUNT to expect (UE) or to use (AMF).
    dl_count: u32,
    /// NAS uplink COUNT for non-3GPP access.
    ul_count_non_3gpp: u32,
    /// NAS downlink COUNT for non-3GPP access.
    dl_count_non_3gpp: u32,
    /// Bearer value for 3GPP NAS access; non-3GPP access uses bearer 2.
    bearer: u8,
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
                "Reserved 5GS NAS security algorithm is not implemented".into(),
            ));
        }
        // NIA0 is only used for unauthenticated emergency sessions, which
        // select NEA0 (TS 33.501 §5.2.3 and §10.2.2).
        if self.integrity_algo == IntegrityAlgorithm::NIA0
            && self.ciphering_algo != CipheringAlgorithm::NEA0
        {
            return Err(NasError::EncodingError("5GS NIA0 requires NEA0".into()));
        }
        Ok(())
    }

    fn check_bearer(&self, access_type: NasCountAccessType) -> Result<()> {
        if access_type == NasCountAccessType::ThreeGpp && self.bearer != 1 {
            return Err(NasError::EncodingError(
                "3GPP NAS connection identifier must be 1".into(),
            ));
        }
        Ok(())
    }

    fn bearer_for_access(&self, access_type: NasCountAccessType) -> u8 {
        match access_type {
            NasCountAccessType::ThreeGpp => self.bearer,
            NasCountAccessType::Non3Gpp => 2,
        }
    }

    fn advance_count(&mut self, direction: Direction, access_type: NasCountAccessType, count: u32) {
        *self.count_mut(direction, access_type) = if self.integrity_algo == IntegrityAlgorithm::NIA0
        {
            (count + 1) & 0x00ff_ffff
        } else {
            count + 1
        };
    }

    /// Create a context for genuinely fresh NAS keys with COUNT values at zero.
    ///
    /// Reusing the same keys with this constructor violates TS 33.501 §6.4.5;
    /// use [`Self::reselect_algorithms`] for an existing KAMF.
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
            ul_count_non_3gpp: 0,
            dl_count_non_3gpp: 0,
            bearer: 1,
        }
    }

    /// Derive a fresh 5GS NAS context from a newly established KAMF.
    ///
    /// COUNT starts at zero. Calling this again for the same KAMF would violate
    /// TS 33.501 §6.4.5; use [`Self::reselect_algorithms`] instead.
    pub fn from_fresh_kamf(
        kamf: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Self {
        let knas_int = zeroize::Zeroizing::new(oxirush_security::nas_5gs::derive_nas_key(
            kamf,
            0x02,
            integrity_algo as u8,
        ));
        let knas_enc = zeroize::Zeroizing::new(oxirush_security::nas_5gs::derive_nas_key(
            kamf,
            0x01,
            ciphering_algo as u8,
        ));
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

    /// Next NAS COUNT to use or expect for a direction and access type.
    pub fn nas_count(&self, direction: Direction, access_type: NasCountAccessType) -> u32 {
        *self.count_ref(direction, access_type)
    }

    /// Restore a 5GS context and its next COUNT values from persistent state.
    ///
    /// The caller must supply the counts stored for this exact KAMF. Passing
    /// zero for a KAMF that has already protected traffic violates TS 33.501
    /// §6.4.5. A value of `0x0100_0000` represents an exhausted COUNT.
    pub fn restore_from_kamf(
        kamf: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
        three_gpp_counts: (u32, u32),
        non_3gpp_counts: (u32, u32),
    ) -> Result<Self> {
        if [
            three_gpp_counts.0,
            three_gpp_counts.1,
            non_3gpp_counts.0,
            non_3gpp_counts.1,
        ]
        .into_iter()
        .any(|count| count > 0x0100_0000)
        {
            return Err(NasError::EncodingError(
                "Persisted 5GS NAS COUNT exceeds its representable state".into(),
            ));
        }
        let mut context = Self::from_fresh_kamf(kamf, integrity_algo, ciphering_algo);
        context.check_algorithms()?;
        (context.ul_count, context.dl_count) = three_gpp_counts;
        (context.ul_count_non_3gpp, context.dl_count_non_3gpp) = non_3gpp_counts;
        Ok(context)
    }

    /// Re-derive NAS keys for a new algorithm selection under the same KAMF.
    ///
    /// All four access-specific COUNTs are preserved as required by TS 33.501
    /// §6.4.5.
    pub fn reselect_algorithms(
        &mut self,
        kamf: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<()> {
        use zeroize::Zeroize;

        let replacement = Self::from_fresh_kamf(kamf, integrity_algo, ciphering_algo);
        replacement.check_algorithms()?;
        self.knas_int.zeroize();
        self.knas_enc.zeroize();
        self.knas_int = replacement.knas_int;
        self.knas_enc = replacement.knas_enc;
        self.integrity_algo = integrity_algo;
        self.ciphering_algo = ciphering_algo;
        Ok(())
    }

    /// Map an EPS KASME to a 5GS context for idle mobility.
    ///
    /// `tau_ul_nas_count` protects the EPS mobility-triggering message. The
    /// mapped 5GS NAS COUNT values start at zero. The mapped ngKSI is handled
    /// by the enclosing mobility procedure. A COUNT above the 24-bit NAS COUNT
    /// range is rejected.
    pub fn from_mapped_kamf_idle(
        kasme: &[u8; 32],
        tau_ul_nas_count: u32,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        if tau_ul_nas_count > 0x00ff_ffff {
            return Err(NasError::EncodingError(
                "EPS NAS COUNT exceeds 24 bits".into(),
            ));
        }
        let kamf = zeroize::Zeroizing::new(oxirush_security::nas_eps::derive_mapped_kamf_idle(
            kasme,
            tau_ul_nas_count,
        ));
        Ok(Self::from_fresh_kamf(&kamf, integrity_algo, ciphering_algo))
    }

    /// Map an EPS KASME to a 5GS context for connected handover using NH.
    /// The mapped 5GS NAS COUNT values start at zero. This derivation has no
    /// COUNT input and cannot fail.
    pub fn from_mapped_kamf_handover(
        kasme: &[u8; 32],
        nh: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Self {
        let kamf = zeroize::Zeroizing::new(oxirush_security::nas_eps::derive_mapped_kamf_handover(
            kasme, nh,
        ));
        Self::from_fresh_kamf(&kamf, integrity_algo, ciphering_algo)
    }

    fn count_ref(&self, direction: Direction, access_type: NasCountAccessType) -> &u32 {
        match (direction, access_type) {
            (Direction::Uplink, NasCountAccessType::ThreeGpp) => &self.ul_count,
            (Direction::Downlink, NasCountAccessType::ThreeGpp) => &self.dl_count,
            (Direction::Uplink, NasCountAccessType::Non3Gpp) => &self.ul_count_non_3gpp,
            (Direction::Downlink, NasCountAccessType::Non3Gpp) => &self.dl_count_non_3gpp,
        }
    }

    fn count_mut(&mut self, direction: Direction, access_type: NasCountAccessType) -> &mut u32 {
        match (direction, access_type) {
            (Direction::Uplink, NasCountAccessType::ThreeGpp) => &mut self.ul_count,
            (Direction::Downlink, NasCountAccessType::ThreeGpp) => &mut self.dl_count,
            (Direction::Uplink, NasCountAccessType::Non3Gpp) => &mut self.ul_count_non_3gpp,
            (Direction::Downlink, NasCountAccessType::Non3Gpp) => &mut self.dl_count_non_3gpp,
        }
    }

    /// Protect an outbound NAS message (uplink or downlink).
    ///
    /// 1. Encodes the inner message to bytes
    /// 2. Optionally ciphers the payload (for SHT 0x02 and 0x04)
    /// 3. Computes MAC over [SN || payload]
    /// 4. Assembles the security header: [EPD | SHT | MAC(4) | SN | payload]
    ///
    /// The appropriate COUNT is incremented after each call.
    pub fn protect(
        &mut self,
        inner: &Nas5gsMessage,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        self.protect_for_access(inner, sht, direction, NasCountAccessType::ThreeGpp)
    }

    /// Protect an outbound NAS message for a specific access type.
    pub fn protect_for_access(
        &mut self,
        inner: &Nas5gsMessage,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
        access_type: NasCountAccessType,
    ) -> Result<Vec<u8>> {
        validate_security_protected_inner_message(inner, sht)?;
        let inner_bytes = encode_nas_5gs_message(inner)?;
        self.protect_bytes_for_access(inner_bytes, sht, direction, access_type)
    }

    /// Protect raw NAS bytes that are already encoded.
    ///
    /// Useful when you need to protect a pre-encoded PDU.
    pub fn protect_bytes(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        self.protect_bytes_for_access(inner_bytes, sht, direction, NasCountAccessType::ThreeGpp)
    }

    /// Protect raw NAS bytes that are already encoded for a specific access.
    pub fn protect_bytes_for_access(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
        access_type: NasCountAccessType,
    ) -> Result<Vec<u8>> {
        self.check_algorithms()?;
        self.check_bearer(access_type)?;
        let decoded = decode_nas_5gs_message(&inner_bytes)?;
        validate_security_protected_inner_message(&decoded, sht)?;
        validate_message_direction(&decoded, direction)?;

        let current_count = *self.count_ref(direction, access_type);
        if current_count > 0x00ff_ffff {
            return Err(NasError::EncodingError("5GS NAS COUNT exhausted".into()));
        }
        let sn = (current_count & 0xFF) as u8;

        let mut payload = inner_bytes;

        // Cipher if SHT includes ciphering
        let should_cipher = matches!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
        );
        let dir = direction.as_u8();
        if should_cipher {
            nas_cipher(
                &self.knas_enc,
                current_count,
                self.bearer_for_access(access_type),
                dir,
                &mut payload,
                self.ciphering_algo as u8,
            );
        }

        // MAC input = [SN || ciphertext] per TS 33.501 §6.4.3.1
        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sn);
        mac_input.extend_from_slice(&payload);
        let mac = nas_mac(
            &self.knas_int,
            current_count,
            self.bearer_for_access(access_type),
            dir,
            &mac_input,
            self.integrity_algo as u8,
        );

        // Assemble: [EPD=0x7e | SHT | MAC(4) | SN | ciphered_payload]
        let mut out = Vec::with_capacity(7 + payload.len());
        out.push(EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        out.push(sht as u8);
        out.extend_from_slice(&mac.to_be_bytes());
        out.push(sn);
        out.extend_from_slice(&payload);
        self.advance_count(direction, access_type, current_count);
        Ok(out)
    }

    /// Unprotect an inbound security-protected NAS message.
    ///
    /// 1. Parses the security header (EPD, SHT, MAC, SN)
    /// 2. Verifies the MAC
    /// 3. Deciphers if needed
    /// 4. Decodes the inner NAS message
    ///
    /// On success, returns `(decoded_message, security_header_type)`.
    /// The appropriate COUNT is incremented immediately after successful MAC
    /// verification, even if later deciphering or inner-message checks fail.
    ///
    /// A MAC mismatch returns [`NasError::IntegrityCheckFailed`]. A receiver
    /// that must still process the message (TS 24.501 §4.4.4.3) can decode
    /// the PDU with
    /// [`decode_nas_5gs_message`],
    /// which returns the unverified inner message when it is not ciphered.
    pub fn unprotect(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<(Nas5gsMessage, Nas5gsSecurityHeaderType)> {
        self.unprotect_for_access(data, direction, NasCountAccessType::ThreeGpp)
    }

    /// Unprotect an inbound security-protected NAS message for a specific access.
    pub fn unprotect_for_access(
        &mut self,
        data: &[u8],
        direction: Direction,
        access_type: NasCountAccessType,
    ) -> Result<(Nas5gsMessage, Nas5gsSecurityHeaderType)> {
        let (plain, sht) = self.unprotect_raw_for_access(data, direction, access_type)?;
        Ok((decode_nas_5gs_message(&plain)?, sht))
    }

    /// Unprotect and return raw decrypted bytes without decoding.
    ///
    /// Useful when you need the raw bytes for further processing (e.g.,
    /// re-encoding into a NAS message container).
    pub fn unprotect_raw(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<(Vec<u8>, Nas5gsSecurityHeaderType)> {
        self.unprotect_raw_for_access(data, direction, NasCountAccessType::ThreeGpp)
    }

    /// Unprotect and return raw decrypted bytes for a specific access type.
    pub fn unprotect_raw_for_access(
        &mut self,
        data: &[u8],
        direction: Direction,
        access_type: NasCountAccessType,
    ) -> Result<(Vec<u8>, Nas5gsSecurityHeaderType)> {
        self.check_algorithms()?;
        self.check_bearer(access_type)?;
        if data.len() < 7 {
            return Err(NasError::BufferTooShort);
        }
        if data[0] != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(NasError::DecodingError(
                "Invalid 5GS NAS security discriminator".into(),
            ));
        }

        // Bits 8-5 of octet 2 are a spare half octet (Figure 9.1.1-2).
        let sht = Nas5gsSecurityHeaderType::try_from(data[1] & 0x0f)?;

        if sht == Nas5gsSecurityHeaderType::PlainNasMessage {
            return Err(NasError::DecodingError(
                "Not a security-protected message".into(),
            ));
        }

        let received_mac = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let sequence_number = data[6];
        let payload = &data[7..];
        if payload.is_empty() {
            return Err(NasError::BufferTooShort);
        }

        let stored_count = *self.count_ref(direction, access_type);
        let mut estimated_count = crate::common::estimate_count(stored_count, sequence_number);
        if self.integrity_algo == IntegrityAlgorithm::NIA0 {
            estimated_count &= 0x00ff_ffff;
        } else if estimated_count < stored_count || estimated_count > 0x00ff_ffff {
            return Err(NasError::DecodingError(
                "5GS NAS COUNT replay or exhaustion".into(),
            ));
        }
        let dir = direction.as_u8();

        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sequence_number);
        mac_input.extend_from_slice(payload);
        let expected_mac = nas_mac(
            &self.knas_int,
            estimated_count,
            self.bearer_for_access(access_type),
            dir,
            &mac_input,
            self.integrity_algo as u8,
        );

        if self.integrity_algo != IntegrityAlgorithm::NIA0 && received_mac != expected_mac {
            // The expected MAC is not reported: it would let an observer of the
            // error resend the same bytes with a valid MAC.
            return Err(NasError::IntegrityCheckFailed);
        }

        // TS 24.501 §4.4.3.3 commits the received NAS COUNT after successful
        // integrity verification. Inner syntax, header-pairing, and direction
        // checks must not make an authenticated COUNT reusable.
        self.advance_count(direction, access_type, estimated_count);

        let should_cipher = matches!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
        );

        let mut decrypted = payload.to_vec();
        if should_cipher {
            nas_cipher(
                &self.knas_enc,
                estimated_count,
                self.bearer_for_access(access_type),
                dir,
                &mut decrypted,
                self.ciphering_algo as u8,
            );
        }

        let decoded = decode_nas_5gs_message(&decrypted)?;
        validate_security_protected_inner_message(&decoded, sht).map_err(|err| match err {
            NasError::EncodingError(message) | NasError::DecodingError(message) => {
                NasError::DecodingError(message)
            }
            other => other,
        })?;
        validate_message_direction(&decoded, direction).map_err(|err| match err {
            NasError::EncodingError(message) => NasError::DecodingError(message),
            other => other,
        })?;

        Ok((decrypted, sht))
    }

    /// Integrity protect a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE
    /// REQUEST with this 5G NAS security context, as a UE does when it moves
    /// from 5GS to EPS (TS 33.501 §8.5.2 step 1, TS 24.301 §4.4.2.3). The
    /// PDU has the EPS security header with SHT 0001; the MAC uses KNASint,
    /// the 5G uplink NAS COUNT, and the 3GPP NAS connection identifier. The
    /// uplink COUNT advances.
    pub fn protect_eps_message(&mut self, eps_plain: &[u8]) -> Result<Vec<u8>> {
        self.check_algorithms()?;
        self.check_bearer(NasCountAccessType::ThreeGpp)?;
        check_eps_mobility_request(eps_plain)?;
        let count = self.ul_count;
        if count > 0x00ff_ffff {
            return Err(NasError::EncodingError("5GS NAS COUNT exhausted".into()));
        }
        let sequence_number = count as u8;
        let mut mac_input = Vec::with_capacity(1 + eps_plain.len());
        mac_input.push(sequence_number);
        mac_input.extend_from_slice(eps_plain);
        let mac = nas_mac(
            &self.knas_int,
            count,
            self.bearer,
            Direction::Uplink.as_u8(),
            &mac_input,
            self.integrity_algo as u8,
        );
        let mut out = Vec::with_capacity(6 + eps_plain.len());
        out.push(0x17);
        out.extend_from_slice(&mac.to_be_bytes());
        out.extend_from_slice(&mac_input);
        self.advance_count(Direction::Uplink, NasCountAccessType::ThreeGpp, count);
        Ok(out)
    }

    /// Verify an EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST that the
    /// UE protected with this 5G context, "as if it was a 5G NAS message
    /// received over 3GPP access" (TS 33.501 §8.5.2 step 4). Returns the plain
    /// EPS message; the uplink COUNT advances.
    pub fn unprotect_eps_message(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
        self.check_algorithms()?;
        self.check_bearer(NasCountAccessType::ThreeGpp)?;
        let [first, a, b, c, d, sequence_number, plain @ ..] = pdu else {
            return Err(NasError::MessageTooShort);
        };
        if *first != 0x17 {
            return Err(NasError::DecodingError(
                "EPS PDU is not integrity protected with SHT 0001".into(),
            ));
        }
        let stored_count = self.ul_count;
        let count = crate::common::estimate_count(stored_count, *sequence_number);
        if self.integrity_algo != IntegrityAlgorithm::NIA0
            && (count < stored_count || count > 0x00ff_ffff)
        {
            return Err(NasError::DecodingError(
                "5GS NAS COUNT replay or exhaustion".into(),
            ));
        }
        let expected_mac = nas_mac(
            &self.knas_int,
            count & 0x00ff_ffff,
            self.bearer,
            Direction::Uplink.as_u8(),
            &pdu[5..],
            self.integrity_algo as u8,
        );
        if self.integrity_algo != IntegrityAlgorithm::NIA0
            && u32::from_be_bytes([*a, *b, *c, *d]) != expected_mac
        {
            return Err(NasError::IntegrityCheckFailed);
        }
        self.advance_count(Direction::Uplink, NasCountAccessType::ThreeGpp, count);
        check_eps_mobility_request(plain)?;
        Ok(plain.to_vec())
    }
}

/// Only a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST is sent
/// under the 5G context (TS 33.501 §8.5.2, TS 24.301 §4.4.2.3).
fn check_eps_mobility_request(eps_plain: &[u8]) -> Result<()> {
    if matches!(eps_plain, [0x07, 0x41 | 0x48, ..]) {
        Ok(())
    } else {
        Err(NasError::EncodingError(
            "Only a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST uses the 5G context"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eps_mobility_request_is_protected_with_the_5g_context() {
        let mut ue = NasSecurityContext::from_fresh_keys(
            [0x21; 16],
            [0x22; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA0,
        );
        ue.ul_count = 0x0102;
        let mut amf = ue.clone();
        // A TAU REQUEST: update type, KSI, and old GUTI are enough here.
        let tau = [
            0x07, 0x48, 0x00, 0x0b, 0xf6, 0x02, 0xf8, 0x39, 0x80, 0x01, 0x01, 0, 0, 0, 1,
        ];
        let pdu = ue.protect_eps_message(&tau).unwrap();
        assert_eq!((pdu[0], pdu[5]), (0x17, 0x02));
        let expected = oxirush_security::nas_5gs::nas_mac(&[0x21; 16], 0x0102, 1, 0, &pdu[5..], 2);
        assert_eq!(u32::from_be_bytes(pdu[1..5].try_into().unwrap()), expected);
        assert_eq!(ue.ul_count, 0x0103);
        assert_eq!(amf.unprotect_eps_message(&pdu).unwrap(), tau);
        assert_eq!(amf.ul_count, 0x0103);
        // Replay and tampering are rejected without changing the COUNT.
        assert!(amf.unprotect_eps_message(&pdu).is_err());
        let mut tampered = ue.protect_eps_message(&tau).unwrap();
        tampered[10] ^= 1;
        assert_eq!(
            amf.unprotect_eps_message(&tampered),
            Err(NasError::IntegrityCheckFailed)
        );
        assert_eq!(amf.ul_count, 0x0103);
        assert!(ue.protect_eps_message(&[0x07, 0x43, 0x00, 0x00]).is_err());

        let mut invalid_sender = NasSecurityContext::from_fresh_keys(
            [0x21; 16],
            [0x22; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA0,
        );
        let mut invalid_receiver = invalid_sender.clone();
        let invalid_plain = [0x07, 0x43, 0x00, 0x00];
        let mut invalid_pdu = vec![0x17];
        let mac_input = [&[0][..], &invalid_plain].concat();
        let mac = oxirush_security::nas_5gs::nas_mac(
            &[0x21; 16],
            0,
            1,
            Direction::Uplink.as_u8(),
            &mac_input,
            2,
        );
        invalid_pdu.extend_from_slice(&mac.to_be_bytes());
        invalid_pdu.extend_from_slice(&mac_input);
        assert!(
            invalid_receiver
                .unprotect_eps_message(&invalid_pdu)
                .is_err()
        );
        assert_eq!(invalid_receiver.ul_count, 1);

        let valid_pdu = invalid_sender.protect_eps_message(&tau).unwrap();
        assert!(invalid_receiver.unprotect_eps_message(&valid_pdu).is_err());
        assert_eq!(invalid_receiver.ul_count, 1);
    }

    #[test]
    fn security_mode_requires_its_header_and_direction() {
        let command = Nas5gsMessage::new_5gmm(Nas5gmmMessage::SecurityModeCommand(
            crate::nas_5gs::messages::NasSecurityModeCommand::new(
                crate::nas_5gs::types::NasSecurityAlgorithms::from_algorithms(
                    CipheringAlgorithm::NEA0,
                    IntegrityAlgorithm::NIA0,
                ),
                crate::nas_5gs::types::NasKeySetIdentifier::new(0),
                crate::nas_5gs::types::NasUeSecurityCapability::new(vec![0, 0]),
            ),
        ));
        let complete = Nas5gsMessage::new_5gmm(Nas5gmmMessage::SecurityModeComplete(
            crate::nas_5gs::messages::NasSecurityModeComplete::new(),
        ));
        let mut tx = NasSecurityContext::from_fresh_keys(
            [0; 16],
            [0; 16],
            IntegrityAlgorithm::NIA0,
            CipheringAlgorithm::NEA0,
        );
        for (message, required_sht, wrong_sht, direction, wrong_direction) in [
            (
                &command,
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
                Direction::Uplink,
            ),
            (
                &complete,
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                Direction::Downlink,
            ),
        ] {
            assert!(tx.protect(message, wrong_sht, direction).is_err());
            assert!(tx.protect(message, required_sht, wrong_direction).is_err());
            let wire = tx.protect(message, required_sht, direction).unwrap();
            let mut rx = NasSecurityContext::from_fresh_keys(
                [0; 16],
                [0; 16],
                IntegrityAlgorithm::NIA0,
                CipheringAlgorithm::NEA0,
            );
            assert!(rx.unprotect(&wire, wrong_direction).is_err());
            assert!(rx.unprotect(&wire, direction).is_ok());
        }
    }

    #[test]
    fn mapped_eps_context_starts_5gs_counts_at_zero() {
        let kasme = core::array::from_fn(|i| i as u8);
        let nh = core::array::from_fn(|i| (i + 32) as u8);
        let mut idle = NasSecurityContext::from_mapped_kamf_idle(
            &kasme,
            0x1234,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        assert!(
            NasSecurityContext::from_mapped_kamf_idle(
                &kasme,
                0x0100_0000,
                IntegrityAlgorithm::NIA2,
                CipheringAlgorithm::NEA2,
            )
            .is_err()
        );
        let handover = NasSecurityContext::from_mapped_kamf_handover(
            &kasme,
            &nh,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        assert_eq!((idle.ul_count, idle.dl_count), (0, 0));
        assert_eq!((handover.ul_count, handover.dl_count), (0, 0));
        assert_ne!(idle.knas_int, handover.knas_int);
        // Independent AES-CTR and AES-CMAC check for the mapped key at COUNT 0.
        let wire = idle
            .protect_bytes(
                vec![0x7e, 0x00, 0x43],
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(
            wire,
            [0x7e, 0x02, 0xbd, 0x0f, 0xdc, 0xe7, 0x00, 0x96, 0xef, 0xc5]
        );
        assert_eq!(idle.ul_count, 1);
    }

    #[test]
    fn test_protect_unprotect_roundtrip_integrity_only() {
        let key_int = [0x01u8; 16];
        let key_enc = [0x02u8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );

        // Build a simple RegistrationComplete message
        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::RegistrationComplete(
                crate::nas_5gs::messages::NasRegistrationComplete::new(),
            ),
        );

        // Protect (UL) with integrity only
        let protected = tx
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();

        assert!(protected.len() > 7);
        assert_eq!(protected[0], 0x7E); // EPD
        assert_eq!(protected[1], 0x01); // SHT = IntegrityProtected

        // Unprotect (UL)
        let (_decoded, sht) = rx.unprotect(&protected, Direction::Uplink).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtected);

        // Verify counts advanced
        assert_eq!(tx.ul_count, 1);
        assert_eq!(rx.ul_count, 1);
    }

    #[test]
    fn test_protect_unprotect_roundtrip_ciphered() {
        let key_int = [0xABu8; 16];
        let key_enc = [0xCDu8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );

        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::AuthenticationResult(
                crate::nas_5gs::messages::NasAuthenticationResult::new(
                    crate::nas_5gs::types::NasKeySetIdentifier::new(0),
                    crate::nas_5gs::types::NasEapMessage::new(vec![0x03, 0x01, 0x00, 0x04]),
                ),
            ),
        );

        let protected = tx
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
            )
            .unwrap();

        assert_eq!(protected[1], 0x02); // SHT = IntegrityProtectedAndCiphered

        let (_decoded, sht) = rx.unprotect(&protected, Direction::Downlink).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered);
        assert_eq!(tx.dl_count, 1);
        assert_eq!(rx.dl_count, 1);
    }

    #[test]
    fn fixed_direction_5gmm_messages_are_rejected_in_the_other_direction() {
        // TS 24.501 Chapter 8 gives each 5GMM message except 5GMM STATUS one
        // sending side; protection and verification both enforce it.
        let uplink = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationComplete(
            crate::nas_5gs::messages::NasRegistrationComplete::new(),
        ));
        let status = Nas5gsMessage::new_5gmm(Nas5gmmMessage::FGmmStatus(
            crate::nas_5gs::messages::NasFGmmStatus::new(crate::NasFGmmCause::new(0x6f)),
        ));
        let context = || {
            NasSecurityContext::from_fresh_keys(
                [0x21; 16],
                [0x43; 16],
                IntegrityAlgorithm::NIA2,
                CipheringAlgorithm::NEA2,
            )
        };
        let sht = Nas5gsSecurityHeaderType::IntegrityProtected;
        let mut tx = context();
        assert!(tx.protect(&uplink, sht, Direction::Downlink).is_err());
        assert_eq!(tx.dl_count, 0);
        let wire = tx.protect(&uplink, sht, Direction::Uplink).unwrap();
        let mut rx = context();
        assert!(rx.unprotect(&wire, Direction::Uplink).is_ok());
        for direction in [Direction::Uplink, Direction::Downlink] {
            let wire = context().protect(&status, sht, direction).unwrap();
            assert!(context().unprotect(&wire, direction).is_ok());
        }
    }

    #[test]
    fn test_security_mode_command_with_new_context_is_not_ciphered() {
        let key_int = [0x21u8; 16];
        let key_enc = [0x43u8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );

        let smc = crate::nas_5gs::messages::NasSecurityModeCommand::new(
            crate::nas_5gs::types::NasSecurityAlgorithms::from_algorithms(
                CipheringAlgorithm::NEA2,
                IntegrityAlgorithm::NIA2,
            ),
            crate::nas_5gs::types::NasKeySetIdentifier::new(0),
            crate::nas_5gs::types::NasUeSecurityCapability::new(vec![0xE0, 0xE0]),
        )
        .set_abba(crate::nas_5gs::types::NasAbba::new(vec![0x00, 0x00]));
        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::SecurityModeCommand(smc),
        );
        let plain = encode_nas_5gs_message(&inner).unwrap();

        let protected = tx
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
                Direction::Downlink,
            )
            .unwrap();

        assert_eq!(protected[1], 0x03);
        assert_eq!(&protected[7..], plain.as_slice());

        let (decoded, sht) = rx.unprotect(&protected, Direction::Downlink).unwrap();
        assert_eq!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext
        );
        assert!(matches!(
            decoded,
            Nas5gsMessage::Gmm(
                _,
                crate::nas_5gs::messages::Nas5gmmMessage::SecurityModeCommand(_)
            )
        ));
    }

    #[test]
    fn test_mac_failure_rejects() {
        let key_int = [0x01u8; 16];
        let key_enc = [0x02u8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::from_fresh_keys(
            [0xFFu8; 16],
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        ); // Different key!

        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::RegistrationComplete(
                crate::nas_5gs::messages::NasRegistrationComplete::new(),
            ),
        );

        let protected = tx
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();

        let result = rx.unprotect(&protected, Direction::Uplink);
        assert!(result.is_err());
        let error = result.unwrap_err().to_string();
        assert!(error.contains("MAC verification failed"));
        assert!(!error.contains("expected"), "{error}");
        // COUNT should NOT advance on failure
        assert_eq!(rx.ul_count, 0);
    }

    #[test]
    fn test_unprotect_estimates_count_from_sequence_number() {
        let key_int = [0x11u8; 16];
        let key_enc = [0x22u8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );

        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::RegistrationComplete(
                crate::nas_5gs::messages::NasRegistrationComplete::new(),
            ),
        );

        let _first = tx
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        let second = tx
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();

        // Fresh receiver starts with COUNT 0 but should still accept SN=1 by
        // estimating the correct NAS COUNT from the received sequence number.
        let (_, sht) = rx.unprotect(&second, Direction::Uplink).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtected);
        assert_eq!(second[6], 0x01);
        assert_eq!(rx.ul_count, 2);
    }

    #[test]
    fn nia0_requires_nea0() {
        let message = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationComplete(
            crate::nas_5gs::messages::NasRegistrationComplete::new(),
        ));
        let mut context = NasSecurityContext::from_fresh_keys(
            [0; 16],
            [0; 16],
            IntegrityAlgorithm::NIA0,
            CipheringAlgorithm::NEA2,
        );
        assert!(
            context
                .protect(
                    &message,
                    Nas5gsSecurityHeaderType::IntegrityProtected,
                    Direction::Uplink
                )
                .is_err()
        );
        assert_eq!(context.ul_count, 0);
    }

    #[test]
    fn spare_half_octet_of_the_security_header_is_ignored() {
        // Security review F7: octet 2 is "spare half octet | security header
        // type" (TS 24.501 Figure 9.1.1-2); the spare bits are outside the MAC.
        let context = || {
            NasSecurityContext::from_fresh_keys(
                [0x31; 16],
                [0x32; 16],
                IntegrityAlgorithm::NIA2,
                CipheringAlgorithm::NEA2,
            )
        };
        let message = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationComplete(
            crate::nas_5gs::messages::NasRegistrationComplete::new(),
        ));
        let mut wire = context()
            .protect(
                &message,
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Uplink,
            )
            .unwrap();
        wire[1] |= 0x10;
        assert!(crate::nas_5gs::messages::is_security_protected(&wire));
        let (decoded, sht) = context().unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered);
    }

    #[test]
    fn fresh_count_after_gap_is_accepted_and_replay_is_not() {
        // TS 24.501 §4.4.3.1: a lower sequence number means the overflow
        // counter advanced, independent of the current overflow value.
        let message = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationComplete(
            crate::nas_5gs::messages::NasRegistrationComplete::new(),
        ));
        for (receiver_next, sender_count) in [(0x05, 0x90), (0x0105, 0x0190), (0x01f0, 0x0202)] {
            let context = || {
                NasSecurityContext::from_fresh_keys(
                    [0x31; 16],
                    [0x32; 16],
                    IntegrityAlgorithm::NIA2,
                    CipheringAlgorithm::NEA2,
                )
            };
            let mut sender = context();
            let mut receiver = context();
            sender.ul_count = sender_count;
            receiver.ul_count = receiver_next;
            let wire = sender
                .protect(
                    &message,
                    Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
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
    }

    #[test]
    fn test_non_3gpp_access_counts_are_separate() {
        let key_int = [0x31u8; 16];
        let key_enc = [0x41u8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );

        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::AuthenticationResult(
                crate::nas_5gs::messages::NasAuthenticationResult::new(
                    crate::nas_5gs::types::NasKeySetIdentifier::new(0),
                    crate::nas_5gs::types::NasEapMessage::new(vec![0x03, 0x01, 0x00, 0x04]),
                ),
            ),
        );

        let protected = tx
            .protect_for_access(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Downlink,
                NasCountAccessType::Non3Gpp,
            )
            .unwrap();

        assert_eq!(tx.dl_count, 0);
        assert_eq!(tx.dl_count_non_3gpp, 1);

        let (_, _) = rx
            .unprotect_for_access(&protected, Direction::Downlink, NasCountAccessType::Non3Gpp)
            .unwrap();

        assert_eq!(rx.dl_count, 0);
        assert_eq!(rx.dl_count_non_3gpp, 1);
    }

    #[test]
    fn test_protect_bytes_rejects_plain_5gsm_inner_message() {
        let mut ctx = NasSecurityContext::from_fresh_keys(
            [0x51u8; 16],
            [0x61u8; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );

        let inner = encode_nas_5gs_message(&Nas5gsMessage::new_5gsm(
            crate::nas_5gs::messages::Nas5gsmMessage::PduSessionEstablishmentRequest(
                crate::nas_5gs::messages::NasPduSessionEstablishmentRequest::new(
                    crate::NasIntegrityProtectionMaximumDataRate::from_rates(
                        crate::nas_5gs::ie::MaxDataRate::FullRate,
                        crate::nas_5gs::ie::MaxDataRate::FullRate,
                    ),
                ),
            ),
            1,
            1,
        ))
        .unwrap();

        assert!(
            ctx.protect_bytes(
                inner,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_5gs_context_and_algorithm_reselection_preserve_all_counts() {
        let kamf = [0x24; 32];
        let mut context = NasSecurityContext::restore_from_kamf(
            &kamf,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
            (0x0012_3456, 0x0000_abcd),
            (0x0000_1234, 0x0000_5678),
        )
        .unwrap();
        let old_keys = (context.knas_int, context.knas_enc);
        assert_eq!(
            context.nas_count(Direction::Uplink, NasCountAccessType::ThreeGpp),
            0x0012_3456
        );
        assert_eq!(
            context.nas_count(Direction::Downlink, NasCountAccessType::ThreeGpp),
            0x0000_abcd
        );
        assert_eq!(
            context.nas_count(Direction::Uplink, NasCountAccessType::Non3Gpp),
            0x0000_1234
        );
        assert_eq!(
            context.nas_count(Direction::Downlink, NasCountAccessType::Non3Gpp),
            0x0000_5678
        );

        context
            .reselect_algorithms(&kamf, IntegrityAlgorithm::NIA1, CipheringAlgorithm::NEA1)
            .unwrap();
        assert_eq!(context.integrity_algorithm(), IntegrityAlgorithm::NIA1);
        assert_eq!(context.ciphering_algorithm(), CipheringAlgorithm::NEA1);
        assert_eq!(
            context.nas_count(Direction::Uplink, NasCountAccessType::ThreeGpp),
            0x0012_3456
        );
        assert_eq!(
            context.nas_count(Direction::Downlink, NasCountAccessType::ThreeGpp),
            0x0000_abcd
        );
        assert_eq!(
            context.nas_count(Direction::Uplink, NasCountAccessType::Non3Gpp),
            0x0000_1234
        );
        assert_eq!(
            context.nas_count(Direction::Downlink, NasCountAccessType::Non3Gpp),
            0x0000_5678
        );
        assert_ne!((context.knas_int, context.knas_enc), old_keys);

        assert!(
            NasSecurityContext::restore_from_kamf(
                &kamf,
                IntegrityAlgorithm::NIA2,
                CipheringAlgorithm::NEA2,
                (0, 0),
                (0, 0x0100_0001),
            )
            .is_err()
        );
    }

    #[test]
    fn test_protect_bytes_rejects_invalid_new_context_sht_for_non_security_mode_command() {
        let mut ctx = NasSecurityContext::from_fresh_keys(
            [0x71u8; 16],
            [0x81u8; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );

        let inner = encode_nas_5gs_message(&Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::RegistrationComplete(
                crate::nas_5gs::messages::NasRegistrationComplete::new(),
            ),
        ))
        .unwrap();

        assert!(
            ctx.protect_bytes(
                inner,
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
                Direction::Uplink,
            )
            .is_err()
        );
    }

    #[test]
    fn protected_5gs_commits_authenticated_count_before_inner_validation() {
        let key = [0x29; 16];
        let mut sender = NasSecurityContext::from_fresh_keys(
            key,
            key,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut receiver = sender.clone();
        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::RegistrationComplete(
                crate::nas_5gs::messages::NasRegistrationComplete::new(),
            ),
        );
        let wire = sender
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        let mut bad_epd = wire.clone();
        bad_epd[0] = 0;
        assert!(receiver.unprotect(&bad_epd, Direction::Uplink).is_err());
        assert_eq!(receiver.ul_count, 0);
        let mut bad_inner = wire.clone();
        bad_inner[9] = 0xff;
        let mac = nas_mac(&key, 0, 1, 0, &bad_inner[6..], 2);
        bad_inner[2..6].copy_from_slice(&mac.to_be_bytes());
        assert!(receiver.unprotect(&bad_inner, Direction::Uplink).is_err());
        assert_eq!(receiver.ul_count, 1);
        assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
        assert_eq!(receiver.ul_count, 1);
    }

    #[test]
    fn reserved_5gs_algorithm_returns_error_before_cipher_dispatch() {
        let mut context = NasSecurityContext::from_fresh_keys(
            [0; 16],
            [0; 16],
            IntegrityAlgorithm::NIA7,
            CipheringAlgorithm::NEA2,
        );
        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::RegistrationComplete(
                crate::nas_5gs::messages::NasRegistrationComplete::new(),
            ),
        );
        assert!(
            context
                .protect(
                    &inner,
                    Nas5gsSecurityHeaderType::IntegrityProtected,
                    Direction::Uplink
                )
                .is_err()
        );
        assert_eq!(context.ul_count, 0);
    }

    #[test]
    fn invalid_3gpp_connection_identifier_is_rejected_before_mac() {
        let mut context = NasSecurityContext::from_fresh_keys(
            [0; 16],
            [0; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        context.bearer = 0;
        let inner = Nas5gsMessage::new_5gmm(
            crate::nas_5gs::messages::Nas5gmmMessage::RegistrationComplete(
                crate::nas_5gs::messages::NasRegistrationComplete::new(),
            ),
        );
        assert!(
            context
                .protect(
                    &inner,
                    Nas5gsSecurityHeaderType::IntegrityProtected,
                    Direction::Uplink,
                )
                .is_err()
        );
        assert_eq!(context.ul_count, 0);
    }
}
