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
//! ```rust,ignore
//! use oxirush_nas::nas_5gs::NasSecurityContext;
//! use oxirush_nas::nas_5gs::security::Direction;
//! use oxirush_nas::nas_5gs::ie::{IntegrityAlgorithm, CipheringAlgorithm};
//! use oxirush_nas::nas_5gs::message_types::Nas5gsSecurityHeaderType;
//!
//! let mut tx = NasSecurityContext::new(
//!     knas_int, knas_enc,
//!     IntegrityAlgorithm::NIA2,
//!     CipheringAlgorithm::NEA2,
//! );
//! let mut rx = tx.clone();
//!
//! // Protect (integrity + cipher)
//! let wire = tx.protect(&msg, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered, Direction::Uplink)?;
//!
//! // Unprotect (verify MAC + decipher + decode)
//! let (decoded, sht) = rx.unprotect(&wire, Direction::Uplink)?;
//! ```

pub use crate::common::Direction;
use crate::nas_5gs::ie::{AccessTypeValue, CipheringAlgorithm, IntegrityAlgorithm};
use crate::nas_5gs::message_types::Nas5gsSecurityHeaderType;
use crate::nas_5gs::messages::{
    Nas5gmmMessage, Nas5gsMessage, decode_nas_5gs_message, encode_nas_5gs_message,
    validate_security_protected_inner_message,
};
use crate::nas_5gs::types::{EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, NasError, Result};
use oxirush_security::nas_5gs::{nas_cipher, nas_mac};

fn validate_security_mode_direction(message: &Nas5gsMessage, direction: Direction) -> Result<()> {
    match message {
        Nas5gsMessage::Gmm(_, Nas5gmmMessage::SecurityModeCommand(_))
            if direction != Direction::Downlink =>
        {
            Err(NasError::EncodingError(
                "SecurityModeCommand requires downlink direction".into(),
            ))
        }
        Nas5gsMessage::Gmm(_, Nas5gmmMessage::SecurityModeComplete(_))
            if direction != Direction::Uplink =>
        {
            Err(NasError::EncodingError(
                "SecurityModeComplete requires uplink direction".into(),
            ))
        }
        _ => Ok(()),
    }
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
#[derive(Clone)]
pub struct NasSecurityContext {
    /// 128-bit NAS integrity key (KNASint).
    pub knas_int: [u8; 16],
    /// 128-bit NAS ciphering key (KNASenc).
    pub knas_enc: [u8; 16],
    /// Integrity algorithm.
    pub integrity_algo: IntegrityAlgorithm,
    /// Ciphering algorithm.
    pub ciphering_algo: CipheringAlgorithm,
    /// NAS uplink COUNT (incremented on each protect call).
    pub ul_count: u32,
    /// NAS downlink COUNT (incremented on each successful unprotect call).
    pub dl_count: u32,
    /// NAS uplink COUNT for non-3GPP access.
    pub ul_count_non_3gpp: u32,
    /// NAS downlink COUNT for non-3GPP access.
    pub dl_count_non_3gpp: u32,
    /// Bearer value for 3GPP NAS access; non-3GPP access uses bearer 2.
    pub bearer: u8,
}

impl NasSecurityContext {
    fn check_algorithms(&self) -> Result<()> {
        if self.integrity_algo as u8 > 3 || self.ciphering_algo as u8 > 3 {
            return Err(NasError::EncodingError(
                "Reserved 5GS NAS security algorithm is not implemented".into(),
            ));
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

    /// Create a new security context with the given keys and algorithms.
    /// Counts start at 0.
    pub fn new(
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

    /// Derive the 128-bit 5GS NAS keys from KAMF and the selected algorithms.
    pub fn from_kamf(
        kamf: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Self {
        let knas_int = oxirush_security::extract_128(&oxirush_security::nas_5gs::derive_nas_key(
            kamf,
            0x02,
            integrity_algo as u8,
        ));
        let knas_enc = oxirush_security::extract_128(&oxirush_security::nas_5gs::derive_nas_key(
            kamf,
            0x01,
            ciphering_algo as u8,
        ));
        Self::new(knas_int, knas_enc, integrity_algo, ciphering_algo)
    }

    /// Map an EPS KASME to a 5GS context for idle mobility.
    ///
    /// `tau_ul_nas_count` protects the EPS mobility-triggering message. The
    /// mapped 5GS NAS COUNT values start at zero. The mapped ngKSI is handled
    /// by the enclosing mobility procedure.
    pub fn from_mapped_kamf_idle(
        kasme: &[u8; 32],
        tau_ul_nas_count: u32,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Self {
        let kamf = oxirush_security::nas_eps::derive_mapped_kamf_idle(kasme, tau_ul_nas_count);
        Self::from_kamf(&kamf, integrity_algo, ciphering_algo)
    }

    /// Map an EPS KASME to a 5GS context for connected handover using NH.
    /// The mapped 5GS NAS COUNT values start at zero.
    pub fn from_mapped_kamf_handover(
        kasme: &[u8; 32],
        nh: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Self {
        let kamf = oxirush_security::nas_eps::derive_mapped_kamf_handover(kasme, nh);
        Self::from_kamf(&kamf, integrity_algo, ciphering_algo)
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
        validate_security_mode_direction(&decoded, direction)?;

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
    /// The appropriate COUNT is incremented after MAC verification and inner decoding succeed.
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

        let sht_byte = data[1];
        let sht = Nas5gsSecurityHeaderType::try_from(sht_byte)?;

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
            return Err(NasError::DecodingError(format!(
                "MAC verification failed: received {:#010x}, expected {:#010x}",
                received_mac, expected_mac
            )));
        }

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
        validate_security_mode_direction(&decoded, direction).map_err(|err| match err {
            NasError::EncodingError(message) => NasError::DecodingError(message),
            other => other,
        })?;

        self.advance_count(direction, access_type, estimated_count);

        Ok((decrypted, sht))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut tx = NasSecurityContext::new(
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
            let mut rx = NasSecurityContext::new(
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

        let mut tx = NasSecurityContext::new(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::new(
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

        let mut tx = NasSecurityContext::new(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::new(
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
    fn test_security_mode_command_with_new_context_is_not_ciphered() {
        let key_int = [0x21u8; 16];
        let key_enc = [0x43u8; 16];

        let mut tx = NasSecurityContext::new(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::new(
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

        let mut tx = NasSecurityContext::new(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::new(
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
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("MAC verification failed")
        );
        // COUNT should NOT advance on failure
        assert_eq!(rx.ul_count, 0);
    }

    #[test]
    fn test_unprotect_estimates_count_from_sequence_number() {
        let key_int = [0x11u8; 16];
        let key_enc = [0x22u8; 16];

        let mut tx = NasSecurityContext::new(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::new(
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
    fn test_non_3gpp_access_counts_are_separate() {
        let key_int = [0x31u8; 16];
        let key_enc = [0x41u8; 16];

        let mut tx = NasSecurityContext::new(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        );
        let mut rx = NasSecurityContext::new(
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
        let mut ctx = NasSecurityContext::new(
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
    fn test_protect_bytes_rejects_invalid_new_context_sht_for_non_security_mode_command() {
        let mut ctx = NasSecurityContext::new(
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
    fn protected_5gs_rejects_replay_bad_discriminator_and_invalid_inner_without_advancing() {
        let key = [0x29; 16];
        let mut sender =
            NasSecurityContext::new(key, key, IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
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
        assert_eq!(receiver.ul_count, 0);
        assert!(receiver.unprotect(&wire, Direction::Uplink).is_ok());
        assert_eq!(receiver.ul_count, 1);
        assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
        assert_eq!(receiver.ul_count, 1);
    }

    #[test]
    fn reserved_5gs_algorithm_returns_error_before_cipher_dispatch() {
        let mut context = NasSecurityContext::new(
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
        let mut context = NasSecurityContext::new(
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
