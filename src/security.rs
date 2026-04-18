/*
   OxiRush — NAS Security Envelope
   Integrated protect/unprotect API per TS 33.501 §6.4.3.

   Requires the `security` feature flag:
       oxirush-nas = { features = ["security"] }
*/

//! NAS security envelope — integrity protection and ciphering.
//!
//! This module provides [`NasSecurityContext`] which wraps NAS keys and algorithms
//! to protect outbound messages and unprotect (verify + decipher) inbound messages
//! per TS 33.501 &sect;6.4.3.
//!
//! Requires the `security` feature flag:
//! ```toml
//! oxirush-nas = { version = "0.2", features = ["security"] }
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use oxirush_nas::NasSecurityContext;
//! use oxirush_nas::security::Direction;
//! use oxirush_nas::ie::{IntegrityAlgorithm, CipheringAlgorithm};
//! use oxirush_nas::message_types::Nas5gsSecurityHeaderType;
//!
//! let mut ctx = NasSecurityContext::new(
//!     knas_int, knas_enc,
//!     IntegrityAlgorithm::NIA2,
//!     CipheringAlgorithm::NEA2,
//! );
//!
//! // Protect (integrity + cipher)
//! let wire = ctx.protect(&msg, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered, Direction::Uplink)?;
//!
//! // Unprotect (verify MAC + decipher + decode)
//! let (decoded, sht) = ctx.unprotect(&wire, Direction::Uplink)?;
//! ```

use crate::ie::{AccessTypeValue, CipheringAlgorithm, IntegrityAlgorithm};
use crate::message_types::Nas5gsSecurityHeaderType;
use crate::messages::{
    Nas5gsMessage, decode_nas_5gs_message, encode_nas_5gs_message,
    validate_security_protected_inner_message,
};
use crate::types::{EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, NasError, Result};
use oxirush_security::{nas_cipher, nas_mac};

/// NAS transmission direction.
///
/// Used by [`NasSecurityContext`] protect/unprotect methods instead of raw `0`/`1`.
/// Values match TS 33.501 §6.4.3.1: 0 = uplink (UE→network), 1 = downlink (network→UE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Direction {
    /// Uplink: UE → network (value 0).
    Uplink = 0,
    /// Downlink: network → UE (value 1).
    Downlink = 1,
}

impl Direction {
    /// Raw u8 value for use with cryptographic primitives.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Access domain associated with NAS COUNT tracking.
///
/// TS 24.501 §4.4.3 keeps separate NAS COUNT pairs per access type when the
/// same NAS security context is used over both 3GPP and non-3GPP access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NasCountAccessType {
    /// 3GPP access.
    ThreeGpp,
    /// Non-3GPP access.
    Non3Gpp,
}

impl Default for NasCountAccessType {
    fn default() -> Self {
        Self::ThreeGpp
    }
}

impl TryFrom<AccessTypeValue> for NasCountAccessType {
    type Error = NasError;

    fn try_from(value: AccessTypeValue) -> Result<Self> {
        match value {
            AccessTypeValue::ThreeGpp => Ok(Self::ThreeGpp),
            AccessTypeValue::Non3Gpp => Ok(Self::Non3Gpp),
            AccessTypeValue::BothAccesses => Err(NasError::DecodingError(
                "Cannot map BothAccesses to a single NAS COUNT access type".into(),
            )),
        }
    }
}

/// NAS security context for protect/unprotect operations.
///
/// Tracks NAS COUNT, keys, and algorithm identifiers for one direction.
/// Create one `NasSecurityContext` per direction (UL and DL) or use the
/// convenience constructors that pair both.
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
    /// Bearer value (always 1 for NAS, per TS 33.501 §6.4.3.1).
    pub bearer: u8,
}

impl NasSecurityContext {
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

    fn estimate_count(stored_count: u32, sequence_number: u8) -> u32 {
        let stored_sn = (stored_count & 0xFF) as u8;
        let base = stored_count & !0xFF;

        if stored_sn > sequence_number && stored_sn - sequence_number > 128 {
            base.wrapping_add(0x100) | u32::from(sequence_number)
        } else if sequence_number > stored_sn && sequence_number - stored_sn > 128 {
            base.saturating_sub(0x100) | u32::from(sequence_number)
        } else {
            base | u32::from(sequence_number)
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
        let decoded = decode_nas_5gs_message(&inner_bytes)?;
        validate_security_protected_inner_message(&decoded, sht)?;

        let count = self.count_mut(direction, access_type);
        let current_count = *count;
        let sn = (current_count & 0xFF) as u8;
        *count += 1;

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
                self.bearer,
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
            self.bearer,
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
    /// The appropriate COUNT is incremented only on MAC verification success.
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
        if data.len() < 7 {
            return Err(NasError::BufferTooShort);
        }

        let _epd = data[0];
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

        let stored_count = *self.count_ref(direction, access_type);
        let estimated_count = Self::estimate_count(stored_count, sequence_number);
        let dir = direction.as_u8();

        // Verify MAC over [SN || payload]
        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sequence_number); // SN
        mac_input.extend_from_slice(payload);
        let expected_mac = nas_mac(
            &self.knas_int,
            estimated_count,
            self.bearer,
            dir,
            &mac_input,
            self.integrity_algo as u8,
        );

        if received_mac != expected_mac {
            return Err(NasError::DecodingError(format!(
                "MAC verification failed: received {:#010x}, expected {:#010x}",
                received_mac, expected_mac
            )));
        }

        *self.count_mut(direction, access_type) = estimated_count.wrapping_add(1);

        // Decipher if needed
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
                self.bearer,
                dir,
                &mut decrypted,
                self.ciphering_algo as u8,
            );
        }

        // Decode inner plain NAS message
        let inner = decode_nas_5gs_message(&decrypted)?;
        validate_security_protected_inner_message(&inner, sht).map_err(|err| match err {
            NasError::EncodingError(message) | NasError::DecodingError(message) => {
                NasError::DecodingError(message)
            }
            other => other,
        })?;
        Ok((inner, sht))
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
        if data.len() < 7 {
            return Err(NasError::BufferTooShort);
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

        let stored_count = *self.count_ref(direction, access_type);
        let estimated_count = Self::estimate_count(stored_count, sequence_number);
        let dir = direction.as_u8();

        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(sequence_number);
        mac_input.extend_from_slice(payload);
        let expected_mac = nas_mac(
            &self.knas_int,
            estimated_count,
            self.bearer,
            dir,
            &mac_input,
            self.integrity_algo as u8,
        );

        if received_mac != expected_mac {
            return Err(NasError::DecodingError(format!(
                "MAC verification failed: received {:#010x}, expected {:#010x}",
                received_mac, expected_mac
            )));
        }

        *self.count_mut(direction, access_type) = estimated_count.wrapping_add(1);

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
                self.bearer,
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

        Ok((decrypted, sht))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let inner = Nas5gsMessage::new_5gmm(crate::messages::Nas5gmmMessage::RegistrationComplete(
            crate::messages::NasRegistrationComplete::new(),
        ));

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
        let (decoded, sht) = rx.unprotect(&protected, Direction::Uplink).unwrap();
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

        let inner = Nas5gsMessage::new_5gmm(crate::messages::Nas5gmmMessage::RegistrationComplete(
            crate::messages::NasRegistrationComplete::new(),
        ));

        let protected = tx
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
            )
            .unwrap();

        assert_eq!(protected[1], 0x02); // SHT = IntegrityProtectedAndCiphered

        let (decoded, sht) = rx.unprotect(&protected, Direction::Downlink).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered);
        assert_eq!(tx.dl_count, 1);
        assert_eq!(rx.dl_count, 1);
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

        let inner = Nas5gsMessage::new_5gmm(crate::messages::Nas5gmmMessage::RegistrationComplete(
            crate::messages::NasRegistrationComplete::new(),
        ));

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

        let inner = Nas5gsMessage::new_5gmm(crate::messages::Nas5gmmMessage::RegistrationComplete(
            crate::messages::NasRegistrationComplete::new(),
        ));

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

        let inner = Nas5gsMessage::new_5gmm(crate::messages::Nas5gmmMessage::RegistrationComplete(
            crate::messages::NasRegistrationComplete::new(),
        ));

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
            crate::messages::Nas5gsmMessage::PduSessionEstablishmentRequest(
                crate::messages::NasPduSessionEstablishmentRequest::new(
                    crate::NasIntegrityProtectionMaximumDataRate::from_rates(
                        crate::ie::MaxDataRate::FullRate,
                        crate::ie::MaxDataRate::FullRate,
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
            crate::messages::Nas5gmmMessage::RegistrationComplete(
                crate::messages::NasRegistrationComplete::new(),
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
}
