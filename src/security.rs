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
//! let wire = ctx.protect(&msg, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered, 0)?;
//!
//! // Unprotect (verify MAC + decipher + decode)
//! let (decoded, sht) = ctx.unprotect(&wire, 0)?;
//! ```

use crate::ie::{IntegrityAlgorithm, CipheringAlgorithm};
use crate::message_types::Nas5gsSecurityHeaderType;
use crate::messages::{encode_nas_5gs_message, Nas5gsMessage};
use crate::types::{NasError, Result, EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM};
use oxirush_security::{nas_mac, nas_cipher};

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
            bearer: 1,
        }
    }

    /// Protect an outbound NAS message (uplink or downlink).
    ///
    /// 1. Encodes the inner message to bytes
    /// 2. Optionally ciphers the payload (for SHT 0x02 and 0x04)
    /// 3. Computes MAC over [SN || payload]
    /// 4. Assembles the security header: [EPD | SHT | MAC(4) | SN | payload]
    ///
    /// `direction`: 0 = uplink, 1 = downlink.
    ///
    /// The appropriate COUNT is incremented after each call.
    pub fn protect(
        &mut self,
        inner: &Nas5gsMessage,
        sht: Nas5gsSecurityHeaderType,
        direction: u8,
    ) -> Result<Vec<u8>> {
        let inner_bytes = encode_nas_5gs_message(inner)?;
        self.protect_bytes(inner_bytes, sht, direction)
    }

    /// Protect raw NAS bytes that are already encoded.
    ///
    /// Useful when you need to protect a pre-encoded PDU.
    pub fn protect_bytes(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: Nas5gsSecurityHeaderType,
        direction: u8,
    ) -> Result<Vec<u8>> {
        let count = if direction == 0 { &mut self.ul_count } else { &mut self.dl_count };
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
        if should_cipher {
            nas_cipher(
                &self.knas_enc,
                current_count,
                self.bearer,
                direction,
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
            direction,
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
    /// `direction`: 0 = uplink (from UE), 1 = downlink (from network).
    ///
    /// On success, returns `(decoded_message, security_header_type)`.
    /// The appropriate COUNT is incremented only on MAC verification success.
    pub fn unprotect(
        &mut self,
        data: &[u8],
        direction: u8,
    ) -> Result<(Nas5gsMessage, Nas5gsSecurityHeaderType)> {
        if data.len() < 7 {
            return Err(NasError::BufferTooShort);
        }

        let _epd = data[0];
        let sht_byte = data[1];
        let sht = Nas5gsSecurityHeaderType::try_from(sht_byte)?;

        if sht == Nas5gsSecurityHeaderType::PlainNasMessage {
            return Err(NasError::DecodingError("Not a security-protected message".into()));
        }

        let received_mac = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let _sn = data[6];
        let payload = &data[7..];

        let count = if direction == 0 { &mut self.ul_count } else { &mut self.dl_count };
        let current_count = *count;

        // Verify MAC over [SN || payload]
        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(data[6]); // SN
        mac_input.extend_from_slice(payload);
        let expected_mac = nas_mac(
            &self.knas_int,
            current_count,
            self.bearer,
            direction,
            &mac_input,
            self.integrity_algo as u8,
        );

        if received_mac != expected_mac {
            return Err(NasError::DecodingError(format!(
                "MAC verification failed: received {:#010x}, expected {:#010x}",
                received_mac, expected_mac
            )));
        }

        *count += 1;

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
                current_count,
                self.bearer,
                direction,
                &mut decrypted,
                self.ciphering_algo as u8,
            );
        }

        // Decode inner plain NAS message
        let inner = crate::messages::decode_nas_5gs_message(&decrypted)?;
        Ok((inner, sht))
    }

    /// Unprotect and return raw decrypted bytes without decoding.
    ///
    /// Useful when you need the raw bytes for further processing (e.g.,
    /// re-encoding into a NAS message container).
    pub fn unprotect_raw(
        &mut self,
        data: &[u8],
        direction: u8,
    ) -> Result<(Vec<u8>, Nas5gsSecurityHeaderType)> {
        if data.len() < 7 {
            return Err(NasError::BufferTooShort);
        }

        let sht_byte = data[1];
        let sht = Nas5gsSecurityHeaderType::try_from(sht_byte)?;

        if sht == Nas5gsSecurityHeaderType::PlainNasMessage {
            return Err(NasError::DecodingError("Not a security-protected message".into()));
        }

        let received_mac = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let payload = &data[7..];

        let count = if direction == 0 { &mut self.ul_count } else { &mut self.dl_count };
        let current_count = *count;

        let mut mac_input = Vec::with_capacity(1 + payload.len());
        mac_input.push(data[6]);
        mac_input.extend_from_slice(payload);
        let expected_mac = nas_mac(
            &self.knas_int,
            current_count,
            self.bearer,
            direction,
            &mac_input,
            self.integrity_algo as u8,
        );

        if received_mac != expected_mac {
            return Err(NasError::DecodingError(format!(
                "MAC verification failed: received {:#010x}, expected {:#010x}",
                received_mac, expected_mac
            )));
        }

        *count += 1;

        let should_cipher = matches!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
            | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
        );

        let mut decrypted = payload.to_vec();
        if should_cipher {
            nas_cipher(
                &self.knas_enc,
                current_count,
                self.bearer,
                direction,
                &mut decrypted,
                self.ciphering_algo as u8,
            );
        }

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

        let mut tx = NasSecurityContext::new(key_int, key_enc, IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
        let mut rx = NasSecurityContext::new(key_int, key_enc, IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);

        // Build a simple RegistrationComplete message
        let inner = Nas5gsMessage::new_5gmm(
            crate::message_types::Nas5gmmMessageType::RegistrationComplete,
            crate::messages::Nas5gmmMessage::RegistrationComplete(
                crate::messages::NasRegistrationComplete::new(),
            ),
        );

        // Protect (UL direction=0) with integrity only
        let protected = tx.protect(
            &inner,
            Nas5gsSecurityHeaderType::IntegrityProtected,
            0,
        ).unwrap();

        assert!(protected.len() > 7);
        assert_eq!(protected[0], 0x7E); // EPD
        assert_eq!(protected[1], 0x01); // SHT = IntegrityProtected

        // Unprotect (UL direction=0)
        let (decoded, sht) = rx.unprotect(&protected, 0).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtected);

        // Verify counts advanced
        assert_eq!(tx.ul_count, 1);
        assert_eq!(rx.ul_count, 1);
    }

    #[test]
    fn test_protect_unprotect_roundtrip_ciphered() {
        let key_int = [0xABu8; 16];
        let key_enc = [0xCDu8; 16];

        let mut tx = NasSecurityContext::new(key_int, key_enc, IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
        let mut rx = NasSecurityContext::new(key_int, key_enc, IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);

        let inner = Nas5gsMessage::new_5gmm(
            crate::message_types::Nas5gmmMessageType::RegistrationComplete,
            crate::messages::Nas5gmmMessage::RegistrationComplete(
                crate::messages::NasRegistrationComplete::new(),
            ),
        );

        let protected = tx.protect(
            &inner,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
            1, // DL
        ).unwrap();

        assert_eq!(protected[1], 0x02); // SHT = IntegrityProtectedAndCiphered

        let (decoded, sht) = rx.unprotect(&protected, 1).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered);
        assert_eq!(tx.dl_count, 1);
        assert_eq!(rx.dl_count, 1);
    }

    #[test]
    fn test_mac_failure_rejects() {
        let key_int = [0x01u8; 16];
        let key_enc = [0x02u8; 16];

        let mut tx = NasSecurityContext::new(key_int, key_enc, IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
        let mut rx = NasSecurityContext::new([0xFFu8; 16], key_enc, IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2); // Different key!

        let inner = Nas5gsMessage::new_5gmm(
            crate::message_types::Nas5gmmMessageType::RegistrationComplete,
            crate::messages::Nas5gmmMessage::RegistrationComplete(
                crate::messages::NasRegistrationComplete::new(),
            ),
        );

        let protected = tx.protect(
            &inner,
            Nas5gsSecurityHeaderType::IntegrityProtected,
            0,
        ).unwrap();

        let result = rx.unprotect(&protected, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("MAC verification failed"));
        // COUNT should NOT advance on failure
        assert_eq!(rx.ul_count, 0);
    }
}
