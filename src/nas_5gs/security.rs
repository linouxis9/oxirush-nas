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

//! NAS security envelope — integrity protection and ciphering.
//!
//! This module provides [`NasSecurityContext`] which wraps NAS keys and algorithms
//! to protect outbound messages and unprotect (verify + decipher) inbound messages
//! per TS 33.501 &sect;6.4.3.
//!
//! Requires the `security` feature flag:
//! ```toml
//! oxirush-nas = { version = "0.5", features = ["security"] }
//! ```
//!
//! A protected message is under a security header with a message
//! authentication code (MAC), and may be ciphered. A context has the NAS
//! keys, the algorithms and the next NAS COUNT of each direction, and in 5GS
//! of each access: the COUNT numbers the messages of a direction, and goes
//! into each code so that a message is not accepted twice. The keys come
//! from KAMF in 5GS and from KASME in EPS, the key that the UE and the
//! network share after authentication.
//!
//! `from_fresh_*` starts every COUNT at zero, so it is only for keys that were
//! just established (TS 33.501 §6.4.5, TS 33.401 §6.5). After a restart,
//! `restore_from_*` takes the next COUNT values, which the caller persisted.
//! Under an existing KAMF or KASME, `reselect_algorithms` changes the algorithms
//! and keeps the COUNTs. A context is not `Clone`: the two below are the two
//! ends of one link.
//!
//! A context is made of algorithms that exist: a reserved code, and the null
//! integrity algorithm with another cipher than the null one, are errors. A
//! COUNT is a [`NasCount`] and a 5GS access a [`NasConnection`], both of
//! [oxirush-security](https://github.com/linouxis9/oxirush-security) and
//! re-exported by the `security` modules; the next COUNT of a direction is
//! `None` once all its COUNTs were used.
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::nas_5gs::ie::{CipheringAlgorithm, IntegrityAlgorithm};
//! use oxirush_nas::nas_5gs::{
//!     Direction, Nas5gsMessage, Nas5gsSecurityHeaderType, NasSecurityContext,
//! };
//!
//! // REGISTRATION REJECT, cause #3
//! let msg = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();
//!
//! // The two ends of one link: the same keys and the same algorithms
//! let (knas_int, knas_enc) = ([0u8; 16], [0u8; 16]);
//! let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
//! let mut tx = NasSecurityContext::from_fresh_keys(knas_int, knas_enc, nia, nea).unwrap();
//! let mut rx = NasSecurityContext::from_fresh_keys(knas_int, knas_enc, nia, nea).unwrap();
//!
//! // Protect outbound: integrity and ciphering
//! let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
//! let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();
//!
//! // Unprotect inbound: MAC check, deciphering and decoding
//! let (decoded, header_type) = rx.unprotect(&protected, Direction::Downlink).unwrap();
//! assert_eq!((decoded, header_type), (msg, sht));
//! ```
//!
//! `protect` and `protect_bytes` validate the inner message. For negative tests,
//! `protect_opaque_payload` ciphers and integrity-protects any inner octets
//! under security header types 1 to 4.

pub use crate::common::{Direction, estimate_nas_count};
use crate::nas_5gs::ie::{AccessTypeValue, CipheringAlgorithm, IntegrityAlgorithm};
use crate::nas_5gs::message_types::Nas5gsSecurityHeaderType;
use crate::nas_5gs::messages::{
    Nas5gmmMessage, Nas5gsMessage, validate_security_protected_inner_message,
};
use crate::nas_5gs::types::{EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, NasError, Result};
use crate::prelude::*;
use oxirush_security::constant_time_eq;
pub use oxirush_security::nas_5gs::{NasConnection, NasCount};
use oxirush_security::nas_5gs::{nas_cipher, nas_mac};

/// The integrity algorithm of the security crate that a code of TS 24.501
/// Table 9.11.3.34.1 selects: the codes 4 to 7 are reserved, and no algorithm.
impl TryFrom<IntegrityAlgorithm> for oxirush_security::IntegrityAlgorithm {
    type Error = NasError;

    fn try_from(algorithm: IntegrityAlgorithm) -> Result<Self> {
        Self::try_from(algorithm as u8).map_err(|_| {
            NasError::EncodingError(format!(
                "{algorithm:?} is a reserved 5GS integrity algorithm: no key and no code are computed with it"
            ))
        })
    }
}

/// The ciphering algorithm of the security crate that a code of TS 24.501
/// Table 9.11.3.34.1 selects: the codes 4 to 7 are reserved, and no algorithm.
impl TryFrom<CipheringAlgorithm> for oxirush_security::CipheringAlgorithm {
    type Error = NasError;

    fn try_from(algorithm: CipheringAlgorithm) -> Result<Self> {
        Self::try_from(algorithm as u8).map_err(|_| {
            NasError::EncodingError(format!(
                "{algorithm:?} is a reserved 5GS ciphering algorithm: no key is derived and nothing is ciphered with it"
            ))
        })
    }
}

/// The first value of a NAS COUNT that no message is protected with: a
/// COUNT of a context that holds it is exhausted.
const EXHAUSTED: u32 = 0x0100_0000;

/// The NAS COUNT `count` of a message, unless the COUNTs are exhausted.
fn nas_count(count: u32, error: fn(String) -> NasError) -> Result<NasCount> {
    NasCount::new(count).map_err(|_| error("5GS NAS COUNT exhausted".into()))
}

/// The next COUNT of a context as it is kept: `None` is one that is
/// exhausted.
fn next_count(count: Option<NasCount>) -> u32 {
    count.map_or(EXHAUSTED, NasCount::get)
}

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
    match required_direction {
        Some(required) if required != direction => Err(NasError::EncodingError(format!(
            "{:?} requires {required:?} direction",
            inner.message_type()
        ))),
        _ => Ok(()),
    }
}

impl From<AccessTypeValue> for NasConnection {
    /// The NAS connection of an access type: a security context keeps a
    /// pair of NAS COUNTs for each (TS 24.501 §4.4.3).
    fn from(value: AccessTypeValue) -> Self {
        match value {
            AccessTypeValue::ThreeGpp => Self::ThreeGpp,
            AccessTypeValue::Non3Gpp => Self::Non3Gpp,
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
    /// Integrity algorithm, as it was selected.
    integrity_algo: IntegrityAlgorithm,
    /// Ciphering algorithm, as it was selected.
    ciphering_algo: CipheringAlgorithm,
    /// The algorithms that the two codes select.
    integrity: oxirush_security::IntegrityAlgorithm,
    ciphering: oxirush_security::CipheringAlgorithm,
    /// Next uplink NAS COUNT to use (UE) or to expect (AMF).
    ul_count: u32,
    /// Next downlink NAS COUNT to expect (UE) or to use (AMF).
    dl_count: u32,
    /// NAS uplink COUNT for non-3GPP access.
    ul_count_non_3gpp: u32,
    /// NAS downlink COUNT for non-3GPP access.
    dl_count_non_3gpp: u32,
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
    /// The algorithms of the security crate that the two codes select. A
    /// reserved code selects none, and NIA0 is only used for unauthenticated
    /// emergency sessions, which select NEA0 (TS 33.501 §5.2.3 and §10.2.2).
    fn algorithms(
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<(
        oxirush_security::IntegrityAlgorithm,
        oxirush_security::CipheringAlgorithm,
    )> {
        let algorithms = (integrity_algo.try_into()?, ciphering_algo.try_into()?);
        if integrity_algo == IntegrityAlgorithm::NIA0 && ciphering_algo != CipheringAlgorithm::NEA0
        {
            return Err(NasError::EncodingError("5GS NIA0 requires NEA0".into()));
        }
        Ok(algorithms)
    }

    fn advance_count(&mut self, direction: Direction, connection: NasConnection, count: u32) {
        *self.count_mut(direction, connection) = if self.integrity_algo == IntegrityAlgorithm::NIA0
        {
            (count + 1) & 0x00ff_ffff
        } else {
            count + 1
        };
    }

    /// Create a context for genuinely fresh NAS keys with COUNT values at zero.
    ///
    /// Reusing the same keys with this constructor violates TS 33.501 §6.4.5;
    /// use [`Self::reselect_algorithms`] for an existing KAMF. A reserved
    /// algorithm (the codes 4 to 7) and NIA0 with another cipher than NEA0
    /// are errors.
    pub fn from_fresh_keys(
        knas_int: [u8; 16],
        knas_enc: [u8; 16],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        let (integrity, ciphering) = Self::algorithms(integrity_algo, ciphering_algo)?;
        Ok(Self {
            knas_int,
            knas_enc,
            integrity_algo,
            ciphering_algo,
            integrity,
            ciphering,
            ul_count: 0,
            dl_count: 0,
            ul_count_non_3gpp: 0,
            dl_count_non_3gpp: 0,
        })
    }

    /// Derive a fresh 5GS NAS context from a newly established KAMF.
    ///
    /// COUNT starts at zero. Calling this again for the same KAMF would violate
    /// TS 33.501 §6.4.5; use [`Self::reselect_algorithms`] instead. The
    /// algorithms are checked as [`Self::from_fresh_keys`] checks them.
    pub fn from_fresh_kamf(
        kamf: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        use oxirush_security::nas_5gs::{derive_knas_enc, derive_knas_int};
        let (integrity, ciphering) = Self::algorithms(integrity_algo, ciphering_algo)?;
        let knas_int = zeroize::Zeroizing::new(derive_knas_int(kamf, integrity));
        let knas_enc = zeroize::Zeroizing::new(derive_knas_enc(kamf, ciphering));
        Self::from_fresh_keys(*knas_int, *knas_enc, integrity_algo, ciphering_algo)
    }

    /// Selected integrity algorithm.
    pub fn integrity_algorithm(&self) -> IntegrityAlgorithm {
        self.integrity_algo
    }

    /// Selected ciphering algorithm.
    pub fn ciphering_algorithm(&self) -> CipheringAlgorithm {
        self.ciphering_algo
    }

    /// Next NAS COUNT to use or expect for a direction and access type:
    /// `None` when every COUNT of the direction was used, after which the
    /// context protects nothing more in it.
    pub fn nas_count(&self, direction: Direction, connection: NasConnection) -> Option<NasCount> {
        NasCount::new(*self.count_ref(direction, connection)).ok()
    }

    /// Restore a 5GS context and its next COUNT values from persistent state.
    ///
    /// The caller must supply the counts stored for this exact KAMF, as
    /// [`Self::nas_count`] gave them: the uplink then the downlink COUNT of
    /// each access, `None` for one that is exhausted. Passing zero for a KAMF
    /// that has already protected traffic violates TS 33.501 §6.4.5.
    pub fn restore_from_kamf(
        kamf: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
        three_gpp_counts: (Option<NasCount>, Option<NasCount>),
        non_3gpp_counts: (Option<NasCount>, Option<NasCount>),
    ) -> Result<Self> {
        let mut context = Self::from_fresh_kamf(kamf, integrity_algo, ciphering_algo)?;
        context.ul_count = next_count(three_gpp_counts.0);
        context.dl_count = next_count(three_gpp_counts.1);
        context.ul_count_non_3gpp = next_count(non_3gpp_counts.0);
        context.dl_count_non_3gpp = next_count(non_3gpp_counts.1);
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

        let replacement = Self::from_fresh_kamf(kamf, integrity_algo, ciphering_algo)?;
        self.knas_int.zeroize();
        self.knas_enc.zeroize();
        self.knas_int = replacement.knas_int;
        self.knas_enc = replacement.knas_enc;
        self.integrity_algo = integrity_algo;
        self.ciphering_algo = ciphering_algo;
        self.integrity = replacement.integrity;
        self.ciphering = replacement.ciphering;
        Ok(())
    }

    /// Map an EPS KASME to a 5GS context for idle mobility.
    ///
    /// `tau_ul_nas_count` protects the EPS mobility-triggering message. The
    /// mapped 5GS NAS COUNT values start at zero. The mapped ngKSI is handled
    /// by the enclosing mobility procedure.
    pub fn from_mapped_kamf_idle(
        kasme: &[u8; 32],
        tau_ul_nas_count: NasCount,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        let kamf = zeroize::Zeroizing::new(oxirush_security::nas_eps::derive_mapped_kamf_idle(
            kasme,
            tau_ul_nas_count,
        ));
        Self::from_fresh_kamf(&kamf, integrity_algo, ciphering_algo)
    }

    /// Map an EPS KASME to a 5GS context for connected handover using NH.
    /// The mapped 5GS NAS COUNT values start at zero. This derivation has no
    /// COUNT input.
    pub fn from_mapped_kamf_handover(
        kasme: &[u8; 32],
        nh: &[u8; 32],
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        let kamf = zeroize::Zeroizing::new(oxirush_security::nas_eps::derive_mapped_kamf_handover(
            kasme, nh,
        ));
        Self::from_fresh_kamf(&kamf, integrity_algo, ciphering_algo)
    }

    fn count_ref(&self, direction: Direction, connection: NasConnection) -> &u32 {
        match (direction, connection) {
            (Direction::Uplink, NasConnection::ThreeGpp) => &self.ul_count,
            (Direction::Downlink, NasConnection::ThreeGpp) => &self.dl_count,
            (Direction::Uplink, NasConnection::Non3Gpp) => &self.ul_count_non_3gpp,
            (Direction::Downlink, NasConnection::Non3Gpp) => &self.dl_count_non_3gpp,
        }
    }

    fn count_mut(&mut self, direction: Direction, connection: NasConnection) -> &mut u32 {
        match (direction, connection) {
            (Direction::Uplink, NasConnection::ThreeGpp) => &mut self.ul_count,
            (Direction::Downlink, NasConnection::ThreeGpp) => &mut self.dl_count,
            (Direction::Uplink, NasConnection::Non3Gpp) => &mut self.ul_count_non_3gpp,
            (Direction::Downlink, NasConnection::Non3Gpp) => &mut self.dl_count_non_3gpp,
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
        self.protect_for_access(inner, sht, direction, NasConnection::ThreeGpp)
    }

    /// Protect an outbound NAS message for a specific access type.
    pub fn protect_for_access(
        &mut self,
        inner: &Nas5gsMessage,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        validate_security_protected_inner_message(inner, sht)?;
        let inner_bytes = inner.encode()?;
        self.protect_bytes_for_access(inner_bytes, sht, direction, connection)
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
        self.protect_bytes_for_access(inner_bytes, sht, direction, NasConnection::ThreeGpp)
    }

    /// Protect raw NAS bytes that are already encoded for a specific access.
    pub fn protect_bytes_for_access(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        let decoded = Nas5gsMessage::decode(&inner_bytes)?;
        validate_security_protected_inner_message(&decoded, sht)?;
        validate_message_direction(&decoded, direction)?;

        self.protect_envelope(inner_bytes, sht, direction, connection)
    }

    /// Protect explicitly opaque or malformed inner bytes without codec checks.
    ///
    /// Only regular security headers 1 through 4 are supported. The payload is
    /// not decoded or re-encoded, so its message direction and header pairing
    /// are deliberately unchecked. Existing keys and COUNT are used even for
    /// a new-context header; no keys are installed and no COUNT is reset.
    /// COUNT advances once after successful composition. Checked receivers may
    /// reject the authenticated inner payload.
    pub fn protect_opaque_payload(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        self.protect_opaque_payload_for_access(inner_bytes, sht, direction, NasConnection::ThreeGpp)
    }

    /// Protect opaque inner bytes with the COUNT and bearer of a specific access.
    pub fn protect_opaque_payload_for_access(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        if !matches!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtected
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                | Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
        ) {
            return Err(NasError::EncodingError(
                "Opaque 5GS protection requires a regular security header type".into(),
            ));
        }
        self.protect_envelope(inner_bytes, sht, direction, connection)
    }

    fn protect_envelope(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        let current_count = *self.count_ref(direction, connection);
        let count = nas_count(current_count, NasError::EncodingError)?;
        let sn = count.sequence_number();

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
                count,
                connection,
                direction.into(),
                &mut payload,
                self.ciphering,
            );
        }

        // Assemble: [EPD=0x7e | SHT | MAC(4) | SN | ciphered_payload]
        let mut out = Vec::with_capacity(7 + payload.len());
        out.push(EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM);
        out.push(sht as u8);
        out.extend_from_slice(&[0; 4]);
        out.push(sn);
        out.extend_from_slice(&payload);

        // MAC input = [SN || ciphertext] per TS 33.501 §6.4.3.1: the octets
        // of the message after the code.
        let mac = nas_mac(
            &self.knas_int,
            count,
            connection,
            direction.into(),
            &out[6..],
            self.integrity,
        );
        out[2..6].copy_from_slice(&mac.to_be_bytes());
        self.advance_count(direction, connection, current_count);
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
    /// [`Nas5gsMessage::decode`],
    /// which returns the unverified inner message when it is not ciphered.
    pub fn unprotect(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<(Nas5gsMessage, Nas5gsSecurityHeaderType)> {
        self.unprotect_for_access(data, direction, NasConnection::ThreeGpp)
    }

    /// Unprotect an inbound security-protected NAS message for a specific access.
    pub fn unprotect_for_access(
        &mut self,
        data: &[u8],
        direction: Direction,
        connection: NasConnection,
    ) -> Result<(Nas5gsMessage, Nas5gsSecurityHeaderType)> {
        let (_, message, sht) = self.unprotect_checked(data, direction, connection)?;
        Ok((message, sht))
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
        self.unprotect_raw_for_access(data, direction, NasConnection::ThreeGpp)
    }

    /// Unprotect and return raw decrypted bytes for a specific access type.
    pub fn unprotect_raw_for_access(
        &mut self,
        data: &[u8],
        direction: Direction,
        connection: NasConnection,
    ) -> Result<(Vec<u8>, Nas5gsSecurityHeaderType)> {
        let (plain, _, sht) = self.unprotect_checked(data, direction, connection)?;
        Ok((plain, sht))
    }

    /// The plain octets of a protected message and the message they are,
    /// which is decoded once to check it.
    fn unprotect_checked(
        &mut self,
        data: &[u8],
        direction: Direction,
        connection: NasConnection,
    ) -> Result<(Vec<u8>, Nas5gsMessage, Nas5gsSecurityHeaderType)> {
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

        let stored_count = *self.count_ref(direction, connection);
        let mut estimated_count = crate::common::estimate_count(stored_count, sequence_number);
        if self.integrity_algo == IntegrityAlgorithm::NIA0 {
            estimated_count &= 0x00ff_ffff;
        } else if estimated_count < stored_count || estimated_count > 0x00ff_ffff {
            return Err(NasError::DecodingError(
                "5GS NAS COUNT replay or exhaustion".into(),
            ));
        }
        let count = nas_count(estimated_count, NasError::DecodingError)?;

        // The code is that of the sequence number and of what follows it.
        let expected_mac = nas_mac(
            &self.knas_int,
            count,
            connection,
            direction.into(),
            &data[6..],
            self.integrity,
        );

        if self.integrity_algo != IntegrityAlgorithm::NIA0
            && !constant_time_eq(&received_mac.to_be_bytes(), &expected_mac.to_be_bytes())
        {
            // The expected MAC is not reported: it would let an observer of the
            // error resend the same bytes with a valid MAC.
            return Err(NasError::IntegrityCheckFailed);
        }

        // TS 24.501 §4.4.3.3 commits the received NAS COUNT after successful
        // integrity verification. Inner syntax, header-pairing, and direction
        // checks must not make an authenticated COUNT reusable.
        self.advance_count(direction, connection, estimated_count);

        let should_cipher = matches!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
        );

        let mut decrypted = payload.to_vec();
        if should_cipher {
            nas_cipher(
                &self.knas_enc,
                count,
                connection,
                direction.into(),
                &mut decrypted,
                self.ciphering,
            );
        }

        let decoded = Nas5gsMessage::decode(&decrypted)?;
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

        Ok((decrypted, decoded, sht))
    }

    /// Integrity protect a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE
    /// REQUEST with this 5G NAS security context, as a UE does when it moves
    /// from 5GS to EPS (TS 33.501 §8.5.2 step 1, TS 24.301 §4.4.2.3). The
    /// PDU has the EPS security header with SHT 0001; the MAC uses KNASint,
    /// the 5G uplink NAS COUNT, and the 3GPP NAS connection identifier. The
    /// uplink COUNT advances.
    pub fn protect_eps_message(&mut self, eps_plain: &[u8]) -> Result<Vec<u8>> {
        check_eps_mobility_request(eps_plain)?;
        let current_count = self.ul_count;
        let count = nas_count(current_count, NasError::EncodingError)?;
        let mut mac_input = Vec::with_capacity(1 + eps_plain.len());
        mac_input.push(count.sequence_number());
        mac_input.extend_from_slice(eps_plain);
        let mac = nas_mac(
            &self.knas_int,
            count,
            NasConnection::ThreeGpp,
            Direction::Uplink.into(),
            &mac_input,
            self.integrity,
        );
        let mut out = Vec::with_capacity(6 + eps_plain.len());
        out.push(0x17);
        out.extend_from_slice(&mac.to_be_bytes());
        out.extend_from_slice(&mac_input);
        self.advance_count(Direction::Uplink, NasConnection::ThreeGpp, current_count);
        Ok(out)
    }

    /// Verify an EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST that the
    /// UE protected with this 5G context, "as if it was a 5G NAS message
    /// received over 3GPP access" (TS 33.501 §8.5.2 step 4). Returns the plain
    /// EPS message; the uplink COUNT advances.
    pub fn unprotect_eps_message(&mut self, pdu: &[u8]) -> Result<Vec<u8>> {
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
            nas_count(count & 0x00ff_ffff, NasError::DecodingError)?,
            NasConnection::ThreeGpp,
            Direction::Uplink.into(),
            &pdu[5..],
            self.integrity,
        );
        if self.integrity_algo != IntegrityAlgorithm::NIA0
            && !constant_time_eq(&[*a, *b, *c, *d], &expected_mac.to_be_bytes())
        {
            return Err(NasError::IntegrityCheckFailed);
        }
        self.advance_count(Direction::Uplink, NasConnection::ThreeGpp, count);
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
    use oxirush_security::CipheringAlgorithm as Nea;
    use oxirush_security::IntegrityAlgorithm as Nia;

    /// A NAS COUNT of a message.
    fn count(count: u32) -> NasCount {
        NasCount::new(count).unwrap()
    }

    #[test]
    fn opaque_payload_preserves_malformed_bytes_and_authenticates_all_regular_headers() {
        let inner = vec![0x7e, 0x00, 0xff, 0x20, 0x02, 0xbb, 0xaa, 0x20, 0x01, 0xcc];
        for access in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
            for direction in [Direction::Uplink, Direction::Downlink] {
                for sht in [
                    Nas5gsSecurityHeaderType::IntegrityProtected,
                    Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                    Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
                    Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext,
                ] {
                    let mut sender = NasSecurityContext::from_fresh_keys(
                        [0x29; 16],
                        [0x37; 16],
                        IntegrityAlgorithm::NIA2,
                        CipheringAlgorithm::NEA2,
                    )
                    .unwrap();
                    *sender.count_mut(direction, access) = 0x1234;
                    assert!(
                        sender
                            .protect_bytes_for_access(inner.clone(), sht, direction, access)
                            .is_err()
                    );
                    assert_eq!(*sender.count_ref(direction, access), 0x1234);
                    let mut receiver = sender.clone();
                    let mut tampered_receiver = receiver.clone();
                    let wire = sender
                        .protect_opaque_payload_for_access(inner.clone(), sht, direction, access)
                        .unwrap();
                    let mut payload = inner.clone();
                    if matches!(sht as u8, 2 | 4) {
                        nas_cipher(
                            &[0x37; 16],
                            count(0x1234),
                            access,
                            direction.into(),
                            &mut payload,
                            Nea::NEA2,
                        );
                    }
                    assert_eq!(&wire[..2], &[0x7e, sht as u8]);
                    assert_eq!(wire[6], 0x34);
                    assert_eq!(&wire[7..], payload);
                    let mac = nas_mac(
                        &[0x29; 16],
                        count(0x1234),
                        access,
                        direction.into(),
                        &wire[6..],
                        Nia::NIA2,
                    );
                    assert_eq!(&wire[2..6], mac.to_be_bytes());
                    if matches!(sht as u8, 2 | 4) {
                        nas_cipher(
                            &[0x37; 16],
                            count(0x1234),
                            access,
                            direction.into(),
                            &mut payload,
                            Nea::NEA2,
                        );
                    }
                    assert_eq!(payload, inner);
                    assert_eq!(*sender.count_ref(direction, access), 0x1235);
                    assert_eq!(sender.knas_int, [0x29; 16]);
                    assert_eq!(sender.knas_enc, [0x37; 16]);
                    for other_direction in [Direction::Uplink, Direction::Downlink] {
                        for other_access in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
                            if (other_direction, other_access) != (direction, access) {
                                assert_eq!(*sender.count_ref(other_direction, other_access), 0);
                            }
                        }
                    }
                    let mut tampered = wire.clone();
                    tampered[2] ^= 1;
                    assert!(matches!(
                        tampered_receiver.unprotect_raw_for_access(&tampered, direction, access),
                        Err(NasError::IntegrityCheckFailed)
                    ));
                    assert_eq!(*tampered_receiver.count_ref(direction, access), 0x1234);
                    assert!(matches!(
                        receiver.unprotect_raw_for_access(&wire, direction, access),
                        Err(NasError::UnknownMessageType(0xff))
                    ));
                    assert_eq!(*receiver.count_ref(direction, access), 0x1235);
                }
            }
        }
    }

    #[test]
    fn opaque_payload_matches_checked_protection_without_relaxing_checked_headers_or_direction() {
        let inner = vec![0x7e, 0x00, 0x43]; // REGISTRATION COMPLETE.
        let mut sender = NasSecurityContext::from_fresh_keys(
            [0x29; 16],
            [0x37; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let mut receiver = sender.clone();
        for sht in [
            Nas5gsSecurityHeaderType::IntegrityProtected,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
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
        for (sht, direction) in [
            (
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Downlink,
            ),
            (
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
                Direction::Uplink,
            ),
        ] {
            assert!(sender.protect_bytes(inner.clone(), sht, direction).is_err());
        }
        assert_eq!((sender.ul_count, sender.dl_count), (2, 0));
    }

    #[test]
    fn opaque_payload_rejects_envelope_errors_without_consuming_count() {
        let mut sender = NasSecurityContext::from_fresh_keys(
            [0x29; 16],
            [0x37; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
        assert!(
            sender
                .protect_opaque_payload(
                    vec![0xff],
                    Nas5gsSecurityHeaderType::PlainNasMessage,
                    Direction::Uplink
                )
                .is_err()
        );
        assert_eq!(sender.ul_count, 0);
        // A reserved algorithm, and NIA0 with a cipher, make no context.
        for (integrity, ciphering) in [
            (IntegrityAlgorithm::NIA7, CipheringAlgorithm::NEA2),
            (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA7),
            (IntegrityAlgorithm::NIA0, CipheringAlgorithm::NEA2),
        ] {
            let context =
                NasSecurityContext::from_fresh_keys([0x29; 16], [0x37; 16], integrity, ciphering);
            assert!(context.is_err(), "{integrity:?} {ciphering:?}");
        }
        for access in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
            for direction in [Direction::Uplink, Direction::Downlink] {
                *sender.count_mut(direction, access) = 0x00ff_ffff;
                let wire = sender
                    .protect_opaque_payload_for_access(Vec::new(), sht, direction, access)
                    .unwrap();
                assert_eq!(wire.len(), 7);
                assert_eq!(wire[6], 0xff);
                let mac = nas_mac(
                    &[0x29; 16],
                    NasCount::MAX,
                    access,
                    direction.into(),
                    &wire[6..],
                    Nia::NIA2,
                );
                assert_eq!(&wire[2..6], mac.to_be_bytes());
                assert_eq!(*sender.count_ref(direction, access), 0x0100_0000);
                assert!(
                    sender
                        .protect_opaque_payload_for_access(vec![0xff], sht, direction, access)
                        .is_err()
                );
                assert_eq!(*sender.count_ref(direction, access), 0x0100_0000);
            }
        }
    }

    #[test]
    fn eps_mobility_request_is_protected_with_the_5g_context() {
        let mut ue = NasSecurityContext::from_fresh_keys(
            [0x21; 16],
            [0x22; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA0,
        )
        .unwrap();
        ue.ul_count = 0x0102;
        let mut amf = ue.clone();
        // A TAU REQUEST: update type, KSI, and old GUTI are enough here.
        let tau = [
            0x07, 0x48, 0x00, 0x0b, 0xf6, 0x02, 0xf8, 0x39, 0x80, 0x01, 0x01, 0, 0, 0, 1,
        ];
        let pdu = ue.protect_eps_message(&tau).unwrap();
        assert_eq!((pdu[0], pdu[5]), (0x17, 0x02));
        let expected = nas_mac(
            &[0x21; 16],
            count(0x0102),
            NasConnection::ThreeGpp,
            Direction::Uplink.into(),
            &pdu[5..],
            Nia::NIA2,
        );
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
        )
        .unwrap();
        let mut invalid_receiver = invalid_sender.clone();
        let invalid_plain = [0x07, 0x43, 0x00, 0x00];
        let mut invalid_pdu = vec![0x17];
        let mac_input = [&[0][..], &invalid_plain].concat();
        let mac = nas_mac(
            &[0x21; 16],
            NasCount::ZERO,
            NasConnection::ThreeGpp,
            Direction::Uplink.into(),
            &mac_input,
            Nia::NIA2,
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
        let command =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasSecurityModeCommand::new(
                crate::nas_5gs::types::NasSecurityAlgorithms::from_algorithms(
                    CipheringAlgorithm::NEA0,
                    IntegrityAlgorithm::NIA0,
                ),
                crate::nas_5gs::types::NasKeySetIdentifier::new(0),
                crate::nas_5gs::types::NasUeSecurityCapability::new(vec![0, 0]),
            ));
        let complete =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasSecurityModeComplete::new());
        let mut tx = NasSecurityContext::from_fresh_keys(
            [0; 16],
            [0; 16],
            IntegrityAlgorithm::NIA0,
            CipheringAlgorithm::NEA0,
        )
        .unwrap();
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
            )
            .unwrap();
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
            count(0x1234),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        // A COUNT above 24 bits is no NAS COUNT.
        assert!(NasCount::new(0x0100_0000).is_err());
        let handover = NasSecurityContext::from_mapped_kamf_handover(
            &kasme,
            &nh,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
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
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();

        // Build a simple RegistrationComplete message
        let inner =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());

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
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();

        let inner =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasAuthenticationResult::new(
                crate::nas_5gs::types::NasKeySetIdentifier::new(0),
                crate::nas_5gs::types::NasEapMessage::new(vec![0x03, 0x01, 0x00, 0x04]),
            ));

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
        let uplink =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());
        let status = Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasFGmmStatus::new(
            crate::NasFGmmCause::new(0x6f),
        ));
        let context = || {
            NasSecurityContext::from_fresh_keys(
                [0x21; 16],
                [0x43; 16],
                IntegrityAlgorithm::NIA2,
                CipheringAlgorithm::NEA2,
            )
            .unwrap()
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
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();

        let smc = crate::nas_5gs::messages::NasSecurityModeCommand::new(
            crate::nas_5gs::types::NasSecurityAlgorithms::from_algorithms(
                CipheringAlgorithm::NEA2,
                IntegrityAlgorithm::NIA2,
            ),
            crate::nas_5gs::types::NasKeySetIdentifier::new(0),
            crate::nas_5gs::types::NasUeSecurityCapability::new(vec![0xE0, 0xE0]),
        )
        .set_abba(crate::nas_5gs::types::NasAbba::new(vec![0x00, 0x00]));
        let inner = Nas5gsMessage::new_5gmm(smc);
        let plain = inner.encode().unwrap();

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
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            [0xFFu8; 16],
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap(); // Different key!

        let inner =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());

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
        assert!(error.contains("message authentication code does not match"));
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
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();

        let inner =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());

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
        let message =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());
        let keys = ([0; 16], [0; 16]);
        let context = |nea| {
            NasSecurityContext::from_fresh_keys(keys.0, keys.1, IntegrityAlgorithm::NIA0, nea)
        };
        assert!(context(CipheringAlgorithm::NEA2).is_err());
        assert!(context(CipheringAlgorithm::NEA0).is_ok());
        let kamf = [0x24; 32];
        let derived =
            |nea| NasSecurityContext::from_fresh_kamf(&kamf, IntegrityAlgorithm::NIA0, nea);
        assert!(derived(CipheringAlgorithm::NEA1).is_err());
        let mut null = derived(CipheringAlgorithm::NEA0).unwrap();
        assert!(
            null.reselect_algorithms(&kamf, IntegrityAlgorithm::NIA0, CipheringAlgorithm::NEA3)
                .is_err()
        );
        // A context that refuses its new algorithms keeps those it had.
        assert_eq!(null.ciphering_algorithm(), CipheringAlgorithm::NEA0);
        let wire = null
            .protect(
                &message,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(&wire[2..6], [0; 4]);
    }

    #[test]
    fn spare_half_octet_of_the_security_header_is_ignored() {
        // Octet 2 is "spare half octet | security header
        // type" (TS 24.501 Figure 9.1.1-2); the spare bits are outside the MAC.
        let context = || {
            NasSecurityContext::from_fresh_keys(
                [0x31; 16],
                [0x32; 16],
                IntegrityAlgorithm::NIA2,
                CipheringAlgorithm::NEA2,
            )
            .unwrap()
        };
        let message =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());
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
        let message =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());
        for (receiver_next, sender_count) in [(0x05, 0x90), (0x0105, 0x0190), (0x01f0, 0x0202)] {
            let context = || {
                NasSecurityContext::from_fresh_keys(
                    [0x31; 16],
                    [0x32; 16],
                    IntegrityAlgorithm::NIA2,
                    CipheringAlgorithm::NEA2,
                )
                .unwrap()
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
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            key_int,
            key_enc,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();

        let inner =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasAuthenticationResult::new(
                crate::nas_5gs::types::NasKeySetIdentifier::new(0),
                crate::nas_5gs::types::NasEapMessage::new(vec![0x03, 0x01, 0x00, 0x04]),
            ));

        let protected = tx
            .protect_for_access(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Downlink,
                NasConnection::Non3Gpp,
            )
            .unwrap();

        assert_eq!(tx.dl_count, 0);
        assert_eq!(tx.dl_count_non_3gpp, 1);

        let (_, _) = rx
            .unprotect_for_access(&protected, Direction::Downlink, NasConnection::Non3Gpp)
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
        )
        .unwrap();

        let inner = Nas5gsMessage::new_5gsm(
            crate::nas_5gs::messages::NasPduSessionEstablishmentRequest::new(
                crate::NasIntegrityProtectionMaximumDataRate::from_rates(
                    crate::nas_5gs::ie::MaxDataRate::FullRate,
                    crate::nas_5gs::ie::MaxDataRate::FullRate,
                ),
            ),
            1,
            1,
        )
        .encode()
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
            (Some(count(0x0012_3456)), Some(count(0x0000_abcd))),
            (Some(count(0x0000_1234)), None),
        )
        .unwrap();
        let old_keys = (context.knas_int, context.knas_enc);
        assert_eq!(
            context.nas_count(Direction::Uplink, NasConnection::ThreeGpp),
            Some(count(0x0012_3456))
        );
        assert_eq!(
            context.nas_count(Direction::Downlink, NasConnection::ThreeGpp),
            Some(count(0x0000_abcd))
        );
        assert_eq!(
            context.nas_count(Direction::Uplink, NasConnection::Non3Gpp),
            Some(count(0x0000_1234))
        );
        assert_eq!(
            context.nas_count(Direction::Downlink, NasConnection::Non3Gpp),
            None
        );

        context
            .reselect_algorithms(&kamf, IntegrityAlgorithm::NIA1, CipheringAlgorithm::NEA1)
            .unwrap();
        assert_eq!(context.integrity_algorithm(), IntegrityAlgorithm::NIA1);
        assert_eq!(context.ciphering_algorithm(), CipheringAlgorithm::NEA1);
        assert_eq!(
            context.nas_count(Direction::Uplink, NasConnection::ThreeGpp),
            Some(count(0x0012_3456))
        );
        assert_eq!(
            context.nas_count(Direction::Downlink, NasConnection::ThreeGpp),
            Some(count(0x0000_abcd))
        );
        assert_eq!(
            context.nas_count(Direction::Uplink, NasConnection::Non3Gpp),
            Some(count(0x0000_1234))
        );
        assert_eq!(
            context.nas_count(Direction::Downlink, NasConnection::Non3Gpp),
            None
        );
        assert_ne!((context.knas_int, context.knas_enc), old_keys);

        // A direction whose COUNTs are all used protects nothing more.
        let reject = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();
        let sht = Nas5gsSecurityHeaderType::IntegrityProtected;
        assert!(
            context
                .protect_for_access(&reject, sht, Direction::Downlink, NasConnection::Non3Gpp)
                .is_err()
        );
        assert!(
            context
                .protect_for_access(&reject, sht, Direction::Downlink, NasConnection::ThreeGpp)
                .is_ok()
        );
    }

    #[test]
    fn test_protect_bytes_rejects_invalid_new_context_sht_for_non_security_mode_command() {
        let mut ctx = NasSecurityContext::from_fresh_keys(
            [0x71u8; 16],
            [0x81u8; 16],
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();

        let inner =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new())
                .encode()
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
        )
        .unwrap();
        let mut receiver = sender.clone();
        let inner =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());
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
        let mac = nas_mac(
            &key,
            NasCount::ZERO,
            NasConnection::ThreeGpp,
            Direction::Uplink.into(),
            &bad_inner[6..],
            Nia::NIA2,
        );
        bad_inner[2..6].copy_from_slice(&mac.to_be_bytes());
        assert!(receiver.unprotect(&bad_inner, Direction::Uplink).is_err());
        assert_eq!(receiver.ul_count, 1);
        assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
        assert_eq!(receiver.ul_count, 1);
    }

    #[test]
    fn a_reserved_5gs_algorithm_makes_no_context() {
        // The codes 4 to 7 of TS 24.501 Table 9.11.3.34.1 are reserved: no
        // key is derived and nothing is computed with one.
        let kamf = [0x24; 32];
        for reserved in [
            IntegrityAlgorithm::NIA4,
            IntegrityAlgorithm::NIA5,
            IntegrityAlgorithm::NIA6,
            IntegrityAlgorithm::NIA7,
        ] {
            assert!(oxirush_security::IntegrityAlgorithm::try_from(reserved).is_err());
            let nea = CipheringAlgorithm::NEA2;
            assert!(NasSecurityContext::from_fresh_keys([0; 16], [0; 16], reserved, nea).is_err());
            assert!(NasSecurityContext::from_fresh_kamf(&kamf, reserved, nea).is_err());
            let counts = (Some(NasCount::ZERO), Some(NasCount::ZERO));
            assert!(
                NasSecurityContext::restore_from_kamf(&kamf, reserved, nea, counts, counts)
                    .is_err()
            );
        }
        for reserved in [
            CipheringAlgorithm::NEA4,
            CipheringAlgorithm::NEA5,
            CipheringAlgorithm::NEA6,
            CipheringAlgorithm::NEA7,
        ] {
            assert!(oxirush_security::CipheringAlgorithm::try_from(reserved).is_err());
            let nia = IntegrityAlgorithm::NIA2;
            assert!(NasSecurityContext::from_fresh_keys([0; 16], [0; 16], nia, reserved).is_err());
            assert!(NasSecurityContext::from_fresh_kamf(&kamf, nia, reserved).is_err());
        }
        assert_eq!(
            oxirush_security::IntegrityAlgorithm::try_from(IntegrityAlgorithm::NIA3),
            Ok(Nia::NIA3)
        );
        assert_eq!(
            oxirush_security::CipheringAlgorithm::try_from(CipheringAlgorithm::NEA1),
            Ok(Nea::NEA1)
        );
    }

    #[test]
    fn the_connection_of_an_access_type_and_the_direction_convert() {
        assert_eq!(
            NasConnection::from(AccessTypeValue::ThreeGpp),
            NasConnection::ThreeGpp
        );
        assert_eq!(
            NasConnection::from(AccessTypeValue::Non3Gpp),
            NasConnection::Non3Gpp
        );
        assert_eq!(
            oxirush_security::Direction::from(Direction::Downlink),
            oxirush_security::Direction::Downlink
        );
        assert_eq!(
            Direction::from(oxirush_security::Direction::Uplink),
            Direction::Uplink
        );
    }
}
