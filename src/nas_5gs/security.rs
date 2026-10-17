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
//! key is a type of its own that is wiped when it is dropped ([`KAmf`],
//! [`KNasInt`], [`KNasEnc`]), a COUNT is a [`NasCount`] and a 5GS access a
//! [`NasConnection`]: they are those of
//! [oxirush-security](https://github.com/linouxis9/oxirush-security), and
//! [`nas_5gs`](crate::nas_5gs) exports them beside the context. The next
//! COUNT of a direction is `None` once all its COUNTs were used, and the
//! context then protects and verifies nothing more in it
//! ([`NasError::NasCountExhausted`]).
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::nas_5gs::{
//!     CipheringAlgorithm, Direction, IntegrityAlgorithm, KAmf, Nas5gsMessage,
//!     Nas5gsSecurityHeaderType, NasCount, NasSecurityContext,
//! };
//!
//! // REGISTRATION REJECT, cause #3
//! let msg = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();
//!
//! // The two ends of one link: the same KAMF and the same algorithms
//! let kamf = KAmf::new(&[0x11; 32]);
//! let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
//! let mut tx = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
//! let mut rx = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
//!
//! // Protect outbound: integrity and ciphering
//! let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
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

use crate::common::{Core, Direction, Keys, NextCount, System, wiped};
use crate::nas_5gs::ie::{AccessTypeValue, CipheringAlgorithm, IntegrityAlgorithm};
use crate::nas_5gs::message_types::Nas5gsSecurityHeaderType;
use crate::nas_5gs::messages::{
    Nas5gmmMessage, Nas5gsMessage, NasControlPlaneServiceRequest,
    NasDeregistrationRequestUeOriginating, NasRegistrationRequest, NasServiceRequest,
    validate_security_protected_inner_message,
};
use crate::nas_5gs::types::NasMessageContainer;
use crate::nas_5gs::types::{EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, NasError, Result};
use crate::prelude::*;
use core::fmt;
use oxirush_security::NasCount;
use oxirush_security::nas_5gs::{
    KAmf, KNasEnc, KNasInt, NasConnection, derive_knas_enc, derive_knas_int,
    derive_mapped_kamf_handover, derive_mapped_kamf_idle,
};
use oxirush_security::nas_eps::{KAsme, Nh};

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

/// A message that a security context verified, and what it was verified
/// with.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct Verified<M> {
    /// The message to act on: decoded, or its plain octets from
    /// `unprotect_raw`. It is the message under the security header, or
    /// the complete initial NAS message that this one carries ciphered
    /// (TS 24.501 §4.4.6): see [`NasSecurityContext::unprotect`].
    pub message: M,
    /// The security header type that the message came under.
    pub security_header_type: Nas5gsSecurityHeaderType,
    /// The NAS COUNT that the message authentication code was verified
    /// with: the uplink NAS COUNT of the message that K_gNB and K_N3IWF are
    /// derived with (TS 33.501 Annex A.9), for a message that starts the
    /// access stratum security.
    pub count: NasCount,
    /// The message as it was sent, when `message` is the complete initial
    /// NAS message that it carries: its cleartext IEs and the NAS message
    /// container, or the CIoT small data container, as they were received,
    /// ciphered. `None` for every other message.
    pub sent: Option<M>,
}

/// What is under a security header: its octets, the message that they are,
/// and the complete initial NAS message that this one carries ciphered,
/// with its octets.
struct Plain {
    octets: Vec<u8>,
    message: Nas5gsMessage,
    initial: Option<(Vec<u8>, Nas5gsMessage)>,
}

/// What `error` of the plain message `plain` is once the code of the
/// message was verified.
fn refused(error: NasError, plain: &[u8]) -> NasError {
    NasError::AuthenticMessageRefused {
        error: Box::new(error),
        plain: plain.into(),
    }
}

/// [`refused`] for an error of the checks of a received message, which are
/// those of a sender: a message that is not one to receive does not decode.
fn refused_received(error: NasError, plain: &[u8]) -> NasError {
    match error {
        NasError::EncodingError(message) => refused(NasError::DecodingError(message), plain),
        other => refused(other, plain),
    }
}

/// How a UE that has a security context sends an initial NAS message
/// (TS 24.501 §4.4.6).
enum InitialForm {
    /// As it is: it has cleartext IEs alone.
    Cleartext,
    /// With its cleartext IEs alone, as this message has them, and the
    /// complete message ciphered in a NAS message container.
    Contained(Nas5gmmMessage),
    /// As it is, with the value of its CIoT small data container ciphered:
    /// a CONTROL PLANE SERVICE REQUEST that has no other IE to cipher.
    SmallData,
}

/// The octets of a CONTROL PLANE SERVICE REQUEST before its optional IEs:
/// its header and the octet of its control plane service type and ngKSI,
/// which are its cleartext IEs. Its NAS message container has the IEs after
/// them, its non-cleartext IEs (TS 24.501 §4.4.6 b) 2) ii), §9.11.3.33).
const CPSR_CLEARTEXT: usize = 4;

/// How the initial NAS message `message` is sent. The cleartext IEs are
/// those that the clause lists for each of the four messages; every other
/// IE, and an IE that the message table does not have, is ciphered.
fn initial_form(message: &Nas5gmmMessage) -> Result<InitialForm> {
    let contained = |with_container: bool, cleartext: Nas5gmmMessage| match with_container {
        true => Err(NasError::EncodingError(
            "the NAS message container of an initial NAS message is made by the security \
             context: the message is given without one"
                .into(),
        )),
        false if cleartext == *message => Ok(InitialForm::Cleartext),
        false => Ok(InitialForm::Contained(cleartext)),
    };
    match message {
        Nas5gmmMessage::RegistrationRequest(request) => {
            let mut cleartext = NasRegistrationRequest::new(
                request.fgs_registration_type,
                request.ngksi,
                request.fgs_mobile_identity.clone(),
            );
            cleartext.ue_security_capability = request.ue_security_capability.clone();
            cleartext.additional_guti = request.additional_guti.clone();
            cleartext.ue_status = request.ue_status.clone();
            cleartext.eps_nas_message_container = request.eps_nas_message_container.clone();
            cleartext.nid = request.nid.clone();
            cleartext.ue_determined_plmn_with_disaster_condition =
                request.ue_determined_plmn_with_disaster_condition.clone();
            contained(request.nas_message_container.is_some(), cleartext.into())
        }
        Nas5gmmMessage::DeregistrationRequestUeOriginating(request) => {
            let cleartext = NasDeregistrationRequestUeOriginating::new(
                request.de_registration_type,
                request.ngksi,
                request.fgs_mobile_identity.clone(),
            );
            contained(request.nas_message_container.is_some(), cleartext.into())
        }
        Nas5gmmMessage::ServiceRequest(request) => {
            let cleartext = NasServiceRequest::new(
                request.ngksi,
                request.service_type,
                request.fg_s_tmsi.clone(),
            );
            contained(request.nas_message_container.is_some(), cleartext.into())
        }
        Nas5gmmMessage::ControlPlaneServiceRequest(request) => {
            let cleartext = NasControlPlaneServiceRequest::new(
                request.control_plane_service_type,
                request.ngksi,
            );
            let mut small_data = cleartext.clone();
            small_data.ciot_small_data_container = request.ciot_small_data_container.clone();
            match request.ciot_small_data_container.is_some() && small_data == **request {
                true => Ok(InitialForm::SmallData),
                false => contained(request.nas_message_container.is_some(), cleartext.into()),
            }
        }
        other => Err(NasError::EncodingError(format!(
            "{:?} is no initial NAS message: REGISTRATION REQUEST, DEREGISTRATION REQUEST from \
             the UE, SERVICE REQUEST and CONTROL PLANE SERVICE REQUEST are",
            other.message_type()
        ))),
    }
}

/// Give the initial NAS message `message` its NAS message container.
fn contain(message: &mut Nas5gmmMessage, container: NasMessageContainer) {
    let place = match message {
        Nas5gmmMessage::RegistrationRequest(request) => &mut request.nas_message_container,
        Nas5gmmMessage::DeregistrationRequestUeOriginating(request) => {
            &mut request.nas_message_container
        }
        Nas5gmmMessage::ServiceRequest(request) => &mut request.nas_message_container,
        Nas5gmmMessage::ControlPlaneServiceRequest(request) => &mut request.nas_message_container,
        _ => return,
    };
    *place = Some(container);
}

/// Whether `message` is one that a context protects under `sht` in
/// `direction`: a plain message of that direction, under a header type that
/// protects it.
fn check_protected(
    message: &Nas5gsMessage,
    sht: Nas5gsSecurityHeaderType,
    direction: Direction,
) -> Result<()> {
    validate_security_protected_inner_message(message, sht)?;
    validate_message_direction(message, direction)
}

fn validate_message_direction(message: &Nas5gsMessage, direction: Direction) -> Result<()> {
    let Nas5gsMessage::Gmm(_, inner) = message else {
        return Ok(());
    };
    // TS 24.501 Chapter 8 assigns a sending side to each 5GMM message.
    let required_direction = match inner {
        Nas5gmmMessage::RegistrationRequest(_)
        | Nas5gmmMessage::RegistrationComplete(_)
        | Nas5gmmMessage::DeregistrationRequestUeOriginating(_)
        | Nas5gmmMessage::DeregistrationAcceptUeTerminated(_)
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
        | Nas5gmmMessage::DeregistrationRequestUeTerminated(_)
        | Nas5gmmMessage::DeregistrationAcceptUeOriginating(_)
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
        Nas5gmmMessage::FiveGmmStatus(_) => None,
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
            AccessTypeValue::ThreeGppAccess => Self::ThreeGpp,
            AccessTypeValue::Non3GppAccess => Self::Non3Gpp,
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
///
/// The keys are wiped when the context is dropped, by their own types, and
/// `Debug` shows the algorithms and the COUNTs without them.
#[cfg_attr(test, derive(Clone))]
pub struct NasSecurityContext {
    /// The keys, the algorithms and the COUNTs of each access.
    core: Core<FiveGs>,
}

/// The system of the 5GS contexts: KNASint and KNASenc of TS 33.501, the
/// codes of TS 24.501 §9.11.3.34, and the two NAS connections.
pub(crate) enum FiveGs {}

impl System for FiveGs {
    type IntegrityKey = KNasInt;
    type CipheringKey = KNasEnc;
    type Integrity = IntegrityAlgorithm;
    type Ciphering = CipheringAlgorithm;
    type Connection = NasConnection;
    type Counts = [[NextCount; 2]; 2];
    const NAME: &'static str = "5GS";
    const NULL_INTEGRITY: IntegrityAlgorithm = IntegrityAlgorithm::NIA0;
    const NULL_CIPHERING: CipheringAlgorithm = CipheringAlgorithm::NEA0;

    fn place(connection: NasConnection) -> usize {
        // The NAS connection identifiers are 1 and 2.
        usize::from(u8::from(connection)).saturating_sub(1).min(1)
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

    fn bearer(connection: NasConnection) -> oxirush_security::Bearer {
        connection.into()
    }
}

impl fmt::Debug for NasSecurityContext {
    /// The algorithms and the next NAS COUNTs, without the keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = |direction, connection| self.nas_count(direction, connection);
        f.debug_struct("NasSecurityContext")
            .field("integrity_algorithm", &self.core.integrity_code)
            .field("ciphering_algorithm", &self.core.ciphering_code)
            .field(
                "uplink_count",
                &count(Direction::Uplink, NasConnection::ThreeGpp),
            )
            .field(
                "downlink_count",
                &count(Direction::Downlink, NasConnection::ThreeGpp),
            )
            .field(
                "uplink_count_non_3gpp",
                &count(Direction::Uplink, NasConnection::Non3Gpp),
            )
            .field(
                "downlink_count_non_3gpp",
                &count(Direction::Downlink, NasConnection::Non3Gpp),
            )
            .finish_non_exhaustive()
    }
}

impl NasSecurityContext {
    /// Create a context for genuinely fresh NAS keys with COUNT values at zero.
    ///
    /// Reusing the same keys with this constructor violates TS 33.501 §6.4.5;
    /// use [`Self::reselect_algorithms`] for an existing KAMF. A reserved
    /// algorithm (the codes 4 to 7) and NIA0 with another cipher than NEA0
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

    /// Derive a fresh 5GS NAS context from a newly established KAMF.
    ///
    /// COUNT starts at zero. Calling this again for the same KAMF would violate
    /// TS 33.501 §6.4.5; use [`Self::reselect_algorithms`] instead. The
    /// algorithms are checked as [`Self::from_fresh_keys`] checks them.
    pub fn from_fresh_kamf(
        kamf: &KAmf,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        let core = Core::derived(integrity_algo, ciphering_algo, |integrity, ciphering| {
            Keys {
                integrity: derive_knas_int(kamf, integrity),
                ciphering: derive_knas_enc(kamf, ciphering),
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

    /// Next NAS COUNT to use or expect for a direction and access type:
    /// `None` when every COUNT of the direction was used, after which the
    /// context protects nothing more in it.
    pub fn nas_count(&self, direction: Direction, connection: NasConnection) -> Option<NasCount> {
        self.core.count(direction, connection).get()
    }

    /// Restore a 5GS context and its next COUNT values from persistent state.
    ///
    /// The caller must supply the counts stored for this exact KAMF, as
    /// [`Self::nas_count`] gave them: the uplink then the downlink COUNT of
    /// each access, `None` for one that is exhausted. Passing zero for a KAMF
    /// that has already protected traffic violates TS 33.501 §6.4.5.
    pub fn restore_from_kamf(
        kamf: &KAmf,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
        three_gpp_counts: (Option<NasCount>, Option<NasCount>),
        non_3gpp_counts: (Option<NasCount>, Option<NasCount>),
    ) -> Result<Self> {
        let mut context = Self::from_fresh_kamf(kamf, integrity_algo, ciphering_algo)?;
        for (connection, (uplink, downlink)) in [
            (NasConnection::ThreeGpp, three_gpp_counts),
            (NasConnection::Non3Gpp, non_3gpp_counts),
        ] {
            *context.core.count_mut(Direction::Uplink, connection) = NextCount::of(uplink);
            *context.core.count_mut(Direction::Downlink, connection) = NextCount::of(downlink);
        }
        Ok(context)
    }

    /// Re-derive NAS keys for a new algorithm selection under the same KAMF.
    ///
    /// All four access-specific COUNTs are preserved as required by TS 33.501
    /// §6.4.5.
    pub fn reselect_algorithms(
        &mut self,
        kamf: &KAmf,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<()> {
        // A key that is replaced is wiped as it is dropped.
        let derive = |integrity, ciphering| Keys {
            integrity: derive_knas_int(kamf, integrity),
            ciphering: derive_knas_enc(kamf, ciphering),
        };
        self.core.reselect(integrity_algo, ciphering_algo, derive)
    }

    /// Map an EPS KASME to a 5GS context for idle mobility.
    ///
    /// `tau_ul_nas_count` protects the EPS mobility-triggering message. The
    /// mapped 5GS NAS COUNT values start at zero. The mapped ngKSI is handled
    /// by the enclosing mobility procedure.
    pub fn from_mapped_kamf_idle(
        kasme: &KAsme,
        tau_ul_nas_count: NasCount,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        wiped(|| {
            let kamf = derive_mapped_kamf_idle(kasme, tau_ul_nas_count);
            Self::from_fresh_kamf(&kamf, integrity_algo, ciphering_algo)
        })
    }

    /// Map an EPS KASME to a 5GS context for connected handover using NH.
    /// The mapped 5GS NAS COUNT values start at zero. This derivation has no
    /// COUNT input.
    pub fn from_mapped_kamf_handover(
        kasme: &KAsme,
        nh: &Nh,
        integrity_algo: IntegrityAlgorithm,
        ciphering_algo: CipheringAlgorithm,
    ) -> Result<Self> {
        wiped(|| {
            let kamf = derive_mapped_kamf_handover(kasme, nh);
            Self::from_fresh_kamf(&kamf, integrity_algo, ciphering_algo)
        })
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
        check_protected(inner, sht, direction)?;
        let inner_bytes = inner.encode()?;
        self.protect_envelope(inner_bytes, sht, direction, connection)
    }

    /// Protect an initial NAS message as a UE that has this security
    /// context sends it (TS 24.501 §4.4.6, TS 33.501 §6.4.6), over 3GPP
    /// access: a REGISTRATION REQUEST, a DEREGISTRATION REQUEST from the UE,
    /// a SERVICE REQUEST or a CONTROL PLANE SERVICE REQUEST, given complete
    /// and plain, with every IE that it is to carry and no NAS message
    /// container.
    ///
    /// The message goes out integrity protected, with its cleartext IEs
    /// alone and the complete message in a NAS message container, whose
    /// value is ciphered with the uplink NAS COUNT of the message. A message
    /// that has cleartext IEs alone goes out as it is, without a container.
    /// A CONTROL PLANE SERVICE REQUEST whose only other IE is the CIoT small
    /// data container keeps it, with its value ciphered; with other IEs,
    /// its container has those IEs, its non-cleartext IEs, and not the
    /// complete message (§4.4.6 b) 2) ii), §9.11.3.33). With the null
    /// ciphering algorithm the value is as it is, which the clause counts as
    /// ciphered.
    ///
    /// The receiving end is [`Self::unprotect`], which gives the complete
    /// message back. [`Self::protect`] with "integrity protected" sends a
    /// message as it is given, with all its IEs in clear.
    ///
    /// ```rust
    /// use oxirush_nas::common::Plmn;
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
    /// let mut ue = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// let mut amf = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    ///
    /// // A mobility registration update with a requested NSSAI
    /// let guti = Guti::new(Plmn::new("208", "93").unwrap(), 1, 1, 0, 0xc000_0001).unwrap();
    /// let kind = RegistrationType::MobilityRegistrationUpdating;
    /// let nssai = NasNssai::from_snssais(&[NasSNssai::from_sst_sd(1, None)]).unwrap();
    /// let ngksi = NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Native(0));
    /// let request = NasRegistrationRequest::new(
    ///     NasFGsRegistrationType::from_registration_type(kind),
    ///     ngksi.unwrap(),
    ///     NasFGsMobileIdentity::from_guti(guti),
    /// )
    /// .with_requested_nssai(nssai);
    /// let request = Nas5gsMessage::new_5gmm(request);
    /// let sent = ue.protect_initial(&request).unwrap();
    ///
    /// // On the way, the NSSAI is in no IE that is read without the key
    /// let Nas5gsMessage::SecurityProtected(_, cleartext) = Nas5gsMessage::decode(&sent).unwrap()
    /// else {
    ///     unreachable!()
    /// };
    /// let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(cleartext)) = *cleartext
    /// else {
    ///     unreachable!()
    /// };
    /// assert!(cleartext.requested_nssai.is_none() && cleartext.nas_message_container.is_some());
    ///
    /// // The AMF acts on the complete message
    /// let verified = amf.unprotect(&sent, Direction::Uplink).unwrap();
    /// assert_eq!(verified.message, request);
    /// assert!(verified.sent.is_some());
    /// ```
    pub fn protect_initial(&mut self, message: &Nas5gsMessage) -> Result<Vec<u8>> {
        self.protect_initial_for_access(message, NasConnection::ThreeGpp)
    }

    /// [`Self::protect_initial`] over one access, with its NAS COUNT and its
    /// NAS connection identifier.
    pub fn protect_initial_for_access(
        &mut self,
        message: &Nas5gsMessage,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        let Nas5gsMessage::Gmm(header, complete) = message else {
            return Err(NasError::EncodingError(
                "an initial NAS message is a plain 5GMM message".into(),
            ));
        };
        // The value is ciphered with the NAS COUNT that the message is then
        // sent with (TS 24.501 §4.4.3.4): the next one of the uplink.
        let count = self.core.count(Direction::Uplink, connection).to_send()?;
        let cipher = |octets: &mut [u8]| {
            (self.core).cipher(count, connection, Direction::Uplink, octets);
        };
        let sent = match initial_form(complete)? {
            InitialForm::Cleartext => complete.clone(),
            InitialForm::Contained(mut cleartext) => {
                let mut value = message.encode()?;
                // The container of a CONTROL PLANE SERVICE REQUEST has its
                // non-cleartext IEs alone, and that of the other three the
                // complete message
                if matches!(complete, Nas5gmmMessage::ControlPlaneServiceRequest(_)) {
                    value.drain(..CPSR_CLEARTEXT);
                }
                cipher(&mut value);
                contain(&mut cleartext, NasMessageContainer::new(value));
                cleartext
            }
            InitialForm::SmallData => {
                let mut sent = complete.clone();
                if let Nas5gmmMessage::ControlPlaneServiceRequest(request) = &mut sent
                    && let Some(container) = &mut request.ciot_small_data_container
                {
                    cipher(&mut container.value);
                }
                sent
            }
        };
        let sent = Nas5gsMessage::Gmm(*header, sent);
        let integrity_protected = Nas5gsSecurityHeaderType::IntegrityProtected;
        self.protect_for_access(&sent, integrity_protected, Direction::Uplink, connection)
    }

    /// The complete initial NAS message that `received` carries ciphered
    /// (TS 24.501 §4.4.6), and its octets: the message of its NAS message
    /// container, or the CONTROL PLANE SERVICE REQUEST itself with the value
    /// of its CIoT small data container deciphered. `None` for a message
    /// that carries none.
    fn initial(
        &self,
        received: &Nas5gsMessage,
        plain: &[u8],
        count: NasCount,
        connection: NasConnection,
    ) -> Result<Option<(Vec<u8>, Nas5gsMessage)>> {
        let Nas5gsMessage::Gmm(header, message) = received else {
            return Ok(None);
        };
        let decipher = |octets: &mut [u8]| {
            (self.core).cipher(count, connection, Direction::Uplink, octets);
        };
        let container = match message {
            Nas5gmmMessage::RegistrationRequest(request) => &request.nas_message_container,
            Nas5gmmMessage::DeregistrationRequestUeOriginating(request) => {
                &request.nas_message_container
            }
            Nas5gmmMessage::ServiceRequest(request) => &request.nas_message_container,
            // The AMF deciphers the CIoT small data container if the
            // message has one, and the NAS message container otherwise
            // (TS 24.501 §5.6.1.4.2).
            Nas5gmmMessage::ControlPlaneServiceRequest(request)
                if request.ciot_small_data_container.is_some() =>
            {
                let mut complete = request.clone();
                if let Some(container) = &mut complete.ciot_small_data_container {
                    decipher(&mut container.value);
                }
                let complete = Nas5gsMessage::Gmm(
                    *header,
                    Nas5gmmMessage::ControlPlaneServiceRequest(complete),
                );
                let octets = complete.encode().map_err(|error| refused(error, plain))?;
                return Ok(Some((octets, complete)));
            }
            Nas5gmmMessage::ControlPlaneServiceRequest(request) => &request.nas_message_container,
            _ => return Ok(None),
        };
        let Some(container) = container else {
            return Ok(None);
        };
        let mut octets = container.value.to_vec();
        decipher(&mut octets);
        // The container of a CONTROL PLANE SERVICE REQUEST has its
        // non-cleartext IEs (§9.11.3.33), which the complete message has after
        // its cleartext IEs; one that begins with the discriminator of 5GMM
        // has the complete message, as that of the other three has
        if matches!(message, Nas5gmmMessage::ControlPlaneServiceRequest(_))
            && octets.first() != Some(&EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM)
        {
            let cleartext = plain.get(..CPSR_CLEARTEXT).unwrap_or(plain);
            octets = [cleartext, &octets].concat();
        }
        let complete = Nas5gsMessage::decode(&octets).map_err(|error| refused(error, &octets))?;
        // The container has the entire message that it is in.
        match &complete {
            Nas5gsMessage::Gmm(_, inner) if inner.message_type() == message.message_type() => {
                Ok(Some((octets, complete)))
            }
            _ => Err(refused(
                NasError::DecodingError(format!(
                    "the NAS message container of a {:?} has another message",
                    message.message_type()
                )),
                &octets,
            )),
        }
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
        check_protected(&decoded, sht, direction)?;
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
                | Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        ) {
            return Err(NasError::EncodingError(
                "opaque 5GS protection requires a regular security header type".into(),
            ));
        }
        self.protect_envelope(inner_bytes, sht, direction, connection)
    }

    /// The message under its security header `[EPD | SHT | MAC | SN]`,
    /// ciphered for the header types that cipher (TS 33.501 §6.4.3.1).
    fn protect_envelope(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: Nas5gsSecurityHeaderType,
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        let ciphers = matches!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        );
        let header = [EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, sht as u8];
        let cipher = |core: &Core<FiveGs>, count, payload: &mut Vec<u8>| {
            if ciphers {
                core.cipher(count, connection, direction, payload);
            }
            Ok(())
        };
        (self.core).seal(&header, inner_bytes, direction, connection, cipher)
    }

    /// Unprotect an inbound security-protected NAS message.
    ///
    /// 1. Parses the security header (EPD, SHT, MAC, SN)
    /// 2. Verifies the MAC
    /// 3. Deciphers if needed
    /// 4. Decodes the inner NAS message
    ///
    /// On success, returns the message, its security header type and the
    /// NAS COUNT that it was verified with. The COUNT of the direction
    /// advances as soon as the MAC is verified: a message that is then
    /// refused for what it is, is [`NasError::AuthenticMessageRefused`],
    /// with its COUNT used and its plain octets, deciphered, which
    /// [`Nas5gsMessage::answer_to_refused`] answers.
    ///
    /// An initial NAS message from a UE that has a security context comes
    /// integrity protected, with its cleartext IEs alone and the complete
    /// message ciphered in its NAS message container (TS 24.501 §4.4.6,
    /// [`Self::protect_initial`]). The container is deciphered with the
    /// NAS COUNT of the message, and `message` is then the complete
    /// message, which the AMF is to take as the one that started the
    /// procedure; `sent` has the message as it came. This is so for an
    /// uplink REGISTRATION REQUEST, DEREGISTRATION REQUEST, SERVICE REQUEST
    /// and CONTROL PLANE SERVICE REQUEST under "integrity protected", the
    /// last one also with the value of its CIoT small data container. The
    /// container of a CONTROL PLANE SERVICE REQUEST has its non-cleartext
    /// IEs (§9.11.3.33), which `message` has after its cleartext IEs, or the
    /// complete message, which is read too. A container that is not such a
    /// message of the type that carries it is
    /// refused as an authentic message is: the AMF then asks for the
    /// message again in the SECURITY MODE COMMAND (§5.4.2.2), with the
    /// cleartext IEs that `Nas5gsMessage::decode` reads in the same octets.
    ///
    /// A MAC mismatch returns [`NasError::IntegrityCheckFailed`]. A receiver
    /// that must still process the message (TS 24.501 §4.4.4.3) can decode
    /// the PDU with
    /// [`Nas5gsMessage::decode`],
    /// which returns the unverified inner message when it is not ciphered.
    ///
    /// With NIA0 no MAC is checked and no message is refused as a replay
    /// (§4.4.3.2, TS 33.501 annex D.1): a message received again is taken
    /// with a COUNT higher than the stored one (§4.4.3.1). A SECURITY MODE
    /// COMMAND is verified by the context that it takes into use, which the
    /// caller makes (§5.4.2.3): the context in use, with its COUNTs, one of
    /// [`Self::restore_from_kamf`] for new algorithms under its KAMF, or one
    /// of [`Self::from_fresh_kamf`] after an authentication.
    pub fn unprotect(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<Verified<Nas5gsMessage>> {
        self.unprotect_for_access(data, direction, NasConnection::ThreeGpp)
    }

    /// Unprotect an inbound security-protected NAS message for a specific access.
    pub fn unprotect_for_access(
        &mut self,
        data: &[u8],
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Verified<Nas5gsMessage>> {
        let (plain, security_header_type, count) =
            self.unprotect_checked(data, direction, connection)?;
        let (message, sent) = match plain.initial {
            Some((_, complete)) => (complete, Some(plain.message)),
            None => (plain.message, None),
        };
        Ok(Verified {
            message,
            security_header_type,
            count,
            sent,
        })
    }

    /// Unprotect and return raw decrypted bytes without decoding.
    ///
    /// Useful when you need the raw bytes for further processing (e.g.,
    /// re-encoding into a NAS message container).
    pub fn unprotect_raw(
        &mut self,
        data: &[u8],
        direction: Direction,
    ) -> Result<Verified<Vec<u8>>> {
        self.unprotect_raw_for_access(data, direction, NasConnection::ThreeGpp)
    }

    /// Unprotect and return raw decrypted bytes for a specific access type.
    pub fn unprotect_raw_for_access(
        &mut self,
        data: &[u8],
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Verified<Vec<u8>>> {
        let (plain, security_header_type, count) =
            self.unprotect_checked(data, direction, connection)?;
        let (message, sent) = match plain.initial {
            Some((complete, _)) => (complete, Some(plain.octets)),
            None => (plain.octets, None),
        };
        Ok(Verified {
            message,
            security_header_type,
            count,
            sent,
        })
    }

    /// The plain octets of a protected message and the message they are,
    /// which is decoded once to check it, with the complete initial NAS
    /// message that it carries.
    fn unprotect_checked(
        &mut self,
        data: &[u8],
        direction: Direction,
        connection: NasConnection,
    ) -> Result<(Plain, Nas5gsSecurityHeaderType, NasCount)> {
        if data.len() < 7 {
            return Err(NasError::BufferTooShort);
        }
        if data[0] != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(NasError::DecodingError(
                "invalid 5GS NAS security discriminator".into(),
            ));
        }

        // Bits 8-5 of octet 2 are a spare half octet (Figure 9.1.1-2).
        let sht = Nas5gsSecurityHeaderType::try_from(data[1] & 0x0f)?;

        if sht == Nas5gsSecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected {
            return Err(NasError::DecodingError(
                "not a security-protected message".into(),
            ));
        }

        let payload = &data[7..];
        if payload.is_empty() {
            return Err(NasError::BufferTooShort);
        }

        // TS 24.501 §4.4.3.3 commits the received NAS COUNT after successful
        // integrity verification. Inner syntax, header-pairing, and direction
        // checks must not make an authenticated COUNT reusable.
        let count = self.core.open(data, 2, direction, connection)?;

        let should_cipher = matches!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        );

        let mut decrypted = payload.to_vec();
        if should_cipher {
            (self.core).cipher(count, connection, direction, &mut decrypted);
        }

        let decoded =
            Nas5gsMessage::decode(&decrypted).map_err(|error| refused(error, &decrypted))?;
        let received = |error| refused_received(error, &decrypted);
        validate_security_protected_inner_message(&decoded, sht).map_err(received)?;
        validate_message_direction(&decoded, direction).map_err(received)?;

        let initial = match (sht, direction) {
            (Nas5gsSecurityHeaderType::IntegrityProtected, Direction::Uplink) => {
                self.initial(&decoded, &decrypted, count, connection)?
            }
            _ => None,
        };
        let plain = Plain {
            octets: decrypted,
            message: decoded,
            initial,
        };
        Ok((plain, sht, count))
    }

    /// Integrity protect a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE
    /// REQUEST with this 5G NAS security context, as a UE does when it moves
    /// from 5GS to EPS (TS 33.501 §8.5.2 step 1, TS 24.301 §4.4.2.3). The
    /// PDU has the EPS security header with SHT 0001; the MAC uses KNASint,
    /// the 5G uplink NAS COUNT, and the 3GPP NAS connection identifier. The
    /// uplink COUNT advances. Returns the PDU and the NAS COUNT that it is
    /// protected with, which the mapped EPS security context is derived
    /// with (TS 33.501 §8.6.1).
    pub fn protect_eps_message(&mut self, eps_plain: &[u8]) -> Result<(Vec<u8>, NasCount)> {
        check_eps_mobility_request(eps_plain)?;
        let (uplink, three_gpp) = (Direction::Uplink, NasConnection::ThreeGpp);
        let count = self.core.count(uplink, three_gpp).to_send()?;
        // The EPS security header: SHT 0001 and the EMM discriminator
        let plain = eps_plain.to_vec();
        let out = (self.core).seal(&[0x17], plain, uplink, three_gpp, |_, _, _| Ok(()))?;
        Ok((out, count))
    }

    /// Verify an EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST that the
    /// UE protected with this 5G context, "as if it was a 5G NAS message
    /// received over 3GPP access" (TS 33.501 §8.5.2 step 4). Returns the plain
    /// EPS message and the NAS COUNT that it was verified with, which the
    /// mapped EPS security context is derived with; the uplink COUNT
    /// advances.
    pub fn unprotect_eps_message(&mut self, pdu: &[u8]) -> Result<(Vec<u8>, NasCount)> {
        let [first, _, _, _, _, _, plain @ ..] = pdu else {
            return Err(NasError::MessageTooShort);
        };
        if *first != 0x17 {
            return Err(NasError::DecodingError(
                "EPS PDU is not integrity protected with SHT 0001".into(),
            ));
        }
        let (uplink, three_gpp) = (Direction::Uplink, NasConnection::ThreeGpp);
        let count = self.core.open(pdu, 1, uplink, three_gpp)?;
        check_eps_mobility_request(plain).map_err(|error| refused_received(error, plain))?;
        Ok((plain.to_vec(), count))
    }
}

/// Only a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST is sent
/// under the 5G context (TS 33.501 §8.5.2, TS 24.301 §4.4.2.3).
fn check_eps_mobility_request(eps_plain: &[u8]) -> Result<()> {
    if matches!(eps_plain, [0x07, 0x41 | 0x48, ..]) {
        Ok(())
    } else {
        Err(NasError::EncodingError(
            "only a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST uses the 5G context"
                .into(),
        ))
    }
}

#[cfg(test)]
impl NasSecurityContext {
    /// The next COUNT of a direction of an access, as the context keeps it.
    fn count_ref(&self, direction: Direction, connection: NasConnection) -> NextCount {
        self.core.count(direction, connection)
    }

    /// The next COUNT of a direction of an access, to set it.
    fn count_mut(&mut self, direction: Direction, connection: NasConnection) -> &mut NextCount {
        self.core.count_mut(direction, connection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxirush_security::CipheringAlgorithm as Nea;
    use oxirush_security::IntegrityAlgorithm as Nia;
    use oxirush_security::nas_5gs::{nas_cipher, nas_mac};

    /// A NAS COUNT of a message.
    fn count(count: u32) -> NasCount {
        NasCount::new(count).unwrap()
    }

    #[test]
    fn a_context_is_shown_without_its_keys_and_gives_the_count_it_verified_with() {
        let mut sender = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x11; 16]),
            &KNasEnc::new(&[0x22; 16]),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        *sender.count_mut(Direction::Uplink, NasConnection::Non3Gpp) = (0x0000_02fe).into();
        let mut receiver = sender.clone();
        let shown = format!("{receiver:?}");
        assert_eq!(
            shown,
            "NasSecurityContext { integrity_algorithm: NIA2, ciphering_algorithm: NEA2, \
             uplink_count: Some(NasCount(0)), downlink_count: Some(NasCount(0)), \
             uplink_count_non_3gpp: Some(NasCount(766)), \
             downlink_count_non_3gpp: Some(NasCount(0)), .. }"
        );
        // Neither a key nor one of its octets
        assert!(!shown.contains("11") && !shown.contains("22") && !shown.contains("17"));
        // What a UE costs: the place of the keys, the algorithms and four
        // COUNTs, and the two keys in the heap
        #[cfg(target_pointer_width = "64")]
        assert_eq!(core::mem::size_of::<NasSecurityContext>(), 32);
        assert_eq!(core::mem::size_of::<Keys<KNasInt, KNasEnc>>(), 32);

        // The COUNT of each message that is verified, across a wrap of the
        // sequence number, on the access that it came over
        let message =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());
        let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
        let (uplink, access) = (Direction::Uplink, NasConnection::Non3Gpp);
        for expected in [0x02fe, 0x02ff, 0x0300] {
            let wire = sender
                .protect_for_access(&message, sht, uplink, access)
                .unwrap();
            let verified = receiver
                .unprotect_for_access(&wire, uplink, access)
                .unwrap();
            assert_eq!(verified.count, count(expected));
            assert_eq!(verified.security_header_type, sht);
            assert_eq!(verified.message, message);
            let raw = (sender.clone()).protect_for_access(&message, sht, uplink, access);
            let raw = (receiver.clone()).unprotect_raw_for_access(&raw.unwrap(), uplink, access);
            assert_eq!(raw.unwrap().count, count(expected + 1));
        }
    }

    #[test]
    fn opaque_payload_preserves_malformed_bytes_and_authenticates_all_regular_headers() {
        let inner = vec![0x7e, 0x00, 0xff, 0x20, 0x02, 0xbb, 0xaa, 0x20, 0x01, 0xcc];
        for access in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
            for direction in [Direction::Uplink, Direction::Downlink] {
                for sht in [
                    Nas5gsSecurityHeaderType::IntegrityProtected,
                    Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                    Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                    Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
                ] {
                    let mut sender = NasSecurityContext::from_fresh_keys(
                        &KNasInt::new(&[0x29; 16]),
                        &KNasEnc::new(&[0x37; 16]),
                        IntegrityAlgorithm::NIA2,
                        CipheringAlgorithm::NEA2,
                    )
                    .unwrap();
                    *sender.count_mut(direction, access) = (0x1234).into();
                    assert!(
                        sender
                            .protect_bytes_for_access(inner.clone(), sht, direction, access)
                            .is_err()
                    );
                    assert_eq!(sender.count_ref(direction, access), 0x1234);
                    let mut receiver = sender.clone();
                    let mut tampered_receiver = receiver.clone();
                    let wire = sender
                        .protect_opaque_payload_for_access(inner.clone(), sht, direction, access)
                        .unwrap();
                    let mut payload = inner.clone();
                    if matches!(sht as u8, 2 | 4) {
                        nas_cipher(
                            &KNasEnc::new(&[0x37; 16]),
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
                        &KNasInt::new(&[0x29; 16]),
                        count(0x1234),
                        access,
                        direction.into(),
                        &wire[6..],
                        Nia::NIA2,
                    );
                    assert_eq!(&wire[2..6], mac.to_be_bytes());
                    if matches!(sht as u8, 2 | 4) {
                        nas_cipher(
                            &KNasEnc::new(&[0x37; 16]),
                            count(0x1234),
                            access,
                            direction.into(),
                            &mut payload,
                            Nea::NEA2,
                        );
                    }
                    assert_eq!(payload, inner);
                    assert_eq!(sender.count_ref(direction, access), 0x1235);
                    assert_eq!(sender.core.keys.integrity, [0x29; 16]);
                    assert_eq!(sender.core.keys.ciphering, [0x37; 16]);
                    for other_direction in [Direction::Uplink, Direction::Downlink] {
                        for other_access in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
                            if (other_direction, other_access) != (direction, access) {
                                assert_eq!(sender.count_ref(other_direction, other_access), 0);
                            }
                        }
                    }
                    let mut tampered = wire.clone();
                    tampered[2] ^= 1;
                    assert!(matches!(
                        tampered_receiver.unprotect_raw_for_access(&tampered, direction, access),
                        Err(NasError::IntegrityCheckFailed)
                    ));
                    assert_eq!(tampered_receiver.count_ref(direction, access), 0x1234);
                    // The code is right and the message is refused for what
                    // it is, with its COUNT used.
                    assert_eq!(
                        receiver.unprotect_raw_for_access(&wire, direction, access),
                        Err(NasError::AuthenticMessageRefused {
                            error: Box::new(NasError::UnknownMessageType(0xff)),
                            plain: inner.clone().into(),
                        })
                    );
                    assert_eq!(receiver.count_ref(direction, access), 0x1235);
                }
            }
        }
    }

    #[test]
    fn opaque_payload_matches_checked_protection_without_relaxing_checked_headers_or_direction() {
        let inner = vec![0x7e, 0x00, 0x43]; // REGISTRATION COMPLETE.
        let mut sender = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x29; 16]),
            &KNasEnc::new(&[0x37; 16]),
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
            let raw = receiver.unprotect_raw(&opaque, Direction::Uplink).unwrap();
            assert_eq!(
                (raw.message, raw.security_header_type),
                (inner.clone(), sht)
            );
        }
        for (sht, direction) in [
            (
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Downlink,
            ),
            (
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                Direction::Uplink,
            ),
        ] {
            assert!(sender.protect_bytes(inner.clone(), sht, direction).is_err());
        }
        assert_eq!(
            (
                sender.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
                sender.count_ref(Direction::Downlink, NasConnection::ThreeGpp)
            ),
            ((2).into(), (0).into())
        );
    }

    #[test]
    fn opaque_payload_rejects_envelope_errors_without_consuming_count() {
        let mut sender = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x29; 16]),
            &KNasEnc::new(&[0x37; 16]),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
        assert!(
            sender
                .protect_opaque_payload(
                    vec![0xff],
                    Nas5gsSecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected,
                    Direction::Uplink
                )
                .is_err()
        );
        assert_eq!(
            sender.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            0
        );
        // A reserved algorithm, and NIA0 with a cipher, make no context.
        for (integrity, ciphering) in [
            (IntegrityAlgorithm::NIA7, CipheringAlgorithm::NEA2),
            (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA7),
            (IntegrityAlgorithm::NIA0, CipheringAlgorithm::NEA2),
        ] {
            let context = NasSecurityContext::from_fresh_keys(
                &KNasInt::new(&[0x29; 16]),
                &KNasEnc::new(&[0x37; 16]),
                integrity,
                ciphering,
            );
            assert!(context.is_err(), "{integrity:?} {ciphering:?}");
        }
        for access in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
            for direction in [Direction::Uplink, Direction::Downlink] {
                *sender.count_mut(direction, access) = (0x00ff_ffff).into();
                let wire = sender
                    .protect_opaque_payload_for_access(Vec::new(), sht, direction, access)
                    .unwrap();
                assert_eq!(wire.len(), 7);
                assert_eq!(wire[6], 0xff);
                let mac = nas_mac(
                    &KNasInt::new(&[0x29; 16]),
                    NasCount::MAX,
                    access,
                    direction.into(),
                    &wire[6..],
                    Nia::NIA2,
                );
                assert_eq!(&wire[2..6], mac.to_be_bytes());
                assert_eq!(sender.count_ref(direction, access), 0x0100_0000);
                // After the last COUNT the context protects and verifies
                // nothing more in the direction, and says so by a variant.
                assert_eq!(
                    sender.protect_opaque_payload_for_access(vec![0xff], sht, direction, access),
                    Err(NasError::NasCountExhausted)
                );
                let received = [&wire[..], &[0x7e]].concat();
                assert_eq!(
                    sender.unprotect_raw_for_access(&received, direction, access),
                    Err(NasError::NasCountExhausted)
                );
                assert_eq!(sender.count_ref(direction, access), 0x0100_0000);
                assert_eq!(sender.nas_count(direction, access), None);
            }
        }
    }

    #[test]
    fn eps_mobility_request_is_protected_with_the_5g_context() {
        let mut ue = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x21; 16]),
            &KNasEnc::new(&[0x22; 16]),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA0,
        )
        .unwrap();
        *ue.count_mut(Direction::Uplink, NasConnection::ThreeGpp) = (0x0102).into();
        let mut amf = ue.clone();
        // A TAU REQUEST: update type, KSI, and old GUTI are enough here.
        let tau = [
            0x07, 0x48, 0x00, 0x0b, 0xf6, 0x02, 0xf8, 0x39, 0x80, 0x01, 0x01, 0, 0, 0, 1,
        ];
        let (pdu, used) = ue.protect_eps_message(&tau).unwrap();
        assert_eq!(used, count(0x0102));
        assert_eq!((pdu[0], pdu[5]), (0x17, 0x02));
        let expected = nas_mac(
            &KNasInt::new(&[0x21; 16]),
            count(0x0102),
            NasConnection::ThreeGpp,
            Direction::Uplink.into(),
            &pdu[5..],
            Nia::NIA2,
        );
        assert_eq!(u32::from_be_bytes(pdu[1..5].try_into().unwrap()), expected);
        assert_eq!(
            ue.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            0x0103
        );
        assert_eq!(
            amf.unprotect_eps_message(&pdu).unwrap(),
            (tau.to_vec(), count(0x0102))
        );
        assert_eq!(
            amf.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            0x0103
        );
        // Replay and tampering are rejected without changing the COUNT.
        assert!(amf.unprotect_eps_message(&pdu).is_err());
        let (mut tampered, _) = ue.protect_eps_message(&tau).unwrap();
        tampered[10] ^= 1;
        assert_eq!(
            amf.unprotect_eps_message(&tampered),
            Err(NasError::IntegrityCheckFailed)
        );
        assert_eq!(
            amf.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            0x0103
        );
        assert!(ue.protect_eps_message(&[0x07, 0x43, 0x00, 0x00]).is_err());

        let mut invalid_sender = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x21; 16]),
            &KNasEnc::new(&[0x22; 16]),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA0,
        )
        .unwrap();
        let mut invalid_receiver = invalid_sender.clone();
        let invalid_plain = [0x07, 0x43, 0x00, 0x00];
        let mut invalid_pdu = vec![0x17];
        let mac_input = [&[0][..], &invalid_plain].concat();
        let mac = nas_mac(
            &KNasInt::new(&[0x21; 16]),
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
        assert_eq!(
            invalid_receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            1
        );

        let (valid_pdu, _) = invalid_sender.protect_eps_message(&tau).unwrap();
        assert!(invalid_receiver.unprotect_eps_message(&valid_pdu).is_err());
        assert_eq!(
            invalid_receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            1
        );
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
            &KNasInt::new(&[0; 16]),
            &KNasEnc::new(&[0; 16]),
            IntegrityAlgorithm::NIA0,
            CipheringAlgorithm::NEA0,
        )
        .unwrap();
        for (message, required_sht, wrong_sht, direction, wrong_direction) in [
            (
                &command,
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
                Direction::Uplink,
            ),
            (
                &complete,
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
                Nas5gsSecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                Direction::Downlink,
            ),
        ] {
            assert!(tx.protect(message, wrong_sht, direction).is_err());
            assert!(tx.protect(message, required_sht, wrong_direction).is_err());
            let wire = tx.protect(message, required_sht, direction).unwrap();
            let mut rx = NasSecurityContext::from_fresh_keys(
                &KNasInt::new(&[0; 16]),
                &KNasEnc::new(&[0; 16]),
                IntegrityAlgorithm::NIA0,
                CipheringAlgorithm::NEA0,
            )
            .unwrap();
            assert!(rx.unprotect(&wire, wrong_direction).is_err());
            assert!(rx.unprotect(&wire, direction).is_ok());
        }
    }

    #[test]
    fn nia0_takes_a_message_again_with_a_higher_count() {
        // TS 24.501 §4.4.3.2, TS 33.501 §6.4.3.2 and annex D.1: no replay
        // protection and no MAC with NIA0. A message received again is taken
        // with a COUNT higher than the stored one (§4.4.3.1), which wraps
        // (§4.4.3.5). With NIA2 the same message is refused.
        let status = Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasFGmmStatus::new(
            crate::nas_5gs::NasFGmmCause::new(0x6f),
        ));
        let context = |nia, nea| {
            NasSecurityContext::from_fresh_keys(
                &KNasInt::new(&[0x61; 16]),
                &KNasEnc::new(&[0x62; 16]),
                nia,
                nea,
            )
            .unwrap()
        };
        let (downlink, access) = (Direction::Downlink, NasConnection::ThreeGpp);
        let sht = Nas5gsSecurityHeaderType::IntegrityProtected;
        let mut amf = context(IntegrityAlgorithm::NIA0, CipheringAlgorithm::NEA0);
        let mut ue = context(IntegrityAlgorithm::NIA0, CipheringAlgorithm::NEA0);
        *amf.count_mut(downlink, access) = (0x00ff_ffff).into();
        *ue.count_mut(downlink, access) = (0x00ff_ffff).into();
        let wire = amf.protect(&status, sht, downlink).unwrap();
        assert_eq!(amf.count_ref(downlink, access), 0);
        assert_eq!(
            ue.unprotect(&wire, downlink).unwrap().count,
            count(0x00ff_ffff)
        );
        assert_eq!(ue.unprotect(&wire, downlink).unwrap().count, count(0xff));
        assert_eq!(ue.unprotect(&wire, downlink).unwrap().count, count(0x01ff));
        assert_eq!(ue.count_ref(downlink, access), 0x0200);

        let mut amf = context(IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA0);
        let mut ue = context(IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA0);
        let wire = amf.protect(&status, sht, downlink).unwrap();
        assert_eq!(ue.unprotect(&wire, downlink).unwrap().count, count(0));
        assert!(matches!(
            ue.unprotect(&wire, downlink),
            Err(NasError::IntegrityCheckFailed)
        ));
        assert_eq!(ue.count_ref(downlink, access), 1);
    }

    #[test]
    fn a_security_mode_command_is_verified_by_the_context_that_it_takes_into_use() {
        // Every SECURITY MODE COMMAND has the header "integrity protected
        // with new 5G NAS security context" (TS 24.501 §5.4.2.2). One for
        // the context in use, or for new algorithms under its KAMF, has its
        // COUNTs, and the UE keeps the downlink COUNT that verified it
        // (§5.4.2.3); one after an authentication has a new KAMF and a
        // downlink COUNT of 0.
        use crate::nas_5gs::messages::NasSecurityModeCommand;
        use crate::nas_5gs::types::{
            NasKeySetIdentifier, NasSecurityAlgorithms, NasUeSecurityCapability,
        };
        let command = |nia, nea| {
            Nas5gsMessage::new_5gmm(NasSecurityModeCommand::new(
                NasSecurityAlgorithms::from_algorithms(nea, nia),
                NasKeySetIdentifier::new(0),
                NasUeSecurityCapability::new(vec![0xf0, 0xf0]),
            ))
        };
        let status = Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasFGmmStatus::new(
            crate::nas_5gs::NasFGmmCause::new(0x6f),
        ));
        let new_context =
            Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext;
        let (downlink, access) = (Direction::Downlink, NasConnection::ThreeGpp);
        let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
        let kamf = KAmf::new(&[0x51; 32]);
        let mut amf = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        let mut ue = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        for _ in 0..3 {
            let sent = amf
                .protect(
                    &status,
                    Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                    downlink,
                )
                .unwrap();
            ue.unprotect(&sent, downlink).unwrap();
        }

        // The context in use
        let sent = amf
            .protect(&command(nia, nea), new_context, downlink)
            .unwrap();
        let verified = ue.unprotect(&sent, downlink).unwrap();
        assert_eq!(
            (verified.count, verified.security_header_type),
            (count(3), new_context)
        );

        // New algorithms: the context in use refuses the command and keeps
        // its COUNT, one with the new algorithms and its COUNTs verifies it
        let (nia, nea) = (IntegrityAlgorithm::NIA1, CipheringAlgorithm::NEA1);
        amf.reselect_algorithms(&kamf, nia, nea).unwrap();
        let sent = amf
            .protect(&command(nia, nea), new_context, downlink)
            .unwrap();
        assert!(matches!(
            ue.unprotect(&sent, downlink),
            Err(NasError::IntegrityCheckFailed)
        ));
        assert_eq!(ue.count_ref(downlink, access), 4);
        let counts = |connection| {
            (
                ue.nas_count(Direction::Uplink, connection),
                ue.nas_count(downlink, connection),
            )
        };
        let mut reselected = NasSecurityContext::restore_from_kamf(
            &kamf,
            nia,
            nea,
            counts(NasConnection::ThreeGpp),
            counts(NasConnection::Non3Gpp),
        )
        .unwrap();
        assert_eq!(
            reselected.unprotect(&sent, downlink).unwrap().count,
            count(4)
        );

        // After an authentication
        let kamf = KAmf::new(&[0x52; 32]);
        let mut amf = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        let sent = amf
            .protect(&command(nia, nea), new_context, downlink)
            .unwrap();
        assert!(reselected.unprotect(&sent, downlink).is_err());
        let mut fresh = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        assert_eq!(fresh.unprotect(&sent, downlink).unwrap().count, count(0));
    }

    #[test]
    fn mapped_eps_context_starts_5gs_counts_at_zero() {
        let kasme = KAsme::new(&core::array::from_fn(|i| i as u8));
        let nh = Nh::new(&core::array::from_fn(|i| (i + 32) as u8));
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
        assert_eq!(
            (
                idle.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
                idle.count_ref(Direction::Downlink, NasConnection::ThreeGpp)
            ),
            ((0).into(), (0).into())
        );
        assert_eq!(
            (
                handover.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
                handover.count_ref(Direction::Downlink, NasConnection::ThreeGpp)
            ),
            ((0).into(), (0).into())
        );
        assert_ne!(idle.core.keys.integrity, handover.core.keys.integrity);
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
        assert_eq!(
            idle.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            1
        );
    }

    #[test]
    fn test_protect_unprotect_roundtrip_integrity_only() {
        let key_int = [0x01u8; 16];
        let key_enc = [0x02u8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
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
        let Verified {
            message: _decoded,
            security_header_type: sht,
            ..
        } = rx.unprotect(&protected, Direction::Uplink).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtected);

        // Verify counts advanced
        assert_eq!(tx.count_ref(Direction::Uplink, NasConnection::ThreeGpp), 1);
        assert_eq!(rx.count_ref(Direction::Uplink, NasConnection::ThreeGpp), 1);
    }

    #[test]
    fn test_protect_unprotect_roundtrip_ciphered() {
        let key_int = [0xABu8; 16];
        let key_enc = [0xCDu8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
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

        let Verified {
            message: _decoded,
            security_header_type: sht,
            ..
        } = rx.unprotect(&protected, Direction::Downlink).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered);
        assert_eq!(
            tx.count_ref(Direction::Downlink, NasConnection::ThreeGpp),
            1
        );
        assert_eq!(
            rx.count_ref(Direction::Downlink, NasConnection::ThreeGpp),
            1
        );
    }

    #[test]
    fn fixed_direction_5gmm_messages_are_rejected_in_the_other_direction() {
        // TS 24.501 Chapter 8 gives each 5GMM message except 5GMM STATUS one
        // sending side; protection and verification both enforce it.
        let uplink =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());
        let status = Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasFGmmStatus::new(
            crate::nas_5gs::NasFGmmCause::new(0x6f),
        ));
        let context = || {
            NasSecurityContext::from_fresh_keys(
                &KNasInt::new(&[0x21; 16]),
                &KNasEnc::new(&[0x43; 16]),
                IntegrityAlgorithm::NIA2,
                CipheringAlgorithm::NEA2,
            )
            .unwrap()
        };
        let sht = Nas5gsSecurityHeaderType::IntegrityProtected;
        let mut tx = context();
        assert!(tx.protect(&uplink, sht, Direction::Downlink).is_err());
        assert_eq!(
            tx.count_ref(Direction::Downlink, NasConnection::ThreeGpp),
            0
        );
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
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
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
        .with_abba(crate::nas_5gs::types::NasAbba::new(vec![0x00, 0x00]));
        let inner = Nas5gsMessage::new_5gmm(smc);
        let plain = inner.encode().unwrap();

        let protected = tx
            .protect(
                &inner,
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                Direction::Downlink,
            )
            .unwrap();

        assert_eq!(protected[1], 0x03);
        assert_eq!(&protected[7..], plain.as_slice());

        let Verified {
            message: decoded,
            security_header_type: sht,
            ..
        } = rx.unprotect(&protected, Direction::Downlink).unwrap();
        assert_eq!(
            sht,
            Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext
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
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&[0xFFu8; 16]),
            &KNasEnc::new(&key_enc),
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
        assert_eq!(rx.count_ref(Direction::Uplink, NasConnection::ThreeGpp), 0);
    }

    #[test]
    fn test_unprotect_estimates_count_from_sequence_number() {
        let key_int = [0x11u8; 16];
        let key_enc = [0x22u8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
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
        let Verified {
            security_header_type: sht,
            ..
        } = rx.unprotect(&second, Direction::Uplink).unwrap();
        assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtected);
        assert_eq!(second[6], 0x01);
        assert_eq!(rx.count_ref(Direction::Uplink, NasConnection::ThreeGpp), 2);
    }

    #[test]
    fn nia0_requires_nea0() {
        let message =
            Nas5gsMessage::new_5gmm(crate::nas_5gs::messages::NasRegistrationComplete::new());
        let keys = ([0; 16], [0; 16]);
        let context = |nea| {
            NasSecurityContext::from_fresh_keys(
                &KNasInt::new(&keys.0),
                &KNasEnc::new(&keys.1),
                IntegrityAlgorithm::NIA0,
                nea,
            )
        };
        assert!(context(CipheringAlgorithm::NEA2).is_err());
        assert!(context(CipheringAlgorithm::NEA0).is_ok());
        let kamf = KAmf::new(&[0x24; 32]);
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
                &KNasInt::new(&[0x31; 16]),
                &KNasEnc::new(&[0x32; 16]),
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
        let Verified {
            message: decoded,
            security_header_type: sht,
            ..
        } = context().unprotect(&wire, Direction::Uplink).unwrap();
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
                    &KNasInt::new(&[0x31; 16]),
                    &KNasEnc::new(&[0x32; 16]),
                    IntegrityAlgorithm::NIA2,
                    CipheringAlgorithm::NEA2,
                )
                .unwrap()
            };
            let mut sender = context();
            let mut receiver = context();
            *sender.count_mut(Direction::Uplink, NasConnection::ThreeGpp) = (sender_count).into();
            *receiver.count_mut(Direction::Uplink, NasConnection::ThreeGpp) =
                (receiver_next).into();
            let wire = sender
                .protect(
                    &message,
                    Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
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
            assert_eq!(
                receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
                sender_count + 1
            );
            assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
            assert_eq!(
                receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
                sender_count + 1
            );
        }
    }

    #[test]
    fn test_non_3gpp_access_counts_are_separate() {
        let key_int = [0x31u8; 16];
        let key_enc = [0x41u8; 16];

        let mut tx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();
        let mut rx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
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

        assert_eq!(
            tx.count_ref(Direction::Downlink, NasConnection::ThreeGpp),
            0
        );
        assert_eq!(tx.count_ref(Direction::Downlink, NasConnection::Non3Gpp), 1);

        let Verified { .. } = rx
            .unprotect_for_access(&protected, Direction::Downlink, NasConnection::Non3Gpp)
            .unwrap();

        assert_eq!(
            rx.count_ref(Direction::Downlink, NasConnection::ThreeGpp),
            0
        );
        assert_eq!(rx.count_ref(Direction::Downlink, NasConnection::Non3Gpp), 1);
    }

    #[test]
    fn test_protect_bytes_rejects_plain_5gsm_inner_message() {
        let mut ctx = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x51u8; 16]),
            &KNasEnc::new(&[0x61u8; 16]),
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
        )
        .unwrap();

        let inner = Nas5gsMessage::new_5gsm(
            crate::nas_5gs::messages::NasPduSessionEstablishmentRequest::new(
                crate::nas_5gs::NasIntegrityProtectionMaximumDataRate::from_rates(
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
        let kamf = KAmf::new(&[0x24; 32]);
        let mut context = NasSecurityContext::restore_from_kamf(
            &kamf,
            IntegrityAlgorithm::NIA2,
            CipheringAlgorithm::NEA2,
            (Some(count(0x0012_3456)), Some(count(0x0000_abcd))),
            (Some(count(0x0000_1234)), None),
        )
        .unwrap();
        let old_keys = (
            context.core.keys.integrity.clone(),
            context.core.keys.ciphering.clone(),
        );
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
        assert_ne!(
            (&context.core.keys.integrity, &context.core.keys.ciphering),
            (&old_keys.0, &old_keys.1)
        );

        // A direction whose COUNTs are all used protects nothing more.
        let reject = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();
        let sht = Nas5gsSecurityHeaderType::IntegrityProtected;
        assert_eq!(
            context.protect_for_access(&reject, sht, Direction::Downlink, NasConnection::Non3Gpp),
            Err(NasError::NasCountExhausted)
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
            &KNasInt::new(&[0x71u8; 16]),
            &KNasEnc::new(&[0x81u8; 16]),
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
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                Direction::Uplink,
            )
            .is_err()
        );
    }

    #[test]
    fn protected_5gs_commits_authenticated_count_before_inner_validation() {
        let key = [0x29; 16];
        let mut sender = NasSecurityContext::from_fresh_keys(
            &KNasInt::new(&key),
            &KNasEnc::new(&key),
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
        assert_eq!(
            receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            0
        );
        let mut bad_inner = wire.clone();
        bad_inner[9] = 0xff;
        let mac = nas_mac(
            &KNasInt::new(&key),
            NasCount::ZERO,
            NasConnection::ThreeGpp,
            Direction::Uplink.into(),
            &bad_inner[6..],
            Nia::NIA2,
        );
        bad_inner[2..6].copy_from_slice(&mac.to_be_bytes());
        assert!(receiver.unprotect(&bad_inner, Direction::Uplink).is_err());
        assert_eq!(
            receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            1
        );
        assert!(receiver.unprotect(&wire, Direction::Uplink).is_err());
        assert_eq!(
            receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            1
        );
    }

    #[test]
    fn a_reserved_5gs_algorithm_makes_no_context() {
        // The codes 4 to 7 of TS 24.501 Table 9.11.3.34.1 are reserved: no
        // key is derived and nothing is computed with one.
        let kamf = KAmf::new(&[0x24; 32]);
        for reserved in [
            IntegrityAlgorithm::NIA4,
            IntegrityAlgorithm::NIA5,
            IntegrityAlgorithm::NIA6,
            IntegrityAlgorithm::NIA7,
        ] {
            assert!(oxirush_security::IntegrityAlgorithm::try_from(reserved).is_err());
            let nea = CipheringAlgorithm::NEA2;
            assert!(
                NasSecurityContext::from_fresh_keys(
                    &KNasInt::new(&[0; 16]),
                    &KNasEnc::new(&[0; 16]),
                    reserved,
                    nea
                )
                .is_err()
            );
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
            assert!(
                NasSecurityContext::from_fresh_keys(
                    &KNasInt::new(&[0; 16]),
                    &KNasEnc::new(&[0; 16]),
                    nia,
                    reserved
                )
                .is_err()
            );
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
            NasConnection::from(AccessTypeValue::ThreeGppAccess),
            NasConnection::ThreeGpp
        );
        assert_eq!(
            NasConnection::from(AccessTypeValue::Non3GppAccess),
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
