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
//! This module provides [`SecurityContext`] which wraps NAS keys and algorithms
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
//! ([`Error::NasCountExhausted`]).
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::identity::Algorithm;
//! use oxirush_nas::nas_5gs::{KAmf, Message, NasConnection, SecurityHeaderType, SecurityContext};
//! use oxirush_nas::{Direction, NasCount};
//!
//! // REGISTRATION REJECT, cause #3
//! let msg = Message::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();
//!
//! // The two ends of one link: the same KAMF and the same algorithms
//! let kamf = KAmf::new(&[0x11; 32]);
//! let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
//! let mut tx = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
//! let mut rx = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
//!
//! // Protect outbound, over 3GPP access: integrity and ciphering
//! let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
//! let access = NasConnection::ThreeGpp;
//! let protected = tx.protect(&msg, sht, Direction::Downlink, access).unwrap();
//!
//! // Unprotect inbound: MAC check, deciphering and decoding
//! let verified = rx.unprotect(&protected, Direction::Downlink, access).unwrap();
//! assert_eq!(verified.message, msg);
//! assert_eq!(verified.security_header_type, sht);
//! assert_eq!(verified.count, NasCount::ZERO);
//! ```
//!
//! `protect` validates the inner message. For negative tests,
//! `protect_opaque_payload` ciphers and integrity-protects any inner octets
//! under security header types 1 to 4.

use crate::common::{Core, Direction, Keys, NextCount, System, wiped};
use crate::nas_5gs::AccessTypeValue;
use crate::nas_5gs::MessageContainer;
use crate::nas_5gs::SecurityHeaderType;
use crate::nas_5gs::{
    ControlPlaneServiceRequest, DeregistrationRequestUeOriginating, GmmMessage, Message,
    RegistrationRequest, ServiceRequest, validate_security_protected_inner_message,
};
use crate::nas_5gs::{EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, Error, Result};
use crate::nas_5gs::{
    KeySetIdentifier, N1ModeToS1ModeNasTransparentContainer, S1ModeToN1ModeNasTransparentContainer,
    SecurityAlgorithms,
};
use crate::prelude::*;
use core::fmt;
use oxirush_security::NasCount;
use oxirush_security::nas_5gs::{
    KAmf, KNasEnc, KNasInt, NasConnection, derive_knas_enc, derive_knas_int,
    derive_mapped_kamf_handover, derive_mapped_kamf_idle,
};
use oxirush_security::nas_eps::{KAsme, Nh};
use oxirush_utils::identity::Algorithm;

/// A message that a security context verified, and what it was verified
/// with.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct Verified<M> {
    /// The message to act on: decoded, or its plain octets from
    /// `unprotect_raw`. It is the message under the security header, or
    /// the complete initial NAS message that this one carries ciphered
    /// (TS 24.501 §4.4.6): see [`SecurityContext::unprotect`].
    pub message: M,
    /// The security header type that the message came under.
    pub security_header_type: SecurityHeaderType,
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
    message: Message,
    initial: Option<(Vec<u8>, Message)>,
}

/// What `error` of the plain message `plain` is once the code of the
/// message was verified.
fn refused(error: Error, plain: &[u8]) -> Error {
    Error::AuthenticMessageRefused {
        error: Box::new(error),
        plain: plain.into(),
    }
}

/// [`refused`] for an error of the checks of a received message, which are
/// those of a sender: a message that is not one to receive does not decode.
fn refused_received(error: Error, plain: &[u8]) -> Error {
    match error {
        Error::EncodingError(message) => refused(Error::DecodingError(message), plain),
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
    Contained(GmmMessage),
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
fn initial_form(message: &GmmMessage) -> Result<InitialForm> {
    let contained = |with_container: bool, cleartext: GmmMessage| match with_container {
        true => Err(Error::EncodingError(
            "the NAS message container of an initial NAS message is made by the security \
             context: the message is given without one"
                .into(),
        )),
        false if cleartext == *message => Ok(InitialForm::Cleartext),
        false => Ok(InitialForm::Contained(cleartext)),
    };
    match message {
        GmmMessage::RegistrationRequest(request) => {
            let mut cleartext = RegistrationRequest::new(
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
        GmmMessage::DeregistrationRequestUeOriginating(request) => {
            let cleartext = DeregistrationRequestUeOriginating::new(
                request.de_registration_type,
                request.ngksi,
                request.fgs_mobile_identity.clone(),
            );
            contained(request.nas_message_container.is_some(), cleartext.into())
        }
        GmmMessage::ServiceRequest(request) => {
            let cleartext = ServiceRequest::new(
                request.ngksi,
                request.service_type,
                request.fg_s_tmsi.clone(),
            );
            contained(request.nas_message_container.is_some(), cleartext.into())
        }
        GmmMessage::ControlPlaneServiceRequest(request) => {
            let cleartext =
                ControlPlaneServiceRequest::new(request.control_plane_service_type, request.ngksi);
            let mut small_data = cleartext.clone();
            small_data.ciot_small_data_container = request.ciot_small_data_container.clone();
            match request.ciot_small_data_container.is_some() && small_data == **request {
                true => Ok(InitialForm::SmallData),
                false => contained(request.nas_message_container.is_some(), cleartext.into()),
            }
        }
        other => Err(Error::EncodingError(format!(
            "{:?} is no initial NAS message: REGISTRATION REQUEST, DEREGISTRATION REQUEST from \
             the UE, SERVICE REQUEST and CONTROL PLANE SERVICE REQUEST are",
            other.message_type()
        ))),
    }
}

/// Give the initial NAS message `message` its NAS message container.
fn contain(message: &mut GmmMessage, container: MessageContainer) {
    let place = match message {
        GmmMessage::RegistrationRequest(request) => &mut request.nas_message_container,
        GmmMessage::DeregistrationRequestUeOriginating(request) => {
            &mut request.nas_message_container
        }
        GmmMessage::ServiceRequest(request) => &mut request.nas_message_container,
        GmmMessage::ControlPlaneServiceRequest(request) => &mut request.nas_message_container,
        _ => return,
    };
    *place = Some(container);
}

/// Whether `message` is one that a context protects under `sht` in
/// `direction`: a plain message of that direction, under a header type that
/// protects it.
fn check_protected(message: &Message, sht: SecurityHeaderType, direction: Direction) -> Result<()> {
    if sht == SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected {
        return Err(Error::SecurityRefused(format!(
            "{sht:?} is no header type that protects a message"
        )));
    }
    validate_security_protected_inner_message(message, sht)?;
    validate_message_direction(message, direction)
}

fn validate_message_direction(message: &Message, direction: Direction) -> Result<()> {
    let Message::Gmm(_, inner) = message else {
        return Ok(());
    };
    // TS 24.501 Chapter 8 assigns a sending side to each 5GMM message.
    let required_direction = match inner {
        GmmMessage::RegistrationRequest(_)
        | GmmMessage::RegistrationComplete(_)
        | GmmMessage::DeregistrationRequestUeOriginating(_)
        | GmmMessage::DeregistrationAcceptUeTerminated(_)
        | GmmMessage::ConfigurationUpdateComplete(_)
        | GmmMessage::ServiceRequest(_)
        | GmmMessage::AuthenticationResponse(_)
        | GmmMessage::AuthenticationFailure(_)
        | GmmMessage::IdentityResponse(_)
        | GmmMessage::SecurityModeComplete(_)
        | GmmMessage::SecurityModeReject(_)
        | GmmMessage::NotificationResponse(_)
        | GmmMessage::UlNasTransport(_)
        | GmmMessage::ControlPlaneServiceRequest(_)
        | GmmMessage::NetworkSliceSpecificAuthenticationComplete(_)
        | GmmMessage::RelayKeyRequest(_)
        | GmmMessage::RelayAuthenticationResponse(_) => Some(Direction::Uplink),
        GmmMessage::RegistrationAccept(_)
        | GmmMessage::RegistrationReject(_)
        | GmmMessage::DeregistrationRequestUeTerminated(_)
        | GmmMessage::DeregistrationAcceptUeOriginating(_)
        | GmmMessage::ServiceAccept(_)
        | GmmMessage::ServiceReject(_)
        | GmmMessage::ConfigurationUpdateCommand(_)
        | GmmMessage::AuthenticationRequest(_)
        | GmmMessage::AuthenticationReject(_)
        | GmmMessage::AuthenticationResult(_)
        | GmmMessage::IdentityRequest(_)
        | GmmMessage::SecurityModeCommand(_)
        | GmmMessage::Notification(_)
        | GmmMessage::DlNasTransport(_)
        | GmmMessage::NetworkSliceSpecificAuthenticationCommand(_)
        | GmmMessage::NetworkSliceSpecificAuthenticationResult(_)
        | GmmMessage::RelayKeyAccept(_)
        | GmmMessage::RelayKeyReject(_)
        | GmmMessage::RelayAuthenticationRequest(_) => Some(Direction::Downlink),
        GmmMessage::FiveGmmStatus(_) => None,
    };
    match required_direction {
        Some(required) if required != direction => Err(Error::EncodingError(format!(
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
///
/// ```
/// use oxirush_nas::identity::Algorithm;
/// use oxirush_nas::nas_5gs::*;
/// use oxirush_nas::{Direction, NasCount};
///
/// // The AMF and the UE, with the KAMF of their authentication
/// let kamf = KAmf::new(&[0x11; 32]);
/// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
/// let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
/// let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
///
/// // Each message takes the next NAS COUNT of its direction
/// let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
/// let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
/// let access = NasConnection::ThreeGpp;
/// let octets = amf.protect(&status, header, Direction::Downlink, access).unwrap();
/// let received = ue.unprotect(&octets, Direction::Downlink, access).unwrap();
/// assert_eq!((received.message, received.count.get()), (status, 0));
/// let next = ue.nas_count(Direction::Downlink, access);
/// assert_eq!(next, Some(NasCount::new(1).unwrap()));
/// ```
#[cfg_attr(test, derive(Clone))]
pub struct SecurityContext {
    /// The keys, the algorithms and the COUNTs of each access.
    core: Core<FiveGs>,
}

/// The system of the 5GS contexts: KNASint and KNASenc of TS 33.501, the
/// codes of TS 24.501 §9.11.3.34, and the two NAS connections.
pub(crate) enum FiveGs {}

impl System for FiveGs {
    type IntegrityKey = KNasInt;
    type CipheringKey = KNasEnc;
    type Connection = NasConnection;
    type Counts = [[NextCount; 2]; 2];
    type Accepted = [[u64; 2]; 2];
    const NAME: &'static str = "5GS";
    const NULL_NAMES: (&'static str, &'static str) = ("NIA0", "NEA0");

    fn place(connection: NasConnection) -> usize {
        // The NAS connection identifiers are 1 and 2.
        usize::from(u8::from(connection)).saturating_sub(1).min(1)
    }

    fn bearer(connection: NasConnection) -> oxirush_security::Bearer {
        connection.into()
    }
}

impl fmt::Debug for SecurityContext {
    /// The algorithms and the next NAS COUNTs, without the keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = |direction, connection| self.nas_count(direction, connection);
        f.debug_struct("SecurityContext")
            .field("integrity_algorithm", &self.core.integrity)
            .field("ciphering_algorithm", &self.core.ciphering)
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

impl SecurityContext {
    /// Create a context for genuinely fresh NAS keys with COUNT values at zero.
    ///
    /// Reusing the same keys with this constructor violates TS 33.501 §6.4.5;
    /// use [`Self::reselect_algorithms`] for an existing KAMF. A reserved
    /// algorithm (the codes 4 to 7) and NIA0 with another cipher than NEA0
    /// are errors.
    pub fn from_fresh_keys(
        knas_int: &KNasInt,
        knas_enc: &KNasEnc,
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<Self> {
        let keys = |_, _| Keys {
            integrity: knas_int.clone(),
            ciphering: knas_enc.clone(),
        };
        let core = Core::derived(integrity, ciphering, keys)?;
        Ok(Self { core })
    }

    /// Derive a fresh 5GS NAS context from a newly established KAMF.
    ///
    /// COUNT starts at zero. Calling this again for the same KAMF would violate
    /// TS 33.501 §6.4.5; use [`Self::reselect_algorithms`] instead. The
    /// algorithms are checked as [`Self::from_fresh_keys`] checks them.
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::{Direction, NasCount};
    ///
    /// // After the authentication: each direction starts at NAS COUNT 0
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// let count = amf.nas_count(Direction::Downlink, NasConnection::ThreeGpp);
    /// assert_eq!(count, Some(NasCount::ZERO));
    ///
    /// // The null integrity algorithm goes with the null cipher alone
    /// let refused = SecurityContext::from_fresh_kamf(&kamf, Algorithm::Null, nea);
    /// assert!(refused.is_err());
    /// ```
    pub fn from_fresh_kamf(
        kamf: &KAmf,
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<Self> {
        let core = Core::derived(integrity, ciphering, |integrity, ciphering| Keys {
            integrity: derive_knas_int(kamf, integrity),
            ciphering: derive_knas_enc(kamf, ciphering),
        })?;
        Ok(Self { core })
    }

    /// Selected integrity algorithm.
    pub fn integrity_algorithm(&self) -> Algorithm {
        self.core.integrity
    }

    /// Selected ciphering algorithm.
    pub fn ciphering_algorithm(&self) -> Algorithm {
        self.core.ciphering
    }

    /// Next NAS COUNT to use or expect for a direction and access type:
    /// `None` when every COUNT of the direction was used, after which the
    /// context protects nothing more in it.
    pub fn nas_count(&self, direction: Direction, connection: NasConnection) -> Option<NasCount> {
        self.core.count(direction, connection).get()
    }

    /// How many COUNTs below the highest that the context accepted in a
    /// direction its replay window holds: 0, the default, for none.
    pub fn replay_window(&self) -> u8 {
        self.core.window()
    }

    /// Take a received message whose NAS COUNT is below the highest that the
    /// context accepted in its direction, once. A receiver that can guarantee
    /// that a message was not accepted before may estimate its COUNT below
    /// the stored one (TS 24.501 §4.4.3.1), as a message that the sender
    /// protected first can come after the next one. With a window of `size`,
    /// the context takes a message of one of the `size` COUNTs below the
    /// highest that it accepted, if it has not accepted it and its code
    /// verifies with that COUNT; the next COUNT stays the one after the
    /// highest. A COUNT that it accepted, and one below the window, are
    /// refused as replays (§4.4.3.2). The COUNTs below the next one when the
    /// window is set, and below one that is set or restored, are taken as
    /// accepted. A window of 0, the default, takes none; one of more than
    /// [`MAX_REPLAY_WINDOW`](crate::MAX_REPLAY_WINDOW) is an error.
    /// The null integrity algorithm has no replay protection and no window.
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::{Direction, NasCount};
    ///
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// ue.set_replay_window(32).unwrap();
    ///
    /// // Two messages, of COUNT 0 and 1, which come in the other order
    /// let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
    /// let access = NasConnection::ThreeGpp;
    /// let first = amf.protect(&status, header, Direction::Downlink, access).unwrap();
    /// let second = amf.protect(&status, header, Direction::Downlink, access).unwrap();
    /// assert_eq!(ue.unprotect(&second, Direction::Downlink, access).unwrap().count.get(), 1);
    /// assert_eq!(ue.unprotect(&first, Direction::Downlink, access).unwrap().count.get(), 0);
    ///
    /// // Each once, and the next COUNT is the one after the highest
    /// assert!(ue.unprotect(&first, Direction::Downlink, access).is_err());
    /// let next = ue.nas_count(Direction::Downlink, access);
    /// assert_eq!(next, Some(NasCount::new(2).unwrap()));
    /// ```
    pub fn set_replay_window(&mut self, size: u8) -> Result<()> {
        self.core.set_window(size)
    }

    /// Restore a 5GS context and its next COUNT values from persistent state.
    ///
    /// The caller must supply the counts stored for this exact KAMF, as
    /// [`Self::nas_count`] gave them: the uplink then the downlink COUNT of
    /// each access, `None` for one that is exhausted. Passing zero for a KAMF
    /// that has already protected traffic violates TS 33.501 §6.4.5.
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::{Direction, NasCount};
    ///
    /// // The next uplink and downlink COUNTs of 3GPP access, as `nas_count` gave
    /// // them before a restart
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let three_gpp = (Some(NasCount::new(2).unwrap()), Some(NasCount::new(3).unwrap()));
    /// let amf = SecurityContext::restore_from_kamf(&kamf, nia, nea, three_gpp, (None, None));
    /// let next = amf.unwrap().nas_count(Direction::Downlink, NasConnection::ThreeGpp);
    /// assert_eq!(next, Some(NasCount::new(3).unwrap()));
    /// ```
    pub fn restore_from_kamf(
        kamf: &KAmf,
        integrity: Algorithm,
        ciphering: Algorithm,
        three_gpp_counts: (Option<NasCount>, Option<NasCount>),
        non_3gpp_counts: (Option<NasCount>, Option<NasCount>),
    ) -> Result<Self> {
        let mut context = Self::from_fresh_kamf(kamf, integrity, ciphering)?;
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
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::Direction;
    ///
    /// // Both ends protect with 128-NIA2 and 128-NEA2
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia2, nea2) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia2, nea2).unwrap();
    /// let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia2, nea2).unwrap();
    /// let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
    /// let access = NasConnection::ThreeGpp;
    /// let first = amf.protect(&status, header, Direction::Downlink, access).unwrap();
    /// ue.unprotect(&first, Direction::Downlink, access).unwrap();
    ///
    /// // A SECURITY MODE COMMAND selects 128-NIA1 and 128-NEA1: each end takes
    /// // the keys of the new algorithms, and its NAS COUNTs go on
    /// let (nia1, nea1) = (Algorithm::Snow3g, Algorithm::Snow3g);
    /// amf.reselect_algorithms(&kamf, nia1, nea1).unwrap();
    /// ue.reselect_algorithms(&kamf, nia1, nea1).unwrap();
    /// let second = amf.protect(&status, header, Direction::Downlink, access).unwrap();
    /// let received = ue.unprotect(&second, Direction::Downlink, access).unwrap();
    /// assert_eq!((received.message, received.count.get()), (status, 1));
    /// ```
    pub fn reselect_algorithms(
        &mut self,
        kamf: &KAmf,
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<()> {
        // A key that is replaced is wiped as it is dropped.
        let derive = |integrity, ciphering| Keys {
            integrity: derive_knas_int(kamf, integrity),
            ciphering: derive_knas_enc(kamf, ciphering),
        };
        self.core.reselect(integrity, ciphering, derive)
    }

    /// Map an EPS KASME to a 5GS context for idle mobility.
    ///
    /// `tau_ul_nas_count` protects the EPS mobility-triggering message. The
    /// mapped 5GS NAS COUNT values start at zero. The mapped ngKSI is handled
    /// by the enclosing mobility procedure.
    pub fn from_mapped_kamf_idle(
        kasme: &KAsme,
        tau_ul_nas_count: NasCount,
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<Self> {
        wiped(|| {
            let kamf = derive_mapped_kamf_idle(kasme, tau_ul_nas_count);
            Self::from_fresh_kamf(&kamf, integrity, ciphering)
        })
    }

    /// Map an EPS KASME to a 5GS context for connected handover using NH.
    /// The mapped 5GS NAS COUNT values start at zero. This derivation has no
    /// COUNT input.
    pub fn from_mapped_kamf_handover(
        kasme: &KAsme,
        nh: &Nh,
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<Self> {
        wiped(|| {
            let kamf = derive_mapped_kamf_handover(kasme, nh);
            Self::from_fresh_kamf(&kamf, integrity, ciphering)
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
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::Direction;
    ///
    /// // The two ends of a link, with the same KAMF and the same algorithms
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    ///
    /// // A REGISTRATION ACCEPT, integrity protected and ciphered
    /// let result = RegistrationResult::from_result(RegistrationResultValue::ThreeGppAccess);
    /// let accept = Message::new_5gmm(RegistrationAccept::new(result));
    /// let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
    /// let access = NasConnection::ThreeGpp;
    /// let sent = amf.protect(&accept, header, Direction::Downlink, access).unwrap();
    /// assert_eq!(sent[..2], [0x7e, 0x02]);
    /// assert_eq!(ue.unprotect(&sent, Direction::Downlink, access).unwrap().message, accept);
    /// ```
    pub fn protect(
        &mut self,
        inner: &Message,
        sht: SecurityHeaderType,
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
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::Direction;
    /// use oxirush_nas::identity::{Guti5g, Plmn};
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    ///
    /// // A mobility registration update with a requested NSSAI
    /// let guti = Guti5g::new(Plmn::new("208", "93").unwrap(), 1, 1, 0, 0xc000_0001).unwrap();
    /// let kind = RegistrationTypeValue::MobilityRegistrationUpdating;
    /// let nssai = Nssai::from_snssais(&[SNssai::from_sst_sd(1, None)]).unwrap();
    /// let ngksi = KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Native(0));
    /// let request = RegistrationRequest::new(
    ///     RegistrationType::from_registration_type(kind),
    ///     ngksi.unwrap(),
    ///     MobileIdentity::from_guti(guti),
    /// )
    /// .with_requested_nssai(nssai);
    /// let request = Message::new_5gmm(request);
    /// let access = NasConnection::ThreeGpp;
    /// let sent = ue.protect_initial(&request, access).unwrap();
    ///
    /// // On the way, the NSSAI is in no IE that is read without the key
    /// let Message::SecurityProtected(_, cleartext) = Message::decode(&sent).unwrap()
    /// else {
    ///     unreachable!()
    /// };
    /// let Message::Gmm(_, GmmMessage::RegistrationRequest(cleartext)) = *cleartext
    /// else {
    ///     unreachable!()
    /// };
    /// assert!(cleartext.requested_nssai.is_none() && cleartext.nas_message_container.is_some());
    ///
    /// // The AMF acts on the complete message
    /// let verified = amf.unprotect(&sent, Direction::Uplink, access).unwrap();
    /// assert_eq!(verified.message, request);
    /// assert!(verified.sent.is_some());
    /// ```
    pub fn protect_initial(
        &mut self,
        message: &Message,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        let Message::Gmm(header, complete) = message else {
            return Err(Error::EncodingError(
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
                if matches!(complete, GmmMessage::ControlPlaneServiceRequest(_)) {
                    value.drain(..CPSR_CLEARTEXT);
                }
                cipher(&mut value);
                contain(&mut cleartext, MessageContainer::new(value));
                cleartext
            }
            InitialForm::SmallData => {
                let mut sent = complete.clone();
                if let GmmMessage::ControlPlaneServiceRequest(request) = &mut sent
                    && let Some(container) = &mut request.ciot_small_data_container
                {
                    cipher(&mut container.value);
                }
                sent
            }
        };
        let sent = Message::Gmm(*header, sent);
        let integrity_protected = SecurityHeaderType::IntegrityProtected;
        self.protect(&sent, integrity_protected, Direction::Uplink, connection)
    }

    /// The complete initial NAS message that `received` carries ciphered
    /// (TS 24.501 §4.4.6), and its octets: the message of its NAS message
    /// container, or the CONTROL PLANE SERVICE REQUEST itself with the value
    /// of its CIoT small data container deciphered. `None` for a message
    /// that carries none.
    fn initial(
        &self,
        received: &Message,
        plain: &[u8],
        count: NasCount,
        connection: NasConnection,
    ) -> Result<Option<(Vec<u8>, Message)>> {
        let Message::Gmm(header, message) = received else {
            return Ok(None);
        };
        let decipher = |octets: &mut [u8]| {
            (self.core).cipher(count, connection, Direction::Uplink, octets);
        };
        let container = match message {
            GmmMessage::RegistrationRequest(request) => &request.nas_message_container,
            GmmMessage::DeregistrationRequestUeOriginating(request) => {
                &request.nas_message_container
            }
            GmmMessage::ServiceRequest(request) => &request.nas_message_container,
            // The AMF deciphers the CIoT small data container if the
            // message has one, and the NAS message container otherwise
            // (TS 24.501 §5.6.1.4.2).
            GmmMessage::ControlPlaneServiceRequest(request)
                if request.ciot_small_data_container.is_some() =>
            {
                let mut complete = request.clone();
                if let Some(container) = &mut complete.ciot_small_data_container {
                    decipher(&mut container.value);
                }
                let complete =
                    Message::Gmm(*header, GmmMessage::ControlPlaneServiceRequest(complete));
                let octets = complete.encode().map_err(|error| refused(error, plain))?;
                return Ok(Some((octets, complete)));
            }
            GmmMessage::ControlPlaneServiceRequest(request) => &request.nas_message_container,
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
        if matches!(message, GmmMessage::ControlPlaneServiceRequest(_))
            && octets.first() != Some(&EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM)
        {
            let cleartext = plain.get(..CPSR_CLEARTEXT).unwrap_or(plain);
            octets = [cleartext, &octets].concat();
        }
        let complete = Message::decode(&octets).map_err(|error| refused(error, &octets))?;
        // The container has the entire message that it is in.
        match &complete {
            Message::Gmm(_, inner) if inner.message_type() == message.message_type() => {
                Ok(Some((octets, complete)))
            }
            _ => Err(refused(
                Error::DecodingError(format!(
                    "the NAS message container of a {:?} has another message",
                    message.message_type()
                )),
                &octets,
            )),
        }
    }

    /// Protect explicitly opaque or malformed inner bytes without codec checks.
    ///
    /// Only regular security headers 1 through 4 are supported. The payload is
    /// not decoded or re-encoded, so its message direction and header pairing
    /// are deliberately unchecked. Existing keys and COUNT are used even for
    /// a new-context header; no keys are installed and no COUNT is reset.
    /// COUNT advances once after successful composition. Checked receivers may
    /// reject the authenticated inner payload.
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::{Direction, Error};
    ///
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    ///
    /// // A negative test: a 5GMM STATUS without its cause, which `protect`
    /// // would refuse, under a MAC that is right
    /// let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
    /// let cut = vec![0x7e, 0x00, 0x64];
    /// let access = NasConnection::ThreeGpp;
    /// let octets = amf.protect_opaque_payload(cut, header, Direction::Downlink, access).unwrap();
    ///
    /// // The UE verifies the MAC, and refuses the message, whose plain octets
    /// // it has to answer it
    /// let refused = ue.unprotect(&octets, Direction::Downlink, access).unwrap_err();
    /// let Error::AuthenticMessageRefused { plain, .. } = refused else {
    ///     unreachable!()
    /// };
    /// assert_eq!(plain[..], [0x7e, 0x00, 0x64]);
    /// ```
    pub fn protect_opaque_payload(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: SecurityHeaderType,
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        if !matches!(
            sht,
            SecurityHeaderType::IntegrityProtected
                | SecurityHeaderType::IntegrityProtectedAndCiphered
                | SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext
                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        ) {
            return Err(Error::SecurityRefused(
                "opaque 5GS protection takes a header type that protects".into(),
            ));
        }
        self.protect_envelope(inner_bytes, sht, direction, connection)
    }

    /// The message under its security header `[EPD | SHT | MAC | SN]`,
    /// ciphered for the header types that cipher (TS 33.501 §6.4.3.1).
    fn protect_envelope(
        &mut self,
        inner_bytes: Vec<u8>,
        sht: SecurityHeaderType,
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Vec<u8>> {
        let ciphers = matches!(
            sht,
            SecurityHeaderType::IntegrityProtectedAndCiphered
                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
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
    /// refused for what it is, is [`Error::AuthenticMessageRefused`],
    /// with its COUNT used and its plain octets, deciphered, which
    /// [`Message::answer_to_refused`] answers.
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
    /// cleartext IEs that `Message::decode` reads in the same octets.
    ///
    /// A MAC mismatch returns [`Error::IntegrityCheckFailed`]. A receiver
    /// that must still process the message (TS 24.501 §4.4.4.3) can decode
    /// the PDU with
    /// [`Message::decode`],
    /// which returns the unverified inner message when it is not ciphered.
    ///
    /// With NIA0 no MAC is checked and no message is refused as a replay
    /// (§4.4.3.2, TS 33.501 annex D.1): a message received again is taken
    /// with a COUNT higher than the stored one (§4.4.3.1). A SECURITY MODE
    /// COMMAND is verified by the context that it takes into use, which the
    /// caller makes (§5.4.2.3): the context in use, with its COUNTs, one of
    /// [`Self::restore_from_kamf`] for new algorithms under its KAMF, or one
    /// of [`Self::from_fresh_kamf`] after an authentication.
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::{Direction, NasCount};
    ///
    /// // The two ends of a link, with the same KAMF and the same algorithms
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    ///
    /// // A 5GMM STATUS, then the same octets again: a replay
    /// let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
    /// let access = NasConnection::ThreeGpp;
    /// let sent = ue.protect(&status, header, Direction::Uplink, access).unwrap();
    /// let verified = amf.unprotect(&sent, Direction::Uplink, access).unwrap();
    /// assert_eq!(verified.message, status);
    /// assert_eq!(verified.count, NasCount::ZERO);
    /// assert!(amf.unprotect(&sent, Direction::Uplink, access).is_err());
    ///
    /// // A changed octet fails the MAC
    /// let mut forged = ue.protect(&status, header, Direction::Uplink, access).unwrap();
    /// forged[7] ^= 1;
    /// assert!(amf.unprotect(&forged, Direction::Uplink, access).is_err());
    /// ```
    pub fn unprotect(
        &mut self,
        data: &[u8],
        direction: Direction,
        connection: NasConnection,
    ) -> Result<Verified<Message>> {
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
    ) -> Result<(Plain, SecurityHeaderType, NasCount)> {
        if data.len() < 7 {
            return Err(Error::BufferTooShort);
        }
        if data[0] != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(Error::DecodingError(
                "invalid 5GS NAS security discriminator".into(),
            ));
        }

        // Bits 8-5 of octet 2 are a spare half octet (Figure 9.1.1-2).
        let sht = SecurityHeaderType::try_from(data[1] & 0x0f)?;

        if sht == SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected {
            return Err(Error::DecodingError(
                "not a security-protected message".into(),
            ));
        }

        let payload = &data[7..];
        if payload.is_empty() {
            return Err(Error::BufferTooShort);
        }

        // TS 24.501 §4.4.3.3 commits the received NAS COUNT after successful
        // integrity verification. Inner syntax, header-pairing, and direction
        // checks must not make an authenticated COUNT reusable.
        let count = self.core.open(data, 2, direction, connection)?;

        let should_cipher = matches!(
            sht,
            SecurityHeaderType::IntegrityProtectedAndCiphered
                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        );

        let mut decrypted = payload.to_vec();
        if should_cipher {
            (self.core).cipher(count, connection, direction, &mut decrypted);
        }

        let decoded = Message::decode(&decrypted).map_err(|error| refused(error, &decrypted))?;
        let received = |error| refused_received(error, &decrypted);
        validate_security_protected_inner_message(&decoded, sht).map_err(received)?;
        validate_message_direction(&decoded, direction).map_err(received)?;

        let initial = match (sht, direction) {
            (SecurityHeaderType::IntegrityProtected, Direction::Uplink) => {
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
            return Err(Error::MessageTooShort);
        };
        if *first != 0x17 {
            return Err(Error::DecodingError(
                "EPS PDU is not integrity protected with SHT 0001".into(),
            ));
        }
        let (uplink, three_gpp) = (Direction::Uplink, NasConnection::ThreeGpp);
        let count = self.core.open(pdu, 1, uplink, three_gpp)?;
        check_eps_mobility_request(plain).map_err(|error| refused_received(error, plain))?;
        Ok((plain.to_vec(), count))
    }
}

/// The NAS transparent containers of a handover between 5GS and EPS
/// (TS 24.501 §4.4.2.2, §4.4.2.4, §9.11.2.7 and §9.11.2.9). Each goes to the
/// UE in the handover command of the radio, and counts as a downlink message
/// of 3GPP access of the context of the AMF (§4.4.3.1).
impl SecurityContext {
    /// The N1 mode to S1 mode NAS transparent container of a handover from
    /// 5GS to EPS, as the AMF makes it (TS 24.501 §4.4.2.4, TS 33.501 §8.3.2
    /// step 2): the sequence number of the current downlink NAS COUNT of
    /// 3GPP access, and that COUNT, from which the AMF derives KASME'
    /// (`derive_mapped_kasme_handover` of oxirush-security). The downlink
    /// COUNT then advances by one. With every downlink COUNT used, it is
    /// [`Error::NasCountExhausted`], and nothing changes.
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::{Direction, NasCount};
    ///
    /// let kamf = KAmf::new(&[0x11; 32]);
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    /// let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    ///
    /// // The AMF derives KASME' with the COUNT of the container, and the UE
    /// // finds the same COUNT from its sequence number
    /// let (container, count) = amf.n1_to_s1_container().unwrap();
    /// assert_eq!((container.sequence_number(), count), (0, NasCount::ZERO));
    /// assert_eq!(ue.verify_n1_to_s1_container(&container), Ok(count));
    /// let next = amf.nas_count(Direction::Downlink, NasConnection::ThreeGpp);
    /// assert_eq!(next, Some(NasCount::new(1).unwrap()));
    /// ```
    pub fn n1_to_s1_container(
        &mut self,
    ) -> Result<(N1ModeToS1ModeNasTransparentContainer, NasCount)> {
        let (downlink, three_gpp) = (Direction::Downlink, NasConnection::ThreeGpp);
        let count = self.core.count(downlink, three_gpp).to_send()?;
        self.core.advance(downlink, three_gpp, count);
        let number = count.sequence_number();
        let container = N1ModeToS1ModeNasTransparentContainer::from_sequence_number(number);
        Ok((container, count))
    }

    /// The downlink NAS COUNT that the N1 mode to S1 mode NAS transparent
    /// container of a handover command gives the UE (TS 24.501 §4.4.2.4,
    /// TS 33.501 §8.3.2 step 8): the least COUNT above the largest downlink
    /// COUNT of 3GPP access that the UE received whose 8 low bits are the
    /// sequence number of the container (TS 24.501 §4.4.3.1). The UE derives
    /// KASME' with it, and the COUNT after it is the next downlink COUNT. A
    /// container has no code: its COUNT is never one that the UE received,
    /// and one above the last COUNT is [`Error::NasCountExhausted`], which
    /// changes nothing.
    pub fn verify_n1_to_s1_container(
        &mut self,
        container: &N1ModeToS1ModeNasTransparentContainer,
    ) -> Result<NasCount> {
        let (downlink, three_gpp) = (Direction::Downlink, NasConnection::ThreeGpp);
        let number = container.sequence_number();
        let wraps = self.core.wraps();
        let count = (self.core.count(downlink, three_gpp)).received(number, 8, wraps)?;
        self.core.advance(downlink, three_gpp, count);
        Ok(count)
    }

    /// The S1 mode to N1 mode NAS transparent container of a handover from
    /// EPS to 5GS, as the AMF makes it with the mapped context that it
    /// derived (TS 24.501 §4.4.2.2, TS 33.501 §8.4.2 step 3): the algorithms
    /// of the context, `ncc` the NCC of the NH that KAMF' was derived from,
    /// `ngksi` the ngKSI of the context, whose type is mapped, and the spare
    /// octets at zero. Its code is that of octets 7 to 10 (TS 24.501
    /// §4.4.3.3 b)) with KNASint, the COUNT 2^32 - 1, the downlink direction
    /// and the bearer of 3GPP access (TS 33.501 §6.9.2.3.3). The downlink
    /// COUNT of 3GPP access then advances by one, as after an initial
    /// SECURITY MODE COMMAND (TS 24.501 §4.4.3.1). An `ncc` above 7 is
    /// [`Error::EncodingError`], and with every downlink COUNT used it is
    /// [`Error::NasCountExhausted`]; nothing changes then.
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    /// use oxirush_nas::nas_eps::{KAsme, Nh};
    ///
    /// // The KASME and the NH that the MME gives, from which the AMF and the
    /// // UE derive the same mapped context
    /// let (kasme, nh) = (KAsme::new(&[0x11; 32]), Nh::new(&[0x22; 32]));
    /// let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut amf = SecurityContext::from_mapped_kamf_handover(&kasme, &nh, nia, nea).unwrap();
    /// let ngksi = KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Mapped(1));
    /// let container = amf.s1_to_n1_container(2, ngksi.unwrap()).unwrap();
    ///
    /// // The UE derives its context with the algorithms of the container
    /// let algorithms = container.security_algorithms().unwrap();
    /// let (nia, nea) = (algorithms.integrity().unwrap(), algorithms.ciphering().unwrap());
    /// let mut ue = SecurityContext::from_mapped_kamf_handover(&kasme, &nh, nia, nea).unwrap();
    /// ue.verify_s1_to_n1_container(&container).unwrap();
    /// ```
    pub fn s1_to_n1_container(
        &mut self,
        ncc: u8,
        ngksi: KeySetIdentifier,
    ) -> Result<S1ModeToN1ModeNasTransparentContainer> {
        let (downlink, three_gpp) = (Direction::Downlink, NasConnection::ThreeGpp);
        let count = self.core.count(downlink, three_gpp).to_send()?;
        let (nea, nia) = (self.core.ciphering, self.core.integrity);
        let algorithms = SecurityAlgorithms::from_algorithms(nea, nia);
        let mut container =
            S1ModeToN1ModeNasTransparentContainer::from_fields(0, algorithms, ncc, ngksi)?;
        let code = self.container_code(&container.value[4..]);
        container.set_message_authentication_code(code);
        self.core.advance(downlink, three_gpp, count);
        Ok(container)
    }

    /// Verify the S1 mode to N1 mode NAS transparent container of a handover
    /// command with the mapped context that the UE derived from it: KAMF'
    /// of its KASME and of the NH of the NCC of the container, with the
    /// algorithms of the container (TS 24.501 §4.4.2.2, TS 33.501 §8.4.2
    /// step 8). The code is of every octet of the value from octet 7 on, as a
    /// UE of every release reads it (TS 24.501 §4.4.3.3 b) and its note), at
    /// the COUNT 2^32 - 1. Once it verifies, the downlink COUNT of 3GPP access
    /// advances by one, as the AMF's did.
    ///
    /// A value shorter than the 8 octets of §9.11.2.9 is
    /// [`Error::BufferTooShort`]; algorithms that are not those of the
    /// context, a reserved one among them, are [`Error::SecurityRefused`];
    /// a code that does not match is [`Error::IntegrityCheckFailed`]; with
    /// every downlink COUNT used it is [`Error::NasCountExhausted`].
    /// Nothing changes then.
    pub fn verify_s1_to_n1_container(
        &mut self,
        container: &S1ModeToN1ModeNasTransparentContainer,
    ) -> Result<()> {
        let (downlink, three_gpp) = (Direction::Downlink, NasConnection::ThreeGpp);
        let [a, b, c, d, algorithms, _, _, _, ..] = container.value[..] else {
            return Err(Error::BufferTooShort);
        };
        let selected = SecurityAlgorithms::new(algorithms);
        let codes = (selected.ciphering_raw(), selected.integrity_raw());
        let (nea, nia) = (self.core.ciphering, self.core.integrity);
        if codes != (u8::from(nea), u8::from(nia)) {
            return Err(Error::SecurityRefused(format!(
                "the container selects the 5GS ciphering algorithm {} and the integrity \
                 algorithm {}, and the context has {nea:?} and {nia:?}",
                codes.0, codes.1
            )));
        }
        let count = self.core.count(downlink, three_gpp).to_send()?;
        let code = self.container_code(&container.value[4..]);
        self.core.check(&[a, b, c, d], &code.to_be_bytes())?;
        self.core.advance(downlink, three_gpp, count);
        Ok(())
    }

    /// The code of the octets of a NAS transparent container from octet 7
    /// on: KNASint, the COUNT 2^32 - 1, the downlink direction and the bearer
    /// of 3GPP access (TS 33.501 §6.9.2.3.3).
    fn container_code(&self, octets: &[u8]) -> u32 {
        (self.core).mac(
            u32::MAX,
            NasConnection::ThreeGpp,
            Direction::Downlink,
            octets,
        )
    }
}

/// Only a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST is sent
/// under the 5G context (TS 33.501 §8.5.2, TS 24.301 §4.4.2.3).
fn check_eps_mobility_request(eps_plain: &[u8]) -> Result<()> {
    if matches!(eps_plain, [0x07, 0x41 | 0x48, ..]) {
        Ok(())
    } else {
        Err(Error::EncodingError(
            "only a plain EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST uses the 5G context"
                .into(),
        ))
    }
}

#[cfg(test)]
impl SecurityContext {
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
    use oxirush_security::nas_5gs::{nas_cipher, nas_mac};
    use oxirush_utils::identity::Algorithm;

    /// A NAS COUNT of a message.
    fn count(count: u32) -> NasCount {
        NasCount::new(count).unwrap()
    }

    #[test]
    fn a_context_is_shown_without_its_keys_and_gives_the_count_it_verified_with() {
        let mut sender = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x11; 16]),
            &KNasEnc::new(&[0x22; 16]),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        *sender.count_mut(Direction::Uplink, NasConnection::Non3Gpp) = (0x0000_02fe).into();
        let mut receiver = sender.clone();
        let shown = format!("{receiver:?}");
        assert_eq!(
            shown,
            "SecurityContext { integrity_algorithm: Aes, ciphering_algorithm: Aes, \
             uplink_count: Some(NasCount(0)), downlink_count: Some(NasCount(0)), \
             uplink_count_non_3gpp: Some(NasCount(766)), \
             downlink_count_non_3gpp: Some(NasCount(0)), .. }"
        );
        // Neither a key nor one of its octets
        assert!(!shown.contains("11") && !shown.contains("22") && !shown.contains("17"));
        // What a UE costs: the place of the keys, the algorithms, four
        // COUNTs and the place of a replay window, and the two keys in the
        // heap
        #[cfg(target_pointer_width = "64")]
        assert_eq!(core::mem::size_of::<SecurityContext>(), 40);
        assert_eq!(core::mem::size_of::<Keys<KNasInt, KNasEnc>>(), 32);

        // The COUNT of each message that is verified, across a wrap of the
        // sequence number, on the access that it came over
        let message = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());
        let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
        let (uplink, access) = (Direction::Uplink, NasConnection::Non3Gpp);
        for expected in [0x02fe, 0x02ff, 0x0300] {
            let wire = sender.protect(&message, sht, uplink, access).unwrap();
            let verified = receiver.unprotect(&wire, uplink, access).unwrap();
            assert_eq!(verified.count, count(expected));
            assert_eq!(verified.security_header_type, sht);
            assert_eq!(verified.message, message);
            let raw = (sender.clone()).protect(&message, sht, uplink, access);
            let raw = (receiver.clone()).unprotect_raw(&raw.unwrap(), uplink, access);
            assert_eq!(raw.unwrap().count, count(expected + 1));
        }
    }

    #[test]
    fn opaque_payload_preserves_malformed_bytes_and_authenticates_all_regular_headers() {
        let inner = vec![0x7e, 0x00, 0xff, 0x20, 0x02, 0xbb, 0xaa, 0x20, 0x01, 0xcc];
        for access in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
            for direction in [Direction::Uplink, Direction::Downlink] {
                for sht in [
                    SecurityHeaderType::IntegrityProtected,
                    SecurityHeaderType::IntegrityProtectedAndCiphered,
                    SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                    SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
                ] {
                    let mut sender = SecurityContext::from_fresh_keys(
                        &KNasInt::new(&[0x29; 16]),
                        &KNasEnc::new(&[0x37; 16]),
                        Algorithm::Aes,
                        Algorithm::Aes,
                    )
                    .unwrap();
                    *sender.count_mut(direction, access) = (0x1234).into();
                    let refused = Message::decode(&inner).map_or(true, |message| {
                        sender.protect(&message, sht, direction, access).is_err()
                    });
                    assert!(refused);
                    assert_eq!(sender.count_ref(direction, access), 0x1234);
                    let mut receiver = sender.clone();
                    let mut tampered_receiver = receiver.clone();
                    let wire = sender
                        .protect_opaque_payload(inner.clone(), sht, direction, access)
                        .unwrap();
                    let mut payload = inner.clone();
                    if matches!(sht as u8, 2 | 4) {
                        nas_cipher(
                            &KNasEnc::new(&[0x37; 16]),
                            count(0x1234),
                            access,
                            direction.into(),
                            &mut payload,
                            Algorithm::Aes,
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
                        Algorithm::Aes,
                    );
                    assert_eq!(&wire[2..6], mac.to_be_bytes());
                    if matches!(sht as u8, 2 | 4) {
                        nas_cipher(
                            &KNasEnc::new(&[0x37; 16]),
                            count(0x1234),
                            access,
                            direction.into(),
                            &mut payload,
                            Algorithm::Aes,
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
                        tampered_receiver.unprotect_raw(&tampered, direction, access),
                        Err(Error::IntegrityCheckFailed)
                    ));
                    assert_eq!(tampered_receiver.count_ref(direction, access), 0x1234);
                    // The code is right and the message is refused for what
                    // it is, with its COUNT used.
                    assert_eq!(
                        receiver.unprotect_raw(&wire, direction, access),
                        Err(Error::AuthenticMessageRefused {
                            error: Box::new(Error::UnknownMessageType(0xff)),
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
        let mut sender = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x29; 16]),
            &KNasEnc::new(&[0x37; 16]),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut receiver = sender.clone();
        for sht in [
            SecurityHeaderType::IntegrityProtected,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
        ] {
            let message = Message::decode(&inner).unwrap();
            let checked = (sender.clone())
                .protect(&message, sht, Direction::Uplink, NasConnection::ThreeGpp)
                .unwrap();
            let opaque = sender
                .protect_opaque_payload(
                    inner.clone(),
                    sht,
                    Direction::Uplink,
                    NasConnection::ThreeGpp,
                )
                .unwrap();
            assert_eq!(opaque, checked);
            let raw = receiver
                .unprotect_raw(&opaque, Direction::Uplink, NasConnection::ThreeGpp)
                .unwrap();
            assert_eq!(
                (raw.message, raw.security_header_type),
                (inner.clone(), sht)
            );
        }
        for (sht, direction) in [
            (SecurityHeaderType::IntegrityProtected, Direction::Downlink),
            (
                SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                Direction::Uplink,
            ),
        ] {
            let message = Message::decode(&inner).unwrap();
            assert!((sender.protect(&message, sht, direction, NasConnection::ThreeGpp)).is_err());
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
        let mut sender = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x29; 16]),
            &KNasEnc::new(&[0x37; 16]),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
        assert!(
            sender
                .protect_opaque_payload(
                    vec![0xff],
                    SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected,
                    Direction::Uplink,
                    NasConnection::ThreeGpp
                )
                .is_err()
        );
        assert_eq!(
            sender.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            0
        );
        // NIA0 with a cipher makes no context.
        let context = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x29; 16]),
            &KNasEnc::new(&[0x37; 16]),
            Algorithm::Null,
            Algorithm::Aes,
        );
        assert!(context.is_err());
        for access in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
            for direction in [Direction::Uplink, Direction::Downlink] {
                *sender.count_mut(direction, access) = (0x00ff_ffff).into();
                let wire = sender
                    .protect_opaque_payload(Vec::new(), sht, direction, access)
                    .unwrap();
                assert_eq!(wire.len(), 7);
                assert_eq!(wire[6], 0xff);
                let mac = nas_mac(
                    &KNasInt::new(&[0x29; 16]),
                    NasCount::MAX,
                    access,
                    direction.into(),
                    &wire[6..],
                    Algorithm::Aes,
                );
                assert_eq!(&wire[2..6], mac.to_be_bytes());
                assert_eq!(sender.count_ref(direction, access), 0x0100_0000);
                // After the last COUNT the context protects and verifies
                // nothing more in the direction, and says so by a variant.
                assert_eq!(
                    sender.protect_opaque_payload(vec![0xff], sht, direction, access),
                    Err(Error::NasCountExhausted)
                );
                let received = [&wire[..], &[0x7e]].concat();
                assert_eq!(
                    sender.unprotect_raw(&received, direction, access),
                    Err(Error::NasCountExhausted)
                );
                assert_eq!(sender.count_ref(direction, access), 0x0100_0000);
                assert_eq!(sender.nas_count(direction, access), None);
            }
        }
    }

    #[test]
    fn eps_mobility_request_is_protected_with_the_5g_context() {
        let mut ue = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x21; 16]),
            &KNasEnc::new(&[0x22; 16]),
            Algorithm::Aes,
            Algorithm::Null,
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
            Algorithm::Aes,
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
            Err(Error::IntegrityCheckFailed)
        );
        assert_eq!(
            amf.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            0x0103
        );
        assert!(ue.protect_eps_message(&[0x07, 0x43, 0x00, 0x00]).is_err());

        let mut invalid_sender = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x21; 16]),
            &KNasEnc::new(&[0x22; 16]),
            Algorithm::Aes,
            Algorithm::Null,
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
            Algorithm::Aes,
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
        let command = Message::new_5gmm(crate::nas_5gs::SecurityModeCommand::new(
            crate::nas_5gs::SecurityAlgorithms::from_algorithms(Algorithm::Null, Algorithm::Null),
            crate::nas_5gs::KeySetIdentifier::new(0),
            crate::nas_5gs::UeSecurityCapability::new(vec![0, 0]),
        ));
        let complete = Message::new_5gmm(crate::nas_5gs::SecurityModeComplete::new());
        let mut tx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0; 16]),
            &KNasEnc::new(&[0; 16]),
            Algorithm::Null,
            Algorithm::Null,
        )
        .unwrap();
        for (message, required_sht, wrong_sht, direction, wrong_direction) in [
            (
                &command,
                SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
                Direction::Uplink,
            ),
            (
                &complete,
                SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                Direction::Downlink,
            ),
        ] {
            assert!(
                tx.protect(message, wrong_sht, direction, NasConnection::ThreeGpp)
                    .is_err()
            );
            assert!(
                tx.protect(
                    message,
                    required_sht,
                    wrong_direction,
                    NasConnection::ThreeGpp
                )
                .is_err()
            );
            let wire = tx
                .protect(message, required_sht, direction, NasConnection::ThreeGpp)
                .unwrap();
            let mut rx = SecurityContext::from_fresh_keys(
                &KNasInt::new(&[0; 16]),
                &KNasEnc::new(&[0; 16]),
                Algorithm::Null,
                Algorithm::Null,
            )
            .unwrap();
            assert!(
                rx.unprotect(&wire, wrong_direction, NasConnection::ThreeGpp)
                    .is_err()
            );
            assert!(
                rx.unprotect(&wire, direction, NasConnection::ThreeGpp)
                    .is_ok()
            );
        }
    }

    #[test]
    fn nia0_takes_a_message_again_with_a_higher_count() {
        // TS 24.501 §4.4.3.2, TS 33.501 §6.4.3.2 and annex D.1: no replay
        // protection and no MAC with NIA0. A message received again is taken
        // with a COUNT higher than the stored one (§4.4.3.1), which wraps
        // (§4.4.3.5). With NIA2 the same message is refused.
        let status = Message::new_5gmm(crate::nas_5gs::GmmStatus::new(
            crate::nas_5gs::GmmCause::new(0x6f),
        ));
        let context = |nia, nea| {
            SecurityContext::from_fresh_keys(
                &KNasInt::new(&[0x61; 16]),
                &KNasEnc::new(&[0x62; 16]),
                nia,
                nea,
            )
            .unwrap()
        };
        let (downlink, access) = (Direction::Downlink, NasConnection::ThreeGpp);
        let sht = SecurityHeaderType::IntegrityProtected;
        let mut amf = context(Algorithm::Null, Algorithm::Null);
        let mut ue = context(Algorithm::Null, Algorithm::Null);
        *amf.count_mut(downlink, access) = (0x00ff_ffff).into();
        *ue.count_mut(downlink, access) = (0x00ff_ffff).into();
        let wire = amf
            .protect(&status, sht, downlink, NasConnection::ThreeGpp)
            .unwrap();
        assert_eq!(amf.count_ref(downlink, access), 0);
        assert_eq!(
            ue.unprotect(&wire, downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(0x00ff_ffff)
        );
        assert_eq!(
            ue.unprotect(&wire, downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(0xff)
        );
        assert_eq!(
            ue.unprotect(&wire, downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(0x01ff)
        );
        assert_eq!(ue.count_ref(downlink, access), 0x0200);

        let mut amf = context(Algorithm::Aes, Algorithm::Null);
        let mut ue = context(Algorithm::Aes, Algorithm::Null);
        let wire = amf
            .protect(&status, sht, downlink, NasConnection::ThreeGpp)
            .unwrap();
        assert_eq!(
            ue.unprotect(&wire, downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(0)
        );
        assert!(matches!(
            ue.unprotect(&wire, downlink, NasConnection::ThreeGpp),
            Err(Error::IntegrityCheckFailed)
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
        use crate::nas_5gs::SecurityModeCommand;
        use crate::nas_5gs::{KeySetIdentifier, SecurityAlgorithms, UeSecurityCapability};
        let command = |nia, nea| {
            Message::new_5gmm(SecurityModeCommand::new(
                SecurityAlgorithms::from_algorithms(nea, nia),
                KeySetIdentifier::new(0),
                UeSecurityCapability::new(vec![0xf0, 0xf0]),
            ))
        };
        let status = Message::new_5gmm(crate::nas_5gs::GmmStatus::new(
            crate::nas_5gs::GmmCause::new(0x6f),
        ));
        let new_context = SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext;
        let (downlink, access) = (Direction::Downlink, NasConnection::ThreeGpp);
        let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
        let kamf = KAmf::new(&[0x51; 32]);
        let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        for _ in 0..3 {
            let sent = amf
                .protect(
                    &status,
                    SecurityHeaderType::IntegrityProtectedAndCiphered,
                    downlink,
                    NasConnection::ThreeGpp,
                )
                .unwrap();
            ue.unprotect(&sent, downlink, NasConnection::ThreeGpp)
                .unwrap();
        }

        // The context in use
        let sent = amf
            .protect(
                &command(nia, nea),
                new_context,
                downlink,
                NasConnection::ThreeGpp,
            )
            .unwrap();
        let verified = ue
            .unprotect(&sent, downlink, NasConnection::ThreeGpp)
            .unwrap();
        assert_eq!(
            (verified.count, verified.security_header_type),
            (count(3), new_context)
        );

        // New algorithms: the context in use refuses the command and keeps
        // its COUNT, one with the new algorithms and its COUNTs verifies it
        let (nia, nea) = (Algorithm::Snow3g, Algorithm::Snow3g);
        amf.reselect_algorithms(&kamf, nia, nea).unwrap();
        let sent = amf
            .protect(
                &command(nia, nea),
                new_context,
                downlink,
                NasConnection::ThreeGpp,
            )
            .unwrap();
        assert!(matches!(
            ue.unprotect(&sent, downlink, NasConnection::ThreeGpp),
            Err(Error::IntegrityCheckFailed)
        ));
        assert_eq!(ue.count_ref(downlink, access), 4);
        let counts = |connection| {
            (
                ue.nas_count(Direction::Uplink, connection),
                ue.nas_count(downlink, connection),
            )
        };
        let mut reselected = SecurityContext::restore_from_kamf(
            &kamf,
            nia,
            nea,
            counts(NasConnection::ThreeGpp),
            counts(NasConnection::Non3Gpp),
        )
        .unwrap();
        assert_eq!(
            reselected
                .unprotect(&sent, downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(4)
        );

        // After an authentication
        let kamf = KAmf::new(&[0x52; 32]);
        let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        let sent = amf
            .protect(
                &command(nia, nea),
                new_context,
                downlink,
                NasConnection::ThreeGpp,
            )
            .unwrap();
        assert!(
            reselected
                .unprotect(&sent, downlink, NasConnection::ThreeGpp)
                .is_err()
        );
        let mut fresh = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        assert_eq!(
            fresh
                .unprotect(&sent, downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(0)
        );
    }

    #[test]
    fn mapped_eps_context_starts_5gs_counts_at_zero() {
        let kasme = KAsme::new(&core::array::from_fn(|i| i as u8));
        let nh = Nh::new(&core::array::from_fn(|i| (i + 32) as u8));
        let mut idle = SecurityContext::from_mapped_kamf_idle(
            &kasme,
            count(0x1234),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        // A COUNT above 24 bits is no NAS COUNT.
        assert!(NasCount::new(0x0100_0000).is_err());
        let handover =
            SecurityContext::from_mapped_kamf_handover(&kasme, &nh, Algorithm::Aes, Algorithm::Aes)
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
        let complete = Message::decode(&[0x7e, 0x00, 0x43]).unwrap();
        let wire = idle
            .protect(
                &complete,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Uplink,
                NasConnection::ThreeGpp,
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

        let mut tx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut rx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();

        // Build a simple RegistrationComplete message
        let inner = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());

        // Protect (UL) with integrity only
        let protected = tx
            .protect(
                &inner,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                NasConnection::ThreeGpp,
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
        } = rx
            .unprotect(&protected, Direction::Uplink, NasConnection::ThreeGpp)
            .unwrap();
        assert_eq!(sht, SecurityHeaderType::IntegrityProtected);

        // Verify counts advanced
        assert_eq!(tx.count_ref(Direction::Uplink, NasConnection::ThreeGpp), 1);
        assert_eq!(rx.count_ref(Direction::Uplink, NasConnection::ThreeGpp), 1);
    }

    #[test]
    fn test_protect_unprotect_roundtrip_ciphered() {
        let key_int = [0xABu8; 16];
        let key_enc = [0xCDu8; 16];

        let mut tx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut rx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();

        let inner = Message::new_5gmm(crate::nas_5gs::AuthenticationResult::new(
            crate::nas_5gs::KeySetIdentifier::new(0),
            crate::nas_5gs::EapMessage::new(vec![0x03, 0x01, 0x00, 0x04]),
        ));

        let protected = tx
            .protect(
                &inner,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
                NasConnection::ThreeGpp,
            )
            .unwrap();

        assert_eq!(protected[1], 0x02); // SHT = IntegrityProtectedAndCiphered

        let Verified {
            message: _decoded,
            security_header_type: sht,
            ..
        } = rx
            .unprotect(&protected, Direction::Downlink, NasConnection::ThreeGpp)
            .unwrap();
        assert_eq!(sht, SecurityHeaderType::IntegrityProtectedAndCiphered);
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
        let uplink = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());
        let status = Message::new_5gmm(crate::nas_5gs::GmmStatus::new(
            crate::nas_5gs::GmmCause::new(0x6f),
        ));
        let context = || {
            SecurityContext::from_fresh_keys(
                &KNasInt::new(&[0x21; 16]),
                &KNasEnc::new(&[0x43; 16]),
                Algorithm::Aes,
                Algorithm::Aes,
            )
            .unwrap()
        };
        let sht = SecurityHeaderType::IntegrityProtected;
        let mut tx = context();
        assert!(
            tx.protect(&uplink, sht, Direction::Downlink, NasConnection::ThreeGpp)
                .is_err()
        );
        assert_eq!(
            tx.count_ref(Direction::Downlink, NasConnection::ThreeGpp),
            0
        );
        let wire = tx
            .protect(&uplink, sht, Direction::Uplink, NasConnection::ThreeGpp)
            .unwrap();
        let mut rx = context();
        assert!(
            rx.unprotect(&wire, Direction::Uplink, NasConnection::ThreeGpp)
                .is_ok()
        );
        for direction in [Direction::Uplink, Direction::Downlink] {
            let wire = context()
                .protect(&status, sht, direction, NasConnection::ThreeGpp)
                .unwrap();
            assert!(
                context()
                    .unprotect(&wire, direction, NasConnection::ThreeGpp)
                    .is_ok()
            );
        }
    }

    #[test]
    fn test_security_mode_command_with_new_context_is_not_ciphered() {
        let key_int = [0x21u8; 16];
        let key_enc = [0x43u8; 16];

        let mut tx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut rx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();

        let smc = crate::nas_5gs::SecurityModeCommand::new(
            crate::nas_5gs::SecurityAlgorithms::from_algorithms(Algorithm::Aes, Algorithm::Aes),
            crate::nas_5gs::KeySetIdentifier::new(0),
            crate::nas_5gs::UeSecurityCapability::new(vec![0xE0, 0xE0]),
        )
        .with_abba(crate::nas_5gs::Abba::new(vec![0x00, 0x00]));
        let inner = Message::new_5gmm(smc);
        let plain = inner.encode().unwrap();

        let protected = tx
            .protect(
                &inner,
                SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                Direction::Downlink,
                NasConnection::ThreeGpp,
            )
            .unwrap();

        assert_eq!(protected[1], 0x03);
        assert_eq!(&protected[7..], plain.as_slice());

        let Verified {
            message: decoded,
            security_header_type: sht,
            ..
        } = rx
            .unprotect(&protected, Direction::Downlink, NasConnection::ThreeGpp)
            .unwrap();
        assert_eq!(
            sht,
            SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext
        );
        assert!(matches!(
            decoded,
            Message::Gmm(_, crate::nas_5gs::GmmMessage::SecurityModeCommand(_))
        ));
    }

    #[test]
    fn test_mac_failure_rejects() {
        let key_int = [0x01u8; 16];
        let key_enc = [0x02u8; 16];

        let mut tx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut rx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0xFFu8; 16]),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap(); // Different key!

        let inner = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());

        let protected = tx
            .protect(
                &inner,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                NasConnection::ThreeGpp,
            )
            .unwrap();

        let result = rx.unprotect(&protected, Direction::Uplink, NasConnection::ThreeGpp);
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

        let mut tx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut rx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();

        let inner = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());

        let _first = tx
            .protect(
                &inner,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                NasConnection::ThreeGpp,
            )
            .unwrap();
        let second = tx
            .protect(
                &inner,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                NasConnection::ThreeGpp,
            )
            .unwrap();

        // Fresh receiver starts with COUNT 0 but should still accept SN=1 by
        // estimating the correct NAS COUNT from the received sequence number.
        let Verified {
            security_header_type: sht,
            ..
        } = rx
            .unprotect(&second, Direction::Uplink, NasConnection::ThreeGpp)
            .unwrap();
        assert_eq!(sht, SecurityHeaderType::IntegrityProtected);
        assert_eq!(second[6], 0x01);
        assert_eq!(rx.count_ref(Direction::Uplink, NasConnection::ThreeGpp), 2);
    }

    #[test]
    fn nia0_requires_nea0() {
        let message = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());
        let keys = ([0; 16], [0; 16]);
        let context = |nea| {
            SecurityContext::from_fresh_keys(
                &KNasInt::new(&keys.0),
                &KNasEnc::new(&keys.1),
                Algorithm::Null,
                nea,
            )
        };
        assert!(context(Algorithm::Aes).is_err());
        assert!(context(Algorithm::Null).is_ok());
        let kamf = KAmf::new(&[0x24; 32]);
        let derived = |nea| SecurityContext::from_fresh_kamf(&kamf, Algorithm::Null, nea);
        assert!(derived(Algorithm::Snow3g).is_err());
        let mut null = derived(Algorithm::Null).unwrap();
        assert!(
            null.reselect_algorithms(&kamf, Algorithm::Null, Algorithm::Zuc)
                .is_err()
        );
        // A context that refuses its new algorithms keeps those it had.
        assert_eq!(null.ciphering_algorithm(), Algorithm::Null);
        let wire = null
            .protect(
                &message,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                NasConnection::ThreeGpp,
            )
            .unwrap();
        assert_eq!(&wire[2..6], [0; 4]);
    }

    #[test]
    fn spare_half_octet_of_the_security_header_is_ignored() {
        // Octet 2 is "spare half octet | security header
        // type" (TS 24.501 Figure 9.1.1-2); the spare bits are outside the MAC.
        let context = || {
            SecurityContext::from_fresh_keys(
                &KNasInt::new(&[0x31; 16]),
                &KNasEnc::new(&[0x32; 16]),
                Algorithm::Aes,
                Algorithm::Aes,
            )
            .unwrap()
        };
        let message = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());
        let mut wire = context()
            .protect(
                &message,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Uplink,
                NasConnection::ThreeGpp,
            )
            .unwrap();
        wire[1] |= 0x10;
        assert!(crate::nas_5gs::is_security_protected(&wire));
        let Verified {
            message: decoded,
            security_header_type: sht,
            ..
        } = context()
            .unprotect(&wire, Direction::Uplink, NasConnection::ThreeGpp)
            .unwrap();
        assert_eq!(decoded, message);
        assert_eq!(sht, SecurityHeaderType::IntegrityProtectedAndCiphered);
    }

    #[test]
    fn fresh_count_after_gap_is_accepted_and_replay_is_not() {
        // TS 24.501 §4.4.3.1: a lower sequence number means the overflow
        // counter advanced, independent of the current overflow value.
        let message = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());
        for (receiver_next, sender_count) in [(0x05, 0x90), (0x0105, 0x0190), (0x01f0, 0x0202)] {
            let context = || {
                SecurityContext::from_fresh_keys(
                    &KNasInt::new(&[0x31; 16]),
                    &KNasEnc::new(&[0x32; 16]),
                    Algorithm::Aes,
                    Algorithm::Aes,
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
                    SecurityHeaderType::IntegrityProtectedAndCiphered,
                    Direction::Uplink,
                    NasConnection::ThreeGpp,
                )
                .unwrap();
            assert_eq!(
                receiver
                    .unprotect(&wire, Direction::Uplink, NasConnection::ThreeGpp)
                    .unwrap()
                    .message,
                message
            );
            assert_eq!(
                receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
                sender_count + 1
            );
            assert!(
                receiver
                    .unprotect(&wire, Direction::Uplink, NasConnection::ThreeGpp)
                    .is_err()
            );
            assert_eq!(
                receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
                sender_count + 1
            );
        }
    }

    /// Two contexts of the same keys, as an AMF and a UE have them.
    fn two_ends() -> (SecurityContext, SecurityContext) {
        let context = || {
            SecurityContext::from_fresh_keys(
                &KNasInt::new(&[0x41; 16]),
                &KNasEnc::new(&[0x42; 16]),
                Algorithm::Aes,
                Algorithm::Aes,
            )
            .unwrap()
        };
        (context(), context())
    }

    /// `n` downlink messages that `amf` protects one after the other.
    fn sent(amf: &mut SecurityContext, n: usize) -> Vec<Vec<u8>> {
        // A 5GMM STATUS, which goes both ways
        let message = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
        let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
        (0..n)
            .map(|_| {
                amf.protect(
                    &message,
                    header,
                    Direction::Downlink,
                    NasConnection::ThreeGpp,
                )
                .unwrap()
            })
            .collect()
    }

    #[test]
    fn a_replay_window_takes_a_lower_count_once_and_keeps_the_highest() {
        // TS 24.501 §4.4.3.1: a receiver that can guarantee that a message
        // was not accepted before may estimate its COUNT below the stored one.
        // An INITIAL CONTEXT SETUP REQUEST can carry a message built first, at
        // n, beside the one of the request, at n + 1, which the UE takes first.
        let (mut amf, mut ue) = two_ends();
        ue.set_replay_window(32).unwrap();
        assert_eq!(ue.replay_window(), 32);
        let wire = sent(&mut amf, 3);
        let downlink = |ue: &mut SecurityContext, wire: &[u8]| {
            ue.unprotect(wire, Direction::Downlink, NasConnection::ThreeGpp)
                .map(|verified| verified.count)
        };
        assert_eq!(downlink(&mut ue, &wire[0]), Ok(count(0)));
        assert_eq!(downlink(&mut ue, &wire[2]), Ok(count(2)));
        let next =
            |ue: &SecurityContext| ue.nas_count(Direction::Downlink, NasConnection::ThreeGpp);
        assert_eq!(next(&ue), Some(count(3)));
        // The message of COUNT 1, which came after that of 2: verified with
        // its own COUNT, and the highest stays
        assert_eq!(downlink(&mut ue, &wire[1]), Ok(count(1)));
        assert_eq!(next(&ue), Some(count(3)));
        // A replay of each is refused, the next COUNT unchanged (§4.4.3.2)
        for replayed in &wire {
            assert_eq!(
                downlink(&mut ue, replayed),
                Err(Error::IntegrityCheckFailed)
            );
            assert_eq!(next(&ue), Some(count(3)));
        }
        // What follows is taken as before
        let later = sent(&mut amf, 1);
        assert_eq!(downlink(&mut ue, &later[0]), Ok(count(3)));
        assert_eq!(next(&ue), Some(count(4)));
    }

    #[test]
    fn a_replay_window_refuses_a_count_below_it() {
        let (mut amf, mut ue) = two_ends();
        ue.set_replay_window(32).unwrap();
        let wire = sent(&mut amf, 40);
        // The 40th first: the COUNTs 7 to 38 are the 32 below it
        assert_eq!(
            ue.unprotect(&wire[39], Direction::Downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(39)
        );
        for below in [0, 6] {
            let refused = ue.unprotect(&wire[below], Direction::Downlink, NasConnection::ThreeGpp);
            assert_eq!(refused.map(|v| v.count), Err(Error::IntegrityCheckFailed));
        }
        for inside in [7, 38] {
            let verified =
                ue.unprotect(&wire[inside], Direction::Downlink, NasConnection::ThreeGpp);
            assert_eq!(verified.map(|v| v.count), Ok(count(inside as u32)));
        }
        assert_eq!(
            ue.nas_count(Direction::Downlink, NasConnection::ThreeGpp),
            Some(count(40))
        );
    }

    #[test]
    fn without_a_replay_window_a_lower_count_is_refused_as_before() {
        let (mut amf, mut ue) = two_ends();
        assert_eq!(ue.replay_window(), 0);
        let wire = sent(&mut amf, 2);
        assert_eq!(
            ue.unprotect(&wire[1], Direction::Downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(1)
        );
        let refused = ue.unprotect(&wire[0], Direction::Downlink, NasConnection::ThreeGpp);
        assert_eq!(refused.map(|v| v.count), Err(Error::IntegrityCheckFailed));
        assert_eq!(
            ue.nas_count(Direction::Downlink, NasConnection::ThreeGpp),
            Some(count(2))
        );
        // A window set and taken off again changes nothing either
        let (mut amf, mut ue) = two_ends();
        ue.set_replay_window(32).unwrap();
        ue.set_replay_window(0).unwrap();
        let wire = sent(&mut amf, 2);
        ue.unprotect(&wire[1], Direction::Downlink, NasConnection::ThreeGpp)
            .unwrap();
        assert!(
            ue.unprotect(&wire[0], Direction::Downlink, NasConnection::ThreeGpp)
                .is_err()
        );
    }

    #[test]
    fn a_replay_window_takes_the_counts_below_a_restored_one_as_accepted() {
        // The COUNTs below one that is set, restored or reached before the
        // window was set are not known to be unused: a message of one of them
        // is refused.
        let kamf = KAmf::new(&[0x43; 32]);
        let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
        let mut amf = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        let wire = sent(&mut amf, 3);
        let restored = (Some(count(0)), Some(count(2)));
        let mut ue =
            SecurityContext::restore_from_kamf(&kamf, nia, nea, restored, (None, None)).unwrap();
        ue.set_replay_window(32).unwrap();
        assert!(
            ue.unprotect(&wire[1], Direction::Downlink, NasConnection::ThreeGpp)
                .is_err()
        );
        assert_eq!(
            ue.unprotect(&wire[2], Direction::Downlink, NasConnection::ThreeGpp)
                .unwrap()
                .count,
            count(2)
        );
        let mut later = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
        later
            .unprotect(&wire[1], Direction::Downlink, NasConnection::ThreeGpp)
            .unwrap();
        later.set_replay_window(32).unwrap();
        assert!(
            later
                .unprotect(&wire[0], Direction::Downlink, NasConnection::ThreeGpp)
                .is_err()
        );
        *later.count_mut(Direction::Downlink, NasConnection::ThreeGpp) = (0x02).into();
        assert!(
            later
                .unprotect(&wire[1], Direction::Downlink, NasConnection::ThreeGpp)
                .is_err()
        );
    }

    #[test]
    fn a_replay_window_that_is_resized_keeps_what_it_saw() {
        // The COUNTs that the window held keep whether they were accepted; the
        // ones that it did not hold are taken as accepted.
        let (mut amf, mut ue) = two_ends();
        ue.set_replay_window(4).unwrap();
        let wire = sent(&mut amf, 10);
        let downlink = |ue: &mut SecurityContext, at: usize| {
            ue.unprotect(&wire[at], Direction::Downlink, NasConnection::ThreeGpp)
                .map(|verified| verified.count)
        };
        assert_eq!(downlink(&mut ue, 0), Ok(count(0)));
        assert_eq!(downlink(&mut ue, 9), Ok(count(9)));
        // 5 to 8 are the four below 9, not accepted; 1 to 4 are past the window
        ue.set_replay_window(8).unwrap();
        assert_eq!(ue.replay_window(), 8);
        assert_eq!(downlink(&mut ue, 7), Ok(count(7)));
        assert_eq!(downlink(&mut ue, 7), Err(Error::IntegrityCheckFailed));
        assert_eq!(downlink(&mut ue, 2), Err(Error::IntegrityCheckFailed));
        // A window made smaller holds fewer of them
        ue.set_replay_window(3).unwrap();
        assert_eq!(downlink(&mut ue, 5), Err(Error::IntegrityCheckFailed));
        assert_eq!(downlink(&mut ue, 6), Ok(count(6)));
        ue.set_replay_window(8).unwrap();
        assert_eq!(downlink(&mut ue, 5), Err(Error::IntegrityCheckFailed));
        assert_eq!(downlink(&mut ue, 8), Ok(count(8)));
    }

    #[test]
    fn a_replay_window_has_at_most_64_counts() {
        let (_, mut ue) = two_ends();
        assert_eq!(crate::MAX_REPLAY_WINDOW, 64);
        assert!(ue.set_replay_window(64).is_ok());
        assert!(matches!(
            ue.set_replay_window(65),
            Err(Error::SecurityRefused(_))
        ));
        assert_eq!(ue.replay_window(), 64);
    }

    #[test]
    fn test_non_3gpp_access_counts_are_separate() {
        let key_int = [0x31u8; 16];
        let key_enc = [0x41u8; 16];

        let mut tx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut rx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key_int),
            &KNasEnc::new(&key_enc),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();

        let inner = Message::new_5gmm(crate::nas_5gs::AuthenticationResult::new(
            crate::nas_5gs::KeySetIdentifier::new(0),
            crate::nas_5gs::EapMessage::new(vec![0x03, 0x01, 0x00, 0x04]),
        ));

        let protected = tx
            .protect(
                &inner,
                SecurityHeaderType::IntegrityProtected,
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
            .unprotect(&protected, Direction::Downlink, NasConnection::Non3Gpp)
            .unwrap();

        assert_eq!(
            rx.count_ref(Direction::Downlink, NasConnection::ThreeGpp),
            0
        );
        assert_eq!(rx.count_ref(Direction::Downlink, NasConnection::Non3Gpp), 1);
    }

    #[test]
    fn test_protect_rejects_plain_5gsm_inner_message() {
        let mut ctx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x51u8; 16]),
            &KNasEnc::new(&[0x61u8; 16]),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();

        let inner = Message::new_5gsm(
            crate::nas_5gs::PduSessionEstablishmentRequest::new(
                crate::nas_5gs::IntegrityProtectionMaximumDataRate::from_rates(
                    crate::nas_5gs::MaxDataRate::FullRate,
                    crate::nas_5gs::MaxDataRate::FullRate,
                ),
            ),
            1,
            1,
        );

        assert!(
            ctx.protect(
                &inner,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                NasConnection::ThreeGpp,
            )
            .is_err()
        );
    }

    #[test]
    fn persisted_5gs_context_and_algorithm_reselection_preserve_all_counts() {
        let kamf = KAmf::new(&[0x24; 32]);
        let mut context = SecurityContext::restore_from_kamf(
            &kamf,
            Algorithm::Aes,
            Algorithm::Aes,
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
            .reselect_algorithms(&kamf, Algorithm::Snow3g, Algorithm::Snow3g)
            .unwrap();
        assert_eq!(context.integrity_algorithm(), Algorithm::Snow3g);
        assert_eq!(context.ciphering_algorithm(), Algorithm::Snow3g);
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
        let reject = Message::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();
        let sht = SecurityHeaderType::IntegrityProtected;
        assert_eq!(
            context.protect(&reject, sht, Direction::Downlink, NasConnection::Non3Gpp),
            Err(Error::NasCountExhausted)
        );
        assert!(
            context
                .protect(&reject, sht, Direction::Downlink, NasConnection::ThreeGpp)
                .is_ok()
        );
    }

    #[test]
    fn test_protect_rejects_invalid_new_context_sht_for_non_security_mode_command() {
        let mut ctx = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x71u8; 16]),
            &KNasEnc::new(&[0x81u8; 16]),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();

        let inner = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());

        assert!(
            ctx.protect(
                &inner,
                SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                Direction::Uplink,
                NasConnection::ThreeGpp,
            )
            .is_err()
        );
    }

    #[test]
    fn protected_5gs_commits_authenticated_count_before_inner_validation() {
        let key = [0x29; 16];
        let mut sender = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key),
            &KNasEnc::new(&key),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut receiver = sender.clone();
        let inner = Message::new_5gmm(crate::nas_5gs::RegistrationComplete::new());
        let wire = sender
            .protect(
                &inner,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
                NasConnection::ThreeGpp,
            )
            .unwrap();
        let mut bad_epd = wire.clone();
        bad_epd[0] = 0;
        assert!(
            receiver
                .unprotect(&bad_epd, Direction::Uplink, NasConnection::ThreeGpp)
                .is_err()
        );
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
            Algorithm::Aes,
        );
        bad_inner[2..6].copy_from_slice(&mac.to_be_bytes());
        assert!(
            receiver
                .unprotect(&bad_inner, Direction::Uplink, NasConnection::ThreeGpp)
                .is_err()
        );
        assert_eq!(
            receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            1
        );
        assert!(
            receiver
                .unprotect(&wire, Direction::Uplink, NasConnection::ThreeGpp)
                .is_err()
        );
        assert_eq!(
            receiver.count_ref(Direction::Uplink, NasConnection::ThreeGpp),
            1
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

    #[test]
    fn a_message_of_its_security_header_alone_is_too_short_and_uses_no_count() {
        // Seven octets: the security header, the code and the sequence number,
        // with no message under them. It is too short, with the code that it
        // has: no COUNT is used.
        let mut receiver = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x29; 16]),
            &KNasEnc::new(&[0x37; 16]),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap();
        let mut wire = vec![0x7e, 0x01, 0, 0, 0, 0, 0x00];
        let mac = nas_mac(
            &KNasInt::new(&[0x29; 16]),
            count(0),
            NasConnection::ThreeGpp,
            Direction::Downlink.into(),
            &wire[6..],
            Algorithm::Aes,
        );
        wire[2..6].copy_from_slice(&mac.to_be_bytes());
        // A header of seven octets is read, and one of fewer is not
        let mut other = wire.clone();
        other[0] = 0x2e;
        let error = receiver
            .unprotect(&other, Direction::Downlink, NasConnection::ThreeGpp)
            .unwrap_err();
        assert!(matches!(error, Error::DecodingError(_)), "{error:?}");
        for short in [&wire[..], &wire[..6], &wire[..1], &[][..]] {
            let error = receiver
                .unprotect(short, Direction::Downlink, NasConnection::ThreeGpp)
                .unwrap_err();
            assert!(matches!(error, Error::BufferTooShort), "{error:?}");
        }
        let short = [0x2e, 0x01, 0, 0, 0, 0];
        let error = receiver
            .unprotect(&short, Direction::Downlink, NasConnection::ThreeGpp)
            .unwrap_err();
        assert!(matches!(error, Error::BufferTooShort), "{error:?}");
        assert_eq!(
            receiver.count_ref(Direction::Downlink, NasConnection::ThreeGpp),
            0
        );
    }
}
