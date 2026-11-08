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
//! This module provides [`SecurityContext`] which wraps EPS NAS keys and
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
//! use oxirush_nas::identity::Algorithm;
//! use oxirush_nas::nas_eps::{KAsme, Message, SecurityHeaderType, SecurityContext};
//! use oxirush_nas::{Direction, NasCount};
//!
//! // ATTACH REJECT, cause #3
//! let msg = Message::decode(&[0x07, 0x44, 0x03]).unwrap();
//!
//! // The two ends of one link: the same KASME and the same algorithms
//! let kasme = KAsme::new(&[0x11; 32]);
//! let (eia, eea) = (Algorithm::Aes, Algorithm::Aes);
//! let mut tx = SecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
//! let mut rx = SecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
//!
//! // Protect outbound: integrity and ciphering
//! let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
//! let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();
//!
//! // Unprotect inbound: MAC check, deciphering and decoding
//! let verified = rx.unprotect(&protected, Direction::Downlink).unwrap();
//! assert_eq!(verified.message, msg);
//! assert_eq!(verified.security_header_type, sht);
//! assert_eq!(verified.count, NasCount::ZERO);
//! ```
//!
//! `protect` validates the inner message. For negative tests,
//! `protect_opaque_payload` ciphers and integrity-protects any inner octets
//! under security header types 1 to 4.

use crate::common::{Core, Direction, Error, Keys, NextCount, Result, System, wiped};
use crate::nas_eps::{EPS_EMM_PROTOCOL_DISCRIMINATOR, SecurityHeaderType};
use crate::prelude::*;
use core::convert::TryFrom;
use core::fmt;
use oxirush_utils::identity::Algorithm;

use crate::nas_eps::{
    EPS_SECURITY_HEADER_LEN, EmmMessage, EmmTransport, EsmMessage, Message, ServiceRequest,
    received_emm_data_container_is_valid, valid_emm_data_container,
};
use oxirush_security::NasCount;
use oxirush_security::nas_5gs::{KAmf, derive_mapped_kasme_handover, derive_mapped_kasme_idle};
use oxirush_security::nas_eps as eps;
use oxirush_security::nas_eps::{KAsme, KNasEnc, KNasInt};

/// A message that a security context verified, and what it was verified
/// with.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct Verified<M> {
    /// The message under the security header: decoded, or its plain octets
    /// from `unprotect_raw`.
    pub message: M,
    /// The security header type that the message came under.
    pub security_header_type: SecurityHeaderType,
    /// The NAS COUNT that the message authentication code was verified
    /// with: the uplink NAS COUNT of the message that K_eNB is derived with
    /// (TS 33.401 Annex A.3), for a message that starts the access stratum
    /// security.
    pub count: NasCount,
}

/// What `error` of the plain message `plain` is once the code of the
/// message was verified.
fn refused(error: Error, plain: &[u8]) -> Error {
    Error::AuthenticMessageRefused {
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
    algorithm: Algorithm,
) -> Result<()> {
    let mut message = Message::decode(payload)?;
    let Message::Emm(_, EmmMessage::ControlPlaneServiceRequest(request)) = &mut message else {
        return Err(Error::DecodingError(
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
            return Err(Error::DecodingError(
                "partial EPS ciphering requires exactly one message container".into(),
            ));
        }
    }
    *payload = message.encode()?;
    Ok(())
}

fn validate_sht_message(
    sht: SecurityHeaderType,
    message: &Message,
    direction: Direction,
) -> Result<()> {
    if !matches!(message, Message::Emm(..) | Message::Esm(..)) {
        return Err(Error::EncodingError(
            "EPS security envelope requires a plain EMM or ESM message".into(),
        ));
    }
    if let Message::Emm(_, inner) = message {
        // TS 24.301 Chapter 8 assigns a sending side to each EMM message.
        let required_direction = match inner {
            EmmMessage::AttachComplete(_)
            | EmmMessage::AttachRequest(_)
            | EmmMessage::AuthenticationFailure(_)
            | EmmMessage::AuthenticationResponse(_)
            | EmmMessage::DetachRequestUeOriginating(_)
            | EmmMessage::ExtendedServiceRequest(_)
            | EmmMessage::GutiReallocationComplete(_)
            | EmmMessage::IdentityResponse(_)
            | EmmMessage::SecurityModeComplete(_)
            | EmmMessage::SecurityModeReject(_)
            | EmmMessage::TrackingAreaUpdateComplete(_)
            | EmmMessage::TrackingAreaUpdateRequest(_)
            | EmmMessage::UplinkNasTransport(_)
            | EmmMessage::UplinkGenericNasTransport(_)
            | EmmMessage::ControlPlaneServiceRequest(_) => Some(Direction::Uplink),
            EmmMessage::AttachAccept(_)
            | EmmMessage::AttachReject(_)
            | EmmMessage::AuthenticationReject(_)
            | EmmMessage::AuthenticationRequest(_)
            | EmmMessage::CsServiceNotification(_)
            | EmmMessage::DetachRequestUeTerminated(_)
            | EmmMessage::DownlinkNasTransport(_)
            | EmmMessage::EmmInformation(_)
            | EmmMessage::GutiReallocationCommand(_)
            | EmmMessage::IdentityRequest(_)
            | EmmMessage::SecurityModeCommand(_)
            | EmmMessage::ServiceReject(_)
            | EmmMessage::TrackingAreaUpdateAccept(_)
            | EmmMessage::TrackingAreaUpdateReject(_)
            | EmmMessage::DownlinkGenericNasTransport(_)
            | EmmMessage::ServiceAccept(_) => Some(Direction::Downlink),
            EmmMessage::DetachAccept(_) | EmmMessage::EmmStatus(_) => None,
        };
        if required_direction.is_some_and(|required| required != direction) {
            return Err(Error::EncodingError(
                "EPS EMM message direction does not match its message type".into(),
            ));
        }
        match inner {
            EmmMessage::SecurityModeCommand(_)
                if sht != SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
                    || direction != Direction::Downlink =>
            {
                return Err(Error::EncodingError(
                    "SECURITY MODE COMMAND requires downlink integrity protection with new context"
                        .into(),
                ));
            }
            EmmMessage::SecurityModeComplete(_)
                if sht != SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
                    || direction != Direction::Uplink =>
            {
                return Err(Error::EncodingError(
                    "SECURITY MODE COMPLETE requires uplink ciphering with new context".into(),
                ));
            }
            _ => {}
        }
    }
    if let Message::Esm(_, inner) = message {
        let required_direction = match inner {
            EsmMessage::ActivateDedicatedEpsBearerContextAccept(_)
            | EsmMessage::ActivateDedicatedEpsBearerContextReject(_)
            | EsmMessage::ActivateDefaultEpsBearerContextAccept(_)
            | EsmMessage::ActivateDefaultEpsBearerContextReject(_)
            | EsmMessage::BearerResourceAllocationRequest(_)
            | EsmMessage::BearerResourceModificationRequest(_)
            | EsmMessage::DeactivateEpsBearerContextAccept(_)
            | EsmMessage::EsmInformationResponse(_)
            | EsmMessage::ModifyEpsBearerContextAccept(_)
            | EsmMessage::ModifyEpsBearerContextReject(_)
            | EsmMessage::PdnConnectivityRequest(_)
            | EsmMessage::PdnDisconnectRequest(_)
            | EsmMessage::RemoteUeReport(_) => Some(Direction::Uplink),
            EsmMessage::ActivateDedicatedEpsBearerContextRequest(_)
            | EsmMessage::ActivateDefaultEpsBearerContextRequest(_)
            | EsmMessage::BearerResourceAllocationReject(_)
            | EsmMessage::BearerResourceModificationReject(_)
            | EsmMessage::DeactivateEpsBearerContextRequest(_)
            | EsmMessage::EsmInformationRequest(_)
            | EsmMessage::ModifyEpsBearerContextRequest(_)
            | EsmMessage::Notification(_)
            | EsmMessage::PdnConnectivityReject(_)
            | EsmMessage::PdnDisconnectReject(_)
            | EsmMessage::RemoteUeReportResponse(_) => Some(Direction::Downlink),
            EsmMessage::EsmDummyMessage(_)
            | EsmMessage::EsmStatus(_)
            | EsmMessage::EsmDataTransport(_) => None,
        };
        if required_direction.is_some_and(|required| required != direction) {
            return Err(Error::EncodingError(
                "EPS ESM message direction does not match its message type".into(),
            ));
        }
    }
    if let Message::Emm(_, EmmMessage::ControlPlaneServiceRequest(request)) = message
        && sht
            != if request.esm_message_container.is_some() || request.nas_message_container.is_some()
            {
                SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
            } else {
                SecurityHeaderType::IntegrityProtected
            }
    {
        return Err(Error::EncodingError(
            "CONTROL PLANE SERVICE REQUEST security header type does not match its container"
                .into(),
        ));
    }
    let valid = match sht {
        SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext => {
            matches!(message, Message::Emm(_, EmmMessage::SecurityModeCommand(_)))
        }
        SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext => {
            matches!(
                message,
                Message::Emm(_, EmmMessage::SecurityModeComplete(_))
            )
        }
        SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage => matches!(
            message,
            Message::Emm(_, EmmMessage::ControlPlaneServiceRequest(_))
        ),
        SecurityHeaderType::IntegrityProtectedAndCiphered => !matches!(
            message,
            Message::Emm(
                _,
                EmmMessage::AttachRequest(_) | EmmMessage::TrackingAreaUpdateRequest(_)
            )
        ),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::EncodingError(
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
pub struct SecurityContext {
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
    type Connection = ();
    type Counts = [[NextCount; 2]; 1];
    type Accepted = [[u64; 2]; 1];
    const NAME: &'static str = "EPS";
    const NULL_NAMES: (&'static str, &'static str) = ("EIA0", "EEA0");

    fn place((): ()) -> usize {
        0
    }

    fn bearer((): ()) -> oxirush_security::Bearer {
        oxirush_security::Bearer::ZERO
    }
}

/// Whether `inner` is a message that a context protects under `sht` in
/// `direction`: a plain EMM or ESM message, under a header type that
/// protects it.
fn check_protected(inner: &Message, sht: SecurityHeaderType, direction: Direction) -> Result<()> {
    if !matches!(inner, Message::Emm(..) | Message::Esm(..)) {
        return Err(Error::EncodingError(
            "EPS security requires a plain EMM or ESM message".into(),
        ));
    }
    if !matches!(
        sht,
        SecurityHeaderType::IntegrityProtected
            | SecurityHeaderType::IntegrityProtectedAndCiphered
            | SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
            | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
            | SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
    ) {
        return Err(Error::SecurityRefused(format!(
            "{sht:?} is no header type that protects a message"
        )));
    }
    validate_sht_message(sht, inner, direction)
}

impl fmt::Debug for SecurityContext {
    /// The algorithms and the next NAS COUNTs, without the keys.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurityContext")
            .field("integrity_algorithm", &self.core.integrity)
            .field("ciphering_algorithm", &self.core.ciphering)
            .field("uplink_count", &self.nas_count(Direction::Uplink))
            .field("downlink_count", &self.nas_count(Direction::Downlink))
            .finish_non_exhaustive()
    }
}

impl SecurityContext {
    /// Create a context for genuinely fresh NAS keys with COUNT values at zero.
    ///
    /// Reusing the same keys with this constructor violates TS 33.401 §6.5;
    /// use [`Self::reselect_algorithms`] for an existing KASME. A reserved
    /// algorithm (the codes 4 to 7) and EIA0 with another cipher than EEA0
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

    /// Derive a fresh EPS NAS context from a newly established KASME.
    ///
    /// COUNT starts at zero. Calling this again for the same KASME would violate
    /// TS 33.401 §6.5; use [`Self::reselect_algorithms`] instead. The
    /// algorithms are checked as [`Self::from_fresh_keys`] checks them.
    pub fn from_fresh_kasme(
        kasme: &KAsme,
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<Self> {
        let core = Core::derived(integrity, ciphering, |integrity, ciphering| Keys {
            integrity: eps::derive_knas_int(kasme, integrity),
            ciphering: eps::derive_knas_enc(kasme, ciphering),
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

    /// Next NAS COUNT to use or expect for a direction: `None` when every
    /// COUNT of the direction was used, after which the context protects
    /// nothing more in it.
    pub fn nas_count(&self, direction: Direction) -> Option<NasCount> {
        self.core.count(direction, ()).get()
    }

    /// How many COUNTs below the highest that the context accepted in a
    /// direction its replay window holds: 0, the default, for none.
    pub fn replay_window(&self) -> u8 {
        self.core.window()
    }

    /// Take a received message whose NAS COUNT is below the highest that the
    /// context accepted in its direction, once, as TS 24.301 §4.4.3.1 lets a
    /// receiver that can guarantee that the message was not accepted before:
    /// as the 5GS context does, see
    /// [`nas_5gs::SecurityContext::set_replay_window`](crate::nas_5gs::SecurityContext::set_replay_window).
    /// The window holds the COUNTs of the messages that a security header
    /// protects; the SERVICE REQUEST, whose short MAC has five bits of its
    /// COUNT, takes none below the next one.
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_eps::*;
    /// use oxirush_nas::Direction;
    ///
    /// let (int, enc) = (KNasInt::new(&[0x11; 16]), KNasEnc::new(&[0x22; 16]));
    /// let (eia, eea) = (Algorithm::Aes, Algorithm::Aes);
    /// let mut mme = SecurityContext::from_fresh_keys(&int, &enc, eia, eea).unwrap();
    /// let mut ue = SecurityContext::from_fresh_keys(&int, &enc, eia, eea).unwrap();
    /// ue.set_replay_window(32).unwrap();
    ///
    /// // Two EMM STATUS, of COUNT 0 and 1, which come in the other order, each once
    /// let status = Message::new_emm(EmmStatus::new(EmmCause::new(3)));
    /// let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
    /// let first = mme.protect(&status, header, Direction::Downlink).unwrap();
    /// let second = mme.protect(&status, header, Direction::Downlink).unwrap();
    /// assert_eq!(ue.unprotect(&second, Direction::Downlink).unwrap().count.get(), 1);
    /// assert_eq!(ue.unprotect(&first, Direction::Downlink).unwrap().count.get(), 0);
    /// assert!(ue.unprotect(&first, Direction::Downlink).is_err());
    /// ```
    pub fn set_replay_window(&mut self, size: u8) -> Result<()> {
        self.core.set_window(size)
    }

    /// Restore an EPS context and its next COUNT values from persistent state.
    ///
    /// The caller must supply the counts stored for this exact KASME, as
    /// [`Self::nas_count`] gave them: the uplink then the downlink COUNT,
    /// `None` for one that is exhausted. Passing zero for a KASME that has
    /// already protected traffic violates TS 33.401 §6.5.
    pub fn restore_from_kasme(
        kasme: &KAsme,
        integrity: Algorithm,
        ciphering: Algorithm,
        counts: (Option<NasCount>, Option<NasCount>),
    ) -> Result<Self> {
        let mut context = Self::from_fresh_kasme(kasme, integrity, ciphering)?;
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
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<()> {
        // A key that is replaced is wiped as it is dropped.
        let derive = |integrity, ciphering| Keys {
            integrity: eps::derive_knas_int(kasme, integrity),
            ciphering: eps::derive_knas_enc(kasme, ciphering),
        };
        self.core.reselect(integrity, ciphering, derive)
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
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<Self> {
        // The mapped context goes on from the COUNT after the one that was
        // used, and there is none after the last.
        let ul_count = ul_nas_count_used
            .next()
            .map_err(|_| Error::NasCountExhausted)?;
        let mut context = wiped(|| {
            let kasme = derive_mapped_kasme_idle(kamf, ul_nas_count_used);
            Self::from_fresh_kasme(&kasme, integrity, ciphering)
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
        integrity: Algorithm,
        ciphering: Algorithm,
    ) -> Result<Self> {
        let dl_count = dl_nas_count_used
            .next()
            .map_err(|_| Error::NasCountExhausted)?;
        let mut context = wiped(|| {
            let kasme = derive_mapped_kasme_handover(kamf, dl_nas_count_used);
            Self::from_fresh_kasme(&kasme, integrity, ciphering)
        })?;
        context.set_counts(Some(ul_nas_count), Some(dl_count));
        Ok(context)
    }

    /// Protect a short SERVICE REQUEST with the five-bit NAS SQN and 16-bit MAC.
    pub fn protect_service_request(&mut self, ksi: u8) -> Result<ServiceRequest> {
        if ksi >= 7 {
            return Err(Error::EncodingError(
                "EPS NAS SERVICE REQUEST requires a current security context KSI".into(),
            ));
        }
        let count = self.core.count(Direction::Uplink, ()).to_send()?;
        let ksi_and_sequence_number = (ksi << 5) | (count.sequence_number() & 0x1f);
        let mac = eps::service_request_short_mac(
            &self.core.keys.integrity,
            count,
            Direction::Uplink.into(),
            // The security header type 12 of a SERVICE REQUEST, as `new` writes it
            (12 << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR,
            ksi_and_sequence_number,
            self.core.integrity,
        )
        .map_err(|error| Error::EncodingError(error.to_string()))?;
        self.core.advance(Direction::Uplink, (), count);
        Ok(ServiceRequest::new(ksi_and_sequence_number, mac))
    }

    /// Verify a short SERVICE REQUEST and advance the uplink COUNT. Returns
    /// the NAS COUNT that the request was verified with: K_eNB is derived
    /// with it (TS 33.401 Annex A.3).
    pub fn unprotect_service_request(&mut self, request: &ServiceRequest) -> Result<NasCount> {
        if !(12..=15).contains(&request.security_header_type) {
            return Err(Error::DecodingError(
                "invalid EPS SERVICE REQUEST security header type".into(),
            ));
        }
        if request.ksi_and_sequence_number >> 5 == 7 {
            return Err(Error::DecodingError(
                "EPS NAS SERVICE REQUEST has no current security context KSI".into(),
            ));
        }
        let sequence_number = request.ksi_and_sequence_number & 0x1f;
        let lowest = self.core.count(Direction::Uplink, ());
        let count = lowest.received(sequence_number, 5, self.core.wraps())?;
        let mac = eps::service_request_short_mac(
            &self.core.keys.integrity,
            count,
            Direction::Uplink.into(),
            (request.security_header_type << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR,
            request.ksi_and_sequence_number,
            self.core.integrity,
        )
        .map_err(|error| Error::DecodingError(error.to_string()))?;
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
        .map_err(|_| Error::EncodingError("E-UTRAN Cell Identifier must be 28 bits".into()))?;
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
            return Err(Error::DecodingError(
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
        .map_err(|_| Error::DecodingError("E-UTRAN Cell Identifier must be 28 bits".into()))?;
        let (received, expected) = (ul_nas_mac.to_be_bytes(), expected_ul_nas_mac.to_be_bytes());
        self.core.check(&received, &expected)?;
        self.core.advance(Direction::Uplink, (), count);
        Ok(dl_nas_mac)
    }

    /// Protect a plain EMM or ESM message.
    pub fn protect(
        &mut self,
        inner: &Message,
        sht: SecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        check_protected(inner, sht, direction)?;
        let inner_bytes = inner.encode()?;
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
        sht: SecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        if !matches!(
            sht,
            SecurityHeaderType::IntegrityProtected
                | SecurityHeaderType::IntegrityProtectedAndCiphered
                | SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
        ) {
            return Err(Error::SecurityRefused(
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
        sht: SecurityHeaderType,
        direction: Direction,
    ) -> Result<Vec<u8>> {
        let header = [((sht as u8) << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR];
        let cipher = |core: &Core<Eps>, count, payload: &mut Vec<u8>| match sht {
            SecurityHeaderType::IntegrityProtectedAndCiphered
            | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext => {
                core.cipher(count, (), direction, payload);
                Ok(())
            }
            SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage => {
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
            return Err(Error::EncodingError(
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
    /// [`Error::AuthenticMessageRefused`], with its COUNT used and its
    /// plain octets, deciphered, which [`Message::answer_to_refused`]
    /// answers. A MAC mismatch returns [`Error::IntegrityCheckFailed`] and leaves
    /// the COUNTs unchanged. A receiver that must still process the message
    /// (TS 24.301 §4.4.4.3) can decode the PDU with
    /// [`Message::decode`],
    /// which returns the unverified inner message when it is not ciphered.
    ///
    /// With EIA0 no MAC is checked and no message is refused as a replay
    /// (§4.4.3.2, TS 33.401 annex B.0): a message received again is taken
    /// with a COUNT higher than the stored one (§4.4.3.1). A SECURITY MODE
    /// COMMAND is verified by the context that it takes into use, which the
    /// caller makes (§5.4.3.3): the context in use, with its COUNTs, one of
    /// [`Self::restore_from_kasme`] for new algorithms under its KASME, or
    /// one of [`Self::from_fresh_kasme`] after an authentication.
    pub fn unprotect(&mut self, data: &[u8], direction: Direction) -> Result<Verified<Message>> {
        let (plain, message, security_header_type, count) =
            self.unprotect_checked(data, direction)?;
        let message = match (security_header_type, message) {
            (SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage, _) => {
                let mac = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
                Message::EmmTransport(if plain.is_empty() {
                    EmmTransport::new(mac, data[5])
                } else {
                    EmmTransport::new(mac, data[5]).set_data_container(plain)
                })
            }
            (_, Some(message @ (Message::Emm(..) | Message::Esm(..)))) => message,
            _ => {
                return Err(refused(
                    Error::DecodingError(
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
    ) -> Result<(Vec<u8>, Option<Message>, SecurityHeaderType, NasCount)> {
        if data.len() < EPS_SECURITY_HEADER_LEN {
            return Err(Error::BufferTooShort);
        }
        if data[0] & 0x0F != EPS_EMM_PROTOCOL_DISCRIMINATOR {
            return Err(Error::DecodingError(
                "invalid EPS security protocol discriminator".into(),
            ));
        }
        let sht = SecurityHeaderType::try_from(data[0] >> 4)?;
        if !matches!(
            sht,
            SecurityHeaderType::IntegrityProtected
                | SecurityHeaderType::IntegrityProtectedAndCiphered
                | SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
                | SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
                | SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        ) {
            return Err(Error::DecodingError(
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
            SecurityHeaderType::IntegrityProtectedAndCiphered
                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
                | SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        ) {
            self.core.cipher(nas_count, (), direction, &mut plain);
        } else if sht == SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage {
            let (key, algorithm) = (&self.core.keys.ciphering, self.core.ciphering);
            cipher_control_plane_container(&mut plain, key, nas_count, direction, algorithm)
                .map_err(|error| refused(error, &plain))?;
        }
        if sht == SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage {
            if !plain.is_empty()
                && !received_emm_data_container_is_valid(&plain, direction == Direction::Downlink)
            {
                return Err(refused(
                    Error::DecodingError("invalid EMM TRANSPORT data container".into()),
                    &plain,
                ));
            }
            return Ok((plain, None, sht, nas_count));
        }
        let inner = Message::decode_with_direction(&plain, direction)
            .map_err(|error| refused(error, &plain))?;
        validate_sht_message(sht, &inner, direction).map_err(|_| {
            let error = "EPS security header type does not match message type";
            refused(Error::DecodingError(error.into()), &plain)
        })?;
        Ok((plain, Some(inner), sht, nas_count))
    }
}

#[cfg(test)]
impl SecurityContext {
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
    use oxirush_utils::identity::Algorithm;

    /// A NAS COUNT of a message.
    fn count(count: u32) -> NasCount {
        NasCount::new(count).unwrap()
    }
    use crate::common::Validate;
    use crate::nas_eps::{
        ControlPlaneServiceRequest, EmmMessage, EmmStatus, PdnConnectivityRequest,
        SecurityModeCommand, SecurityModeComplete,
    };
    use crate::nas_eps::{
        ControlPlaneServiceType, EmmCause, EsmMessageContainer, KeySetIdentifier, MessageContainer,
        PdnType, RequestType, SecurityAlgorithms, UeSecurityCapability,
    };

    #[test]
    fn security_mode_requires_its_header_and_direction() {
        let command = Message::new_emm(SecurityModeCommand::new(
            SecurityAlgorithms::new(0),
            KeySetIdentifier::new(0),
            UeSecurityCapability::new(vec![0; 2]),
        ));
        let complete = Message::new_emm(SecurityModeComplete::new());
        let cases = [
            (
                &command,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
            ),
            (
                &command,
                SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
                Direction::Uplink,
            ),
            (
                &complete,
                SecurityHeaderType::IntegrityProtected,
                Direction::Uplink,
            ),
            (
                &complete,
                SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
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
                    SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
                    Direction::Downlink,
                )
                .is_ok()
        );
        assert!(
            context()
                .protect(
                    &complete,
                    SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
                    Direction::Uplink,
                )
                .is_ok()
        );
    }

    #[test]
    fn mapped_5gs_context_copies_counts_and_uses_mapped_key() {
        let kamf = KAmf::new(&core::array::from_fn(|i| i as u8));
        let kasme = derive_mapped_kasme_idle(&kamf, count(0x1234));
        let expected =
            SecurityContext::from_fresh_kasme(&kasme, Algorithm::Aes, Algorithm::Aes).unwrap();
        let context = SecurityContext::from_mapped_kasme_idle(
            &kamf,
            count(0x1234),
            count(0x5678),
            Algorithm::Aes,
            Algorithm::Aes,
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
        let message = Message::new_emm(EmmStatus::new(EmmCause::new(3)));
        let wire = context
            .clone()
            .protect(
                &message,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Uplink,
            )
            .unwrap();
        assert_eq!(wire, [0x27, 0x3b, 0xa8, 0xe0, 0xf4, 0x35, 0xbb, 0x27, 0x2e]);

        let handover = SecurityContext::from_mapped_kasme_handover(
            &kamf,
            count(0x1234),
            count(0x5678),
            Algorithm::Aes,
            Algorithm::Aes,
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
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                Direction::Downlink,
            )
            .unwrap();
        assert_eq!(wire, [0x27, 0x77, 0x6a, 0x52, 0xea, 0x79, 0x31, 0x21, 0x28]);
        assert!(
            SecurityContext::from_mapped_kasme_idle(
                &kamf,
                NasCount::MAX,
                NasCount::ZERO,
                Algorithm::Aes,
                Algorithm::Aes,
            )
            .is_err()
        );
        assert!(
            SecurityContext::from_mapped_kasme_handover(
                &kamf,
                NasCount::ZERO,
                NasCount::MAX,
                Algorithm::Aes,
                Algorithm::Aes,
            )
            .is_err()
        );
    }

    fn context() -> SecurityContext {
        SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x11; 16]),
            &KNasEnc::new(&[0x22; 16]),
            Algorithm::Aes,
            Algorithm::Aes,
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
            "SecurityContext { integrity_algorithm: Aes, ciphering_algorithm: Aes, \
             uplink_count: Some(NasCount(766)), downlink_count: Some(NasCount(0)), .. }"
        );
        // Neither a key nor one of its octets
        assert!(!shown.contains("11") && !shown.contains("22") && !shown.contains("17"));
        // What a UE costs: the place of the keys, the algorithms, two COUNTs
        // and the place of a replay window, and the two keys in the heap
        #[cfg(target_pointer_width = "64")]
        assert_eq!(core::mem::size_of::<SecurityContext>(), 32);
        assert_eq!(core::mem::size_of::<Keys<KNasInt, KNasEnc>>(), 32);

        // The COUNT of each message that is verified, across a wrap of the
        // sequence number
        let message = Message::new_emm(EmmStatus::new(EmmCause::new(3)));
        let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
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
                SecurityHeaderType::IntegrityProtected,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
                SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
                SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
            ] {
                let mut sender = context();
                match direction {
                    Direction::Uplink => *sender.count_mut(Direction::Uplink) = (0x1234).into(),
                    Direction::Downlink => *sender.count_mut(Direction::Downlink) = (0x1234).into(),
                }
                let refused = Message::decode(&inner).map_or(true, |message| {
                    sender.protect(&message, sht, direction).is_err()
                });
                assert!(refused);
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
                        Algorithm::Aes,
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
                    Algorithm::Aes,
                );
                assert_eq!(&wire[1..5], mac.to_be_bytes());
                if matches!(sht as u8, 2 | 4) {
                    eps::nas_cipher(
                        &KNasEnc::new(&[0x22; 16]),
                        count(0x1234),
                        direction.into(),
                        &mut payload,
                        Algorithm::Aes,
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
                    Err(Error::IntegrityCheckFailed)
                ));
                assert_eq!(tampered_receiver.count_ref(direction), 0x1234);
                // The code is right and the message is refused for what it
                // is, with its COUNT used.
                assert_eq!(
                    receiver.unprotect_raw(&wire, direction),
                    Err(Error::AuthenticMessageRefused {
                        error: Box::new(Error::UnknownMessageType(0xff)),
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
            SecurityHeaderType::IntegrityProtected,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
        ] {
            let message = Message::decode(&inner).unwrap();
            let checked = (sender.clone())
                .protect(&message, sht, Direction::Uplink)
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
        let new_context = SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext;
        let message = Message::decode(&inner).unwrap();
        assert!(
            sender
                .protect(&message, new_context, Direction::Uplink)
                .is_err()
        );
        // An uplink SECURITY MODE REJECT
        let reject = Message::decode(&[0x07, 0x5f, 0x03]).unwrap();
        let integrity = SecurityHeaderType::IntegrityProtected;
        assert!(
            sender
                .protect(&reject, integrity, Direction::Downlink)
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
        let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
        for unsupported in [
            SecurityHeaderType::PlainNasMessageNotSecurityProtected,
            SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
            SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage,
            SecurityHeaderType::SecurityHeaderForTheServiceRequestMessage,
        ] {
            assert!(
                sender
                    .protect_opaque_payload(vec![0xff], unsupported, Direction::Uplink)
                    .is_err()
            );
            assert_eq!(sender.count_ref(Direction::Uplink), 0);
        }
        // EIA0 with a cipher makes no context.
        let (integrity, ciphering) = (Algorithm::Null, Algorithm::Aes);
        let context = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0x11; 16]),
            &KNasEnc::new(&[0x22; 16]),
            integrity,
            ciphering,
        );
        assert!(context.is_err());
        let kasme = KAsme::new(&[0x42; 32]);
        assert!(SecurityContext::from_fresh_kasme(&kasme, integrity, ciphering).is_err());
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
                Algorithm::Aes,
            );
            assert_eq!(&wire[1..5], mac.to_be_bytes());
            assert_eq!(sender.count_ref(direction), 0x0100_0000);
            // After the last COUNT the context protects and verifies nothing
            // more in the direction, and says so by a variant.
            assert_eq!(
                sender.protect_opaque_payload(vec![0xff], sht, direction),
                Err(Error::NasCountExhausted)
            );
            assert_eq!(
                sender.unprotect_raw(&wire, direction),
                Err(Error::NasCountExhausted)
            );
            assert_eq!(sender.count_ref(direction), 0x0100_0000);
        }
    }

    #[test]
    fn eps_ciphered_message_uses_zero_bearer_and_rejects_tampering() {
        let message = Message::new_emm(EmmStatus::new(EmmCause::new(3)));
        let mut sender = context();
        let mut receiver = context();
        let wire = sender
            .protect(
                &message,
                SecurityHeaderType::IntegrityProtectedAndCiphered,
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
            Algorithm::Aes,
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
        assert_eq!(sht, SecurityHeaderType::IntegrityProtectedAndCiphered);
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
        let message = Message::decode_with_direction(&plain, Direction::Downlink).unwrap();
        assert!(matches!(
            message,
            Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_))
        ));
        let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
        let wire = context()
            .protect(&message, sht, Direction::Downlink)
            .unwrap();
        let Verified {
            message: decoded, ..
        } = context().unprotect(&wire, Direction::Downlink).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn independent_eps_count_boundary_vectors_and_replay() {
        let message = Message::new_emm(EmmStatus::new(EmmCause::new(3)));
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
                    SecurityHeaderType::IntegrityProtectedAndCiphered,
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
                            SecurityHeaderType::IntegrityProtectedAndCiphered,
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
            SecurityContext::from_fresh_keys(
                &KNasInt::new(&[0; 16]),
                &KNasEnc::new(&[0; 16]),
                Algorithm::Null,
                eea,
            )
        };
        assert!(context(Algorithm::Aes).is_err());
        let kasme = KAsme::new(&[0x42; 32]);
        let mut null = context(Algorithm::Null).unwrap();
        assert!(
            null.reselect_algorithms(&kasme, Algorithm::Null, Algorithm::Snow3g)
                .is_err()
        );
        // A context that refuses its new algorithms keeps those it had.
        assert_eq!(null.ciphering_algorithm(), Algorithm::Null);
        assert_eq!(null.count_ref(Direction::Uplink), 0);
    }

    #[test]
    fn fresh_count_after_gap_is_accepted_and_replay_is_not() {
        // TS 24.301 §4.4.3.1: a lower sequence number means the overflow
        // counter advanced, independent of the current overflow value.
        let message = Message::new_emm(EmmStatus::new(EmmCause::new(3)));
        for (receiver_next, sender_count) in [(0x05, 0x90), (0x0105, 0x0190), (0x01f0, 0x0202)] {
            let mut sender = context();
            let mut receiver = context();
            *sender.count_mut(Direction::Uplink) = (sender_count).into();
            *receiver.count_mut(Direction::Uplink) = (receiver_next).into();
            let wire = sender
                .protect(
                    &message,
                    SecurityHeaderType::IntegrityProtectedAndCiphered,
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
    fn a_replay_window_takes_a_lower_count_once_in_eps_too() {
        // TS 24.301 §4.4.3.1 as TS 24.501 has it: the message of COUNT 1
        // after that of 2, once; one below the window is refused; without a
        // window the lower COUNT is refused as before.
        let message = Message::new_emm(EmmStatus::new(EmmCause::new(3)));
        let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
        for window in [0, 32] {
            let mut mme = context();
            let mut ue = context();
            ue.set_replay_window(window).unwrap();
            assert_eq!(ue.replay_window(), window);
            let wire: Vec<_> = (0..40)
                .map(|_| mme.protect(&message, header, Direction::Downlink).unwrap())
                .collect();
            let mut downlink = |at: usize| {
                ue.unprotect(&wire[at], Direction::Downlink)
                    .map(|verified| verified.count)
            };
            assert_eq!(downlink(2), Ok(count(2)));
            assert_eq!(downlink(1).is_ok(), window > 0);
            assert!(downlink(1).is_err());
            assert_eq!(downlink(39), Ok(count(39)));
            assert!(downlink(6).is_err());
            assert_eq!(downlink(7).is_ok(), window > 0);
            assert_eq!(ue.count_ref(Direction::Downlink), 40);
        }
        assert!(context().set_replay_window(65).is_err());
    }

    #[test]
    fn eps_integrity_only_esm_message_round_trips() {
        let message = Message::new_esm(
            PdnConnectivityRequest::new(RequestType::new(1), PdnType::new(3)),
            0,
            1,
        );
        let mut sender = context();
        let mut receiver = context();
        assert!(
            sender
                .protect(
                    &message,
                    SecurityHeaderType::IntegrityProtected,
                    Direction::Downlink,
                )
                .is_err()
        );
        assert_eq!(sender.count_ref(Direction::Downlink), 0);
        let wire = sender
            .protect(
                &message,
                SecurityHeaderType::IntegrityProtected,
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
        let context =
            SecurityContext::from_fresh_kasme(&kasme, Algorithm::Aes, Algorithm::Snow3g).unwrap();
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
        let mut context = SecurityContext::restore_from_kasme(
            &kasme,
            Algorithm::Aes,
            Algorithm::Aes,
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
            .reselect_algorithms(&kasme, Algorithm::Snow3g, Algorithm::Snow3g)
            .unwrap();
        assert_eq!(context.integrity_algorithm(), Algorithm::Snow3g);
        assert_eq!(context.ciphering_algorithm(), Algorithm::Snow3g);
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
        let exhausted = SecurityContext::restore_from_kasme(
            &kasme,
            Algorithm::Aes,
            Algorithm::Aes,
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
                0xc7,
                0x7f,
                Algorithm::Aes
            )
            .unwrap()
        );
        let wire = Message::ServiceRequest(request.clone()).encode().unwrap();
        assert_eq!(wire.len(), 4);
        let decoded = Message::decode(&wire).unwrap();
        assert_eq!(decoded, Message::ServiceRequest(request.clone()));
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
            Algorithm::Aes,
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
            Err(Error::NasCountExhausted)
        );
        assert_eq!(context.count_ref(Direction::Uplink), 0x0100_0000);
        assert_eq!(
            context.protect_service_request(1).map(|_| ()),
            Err(Error::NasCountExhausted)
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
            Algorithm::Aes,
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
            Algorithm::Aes,
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
            Algorithm::Aes,
        )
        .unwrap();
        let error = receiver
            .verify_re_establishment(0x20, ul_nas_mac, 0x0123_4567)
            .unwrap_err();
        assert!(matches!(error, Error::DecodingError(_)), "{error:?}");
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
        let mac = eps::service_request_short_mac(
            &receiver.core.keys.integrity,
            count(0),
            Direction::Uplink.into(),
            0xc7,
            ksi_and_sequence_number,
            Algorithm::Aes,
        )
        .unwrap();
        let request = ServiceRequest::new(ksi_and_sequence_number, mac);
        let error = receiver.unprotect_service_request(&request).unwrap_err();
        assert!(matches!(error, Error::DecodingError(_)), "{error:?}");
        assert_eq!(receiver.count_ref(Direction::Uplink), 0);
        // The KSI 6 is one
        let ksi_and_sequence_number = 6 << 5;
        let mac = eps::service_request_short_mac(
            &receiver.core.keys.integrity,
            count(0),
            Direction::Uplink.into(),
            0xc7,
            ksi_and_sequence_number,
            Algorithm::Aes,
        )
        .unwrap();
        let request = ServiceRequest::new(ksi_and_sequence_number, mac);
        assert_eq!(receiver.unprotect_service_request(&request), Ok(count(0)));
    }

    #[test]
    fn eps_partial_ciphering_preserves_clear_header_and_recovers_container() {
        for use_esm in [true, false] {
            let mut request = ControlPlaneServiceRequest::new(
                ControlPlaneServiceType::new(0),
                KeySetIdentifier::new(0),
            );
            if use_esm {
                request.esm_message_container =
                    Some(EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]));
            } else {
                request.nas_message_container = Some(MessageContainer::new(vec![0x11, 0x22, 0x33]));
            }
            let message = Message::new_emm(request);
            let plain = message.encode().unwrap();
            let mut sender = context();
            let mut receiver = context();
            assert!(
                sender
                    .protect(
                        &message,
                        SecurityHeaderType::IntegrityProtected,
                        Direction::Uplink
                    )
                    .is_err()
            );
            assert!(
                sender
                    .protect(
                        &message,
                        SecurityHeaderType::IntegrityProtectedAndCiphered,
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
                Algorithm::Aes,
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
                    SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
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
                SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
            );
            assert_eq!(decoded.encode().unwrap(), plain);
            let mut tampered = wire;
            tampered[7] ^= 1;
            assert!(context().unprotect(&tampered, Direction::Uplink).is_err());
        }
    }

    #[test]
    fn control_plane_service_request_without_container_uses_integrity_only() {
        let message = Message::new_emm(ControlPlaneServiceRequest::new(
            ControlPlaneServiceType::new(0),
            KeySetIdentifier::new(0),
        ));
        assert!(
            context()
                .protect(
                    &message,
                    SecurityHeaderType::IntegrityProtected,
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
            Algorithm::Aes,
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
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
        ] {
            assert!(sender.protect(&message, sht, Direction::Uplink).is_err());
            assert_eq!(sender.count_ref(Direction::Uplink), 0);
        }
        let wire = sender
            .protect(
                &message,
                SecurityHeaderType::IntegrityProtected,
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
        let opaque = Message::decode(&wire).unwrap();
        assert_eq!(opaque.encode().unwrap(), wire);
        let Verified {
            message: decoded,
            security_header_type: sht,
            ..
        } = receiver.unprotect(&wire, Direction::Uplink).unwrap();
        assert_eq!(
            sht,
            SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        );
        let Message::EmmTransport(transport) = decoded else {
            panic!("expected EMM TRANSPORT")
        };
        assert_eq!(transport.data_container.as_deref(), Some(&[0x01, 0xab][..]));
        assert!(Message::EmmTransport(transport).encode().is_err());
        let empty_wire = sender
            .protect_emm_transport(None, Direction::Uplink)
            .unwrap();
        let Verified { message: empty, .. } =
            receiver.unprotect(&empty_wire, Direction::Uplink).unwrap();
        let Message::EmmTransport(empty) = empty else {
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
        // direction), 01 or 11, are accepted once the MAC verifies (TS 24.007
        // §11.1.4).
        let wire_of = |container: &[u8], direction: Direction| {
            let mut payload = container.to_vec();
            eps::nas_cipher(
                &KNasEnc::new(&[0x22; 16]),
                NasCount::ZERO,
                direction.into(),
                &mut payload,
                Algorithm::Aes,
            );
            let mut mac_input = vec![0];
            mac_input.extend_from_slice(&payload);
            let mac = eps::nas_mac(
                &KNasInt::new(&[0x11; 16]),
                NasCount::ZERO,
                direction.into(),
                &mac_input,
                Algorithm::Aes,
            );
            let mut wire = vec![0xb7];
            wire.extend_from_slice(&mac.to_be_bytes());
            wire.extend_from_slice(&mac_input);
            wire
        };
        // Uplink, the DDX 11 is reserved: the container is refused once the
        // MAC verifies
        let wire = wire_of(&[0x19, 0xaa], Direction::Uplink);
        let error = context()
            .unprotect_raw(&wire, Direction::Uplink)
            .unwrap_err();
        assert!(
            matches!(error, Error::AuthenticMessageRefused { .. }),
            "{error:?}"
        );
        for container in [[0x21, 0xaa], [0x09, 0xaa], [0x19, 0xaa]] {
            let wire = wire_of(&container, Direction::Downlink);
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
        let mut sender = SecurityContext::from_fresh_keys(
            &KNasInt::new(&[0; 16]),
            &KNasEnc::new(&[0; 16]),
            Algorithm::Null,
            Algorithm::Null,
        )
        .unwrap();
        let mut receiver = sender.clone();
        *sender.count_mut(Direction::Uplink) = (0x00ff_ffff).into();
        *receiver.count_mut(Direction::Uplink) = (0x00ff_ffff).into();
        let message = Message::new_emm(EmmStatus::new(EmmCause::new(3)));
        let mut wire = sender
            .protect(
                &message,
                SecurityHeaderType::IntegrityProtected,
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
            Algorithm::Aes,
        );
        let mut wire = vec![0x17];
        wire.extend_from_slice(&mac.to_be_bytes());
        wire.extend_from_slice(&mac_input);

        let mut raw_receiver = SecurityContext::from_fresh_keys(
            &KNasInt::new(&key),
            &KNasEnc::new(&[0x22; 16]),
            Algorithm::Aes,
            Algorithm::Aes,
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
        let request = ServiceRequest::new(0xe0, 0);
        assert!(receiver.unprotect_service_request(&request).is_err());
        assert_eq!(receiver.count_ref(Direction::Uplink), 0);
        assert!(!Message::ServiceRequest(request).validate().is_empty());
    }

    #[test]
    fn service_request_uses_actual_received_first_octet() {
        let mut sender = context();
        let mut receiver = context();
        let mut request = sender.protect_service_request(1).unwrap();
        request.security_header_type = 13;
        request.message_authentication_code = eps::service_request_short_mac(
            &KNasInt::new(&[0x11; 16]),
            NasCount::ZERO,
            Direction::Uplink.into(),
            0xd7,
            request.ksi_and_sequence_number,
            Algorithm::Aes,
        )
        .unwrap();
        receiver.unprotect_service_request(&request).unwrap();
        request.security_header_type = 0;
        assert!(receiver.unprotect_service_request(&request).is_err());
    }
}
