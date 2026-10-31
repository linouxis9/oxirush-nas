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

//! The `Display` of the 5GS messages and of their IEs.
//!
//! A message prints its protocol and its type, then what a log needs of its
//! IEs, in the order of the message. Each IE prints in the form of its type,
//! which the IEs of EPS share ([`crate::nas_eps::display`]):
//!
//! - a cause by its number and the name of its table: `#22 (Congestion)`;
//! - a timer with its unit: `T3346=10 min`, `T3512=1 h`, `deactivated`;
//! - RAND, AUTN and AUTS whole, in lower case: they travel in clear. RES\*
//!   is a key, and prints its length alone;
//! - an identity whole, as the service based interfaces write it:
//!   `suci-0-208-93-0-0-0-0000000001`, `5g-guti-...`, `imei-...`;
//! - a TAI as `208-93-000001`, an S-NSSAI as `1/0000ff`, a list whole up to
//!   four entries, then its first three and how many more;
//! - the message that a container carries.
//!
//! An IE whose octets do not read as its type prints them.
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//!
//! let reject = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x2a]).unwrap();
//! let shown = "5GMM RegistrationReject (cause=#22 (Congestion), T3346=10 min)";
//! assert_eq!(reject.to_string(), shown);
//! ```

use crate::common::display::{self, Items};
use crate::nas_5gs::ie::*;
use crate::nas_5gs::message_types::*;
use crate::nas_5gs::messages::*;
use crate::nas_5gs::types::*;
use crate::nas_5gs::upds::*;
use crate::prelude::*;
use core::fmt;

// ============================================================================
// Top-level message
// ============================================================================

impl fmt::Display for Nas5gsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Nas5gsMessage::Gmm(_hdr, msg) => {
                write!(f, "5GMM {msg}")
            }
            Nas5gsMessage::Gsm(hdr, msg) => {
                write!(
                    f,
                    "5GSM (PSI={}, PTI={}) {}",
                    hdr.pdu_session_identity, hdr.procedure_transaction_identity, msg
                )
            }
            Nas5gsMessage::SecurityProtected(hdr, inner) => {
                write!(
                    f,
                    "SecurityProtected (SHT={:?}, MAC={:#010x}, SN={}) {}",
                    hdr.security_header_type,
                    hdr.message_authentication_code,
                    hdr.sequence_number,
                    inner
                )
            }
            Nas5gsMessage::Opaque(data) => write!(f, "Opaque ({} octets)", data.len()),
        }
    }
}

// ============================================================================
// UPDS
// ============================================================================

impl fmt::Display for NasUpdsMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManageUePolicyCommand => write!(f, "ManageUePolicyCommand"),
            Self::ManageUePolicyComplete => write!(f, "ManageUePolicyComplete"),
            Self::ManageUePolicyCommandReject => write!(f, "ManageUePolicyCommandReject"),
            Self::UeStateIndication => write!(f, "UeStateIndication"),
            Self::UePolicyProvisioningRequest => write!(f, "UePolicyProvisioningRequest"),
            Self::UePolicyProvisioningReject => write!(f, "UePolicyProvisioningReject"),
        }
    }
}

impl fmt::Display for NasUpdsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManageUePolicyCommand(message) => {
                NasUpdsMessageType::ManageUePolicyCommand.fmt(f)?;
                let mut items = Items::new(f);
                let sublists = message.ue_policy_section_management_list.sublists();
                items.item("sublists", sublists.len())?;
                let classmark = message.ue_policy_network_classmark.is_some();
                items.flag("network classmark", classmark)?;
                items.flag("VPS URSP", message.vps_ursp_configuration.is_some())?;
                items.end()
            }
            Self::ManageUePolicyComplete(_) => NasUpdsMessageType::ManageUePolicyComplete.fmt(f),
            Self::ManageUePolicyCommandReject(message) => {
                NasUpdsMessageType::ManageUePolicyCommandReject.fmt(f)?;
                let mut items = Items::new(f);
                let result = &message.ue_policy_section_management_result;
                items.item("subresults", result.subresults().len())?;
                items.end()
            }
            Self::UeStateIndication(message) => {
                NasUpdsMessageType::UeStateIndication.fmt(f)?;
                let mut items = Items::new(f);
                items.item("UPSI-sublists", message.upsi_list.sublists().len())?;
                items.flag("UE OS id", message.ue_os_id.is_some())?;
                items.end()
            }
            Self::UePolicyProvisioningRequest(message) => {
                NasUpdsMessageType::UePolicyProvisioningRequest.fmt(f)?;
                let mut items = Items::new(f);
                items.item("payload", display::Octets(&message.payload))?;
                items.end()
            }
            Self::UePolicyProvisioningReject(message) => {
                NasUpdsMessageType::UePolicyProvisioningReject.fmt(f)?;
                let mut items = Items::new(f);
                items.item("payload", display::Octets(&message.payload))?;
                items.end()
            }
            Self::Unsupported(message) => {
                f.write_str("UnsupportedUpdsMessage")?;
                let mut items = Items::new(f);
                items.item("type", format_args!("{:#04x}", message.message_type))?;
                items.item("body", display::Octets(&message.body))?;
                items.end()
            }
        }
    }
}

impl fmt::Display for NasUpdsEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UPDS (PTI={}, type={:#04x}) {}",
            self.procedure_transaction_identity_value(),
            self.message_type_code(),
            self.message
        )
    }
}

// ============================================================================
// Message types
// ============================================================================

impl fmt::Display for Nas5gmmMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for Nas5gsmMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ============================================================================
// 5GMM Message enum
// ============================================================================

impl fmt::Display for Nas5gmmMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistrationRequest(m) => write!(f, "{m}"),
            Self::RegistrationAccept(m) => write!(f, "{m}"),
            Self::RegistrationComplete(m) => write!(f, "{m}"),
            Self::RegistrationReject(m) => write!(f, "{m}"),
            Self::DeregistrationRequestUeOriginating(m) => write!(f, "{m}"),
            Self::DeregistrationRequestUeTerminated(m) => write!(f, "{m}"),
            Self::DeregistrationAcceptUeOriginating(m) => write!(f, "{m}"),
            Self::DeregistrationAcceptUeTerminated(m) => write!(f, "{m}"),
            Self::ConfigurationUpdateComplete(m) => write!(f, "{m}"),
            Self::ServiceRequest(m) => write!(f, "{m}"),
            Self::ServiceReject(m) => write!(f, "{m}"),
            Self::ServiceAccept(m) => write!(f, "{m}"),
            Self::ConfigurationUpdateCommand(m) => write!(f, "{m}"),
            Self::AuthenticationRequest(m) => write!(f, "{m}"),
            Self::AuthenticationResponse(m) => write!(f, "{m}"),
            Self::AuthenticationReject(m) => write!(f, "{m}"),
            Self::AuthenticationFailure(m) => write!(f, "{m}"),
            Self::AuthenticationResult(m) => write!(f, "{m}"),
            Self::IdentityRequest(m) => write!(f, "{m}"),
            Self::IdentityResponse(m) => write!(f, "{m}"),
            Self::SecurityModeCommand(m) => write!(f, "{m}"),
            Self::SecurityModeComplete(m) => write!(f, "{m}"),
            Self::SecurityModeReject(m) => write!(f, "{m}"),
            Self::FiveGmmStatus(m) => write!(f, "{m}"),
            Self::Notification(m) => write!(f, "{m}"),
            Self::NotificationResponse(m) => write!(f, "{m}"),
            Self::UlNasTransport(m) => write!(f, "{m}"),
            Self::DlNasTransport(m) => write!(f, "{m}"),
            Self::ControlPlaneServiceRequest(m) => write!(f, "{m}"),
            Self::NetworkSliceSpecificAuthenticationCommand(m) => write!(f, "{m}"),
            Self::NetworkSliceSpecificAuthenticationComplete(m) => write!(f, "{m}"),
            Self::NetworkSliceSpecificAuthenticationResult(m) => write!(f, "{m}"),
            Self::RelayKeyRequest(m) => write!(f, "{m}"),
            Self::RelayKeyAccept(m) => write!(f, "{m}"),
            Self::RelayKeyReject(m) => write!(f, "{m}"),
            Self::RelayAuthenticationRequest(m) => write!(f, "{m}"),
            Self::RelayAuthenticationResponse(m) => write!(f, "{m}"),
        }
    }
}

// ============================================================================
// 5GSM Message enum
// ============================================================================

impl fmt::Display for Nas5gsmMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PduSessionEstablishmentRequest(m) => write!(f, "{m}"),
            Self::PduSessionEstablishmentAccept(m) => write!(f, "{m}"),
            Self::PduSessionEstablishmentReject(m) => write!(f, "{m}"),
            Self::PduSessionAuthenticationCommand(m) => write!(f, "{m}"),
            Self::PduSessionAuthenticationComplete(m) => write!(f, "{m}"),
            Self::PduSessionAuthenticationResult(m) => write!(f, "{m}"),
            Self::PduSessionModificationRequest(m) => write!(f, "{m}"),
            Self::PduSessionModificationReject(m) => write!(f, "{m}"),
            Self::PduSessionModificationCommand(m) => write!(f, "{m}"),
            Self::PduSessionModificationComplete(m) => write!(f, "{m}"),
            Self::PduSessionModificationCommandReject(m) => write!(f, "{m}"),
            Self::PduSessionReleaseRequest(m) => write!(f, "{m}"),
            Self::PduSessionReleaseReject(m) => write!(f, "{m}"),
            Self::PduSessionReleaseCommand(m) => write!(f, "{m}"),
            Self::PduSessionReleaseComplete(m) => write!(f, "{m}"),
            Self::FiveGsmStatus(m) => write!(f, "{m}"),
            Self::ServiceLevelAuthenticationCommand(m) => write!(f, "{m}"),
            Self::ServiceLevelAuthenticationComplete(m) => write!(f, "{m}"),
            Self::RemoteUeReport(m) => write!(f, "{m}"),
            Self::RemoteUeReportResponse(m) => write!(f, "{m}"),
        }
    }
}

// ============================================================================
// IEs
// ============================================================================

/// A 5GMM cause by its number and its name: `#22 (Congestion)`.
impl fmt::Display for NasFGmmCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.cause().map(GmmCause::description);
        display::cause(f, self.value, name)
    }
}

/// A 5GSM cause by its number and its name: `#26 (Insufficient resources)`.
impl fmt::Display for NasFGsmCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.cause().map(GsmCause::description);
        display::cause(f, self.value, name)
    }
}

/// An ngKSI: `0`, `mapped 3` or `no key`.
impl fmt::Display for NasKeySetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.key_set_identifier().fmt(f)
    }
}

/// The selected algorithms: `NEA2 NIA2`.
impl fmt::Display for NasSecurityAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ciphering = Coded(self.ciphering(), self.ciphering_raw());
        let integrity = Coded(self.integrity(), self.integrity_raw());
        write!(f, "{ciphering} {integrity}")
    }
}

/// The selected EPS algorithms of a SECURITY MODE COMMAND: `EEA2 EIA2`.
impl fmt::Display for NasEpsNasSecurityAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ciphering = Coded(self.ciphering(), self.ciphering_raw());
        let integrity = Coded(self.integrity(), self.integrity_raw());
        write!(f, "{ciphering} {integrity}")
    }
}

/// The algorithms of a UE security capability: `EA0 EA2 / IA2`, and those
/// of EPS after a `+` when it has one.
impl fmt::Display for NasUeSecurityCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ea = |number| self.supports_ea(number);
        let ia = |number| self.supports_ia(number);
        display::algorithms(f, ("EA", "IA"), ea, ia)?;
        if self.eea_byte() | self.eia_byte() != 0 {
            f.write_str(" + ")?;
            let eea = |number| self.supports_eea(number);
            let eia = |number| self.supports_eia(number);
            display::algorithms(f, ("EEA", "EIA"), eea, eia)?;
        }
        Ok(())
    }
}

/// A 5GS mobile identity, whole, as the service based interfaces write
/// it: `suci-0-208-93-0-0-0-0000000001`, `5g-guti-...`, `5g-s-tmsi-...`,
/// `imei-...`, `imeisv-...`, `mac-...`, `eui-...` or `no identity`. One
/// whose octets do not read as its type shows them.
impl fmt::Display for NasFGsMobileIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let octets = &self.value[..];
        let shown = match self.identity_type() {
            Some(MobileIdentityType::Suci) => self.as_suci().map(|suci| suci.fmt(f)),
            Some(MobileIdentityType::Guti) => self.as_guti().map(|guti| guti.fmt(f)),
            Some(MobileIdentityType::STmsi) => self.as_s_tmsi().map(|s_tmsi| s_tmsi.fmt(f)),
            Some(MobileIdentityType::Imei) => self.as_imei().map(|imei| write!(f, "imei-{imei}")),
            Some(MobileIdentityType::Imeisv) => {
                self.as_imeisv().map(|imeisv| write!(f, "imeisv-{imeisv}"))
            }
            Some(MobileIdentityType::MacAddress) => self.as_mac_address().map(|address| {
                let suffix = if self.mauri() == Some(true) {
                    "-untrusted"
                } else {
                    ""
                };
                display::hyphenated(f, "mac", &address, suffix)
            }),
            Some(MobileIdentityType::Eui64) => self
                .as_eui64()
                .map(|identifier| display::hyphenated(f, "eui", &identifier, "")),
            Some(MobileIdentityType::NoIdentity) => Some(f.write_str("no identity")),
            _ => None,
        };
        match (shown, self.identity_type()) {
            (Some(shown), _) => shown,
            (None, Some(kind)) => display::unread_identity(f, identity_type_name(kind), octets),
            (None, None) => display::unread_identity(f, "identity", octets),
        }
    }
}

/// A list of tracking areas: `[208-93-000001, 208-93-000002]`.
impl fmt::Display for NasFGsTrackingAreaIdentityList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tais: Vec<Tai> = (self.entries().iter())
            .flat_map(TaiListEntry::tracking_area_identities)
            .collect();
        match tais.is_empty() {
            true => display::Octets(&self.value).fmt(f),
            false => display::List(&tais).fmt(f),
        }
    }
}

/// A tracking area identity: `208-93-000001`.
impl fmt::Display for NasFGsTrackingAreaIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tai() {
            Some(tai) => tai.fmt(f),
            None if self.is_deleted() => f.write_str("deleted"),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// An S-NSSAI: its SST, then `/` and its SD in hexadecimal when it has one,
/// `1/0000ff`, and the S-NSSAI of the HPLMN that it is mapped to.
impl fmt::Display for SNssaiContents {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s_nssai = |f: &mut fmt::Formatter<'_>, sst: u8, sd: Option<[u8; 3]>| match sd {
            Some(sd) => write!(f, "{sst}/{}", display::Hex(&sd)),
            None => write!(f, "{sst}"),
        };
        s_nssai(f, self.sst, self.sd)?;
        if let Some(mapped) = self.mapped_sst {
            f.write_str(" mapped to ")?;
            s_nssai(f, mapped, self.mapped_sd)?;
        }
        Ok(())
    }
}

/// An S-NSSAI: `1/0000ff`.
impl fmt::Display for NasSNssai {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.parse() {
            Some(s_nssai) => s_nssai.fmt(f),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// An NSSAI: `[1, 1/000001]`.
impl fmt::Display for NasNssai {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.try_parse_all() {
            Some(s_nssais) => display::List(&s_nssais).fmt(f),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// A rejected NSSAI: each S-NSSAI with the cause of its rejection,
/// `[1/000001 NotAvailableInRegistrationArea]`.
impl fmt::Display for NasRejectedNssai {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Rejected(RejectedNssaiCause, SNssaiContents);
        impl fmt::Display for Rejected {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{} {:?}", self.1, self.0)
            }
        }
        let entries: Vec<Rejected> = (self.entries().into_iter())
            .map(|(cause, s_nssai)| Rejected(cause, s_nssai))
            .collect();
        match entries.is_empty() {
            true => display::Octets(&self.value).fmt(f),
            false => display::List(&entries).fmt(f),
        }
    }
}

/// A T3512 value, as a UE reads it in an integrity protected message:
/// `54 min`.
impl fmt::Display for NasT3512Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display::timer(f, self.value(), &self.value)
    }
}

/// A DNN: `internet`.
impl fmt::Display for NasDnn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_string() {
            Some(name) => f.write_str(&name),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// A PDU address: `IPv4 10.45.0.2`.
impl fmt::Display for NasPduAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.ipv4(), self.ipv6_interface_id()) {
            (None, None) => display::Octets(&self.value).fmt(f),
            (ipv4, interface) => display::address(f, ipv4, interface),
        }
    }
}

/// A session-AMBR: `DL 100 Mbps UL 50 Mbps`.
impl fmt::Display for NasSessionAmbr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display::rates(f, self.downlink_kbps(), self.uplink_kbps(), &self.value)
    }
}

/// An EAP message by its code: `Request`, `Success`.
impl fmt::Display for NasEapMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.eap_code() {
            Some(code) => write!(f, "{code:?}"),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// An ABBA in hexadecimal: `0000`.
impl fmt::Display for NasAbba {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display::Hex(&self.value).fmt(f)
    }
}

/// The type of an identity as TS 24.501 names it.
fn identity_type_name(kind: MobileIdentityType) -> &'static str {
    match kind {
        MobileIdentityType::NoIdentity => "no identity",
        MobileIdentityType::Suci => "SUCI",
        MobileIdentityType::Guti => "5G-GUTI",
        MobileIdentityType::Imei => "IMEI",
        MobileIdentityType::STmsi => "5G-S-TMSI",
        MobileIdentityType::Imeisv => "IMEISV",
        MobileIdentityType::MacAddress => "MAC address",
        MobileIdentityType::Eui64 => "EUI-64",
        _ => "identity",
    }
}

/// A coded value by its name, or its code when it has none.
struct Coded<T>(Option<T>, u8);

impl<T: fmt::Debug> fmt::Display for Coded<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(value) => write!(f, "{value:?}"),
            None => write!(f, "{:#04x}", self.1),
        }
    }
}

/// The PDU sessions of a status IE, or of what it says of them.
struct Sessions(Vec<u8>);

impl fmt::Display for Sessions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display::List(&self.0).fmt(f)
    }
}

/// What a payload container carries: the 5GSM message or the UE policy
/// message that it decodes to, or its octets.
struct Payload<'a>(&'a NasPayloadContainerType, &'a NasPayloadContainer);

impl fmt::Display for Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(kind, container) = self;
        match kind.kind() {
            Some(PayloadContainerKind::N1SmInformation) => {
                if let Ok(message) = container.decode_as_n1_sm_message() {
                    return message.fmt(f);
                }
            }
            Some(PayloadContainerKind::UePolicy) => {
                if let Ok(message) = container.decode_as_ue_policy_message() {
                    return message.fmt(f);
                }
            }
            _ => {}
        }
        display::Octets(&container.value).fmt(f)
    }
}

/// What a NAS message container carries: the message that it decodes to,
/// or its octets, as those of a message that is ciphered.
struct Container<'a>(&'a NasMessageContainer);

impl fmt::Display for Container<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.decode_as_nas_message() {
            Ok(message) => message.fmt(f),
            Err(_) => display::Octets(&self.0.value).fmt(f),
        }
    }
}

/// A PDU session identity of a 5GMM message: `5`.
impl fmt::Display for NasPduSessionIdentity2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.pdu_session_id().fmt(f)
    }
}

// ============================================================================
// Individual 5GMM messages
// ============================================================================

impl fmt::Display for NasRegistrationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistrationRequest")?;
        let mut items = Items::new(f);
        let kind = &self.fgs_registration_type;
        items.item("type", Coded(kind.registration_type(), kind.value & 0x07))?;
        items.flag("FOR", kind.follow_on_request())?;
        items.item("ngKSI", self.ngksi)?;
        items.item("identity", &self.fgs_mobile_identity)?;
        items.some("UE-SecCap", self.ue_security_capability.as_ref())?;
        items.some("Requested-NSSAI", self.requested_nssai.as_ref())?;
        items.some("Last-TAI", self.last_visited_registered_tai.as_ref())?;
        let sessions = |status: &NasPduSessionStatus| Sessions(status.active_sessions());
        items.some(
            "PDU-sessions",
            self.pdu_session_status.as_ref().map(sessions),
        )?;
        let data = |status: &NasUplinkDataStatus| Sessions(status.sessions_with_data());
        items.some("Uplink-data", self.uplink_data_status.as_ref().map(data))?;
        items.some("Additional-GUTI", self.additional_guti.as_ref())?;
        items.some("Requested-T3512", self.requested_t3512_value.as_ref())?;
        items.some(
            "NAS-container",
            self.nas_message_container.as_ref().map(Container),
        )?;
        items.end()
    }
}

impl fmt::Display for NasRegistrationAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistrationAccept")?;
        let mut items = Items::new(f);
        let result = &self.fgs_registration_result;
        let value = Coded(result.result_value(), result.result_value_raw());
        items.item("result", value)?;
        items.flag("SMS allowed", result.sms_allowed())?;
        items.flag("emergency registered", result.emergency_registered())?;
        items.some("GUTI", self.fg_guti.as_ref())?;
        items.some("TAI-list", self.tai_list.as_ref())?;
        items.some("Allowed-NSSAI", self.allowed_nssai.as_ref())?;
        items.some("Rejected-NSSAI", self.rejected_nssai.as_ref())?;
        items.some("Configured-NSSAI", self.configured_nssai.as_ref())?;
        let sessions = |status: &NasPduSessionStatus| Sessions(status.active_sessions());
        items.some(
            "PDU-sessions",
            self.pdu_session_status.as_ref().map(sessions),
        )?;
        let failed = |result: &NasPduSessionReactivationResult| Sessions(result.failed_sessions());
        let failed = self.pdu_session_reactivation_result.as_ref().map(failed);
        items.some("Reactivation-failed", failed)?;
        items.some("T3512", self.t3512_value.as_ref())?;
        items.some("T3502", self.t3502_value.as_ref())?;
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasRegistrationReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RegistrationReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgmm_cause)?;
        items.some("T3346", self.t3346_value.as_ref())?;
        items.some("T3502", self.t3502_value.as_ref())?;
        items.some("Rejected-NSSAI", self.rejected_nssai.as_ref())?;
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

/// The access type of a DEREGISTRATION REQUEST.
fn deregistration_access(kind: &NasDeRegistrationType) -> Coded<DeregistrationAccessType> {
    Coded(kind.deregistration_access_type(), kind.access_type_raw())
}

impl fmt::Display for NasDeregistrationRequestUeOriginating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeregistrationRequestUeOriginating")?;
        let mut items = Items::new(f);
        let kind = &self.de_registration_type;
        items.flag("switch off", kind.switch_off())?;
        items.item("access", deregistration_access(kind))?;
        items.item("ngKSI", self.ngksi)?;
        items.item("identity", &self.fgs_mobile_identity)?;
        items.end()
    }
}

impl fmt::Display for NasDeregistrationRequestUeTerminated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeregistrationRequestUeTerminated")?;
        let mut items = Items::new(f);
        let kind = &self.de_registration_type;
        items.flag("re-registration required", kind.re_registration_required())?;
        items.item("access", deregistration_access(kind))?;
        items.some("cause", self.fgmm_cause.as_ref())?;
        items.some("T3346", self.t3346_value.as_ref())?;
        items.some("Rejected-NSSAI", self.rejected_nssai.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceRequest")?;
        let mut items = Items::new(f);
        let kind = &self.service_type;
        items.item("type", Coded(kind.service_type(), kind.service_type_raw()))?;
        items.item("ngKSI", self.ngksi)?;
        items.item("identity", &self.fg_s_tmsi)?;
        let data = |status: &NasUplinkDataStatus| Sessions(status.sessions_with_data());
        items.some("Uplink-data", self.uplink_data_status.as_ref().map(data))?;
        let sessions = |status: &NasPduSessionStatus| Sessions(status.active_sessions());
        items.some(
            "PDU-sessions",
            self.pdu_session_status.as_ref().map(sessions),
        )?;
        let allowed = |status: &NasAllowedPduSessionStatus| Sessions(status.allowed_sessions());
        let allowed = self.allowed_pdu_session_status.as_ref().map(allowed);
        items.some("Allowed-PDU-sessions", allowed)?;
        items.some(
            "NAS-container",
            self.nas_message_container.as_ref().map(Container),
        )?;
        items.end()
    }
}

impl fmt::Display for NasServiceReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgmm_cause)?;
        let sessions = |status: &NasPduSessionStatus| Sessions(status.active_sessions());
        items.some(
            "PDU-sessions",
            self.pdu_session_status.as_ref().map(sessions),
        )?;
        items.some("T3346", self.t3346_value.as_ref())?;
        items.some("T3448", self.t3448_value.as_ref())?;
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasServiceAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceAccept")?;
        let mut items = Items::new(f);
        let sessions = |status: &NasPduSessionStatus| Sessions(status.active_sessions());
        items.some(
            "PDU-sessions",
            self.pdu_session_status.as_ref().map(sessions),
        )?;
        let failed = |result: &NasPduSessionReactivationResult| Sessions(result.failed_sessions());
        let failed = self.pdu_session_reactivation_result.as_ref().map(failed);
        items.some("Reactivation-failed", failed)?;
        items.some("T3448", self.t3448_value.as_ref())?;
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasConfigurationUpdateCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigurationUpdateCommand")?;
        let mut items = Items::new(f);
        if let Some(indication) = &self.configuration_update_indication {
            items.flag("acknowledgement requested", indication.ack())?;
            items.flag("registration requested", indication.red())?;
        }
        items.some("GUTI", self.fg_guti.as_ref())?;
        items.some("TAI-list", self.tai_list.as_ref())?;
        items.some("Allowed-NSSAI", self.allowed_nssai.as_ref())?;
        items.some("Network-name", self.full_name_for_network.as_ref())?;
        items.some("Short-name", self.short_name_for_network.as_ref())?;
        items.some("Time-zone", self.local_time_zone.as_ref())?;
        items.some("Configured-NSSAI", self.configured_nssai.as_ref())?;
        items.some("Rejected-NSSAI", self.rejected_nssai.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasAuthenticationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationRequest")?;
        let mut items = Items::new(f);
        items.item("ngKSI", self.ngksi)?;
        items.item("ABBA", &self.abba)?;
        items.some("RAND", self.authentication_parameter_rand.as_ref())?;
        items.some("AUTN", self.authentication_parameter_autn.as_ref())?;
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasAuthenticationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationResponse")?;
        let mut items = Items::new(f);
        // RES* is the answer to the challenge: a key, which is not printed
        let res_star = self.authentication_response_parameter.as_ref();
        items.some("RES*", res_star.map(|res| display::Hidden(res.value.len())))?;
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasAuthenticationReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationReject")?;
        let mut items = Items::new(f);
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasAuthenticationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationFailure")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgmm_cause)?;
        items.some("AUTS", self.authentication_failure_parameter.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasAuthenticationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationResult")?;
        let mut items = Items::new(f);
        items.item("ngKSI", self.ngksi)?;
        items.item("EAP", &self.eap_message)?;
        items.some("ABBA", self.abba.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasIdentityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentityRequest")?;
        let mut items = Items::new(f);
        match self.identity_type.identity_type() {
            Some(kind) => items.item("type", identity_type_name(kind))?,
            None => items.item("type", Coded::<()>(None, self.identity_type.value & 0x07))?,
        }
        items.end()
    }
}

impl fmt::Display for NasIdentityResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentityResponse")?;
        let mut items = Items::new(f);
        items.item("identity", &self.mobile_identity)?;
        items.end()
    }
}

impl fmt::Display for NasSecurityModeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityModeCommand")?;
        let mut items = Items::new(f);
        items.item("algorithms", self.selected_nas_security_algorithms)?;
        items.item("ngKSI", self.ngksi)?;
        items.item(
            "Replayed-UE-SecCap",
            &self.replayed_ue_security_capabilities,
        )?;
        let requested = (self.imeisv_request.as_ref()).is_some_and(NasImeisvRequest::is_requested);
        items.flag("IMEISV requested", requested)?;
        let eps = self.selected_eps_nas_security_algorithms.as_ref();
        items.some("EPS-algorithms", eps)?;
        if let Some(information) = &self.additional_5g_security_information {
            items.flag("RINMR", information.rinmr())?;
            items.flag("HDP", information.hdp())?;
        }
        items.some("EAP", self.eap_message.as_ref())?;
        items.some("ABBA", self.abba.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasSecurityModeComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityModeComplete")?;
        let mut items = Items::new(f);
        items.some("identity", self.imeisv.as_ref())?;
        items.some("PEI", self.non_imeisv_pei.as_ref())?;
        items.some(
            "NAS-container",
            self.nas_message_container.as_ref().map(Container),
        )?;
        items.end()
    }
}

impl fmt::Display for NasSecurityModeReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityModeReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgmm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasFGmmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Status")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgmm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Notification")?;
        let mut items = Items::new(f);
        let access = &self.access_type;
        items.item(
            "access",
            Coded(access.access_type(), access.access_type_raw()),
        )?;
        items.end()
    }
}

impl fmt::Display for NasNotificationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NotificationResponse")?;
        let mut items = Items::new(f);
        let sessions = |status: &NasPduSessionStatus| Sessions(status.active_sessions());
        items.some(
            "PDU-sessions",
            self.pdu_session_status.as_ref().map(sessions),
        )?;
        items.end()
    }
}

impl fmt::Display for NasUlNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UlNasTransport")?;
        let mut items = Items::new(f);
        let kind = &self.payload_container_type;
        items.item("type", Coded(kind.kind(), kind.value))?;
        items.some("PSI", self.pdu_session_id.as_ref())?;
        items.some("old-PSI", self.old_pdu_session_id.as_ref())?;
        if let Some(request) = &self.request_type {
            let value = Coded(request.request_type(), request.request_type_raw());
            items.item("request", value)?;
        }
        items.some("S-NSSAI", self.s_nssai.as_ref())?;
        items.some("DNN", self.dnn.as_ref())?;
        items.item("payload", Payload(kind, &self.payload_container))?;
        items.end()
    }
}

impl fmt::Display for NasDlNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DlNasTransport")?;
        let mut items = Items::new(f);
        let kind = &self.payload_container_type;
        items.item("type", Coded(kind.kind(), kind.value))?;
        items.some("PSI", self.pdu_session_id.as_ref())?;
        items.some("cause", self.fgmm_cause.as_ref())?;
        items.some("Back-off", self.back_off_timer_value.as_ref())?;
        items.item("payload", Payload(kind, &self.payload_container))?;
        items.end()
    }
}

impl fmt::Display for NasControlPlaneServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlPlaneServiceRequest")?;
        let mut items = Items::new(f);
        let kind = &self.control_plane_service_type;
        let value = Coded(kind.service_type_strict(), kind.service_type_raw());
        items.item("type", value)?;
        items.item("ngKSI", self.ngksi)?;
        items.some("PSI", self.pdu_session_id.as_ref())?;
        if let (Some(kind), Some(container)) =
            (&self.payload_container_type, &self.payload_container)
        {
            items.item("payload", Payload(kind, container))?;
        }
        let ciot = self.ciot_small_data_container.as_ref();
        items.some(
            "CIoT-data",
            ciot.map(|container| display::Octets(&container.value)),
        )?;
        items.some(
            "NAS-container",
            self.nas_message_container.as_ref().map(Container),
        )?;
        items.end()
    }
}

impl fmt::Display for NasNetworkSliceSpecificAuthenticationCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkSliceSpecificAuthenticationCommand")?;
        let mut items = Items::new(f);
        items.item("S-NSSAI", &self.s_nssai)?;
        items.item("EAP", &self.eap_message)?;
        items.end()
    }
}

impl fmt::Display for NasNetworkSliceSpecificAuthenticationComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkSliceSpecificAuthenticationComplete")?;
        let mut items = Items::new(f);
        items.item("S-NSSAI", &self.s_nssai)?;
        items.item("EAP", &self.eap_message)?;
        items.end()
    }
}

impl fmt::Display for NasNetworkSliceSpecificAuthenticationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NetworkSliceSpecificAuthenticationResult")?;
        let mut items = Items::new(f);
        items.item("S-NSSAI", &self.s_nssai)?;
        items.item("EAP", &self.eap_message)?;
        items.end()
    }
}

// ============================================================================
// Individual 5GSM messages
// ============================================================================

/// A PDU session type by its name, or its code when it has none.
fn session_type(session_type: &NasPduSessionType) -> Coded<PduSessionTypeValue> {
    Coded(session_type.session_type(), session_type.session_type_raw())
}

/// An SSC mode by its number: `1`.
fn ssc_mode(mode: &NasSscMode) -> impl fmt::Display {
    match mode.mode() {
        Some(_) => Coded::<u8>(Some(mode.mode_raw()), mode.mode_raw()),
        None => Coded(None, mode.mode_raw()),
    }
}

/// The QoS rules of a message: how many, or their octets when they do not
/// read.
fn qos_rules(rules: &NasQosRules) -> impl fmt::Display + '_ {
    struct Rules<'a>(&'a NasQosRules);
    impl fmt::Display for Rules<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let parsed = self.0.parse_rules();
            match parsed.iter().all(|rule| rule.is_ok()) && !parsed.is_empty() {
                true => parsed.len().fmt(f),
                false => display::Octets(&self.0.value).fmt(f),
            }
        }
    }
    Rules(rules)
}

impl fmt::Display for NasPduSessionEstablishmentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionEstablishmentRequest")?;
        let mut items = Items::new(f);
        items.some("type", self.pdu_session_type.as_ref().map(session_type))?;
        items.some("SSC", self.ssc_mode.as_ref().map(ssc_mode))?;
        let always_on = self.always_on_pdu_session_requested.as_ref();
        let always_on = always_on.is_some_and(|requested| requested.value & 0x01 != 0);
        items.flag("always-on requested", always_on)?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionEstablishmentAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionEstablishmentAccept")?;
        let mut items = Items::new(f);
        items.item("type", session_type(&self.selected_pdu_session_type))?;
        items.item("SSC", ssc_mode(&self.selected_ssc_mode))?;
        items.item("QoS-rules", qos_rules(&self.authorized_qos_rules))?;
        items.item("S-AMBR", &self.session_ambr)?;
        items.some("cause", self.fgsm_cause.as_ref())?;
        items.some("PDU-address", self.pdu_address.as_ref())?;
        items.some("S-NSSAI", self.s_nssai.as_ref())?;
        items.some("DNN", self.dnn.as_ref())?;
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionEstablishmentReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionEstablishmentReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgsm_cause)?;
        items.some("Back-off", self.back_off_timer_value.as_ref())?;
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionAuthenticationCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionAuthenticationCommand")?;
        let mut items = Items::new(f);
        items.item("EAP", &self.eap_message)?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionAuthenticationComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionAuthenticationComplete")?;
        let mut items = Items::new(f);
        items.item("EAP", &self.eap_message)?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionAuthenticationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionAuthenticationResult")?;
        let mut items = Items::new(f);
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionModificationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionModificationRequest")?;
        let mut items = Items::new(f);
        items.some("cause", self.fgsm_cause.as_ref())?;
        items.some(
            "QoS-rules",
            self.requested_qos_rules.as_ref().map(qos_rules),
        )?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionModificationReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionModificationReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgsm_cause)?;
        items.some("Back-off", self.back_off_timer_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionModificationCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionModificationCommand")?;
        let mut items = Items::new(f);
        items.some("cause", self.fgsm_cause.as_ref())?;
        items.some("S-AMBR", self.session_ambr.as_ref())?;
        items.some(
            "QoS-rules",
            self.authorized_qos_rules.as_ref().map(qos_rules),
        )?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionModificationComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionModificationComplete")?;
        let mut items = Items::new(f);
        items.some("cause", self.fgsm_cause.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionModificationCommandReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionModificationCommandReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgsm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionReleaseRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionReleaseRequest")?;
        let mut items = Items::new(f);
        items.some("cause", self.fgsm_cause.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionReleaseReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionReleaseReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgsm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionReleaseCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionReleaseCommand")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgsm_cause)?;
        items.some("Back-off", self.back_off_timer_value.as_ref())?;
        if let Some(access) = &self.access_type {
            items.item(
                "access",
                Coded(access.access_type(), access.access_type_raw()),
            )?;
        }
        items.some("EAP", self.eap_message.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasPduSessionReleaseComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PduSessionReleaseComplete")?;
        let mut items = Items::new(f);
        items.some("cause", self.fgsm_cause.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasFGsmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Status")?;
        let mut items = Items::new(f);
        items.item("cause", self.fgsm_cause)?;
        items.end()
    }
}

macro_rules! simple_message_display {
    ($($name:ty => $label:literal),+ $(,)?) => {
        $(
            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str($label)
                }
            }
        )+
    };
}

simple_message_display!(
    NasRegistrationComplete => "RegistrationComplete",
    NasDeregistrationAcceptUeOriginating => "DeregistrationAcceptUeOriginating",
    NasDeregistrationAcceptUeTerminated => "DeregistrationAcceptUeTerminated",
    NasConfigurationUpdateComplete => "ConfigurationUpdateComplete",
    NasRelayKeyRequest => "RelayKeyRequest",
    NasRelayKeyAccept => "RelayKeyAccept",
    NasRelayKeyReject => "RelayKeyReject",
    NasRelayAuthenticationRequest => "RelayAuthenticationRequest",
    NasRelayAuthenticationResponse => "RelayAuthenticationResponse",
    NasServiceLevelAuthenticationCommand => "ServiceLevelAuthenticationCommand",
    NasServiceLevelAuthenticationComplete => "ServiceLevelAuthenticationComplete",
    NasRemoteUeReport => "RemoteUeReport",
    NasRemoteUeReportResponse => "RemoteUeReportResponse"
);

#[cfg(test)]
mod tests {
    use super::*;

    /// The protocol is said once, a cause by its number and its name, and
    /// a coded value by its name.
    #[test]
    fn a_status_and_a_result_display_as_their_words() {
        let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x03]).unwrap();
        assert_eq!(status.to_string(), "5GMM Status (cause=#3 (Illegal UE))");
        let status = Nas5gsMessage::decode(&[0x2e, 0x01, 0x01, 0xd6, 0x1a]).unwrap();
        assert_eq!(
            status.to_string(),
            "5GSM (PSI=1, PTI=1) Status (cause=#26 (Insufficient resources))"
        );
        let accept = Nas5gsMessage::decode(&[0x7e, 0x00, 0x42, 0x01, 0x01]).unwrap();
        assert_eq!(
            accept.to_string(),
            "5GMM RegistrationAccept (result=ThreeGppAccess)"
        );
        // A cause that the table does not have: its number
        let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x04]).unwrap();
        assert_eq!(status.to_string(), "5GMM Status (cause=#4)");
    }

    #[test]
    fn message_types_display_like_eps() {
        assert_eq!(
            Nas5gmmMessageType::RegistrationRequest.to_string(),
            "RegistrationRequest"
        );
        assert_eq!(
            Nas5gsmMessageType::PduSessionEstablishmentRequest.to_string(),
            "PduSessionEstablishmentRequest"
        );
    }

    /// A message shows what a log needs of it, each IE in the form of its
    /// type: the timers of a REJECT with their units, the TAIs and the
    /// S-NSSAIs of an ACCEPT, RAND and AUTN whole, AUTS whole, RES* never,
    /// the IMEISV request of a SECURITY MODE COMMAND, and the message that
    /// a container carries.
    #[test]
    fn each_ie_has_the_form_of_its_type() {
        let shown = |octets: &str| {
            Nas5gsMessage::decode(&hex::decode(octets).unwrap())
                .unwrap()
                .to_string()
        };
        assert_eq!(
            shown("7e0044165f012a"),
            "5GMM RegistrationReject (cause=#22 (Congestion), T3346=10 min)"
        );
        let plmn = Plmn::new("208", "93").unwrap();
        let guti = Guti::new(plmn, 0xca, 0x3fe, 0, 0x1122_3344).unwrap();
        let slices = [
            NasSNssai::from_sst_sd(1, None),
            NasSNssai::from_sst_sd(1, Some([0, 0, 0xff])),
        ];
        let result = NasFGsRegistrationResult::from_result(RegistrationResult::ThreeGppAccess);
        let accept = NasRegistrationAccept::new(result)
            .with_fg_guti(NasFGsMobileIdentity::from_guti(guti))
            .with_tai_list(NasFGsTrackingAreaIdentityList::from_plmn_tacs(&plmn, &[1, 2]).unwrap())
            .with_allowed_nssai(NasNssai::from_snssais(&slices).unwrap())
            .with_t3512_value(NasT3512Value::from_seconds(3_600).unwrap());
        assert_eq!(
            Nas5gsMessage::new_5gmm(accept).to_string(),
            "5GMM RegistrationAccept (result=ThreeGppAccess, GUTI=5g-guti-20893caff8011223344, \
             TAI-list=[208-93-000001, 208-93-000002], Allowed-NSSAI=[1, 1/0000ff], T3512=1 h)"
        );
        let ngksi = NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Native(0));
        let request = NasAuthenticationRequest::new(ngksi.unwrap(), NasAbba::new(vec![0, 0]))
            .with_authentication_parameter_rand(NasAuthenticationParameterRand::from_rand(
                [0x23; 16],
            ))
            .with_authentication_parameter_autn(NasAuthenticationParameterAutn::from_autn(
                [0x55; 16],
            ));
        assert_eq!(
            Nas5gsMessage::new_5gmm(request).to_string(),
            format!(
                "5GMM AuthenticationRequest (ngKSI=0, ABBA=0000, RAND={}, AUTN={})",
                "23".repeat(16),
                "55".repeat(16)
            )
        );
        let failure =
            NasAuthenticationFailure::new(NasFGmmCause::from_cause(GmmCause::SynchFailure))
                .with_authentication_failure_parameter(
                    NasAuthenticationFailureParameter::from_auts([0x5e; 14]),
                );
        assert_eq!(
            Nas5gsMessage::new_5gmm(failure).to_string(),
            format!(
                "5GMM AuthenticationFailure (cause=#21 (Synch failure), AUTS={})",
                "5e".repeat(14)
            )
        );
        let response = NasAuthenticationResponse::new().with_authentication_response_parameter(
            NasAuthenticationResponseParameter::from_res_star([0xab; 16]),
        );
        let response = Nas5gsMessage::new_5gmm(response).to_string();
        assert_eq!(
            response,
            "5GMM AuthenticationResponse (RES*=hidden (16 octets))"
        );
        assert!(!response.contains("abab"));
        // The EPS algorithms after a `+`, when it has one of them: the same
        // ones for ciphering and integrity too
        for (octets, shown) in [
            (
                vec![0xa0, 0x20, 0xa0, 0xa0],
                "EA0 EA2 / IA2 + EEA0 EEA2 / EIA0 EIA2",
            ),
            (vec![0xa0, 0x20, 0x00, 0x40], "EA0 EA2 / IA2 + none / EIA1"),
            (vec![0xa0, 0x20, 0x00, 0x00], "EA0 EA2 / IA2"),
        ] {
            assert_eq!(NasUeSecurityCapability::new(octets).to_string(), shown);
        }
        let capability = NasUeSecurityCapability::new(vec![0xa0, 0x20]);
        let algorithms = NasSecurityAlgorithms::from_algorithms(
            CipheringAlgorithm::NEA2,
            IntegrityAlgorithm::NIA2,
        );
        let command = NasSecurityModeCommand::new(algorithms, ngksi.unwrap(), capability)
            .with_imeisv_request(NasImeisvRequest::from_requested(true));
        assert_eq!(
            Nas5gsMessage::new_5gmm(command).to_string(),
            "5GMM SecurityModeCommand (algorithms=NEA2 NIA2, ngKSI=0, \
             Replayed-UE-SecCap=EA0 EA2 / IA2, IMEISV requested)"
        );
        // A 5GSM message in UL NAS TRANSPORT
        assert_eq!(
            shown("7e00670100062e0501c1ffff120581250908696e7465726e6574"),
            "5GMM UlNasTransport (type=N1SmInformation, PSI=5, request=InitialRequest, \
             DNN=internet, payload=5GSM (PSI=5, PTI=1) PduSessionEstablishmentRequest)"
        );
    }

    /// An identity is shown whole, in every message that shows one, as the
    /// service based interfaces write it, and the octets of one that does
    /// not read as an identity of its type.
    #[test]
    fn an_identity_is_shown_whole() {
        let identity = |identity: NasFGsMobileIdentity| identity.to_string();
        let plmn = Plmn::new("208", "93").unwrap();
        let routing_indicator = RoutingIndicator::new("123").unwrap();
        let null = ImsiSuci::null(plmn, routing_indicator, "1234567890").unwrap();
        let null = NasFGsMobileIdentity::from_suci(&Suci::Imsi(null));
        assert_eq!(identity(null.unwrap()), "suci-0-208-93-123-0-0-1234567890");
        let profile_a = ImsiSuci::concealed(
            plmn,
            routing_indicator,
            ProtectionScheme::PROFILE_A,
            1,
            vec![0xab; 45],
        );
        let profile_a = NasFGsMobileIdentity::from_suci(&Suci::Imsi(profile_a.unwrap()));
        assert_eq!(
            identity(profile_a.unwrap()),
            format!("suci-0-208-93-123-1-1-{}", "ab".repeat(45))
        );
        let nai =
            NasFGsMobileIdentity::from_suci_nai("type1.rid678.schid0.useriduser17@example.com");
        assert_eq!(
            identity(nai.unwrap()),
            "type1.rid678.schid0.useriduser17@example.com"
        );
        let imei = NasFGsMobileIdentity::from_imei("490154203237518").unwrap();
        assert_eq!(identity(imei), "imei-490154203237518");
        let imeisv = NasFGsMobileIdentity::from_imeisv("4901542032375181").unwrap();
        assert_eq!(identity(imeisv.clone()), "imeisv-4901542032375181");
        let mac = NasFGsMobileIdentity::from_mac_address([1, 2, 3, 4, 5, 6]);
        assert_eq!(identity(mac.clone()), "mac-01-02-03-04-05-06");
        let eui = NasFGsMobileIdentity::from_eui64([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(identity(eui), "eui-01-02-03-04-05-06-07-08");
        let guti = Guti::new(Plmn::new("999", "70").unwrap(), 1, 1, 0, 0xc000_0001).unwrap();
        assert_eq!(
            identity(NasFGsMobileIdentity::from_guti(guti)),
            "5g-guti-99970010040c0000001"
        );
        // An identity that does not read as one of its type: its octets
        assert_eq!(
            identity(NasFGsMobileIdentity::new(vec![0x03, 0x21])),
            "IMEI (0321)"
        );

        // In the messages that carry one
        let shown = |octets: &str| {
            Nas5gsMessage::decode(&hex::decode(octets).unwrap())
                .unwrap()
                .to_string()
        };
        assert_eq!(
            shown("7e004c100007f40040c0000001"),
            "5GMM ServiceRequest (type=Data, ngKSI=0, identity=5g-s-tmsi-0040c0000001)"
        );
        let complete = NasSecurityModeComplete::new()
            .with_imeisv(imeisv)
            .with_non_imeisv_pei(mac);
        assert_eq!(
            Nas5gsMessage::new_5gmm(complete).to_string(),
            "5GMM SecurityModeComplete (identity=imeisv-4901542032375181, \
             PEI=mac-01-02-03-04-05-06)"
        );
    }

    #[test]
    fn test_upds_display() {
        let envelope = NasUpdsEnvelope::new_with_pti(
            NasUpdsProcedureTransactionIdentity::from_network_initiated(0x80).unwrap(),
            NasUpdsMessage::UePolicyProvisioningReject(NasUePolicyProvisioningReject::new(vec![
                0x01, 0x02,
            ])),
        );
        assert_eq!(
            envelope.to_string(),
            "UPDS (PTI=0x80 (network-initiated), type=0x06) UePolicyProvisioningReject \
             (payload=0102)"
        );
    }
}
