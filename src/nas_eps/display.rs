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

//! The `Display` of the EPS messages and of their IEs.
//!
//! The forms are those of 5GS ([`crate::nas_5gs::display`]): a cause as
//! `#22 (Congestion)`, a timer with its unit, RAND, AUTN and AUTS whole, RES
//! by its length alone, an identity as the service based interfaces write
//! it, `4g-guti-...` or `imsi-...`, a TAI as `208-93-0001`, and the ESM
//! message that a container carries.
//!
//! ```rust
//! use oxirush_nas::nas_eps::NasEpsMessage;
//!
//! let reject = NasEpsMessage::decode(&[0x07, 0x44, 0x16, 0x5f, 0x01, 0x2a]).unwrap();
//! let shown = "EMM AttachReject (cause=#22 (Congestion), T3346=10 min)";
//! assert_eq!(reject.to_string(), shown);
//! ```

use crate::common::display::{self, Items};
use crate::nas_eps::ie::*;
use crate::nas_eps::message_types::*;
use crate::nas_eps::messages::*;
use crate::nas_eps::types::*;
use crate::prelude::*;
use core::fmt;

impl fmt::Display for NasEmmMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for NasEsmMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for NasEmmMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AttachRequest(message) => fmt::Display::fmt(message, f),
            Self::AttachAccept(message) => fmt::Display::fmt(message, f),
            Self::AttachComplete(message) => fmt::Display::fmt(message, f),
            Self::AttachReject(message) => fmt::Display::fmt(message, f),
            Self::DetachRequestUeOriginating(message) => fmt::Display::fmt(message, f),
            Self::DetachRequestUeTerminated(message) => fmt::Display::fmt(message, f),
            Self::AuthenticationRequest(message) => fmt::Display::fmt(message, f),
            Self::AuthenticationResponse(message) => fmt::Display::fmt(message, f),
            Self::AuthenticationReject(message) => fmt::Display::fmt(message, f),
            Self::AuthenticationFailure(message) => fmt::Display::fmt(message, f),
            Self::CsServiceNotification(message) => fmt::Display::fmt(message, f),
            Self::DetachAccept(message) => fmt::Display::fmt(message, f),
            Self::DownlinkNasTransport(message) => fmt::Display::fmt(message, f),
            Self::EmmInformation(message) => fmt::Display::fmt(message, f),
            Self::ExtendedServiceRequest(message) => fmt::Display::fmt(message, f),
            Self::GutiReallocationCommand(message) => fmt::Display::fmt(message, f),
            Self::GutiReallocationComplete(message) => fmt::Display::fmt(message, f),
            Self::SecurityModeCommand(message) => fmt::Display::fmt(message, f),
            Self::SecurityModeReject(message) => fmt::Display::fmt(message, f),
            Self::ServiceReject(message) => fmt::Display::fmt(message, f),
            Self::TrackingAreaUpdateRequest(message) => fmt::Display::fmt(message, f),
            Self::TrackingAreaUpdateAccept(message) => fmt::Display::fmt(message, f),
            Self::TrackingAreaUpdateComplete(message) => fmt::Display::fmt(message, f),
            Self::TrackingAreaUpdateReject(message) => fmt::Display::fmt(message, f),
            Self::IdentityResponse(message) => fmt::Display::fmt(message, f),
            Self::IdentityRequest(message) => fmt::Display::fmt(message, f),
            Self::SecurityModeComplete(message) => fmt::Display::fmt(message, f),
            Self::ControlPlaneServiceRequest(message) => fmt::Display::fmt(message, f),
            Self::UplinkNasTransport(message) => fmt::Display::fmt(message, f),
            Self::DownlinkGenericNasTransport(message) => fmt::Display::fmt(message, f),
            Self::UplinkGenericNasTransport(message) => fmt::Display::fmt(message, f),
            Self::ServiceAccept(message) => fmt::Display::fmt(message, f),
            Self::EmmStatus(message) => fmt::Display::fmt(message, f),
        }
    }
}

impl fmt::Display for NasEsmMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PdnConnectivityRequest(message) => fmt::Display::fmt(message, f),
            Self::PdnConnectivityReject(message) => fmt::Display::fmt(message, f),
            Self::ActivateDefaultEpsBearerContextRequest(message) => fmt::Display::fmt(message, f),
            Self::ActivateDefaultEpsBearerContextAccept(message) => fmt::Display::fmt(message, f),
            Self::ActivateDefaultEpsBearerContextReject(message) => fmt::Display::fmt(message, f),
            Self::ActivateDedicatedEpsBearerContextRequest(message) => {
                fmt::Display::fmt(message, f)
            }
            Self::ActivateDedicatedEpsBearerContextAccept(message) => fmt::Display::fmt(message, f),
            Self::ActivateDedicatedEpsBearerContextReject(message) => fmt::Display::fmt(message, f),
            Self::DeactivateEpsBearerContextRequest(message) => fmt::Display::fmt(message, f),
            Self::DeactivateEpsBearerContextAccept(message) => fmt::Display::fmt(message, f),
            Self::ModifyEpsBearerContextRequest(message) => fmt::Display::fmt(message, f),
            Self::ModifyEpsBearerContextAccept(message) => fmt::Display::fmt(message, f),
            Self::ModifyEpsBearerContextReject(message) => fmt::Display::fmt(message, f),
            Self::EsmInformationResponse(message) => fmt::Display::fmt(message, f),
            Self::EsmInformationRequest(message) => fmt::Display::fmt(message, f),
            Self::EsmDummyMessage(message) => fmt::Display::fmt(message, f),
            Self::PdnDisconnectRequest(message) => fmt::Display::fmt(message, f),
            Self::PdnDisconnectReject(message) => fmt::Display::fmt(message, f),
            Self::BearerResourceAllocationRequest(message) => fmt::Display::fmt(message, f),
            Self::BearerResourceAllocationReject(message) => fmt::Display::fmt(message, f),
            Self::BearerResourceModificationRequest(message) => fmt::Display::fmt(message, f),
            Self::BearerResourceModificationReject(message) => fmt::Display::fmt(message, f),
            Self::Notification(message) => fmt::Display::fmt(message, f),
            Self::RemoteUeReport(message) => fmt::Display::fmt(message, f),
            Self::RemoteUeReportResponse(message) => fmt::Display::fmt(message, f),
            Self::EsmDataTransport(message) => fmt::Display::fmt(message, f),
            Self::EsmStatus(message) => fmt::Display::fmt(message, f),
        }
    }
}

impl fmt::Display for NasEpsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Emm(_, message) => write!(f, "EMM {message}"),
            Self::Esm(header, message) => write!(
                f,
                "ESM (EBI={}, PTI={}) {message}",
                header.eps_bearer_identity, header.procedure_transaction_identity
            ),
            Self::SecurityProtected(header, inner) => write!(
                f,
                "SecurityProtected (SHT={:?}, MAC={:#010x}, SN={}) {inner}",
                header.security_header_type,
                header.message_authentication_code,
                header.sequence_number
            ),
            Self::ServiceRequest(message) => write!(f, "EMM {message}"),
            Self::EmmTransport(message) => write!(f, "EMM {message}"),
            Self::Opaque(data) => write!(f, "Opaque ({} octets)", data.len()),
        }
    }
}

// ============================================================================
// IEs
// ============================================================================

/// An EMM cause by its number and its name: `#22 (Congestion)`.
impl fmt::Display for NasEmmCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display::cause(f, self.value, self.cause().map(EmmCause::description))
    }
}

/// An ESM cause by its number and its name: `#26 (Insufficient resources)`.
impl fmt::Display for NasEsmCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display::cause(f, self.value, self.cause().map(EsmCause::description))
    }
}

/// A NAS key set identifier: `0`, `mapped 3` or `no key`.
impl fmt::Display for NasKeySetIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.key_set_identifier().fmt(f)
    }
}

/// The selected algorithms: `EEA2 EIA2`.
impl fmt::Display for NasSecurityAlgorithms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ciphering = Coded(self.ciphering(), self.ciphering_raw());
        let integrity = Coded(self.integrity(), self.integrity_raw());
        write!(f, "{ciphering} {integrity}")
    }
}

/// The EPS algorithms of a UE network capability: `EEA0 EEA2 / EIA2`.
impl fmt::Display for NasUeNetworkCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let eea = |number| self.supports_eea(number);
        let eia = |number| self.supports_eia(number);
        display::algorithms(f, ("EEA", "EIA"), eea, eia)
    }
}

/// The EPS algorithms of a UE security capability: `EEA0 EEA2 / EIA2`.
impl fmt::Display for NasUeSecurityCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let eea = |number| self.supports_eea(number);
        let eia = |number| self.supports_eia(number);
        display::algorithms(f, ("EEA", "EIA"), eea, eia)
    }
}

/// An EPS mobile identity, whole, as the service based interfaces write
/// it: `4g-guti-...`, `imsi-...` or `imei-...`. One whose octets do not
/// read as its type shows them.
impl fmt::Display for NasEpsMobileIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(guti) = self.as_guti() {
            guti.fmt(f)
        } else if let Some(imsi) = self.as_imsi() {
            write!(f, "imsi-{imsi}")
        } else if let Some(imei) = self.as_imei() {
            write!(f, "imei-{imei}")
        } else {
            let kind = match self.identity_type() {
                Some(MobileIdentityType::Guti) => "GUTI",
                Some(MobileIdentityType::Imsi) => "IMSI",
                Some(MobileIdentityType::Imei) => "IMEI",
                _ => "identity",
            };
            display::unread_identity(f, kind, &self.value)
        }
    }
}

/// A mobile identity of TS 24.008, whole: `imsi-...`, `imei-...`,
/// `imeisv-...`, `tmsi-c0000001` or `no identity`. One of another type, as
/// a TMGI, shows its octets.
impl fmt::Display for NasMobileIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(imsi) = self.as_imsi() {
            write!(f, "imsi-{imsi}")
        } else if let Some(imei) = self.as_imei() {
            write!(f, "imei-{imei}")
        } else if let Some(imeisv) = self.as_imeisv() {
            write!(f, "imeisv-{imeisv}")
        } else if let Some(tmsi) = self.as_tmsi() {
            write!(f, "tmsi-{tmsi:08x}")
        } else if self.is_no_identity() {
            f.write_str("no identity")
        } else {
            let kind = match self.identity_type_raw() {
                Some(1) => "IMSI",
                Some(2) => "IMEI",
                Some(3) => "IMEISV",
                Some(4) => "TMSI",
                Some(5) => "TMGI",
                _ => "identity",
            };
            display::unread_identity(f, kind, &self.value)
        }
    }
}

/// A list of tracking areas: `[208-93-0001, 208-93-0002]`.
impl fmt::Display for NasTrackingAreaIdentityList {
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

/// A tracking area identity: `208-93-0001`.
impl fmt::Display for NasTrackingAreaIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tai() {
            Some(tai) => tai.fmt(f),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// A T3412 value: `9 min`, `deactivated`.
impl fmt::Display for NasT3412Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value().fmt(f)
    }
}

/// A T3412 extended value, as a UE reads it in an integrity protected
/// message: `54 min`, `deactivated`, or `not included` for unit 111.
impl fmt::Display for NasT3412ExtendedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value_for_ue(true) {
            Some(T3412ExtendedValue::Seconds(seconds)) => display::Duration(seconds).fmt(f),
            Some(T3412ExtendedValue::Deactivated) => f.write_str("deactivated"),
            Some(T3412ExtendedValue::NotIncluded) => f.write_str("not included"),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// An access point name: `internet`.
impl fmt::Display for NasAccessPointName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_string() {
            Some(name) => f.write_str(&name),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// A PDN address: `IPv4 10.0.0.1`, `non-IP`, `Ethernet`.
impl fmt::Display for NasPdnAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pdn_address() {
            Some(PdnAddress::Ipv4(ipv4)) => display::address(f, Some(ipv4), None),
            Some(PdnAddress::Ipv6InterfaceId(identifier)) => {
                display::address(f, None, Some(identifier))
            }
            Some(PdnAddress::Ipv4v6 {
                ipv6_interface_id,
                ipv4,
            }) => display::address(f, Some(ipv4), Some(ipv6_interface_id)),
            Some(PdnAddress::NonIp) => f.write_str("non-IP"),
            Some(PdnAddress::Ethernet) => f.write_str("Ethernet"),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// An APN-AMBR: `DL 100 Mbps UL 50 Mbps`.
impl fmt::Display for NasApnAggregateMaximumBitRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        display::rates(f, self.downlink_kbps(), self.uplink_kbps(), &self.value)
    }
}

/// An EPS QoS by its QCI: `QCI 9`.
impl fmt::Display for NasEpsQualityOfService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.qos() {
            Some(qos) => write!(f, "QCI {}", qos.qci),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// A traffic flow template: its operation and its packet filters,
/// `Create, 2 filters`.
impl fmt::Display for NasTrafficFlowTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tft() {
            Some(tft) => tft_shown(f, &tft),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

/// A traffic flow aggregate: its operation and its packet filters.
impl fmt::Display for NasTrafficFlowAggregateDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.tft() {
            Some(tft) => tft_shown(f, &tft),
            None => display::Octets(&self.value).fmt(f),
        }
    }
}

fn tft_shown(f: &mut fmt::Formatter<'_>, tft: &Tft) -> fmt::Result {
    match tft.packet_filters.len() {
        0 => write!(f, "{:?}", tft.operation),
        1 => write!(f, "{:?} 1 filter", tft.operation),
        filters => write!(f, "{:?} {filters} filters", tft.operation),
    }
}

/// A linked EPS bearer identity: `5`.
impl fmt::Display for NasLinkedEpsBearerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ebi() {
            Some(ebi) => ebi.fmt(f),
            None => write!(f, "{:#04x}", self.bearer_identity()),
        }
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

/// What an ESM message container carries: the ESM message, or its octets.
struct Esm<'a>(&'a NasEsmMessageContainer);

impl fmt::Display for Esm<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.decode_as_esm_message() {
            Ok(message) => message.fmt(f),
            Err(_) => display::Octets(&self.0.value).fmt(f),
        }
    }
}

/// What a replayed NAS message container carries: the ATTACH REQUEST or
/// the TRACKING AREA UPDATE REQUEST, or its octets.
struct Replayed<'a>(&'a NasReplayedNasMessageContainer);

impl fmt::Display for Replayed<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0.decode_as_emm_message() {
            Ok(message) => message.fmt(f),
            Err(_) => display::Octets(&self.0.value).fmt(f),
        }
    }
}

// ============================================================================
// EMM messages
// ============================================================================

impl fmt::Display for NasAttachRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttachRequest")?;
        let mut items = Items::new(f);
        let kind = &self.eps_attach_type;
        items.item(
            "type",
            Coded(kind.attach_type_strict(), kind.attach_type_raw()),
        )?;
        items.item("KSI", self.nas_key_set_identifier)?;
        items.item("identity", &self.eps_mobile_identity)?;
        items.item("UE-NetCap", &self.ue_network_capability)?;
        items.some("Last-TAI", self.last_visited_registered_tai.as_ref())?;
        items.some("Additional-GUTI", self.additional_guti.as_ref())?;
        items.item("ESM-container", Esm(&self.esm_message_container))?;
        items.end()
    }
}

impl fmt::Display for NasAttachAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttachAccept")?;
        let mut items = Items::new(f);
        let result = &self.eps_attach_result;
        items.item(
            "result",
            Coded(result.attach_result(), result.attach_result_raw()),
        )?;
        items.item("T3412", self.t3412_value)?;
        items.item("TAI-list", &self.tai_list)?;
        items.some("GUTI", self.guti.as_ref())?;
        items.some("cause", self.emm_cause.as_ref())?;
        items.some("T3402", self.t3402_value.as_ref())?;
        items.some("T3423", self.t3423_value.as_ref())?;
        items.some("T3412-extended", self.t3412_extended_value.as_ref())?;
        items.item("ESM-container", Esm(&self.esm_message_container))?;
        items.end()
    }
}

impl fmt::Display for NasAttachComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttachComplete")?;
        let mut items = Items::new(f);
        items.item("ESM-container", Esm(&self.esm_message_container))?;
        items.end()
    }
}

impl fmt::Display for NasAttachReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AttachReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.emm_cause)?;
        items.some("T3346", self.t3346_value.as_ref())?;
        items.some("T3402", self.t3402_value.as_ref())?;
        items.some(
            "ESM-container",
            self.esm_message_container.as_ref().map(Esm),
        )?;
        items.end()
    }
}

impl fmt::Display for NasDetachRequestUeOriginating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DetachRequestUeOriginating")?;
        let mut items = Items::new(f);
        let kind = &self.detach_type;
        items.item("type", format_args!("{:?}", kind.ue_detach_kind()))?;
        items.flag("switch off", kind.is_switch_off())?;
        items.item("KSI", self.nas_key_set_identifier)?;
        items.item("identity", &self.eps_mobile_identity)?;
        items.end()
    }
}

impl fmt::Display for NasDetachRequestUeTerminated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DetachRequestUeTerminated")?;
        let mut items = Items::new(f);
        let kind = &self.detach_type;
        items.item("type", format_args!("{:?}", kind.network_detach_kind()))?;
        items.some("cause", self.emm_cause.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasAuthenticationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationRequest")?;
        let mut items = Items::new(f);
        items.item("KSI", self.nas_key_set_identifier_asme)?;
        items.item("RAND", &self.authentication_parameter_rand)?;
        items.item("AUTN", &self.authentication_parameter_autn)?;
        items.end()
    }
}

impl fmt::Display for NasAuthenticationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationResponse")?;
        let mut items = Items::new(f);
        // RES is the answer to the challenge: a key, which is not printed
        let res = &self.authentication_response_parameter;
        items.item("RES", display::Hidden(res.value.len()))?;
        items.end()
    }
}

impl fmt::Display for NasAuthenticationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticationFailure")?;
        let mut items = Items::new(f);
        items.item("cause", self.emm_cause)?;
        items.some("AUTS", self.authentication_failure_parameter.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasCsServiceNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsServiceNotification")?;
        let mut items = Items::new(f);
        let paging = match self.paging_identity.paging_identity() {
            PagingIdentityValue::Imsi => "IMSI",
            PagingIdentityValue::Tmsi => "TMSI",
        };
        items.item("paging", paging)?;
        items.end()
    }
}

impl fmt::Display for NasSecurityModeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityModeCommand")?;
        let mut items = Items::new(f);
        items.item("algorithms", self.selected_nas_security_algorithms)?;
        items.item("KSI", self.nas_key_set_identifier)?;
        items.item(
            "Replayed-UE-SecCap",
            &self.replayed_ue_security_capabilities,
        )?;
        let requested = (self.imeisv_request.as_ref()).is_some_and(NasImeisvRequest::is_requested);
        items.flag("IMEISV requested", requested)?;
        items.flag("HashMME", self.hash_mme.is_some())?;
        items.end()
    }
}

impl fmt::Display for NasSecurityModeComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityModeComplete")?;
        let mut items = Items::new(f);
        items.some("identity", self.imeisv.as_ref())?;
        let replayed = self.replayed_nas_message_container.as_ref();
        items.some("Replayed-NAS", replayed.map(Replayed))?;
        items.end()
    }
}

impl fmt::Display for NasSecurityModeReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecurityModeReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.emm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasEmmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Status")?;
        let mut items = Items::new(f);
        items.item("cause", self.emm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasEmmInformation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Information")?;
        let mut items = Items::new(f);
        items.some("Network-name", self.full_name_for_network.as_ref())?;
        items.some("Short-name", self.short_name_for_network.as_ref())?;
        items.some("Time-zone", self.local_time_zone.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasIdentityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IdentityRequest")?;
        let mut items = Items::new(f);
        let kind = &self.identity_type;
        let name = match kind.identity_type_strict() {
            Some(IdentityType::Imsi) => "IMSI",
            Some(IdentityType::Imei) => "IMEI",
            Some(IdentityType::Imeisv) => "IMEISV",
            Some(IdentityType::Tmsi) => "TMSI",
            Some(_) | None => "",
        };
        match name {
            "" => items.item("type", format_args!("{:#04x}", kind.identity_type_raw()))?,
            name => items.item("type", name)?,
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

impl fmt::Display for NasControlPlaneServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ControlPlaneServiceRequest")?;
        let mut items = Items::new(f);
        let kind = &self.control_plane_service_type;
        items.item(
            "type",
            Coded(kind.service_type_strict(), kind.service_type_raw()),
        )?;
        items.flag("active", kind.is_active())?;
        items.item("KSI", self.nas_key_set_identifier)?;
        items.some(
            "ESM-container",
            self.esm_message_container.as_ref().map(Esm),
        )?;
        let container = self.nas_message_container.as_ref();
        items.some(
            "NAS-container",
            container.map(|container| display::Octets(&container.value)),
        )?;
        items.some("Bearers", self.eps_bearer_context_status.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasServiceReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.emm_cause)?;
        items.some("T3442", self.t3442_value.as_ref())?;
        items.some("T3346", self.t3346_value.as_ref())?;
        items.some("T3448", self.t3448_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasServiceAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceAccept")?;
        let mut items = Items::new(f);
        items.some("Bearers", self.eps_bearer_context_status.as_ref())?;
        items.some("T3448", self.t3448_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasTrackingAreaUpdateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrackingAreaUpdateRequest")?;
        let mut items = Items::new(f);
        let kind = &self.eps_update_type;
        items.item("type", Coded(kind.update_type(), kind.update_type_raw()))?;
        items.flag("active", kind.is_active())?;
        items.item("KSI", self.nas_key_set_identifier)?;
        items.item("old-GUTI", &self.old_guti)?;
        items.some("UE-NetCap", self.ue_network_capability.as_ref())?;
        items.some("Last-TAI", self.last_visited_registered_tai.as_ref())?;
        items.some("Bearers", self.eps_bearer_context_status.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasTrackingAreaUpdateAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrackingAreaUpdateAccept")?;
        let mut items = Items::new(f);
        let result = &self.eps_update_result;
        items.item(
            "result",
            Coded(result.update_result(), result.update_result_raw()),
        )?;
        items.some("T3412", self.t3412_value.as_ref())?;
        items.some("GUTI", self.guti.as_ref())?;
        items.some("TAI-list", self.tai_list.as_ref())?;
        items.some("Bearers", self.eps_bearer_context_status.as_ref())?;
        items.some("cause", self.emm_cause.as_ref())?;
        items.some("T3402", self.t3402_value.as_ref())?;
        items.some("T3423", self.t3423_value.as_ref())?;
        items.some("T3412-extended", self.t3412_extended_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasTrackingAreaUpdateReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrackingAreaUpdateReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.emm_cause)?;
        items.some("T3346", self.t3346_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasExtendedServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExtendedServiceRequest")?;
        let mut items = Items::new(f);
        let kind = &self.service_type;
        items.item("type", Coded(kind.service_type(), kind.service_type_raw()))?;
        items.item("KSI", self.nas_key_set_identifier)?;
        items.item("identity", &self.m_tmsi)?;
        items.some("Bearers", self.eps_bearer_context_status.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasGutiReallocationCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GutiReallocationCommand")?;
        let mut items = Items::new(f);
        items.item("GUTI", &self.guti)?;
        items.some("TAI-list", self.tai_list.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasDownlinkNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DownlinkNasTransport")?;
        let mut items = Items::new(f);
        let container = &self.nas_message_container.value;
        items.item("container", display::Octets(container))?;
        items.end()
    }
}

impl fmt::Display for NasUplinkNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UplinkNasTransport")?;
        let mut items = Items::new(f);
        let container = &self.nas_message_container.value;
        items.item("container", display::Octets(container))?;
        items.end()
    }
}

impl fmt::Display for NasDownlinkGenericNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DownlinkGenericNasTransport")?;
        let mut items = Items::new(f);
        let kind = &self.generic_message_container_type;
        items.item(
            "type",
            Coded(kind.container_type(), kind.container_type_raw()),
        )?;
        let container = &self.generic_message_container.value;
        items.item("container", display::Octets(container))?;
        items.end()
    }
}

impl fmt::Display for NasUplinkGenericNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UplinkGenericNasTransport")?;
        let mut items = Items::new(f);
        let kind = &self.generic_message_container_type;
        items.item(
            "type",
            Coded(kind.container_type(), kind.container_type_raw()),
        )?;
        let container = &self.generic_message_container.value;
        items.item("container", display::Octets(container))?;
        items.end()
    }
}

impl fmt::Display for NasServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceRequest")?;
        let mut items = Items::new(f);
        items.item("KSI", self.ksi_and_sequence_number >> 5)?;
        items.item("SN", self.ksi_and_sequence_number & 0x1f)?;
        let mac = self.message_authentication_code;
        items.item("short-MAC", format_args!("{mac:#06x}"))?;
        items.end()
    }
}

impl fmt::Display for NasEmmTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Transport")?;
        let mut items = Items::new(f);
        items.item("SN", self.security_header.sequence_number)?;
        match &self.protected_payload {
            Some(opaque) => items.item("protected", display::Octets(opaque))?,
            None => {
                let container = self.data_container.as_deref().unwrap_or_default();
                items.item("container", display::Octets(container))?
            }
        }
        items.end()
    }
}

// ============================================================================
// ESM messages
// ============================================================================

impl fmt::Display for NasPdnConnectivityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PdnConnectivityRequest")?;
        let mut items = Items::new(f);
        let request = &self.request_type;
        items.item(
            "request",
            Coded(request.request_type(), request.request_type_raw()),
        )?;
        let pdn = &self.pdn_type;
        items.item("PDN", Coded(pdn.pdn_type(), pdn.pdn_type_raw()))?;
        let transfer = self.esm_information_transfer_flag.as_ref();
        items.flag(
            "ESM information transfer",
            transfer.is_some_and(|flag| flag.is_required()),
        )?;
        items.some("APN", self.access_point_name.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasPdnConnectivityReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PdnConnectivityReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.some("Back-off", self.back_off_timer_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasActivateDefaultEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActivateDefaultEpsBearerContextRequest")?;
        let mut items = Items::new(f);
        items.item("QoS", &self.eps_qos)?;
        items.item("APN", &self.access_point_name)?;
        items.item("PDN-address", &self.pdn_address)?;
        items.some("APN-AMBR", self.apn_ambr.as_ref())?;
        items.some("cause", self.esm_cause.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasActivateDefaultEpsBearerContextReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActivateDefaultEpsBearerContextReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasActivateDedicatedEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActivateDedicatedEpsBearerContextRequest")?;
        let mut items = Items::new(f);
        items.item("linked-EBI", self.linked_eps_bearer_identity)?;
        items.item("QoS", &self.eps_qos)?;
        items.item("TFT", &self.tft)?;
        items.end()
    }
}

impl fmt::Display for NasActivateDedicatedEpsBearerContextReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ActivateDedicatedEpsBearerContextReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasDeactivateEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeactivateEpsBearerContextRequest")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.some("T3396", self.t3396_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasModifyEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ModifyEpsBearerContextRequest")?;
        let mut items = Items::new(f);
        items.some("QoS", self.new_eps_qos.as_ref())?;
        items.some("TFT", self.tft.as_ref())?;
        items.some("APN-AMBR", self.apn_ambr.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasModifyEpsBearerContextReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ModifyEpsBearerContextReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasEsmInformationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InformationResponse")?;
        let mut items = Items::new(f);
        items.some("APN", self.access_point_name.as_ref())?;
        let options = self.protocol_configuration_options.is_some()
            || self.extended_protocol_configuration_options.is_some();
        items.flag("PCO", options)?;
        items.end()
    }
}

impl fmt::Display for NasPdnDisconnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PdnDisconnectRequest")?;
        let mut items = Items::new(f);
        items.item("linked-EBI", self.linked_eps_bearer_identity)?;
        items.end()
    }
}

impl fmt::Display for NasPdnDisconnectReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PdnDisconnectReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasBearerResourceAllocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerResourceAllocationRequest")?;
        let mut items = Items::new(f);
        items.item("linked-EBI", self.linked_eps_bearer_identity)?;
        items.item("TFA", &self.traffic_flow_aggregate)?;
        items.item("QoS", &self.required_traffic_flow_qos)?;
        items.end()
    }
}

impl fmt::Display for NasBearerResourceAllocationReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerResourceAllocationReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.some("Back-off", self.back_off_timer_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasBearerResourceModificationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerResourceModificationRequest")?;
        let mut items = Items::new(f);
        items.item("EBI", self.eps_bearer_identity_for_packet_filter)?;
        items.item("TFA", &self.traffic_flow_aggregate)?;
        items.some("QoS", self.required_traffic_flow_qos.as_ref())?;
        items.some("cause", self.esm_cause.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasBearerResourceModificationReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerResourceModificationReject")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.some("Back-off", self.back_off_timer_value.as_ref())?;
        items.end()
    }
}

impl fmt::Display for NasNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Notification")?;
        let mut items = Items::new(f);
        let indicator = &self.notification_indicator;
        match (indicator.indicator(), indicator.indicator_raw()) {
            (Some(value), _) => items.item("indicator", format_args!("{value:?}"))?,
            (None, Some(raw)) => items.item("indicator", format_args!("{raw:#04x}"))?,
            (None, None) => items.item("indicator", "empty")?,
        }
        items.end()
    }
}

impl fmt::Display for NasEsmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Status")?;
        let mut items = Items::new(f);
        items.item("cause", self.esm_cause)?;
        items.end()
    }
}

impl fmt::Display for NasEsmDataTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataTransport")?;
        let mut items = Items::new(f);
        let container = &self.user_data_container.value;
        items.item("container", display::Octets(container))?;
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
    NasAuthenticationReject => "AuthenticationReject",
    NasDetachAccept => "DetachAccept",
    NasGutiReallocationComplete => "GutiReallocationComplete",
    NasTrackingAreaUpdateComplete => "TrackingAreaUpdateComplete",
    NasActivateDedicatedEpsBearerContextAccept => "ActivateDedicatedEpsBearerContextAccept",
    NasActivateDefaultEpsBearerContextAccept => "ActivateDefaultEpsBearerContextAccept",
    NasDeactivateEpsBearerContextAccept => "DeactivateEpsBearerContextAccept",
    NasEsmDummyMessage => "DummyMessage",
    NasEsmInformationRequest => "InformationRequest",
    NasModifyEpsBearerContextAccept => "ModifyEpsBearerContextAccept",
    NasRemoteUeReport => "RemoteUeReport",
    NasRemoteUeReportResponse => "RemoteUeReportResponse",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_unwraps_values_and_describes_causes() {
        let reject = NasEpsMessage::decode(&[0x07, 0x44, 0x0f]).unwrap();
        assert_eq!(
            reject.to_string(),
            "EMM AttachReject (cause=#15 (No Suitable Cells In tracking area))"
        );
        let unknown = NasEpsMessage::decode(&[0x07, 0x60, 0x04]).unwrap();
        // The protocol is said once: EMM STATUS is an EMM Status. A cause
        // that the table does not have is its number.
        assert_eq!(unknown.to_string(), "EMM Status (cause=#4)");
        let esm = NasEpsMessage::decode(&[0x02, 0x01, 0xdc]).unwrap();
        assert_eq!(esm.to_string(), "ESM (EBI=0, PTI=1) DummyMessage");
        // An address is shown as an address.
        let default = NasEpsMessage::decode(
            &hex::decode("5201c101090908696e7465726e657405010a000001").unwrap(),
        )
        .unwrap();
        assert_eq!(
            default.to_string(),
            "ESM (EBI=5, PTI=1) ActivateDefaultEpsBearerContextRequest (QoS=QCI 9, \
             APN=internet, PDN-address=IPv4 10.0.0.1)"
        );
        assert_eq!(
            NasEmmMessageType::AttachRequest.to_string(),
            "AttachRequest"
        );
    }

    /// An ATTACH ACCEPT shows its timers with their units, its tracking
    /// areas, its GUTI as the service based interfaces write it, and the
    /// ESM message that it carries.
    #[test]
    fn an_attach_accept_shows_what_a_log_needs() {
        // Open5GS's, as captured
        let accept = NasEpsMessage::decode(
            &hex::decode(
                "07420129064002f8390001001d5201c101090908696e7465726e657405010a2d00035e06fefe\
                 fafa0202500bf602f839000201c000053664020108",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            accept.to_string(),
            "EMM AttachAccept (result=EpsOnly, T3412=9 min, TAI-list=[208-93-0001], \
             GUTI=4g-guti-20893000201c0000536, ESM-container=ESM (EBI=5, PTI=1) \
             ActivateDefaultEpsBearerContextRequest (QoS=QCI 9, APN=internet, \
             PDN-address=IPv4 10.45.0.3, APN-AMBR=DL 768 Mbps UL 768 Mbps))"
        );
    }

    /// An identity is shown whole, as the service based interfaces write
    /// it, and one of a type that is not read by its octets.
    #[test]
    fn an_identity_is_shown_whole() {
        let shown = |octets: &str| {
            NasEpsMessage::decode(&hex::decode(octets).unwrap())
                .unwrap()
                .to_string()
        };
        assert_eq!(
            shown("0756080910101032547698"),
            "EMM IdentityResponse (identity=imsi-001010123456789)"
        );
        assert_eq!(
            shown("0756084a09512430325781"),
            "EMM IdentityResponse (identity=imei-490154203237518)"
        );
        assert_eq!(
            shown("0756094309512430325781f1"),
            "EMM IdentityResponse (identity=imeisv-4901542032375181)"
        );
        assert_eq!(
            shown("075605f4c0000001"),
            "EMM IdentityResponse (identity=tmsi-c0000001)"
        );
        // A TMGI, which the crate does not read: its octets
        let tmgi = NasMobileIdentity::new(vec![0x1d, 1, 2, 3, 4, 5]);
        assert_eq!(
            NasEpsMessage::new_emm(NasIdentityResponse::new(tmgi)).to_string(),
            "EMM IdentityResponse (identity=TMGI (1d0102030405))"
        );
    }

    /// RES is a key: its length alone.
    #[test]
    fn an_authentication_response_hides_res() {
        let message = NasEpsMessage::decode(&[0x07, 0x53, 0x04, 0x11, 0x22, 0x33, 0x44]).unwrap();
        assert_eq!(
            message.to_string(),
            "EMM AuthenticationResponse (RES=hidden (4 octets))"
        );
    }
}
