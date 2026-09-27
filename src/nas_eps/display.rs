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

//! Human-readable `fmt::Display` implementations for EPS NAS messages.
//!
//! EMM, ESM, and security envelope messages show their header details and
//! common identity, cause, APN, and algorithm fields for debugging and logging.
//!
//! ```rust
//! use oxirush_nas::nas_eps::decode_nas_eps_message;
//!
//! let message = decode_nas_eps_message(&[0x07, 0x60, 0x03]).unwrap();
//! println!("{message}");
//! ```

use crate::nas_eps::ie::*;
use crate::nas_eps::message_types::*;
use crate::nas_eps::messages::*;
use crate::nas_eps::types::*;
use std::fmt;

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
            Self::DetachRequestFromUe(message) => fmt::Display::fmt(message, f),
            Self::DetachRequestToUe(message) => fmt::Display::fmt(message, f),
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
            Self::Opaque(data) => write!(f, "Opaque ({} bytes)", data.len()),
        }
    }
}

impl fmt::Display for Guti {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GUTI (PLMN={}, MMEGI={:#06X}, MMEC={:#04X}, M-TMSI={:#010X})",
            self.plmn, self.mme_group_id, self.mme_code, self.m_tmsi
        )
    }
}

/// Show a decoded value, or "?" when it does not decode.
fn show<T: fmt::Debug>(value: Option<T>) -> String {
    value.map_or_else(|| "?".into(), |value| format!("{value:?}"))
}

fn format_emm_cause(cause: &NasEmmCause) -> String {
    format!("0x{:02X} ({})", cause.value, cause.cause().description())
}

fn format_esm_cause(cause: &NasEsmCause) -> String {
    format!("0x{:02X} ({})", cause.value, cause.cause().description())
}

fn format_eps_mobile_identity(identity: &NasEpsMobileIdentity) -> String {
    if let Some(guti) = identity.as_guti() {
        guti.to_string()
    } else if let Some(imsi) = identity.as_imsi() {
        format!("IMSI {imsi}")
    } else if let Some(imei) = identity.as_imei() {
        format!("IMEI {imei}")
    } else {
        format!("identity type {}", show(identity.identity_type_raw()))
    }
}

fn format_mobile_identity(identity: &NasMobileIdentity) -> String {
    if let Some(imsi) = identity.as_imsi() {
        format!("IMSI {imsi}")
    } else if let Some(imei) = identity.as_imei() {
        format!("IMEI {imei}")
    } else if let Some(imeisv) = identity.as_imeisv() {
        format!("IMEISV {imeisv}")
    } else if let Some(tmsi) = identity.as_tmsi() {
        format!("TMSI {tmsi:#010X}")
    } else if identity.is_no_identity() {
        "no identity".into()
    } else {
        format!("identity type {}", show(identity.identity_type_raw()))
    }
}

fn format_ue_net_cap(capability: &NasUeNetworkCapability) -> String {
    let eea = (0..=7)
        .filter(|&algo| capability.supports_eea(algo))
        .map(|algo| format!("EEA{algo}"));
    let eia = (0..=6)
        .filter(|&algo| capability.supports_eia(algo))
        .map(|algo| format!("EIA{algo}"));
    format!(
        "{} / {}",
        eea.collect::<Vec<_>>().join(" "),
        eia.collect::<Vec<_>>().join(" ")
    )
}

impl fmt::Display for NasAttachRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AttachRequest (type={:?}, KSI={:?}, identity={}, UE-NetCap={}, ESM={}B)",
            self.eps_attach_type.attach_type(),
            self.nas_key_set_identifier.key_set_identifier(),
            format_eps_mobile_identity(&self.eps_mobile_identity),
            format_ue_net_cap(&self.ue_network_capability),
            self.esm_message_container.value.len()
        )
    }
}

impl fmt::Display for NasAttachAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AttachAccept (result={}, T3412={}, TAIs={}",
            show(self.eps_attach_result.attach_result()),
            show(self.t3412_value.to_seconds()),
            self.tai_list.tai_list().map_or(0, |list| list.0.len())
        )?;
        if let Some(guti) = &self.guti {
            write!(f, ", GUTI={}", format_eps_mobile_identity(guti))?;
        }
        if let Some(cause) = &self.emm_cause {
            write!(f, ", cause={}", format_emm_cause(cause))?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasAttachReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AttachReject (cause={})",
            format_emm_cause(&self.emm_cause)
        )
    }
}

impl fmt::Display for NasDetachRequestFromUe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DetachRequestFromUe (type={:?}, switch_off={}, identity={})",
            self.detach_type.ue_detach_kind(),
            u8::from(self.detach_type.is_switch_off()),
            format_eps_mobile_identity(&self.eps_mobile_identity)
        )
    }
}

impl fmt::Display for NasDetachRequestToUe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DetachRequestToUe (type={:?}",
            self.detach_type.network_detach_kind()
        )?;
        if let Some(cause) = &self.emm_cause {
            write!(f, ", cause={}", format_emm_cause(cause))?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasAuthenticationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthenticationRequest (KSI={:?}, RAND={}B, AUTN={}B)",
            self.nas_key_set_identifier_asme.key_set_identifier(),
            self.authentication_parameter_rand_eps_challenge.value.len(),
            self.authentication_parameter_autn_eps_challenge.value.len()
        )
    }
}

impl fmt::Display for NasAuthenticationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthenticationFailure (cause={}",
            format_emm_cause(&self.emm_cause)
        )?;
        if let Some(parameter) = &self.authentication_failure_parameter {
            write!(f, ", AUTS={}B", parameter.value.len())?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasSecurityModeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecurityModeCommand (cipher={}, integrity={}, KSI={:?}",
            show(self.selected_nas_security_algorithms.ciphering()),
            show(self.selected_nas_security_algorithms.integrity()),
            self.nas_key_set_identifier.key_set_identifier()
        )?;
        if self
            .imeisv_request
            .as_ref()
            .is_some_and(|request| request.is_requested())
        {
            write!(f, ", IMEISV requested")?;
        }
        if self.hash_mme.is_some() {
            write!(f, ", HashMME")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasEmmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmmStatus (cause={})", format_emm_cause(&self.emm_cause))
    }
}

impl fmt::Display for NasIdentityResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdentityResponse (identity={})",
            format_mobile_identity(&self.mobile_identity)
        )
    }
}

impl fmt::Display for NasIdentityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IdentityRequest (type={:?})",
            self.identity_type.identity_type()
        )
    }
}

impl fmt::Display for NasSecurityModeComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecurityModeComplete (")?;
        match &self.imeisv {
            Some(identity) => write!(f, "identity={}", format_mobile_identity(identity))?,
            None => write!(f, "no IMEISV")?,
        }
        if let Some(container) = &self.replayed_nas_message_container {
            write!(f, ", replayed NAS={}B", container.value.len())?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasControlPlaneServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ControlPlaneServiceRequest (type={:?}, active={}, ESM={}B, NAS={}B)",
            self.control_plane_service_type.service_type(),
            u8::from(self.control_plane_service_type.is_active()),
            self.esm_message_container
                .as_ref()
                .map_or(0, |container| container.value.len()),
            self.nas_message_container
                .as_ref()
                .map_or(0, |container| container.value.len())
        )
    }
}

impl fmt::Display for NasSecurityModeReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecurityModeReject (cause={})",
            format_emm_cause(&self.emm_cause)
        )
    }
}

impl fmt::Display for NasServiceReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServiceReject (cause={})",
            format_emm_cause(&self.emm_cause)
        )
    }
}

impl fmt::Display for NasTrackingAreaUpdateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrackingAreaUpdateRequest (type={}, active={}, KSI={:?}, old GUTI={}",
            show(self.eps_update_type.update_type()),
            u8::from(self.eps_update_type.is_active()),
            self.nas_key_set_identifier.key_set_identifier(),
            format_eps_mobile_identity(&self.old_guti)
        )?;
        if let Some(capability) = &self.ue_network_capability {
            write!(f, ", UE-NetCap={}", format_ue_net_cap(capability))?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasTrackingAreaUpdateAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrackingAreaUpdateAccept (result={}",
            show(self.eps_update_result.update_result())
        )?;
        if let Some(timer) = &self.t3412_value {
            write!(f, ", T3412={}", show(timer.to_seconds()))?;
        }
        if let Some(guti) = &self.guti {
            write!(f, ", GUTI={}", format_eps_mobile_identity(guti))?;
        }
        if let Some(cause) = &self.emm_cause {
            write!(f, ", cause={}", format_emm_cause(cause))?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasTrackingAreaUpdateReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrackingAreaUpdateReject (cause={})",
            format_emm_cause(&self.emm_cause)
        )
    }
}

impl fmt::Display for NasPdnConnectivityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdnConnectivityRequest (request={}, PDN={}",
            show(self.request_type.request_type()),
            show(self.pdn_type.pdn_type())
        )?;
        if let Some(apn) = &self.access_point_name {
            write!(f, ", APN={}", show(apn.as_string()))?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasPdnConnectivityReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdnConnectivityReject (cause={})",
            format_esm_cause(&self.esm_cause)
        )
    }
}

impl fmt::Display for NasActivateDefaultEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ActivateDefaultEpsBearerContextRequest (APN={}, PDN={}, QCI={})",
            show(self.access_point_name.as_string()),
            show(self.pdn_address.pdn_address()),
            show(self.eps_qos.qos().map(|qos| qos.qci))
        )
    }
}

impl fmt::Display for NasActivateDedicatedEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ActivateDedicatedEpsBearerContextRequest (linked EBI={}, QCI={}, filters={})",
            show(self.linked_eps_bearer_identity.ebi()),
            show(self.eps_qos.qos().map(|qos| qos.qci)),
            self.tft.tft().map_or(0, |tft| tft.packet_filters.len())
        )
    }
}

impl fmt::Display for NasDeactivateEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeactivateEpsBearerContextRequest (cause={})",
            format_esm_cause(&self.esm_cause)
        )
    }
}

impl fmt::Display for NasModifyEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ModifyEpsBearerContextRequest (")?;
        let mut fields = Vec::new();
        if let Some(qos) = &self.new_eps_qos {
            fields.push(format!("QCI={}", show(qos.qos().map(|qos| qos.qci))));
        }
        if let Some(tft) = &self.tft {
            fields.push(format!("TFT={}", show(tft.tft().map(|tft| tft.operation))));
        }
        if let Some(ambr) = &self.apn_ambr {
            fields.push(format!("APN-AMBR={}", show(ambr.ambr())));
        }
        write!(f, "{})", fields.join(", "))
    }
}

impl fmt::Display for NasEsmInformationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EsmInformationResponse (")?;
        match &self.access_point_name {
            Some(apn) => write!(f, "APN={}", show(apn.as_string()))?,
            None => write!(f, "no APN")?,
        }
        if self.protocol_configuration_options.is_some()
            || self.extended_protocol_configuration_options.is_some()
        {
            write!(f, ", PCO")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasPdnDisconnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdnDisconnectRequest (linked EBI={})",
            show(self.linked_eps_bearer_identity.ebi())
        )
    }
}

impl fmt::Display for NasBearerResourceAllocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BearerResourceAllocationRequest (linked EBI={}, filters={})",
            show(self.linked_eps_bearer_identity.ebi()),
            self.traffic_flow_aggregate
                .tft()
                .map_or(0, |tft| tft.packet_filters.len())
        )
    }
}

impl fmt::Display for NasEsmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EsmStatus (cause={})", format_esm_cause(&self.esm_cause))
    }
}

impl fmt::Display for NasServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServiceRequest (KSI={}, SQN={}, short MAC={:#06x})",
            self.ksi_and_sequence_number >> 5,
            self.ksi_and_sequence_number & 0x1f,
            self.message_authentication_code
        )
    }
}

impl fmt::Display for NasEmmTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(opaque) = &self.protected_payload {
            write!(
                f,
                "EmmTransport (SN={}, protected={}B)",
                self.security_header.sequence_number,
                opaque.len()
            )
        } else {
            write!(
                f,
                "EmmTransport (SN={}, container={}B)",
                self.security_header.sequence_number,
                self.data_container.as_ref().map_or(0, Vec::len)
            )
        }
    }
}

impl fmt::Display for NasAuthenticationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthenticationResponse (RES={}B)",
            self.authentication_response_parameter.value.len()
        )
    }
}

impl fmt::Display for NasDownlinkNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DownlinkNasTransport (container={}B)",
            self.nas_message_container.value.len()
        )
    }
}

impl fmt::Display for NasUplinkNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UplinkNasTransport (container={}B)",
            self.nas_message_container.value.len()
        )
    }
}

impl fmt::Display for NasNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Notification (indicator={})",
            show(self.notification_indicator.indicator_raw())
        )
    }
}

impl fmt::Display for NasExtendedServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExtendedServiceRequest (type={}, identity={})",
            show(self.service_type.service_type()),
            format_mobile_identity(&self.m_tmsi)
        )
    }
}

impl fmt::Display for NasDownlinkGenericNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DownlinkGenericNasTransport (type={}, container={}B)",
            show(self.generic_message_container_type.container_type()),
            self.generic_message_container.value.len()
        )
    }
}

impl fmt::Display for NasUplinkGenericNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UplinkGenericNasTransport (type={}, container={}B)",
            show(self.generic_message_container_type.container_type()),
            self.generic_message_container.value.len()
        )
    }
}

impl fmt::Display for NasEsmDataTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EsmDataTransport (container={}B)",
            self.user_data_container.value.len()
        )
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
    NasAttachComplete => "AttachComplete",
    NasAuthenticationReject => "AuthenticationReject",
    NasCsServiceNotification => "CsServiceNotification",
    NasDetachAccept => "DetachAccept",
    NasEmmInformation => "EmmInformation",
    NasGutiReallocationCommand => "GutiReallocationCommand",
    NasGutiReallocationComplete => "GutiReallocationComplete",
    NasTrackingAreaUpdateComplete => "TrackingAreaUpdateComplete",
    NasServiceAccept => "ServiceAccept",
    NasActivateDedicatedEpsBearerContextAccept => "ActivateDedicatedEpsBearerContextAccept",
    NasActivateDedicatedEpsBearerContextReject => "ActivateDedicatedEpsBearerContextReject",
    NasActivateDefaultEpsBearerContextAccept => "ActivateDefaultEpsBearerContextAccept",
    NasActivateDefaultEpsBearerContextReject => "ActivateDefaultEpsBearerContextReject",
    NasBearerResourceAllocationReject => "BearerResourceAllocationReject",
    NasBearerResourceModificationReject => "BearerResourceModificationReject",
    NasBearerResourceModificationRequest => "BearerResourceModificationRequest",
    NasDeactivateEpsBearerContextAccept => "DeactivateEpsBearerContextAccept",
    NasEsmDummyMessage => "EsmDummyMessage",
    NasEsmInformationRequest => "EsmInformationRequest",
    NasModifyEpsBearerContextAccept => "ModifyEpsBearerContextAccept",
    NasModifyEpsBearerContextReject => "ModifyEpsBearerContextReject",
    NasPdnDisconnectReject => "PdnDisconnectReject",
    NasRemoteUeReport => "RemoteUeReport",
    NasRemoteUeReportResponse => "RemoteUeReportResponse",
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_unwraps_values_and_describes_causes() {
        let reject = NasEpsMessage::from_bytes(&[0x07, 0x44, 0x0f]).unwrap();
        assert_eq!(
            reject.to_string(),
            "EMM AttachReject (cause=0x0F (No Suitable Cells In tracking area))"
        );
        let unknown = NasEpsMessage::from_bytes(&[0x07, 0x60, 0x04]).unwrap();
        assert_eq!(
            unknown.to_string(),
            "EMM EmmStatus (cause=0x04 (Unknown EMM cause))"
        );
        let guti = Guti {
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0f],
            },
            mme_group_id: 0x8001,
            mme_code: 1,
            m_tmsi: 0xcafe_babe,
        };
        assert_eq!(
            guti.to_string(),
            "GUTI (PLMN=208/93, MMEGI=0x8001, MMEC=0x01, M-TMSI=0xCAFEBABE)"
        );
        let esm = NasEpsMessage::from_bytes(&[0x02, 0x01, 0xdc]).unwrap();
        assert_eq!(esm.to_string(), "ESM (EBI=0, PTI=1) EsmDummyMessage");
        assert_eq!(
            NasEmmMessageType::AttachRequest.to_string(),
            "AttachRequest"
        );
    }

    #[test]
    fn top_level_authentication_response_displays_res_length() {
        let message =
            NasEpsMessage::from_bytes(&[0x07, 0x53, 0x04, 0x11, 0x22, 0x33, 0x44]).unwrap();
        assert!(message.to_string().contains("RES=4B"));
    }
}
