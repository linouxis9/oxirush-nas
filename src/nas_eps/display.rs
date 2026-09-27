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

use crate::nas_eps::ie::Guti;
use crate::nas_eps::message_types::*;
use crate::nas_eps::messages::*;
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
            Self::AttachReject(message) => fmt::Display::fmt(message, f),
            Self::DetachRequestFromUe(message) => fmt::Display::fmt(message, f),
            Self::DetachRequestToUe(message) => fmt::Display::fmt(message, f),
            Self::AuthenticationRequest(message) => fmt::Display::fmt(message, f),
            Self::AuthenticationFailure(message) => fmt::Display::fmt(message, f),
            Self::SecurityModeCommand(message) => fmt::Display::fmt(message, f),
            Self::SecurityModeReject(message) => fmt::Display::fmt(message, f),
            Self::ServiceReject(message) => fmt::Display::fmt(message, f),
            Self::TrackingAreaUpdateRequest(message) => fmt::Display::fmt(message, f),
            Self::TrackingAreaUpdateAccept(message) => fmt::Display::fmt(message, f),
            Self::TrackingAreaUpdateReject(message) => fmt::Display::fmt(message, f),
            Self::IdentityResponse(message) => fmt::Display::fmt(message, f),
            Self::IdentityRequest(message) => fmt::Display::fmt(message, f),
            Self::SecurityModeComplete(message) => fmt::Display::fmt(message, f),
            Self::ControlPlaneServiceRequest(message) => fmt::Display::fmt(message, f),
            Self::EmmStatus(message) => fmt::Display::fmt(message, f),
            _ => fmt::Display::fmt(&self.message_type(), f),
        }
    }
}

impl fmt::Display for NasEsmMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PdnConnectivityRequest(message) => fmt::Display::fmt(message, f),
            Self::PdnConnectivityReject(message) => fmt::Display::fmt(message, f),
            Self::ActivateDefaultEpsBearerContextRequest(message) => fmt::Display::fmt(message, f),
            Self::ActivateDedicatedEpsBearerContextRequest(message) => {
                fmt::Display::fmt(message, f)
            }
            Self::DeactivateEpsBearerContextRequest(message) => fmt::Display::fmt(message, f),
            Self::ModifyEpsBearerContextRequest(message) => fmt::Display::fmt(message, f),
            Self::EsmInformationResponse(message) => fmt::Display::fmt(message, f),
            Self::PdnDisconnectRequest(message) => fmt::Display::fmt(message, f),
            Self::BearerResourceAllocationRequest(message) => fmt::Display::fmt(message, f),
            Self::EsmStatus(message) => fmt::Display::fmt(message, f),
            _ => fmt::Display::fmt(&self.message_type(), f),
        }
    }
}

impl fmt::Display for NasEpsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Emm(_, message) => write!(f, "EPS EMM {message}"),
            Self::Esm(header, message) => write!(
                f,
                "EPS ESM (EBI={}, PTI={}) {message}",
                header.eps_bearer_identity, header.procedure_transaction_identity
            ),
            Self::SecurityProtected(header, inner) => write!(
                f,
                "EPS SecurityProtected (SHT={:?}, MAC={:#010x}, SN={}) {inner}",
                header.security_header_type,
                header.message_authentication_code,
                header.sequence_number
            ),
            Self::ServiceRequest(message) => write!(f, "EPS EMM {message}"),
            Self::EmmTransport(message) => write!(f, "EPS EMM {message}"),
            Self::Opaque(data) => write!(f, "EPS opaque payload ({} bytes)", data.len()),
        }
    }
}

impl fmt::Display for Guti {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{:04X}-{:02X}-{:08X}",
            self.plmn, self.mme_group_id, self.mme_code, self.m_tmsi
        )
    }
}

impl fmt::Display for NasAttachRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AttachRequest ({:?}, ",
            self.eps_attach_type.attach_type()
        )?;
        if let Some(guti) = self.eps_mobile_identity.as_guti() {
            write!(f, "GUTI={guti}")?;
        } else if let Some(imsi) = self.eps_mobile_identity.as_imsi() {
            write!(f, "IMSI={imsi}")?;
        } else if let Some(imei) = self.eps_mobile_identity.as_imei() {
            write!(f, "IMEI={imei}")?;
        } else {
            write!(f, "identity={:?}", self.eps_mobile_identity.identity_type())?;
        }
        write!(f, ", ESM={}B)", self.esm_message_container.value.len())
    }
}

impl fmt::Display for NasAttachAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AttachAccept ({:?}, T3412={:?}, TAIs={})",
            self.eps_attach_result.attach_result(),
            self.t3412_value.to_seconds(),
            self.tai_list.tai_list().map_or(0, |list| list.0.len())
        )
    }
}

impl fmt::Display for NasAttachReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AttachReject (cause={:?})", self.emm_cause.cause())
    }
}

impl fmt::Display for NasDetachRequestFromUe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DetachRequestFromUe ({:?}, switch-off={})",
            self.detach_type.ue_detach_kind(),
            self.detach_type.is_switch_off()
        )
    }
}

impl fmt::Display for NasDetachRequestToUe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DetachRequestToUe ({:?}, cause={:?})",
            self.detach_type.network_detach_kind(),
            self.emm_cause.as_ref().map(|cause| cause.cause())
        )
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
            "AuthenticationFailure (cause={:?})",
            self.emm_cause.cause()
        )
    }
}

impl fmt::Display for NasSecurityModeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecurityModeCommand (cipher={:?}, integrity={:?}, KSI={:?})",
            self.selected_nas_security_algorithms.ciphering(),
            self.selected_nas_security_algorithms.integrity(),
            self.nas_key_set_identifier.key_set_identifier()
        )
    }
}

impl fmt::Display for NasEmmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmmStatus (cause={:?})", self.emm_cause.cause())
    }
}

impl fmt::Display for NasIdentityResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(imsi) = self.mobile_identity.as_imsi() {
            write!(f, "IdentityResponse (IMSI={imsi})")
        } else if let Some(imei) = self.mobile_identity.as_imei() {
            write!(f, "IdentityResponse (IMEI={imei})")
        } else if let Some(imeisv) = self.mobile_identity.as_imeisv() {
            write!(f, "IdentityResponse (IMEISV={imeisv})")
        } else if let Some(tmsi) = self.mobile_identity.as_tmsi() {
            write!(f, "IdentityResponse (TMSI={tmsi:08X})")
        } else {
            f.write_str("IdentityResponse (unknown identity)")
        }
    }
}

impl fmt::Display for NasIdentityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityRequest (type={})", self.identity_type.value)
    }
}

impl fmt::Display for NasSecurityModeComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecurityModeComplete (IMEISV={:?}, replayed NAS={}B)",
            self.imeisv
                .as_ref()
                .and_then(|identity| identity.as_imeisv()),
            self.replayed_nas_message_container
                .as_ref()
                .map_or(0, |container| container.value.len())
        )
    }
}

impl fmt::Display for NasControlPlaneServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ControlPlaneServiceRequest (type={}, ESM={}B, NAS={}B)",
            self.control_plane_service_type.value,
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
        write!(f, "SecurityModeReject (cause={:?})", self.emm_cause.cause())
    }
}

impl fmt::Display for NasServiceReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceReject (cause={:?})", self.emm_cause.cause())
    }
}

impl fmt::Display for NasTrackingAreaUpdateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrackingAreaUpdateRequest ({:?}, active={}, old GUTI={:?})",
            self.eps_update_type.update_type(),
            self.eps_update_type.is_active(),
            self.old_guti.as_guti()
        )
    }
}

impl fmt::Display for NasTrackingAreaUpdateAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrackingAreaUpdateAccept ({:?}, T3412={:?}, GUTI={:?})",
            self.eps_update_result.update_result(),
            self.t3412_value
                .as_ref()
                .and_then(|timer| timer.to_seconds()),
            self.guti.as_ref().and_then(|guti| guti.as_guti())
        )
    }
}

impl fmt::Display for NasTrackingAreaUpdateReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrackingAreaUpdateReject (cause={:?})",
            self.emm_cause.cause()
        )
    }
}

impl fmt::Display for NasPdnConnectivityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdnConnectivityRequest (request=0x{:X}, PDN={:?}, APN={:?})",
            self.request_type.value,
            self.pdn_type.pdn_type(),
            self.access_point_name
                .as_ref()
                .and_then(|apn| apn.as_string())
        )
    }
}

impl fmt::Display for NasPdnConnectivityReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdnConnectivityReject (cause={:?})",
            self.esm_cause.cause()
        )
    }
}

impl fmt::Display for NasActivateDefaultEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ActivateDefaultEpsBearerContextRequest (APN={:?}, PDN={:?}, QCI={:?})",
            self.access_point_name.as_string(),
            self.pdn_address.pdn_address(),
            self.eps_qos.qos().map(|qos| qos.qci)
        )
    }
}

impl fmt::Display for NasActivateDedicatedEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ActivateDedicatedEpsBearerContextRequest (linked EBI={}, QCI={:?}, filters={})",
            self.linked_eps_bearer_identity.value,
            self.eps_qos.qos().map(|qos| qos.qci),
            self.tft.tft().map_or(0, |tft| tft.packet_filters.len())
        )
    }
}

impl fmt::Display for NasDeactivateEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DeactivateEpsBearerContextRequest (cause={:?})",
            self.esm_cause.cause()
        )
    }
}

impl fmt::Display for NasModifyEpsBearerContextRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ModifyEpsBearerContextRequest (QoS={}, TFT={}, APN-AMBR={})",
            self.new_eps_qos.is_some(),
            self.tft.is_some(),
            self.apn_ambr.is_some()
        )
    }
}

impl fmt::Display for NasEsmInformationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EsmInformationResponse (APN={:?}, PCO={})",
            self.access_point_name
                .as_ref()
                .and_then(|apn| apn.as_string()),
            self.protocol_configuration_options.is_some()
                || self.extended_protocol_configuration_options.is_some()
        )
    }
}

impl fmt::Display for NasPdnDisconnectRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PdnDisconnectRequest (linked EBI={})",
            self.linked_eps_bearer_identity.value
        )
    }
}

impl fmt::Display for NasBearerResourceAllocationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BearerResourceAllocationRequest (linked EBI={}, filters={})",
            self.linked_eps_bearer_identity.value,
            self.traffic_flow_aggregate
                .tft()
                .map_or(0, |tft| tft.packet_filters.len())
        )
    }
}

impl fmt::Display for NasEsmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EsmStatus (cause={:?})", self.esm_cause.cause())
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

macro_rules! simple_message_display {
    ($($name:ident),+ $(,)?) => {
        $(
            impl fmt::Display for $name {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(stringify!($name))
                }
            }
        )+
    };
}

simple_message_display!(
    NasAttachComplete,
    NasAuthenticationReject,
    NasAuthenticationResponse,
    NasCsServiceNotification,
    NasDetachAccept,
    NasDownlinkNasTransport,
    NasEmmInformation,
    NasExtendedServiceRequest,
    NasGutiReallocationCommand,
    NasGutiReallocationComplete,
    NasTrackingAreaUpdateComplete,
    NasUplinkNasTransport,
    NasDownlinkGenericNasTransport,
    NasUplinkGenericNasTransport,
    NasServiceAccept,
    NasActivateDedicatedEpsBearerContextAccept,
    NasActivateDedicatedEpsBearerContextReject,
    NasActivateDefaultEpsBearerContextAccept,
    NasActivateDefaultEpsBearerContextReject,
    NasBearerResourceAllocationReject,
    NasBearerResourceModificationReject,
    NasBearerResourceModificationRequest,
    NasDeactivateEpsBearerContextAccept,
    NasEsmDummyMessage,
    NasEsmInformationRequest,
    NasModifyEpsBearerContextAccept,
    NasModifyEpsBearerContextReject,
    NasNotification,
    NasPdnDisconnectReject,
    NasRemoteUeReport,
    NasRemoteUeReportResponse,
    NasEsmDataTransport,
);
