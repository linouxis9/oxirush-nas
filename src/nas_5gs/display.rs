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

//! Human-readable `fmt::Display` implementations for NAS messages and key IEs.
//!
//! Provides Wireshark-style formatting useful for debugging and logging.
//! All top-level messages implement `Display`, and many commonly used
//! individual 5GMM/5GSM message structs plus key IE structs (GUTI, S-TMSI,
//! PLMN) provide dedicated formatting as well.
//!
//! ```rust
//! use oxirush_nas::decode_nas_5gs_message;
//!
//! let bytes = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000").unwrap();
//! let msg = decode_nas_5gs_message(&bytes).unwrap();
//! println!("{msg}");
//! // => 5GMM RegistrationRequest (type=InitialRegistration, ..., identity=SUCI (PLMN=208/93, scheme=0), ...)
//! ```

use crate::nas_5gs::ie::*;
use crate::nas_5gs::message_types::*;
use crate::nas_5gs::messages::*;
use crate::nas_5gs::types::*;
use crate::nas_5gs::upds::*;
use std::fmt;

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
            Nas5gsMessage::Opaque(data) => write!(f, "Opaque ({} bytes)", data.len()),
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
            Self::ManageUePolicyCommand(message) => write!(
                f,
                "{} (sublists={}, network-classmark={}, vps-ursp={})",
                NasUpdsMessageType::ManageUePolicyCommand,
                message.ue_policy_section_management_list.sublists().len(),
                if message.ue_policy_network_classmark.is_some() {
                    "present"
                } else {
                    "absent"
                },
                if message.vps_ursp_configuration.is_some() {
                    "present"
                } else {
                    "absent"
                }
            ),
            Self::ManageUePolicyComplete(_) => {
                write!(f, "{}", NasUpdsMessageType::ManageUePolicyComplete)
            }
            Self::ManageUePolicyCommandReject(message) => write!(
                f,
                "{} (subresults={})",
                NasUpdsMessageType::ManageUePolicyCommandReject,
                message
                    .ue_policy_section_management_result
                    .subresults()
                    .len()
            ),
            Self::UeStateIndication(message) => write!(
                f,
                "{} (upsi-sublists={}, ue-os-id={})",
                NasUpdsMessageType::UeStateIndication,
                message.upsi_list.sublists().len(),
                if message.ue_os_id.is_some() {
                    "present"
                } else {
                    "absent"
                }
            ),
            Self::UePolicyProvisioningRequest(message) => write!(
                f,
                "{} ({}B payload)",
                NasUpdsMessageType::UePolicyProvisioningRequest,
                message.payload.len()
            ),
            Self::UePolicyProvisioningReject(message) => write!(
                f,
                "{} ({}B payload)",
                NasUpdsMessageType::UePolicyProvisioningReject,
                message.payload.len()
            ),
            Self::Unsupported(message) => write!(
                f,
                "UnsupportedUpdsMessage (type=0x{:02X}, {}B body)",
                message.message_type,
                message.body.len()
            ),
        }
    }
}

impl fmt::Display for NasUpdsEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UPDS (PTI={}, type=0x{:02X}) {}",
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
            Self::DeregistrationRequestFromUe(m) => write!(f, "{m}"),
            Self::DeregistrationRequestToUe(m) => write!(f, "{m}"),
            Self::DeregistrationAcceptFromUe(m) => write!(f, "{m}"),
            Self::DeregistrationAcceptToUe(m) => write!(f, "{m}"),
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
            Self::FGmmStatus(m) => write!(f, "{m}"),
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
            Self::FGsmStatus(m) => write!(f, "{m}"),
            Self::ServiceLevelAuthenticationCommand(m) => write!(f, "{m}"),
            Self::ServiceLevelAuthenticationComplete(m) => write!(f, "{m}"),
            Self::RemoteUeReport(m) => write!(f, "{m}"),
            Self::RemoteUeReportResponse(m) => write!(f, "{m}"),
        }
    }
}

// ============================================================================
// Individual 5GMM messages
// ============================================================================

impl fmt::Display for NasRegistrationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rt = &self.fgs_registration_type;
        let reg_type_str = rt
            .registration_type()
            .map(|r| format!("{r:?}"))
            .unwrap_or_else(|| format!("0x{:02X}", rt.value & 0x07));
        write!(
            f,
            "RegistrationRequest (type={}, FOR={}, ngKSI={}",
            reg_type_str,
            if rt.follow_on_request() { "1" } else { "0" },
            rt.ngksi()
        )?;
        write!(
            f,
            ", identity={}",
            format_mobile_identity(&self.fgs_mobile_identity)
        )?;
        if let Some(ref cap) = self.ue_security_capability {
            write!(f, ", UE-SecCap={}", format_ue_sec_cap(cap))?;
        }
        if let Some(ref nssai) = self.requested_nssai {
            write!(f, ", NSSAI={}B", nssai.length)?;
        }
        if let Some(ref status) = self.pdu_session_status {
            let s = NasPduSessionStatus {
                type_field: 0,
                length: status.length,
                value: status.value.clone(),
            };
            let active = s.active_sessions();
            if !active.is_empty() {
                write!(f, ", PDU-sessions={active:?}")?;
            }
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasRegistrationAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result_val = self.fgs_registration_result.result_value_raw();
        write!(f, "RegistrationAccept (result=0x{result_val:02X}")?;
        if let Some(ref guti) = self.fg_guti {
            write!(f, ", GUTI={}", format_mobile_identity(guti))?;
        }
        if let Some(ref tai) = self.tai_list {
            write!(f, ", TAI-list={}B", tai.length)?;
        }
        if let Some(ref nssai) = self.allowed_nssai {
            write!(f, ", Allowed-NSSAI={}B", nssai.length)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasRegistrationReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegistrationReject (cause={})",
            format_gmm_cause(self.fgmm_cause.value)
        )
    }
}

impl fmt::Display for NasDeregistrationRequestFromUe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dt = &self.de_registration_type;
        write!(
            f,
            "DeregistrationRequestFromUe (switch_off={}, access_type={:?}, identity={})",
            if dt.switch_off() { "1" } else { "0" },
            dt.access_type(),
            format_mobile_identity(&self.fgs_mobile_identity)
        )
    }
}

impl fmt::Display for NasDeregistrationRequestToUe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dt = &self.de_registration_type;
        write!(
            f,
            "DeregistrationRequestToUe (re_reg={}, access_type={:?}",
            if dt.re_registration_required() {
                "1"
            } else {
                "0"
            },
            dt.access_type()
        )?;
        if let Some(ref cause) = self.fgmm_cause {
            write!(f, ", cause={}", format_gmm_cause(cause.value))?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServiceRequest (5G-S-TMSI={})",
            format_mobile_identity(&self.fg_s_tmsi)
        )
    }
}

impl fmt::Display for NasServiceReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ServiceReject (cause={})",
            format_gmm_cause(self.fgmm_cause.value)
        )
    }
}

impl fmt::Display for NasServiceAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceAccept")?;
        if let Some(ref status) = self.pdu_session_status {
            let s = NasPduSessionStatus {
                type_field: 0,
                length: status.length,
                value: status.value.clone(),
            };
            let active = s.active_sessions();
            if !active.is_empty() {
                write!(f, " (PDU-sessions={active:?})")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for NasConfigurationUpdateCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ConfigurationUpdateCommand")?;
        if let Some(ref guti) = self.fg_guti {
            write!(f, " (GUTI={})", format_mobile_identity(guti))?;
        }
        Ok(())
    }
}

impl fmt::Display for NasAuthenticationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthenticationRequest (ngKSI={}", self.ngksi.ngksi())?;
        if let Some(ref rand) = self.authentication_parameter_rand {
            write!(f, ", RAND={}...", &hex::encode(&rand.value)[..8])?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasAuthenticationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthenticationResponse")?;
        if let Some(ref res) = self.authentication_response_parameter {
            write!(f, " (RES*={}B)", res.length)?;
        }
        Ok(())
    }
}

impl fmt::Display for NasAuthenticationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AuthenticationFailure (cause={})",
            format_gmm_cause(self.fgmm_cause.value)
        )?;
        if self.authentication_failure_parameter.is_some() {
            write!(f, " [AUTS present]")?;
        }
        Ok(())
    }
}

impl fmt::Display for NasAuthenticationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthenticationResult (ngKSI={})", self.ngksi.ngksi())
    }
}

impl fmt::Display for NasIdentityRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_type = self
            .identity_type
            .identity_type()
            .map(|t| format!("{t:?}"))
            .unwrap_or_else(|| format!("0x{:02X}", self.identity_type.value & 0x07));
        write!(f, "IdentityRequest (type={id_type})")
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

impl fmt::Display for NasSecurityModeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sa = &self.selected_nas_security_algorithms;
        let cipher_str = sa
            .ciphering()
            .map(|c| format!("{c:?}"))
            .unwrap_or_else(|| "?".into());
        let integ_str = sa
            .integrity()
            .map(|i| format!("{i:?}"))
            .unwrap_or_else(|| "?".into());
        write!(
            f,
            "SecurityModeCommand (cipher={}, integrity={}, ngKSI={})",
            cipher_str,
            integ_str,
            self.ngksi.ngksi()
        )
    }
}

impl fmt::Display for NasSecurityModeComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecurityModeComplete")?;
        if self.nas_message_container.is_some() {
            write!(f, " [NAS container present]")?;
        }
        Ok(())
    }
}

impl fmt::Display for NasSecurityModeReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SecurityModeReject (cause={})",
            format_gmm_cause(self.fgmm_cause.value)
        )
    }
}

impl fmt::Display for NasFGmmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "5GMM Status (cause={})",
            format_gmm_cause(self.fgmm_cause.value)
        )
    }
}

impl fmt::Display for NasNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Notification (access_type=0x{:02X})",
            self.access_type.value
        )
    }
}

impl fmt::Display for NasUlNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind_str = self
            .payload_container_type
            .kind()
            .map(|k| format!("{k:?}"))
            .unwrap_or_else(|| format!("0x{:02X}", self.payload_container_type.value));
        write!(
            f,
            "UlNasTransport (type={}, {}B",
            kind_str, self.payload_container.length
        )?;
        if let Some(ref id) = self.pdu_session_id {
            write!(f, ", PSI={}", id.value)?;
        }
        if let Some(ref dnn) = self.dnn {
            let dnn_ie = NasDnn {
                type_field: 0,
                length: dnn.length,
                value: dnn.value.clone(),
            };
            if let Some(s) = dnn_ie.as_string() {
                write!(f, ", DNN={s}")?;
            }
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasDlNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind_str = self
            .payload_container_type
            .kind()
            .map(|k| format!("{k:?}"))
            .unwrap_or_else(|| format!("0x{:02X}", self.payload_container_type.value));
        write!(
            f,
            "DlNasTransport (type={}, {}B",
            kind_str, self.payload_container.length
        )?;
        if let Some(ref id) = self.pdu_session_id {
            write!(f, ", PSI={}", id.value)?;
        }
        write!(f, ")")
    }
}

// ============================================================================
// Individual 5GSM messages
// ============================================================================

impl fmt::Display for NasPduSessionEstablishmentRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PduSessionEstablishmentRequest")?;
        if let Some(ref pst) = self.pdu_session_type {
            write!(f, " (type=0x{:X}", pst.value & 0x07)?;
            if let Some(ref ssc) = self.ssc_mode {
                write!(f, ", SSC={}", ssc.value & 0x07)?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

impl fmt::Display for NasPduSessionEstablishmentAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PduSessionEstablishmentAccept (type=0x{:X}, QoS-rules={}B, S-AMBR={}B",
            self.selected_pdu_session_type.value & 0x07,
            self.authorized_qos_rules.length,
            self.session_ambr.length
        )?;
        if let Some(ref cause) = self.fgsm_cause {
            write!(f, ", cause={}", format_gsm_cause(cause.value))?;
        }
        if let Some(ref addr) = self.pdu_address {
            write!(f, ", addr={}B", addr.length)?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasPduSessionEstablishmentReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PduSessionEstablishmentReject (cause={})",
            format_gsm_cause(self.fgsm_cause.value)
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
    NasRegistrationComplete => "RegistrationComplete",
    NasDeregistrationAcceptFromUe => "DeregistrationAcceptFromUe",
    NasDeregistrationAcceptToUe => "DeregistrationAcceptToUe",
    NasConfigurationUpdateComplete => "ConfigurationUpdateComplete",
    NasAuthenticationReject => "AuthenticationReject",
    NasNotificationResponse => "NotificationResponse",
    NasControlPlaneServiceRequest => "ControlPlaneServiceRequest",
    NasNetworkSliceSpecificAuthenticationCommand => "NetworkSliceSpecificAuthenticationCommand",
    NasNetworkSliceSpecificAuthenticationComplete => "NetworkSliceSpecificAuthenticationComplete",
    NasNetworkSliceSpecificAuthenticationResult => "NetworkSliceSpecificAuthenticationResult",
    NasRelayKeyRequest => "RelayKeyRequest",
    NasRelayKeyAccept => "RelayKeyAccept",
    NasRelayKeyReject => "RelayKeyReject",
    NasRelayAuthenticationRequest => "RelayAuthenticationRequest",
    NasRelayAuthenticationResponse => "RelayAuthenticationResponse",
    NasPduSessionAuthenticationCommand => "PduSessionAuthenticationCommand",
    NasPduSessionAuthenticationComplete => "PduSessionAuthenticationComplete",
    NasPduSessionAuthenticationResult => "PduSessionAuthenticationResult",
    NasPduSessionModificationRequest => "PduSessionModificationRequest",
    NasPduSessionModificationCommand => "PduSessionModificationCommand",
    NasPduSessionModificationComplete => "PduSessionModificationComplete",
    NasPduSessionReleaseRequest => "PduSessionReleaseRequest",
    NasPduSessionReleaseComplete => "PduSessionReleaseComplete",
    NasServiceLevelAuthenticationCommand => "ServiceLevelAuthenticationCommand",
    NasServiceLevelAuthenticationComplete => "ServiceLevelAuthenticationComplete",
    NasRemoteUeReport => "RemoteUeReport",
    NasRemoteUeReportResponse => "RemoteUeReportResponse"
);

impl fmt::Display for NasPduSessionModificationReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PduSessionModificationReject (cause={})",
            format_gsm_cause(self.fgsm_cause.value)
        )
    }
}

impl fmt::Display for NasPduSessionModificationCommandReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PduSessionModificationCommandReject (cause={})",
            format_gsm_cause(self.fgsm_cause.value)
        )
    }
}

impl fmt::Display for NasPduSessionReleaseReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PduSessionReleaseReject (cause={})",
            format_gsm_cause(self.fgsm_cause.value)
        )
    }
}

impl fmt::Display for NasPduSessionReleaseCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PduSessionReleaseCommand (cause={})",
            format_gsm_cause(self.fgsm_cause.value)
        )
    }
}

impl fmt::Display for NasFGsmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "5GSM Status (cause={})",
            format_gsm_cause(self.fgsm_cause.value)
        )
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn format_mobile_identity(id: &NasFGsMobileIdentity) -> String {
    match id.identity_type() {
        Some(MobileIdentityType::Suci) => {
            if let Some(suci) = id.as_suci() {
                match suci {
                    Suci::Imsi(suci) => format!(
                        "SUCI (PLMN={}, scheme={})",
                        suci.plmn_id,
                        suci.protection_scheme.to_u8()
                    ),
                    Suci::Utf8 { supi_format, nai } => {
                        format!("SUCI ({supi_format:?}, {nai})")
                    }
                }
            } else {
                format!("SUCI ({}B)", id.length)
            }
        }
        Some(MobileIdentityType::Guti) => {
            if let Some(guti) = id.as_guti() {
                guti.to_string()
            } else {
                format!("5G-GUTI ({}B)", id.length)
            }
        }
        Some(MobileIdentityType::STmsi) => {
            if let Some(tmsi) = id.as_s_tmsi() {
                format!("5G-S-TMSI (TMSI={:#010X})", tmsi.tmsi)
            } else {
                format!("5G-S-TMSI ({}B)", id.length)
            }
        }
        Some(MobileIdentityType::Imei) => id
            .as_imei()
            .map(|s| format!("IMEI ({s})"))
            .unwrap_or_else(|| format!("IMEI ({}B)", id.length)),
        Some(MobileIdentityType::Imeisv) => id
            .as_imeisv()
            .map(|s| format!("IMEISV ({s})"))
            .unwrap_or_else(|| format!("IMEISV ({}B)", id.length)),
        Some(t) => format!("{:?} ({}B)", t, id.length),
        None => format!("Unknown ({}B)", id.length),
    }
}

fn format_gmm_cause(value: u8) -> String {
    let cause = NasFGmmCause::new(value);
    match cause.cause() {
        Some(c) => format!("0x{:02X} ({})", value, c.description()),
        None => format!("0x{value:02X}"),
    }
}

fn format_gsm_cause(value: u8) -> String {
    let cause_ie = NasFGsmCause {
        type_field: 0,
        value,
    };
    match cause_ie.cause() {
        Some(c) => format!("0x{:02X} ({})", value, c.description()),
        None => format!("0x{value:02X}"),
    }
}

fn format_ue_sec_cap(cap: &NasUeSecurityCapability) -> String {
    let mut ea = Vec::new();
    let mut ia = Vec::new();
    for i in 0..=7 {
        if cap.supports_ea(i) {
            ea.push(format!("EA{i}"));
        }
        if cap.supports_ia(i) {
            ia.push(format!("IA{i}"));
        }
    }
    format!("{} / {}", ea.join(" "), ia.join(" "))
}

// ============================================================================
// Typed IE display
// ============================================================================

impl fmt::Display for Guti {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "5G-GUTI (PLMN={}, AMF={}/{}/{}, TMSI={:#010X})",
            self.plmn, self.amf_region_id, self.amf_set_id, self.amf_pointer, self.tmsi
        )
    }
}

impl fmt::Display for STmsi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "5G-S-TMSI (set={}, ptr={}, TMSI={:#010X})",
            self.amf_set_id, self.amf_pointer, self.tmsi
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_types_and_guti_display_like_eps() {
        assert_eq!(
            Nas5gmmMessageType::RegistrationRequest.to_string(),
            "RegistrationRequest"
        );
        assert_eq!(
            Nas5gsmMessageType::PduSessionEstablishmentRequest.to_string(),
            "PduSessionEstablishmentRequest"
        );
        let guti = Guti {
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0f],
            },
            amf_region_id: 2,
            amf_set_id: 64,
            amf_pointer: 0,
            tmsi: 0xcafe_babe,
        };
        assert_eq!(
            guti.to_string(),
            "5G-GUTI (PLMN=208/93, AMF=2/64/0, TMSI=0xCAFEBABE)"
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
        let rendered = format!("{envelope}");
        assert!(rendered.contains("UPDS"));
        assert!(rendered.contains("UePolicyProvisioningReject"));
        assert!(rendered.contains("0x06"));
    }
}
