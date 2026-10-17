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

//! Human-readable `fmt::Display` implementations for NAS messages and key IEs.
//!
//! Provides Wireshark-style formatting useful for debugging and logging.
//! All top-level messages implement `Display`, and many commonly used
//! individual 5GMM/5GSM message structs plus key IE structs (GUTI, S-TMSI,
//! PLMN) provide dedicated formatting as well. An identity is printed
//! whole: what goes to a log is the caller's choice.
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//!
//! let bytes = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000").unwrap();
//! let msg = Nas5gsMessage::decode(&bytes).unwrap();
//! println!("{msg}");
//! // => 5GMM RegistrationRequest (type=InitialRegistration, ..., identity=SUCI (PLMN=208-93, ..., MSIN=0000000120), ...)
//! ```

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
            self.ngksi.ksi()
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
            write!(f, ", NSSAI={}B", nssai.value.len())?;
        }
        if let Some(ref status) = self.pdu_session_status {
            let active = status.active_sessions();
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
            write!(f, ", TAI-list={}B", tai.value.len())?;
        }
        if let Some(ref nssai) = self.allowed_nssai {
            write!(f, ", Allowed-NSSAI={}B", nssai.value.len())?;
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

impl fmt::Display for NasDeregistrationRequestUeOriginating {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dt = &self.de_registration_type;
        write!(
            f,
            "DeregistrationRequestUeOriginating (switch_off={}, access_type={:?}, identity={})",
            if dt.switch_off() { "1" } else { "0" },
            dt.access_type(),
            format_mobile_identity(&self.fgs_mobile_identity)
        )
    }
}

impl fmt::Display for NasDeregistrationRequestUeTerminated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dt = &self.de_registration_type;
        write!(
            f,
            "DeregistrationRequestUeTerminated (re_reg={}, access_type={:?}",
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
            "ServiceRequest (identity={})",
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
            let active = status.active_sessions();
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
        write!(f, "AuthenticationRequest (ngKSI={}", self.ngksi.ksi())?;
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
            write!(f, " (RES*={}B)", res.value.len())?;
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
        write!(f, "AuthenticationResult (ngKSI={})", self.ngksi.ksi())
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
            self.ngksi.ksi()
        )
    }
}

impl fmt::Display for NasSecurityModeComplete {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecurityModeComplete")?;
        // The identities that the message has, each whole.
        let identities = [&self.imeisv, &self.non_imeisv_pei];
        let identities: Vec<String> = (identities.into_iter().flatten())
            .map(format_mobile_identity)
            .collect();
        if !identities.is_empty() {
            write!(f, " (identity={})", identities.join(", "))?;
        }
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
            kind_str,
            self.payload_container.value.len()
        )?;
        if let Some(ref id) = self.pdu_session_id {
            write!(f, ", PSI={}", id.value)?;
        }
        if let Some(ref dnn) = self.dnn
            && let Some(s) = dnn.as_string()
        {
            write!(f, ", DNN={s}")?;
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
            kind_str,
            self.payload_container.value.len()
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
            self.authorized_qos_rules.value.len(),
            self.session_ambr.value.len()
        )?;
        if let Some(ref cause) = self.fgsm_cause {
            write!(f, ", cause={}", format_gsm_cause(cause.value))?;
        }
        if let Some(ref addr) = self.pdu_address {
            write!(f, ", addr={}B", addr.value.len())?;
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
    NasDeregistrationAcceptUeOriginating => "DeregistrationAcceptUeOriginating",
    NasDeregistrationAcceptUeTerminated => "DeregistrationAcceptUeTerminated",
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

/// A mobile identity, whole: every part that the IE has of it, and the
/// octets of one that does not read as an identity of its type.
fn format_mobile_identity(id: &NasFGsMobileIdentity) -> String {
    let octets = || hex::encode(&id.value[..]);
    match id.identity_type() {
        Some(MobileIdentityType::Suci) => match id.as_suci() {
            Some(Suci::Imsi(suci)) => {
                // The scheme output of the null scheme is the MSIN.
                let output = match (suci.msin(), suci.concealed_output()) {
                    (Some(msin), _) => format!("MSIN={msin}"),
                    (_, output) => format!("scheme-output={}", hex::encode(output.unwrap_or(&[]))),
                };
                format!(
                    "SUCI (PLMN={}, routing-indicator={}, scheme={}, key={}, {output})",
                    suci.plmn(),
                    suci.routing_indicator(),
                    suci.protection_scheme().identifier(),
                    suci.home_network_public_key_identifier(),
                )
            }
            Some(Suci::Nai(suci)) => format!("SUCI ({:?}, {suci})", suci.supi_type()),
            None => format!("SUCI ({})", octets()),
        },
        Some(MobileIdentityType::Guti) => match id.as_guti() {
            Some(guti) => format_guti(&guti),
            None => format!("5G-GUTI ({})", octets()),
        },
        Some(MobileIdentityType::STmsi) => match id.as_s_tmsi() {
            Some(s_tmsi) => format_s_tmsi(&s_tmsi),
            None => format!("5G-S-TMSI ({})", octets()),
        },
        Some(MobileIdentityType::Imei) => match id.as_imei() {
            Some(digits) => format!("IMEI ({digits})"),
            None => format!("IMEI ({})", octets()),
        },
        Some(MobileIdentityType::Imeisv) => match id.as_imeisv() {
            Some(digits) => format!("IMEISV ({digits})"),
            None => format!("IMEISV ({})", octets()),
        },
        Some(MobileIdentityType::MacAddress) => match (id.as_mac_address(), id.mauri()) {
            (Some(address), Some(true)) => {
                format!(
                    "MAC address ({}, not usable as an equipment identifier)",
                    hex::encode(address)
                )
            }
            (Some(address), _) => format!("MAC address ({})", hex::encode(address)),
            (None, _) => format!("MAC address ({})", octets()),
        },
        Some(MobileIdentityType::Eui64) => match id.as_eui64() {
            Some(identifier) => format!("EUI-64 ({})", hex::encode(identifier)),
            None => format!("EUI-64 ({})", octets()),
        },
        Some(MobileIdentityType::NoIdentity) => "no identity".into(),
        _ => format!("Unknown ({})", octets()),
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
    match NasFGsmCause::new(value).cause() {
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

/// A 5G-GUTI by its parts, in the words of TS 24.501.
fn format_guti(guti: &Guti) -> String {
    format!(
        "5G-GUTI (PLMN={}, AMF={}/{}/{}, TMSI={:#010X})",
        guti.plmn(),
        guti.amf_region_id(),
        guti.amf_set_id(),
        guti.amf_pointer(),
        guti.tmsi()
    )
}

/// A 5G-S-TMSI by its parts.
fn format_s_tmsi(s_tmsi: &STmsi) -> String {
    format!(
        "5G-S-TMSI (set={}, ptr={}, TMSI={:#010X})",
        s_tmsi.amf_set_id(),
        s_tmsi.amf_pointer(),
        s_tmsi.tmsi()
    )
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
        let plmn = Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap();
        let guti = Guti::new(plmn, 2, 64, 0, 0xcafe_babe).unwrap();
        assert_eq!(
            format_guti(&guti),
            "5G-GUTI (PLMN=208-93, AMF=2/64/0, TMSI=0xCAFEBABE)"
        );
        // The value itself prints as the service based interfaces write it
        assert_eq!(guti.to_string(), "5g-guti-20893021000cafebabe");
    }

    /// An identity is shown whole, in every message that shows one: every
    /// part that its IE has, and the octets of one that does not read as an
    /// identity of its type. A SUCI was shown without its MSIN, a
    /// 5G-S-TMSI without its AMF, a MAC address and an EUI-64 by their
    /// length, and the IMEISV of a SECURITY MODE COMPLETE not at all.
    #[test]
    fn an_identity_is_shown_whole() {
        let identity = |identity: NasFGsMobileIdentity| {
            let message = Nas5gsMessage::new_5gmm(NasIdentityResponse::new(identity));
            let line = message.to_string();
            let shown = line.strip_prefix("5GMM IdentityResponse (identity=");
            shown
                .and_then(|shown| shown.strip_suffix(')'))
                .unwrap()
                .to_string()
        };
        let plmn = Plmn::new("208", "93").unwrap();
        let routing_indicator = RoutingIndicator::new("123").unwrap();
        let null = ImsiSuci::null(plmn, routing_indicator, "1234567890").unwrap();
        let null = NasFGsMobileIdentity::from_suci(&Suci::Imsi(null));
        assert_eq!(
            identity(null.unwrap()),
            "SUCI (PLMN=208-93, routing-indicator=123, scheme=0, key=0, MSIN=1234567890)"
        );
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
            format!(
                "SUCI (PLMN=208-93, routing-indicator=123, scheme=1, key=1, scheme-output={})",
                "ab".repeat(45)
            )
        );
        let nai =
            NasFGsMobileIdentity::from_suci_nai("type1.rid678.schid0.useriduser17@example.com");
        assert_eq!(
            identity(nai.unwrap()),
            "SUCI (NetworkSpecific, type1.rid678.schid0.useriduser17@example.com)"
        );
        let imei = NasFGsMobileIdentity::from_imei("490154203237518").unwrap();
        assert_eq!(identity(imei), "IMEI (490154203237518)");
        let imeisv = NasFGsMobileIdentity::from_imeisv("4901542032375181").unwrap();
        assert_eq!(identity(imeisv.clone()), "IMEISV (4901542032375181)");
        let mac = NasFGsMobileIdentity::from_mac_address([1, 2, 3, 4, 5, 6]);
        assert_eq!(identity(mac.clone()), "MAC address (010203040506)");
        let eui = NasFGsMobileIdentity::from_eui64([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(identity(eui), "EUI-64 (0102030405060708)");
        let guti = Guti::new(Plmn::new("999", "70").unwrap(), 1, 1, 0, 0xc000_0001).unwrap();
        assert_eq!(
            identity(NasFGsMobileIdentity::from_guti(guti)),
            "5G-GUTI (PLMN=999-70, AMF=1/1/0, TMSI=0xC0000001)"
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
            "5GMM ServiceRequest (identity=5G-S-TMSI (set=1, ptr=0, TMSI=0xC0000001))"
        );
        let complete = NasSecurityModeComplete::new()
            .with_imeisv(imeisv)
            .with_non_imeisv_pei(mac);
        assert_eq!(
            Nas5gsMessage::new_5gmm(complete).to_string(),
            "5GMM SecurityModeComplete (identity=IMEISV (4901542032375181), MAC address \
             (010203040506))"
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
