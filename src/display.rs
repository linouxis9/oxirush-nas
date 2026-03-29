/*
    OxiRush — Human-Readable NAS Message Display
    Wireshark-style formatting for debugging and logging.
 */

use std::fmt;
use crate::ie::*;
use crate::message_types::*;
use crate::messages::*;
use crate::types::*;

// ============================================================================
// Top-level message
// ============================================================================

impl fmt::Display for Nas5gsMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Nas5gsMessage::Gmm(hdr, msg) => {
                write!(f, "5GMM {}", msg)
            }
            Nas5gsMessage::Gsm(hdr, msg) => {
                write!(f, "5GSM (PSI={}, PTI={}) {}", hdr.pdu_session_identity, hdr.procedure_transaction_identity, msg)
            }
            Nas5gsMessage::SecurityProtected(hdr, inner) => {
                write!(f, "SecurityProtected (SHT={:?}, MAC={:#010x}, SN={}) {}",
                    hdr.security_header_type, hdr.message_authentication_code, hdr.sequence_number, inner)
            }
        }
    }
}

// ============================================================================
// 5GMM Message enum
// ============================================================================

impl fmt::Display for Nas5gmmMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RegistrationRequest(m) => write!(f, "{}", m),
            Self::RegistrationAccept(m) => write!(f, "{}", m),
            Self::RegistrationComplete(_) => write!(f, "RegistrationComplete"),
            Self::RegistrationReject(m) => write!(f, "{}", m),
            Self::DeregistrationRequestFromUe(m) => write!(f, "{}", m),
            Self::DeregistrationRequestToUe(m) => write!(f, "{}", m),
            Self::DeregistrationAcceptFromUe(_) => write!(f, "DeregistrationAcceptFromUe"),
            Self::DeregistrationAcceptToUe(_) => write!(f, "DeregistrationAcceptToUe"),
            Self::ConfigurationUpdateComplete(_) => write!(f, "ConfigurationUpdateComplete"),
            Self::ServiceRequest(m) => write!(f, "{}", m),
            Self::ServiceReject(m) => write!(f, "{}", m),
            Self::ServiceAccept(m) => write!(f, "{}", m),
            Self::ConfigurationUpdateCommand(m) => write!(f, "{}", m),
            Self::AuthenticationRequest(m) => write!(f, "{}", m),
            Self::AuthenticationResponse(m) => write!(f, "{}", m),
            Self::AuthenticationReject(_) => write!(f, "AuthenticationReject"),
            Self::AuthenticationFailure(m) => write!(f, "{}", m),
            Self::AuthenticationResult(m) => write!(f, "{}", m),
            Self::IdentityRequest(m) => write!(f, "{}", m),
            Self::IdentityResponse(m) => write!(f, "{}", m),
            Self::SecurityModeCommand(m) => write!(f, "{}", m),
            Self::SecurityModeComplete(m) => write!(f, "{}", m),
            Self::SecurityModeReject(m) => write!(f, "{}", m),
            Self::FGmmStatus(m) => write!(f, "{}", m),
            Self::Notification(m) => write!(f, "{}", m),
            Self::NotificationResponse(_) => write!(f, "NotificationResponse"),
            Self::UlNasTransport(m) => write!(f, "{}", m),
            Self::DlNasTransport(m) => write!(f, "{}", m),
        }
    }
}

// ============================================================================
// 5GSM Message enum
// ============================================================================

impl fmt::Display for Nas5gsmMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PduSessionEstablishmentRequest(m) => write!(f, "{}", m),
            Self::PduSessionEstablishmentAccept(m) => write!(f, "{}", m),
            Self::PduSessionEstablishmentReject(m) => write!(f, "{}", m),
            Self::PduSessionAuthenticationCommand(_) => write!(f, "PduSessionAuthenticationCommand"),
            Self::PduSessionAuthenticationComplete(_) => write!(f, "PduSessionAuthenticationComplete"),
            Self::PduSessionAuthenticationResult(_) => write!(f, "PduSessionAuthenticationResult"),
            Self::PduSessionModificationRequest(_) => write!(f, "PduSessionModificationRequest"),
            Self::PduSessionModificationReject(m) => write!(f, "PduSessionModificationReject (cause={})", format_gsm_cause(m.fgsm_cause.value)),
            Self::PduSessionModificationCommand(_) => write!(f, "PduSessionModificationCommand"),
            Self::PduSessionModificationComplete(_) => write!(f, "PduSessionModificationComplete"),
            Self::PduSessionModificationCommandReject(m) => write!(f, "PduSessionModificationCommandReject (cause={})", format_gsm_cause(m.fgsm_cause.value)),
            Self::PduSessionReleaseRequest(_) => write!(f, "PduSessionReleaseRequest"),
            Self::PduSessionReleaseReject(m) => write!(f, "PduSessionReleaseReject (cause={})", format_gsm_cause(m.fgsm_cause.value)),
            Self::PduSessionReleaseCommand(m) => write!(f, "PduSessionReleaseCommand (cause={})", format_gsm_cause(m.fgsm_cause.value)),
            Self::PduSessionReleaseComplete(_) => write!(f, "PduSessionReleaseComplete"),
            Self::FGsmStatus(m) => write!(f, "5GSM Status (cause={})", format_gsm_cause(m.fgsm_cause.value)),
        }
    }
}

// ============================================================================
// Individual 5GMM messages
// ============================================================================

impl fmt::Display for NasRegistrationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rt = &self.fgs_registration_type;
        let reg_type_str = rt.registration_type()
            .map(|r| format!("{:?}", r))
            .unwrap_or_else(|| format!("0x{:02X}", rt.value & 0x07));
        write!(f, "RegistrationRequest (type={}, FOR={}, ngKSI={}",
            reg_type_str,
            if rt.follow_on_request() { "1" } else { "0" },
            rt.ngksi())?;
        write!(f, ", identity={}", format_mobile_identity(&self.fgs_mobile_identity))?;
        if let Some(ref cap) = self.ue_security_capability {
            write!(f, ", UE-SecCap={}", format_ue_sec_cap(cap))?;
        }
        if let Some(ref nssai) = self.requested_nssai {
            write!(f, ", NSSAI={}B", nssai.length)?;
        }
        if let Some(ref status) = self.pdu_session_status {
            let s = NasPduSessionStatus { type_field: 0, length: status.length, value: status.value.clone() };
            let active = s.active_sessions();
            if !active.is_empty() {
                write!(f, ", PDU-sessions={:?}", active)?;
            }
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasRegistrationAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result_val = self.fgs_registration_result.result_value();
        write!(f, "RegistrationAccept (result=0x{:02X}", result_val)?;
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
        write!(f, "RegistrationReject (cause={})", format_gmm_cause(self.fgmm_cause.value))
    }
}

impl fmt::Display for NasDeregistrationRequestFromUe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dt = &self.de_registration_type;
        write!(f, "DeregistrationRequestFromUe (switch_off={}, access_type={}, identity={})",
            if dt.switch_off() { "1" } else { "0" },
            dt.access_type(),
            format_mobile_identity(&self.fgs_mobile_identity))
    }
}

impl fmt::Display for NasDeregistrationRequestToUe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dt = &self.de_registration_type;
        write!(f, "DeregistrationRequestToUe (re_reg={}, access_type={}",
            if dt.re_registration_required() { "1" } else { "0" },
            dt.access_type())?;
        if let Some(ref cause) = self.fgmm_cause {
            write!(f, ", cause={}", format_gmm_cause(cause.value))?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasServiceRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceRequest (5G-S-TMSI={})", format_mobile_identity(&self.fg_s_tmsi))
    }
}

impl fmt::Display for NasServiceReject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceReject (cause={})", format_gmm_cause(self.fgmm_cause.value))
    }
}

impl fmt::Display for NasServiceAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceAccept")?;
        if let Some(ref status) = self.pdu_session_status {
            let s = NasPduSessionStatus { type_field: 0, length: status.length, value: status.value.clone() };
            let active = s.active_sessions();
            if !active.is_empty() {
                write!(f, " (PDU-sessions={:?})", active)?;
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
        write!(f, "AuthenticationFailure (cause={})", format_gmm_cause(self.fgmm_cause.value))?;
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
        let id_type = self.identity_type.identity_type()
            .map(|t| format!("{:?}", t))
            .unwrap_or_else(|| format!("0x{:02X}", self.identity_type.value & 0x07));
        write!(f, "IdentityRequest (type={})", id_type)
    }
}

impl fmt::Display for NasIdentityResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IdentityResponse (identity={})", format_mobile_identity(&self.mobile_identity))
    }
}

impl fmt::Display for NasSecurityModeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sa = &self.selected_nas_security_algorithms;
        let cipher_str = sa.ciphering().map(|c| format!("{:?}", c)).unwrap_or_else(|| "?".into());
        let integ_str = sa.integrity().map(|i| format!("{:?}", i)).unwrap_or_else(|| "?".into());
        write!(f, "SecurityModeCommand (cipher={}, integrity={}, ngKSI={})",
            cipher_str, integ_str, self.ngksi.ngksi())
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
        write!(f, "SecurityModeReject (cause={})", format_gmm_cause(self.fgmm_cause.value))
    }
}

impl fmt::Display for NasFGmmStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "5GMM Status (cause={})", format_gmm_cause(self.fgmm_cause.value))
    }
}

impl fmt::Display for NasNotification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Notification (access_type=0x{:02X})", self.access_type.value)
    }
}

impl fmt::Display for NasUlNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind_str = self.payload_container_type.kind()
            .map(|k| format!("{:?}", k))
            .unwrap_or_else(|| format!("0x{:02X}", self.payload_container_type.value));
        write!(f, "UlNasTransport (type={}, {}B", kind_str, self.payload_container.length)?;
        if let Some(ref id) = self.pdu_session_id {
            write!(f, ", PSI={}", id.value)?;
        }
        if let Some(ref dnn) = self.dnn {
            let dnn_ie = NasDnn { type_field: 0, length: dnn.length, value: dnn.value.clone() };
            if let Some(s) = dnn_ie.as_string() {
                write!(f, ", DNN={}", s)?;
            }
        }
        write!(f, ")")
    }
}

impl fmt::Display for NasDlNasTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind_str = self.payload_container_type.kind()
            .map(|k| format!("{:?}", k))
            .unwrap_or_else(|| format!("0x{:02X}", self.payload_container_type.value));
        write!(f, "DlNasTransport (type={}, {}B", kind_str, self.payload_container.length)?;
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
        write!(f, "PduSessionEstablishmentAccept (type=0x{:X}, QoS-rules={}B, S-AMBR={}B",
            self.selected_pdu_session_type.value & 0x07,
            self.authorized_qos_rules.length,
            self.session_ambr.length)?;
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
        write!(f, "PduSessionEstablishmentReject (cause={})", format_gsm_cause(self.fgsm_cause.value))
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn format_mobile_identity(id: &NasFGsMobileIdentity) -> String {
    match id.identity_type() {
        Some(MobileIdentityType::Suci) => {
            if let Some(suci) = id.as_suci() {
                let plmn = PlmnId { mcc: suci.mcc, mnc: suci.mnc };
                format!("SUCI (PLMN={}{}, scheme={})",
                    plmn.mcc_string(), plmn.mnc_string(), suci.protection_scheme)
            } else {
                format!("SUCI ({}B)", id.length)
            }
        }
        Some(MobileIdentityType::Guti) => {
            if let Some(guti) = id.as_guti() {
                let plmn = PlmnId { mcc: guti.mcc, mnc: guti.mnc };
                format!("5G-GUTI (PLMN={}{}, TMSI={:#010X})",
                    plmn.mcc_string(), plmn.mnc_string(), guti.tmsi)
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
        Some(MobileIdentityType::Imei) => {
            id.as_imei()
                .map(|s| format!("IMEI ({})", s))
                .unwrap_or_else(|| format!("IMEI ({}B)", id.length))
        }
        Some(MobileIdentityType::Imeisv) => {
            id.as_imeisv()
                .map(|s| format!("IMEISV ({})", s))
                .unwrap_or_else(|| format!("IMEISV ({}B)", id.length))
        }
        Some(t) => format!("{:?} ({}B)", t, id.length),
        None => format!("Unknown ({}B)", id.length),
    }
}

fn format_gmm_cause(value: u8) -> String {
    let cause = NasFGmmCause::new(value);
    match cause.cause() {
        Some(c) => format!("0x{:02X} ({})", value, c.description()),
        None => format!("0x{:02X}", value),
    }
}

fn format_gsm_cause(value: u8) -> String {
    let cause_ie = NasFGsmCause { type_field: 0, value };
    match cause_ie.cause() {
        Some(c) => format!("0x{:02X} ({})", value, c.description()),
        None => format!("0x{:02X}", value),
    }
}

fn format_ue_sec_cap(cap: &NasUeSecurityCapability) -> String {
    let mut ea = Vec::new();
    let mut ia = Vec::new();
    for i in 0..=7 {
        if cap.supports_ea(i) { ea.push(format!("EA{}", i)); }
        if cap.supports_ia(i) { ia.push(format!("IA{}", i)); }
    }
    format!("{} / {}", ea.join(" "), ia.join(" "))
}

// ============================================================================
// Typed IE display
// ============================================================================

impl fmt::Display for Guti {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let plmn = PlmnId { mcc: self.mcc, mnc: self.mnc };
        write!(f, "5G-GUTI (PLMN={}{}, AMF={}/{}/{}, TMSI={:#010X})",
            plmn.mcc_string(), plmn.mnc_string(),
            self.amf_region_id, self.amf_set_id, self.amf_pointer, self.tmsi)
    }
}

impl fmt::Display for STmsi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "5G-S-TMSI (set={}, ptr={}, TMSI={:#010X})",
            self.amf_set_id, self.amf_pointer, self.tmsi)
    }
}

impl fmt::Display for PlmnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.mcc_string(), self.mnc_string())
    }
}
