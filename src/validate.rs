/*
   OxiRush — NAS Message Validation
   Checks structural correctness per TS 24.501.
*/

//! Structural validation for NAS messages per TS 24.501.
//!
//! The [`Validate`] trait returns a list of [`ValidationError`]s, each tagged with
//! a [`Severity`] (Error or Warning). An empty list means the message is structurally
//! correct according to the spec.
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::{decode_nas_5gs_message, Validate};
//!
//! let bytes = hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
//! let msg = decode_nas_5gs_message(&bytes).unwrap();
//! let errors = msg.validate();
//! assert!(errors.is_empty(), "Validation errors: {:?}", errors);
//! ```

use crate::ie::*;
use crate::messages::*;
use crate::types::*;
use std::fmt;

/// A single validation finding against a NAS message or IE.
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Whether this is a hard error or a warning.
    pub severity: Severity,
    /// The field or IE name that triggered the finding.
    pub field: &'static str,
    /// Human-readable description of the issue.
    pub message: String,
}

/// Severity level for validation findings.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Message will be rejected by a compliant peer.
    Error,
    /// Message is technically valid but may cause interoperability issues.
    Warning,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:?}] {}: {}", self.severity, self.field, self.message)
    }
}

/// Trait for validating NAS messages and IEs against TS 24.501 structural rules.
///
/// Returns an empty `Vec` if the message is valid.
pub trait Validate {
    /// Check structural correctness and return any findings.
    fn validate(&self) -> Vec<ValidationError>;
}

// ============================================================================
// Top-level dispatch
// ============================================================================

impl Validate for Nas5gsMessage {
    fn validate(&self) -> Vec<ValidationError> {
        match self {
            Nas5gsMessage::Gmm(hdr, msg) => {
                let mut errs = Vec::new();
                if hdr.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "EPD",
                        message: format!(
                            "Expected 0x7E for 5GMM, got 0x{:02X}",
                            hdr.extended_protocol_discriminator
                        ),
                    });
                }
                errs.extend(msg.validate());
                errs
            }
            Nas5gsMessage::Gsm(hdr, msg) => {
                let mut errs = Vec::new();
                if hdr.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "EPD",
                        message: format!(
                            "Expected 0x2E for 5GSM, got 0x{:02X}",
                            hdr.extended_protocol_discriminator
                        ),
                    });
                }
                if hdr.pdu_session_identity == 0 || hdr.pdu_session_identity > 15 {
                    errs.push(ValidationError {
                        severity: Severity::Warning,
                        field: "PDU Session ID",
                        message: format!(
                            "Invalid PDU session identity {}",
                            hdr.pdu_session_identity
                        ),
                    });
                }
                errs.extend(msg.validate());
                errs
            }
            Nas5gsMessage::SecurityProtected(hdr, inner) => {
                let mut errs = Vec::new();
                if hdr.security_header_type
                    == crate::message_types::Nas5gsSecurityHeaderType::PlainNasMessage
                {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "SHT",
                        message: "SecurityProtected wrapper has SHT=PlainNasMessage".into(),
                    });
                }
                errs.extend(inner.validate());
                errs
            }
        }
    }
}

impl Validate for Nas5gmmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        match self {
            Self::RegistrationRequest(m) => m.validate(),
            Self::RegistrationAccept(m) => m.validate(),
            Self::RegistrationReject(m) => m.validate(),
            Self::AuthenticationRequest(m) => m.validate(),
            Self::AuthenticationFailure(m) => m.validate(),
            Self::SecurityModeCommand(m) => m.validate(),
            Self::SecurityModeComplete(m) => m.validate(),
            Self::IdentityRequest(m) => m.validate(),
            Self::IdentityResponse(m) => m.validate(),
            Self::ServiceRequest(m) => m.validate(),
            Self::UlNasTransport(m) => m.validate(),
            Self::DlNasTransport(m) => m.validate(),
            _ => Vec::new(), // Remaining messages have minimal structure to validate
        }
    }
}

impl Validate for Nas5gsmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        match self {
            Self::PduSessionEstablishmentRequest(m) => m.validate(),
            Self::PduSessionEstablishmentAccept(m) => m.validate(),
            Self::PduSessionEstablishmentReject(m) => m.validate(),
            _ => Vec::new(),
        }
    }
}

// ============================================================================
// Individual messages
// ============================================================================

impl Validate for NasRegistrationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        // Registration type must be 1-7
        let reg_type = self.fgs_registration_type.value & 0x07;
        if reg_type == 0 || self.fgs_registration_type.registration_type().is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "5GS registration type",
                message: format!("Invalid registration type value {}", reg_type),
            });
        }

        // Mobile identity must not be empty
        if self.fgs_mobile_identity.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "5GS mobile identity",
                message: "Mobile identity is empty".into(),
            });
        } else {
            let id_type = self.fgs_mobile_identity.value[0] & 0x07;
            // RegistrationRequest only allows SUCI (1), GUTI (2), or 5G-S-TMSI (4) for initial
            if id_type != 0x01 && id_type != 0x02 {
                errs.push(ValidationError {
                    severity: Severity::Warning,
                    field: "5GS mobile identity",
                    message: format!(
                        "Unusual identity type {} for registration (expected SUCI=1 or GUTI=2)",
                        id_type
                    ),
                });
            }
        }

        // UE security capability minimum 2 bytes
        if let Some(ref cap) = self.ue_security_capability {
            if cap.value.len() < 2 {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "UE security capability",
                    message: format!("Must be at least 2 bytes (EA+IA), got {}", cap.value.len()),
                });
            }
        }

        errs
    }
}

impl Validate for NasRegistrationAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        // Registration result must not be empty
        if self.fgs_registration_result.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "5GS registration result",
                message: "Registration result value is empty".into(),
            });
        }

        errs
    }
}

impl Validate for NasRegistrationReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if NasFGmmCause::new(self.fgmm_cause.value).cause().is_none() {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "5GMM cause",
                message: format!("Unknown 5GMM cause code 0x{:02X}", self.fgmm_cause.value),
            });
        }
        errs
    }
}

impl Validate for NasAuthenticationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        // ABBA is mandatory (minimum 2 bytes)
        if self.abba.value.len() < 2 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "ABBA",
                message: format!(
                    "ABBA must be at least 2 bytes, got {}",
                    self.abba.value.len()
                ),
            });
        }

        // RAND must be exactly 16 bytes if present
        if let Some(ref rand) = self.authentication_parameter_rand {
            if rand.value.len() != 16 {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "RAND",
                    message: format!("RAND must be 16 bytes, got {}", rand.value.len()),
                });
            }
        }

        // AUTN must be exactly 16 bytes if present
        if let Some(ref autn) = self.authentication_parameter_autn {
            if autn.value.len() != 16 {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "AUTN",
                    message: format!("AUTN must be 16 bytes, got {}", autn.value.len()),
                });
            }
        }

        errs
    }
}

impl Validate for NasAuthenticationFailure {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        // If cause is SynchFailure (0x15), AUTS must be present
        if self.fgmm_cause.value == 0x15 {
            if self.authentication_failure_parameter.is_none() {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "Authentication failure parameter",
                    message: "AUTS is required when cause is SynchFailure (0x15)".into(),
                });
            } else if let Some(ref auts) = self.authentication_failure_parameter {
                if auts.value.len() != 14 {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "Authentication failure parameter",
                        message: format!("AUTS must be 14 bytes, got {}", auts.value.len()),
                    });
                }
            }
        }

        errs
    }
}

impl Validate for NasSecurityModeCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        let sa = &self.selected_nas_security_algorithms;
        if sa.ciphering().is_none() {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "Selected NAS security algorithms",
                message: format!("Unknown ciphering algorithm 0x{:X}", (sa.value >> 4) & 0x0F),
            });
        }
        if sa.integrity().is_none() {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "Selected NAS security algorithms",
                message: format!("Unknown integrity algorithm 0x{:X}", sa.value & 0x0F),
            });
        }
        // NIA0 is generally not allowed per TS 33.501 §5.5.1.2,
        // except for emergency registration and unauthenticated emergency services
        if sa.integrity() == Some(IntegrityAlgorithm::NIA0) {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "Selected NAS security algorithms",
                message: "NIA0 (null integrity) selected — only valid for emergency services per TS 33.501 §5.5.1.2".into(),
            });
        }

        // Replayed UE security capability minimum 2 bytes
        if self.replayed_ue_security_capabilities.value.len() < 2 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Replayed UE security capabilities",
                message: format!(
                    "Must be at least 2 bytes, got {}",
                    self.replayed_ue_security_capabilities.value.len()
                ),
            });
        }

        errs
    }
}

impl Validate for NasSecurityModeComplete {
    fn validate(&self) -> Vec<ValidationError> {
        // NAS message container should be present for initial registration
        // (contains the initial RegistrationRequest), but it's technically optional
        Vec::new()
    }
}

impl Validate for NasIdentityRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        let id_type = self.identity_type.value & 0x07;
        if id_type == 0 || id_type > 7 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Identity type",
                message: format!("Invalid identity type {}", id_type),
            });
        }
        errs
    }
}

impl Validate for NasIdentityResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.mobile_identity.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Mobile identity",
                message: "Mobile identity is empty".into(),
            });
        }
        errs
    }
}

impl Validate for NasServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.fg_s_tmsi.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "5G-S-TMSI",
                message: "5G-S-TMSI is empty".into(),
            });
        }
        errs
    }
}

impl Validate for NasUlNasTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        // Payload container type 1 (N1 SM) requires PDU session ID
        if self.payload_container_type.is_n1_sm() && self.pdu_session_id.is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "PDU session ID",
                message: "PDU session ID is required for N1 SM payload".into(),
            });
        }

        if self.payload_container.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container",
                message: "Payload container is empty".into(),
            });
        }

        errs
    }
}

impl Validate for NasDlNasTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        if self.payload_container_type.is_n1_sm() && self.pdu_session_id.is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "PDU session ID",
                message: "PDU session ID is required for N1 SM payload".into(),
            });
        }

        if self.payload_container.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container",
                message: "Payload container is empty".into(),
            });
        }

        errs
    }
}

impl Validate for NasPduSessionEstablishmentRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        // Integrity protection max data rate is mandatory (2 bytes)
        // It's always present by construction, so just check the value
        if self.integrity_protection_maximum_data_rate.value == 0 {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "Integrity protection maximum data rate",
                message: "Data rate is 0".into(),
            });
        }
        errs
    }
}

impl Validate for NasPduSessionEstablishmentAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        // QoS rules must not be empty
        if self.authorized_qos_rules.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Authorized QoS rules",
                message: "QoS rules are empty".into(),
            });
        }

        // Session-AMBR must be 6 bytes
        if self.session_ambr.value.len() != 6 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Session-AMBR",
                message: format!(
                    "Session-AMBR must be 6 bytes, got {}",
                    self.session_ambr.value.len()
                ),
            });
        }

        errs
    }
}

impl Validate for NasPduSessionEstablishmentReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        let cause_ie = NasFGsmCause {
            type_field: 0,
            value: self.fgsm_cause.value,
        };
        if cause_ie.cause().is_none() {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "5GSM cause",
                message: format!("Unknown 5GSM cause code 0x{:02X}", self.fgsm_cause.value),
            });
        }
        errs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_registration_request() {
        let msg = NasRegistrationRequest::new(
            NasFGsRegistrationType::new(0x79), // FOR=1, initial, ngKSI=7
            NasFGsMobileIdentity::new(vec![0x01, 0x02, 0x03, 0x04, 0x05]), // SUCI
        );
        let errs = msg.validate();
        assert!(errs.is_empty(), "Unexpected errors: {:?}", errs);
    }

    #[test]
    fn test_invalid_registration_type() {
        let msg = NasRegistrationRequest::new(
            NasFGsRegistrationType::new(0x00), // Invalid: type=0
            NasFGsMobileIdentity::new(vec![0x01, 0x02]),
        );
        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "5GS registration type" && e.severity == Severity::Error)
        );
    }

    #[test]
    fn test_invalid_abba_length() {
        let msg = NasAuthenticationRequest::new(
            NasKeySetIdentifier::new(0),
            NasAbba::new(vec![0x00]), // Only 1 byte, need 2
        );
        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "ABBA" && e.severity == Severity::Error)
        );
    }

    #[test]
    fn test_nia0_rejected() {
        let msg = NasSecurityModeCommand::new(
            NasSecurityAlgorithms::new(0x20), // NEA2 + NIA0
            NasKeySetIdentifier::new(0),
            NasUeSecurityCapability::new(vec![0xE0, 0xE0]),
        );
        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.message.contains("NIA0") && e.severity == Severity::Warning)
        );
    }

    #[test]
    fn test_synch_failure_needs_auts() {
        let msg = NasAuthenticationFailure::new(NasFGmmCause::new(0x15)); // SynchFailure, no AUTS
        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "Authentication failure parameter")
        );
    }

    #[test]
    fn test_ul_nas_transport_needs_psi() {
        let msg = NasUlNasTransport::new(
            NasPayloadContainerType::new(0x01), // N1 SM
            NasPayloadContainer::new(vec![0x2E, 0x01, 0x01, 0xC1]),
        );
        // No PDU session ID set
        let errs = msg.validate();
        assert!(errs.iter().any(|e| e.field == "PDU session ID"));
    }
}
