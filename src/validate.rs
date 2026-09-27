/*
   OxiRush — NAS Message Validation
   Checks structural correctness per TS 24.501.
*/

//! Structural validation helpers for NAS messages against a common TS 24.501 subset.
//!
//! Byte-level IE invariants live on the IE helpers in [`crate::ie`]. This module
//! validates message/procedure structure and composes those IE-local strict
//! validators for fields that carry stricter TS 24.501 rules.
//!
//! The [`Validate`] trait returns a list of [`ValidationError`]s, each tagged with
//! a [`Severity`] (Error or Warning). An empty list means the message passed the
//! checks currently implemented by the crate; it does not imply full clause-by-clause
//! TS 24.501 validation for every message type.
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
use crate::upds::*;
use std::fmt;

/// A single validation finding against a NAS message or composed IE check.
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

/// Trait for validating NAS messages against the implemented TS 24.501 checks.
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
                if hdr.security_header_type
                    != crate::message_types::Nas5gsSecurityHeaderType::PlainNasMessage
                {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "SHT",
                        message: format!(
                            "Plain 5GMM message shall use SHT=PlainNasMessage, got {:?}",
                            hdr.security_header_type
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
                if hdr.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "EPD",
                        message: format!(
                            "Security-protected outer header must use 0x7E (5GMM), got 0x{:02X}",
                            hdr.extended_protocol_discriminator
                        ),
                    });
                }
                if hdr.security_header_type
                    == crate::message_types::Nas5gsSecurityHeaderType::PlainNasMessage
                {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "SHT",
                        message: "SecurityProtected wrapper has SHT=PlainNasMessage".into(),
                    });
                }
                match inner.as_ref() {
                    Nas5gsMessage::SecurityProtected(_, _) => errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "Plain NAS message",
                        message:
                            "Security-protected 5GS NAS message shall carry a plain inner 5GMM message"
                                .into(),
                    }),
                    Nas5gsMessage::Gsm(_, _) => errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "Plain NAS message",
                        message:
                            "Security-protected 5GS NAS message shall carry a plain inner 5GMM message; 5GSM messages are protected only via the enclosing 5GMM message"
                                .into(),
                    }),
                    Nas5gsMessage::Gmm(inner_hdr, inner_msg) => {
                        if inner_hdr.extended_protocol_discriminator
                            != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "Inner EPD",
                                message: format!(
                                    "Inner plain 5GMM message shall use EPD=0x7E, got 0x{:02X}",
                                    inner_hdr.extended_protocol_discriminator
                                ),
                            });
                        }
                        if inner_hdr.security_header_type
                            != crate::message_types::Nas5gsSecurityHeaderType::PlainNasMessage
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "Inner SHT",
                                message: format!(
                                    "Inner plain 5GMM message shall use SHT=PlainNasMessage, got {:?}",
                                    inner_hdr.security_header_type
                                ),
                            });
                        }
                        match hdr.security_header_type {
                            crate::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext
                                if !matches!(inner_msg, Nas5gmmMessage::SecurityModeCommand(_)) =>
                            {
                                errs.push(ValidationError {
                                    severity: Severity::Error,
                                    field: "SHT",
                                    message:
                                        "IntegrityProtectedWithNewContext is only valid for SecurityModeCommand per TS 24.501 Table 9.3.1 note 1"
                                            .into(),
                                });
                            }
                            crate::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                                if !matches!(inner_msg, Nas5gmmMessage::SecurityModeComplete(_)) =>
                            {
                                errs.push(ValidationError {
                                    severity: Severity::Error,
                                    field: "SHT",
                                    message:
                                        "IntegrityProtectedAndCipheredWithNewContext is only valid for SecurityModeComplete per TS 24.501 Table 9.3.1 note 2"
                                            .into(),
                                });
                            }
                            _ => {}
                        }
                    }
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
            Self::RegistrationComplete(m) => m.validate(),
            Self::RegistrationReject(m) => m.validate(),
            Self::DeregistrationRequestFromUe(m) => m.validate(),
            Self::DeregistrationRequestToUe(m) => m.validate(),
            Self::DeregistrationAcceptFromUe(m) => m.validate(),
            Self::DeregistrationAcceptToUe(m) => m.validate(),
            Self::ConfigurationUpdateComplete(m) => m.validate(),
            Self::ServiceReject(m) => m.validate(),
            Self::ServiceAccept(m) => m.validate(),
            Self::ConfigurationUpdateCommand(m) => m.validate(),
            Self::AuthenticationRequest(m) => m.validate(),
            Self::AuthenticationResponse(m) => m.validate(),
            Self::AuthenticationReject(m) => m.validate(),
            Self::AuthenticationFailure(m) => m.validate(),
            Self::AuthenticationResult(m) => m.validate(),
            Self::SecurityModeCommand(m) => m.validate(),
            Self::SecurityModeComplete(m) => m.validate(),
            Self::SecurityModeReject(m) => m.validate(),
            Self::IdentityRequest(m) => m.validate(),
            Self::IdentityResponse(m) => m.validate(),
            Self::FGmmStatus(m) => m.validate(),
            Self::Notification(m) => m.validate(),
            Self::NotificationResponse(m) => m.validate(),
            Self::ServiceRequest(m) => m.validate(),
            Self::UlNasTransport(m) => m.validate(),
            Self::DlNasTransport(m) => m.validate(),
            Self::ControlPlaneServiceRequest(m) => m.validate(),
            Self::NetworkSliceSpecificAuthenticationCommand(m) => m.validate(),
            Self::NetworkSliceSpecificAuthenticationComplete(m) => m.validate(),
            Self::NetworkSliceSpecificAuthenticationResult(m) => m.validate(),
            Self::RelayKeyRequest(m) => m.validate(),
            Self::RelayKeyAccept(m) => m.validate(),
            Self::RelayKeyReject(m) => m.validate(),
            Self::RelayAuthenticationRequest(m) => m.validate(),
            Self::RelayAuthenticationResponse(m) => m.validate(),
        }
    }
}

impl Validate for Nas5gsmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        match self {
            Self::PduSessionEstablishmentRequest(m) => m.validate(),
            Self::PduSessionEstablishmentAccept(m) => m.validate(),
            Self::PduSessionEstablishmentReject(m) => m.validate(),
            Self::PduSessionAuthenticationCommand(m) => m.validate(),
            Self::PduSessionAuthenticationComplete(m) => m.validate(),
            Self::PduSessionAuthenticationResult(m) => m.validate(),
            Self::PduSessionModificationRequest(m) => m.validate(),
            Self::PduSessionModificationReject(m) => m.validate(),
            Self::PduSessionModificationCommand(m) => m.validate(),
            Self::PduSessionModificationComplete(m) => m.validate(),
            Self::PduSessionModificationCommandReject(m) => m.validate(),
            Self::PduSessionReleaseRequest(m) => m.validate(),
            Self::PduSessionReleaseReject(m) => m.validate(),
            Self::PduSessionReleaseCommand(m) => m.validate(),
            Self::PduSessionReleaseComplete(m) => m.validate(),
            Self::FGsmStatus(m) => m.validate(),
            Self::ServiceLevelAuthenticationCommand(m) => m.validate(),
            Self::ServiceLevelAuthenticationComplete(m) => m.validate(),
            Self::RemoteUeReport(m) => m.validate(),
            Self::RemoteUeReportResponse(m) => m.validate(),
        }
    }
}

impl Validate for NasUpdsEnvelope {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = self.message.validate();
        let pti = self.procedure_transaction_identity_value();
        if pti.is_reserved() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UPDS PTI",
                message:
                    "Reserved UPDS procedure transaction identity; TS 24.501 Annex D says reserved values shall be ignored"
                        .into(),
            });
        }
        if pti.is_unassigned() {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "UPDS PTI",
                message:
                    "UPDS procedure transaction identity is unassigned (0x00); this is only meaningful when no procedure transaction is allocated"
                        .into(),
            });
        }
        if let Some(semantics) = self.message.semantics() {
            let expected_kind = match semantics.initiator {
                UpdsProcedureInitiator::Ue => UpdsProcedureTransactionIdentityKind::UeInitiated,
                UpdsProcedureInitiator::Network => {
                    UpdsProcedureTransactionIdentityKind::NetworkInitiated
                }
            };
            if pti.kind() != expected_kind {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "UPDS PTI",
                    message: format!(
                        "PTI {} does not match the {}-initiated {} semantics of {:?}",
                        pti,
                        match semantics.initiator {
                            UpdsProcedureInitiator::Ue => "UE",
                            UpdsProcedureInitiator::Network => "network",
                        },
                        match semantics.role {
                            UpdsProcedureRole::Command => "command",
                            UpdsProcedureRole::Request => "request",
                            UpdsProcedureRole::Response => "response",
                        },
                        self.message_type()
                    ),
                });
            }
        }
        errs
    }
}

impl Validate for NasUpdsMessage {
    fn validate(&self) -> Vec<ValidationError> {
        match self {
            Self::ManageUePolicyCommand(message) => message.validate(),
            Self::ManageUePolicyComplete(message) => message.validate(),
            Self::ManageUePolicyCommandReject(message) => message.validate(),
            Self::UeStateIndication(message) => message.validate(),
            Self::UePolicyProvisioningRequest(message) => message.validate(),
            Self::UePolicyProvisioningReject(message) => message.validate(),
            Self::Unsupported(message) => message.validate(),
        }
    }
}

impl Validate for NasManageUePolicyCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.ue_policy_section_management_list.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UE policy section management list",
                message: "Mandatory UE policy section management list is empty".into(),
            });
        }
        if let Some(network_classmark) = &self.ue_policy_network_classmark
            && network_classmark.value.len() != 1
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UE policy network classmark",
                message: "UE policy network classmark shall be one octet".into(),
            });
        }
        errs
    }
}

impl Validate for NasManageUePolicyComplete {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasManageUePolicyCommandReject {
    fn validate(&self) -> Vec<ValidationError> {
        if self.ue_policy_section_management_result.value.is_empty() {
            vec![ValidationError {
                severity: Severity::Error,
                field: "UE policy section management result",
                message: "Mandatory UE policy section management result is empty".into(),
            }]
        } else {
            Vec::new()
        }
    }
}

impl Validate for NasUeStateIndication {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.upsi_list.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UPSI list",
                message: "Mandatory UPSI list is empty".into(),
            });
        }
        if self.ue_policy_classmark.value.len() != 1 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UE policy classmark",
                message: "UE policy classmark shall be one octet".into(),
            });
        }
        if let Some(ue_os_id) = &self.ue_os_id {
            if ue_os_id.value.len() % 16 != 0 {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "UE OS Id",
                    message: "UE OS Id shall be a concatenation of 16-octet OS identifiers".into(),
                });
            }
            let os_id_count = ue_os_id.os_ids().len();
            if !(1..=15).contains(&os_id_count) {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "UE OS Id",
                    message: format!(
                        "UE OS Id shall contain between 1 and 15 OS identifiers, got {}",
                        os_id_count
                    ),
                });
            }
        }
        errs
    }
}

impl Validate for NasUePolicyProvisioningRequest {
    fn validate(&self) -> Vec<ValidationError> {
        if self.payload.is_empty() {
            vec![ValidationError {
                severity: Severity::Warning,
                field: "payload",
                message:
                    "UPDS UE policy provisioning request payload is empty; detailed body coding is delegated outside TS 24.501"
                        .into(),
            }]
        } else {
            Vec::new()
        }
    }
}

impl Validate for NasUePolicyProvisioningReject {
    fn validate(&self) -> Vec<ValidationError> {
        if self.payload.is_empty() {
            vec![ValidationError {
                severity: Severity::Warning,
                field: "payload",
                message:
                    "UPDS UE policy provisioning reject payload is empty; detailed body coding is delegated outside TS 24.501"
                        .into(),
            }]
        } else {
            Vec::new()
        }
    }
}

impl Validate for NasUnsupportedUpdsMessage {
    fn validate(&self) -> Vec<ValidationError> {
        vec![ValidationError {
            severity: Severity::Warning,
            field: "UPDS message type",
            message: format!(
                "Unsupported or unknown UPDS message type 0x{:02X}; Annex D says it shall be ignored by the receiver",
                self.message_type
            ),
        }]
    }
}

macro_rules! impl_validate_empty {
    ($($name:ty),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    Vec::new()
                }
            }
        )+
    };
}

fn push_ie_strict_result(
    errs: &mut Vec<ValidationError>,
    field: &'static str,
    result: crate::types::Result<()>,
) {
    if let Err(err) = result {
        errs.push(ValidationError {
            severity: Severity::Error,
            field,
            message: err.to_string(),
        });
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
        if let Some(ref cap) = self.ue_security_capability
            && cap.value.len() < 2
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UE security capability",
                message: format!("Must be at least 2 bytes (EA+IA), got {}", cap.value.len()),
            });
        }

        if let Some(capability) = &self.fgmm_capability {
            push_ie_strict_result(&mut errs, "5GMM capability", capability.validate_strict());
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
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

        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
        }
        if let Some(status) = &self.lp_wus_status {
            push_ie_strict_result(&mut errs, "LP-WUS status", status.validate_strict());
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
        if let Some(cause) = &self.extended_5gmm_cause {
            push_ie_strict_result(&mut errs, "Extended 5GMM cause", cause.validate_strict());
        }
        errs
    }
}

impl Validate for NasConfigurationUpdateCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
        }
        if let Some(status) = &self.lp_wus_status {
            push_ie_strict_result(&mut errs, "LP-WUS status", status.validate_strict());
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
        if let Some(ref rand) = self.authentication_parameter_rand
            && rand.value.len() != 16
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "RAND",
                message: format!("RAND must be 16 bytes, got {}", rand.value.len()),
            });
        }

        // AUTN must be exactly 16 bytes if present
        if let Some(ref autn) = self.authentication_parameter_autn
            && autn.value.len() != 16
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "AUTN",
                message: format!("AUTN must be 16 bytes, got {}", autn.value.len()),
            });
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
            } else if let Some(ref auts) = self.authentication_failure_parameter
                && auts.value.len() != 14
            {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "Authentication failure parameter",
                    message: format!("AUTS must be 14 bytes, got {}", auts.value.len()),
                });
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

impl Validate for NasControlPlaneServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        if self.ciot_small_data_container.is_some()
            && !self.ciot_small_data_container_is_exclusive()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "CIoT small data container",
                message: "CIoT small data container shall not be combined with other optional IEs"
                    .into(),
            });
        }

        if let Some(container) = &self.ciot_small_data_container {
            push_ie_strict_result(
                &mut errs,
                "CIoT small data container",
                container.validate_strict(),
            );
        }

        if self.payload_container.is_some() && self.payload_container_type.is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container type",
                message:
                    "Payload container type is required when the payload container IE is present"
                        .into(),
            });
        }

        if matches!(
            self.payload_container_type
                .as_ref()
                .and_then(|kind| kind.kind()),
            Some(PayloadContainerKind::CIoT)
        ) && self.pdu_session_id.is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "PDU session ID",
                message: "PDU session ID is required for a CIoT user data payload container".into(),
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
        if let Some(packet_filters) = &self.maximum_number_of_supported_packet_filters {
            push_ie_strict_result(
                &mut errs,
                "Maximum number of supported packet filters",
                packet_filters.validate_strict(),
            );
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
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
        push_ie_strict_result(
            &mut errs,
            "Authorized QoS rules",
            self.authorized_qos_rules.validate_strict(),
        );

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

        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
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
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for NasPduSessionModificationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if let Some(packet_filters) = &self.maximum_number_of_supported_packet_filters {
            push_ie_strict_result(
                &mut errs,
                "Maximum number of supported packet filters",
                packet_filters.validate_strict(),
            );
        }
        if let Some(rules) = &self.requested_qos_rules {
            push_ie_strict_result(&mut errs, "Requested QoS rules", rules.validate_strict());
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
        }
        if let Some(device_information) = &self.non_3gpp_device_information {
            push_ie_strict_result(
                &mut errs,
                "Non-3GPP device information",
                device_information.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for NasPduSessionModificationCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if let Some(rules) = &self.authorized_qos_rules {
            push_ie_strict_result(&mut errs, "Authorized QoS rules", rules.validate_strict());
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for NasPduSessionReleaseCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "Service-level-AA container",
                container.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for NasServiceLevelAuthenticationCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_ie_strict_result(
            &mut errs,
            "Service-level-AA container",
            self.service_level_aa_container.validate_strict(),
        );
        errs
    }
}

impl Validate for NasServiceLevelAuthenticationComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_ie_strict_result(
            &mut errs,
            "Service-level-AA container",
            self.service_level_aa_container.validate_strict(),
        );
        errs
    }
}

impl Validate for NasDeregistrationRequestFromUe {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        if self.de_registration_type.access_type().is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "De-registration type",
                message: format!(
                    "Invalid access type value {}",
                    self.de_registration_type.access_type_raw()
                ),
            });
        }

        if self.fgs_mobile_identity.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "5GS mobile identity",
                message: "Mobile identity is empty".into(),
            });
        }

        errs
    }
}

impl Validate for NasDeregistrationRequestToUe {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        if self.de_registration_type.access_type().is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "De-registration type",
                message: format!(
                    "Invalid access type value {}",
                    self.de_registration_type.access_type_raw()
                ),
            });
        }

        errs
    }
}

impl Validate for NasNotification {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        if self.access_type.access_type().is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Access type",
                message: format!(
                    "Invalid access type value {}",
                    self.access_type.access_type_raw()
                ),
            });
        }

        errs
    }
}

impl_validate_empty!(
    NasRegistrationComplete,
    NasDeregistrationAcceptFromUe,
    NasDeregistrationAcceptToUe,
    NasConfigurationUpdateComplete,
    NasServiceReject,
    NasServiceAccept,
    NasAuthenticationResponse,
    NasAuthenticationReject,
    NasAuthenticationResult,
    NasSecurityModeReject,
    NasFGmmStatus,
    NasNotificationResponse,
    NasNetworkSliceSpecificAuthenticationCommand,
    NasNetworkSliceSpecificAuthenticationComplete,
    NasNetworkSliceSpecificAuthenticationResult,
    NasRelayKeyRequest,
    NasRelayKeyAccept,
    NasRelayKeyReject,
    NasRelayAuthenticationRequest,
    NasRelayAuthenticationResponse,
    NasPduSessionAuthenticationCommand,
    NasPduSessionAuthenticationComplete,
    NasPduSessionAuthenticationResult,
    NasPduSessionModificationReject,
    NasPduSessionModificationComplete,
    NasPduSessionModificationCommandReject,
    NasPduSessionReleaseRequest,
    NasPduSessionReleaseReject,
    NasPduSessionReleaseComplete,
    NasFGsmStatus,
    NasRemoteUeReport,
    NasRemoteUeReportResponse,
);

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

    #[test]
    fn test_control_plane_service_request_ciot_must_be_exclusive() {
        let ciot = NasCiotSmallDataContainer::from_parsed(&CiotSmallDataContainerContents::Sms {
            data: vec![0xAA],
        })
        .unwrap();
        let msg = NasControlPlaneServiceRequest::new(NasControlPlaneServiceType::default())
            .set_ciot_small_data_container(ciot)
            .set_release_assistance_indication(NasReleaseAssistanceIndication::from_ddx(
                DownlinkDataExpected::NoFurtherData,
            ));

        let errs = msg.validate();
        assert!(
            errs.iter().any(|e| {
                e.field == "CIoT small data container" && e.severity == Severity::Error
            })
        );
    }

    #[test]
    fn test_registration_request_composes_fgmm_capability_strict_validation() {
        let mut msg = NasRegistrationRequest::new(
            NasFGsRegistrationType::new(0x79),
            NasFGsMobileIdentity::new(vec![0x01, 0x02]),
        );
        let mut capability = vec![0; 13];
        capability[12] = 0x01;
        msg.fgmm_capability = Some(NasFGmmCapability::new(capability));

        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "5GMM capability" && e.severity == Severity::Error)
        );
    }

    #[test]
    fn test_pdu_session_modification_request_composes_ie_strict_validation() {
        let msg = NasPduSessionModificationRequest::new()
            .set_maximum_number_of_supported_packet_filters(
                NasMaximumNumberOfSupportedPacketFilters::new(vec![0x00, 0x01]),
            );

        let errs = msg.validate();
        assert!(errs.iter().any(|e| {
            e.field == "Maximum number of supported packet filters" && e.severity == Severity::Error
        }));
    }

    #[test]
    fn test_upds_pti_must_match_message_initiator() {
        let message = NasUpdsMessage::ManageUePolicyCommand(NasManageUePolicyCommand::new(
            NasUePolicySectionManagementList::new(vec![0x00, 0x00]),
        ));
        let envelope = NasUpdsEnvelope::new_with_pti(
            NasUpdsProcedureTransactionIdentity::from_ue_initiated(0x01).unwrap(),
            message,
        );
        let errs = envelope.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "UPDS PTI" && e.severity == Severity::Error)
        );
    }

    #[test]
    fn test_upds_unsupported_message_warns() {
        let message = NasUnsupportedUpdsMessage::new(0x99, vec![0xAA]);
        let errs = message.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "UPDS message type" && e.severity == Severity::Warning)
        );
    }
}
