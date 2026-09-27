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

//! Structural validation helpers for NAS messages against a common TS 24.501 subset.
//!
//! Byte-level IE invariants live on the IE helpers in [`crate::nas_5gs::ie`]. This module
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

use crate::nas_5gs::ie::*;
use crate::nas_5gs::messages::*;
use crate::nas_5gs::types::*;
use crate::nas_5gs::upds::*;

pub use crate::common::{Severity, Validate, ValidationError};

// ============================================================================
// Top-level dispatch
// ============================================================================

impl Validate for Nas5gsMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = match self {
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
                    != crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::PlainNasMessage
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
                if hdr.procedure_transaction_identity == 255
                    || hdr.procedure_transaction_identity == 0
                        && matches!(
                            msg,
                            Nas5gsmMessage::PduSessionEstablishmentRequest(_)
                                | Nas5gsmMessage::PduSessionModificationRequest(_)
                                | Nas5gsmMessage::PduSessionReleaseRequest(_)
                        )
                {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "Procedure Transaction ID",
                        message: "Invalid 5GSM procedure transaction identity".into(),
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
                    == crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::PlainNasMessage
                {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "SHT",
                        message: "SecurityProtected wrapper has SHT=PlainNasMessage".into(),
                    });
                }
                match inner.as_ref() {
                    Nas5gsMessage::Opaque(data) => {
                        if data.is_empty()
                            || !matches!(
                                hdr.security_header_type,
                                crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                                    | crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                            )
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "Protected payload",
                                message: "Ciphertext requires a ciphered security header and nonempty body".into(),
                            });
                        }
                    }
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
                        if matches!(
                            hdr.security_header_type,
                            crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                                | crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                        ) {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "Protected payload",
                                message: "Ciphered security header cannot carry cleartext".into(),
                            });
                        }
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
                            != crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::PlainNasMessage
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
                            crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext
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
                            crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
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
            Nas5gsMessage::Opaque(_) => Vec::new(),
        };
        if !matches!(self, Self::Opaque(_))
            && let Err(error) = self.to_bytes()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "5GS NAS header",
                message: error.to_string(),
            });
        }
        errors
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

macro_rules! impl_validate_mandatory_eap {
    ($($name:ty),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    let mut errors = Vec::new();
                    push_ie_strict_result(&mut errors, "EAP message", self.eap_message.validate_strict());
                    errors
                }
            }
        )+
    };
}

macro_rules! impl_validate_optional_eap {
    ($($name:ty),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    let mut errors = Vec::new();
                    push_optional_eap(&mut errors, self.eap_message.as_ref());
                    errors
                }
            }
        )+
    };
}

macro_rules! impl_validate_snssai_eap {
    ($($name:ty),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    let mut errors = Vec::new();
                    if self.s_nssai.value.len() > 4 || self.s_nssai.parse().is_none() {
                        errors.push(ValidationError {
                            severity: Severity::Error,
                            field: "S-NSSAI",
                            message: "Mandatory S-NSSAI must use a valid 1–4 octet value".into(),
                        });
                    }
                    push_ie_strict_result(&mut errors, "EAP message", self.eap_message.validate_strict());
                    errors
                }
            }
        )+
    };
}

macro_rules! impl_validate_optional_epco {
    ($($name:ty),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    let mut errors = Vec::new();
                    if self.extended_protocol_configuration_options.as_ref()
                        .is_some_and(|epco| epco.value.is_empty())
                    {
                        errors.push(ValidationError {
                            severity: Severity::Error,
                            field: "Extended protocol configuration options",
                            message: "ePCO must contain at least one octet".into(),
                        });
                    }
                    errors
                }
            }
        )+
    };
}

fn push_ie_strict_result(
    errs: &mut Vec<ValidationError>,
    field: &'static str,
    result: crate::nas_5gs::types::Result<()>,
) {
    if let Err(err) = result {
        errs.push(ValidationError {
            severity: Severity::Error,
            field,
            message: err.to_string(),
        });
    }
}

fn push_optional_eap(errors: &mut Vec<ValidationError>, eap: Option<&NasEapMessage>) {
    if let Some(eap) = eap {
        push_ie_strict_result(errors, "EAP message", eap.validate_strict());
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
        push_optional_eap(&mut errs, self.eap_message.as_ref());

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
        push_optional_eap(&mut errs, self.eap_message.as_ref());
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
        push_optional_eap(&mut errs, self.eap_message.as_ref());

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
        push_optional_eap(&mut errs, self.eap_message.as_ref());

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
        let mut errors = Vec::new();
        // NAS message container should be present for initial registration
        // (contains the initial RegistrationRequest), but it's technically optional
        if self.imeisv.as_ref().is_some_and(|identity| {
            identity.length as usize != identity.value.len() || identity.as_imeisv().is_none()
        }) {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "IMEISV",
                message: "IMEISV must contain a 9-octet mobile identity with matching length"
                    .into(),
            });
        }
        if self
            .non_imeisv_pei
            .as_ref()
            .and_then(|identity| identity.as_imei())
            .is_some_and(|imei| !imei.ends_with('0'))
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "Non-IMEISV PEI",
                message: "Transmitted IMEI spare digit must be zero".into(),
            });
        }
        errors
    }
}

impl Validate for NasIdentityRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.identity_type.value & 0xF8 != 0 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Identity type",
                message: "Spare bits in 5GS identity type must be zero".into(),
            });
        }
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
        if self
            .mobile_identity
            .as_imei()
            .is_some_and(|imei| !imei.ends_with('0'))
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Mobile identity",
                message: "Transmitted IMEI spare digit must be zero".into(),
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

        if self.payload_container_type.value & 0xF0 != 0 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container type",
                message: "Spare half octet must be zero".into(),
            });
        }

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

        if self.payload_container_type.value & 0xF0 != 0 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container type",
                message: "Spare half octet must be zero".into(),
            });
        }

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
        push_optional_eap(&mut errs, self.eap_message.as_ref());

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
        push_optional_eap(&mut errs, self.eap_message.as_ref());
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
        push_optional_eap(&mut errs, self.eap_message.as_ref());
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
        if self.service_level_aa_container.value.len() < 3 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Service-level-AA container",
                message: "Mandatory container must contain at least 3 octets".into(),
            });
        }
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
        if self.service_level_aa_container.value.len() < 3 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Service-level-AA container",
                message: "Mandatory container must contain at least 3 octets".into(),
            });
        }
        push_ie_strict_result(
            &mut errs,
            "Service-level-AA container",
            self.service_level_aa_container.validate_strict(),
        );
        errs
    }
}

impl Validate for NasRelayKeyRequest {
    fn validate(&self) -> Vec<ValidationError> {
        if self.relay_key_request_parameters.parse().is_some() {
            Vec::new()
        } else {
            vec![ValidationError {
                severity: Severity::Error,
                field: "Relay key request parameters",
                message: "Mandatory relay key request parameters require at least 20 octets".into(),
            }]
        }
    }
}

impl Validate for NasRelayKeyAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if self.relay_key_response_parameters.parse().is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "Relay key response parameters",
                message: "Mandatory relay key response parameters require at least 49 octets"
                    .into(),
            });
        }
        push_optional_eap(&mut errors, self.eap_message.as_ref());
        errors
    }
}

impl Validate for NasNotificationResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(status) = &self.pdu_session_status
            && !(2..=32).contains(&status.value.len())
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "PDU session status",
                message: "PDU session status must contain 2–32 octets".into(),
            });
        }
        errors
    }
}

impl Validate for NasRemoteUeReport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        for (field, list) in [
            (
                "Connected remote UE context list",
                self.connected_remote_ue_context_list.as_ref(),
            ),
            (
                "Disconnected remote UE context list",
                self.disconnected_remote_ue_context_list.as_ref(),
            ),
        ] {
            if list.is_some_and(|list| list.value.len() < 13) {
                errors.push(ValidationError {
                    severity: Severity::Error,
                    field,
                    message: "Remote UE context list must contain at least 13 octets".into(),
                });
            }
        }
        errors
    }
}

impl Validate for NasPduSessionModificationComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        for (field, empty) in [
            (
                "Extended protocol configuration options",
                self.extended_protocol_configuration_options
                    .as_ref()
                    .is_some_and(|ie| ie.value.is_empty()),
            ),
            (
                "Port management information container",
                self.port_management_information_container
                    .as_ref()
                    .is_some_and(|ie| ie.value.is_empty()),
            ),
        ] {
            if empty {
                errors.push(ValidationError {
                    severity: Severity::Error,
                    field,
                    message: "Optional container must contain at least one octet".into(),
                });
            }
        }
        errors
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
    NasSecurityModeReject,
    NasFGmmStatus,
    NasFGsmStatus,
    NasRemoteUeReportResponse,
);

impl_validate_mandatory_eap!(
    NasAuthenticationResult,
    NasRelayAuthenticationRequest,
    NasRelayAuthenticationResponse,
    NasPduSessionAuthenticationCommand,
    NasPduSessionAuthenticationComplete,
);

impl_validate_optional_eap!(
    NasServiceReject,
    NasServiceAccept,
    NasAuthenticationResponse,
    NasAuthenticationReject,
    NasRelayKeyReject,
    NasPduSessionAuthenticationResult,
);

impl_validate_snssai_eap!(
    NasNetworkSliceSpecificAuthenticationCommand,
    NasNetworkSliceSpecificAuthenticationComplete,
    NasNetworkSliceSpecificAuthenticationResult,
);

impl_validate_optional_epco!(
    NasPduSessionModificationReject,
    NasPduSessionModificationCommandReject,
    NasPduSessionReleaseRequest,
    NasPduSessionReleaseReject,
    NasPduSessionReleaseComplete,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_request_preserves_wire_spares_and_reports_them() {
        let wire = [0x7e, 0x00, 0x5b, 0xf1];
        let message = Nas5gsMessage::from_bytes(&wire).unwrap();
        assert_eq!(message.to_bytes().unwrap(), wire);
        assert!(message.validate().iter().any(|error| {
            error.field == "Identity type" && error.message.contains("Spare bits")
        }));
    }

    #[test]
    fn ul_nas_transport_preserves_wire_spares_and_reports_them() {
        let wire = [0x7e, 0x00, 0x67, 0xf2, 0x00, 0x01, 0x00];
        let message = Nas5gsMessage::from_bytes(&wire).unwrap();
        assert_eq!(message.to_bytes().unwrap(), wire);
        assert!(message.validate().iter().any(|error| {
            error.field == "Payload container type" && error.message.contains("Spare")
        }));
    }

    #[test]
    fn mandatory_eap_requires_a_complete_packet() {
        let empty = NasPduSessionAuthenticationCommand::new(NasEapMessage::new(vec![]));
        assert!(
            empty
                .validate()
                .iter()
                .any(|error| error.field == "EAP message")
        );
        let valid = NasPduSessionAuthenticationCommand::new(NasEapMessage::new(vec![
            0x03, 0x01, 0x00, 0x04,
        ]));
        assert!(valid.validate().is_empty());
        let mismatched = NasPduSessionAuthenticationCommand::new(NasEapMessage::new(vec![
            0x03, 0x01, 0x00, 0x05,
        ]));
        assert!(
            mismatched
                .validate()
                .iter()
                .any(|error| error.field == "EAP message")
        );
    }

    #[test]
    fn optional_eap_is_checked_when_present() {
        let empty = NasServiceReject::new(NasFGmmCause::new(0x16))
            .set_eap_message(NasEapMessage::new(vec![]));
        assert!(
            empty
                .validate()
                .iter()
                .any(|error| error.field == "EAP message")
        );
        let absent = NasServiceReject::new(NasFGmmCause::new(0x16));
        assert!(absent.validate().is_empty());
    }

    #[test]
    fn relay_parameter_and_slice_auth_mandatory_lengths() {
        let request = NasRelayKeyRequest::new(
            NasProseRelayTransactionIdentity::new(1),
            NasRelayKeyRequestParameters::new(vec![]),
        );
        assert!(
            request
                .validate()
                .iter()
                .any(|error| error.field == "Relay key request parameters")
        );
        let accept = NasRelayKeyAccept::new(
            NasProseRelayTransactionIdentity::new(1),
            NasRelayKeyResponseParameters::new(vec![0; 48]),
        );
        assert!(
            accept
                .validate()
                .iter()
                .any(|error| error.field == "Relay key response parameters")
        );
        let slice = NasNetworkSliceSpecificAuthenticationCommand::new(
            NasSNssai::new(vec![]),
            NasEapMessage::new(vec![3, 1, 0, 4]),
        );
        assert!(
            slice
                .validate()
                .iter()
                .any(|error| error.field == "S-NSSAI")
        );
    }

    #[test]
    fn notification_response_checks_pdu_session_status_length() {
        let invalid =
            NasNotificationResponse::new().set_pdu_session_status(NasPduSessionStatus::new(vec![]));
        assert!(
            invalid
                .validate()
                .iter()
                .any(|error| error.field == "PDU session status")
        );
        let valid = NasNotificationResponse::new()
            .set_pdu_session_status(NasPduSessionStatus::from_sessions(&[1]));
        assert!(valid.validate().is_empty());
    }

    #[test]
    fn remote_ue_report_checks_context_list_length() {
        let report = NasRemoteUeReport::new()
            .set_connected_remote_ue_context_list(NasRemoteUeContextList::new(vec![]));
        assert!(
            report
                .validate()
                .iter()
                .any(|error| { error.field == "Connected remote UE context list" })
        );
    }

    #[test]
    fn optional_epco_requires_a_value() {
        let reject = NasPduSessionReleaseReject::new(NasFGsmCause::new(0x1a))
            .set_extended_protocol_configuration_options(
                NasExtendedProtocolConfigurationOptions::new(vec![]),
            );
        assert!(
            reject
                .validate()
                .iter()
                .any(|error| { error.field == "Extended protocol configuration options" })
        );
        let complete = NasPduSessionModificationComplete::new()
            .set_port_management_information_container(NasPortManagementInformationContainer::new(
                vec![],
            ));
        assert!(
            complete
                .validate()
                .iter()
                .any(|error| { error.field == "Port management information container" })
        );
    }

    #[test]
    fn security_mode_complete_requires_imeisv_identity() {
        let valid = NasSecurityModeComplete::new()
            .set_imeisv(NasFGsMobileIdentity::from_imeisv("1234567890123456"));
        assert!(valid.validate().is_empty());
        let invalid = NasSecurityModeComplete::new().set_imeisv(NasFGsMobileIdentity::new(vec![]));
        assert!(
            invalid
                .validate()
                .iter()
                .any(|error| error.field == "IMEISV")
        );
    }

    #[test]
    fn transmitted_imei_requires_zero_spare_digit() {
        let conforming = NasIdentityResponse::new(
            NasFGsMobileIdentity::from_imei_tac_snr("49015420323751").unwrap(),
        );
        assert!(conforming.validate().is_empty());
        let interoperable =
            NasIdentityResponse::new(NasFGsMobileIdentity::from_imei("490154203237518"));
        assert!(
            interoperable
                .validate()
                .iter()
                .any(|error| error.field == "Mobile identity")
        );
    }

    #[test]
    fn top_level_validation_reports_message_type_mismatch() {
        let mut message = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationComplete(
            NasRegistrationComplete::new(),
        ));
        if let Nas5gsMessage::Gmm(header, _) = &mut message {
            header.message_type =
                crate::nas_5gs::message_types::Nas5gmmMessageType::RegistrationRequest;
        }
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "5GS NAS header")
        );
    }

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
