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
//! use oxirush_nas::Validate;
//! use oxirush_nas::nas_5gs::Message;
//!
//! let bytes = hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
//! let msg = Message::decode(&bytes).unwrap();
//! let errors = msg.validate();
//! assert!(errors.is_empty(), "Validation errors: {:?}", errors);
//! ```

use crate::nas_5gs::*;
use crate::prelude::*;

use crate::common::{
    IgnoredIeReason, OptionalIeOrder, ReceiverSyntaxCheck, with_optional_ie_checks,
};
pub(crate) use crate::common::{Severity, Validate, ValidationError};

// The rules of the IE types that `validate()` checks: the value lengths of
// their clauses, the values that a sender sets, and a receiver's grammar.
crate::common::ie_rules! {
    Abba: lengths(2, usize::MAX);
    AccessType: sender;
    Additional5gSecurityInformation: lengths(1, 1);
    AdditionalConfigurationIndication;
    AdditionalInformation: lengths(1, usize::MAX);
    AdditionalInformationRequested: lengths(1, 1), sender;
    AdditionalRequestResult: lengths(1, 1), sender;
    AllowedPduSessionStatus: lengths(2, 32);
    AllowedSscMode;
    AlternativeNssai: lengths(0, 144);
    AlwaysOnPduSessionIndication;
    AlwaysOnPduSessionRequested;
    AtsssContainer: lengths(0, 65535);
    Aun3DeviceSecurityKey: lengths(34, usize::MAX);
    Aun3Indication: lengths(1, 1);
    CagInformationList: lengths(0, usize::MAX), sender, receiver;
    CiotSmallDataContainer: lengths(2, 255);
    CipheringKeyData: lengths(31, 2672), sender, receiver;
    ConfigurationUpdateIndication;
    ControlPlaneOnlyIndication: sender;
    ControlPlaneServiceType;
    DeRegistrationType;
    Dnn: lengths(1, 100), sender, receiver;
    DrxParameters: lengths(1, 1);
    DsTtEthernetPortMacAddress: lengths(6, 6);
    EapMessage: lengths(4, 1500);
    EcnMarkingForL4sIndication: lengths(0, 255);
    EpsNasMessageContainer: lengths(1, usize::MAX);
    EpsNasSecurityAlgorithms: sender;
    EthernetHeaderCompressionConfiguration: lengths(1, 1);
    ExtendedCagInformationList: lengths(0, usize::MAX), sender, receiver;
    ExtendedFGmmCause: lengths(1, 1);
    ExtendedLadnInformation: lengths(0, 1784);
    ExtendedRejectedNssai: lengths(3, 88), sender, receiver;
    FeatureAuthorizationIndication: lengths(1, 255);
    GmmCapability: lengths(1, 13);
    GmmCause;
    GsmCapability: lengths(1, 13);
    GsmCause;
    GsmCongestionReAttemptIndicator: lengths(1, 1);
    GsmNetworkFeatureSupport: lengths(1, 13);
    IdentityType;
    IntegrityProtectionMaximumDataRate: sender;
    IpHeaderCompressionConfiguration: lengths(3, 255), sender;
    KeySetIdentifier;
    LadnIndication: lengths(0, 808), sender, receiver;
    LadnInformation: lengths(0, 1712), sender, receiver;
    LpWuspsAssistanceInformation: lengths(0, 1);
    LpWusStatus;
    MaPduSessionInformation;
    MappedEpsBearerContexts: lengths(4, 65535), sender, receiver;
    MappedNssai: lengths(1, 40), sender, receiver;
    MaximumNumberOfSupportedPacketFilters: sender, receiver;
    MessageContainer: lengths(1, usize::MAX);
    MicoIndication;
    MobileIdentity: lengths(1, usize::MAX), sender, receiver;
    N3iwfIdentifier: lengths(5, usize::MAX);
    N3Qai: lengths(6, usize::MAX), sender, receiver;
    N5gcIndication;
    NbN1ModeDrxParameters: lengths(1, 1);
    NetworkFeatureSupport: lengths(1, 4), sender;
    NetworkSlicingIndication;
    Nid: lengths(6, 6);
    Non3GppAccessPathSwitchingIndication: lengths(1, 1);
    Non3GppDelayBudget: lengths(3, usize::MAX);
    Non3GppDeviceInformation: lengths(4, usize::MAX);
    Non3GppPathSwitchingInformation: lengths(1, 1);
    NsagInformation: lengths(6, 3140), sender, receiver;
    Nssai: lengths(2, 144), sender, receiver;
    NssaiInclusionMode;
    NssrgInformation: lengths(4, 4096), sender, receiver;
    OnDemandNssai: lengths(3, 208);
    OperatorDefinedAccessCategoryDefinitions: lengths(0, 8320), sender, receiver;
    PagingRestriction: lengths(1, 33), sender;
    PartialNssai: lengths(0, 805);
    PayloadContainer: lengths(1, 65535);
    PayloadContainerInformation;
    PayloadContainerType: sender;
    PduAddress: lengths(5, 29), sender, receiver;
    PduSessionIdentity2;
    PduSessionPairId: lengths(1, 1);
    PduSessionReactivationResult: lengths(2, 32);
    PduSessionReactivationResultErrorCause: lengths(2, 512), sender, receiver;
    PduSessionStatus: lengths(2, 32);
    PduSessionType: sender;
    PeipsAssistanceInformation: lengths(1, 1);
    PortManagementInformationContainer: lengths(1, 65535);
    PriorityIndicator;
    ProseRelayTransactionIdentity;
    ProtocolDescription: lengths(3, usize::MAX), sender;
    QosFlowDescriptions: lengths(3, 65535), sender;
    QosRules: lengths(4, 65535), sender;
    RanTimingSynchronization: lengths(1, 1);
    ReAttemptIndicator: lengths(1, 1), sender;
    ReceivedMbsContainer: lengths(6, 65535), sender, receiver;
    RegistrationResult: lengths(1, 1), sender;
    RegistrationType;
    RejectedNssai: lengths(2, 40), sender, receiver;
    RelayKeyRequestParameters: lengths(20, 65535);
    RelayKeyResponseParameters: lengths(49, 65535);
    RemoteUeContextList: lengths(13, 65535);
    RequestedMbsContainer: lengths(5, 65535), sender, receiver;
    RequestType: sender;
    Rsn: lengths(1, 1);
    S1UeNetworkCapability: lengths(2, 13), sender;
    S1UeSecurityCapability: lengths(2, 5), sender;
    SecurityAlgorithms: sender;
    ServiceAreaList: lengths(4, 112), sender, receiver;
    ServiceLevelAaContainer: lengths(1, 65535);
    ServiceType;
    SessionAmbr: lengths(6, 6), sender;
    SmPduDnRequestContainer: lengths(1, 253);
    SmsIndication;
    SnpnList: lengths(9, 135);
    SNssai: lengths(1, 8), sender, receiver;
    SNssaiLocationValidityInformation: lengths(14, 38608), sender;
    SNssaiTimeValidityInformation: lengths(21, 255);
    SorTransparentContainer: lengths(17, usize::MAX), sender, receiver;
    SscMode: sender;
    T3512Value: lengths(1, 1), sender;
    TnanInformation: lengths(1, usize::MAX);
    TrackingAreaIdentity;
    TrackingAreaIdentityList: lengths(7, 112), sender, receiver;
    TruncatedFGSTmsiConfiguration: lengths(1, 1), sender;
    Type6IeContainer: lengths(3, 65535), sender;
    UeDsTtResidenceTime: lengths(8, 8), sender;
    UeSecurityCapability: lengths(2, 8);
    UeUsageSetting: lengths(1, 1);
    UpdateType: lengths(1, 1);
    UplinkDataStatus: lengths(2, 32), sender;
    UrspRuleEnforcementReports: lengths(2, usize::MAX);
}

impl ReceiverSyntaxCheck for Dnn {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for MobileIdentity {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }

    fn receiver_syntax_fault(&self) -> Option<String> {
        self.receiver_fault()
    }
}

impl ReceiverSyntaxCheck for TrackingAreaIdentityList {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for SNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.parse().is_some()
    }
}

impl ReceiverSyntaxCheck for Nssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }

    fn receiver_syntax_ok_for_field(&self, field: &str) -> bool {
        self.receiver_syntax_is_valid_for_field(field)
    }
}

impl ReceiverSyntaxCheck for MappedNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_parse_all().is_some()
    }
}

impl ReceiverSyntaxCheck for ExtendedRejectedNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for RejectedNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for PduSessionReactivationResultErrorCause {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for PduAddress {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for MappedEpsBearerContexts {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for OperatorDefinedAccessCategoryDefinitions {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_definitions().is_some()
    }
}

// The spare bits of octet 3 are ignored on receipt (TS 24.501 §9.11.4.9).
impl ReceiverSyntaxCheck for MaximumNumberOfSupportedPacketFilters {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() == 2 && (17..=1024).contains(&self.max_filters())
    }
}

impl ReceiverSyntaxCheck for LadnIndication {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.is_empty() || !self.dnn_values().is_empty()
    }
}

impl ReceiverSyntaxCheck for LadnInformation {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.is_empty() || !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for NsagInformation {
    fn receiver_syntax_ok(&self) -> bool {
        !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for NssrgInformation {
    fn receiver_syntax_ok(&self) -> bool {
        !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for CipheringKeyData {
    fn receiver_syntax_ok(&self) -> bool {
        !self.data_sets().is_empty()
    }
}

impl ReceiverSyntaxCheck for CagInformationList {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.is_empty() || !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for ExtendedCagInformationList {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.is_empty() || !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for ReceivedMbsContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_sessions().is_some()
    }
}

impl ReceiverSyntaxCheck for RequestedMbsContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_sessions().is_some()
    }
}

impl ReceiverSyntaxCheck for N3Qai {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_entries().is_some()
    }
}

impl ReceiverSyntaxCheck for ServiceAreaList {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for SorTransparentContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

// ============================================================================
// Top-level dispatch
// ============================================================================

impl Validate for Message {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = match self {
            Message::Gmm(hdr, msg) => {
                let mut errs = Vec::new();
                if hdr.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "extended_protocol_discriminator",
                        message: format!(
                            "Expected 0x7e for 5GMM, got 0x{:02x}",
                            hdr.extended_protocol_discriminator
                        ),
                    });
                }
                if hdr.security_header_type
                    != crate::nas_5gs::SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected
                {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "security_header_type",
                        message: format!(
                            "Plain 5GMM message shall use SHT=PlainFiveGsNasMessageNotSecurityProtected, got {:?}",
                            hdr.security_header_type
                        ),
                    });
                }
                push_header_spare(&mut errs, hdr.spare_half_octet);
                errs.extend(msg.validate());
                errs
            }
            Message::Gsm(hdr, msg) => {
                let mut errs = Vec::new();
                if hdr.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "extended_protocol_discriminator",
                        message: format!(
                            "Expected 0x2e for 5GSM, got 0x{:02x}",
                            hdr.extended_protocol_discriminator
                        ),
                    });
                }
                if hdr.pdu_session_identity == 0 || hdr.pdu_session_identity > 15 {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "pdu_session_identity",
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
                            GsmMessage::PduSessionEstablishmentRequest(_)
                                | GsmMessage::PduSessionModificationRequest(_)
                                | GsmMessage::PduSessionReleaseRequest(_)
                        )
                {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "procedure_transaction_identity",
                        message: "Invalid 5GSM procedure transaction identity".into(),
                    });
                }
                errs.extend(msg.validate());
                errs
            }
            Message::SecurityProtected(hdr, inner) => {
                let mut errs = Vec::new();
                if hdr.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "extended_protocol_discriminator",
                        message: format!(
                            "Security-protected outer header must use 0x7e (5GMM), got 0x{:02x}",
                            hdr.extended_protocol_discriminator
                        ),
                    });
                }
                if hdr.security_header_type
                    == crate::nas_5gs::SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected
                {
                    errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "security_header_type",
                        message: "SecurityProtected wrapper has SHT=PlainFiveGsNasMessageNotSecurityProtected".into(),
                    });
                }
                push_header_spare(&mut errs, hdr.spare_half_octet);
                match inner.as_ref() {
                    Message::Opaque(data) => {
                        if data.is_empty()
                            || !matches!(
                                hdr.security_header_type,
                                crate::nas_5gs::SecurityHeaderType::IntegrityProtectedAndCiphered
                                    | crate::nas_5gs::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
                            )
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "plain_fgs_nas_message",
                                message: "Ciphertext requires a ciphered security header and nonempty body".into(),
                            });
                        }
                    }
                    Message::SecurityProtected(_, _) => errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "plain_fgs_nas_message",
                        message:
                            "Security-protected 5GS NAS message shall carry a plain inner 5GMM message"
                                .into(),
                    }),
                    Message::Gsm(_, _) => errs.push(ValidationError {
                        severity: Severity::Error,
                        field: "plain_fgs_nas_message",
                        message:
                            "Security-protected 5GS NAS message shall carry a plain inner 5GMM message; 5GSM messages are protected only via the enclosing 5GMM message"
                                .into(),
                    }),
                    Message::Gmm(inner_hdr, inner_msg) => {
                        if matches!(
                            hdr.security_header_type,
                            crate::nas_5gs::SecurityHeaderType::IntegrityProtectedAndCiphered
                                | crate::nas_5gs::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
                        ) {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "plain_fgs_nas_message",
                                message: "Ciphered security header cannot carry cleartext".into(),
                            });
                        }
                        if inner_hdr.extended_protocol_discriminator
                            != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "plain_fgs_nas_message.extended_protocol_discriminator",
                                message: format!(
                                    "inner plain 5GMM message shall use EPD=0x7e, got 0x{:02x}",
                                    inner_hdr.extended_protocol_discriminator
                                ),
                            });
                        }
                        if inner_hdr.security_header_type
                            != crate::nas_5gs::SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "plain_fgs_nas_message.security_header_type",
                                message: format!(
                                    "inner plain 5GMM message shall use SHT=PlainFiveGsNasMessageNotSecurityProtected, got {:?}",
                                    inner_hdr.security_header_type
                                ),
                            });
                        }
                        if matches!(inner_msg, GmmMessage::SecurityModeCommand(_))
                            && hdr.security_header_type
                                != crate::nas_5gs::SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "security_header_type",
                                message:
                                    "SecurityModeCommand requires integrity protection with new context"
                                        .into(),
                            });
                        }
                        if matches!(inner_msg, GmmMessage::SecurityModeComplete(_))
                            && hdr.security_header_type
                                != crate::nas_5gs::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "security_header_type",
                                message:
                                    "SecurityModeComplete requires ciphering with new context"
                                        .into(),
                            });
                        }
                        match hdr.security_header_type {
                            crate::nas_5gs::SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext
                                if !matches!(inner_msg, GmmMessage::SecurityModeCommand(_)) =>
                            {
                                errs.push(ValidationError {
                                    severity: Severity::Error,
                                    field: "security_header_type",
                                    message:
                                        "IntegrityProtectedWithNewFiveGNasSecurityContext is only valid for SecurityModeCommand per TS 24.501 Table 9.3.1 note 1"
                                            .into(),
                                });
                            }
                            crate::nas_5gs::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
                                if !matches!(inner_msg, GmmMessage::SecurityModeComplete(_)) =>
                            {
                                errs.push(ValidationError {
                                    severity: Severity::Error,
                                    field: "security_header_type",
                                    message:
                                        "IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext is only valid for SecurityModeComplete per TS 24.501 Table 9.3.1 note 2"
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
            Message::Opaque(_) => Vec::new(),
        };
        if !matches!(self, Self::Opaque(_))
            && let Err(error) = self.encode()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "message",
                message: error.to_string(),
            });
        }
        errors
    }
}

impl Validate for GmmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let body = self.body();
        let unknown = body.unknown_ies();
        with_optional_ie_checks(
            body.validate(),
            unknown,
            body.ie_findings(),
            UNKNOWN_TLVE_START,
        )
    }
}

impl Validate for GsmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let body = self.body();
        let unknown = body.unknown_ies();
        with_optional_ie_checks(
            body.validate(),
            unknown,
            body.ie_findings(),
            UNKNOWN_TLVE_START,
        )
    }
}

fn upds_optional_ie_findings(
    unknown_ies: &[UpdsUnknownIe],
    order: Option<&[OptionalIeOrder]>,
) -> Vec<ValidationError> {
    let mut findings = Vec::new();
    if let Some(order) = order {
        for entry in order {
            if let OptionalIeOrder::Ignored(index, reason) = *entry
                && let Some(ie) = unknown_ies.get(index)
            {
                let description = match reason {
                    IgnoredIeReason::Malformed => "malformed",
                    IgnoredIeReason::Repeated => "repeated",
                    IgnoredIeReason::OutOfSequence => "out of sequence",
                };
                findings.push(ValidationError {
                    severity: Severity::Error,
                    field: "unknown_ies",
                    message: format!("IEI 0x{:02x} was ignored as {description}", ie.iei),
                });
            }
        }
    }
    for ie in unknown_ies {
        if ie.is_comprehension_required() {
            findings.push(ValidationError {
                severity: Severity::Error,
                field: "unknown_ies",
                message: format!("Unknown comprehension-required IEI 0x{:02x}", ie.iei),
            });
        }
    }
    findings
}

impl Validate for UpdsEnvelope {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = self.message.validate();
        let pti = self.procedure_transaction_identity_value();
        if pti.is_reserved() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "procedure_transaction_identity",
                message:
                    "Reserved UPDS procedure transaction identity; TS 24.501 Annex D says reserved values shall be ignored"
                        .into(),
            });
        }
        if pti.is_unassigned() {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "procedure_transaction_identity",
                message:
                    "UPDS procedure transaction identity is unassigned (0x00); this is only meaningful when no procedure transaction is allocated"
                        .into(),
            });
        }
        let requires_ue_initiated_pti = matches!(
            self.message_type(),
            Some(
                UpdsMessageType::UeStateIndication
                    | UpdsMessageType::UePolicyProvisioningRequest
                    | UpdsMessageType::UePolicyProvisioningReject
            )
        );
        if requires_ue_initiated_pti && !pti.is_ue_initiated() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "procedure_transaction_identity",
                message: format!(
                    "PTI {} does not identify the UE-initiated procedure for {:?}",
                    pti,
                    self.message_type()
                ),
            });
        }
        errs
    }
}

impl Validate for UpdsMessage {
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

impl Validate for ManageUePolicyCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if !self.ue_policy_section_management_list.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "ue_policy_section_management_list",
                message: "Mandatory UE policy section management list has invalid Annex D.6.2 framing or values".into(),
            });
        }
        if let Some(network_classmark) = &self.ue_policy_network_classmark
            && (!(1..=3).contains(&network_classmark.value.len())
                || network_classmark.value[0] & 0xfe != 0
                || network_classmark.value[1..].iter().any(|octet| *octet != 0))
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "ue_policy_network_classmark",
                message:
                    "UE policy network classmark shall contain 1–3 octets with all spare bits zero"
                        .into(),
            });
        }
        if let Some(configuration) = &self.vps_ursp_configuration
            && !configuration.is_well_formed()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "vps_ursp_configuration",
                message: "VPS URSP configuration has invalid Annex D.6.8 framing or values".into(),
            });
        }
        errs.extend(upds_optional_ie_findings(
            &self.unknown_ies,
            Some(&self.optional_ie_order),
        ));
        errs
    }
}

impl Validate for ManageUePolicyComplete {
    fn validate(&self) -> Vec<ValidationError> {
        upds_optional_ie_findings(&self.unknown_ies, None)
    }
}

impl Validate for ManageUePolicyCommandReject {
    fn validate(&self) -> Vec<ValidationError> {
        if !self.ue_policy_section_management_result.is_well_formed() {
            vec![ValidationError {
                severity: Severity::Error,
                field: "ue_policy_section_management_result",
                message: "Mandatory UE policy section management result has invalid Annex D.6.3 framing or values".into(),
            }]
        } else {
            upds_optional_ie_findings(&self.unknown_ies, None)
        }
    }
}

impl Validate for UeStateIndication {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if !self.upsi_list.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "upsi_list",
                message: "Mandatory UPSI list has invalid Annex D.6.4 framing or values".into(),
            });
        }
        if !(1..=3).contains(&self.ue_policy_classmark.value.len())
            || self.ue_policy_classmark.value[0] & 0xf0 != 0
            || self.ue_policy_classmark.value[1..]
                .iter()
                .any(|octet| *octet != 0)
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "ue_policy_classmark",
                message: "UE policy classmark shall contain 1–3 octets with all spare bits zero"
                    .into(),
            });
        }
        if let Some(ue_os_id) = &self.ue_os_id {
            if ue_os_id.value.len() % 16 != 0 {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "ue_os_id",
                    message: "UE OS Id shall be a concatenation of 16-octet OS identifiers".into(),
                });
            }
            let os_id_count = ue_os_id.os_ids().len();
            if !(1..=15).contains(&os_id_count) {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "ue_os_id",
                    message: format!(
                        "UE OS Id shall contain between 1 and 15 OS identifiers, got {os_id_count}"
                    ),
                });
            }
        }
        errs.extend(upds_optional_ie_findings(
            &self.unknown_ies,
            Some(&self.optional_ie_order),
        ));
        errs
    }
}

impl Validate for UePolicyProvisioningRequest {
    fn validate(&self) -> Vec<ValidationError> {
        if self.payload.len() > 65533 {
            vec![ValidationError {
                severity: Severity::Error,
                field: "payload",
                message: "UPDS message exceeds 65535 octets".into(),
            }]
        } else if self.payload.is_empty() {
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

impl Validate for UePolicyProvisioningReject {
    fn validate(&self) -> Vec<ValidationError> {
        if self.payload.len() > 65533 {
            vec![ValidationError {
                severity: Severity::Error,
                field: "payload",
                message: "UPDS message exceeds 65535 octets".into(),
            }]
        } else if self.payload.is_empty() {
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

impl Validate for UnsupportedUpdsMessage {
    fn validate(&self) -> Vec<ValidationError> {
        vec![ValidationError {
            severity: Severity::Warning,
            field: "message_type",
            message: format!(
                "Unsupported or unknown UPDS message type 0x{:02x}; Annex D says it shall be ignored by the receiver",
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
    ($($name:ty $(=> $epco:ident)?),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    let mut errors = Vec::new();
                    push_ie_strict_result(&mut errors, "eap_message", self.eap_message.validate_strict());
                    $(push_optional_epco(&mut errors, self.$epco.as_ref());)?
                    errors
                }
            }
        )+
    };
}

macro_rules! impl_validate_optional_eap {
    ($($name:ty $(=> $epco:ident)?),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    let mut errors = Vec::new();
                    push_optional_eap(&mut errors, self.eap_message.as_ref());
                    $(push_optional_epco(&mut errors, self.$epco.as_ref());)?
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
                            field: "s_nssai",
                            message: "Mandatory S-NSSAI must use a valid 1–4 octet value".into(),
                        });
                    }
                    push_ie_strict_result(&mut errors, "eap_message", self.eap_message.validate_strict());
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
                    push_optional_epco(&mut errors, self.extended_protocol_configuration_options.as_ref());
                    errors
                }
            }
        )+
    };
}

fn push_ie_strict_result(
    errs: &mut Vec<ValidationError>,
    field: &'static str,
    result: crate::nas_5gs::Result<()>,
) {
    if let Err(err) = result {
        errs.push(ValidationError {
            severity: Severity::Error,
            field,
            message: err.to_string(),
        });
    }
}

fn push_optional_eap(errors: &mut Vec<ValidationError>, eap: Option<&EapMessage>) {
    if let Some(eap) = eap {
        push_ie_strict_result(errors, "eap_message", eap.validate_strict());
    }
}

/// The spare half octet beside the security header type of a header is
/// zero in a message that is sent (TS 24.501 §9.5).
fn push_header_spare(errors: &mut Vec<ValidationError>, spare_half_octet: u8) {
    if spare_half_octet != 0 {
        errors.push(ValidationError {
            severity: Severity::Error,
            field: "spare_half_octet",
            message: format!("Spare half octet must be zero, got 0x{spare_half_octet:x}"),
        });
    }
}

fn push_payload_container_type(
    errors: &mut Vec<ValidationError>,
    container_type: Option<&PayloadContainerType>,
) {
    if let Some(container_type) = container_type {
        let message = if container_type.value & 0xF0 != 0 {
            Some("Spare half octet must be zero")
        } else if container_type.kind().is_none() {
            Some("Payload container type is reserved")
        } else {
            None
        };
        if let Some(message) = message {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "payload_container_type",
                message: message.into(),
            });
        }
    }
}

fn push_sor_direction(
    errors: &mut Vec<ValidationError>,
    container: &SorTransparentContainer,
    direction: SorTransparentContainerDirection,
) {
    if !container.is_well_formed_for(direction) {
        errors.push(ValidationError {
            severity: Severity::Error,
            field: "sor_transparent_container",
            message: "SOR grammar or data type does not match the NAS message direction".into(),
        });
    }
}

fn push_payload_sor_direction(
    errors: &mut Vec<ValidationError>,
    container_type: &PayloadContainerType,
    payload: &PayloadContainer,
    direction: SorTransparentContainerDirection,
) {
    match container_type.kind() {
        Some(PayloadContainerKind::SorTransparentContainer) => {
            let container = SorTransparentContainer::new(payload.value.clone());
            push_sor_direction(errors, &container, direction);
        }
        Some(PayloadContainerKind::MultiplePayloads) => {
            match payload.decode_as_multiple_payload_container() {
                Ok(multiple) => {
                    for entry in multiple.entries {
                        if entry.payload_container_type.kind()
                            == Some(PayloadContainerKind::SorTransparentContainer)
                        {
                            let container = SorTransparentContainer::new(entry.contents);
                            push_sor_direction(errors, &container, direction);
                        }
                    }
                }
                Err(err) => errors.push(ValidationError {
                    severity: Severity::Error,
                    field: "payload_container",
                    message: err.to_string(),
                }),
            }
        }
        _ => {}
    }
}

fn push_optional_epco(
    errors: &mut Vec<ValidationError>,
    epco: Option<&ExtendedProtocolConfigurationOptions>,
) {
    if let Some(epco) = epco {
        if epco.value.is_empty() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "extended_protocol_configuration_options",
                message: "ePCO must contain at least one octet".into(),
            });
        } else if epco.value[0] & 0xf8 != 0x80 {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "extended_protocol_configuration_options",
                message: "ePCO extension bit and spare bits are invalid".into(),
            });
        }
    }
}

// ============================================================================
// Individual messages
// ============================================================================

impl Validate for RegistrationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        // Registration type must be 1-7
        let reg_type = self.fgs_registration_type.value & 0x07;
        if reg_type == 0 || self.fgs_registration_type.registration_type().is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "fgs_registration_type",
                message: format!("Invalid registration type value {reg_type}"),
            });
        }

        // Mobile identity must not be empty
        if self.fgs_mobile_identity.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "fgs_mobile_identity",
                message: "Mobile identity is empty".into(),
            });
        } else {
            let id_type = self.fgs_mobile_identity.value[0] & 0x07;
            // RegistrationRequest only allows SUCI (1), GUTI (2), or 5G-S-TMSI (4) for initial
            if id_type != 0x01 && id_type != 0x02 {
                errs.push(ValidationError {
                    severity: Severity::Warning,
                    field: "fgs_mobile_identity",
                    message: format!(
                        "Unusual identity type {id_type} for registration (expected SUCI=1 or GUTI=2)"
                    ),
                });
            }
        }

        // The non-current native ngKSI is that of a native context, 0 to 6
        // (§8.2.6.2).
        if let Some(ksi) = &self.non_current_native_nas_key_set_identifier
            && ksi.value > 6
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "non_current_native_nas_key_set_identifier",
                message: format!("A native ngKSI is 0 to 6, got 0x{:x}", ksi.value),
            });
        }

        // UE security capability minimum 2 bytes
        if let Some(ref cap) = self.ue_security_capability
            && cap.value.len() < 2
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "ue_security_capability",
                message: format!("Must be at least 2 bytes (EA+IA), got {}", cap.value.len()),
            });
        }

        if let Some(capability) = &self.fgmm_capability {
            push_ie_strict_result(&mut errs, "fgmm_capability", capability.validate_strict());
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }

        push_payload_container_type(&mut errs, self.payload_container_type.as_ref());
        match (&self.payload_container_type, &self.payload_container) {
            (None, None) => {}
            (Some(container_type), Some(_))
                if container_type.kind() == Some(PayloadContainerKind::UePolicy) => {}
            (Some(_), Some(_)) => errs.push(ValidationError {
                severity: Severity::Error,
                field: "payload_container_type",
                message: "REGISTRATION REQUEST only carries a UE policy payload container".into(),
            }),
            (None, Some(_)) => errs.push(ValidationError {
                severity: Severity::Error,
                field: "payload_container_type",
                message: "Payload container type is required with a payload container".into(),
            }),
            (Some(_), None) => errs.push(ValidationError {
                severity: Severity::Error,
                field: "payload_container",
                message: "Payload container is required with its type".into(),
            }),
        }

        errs
    }
}

impl Validate for RegistrationAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_eap(&mut errs, self.eap_message.as_ref());

        // Registration result must not be empty
        if self.fgs_registration_result.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "fgs_registration_result",
                message: "Registration result value is empty".into(),
            });
        }

        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }
        if let Some(status) = &self.lp_wus_status {
            push_ie_strict_result(&mut errs, "lp_wus_status", status.validate_strict());
        }
        if let Some(container) = &self.sor_transparent_container {
            push_sor_direction(
                &mut errs,
                container,
                SorTransparentContainerDirection::NetworkToUe,
            );
        }

        errs
    }
}

impl Validate for RegistrationReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_eap(&mut errs, self.eap_message.as_ref());
        if GmmCause::new(self.fgmm_cause.value).cause().is_none() {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "fgmm_cause",
                message: format!("Unknown 5GMM cause code 0x{:02x}", self.fgmm_cause.value),
            });
        }
        if let Some(cause) = &self.extended_5gmm_cause {
            push_ie_strict_result(&mut errs, "extended_5gmm_cause", cause.validate_strict());
        }
        errs
    }
}

impl Validate for ConfigurationUpdateCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }
        if let Some(status) = &self.lp_wus_status {
            push_ie_strict_result(&mut errs, "lp_wus_status", status.validate_strict());
        }
        errs
    }
}

impl Validate for AuthenticationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_eap(&mut errs, self.eap_message.as_ref());

        // ABBA is mandatory (minimum 2 bytes)
        if self.abba.value.len() < 2 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "abba",
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
                field: "authentication_parameter_rand",
                message: format!("RAND must be 16 bytes, got {}", rand.value.len()),
            });
        }

        // AUTN must be exactly 16 bytes if present
        if let Some(ref autn) = self.authentication_parameter_autn
            && autn.value.len() != 16
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "authentication_parameter_autn",
                message: format!("AUTN must be 16 bytes, got {}", autn.value.len()),
            });
        }

        let has_rand = self.authentication_parameter_rand.is_some();
        let has_autn = self.authentication_parameter_autn.is_some();
        if has_rand != has_autn {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "authentication_parameter_rand",
                message: "RAND and AUTN are required together for 5G AKA".into(),
            });
        }
        if (has_rand && has_autn) == self.eap_message.is_some() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "eap_message",
                message: "exactly one of the 5G AKA or EAP authentication challenges is required"
                    .into(),
            });
        }

        errs
    }
}

impl Validate for AuthenticationFailure {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        // If cause is SynchFailure (0x15), AUTS must be present
        if self.fgmm_cause.value == 0x15 {
            if self.authentication_failure_parameter.is_none() {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "authentication_failure_parameter",
                    message: "AUTS is required when cause is SynchFailure (0x15)".into(),
                });
            } else if let Some(ref auts) = self.authentication_failure_parameter
                && auts.value.len() != 14
            {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "authentication_failure_parameter",
                    message: format!("AUTS must be 14 bytes, got {}", auts.value.len()),
                });
            }
        }

        errs
    }
}

impl Validate for SecurityModeCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_eap(&mut errs, self.eap_message.as_ref());

        let sa = &self.selected_nas_security_algorithms;
        if CipheringAlgorithm::try_from(sa.ciphering_raw())
            .ok()
            .is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "selected_nas_security_algorithms",
                message: format!("Unknown ciphering algorithm 0x{:x}", (sa.value >> 4) & 0x0F),
            });
        }
        if IntegrityAlgorithm::try_from(sa.integrity_raw())
            .ok()
            .is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "selected_nas_security_algorithms",
                message: format!("Unknown integrity algorithm 0x{:x}", sa.value & 0x0F),
            });
        }
        // NIA0 is generally not allowed per TS 33.501 §5.5.1.2,
        // except for emergency registration and unauthenticated emergency services
        if sa.integrity() == Ok(oxirush_utils::identity::Algorithm::Null) {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "selected_nas_security_algorithms",
                message: "NIA0 (null integrity) selected — only valid for emergency services per TS 33.501 §5.5.1.2".into(),
            });
        }

        // Replayed UE security capability minimum 2 bytes
        if self.replayed_ue_security_capabilities.value.len() < 2 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "replayed_ue_security_capabilities",
                message: format!(
                    "Must be at least 2 bytes, got {}",
                    self.replayed_ue_security_capabilities.value.len()
                ),
            });
        }

        errs
    }
}

impl Validate for SecurityModeComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        // NAS message container should be present for initial registration
        // (contains the initial RegistrationRequest), but it's technically optional
        if self
            .imeisv
            .as_ref()
            .is_some_and(|identity| identity.as_imeisv().is_none())
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "imeisv",
                message: "IMEISV must contain a 9-octet mobile identity with matching length"
                    .into(),
            });
        }
        if self
            .non_imeisv_pei
            .as_ref()
            .and_then(|identity| identity.as_imei())
            .is_some_and(|imei| !imei.as_str().ends_with('0'))
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "non_imeisv_pei",
                message: "Transmitted IMEI spare digit must be zero".into(),
            });
        }
        errors
    }
}

impl Validate for IdentityRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.identity_type.value & 0xF8 != 0 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "identity_type",
                message: "Spare bits in 5GS identity type must be zero".into(),
            });
        }
        let id_type = self.identity_type.value & 0x07;
        if id_type == 0 || id_type > 7 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "identity_type",
                message: format!("Invalid identity type {id_type}"),
            });
        }
        errs
    }
}

impl Validate for IdentityResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.mobile_identity.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "mobile_identity",
                message: "Mobile identity is empty".into(),
            });
        }
        if self
            .mobile_identity
            .as_imei()
            .is_some_and(|imei| !imei.as_str().ends_with('0'))
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "mobile_identity",
                message: "Transmitted IMEI spare digit must be zero".into(),
            });
        }
        errs
    }
}

impl Validate for ServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if ServiceTypeValue::try_from(self.service_type.service_type_raw() & 0x0F)
            .ok()
            .is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "service_type",
                message: format!(
                    "Reserved service type 0x{:x}",
                    self.service_type.service_type_raw()
                ),
            });
        }
        if self.fg_s_tmsi.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "fg_s_tmsi",
                message: "5G-S-TMSI is empty".into(),
            });
        }
        errs
    }
}

impl Validate for UlNasTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        push_payload_container_type(&mut errs, Some(&self.payload_container_type));

        let kind = self.payload_container_type.kind();
        push_payload_sor_direction(
            &mut errs,
            &self.payload_container_type,
            &self.payload_container,
            SorTransparentContainerDirection::UeToNetwork,
        );
        if let Some(request_type) = &self.request_type
            && !request_type.is_well_formed()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "request_type",
                message: "Request type uses a reserved sender value or non-zero spare bit".into(),
            });
        }
        if matches!(
            kind,
            Some(PayloadContainerKind::N1SmInformation | PayloadContainerKind::CIoT)
        ) && self.pdu_session_id.is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "pdu_session_id",
                message: "PDU session ID is required for N1 SM or CIoT user data payload".into(),
            });
        }

        if matches!(
            kind,
            Some(PayloadContainerKind::LtePp | PayloadContainerKind::SlppMessageContainer)
        ) && self.additional_information.is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "additional_information",
                message: "Additional information is required for LPP or SLPP payload".into(),
            });
        }

        if self.payload_container.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "payload_container",
                message: "Payload container is empty".into(),
            });
        }

        errs
    }
}

impl Validate for DlNasTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        push_payload_container_type(&mut errs, Some(&self.payload_container_type));

        let kind = self.payload_container_type.kind();
        push_payload_sor_direction(
            &mut errs,
            &self.payload_container_type,
            &self.payload_container,
            SorTransparentContainerDirection::NetworkToUe,
        );
        if matches!(
            kind,
            Some(PayloadContainerKind::N1SmInformation | PayloadContainerKind::CIoT)
        ) && self.pdu_session_id.is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "pdu_session_id",
                message: "PDU session ID is required for N1 SM or CIoT user data payload".into(),
            });
        }

        if matches!(
            kind,
            Some(
                PayloadContainerKind::LtePp
                    | PayloadContainerKind::LocationServices
                    | PayloadContainerKind::UppCmiContainer
                    | PayloadContainerKind::SlppMessageContainer
            )
        ) && self.additional_information.is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "additional_information",
                message: "Additional information is required for this positioning payload".into(),
            });
        }

        if self.payload_container.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "payload_container",
                message: "Payload container is empty".into(),
            });
        }

        errs
    }
}

impl Validate for ControlPlaneServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_payload_container_type(&mut errs, self.payload_container_type.as_ref());

        if self.ciot_small_data_container.is_some()
            && !self.ciot_small_data_container_is_exclusive()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "ciot_small_data_container",
                message: "CIoT small data container shall not be combined with other optional IEs"
                    .into(),
            });
        }

        if let Some(container) = &self.ciot_small_data_container {
            push_ie_strict_result(
                &mut errs,
                "ciot_small_data_container",
                container.validate_strict(),
            );
        }

        if self.payload_container.is_some() && self.payload_container_type.is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "payload_container_type",
                message:
                    "Payload container type is required when the payload container IE is present"
                        .into(),
            });
        }
        if self.payload_container_type.is_some() && self.payload_container.is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "payload_container",
                message: "Payload container is required when its type IE is present".into(),
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
                field: "pdu_session_id",
                message: "PDU session ID is required for a CIoT user data payload container".into(),
            });
        }

        errs
    }
}

impl Validate for PduSessionEstablishmentRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
        if !self.integrity_protection_maximum_data_rate.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "integrity_protection_maximum_data_rate",
                message: "UL and DL rates must use 64 kbps, NULL, or full-rate codes".into(),
            });
        }
        if let Some(session_type) = &self.pdu_session_type
            && !session_type.is_well_formed()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "pdu_session_type",
                message: "PDU session type uses a reserved value or non-zero spare bit".into(),
            });
        }
        if let Some(ssc_mode) = &self.ssc_mode
            && !ssc_mode.is_well_formed()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "ssc_mode",
                message: "SSC mode uses a reserved sender value or non-zero spare bit".into(),
            });
        }
        if let Some(address) = &self.suggested_interface_identifier {
            if !address.is_well_formed() {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "suggested_interface_identifier",
                    message: "PDU address contents do not match the selected type".into(),
                });
            } else if address.smf_ipv6_ll_indicator() {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "suggested_interface_identifier",
                    message: "SI6LLA is not sent by the UE".into(),
                });
            }
        }
        if let Some(packet_filters) = &self.maximum_number_of_supported_packet_filters {
            push_ie_strict_result(
                &mut errs,
                "maximum_number_of_supported_packet_filters",
                packet_filters.validate_strict(),
            );
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for PduSessionEstablishmentAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if !self.selected_pdu_session_type.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "selected_pdu_session_type",
                message: "PDU session type uses a reserved value or non-zero spare bit".into(),
            });
        }
        let selected_ssc_mode = self.selected_ssc_mode.value;
        if selected_ssc_mode & 0x08 != 0
            || SscModeValue::try_from(selected_ssc_mode & 0x07)
                .ok()
                .is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "selected_ssc_mode",
                message: "selected SSC mode uses a reserved sender value or non-zero spare bit"
                    .into(),
            });
        }
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
        push_optional_eap(&mut errs, self.eap_message.as_ref());

        if let Some(address) = &self.pdu_address
            && !address.is_well_formed()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "pdu_address",
                message: "PDU address contents do not match the selected type".into(),
            });
        }

        // QoS rules must not be empty
        if self.authorized_qos_rules.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "authorized_qos_rules",
                message: "QoS rules are empty".into(),
            });
        }
        push_ie_strict_result(
            &mut errs,
            "authorized_qos_rules",
            self.authorized_qos_rules.validate_strict(),
        );

        // Session-AMBR must be 6 bytes
        if self.session_ambr.value.len() != 6 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "session_ambr",
                message: format!(
                    "Session-AMBR must be 6 bytes, got {}",
                    self.session_ambr.value.len()
                ),
            });
        }

        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }

        errs
    }
}

impl Validate for PduSessionEstablishmentReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
        push_optional_eap(&mut errs, self.eap_message.as_ref());
        if self.fgsm_cause.cause().is_none() {
            errs.push(ValidationError {
                severity: Severity::Warning,
                field: "fgsm_cause",
                message: format!("Unknown 5GSM cause code 0x{:02x}", self.fgsm_cause.value),
            });
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for PduSessionModificationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
        if let Some(packet_filters) = &self.maximum_number_of_supported_packet_filters {
            push_ie_strict_result(
                &mut errs,
                "maximum_number_of_supported_packet_filters",
                packet_filters.validate_strict(),
            );
        }
        if let Some(rules) = &self.requested_qos_rules {
            push_ie_strict_result(&mut errs, "requested_qos_rules", rules.validate_strict());
        }
        if let Some(descriptions) = &self.requested_qos_flow_descriptions
            && descriptions.contains_eps_bearer_identity()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "requested_qos_flow_descriptions",
                message:
                    "EPS bearer identity shall not be included in a mobile-originated 5GSM message"
                        .into(),
            });
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }
        if let Some(device_information) = &self.non_3gpp_device_information {
            push_ie_strict_result(
                &mut errs,
                "non_3gpp_device_information",
                device_information.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for PduSessionModificationCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
        if let Some(rules) = &self.authorized_qos_rules {
            push_ie_strict_result(&mut errs, "authorized_qos_rules", rules.validate_strict());
        }
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for PduSessionReleaseCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
        push_optional_eap(&mut errs, self.eap_message.as_ref());
        if let Some(container) = &self.service_level_aa_container {
            push_ie_strict_result(
                &mut errs,
                "service_level_aa_container",
                container.validate_strict(),
            );
        }
        errs
    }
}

impl Validate for ServiceLevelAuthenticationCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.service_level_aa_container.value.len() < 3 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "service_level_aa_container",
                message: "Mandatory container must contain at least 3 octets".into(),
            });
        }
        push_ie_strict_result(
            &mut errs,
            "service_level_aa_container",
            self.service_level_aa_container.validate_strict(),
        );
        errs
    }
}

impl Validate for ServiceLevelAuthenticationComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if self.service_level_aa_container.value.len() < 3 {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "service_level_aa_container",
                message: "Mandatory container must contain at least 3 octets".into(),
            });
        }
        push_ie_strict_result(
            &mut errs,
            "service_level_aa_container",
            self.service_level_aa_container.validate_strict(),
        );
        errs
    }
}

impl Validate for RelayKeyRequest {
    fn validate(&self) -> Vec<ValidationError> {
        if self.relay_key_request_parameters.parse().is_some() {
            Vec::new()
        } else {
            vec![ValidationError {
                severity: Severity::Error,
                field: "relay_key_request_parameters",
                message: "Mandatory relay key request parameters require at least 20 octets".into(),
            }]
        }
    }
}

impl Validate for RelayKeyAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if self.relay_key_response_parameters.parse().is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "relay_key_response_parameters",
                message: "Mandatory relay key response parameters require at least 49 octets"
                    .into(),
            });
        }
        push_optional_eap(&mut errors, self.eap_message.as_ref());
        errors
    }
}

impl Validate for NotificationResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(status) = &self.pdu_session_status
            && !(2..=32).contains(&status.value.len())
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "pdu_session_status",
                message: "PDU session status must contain 2–32 octets".into(),
            });
        }
        errors
    }
}

impl Validate for RemoteUeReport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        for (field, list) in [
            (
                "remote_ue_context_connected",
                self.remote_ue_context_connected.as_ref(),
            ),
            (
                "remote_ue_context_disconnected",
                self.remote_ue_context_disconnected.as_ref(),
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

impl Validate for PduSessionModificationComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if self.fgsm_cause.is_some() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "fgsm_cause",
                message: "IEI 0x59 is receiver-compatible Release-15.3 syntax and shall not be sent by a current-release implementation".into(),
            });
        }
        push_optional_epco(
            &mut errors,
            self.extended_protocol_configuration_options.as_ref(),
        );
        if self
            .port_management_information_container
            .as_ref()
            .is_some_and(|ie| ie.value.is_empty())
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "port_management_information_container",
                message: "Optional container must contain at least one octet".into(),
            });
        }
        errors
    }
}

impl Validate for DeregistrationRequestUeOriginating {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        if self.de_registration_type.access_type().is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "de_registration_type",
                message: format!(
                    "Invalid access type value {}",
                    self.de_registration_type.access_type_raw()
                ),
            });
        }

        if self.fgs_mobile_identity.value.is_empty() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "fgs_mobile_identity",
                message: "Mobile identity is empty".into(),
            });
        }

        errs
    }
}

impl Validate for DeregistrationRequestUeTerminated {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        if self.de_registration_type.access_type().is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "de_registration_type",
                message: format!(
                    "Invalid access type value {}",
                    self.de_registration_type.access_type_raw()
                ),
            });
        }

        errs
    }
}

impl Validate for Notification {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();

        if !self.access_type.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "access_type",
                message: format!(
                    "Invalid access type value {}",
                    self.access_type.access_type_raw()
                ),
            });
        }

        errs
    }
}

impl Validate for RegistrationComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(container) = &self.sor_transparent_container {
            push_sor_direction(
                &mut errors,
                container,
                SorTransparentContainerDirection::UeToNetwork,
            );
        }
        errors
    }
}

impl_validate_empty!(
    DeregistrationAcceptUeOriginating,
    DeregistrationAcceptUeTerminated,
    ConfigurationUpdateComplete,
    SecurityModeReject,
    GmmStatus,
    GsmStatus,
    RemoteUeReportResponse,
);

impl_validate_mandatory_eap!(
    AuthenticationResult,
    RelayAuthenticationRequest,
    RelayAuthenticationResponse,
    PduSessionAuthenticationCommand => extended_protocol_configuration_options,
    PduSessionAuthenticationComplete => extended_protocol_configuration_options,
);

impl_validate_optional_eap!(
    ServiceReject,
    ServiceAccept,
    AuthenticationResponse,
    AuthenticationReject,
    RelayKeyReject,
    PduSessionAuthenticationResult => extended_protocol_configuration_options,
);

impl_validate_snssai_eap!(
    NetworkSliceSpecificAuthenticationCommand,
    NetworkSliceSpecificAuthenticationComplete,
    NetworkSliceSpecificAuthenticationResult,
);

impl_validate_optional_epco!(
    PduSessionModificationReject,
    PduSessionModificationCommandReject,
    PduSessionReleaseRequest,
    PduSessionReleaseReject,
    PduSessionReleaseComplete,
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_ie_sender_checks_run_in_5gs_messages() {
        // A network name without its extension bit, as in
        // EPS EMM INFORMATION.
        let command = Message::decode(&[0x7e, 0x00, 0x54, 0x43, 0x02, 0x10, 0x41]).unwrap();
        assert!(command.validate().iter().any(|error| {
            error.field == "full_name_for_network" && error.severity == Severity::Error
        }));
        // A two-octet UE status with spare bits set.
        let mut request =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        assert!(Message::decode(&request).unwrap().validate().is_empty());
        request.extend([0x2b, 0x02, 0xff, 0xff]);
        let request = Message::decode(&request).unwrap();
        assert!(
            request
                .validate()
                .iter()
                .any(|error| error.field == "ue_status" && error.severity == Severity::Error)
        );
    }

    #[test]
    fn sor_wire_values_preserve_receiver_fallback_and_enforce_message_direction() {
        // A syntactically short information form is a malformed optional IE:
        // it is absent from the typed message but retained for byte-exact relay.
        let mut malformed = hex::decode("7e00420101730011").unwrap();
        malformed.extend([0u8; 17]);
        let decoded = Message::decode(&malformed).unwrap();
        assert_eq!(decoded.encode().unwrap(), malformed);
        let Message::Gmm(_, GmmMessage::RegistrationAccept(accept)) = decoded else {
            panic!("REGISTRATION ACCEPT expected");
        };
        assert!(accept.sor_transparent_container.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);

        // ACK is structurally valid but UE-to-network only, so its use in a
        // network Registration Accept is retained and rejected for sending.
        let mut wrong_ack = hex::decode("7e00420101730011").unwrap();
        wrong_ack.push(0x01);
        wrong_ack.extend([0u8; 16]);
        let decoded = Message::decode(&wrong_ack).unwrap();
        assert_eq!(decoded.encode().unwrap(), wrong_ack);
        assert!(
            decoded
                .validate()
                .iter()
                .any(|error| { error.field == "sor_transparent_container" })
        );

        // Conversely, an LT=0 information form belongs to network-to-UE and
        // is invalid in a UE Registration Complete.
        let mut wrong_information = hex::decode("7e0043730013").unwrap();
        wrong_information.extend([0u8; 19]);
        let decoded = Message::decode(&wrong_information).unwrap();
        assert_eq!(decoded.encode().unwrap(), wrong_information);
        assert!(
            decoded
                .validate()
                .iter()
                .any(|error| { error.field == "sor_transparent_container" })
        );
    }

    #[test]
    fn repeated_and_out_of_sequence_ies_are_reported() {
        // REGISTRATION REJECT with T3346 (5F) twice, then T3502 (16) before
        // T3346, which Table 8.2.9.1 lists first.
        let repeated =
            Message::decode(&[0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x21, 0x5f, 0x01, 0x22]).unwrap();
        assert!(
            repeated
                .validate()
                .iter()
                .any(|error| { error.field == "unknown_ies" && error.severity == Severity::Error })
        );
        let wire = [0x7e, 0x00, 0x44, 0x16, 0x16, 0x01, 0x21, 0x5f, 0x01, 0x21];
        let reordered = Message::decode(&wire).unwrap();
        assert_eq!(reordered.encode().unwrap(), wire);
        assert!(
            reordered
                .validate()
                .iter()
                .any(|error| { error.field == "unknown_ies" && error.severity == Severity::Error })
        );
    }

    #[test]
    fn identity_request_preserves_wire_spares_and_reports_them() {
        let wire = [0x7e, 0x00, 0x5b, 0xf1];
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
        assert!(message.validate().iter().any(|error| {
            error.field == "identity_type" && error.message.contains("Spare bits")
        }));
    }

    #[test]
    fn ul_nas_transport_preserves_wire_spares_and_reports_them() {
        let wire = [0x7e, 0x00, 0x67, 0xf2, 0x00, 0x01, 0x00];
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
        assert!(message.validate().iter().any(|error| {
            error.field == "payload_container_type" && error.message.contains("Spare")
        }));
    }

    #[test]
    fn malformed_dnn_and_pdu_address_are_absent_on_receive() {
        let dnn_wire = [
            0x7e, 0x00, 0x67, 0x02, 0x00, 0x01, 0x01, 0x25, 0x02, 0x05, 0x61,
        ];
        let decoded = Message::decode(&dnn_wire).unwrap();
        assert_eq!(decoded.encode().unwrap(), dnn_wire);
        let Message::Gmm(_, GmmMessage::UlNasTransport(transport)) = decoded else {
            panic!("UL NAS TRANSPORT expected");
        };
        assert!(transport.dnn.is_none());
        assert_eq!(transport.unknown_ies.len(), 1);

        let wire =
            hex::decode("2e0101c211000901000631310101ff010603f42403f42429050200000000").unwrap();
        let decoded = Message::decode(&wire).unwrap();
        assert_eq!(decoded.encode().unwrap(), wire);
        let Message::Gsm(_, GsmMessage::PduSessionEstablishmentAccept(accept)) = decoded else {
            panic!("PDU SESSION ESTABLISHMENT ACCEPT expected");
        };
        assert!(accept.pdu_address.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);
    }

    #[test]
    fn malformed_tai_list_is_absent_on_receive() {
        let plmn = Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap();
        let one = TrackingAreaIdentityList::from_plmn_tacs(&plmn, &[1]);
        let mut malformed = one.unwrap().value;
        malformed[0] = 0x01;
        let message = Message::new_5gmm(
            RegistrationAccept::new(RegistrationResult::new(vec![1]))
                .with_tai_list(TrackingAreaIdentityList::new(malformed)),
        );
        let wire = message.encode().unwrap();
        let decoded = Message::decode(&wire).unwrap();
        assert_eq!(decoded.encode().unwrap(), wire);
        let Message::Gmm(_, GmmMessage::RegistrationAccept(accept)) = decoded else {
            panic!("REGISTRATION ACCEPT expected");
        };
        assert!(accept.tai_list.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);
    }

    #[test]
    fn malformed_service_area_list_is_absent_on_receive() {
        let plmn = Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap();
        let mut malformed =
            ServiceAreaList::from_plmn_tacs(ServiceAreaListAllowedType::Allowed, &plmn, &[1])
                .unwrap();
        malformed.value[0] = 0x01;
        let message = Message::new_5gmm(
            RegistrationAccept::new(RegistrationResult::new(vec![1]))
                .with_service_area_list(malformed),
        );
        let wire = message.encode().unwrap();
        let decoded = Message::decode(&wire).unwrap();
        assert_eq!(decoded.encode().unwrap(), wire);
        let Message::Gmm(_, GmmMessage::RegistrationAccept(accept)) = decoded else {
            panic!("REGISTRATION ACCEPT expected");
        };
        assert!(accept.service_area_list.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);
    }

    #[test]
    fn mandatory_eap_requires_a_complete_packet() {
        let empty = PduSessionAuthenticationCommand::new(EapMessage::new(vec![]));
        assert!(
            empty
                .validate()
                .iter()
                .any(|error| error.field == "eap_message")
        );
        let valid =
            PduSessionAuthenticationCommand::new(EapMessage::new(vec![0x03, 0x01, 0x00, 0x04]));
        assert!(valid.validate().is_empty());
        let mismatched =
            PduSessionAuthenticationCommand::new(EapMessage::new(vec![0x03, 0x01, 0x00, 0x05]));
        assert!(
            mismatched
                .validate()
                .iter()
                .any(|error| error.field == "eap_message")
        );
    }

    #[test]
    fn optional_eap_is_checked_when_present() {
        let empty =
            ServiceReject::new(GmmCause::new(0x16)).with_eap_message(EapMessage::new(vec![]));
        assert!(
            empty
                .validate()
                .iter()
                .any(|error| error.field == "eap_message")
        );
        let absent = ServiceReject::new(GmmCause::new(0x16));
        assert!(absent.validate().is_empty());
    }

    #[test]
    fn relay_parameter_and_slice_auth_mandatory_lengths() {
        let request = RelayKeyRequest::new(
            ProseRelayTransactionIdentity::new(1),
            RelayKeyRequestParameters::new(vec![]),
        );
        assert!(
            request
                .validate()
                .iter()
                .any(|error| error.field == "relay_key_request_parameters")
        );
        let accept = RelayKeyAccept::new(
            ProseRelayTransactionIdentity::new(1),
            RelayKeyResponseParameters::new(vec![0; 48]),
        );
        assert!(
            accept
                .validate()
                .iter()
                .any(|error| error.field == "relay_key_response_parameters")
        );
        let slice = NetworkSliceSpecificAuthenticationCommand::new(
            SNssai::new(vec![]),
            EapMessage::new(vec![3, 1, 0, 4]),
        );
        assert!(
            slice
                .validate()
                .iter()
                .any(|error| error.field == "s_nssai")
        );
    }

    #[test]
    fn notification_response_checks_pdu_session_status_length() {
        let invalid =
            NotificationResponse::new().with_pdu_session_status(PduSessionStatus::new(vec![]));
        assert!(
            invalid
                .validate()
                .iter()
                .any(|error| error.field == "pdu_session_status")
        );
        let valid = NotificationResponse::new()
            .with_pdu_session_status(PduSessionStatus::from_sessions(&[1]).unwrap());
        assert!(valid.validate().is_empty());
    }

    #[test]
    fn remote_ue_report_checks_context_list_length() {
        let report = RemoteUeReport::new()
            .with_remote_ue_context_connected(RemoteUeContextList::new(vec![]));
        assert!(
            report
                .validate()
                .iter()
                .any(|error| { error.field == "remote_ue_context_connected" })
        );
    }

    #[test]
    fn optional_epco_requires_a_value() {
        let request =
            PduSessionEstablishmentRequest::new(IntegrityProtectionMaximumDataRate::new(1))
                .with_extended_protocol_configuration_options(
                    ExtendedProtocolConfigurationOptions::new(vec![]),
                );
        assert!(
            request
                .validate()
                .iter()
                .any(|error| { error.field == "extended_protocol_configuration_options" })
        );
        let malformed = PduSessionReleaseReject::new(GsmCause::new(0x1a))
            .with_extended_protocol_configuration_options(
                ExtendedProtocolConfigurationOptions::new(vec![0x00]),
            );
        assert!(
            malformed
                .validate()
                .iter()
                .any(|error| { error.field == "extended_protocol_configuration_options" })
        );
        let authentication =
            PduSessionAuthenticationCommand::new(EapMessage::new(vec![3, 1, 0, 4]))
                .with_extended_protocol_configuration_options(
                    ExtendedProtocolConfigurationOptions::new(vec![]),
                );
        assert!(
            authentication
                .validate()
                .iter()
                .any(|error| { error.field == "extended_protocol_configuration_options" })
        );
        let reject = PduSessionReleaseReject::new(GsmCause::new(0x1a))
            .with_extended_protocol_configuration_options(
                ExtendedProtocolConfigurationOptions::new(vec![]),
            );
        assert!(
            reject
                .validate()
                .iter()
                .any(|error| { error.field == "extended_protocol_configuration_options" })
        );
        let complete = PduSessionModificationComplete::new()
            .with_port_management_information_container(PortManagementInformationContainer::new(
                vec![],
            ));
        assert!(
            complete
                .validate()
                .iter()
                .any(|error| { error.field == "port_management_information_container" })
        );
    }

    #[test]
    fn security_mode_complete_requires_imeisv_identity() {
        let valid = SecurityModeComplete::new()
            .with_imeisv(MobileIdentity::from_imeisv("1234567890123456").unwrap());
        assert!(valid.validate().is_empty());
        let invalid = SecurityModeComplete::new().with_imeisv(MobileIdentity::new(vec![]));
        assert!(
            invalid
                .validate()
                .iter()
                .any(|error| error.field == "imeisv")
        );
    }

    #[test]
    fn transmitted_imei_requires_zero_spare_digit() {
        let conforming =
            IdentityResponse::new(MobileIdentity::from_imei_tac_snr("49015420323751").unwrap());
        assert!(conforming.validate().is_empty());
        let interoperable =
            IdentityResponse::new(MobileIdentity::from_imei("490154203237518").unwrap());
        assert!(
            interoperable
                .validate()
                .iter()
                .any(|error| error.field == "mobile_identity")
        );
    }

    #[test]
    fn a_spare_half_octet_of_a_header_that_is_not_zero_is_reported() {
        let spare = |findings: Vec<ValidationError>| {
            (findings.iter())
                .filter(|finding| finding.field == "spare_half_octet")
                .count()
        };

        // A plain message, then one whose header and whose inner header
        // both have spare bits set
        for (wire, reported) in [
            (&[0x7e, 0x00, 0x43][..], 0),
            (&[0x7e, 0xf0, 0x43][..], 1),
            (&[0x7e, 0x01, 0, 0, 0, 0, 0, 0x7e, 0x00, 0x43][..], 0),
            (&[0x7e, 0xa1, 0, 0, 0, 0, 0, 0x7e, 0xf0, 0x43][..], 2),
        ] {
            let message = Message::decode(wire).unwrap();
            assert_eq!(spare(message.validate()), reported, "{wire:02x?}");
        }
    }

    #[test]
    fn top_level_validation_reports_message_type_mismatch() {
        let mut message = Message::new_5gmm(RegistrationComplete::new());
        if let Message::Gmm(header, _) = &mut message {
            header.message_type = crate::nas_5gs::GmmMessageType::RegistrationRequest;
        }
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "message")
        );
    }

    #[test]
    fn test_valid_registration_request() {
        let msg = RegistrationRequest::new(
            RegistrationType::new(0x09), // FOR=1, initial
            KeySetIdentifier::new(7),
            MobileIdentity::new(vec![0x01, 0x02, 0x03, 0x04, 0x05]), // SUCI
        );
        let errs = msg.validate();
        assert!(errs.is_empty(), "Unexpected errors: {errs:?}");
    }

    /// A T3512 value may have the 320-hour unit (TS 24.008 Table 10.5.163a
    /// NOTE 1), which the other GPRS timers 3 of TS 24.501 may not.
    #[test]
    fn a_t3512_value_may_count_in_320_hours() {
        // REGISTRATION ACCEPT, 3GPP access, T3512 of twice 320 hours.
        let wire = [0x7e, 0x00, 0x42, 0x01, 0x01, 0x5e, 0x01, 0xc2];
        let message = Message::decode(&wire).unwrap();
        let fields: Vec<_> = message.validate().iter().map(|error| error.field).collect();
        assert!(!fields.contains(&"t3512_value"), "{fields:?}");
    }

    /// The non-current native ngKSI of a REGISTRATION REQUEST is that of a
    /// native context, 0 to 6 (§8.2.6.2), as in EPS (TS 24.301 §8.2.29.2).
    #[test]
    fn non_current_native_ngksi_is_native() {
        let request = |ksi: u8| {
            RegistrationRequest::new(
                RegistrationType::new(0x02),
                KeySetIdentifier::new(0x09),
                MobileIdentity::new(vec![0xf2, 0x02, 0xf8, 0x39, 1, 0, 0x41, 1, 2, 3, 4]),
            )
            .with_non_current_native_nas_key_set_identifier(KeySetIdentifier::new(ksi))
        };
        let fields = |ksi: u8| -> Vec<&'static str> {
            request(ksi)
                .validate()
                .iter()
                .map(|error| error.field)
                .collect()
        };
        assert!(!fields(6).contains(&"non_current_native_nas_key_set_identifier"));
        for ksi in [7, 0x08, 0x0e] {
            assert!(
                fields(ksi).contains(&"non_current_native_nas_key_set_identifier"),
                "{ksi}"
            );
        }
    }

    #[test]
    fn test_invalid_registration_type() {
        let msg = RegistrationRequest::new(
            RegistrationType::new(0x00), // Invalid: type=0
            KeySetIdentifier::new(0),
            MobileIdentity::new(vec![0x01, 0x02]),
        );
        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "fgs_registration_type" && e.severity == Severity::Error)
        );
    }

    #[test]
    fn test_invalid_abba_length() {
        let msg = AuthenticationRequest::new(
            KeySetIdentifier::new(0),
            Abba::new(vec![0x00]), // Only 1 byte, need 2
        );
        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "abba" && e.severity == Severity::Error)
        );
    }

    #[test]
    fn authentication_request_requires_exactly_one_complete_mechanism() {
        let base =
            || AuthenticationRequest::new(KeySetIdentifier::new(0), Abba::new(vec![0x00, 0x00]));
        assert!(base().validate().iter().any(|e| e.field == "eap_message"));
        assert!(
            base()
                .with_authentication_parameter_rand(AuthenticationParameterRand::new(vec![0; 16]))
                .validate()
                .iter()
                .any(|e| e.field == "authentication_parameter_rand")
        );

        let aka = base()
            .with_authentication_parameter_rand(AuthenticationParameterRand::new(vec![0; 16]))
            .with_authentication_parameter_autn(AuthenticationParameterAutn::new(vec![0; 16]));
        assert!(aka.validate().is_empty());

        let eap = base().with_eap_message(EapMessage::new(vec![3, 1, 0, 4]));
        assert!(eap.validate().is_empty());
        assert!(
            aka.with_eap_message(EapMessage::new(vec![3, 1, 0, 4]))
                .validate()
                .iter()
                .any(|e| e.field == "eap_message")
        );
    }

    #[test]
    fn payload_container_types_and_registration_pair_are_checked() {
        let invalid =
            UlNasTransport::new(PayloadContainerType::new(0), PayloadContainer::new(vec![1]));
        assert!(
            invalid
                .validate()
                .iter()
                .any(|e| { e.field == "payload_container_type" && e.message.contains("reserved") })
        );

        let registration = RegistrationRequest::new(
            RegistrationType::new(0x01),
            KeySetIdentifier::new(0),
            MobileIdentity::new(vec![1, 2]),
        )
        .with_payload_container(PayloadContainer::new(vec![1]));
        assert!(
            registration
                .validate()
                .iter()
                .any(|e| e.field == "payload_container_type")
        );
        let wrong_kind = registration.with_payload_container_type(PayloadContainerType::from_kind(
            PayloadContainerKind::Sms,
        ));
        assert!(
            wrong_kind.validate().iter().any(|e| {
                e.field == "payload_container_type" && e.message.contains("UE policy")
            })
        );
    }

    #[test]
    fn establishment_sender_values_follow_strict_tables() {
        for value in [0x0000, 0x0101, 0xFFFF] {
            let request =
                PduSessionEstablishmentRequest::new(IntegrityProtectionMaximumDataRate::new(value));
            assert!(request.validate().is_empty(), "0x{value:04x}");
        }
        for value in [0x0002, 0x0200] {
            let request =
                PduSessionEstablishmentRequest::new(IntegrityProtectionMaximumDataRate::new(value));
            assert!(
                request
                    .validate()
                    .iter()
                    .any(|e| { e.field == "integrity_protection_maximum_data_rate" })
            );
        }
        let request =
            PduSessionEstablishmentRequest::new(IntegrityProtectionMaximumDataRate::new(0))
                .with_pdu_session_type(PduSessionType::new(7))
                .with_ssc_mode(SscMode::new(7));
        let findings = request.validate();
        assert!(findings.iter().any(|e| e.field == "pdu_session_type"));
        assert!(findings.iter().any(|e| e.field == "ssc_mode"));

        let accept = PduSessionEstablishmentAccept::new(
            PduSessionType::new(7),
            SscMode::new(1),
            QosRules::new(vec![]),
            SessionAmbr::new(vec![0; 6]),
        );
        assert!(
            accept
                .validate()
                .iter()
                .any(|e| e.field == "selected_pdu_session_type")
        );
        let mut accept = PduSessionEstablishmentAccept::new(
            PduSessionType::from_session_type(PduSessionTypeValue::Ipv4),
            SscMode::new(1),
            QosRules::new(vec![]),
            SessionAmbr::new(vec![0; 6]),
        );
        for value in [0, 4, 5, 6, 7, 9] {
            accept.selected_ssc_mode.value = value;
            assert!(
                accept
                    .validate()
                    .iter()
                    .any(|e| e.field == "selected_ssc_mode")
            );
        }
    }

    #[test]
    fn test_nia0_rejected() {
        let msg = SecurityModeCommand::new(
            SecurityAlgorithms::new(0x20), // NEA2 + NIA0
            KeySetIdentifier::new(0),
            UeSecurityCapability::new(vec![0xE0, 0xE0]),
        );
        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.message.contains("NIA0") && e.severity == Severity::Warning)
        );
    }

    #[test]
    fn test_synch_failure_needs_auts() {
        let msg = AuthenticationFailure::new(GmmCause::new(0x15)); // SynchFailure, no AUTS
        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "authentication_failure_parameter")
        );
    }

    #[test]
    fn test_ul_nas_transport_needs_psi() {
        let msg = UlNasTransport::new(
            PayloadContainerType::new(0x01), // N1 SM
            PayloadContainer::new(vec![0x2E, 0x01, 0x01, 0xC1]),
        );
        // No PDU session ID set
        let errs = msg.validate();
        assert!(errs.iter().any(|e| e.field == "pdu_session_id"));
    }

    #[test]
    fn nas_transport_conditional_ies_cover_all_payload_kinds() {
        for kind in [
            PayloadContainerKind::N1SmInformation,
            PayloadContainerKind::CIoT,
        ] {
            let ul = UlNasTransport::new(
                PayloadContainerType::from_kind(kind),
                PayloadContainer::new(vec![0x01]),
            );
            let dl = DlNasTransport::new(
                PayloadContainerType::from_kind(kind),
                PayloadContainer::new(vec![0x01]),
            );
            assert!(ul.validate().iter().any(|e| e.field == "pdu_session_id"));
            assert!(dl.validate().iter().any(|e| e.field == "pdu_session_id"));
        }

        for kind in [
            PayloadContainerKind::LtePp,
            PayloadContainerKind::SlppMessageContainer,
        ] {
            let message = UlNasTransport::new(
                PayloadContainerType::from_kind(kind),
                PayloadContainer::new(vec![0x01]),
            );
            assert!(
                message
                    .validate()
                    .iter()
                    .any(|e| e.field == "additional_information")
            );
        }
        for kind in [
            PayloadContainerKind::LtePp,
            PayloadContainerKind::LocationServices,
            PayloadContainerKind::UppCmiContainer,
            PayloadContainerKind::SlppMessageContainer,
        ] {
            let message = DlNasTransport::new(
                PayloadContainerType::from_kind(kind),
                PayloadContainer::new(vec![0x01]),
            );
            assert!(
                message
                    .validate()
                    .iter()
                    .any(|e| e.field == "additional_information")
            );
        }
    }

    #[test]
    fn request_and_access_type_sender_values_are_strict() {
        let request = UlNasTransport::new(
            PayloadContainerType::from_kind(PayloadContainerKind::Sms),
            PayloadContainer::new(vec![1]),
        )
        .with_request_type(RequestType::new(7));
        assert!(request.validate().iter().any(|e| e.field == "request_type"));

        // A spare bit of the access type, and the spare half octet beside it.
        for access_type in [AccessType::new(0x0A), AccessType::new(0xF2)] {
            let notification = Notification::new(access_type);
            assert!(
                notification
                    .validate()
                    .iter()
                    .any(|e| e.field == "access_type")
            );
        }
        let decoded = Message::decode(&[0x7e, 0x00, 0x65, 0xfa]).unwrap();
        assert!(decoded.validate().iter().any(|e| e.field == "access_type"));
    }

    #[test]
    fn test_control_plane_service_request_ciot_must_be_exclusive() {
        let ciot = CiotSmallDataContainer::from_parsed(&CiotSmallDataContainerContents::Sms {
            data: vec![0xAA],
        })
        .unwrap();
        let msg = ControlPlaneServiceRequest::new(
            ControlPlaneServiceType::default(),
            KeySetIdentifier::default(),
        )
        .with_ciot_small_data_container(ciot)
        .with_release_assistance_indication(ReleaseAssistanceIndication::from_ddx(
            DownlinkDataExpected::NoFurtherData,
        ));

        let errs = msg.validate();
        assert!(
            errs.iter().any(|e| {
                e.field == "ciot_small_data_container" && e.severity == Severity::Error
            })
        );
    }

    #[test]
    fn test_registration_request_composes_fgmm_capability_strict_validation() {
        let mut msg = RegistrationRequest::new(
            RegistrationType::new(0x09),
            KeySetIdentifier::new(7),
            MobileIdentity::new(vec![0x01, 0x02]),
        );
        let mut capability = vec![0; 13];
        capability[12] = 0x01;
        msg.fgmm_capability = Some(GmmCapability::new(capability));

        let errs = msg.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "fgmm_capability" && e.severity == Severity::Error)
        );
    }

    #[test]
    fn test_pdu_session_modification_request_composes_ie_strict_validation() {
        let msg = PduSessionModificationRequest::new()
            .with_maximum_number_of_supported_packet_filters(
                MaximumNumberOfSupportedPacketFilters::new(vec![0x00, 0x01]),
            );

        let errs = msg.validate();
        assert!(errs.iter().any(|e| {
            e.field == "maximum_number_of_supported_packet_filters" && e.severity == Severity::Error
        }));
    }

    #[test]
    fn test_upds_pti_must_match_ue_initiated_procedure() {
        let message = UpdsMessage::UeStateIndication(UeStateIndication::new(
            NasUpsiList::new(Vec::new()),
            NasUePolicyClassmark::from_flags(false, false, false, false),
        ));
        let envelope = UpdsEnvelope::new_with_pti(
            UpdsProcedureTransactionIdentity::from_network_initiated(0x80).unwrap(),
            message,
        );
        let errs = envelope.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "procedure_transaction_identity"
                    && e.severity == Severity::Error)
        );
    }

    #[test]
    fn test_upds_unsupported_message_warns() {
        let message = UnsupportedUpdsMessage::new(0x99, vec![0xAA]);
        let errs = message.validate();
        assert!(
            errs.iter()
                .any(|e| e.field == "message_type" && e.severity == Severity::Warning)
        );
    }
}
