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

use crate::common::{
    IeLengthCheck, IgnoredIeReason, OptionalIeOrder, ReceiverSyntaxCheck, SenderCheck,
    with_optional_ie_checks,
};
pub use crate::common::{Severity, Validate, ValidationError};

/// Table-derived value-length checks for variable-length 5GS IEs.
macro_rules! ie_length_checked {
    ($($name:ident => $min:expr, $max:expr),* $(,)?) => {
        $(
            impl IeLengthCheck for $name {
                fn receiver_length_ok(&self) -> bool {
                    self.value.len().checked_sub($min).is_some()
                }

                fn sender_length_ok(&self) -> bool {
                    ($min..=$max).contains(&self.value.len())
                }
            }
        )*
    };
}

ie_length_checked!(
    NasAbba => 2, usize::MAX,
    NasAccessTechnologyUtilizationControl => 0, 3,
    NasAdditional5gSecurityInformation => 1, 1,
    NasAdditionalInformation => 1, usize::MAX,
    NasAdditionalInformationRequested => 1, 1,
    NasAllowedPduSessionStatus => 2, 32,
    NasAlternativeNssai => 0, 144,
    NasAtsssContainer => 0, 65535,
    NasAun3DeviceSecurityKey => 34, usize::MAX,
    NasAun3Indication => 1, 1,
    NasAuthenticationFailureParameter => 14, 14,
    NasAuthenticationParameterAutn => 16, 16,
    NasAuthenticationResponseParameter => 16, 16,
    NasCagInformationList => 0, usize::MAX,
    NasCiotSmallDataContainer => 2, 255,
    NasCipheringKeyData => 31, 2672,
    NasDaylightSavingTime => 1, 1,
    NasDnn => 1, 100,
    NasDsTtEthernetPortMacAddress => 6, 6,
    NasEapMessage => 4, 1500,
    NasEcnMarkingL4sIndication => 0, 255,
    NasEmergencyNumberList => 3, 48,
    NasEpsBearerContextStatus => 2, 2,
    NasEpsNasMessageContainer => 1, usize::MAX,
    NasEthernetHeaderCompressionConfiguration => 1, 1,
    NasExtendedCagInformationList => 0, usize::MAX,
    NasExtendedDrxParameters => 1, 2,
    NasExtendedEmergencyNumberList => 4, 65535,
    NasExtendedFGmmCause => 1, 1,
    NasExtendedLadnInformation => 0, 1784,
    NasExtendedProtocolConfigurationOptions => 1, 65535,
    NasExtendedRejectedNssai => 3, 88,
    NasFGmmCapability => 1, 13,
    NasFGsAdditionalRequestResult => 1, 1,
    NasFGsDrxParameters => 1, 1,
    NasFGsMobileIdentity => 1, usize::MAX,
    NasFGsNetworkFeatureSupport => 1, 4,
    NasFGsRegistrationResult => 1, 1,
    NasFGsTrackingAreaIdentityList => 7, 112,
    NasFGsUpdateType => 1, 1,
    NasFGsmCapability => 1, 13,
    NasFGsmCongestionReAttemptIndicator => 1, 1,
    NasFGsmNetworkFeatureSupport => 1, 13,
    NasFeatureAuthorizationIndication => 1, 255,
    NasGprsTimer2 => 1, 1,
    NasGprsTimer3 => 1, 1,
    NasIpHeaderCompressionConfiguration => 3, 255,
    NasLadnIndication => 0, 808,
    NasLadnInformation => 0, 1712,
    NasListOfPlmnsToBeUsedInDisasterCondition => 0, usize::MAX,
    NasLpWuspsAssistanceInformation => 0, 1,
    NasMappedEpsBearerContexts => 4, 65535,
    NasMappedNssai => 1, 40,
    NasMessageContainer => 1, usize::MAX,
    NasMobileStationClassmark2 => 3, 3,
    NasN3Qai => 6, usize::MAX,
    NasN3iwfIdentifier => 5, usize::MAX,
    NasNbN1ModeDrxParameters => 1, 1,
    NasNetworkName => 1, usize::MAX,
    NasNid => 6, 6,
    NasNon3GppAccessPathSwitchingIndication => 1, 1,
    NasNon3GppDelayBudget => 3, usize::MAX,
    NasNon3GppDeviceInformation => 4, usize::MAX,
    NasNon3GppPathSwitchingInformation => 1, 1,
    NasNsagInformation => 6, 3140,
    NasNssai => 2, 144,
    NasNssrgInformation => 4, 4096,
    NasOnDemandNssai => 3, 208,
    NasOperatorDefinedAccessCategoryDefinitions => 0, 8320,
    NasPagingRestriction => 1, 33,
    NasPartialNssai => 0, 805,
    NasPayloadContainer => 1, 65535,
    NasPduAddress => 5, 29,
    NasPduSessionPairId => 1, 1,
    NasPduSessionReactivationResult => 2, 32,
    NasPduSessionReactivationResultErrorCause => 2, 512,
    NasPduSessionStatus => 2, 32,
    NasPeipsAssistanceInformation => 1, 1,
    NasPlmnIdentity => 3, 3,
    NasPlmnList => 3, 45,
    NasPortManagementInformationContainer => 1, 65535,
    NasProtocolDescription => 3, usize::MAX,
    NasQosFlowDescriptions => 3, 65535,
    NasQosRules => 4, 65535,
    NasRanTimingSynchronization => 1, 1,
    NasReAttemptIndicator => 1, 1,
    NasReceivedMbsContainer => 6, 65535,
    NasRegistrationWaitRange => 2, 2,
    NasRejectedNssai => 2, 40,
    NasRelayKeyRequestParameters => 20, 65535,
    NasRelayKeyResponseParameters => 49, 65535,
    NasRemoteUeContextList => 13, 65535,
    NasRequestedMbsContainer => 5, 65535,
    NasRsn => 1, 1,
    NasS1UeNetworkCapability => 2, 13,
    NasS1UeSecurityCapability => 2, 5,
    NasSNssai => 1, 8,
    NasSNssaiLocationValidityInformation => 14, 38608,
    NasSNssaiTimeValidityInformation => 21, 255,
    NasServiceAreaList => 4, 112,
    NasServiceLevelAaContainer => 1, 65535,
    NasServingPlmnRateControl => 2, 2,
    NasSessionAmbr => 6, 6,
    NasSmPduDnRequestContainer => 1, 253,
    NasSnpnList => 9, 135,
    NasSorTransparentContainer => 17, usize::MAX,
    NasSupportedCodecList => 3, usize::MAX,
    NasTnanInformation => 1, usize::MAX,
    NasTruncatedFGSTmsiConfiguration => 1, 1,
    NasType6IeContainer => 3, 65535,
    NasUeDsTtResidenceTime => 8, 8,
    NasUeRadioCapabilityId => 1, usize::MAX,
    NasUeRequestType => 1, 1,
    NasUeSecurityCapability => 2, 8,
    NasUeStatus => 1, 1,
    NasUeUsageSetting => 1, 1,
    NasUnavailabilityConfiguration => 1, 4,
    NasUnavailabilityInformation => 1, 7,
    NasUplinkDataStatus => 2, 32,
    NasUrspRuleEnforcementReports => 2, usize::MAX,
    NasWusAssistanceInformation => 1, 1,
);

/// IE types whose grammar is shared with EPS and whose `is_well_formed()`
/// sender check runs for every message field of that type.
macro_rules! sender_checked {
    ($($name:ident),* $(,)?) => {
        $(
            impl SenderCheck for $name {
                fn sender_check(&self) -> bool {
                    self.is_well_formed()
                }
            }
        )*
    };
}

sender_checked!(
    NasFGsMobileIdentity,
    NasFGsTrackingAreaIdentityList,
    NasFGsNetworkFeatureSupport,
    NasFGsRegistrationResult,
    NasNssai,
    NasQosFlowDescriptions,
    NasQosRules,
    NasReceivedMbsContainer,
    NasRequestedMbsContainer,
    NasSNssai,
    NasSNssaiLocationValidityInformation,
    NasType6IeContainer,
    NasUeDsTtResidenceTime,
    NasUplinkDataStatus,
    NasAccessTechnologyUtilizationControl,
    NasAccessType,
    NasAdditionalInformationRequested,
    NasCagInformationList,
    NasCipheringKeyData,
    NasControlPlaneOnlyIndication,
    NasDaylightSavingTime,
    NasExtendedCagInformationList,
    NasDnn,
    NasIntegrityProtectionMaximumDataRate,
    NasPayloadContainerType,
    NasPduSessionType,
    NasSscMode,
    NasEmergencyNumberList,
    NasEpsBearerContextStatus,
    NasEpsNasSecurityAlgorithms,
    NasExtendedDrxParameters,
    NasExtendedEmergencyNumberList,
    NasExtendedRejectedNssai,
    NasGprsTimer2,
    NasGprsTimer3,
    NasIpHeaderCompressionConfiguration,
    NasLadnIndication,
    NasLadnInformation,
    NasListOfPlmnsToBeUsedInDisasterCondition,
    NasMappedEpsBearerContexts,
    NasMappedNssai,
    NasMaximumNumberOfSupportedPacketFilters,
    NasN3Qai,
    NasMobileStationClassmark2,
    NasNetworkName,
    NasNsagInformation,
    NasNssrgInformation,
    NasOperatorDefinedAccessCategoryDefinitions,
    NasPlmnIdentity,
    NasPlmnList,
    NasProtocolDescription,
    NasPagingRestriction,
    NasPduSessionReactivationResultErrorCause,
    NasPduAddress,
    NasReAttemptIndicator,
    NasRegistrationWaitRange,
    NasRequestType,
    NasRejectedNssai,
    NasS1UeNetworkCapability,
    NasS1UeSecurityCapability,
    NasSecurityAlgorithms,
    NasServiceAreaList,
    NasSorTransparentContainer,
    NasServingPlmnRateControl,
    NasSessionAmbr,
    NasSupportedCodecList,
    NasTimeZone,
    NasTimeZoneAndTime,
    NasTruncatedFGSTmsiConfiguration,
    NasUeRequestType,
    NasUeStatus,
    NasUnavailabilityConfiguration,
    NasUnavailabilityInformation,
    NasWusAssistanceInformation,
);

// TS 24.007 §11.4.2: extra value octets are receiver-tolerated, but an
// empty timer value is a syntactically incorrect optional IE.
impl ReceiverSyntaxCheck for NasGprsTimer2 {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasGprsTimer3 {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasDnn {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasFGsMobileIdentity {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasFGsTrackingAreaIdentityList {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasFGsRegistrationResult {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasFGsNetworkFeatureSupport {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasSNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.parse().is_some()
    }
}

impl ReceiverSyntaxCheck for NasNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }

    fn receiver_syntax_ok_for_field(&self, field: &str) -> bool {
        self.receiver_syntax_is_valid_for_field(field)
    }
}

impl ReceiverSyntaxCheck for NasMappedNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_parse_all().is_some()
    }
}

impl ReceiverSyntaxCheck for NasExtendedRejectedNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasRejectedNssai {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasPduSessionReactivationResultErrorCause {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasPduAddress {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasMappedEpsBearerContexts {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasOperatorDefinedAccessCategoryDefinitions {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_definitions().is_some()
    }
}

// The spare bits of octet 3 are ignored on receipt (TS 24.501 §9.11.4.9).
impl ReceiverSyntaxCheck for NasMaximumNumberOfSupportedPacketFilters {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() == 2 && (17..=1024).contains(&self.max_filters())
    }
}

impl ReceiverSyntaxCheck for NasLadnIndication {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.is_empty() || !self.dnn_values().is_empty()
    }
}

impl ReceiverSyntaxCheck for NasLadnInformation {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.is_empty() || !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for NasNsagInformation {
    fn receiver_syntax_ok(&self) -> bool {
        !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for NasNssrgInformation {
    fn receiver_syntax_ok(&self) -> bool {
        !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for NasCipheringKeyData {
    fn receiver_syntax_ok(&self) -> bool {
        !self.data_sets().is_empty()
    }
}

impl ReceiverSyntaxCheck for NasCagInformationList {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.is_empty() || !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for NasExtendedCagInformationList {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.is_empty() || !self.entries().is_empty()
    }
}

impl ReceiverSyntaxCheck for NasReceivedMbsContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_sessions().is_some()
    }
}

impl ReceiverSyntaxCheck for NasRequestedMbsContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_sessions().is_some()
    }
}

impl ReceiverSyntaxCheck for NasUeDsTtResidenceTime {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 8
    }
}

// Errors inside QoS flow descriptions and QoS rules are errors of the 5GSM
// procedure (§6.3.2.4, §6.4.1.3), which the receiver answers with a 5GSM
// cause; see parse_descriptions and parse_rules. Only an empty value is short
// of the message tables.
impl ReceiverSyntaxCheck for NasQosFlowDescriptions {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasN3Qai {
    fn receiver_syntax_ok(&self) -> bool {
        self.try_entries().is_some()
    }
}

impl ReceiverSyntaxCheck for NasServiceAreaList {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasSorTransparentContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasUplinkDataStatus {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 2
    }
}

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
                        severity: Severity::Error,
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
                        if matches!(inner_msg, Nas5gmmMessage::SecurityModeCommand(_))
                            && hdr.security_header_type
                                != crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "SHT",
                                message:
                                    "SecurityModeCommand requires integrity protection with new context"
                                        .into(),
                            });
                        }
                        if matches!(inner_msg, Nas5gmmMessage::SecurityModeComplete(_))
                            && hdr.security_header_type
                                != crate::nas_5gs::message_types::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                        {
                            errs.push(ValidationError {
                                severity: Severity::Error,
                                field: "SHT",
                                message:
                                    "SecurityModeComplete requires ciphering with new context"
                                        .into(),
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
            Self::RegistrationRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RegistrationAccept(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RegistrationComplete(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RegistrationReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::DeregistrationRequestFromUe(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::DeregistrationRequestToUe(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::DeregistrationAcceptFromUe(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::DeregistrationAcceptToUe(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::ConfigurationUpdateComplete(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::ServiceReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::ServiceAccept(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::ConfigurationUpdateCommand(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::AuthenticationRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::AuthenticationResponse(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::AuthenticationReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::AuthenticationFailure(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::AuthenticationResult(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::SecurityModeCommand(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::SecurityModeComplete(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::SecurityModeReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::IdentityRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::IdentityResponse(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::FGmmStatus(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::Notification(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::NotificationResponse(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::ServiceRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::UlNasTransport(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::DlNasTransport(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::ControlPlaneServiceRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::NetworkSliceSpecificAuthenticationCommand(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::NetworkSliceSpecificAuthenticationComplete(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::NetworkSliceSpecificAuthenticationResult(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RelayKeyRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RelayKeyAccept(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RelayKeyReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RelayAuthenticationRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RelayAuthenticationResponse(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
        }
    }
}

impl Validate for Nas5gsmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        match self {
            Self::PduSessionEstablishmentRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionEstablishmentAccept(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionEstablishmentReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionAuthenticationCommand(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionAuthenticationComplete(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionAuthenticationResult(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionModificationRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionModificationReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionModificationCommand(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionModificationComplete(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionModificationCommandReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionReleaseRequest(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionReleaseReject(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionReleaseCommand(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::PduSessionReleaseComplete(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::FGsmStatus(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::ServiceLevelAuthenticationCommand(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::ServiceLevelAuthenticationComplete(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RemoteUeReport(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
            Self::RemoteUeReportResponse(m) => {
                with_optional_ie_checks(m.validate(), &m.unknown_ies, m.ie_findings())
            }
        }
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
                    field: "UPDS optional IEs",
                    message: format!("IEI 0x{:02X} was ignored as {description}", ie.iei),
                });
            }
        }
    }
    for ie in unknown_ies {
        if ie.is_comprehension_required() {
            findings.push(ValidationError {
                severity: Severity::Error,
                field: "UPDS optional IEs",
                message: format!("Unknown comprehension-required IEI 0x{:02X}", ie.iei),
            });
        }
    }
    findings
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
        let requires_ue_initiated_pti = matches!(
            self.message_type(),
            Some(
                NasUpdsMessageType::UeStateIndication
                    | NasUpdsMessageType::UePolicyProvisioningRequest
                    | NasUpdsMessageType::UePolicyProvisioningReject
            )
        );
        if requires_ue_initiated_pti && !pti.is_ue_initiated() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UPDS PTI",
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
        if !self.ue_policy_section_management_list.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UE policy section management list",
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
                field: "UE policy network classmark",
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
                field: "VPS URSP configuration",
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

impl Validate for NasManageUePolicyComplete {
    fn validate(&self) -> Vec<ValidationError> {
        upds_optional_ie_findings(&self.unknown_ies, None)
    }
}

impl Validate for NasManageUePolicyCommandReject {
    fn validate(&self) -> Vec<ValidationError> {
        if !self.ue_policy_section_management_result.is_well_formed() {
            vec![ValidationError {
                severity: Severity::Error,
                field: "UE policy section management result",
                message: "Mandatory UE policy section management result has invalid Annex D.6.3 framing or values".into(),
            }]
        } else {
            upds_optional_ie_findings(&self.unknown_ies, None)
        }
    }
}

impl Validate for NasUeStateIndication {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errs = Vec::new();
        if !self.upsi_list.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "UPSI list",
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
                field: "UE policy classmark",
                message: "UE policy classmark shall contain 1–3 octets with all spare bits zero"
                    .into(),
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

impl Validate for NasUePolicyProvisioningRequest {
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

impl Validate for NasUePolicyProvisioningReject {
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
    ($($name:ty $(=> $epco:ident)?),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    let mut errors = Vec::new();
                    push_ie_strict_result(&mut errors, "EAP message", self.eap_message.validate_strict());
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

fn push_payload_container_type(
    errors: &mut Vec<ValidationError>,
    container_type: Option<&NasPayloadContainerType>,
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
                field: "Payload container type",
                message: message.into(),
            });
        }
    }
}

fn push_sor_direction(
    errors: &mut Vec<ValidationError>,
    container: &NasSorTransparentContainer,
    direction: SorTransparentContainerDirection,
) {
    if !container.is_well_formed_for(direction) {
        errors.push(ValidationError {
            severity: Severity::Error,
            field: "SOR transparent container",
            message: "SOR grammar or data type does not match the NAS message direction".into(),
        });
    }
}

fn push_payload_sor_direction(
    errors: &mut Vec<ValidationError>,
    container_type: &NasPayloadContainerType,
    payload: &NasPayloadContainer,
    direction: SorTransparentContainerDirection,
) {
    match container_type.kind() {
        Some(PayloadContainerKind::SorTransparentContainer) => {
            let container = NasSorTransparentContainer::new(payload.value.clone());
            push_sor_direction(errors, &container, direction);
        }
        Some(PayloadContainerKind::MultiplePayloads) => {
            match payload.decode_as_multiple_payload_container() {
                Ok(multiple) => {
                    for entry in multiple.entries {
                        if entry.payload_container_type.kind()
                            == Some(PayloadContainerKind::SorTransparentContainer)
                        {
                            let container = NasSorTransparentContainer::new(entry.contents);
                            push_sor_direction(errors, &container, direction);
                        }
                    }
                }
                Err(err) => errors.push(ValidationError {
                    severity: Severity::Error,
                    field: "Payload container",
                    message: err.to_string(),
                }),
            }
        }
        _ => {}
    }
}

fn push_optional_epco(
    errors: &mut Vec<ValidationError>,
    epco: Option<&NasExtendedProtocolConfigurationOptions>,
) {
    if let Some(epco) = epco {
        if epco.value.is_empty() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "Extended protocol configuration options",
                message: "ePCO must contain at least one octet".into(),
            });
        } else if epco.value[0] & 0xf8 != 0x80 {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "Extended protocol configuration options",
                message: "ePCO extension bit and spare bits are invalid".into(),
            });
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
                message: format!("Invalid registration type value {reg_type}"),
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
                        "Unusual identity type {id_type} for registration (expected SUCI=1 or GUTI=2)"
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

        push_payload_container_type(&mut errs, self.payload_container_type.as_ref());
        match (&self.payload_container_type, &self.payload_container) {
            (None, None) => {}
            (Some(container_type), Some(_))
                if container_type.kind() == Some(PayloadContainerKind::UePolicy) => {}
            (Some(_), Some(_)) => errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container type",
                message: "REGISTRATION REQUEST only carries a UE policy payload container".into(),
            }),
            (None, Some(_)) => errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container type",
                message: "Payload container type is required with a payload container".into(),
            }),
            (Some(_), None) => errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container",
                message: "Payload container is required with its type".into(),
            }),
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

        let has_rand = self.authentication_parameter_rand.is_some();
        let has_autn = self.authentication_parameter_autn.is_some();
        if has_rand != has_autn {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "RAND/AUTN",
                message: "RAND and AUTN are required together for 5G AKA".into(),
            });
        }
        if (has_rand && has_autn) == self.eap_message.is_some() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Authentication mechanism",
                message: "exactly one of the 5G AKA or EAP authentication challenges is required"
                    .into(),
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
                message: format!("Invalid identity type {id_type}"),
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
        if ServiceType::from_u8_strict(self.service_type_raw()).is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Service type",
                message: format!("Reserved service type 0x{:X}", self.service_type_raw()),
            });
        }
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
                field: "Request type",
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
                field: "PDU session ID",
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
                field: "Additional information",
                message: "Additional information is required for LPP or SLPP payload".into(),
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
                field: "PDU session ID",
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
                field: "Additional information",
                message: "Additional information is required for this positioning payload".into(),
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
        push_payload_container_type(&mut errs, self.payload_container_type.as_ref());

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
        if self.payload_container_type.is_some() && self.payload_container.is_none() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Payload container",
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
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
        if !self.integrity_protection_maximum_data_rate.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Integrity protection maximum data rate",
                message: "UL and DL rates must use 64 kbps, NULL, or full-rate codes".into(),
            });
        }
        if let Some(session_type) = &self.pdu_session_type
            && !session_type.is_well_formed()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "PDU session type",
                message: "PDU session type uses a reserved value or non-zero spare bit".into(),
            });
        }
        if let Some(ssc_mode) = &self.ssc_mode
            && !ssc_mode.is_well_formed()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "SSC mode",
                message: "SSC mode uses a reserved sender value or non-zero spare bit".into(),
            });
        }
        if let Some(address) = &self.suggested_interface_identifier {
            if !address.is_well_formed() {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "Suggested interface identifier",
                    message: "PDU address contents do not match the selected type".into(),
                });
            } else if address.smf_ipv6_ll_indicator() {
                errs.push(ValidationError {
                    severity: Severity::Error,
                    field: "Suggested interface identifier",
                    message: "SI6LLA is not sent by the UE".into(),
                });
            }
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
        if !self.selected_pdu_session_type.is_well_formed() {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Selected PDU session type",
                message: "PDU session type uses a reserved value or non-zero spare bit".into(),
            });
        }
        let selected_ssc_mode = self.selected_pdu_session_type.type_field;
        if selected_ssc_mode & 0x08 != 0
            || SscModeValue::from_u8_strict(selected_ssc_mode).is_none()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Selected SSC mode",
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
                field: "PDU address",
                message: "PDU address contents do not match the selected type".into(),
            });
        }

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
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
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
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
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
        if let Some(descriptions) = &self.requested_qos_flow_descriptions
            && descriptions.contains_eps_bearer_identity()
        {
            errs.push(ValidationError {
                severity: Severity::Error,
                field: "Requested QoS flow descriptions",
                message:
                    "EPS bearer identity shall not be included in a mobile-originated 5GSM message"
                        .into(),
            });
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
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
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
        push_optional_epco(
            &mut errs,
            self.extended_protocol_configuration_options.as_ref(),
        );
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
        if self.fgsm_cause.is_some() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "5GSM cause",
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
                field: "Port management information container",
                message: "Optional container must contain at least one octet".into(),
            });
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

        if !self.access_type.is_well_formed() || self.access_type.type_field != 0 {
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

impl Validate for NasRegistrationComplete {
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
    NasPduSessionAuthenticationCommand => extended_protocol_configuration_options,
    NasPduSessionAuthenticationComplete => extended_protocol_configuration_options,
);

impl_validate_optional_eap!(
    NasServiceReject,
    NasServiceAccept,
    NasAuthenticationResponse,
    NasAuthenticationReject,
    NasRelayKeyReject,
    NasPduSessionAuthenticationResult => extended_protocol_configuration_options,
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
    fn shared_ie_sender_checks_run_in_5gs_messages() {
        // A network name without its extension bit, as in
        // EPS EMM INFORMATION.
        let command =
            Nas5gsMessage::from_bytes(&[0x7e, 0x00, 0x54, 0x43, 0x02, 0x10, 0x41]).unwrap();
        assert!(command.validate().iter().any(|error| {
            error.field == "full_name_for_network" && error.severity == Severity::Error
        }));
        // A two-octet UE status with spare bits set.
        let mut request =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        assert!(
            Nas5gsMessage::from_bytes(&request)
                .unwrap()
                .validate()
                .is_empty()
        );
        request.extend([0x2b, 0x02, 0xff, 0xff]);
        let request = Nas5gsMessage::from_bytes(&request).unwrap();
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
        let decoded = Nas5gsMessage::from_bytes(&malformed).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), malformed);
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = decoded else {
            panic!("REGISTRATION ACCEPT expected");
        };
        assert!(accept.sor_transparent_container.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);

        // ACK is structurally valid but UE-to-network only, so its use in a
        // network Registration Accept is retained and rejected for sending.
        let mut wrong_ack = hex::decode("7e00420101730011").unwrap();
        wrong_ack.push(0x01);
        wrong_ack.extend([0u8; 16]);
        let decoded = Nas5gsMessage::from_bytes(&wrong_ack).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), wrong_ack);
        assert!(
            decoded
                .validate()
                .iter()
                .any(|error| { error.field == "SOR transparent container" })
        );

        // Conversely, an LT=0 information form belongs to network-to-UE and
        // is invalid in a UE Registration Complete.
        let mut wrong_information = hex::decode("7e0043730013").unwrap();
        wrong_information.extend([0u8; 19]);
        let decoded = Nas5gsMessage::from_bytes(&wrong_information).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), wrong_information);
        assert!(
            decoded
                .validate()
                .iter()
                .any(|error| { error.field == "SOR transparent container" })
        );
    }

    #[test]
    fn repeated_and_out_of_sequence_ies_are_reported() {
        // REGISTRATION REJECT with T3346 (5F) twice, then T3502 (16) before
        // T3346, which Table 8.2.9.1 lists first.
        let repeated = Nas5gsMessage::from_bytes(&[
            0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x21, 0x5f, 0x01, 0x22,
        ])
        .unwrap();
        assert!(
            repeated
                .validate()
                .iter()
                .any(|error| { error.field == "unknown_ies" && error.severity == Severity::Error })
        );
        let wire = [0x7e, 0x00, 0x44, 0x16, 0x16, 0x01, 0x21, 0x5f, 0x01, 0x21];
        let reordered = Nas5gsMessage::from_bytes(&wire).unwrap();
        assert_eq!(reordered.to_bytes().unwrap(), wire);
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
    fn malformed_dnn_and_pdu_address_are_absent_on_receive() {
        let dnn_wire = [
            0x7e, 0x00, 0x67, 0x02, 0x00, 0x01, 0x01, 0x25, 0x02, 0x05, 0x61,
        ];
        let decoded = Nas5gsMessage::from_bytes(&dnn_wire).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), dnn_wire);
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) = decoded else {
            panic!("UL NAS TRANSPORT expected");
        };
        assert!(transport.dnn.is_none());
        assert_eq!(transport.unknown_ies.len(), 1);

        let wire =
            hex::decode("2e0101c211000901000631310101ff010603f42403f42429050200000000").unwrap();
        let decoded = Nas5gsMessage::from_bytes(&wire).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), wire);
        let Nas5gsMessage::Gsm(_, Nas5gsmMessage::PduSessionEstablishmentAccept(accept)) = decoded
        else {
            panic!("PDU SESSION ESTABLISHMENT ACCEPT expected");
        };
        assert!(accept.pdu_address.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);
    }

    #[test]
    fn malformed_tai_list_is_absent_on_receive() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let one = NasFGsTrackingAreaIdentityList::from_plmn_tacs(&plmn, &[[0x00, 0x00, 0x01]]);
        let mut malformed = one.value;
        malformed[0] = 0x01;
        let message = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationAccept(
            NasRegistrationAccept::new(NasFGsRegistrationResult::new(vec![1]))
                .set_tai_list(NasFGsTrackingAreaIdentityList::new(malformed)),
        ));
        let wire = message.to_bytes().unwrap();
        let decoded = Nas5gsMessage::from_bytes(&wire).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), wire);
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = decoded else {
            panic!("REGISTRATION ACCEPT expected");
        };
        assert!(accept.tai_list.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);
    }

    #[test]
    fn malformed_service_area_list_is_absent_on_receive() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let mut malformed = NasServiceAreaList::from_plmn_tacs(
            ServiceAreaListAllowedType::Allowed,
            &plmn,
            &[[0x00, 0x00, 0x01]],
        );
        malformed.value[0] = 0x01;
        let message = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationAccept(
            NasRegistrationAccept::new(NasFGsRegistrationResult::new(vec![1]))
                .set_service_area_list(malformed),
        ));
        let wire = message.to_bytes().unwrap();
        let decoded = Nas5gsMessage::from_bytes(&wire).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), wire);
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = decoded else {
            panic!("REGISTRATION ACCEPT expected");
        };
        assert!(accept.service_area_list.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);
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
        let request =
            NasPduSessionEstablishmentRequest::new(NasIntegrityProtectionMaximumDataRate::new(1))
                .set_extended_protocol_configuration_options(
                    NasExtendedProtocolConfigurationOptions::new(vec![]),
                );
        assert!(
            request
                .validate()
                .iter()
                .any(|error| { error.field == "Extended protocol configuration options" })
        );
        let malformed = NasPduSessionReleaseReject::new(NasFGsmCause::new(0x1a))
            .set_extended_protocol_configuration_options(
                NasExtendedProtocolConfigurationOptions::new(vec![0x00]),
            );
        assert!(
            malformed
                .validate()
                .iter()
                .any(|error| { error.field == "Extended protocol configuration options" })
        );
        let authentication =
            NasPduSessionAuthenticationCommand::new(NasEapMessage::new(vec![3, 1, 0, 4]))
                .set_extended_protocol_configuration_options(
                    NasExtendedProtocolConfigurationOptions::new(vec![]),
                );
        assert!(
            authentication
                .validate()
                .iter()
                .any(|error| { error.field == "Extended protocol configuration options" })
        );
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
        assert!(errs.is_empty(), "Unexpected errors: {errs:?}");
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
    fn authentication_request_requires_exactly_one_complete_mechanism() {
        let base = || {
            NasAuthenticationRequest::new(
                NasKeySetIdentifier::new(0),
                NasAbba::new(vec![0x00, 0x00]),
            )
        };
        assert!(
            base()
                .validate()
                .iter()
                .any(|e| e.field == "Authentication mechanism")
        );
        assert!(
            base()
                .set_authentication_parameter_rand(NasAuthenticationParameterRand::new(vec![0; 16]))
                .validate()
                .iter()
                .any(|e| e.field == "RAND/AUTN")
        );

        let aka = base()
            .set_authentication_parameter_rand(NasAuthenticationParameterRand::new(vec![0; 16]))
            .set_authentication_parameter_autn(NasAuthenticationParameterAutn::new(vec![0; 16]));
        assert!(aka.validate().is_empty());

        let eap = base().set_eap_message(NasEapMessage::new(vec![3, 1, 0, 4]));
        assert!(eap.validate().is_empty());
        assert!(
            aka.set_eap_message(NasEapMessage::new(vec![3, 1, 0, 4]))
                .validate()
                .iter()
                .any(|e| e.field == "Authentication mechanism")
        );
    }

    #[test]
    fn payload_container_types_and_registration_pair_are_checked() {
        let invalid = NasUlNasTransport::new(
            NasPayloadContainerType::new(0),
            NasPayloadContainer::new(vec![1]),
        );
        assert!(
            invalid
                .validate()
                .iter()
                .any(|e| { e.field == "Payload container type" && e.message.contains("reserved") })
        );

        let registration = NasRegistrationRequest::new(
            NasFGsRegistrationType::new(1),
            NasFGsMobileIdentity::new(vec![1, 2]),
        )
        .set_payload_container(NasPayloadContainer::new(vec![1]));
        assert!(
            registration
                .validate()
                .iter()
                .any(|e| e.field == "Payload container type")
        );
        let wrong_kind = registration.set_payload_container_type(
            NasPayloadContainerType::from_kind(PayloadContainerKind::Sms),
        );
        assert!(
            wrong_kind.validate().iter().any(|e| {
                e.field == "Payload container type" && e.message.contains("UE policy")
            })
        );
    }

    #[test]
    fn establishment_sender_values_follow_strict_tables() {
        for value in [0x0000, 0x0101, 0xFFFF] {
            let request = NasPduSessionEstablishmentRequest::new(
                NasIntegrityProtectionMaximumDataRate::new(value),
            );
            assert!(request.validate().is_empty(), "0x{value:04X}");
        }
        for value in [0x0002, 0x0200] {
            let request = NasPduSessionEstablishmentRequest::new(
                NasIntegrityProtectionMaximumDataRate::new(value),
            );
            assert!(
                request
                    .validate()
                    .iter()
                    .any(|e| { e.field == "Integrity protection maximum data rate" })
            );
        }
        let request =
            NasPduSessionEstablishmentRequest::new(NasIntegrityProtectionMaximumDataRate::new(0))
                .set_pdu_session_type(NasPduSessionType::new(7))
                .set_ssc_mode(NasSscMode::new(7));
        let findings = request.validate();
        assert!(findings.iter().any(|e| e.field == "PDU session type"));
        assert!(findings.iter().any(|e| e.field == "SSC mode"));

        let accept = NasPduSessionEstablishmentAccept::new(
            NasPduSessionType::new(7),
            NasQosRules::new(vec![]),
            NasSessionAmbr::new(vec![0; 6]),
        );
        assert!(
            accept
                .validate()
                .iter()
                .any(|e| e.field == "Selected PDU session type")
        );
        let mut accept = NasPduSessionEstablishmentAccept::new(
            NasPduSessionType::from_session_type(PduSessionTypeValue::IPv4),
            NasQosRules::new(vec![]),
            NasSessionAmbr::new(vec![0; 6]),
        );
        for value in [0, 4, 5, 6, 7, 9] {
            accept.selected_pdu_session_type.type_field = value;
            assert!(
                accept
                    .validate()
                    .iter()
                    .any(|e| e.field == "Selected SSC mode")
            );
        }
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
    fn nas_transport_conditional_ies_cover_all_payload_kinds() {
        for kind in [
            PayloadContainerKind::N1SmInformation,
            PayloadContainerKind::CIoT,
        ] {
            let ul = NasUlNasTransport::new(
                NasPayloadContainerType::from_kind(kind),
                NasPayloadContainer::new(vec![0x01]),
            );
            let dl = NasDlNasTransport::new(
                NasPayloadContainerType::from_kind(kind),
                NasPayloadContainer::new(vec![0x01]),
            );
            assert!(ul.validate().iter().any(|e| e.field == "PDU session ID"));
            assert!(dl.validate().iter().any(|e| e.field == "PDU session ID"));
        }

        for kind in [
            PayloadContainerKind::LtePp,
            PayloadContainerKind::SlppMessageContainer,
        ] {
            let message = NasUlNasTransport::new(
                NasPayloadContainerType::from_kind(kind),
                NasPayloadContainer::new(vec![0x01]),
            );
            assert!(
                message
                    .validate()
                    .iter()
                    .any(|e| e.field == "Additional information")
            );
        }
        for kind in [
            PayloadContainerKind::LtePp,
            PayloadContainerKind::LocationServices,
            PayloadContainerKind::UppCmiContainer,
            PayloadContainerKind::SlppMessageContainer,
        ] {
            let message = NasDlNasTransport::new(
                NasPayloadContainerType::from_kind(kind),
                NasPayloadContainer::new(vec![0x01]),
            );
            assert!(
                message
                    .validate()
                    .iter()
                    .any(|e| e.field == "Additional information")
            );
        }
    }

    #[test]
    fn request_and_access_type_sender_values_are_strict() {
        let request = NasUlNasTransport::new(
            NasPayloadContainerType::from_kind(PayloadContainerKind::Sms),
            NasPayloadContainer::new(vec![1]),
        )
        .set_request_type(NasRequestType::new(7));
        assert!(request.validate().iter().any(|e| e.field == "Request type"));

        for mut access_type in [NasAccessType::new(0x0A), NasAccessType::new(2)] {
            access_type.type_field = if access_type.value == 2 { 0x0F } else { 0 };
            let notification = NasNotification::new(access_type);
            assert!(
                notification
                    .validate()
                    .iter()
                    .any(|e| e.field == "Access type")
            );
        }
        let decoded = Nas5gsMessage::from_bytes(&[0x7e, 0x00, 0x65, 0xfa]).unwrap();
        assert!(decoded.validate().iter().any(|e| e.field == "Access type"));
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
    fn test_upds_pti_must_match_ue_initiated_procedure() {
        let message = NasUpdsMessage::UeStateIndication(NasUeStateIndication::new(
            NasUpsiList::new(Vec::new()),
            NasUePolicyClassmark::from_flags(false, false, false, false),
        ));
        let envelope = NasUpdsEnvelope::new_with_pti(
            NasUpdsProcedureTransactionIdentity::from_network_initiated(0x80).unwrap(),
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
