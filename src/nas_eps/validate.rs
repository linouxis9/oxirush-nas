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

//! Structural validation helpers for EPS NAS messages against TS 24.301.
//!
//! The [`Validate`] trait returns [`ValidationError`] findings with a
//! [`Severity`] of Error or Warning. Checks cover the byte lengths and spare
//! half octets specified by the chapter 8 message tables, plus sender-side
//! value rules. The decoder still accepts values with specified receiver
//! fallback behavior; these can yield validation findings.
//! An empty list means these implemented checks passed; it does not imply
//! complete procedure validation.
//!
//! The lengths are those of the message tables in
//! [`crate::nas_eps::messages`], and the rules of an IE type apply to every
//! message field of that type. This module lists the IE types that have
//! such rules and adds the rules of single messages.
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::nas_eps::{Validate, decode_nas_eps_message};
//!
//! let message = decode_nas_eps_message(&[0x07, 0x60, 0x03]).unwrap();
//! assert!(message.validate().is_empty());
//! ```

use crate::common::{
    ReceiverSyntaxCheck, SenderCheck, invalid_ie, sender_checked, with_optional_ie_checks,
};
pub use crate::common::{Severity, Validate, ValidationError};
use crate::nas_eps::ie::*;
use crate::nas_eps::message_types::NasEpsSecurityHeaderType;
use crate::nas_eps::messages::*;
use crate::nas_eps::types::*;

// Receiver syntax is intentionally narrower than sender validation. In
// particular, TS 24.007 §11.4.2 says that extra value octets in type 4 and
// type 6 IEs are ignored, so the timer check accepts every non-empty value
// even though a sender emits exactly one octet.
impl ReceiverSyntaxCheck for NasGprsTimer2 {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

macro_rules! nonempty_gprs_timer_2_receiver {
    ($($name:ident),* $(,)?) => {
        $(
            impl ReceiverSyntaxCheck for $name {
                fn receiver_syntax_ok(&self) -> bool {
                    !self.value.is_empty()
                }
            }
        )*
    };
}

nonempty_gprs_timer_2_receiver!(NasT3346Value, NasT3324Value, NasT3448Value);

impl ReceiverSyntaxCheck for NasCli {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasAccessPointName {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasEpsMobileIdentity {
    fn receiver_syntax_ok(&self) -> bool {
        self.as_imsi().is_some() || self.as_imei().is_some() || self.as_guti().is_some()
    }
}

impl ReceiverSyntaxCheck for NasMobileIdentity {
    fn receiver_syntax_ok(&self) -> bool {
        self.as_imsi().is_some()
            || self.as_imei().is_some()
            || self.as_imeisv().is_some()
            || self.as_tmsi().is_some()
            || matches!(self.value.as_slice(), [0, 0, 0, ..])
    }
}

impl ReceiverSyntaxCheck for NasAuthenticationParameterAutnEpsChallenge {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 16
    }
}

impl ReceiverSyntaxCheck for NasAuthenticationResponseParameter {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 4
    }
}

impl ReceiverSyntaxCheck for NasAuthenticationFailureParameter {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 14
    }
}

impl ReceiverSyntaxCheck for NasEsmMessageContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 3
    }
}

impl ReceiverSyntaxCheck for NasMessageContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 2
    }
}

impl ReceiverSyntaxCheck for NasNegotiatedQos {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasNewQos {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasRequiredTrafficFlowQos {
    fn receiver_syntax_ok(&self) -> bool {
        self.qos().is_some()
    }
}

// Errors inside a TFT are errors of the ESM procedure (TS 24.301 §6.4.2.4,
// §6.4.3.4, §6.5.3.4, §6.5.4.4), which the receiver answers with the ESM
// cause of parse_tft. Only an empty value is short of the message tables.
impl ReceiverSyntaxCheck for NasTft {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasTrafficFlowAggregate {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasEpsQos {
    fn receiver_syntax_ok(&self) -> bool {
        self.qos().is_some()
    }
}

impl ReceiverSyntaxCheck for NasPdnAddress {
    fn receiver_syntax_ok(&self) -> bool {
        self.pdn_address().is_some()
    }
}

impl ReceiverSyntaxCheck for NasReplayedUeSecurityCapabilities {
    fn receiver_syntax_ok(&self) -> bool {
        matches!(self.value.len(), 2 | 4..)
    }
}

impl ReceiverSyntaxCheck for NasTaiList {
    fn receiver_syntax_ok(&self) -> bool {
        self.tai_list().is_some()
    }
}

impl ReceiverSyntaxCheck for NasUeNetworkCapability {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 2
    }
}

// The sender rules of an IE type apply to every message field of that type:
// `is_well_formed()`, or the listed values of its octet or half octet.
sender_checked!(
    NasAccessPointName,
    NasAccessTechnologyUtilizationControl,
    NasAdditionalInformationRequested => 0 | 1,
    NasAdditionalUpdateResult => 0..=2,
    NasAdditionalUpdateType => 0..=0x0b,
    NasApnAmbr,
    NasBackOffTimerValue,
    NasCipheringKeyData,
    NasCli,
    NasConnectivityType => 0 | 1,
    NasControlPlaneOnlyIndication => 1,
    NasControlPlaneServiceType => 0 | 1 | 8 | 9,
    NasCsfbResponse => 0 | 1,
    NasDetachType => 1..=3 | 9..=11,
    NasDeviceProperties => 0 | 1,
    NasDisasterReturnWaitRange,
    NasDisasterRoamingWaitRange,
    NasDrxParameter,
    NasDrxParameterInNbS1Mode,
    NasEmergencyNumberList,
    NasEpsAdditionalRequestResult,
    NasEpsAttachResult => 1 | 2,
    NasEpsAttachType => 1..=3 | 6 | 7,
    NasEpsBearerContextStatus,
    NasEpsMobileIdentity,
    NasEpsNetworkFeatureSupport,
    NasEpsUpdateResult => 0 | 1 | 4 | 5,
    NasEpsUpdateType => 0..=3 | 6 | 8..=11 | 14,
    NasEquivalentPlmns,
    NasEsmInformationTransferFlag => 0 | 1,
    NasExtendedApnAmbr,
    NasExtendedEmergencyNumberList,
    NasExtendedEpsQos,
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
    NasGenericMessageContainerType => 1 | 2,
    NasGprsCipheringKeySequenceNumber => 0..=7,
    NasGprsTimer2,
    NasHashMme,
    NasHeaderCompressionConfiguration,
    NasHeaderCompressionConfigurationStatus,
    NasIdentityType => 1..=4,
    NasImeisvRequest => 0 | 1,
    NasKeySetIdentifier => 0..=15,
    NasLinkedEpsBearerIdentity => 1..=15,
    NasListOfPlmnsToBeUsedInDisasterCondition,
    NasLowerBoundTimerValue,
    NasMaximumTimeOffset,
    NasMobileStationClassmark2,
    NasMobileStationClassmark3,
    NasMsNetworkCapability,
    NasMsNetworkFeatureSupport => 0 | 1,
    NasN1UeNetworkCapability,
    NasNegotiatedDrxParameterInNbS1Mode,
    NasNegotiatedLlcSapi => 0 | 3 | 5 | 9 | 11,
    NasNegotiatedQos,
    NasNegotiatedWusAssistanceInformation,
    NasNetworkDaylightSavingTime,
    NasNetworkName,
    NasNetworkPolicy => 0 | 1,
    NasNewQos,
    NasNon3GppNwProvidedPolicies => 0 | 1,
    NasNonCurrentNativeNasKeySetIdentifier,
    NasOldGutiType => 0 | 1,
    NasPacketFlowIdentifier,
    NasPagingIdentity => 0 | 1,
    NasPagingRestriction,
    NasPdnAddress,
    NasPdnType => 1..=3 | 5 | 6,
    NasProseKeyManagementFunctionAddress,
    NasRadioPriority => 1..=4,
    NasReAttemptIndicator,
    NasReleaseAssistanceIndication => 0..=2,
    NasRemoteUeContextConnected,
    NasRemoteUeContextDisconnected,
    NasReplayedUeSecurityCapabilities,
    NasRequestType => 1..=4 | 6,
    NasRequestedWusAssistanceInformation,
    NasSAndFSatelliteOperationParameters,
    NasSelectedNasSecurityAlgorithms,
    NasServiceType => 0..=2 | 8,
    NasServingPlmnRateControl,
    NasSmsServicesStatus => 0..=3,
    NasSpareHalfOctet => 0,
    NasSupportedCodecs,
    NasT3324Value,
    NasT3346Value,
    NasT3396Value,
    NasT3412ExtendedValue,
    NasT3447Value,
    NasT3448Value,
    NasTaiList,
    NasTft,
    NasTmsiBasedNriContainer,
    NasTmsiStatus => 0 | 1,
    NasTrafficFlowAggregate,
    NasTransactionIdentifier,
    NasUeAdditionalSecurityCapability,
    NasUeCoarseLocationInformationRequest => 0 | 1,
    NasUeDeterminedPlmnWithDisasterCondition,
    NasUeNetworkCapability,
    NasUeRadioCapabilityInformationUpdateNeeded => 0 | 1,
    NasUeRequestType,
    NasUnavailabilityConfiguration,
    NasUnavailabilityInformation,
    NasUniversalTimeAndLocalTimeZone,
    NasVoiceDomainPreferenceAndUeUsageSetting,
    NasWlanOffloadIndication => 0..=3,
);

impl SenderCheck for NasNotificationIndicator {
    fn sender_check(&self) -> bool {
        self.value == [1]
    }
}

impl SenderCheck for NasUeRadioCapabilityIdAvailability {
    fn sender_check(&self) -> bool {
        matches!(self.value[..], [0 | 1, ..])
    }
}

impl SenderCheck for NasUeRadioCapabilityIdRequest {
    fn sender_check(&self) -> bool {
        matches!(self.value[..], [0 | 1, ..])
    }
}

// The EPS QoS of the messages from the network: an assigned QCI and no
// reserved bit rate octet. No sender asks for maximum bit rates of 0 kbps
// (§9.9.4.3).
macro_rules! network_eps_qos_sender_checked {
    ($($name:ident),*) => {
        $(
            impl SenderCheck for $name {
                fn sender_check(&self) -> bool {
                    self.is_well_formed()
                        && self.qos().is_some_and(|qos| qos.qci_is_network_valid())
                        && (self.value.len() < 5 || self.value[1..5].iter().all(|&rate| rate != 0))
                        && !self.has_zero_maximum_bit_rates()
                }
            }
        )*
    };
}

network_eps_qos_sender_checked!(NasEpsQos, NasNewEpsQos);

impl SenderCheck for NasRequiredTrafficFlowQos {
    fn sender_check(&self) -> bool {
        self.is_well_formed() && !self.has_zero_maximum_bit_rates()
    }
}

// BEGIN TS24301 VALIDATE
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

impl Validate for NasAttachAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.guti {
            check_eps_ie_valid(&mut errors, "guti", ie.as_guti().is_some());
        }
        check_esm_message_container(
            &mut errors,
            &self.esm_message_container.value,
            Severity::Warning,
        );
        errors
    }
}

impl Validate for NasAttachComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_message_container(
            &mut errors,
            &self.esm_message_container.value,
            Severity::Warning,
        );
        errors
    }
}

impl Validate for NasAttachReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.esm_message_container {
            check_esm_message_container(&mut errors, &ie.value, Severity::Error);
        }
        errors
    }
}

impl Validate for NasAttachRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.additional_guti {
            check_eps_ie_valid(&mut errors, "additional_guti", ie.as_guti().is_some());
        }
        check_esm_message_container(
            &mut errors,
            &self.esm_message_container.value,
            Severity::Warning,
        );
        if self.t3412_extended_value.is_some() && self.t3324_value.is_none() {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "t3412_extended_value",
                message: "Extended T3412 requires T3324".into(),
            });
        }
        if self.ue_determined_plmn_with_disaster_condition.is_some()
            && self.eps_attach_type.value & 0x07 != 7
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "ue_determined_plmn_with_disaster_condition",
                message: "Disaster condition PLMN requires disaster roaming request type".into(),
            });
        }
        if self.eps_mobile_identity.identity_type() == Some(MobileIdentityType::Guti)
            && self.old_guti_type.is_none()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "old_guti_type",
                message: "Old GUTI type is required when ATTACH REQUEST uses a GUTI".into(),
            });
        }
        if let Ok(NasEpsMessage::Esm(_, NasEsmMessage::PdnConnectivityRequest(request))) =
            decode_nas_eps_message(&self.esm_message_container.value)
            && request.access_point_name.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "esm_message_container",
                message: "APN is forbidden in an ATTACH REQUEST PDN container".into(),
            });
        }
        errors
    }
}

impl Validate for NasAuthenticationFailure {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if (self.emm_cause.value == 0x15) != self.authentication_failure_parameter.is_some() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "authentication_failure_parameter",
                message: "AUTS is required exactly for synchronization failure".into(),
            });
        }
        errors
    }
}

impl Validate for NasAuthenticationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "nas_key_set_identifier_asme",
            self.nas_key_set_identifier_asme.value <= 6,
        );
        errors
    }
}

impl Validate for NasDetachRequestToUe {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "detach_type",
            self.detach_type.value & 0x08 == 0,
        );
        errors
    }
}

impl Validate for NasExtendedServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "m_tmsi",
            self.m_tmsi.as_tmsi().is_some() && self.m_tmsi.is_well_formed(),
        );
        if self.csfb_response.is_some() && self.service_type.value & 0x0f != 1 {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "csfb_response",
                message: "CSFB response requires mobile terminating CS fallback service".into(),
            });
        }
        if self.paging_restriction.is_some()
            && self
                .ue_request_type
                .as_ref()
                .and_then(|ie| ie.request_type())
                .is_none()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "paging_restriction",
                message: "Paging restriction requires a UE request type (8.2.15.6, 8.2.33.7)"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasGutiReallocationCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(&mut errors, "guti", self.guti.as_guti().is_some());
        errors
    }
}

impl Validate for NasIdentityResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "mobile_identity",
            self.mobile_identity.is_well_formed(),
        );
        errors
    }
}

impl Validate for NasSecurityModeCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "nas_key_set_identifier",
            !self.nas_key_set_identifier.no_key_available(),
        );
        let algorithms = &self.selected_nas_security_algorithms;
        if algorithms.ciphering_raw() > 3 || algorithms.integrity_raw() > 3 {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "selected_nas_security_algorithms",
                message: "Selected EPS algorithm is not specified in TS 33.401".into(),
            });
        }
        if algorithms.integrity_raw() == 0 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "selected_nas_security_algorithms",
                message: "EIA0 is only used for unauthenticated emergency or RLOS sessions".into(),
            });
        }
        errors
    }
}

impl Validate for NasSecurityModeComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.imeisv {
            check_eps_ie_valid(&mut errors, "imeisv", ie.as_imeisv().is_some());
        }
        errors
    }
}

impl Validate for NasServiceReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if self.emm_cause.value == 0x27 && self.t3442_value.is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "t3442_value",
                message: "T3442 is required for CS service temporarily not available".into(),
            });
        }
        errors
    }
}

impl Validate for NasTrackingAreaUpdateAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.guti {
            check_eps_ie_valid(&mut errors, "guti", ie.as_guti().is_some());
        }
        if self.t3412_extended_value.is_some() && self.t3412_value.is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "t3412_value",
                message: "T3412 value is required with extended T3412".into(),
            });
        }
        errors
    }
}

impl Validate for NasTrackingAreaUpdateRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(&mut errors, "old_guti", self.old_guti.as_guti().is_some());
        if let Some(ie) = &self.additional_guti {
            check_eps_ie_valid(&mut errors, "additional_guti", ie.as_guti().is_some());
        }
        if self.old_guti_type.is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "old_guti_type",
                message: "Old GUTI type is required in TRACKING AREA UPDATE REQUEST".into(),
            });
        }
        if self.eps_update_type.value & 0x07 != 3 && self.ue_network_capability.is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "ue_network_capability",
                message: "UE network capability is required for nonperiodic TAU".into(),
            });
        }
        if self.t3412_extended_value.is_some() && self.t3324_value.is_none() {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "t3412_extended_value",
                message: "Extended T3412 requires T3324".into(),
            });
        }
        if self.ue_determined_plmn_with_disaster_condition.is_some()
            && self.eps_update_type.value & 0x07 != 6
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "ue_determined_plmn_with_disaster_condition",
                message: "Disaster condition PLMN requires disaster roaming request type".into(),
            });
        }
        if self.ue_request_type.as_ref().is_some_and(|ie| {
            ie.request_type() != Some(UeRequestType::NasSignallingConnectionRelease)
        }) {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "ue_request_type",
                message: "TAU REQUEST carries only NAS signalling connection release (8.2.29.35)"
                    .into(),
            });
        }
        if self.paging_restriction.is_some()
            && self
                .ue_request_type
                .as_ref()
                .and_then(|ie| ie.request_type())
                != Some(UeRequestType::NasSignallingConnectionRelease)
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "paging_restriction",
                message: "Paging restriction requires UE request type NAS signalling connection release (8.2.29.36)".into(),
            });
        }
        if self.drx_parameter_in_nb_s1_mode.is_some() && self.eps_update_type.value & 0x07 == 3 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "drx_parameter_in_nb_s1_mode",
                message: "NB-S1 DRX parameter is not sent in periodic TAU (8.2.29.32)".into(),
            });
        }
        errors
    }
}

impl Validate for NasControlPlaneServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.esm_message_container {
            check_esm_message_container(&mut errors, &ie.value, Severity::Warning);
        }
        if self.paging_restriction.is_some()
            && self
                .ue_request_type
                .as_ref()
                .and_then(|ie| ie.request_type())
                .is_none()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "paging_restriction",
                message: "Paging restriction requires a UE request type (8.2.15.6, 8.2.33.7)"
                    .into(),
            });
        }
        errors
    }
}

/// Check the PCO and the ePCO of an ESM message, and its NBIFOM container
/// where one is named, by the rules of the sender: `Uplink, UeToNetwork` or
/// `Downlink, NetworkToUe`. A message with both a PCO and an ePCO gets a
/// warning, and an error in the UE requests marked `exclusive`.
macro_rules! check_esm_options {
    (@each $errors:ident, $message:ident, $direction:ident $(, $nbifom:ident)?) => {
        if let Some(ie) = &$message.protocol_configuration_options {
            check_eps_ie_valid(
                &mut $errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::$direction),
            );
        }
        if let Some(ie) = &$message.extended_protocol_configuration_options {
            check_eps_ie_valid(
                &mut $errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::$direction),
            );
        }
        $(
            if let Some(ie) = &$message.nbifom_container {
                check_eps_ie_valid(
                    &mut $errors,
                    "nbifom_container",
                    ie.is_well_formed_for(NbifomDirection::$nbifom),
                );
            }
        )?
    };
    ($errors:ident, $message:ident, exclusive, $($direction:ident),+) => {
        check_esm_options!(@each $errors, $message, $($direction),+);
        if $message.protocol_configuration_options.is_some()
            && $message.extended_protocol_configuration_options.is_some()
        {
            $errors.push(ValidationError {
                severity: Severity::Error,
                field: "protocol_configuration_options",
                message: "PCO and extended PCO are mutually exclusive".into(),
            });
        }
    };
    ($errors:ident, $message:ident, $($direction:ident),+) => {
        check_esm_options!(@each $errors, $message, $($direction),+);
        if $message.protocol_configuration_options.is_some()
            && $message.extended_protocol_configuration_options.is_some()
        {
            $errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
    };
}

impl Validate for NasActivateDedicatedEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        errors
    }
}

impl Validate for NasActivateDedicatedEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        errors
    }
}

impl Validate for NasActivateDedicatedEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        if self.extended_eps_qos.is_some() && self.eps_qos.value.len() < 13 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_eps_qos",
                message: "Extended EPS QoS needs EPS QoS at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasActivateDefaultEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink);
        errors
    }
}

impl Validate for NasActivateDefaultEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink);
        errors
    }
}

impl Validate for NasActivateDefaultEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        if self.extended_apn_ambr.is_some()
            && self.apn_ambr.as_ref().is_none_or(|ie| ie.value.len() < 6)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_apn_ambr",
                message: "Extended APN-AMBR needs APN-AMBR at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasBearerResourceAllocationReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        if self.re_attempt_indicator.is_some()
            && (self.esm_cause.value == 26 || self.back_off_timer_value.is_none())
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "re_attempt_indicator",
                message: "Re-attempt indicator is not allowed for this cause and timer combination"
                    .into(),
            });
        }
        if self.back_off_timer_value.is_some() && self.esm_cause.value == 65 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "back_off_timer_value",
                message: "Back-off timer is not sent with ESM cause #65 (8.3.7.3)".into(),
            });
        }
        errors
    }
}

impl Validate for NasBearerResourceAllocationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        if self.extended_eps_qos.is_some() && self.required_traffic_flow_qos.value.len() < 13 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_eps_qos",
                message: "Extended EPS QoS needs EPS QoS at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasBearerResourceModificationReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        if self.re_attempt_indicator.is_some()
            && (self.esm_cause.value == 26 || self.back_off_timer_value.is_none())
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "re_attempt_indicator",
                message: "Re-attempt indicator is not allowed for this cause and timer combination"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasBearerResourceModificationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        if self.extended_eps_qos.is_some()
            && self
                .required_traffic_flow_qos
                .as_ref()
                .is_none_or(|ie| ie.value.len() < 13)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_eps_qos",
                message: "Extended EPS QoS needs EPS QoS at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasDeactivateEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink);
        errors
    }
}

impl Validate for NasDeactivateEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        if self.t3396_value.is_some() && self.esm_cause.value != 26 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "t3396_value",
                message: "T3396 is sent with ESM cause #26 (8.3.12.3)".into(),
            });
        }
        errors
    }
}

impl Validate for NasEsmInformationResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, exclusive, Uplink);
        errors
    }
}

impl Validate for NasModifyEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        errors
    }
}

impl Validate for NasModifyEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        errors
    }
}

impl Validate for NasModifyEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        if self.extended_eps_qos.is_some()
            && self
                .new_eps_qos
                .as_ref()
                .is_none_or(|ie| ie.value.len() < 13)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_eps_qos",
                message: "Extended EPS QoS needs EPS QoS at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        if self.extended_apn_ambr.is_some()
            && self.apn_ambr.as_ref().is_none_or(|ie| ie.value.len() < 6)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_apn_ambr",
                message: "Extended APN-AMBR needs APN-AMBR at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasPdnConnectivityReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        if self.re_attempt_indicator.is_some()
            && (self.esm_cause.value == 26
                || (self.back_off_timer_value.is_none()
                    && ![28, 50, 51, 57, 58, 61, 66].contains(&self.esm_cause.value)))
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "re_attempt_indicator",
                message: "Re-attempt indicator is not allowed for this cause and timer combination"
                    .into(),
            });
        }
        if self.back_off_timer_value.is_some()
            && [28, 50, 51, 54, 57, 58, 61, 65].contains(&self.esm_cause.value)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "back_off_timer_value",
                message: "Back-off timer is not sent with this ESM cause (8.3.19.3)".into(),
            });
        }
        errors
    }
}

impl Validate for NasPdnConnectivityRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, exclusive, Uplink, UeToNetwork);
        if matches!(self.request_type.value, 3 | 4 | 6) && self.access_point_name.is_some() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "access_point_name",
                message: "APN is forbidden for RLOS and emergency PDN requests".into(),
            });
        }
        errors
    }
}

impl Validate for NasPdnDisconnectReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink);
        errors
    }
}

impl Validate for NasPdnDisconnectRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink);
        errors
    }
}

/// Messages whose rules are all those of their table and of their IE types.
macro_rules! validate_from_table {
    ($($name:ty),+ $(,)?) => {
        $(
            impl Validate for $name {
                fn validate(&self) -> Vec<ValidationError> {
                    self.sender_check_findings()
                }
            }
        )+
    };
}

validate_from_table!(
    NasAuthenticationReject,
    NasAuthenticationResponse,
    NasCsServiceNotification,
    NasDetachAccept,
    NasDetachRequestFromUe,
    NasDownlinkGenericNasTransport,
    NasDownlinkNasTransport,
    NasEmmInformation,
    NasEmmStatus,
    NasEsmDataTransport,
    NasEsmDummyMessage,
    NasEsmInformationRequest,
    NasEsmStatus,
    NasGutiReallocationComplete,
    NasIdentityRequest,
    NasNotification,
    NasRemoteUeReport,
    NasRemoteUeReportResponse,
    NasSecurityModeReject,
    NasServiceAccept,
    NasTrackingAreaUpdateComplete,
    NasTrackingAreaUpdateReject,
    NasUplinkGenericNasTransport,
    NasUplinkNasTransport,
);

impl Validate for NasEmmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let body = self.body();
        with_optional_ie_checks(
            body.validate(),
            body.unknown_ies(),
            body.ie_order_findings(),
        )
    }
}

impl Validate for NasEsmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let body = self.body();
        with_optional_ie_checks(
            body.validate(),
            body.unknown_ies(),
            body.ie_order_findings(),
        )
    }
}

// END TS24301 VALIDATE

fn check_esm_message_container(
    errors: &mut Vec<ValidationError>,
    value: &[u8],
    severity: Severity,
) {
    if !matches!(decode_nas_eps_message(value), Ok(NasEpsMessage::Esm(..))) {
        errors.push(ValidationError {
            severity,
            field: "esm_message_container",
            message: "ESM message container does not hold one complete ESM PDU".into(),
        });
    }
}

fn check_eps_ie(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    actual: usize,
    minimum: usize,
    maximum: Option<usize>,
) {
    if actual < minimum || maximum.is_some_and(|maximum| actual > maximum) {
        errors.push(ValidationError {
            severity: Severity::Error,
            field,
            message: format!(
                "EPS IE length/value {actual} is outside the TS 24.301 range {minimum}..{maximum:?}"
            ),
        });
    }
}

fn check_eps_ie_valid(errors: &mut Vec<ValidationError>, field: &'static str, valid: bool) {
    if !valid {
        errors.push(invalid_ie(field));
    }
}

impl Validate for NasEmmTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if self.security_header.security_header_type != NasEpsSecurityHeaderType::EmmTransport {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "security_header_type",
                message: "EMM TRANSPORT requires its security header type".into(),
            });
        }
        if self.data_container.is_some() && self.protected_payload.is_some() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "protected_payload",
                message: "EMM TRANSPORT cannot contain clear and opaque payloads together".into(),
            });
        }
        if let Some(data) = &self.data_container {
            check_eps_ie(&mut errors, "data_container", data.len() + 1, 2, None);
            check_eps_ie_valid(
                &mut errors,
                "data_container",
                valid_emm_data_container(data, false),
            );
        }
        // Table 8.2.35.1.1: the data container has at least two octets, and
        // ciphering keeps the length.
        if self
            .protected_payload
            .as_ref()
            .is_some_and(|payload| payload.len() < 2)
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "protected_payload",
                message: "EMM TRANSPORT data container is shorter than two octets".into(),
            });
        }
        errors
    }
}

impl NasEmmTransport {
    /// [`Validate::validate`] with the direction-dependent rule of Table
    /// 9.9.3.74.1: from the network, the DDX bits are spare and zero.
    pub fn validate_with_direction(
        &self,
        direction: crate::common::Direction,
    ) -> Vec<ValidationError> {
        let mut errors = self.validate();
        if direction == crate::common::Direction::Downlink
            && let Some(data) = &self.data_container
            && !valid_emm_data_container(data, true)
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "data_container",
                message: "Downlink EMM TRANSPORT data container has non-zero DDX bits".into(),
            });
        }
        errors
    }
}

impl Validate for NasEpsMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = match self {
            Self::Emm(_, message) => message.validate(),
            Self::Esm(_, message) => message.validate(),
            Self::SecurityProtected(header, inner) => {
                let mut errors = inner.validate();
                if check_protected_inner(header.security_header_type, inner).is_err() {
                    errors.push(ValidationError {
                        severity: Severity::Error,
                        field: "security_header_type",
                        message: "Security header type does not match the protected message".into(),
                    });
                }
                errors
            }
            Self::ServiceRequest(message) => message.validate(),
            Self::EmmTransport(message) => message.validate(),
            _ => Vec::new(),
        };
        if let Self::Esm(header, message) = self {
            let transaction = matches!(
                message,
                NasEsmMessage::BearerResourceAllocationRequest(_)
                    | NasEsmMessage::EsmDummyMessage(_)
                    | NasEsmMessage::BearerResourceAllocationReject(_)
                    | NasEsmMessage::BearerResourceModificationRequest(_)
                    | NasEsmMessage::BearerResourceModificationReject(_)
                    | NasEsmMessage::EsmInformationRequest(_)
                    | NasEsmMessage::EsmInformationResponse(_)
                    | NasEsmMessage::PdnConnectivityRequest(_)
                    | NasEsmMessage::PdnConnectivityReject(_)
                    | NasEsmMessage::PdnDisconnectRequest(_)
                    | NasEsmMessage::PdnDisconnectReject(_)
            );
            let bearer_response = matches!(
                message,
                NasEsmMessage::ActivateDedicatedEpsBearerContextAccept(_)
                    | NasEsmMessage::ActivateDedicatedEpsBearerContextReject(_)
                    | NasEsmMessage::ActivateDefaultEpsBearerContextAccept(_)
                    | NasEsmMessage::ActivateDefaultEpsBearerContextReject(_)
                    | NasEsmMessage::ModifyEpsBearerContextAccept(_)
                    | NasEsmMessage::ModifyEpsBearerContextReject(_)
                    | NasEsmMessage::DeactivateEpsBearerContextAccept(_)
            );
            let bearer_request = matches!(
                message,
                NasEsmMessage::ActivateDedicatedEpsBearerContextRequest(_)
                    | NasEsmMessage::ActivateDefaultEpsBearerContextRequest(_)
                    | NasEsmMessage::ModifyEpsBearerContextRequest(_)
                    | NasEsmMessage::DeactivateEpsBearerContextRequest(_)
            );
            let remote_report = matches!(
                message,
                NasEsmMessage::RemoteUeReport(_) | NasEsmMessage::RemoteUeReportResponse(_)
            );
            let esm_data_transport = matches!(message, NasEsmMessage::EsmDataTransport(_));
            let unassigned_notification = matches!(message, NasEsmMessage::Notification(_))
                && header.eps_bearer_identity == 0
                && header.procedure_transaction_identity == 0;
            if transaction && header.eps_bearer_identity != 0
                || (bearer_response || bearer_request || remote_report || esm_data_transport)
                    && header.eps_bearer_identity == 0
                || unassigned_notification
            {
                errors.push(ValidationError {
                    severity: Severity::Error,
                    field: "eps_bearer_identity",
                    message: "EPS bearer identity does not match the ESM procedure".into(),
                });
            }
            let pti = header.procedure_transaction_identity;
            let invalid_pti = if pti == 255 {
                true
            } else if transaction || remote_report {
                pti == 0
            } else if bearer_response || esm_data_transport {
                pti != 0
            } else {
                false
            };
            if invalid_pti {
                errors.push(ValidationError {
                    severity: Severity::Error,
                    field: "procedure_transaction_identity",
                    message: "Procedure transaction identity does not match the ESM procedure"
                        .into(),
                });
            }
        }
        if !matches!(self, Self::EmmTransport(_))
            && let Err(error) = self.to_bytes()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "EPS NAS header",
                message: error.to_string(),
            });
        }
        errors
    }
}

impl Validate for NasServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "security_header_type",
            self.security_header_type as usize,
            12,
            Some(12),
        );
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier",
            (self.ksi_and_sequence_number >> 5) as usize,
            0,
            Some(6),
        );
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(errors: &[ValidationError]) -> Vec<&'static str> {
        errors.iter().map(|error| error.field).collect()
    }

    fn attach_request(ue_network_capability: Vec<u8>) -> NasAttachRequest {
        NasAttachRequest::new(
            NasEpsAttachType::new(1),
            NasKeySetIdentifier::new(7),
            NasEpsMobileIdentity::from_imsi("001010123456789").unwrap(),
            NasUeNetworkCapability::new(ue_network_capability),
            NasEsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        )
    }

    /// A message struct reports the lengths of its table and the rules of
    /// its IE types.
    #[test]
    fn table_lengths_and_ie_type_rules_apply_to_message_fields() {
        let request = attach_request(vec![0xe0, 0xe0]);
        assert!(request.validate().is_empty());
        // A declared length that differs from the value.
        let mut declared = request.clone();
        declared.esm_message_container.length += 1;
        assert_eq!(fields(&declared.validate()), ["esm_message_container"]);
        // Table 8.2.4.1: a P-TMSI signature of three octets.
        let short = request
            .clone()
            .set_old_p_tmsi_signature(NasOldPTmsiSignature::new(vec![0; 2]));
        assert_eq!(fields(&short.validate()), ["old_p_tmsi_signature"]);
        // EPS attach type 4 and TMSI status 2 are not defined.
        let mut values = request.set_tmsi_status(NasTmsiStatus::new(2));
        values.eps_attach_type = NasEpsAttachType::new(4);
        assert_eq!(
            fields(&values.validate()),
            ["eps_attach_type", "tmsi_status"]
        );
    }

    #[test]
    fn non_sat_lsp_is_a_defined_ue_network_capability_bit() {
        // TS 24.301 V19.8.0 defines octet 12 bit 1; other octet 12-15 bits are spare.
        let mut capability = vec![0xe0, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        assert!(attach_request(capability.clone()).validate().is_empty());
        capability[9] = 0x02;
        assert_eq!(
            fields(&attach_request(capability).validate()),
            ["ue_network_capability"]
        );
    }

    #[test]
    fn one_tai_forbidden_list_meets_the_ie_minimum() {
        // §9.9.3.33 allows 8 octets; Table 8.2.24.1 says 9.
        let bytes = [
            0x07, 0x4e, 0x0f, 0x1d, 0x06, 0x00, 0x02, 0xf8, 0x39, 0x00, 0x01,
        ];
        let message = crate::nas_eps::decode_nas_eps_message(&bytes).unwrap();
        assert!(message.validate().is_empty());
    }

    #[test]
    fn longer_n1_ue_network_capability_is_valid() {
        let request = attach_request(vec![0xe0, 0xe0])
            .set_n1_ue_network_capability(NasN1UeNetworkCapability::new(vec![0x7f, 0, 0]));
        assert!(request.validate().is_empty());
        let spare = attach_request(vec![0xe0, 0xe0])
            .set_n1_ue_network_capability(NasN1UeNetworkCapability::new(vec![0x80]));
        assert_eq!(fields(&spare.validate()), ["n1_ue_network_capability"]);
    }

    /// TFT errors are answered by the ESM procedure with the cause of
    /// `parse_tft` (TS 24.301 §6.4.2.4, §6.4.3.4), so they neither fail the
    /// message with #96 nor drop an optional TFT.
    #[test]
    fn tft_errors_are_left_to_the_esm_procedure() {
        let semantic_error = vec![
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x01, 0xaa, 0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ];
        for receiver_ok in [
            ReceiverSyntaxCheck::receiver_syntax_ok(&NasTft::new(semantic_error.clone())),
            ReceiverSyntaxCheck::receiver_syntax_ok(&NasTrafficFlowAggregate::new(semantic_error)),
        ] {
            assert!(receiver_ok);
        }

        // "Create new TFT" without packet filters.
        assert!(ReceiverSyntaxCheck::receiver_syntax_ok(&NasTft::new(vec![
            0x20
        ])));
        assert!(ReceiverSyntaxCheck::receiver_syntax_ok(
            &NasTrafficFlowAggregate::new(vec![0x20])
        ));
        assert!(!ReceiverSyntaxCheck::receiver_syntax_ok(&NasTft::new(
            vec![]
        )));
        let syntax_error =
            decode_nas_eps_message(&[0x52, 0x01, 0xc5, 0x05, 0x01, 0x00, 0x01, 0x20]).unwrap();
        let NasEpsMessage::Esm(_, NasEsmMessage::ActivateDedicatedEpsBearerContextRequest(request)) =
            syntax_error
        else {
            panic!("wrong mandatory-TFT message");
        };
        assert_eq!(
            request.tft.parse_tft().map_err(TftError::esm_cause),
            Err(EsmCause::SyntacticalErrorInTheTftOperation)
        );

        let mut mandatory_wire = vec![0x52, 0x01, 0xc5, 0x05, 0x01, 0x00, 0x19];
        mandatory_wire.extend_from_slice(&[
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x01, 0xaa, 0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ]);
        let NasEpsMessage::Esm(_, NasEsmMessage::ActivateDedicatedEpsBearerContextRequest(request)) =
            decode_nas_eps_message(&mandatory_wire).unwrap()
        else {
            panic!("wrong mandatory-TFT message");
        };
        assert_eq!(request.tft.parse_tft(), Err(TftError::SemanticTftOperation));

        let mut optional_wire = vec![0x52, 0x01, 0xc9, 0x36, 0x19];
        optional_wire.extend_from_slice(&[
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x01, 0xaa, 0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ]);
        let NasEpsMessage::Esm(_, NasEsmMessage::ModifyEpsBearerContextRequest(request)) =
            decode_nas_eps_message(&optional_wire).unwrap()
        else {
            panic!("wrong optional-TFT message");
        };
        assert_eq!(
            request.tft.unwrap().parse_tft(),
            Err(TftError::SemanticTftOperation)
        );
    }

    #[test]
    fn security_mode_command_rejects_reserved_ksi_and_spare_algorithm_bits() {
        let command = |ksi: u8, algorithms: u8| {
            NasSecurityModeCommand::new(
                NasSelectedNasSecurityAlgorithms::new(algorithms),
                NasKeySetIdentifier::new(ksi),
                NasSpareHalfOctet::new(0),
                NasReplayedUeSecurityCapabilities::new(vec![0xe0, 0xe0]),
            )
        };
        assert!(command(0, 0x02).validate().is_empty());
        let null_integrity = command(0, 0x00).validate();
        assert_eq!(
            fields(&null_integrity),
            ["selected_nas_security_algorithms"]
        );
        assert_eq!(null_integrity[0].severity, Severity::Warning);
        let unspecified = command(0, 0x42).validate();
        assert_eq!(fields(&unspecified), ["selected_nas_security_algorithms"]);
        assert_eq!(unspecified[0].severity, Severity::Error);
        assert_eq!(
            fields(&command(7, 0x02).validate()),
            ["nas_key_set_identifier"]
        );
        assert_eq!(
            fields(&command(0, 0x82).validate()),
            ["selected_nas_security_algorithms"]
        );
        let bad_replay = NasSecurityModeCommand::new(
            NasSelectedNasSecurityAlgorithms::new(0x02),
            NasKeySetIdentifier::new(0),
            NasSpareHalfOctet::new(0),
            NasReplayedUeSecurityCapabilities::new(vec![0xe0, 0xe0, 0, 0]),
        );
        assert_eq!(
            fields(&bad_replay.validate()),
            ["replayed_ue_security_capabilities"]
        );
    }
}
