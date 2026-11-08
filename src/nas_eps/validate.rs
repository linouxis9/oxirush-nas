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
//! use oxirush_nas::Validate;
//! use oxirush_nas::nas_eps::Message;
//!
//! let message = Message::decode(&[0x07, 0x60, 0x03]).unwrap();
//! assert!(message.validate().is_empty());
//! ```

use crate::common::{ReceiverSyntaxCheck, invalid_ie, with_optional_ie_checks};
pub(crate) use crate::common::{Severity, Validate, ValidationError};
use crate::nas_eps::SecurityHeaderType;
use crate::nas_eps::*;
use crate::prelude::*;

impl ReceiverSyntaxCheck for Cli {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for AccessPointName {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for EpsMobileIdentity {
    fn receiver_syntax_ok(&self) -> bool {
        self.as_imsi().is_some() || self.as_imei().is_some() || self.as_guti().is_some()
    }

    fn receiver_syntax_fault(&self) -> Option<String> {
        self.receiver_fault()
    }
}

impl ReceiverSyntaxCheck for MobileIdentity {
    fn receiver_syntax_ok(&self) -> bool {
        self.as_imsi().is_some()
            || self.as_imei().is_some()
            || self.as_imeisv().is_some()
            || self.as_tmsi().is_some()
            || matches!(self.value.as_slice(), [0, 0, 0, ..])
    }
}

impl ReceiverSyntaxCheck for MessageContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 2
    }
}

impl ReceiverSyntaxCheck for QualityOfService {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for EpsQualityOfService {
    fn receiver_syntax_ok(&self) -> bool {
        self.qos().is_some()
    }
}

// Errors inside a TFT are errors of the ESM procedure (TS 24.301 §6.4.2.4,
// §6.4.3.4, §6.5.3.4, §6.5.4.4), which the receiver answers with the ESM
// cause of parse_tft. Only an empty value is short of the message tables.
impl ReceiverSyntaxCheck for TrafficFlowTemplate {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for TrafficFlowAggregateDescription {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for PdnAddress {
    fn receiver_syntax_ok(&self) -> bool {
        self.pdn_address().is_some()
    }
}

impl ReceiverSyntaxCheck for UeSecurityCapability {
    fn receiver_syntax_ok(&self) -> bool {
        matches!(self.value.len(), 2 | 4..)
    }
}

impl ReceiverSyntaxCheck for TrackingAreaIdentityList {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for UeNetworkCapability {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 2
    }
}

// The rules of the IE types that `validate()` checks: the value lengths of
// their clauses, the values that a sender sets, and a receiver's grammar.
crate::common::ie_rules! {
    AccessPointName: sender, receiver;
    AdditionalInformation;
    AdditionalInformationRequested: sender(0 | 1);
    AdditionalUpdateResult: sender(0..=2);
    AdditionalUpdateType: sender(0..=0x0b);
    ApnAggregateMaximumBitRate: sender;
    CipheringKeyData: sender;
    CipheringKeySequenceNumber: sender(0..=7);
    Cli: sender, receiver;
    ConnectivityType: sender(0 | 1);
    ControlPlaneOnlyIndication: sender;
    ControlPlaneServiceType: sender(0 | 1 | 8 | 9);
    CsfbResponse: sender(0 | 1);
    DcnId;
    DetachType: sender(1..=3 | 9..=11);
    DeviceProperties: sender(0 | 1);
    DrxParameter: sender;
    EmmCause;
    EpsAdditionalRequestResult: sender;
    EpsAttachResult: sender(1 | 2);
    EpsAttachType: sender(1..=3 | 6 | 7);
    EpsMobileIdentity: sender, receiver;
    EpsNetworkFeatureSupport: sender;
    EpsQualityOfService: sender_own, receiver;
    EpsUpdateResult: sender(0 | 1 | 4 | 5);
    EpsUpdateType: sender(0..=3 | 6 | 8..=11 | 14);
    EsmCause;
    EsmInformationTransferFlag: sender(0 | 1);
    EsmMessageContainer;
    ExtendedApnAggregateMaximumBitRate: sender;
    ExtendedEmmCause;
    ExtendedQualityOfService: sender;
    GenericMessageContainer;
    GenericMessageContainerType: sender(1 | 2);
    GutiType: sender(0 | 1);
    HashMme: sender;
    HeaderCompressionConfiguration: sender;
    HeaderCompressionConfigurationStatus: sender;
    IdentityType2: sender(1..=4);
    ImsiOffset;
    KeySetIdentifier: sender(0..=15);
    LcsClientIdentity;
    LcsIndicator;
    LinkedEpsBearerIdentity: sender(1..=15);
    LlcServiceAccessPointIdentifier: sender(0 | 3 | 5 | 9 | 11);
    LocationAreaIdentification;
    MessageContainer: receiver;
    MobileIdentity: receiver;
    MobileStationClassmark3: sender;
    MsNetworkCapability: sender;
    MsNetworkFeatureSupport: sender(0 | 1);
    N1UeNetworkCapability: sender;
    NbifomContainer;
    NbS1DrxParameter: sender;
    NetworkPolicy: sender(0 | 1);
    NetworkResourceIdentifierContainer: sender;
    Nonce;
    NotificationIndicator: sender_own;
    PacketFlowIdentifier: sender;
    PagingIdentity: sender(0 | 1);
    PagingRestriction: sender;
    PdnAddress: sender, receiver;
    PdnType: sender(1..=3 | 5 | 6);
    PkmfAddress: sender;
    ProtocolConfigurationOptions;
    PTmsiSignature;
    QualityOfService: sender, receiver;
    RadioPriority: sender(1..=4);
    ReAttemptIndicator: sender;
    RemoteUeContextList: sender;
    ReplayedNasMessageContainer;
    RequestType: sender(1..=4 | 6);
    SAndFSatelliteOperationParameters: sender;
    SecurityAlgorithms: sender;
    ServiceType: sender(0..=2 | 8);
    SmsServicesStatus: sender(0..=3);
    SsCode;
    T3412ExtendedValue: sender;
    T3412Value;
    TmsiStatus: sender(0 | 1);
    TrackingAreaIdentity;
    TrackingAreaIdentityList: sender, receiver;
    TrafficFlowAggregateDescription: sender, receiver;
    TrafficFlowTemplate: sender, receiver;
    TransactionIdentifier: sender;
    UeAdditionalSecurityCapability: sender;
    UeCoarseLocationInformation;
    UeInformationRequest: sender(0 | 1);
    UeNetworkCapability: sender, receiver;
    UeRadioCapabilityIdAvailability: sender_own;
    UeRadioCapabilityIdRequest: sender_own;
    UeRadioCapabilityInformationUpdateNeeded: sender(0 | 1);
    UeSecurityCapability: sender, receiver;
    UserDataContainer;
    VoiceDomainPreferenceAndUeUsageSetting: sender;
    WlanOffloadAcceptability: sender(0..=3);
}

impl NotificationIndicator {
    /// Whether a sender writes the IE.
    fn sender_check(&self) -> bool {
        self.value == [1]
    }

    /// The rule of a sender, as a finding says it.
    fn sender_rule(&self) -> &'static str {
        "the one octet 0x01, \"paging for CS fallback\""
    }
}

impl UeRadioCapabilityIdAvailability {
    /// Whether a sender writes the IE.
    fn sender_check(&self) -> bool {
        matches!(self.value[..], [0 | 1, ..])
    }

    /// The rule of a sender, as a finding says it.
    fn sender_rule(&self) -> &'static str {
        "a first octet of 0 or 1"
    }
}

impl UeRadioCapabilityIdRequest {
    /// Whether a sender writes the IE.
    fn sender_check(&self) -> bool {
        matches!(self.value[..], [0 | 1, ..])
    }

    /// The rule of a sender, as a finding says it.
    fn sender_rule(&self) -> &'static str {
        "a first octet of 0 or 1"
    }
}

impl EpsQualityOfService {
    /// Whether a sender writes the IE.
    fn sender_check(&self) -> bool {
        self.is_well_formed() && !self.has_zero_maximum_bit_rates()
    }

    /// The rule of a sender, as a finding says it.
    fn sender_rule(&self) -> &'static str {
        match self.is_well_formed() {
            true => "maximum bit rates that are not zero (TS 24.301 §9.9.4.3)",
            false => Self::SENDER_RULE,
        }
    }
}

// The EPS QoS of the messages from the network: an assigned QCI and no
// reserved bit rate octet, beyond the rules of every sender (§9.9.4.3).
fn check_network_eps_qos(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    ie: &EpsQualityOfService,
) {
    let assigned = ie.qos().is_some_and(|qos| qos.qci_is_network_valid())
        && (ie.value.len() < 5 || ie.value[1..5].iter().all(|&rate| rate != 0));
    if !assigned && !errors.iter().any(|error| error.field == field) {
        let rule = "from the network an assigned QCI and no reserved bit rate octet (§9.9.4.3)";
        errors.push(invalid_ie(field, rule));
    }
}

// BEGIN TS24301 VALIDATE
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

impl Validate for AttachAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.guti {
            check_eps_ie_valid(
                &mut errors,
                "guti",
                ie.as_guti().is_some(),
                "a GUTI as TS 24.301 §9.9.3.12 writes it",
            );
        }
        // §8.2.1.4: a new TMSI, assigned or unassigned
        if let Some(ie) = &self.ms_identity {
            check_eps_ie_valid(
                &mut errors,
                "ms_identity",
                ie.is_well_formed() && (ie.as_tmsi().is_some() || ie.as_imsi().is_some()),
                "a TMSI, or the IMSI that unassigns one, as TS 24.008 §10.5.1.4 writes it",
            );
        }
        check_esm_message_container(
            &mut errors,
            &self.esm_message_container.value,
            Severity::Warning,
        );
        errors
    }
}

impl Validate for AttachComplete {
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

impl Validate for AttachReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.esm_message_container {
            check_esm_message_container(&mut errors, &ie.value, Severity::Error);
        }
        errors
    }
}

impl Validate for AttachRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.additional_guti {
            check_eps_ie_valid(
                &mut errors,
                "additional_guti",
                ie.as_guti().is_some(),
                "a GUTI as TS 24.301 §9.9.3.12 writes it",
            );
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
        if self.eps_mobile_identity.identity_type() == Some(MobileIdentityTypeEps::Guti)
            && self.old_guti_type.is_none()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "old_guti_type",
                message: "Old GUTI type is required when ATTACH REQUEST uses a GUTI".into(),
            });
        }
        if let Ok(Message::Esm(_, EsmMessage::PdnConnectivityRequest(request))) =
            Message::decode(&self.esm_message_container.value)
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

impl Validate for AuthenticationFailure {
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

impl Validate for AuthenticationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "nas_key_set_identifier_asme",
            self.nas_key_set_identifier_asme.value <= 6,
            "a key set identifier of 0 to 6",
        );
        errors
    }
}

impl Validate for DetachRequestUeTerminated {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "detach_type",
            self.detach_type.value & 0x08 == 0,
            "a detach type with bit 4 clear",
        );
        errors
    }
}

impl Validate for ExtendedServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "m_tmsi",
            self.m_tmsi.as_tmsi().is_some() && self.m_tmsi.is_well_formed(),
            "an M-TMSI as TS 24.008 §10.5.1.4 writes it",
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

impl Validate for GutiReallocationCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "guti",
            self.guti.as_guti().is_some(),
            "a GUTI as TS 24.301 §9.9.3.12 writes it",
        );
        errors
    }
}

impl Validate for IdentityResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "mobile_identity",
            self.mobile_identity.is_well_formed(),
            "a mobile identity as TS 24.008 §10.5.1.4 writes it",
        );
        errors
    }
}

impl Validate for SecurityModeCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_eps_ie_valid(
            &mut errors,
            "nas_key_set_identifier",
            !self.nas_key_set_identifier.no_key_available(),
            "a key set identifier other than 7, no key",
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

impl Validate for SecurityModeComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.imeisv {
            check_eps_ie_valid(
                &mut errors,
                "imeisv",
                ie.as_imeisv().is_some(),
                "an IMEISV as TS 24.008 §10.5.1.4 writes it",
            );
        }
        errors
    }
}

impl Validate for ServiceReject {
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

impl Validate for TrackingAreaUpdateAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        if let Some(ie) = &self.guti {
            check_eps_ie_valid(
                &mut errors,
                "guti",
                ie.as_guti().is_some(),
                "a GUTI as TS 24.301 §9.9.3.12 writes it",
            );
        }
        // §8.2.26.7: a new TMSI, assigned or unassigned
        if let Some(ie) = &self.ms_identity {
            check_eps_ie_valid(
                &mut errors,
                "ms_identity",
                ie.is_well_formed() && (ie.as_tmsi().is_some() || ie.as_imsi().is_some()),
                "a TMSI, or the IMSI that unassigns one, as TS 24.008 §10.5.1.4 writes it",
            );
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

impl Validate for TrackingAreaUpdateRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        // A native key set identifier 0 to 6 (§5.5.3.2.2, §8.2.29.2).
        if let Some(ie) = &self.non_current_native_nas_key_set_identifier {
            check_eps_ie_valid(
                &mut errors,
                "non_current_native_nas_key_set_identifier",
                ie.value <= 6,
                "a key set identifier of 0 to 6",
            );
        }
        check_eps_ie_valid(
            &mut errors,
            "old_guti",
            self.old_guti.as_guti().is_some(),
            "a GUTI as TS 24.301 §9.9.3.12 writes it",
        );
        if let Some(ie) = &self.additional_guti {
            check_eps_ie_valid(
                &mut errors,
                "additional_guti",
                ie.as_guti().is_some(),
                "a GUTI as TS 24.301 §9.9.3.12 writes it",
            );
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
            ie.request_type() != Some(UeRequestTypeValue::NasSignallingConnectionRelease)
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
                != Some(UeRequestTypeValue::NasSignallingConnectionRelease)
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

impl Validate for ControlPlaneServiceRequest {
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
                ie.is_well_formed(PcoDirection::$direction), "the units of configuration options that its direction has",
);
        }
        if let Some(ie) = &$message.extended_protocol_configuration_options {
            check_eps_ie_valid(
                &mut $errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::$direction), "the units of configuration options that its direction has",
);
        }
        $(
            if let Some(ie) = &$message.nbifom_container {
                check_eps_ie_valid(
                    &mut $errors,
                    "nbifom_container",
                    ie.is_well_formed_for(NbifomDirection::$nbifom), "NBIFOM parameters of its direction",
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

impl Validate for ActivateDedicatedEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        errors
    }
}

impl Validate for ActivateDedicatedEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        errors
    }
}

impl Validate for ActivateDedicatedEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        check_network_eps_qos(&mut errors, "eps_qos", &self.eps_qos);
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

impl Validate for ActivateDefaultEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink);
        errors
    }
}

impl Validate for ActivateDefaultEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink);
        errors
    }
}

impl Validate for ActivateDefaultEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        check_network_eps_qos(&mut errors, "eps_qos", &self.eps_qos);
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

impl Validate for BearerResourceAllocationReject {
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

impl Validate for BearerResourceAllocationRequest {
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

impl Validate for BearerResourceModificationReject {
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

impl Validate for BearerResourceModificationRequest {
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

impl Validate for DeactivateEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink);
        errors
    }
}

impl Validate for DeactivateEpsBearerContextRequest {
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

impl Validate for EsmInformationResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, exclusive, Uplink);
        errors
    }
}

impl Validate for ModifyEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        errors
    }
}

impl Validate for ModifyEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Uplink, UeToNetwork);
        errors
    }
}

impl Validate for ModifyEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink, NetworkToUe);
        if let Some(ie) = &self.new_eps_qos {
            check_network_eps_qos(&mut errors, "new_eps_qos", ie);
        }
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

impl Validate for PdnConnectivityReject {
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

impl Validate for PdnConnectivityRequest {
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

impl Validate for PdnDisconnectReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = self.sender_check_findings();
        check_esm_options!(errors, self, Downlink);
        errors
    }
}

impl Validate for PdnDisconnectRequest {
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
    AuthenticationReject,
    AuthenticationResponse,
    CsServiceNotification,
    DetachAccept,
    DetachRequestUeOriginating,
    DownlinkGenericNasTransport,
    DownlinkNasTransport,
    EmmInformation,
    EmmStatus,
    EsmDataTransport,
    EsmDummyMessage,
    EsmInformationRequest,
    EsmStatus,
    GutiReallocationComplete,
    IdentityRequest,
    Notification,
    RemoteUeReport,
    RemoteUeReportResponse,
    SecurityModeReject,
    ServiceAccept,
    TrackingAreaUpdateComplete,
    TrackingAreaUpdateReject,
    UplinkGenericNasTransport,
    UplinkNasTransport,
);

impl Validate for EmmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let body = self.body();
        with_optional_ie_checks(
            body.validate(),
            body.unknown_ies(),
            body.ie_order_findings(),
            UNKNOWN_TLVE_START,
        )
    }
}

impl Validate for EsmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let body = self.body();
        with_optional_ie_checks(
            body.validate(),
            body.unknown_ies(),
            body.ie_order_findings(),
            UNKNOWN_TLVE_START,
        )
    }
}

// END TS24301 VALIDATE

fn check_esm_message_container(
    errors: &mut Vec<ValidationError>,
    value: &[u8],
    severity: Severity,
) {
    if !matches!(Message::decode(value), Ok(Message::Esm(..))) {
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

/// The finding of `field` where it is not `valid`: it breaks `rule`.
fn check_eps_ie_valid(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    valid: bool,
    rule: &str,
) {
    if !valid {
        errors.push(invalid_ie(field, rule));
    }
}

impl Validate for EmmTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if self.security_header.security_header_type
            != SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        {
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
                "an EMM TRANSPORT data container of its direction",
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

impl EmmTransport {
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

impl Validate for Message {
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
                EsmMessage::BearerResourceAllocationRequest(_)
                    | EsmMessage::EsmDummyMessage(_)
                    | EsmMessage::BearerResourceAllocationReject(_)
                    | EsmMessage::BearerResourceModificationRequest(_)
                    | EsmMessage::BearerResourceModificationReject(_)
                    | EsmMessage::EsmInformationRequest(_)
                    | EsmMessage::EsmInformationResponse(_)
                    | EsmMessage::PdnConnectivityRequest(_)
                    | EsmMessage::PdnConnectivityReject(_)
                    | EsmMessage::PdnDisconnectRequest(_)
                    | EsmMessage::PdnDisconnectReject(_)
            );
            let bearer_response = matches!(
                message,
                EsmMessage::ActivateDedicatedEpsBearerContextAccept(_)
                    | EsmMessage::ActivateDedicatedEpsBearerContextReject(_)
                    | EsmMessage::ActivateDefaultEpsBearerContextAccept(_)
                    | EsmMessage::ActivateDefaultEpsBearerContextReject(_)
                    | EsmMessage::ModifyEpsBearerContextAccept(_)
                    | EsmMessage::ModifyEpsBearerContextReject(_)
                    | EsmMessage::DeactivateEpsBearerContextAccept(_)
            );
            let bearer_request = matches!(
                message,
                EsmMessage::ActivateDedicatedEpsBearerContextRequest(_)
                    | EsmMessage::ActivateDefaultEpsBearerContextRequest(_)
                    | EsmMessage::ModifyEpsBearerContextRequest(_)
                    | EsmMessage::DeactivateEpsBearerContextRequest(_)
            );
            let remote_report = matches!(
                message,
                EsmMessage::RemoteUeReport(_) | EsmMessage::RemoteUeReportResponse(_)
            );
            let esm_data_transport = matches!(message, EsmMessage::EsmDataTransport(_));
            let unassigned_notification = matches!(message, EsmMessage::Notification(_))
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
            && let Err(error) = self.encode()
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

impl Validate for ServiceRequest {
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

    fn attach_request(ue_network_capability: Vec<u8>) -> AttachRequest {
        AttachRequest::new(
            EpsAttachType::new(1),
            KeySetIdentifier::new(7),
            EpsMobileIdentity::from_imsi("001010123456789").unwrap(),
            UeNetworkCapability::new(ue_network_capability),
            EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        )
    }

    /// A message struct reports the lengths of its table and the rules of
    /// its IE types.
    #[test]
    fn table_lengths_and_ie_type_rules_apply_to_message_fields() {
        let request = attach_request(vec![0xe0, 0xe0]);
        assert!(request.validate().is_empty());
        // Table 8.2.4.1: a P-TMSI signature of three octets.
        let short = request
            .clone()
            .with_old_p_tmsi_signature(PTmsiSignature::new(vec![0; 2]));
        assert_eq!(fields(&short.validate()), ["old_p_tmsi_signature"]);
        // EPS attach type 4 and TMSI status 2 are not defined.
        let mut values = request.with_tmsi_status(TmsiStatus::new(2));
        values.eps_attach_type = EpsAttachType::new(4);
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
        let message = Message::decode(&bytes).unwrap();
        assert!(message.validate().is_empty());
    }

    #[test]
    fn longer_n1_ue_network_capability_is_valid() {
        let request = attach_request(vec![0xe0, 0xe0])
            .with_n1_ue_network_capability(N1UeNetworkCapability::new(vec![0x7f, 0, 0]));
        assert!(request.validate().is_empty());
        let spare = attach_request(vec![0xe0, 0xe0])
            .with_n1_ue_network_capability(N1UeNetworkCapability::new(vec![0x80]));
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
            ReceiverSyntaxCheck::receiver_syntax_ok(&TrafficFlowTemplate::new(
                semantic_error.clone(),
            )),
            ReceiverSyntaxCheck::receiver_syntax_ok(&TrafficFlowAggregateDescription::new(
                semantic_error,
            )),
        ] {
            assert!(receiver_ok);
        }

        // "Create new TFT" without packet filters.
        assert!(ReceiverSyntaxCheck::receiver_syntax_ok(
            &TrafficFlowTemplate::new(vec![0x20])
        ));
        assert!(ReceiverSyntaxCheck::receiver_syntax_ok(
            &TrafficFlowAggregateDescription::new(vec![0x20])
        ));
        assert!(!ReceiverSyntaxCheck::receiver_syntax_ok(
            &TrafficFlowTemplate::new(vec![])
        ));
        let syntax_error =
            Message::decode(&[0x52, 0x01, 0xc5, 0x05, 0x01, 0x00, 0x01, 0x20]).unwrap();
        let Message::Esm(_, EsmMessage::ActivateDedicatedEpsBearerContextRequest(request)) =
            syntax_error
        else {
            panic!("wrong mandatory-TFT message");
        };
        assert_eq!(
            request.tft.parse_tft().map_err(TftError::esm_cause),
            Err(EsmCauseValue::SyntacticalErrorInTheTftOperation)
        );

        let mut mandatory_wire = vec![0x52, 0x01, 0xc5, 0x05, 0x01, 0x00, 0x19];
        mandatory_wire.extend_from_slice(&[
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x01, 0xaa, 0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ]);
        let Message::Esm(_, EsmMessage::ActivateDedicatedEpsBearerContextRequest(request)) =
            Message::decode(&mandatory_wire).unwrap()
        else {
            panic!("wrong mandatory-TFT message");
        };
        assert_eq!(request.tft.parse_tft(), Err(TftError::SemanticTftOperation));

        let mut optional_wire = vec![0x52, 0x01, 0xc9, 0x36, 0x19];
        optional_wire.extend_from_slice(&[
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x01, 0xaa, 0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ]);
        let Message::Esm(_, EsmMessage::ModifyEpsBearerContextRequest(request)) =
            Message::decode(&optional_wire).unwrap()
        else {
            panic!("wrong optional-TFT message");
        };
        assert_eq!(
            request.tft.unwrap().parse_tft(),
            Err(TftError::SemanticTftOperation)
        );
    }

    /// The QoS that the network assigns has a QCI of TS 23.203 and no
    /// reserved bit rate octet; the QoS that a UE asks for has the rules of
    /// every sender alone (§9.9.4.3).
    #[test]
    fn network_eps_qos_rules_apply_to_the_messages_of_the_network() {
        let unassigned = EpsQualityOfService::new(vec![0x00]);
        assert!(unassigned.sender_check());
        let modify = ModifyEpsBearerContextRequest::new().with_new_eps_qos(unassigned.clone());
        assert_eq!(fields(&modify.validate()), ["new_eps_qos"]);
        let assigned = modify.with_new_eps_qos(EpsQualityOfService::new(vec![0x09]));
        assert!(assigned.validate().is_empty());
        let reserved = EpsQualityOfService::new(vec![0x01, 0x00, 0x01, 0x01, 0x01]);
        let modify = ModifyEpsBearerContextRequest::new().with_new_eps_qos(reserved);
        assert_eq!(fields(&modify.validate()), ["new_eps_qos"]);
    }

    /// The non-current native key set identifier of a TRACKING AREA UPDATE
    /// REQUEST is that of a native context, 0 to 6 (§5.5.3.2.2, §8.2.29.2).
    #[test]
    fn non_current_native_key_set_identifier_is_native() {
        let update = |ksi: u8| {
            TrackingAreaUpdateRequest::new(
                EpsUpdateType::new(0),
                KeySetIdentifier::new(0x09),
                EpsMobileIdentity::new(vec![0xf6, 0x02, 0xf8, 0x39, 0, 1, 1, 0, 0, 0, 1]),
            )
            .with_old_guti_type(GutiType::new(1))
            .with_ue_network_capability(UeNetworkCapability::new(vec![0xe0, 0xe0]))
            .with_non_current_native_nas_key_set_identifier(KeySetIdentifier::new(ksi))
        };
        assert!(
            update(6).validate().is_empty(),
            "{:?}",
            update(6).validate()
        );
        for ksi in [7, 0x08, 0x0e] {
            assert_eq!(
                fields(&update(ksi).validate()),
                ["non_current_native_nas_key_set_identifier"]
            );
        }
    }

    #[test]
    fn security_mode_command_rejects_reserved_ksi_and_spare_algorithm_bits() {
        let command = |ksi: u8, algorithms: u8| {
            SecurityModeCommand::new(
                SecurityAlgorithms::new(algorithms),
                KeySetIdentifier::new(ksi),
                UeSecurityCapability::new(vec![0xe0, 0xe0]),
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
        let bad_replay = SecurityModeCommand::new(
            SecurityAlgorithms::new(0x02),
            KeySetIdentifier::new(0),
            UeSecurityCapability::new(vec![0xe0, 0xe0, 0, 0]),
        );
        assert_eq!(
            fields(&bad_replay.validate()),
            ["replayed_ue_security_capabilities"]
        );
    }
}
