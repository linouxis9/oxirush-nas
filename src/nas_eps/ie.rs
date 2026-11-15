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

//! Typed accessors for EPS NAS information elements.
//!
//! This module provides enums and methods over the raw IE structs in
//! [`crate::nas_eps::types`]. The raw `.value` fields remain public; typed
//! accessors parse bit fields and cause codes according to TS 24.301.
//! Methods are implemented on the IE types from [`crate::nas_eps::types`].
//!
//! # Architecture
//!
//! ```text
//! Layer 3 — This module: typed enums and IE accessors
//! Layer 2 — messages.rs: NAS message structs with IEI dispatch
//! Layer 1 — types.rs: raw TLV/TV/V/LV wire codec
//! ```

pub(crate) use crate::common::Plmn;
use crate::common::field_table::field_row;
use crate::common::{counted, sized, within};
use crate::nas_eps::*;
use crate::prelude::*;

// BEGIN TS24301 IE
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

oxirush_utils::named_values! {
    /// EmmCauseValue values from TS 24.301 Table 9.9.3.9.1.
    pub enum EmmCauseValue "Table 9.9.3.9.1" bits 8 others as 0x6F {
        0x02 ImsiUnknownInHss "IMSI unknown in HSS" tree "imsi-unknown-in-hss",
        0x03 IllegalUe "Illegal UE" tree "illegal-ue",
        0x05 ImeiNotAccepted "IMEI not accepted" tree "imei-not-accepted",
        0x06 IllegalMe "Illegal ME" tree "illegal-me",
        0x07 EpsServicesNotAllowed "EPS services not allowed" tree "eps-services-not-allowed",
        0x08 EpsServicesAndNonEpsServicesNotAllowed "EPS services and non-EPS services not allowed" tree "eps-services-and-non-eps-services-not-allowed",
        0x09 UeIdentityCannotBeDerivedByTheNetwork "UE identity cannot be derived by the network" tree "ue-identity-cannot-be-derived-by-the-network",
        0x0A ImplicitlyDetached "Implicitly detached" tree "implicitly-detached",
        0x0B PlmnNotAllowed "PLMN not allowed" tree "plmn-not-allowed",
        0x0C TrackingAreaNotAllowed "Tracking Area not allowed" tree "tracking-area-not-allowed",
        0x0D RoamingNotAllowedInThisTrackingArea "Roaming not allowed in this tracking area" tree "roaming-not-allowed-in-this-tracking-area",
        0x0E EpsServicesNotAllowedInThisPlmn "EPS services not allowed in this PLMN" tree "eps-services-not-allowed-in-this-plmn",
        0x0F NoSuitableCellsInTrackingArea "No Suitable Cells In tracking area" tree "no-suitable-cells-in-tracking-area",
        0x10 MscTemporarilyNotReachable "MSC temporarily not reachable" tree "msc-temporarily-not-reachable",
        0x11 NetworkFailure "Network failure" tree "network-failure",
        0x12 CsDomainNotAvailable "CS domain not available" tree "cs-domain-not-available",
        0x13 EsmFailure "ESM failure" tree "esm-failure",
        0x14 MacFailure "MAC failure" tree "mac-failure",
        0x15 SynchFailure "Synch failure" tree "synch-failure",
        0x16 Congestion "Congestion" tree "congestion",
        0x17 UeSecurityCapabilitiesMismatch "UE security capabilities mismatch" tree "ue-security-capabilities-mismatch",
        0x18 SecurityModeRejectedUnspecified "Security mode rejected, unspecified" tree "security-mode-rejected-unspecified",
        0x19 NotAuthorizedForThisCsg "Not authorized for this CSG" tree "not-authorized-for-this-csg",
        0x1A NonEpsAuthenticationUnacceptable "Non-EPS authentication unacceptable" tree "non-eps-authentication-unacceptable",
        0x1F RedirectionToFiveGcnRequired "Redirection to 5GCN required" tree "redirection-to-5gcn-required",
        0x23 RequestedServiceOptionNotAuthorizedInThisPlmn "Requested service option not authorized in this PLMN" tree "requested-service-option-not-authorized-in-this-plmn",
        0x24 IabNodeOperationNotAuthorized "IAB-node operation not authorized" tree "iab-node-operation-not-authorized",
        0x27 CsServiceTemporarilyNotAvailable "CS service temporarily not available" tree "cs-service-temporarily-not-available",
        0x28 NoEpsBearerContextActivated "No EPS bearer context activated" tree "no-eps-bearer-context-activated",
        0x2A SevereNetworkFailure "Severe network failure" tree "severe-network-failure",
        0x4E PlmnNotAllowedToOperateAtThePresentUeLocation "PLMN not allowed to operate at the present UE location" tree "plmn-not-allowed-to-operate-at-the-present-ue-location",
        0x50 DisasterRoamingForTheDeterminedPlmnWithDisasterConditionNotAllowed "Disaster roaming for the determined PLMN with disaster condition not allowed" tree "disaster-roaming-for-the-determined-plmn-with-disaster-condition-not-allowed",
        0x53 ProcedureCannotBeCompletedDueToUnavailableFeederLinkWhileMmeIsOperatingInSAndFMode "Procedure cannot be completed due to unavailable feeder link while MME is operating in S&F mode" tree "procedure-cannot-be-completed-due-to-unavailable-feeder-link-while-mme-is-operating-in-s-and-f-mode",
        0x5F SemanticallyIncorrectMessage "Semantically incorrect message" tree "semantically-incorrect-message",
        0x60 InvalidMandatoryInformation "Invalid mandatory information" tree "invalid-mandatory-information",
        0x61 MessageTypeNonExistentOrNotImplemented "Message type non-existent or not implemented" tree "message-type-non-existent-or-not-implemented",
        0x62 MessageTypeNotCompatibleWithTheProtocolState "Message type not compatible with the protocol state" tree "message-type-not-compatible-with-the-protocol-state",
        0x63 InformationElementNonExistentOrNotImplemented "Information element non-existent or not implemented" tree "information-element-non-existent-or-not-implemented",
        0x64 ConditionalIeError "Conditional IE error" tree "conditional-ie-error",
        0x65 MessageNotCompatibleWithTheProtocolState "Message not compatible with the protocol state" tree "message-not-compatible-with-the-protocol-state",
        0x6F ProtocolErrorUnspecified "Protocol error, unspecified" tree "protocol-error-unspecified",
    }
}
crate::common::enums::values_readable!(EmmCauseValue);

impl EmmCause {
    /// Build the raw IE from a typed cause.
    pub fn from_cause(cause: EmmCauseValue) -> Self {
        Self::new(u8::from(cause))
    }
    /// The cause, if its value is one of the table.
    pub fn cause(&self) -> Option<EmmCauseValue> {
        EmmCauseValue::named(self.value)
    }
    /// Decode the cause received by the UE or the network (the table's "interpreted as" rule, `EmmCauseValue::effective`).
    pub fn cause_received(&self) -> EmmCauseValue {
        EmmCauseValue::from_value(self.value).effective()
    }
    /// Set the cause value.
    pub fn set_cause(&mut self, cause: EmmCauseValue) -> &mut Self {
        self.value = u8::from(cause);
        self
    }
    /// Cause text, with the hexadecimal value for unknown codes.
    pub fn description(&self) -> String {
        match self.cause() {
            Some(cause) => cause.name().unwrap_or_default().to_string(),
            None => format!("Unknown EMM cause 0x{:02x}", self.value),
        }
    }
}

oxirush_utils::named_values! {
    /// EsmCauseValue values from TS 24.301 Table 9.9.4.4.1.
    pub enum EsmCauseValue "Table 9.9.4.4.1" bits 8 {
        0x08 OperatorDeterminedBarring "Operator Determined Barring" tree "operator-determined-barring",
        0x1A InsufficientResources "Insufficient resources" tree "insufficient-resources",
        0x1B MissingOrUnknownApn "Missing or unknown APN" tree "missing-or-unknown-apn",
        0x1C UnknownPdnType "Unknown PDN type" tree "unknown-pdn-type",
        0x1D UserAuthenticationOrAuthorizationFailed "User authentication or authorization failed" tree "user-authentication-or-authorization-failed",
        0x1E RequestRejectedByServingGwOrPdnGw "Request rejected by Serving GW or PDN GW" tree "request-rejected-by-serving-gw-or-pdn-gw",
        0x1F RequestRejectedUnspecified "Request rejected, unspecified" tree "request-rejected-unspecified",
        0x20 ServiceOptionNotSupported "Service option not supported" tree "service-option-not-supported",
        0x21 RequestedServiceOptionNotSubscribed "Requested service option not subscribed" tree "requested-service-option-not-subscribed",
        0x22 ServiceOptionTemporarilyOutOfOrder "Service option temporarily out of order" tree "service-option-temporarily-out-of-order",
        0x23 PtiAlreadyInUse "PTI already in use" tree "pti-already-in-use",
        0x24 RegularDeactivation "Regular deactivation" tree "regular-deactivation",
        0x25 EpsQosNotAccepted "EPS QoS not accepted" tree "eps-qos-not-accepted",
        0x26 NetworkFailure "Network failure" tree "network-failure",
        0x27 ReactivationRequested "Reactivation requested" tree "reactivation-requested",
        0x29 SemanticErrorInTheTftOperation "Semantic error in the TFT operation" tree "semantic-error-in-the-tft-operation",
        0x2A SyntacticalErrorInTheTftOperation "Syntactical error in the TFT operation" tree "syntactical-error-in-the-tft-operation",
        0x2B InvalidEpsBearerIdentity "Invalid EPS bearer identity" tree "invalid-eps-bearer-identity",
        0x2C SemanticErrorsInPacketFilters "Semantic errors in packet filter(s)" tree "semantic-errors-in-packet-filters",
        0x2D SyntacticalErrorsInPacketFilters "Syntactical errors in packet filter(s)" tree "syntactical-errors-in-packet-filters",
        0x2F PtiMismatch "PTI mismatch" tree "pti-mismatch",
        0x31 LastPdnDisconnectionNotAllowed "Last PDN disconnection not allowed" tree "last-pdn-disconnection-not-allowed",
        0x32 PdnTypeIpv4OnlyAllowed "PDN type IPv4 only allowed" tree "pdn-type-ipv4-only-allowed",
        0x33 PdnTypeIpv6OnlyAllowed "PDN type IPv6 only allowed" tree "pdn-type-ipv6-only-allowed",
        0x34 SingleAddressBearersOnlyAllowed "Single address bearers only allowed" tree "single-address-bearers-only-allowed",
        0x35 EsmInformationNotReceived "ESM information not received" tree "esm-information-not-received",
        0x36 PdnConnectionDoesNotExist "PDN connection does not exist" tree "pdn-connection-does-not-exist",
        0x37 MultiplePdnConnectionsForAGivenApnNotAllowed "Multiple PDN connections for a given APN not allowed" tree "multiple-pdn-connections-for-a-given-apn-not-allowed",
        0x38 CollisionWithNetworkInitiatedRequest "Collision with network initiated request" tree "collision-with-network-initiated-request",
        0x39 PdnTypeIpv4v6OnlyAllowed "PDN type IPv4v6 only allowed" tree "pdn-type-ipv4v6-only-allowed",
        0x3A PdnTypeNonIpOnlyAllowed "PDN type non IP only allowed" tree "pdn-type-non-ip-only-allowed",
        0x3B UnsupportedQciValue "Unsupported QCI value" tree "unsupported-qci-value",
        0x3C BearerHandlingNotSupported "Bearer handling not supported" tree "bearer-handling-not-supported",
        0x3D PdnTypeEthernetOnlyAllowed "PDN type Ethernet only allowed" tree "pdn-type-ethernet-only-allowed",
        0x41 MaximumNumberOfEpsBearersReached "Maximum number of EPS bearers reached" tree "maximum-number-of-eps-bearers-reached",
        0x42 RequestedApnNotSupportedInCurrentRatAndPlmnCombination "Requested APN not supported in current RAT and PLMN combination" tree "requested-apn-not-supported-in-current-rat-and-plmn-combination",
        0x51 InvalidPtiValue "Invalid PTI value" tree "invalid-pti-value",
        0x5F SemanticallyIncorrectMessage "Semantically incorrect message" tree "semantically-incorrect-message",
        0x60 InvalidMandatoryInformation "Invalid mandatory information" tree "invalid-mandatory-information",
        0x61 MessageTypeNonExistentOrNotImplemented "Message type non-existent or not implemented" tree "message-type-non-existent-or-not-implemented",
        0x62 MessageTypeNotCompatibleWithTheProtocolState "Message type not compatible with the protocol state" tree "message-type-not-compatible-with-the-protocol-state",
        0x63 InformationElementNonExistentOrNotImplemented "Information element non-existent or not implemented" tree "information-element-non-existent-or-not-implemented",
        0x64 ConditionalIeError "Conditional IE error" tree "conditional-ie-error",
        0x65 MessageNotCompatibleWithTheProtocolState "Message not compatible with the protocol state" tree "message-not-compatible-with-the-protocol-state",
        0x6F ProtocolErrorUnspecified "Protocol error, unspecified" tree "protocol-error-unspecified",
        0x70 ApnRestrictionValueIncompatibleWithActiveEpsBearerContext "APN restriction value incompatible with active EPS bearer context" tree "apn-restriction-value-incompatible-with-active-eps-bearer-context",
        0x71 MultipleAccessesToAPdnConnectionNotAllowed "Multiple accesses to a PDN connection not allowed" tree "multiple-accesses-to-a-pdn-connection-not-allowed",
    }
}
crate::common::enums::values_readable!(EsmCauseValue);

impl EsmCauseValue {
    /// Decode a cause received by the UE, applying the rule for values that
    /// are not listed: they are treated as `ServiceOptionTemporarilyOutOfOrder`.
    pub fn from_u8_for_ue(value: u8) -> Self {
        Self::named(value).unwrap_or(Self::ServiceOptionTemporarilyOutOfOrder)
    }
    /// Decode a cause received by the network, applying the rule for values that
    /// are not listed: they are treated as `ProtocolErrorUnspecified`.
    pub fn from_u8_for_network(value: u8) -> Self {
        Self::named(value).unwrap_or(Self::ProtocolErrorUnspecified)
    }
}

impl EsmCause {
    /// Build the raw IE from a typed cause.
    pub fn from_cause(cause: EsmCauseValue) -> Self {
        Self::new(u8::from(cause))
    }
    /// The cause, if its value is one of the table.
    pub fn cause(&self) -> Option<EsmCauseValue> {
        EsmCauseValue::named(self.value)
    }
    /// Decode the cause received by the UE (see [`EsmCauseValue::from_u8_for_ue`]).
    pub fn cause_for_ue(&self) -> EsmCauseValue {
        EsmCauseValue::from_u8_for_ue(self.value)
    }
    /// Decode the cause received by the network (see [`EsmCauseValue::from_u8_for_network`]).
    pub fn cause_for_network(&self) -> EsmCauseValue {
        EsmCauseValue::from_u8_for_network(self.value)
    }
    /// Set the cause value.
    pub fn set_cause(&mut self, cause: EsmCauseValue) -> &mut Self {
        self.value = u8::from(cause);
        self
    }
    /// Cause text, with the hexadecimal value for unknown codes.
    pub fn description(&self) -> String {
        match self.cause() {
            Some(cause) => cause.name().unwrap_or_default().to_string(),
            None => format!("Unknown ESM cause 0x{:02x}", self.value),
        }
    }
}

// END TS24301 IE

impl EsmMessageContainer {
    /// Decode the contained plain ESM PDU.
    pub fn decode_as_esm_message(&self) -> crate::common::Result<crate::nas_eps::Message> {
        use crate::nas_eps::Message;
        let message = Message::decode(&self.value)?;
        if matches!(message, Message::Esm(..)) {
            Ok(message)
        } else {
            Err(crate::common::Error::DecodingError(
                "EPS message container does not contain an ESM PDU".into(),
            ))
        }
    }

    /// Build a container from a plain ESM PDU.
    pub fn from_esm_message(message: &crate::nas_eps::Message) -> crate::common::Result<Self> {
        use crate::nas_eps::Message;
        if !matches!(message, Message::Esm(..)) {
            return Err(crate::common::Error::EncodingError(
                "EPS message container requires a plain ESM PDU".into(),
            ));
        }
        Ok(Self::new(message.encode()?))
    }
}

oxirush_utils::named_values! {
    /// Paging restriction type (TS 24.301 Table 9.9.3.66.1).
    pub enum PagingRestrictionType "Table 9.9.3.66.1" bits 8 {
        1 AllRestricted "all restricted" tree "all-restricted",
        2 AllRestrictedExceptVoice "all restricted except voice" tree "all-restricted-except-voice",
        3 AllRestrictedExceptSpecifiedPdnConnections "all restricted except specified pdn connections" tree "all-restricted-except-specified-pdn-connections",
        4 AllRestrictedExceptVoiceAndSpecifiedPdnConnections "all restricted except voice and specified pdn connections" tree "all-restricted-except-voice-and-specified-pdn-connections",
    }
}
crate::common::enums::values_readable!(PagingRestrictionType);

crate::common::ts24301::paging_restriction_ie!(
    PagingRestriction,
    PagingRestrictionType {
        AllRestrictedExceptSpecifiedPdnConnections,
        AllRestrictedExceptVoiceAndSpecifiedPdnConnections
    },
    unrestricted_ebis,
    "unrestricted-ebis",
    "eps-bearer-identity"
);

pub use crate::common::ts24301::PagingRestrictionDecision;
crate::common::ts24301::additional_request_result_ie!(EpsAdditionalRequestResult);

oxirush_utils::named_values! {
    /// DRX value for S1 mode, the DRX cycle parameter T (TS 24.008 Table
    /// 10.5.139).
    pub enum S1DrxValue "" bits 8 others as 0 {
        0 NotSpecified "not specified" tree "not-specified",
        6 T32 "t32" tree "t32",
        7 T64 "t64" tree "t64",
        8 T128 "t128" tree "t128",
        9 T256 "t256" tree "t256",
    }
}
crate::common::enums::values_readable!(S1DrxValue);

/// SPLIT PG CYCLE values for codes 65 to 98 (TS 24.008 Table 10.5.139).
const SPLIT_PG_CYCLES: [u16; 34] = [
    71, 72, 74, 75, 77, 79, 80, 83, 86, 88, 90, 92, 96, 101, 103, 107, 112, 116, 118, 128, 141,
    144, 150, 160, 171, 176, 192, 214, 224, 235, 256, 288, 320, 352,
];

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl DrxParameter (value) "10.5.5.6" octets 2 {
        split_pg_cycle_code "SPLIT PG CYCLE CODE": 0 1 8,
        s1_drx_value "CN Specific DRX cycle length coefficient and DRX value for S1 mode": 1 5 4 as S1DrxValue,
        split_on_ccch "SPLIT on CCCH": 1 4 1,
        non_drx_timer "non-DRX timer": 1 1 3,
    }
}
crate::common::field_table::table_ie!(DrxParameter, octets, 2..=2, receives 2);

impl DrxParameter {
    /// SPLIT PG CYCLE: code 0 is 704 (no DRX), and reserved codes are read
    /// as 1.
    pub fn split_pg_cycle(&self) -> Option<u16> {
        self.value.first()?;
        Some(match self.split_pg_cycle_code() {
            0 => 704,
            code @ 1..=64 => u16::from(code),
            code @ 65..=98 => SPLIT_PG_CYCLES[usize::from(code - 65)],
            _ => 1,
        })
    }

    /// Build from the fields.
    pub fn from_fields(
        split_pg_cycle_code: u8,
        s1_drx_value: S1DrxValue,
        split_on_ccch: bool,
        non_drx_timer: u8,
    ) -> core::result::Result<Self, ValueError> {
        within("non-drx-timer", non_drx_timer, 0, 7)?;
        Ok(Self::new(vec![
            split_pg_cycle_code,
            (u8::from(s1_drx_value)) << 4 | u8::from(split_on_ccch) << 3 | non_drx_timer,
        ]))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "two octets: a split PG cycle code of at most 98, and an S1 mode DRX value of 0 or 6 to 9 (TS 24.008 §10.5.5.6)";
    /// Check the paging cycle and S1-mode DRX value (TS 24.008 §10.5.5.6).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [cycle, value]
            if *cycle <= 98 && matches!(value >> 4, 0 | 6 | 7 | 8 | 9))
    }
}

oxirush_utils::named_values! {
    /// Voice domain preference for E-UTRAN (TS 24.008 Table 10.5.166A).
    pub enum VoiceDomainPreference "Table 10.5.166A" bits 8 {
        0 CsVoiceOnly "cs voice only" tree "cs-voice-only",
        1 ImsPsVoiceOnly "ims ps voice only" tree "ims-ps-voice-only",
        2 CsVoicePreferred "cs voice preferred" tree "cs-voice-preferred",
        3 ImsPsVoicePreferred "ims ps voice preferred" tree "ims-ps-voice-preferred",
    }
}
crate::common::enums::values_readable!(VoiceDomainPreference);

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl VoiceDomainPreferenceAndUeUsageSetting (value) "10.5.5.28" octets 1 {
        voice_domain_preference "Voice domain preference for E-UTRAN": 0 1 2 as VoiceDomainPreference,
        data_centric "UE's usage setting": 0 3 1,
    }
}
crate::common::field_table::table_ie!(VoiceDomainPreferenceAndUeUsageSetting, octets, 1..=1, receives 1);

impl VoiceDomainPreferenceAndUeUsageSetting {
    /// Build with the spare bits clear.
    pub fn from_fields(preference: VoiceDomainPreference, data_centric: bool) -> Self {
        Self::new(vec![u8::from(data_centric) << 2 | u8::from(preference)])
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "one octet with bits 8 to 4 clear (TS 24.008 §10.5.5.28)";
    /// Check the spare bits of the voice preference octet (TS 24.008 §10.5.5.28).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [value] if value & 0xf8 == 0)
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl N1UeNetworkCapability (value) "9.9.3.57" octets 1 {
        pnb_ciot "5GS-PNB-CIoT": 0 5 2 as PreferredCiotBehavior,
        cp_ciot "5G-CP CIoT": 0 1 1,
        n3_data_not_supported "N3 data": 0 2 1,
        hc_cp_ciot "5G-HC-CP CIoT": 0 3 1,
        up_ciot "5G-UP CIoT": 0 4 1,
        ehc_cp_ciot "5G-EHC-CP CIoT": 0 7 1,
    }
}
crate::common::field_table::table_ie!(N1UeNetworkCapability, octets, 1..=1, receives 0, trailing);

impl Default for N1UeNetworkCapability {
    /// One octet with no capability indicated.
    fn default() -> Self {
        Self::new(vec![0])
    }
}

impl N1UeNetworkCapability {
    /// Whether N3 data transfer is supported (N3 data bit clear).
    pub fn n3_data_transfer_supported(&self) -> bool {
        !self.value.is_empty() && !self.n3_data_not_supported()
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "1 to 13 octets with octet 3 bit 8 clear and later octets spare";
    /// Sender check: 1 to 13 octets with octet 3 bit 8 clear and later octets spare.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.split_first(), Some((first, rest))
            if first & 0x80 == 0 && rest.len() <= 12 && rest.iter().all(|&octet| octet == 0))
    }
}

impl NetworkResourceIdentifierContainer {
    /// The 10-bit NRI container value: TMSI bits 23 to 14 (TS 24.008
    /// §10.5.5.31). Spare bits and extra octets are ignored.
    pub fn nri(&self) -> Option<u16> {
        match self.value.as_slice() {
            [high, low, ..] => Some(u16::from(*high) << 2 | u16::from(low >> 6)),
            _ => None,
        }
    }

    /// Build from a 10-bit NRI container value.
    pub fn from_nri(nri: u16) -> core::result::Result<Self, ValueError> {
        within("nri-container-value", nri, 0, 0x03ff)?;
        Ok(Self::new(vec![(nri >> 2) as u8, ((nri & 0x03) << 6) as u8]))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "two octets with the six spare bits after the NRI clear (TS 24.008 §10.5.5.31)";
    /// Check the six spare bits after the NRI (TS 24.008 §10.5.5.31).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [_, low] if low & 0x3f == 0)
    }
}

pub use crate::common::ts24008::MsRevisionLevel;

oxirush_utils::named_values! {
    /// NBIFOM parameter identifiers (TS 24.161 Table 6.1.1-1).
    pub enum NbifomParameterId "Table 6.1.1" bits 8 {
        0x01 Mode "mode" tree "mode",
        0x02 DefaultAccess "default access" tree "default-access",
        0x03 Status "status" tree "status",
        0x04 RoutingRules "routing rules" tree "routing-rules",
        0x05 IpFlowMapping "ip flow mapping" tree "ip-flow-mapping",
        0x06 RanRulesHandling "ran rules handling" tree "ran-rules-handling",
        0x07 AccessStratumStatus "access stratum status" tree "access-stratum-status",
        0x08 AccessUsabilityIndication "access usability indication" tree "access-usability-indication",
    }
}
crate::common::enums::values_readable!(NbifomParameterId);

/// Direction of an NBIFOM parameter container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NbifomDirection {
    /// UE to network.
    UeToNetwork,
    /// Network to UE.
    NetworkToUe,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum NbifomDirection {
        UeToNetwork,
        NetworkToUe,
    }
);
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(NbifomDirection);

/// One unit of the NBIFOM parameter list (TS 24.161 §6.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NbifomParameter {
    /// Parameter identifier.
    pub identifier: u8,
    /// Parameter contents.
    pub contents: Vec<u8>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct NbifomParameter { identifier, contents });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(NbifomParameter);

oxirush_utils::named_values! {
    /// NBIFOM status parameter (TS 24.161 Table 6.1.3-1).
    pub enum NbifomStatus "Table 6.1.3" bits 8 others as 0x6f {
        0x00 Accepted "accepted" tree "accepted",
        0x1a InsufficientResources "insufficient resources" tree "insufficient-resources",
        0x22 ServiceOptionTemporarilyOutOfOrder "service option temporarily out of order" tree "service-option-temporarily-out-of-order",
        0x25 RequestedServiceOptionNotSubscribed "requested service option not subscribed" tree "requested-service-option-not-subscribed",
        0x3f RequestRejectedUnspecified "request rejected unspecified" tree "request-rejected-unspecified",
        0x39 IncorrectIndicationInRoutingRuleOperation "incorrect indication in routing rule operation" tree "incorrect-indication-in-routing-rule-operation",
        0x3a UnknownInformationInIpFlowFilters "unknown information in ip flow filters" tree "unknown-information-in-ip-flow-filters",
        0x6f ProtocolErrorUnspecified "protocol error unspecified" tree "protocol-error-unspecified",
        0x82 UnknownRoutingAccessInformation "unknown routing access information" tree "unknown-routing-access-information",
    }
}
crate::common::enums::values_readable!(NbifomStatus);

fn nbifom_routing_rule_is_well_formed(rule: &[u8]) -> bool {
    if rule.len() < 7 {
        return false;
    }
    let access_and_operation = rule[1];
    if !matches!(access_and_operation & 0xC0, 0x40 | 0x80)
        || access_and_operation & 0x38 != 0
        || !matches!(access_and_operation & 0x07, 1..=3)
        || rule[4] & 0xC0 != 0
        || rule[5] != 0
        || rule[6] != 0
    {
        return false;
    }
    let first = rule[3];
    let second = rule[4];
    if first & 0x03 != 0 && first & 0x0C != 0
        || second & 0x02 != 0 && second & 0x01 == 0
        || second & 0x08 != 0 && second & 0x04 == 0
    {
        return false;
    }
    let first_sizes = [1usize, 4, 1, 1, 16, 16, 4, 4];
    let second_sizes = [4usize, 4, 4, 4, 1, 4];
    let mut length = 7usize;
    for (index, size) in first_sizes.into_iter().enumerate() {
        if first & (0x80 >> index) != 0 {
            length += size;
        }
    }
    let mut n_offset = None;
    for (index, size) in second_sizes.into_iter().enumerate() {
        if second & (1 << index) != 0 {
            if index == 5 {
                n_offset = Some(length);
            }
            length += size;
        }
    }
    rule.len() == length
        && n_offset.is_none_or(|offset| rule.get(offset).is_some_and(|octet| octet & 0xF0 == 0))
}

fn nbifom_routing_rules_are_well_formed(mut contents: &[u8]) -> bool {
    if contents.is_empty() {
        return false;
    }
    while let Some((&length, rest)) = contents.split_first() {
        let Some(rule) = rest.get(..usize::from(length)) else {
            return false;
        };
        if !nbifom_routing_rule_is_well_formed(rule) {
            return false;
        }
        contents = &rest[rule.len()..];
    }
    true
}

fn nbifom_parameter_is_well_formed(
    parameter: &NbifomParameter,
    direction: NbifomDirection,
) -> bool {
    let contents = parameter.contents.as_slice();
    let allowed = match direction {
        NbifomDirection::UeToNetwork => matches!(parameter.identifier, 1 | 2 | 3 | 4 | 5 | 7 | 8),
        NbifomDirection::NetworkToUe => matches!(parameter.identifier, 1 | 2 | 3 | 4 | 6),
    };
    allowed
        && match parameter.identifier {
            1 | 2 | 6 => matches!(contents, [1 | 2]),
            3 => matches!(contents, [value] if NbifomStatus::named(*value).is_some()),
            4 | 5 => nbifom_routing_rules_are_well_formed(contents),
            7 => matches!(contents, [1..=3]),
            8 => matches!(contents, [value] if value & 0xF0 == 0
                && value & 0x03 != 0x03
                && value & 0x0C != 0x0C),
            _ => false,
        }
}

impl NbifomContainer {
    /// Parameter units in wire order; `None` if a unit overruns the value.
    pub fn parameters(&self) -> Option<Vec<NbifomParameter>> {
        let mut parameters = Vec::new();
        let mut remaining = self.value.as_slice();
        while let Some((&identifier, rest)) = remaining.split_first() {
            let (&length, rest) = rest.split_first()?;
            let contents = rest.get(..usize::from(length))?;
            parameters.push(NbifomParameter {
                identifier,
                contents: contents.to_vec(),
            });
            remaining = &rest[contents.len()..];
        }
        Some(parameters)
    }

    /// Contents of the first unit with `identifier`. Units are unordered
    /// and unsupported identifiers are ignored (TS 24.161 §6.1.1).
    pub fn parameter(&self, identifier: NbifomParameterId) -> Option<Vec<u8>> {
        self.parameters()?
            .into_iter()
            .find(|parameter| parameter.identifier == u8::from(identifier))
            .map(|parameter| parameter.contents)
    }

    /// NBIFOM status of the first status unit, with the receive fallback.
    pub fn status(&self) -> Option<NbifomStatus> {
        let contents = self.parameter(NbifomParameterId::Status)?;
        contents
            .first()
            .map(|&status| NbifomStatus::from_value(status).effective())
    }

    /// Build from parameter units: a unit and the value have 255 octets at
    /// most.
    pub fn from_parameters(
        parameters: &[NbifomParameter],
    ) -> core::result::Result<Self, ValueError> {
        let mut value = Vec::new();
        for (entry, parameter) in parameters.iter().enumerate() {
            let octets = parameter.contents.len();
            sized("contents", "octets", octets, 0, 255).map_err(|error| error.at(entry))?;
            value.push(parameter.identifier);
            value.push(octets as u8);
            value.extend_from_slice(&parameter.contents);
        }
        sized("nbifom-container", "octets", value.len(), 0, 255)?;
        Ok(Self::new(value))
    }

    /// Sender check for a particular NBIFOM message direction.
    pub fn is_well_formed_for(&self, direction: NbifomDirection) -> bool {
        self.parameters().is_some_and(|parameters| {
            !parameters.is_empty()
                && parameters
                    .iter()
                    .all(|parameter| nbifom_parameter_is_well_formed(parameter, direction))
        })
    }

    /// Direction-agnostic sender check for standalone IE construction.
    /// Message validation uses [`Self::is_well_formed_for`].
    pub fn is_well_formed(&self) -> bool {
        self.parameters().is_some_and(|parameters| {
            !parameters.is_empty()
                && parameters.iter().all(|parameter| {
                    nbifom_parameter_is_well_formed(parameter, NbifomDirection::UeToNetwork)
                        || nbifom_parameter_is_well_formed(parameter, NbifomDirection::NetworkToUe)
                })
        })
    }
}

/// One ciphering data set of the ciphering key data IE (TS 24.301 §9.9.3.56).
/// `Debug` prints the length of its ciphering key, and not the key.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub struct CipheringDataSet {
    /// Ciphering set identifier.
    pub set_id: u16,
    /// Ciphering key.
    pub ciphering_key: [u8; 16],
    /// c0 counter value, 0 to 16 octets.
    pub c0: Vec<u8>,
    /// E-UTRA posSIB types bitmap (octets k+1 to k+4).
    pub pos_sib_types: [u8; 4],
    /// Validity start time: octets 2 to 6 of the TS 24.008 time zone and time IE.
    pub validity_start_time: [u8; 5],
    /// Validity duration in minutes.
    pub validity_duration: u16,
    /// TAI list value octets; empty means the whole serving PLMN.
    pub tai_list: Vec<u8>,
}

impl core::fmt::Debug for CipheringDataSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let key = crate::common::display::Hidden(self.ciphering_key.len());
        f.debug_struct("CipheringDataSet")
            .field("set_id", &self.set_id)
            .field("ciphering_key", &format_args!("{key}"))
            .field("c0", &self.c0)
            .field("pos_sib_types", &self.pos_sib_types)
            .field("validity_start_time", &self.validity_start_time)
            .field("validity_duration", &self.validity_duration)
            .field("tai_list", &self.tai_list)
            .finish()
    }
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct CipheringDataSet { set_id, ciphering_key, c0, pos_sib_types, validity_start_time, validity_duration, tai_list as tai_list_eps_octets });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(CipheringDataSet);

impl CipheringDataSet {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(
        set_id: u16,
        ciphering_key: [u8; 16],
        c0: Vec<u8>,
        pos_sib_types: [u8; 4],
        validity_start_time: [u8; 5],
        validity_duration: u16,
        tai_list: Vec<u8>,
    ) -> Self {
        Self {
            set_id,
            ciphering_key,
            c0,
            pos_sib_types,
            validity_start_time,
            validity_duration,
            tai_list,
        }
    }
}

impl CipheringDataSet {
    /// The tracking areas of the set, or `None` for the whole serving PLMN.
    pub fn tai_list_value(&self) -> Option<TrackingAreaIdentityList> {
        (!self.tai_list.is_empty()).then(|| TrackingAreaIdentityList::new(self.tai_list.clone()))
    }
}

impl CipheringKeyData {
    /// Decode the ciphering data sets. The receiver keeps the first 16 sets
    /// and ignores the remaining octets (Table 9.9.3.56.1); decoding stops at
    /// the first incomplete set. Spare bits of the c0 length octet are ignored.
    pub fn data_sets(&self) -> Vec<CipheringDataSet> {
        let mut rest = self.value.as_slice();
        let mut sets = Vec::new();
        while sets.len() < 16 && rest.len() >= 31 {
            let c0_length = usize::from(rest[18] & 0x1f);
            if c0_length > 16 {
                break;
            }
            let fixed = 19 + c0_length;
            let Some(&tai_length) = rest.get(fixed + 11) else {
                break;
            };
            let end = fixed + 12 + usize::from(tai_length);
            if rest.len() < end {
                break;
            }
            let (Ok(ciphering_key), Ok(pos_sib_types), Ok(validity_start_time)) = (
                rest[2..18].try_into(),
                rest[fixed..fixed + 4].try_into(),
                rest[fixed + 4..fixed + 9].try_into(),
            ) else {
                break;
            };
            sets.push(CipheringDataSet {
                set_id: u16::from_be_bytes([rest[0], rest[1]]),
                ciphering_key,
                c0: rest[19..fixed].to_vec(),
                pos_sib_types,
                validity_start_time,
                validity_duration: u16::from_be_bytes([rest[fixed + 9], rest[fixed + 10]]),
                tai_list: rest[fixed + 12..end].to_vec(),
            });
            rest = &rest[end..];
        }
        sets
    }

    /// Encode 1 to 16 ciphering data sets: a c0 of 16 octets at most, and a
    /// TAI list of 255.
    pub fn from_data_sets(sets: &[CipheringDataSet]) -> core::result::Result<Self, ValueError> {
        counted("ciphering-data-sets", sets.len(), 1, 16)?;
        let mut value = Vec::new();
        for (entry, set) in sets.iter().enumerate() {
            let entry = |error: ValueError| error.at(entry);
            sized("c0", "octets", set.c0.len(), 0, 16).map_err(entry)?;
            sized("tai-list", "octets", set.tai_list.len(), 0, 255).map_err(entry)?;
            value.extend_from_slice(&set.set_id.to_be_bytes());
            value.extend_from_slice(&set.ciphering_key);
            value.push(set.c0.len() as u8);
            value.extend_from_slice(&set.c0);
            value.extend_from_slice(&set.pos_sib_types);
            value.extend_from_slice(&set.validity_start_time);
            value.extend_from_slice(&set.validity_duration.to_be_bytes());
            value.push(set.tai_list.len() as u8);
            value.extend_from_slice(&set.tai_list);
        }
        sized("ciphering-key-data", "octets", value.len(), 0, 65535)?;
        Ok(Self::new(value))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "1 to 16 complete ciphering data sets with the spare bits clear (TS 24.301 §9.9.3.56)";
    /// Check ciphering data set boundaries and spare bits (TS 24.301 §9.9.3.56).
    pub fn is_well_formed(&self) -> bool {
        let mut remaining = self.value.as_slice();
        let mut count = 0;
        while !remaining.is_empty() {
            count += 1;
            if count > 16 || remaining.len() < 31 {
                return false;
            }
            let c0_length = remaining[18];
            if c0_length & 0xe0 != 0 || c0_length & 0x1f > 16 {
                return false;
            }
            let sib_start = 19 + usize::from(c0_length & 0x1f);
            let tai_length_at = sib_start + 4 + 5 + 2;
            let Some(&tai_length) = remaining.get(tai_length_at) else {
                return false;
            };
            if remaining[sib_start + 3] & 0x1f != 0 {
                return false;
            }
            let end = tai_length_at + 1 + usize::from(tai_length);
            if remaining.len() < end {
                return false;
            }
            if tai_length != 0
                && !TrackingAreaIdentityList::new(&remaining[tai_length_at + 1..end])
                    .is_well_formed()
            {
                return false;
            }
            remaining = &remaining[end..];
        }
        count > 0
    }
}

/// Handling of the S&F monitoring list (SFMLI, TS 24.301 Table 9.9.3.73.1).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SAndFMonitoringList {
    /// No list; also the reading of the unused value 11.
    NotPresent,
    /// No list, and the UE deletes any list received before.
    Delete,
    /// Satellite IDs.
    Present(Vec<u8>),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum SAndFMonitoringList {
        NotPresent,
        Delete,
        Present(Vec<u8>),
    }
);
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(SAndFMonitoringList);

impl SAndFSatelliteOperationParameters {
    /// S&F wait time duration in seconds, when indicated.
    pub fn wait_time(&self) -> Option<u16> {
        let flags = *self.value.first()?;
        if flags & 0x01 == 0 {
            return None;
        }
        let [high, low] = *self.value.get(1..)?.first_chunk::<2>()?;
        Some(u16::from_be_bytes([high, low]))
    }

    /// Estimated S&F uplink delivery time duration in seconds, when indicated.
    pub fn uplink_delivery_time(&self) -> Option<u32> {
        let flags = *self.value.first()?;
        if flags & 0x02 == 0 {
            return None;
        }
        let offset = 1 + if flags & 0x01 != 0 { 2 } else { 0 };
        crate::common::ts24301::read_time_duration(self.value.get(offset..)?)
    }

    /// S&F monitoring list handling; `None` if the list overruns the value.
    pub fn monitoring_list(&self) -> Option<SAndFMonitoringList> {
        let flags = *self.value.first()?;
        Some(match (flags >> 2) & 0x03 {
            1 => SAndFMonitoringList::Delete,
            2 => {
                let offset = 1
                    + if flags & 0x01 != 0 { 2 } else { 0 }
                    + if flags & 0x02 != 0 { 3 } else { 0 };
                let (&count, ids) = self.value.get(offset..)?.split_first()?;
                SAndFMonitoringList::Present(ids.get(..usize::from(count))?.to_vec())
            }
            _ => SAndFMonitoringList::NotPresent,
        })
    }

    /// Build from the fields; the uplink delivery time is at most 0xFFFFFF
    /// seconds and the list holds at most 255 satellite IDs.
    pub fn from_fields(
        wait_time: Option<u16>,
        uplink_delivery_time: Option<u32>,
        monitoring_list: &SAndFMonitoringList,
    ) -> core::result::Result<Self, ValueError> {
        let list_mode = match monitoring_list {
            SAndFMonitoringList::NotPresent => 0,
            SAndFMonitoringList::Delete => 1,
            SAndFMonitoringList::Present(_) => 2,
        };
        let mut value = vec![
            u8::from(wait_time.is_some())
                | u8::from(uplink_delivery_time.is_some()) << 1
                | list_mode << 2,
        ];
        if let Some(wait_time) = wait_time {
            value.extend_from_slice(&wait_time.to_be_bytes());
        }
        if let Some(seconds) = uplink_delivery_time {
            within("uplink-delivery-time", seconds, 0, 0x00ff_ffff)?;
            value.extend_from_slice(&seconds.to_be_bytes()[1..]);
        }
        if let SAndFMonitoringList::Present(ids) = monitoring_list {
            counted("monitoring-list", ids.len(), 0, 255)?;
            value.push(ids.len() as u8);
            value.extend_from_slice(ids);
        }
        Ok(Self::new(value))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "a flags octet with bits 8 to 5 clear and a list mode that is not 3, then the duration, the time and the satellite list that the flags indicate, and nothing after them (TS 24.301 §9.9.3.73)";
    /// Check flag, duration, and satellite-list lengths from TS 24.301 §9.9.3.73.
    pub fn is_well_formed(&self) -> bool {
        let Some(&flags) = self.value.first() else {
            return false;
        };
        let list_mode = (flags >> 2) & 3;
        if flags & 0xf0 != 0 || list_mode == 3 {
            return false;
        }
        let mut offset =
            1 + if flags & 1 != 0 { 2 } else { 0 } + if flags & 2 != 0 { 3 } else { 0 };
        if self.value.len() < offset {
            return false;
        }
        if list_mode == 2 {
            let Some(&count) = self.value.get(offset) else {
                return false;
            };
            offset += 1 + usize::from(count);
        }
        self.value.len() == offset
    }
}

pub use crate::common::ts24501::PortRange;

oxirush_utils::named_values! {
    /// Type of a remote UE user identity (TS 24.301 Table 9.9.4.20.2).
    pub enum RemoteUeIdentityType "Table 9.9.4.20.2" bits 8 {
        1 EncryptedImsi "encrypted imsi" tree "encrypted-imsi",
        2 Imsi "imsi" tree "imsi",
        3 Msisdn "msisdn" tree "msisdn",
        4 Imei "imei" tree "imei",
        5 Imeisv "imeisv" tree "imeisv",
    }
}
crate::common::enums::values_readable!(RemoteUeIdentityType);

/// One user identity of a remote UE context: octet 4 onwards of the
/// identity, which carries digit 1, the odd/even indication, and the type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteUeUserIdentity {
    /// Identity octets, starting with the type octet.
    pub octets: Vec<u8>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct RemoteUeUserIdentity { octets });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(RemoteUeUserIdentity);

impl RemoteUeUserIdentity {
    /// Raw type of identity (bits 3-1 of the first octet).
    pub fn identity_type_raw(&self) -> Option<u8> {
        self.octets.first().map(|octet| octet & 0x07)
    }

    /// Typed identity type; reserved codes return `None`.
    pub fn identity_type(&self) -> Option<RemoteUeIdentityType> {
        match self.identity_type_raw()? {
            1 => Some(RemoteUeIdentityType::EncryptedImsi),
            2 => Some(RemoteUeIdentityType::Imsi),
            3 => Some(RemoteUeIdentityType::Msisdn),
            4 => Some(RemoteUeIdentityType::Imei),
            5 => Some(RemoteUeIdentityType::Imeisv),
            _ => None,
        }
    }

    /// BCD digits of an IMSI, MSISDN, IMEI, or IMEISV.
    pub fn digits(&self) -> Option<String> {
        let kind = self.identity_type_raw()?;
        let max_digits = match self.identity_type()? {
            RemoteUeIdentityType::EncryptedImsi => return None,
            RemoteUeIdentityType::Imeisv => 16,
            _ => 15,
        };
        let (read, digits) = oxirush_utils::identity::digits::decode(&self.octets).ok()?;
        (read == kind && (2..=max_digits).contains(&digits.len())).then_some(digits)
    }

    /// The 128-bit encrypted IMSI, from the 16 octets after the type octet.
    pub fn encrypted_imsi(&self) -> Option<[u8; 16]> {
        if self.identity_type()? != RemoteUeIdentityType::EncryptedImsi {
            return None;
        }
        self.octets.get(1..17)?.try_into().ok()
    }

    /// Whether this identity uses a defined type and canonical sender coding.
    pub fn is_well_formed(&self) -> bool {
        match self.identity_type() {
            Some(RemoteUeIdentityType::EncryptedImsi) => {
                self.octets.len() == 17
                    && self.octets.first() == Some(&(u8::from(RemoteUeIdentityType::EncryptedImsi)))
            }
            Some(identity_type) => self.digits().is_some_and(|digits| {
                let type_specific = match identity_type {
                    RemoteUeIdentityType::Other(_) => false,
                    RemoteUeIdentityType::Imsi | RemoteUeIdentityType::Msisdn => true,
                    RemoteUeIdentityType::Imei => digits.len() == 15 && digits.ends_with('0'),
                    RemoteUeIdentityType::Imeisv => digits.len() == 16 && !digits.ends_with("99"),
                    // An encrypted IMSI has no digits.
                    RemoteUeIdentityType::EncryptedImsi => false,
                };
                type_specific && Self::from_digits(identity_type, &digits).as_ref() == Ok(self)
            }),
            None => false,
        }
    }

    /// Build a BCD identity: the encrypted IMSI is none, and has its octets.
    pub fn from_digits(
        identity_type: RemoteUeIdentityType,
        digits: &str,
    ) -> core::result::Result<Self, ValueError> {
        let max_digits = match identity_type {
            RemoteUeIdentityType::EncryptedImsi => {
                let rule = "is an identity of digits: the encrypted IMSI is octets";
                return Err(ValueError::combination("identity-type", rule));
            }
            RemoteUeIdentityType::Imei => {
                sized("digits", "digits", digits.len(), 15, 15)?;
                if !digits.ends_with('0') {
                    let rule = "of an IMEI end with the spare digit 0";
                    return Err(ValueError::combination("digits", rule));
                }
                15
            }
            RemoteUeIdentityType::Imeisv => {
                sized("digits", "digits", digits.len(), 16, 16)?;
                if digits.ends_with("99") {
                    let rule = "of an IMEISV do not end with the software version 99";
                    return Err(ValueError::combination("digits", rule));
                }
                16
            }
            _ => 15,
        };
        sized("digits", "digits", digits.len(), 2, max_digits)?;
        if let Some(other) = digits.chars().find(|digit| !digit.is_ascii_digit()) {
            return Err(ValueError::character("digits", other, "decimal digits"));
        }
        let kind = u8::from(identity_type);
        let octets = oxirush_utils::identity::digits::encode(kind, digits)?;
        Ok(Self { octets })
    }

    /// Build an encrypted IMSI identity with bits 8 to 5 of the type octet clear.
    pub fn from_encrypted_imsi(encrypted_imsi: [u8; 16]) -> Self {
        let mut octets = vec![u8::from(RemoteUeIdentityType::EncryptedImsi)];
        octets.extend_from_slice(&encrypted_imsi);
        Self { octets }
    }
}

/// Address information of a remote UE context (TS 24.301 Table 9.9.4.20.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteUeAddress {
    /// No IP information.
    NoIpInfo,
    /// IPv4 address and NAT port, with optional UDP and TCP port ranges.
    Ipv4 {
        /// IPv4 address.
        address: [u8; 4],
        /// Port number assigned in the NAT function.
        port: u16,
        /// UDP port range.
        udp_port_range: Option<PortRange>,
        /// TCP port range.
        tcp_port_range: Option<PortRange>,
    },
    /// /64 IPv6 prefix.
    Ipv6Prefix([u8; 8]),
    /// A reserved address type and the octets after octet j.
    Unknown {
        /// Address type (bits 3-1 of octet j).
        address_type: u8,
        /// Remaining octets of the context.
        octets: Vec<u8>,
    },
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(enum RemoteUeAddress { NoIpInfo, Ipv4 { address, port, udp_port_range, tcp_port_range }, Ipv6Prefix([u8; 8]), Unknown { address_type, octets } });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(RemoteUeAddress);

/// One remote UE context of the remote UE context list IE.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteUeContext {
    /// User identities in wire order.
    pub user_identities: Vec<RemoteUeUserIdentity>,
    /// Address information.
    pub address: RemoteUeAddress,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct RemoteUeContext { user_identities, address });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(RemoteUeContext);

impl RemoteUeContext {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(user_identities: Vec<RemoteUeUserIdentity>, address: RemoteUeAddress) -> Self {
        Self {
            user_identities,
            address,
        }
    }
}

fn read_port_range(octets: &[u8]) -> Option<(PortRange, &[u8])> {
    let (range, rest) = octets.split_first_chunk::<4>()?;
    let low = u16::from_be_bytes([range[0], range[1]]);
    let high = u16::from_be_bytes([range[2], range[3]]);
    Some((PortRange { low, high }, rest))
}

impl RemoteUeContext {
    /// Parse the octets after the context length. Spare bits are ignored;
    /// the port-range indicators apply only to IPv4, and octets after the
    /// address information are ignored.
    pub fn from_bytes(octets: &[u8]) -> Option<Self> {
        let (&count, mut rest) = octets.split_first()?;
        let mut user_identities = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let (&length, after) = rest.split_first()?;
            if length == 0 {
                return None;
            }
            let identity = after.get(..usize::from(length))?;
            user_identities.push(RemoteUeUserIdentity {
                octets: identity.to_vec(),
            });
            rest = &after[identity.len()..];
        }
        let (&flags, rest) = rest.split_first()?;
        let address = match flags & 0x07 {
            0 => RemoteUeAddress::NoIpInfo,
            1 => {
                let (info, mut rest) = rest.split_first_chunk::<6>()?;
                let mut udp_port_range = None;
                let mut tcp_port_range = None;
                if flags & 0x10 != 0 {
                    let (range, after) = read_port_range(rest)?;
                    udp_port_range = Some(range);
                    rest = after;
                }
                if flags & 0x08 != 0 {
                    tcp_port_range = Some(read_port_range(rest)?.0);
                }
                RemoteUeAddress::Ipv4 {
                    address: [info[0], info[1], info[2], info[3]],
                    port: u16::from_be_bytes([info[4], info[5]]),
                    udp_port_range,
                    tcp_port_range,
                }
            }
            2 => RemoteUeAddress::Ipv6Prefix(*rest.first_chunk::<8>()?),
            address_type => RemoteUeAddress::Unknown {
                address_type,
                octets: rest.to_vec(),
            },
        };
        Some(Self {
            user_identities,
            address,
        })
    }

    /// Whether every identity and the address use canonical sender coding.
    pub fn is_well_formed(&self) -> bool {
        self.user_identities
            .iter()
            .all(RemoteUeUserIdentity::is_well_formed)
            && match &self.address {
                RemoteUeAddress::Ipv4 {
                    port,
                    udp_port_range,
                    tcp_port_range,
                    ..
                } => [udp_port_range, tcp_port_range]
                    .into_iter()
                    .flatten()
                    .all(|range| range.low <= *port && *port <= range.high),
                RemoteUeAddress::Unknown { .. } => false,
                _ => true,
            }
    }

    /// Encode the octets after the context length: a count and a length
    /// fit their octet.
    pub fn to_bytes(&self) -> core::result::Result<Vec<u8>, ValueError> {
        counted("user-identities", self.user_identities.len(), 0, 255)?;
        let mut octets = vec![self.user_identities.len() as u8];
        for (entry, identity) in self.user_identities.iter().enumerate() {
            let length = identity.octets.len();
            sized("user-identity", "octets", length, 1, 255).map_err(|error| error.at(entry))?;
            octets.push(length as u8);
            octets.extend_from_slice(&identity.octets);
        }
        match &self.address {
            RemoteUeAddress::NoIpInfo => octets.push(0),
            RemoteUeAddress::Ipv4 {
                address,
                port,
                udp_port_range,
                tcp_port_range,
            } => {
                octets.push(
                    0x01 | u8::from(udp_port_range.is_some()) << 4
                        | u8::from(tcp_port_range.is_some()) << 3,
                );
                octets.extend_from_slice(address);
                octets.extend_from_slice(&port.to_be_bytes());
                for range in [udp_port_range, tcp_port_range].into_iter().flatten() {
                    octets.extend_from_slice(&range.low.to_be_bytes());
                    octets.extend_from_slice(&range.high.to_be_bytes());
                }
            }
            RemoteUeAddress::Ipv6Prefix(prefix) => {
                octets.push(0x02);
                octets.extend_from_slice(prefix);
            }
            RemoteUeAddress::Unknown {
                address_type,
                octets: rest,
            } => {
                octets.push(address_type & 0x07);
                octets.extend_from_slice(rest);
            }
        }
        Ok(octets)
    }
}

/// Remote UE context list (TS 24.301 §9.9.4.20).
impl RemoteUeContextList {
    /// Split the declared remote UE contexts without changing their bytes.
    pub fn context_octets(&self) -> Option<Vec<&[u8]>> {
        let count = usize::from(*self.value.first()?);
        let mut remaining = &self.value[1..];
        let mut contexts = Vec::with_capacity(count);
        for _ in 0..count {
            let (&length, rest) = remaining.split_first()?;
            let context = rest.get(..usize::from(length))?;
            contexts.push(context);
            remaining = &rest[context.len()..];
        }
        Some(contexts)
    }

    /// Typed remote UE contexts; octets after the declared contexts
    /// are ignored.
    pub fn contexts(&self) -> Option<Vec<RemoteUeContext>> {
        self.context_octets()?
            .into_iter()
            .map(RemoteUeContext::from_bytes)
            .collect()
    }

    /// Build from typed contexts, at least one: each is one that
    /// `is_well_formed()` accepts, and its length fits an octet.
    pub fn from_contexts(
        contexts: &[RemoteUeContext],
    ) -> core::result::Result<Self, crate::common::ValueError> {
        use crate::common::{ValueError, counted, sized};
        counted("remote-ue-contexts", contexts.len(), 1, 255)?;
        let mut value = vec![contexts.len() as u8];
        for (entry, context) in contexts.iter().enumerate() {
            let entry = |error: ValueError| error.at(entry);
            if !context.is_well_formed() {
                let rule = "has identities and an address that a sender may code";
                return Err(entry(ValueError::combination("remote-ue-context", rule)));
            }
            let octets = context.to_bytes().map_err(entry)?;
            sized("remote-ue-context", "octets", octets.len(), 0, 255).map_err(entry)?;
            value.push(octets.len() as u8);
            value.extend_from_slice(&octets);
        }
        sized("remote-ue-context-list", "octets", value.len(), 0, 65535)?;
        Ok(Self::new(value))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "at least one context (the §9.9.4.20 minimum of 5 octets), the declared contexts fill the value exactly, and each re-encodes to the same octets";
    /// Sender check: at least one context (the §9.9.4.20 minimum of
    /// 5 octets), the declared contexts fill the value exactly, and
    /// each re-encodes to the same octets.
    pub fn is_well_formed(&self) -> bool {
        let (Some(octets), Some(contexts)) = (self.context_octets(), self.contexts()) else {
            return false;
        };
        let used: usize = octets.iter().map(|context| 1 + context.len()).sum();
        !octets.is_empty()
            && used + 1 == self.value.len()
            && octets.iter().zip(&contexts).all(|(octets, context)| {
                context.is_well_formed() && context.to_bytes().as_deref() == Ok(*octets)
            })
    }
}

oxirush_utils::named_values! {
    /// PKMF address type (TS 24.301 Table 9.9.4.21.1).
    pub enum PkmfAddressType "Table 9.9.4.21.1" bits 8 {
        1 Ipv4 "ipv4" tree "ipv4",
        2 Ipv6 "ipv6" tree "ipv6",
    }
}
crate::common::enums::values_readable!(PkmfAddressType);

impl PkmfAddress {
    /// Raw address type (octet 3, bits 3-1).
    pub fn address_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x07)
    }

    /// Typed address type; reserved codes return `None`.
    pub fn address_type(&self) -> Option<PkmfAddressType> {
        match self.address_type_raw()? {
            1 => Some(PkmfAddressType::Ipv4),
            2 => Some(PkmfAddressType::Ipv6),
            _ => None,
        }
    }

    /// Read the PKMF IPv4 or IPv6 address from TS 24.301 §9.9.4.21. Spare
    /// bits and octets after the address are ignored.
    pub fn address(&self) -> Option<core::net::IpAddr> {
        let address = self.value.get(1..)?;
        match self.address_type()? {
            PkmfAddressType::Other(_) => None,
            PkmfAddressType::Ipv4 => Some(core::net::IpAddr::V4(core::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(address.get(..4)?).ok()?,
            ))),
            PkmfAddressType::Ipv6 => Some(core::net::IpAddr::V6(core::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(address.get(..16)?).ok()?,
            ))),
        }
    }

    /// Build a PKMF address IE from an IP address.
    pub fn from_address(address: core::net::IpAddr) -> Self {
        let mut value = Vec::new();
        match address {
            core::net::IpAddr::V4(ipv4) => {
                value.push(1);
                value.extend_from_slice(&ipv4.octets());
            }
            core::net::IpAddr::V6(ipv6) => {
                value.push(2);
                value.extend_from_slice(&ipv6.octets());
            }
        }
        Self::new(value)
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "spare bits clear and exactly one address";
    /// Sender check: spare bits clear and exactly one address.
    pub fn is_well_formed(&self) -> bool {
        self.address()
            .is_some_and(|address| Self::from_address(address).value == self.value)
    }
}

// ── APN (TS 24.301 §9.9.4.1) ─────────────────────────────────────────────

crate::common::ts24008::access_point_name_ie!(AccessPointName, "access-point-name");
pub use crate::common::ts24008::EutraMode;
pub use crate::common::ts24008::{
    DaylightSavingAdjustment, EmergencyNumber, NetworkNameCodingScheme,
};
pub use crate::common::ts24301::ExtendedEmergencyNumber;
pub use crate::common::ts24301::{UePagingProbability, UeRequestTypeValue};
pub use crate::common::ts24501::RadioCapabilityIdDeletionRequest;

// ── NAS security algorithms (TS 24.301 §9.9.3.23) ─────────────────────────

pub(crate) use crate::common::ts24301::{CipheringAlgorithm, IntegrityAlgorithm};

crate::common::ts24301::nas_security_algorithms_ie!(SecurityAlgorithms, 0x07);

oxirush_utils::named_values! {
    /// EPS attach type from TS 24.301 table 9.9.3.11.1.
    pub enum AttachType "" bits 3 others as 1 {
        1 EpsAttach "eps attach" tree "eps-attach",
        2 CombinedEpsImsiAttach "combined eps imsi attach" tree "combined-eps-imsi-attach",
        3 EpsRlosAttach "eps rlos attach" tree "eps-rlos-attach",
        6 EpsEmergencyAttach "eps emergency attach" tree "eps-emergency-attach",
        7 DisasterRoamingAttach "disaster roaming attach" tree "disaster-roaming-attach",
    }
}
crate::common::enums::values_readable!(AttachType);

impl EpsAttachType {
    /// Build the raw IE from a typed attach type.
    pub fn from_attach_type(value: AttachType) -> Self {
        Self::new(u8::from(value))
    }

    /// Read the EPS attach type from the lower three bits.
    pub fn attach_type(&self) -> AttachType {
        AttachType::from_value(self.value & 0x07).effective()
    }

    /// Read only a defined attach type.
    pub fn attach_type_strict(&self) -> Option<AttachType> {
        AttachType::named(self.value & 0x07)
    }

    /// Raw attach type (bits 3-1).
    pub fn attach_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the attach type and clear the spare bit.
    pub fn set_attach_type(&mut self, value: AttachType) -> &mut Self {
        self.value = u8::from(value);
        self
    }
}

oxirush_utils::named_values! {
    /// Extended SERVICE REQUEST service type (TS 24.301 table 9.9.3.27.1).
    pub enum ServiceTypeValue "" bits 4 read [3 ..= 3 as 0, 4 ..= 4 as 0, 9 ..= 11 as 8] {
        0 MobileOriginatingCsFallbackOr1xCsFallback "mobile originating cs fallback or 1x cs fallback" tree "mobile-originating-cs-fallback-or-1x-cs-fallback",
        1 MobileTerminatingCsFallbackOr1xCsFallback "mobile terminating cs fallback or 1x cs fallback" tree "mobile-terminating-cs-fallback-or-1x-cs-fallback",
        2 MobileOriginatingCsFallbackEmergencyCallOr1xCsFallbackEmergencyCall "mobile originating cs fallback emergency call or 1x cs fallback emergency call" tree "mobile-originating-cs-fallback-emergency-call-or-1x-cs-fallback-emergency-call",
        8 PacketServicesViaS1 "packet services via s1" tree "packet-services-via-s1",
    }
}
crate::common::enums::values_readable!(ServiceTypeValue);

impl ServiceType {
    /// Build from a typed service type.
    pub fn from_service_type(value: ServiceTypeValue) -> Self {
        Self::new(u8::from(value))
    }

    /// Service type with the network receive fallbacks.
    ///
    /// The value as the IE has it: `effective()` is the value as a receiver
    /// reads it.
    pub fn service_type(&self) -> ServiceTypeValue {
        ServiceTypeValue::from_value(self.value & 0x0f)
    }

    /// Service type, only for a defined value.
    pub fn service_type_strict(&self) -> Option<ServiceTypeValue> {
        ServiceTypeValue::named(self.value & 0x0f)
    }

    /// Raw service type (bits 4-1).
    pub fn service_type_raw(&self) -> u8 {
        self.value & 0x0f
    }

    /// Set the service type.
    pub fn set_service_type(&mut self, value: ServiceTypeValue) -> &mut Self {
        self.value = u8::from(value);
        self
    }
}

oxirush_utils::named_values! {
    /// CONTROL PLANE SERVICE REQUEST service type (table 9.9.3.47.1).
    pub enum ControlPlaneServiceTypeValue "" bits 3 others as 0 {
        0 MobileOriginatingRequest "mobile originating request" tree "mobile-originating-request",
        1 MobileTerminatingRequest "mobile terminating request" tree "mobile-terminating-request",
    }
}
crate::common::enums::values_readable!(ControlPlaneServiceTypeValue);

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl ControlPlaneServiceType (value) "9.9.3.47" octets 1 {
        service_type "Control plane service type value": 0 1 3 as ControlPlaneServiceTypeValue,
        active "Active flag": 0 4 1,
    }
}
crate::common::field_table::table_ie!(ControlPlaneServiceType, octet, 1..=1, receives 1);

impl ControlPlaneServiceType {
    /// Build from a service type and the "active" flag.
    pub fn from_service_type(value: ControlPlaneServiceTypeValue, active: bool) -> Self {
        Self::new(u8::from(value) | ((active as u8) << 3))
    }
}

oxirush_utils::named_values! {
    /// EPS PDN type from TS 24.301 table 9.9.4.10.1.
    pub enum PdnTypeValue "" bits 3 read [4 ..= 4 as 2] {
        1 Ipv4 "ipv4" tree "ipv4",
        2 Ipv6 "ipv6" tree "ipv6",
        3 Ipv4v6 "ipv4v6" tree "ipv4v6",
        5 NonIp "non ip" tree "non-ip",
        6 Ethernet "ethernet" tree "ethernet",
    }
}
crate::common::enums::values_readable!(PdnTypeValue);

impl PdnType {
    /// Build the raw IE from a typed PDN type.
    pub fn from_pdn_type(value: PdnTypeValue) -> Self {
        Self::new(u8::from(value))
    }

    /// Read the PDN type from the lower three bits.
    ///
    /// The value as the IE has it: `effective()` is the value as a receiver
    /// reads it.
    pub fn pdn_type(&self) -> PdnTypeValue {
        PdnTypeValue::from_value(self.value & 0x07)
    }

    /// Read only a defined PDN type code.
    pub fn pdn_type_strict(&self) -> Option<PdnTypeValue> {
        PdnTypeValue::named(self.value & 0x07)
    }

    /// Raw PDN type (bits 3-1).
    pub fn pdn_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the PDN type and clear the spare bit.
    pub fn set_pdn_type(&mut self, value: PdnTypeValue) -> &mut Self {
        self.value = u8::from(value);
        self
    }
}

// ── Attach and tracking area update values ─────────────────────────────────

oxirush_utils::named_values! {
    /// EPS attach result from TS 24.301 table 9.9.3.10.1.
    pub enum AttachResult "" bits 3 {
        1 EpsOnly "eps only" tree "eps-only",
        2 CombinedEpsImsiAttach "combined eps imsi attach" tree "combined-eps-imsi-attach",
    }
}
crate::common::enums::values_readable!(AttachResult);

impl EpsAttachResult {
    /// Build from a typed attach result.
    pub fn from_attach_result(value: AttachResult) -> Self {
        Self::new(u8::from(value))
    }

    /// Typed attach result; reserved values return `None`.
    pub fn attach_result(&self) -> Option<AttachResult> {
        AttachResult::named(self.value & 0x07)
    }

    /// Raw attach result (bits 3-1).
    pub fn attach_result_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the attach result and clear the spare bit.
    pub fn set_attach_result(&mut self, value: AttachResult) -> &mut Self {
        self.value = u8::from(value);
        self
    }
}

oxirush_utils::named_values! {
    /// EPS update type from TS 24.301 table 9.9.3.14.1.
    pub enum UpdateType "" bits 3 read [4 ..= 4 as 0, 5 ..= 5 as 0] {
        0 TaUpdating "ta updating" tree "ta-updating",
        1 CombinedTaLaUpdating "combined ta la updating" tree "combined-ta-la-updating",
        2 CombinedTaLaUpdatingWithImsiAttach "combined ta la updating with imsi attach" tree "combined-ta-la-updating-with-imsi-attach",
        3 PeriodicUpdating "periodic updating" tree "periodic-updating",
        6 DisasterRoamingUpdate "disaster roaming update" tree "disaster-roaming-update",
    }
}
crate::common::enums::values_readable!(UpdateType);

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl EpsUpdateType (value) "9.9.3.14" octets 1 {
        update_type "EPS update type value": 0 1 3 as UpdateType,
        active "Active flag": 0 4 1,
    }
}
crate::common::field_table::table_ie!(EpsUpdateType, octet, 1..=1, receives 1);

impl EpsUpdateType {
    /// Build from a typed update type with the "active" flag clear.
    pub fn from_update_type(value: UpdateType) -> Self {
        Self::new(u8::from(value))
    }
}

oxirush_utils::named_values! {
    /// EPS update result from TS 24.301 table 9.9.3.13.1.
    pub enum UpdateResult "" bits 3 {
        0 TaUpdated "ta updated" tree "ta-updated",
        1 CombinedTaLaUpdated "combined ta la updated" tree "combined-ta-la-updated",
        4 TaUpdatedAndIsrActivated "ta updated and isr activated" tree "ta-updated-and-isr-activated",
        5 CombinedTaLaUpdatedAndIsrActivated "combined ta la updated and isr activated" tree "combined-ta-la-updated-and-isr-activated",
    }
}
crate::common::enums::values_readable!(UpdateResult);

impl EpsUpdateResult {
    /// Build from a typed update result.
    pub fn from_update_result(value: UpdateResult) -> Self {
        Self::new(u8::from(value))
    }

    /// Typed update result; reserved values return `None`.
    pub fn update_result(&self) -> Option<UpdateResult> {
        UpdateResult::named(self.value & 0x07)
    }

    /// Raw update result (bits 3-1).
    pub fn update_result_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the update result and clear the spare bit.
    pub fn set_update_result(&mut self, value: UpdateResult) -> &mut Self {
        self.value = u8::from(value);
        self
    }
}

// ── Identity and security context ──────────────────────────────────────────

// The identities of an EPS mobile identity and of the mobile identity of
// TS 24.008 are those of oxirush-utils, which the OxiRush crates share, in
// `crate::identity`.
pub(crate) use oxirush_utils::identity::{
    GutiEps, IdentityType, Imei, Imeisv, Imsi, MobileIdentityTypeEps,
};

/// The IMSI of the identity digits `value` of the type of identity `kind`,
/// in its first eight octets at most: a receiver reads the octets of the
/// identity, and not those after them. Its end mark is 1111: the odd/even
/// indication alone says how many digits an IMSI has.
fn receiver_imsi(value: &[u8], kind: u8) -> Option<Imsi> {
    if !crate::common::of_type(value, kind) {
        return None;
    }
    crate::common::receiver_identity(value, 8, |octets| Imsi::from_nas_octets(kind, octets).ok())
}

impl MobileIdentity {
    /// Build an IDENTITY RESPONSE mobile identity containing an IMSI.
    pub fn from_imsi(imsi: &str) -> core::result::Result<Self, ValueError> {
        Ok(Self::new(Imsi::new(imsi)?.to_nas_octets(1)))
    }

    /// Build an IDENTITY RESPONSE mobile identity containing an IMEI.
    pub fn from_imei(imei: &str) -> core::result::Result<Self, ValueError> {
        Ok(Self::new(Imei::new(imei)?.to_nas_octets(2)))
    }

    /// Build a transmitted IMEI from its 14 TAC and serial-number digits.
    /// The fifteenth wire digit is the zero spare required by TS 23.003 §6.2.1.
    pub fn from_imei_tac_snr(tac_snr: &str) -> core::result::Result<Self, ValueError> {
        Ok(Self::new(Imei::with_spare_digit(tac_snr)?.to_nas_octets(2)))
    }

    /// Build an IDENTITY RESPONSE mobile identity containing an IMEISV.
    pub fn from_imeisv(imeisv: &str) -> core::result::Result<Self, ValueError> {
        Ok(Self::new(Imeisv::new(imeisv)?.to_nas_octets(3)))
    }

    /// Build a TMSI mobile identity; its first value octet is 0xF4.
    pub fn from_tmsi(tmsi: u32) -> Self {
        let mut value = vec![0xf4];
        value.extend_from_slice(&tmsi.to_be_bytes());
        Self::new(value)
    }

    /// Build the "No Identity" value an EMM IDENTITY RESPONSE uses: three
    /// zero octets (TS 24.008 Table 10.5.4).
    pub fn from_no_identity() -> Self {
        Self::new(vec![0; 3])
    }

    /// Raw type of identity (bits 3-1 of the first octet).
    pub fn identity_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x07)
    }

    /// Decode the IMSI supplied in an IDENTITY RESPONSE.
    pub fn as_imsi(&self) -> Option<Imsi> {
        receiver_imsi(&self.value, 1)
    }

    /// Decode the IMEI supplied in an IDENTITY RESPONSE: 15 digits, of the
    /// first eight octets.
    pub fn as_imei(&self) -> Option<Imei> {
        (crate::common::of_type(&self.value, 2)).then_some(())?;
        Imei::from_nas_octets(2, self.value.get(..8)?).ok()
    }

    /// Decode the IMEISV supplied in an IDENTITY RESPONSE: 16 digits, of the
    /// first nine octets.
    ///
    /// The half octet after the 16 digits is no digit, and is read whatever
    /// it holds: a sender fills it with 1111, which [`Self::is_well_formed`]
    /// and `validate()` hold it to.
    pub fn as_imeisv(&self) -> Option<Imeisv> {
        (crate::common::of_type(&self.value, 3)).then_some(())?;
        let octets = self.value.get(..9)?;
        let (imeisv, _) = Imeisv::from_nas_octets_tolerant(3, octets).ok()?;
        Some(imeisv)
    }

    /// Decode a four-octet TMSI from an IDENTITY RESPONSE. Only the type
    /// bits are checked, and octets after the TMSI are ignored.
    pub fn as_tmsi(&self) -> Option<u32> {
        if self.value.first().copied()? & 0x07 != 0x04 {
            return None;
        }
        Some(u32::from_be_bytes(self.value.get(1..5)?.try_into().ok()?))
    }

    /// Whether the UE reported no available identity (type of identity 000).
    pub fn is_no_identity(&self) -> bool {
        self.identity_type_raw() == Some(0)
    }

    /// Sender check: an IMSI, an IMEI with a zero spare digit (TS 23.003
    /// §6.2.1), an IMEISV, a 0xF4-coded TMSI of four octets, or the
    /// three-octet "No Identity" value.
    pub fn is_well_formed(&self) -> bool {
        let of_type = |kind| crate::common::of_type(&self.value, kind);
        (of_type(1) && Imsi::from_nas_octets(1, &self.value).is_ok())
            || (of_type(2)
                && Imei::from_nas_octets(2, &self.value)
                    .is_ok_and(|imei| imei.as_str().ends_with('0')))
            || (of_type(3) && Imeisv::from_nas_octets(3, &self.value).is_ok())
            || matches!(self.value.as_slice(), [0xf4, _, _, _, _] | [0, 0, 0])
    }
}

impl EpsMobileIdentity {
    /// Build an EPS mobile identity containing an IMSI.
    pub fn from_imsi(imsi: &str) -> core::result::Result<Self, ValueError> {
        let kind = u8::from(MobileIdentityTypeEps::Imsi);
        Ok(Self::new(Imsi::new(imsi)?.to_nas_octets(kind)))
    }

    /// Build an EPS mobile identity containing an IMEI of 15 digits.
    pub fn from_imei(imei: &str) -> core::result::Result<Self, ValueError> {
        let kind = u8::from(MobileIdentityTypeEps::Imei);
        Ok(Self::new(Imei::new(imei)?.to_nas_octets(kind)))
    }

    /// Build a transmitted IMEI from its 14 TAC and serial-number digits.
    /// The fifteenth wire digit is the zero spare required by TS 23.003 §6.2.1.
    pub fn from_imei_tac_snr(tac_snr: &str) -> core::result::Result<Self, ValueError> {
        let kind = u8::from(MobileIdentityTypeEps::Imei);
        Ok(Self::new(
            Imei::with_spare_digit(tac_snr)?.to_nas_octets(kind),
        ))
    }

    /// Build an EPS mobile identity containing a GUTI.
    pub fn from_guti(guti: GutiEps) -> Self {
        Self::new(guti.to_nas_octets())
    }

    /// Decode an IMSI identity.
    pub fn as_imsi(&self) -> Option<Imsi> {
        receiver_imsi(&self.value, u8::from(MobileIdentityTypeEps::Imsi))
    }

    /// Decode an IMEI identity: 15 digits, of the first eight octets.
    pub fn as_imei(&self) -> Option<Imei> {
        let kind = u8::from(MobileIdentityTypeEps::Imei);
        (crate::common::of_type(&self.value, kind)).then_some(())?;
        Imei::from_nas_octets(kind, self.value.get(..8)?).ok()
    }

    /// Decode a GUTI identity, as a receiver reads it: of the first octet,
    /// the type of identity alone, and not its bits 8 to 4, which are the
    /// filler 1111 and the odd/even indication of an identity without
    /// digits; and not the octets after the eleventh (TS 24.007 §11.4.2).
    /// [`Self::is_well_formed`] holds a sender to `f6`.
    pub fn as_guti(&self) -> Option<GutiEps> {
        let mut octets: [u8; 11] = self.value.get(..11)?.try_into().ok()?;
        (octets[0] & 0x07 == 0x06).then_some(())?;
        octets[0] = 0xf6;
        GutiEps::from_nas_octets(&octets).ok()
    }

    /// PLMN identity of a GUTI.
    pub fn plmn(&self) -> Option<Plmn> {
        self.as_guti().map(|guti| guti.plmn())
    }

    /// Why a receiver does not read the identity as one of its type, in the
    /// words of oxirush-utils: "`guti` has 10 octets, and must have 11".
    pub(crate) fn receiver_fault(&self) -> Option<String> {
        let value = &self.value[..];
        let first = *value.first()?;
        let first_of = |length: usize| value.get(..length).unwrap_or(value);
        let fault = match MobileIdentityTypeEps::of(first).ok()? {
            MobileIdentityTypeEps::Imsi => Imsi::from_nas_octets_tolerant(first & 0x0f, value)
                .err()?
                .to_string(),
            MobileIdentityTypeEps::Imei => Imei::from_nas_octets(first & 0x0f, first_of(8))
                .err()?
                .to_string(),
            MobileIdentityTypeEps::Guti => {
                let mut octets = first_of(11).to_vec();
                octets[0] = 0xf6;
                GutiEps::from_nas_octets(&octets).err()?.to_string()
            }
            _ => return None,
        };
        Some(fault)
    }

    /// Typed type of identity; reserved values return `None`.
    pub fn identity_type(&self) -> Option<MobileIdentityTypeEps> {
        MobileIdentityTypeEps::of(*self.value.first()?).ok()
    }

    /// Raw type of identity (bits 3-1 of the first octet).
    pub fn identity_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x07)
    }

    /// Odd/even indication (bit 4 of the first octet).
    pub fn is_odd_digits(&self) -> Option<bool> {
        self.value.first().map(|value| value & 0x08 != 0)
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "an IMSI, an IMEI with a zero spare digit (TS 23.003 §6.2.1), or an eleven-octet GUTI whose first octet is 0xf6";
    /// Sender check: an IMSI, an IMEI with a zero spare digit (TS 23.003
    /// §6.2.1), or an eleven-octet GUTI whose first octet is 0xF6.
    pub fn is_well_formed(&self) -> bool {
        let (imsi, imei) = (
            u8::from(MobileIdentityTypeEps::Imsi),
            u8::from(MobileIdentityTypeEps::Imei),
        );
        let of_type = |kind| crate::common::of_type(&self.value, kind);
        (of_type(imsi) && Imsi::from_nas_octets(imsi, &self.value).is_ok())
            || (of_type(imei)
                && Imei::from_nas_octets(imei, &self.value)
                    .is_ok_and(|imei| imei.as_str().ends_with('0')))
            || GutiEps::from_nas_octets(&self.value).is_ok()
    }
}

pub use crate::common::ts24301::KeySetIdentifierValue;
/// Key set identifier value that means no key is available (§9.9.3.21).
pub use crate::common::ts24301::NAS_KSI_NO_KEY_AVAILABLE;

crate::common::ts24301::key_set_identifier_ie!(KeySetIdentifier, builders);

impl Default for KeySetIdentifier {
    /// No key available, native context.
    fn default() -> Self {
        Self::new(NAS_KSI_NO_KEY_AVAILABLE)
    }
}

// ── Detach type ──────────────────────────────────────────────────────────────

oxirush_utils::named_values! {
    /// UE-originated detach kind from TS 24.301 table 9.9.3.7.1.
    pub enum UeDetachKind "" bits 3 others as 3 {
        1 EpsDetach "eps detach" tree "eps-detach",
        2 ImsiDetach "imsi detach" tree "imsi-detach",
        3 CombinedEpsImsiDetach "combined eps imsi detach" tree "combined-eps-imsi-detach",
    }
}
crate::common::enums::values_readable!(UeDetachKind);

oxirush_utils::named_values! {
    /// Network-originated detach kind from TS 24.301 table 9.9.3.7.1.
    pub enum NetworkDetachKind "" bits 3 others as 2 {
        1 ReattachRequired "reattach required" tree "reattach-required",
        2 ReattachNotRequired "reattach not required" tree "reattach-not-required",
        3 ImsiDetach "imsi detach" tree "imsi-detach",
    }
}
crate::common::enums::values_readable!(NetworkDetachKind);

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl DetachType (value) "9.9.3.7" octets 1 {
        ue_detach_kind "Type of detach": 0 1 3 as UeDetachKind,
        network_detach_kind "Type of detach": 0 1 3 as NetworkDetachKind,
        switch_off "Switch off": 0 4 1,
    }
}
crate::common::field_table::table_ie!(DetachType, octet, 1..=1, receives 1);

impl DetachType {
    /// Build a UE-originating detach type.
    pub fn from_ue_detach_kind(value: UeDetachKind, switch_off: bool) -> Self {
        Self::new(u8::from(value) | ((switch_off as u8) << 3))
    }

    /// Build a network-originating detach type; bit 4 is spare.
    pub fn from_network_detach_kind(value: NetworkDetachKind) -> Self {
        Self::new(u8::from(value))
    }
}

// The tracking area identity (TS 24.301 §9.9.3.32) is that of oxirush-utils: a
// PLMN and a TAC of 16 bits.
pub(crate) use oxirush_utils::identity::TaiEps;

/// The TAI of five octets.
fn tai_of(value: &[u8]) -> Option<TaiEps> {
    TaiEps::from_nas_octets(<[u8; 5]>::try_from(value).ok()?).ok()
}

impl TrackingAreaIdentity {
    /// Build from a typed TAI.
    pub fn from_tai(tai: TaiEps) -> Self {
        Self::new(tai.to_nas_octets())
    }

    /// Typed TAI; `None` if the value is not a TAI.
    pub fn tai(&self) -> Option<TaiEps> {
        tai_of(&self.value)
    }
}

pub use crate::common::ts24301::TaiListType;
crate::common::ts24301::tai_list_ie!(TrackingAreaIdentityList, TaiEps, u16, 2);

/// PDN address variants from TS 24.301 table 9.9.4.9.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdnAddressValue {
    /// IPv4 address; 0.0.0.0 when the address is obtained by DHCPv4.
    Ipv4([u8; 4]),
    /// IPv6 interface identifier.
    Ipv6InterfaceId([u8; 8]),
    /// IPv6 interface identifier and IPv4 address.
    Ipv4v6 {
        /// IPv6 interface identifier.
        ipv6_interface_id: [u8; 8],
        /// IPv4 address.
        ipv4: [u8; 4],
    },
    /// Non-IP; the four address octets are spare.
    NonIp,
    /// Ethernet; the four address octets are spare.
    Ethernet,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(enum PdnAddressValue { Ipv4([u8; 4]), Ipv6InterfaceId([u8; 8]), Ipv4v6 { ipv6_interface_id, ipv4 }, NonIp, Ethernet });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(PdnAddressValue);

impl PdnAddressValue {
    /// Parse a received value: spare bits, spare address octets, and
    /// octets beyond the address are ignored (TS 24.007 §11.1.4, §11.4.2).
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let (&kind, data) = value.split_first()?;
        let octets = |length: usize| data.get(..length);
        match kind & 0x07 {
            1 => Some(Self::Ipv4(octets(4)?.try_into().ok()?)),
            2 => Some(Self::Ipv6InterfaceId(octets(8)?.try_into().ok()?)),
            3 => Some(Self::Ipv4v6 {
                ipv6_interface_id: octets(8)?.try_into().ok()?,
                ipv4: data.get(8..12)?.try_into().ok()?,
            }),
            5 => octets(4).map(|_| Self::NonIp),
            6 => octets(4).map(|_| Self::Ethernet),
            _ => None,
        }
    }

    /// Parse only an exactly sized value with spare bits and octets clear.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
        let (&kind, data) = value.split_first()?;
        if kind & 0xf8 != 0 {
            return None;
        }
        match (kind, data) {
            (1, [a, b, c, d]) => Some(Self::Ipv4([*a, *b, *c, *d])),
            (2, [a, b, c, d, e, f, g, h]) => {
                Some(Self::Ipv6InterfaceId([*a, *b, *c, *d, *e, *f, *g, *h]))
            }
            (3, [a, b, c, d, e, f, g, h, i, j, k, l]) => Some(Self::Ipv4v6 {
                ipv6_interface_id: [*a, *b, *c, *d, *e, *f, *g, *h],
                ipv4: [*i, *j, *k, *l],
            }),
            (5, [0, 0, 0, 0]) => Some(Self::NonIp),
            (6, [0, 0, 0, 0]) => Some(Self::Ethernet),
            _ => None,
        }
    }

    /// Encode the PDN type octet and address information.
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::Ipv4(addr) => [vec![1], addr.to_vec()].concat(),
            Self::Ipv6InterfaceId(id) => [vec![2], id.to_vec()].concat(),
            Self::Ipv4v6 {
                ipv6_interface_id,
                ipv4,
            } => [vec![3], ipv6_interface_id.to_vec(), ipv4.to_vec()].concat(),
            Self::NonIp => vec![5, 0, 0, 0, 0],
            Self::Ethernet => vec![6, 0, 0, 0, 0],
        }
    }
}

impl PdnAddress {
    /// Build from a typed address.
    pub fn from_pdn_address(address: PdnAddressValue) -> Self {
        Self::new(address.to_bytes())
    }

    /// An IPv4 PDN address, as `PduAddress::from_ipv4` of 5GS.
    pub fn from_ipv4(ipv4: [u8; 4]) -> Self {
        Self::from_pdn_address(PdnAddressValue::Ipv4(ipv4))
    }

    /// An IPv6 PDN address of an interface identifier, as
    /// `PduAddress::from_ipv6_iid` of 5GS.
    pub fn from_ipv6_iid(iid: [u8; 8]) -> Self {
        Self::from_pdn_address(PdnAddressValue::Ipv6InterfaceId(iid))
    }

    /// An IPv4v6 PDN address, as `PduAddress::from_ipv4v6` of 5GS.
    pub fn from_ipv4v6(iid: [u8; 8], ipv4: [u8; 4]) -> Self {
        Self::from_pdn_address(PdnAddressValue::Ipv4v6 {
            ipv6_interface_id: iid,
            ipv4,
        })
    }

    /// Typed address under the receiver rules of [`PdnAddressValue::from_bytes`].
    pub fn pdn_address(&self) -> Option<PdnAddressValue> {
        PdnAddressValue::from_bytes(&self.value)
    }

    /// Raw PDN type (octet 3, bits 3-1).
    pub fn pdn_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x07)
    }

    /// IPv4 address of an IPv4 or IPv4v6 PDN address.
    pub fn ipv4(&self) -> Option<[u8; 4]> {
        match self.pdn_address()? {
            PdnAddressValue::Ipv4(ipv4) | PdnAddressValue::Ipv4v6 { ipv4, .. } => Some(ipv4),
            _ => None,
        }
    }

    /// IPv6 interface identifier of an IPv6 or IPv4v6 PDN address.
    pub fn ipv6_interface_id(&self) -> Option<[u8; 8]> {
        match self.pdn_address()? {
            PdnAddressValue::Ipv6InterfaceId(id)
            | PdnAddressValue::Ipv4v6 {
                ipv6_interface_id: id,
                ..
            } => Some(id),
            _ => None,
        }
    }

    /// Whether the IPv4 address is 0.0.0.0, meaning it is obtained by DHCPv4.
    pub fn uses_dhcpv4(&self) -> bool {
        self.ipv4() == Some([0; 4])
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "an exactly sized value with spare bits and octets clear";
    /// Sender check: an exactly sized value with spare bits and octets clear.
    pub fn is_well_formed(&self) -> bool {
        PdnAddressValue::from_bytes_strict(&self.value).is_some()
    }
}

/// APN aggregate maximum bit rates (§9.9.4.2), in coded octets.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApnAmbr {
    /// APN-AMBR for downlink (octet 3).
    pub downlink: u8,
    /// APN-AMBR for uplink (octet 4).
    pub uplink: u8,
    /// Downlink and uplink extended octets 5 and 6.
    pub extension: Option<[u8; 2]>,
    /// Downlink and uplink extended-2 octets 7 and 8.
    pub extension2: Option<[u8; 2]>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct ApnAmbr { downlink, uplink, extension, extension2 });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(ApnAmbr);

impl ApnAmbr {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(
        downlink: u8,
        uplink: u8,
        extension: Option<[u8; 2]>,
        extension2: Option<[u8; 2]>,
    ) -> Self {
        Self {
            downlink,
            uplink,
            extension,
            extension2,
        }
    }
}

/// Decoded APN-AMBR bit rates in kbps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApnAmbrValue {
    /// Downlink APN-AMBR in kbps.
    pub dl_kbps: u64,
    /// Uplink APN-AMBR in kbps.
    pub ul_kbps: u64,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct ApnAmbrValue { dl_kbps, ul_kbps });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(ApnAmbrValue);

fn apn_ambr_kbps(base: u8, extended: Option<u8>, extended2: Option<u8>) -> Option<u64> {
    use crate::common::ts24301::{eps_bit_rate_kbps, eps_extended_bit_rate_kbps};
    let low = match extended.and_then(eps_extended_bit_rate_kbps) {
        Some(kbps) => kbps,
        None => eps_bit_rate_kbps(base)?,
    };
    // Extended-2 value 11111111 is interpreted as 00000000.
    Some(match extended2 {
        Some(high @ 1..=0xfe) => u64::from(high) * 256_000 + low,
        _ => low,
    })
}

/// Octets 3, 5, and 7 of one APN-AMBR direction. Above 8640 kbps octet 3
/// is 11111110, so an extended-2 rate adds 8640 kbps (octet 5 unused) or an
/// octet 5 rate to its multiple of 256 Mbps (Table 9.9.4.2.1).
fn apn_ambr_octets(kbps: u64) -> Option<(u8, u8, u8)> {
    use crate::common::ts24301::{eps_bit_rate_octets, eps_extended_bit_rate_octet};
    if let Some((base, extended)) = eps_bit_rate_octets(kbps) {
        return Some((base, extended, 0));
    }
    (1..=0xfe_u8).find_map(|high| {
        let low = kbps.checked_sub(u64::from(high) * 256_000)?;
        let extended = if low == 8_640 {
            0
        } else {
            eps_extended_bit_rate_octet(low)?
        };
        Some((0xfe, extended, high))
    })
}

impl ApnAmbr {
    /// Parse the coded octets as a receiver: pairs beyond the defined three
    /// and an unpaired trailing octet are ignored; a reserved 0 base octet
    /// makes the value invalid unless the extended octet replaces it.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let [downlink, uplink] = *value.get(..2)? else {
            return None;
        };
        let pair =
            |start: usize| -> Option<[u8; 2]> { value.get(start..start + 2)?.try_into().ok() };
        let extension = pair(2);
        let reserved =
            |base: u8, index: usize| base == 0 && extension.is_none_or(|octets| octets[index] == 0);
        if reserved(downlink, 0) || reserved(uplink, 1) {
            return None;
        }
        Some(Self {
            downlink,
            uplink,
            extension,
            extension2: extension.and(pair(4)),
        })
    }

    /// Parse the coded octets as a sender must encode them: 2, 4, or 6 octets.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
        matches!(value.len(), 2 | 4 | 6).then(|| Self::from_bytes(value))?
    }

    /// Encode the coded octets.
    pub fn to_bytes(self) -> core::result::Result<Vec<u8>, ValueError> {
        within("downlink", self.downlink, 1, u8::MAX)?;
        within("uplink", self.uplink, 1, u8::MAX)?;
        if self.extension2.is_some() && self.extension.is_none() {
            return Err(ValueError::combination(
                "extension2",
                "is written with `extension`",
            ));
        }
        let mut value = vec![self.downlink, self.uplink];
        if let Some(extension) = self.extension {
            value.extend_from_slice(&extension);
        }
        if let Some(extension2) = self.extension2 {
            value.extend_from_slice(&extension2);
        }
        Ok(value)
    }

    /// Downlink APN-AMBR in kbps (Table 9.9.4.2.1).
    pub fn downlink_kbps(self) -> Option<u64> {
        apn_ambr_kbps(
            self.downlink,
            self.extension.map(|octets| octets[0]),
            self.extension2.map(|octets| octets[0]),
        )
    }

    /// Uplink APN-AMBR in kbps (Table 9.9.4.2.1).
    pub fn uplink_kbps(self) -> Option<u64> {
        apn_ambr_kbps(
            self.uplink,
            self.extension.map(|octets| octets[1]),
            self.extension2.map(|octets| octets[1]),
        )
    }

    /// Shortest exact encoding of rates up to 65280 Mbps.
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> core::result::Result<Self, ValueError> {
        let exact = "a rate that the IE codes exactly, up to 65280 Mbps";
        let octets =
            |member, kbps| apn_ambr_octets(kbps).ok_or(ValueError::value(member, kbps, exact));
        let (dl, dl_extended, dl_extended2) = octets("dl-kbps", dl_kbps)?;
        let (ul, ul_extended, ul_extended2) = octets("ul-kbps", ul_kbps)?;
        let extended2 = dl_extended2 != 0 || ul_extended2 != 0;
        let extended = extended2 || dl_extended != 0 || ul_extended != 0;
        Ok(Self {
            downlink: dl,
            uplink: ul,
            extension: extended.then_some([dl_extended, ul_extended]),
            extension2: extended2.then_some([dl_extended2, ul_extended2]),
        })
    }
}

impl ApnAggregateMaximumBitRate {
    /// Build from coded octets.
    pub fn from_ambr(ambr: ApnAmbr) -> core::result::Result<Self, ValueError> {
        Ok(Self::new(ambr.to_bytes()?))
    }

    /// Coded octets as a receiver reads them.
    pub fn ambr(&self) -> Option<ApnAmbr> {
        ApnAmbr::from_bytes(&self.value)
    }

    /// Downlink and uplink rates in kbps.
    pub fn parse(&self) -> Option<ApnAmbrValue> {
        let ambr = self.ambr()?;
        Some(ApnAmbrValue {
            dl_kbps: ambr.downlink_kbps()?,
            ul_kbps: ambr.uplink_kbps()?,
        })
    }

    /// Downlink rate in kbps.
    pub fn downlink_kbps(&self) -> Option<u64> {
        self.ambr()?.downlink_kbps()
    }

    /// Uplink rate in kbps.
    pub fn uplink_kbps(&self) -> Option<u64> {
        self.ambr()?.uplink_kbps()
    }

    /// Shortest exact encoding of rates up to 65280 Mbps.
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> core::result::Result<Self, ValueError> {
        Self::from_ambr(ApnAmbr::from_kbps(dl_kbps, ul_kbps)?)
    }

    /// Rates combined with the extended APN-AMBR IE: an extended rate
    /// replaces this IE's rate only when it exceeds 65280 Mbps (§9.9.4.29).
    pub fn effective_kbps(
        &self,
        extended: Option<&ExtendedApnAggregateMaximumBitRate>,
    ) -> Option<ApnAmbrValue> {
        let mut value = self.parse()?;
        if let Some(extended) = extended.and_then(ExtendedApnAggregateMaximumBitRate::ambr) {
            let limit = 65_280_000;
            if let Some(dl) = extended.downlink_kbps().filter(|&kbps| kbps > limit) {
                value.dl_kbps = dl;
            }
            if let Some(ul) = extended.uplink_kbps().filter(|&kbps| kbps > limit) {
                value.ul_kbps = ul;
            }
        }
        Some(value)
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "downlink and uplink rates that are not zero, with extensions within their ranges and only after a rate of 0xfe (TS 24.301 §9.9.4.2)";
    /// Sender check (§9.9.4.2): 2, 4, or 6 octets; octet 3 or 4 is 11111110
    /// when its extended or extended-2 octet is used, and those octets hold
    /// defined values.
    pub fn is_well_formed(&self) -> bool {
        let Some(ambr) = ApnAmbr::from_bytes_strict(&self.value) else {
            return false;
        };
        let [extension, extension2] =
            [ambr.extension, ambr.extension2].map(Option::unwrap_or_default);
        [ambr.downlink, ambr.uplink]
            .into_iter()
            .enumerate()
            .all(|(index, base)| {
                base != 0
                    && extension[index] <= 0xfa
                    && extension2[index] <= 0xfe
                    && (extension[index] == 0 && extension2[index] == 0 || base == 0xfe)
            })
    }
}

/// Extended APN aggregate maximum bit rate (§9.9.4.29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedApnAmbr {
    /// Unit of the downlink value (octet 3).
    pub dl_unit: u8,
    /// Downlink value (octets 4-5).
    pub dl_value: u16,
    /// Unit of the uplink value (octet 6).
    pub ul_unit: u8,
    /// Uplink value (octets 7-8).
    pub ul_value: u16,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct ExtendedApnAmbr { dl_unit, dl_value, ul_unit, ul_value });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(ExtendedApnAmbr);

impl ExtendedApnAmbr {
    /// Parse the first six value octets; extra octets are ignored.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let value = value.get(..6)?;
        Some(Self {
            dl_unit: value[0],
            dl_value: u16::from_be_bytes([value[1], value[2]]),
            ul_unit: value[3],
            ul_value: u16::from_be_bytes([value[4], value[5]]),
        })
    }

    /// Encode the six value octets.
    pub fn to_bytes(self) -> [u8; 6] {
        let [dl_high, dl_low] = self.dl_value.to_be_bytes();
        let [ul_high, ul_low] = self.ul_value.to_be_bytes();
        [self.dl_unit, dl_high, dl_low, self.ul_unit, ul_high, ul_low]
    }

    /// Downlink rate in kbps; unused units 0 to 2 are read as 4 Mbps.
    pub fn downlink_kbps(self) -> Option<u64> {
        u64::from(self.dl_value).checked_mul(crate::common::ts24301::extended_apn_ambr_unit_kbps(
            self.dl_unit,
        ))
    }

    /// Uplink rate in kbps; unused units 0 to 2 are read as 4 Mbps.
    pub fn uplink_kbps(self) -> Option<u64> {
        u64::from(self.ul_value).checked_mul(crate::common::ts24301::extended_apn_ambr_unit_kbps(
            self.ul_unit,
        ))
    }

    /// Smallest exact encoding using units 4 Mbps (3) to 256 Pbps (0x15).
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> core::result::Result<Self, ValueError> {
        use crate::common::ts24301::{eps_extended_unit_value, extended_apn_ambr_unit_kbps};
        let exact = "up to 65535 times a unit from 4 Mbps to 256 Pbps";
        let coded = |member, kbps| {
            eps_extended_unit_value(kbps, 3..=0x15, extended_apn_ambr_unit_kbps)
                .ok_or(ValueError::value(member, kbps, exact))
        };
        let (dl_unit, dl_value) = coded("dl-kbps", dl_kbps)?;
        let (ul_unit, ul_value) = coded("ul-kbps", ul_kbps)?;
        Ok(Self {
            dl_unit,
            dl_value,
            ul_unit,
            ul_value,
        })
    }
}

impl ExtendedApnAggregateMaximumBitRate {
    /// Typed value.
    pub fn ambr(&self) -> Option<ExtendedApnAmbr> {
        ExtendedApnAmbr::from_bytes(&self.value)
    }

    /// Build from a typed value.
    pub fn from_ambr(ambr: ExtendedApnAmbr) -> Self {
        Self::new(ambr.to_bytes())
    }

    /// Downlink rate in kbps.
    pub fn downlink_kbps(&self) -> Option<u64> {
        self.ambr()?.downlink_kbps()
    }

    /// Uplink rate in kbps.
    pub fn uplink_kbps(&self) -> Option<u64> {
        self.ambr()?.uplink_kbps()
    }

    /// Smallest exact encoding of both rates.
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> core::result::Result<Self, ValueError> {
        Ok(Self::from_ambr(ExtendedApnAmbr::from_kbps(
            dl_kbps, ul_kbps,
        )?))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "six octets using defined units (3 or above)";
    /// Sender check: six octets using defined units (3 or above).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.ambr(), Some(ambr) if self.value.len() == 6 && ambr.dl_unit >= 3 && ambr.ul_unit >= 3)
    }
}

/// An EPS QoS bit rate (Table 9.9.4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EpsBitRate {
    /// A bit rate in kbps.
    Kbps(u64),
    /// Base octet 0: the subscribed rate from the UE, reserved from the network.
    SubscribedOrReserved,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum EpsBitRate {
        Kbps(u64),
        SubscribedOrReserved,
    }
);
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(EpsBitRate);

/// EPS QoS coded octets, with optional four-octet bit-rate groups (§9.9.4.3).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EpsQos {
    /// QoS class identifier (octet 3).
    pub qci: u8,
    /// UL-MBR, DL-MBR, UL-GBR, DL-GBR in wire order.
    pub bit_rates: Option<[u8; 4]>,
    /// Extended bit rates in the same order.
    pub extension: Option<[u8; 4]>,
    /// Extended-2 bit rates in the same order.
    pub extension2: Option<[u8; 4]>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct EpsQos { qci, bit_rates, extension, extension2 });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(EpsQos);

impl EpsQos {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(
        qci: u8,
        bit_rates: Option<[u8; 4]>,
        extension: Option<[u8; 4]>,
        extension2: Option<[u8; 4]>,
    ) -> Self {
        Self {
            qci,
            bit_rates,
            extension,
            extension2,
        }
    }
}

impl EpsQos {
    /// Whether the QCI is assigned or operator-specific for a network-to-UE IE.
    ///
    /// TS 24.301 §9.9.4.3 reserves the gaps between the assigned values.
    pub fn qci_is_network_valid(&self) -> bool {
        matches!(self.qci, 1..=10 | 65..=67 | 69..=76 | 79..=80 | 82..=85 | 128..=254)
    }

    /// Whether the QCI is a standardized GBR QCI (TS 23.203 Table 6.1.7).
    pub fn is_gbr(&self) -> bool {
        matches!(self.qci, 1..=4 | 65..=67 | 71..=76 | 82..=85)
    }

    /// Parse as a receiver: groups beyond the third and a trailing partial
    /// group are ignored.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let (&qci, rest) = value.split_first()?;
        let group = |index: usize| -> Option<[u8; 4]> {
            rest.get(index * 4..index * 4 + 4)?.try_into().ok()
        };
        let bit_rates = group(0);
        let extension = bit_rates.and(group(1));
        Some(Self {
            qci,
            bit_rates,
            extension,
            extension2: extension.and(group(2)),
        })
    }

    /// Parse the octet lengths a sender may use: 1, 5, 9, or 13.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
        matches!(value.len(), 1 | 5 | 9 | 13).then(|| Self::from_bytes(value))?
    }

    /// Encode the coded octets.
    pub fn to_bytes(self) -> core::result::Result<Vec<u8>, ValueError> {
        if self.extension.is_some() && self.bit_rates.is_none() {
            return Err(ValueError::combination(
                "extension",
                "is written with `bit-rates`",
            ));
        }
        if self.extension2.is_some() && self.extension.is_none() {
            return Err(ValueError::combination(
                "extension2",
                "is written with `extension`",
            ));
        }
        let mut value = vec![self.qci];
        for group in [self.bit_rates, self.extension, self.extension2]
            .into_iter()
            .flatten()
        {
            value.extend_from_slice(&group);
        }
        Ok(value)
    }

    fn bit_rate(&self, index: usize) -> Option<EpsBitRate> {
        use crate::common::ts24301::{
            eps_bit_rate_kbps, eps_extended_bit_rate_kbps, eps_qos_extended2_bit_rate_kbps,
        };
        let base = self.bit_rates?[index];
        if let Some(kbps) = self
            .extension2
            .and_then(|group| eps_qos_extended2_bit_rate_kbps(group[index]))
        {
            return Some(EpsBitRate::Kbps(kbps));
        }
        if let Some(kbps) = self
            .extension
            .and_then(|group| eps_extended_bit_rate_kbps(group[index]))
        {
            return Some(EpsBitRate::Kbps(kbps));
        }
        Some(eps_bit_rate_kbps(base).map_or(EpsBitRate::SubscribedOrReserved, EpsBitRate::Kbps))
    }

    /// Maximum bit rate for uplink, if the bit rate group is present.
    pub fn mbr_ul(&self) -> Option<EpsBitRate> {
        self.bit_rate(0)
    }

    /// Maximum bit rate for downlink, if the bit rate group is present.
    pub fn mbr_dl(&self) -> Option<EpsBitRate> {
        self.bit_rate(1)
    }

    /// Guaranteed bit rate for uplink, if the bit rate group is present.
    pub fn gbr_ul(&self) -> Option<EpsBitRate> {
        self.bit_rate(2)
    }

    /// Guaranteed bit rate for downlink, if the bit rate group is present.
    pub fn gbr_dl(&self) -> Option<EpsBitRate> {
        self.bit_rate(3)
    }

    /// Shortest exact encoding of a QCI and four rates up to 10 Gbps, in the
    /// order UL-MBR, DL-MBR, UL-GBR, DL-GBR.
    pub fn from_kbps(qci: u8, rates: [u64; 4]) -> core::result::Result<Self, ValueError> {
        use crate::common::ts24301::{eps_bit_rate_octets, eps_qos_extended2_bit_rate_octet};
        let mut base = [0; 4];
        let mut extended = [0; 4];
        let mut extended2 = [0; 4];
        let members = ["mbr-ul-kbps", "mbr-dl-kbps", "gbr-ul-kbps", "gbr-dl-kbps"];
        for (index, &kbps) in rates.iter().enumerate() {
            if let Some((low, high)) = eps_bit_rate_octets(kbps) {
                (base[index], extended[index]) = (low, high);
            } else {
                let exact = "a rate that the IE codes exactly, up to 10 Gbps";
                extended2[index] = eps_qos_extended2_bit_rate_octet(kbps)
                    .ok_or(ValueError::value(members[index], kbps, exact))?;
                (base[index], extended[index]) = (0xfe, 0xfa);
            }
        }
        let has_extended2 = extended2.iter().any(|&octet| octet != 0);
        let has_extended = has_extended2 || extended.iter().any(|&octet| octet != 0);
        Ok(Self {
            qci,
            bit_rates: Some(base),
            extension: has_extended.then_some(extended),
            extension2: has_extended2.then_some(extended2),
        })
    }
}

impl EpsQualityOfService {
    /// Build from coded octets.
    pub fn from_qos(qos: EpsQos) -> core::result::Result<Self, crate::common::ValueError> {
        Ok(Self::new(qos.to_bytes()?))
    }

    /// Coded octets as a receiver reads them.
    pub fn qos(&self) -> Option<EpsQos> {
        EpsQos::from_bytes(&self.value)
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "bit rates with extensions within their ranges, an extension only after a rate of 0xfe and an extension 2 only after an extension of 0xfa (TS 24.301 §9.9.4.3)";
    /// Sender check (§9.9.4.3): 1, 5, 9, or 13 octets; a bit rate
    /// octet is 11111110 when its extended octet is used, an extended
    /// octet is 11111010 when its extended-2 octet is used, and those
    /// octets hold defined values.
    pub fn is_well_formed(&self) -> bool {
        let Some(qos) = EpsQos::from_bytes_strict(&self.value) else {
            return false;
        };
        let [base, extension, extension2] =
            [qos.bit_rates, qos.extension, qos.extension2].map(Option::unwrap_or_default);
        (0..4).all(|index| {
            extension[index] <= 0xfa
                && extension2[index] <= 0xf6
                && (extension[index] == 0 || base[index] == 0xfe)
                && (extension2[index] == 0 || extension[index] == 0xfa)
        })
    }

    /// Whether both maximum bit rates are 0 kbps, which a sender shall
    /// not request and a receiver treats as a syntactical error
    /// (§9.9.4.3).
    pub fn has_zero_maximum_bit_rates(&self) -> bool {
        self.qos().is_some_and(|qos| {
            qos.mbr_ul() == Some(EpsBitRate::Kbps(0)) && qos.mbr_dl() == Some(EpsBitRate::Kbps(0))
        })
    }
}

/// Quality of service of TS 24.008 §10.5.6.5, carried as Negotiated QoS and
/// New QoS (TS 24.301 §9.9.4.12). Value octet `n` is IE octet `n + 3`.
impl QualityOfService {
    fn octet(&self, ie_octet: usize) -> Option<u8> {
        self.value.get(ie_octet - 3).copied()
    }

    /// Delay class with the receiver rule: 5 and 6 are read as class 4
    /// (best effort); 0 (subscribed or reserved) and 7 (reserved) are `None`.
    pub fn delay_class(&self) -> Option<u8> {
        match (self.octet(3)? >> 3) & 0x07 {
            class @ 1..=4 => Some(class),
            5 | 6 => Some(4),
            _ => None,
        }
    }

    /// Reliability class with the receiver rule: 1 is read as 2, and
    /// 6 as 3; 0 and 7 are `None`.
    pub fn reliability_class(&self) -> Option<u8> {
        match self.octet(3)? & 0x07 {
            1 => Some(2),
            class @ 2..=5 => Some(class),
            6 => Some(3),
            _ => None,
        }
    }

    /// Peak throughput class with the receiver rule: undefined codes
    /// are read as 1 (up to 1000 octet/s); 0 and 15 are `None`.
    pub fn peak_throughput(&self) -> Option<u8> {
        match self.octet(4)? >> 4 {
            class @ 1..=9 => Some(class),
            10..=14 => Some(1),
            _ => None,
        }
    }

    /// Precedence class with the receiver rule: 4 to 6 are read as 2
    /// (normal priority); 0 and 7 are `None`.
    pub fn precedence_class(&self) -> Option<u8> {
        match self.octet(4)? & 0x07 {
            class @ 1..=3 => Some(class),
            4..=6 => Some(2),
            _ => None,
        }
    }

    /// Mean throughput class with the receiver rule: undefined codes
    /// are read as 31 (best effort); 0 and 30 are `None`.
    pub fn mean_throughput(&self) -> Option<u8> {
        match self.octet(5)? & 0x1f {
            class @ (1..=18 | 31) => Some(class),
            19..=29 => Some(31),
            _ => None,
        }
    }

    /// Traffic class (octet 6, bits 8-6).
    pub fn traffic_class_raw(&self) -> Option<u8> {
        self.octet(6).map(|octet| octet >> 5)
    }

    /// Delivery order (octet 6, bits 5-4).
    pub fn delivery_order_raw(&self) -> Option<u8> {
        self.octet(6).map(|octet| (octet >> 3) & 0x03)
    }

    /// Delivery of erroneous SDUs (octet 6, bits 3-1).
    pub fn delivery_of_erroneous_sdu_raw(&self) -> Option<u8> {
        self.octet(6).map(|octet| octet & 0x07)
    }

    /// Maximum SDU size code (octet 7).
    pub fn maximum_sdu_size_raw(&self) -> Option<u8> {
        self.octet(7)
    }

    /// Residual BER (octet 10, bits 8-5).
    pub fn residual_ber_raw(&self) -> Option<u8> {
        self.octet(10).map(|octet| octet >> 4)
    }

    /// SDU error ratio (octet 10, bits 4-1).
    pub fn sdu_error_ratio_raw(&self) -> Option<u8> {
        self.octet(10).map(|octet| octet & 0x0f)
    }

    /// Transfer delay code (octet 11, bits 8-3).
    pub fn transfer_delay_raw(&self) -> Option<u8> {
        self.octet(11).map(|octet| octet >> 2)
    }

    /// Traffic handling priority (octet 11, bits 2-1).
    pub fn traffic_handling_priority_raw(&self) -> Option<u8> {
        self.octet(11).map(|octet| octet & 0x03)
    }

    /// Signalling indication (octet 14, bit 5).
    pub fn signalling_indication(&self) -> Option<bool> {
        self.octet(14).map(|octet| octet & 0x10 != 0)
    }

    /// Source statistics descriptor (octet 14, bits 4-1).
    pub fn source_statistics_descriptor_raw(&self) -> Option<u8> {
        self.octet(14).map(|octet| octet & 0x0f)
    }

    fn bit_rate_kbps(&self, base: usize, extended: usize, extended2: usize) -> Option<EpsBitRate> {
        use crate::common::ts24301::{
            eps_bit_rate_kbps, eps_extended_bit_rate_kbps, eps_qos_extended2_bit_rate_kbps,
        };
        let octet = self.octet(base)?;
        if let Some(kbps) = self
            .octet(extended2)
            .and_then(eps_qos_extended2_bit_rate_kbps)
        {
            return Some(EpsBitRate::Kbps(kbps));
        }
        if let Some(kbps) = self.octet(extended).and_then(eps_extended_bit_rate_kbps) {
            return Some(EpsBitRate::Kbps(kbps));
        }
        Some(eps_bit_rate_kbps(octet).map_or(EpsBitRate::SubscribedOrReserved, EpsBitRate::Kbps))
    }

    /// Maximum bit rate for uplink (octets 8, 17, 21).
    pub fn mbr_ul(&self) -> Option<EpsBitRate> {
        self.bit_rate_kbps(8, 17, 21)
    }

    /// Maximum bit rate for downlink (octets 9, 15, 19).
    pub fn mbr_dl(&self) -> Option<EpsBitRate> {
        self.bit_rate_kbps(9, 15, 19)
    }

    /// Guaranteed bit rate for uplink (octets 12, 18, 22).
    pub fn gbr_ul(&self) -> Option<EpsBitRate> {
        self.bit_rate_kbps(12, 18, 22)
    }

    /// Guaranteed bit rate for downlink (octets 13, 16, 20).
    pub fn gbr_dl(&self) -> Option<EpsBitRate> {
        self.bit_rate_kbps(13, 16, 20)
    }

    /// Receiver framing accepted by TS 24.008 §10.5.6.5.
    ///
    /// The three- and eleven-octet legacy values omit octets 6-22 or
    /// 14-22 respectively. Modern values add each extension pair as a
    /// unit. Field-code fallbacks are exposed by the typed getters and
    /// are deliberately not sender validation.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        matches!(self.value.len(), 3 | 11 | 12 | 14 | 16 | 18 | 20)
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "12 to 20 value octets in the specified pairs, with every network-assigned field using a defined code (TS 24.008 Table 10.5.156)";
    /// Sender check: 12 to 20 value octets in the specified pairs,
    /// with every network-assigned field using a defined code.  The
    /// extension dependency rules are from TS 24.008 table 10.5.156.
    pub fn is_well_formed(&self) -> bool {
        if !matches!(self.value.len(), 12 | 14 | 16 | 18 | 20) {
            return false;
        }

        let value = &self.value;
        let mandatory_fields_are_defined = value[0] & 0xc0 == 0
            && matches!((value[0] >> 3) & 0x07, 1..=4)
            && matches!(value[0] & 0x07, 2..=5)
            && matches!(value[1] >> 4, 1..=9)
            && value[1] & 0x08 == 0
            && matches!(value[1] & 0x07, 1..=3)
            && value[2] & 0xe0 == 0
            && matches!(value[2] & 0x1f, 1..=18 | 31)
            && matches!(value[3] >> 5, 1..=4)
            && matches!((value[3] >> 3) & 0x03, 1..=2)
            && matches!(value[3] & 0x07, 1..=3)
            && matches!(value[4], 1..=0x99)
            && value[5] != 0
            && value[6] != 0
            && matches!(value[7] >> 4, 1..=9)
            && matches!(value[7] & 0x0f, 1..=7)
            && matches!(value[8] >> 2, 1..=62)
            && matches!(value[8] & 0x03, 1..=3)
            && value[9] != 0
            && value[10] != 0
            && value[11] & !0x10 == 0;
        if !mandatory_fields_are_defined {
            return false;
        }

        let extension_is_defined = |index: usize, base: usize| {
            value[index] <= 0xfa && (value[index] == 0 || value[base] == 0xfe)
        };
        let extension2_is_defined = |index: usize, extension: usize| {
            value[index] <= 0xf6 && (value[index] == 0 || value[extension] == 0xfa)
        };

        (value.len() < 14 || (extension_is_defined(12, 6) && extension_is_defined(13, 10)))
            && (value.len() < 16 || (extension_is_defined(14, 5) && extension_is_defined(15, 9)))
            && (value.len() < 18
                || (extension2_is_defined(16, 12) && extension2_is_defined(17, 13)))
            && (value.len() < 20
                || (extension2_is_defined(18, 14) && extension2_is_defined(19, 15)))
    }
}

/// Extended quality of service (§9.9.4.30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtendedEpsQos {
    /// Unit of the maximum bit rates (octet 3).
    pub mbr_unit: u8,
    /// Maximum bit rate for uplink (octets 4-5).
    pub mbr_ul: u16,
    /// Maximum bit rate for downlink (octets 6-7).
    pub mbr_dl: u16,
    /// Unit of the guaranteed bit rates (octet 8).
    pub gbr_unit: u8,
    /// Guaranteed bit rate for uplink (octets 9-10).
    pub gbr_ul: u16,
    /// Guaranteed bit rate for downlink (octets 11-12).
    pub gbr_dl: u16,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct ExtendedEpsQos { mbr_unit, mbr_ul, mbr_dl, gbr_unit, gbr_ul, gbr_dl });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(ExtendedEpsQos);

impl ExtendedEpsQos {
    /// Parse the first ten value octets; extra octets are ignored.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let value = value.get(..10)?;
        let word = |index: usize| u16::from_be_bytes([value[index], value[index + 1]]);
        Some(Self {
            mbr_unit: value[0],
            mbr_ul: word(1),
            mbr_dl: word(3),
            gbr_unit: value[5],
            gbr_ul: word(6),
            gbr_dl: word(8),
        })
    }

    /// Encode the ten value octets.
    pub fn to_bytes(self) -> [u8; 10] {
        let mut value = [0; 10];
        value[0] = self.mbr_unit;
        value[1..3].copy_from_slice(&self.mbr_ul.to_be_bytes());
        value[3..5].copy_from_slice(&self.mbr_dl.to_be_bytes());
        value[5] = self.gbr_unit;
        value[6..8].copy_from_slice(&self.gbr_ul.to_be_bytes());
        value[8..10].copy_from_slice(&self.gbr_dl.to_be_bytes());
        value
    }

    fn rate(unit: u8, value: u16) -> Option<u64> {
        // A receiver ignores rates of 10 Gbps or less, including the zero filler.
        u64::from(value)
            .checked_mul(crate::common::ts24301::extended_qos_unit_kbps(unit))
            .filter(|&kbps| kbps > 10_000_000)
    }

    /// Maximum bit rate for uplink above 10 Gbps, in kbps.
    pub fn mbr_ul_kbps(self) -> Option<u64> {
        Self::rate(self.mbr_unit, self.mbr_ul)
    }

    /// Maximum bit rate for downlink above 10 Gbps, in kbps.
    pub fn mbr_dl_kbps(self) -> Option<u64> {
        Self::rate(self.mbr_unit, self.mbr_dl)
    }

    /// Guaranteed bit rate for uplink above 10 Gbps, in kbps.
    pub fn gbr_ul_kbps(self) -> Option<u64> {
        Self::rate(self.gbr_unit, self.gbr_ul)
    }

    /// Guaranteed bit rate for downlink above 10 Gbps, in kbps.
    pub fn gbr_dl_kbps(self) -> Option<u64> {
        Self::rate(self.gbr_unit, self.gbr_dl)
    }

    /// Encode rates in kbps; a rate of 10 Gbps or less is sent as 0 because
    /// the EPS QoS IE carries it. Each pair shares the smallest common unit.
    pub fn from_kbps(
        mbr_ul: u64,
        mbr_dl: u64,
        gbr_ul: u64,
        gbr_dl: u64,
    ) -> core::result::Result<Self, ValueError> {
        use crate::common::ts24301::extended_qos_unit_kbps;
        let pair = |uplink: u64, downlink: u64| -> Option<(u8, u16, u16)> {
            let keep = |kbps: u64| if kbps > 10_000_000 { kbps } else { 0 };
            let (uplink, downlink) = (keep(uplink), keep(downlink));
            (1..=0x15u8).find_map(|unit| {
                let step = extended_qos_unit_kbps(unit);
                let fits =
                    |kbps: u64| kbps.is_multiple_of(step) && kbps / step <= u64::from(u16::MAX);
                (fits(uplink) && fits(downlink))
                    .then(|| (unit, (uplink / step) as u16, (downlink / step) as u16))
            })
        };
        let shared = "with the downlink rate, up to 65535 times one unit of the IE";
        let (mbr_unit, mbr_ul, mbr_dl) =
            pair(mbr_ul, mbr_dl).ok_or(ValueError::value("mbr-ul-kbps", mbr_ul, shared))?;
        let (gbr_unit, gbr_ul, gbr_dl) =
            pair(gbr_ul, gbr_dl).ok_or(ValueError::value("gbr-ul-kbps", gbr_ul, shared))?;
        Ok(Self {
            mbr_unit,
            mbr_ul,
            mbr_dl,
            gbr_unit,
            gbr_ul,
            gbr_dl,
        })
    }
}

impl ExtendedQualityOfService {
    /// Typed value.
    pub fn qos(&self) -> Option<ExtendedEpsQos> {
        ExtendedEpsQos::from_bytes(&self.value)
    }

    /// Build from a typed value.
    pub fn from_qos(qos: ExtendedEpsQos) -> Self {
        Self::new(qos.to_bytes())
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "ten octets using defined units (1 or above)";
    /// Sender check: ten octets using defined units (1 or above).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.qos(), Some(qos) if self.value.len() == 10 && qos.mbr_unit >= 1 && qos.gbr_unit >= 1)
    }
}

crate::common::ts24301::ue_network_capability_ie!(UeNetworkCapability);
crate::common::ts24301::ue_security_capability_ie!(UeSecurityCapability, UeNetworkCapability);

impl UeSecurityCapability {
    /// Add to these replayed capabilities the GPRS algorithms of the MS
    /// network capability that the UE sent, which a SECURITY MODE COMMAND
    /// repeats too (TS 24.301 §5.4.3.2): the octet of GEA1 to GEA7, after
    /// the UMTS octets, zero where the UE sent none.
    pub fn set_gea_of(&mut self, capability: &MsNetworkCapability) {
        let first = if capability.gea1() { 0x40 } else { 0 };
        let gea = (2..=7)
            .filter(|&algo| capability.supports_gea(algo))
            .fold(first, |octet, algo| octet | (0x80 >> algo));
        if gea != 0 {
            let mut value = self.value.as_slice().to_vec();
            value.resize(4, 0);
            value.push(gea);
            self.value = value.into();
        }
    }
}

oxirush_utils::named_values! {
    /// Traffic flow template operation from TS 24.008 §10.5.6.12.
    pub enum TftOperation "§10.5.6.12" bits 8 {
        0 Ignore "ignore" tree "ignore",
        1 Create "create" tree "create",
        2 Delete "delete" tree "delete",
        3 AddFilters "add filters" tree "add-filters",
        4 ReplaceFilters "replace filters" tree "replace-filters",
        5 DeleteFilters "delete filters" tree "delete-filters",
        6 NoOperation "no operation" tree "no-operation",
    }
}
crate::common::enums::values_readable!(TftOperation);

/// Class of a TFT decoding error, as distinguished by TS 24.301
/// §6.4.2.4 and §6.4.3.4.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftError {
    /// The TFT operation, the filter count, or the list coding is invalid
    /// (ESM cause #42).
    SyntacticalTftOperation,
    /// A packet filter is incorrectly coded (ESM cause #45).
    SyntacticalPacketFilter,
    /// The parameters list has consecutive Authorization Tokens without a
    /// Flow Identifier between them (TS 24.008 Table 10.5.162, ESM cause
    /// #41).
    SemanticTftOperation,
}

impl TftError {
    /// ESM cause the UE sends when rejecting the request.
    pub fn esm_cause(self) -> EsmCauseValue {
        match self {
            Self::SyntacticalTftOperation => EsmCauseValue::SyntacticalErrorInTheTftOperation,
            Self::SyntacticalPacketFilter => EsmCauseValue::SyntacticalErrorsInPacketFilters,
            Self::SemanticTftOperation => EsmCauseValue::SemanticErrorInTheTftOperation,
        }
    }
}

oxirush_utils::named_values! {
    /// Direction of a TFT packet filter (octet 4 bits 6-5).
    pub enum TftPacketFilterDirection "" bits 2 {
        0 PreRel7 "pre rel7" tree "pre-rel7",
        1 Downlink "downlink" tree "downlink",
        2 Uplink "uplink" tree "uplink",
        3 Bidirectional "bidirectional" tree "bidirectional",
    }
}
crate::common::enums::values_readable!(TftPacketFilterDirection);

/// One packet filter component (TS 24.008 Table 10.5.162).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftPacketFilterComponent {
    /// IPv4 remote address and mask (0x10).
    Ipv4RemoteAddress {
        /// IPv4 address.
        address: [u8; 4],
        /// Address mask.
        mask: [u8; 4],
    },
    /// IPv4 local address and mask (0x11).
    Ipv4LocalAddress {
        /// IPv4 address.
        address: [u8; 4],
        /// Address mask.
        mask: [u8; 4],
    },
    /// IPv6 remote address and mask (0x20).
    Ipv6RemoteAddress {
        /// IPv6 address.
        address: [u8; 16],
        /// Address mask.
        mask: [u8; 16],
    },
    /// IPv6 remote address and prefix length (0x21).
    Ipv6RemoteAddressPrefix {
        /// IPv6 address.
        address: [u8; 16],
        /// Prefix length.
        prefix_length: u8,
    },
    /// IPv6 local address and prefix length (0x23).
    Ipv6LocalAddressPrefix {
        /// IPv6 address.
        address: [u8; 16],
        /// Prefix length.
        prefix_length: u8,
    },
    /// IPv4 protocol identifier or IPv6 next header (0x30).
    ProtocolIdentifierNextHeader(u8),
    /// Single local port (0x40).
    SingleLocalPort(u16),
    /// Local port range (0x41).
    LocalPortRange {
        /// Low limit.
        low: u16,
        /// High limit.
        high: u16,
    },
    /// Single remote port (0x50).
    SingleRemotePort(u16),
    /// Remote port range (0x51).
    RemotePortRange {
        /// Low limit.
        low: u16,
        /// High limit.
        high: u16,
    },
    /// IPsec security parameter index (0x60).
    SecurityParameterIndex(u32),
    /// Type of service or traffic class, and mask (0x70).
    TypeOfServiceTrafficClass {
        /// Type of service or traffic class.
        value: u8,
        /// Mask.
        mask: u8,
    },
    /// 20-bit IPv6 flow label (0x80).
    FlowLabel(u32),
    /// Destination MAC address (0x81).
    DestinationMacAddress([u8; 6]),
    /// Source MAC address (0x82).
    SourceMacAddress([u8; 6]),
    /// 12-bit 802.1Q C-TAG VID (0x83).
    CTagVid(u16),
    /// 12-bit 802.1Q S-TAG VID (0x84).
    STagVid(u16),
    /// 802.1Q C-TAG PCP and DEI (0x85).
    CTagPcpDei {
        /// Priority code point.
        pcp: u8,
        /// Drop eligible indicator.
        dei: bool,
    },
    /// 802.1Q S-TAG PCP and DEI (0x86).
    STagPcpDei {
        /// Priority code point.
        pcp: u8,
        /// Drop eligible indicator.
        dei: bool,
    },
    /// Ethertype (0x87).
    Ethertype(u16),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(enum TftPacketFilterComponent { Ipv4RemoteAddress { address, mask }, Ipv4LocalAddress { address, mask }, Ipv6RemoteAddress { address, mask }, Ipv6RemoteAddressPrefix { address, prefix_length }, Ipv6LocalAddressPrefix { address, prefix_length }, ProtocolIdentifierNextHeader(u8), SingleLocalPort(u16), LocalPortRange { low, high }, SingleRemotePort(u16), RemotePortRange { low, high }, SecurityParameterIndex(u32), TypeOfServiceTrafficClass { value, mask }, FlowLabel(u32), DestinationMacAddress([u8; 6]), SourceMacAddress([u8; 6]), CTagVid(u16), STagVid(u16), CTagPcpDei { pcp, dei }, STagPcpDei { pcp, dei }, Ethertype(u16) });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(TftPacketFilterComponent);

/// Value length of a component type, or `None` for a reserved type.
fn tft_component_size(kind: u8) -> Option<usize> {
    Some(match kind {
        0x10 | 0x11 => 8,
        0x20 => 32,
        0x21 | 0x23 => 17,
        0x30 | 0x85 | 0x86 => 1,
        0x40 | 0x50 | 0x70 | 0x83 | 0x84 | 0x87 => 2,
        0x41 | 0x51 | 0x60 => 4,
        0x80 => 3,
        0x81 | 0x82 => 6,
        _ => return None,
    })
}

impl TftPacketFilterComponent {
    /// Decode one component value of type `kind`. Spare bits of the flow
    /// label, VID, and PCP/DEI components are ignored.
    fn decode(kind: u8, value: &[u8]) -> Option<Self> {
        let array = |range: core::ops::Range<usize>| value.get(range);
        let word = |index: usize| u16::from_be_bytes([value[index], value[index + 1]]);
        if value.len() != tft_component_size(kind)? {
            return None;
        }
        Some(match kind {
            0x10 => Self::Ipv4RemoteAddress {
                address: array(0..4)?.try_into().ok()?,
                mask: array(4..8)?.try_into().ok()?,
            },
            0x11 => Self::Ipv4LocalAddress {
                address: array(0..4)?.try_into().ok()?,
                mask: array(4..8)?.try_into().ok()?,
            },
            0x20 => Self::Ipv6RemoteAddress {
                address: array(0..16)?.try_into().ok()?,
                mask: array(16..32)?.try_into().ok()?,
            },
            0x21 => Self::Ipv6RemoteAddressPrefix {
                address: array(0..16)?.try_into().ok()?,
                prefix_length: value[16],
            },
            0x23 => Self::Ipv6LocalAddressPrefix {
                address: array(0..16)?.try_into().ok()?,
                prefix_length: value[16],
            },
            0x30 => Self::ProtocolIdentifierNextHeader(value[0]),
            0x40 => Self::SingleLocalPort(word(0)),
            0x41 => Self::LocalPortRange {
                low: word(0),
                high: word(2),
            },
            0x50 => Self::SingleRemotePort(word(0)),
            0x51 => Self::RemotePortRange {
                low: word(0),
                high: word(2),
            },
            0x60 => Self::SecurityParameterIndex(u32::from_be_bytes(array(0..4)?.try_into().ok()?)),
            0x70 => Self::TypeOfServiceTrafficClass {
                value: value[0],
                mask: value[1],
            },
            0x80 => Self::FlowLabel(u32::from_be_bytes([0, value[0] & 0x0f, value[1], value[2]])),
            0x81 => Self::DestinationMacAddress(array(0..6)?.try_into().ok()?),
            0x82 => Self::SourceMacAddress(array(0..6)?.try_into().ok()?),
            0x83 => Self::CTagVid(word(0) & 0x0fff),
            0x84 => Self::STagVid(word(0) & 0x0fff),
            0x85 => Self::CTagPcpDei {
                pcp: (value[0] >> 1) & 0x07,
                dei: value[0] & 1 != 0,
            },
            0x86 => Self::STagPcpDei {
                pcp: (value[0] >> 1) & 0x07,
                dei: value[0] & 1 != 0,
            },
            0x87 => Self::Ethertype(word(0)),
            _ => return None,
        })
    }

    /// Component type identifier.
    pub fn type_identifier(&self) -> u8 {
        match self {
            Self::Ipv4RemoteAddress { .. } => 0x10,
            Self::Ipv4LocalAddress { .. } => 0x11,
            Self::Ipv6RemoteAddress { .. } => 0x20,
            Self::Ipv6RemoteAddressPrefix { .. } => 0x21,
            Self::Ipv6LocalAddressPrefix { .. } => 0x23,
            Self::ProtocolIdentifierNextHeader(_) => 0x30,
            Self::SingleLocalPort(_) => 0x40,
            Self::LocalPortRange { .. } => 0x41,
            Self::SingleRemotePort(_) => 0x50,
            Self::RemotePortRange { .. } => 0x51,
            Self::SecurityParameterIndex(_) => 0x60,
            Self::TypeOfServiceTrafficClass { .. } => 0x70,
            Self::FlowLabel(_) => 0x80,
            Self::DestinationMacAddress(_) => 0x81,
            Self::SourceMacAddress(_) => 0x82,
            Self::CTagVid(_) => 0x83,
            Self::STagVid(_) => 0x84,
            Self::CTagPcpDei { .. } => 0x85,
            Self::STagPcpDei { .. } => 0x86,
            Self::Ethertype(_) => 0x87,
        }
    }

    /// Encode the type identifier and value: a flow label has 20 bits, a VID
    /// 12 and a PCP 3.
    pub fn to_bytes(&self) -> core::result::Result<Vec<u8>, ValueError> {
        let mut octets = vec![self.type_identifier()];
        match *self {
            Self::Ipv4RemoteAddress { address, mask }
            | Self::Ipv4LocalAddress { address, mask } => {
                octets.extend_from_slice(&address);
                octets.extend_from_slice(&mask);
            }
            Self::Ipv6RemoteAddress { address, mask } => {
                octets.extend_from_slice(&address);
                octets.extend_from_slice(&mask);
            }
            Self::Ipv6RemoteAddressPrefix {
                address,
                prefix_length,
            }
            | Self::Ipv6LocalAddressPrefix {
                address,
                prefix_length,
            } => {
                octets.extend_from_slice(&address);
                octets.push(prefix_length);
            }
            Self::ProtocolIdentifierNextHeader(value) => octets.push(value),
            Self::SingleLocalPort(port) | Self::SingleRemotePort(port) | Self::Ethertype(port) => {
                octets.extend_from_slice(&port.to_be_bytes())
            }
            Self::LocalPortRange { low, high } | Self::RemotePortRange { low, high } => {
                octets.extend_from_slice(&low.to_be_bytes());
                octets.extend_from_slice(&high.to_be_bytes());
            }
            Self::SecurityParameterIndex(spi) => octets.extend_from_slice(&spi.to_be_bytes()),
            Self::TypeOfServiceTrafficClass { value, mask } => {
                octets.extend_from_slice(&[value, mask])
            }
            Self::FlowLabel(label) => {
                within("flow-label", label, 0, 0x000f_ffff)?;
                octets.extend_from_slice(&label.to_be_bytes()[1..]);
            }
            Self::DestinationMacAddress(mac) | Self::SourceMacAddress(mac) => {
                octets.extend_from_slice(&mac)
            }
            Self::CTagVid(vid) | Self::STagVid(vid) => {
                within("vid", vid, 0, 0x0fff)?;
                octets.extend_from_slice(&vid.to_be_bytes());
            }
            Self::CTagPcpDei { pcp, dei } | Self::STagPcpDei { pcp, dei } => {
                within("pcp", pcp, 0, 7)?;
                octets.push(pcp << 1 | u8::from(dei));
            }
        }
        Ok(octets)
    }
}

/// Check the packet filter contents rules of TS 24.008 Table 10.5.162:
/// at least one component, no reserved or repeated component type, the
/// exclusive pairs, and no IP component with a non-IP Ethertype.
fn valid_tft_filter_contents(contents: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut ether_type = None;
    let mut remaining = contents;
    while let Some((&kind, rest)) = remaining.split_first() {
        let Some(size) = tft_component_size(kind) else {
            return false;
        };
        if seen[usize::from(kind)] || rest.len() < size {
            return false;
        }
        if kind == 0x87 {
            ether_type = Some(u16::from_be_bytes([rest[0], rest[1]]));
        }
        seen[usize::from(kind)] = true;
        remaining = &rest[size..];
    }
    if seen[0x10] && (seen[0x20] || seen[0x21])
        || seen[0x20] && seen[0x21]
        || seen[0x11] && seen[0x23]
        || seen[0x40] && seen[0x41]
        || seen[0x50] && seen[0x51]
    {
        return false;
    }
    // The "IP packet filter components" listed in Table 10.5.162.
    const IP_COMPONENTS: [usize; 13] = [
        0x10, 0x11, 0x20, 0x21, 0x23, 0x30, 0x40, 0x41, 0x50, 0x51, 0x60, 0x70, 0x80,
    ];
    if ether_type.is_some_and(|value| !matches!(value, 0x0800 | 0x86dd))
        && IP_COMPONENTS.iter().any(|&kind| seen[kind])
    {
        return false;
    }
    !contents.is_empty()
}

/// Whether valid contents also keep their component spare bits clear.
fn canonical_tft_filter_contents(contents: &[u8]) -> bool {
    let filter = TftPacketFilter {
        identifier: 0,
        direction: 0,
        precedence: None,
        contents: contents.to_vec(),
    };
    filter.components().is_some_and(|components| {
        components
            .iter()
            .map(TftPacketFilterComponent::to_bytes)
            .collect::<core::result::Result<Vec<_>, _>>()
            .is_ok_and(|octets| octets.concat() == contents)
    })
}

/// One TFT packet filter. Delete-filter operations carry only `identifier`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TftPacketFilter {
    /// Packet filter identifier (bits 4-1).
    pub identifier: u8,
    /// Raw direction (bits 6-5).
    pub direction: u8,
    /// Evaluation precedence; absent for deleted filters.
    pub precedence: Option<u8>,
    /// Packet filter contents: component type identifiers and values.
    pub contents: Vec<u8>,
}

/// A packet filter as a tree shows it: its direction by its name, and its
/// components where they write its contents back, as the packet filters of
/// a 5GS QoS rule are; its contents in hexadecimal where they do not.
#[cfg(feature = "tree")]
impl crate::common::readable::Readable for TftPacketFilter {
    const TAKES: &'static oxirush_utils::tree::Takes = &oxirush_utils::tree::Takes::Members(
        None,
        &[
            (
                "identifier",
                <u8 as crate::common::readable::Readable>::TAKES,
            ),
            (
                "direction",
                &oxirush_utils::tree::Takes::OneOf(&[
                    <TftPacketFilterDirection as crate::common::readable::Readable>::TAKES,
                    <u8 as crate::common::readable::Readable>::TAKES,
                ]),
            ),
            (
                "precedence",
                <u8 as crate::common::readable::Readable>::TAKES,
            ),
            (
                "components",
                <Vec<TftPacketFilterComponent> as crate::common::readable::Readable>::TAKES,
            ),
            (
                "contents",
                crate::common::forms::hexadecimal::of(core::marker::PhantomData::<()>),
            ),
        ],
    );

    fn shown(&self, _: &'static str) -> oxirush_utils::tree::Value {
        let mut members = crate::common::readable::Members::new();
        members.put("identifier", &self.identifier);
        match self.direction {
            0..=3 => members.put("direction", &self.direction_value()),
            raw => members.put("direction", &raw),
        }
        members.put("precedence", &self.precedence);
        let components = (self.components()).filter(|components| {
            let written: core::result::Result<Vec<Vec<u8>>, _> = components
                .iter()
                .map(TftPacketFilterComponent::to_bytes)
                .collect();
            written.is_ok_and(|written| written.concat() == self.contents)
        });
        match components {
            _ if self.contents.is_empty() => {}
            Some(components) => members.put("components", &components),
            None => members.put_shown(
                "contents",
                crate::common::forms::hexadecimal::shown(&self.contents),
            ),
        }
        members.finish()
    }

    fn read(value: &oxirush_utils::tree::Value) -> core::result::Result<Self, String> {
        use crate::common::readable::{Readable, member, members};
        const FIELDS: &[&str] = &[
            "identifier",
            "direction",
            "precedence",
            "components",
            "contents",
        ];
        let read = members(value, "TftPacketFilter", FIELDS)?;
        let direction = match read[1] {
            Some(written) if written.is_number() => <u8 as Readable>::read(written)?,
            Some(written) => u8::from(<TftPacketFilterDirection as Readable>::read(written)?),
            None => return Err("`direction` is not written".into()),
        };
        let contents = match (read[3], read[4]) {
            (Some(_), Some(_)) => {
                return Err("a packet filter has its `components` or its `contents`".into());
            }
            (Some(components), None) => {
                let components = <Vec<TftPacketFilterComponent> as Readable>::read(components)?;
                let written: core::result::Result<Vec<Vec<u8>>, _> = components
                    .iter()
                    .map(TftPacketFilterComponent::to_bytes)
                    .collect();
                written.map_err(|error| error.to_string())?.concat()
            }
            (None, Some(contents)) => <Vec<u8> as Readable>::read(contents)?,
            (None, None) => Vec::new(),
        };
        Ok(Self {
            identifier: member(read[0], "identifier")?,
            direction,
            precedence: member(read[2], "precedence")?,
            contents,
        })
    }
}

#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(TftPacketFilter);

impl TftPacketFilter {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(identifier: u8, direction: u8, precedence: Option<u8>, contents: Vec<u8>) -> Self {
        Self {
            identifier,
            direction,
            precedence,
            contents,
        }
    }
}

impl TftPacketFilter {
    /// Typed direction.
    pub fn direction_value(&self) -> TftPacketFilterDirection {
        match self.direction & 0x03 {
            0 => TftPacketFilterDirection::PreRel7,
            1 => TftPacketFilterDirection::Downlink,
            2 => TftPacketFilterDirection::Uplink,
            _ => TftPacketFilterDirection::Bidirectional,
        }
    }

    /// Typed components; `None` if the contents are not valid.
    pub fn components(&self) -> Option<Vec<TftPacketFilterComponent>> {
        if !valid_tft_filter_contents(&self.contents) {
            return None;
        }
        let mut components = Vec::new();
        let mut remaining = self.contents.as_slice();
        while let Some((&kind, rest)) = remaining.split_first() {
            let size = tft_component_size(kind)?;
            components.push(TftPacketFilterComponent::decode(kind, rest.get(..size)?)?);
            remaining = &rest[size..];
        }
        Some(components)
    }

    /// Build a packet filter from typed components: an identifier of 15 at
    /// most, and components that Table 10.5.162 lets a filter have.
    pub fn from_components(
        identifier: u8,
        direction: TftPacketFilterDirection,
        precedence: u8,
        components: &[TftPacketFilterComponent],
    ) -> core::result::Result<Self, ValueError> {
        within("identifier", identifier, 0, 15)?;
        let mut contents = Vec::new();
        for (entry, component) in components.iter().enumerate() {
            contents.extend(component.to_bytes().map_err(|error| error.at(entry))?);
        }
        sized("components", "octets", contents.len(), 0, 255)?;
        if !valid_tft_filter_contents(&contents) {
            let rule = "are those that Table 10.5.162 of TS 24.008 lets a filter have together";
            return Err(ValueError::combination("components", rule));
        }
        Ok(Self {
            identifier,
            direction: u8::from(direction),
            precedence: Some(precedence),
            contents,
        })
    }
}

/// A TFT parameter encoded after the packet filters when the E bit is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TftParameter {
    /// Parameter identifier.
    pub identifier: u8,
    /// Parameter contents.
    pub contents: Vec<u8>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct TftParameter { identifier, contents });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(TftParameter);

/// Typed TFT parameter (TS 24.008 Table 10.5.162).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TftParameterValue<'a> {
    /// Authorization token (0x01).
    AuthorizationToken(&'a [u8]),
    /// Flow identifier (0x02): media component number and IP flow number.
    FlowIdentifier {
        /// Media component number.
        media_component: u16,
        /// IP flow number.
        ip_flow: u16,
    },
    /// Packet filter identifiers (0x03), with the spare bits removed.
    PacketFilterIdentifiers(Vec<u8>),
    /// A parameter the receiver discards.
    Unsupported,
}

impl TftParameter {
    /// Typed value; a malformed or unknown parameter is `Unsupported`.
    pub fn value(&self) -> TftParameterValue<'_> {
        match (self.identifier, self.contents.as_slice()) {
            (1, token) => TftParameterValue::AuthorizationToken(token),
            (2, [a, b, c, d]) => TftParameterValue::FlowIdentifier {
                media_component: u16::from_be_bytes([*a, *b]),
                ip_flow: u16::from_be_bytes([*c, *d]),
            },
            (3, ids) if !ids.is_empty() => {
                TftParameterValue::PacketFilterIdentifiers(ids.iter().map(|id| id & 0x0f).collect())
            }
            _ => TftParameterValue::Unsupported,
        }
    }
}

/// Traffic flow template with packet filters and optional parameters.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tft {
    /// TFT operation.
    pub operation: TftOperation,
    /// Packet filters in wire order.
    pub packet_filters: Vec<TftPacketFilter>,
    /// Parameters in wire order.
    pub parameters: Vec<TftParameter>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct Tft { operation, packet_filters, parameters });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(Tft);

impl Tft {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(
        operation: TftOperation,
        packet_filters: Vec<TftPacketFilter>,
        parameters: Vec<TftParameter>,
    ) -> Self {
        Self {
            operation,
            packet_filters,
            parameters,
        }
    }
}

/// Sender rules for the parameters list: an authorization token is
/// followed by at least one flow identifier, a flow identifier has four
/// octets, and packet filter identifiers use only bits 4-1.
/// Error class of a TFT parameters list, if any (TS 24.008 Table 10.5.162).
fn tft_parameters_error(parameters: &[TftParameter]) -> Option<TftError> {
    let mut needs_flow_id = false;
    for parameter in parameters {
        match parameter.identifier {
            1 => {
                if needs_flow_id {
                    return Some(TftError::SemanticTftOperation);
                }
                needs_flow_id = true;
            }
            2 => {
                if parameter.contents.len() != 4 {
                    return Some(TftError::SyntacticalTftOperation);
                }
                needs_flow_id = false;
            }
            3 if parameter.contents.is_empty()
                || parameter.contents.iter().any(|value| value & 0xf0 != 0) =>
            {
                return Some(TftError::SyntacticalTftOperation);
            }
            _ => {}
        }
    }
    needs_flow_id.then_some(TftError::SyntacticalTftOperation)
}

impl Tft {
    /// Parse a TFT value under the receiver rules and classify errors as
    /// TS 24.301 §6.4.2.4 and §6.4.3.4 do. Spare bits are ignored, "Ignore
    /// this IE" ignores the rest of the value, "Delete packet filters" may
    /// repeat an identifier, and unknown parameters are kept for the
    /// caller to discard.
    pub fn parse(value: &[u8]) -> core::result::Result<Self, TftError> {
        Self::parse_mode(value, false)
    }

    /// Parse a TFT value; see [`Self::parse`].
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        Self::parse(value).ok()
    }

    /// Parse only a value that the sender rules would produce unchanged.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
        Self::from_bytes(value).filter(|tft| tft.to_bytes().as_deref() == Ok(value))
    }

    fn parse_mode(
        value: &[u8],
        traffic_flow_aggregate: bool,
    ) -> core::result::Result<Self, TftError> {
        use TftError::{SyntacticalPacketFilter, SyntacticalTftOperation};
        let (&first, mut remaining) = value.split_first().ok_or(SyntacticalTftOperation)?;
        let operation = TftOperation::named(first >> 5).ok_or(SyntacticalTftOperation)?;
        let parameter_present = first & 0x10 != 0;
        let count = usize::from(first & 0x0f);
        match operation {
            TftOperation::Ignore if parameter_present || count != 0 => {
                return Err(SyntacticalTftOperation);
            }
            // TS 24.008 Table 10.5.162: the contents are ignored.
            TftOperation::Ignore => {
                return Ok(Self {
                    operation,
                    packet_filters: Vec::new(),
                    parameters: Vec::new(),
                });
            }
            TftOperation::Delete | TftOperation::NoOperation if count != 0 => {
                return Err(SyntacticalTftOperation);
            }
            TftOperation::Create
            | TftOperation::AddFilters
            | TftOperation::ReplaceFilters
            | TftOperation::DeleteFilters
                if count == 0 =>
            {
                return Err(SyntacticalTftOperation);
            }
            _ => {}
        }
        // Identical identifiers are an error only when filters are created
        // or replaced (§6.4.3.4 d) 1); the UE sends identifier 0 for every
        // new traffic flow aggregate filter.
        let check_duplicates = match operation {
            TftOperation::Create | TftOperation::AddFilters => !traffic_flow_aggregate,
            TftOperation::ReplaceFilters => true,
            _ => false,
        };
        let mut packet_filters = Vec::with_capacity(count);
        let mut seen_filters = [false; 16];
        for _ in 0..count {
            let (&header, rest) = remaining.split_first().ok_or(SyntacticalTftOperation)?;
            remaining = rest;
            let identifier = header & 0x0f;
            if check_duplicates
                && core::mem::replace(&mut seen_filters[usize::from(identifier)], true)
            {
                return Err(SyntacticalPacketFilter);
            }
            if operation == TftOperation::DeleteFilters {
                packet_filters.push(TftPacketFilter {
                    identifier,
                    direction: 0,
                    precedence: None,
                    contents: Vec::new(),
                });
                continue;
            }
            let (&[precedence, length], rest) = remaining
                .split_first_chunk::<2>()
                .ok_or(SyntacticalTftOperation)?;
            let contents = rest
                .get(..usize::from(length))
                .ok_or(SyntacticalTftOperation)?;
            if !valid_tft_filter_contents(contents) {
                return Err(SyntacticalPacketFilter);
            }
            packet_filters.push(TftPacketFilter {
                identifier,
                direction: (header >> 4) & 0x03,
                precedence: Some(precedence),
                contents: contents.to_vec(),
            });
            remaining = &rest[contents.len()..];
        }
        let mut parameters = Vec::new();
        if parameter_present {
            if remaining.is_empty() {
                return Err(SyntacticalTftOperation);
            }
            while let Some((&identifier, rest)) = remaining.split_first() {
                let (&length, rest) = rest.split_first().ok_or(SyntacticalTftOperation)?;
                let contents = rest
                    .get(..usize::from(length))
                    .ok_or(SyntacticalTftOperation)?;
                parameters.push(TftParameter {
                    identifier,
                    contents: contents.to_vec(),
                });
                remaining = &rest[contents.len()..];
            }
        } else if !remaining.is_empty() {
            return Err(SyntacticalTftOperation);
        }
        let known: Vec<_> = parameters
            .iter()
            .filter(|parameter| (1..=3).contains(&parameter.identifier))
            .map(|parameter| TftParameter {
                identifier: parameter.identifier,
                contents: match parameter.identifier {
                    3 => parameter.contents.iter().map(|id| id & 0x0f).collect(),
                    _ => parameter.contents.clone(),
                },
            })
            .collect();
        if let Some(error) = tft_parameters_error(&known) {
            return Err(error);
        }
        Ok(Self {
            operation,
            packet_filters,
            parameters,
        })
    }

    /// Encode a TFT value under the sender rules: operation, filter count,
    /// unique identifiers, record lengths, and parameters list.
    pub fn to_bytes(&self) -> core::result::Result<Vec<u8>, ValueError> {
        self.to_bytes_mode(false)
    }

    fn to_bytes_mode(
        &self,
        traffic_flow_aggregate: bool,
    ) -> core::result::Result<Vec<u8>, ValueError> {
        let count = self.packet_filters.len();
        counted("packet-filters", count, 0, 15)?;
        let rule = match self.operation {
            TftOperation::Ignore | TftOperation::Delete
                if count != 0 || !self.parameters.is_empty() =>
            {
                Some("has no packet filter and no parameter when it ignores or deletes the TFT")
            }
            TftOperation::NoOperation if count != 0 || self.parameters.is_empty() => {
                Some("has parameters and no packet filter when it is no operation")
            }
            TftOperation::Create
            | TftOperation::AddFilters
            | TftOperation::ReplaceFilters
            | TftOperation::DeleteFilters
                if count == 0 =>
            {
                Some("has a packet filter when it creates the TFT or changes its filters")
            }
            _ => None,
        };
        if let Some(rule) = rule {
            return Err(ValueError::combination("operation", rule));
        }
        let mut value = vec![
            (u8::from(self.operation)) << 5
                | if !self.parameters.is_empty() { 0x10 } else { 0 }
                | count as u8,
        ];
        let mut seen_filters = [false; 16];
        for (entry, filter) in self.packet_filters.iter().enumerate() {
            let entry = |error: ValueError| error.at(entry);
            within("identifier", filter.identifier, 0, 15).map_err(entry)?;
            let new_aggregate_filter = traffic_flow_aggregate
                && matches!(
                    self.operation,
                    TftOperation::Create | TftOperation::AddFilters
                );
            if new_aggregate_filter && filter.identifier != 0 {
                let new = "0 in a new filter of a traffic flow aggregate";
                return Err(entry(ValueError::value(
                    "identifier",
                    filter.identifier,
                    new,
                )));
            }
            if !new_aggregate_filter && seen_filters[filter.identifier as usize] {
                return Err(entry(ValueError::repeated("identifier", filter.identifier)));
            }
            seen_filters[filter.identifier as usize] = true;
            if self.operation == TftOperation::DeleteFilters {
                if filter.precedence.is_some()
                    || filter.direction != 0
                    || !filter.contents.is_empty()
                {
                    let rule = "is its identifier alone when filters are deleted";
                    return Err(entry(ValueError::combination("packet-filter", rule)));
                }
                value.push(filter.identifier);
            } else {
                within("direction", filter.direction, 0, 3).map_err(entry)?;
                if !canonical_tft_filter_contents(&filter.contents) {
                    let rule = "are components that Table 10.5.162 of TS 24.008 lets a filter have";
                    return Err(entry(ValueError::combination("contents", rule)));
                }
                let rule = "is written in a filter that is not deleted";
                let precedence = filter
                    .precedence
                    .ok_or(ValueError::combination("precedence", rule));
                let octets = filter.contents.len();
                sized("contents", "octets", octets, 0, 255).map_err(entry)?;
                value.push((filter.direction << 4) | filter.identifier);
                value.push(precedence.map_err(entry)?);
                value.push(octets as u8);
                value.extend_from_slice(&filter.contents);
            }
        }
        if tft_parameters_error(&self.parameters).is_some() {
            let rule = "are those of TS 24.008 Table 10.5.162: an authorization token before its \
                        flow identifiers of four octets, and filter identifiers of four bits";
            return Err(ValueError::combination("parameters", rule));
        }
        for (entry, parameter) in self.parameters.iter().enumerate() {
            let octets = parameter.contents.len();
            sized("contents", "octets", octets, 0, 255).map_err(|error| error.at(entry))?;
            value.push(parameter.identifier);
            value.push(octets as u8);
            value.extend_from_slice(&parameter.contents);
        }
        Ok(value)
    }
}

impl TrafficFlowTemplate {
    /// Parse this IE as a TFT under the receiver rules.
    pub fn tft(&self) -> Option<Tft> {
        Tft::from_bytes(&self.value)
    }

    /// Parse this IE, classifying any error by ESM cause.
    pub fn parse_tft(&self) -> core::result::Result<Tft, TftError> {
        Tft::parse(&self.value)
    }

    /// Build a raw IE from a typed TFT.
    pub fn from_tft(tft: &Tft) -> core::result::Result<Self, crate::common::ValueError> {
        let value = tft.to_bytes()?;
        crate::common::sized("traffic-flow-template", "octets", value.len(), 1, 255)?;
        Ok(Self::new(value))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "the value re-encodes unchanged and does not use the operation \"ignore this IE\", which only a UE uses, in a traffic flow aggregate (TS 24.008 §10.5.6.12)";
    /// Sender check: the value re-encodes unchanged and does not use
    /// "Ignore this IE", which only a UE uses, in a traffic flow
    /// aggregate (TS 24.008 §10.5.6.12).
    pub fn is_well_formed(&self) -> bool {
        Tft::from_bytes_strict(&self.value).is_some_and(|tft| tft.operation != TftOperation::Ignore)
    }
}

impl TrafficFlowAggregateDescription {
    /// Parse a traffic flow aggregate under the receiver rules; new
    /// filters may repeat the identifier 0.
    pub fn tft(&self) -> Option<Tft> {
        self.parse_tft().ok()
    }

    /// Parse this IE, classifying any error by ESM cause.
    pub fn parse_tft(&self) -> core::result::Result<Tft, TftError> {
        Tft::parse_mode(&self.value, true)
    }

    /// Build a UE traffic flow aggregate from packet filters and parameters.
    pub fn from_tft(tft: &Tft) -> core::result::Result<Self, ValueError> {
        let value = tft.to_bytes_mode(true)?;
        sized("traffic-flow-aggregate", "octets", value.len(), 1, 255)?;
        Ok(Self::new(value))
    }

    /// The value a UE sends when the IE serves no purpose: "Ignore this IE".
    pub fn ignore() -> Self {
        Self::new(vec![0x00])
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "the value re-encodes unchanged, and new filters use identifier 0 (§9.9.4.15)";
    /// Sender check: the value re-encodes unchanged, and new filters use
    /// identifier 0 (§9.9.4.15).
    pub fn is_well_formed(&self) -> bool {
        self.tft()
            .and_then(|tft| tft.to_bytes_mode(true).ok())
            .is_some_and(|value| value == self.value)
    }
}

pub use crate::common::ts24008::{GprsTimer3Unit, GprsTimerUnit};

pub use crate::common::ts24008::GprsTimerValue;
use crate::common::ts24008::gprs_timer_ie;

gprs_timer_ie!(T3412Value, true);

/// Receiver interpretation of the T3412 extended value (TS 24.008 Table
/// 10.5.163a NOTE 1 and NOTE 2, TS 24.301 §5.3.5).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum T3412ExtendedTimer {
    /// Unit 111: the IE is treated as not included; use the T3412 value IE.
    NotIncluded,
    /// Timer value 0: T3412 is deactivated.
    Deactivated,
    /// T3412 runs for this many seconds.
    Seconds(u64),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum T3412ExtendedTimer {
        NotIncluded,
        Deactivated,
        Seconds(u64),
    }
);
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(T3412ExtendedTimer);

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl T3412ExtendedValue (value) "10.5.7.4a" octets 1 {
        unit "Unit": 0 6 3 as GprsTimer3Unit,
        timer_value "Timer value": 0 1 5,
    }
}
crate::common::field_table::table_ie!(T3412ExtendedValue, octets, 1..=1, receives 1);

impl T3412ExtendedValue {
    /// Unit and value of the first value octet; extra octets are ignored.
    pub fn timer(&self) -> Option<(GprsTimer3Unit, u8)> {
        let octet = *self.value.first()?;
        Some((
            GprsTimer3Unit::from_value(octet >> 5).effective(),
            octet & 0x1f,
        ))
    }

    /// Value as interpreted by the UE: unit 110 means 320 hours when the
    /// carrying message is integrity protected and 1 hour otherwise.
    pub fn value_for_ue(&self, integrity_protected: bool) -> Option<T3412ExtendedTimer> {
        let (unit, value) = self.timer()?;
        Some(match unit {
            GprsTimer3Unit::Deactivated => T3412ExtendedTimer::NotIncluded,
            _ if value == 0 => T3412ExtendedTimer::Deactivated,
            GprsTimer3Unit::ThreeHundredTwentyHours if !integrity_protected => {
                T3412ExtendedTimer::Seconds(3_600 * u64::from(value))
            }
            unit => T3412ExtendedTimer::Seconds(unit.seconds_multiplier() * u64::from(value)),
        })
    }

    /// Value as interpreted by the network, for which unit 110 is 320 hours.
    pub fn value_for_network(&self) -> Option<T3412ExtendedTimer> {
        self.value_for_ue(true)
    }

    /// Duration in seconds for the UE, or `None` when deactivated, treated
    /// as not included, or missing.
    pub fn to_seconds_with_integrity(&self, integrity_protected: bool) -> Option<u64> {
        match self.value_for_ue(integrity_protected)? {
            T3412ExtendedTimer::Seconds(seconds) => Some(seconds),
            _ => None,
        }
    }

    /// Build from a unit and a timer value of 0 to 31. The value is kept as
    /// it is given with any unit, the "deactivated" one too: the clause gives
    /// those bits no meaning then.
    pub fn from_unit_value(
        unit: GprsTimer3Unit,
        value: u8,
    ) -> core::result::Result<Self, ValueError> {
        within("timer-value", value, 0, 31)?;
        Ok(Self::new(vec![(u8::from(unit)) << 5 | value]))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "exactly one value octet, not using the deactivated unit (TS 24.008 Table 10.5.163a, NOTE 2)";
    /// Sender check: exactly one value octet, not using the deactivated unit
    /// (TS 24.008 Table 10.5.163a, NOTE 2).
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 1 && self.unit() != GprsTimer3Unit::Deactivated
    }
}

impl IdentityType2 {
    /// The requested identity (TS 24.008 §10.5.5.9), reading the values
    /// that table 10.5.142 does not define as IMSI.
    pub fn identity_type(&self) -> IdentityType {
        self.identity_type_strict().unwrap_or(IdentityType::Imsi)
    }

    /// The requested identity, only for a value of table 10.5.142: IMSI,
    /// IMEI, IMEISV or TMSI.
    pub fn identity_type_strict(&self) -> Option<IdentityType> {
        match IdentityType::try_from(self.value & 7) {
            Ok(
                kind @ (IdentityType::Imsi
                | IdentityType::Imei
                | IdentityType::Imeisv
                | IdentityType::Tmsi),
            ) => Some(kind),
            _ => None,
        }
    }

    /// Raw three-bit identity type, preserving unknown codes.
    pub fn identity_type_raw(&self) -> u8 {
        self.value & 7
    }

    /// The request of the identity `identity_type`, with the spare bit
    /// cleared: an IMSI, an IMEI, an IMEISV or a TMSI.
    pub fn from_identity_type(
        identity_type: IdentityType,
    ) -> core::result::Result<Self, ValueError> {
        match identity_type {
            IdentityType::Imsi | IdentityType::Imei | IdentityType::Imeisv | IdentityType::Tmsi => {
                Ok(Self::new(identity_type as u8))
            }
            other => {
                let expected = "an IMSI (1), an IMEI (2), an IMEISV (3) or a TMSI (4)";
                Err(ValueError::value("identity-type", other as u8, expected))
            }
        }
    }
}

pub use crate::common::ts24008::ImeisvRequestValue;

oxirush_utils::named_values! {
    /// EPS PDN connectivity request type (TS 24.008 §10.5.6.17).
    pub enum RequestTypeValue "§10.5.6.17" bits 3 {
        1 Initial "initial" tree "initial",
        2 Handover "handover" tree "handover",
        3 Rlos "rlos" tree "rlos",
        4 Emergency "emergency" tree "emergency",
        6 EmergencyHandover "emergency handover" tree "emergency-handover",
    }
}
crate::common::enums::values_readable!(RequestTypeValue);

impl RequestType {
    /// Decode a defined request type, leaving reserved values untyped.
    ///
    /// The value as the IE has it: `name()` says whether the table names it.
    pub fn request_type(&self) -> RequestTypeValue {
        RequestTypeValue::from_value(self.value & 0x07)
    }

    /// Raw request type (bits 3-1).
    pub fn request_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Whether the request is for emergency bearer services.
    pub fn is_emergency(&self) -> bool {
        matches!(
            self.request_type(),
            RequestTypeValue::Emergency | RequestTypeValue::EmergencyHandover
        )
    }

    /// Construct a sender value with the spare bit cleared.
    pub fn from_request_type(request_type: RequestTypeValue) -> Self {
        Self::new(u8::from(request_type))
    }

    /// Set the request type and clear the spare bit.
    pub fn set_request_type(&mut self, request_type: RequestTypeValue) -> &mut Self {
        self.value = u8::from(request_type);
        self
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl EsmInformationTransferFlag (value) "9.9.4.5" octets 1 {
        is_required "EIT value": 0 1 1,
    }
}
crate::common::field_table::table_ie!(EsmInformationTransferFlag, octet, 1..=1, receives 1);

impl EsmInformationTransferFlag {
    /// Construct the EIT value with spare bits clear.
    pub fn from_required(required: bool) -> Self {
        Self::new(u8::from(required))
    }
}

oxirush_utils::named_values! {
    /// CS location services indicator (TS 24.301 §9.9.3.12A, octet 3 bits 5-4).
    pub enum CsLcsSupport "§9.9.3.12A" bits 2 {
        0 NoInformation "no information" tree "no-information",
        1 Supported "supported" tree "supported",
        2 NotSupported "not supported" tree "not-supported",
    }
}
crate::common::enums::values_readable!(CsLcsSupport);

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl EpsNetworkFeatureSupport (value) "9.9.3.12A" octets 3 {
        cs_lcs "CS-LCS": 0 4 2 as CsLcsSupport,
        ims_vops "IMS VoPS": 0 1 1,
        emc_bs "EMC BS": 0 2 1,
        epc_lcs "EPC-LCS": 0 3 1,
        esr_ps "ESR PS": 0 6 1,
        erw_opdn "ERw/oPDN": 0 7 1,
        cp_ciot "CP CIoT": 0 8 1,
        up_ciot "UP CIoT": 1 1 1,
        s1u_data "S1-U data": 1 2 1,
        hc_cp_ciot "HC-CP CIoT": 1 3 1,
        epco "ePCO": 1 4 1,
        restrict_ec "RestrictEC": 1 5 1,
        restrict_dcnr "RestrictDCNR": 1 6 1,
        iwk_n26 "IWKN26": 1 7 1,
        fifteen_bearers "15 bearers": 1 8 1,
        ncr "NCR": 2 1 1,
        piv "PIV": 2 2 1,
        rpr "RPR": 2 3 1,
        pr "PR": 2 4 1,
        ptcc "PTCC": 2 5 1,
        edc "EDC": 2 6 1,
        ohr_cp_ciot "OHR-CP CIoT": 2 7 1,
    }
}
crate::common::field_table::table_ie!(EpsNetworkFeatureSupport, octets, 1..=3, receives 0, trailing);

impl Default for EpsNetworkFeatureSupport {
    /// One octet with no feature indicated.
    fn default() -> Self {
        Self::new(vec![0])
    }
}

impl EpsNetworkFeatureSupport {
    /// S1-U data transfer as interpreted by the UE: supported when control
    /// plane CIoT EPS optimization is not indicated.
    pub fn s1u_data_supported(&self) -> bool {
        !self.cp_ciot() || self.s1u_data()
    }

    /// Overhead reduction as interpreted by the UE: ignored when control
    /// plane CIoT EPS optimization is not indicated.
    pub fn ohr_cp_ciot_supported(&self) -> bool {
        self.cp_ciot() && self.ohr_cp_ciot()
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "1 to 3 octets, no reserved CS-LCS value, spare bit clear";
    /// Sender check: 1 to 3 octets, no reserved CS-LCS value, spare bit clear.
    pub fn is_well_formed(&self) -> bool {
        (1..=3).contains(&self.value.len())
            && self.cs_lcs().name().is_some()
            && self.spare_bits_are_zero()
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl ReAttemptIndicator (value) "10.5.6.5a" octets 1 {
        ratc_not_allowed "RATC-NOT-ALLOWED": 0 1 1,
        eplmnc_not_allowed "EPLMNC-NOT-ALLOWED": 0 2 1,
    }
}
crate::common::field_table::table_ie!(ReAttemptIndicator, octets, 1..=1, receives 0, trailing);

impl ReAttemptIndicator {
    /// Build from the two restriction flags with spare bits clear.
    pub fn from_flags(eplmnc_not_allowed: bool, ratc_not_allowed: bool) -> Self {
        Self::new(vec![
            (u8::from(eplmnc_not_allowed) << 1) | u8::from(ratc_not_allowed),
        ])
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "one octet with the spare bits clear";
    /// Sender check: one octet with the spare bits clear.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [octet] if octet & 0xfc == 0)
    }
}

pub use crate::common::ts24008::{Pco, PcoDirection, PcoEntry};

pub use crate::common::ts24301::DownlinkDataExpected;
pub use crate::common::ts24301::{IpHdrCompAdditionalSetupType, IpHdrCompProfiles};
crate::common::ts24301::header_compression_configuration_ie!(HeaderCompressionConfiguration);

impl HeaderCompressionConfigurationStatus {
    /// Whether the header compression configuration of EBI 1 to 15 is used
    /// (bit clear, §9.9.4.27); `None` for other EBIs or a missing octet.
    pub fn is_configuration_used(&self, ebi: u8) -> Option<bool> {
        if !(1..=15).contains(&ebi) {
            return None;
        }
        let octet = self.value.get(usize::from(ebi / 8))?;
        Some(octet >> (ebi % 8) & 1 == 0)
    }

    /// EBIs whose configuration is not used. The spare EBI(0) bit and octets
    /// after the second are ignored.
    pub fn not_used_ebis(&self) -> Vec<u8> {
        (1..=15)
            .filter(|&ebi| self.is_configuration_used(ebi) == Some(false))
            .collect()
    }

    /// Build from the EBIs whose configuration is not used, each 1 to 15.
    pub fn from_not_used_ebis(ebis: &[u8]) -> core::result::Result<Self, ValueError> {
        let mut value = [0u8; 2];
        for (entry, &ebi) in ebis.iter().enumerate() {
            within("eps-bearer-identity", ebi, 1, 15).map_err(|error| error.at(entry))?;
            value[usize::from(ebi / 8)] |= 1 << (ebi % 8);
        }
        Ok(Self::new(value))
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "two octets with the spare EBI(0) bit clear";
    /// Sender check: two octets with the spare EBI(0) bit clear.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 2 && self.value[0] & 0x01 == 0
    }
}

oxirush_utils::named_values! {
    /// Additional result for combined attach or tracking-area update (§9.9.3.0A).
    pub enum AdditionalUpdateResultValue "§9.9.3.0A" bits 2 {
        0 NoAdditionalInformation "no additional information" tree "no-additional-information",
        1 CsFallbackNotPreferred "cs fallback not preferred" tree "cs-fallback-not-preferred",
        2 SmsOnly "sms only" tree "sms-only",
    }
}
crate::common::enums::values_readable!(AdditionalUpdateResultValue);

impl AdditionalUpdateResult {
    /// Typed additional update result (bits 1–2).
    pub fn result(&self) -> Option<AdditionalUpdateResultValue> {
        AdditionalUpdateResultValue::named(self.value & 0x03)
    }

    /// Raw result bits, including the reserved value.
    pub fn result_raw(&self) -> u8 {
        self.value & 0x03
    }

    /// Build with spare bits clear.
    pub fn from_result(result: AdditionalUpdateResultValue) -> Self {
        Self::new(u8::from(result))
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl TmsiStatus (value) "" octets 1 {
        has_valid_tmsi "HAS-VALID-TMSI": 0 1 1,
    }
}
crate::common::field_table::table_ie!(TmsiStatus, octet, 1..=1, receives 1);

impl TmsiStatus {
    /// Build with spare bits clear.
    pub fn from_valid_tmsi(valid: bool) -> Self {
        Self::new(u8::from(valid))
    }
}

oxirush_utils::named_values! {
    /// Radio priority level (TS 24.008 §10.5.7.2).
    pub enum RadioPriorityLevel "§10.5.7.2" bits 3 others as 4 {
        1 One "one" tree "one",
        2 Two "two" tree "two",
        3 Three "three" tree "three",
        4 Four "four" tree "four",
    }
}
crate::common::enums::values_readable!(RadioPriorityLevel);

impl RadioPriority {
    /// Effective priority level, including the specified receive fallback.
    pub fn priority_level(&self) -> RadioPriorityLevel {
        RadioPriorityLevel::from_value(self.value & 0x07).effective()
    }

    /// Raw three-bit priority value.
    pub fn priority_level_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Build with spare bit clear.
    pub fn from_priority_level(level: RadioPriorityLevel) -> Self {
        Self::new(u8::from(level))
    }

    /// Set the priority level and clear the spare bit.
    pub fn set_priority_level(&mut self, level: RadioPriorityLevel) -> &mut Self {
        self.value = u8::from(level);
        self
    }
}

oxirush_utils::named_values! {
    /// Type-of-number values for the CLI calling-party number.
    pub enum CallingPartyTypeOfNumber "" bits 3 {
        0 Unknown "unknown" tree "unknown",
        1 International "international" tree "international",
        2 National "national" tree "national",
        3 NetworkSpecific "network specific" tree "network-specific",
        4 DedicatedAccessShortCode "dedicated access short code" tree "dedicated-access-short-code",
    }
}
crate::common::enums::values_readable!(CallingPartyTypeOfNumber);

oxirush_utils::named_values! {
    /// Numbering-plan values for the CLI calling-party number.
    pub enum CallingPartyNumberingPlan "" bits 4 {
        0 Unknown "unknown" tree "unknown",
        1 Isdn "isdn" tree "isdn",
        3 Data "data" tree "data",
        4 Telex "telex" tree "telex",
        8 National "national" tree "national",
        9 Private "private" tree "private",
    }
}
crate::common::enums::values_readable!(CallingPartyNumberingPlan);

oxirush_utils::named_values! {
    /// Presentation indicator in CLI octet 3a.
    pub enum CallingPartyPresentation "" bits 2 {
        0 Allowed "allowed" tree "allowed",
        1 Restricted "restricted" tree "restricted",
        2 Unavailable "unavailable" tree "unavailable",
    }
}
crate::common::enums::values_readable!(CallingPartyPresentation);

oxirush_utils::named_values! {
    /// Screening indicator in CLI octet 3a.
    pub enum CallingPartyScreening "" bits 8 {
        0 UserProvidedNotScreened "user provided not screened" tree "user-provided-not-screened",
        1 UserProvidedVerifiedPassed "user provided verified passed" tree "user-provided-verified-passed",
        2 UserProvidedVerifiedFailed "user provided verified failed" tree "user-provided-verified-failed",
        3 NetworkProvided "network provided" tree "network-provided",
    }
}
crate::common::enums::values_readable!(CallingPartyScreening);

/// Calling party BCD number carried by the CLI IE (TS 24.301 §9.9.3.38,
/// TS 24.008 §10.5.4.9).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingPartyNumber {
    /// Type of number (octet 3, bits 7-5).
    pub type_of_number: u8,
    /// Numbering plan identification (octet 3, bits 4-1).
    pub numbering_plan: u8,
    /// Presentation and screening indicators of octet 3a; when absent, the
    /// receiver assumes "presentation allowed" and "user provided, not
    /// screened".
    pub presentation_screening: Option<(u8, u8)>,
    /// Number digits: `0`-`9`, `*`, `#`, `a`, `b`, and `c`.
    pub digits: String,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct CallingPartyNumber { type_of_number, numbering_plan, presentation_screening, digits });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(CallingPartyNumber);

impl CallingPartyNumber {
    /// The value of its members, in their order. A later version may add a
    /// member that this leaves at its default.
    pub fn new(
        type_of_number: u8,
        numbering_plan: u8,
        presentation_screening: Option<(u8, u8)>,
        digits: String,
    ) -> Self {
        Self {
            type_of_number,
            numbering_plan,
            presentation_screening,
            digits,
        }
    }
}

impl CallingPartyNumber {
    /// Typed type-of-number value.
    pub fn type_of_number_value(&self) -> Option<CallingPartyTypeOfNumber> {
        CallingPartyTypeOfNumber::named(self.type_of_number)
    }

    /// Typed numbering-plan value.
    pub fn numbering_plan_value(&self) -> Option<CallingPartyNumberingPlan> {
        CallingPartyNumberingPlan::named(self.numbering_plan)
    }

    /// Typed presentation and screening values.
    pub fn presentation_screening_values(
        &self,
    ) -> Option<(CallingPartyPresentation, CallingPartyScreening)> {
        let (presentation, screening) = self.presentation_screening?;
        Some((
            CallingPartyPresentation::named(presentation)?,
            CallingPartyScreening::named(screening)?,
        ))
    }
}

impl Cli {
    /// Typed calling party number; spare bits are ignored.
    pub fn number(&self) -> Option<CallingPartyNumber> {
        let (&first, rest) = self.value.split_first()?;
        let (presentation_screening, digits) = match rest.split_first() {
            Some((&octet, digits)) if first & 0x80 == 0 => {
                (Some(((octet >> 5) & 0x03, octet & 0x03)), digits)
            }
            _ => (None, rest),
        };
        Some(CallingPartyNumber {
            type_of_number: (first >> 4) & 0x07,
            numbering_plan: first & 0x0f,
            presentation_screening,
            digits: crate::common::ts24008::decode_number_digits(digits),
        })
    }

    /// Receiver-side structural check for the extension chain, defined code
    /// points, and canonical BCD endmark placement; spare bits are ignored.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        let Some((&first, rest)) = self.value.split_first() else {
            return false;
        };
        if CallingPartyTypeOfNumber::named((first >> 4) & 0x07).is_none()
            || CallingPartyNumberingPlan::named(first & 0x0f).is_none()
        {
            return false;
        }
        let digits = if first & 0x80 == 0 {
            let Some((&second, digits)) = rest.split_first() else {
                return false;
            };
            // Bits 5 to 3 of octet 3a are spare and ignored on receipt.
            if second & 0x80 == 0 || CallingPartyPresentation::named((second >> 5) & 0x03).is_none()
            {
                return false;
            }
            digits
        } else {
            rest
        };
        digits.is_empty() || crate::common::ts24008::number_digits_are_well_formed(digits)
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "at most 12 octets of BCD digits as TS 24.008 §10.5.4.9 writes them, the spare bits clear";
    /// Strict network-sender check, including spare bits and TON digit
    /// restrictions.
    pub fn is_well_formed(&self) -> bool {
        if !self.receiver_syntax_is_valid()
            || self.value.len() > 12
            || self.value[0] & 0x80 == 0 && self.value[1] & 0x1c != 0
        {
            return false;
        }
        let Some(number) = self.number() else {
            return false;
        };
        !matches!(
            number.type_of_number_value(),
            Some(CallingPartyTypeOfNumber::International | CallingPartyTypeOfNumber::National)
        ) || number.digits.bytes().all(|digit| digit.is_ascii_digit())
    }

    /// Build from a typed number: codes of Table 10.5.118 and 10.5.120 of
    /// TS 24.008, digits of its alphabet, and 12 value octets at most.
    pub fn from_number(number: &CallingPartyNumber) -> core::result::Result<Self, ValueError> {
        let defined = "a code of TS 24.008 Table 10.5.118";
        if number.type_of_number_value().is_none() {
            return Err(ValueError::value(
                "type-of-number",
                number.type_of_number,
                defined,
            ));
        }
        if number.numbering_plan_value().is_none() {
            return Err(ValueError::value(
                "numbering-plan",
                number.numbering_plan,
                defined,
            ));
        }
        if matches!(
            number.type_of_number_value(),
            Some(CallingPartyTypeOfNumber::International | CallingPartyTypeOfNumber::National)
        ) {
            let wrong = number.digits.chars().find(|digit| !digit.is_ascii_digit());
            if let Some(wrong) = wrong {
                let digits = "decimal digits in an international or a national number";
                return Err(ValueError::character("digits", wrong, digits));
            }
        }
        let mut value = vec![number.type_of_number << 4 | number.numbering_plan];
        if let Some((presentation, screening)) = number.presentation_screening {
            let defined = "a code of TS 24.008 Table 10.5.120";
            if CallingPartyPresentation::named(presentation).is_none() {
                return Err(ValueError::value("presentation", presentation, defined));
            }
            if CallingPartyScreening::named(screening).is_none() {
                return Err(ValueError::value("screening", screening, defined));
            }
            value.push(0x80 | presentation << 5 | screening);
        } else {
            value[0] |= 0x80;
        }
        if !number.digits.is_empty() {
            value.extend(crate::common::ts24008::encode_number_digits(
                "digits",
                &number.digits,
            )?);
        }
        sized("cli", "octets", value.len(), 1, 12)?;
        Ok(Self::new(value))
    }
}

impl DcnId {
    /// The 16-bit DCN-ID (TS 24.008 §10.5.5.35); extra octets are ignored.
    pub fn dcn_id(&self) -> Option<u16> {
        let [high, low] = *self.value.first_chunk::<2>()?;
        Some(u16::from_be_bytes([high, low]))
    }

    /// Build from a DCN-ID.
    pub fn from_dcn_id(dcn_id: u16) -> Self {
        Self::new(dcn_id.to_be_bytes())
    }
}

oxirush_utils::named_values! {
    /// NB-S1 mode DRX value, the DRX cycle parameter T (TS 24.301 Table
    /// 9.9.3.63.1). T = 1024 is 0110 here but 0111 in the 5GS NB-N1 IE.
    pub enum NbS1DrxValue "" bits 4 others as 0 {
        0 NotSpecified "not specified" tree "not-specified",
        1 T32 "t32" tree "t32",
        2 T64 "t64" tree "t64",
        3 T128 "t128" tree "t128",
        4 T256 "t256" tree "t256",
        5 T512 "t512" tree "t512",
        6 T1024 "t1024" tree "t1024",
    }
}
crate::common::enums::values_readable!(NbS1DrxValue);

/// NB-S1 DRX parameter (TS 24.301 §9.9.3.63).
impl NbS1DrxParameter {
    /// DRX value with the receive fallback; spare bits are ignored.
    pub fn drx_value(&self) -> Option<NbS1DrxValue> {
        self.value
            .first()
            .map(|&octet| NbS1DrxValue::from_value(octet & 0x0f).effective())
    }

    /// Raw DRX value (bits 4-1).
    pub fn drx_value_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x0f)
    }

    /// Build from a DRX value with the spare bits clear.
    pub fn from_drx_value(value: NbS1DrxValue) -> Self {
        Self::new(vec![u8::from(value)])
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "one octet with a defined value";
    /// Sender check: one octet with a defined value.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [octet] if *octet <= 6)
    }
}

/// IMSI offset (TS 24.301 §9.9.3.64).
impl ImsiOffset {
    /// The 16-bit IMSI offset; extra octets are ignored.
    pub fn imsi_offset(&self) -> Option<u16> {
        let [high, low] = *self.value.first_chunk::<2>()?;
        Some(u16::from_be_bytes([high, low]))
    }

    /// Build from an IMSI offset.
    pub fn from_imsi_offset(offset: u16) -> Self {
        Self::new(offset.to_be_bytes())
    }
}

oxirush_utils::named_values! {
    /// Notification indicator value (TS 24.301 Table 9.9.4.7A.1).
    pub enum NotificationIndicatorValue "Table 9.9.4.7A.1" bits 8 {
        1 SrvccHandoverCancelledImsSessionReestablishmentRequired "srvcc handover cancelled ims session reestablishment required" tree "srvcc-handover-cancelled-ims-session-reestablishment-required",
    }
}
crate::common::enums::values_readable!(NotificationIndicatorValue);

impl NotificationIndicator {
    /// Typed indicator; unused and reserved values return `None`.
    pub fn indicator(&self) -> Option<NotificationIndicatorValue> {
        match self.value.first()? {
            1 => Some(
                NotificationIndicatorValue::SrvccHandoverCancelledImsSessionReestablishmentRequired,
            ),
            _ => None,
        }
    }

    /// Raw indicator octet.
    pub fn indicator_raw(&self) -> Option<u8> {
        self.value.first().copied()
    }

    /// Whether the UE ignores the value: 0x02 to 0x7F are unused.
    pub fn is_ignorable(&self) -> bool {
        self.indicator_raw()
            .is_some_and(|value| (0x02..=0x7f).contains(&value))
    }

    /// Build from a typed indicator.
    pub fn from_indicator(indicator: NotificationIndicatorValue) -> Self {
        Self::new(vec![u8::from(indicator)])
    }
}

/// Packet flow identifier value (TS 24.008 Table 10.5.161).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketFlowId {
    /// Best effort (0).
    BestEffort,
    /// Signalling (1).
    Signalling,
    /// SMS (2).
    Sms,
    /// TOM8 (3).
    Tom8,
    /// Dynamically assigned value 8 to 127.
    Dynamic(u8),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum PacketFlowId {
        BestEffort,
        Signalling,
        Sms,
        Tom8,
        Dynamic(u8),
    }
);
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(PacketFlowId);

impl PacketFlowId {
    /// Decode bits 7-1; the reserved values 4 to 7 return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x7f {
            0 => Some(Self::BestEffort),
            1 => Some(Self::Signalling),
            2 => Some(Self::Sms),
            3 => Some(Self::Tom8),
            4..=7 => None,
            dynamic => Some(Self::Dynamic(dynamic)),
        }
    }

    /// Wire value; `None` for a dynamic value outside 8 to 127.
    pub fn as_u8(self) -> Option<u8> {
        match self {
            Self::BestEffort => Some(0),
            Self::Signalling => Some(1),
            Self::Sms => Some(2),
            Self::Tom8 => Some(3),
            Self::Dynamic(value) => (8..=127).contains(&value).then_some(value),
        }
    }
}

impl PacketFlowIdentifier {
    /// Typed PFI; the spare bit is ignored and reserved values return `None`.
    pub fn pfi(&self) -> Option<PacketFlowId> {
        PacketFlowId::from_u8(*self.value.first()?)
    }

    /// Raw PFI (bits 7-1).
    pub fn pfi_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x7f)
    }

    /// Build from a typed PFI: a dynamic value is 8 to 127.
    pub fn from_pfi(pfi: PacketFlowId) -> core::result::Result<Self, ValueError> {
        match (pfi, pfi.as_u8()) {
            (_, Some(octet)) => Ok(Self::new(vec![octet])),
            (PacketFlowId::Dynamic(value), None) => {
                Err(ValueError::range("packet-flow-identifier", value, 8, 127))
            }
            (_, None) => Err(ValueError::range("packet-flow-identifier", 0, 0, 127)),
        }
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "one octet, spare bit clear, and not a reserved value";
    /// Sender check: one octet, spare bit clear, and not a reserved value.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [octet] if octet & 0x80 == 0) && self.pfi().is_some()
    }
}

impl TransactionIdentifier {
    /// TI flag (octet 3, bit 8): set when the message is sent to the side
    /// that originated the TI (TS 24.007 §11.2.3.1.3).
    pub fn ti_flag(&self) -> Option<bool> {
        self.value.first().map(|octet| octet & 0x80 != 0)
    }

    /// TI value: TIE when the extension octet is present, otherwise TIO.
    /// `None` for TIO 7 without an extension, or a reserved TIE of 0 to 6.
    pub fn ti_value(&self) -> Option<u8> {
        match self.value.as_slice() {
            [_, extension, ..] => Some(extension & 0x7f).filter(|&tie| tie >= 7),
            [octet] => Some((octet >> 4) & 0x07).filter(|&tio| tio != 7),
            [] => None,
        }
    }

    /// Build a TI; values 7 to 127 use the extension octet.
    pub fn from_ti(flag: bool, value: u8) -> core::result::Result<Self, ValueError> {
        let flag = u8::from(flag) << 7;
        match value {
            0..=6 => Ok(Self::new(vec![flag | value << 4])),
            7..=127 => Ok(Self::new(vec![flag | 0x70, 0x80 | value])),
            _ => Err(ValueError::range("ti-value", value, 0, 127)),
        }
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "spare bits clear, and the extension octet used only for TI values of 7 or greater";
    /// Sender check: spare bits clear, and the extension octet used only
    /// for TI values of 7 or greater.
    pub fn is_well_formed(&self) -> bool {
        match (self.ti_flag(), self.ti_value()) {
            (Some(flag), Some(value)) => {
                Self::from_ti(flag, value).is_ok_and(|ti| ti.value == self.value)
            }
            _ => false,
        }
    }
}

impl UeRadioCapabilityIdAvailability {
    /// Whether a UE radio capability ID is available; values other than 1
    /// are read as "not available" (Table 9.9.3.58.1).
    pub fn is_available(&self) -> Option<bool> {
        self.value.first().map(|octet| octet & 0x07 == 1)
    }

    /// Build with the spare bits clear.
    pub fn from_available(available: bool) -> Self {
        Self::new(vec![u8::from(available)])
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl UeRadioCapabilityIdRequest (value) "9.9.3.65" octets 1 {
        is_requested "URCIDR": 0 1 1,
    }
}
crate::common::field_table::table_ie!(UeRadioCapabilityIdRequest, octets, 1..=1, receives 1);

impl UeRadioCapabilityIdRequest {
    /// Build with the spare bits clear.
    pub fn from_requested(requested: bool) -> Self {
        Self::new(vec![u8::from(requested)])
    }
}

/// Location area identification (TS 24.008 §10.5.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lai {
    /// PLMN identity.
    pub plmn: Plmn,
    /// Location area code.
    pub lac: u16,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct Lai { plmn as plmn, lac });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(Lai);

impl LocationAreaIdentification {
    /// Typed LAI; `None` for a PLMN that does not decode, which the
    /// network treats as a deleted LAI.
    pub fn lai(&self) -> Option<Lai> {
        let value = self.value.get(..5)?;
        Some(Lai {
            plmn: crate::common::plmn_at(&value[..3])?,
            lac: u16::from_be_bytes([value[3], value[4]]),
        })
    }

    /// Build from a typed LAI.
    pub fn from_lai(lai: Lai) -> Self {
        let mut value = lai.plmn.to_nas_octets().to_vec();
        value.extend_from_slice(&lai.lac.to_be_bytes());
        Self::new(value)
    }
}

// ── Nonces, signatures, and hashes (TS 24.301 §9.9.3.25, §9.9.3.26, §9.9.3.50) ──

impl Nonce {
    /// The 32-bit nonce; `None` unless four octets are present.
    pub fn nonce(&self) -> Option<u32> {
        Some(u32::from_be_bytes(self.value.as_slice().try_into().ok()?))
    }

    /// Build from a 32-bit nonce.
    pub fn from_nonce(nonce: u32) -> Self {
        Self::new(nonce.to_be_bytes())
    }

    /// Replace the nonce.
    pub fn set_nonce(&mut self, nonce: u32) {
        self.value = nonce.to_be_bytes().to_vec().into();
    }
}

impl PTmsiSignature {
    /// The 24-bit P-TMSI signature (TS 24.008 §10.5.5.8).
    pub fn p_tmsi_signature(&self) -> Option<u32> {
        match self.value.as_slice() {
            [high, middle, low] => Some(u32::from_be_bytes([0, *high, *middle, *low])),
            _ => None,
        }
    }

    /// Build from a signature of 24 bits.
    pub fn from_p_tmsi_signature(signature: u32) -> core::result::Result<Self, ValueError> {
        within("p-tmsi-signature", signature, 0, 0x00ff_ffff)?;
        Ok(Self::new(&signature.to_be_bytes()[1..]))
    }
}

impl HashMme {
    /// The 64-bit HashMME (TS 24.301 §9.9.3.50); octets beyond eight are ignored.
    pub fn hash_mme(&self) -> Option<[u8; 8]> {
        self.value.get(..8)?.try_into().ok()
    }

    /// Build from a 64-bit HashMME.
    pub fn from_hash_mme(hash: [u8; 8]) -> Self {
        Self::new(hash)
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "exactly eight octets";
    /// Sender check: exactly eight octets.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 8
    }
}

// ── UE additional security capability (TS 24.301 §9.9.3.53) ─────────────────

impl UeAdditionalSecurityCapability {
    /// 5G-EA0 to 5G-EA15 as a bitmap with 5G-EA0 in the most significant bit.
    pub fn ea_bits(&self) -> Option<u16> {
        Some(u16::from_be_bytes(self.value.get(..2)?.try_into().ok()?))
    }

    /// 5G-IA0 to 5G-IA15 as a bitmap with 5G-IA0 in the most significant bit.
    pub fn ia_bits(&self) -> Option<u16> {
        Some(u16::from_be_bytes(self.value.get(2..4)?.try_into().ok()?))
    }

    /// Whether 5G-EA`algo` (0 to 15) is supported.
    pub fn supports_ea(&self, algo: u8) -> bool {
        algo <= 15
            && self
                .ea_bits()
                .is_some_and(|bits| bits & (0x8000 >> algo) != 0)
    }

    /// Whether 5G-IA`algo` (0 to 15) is supported.
    pub fn supports_ia(&self, algo: u8) -> bool {
        algo <= 15
            && self
                .ia_bits()
                .is_some_and(|bits| bits & (0x8000 >> algo) != 0)
    }

    /// Build from the encryption and integrity bitmaps.
    pub fn from_capabilities(ea_bits: u16, ia_bits: u16) -> Self {
        let mut value = ea_bits.to_be_bytes().to_vec();
        value.extend_from_slice(&ia_bits.to_be_bytes());
        Self::new(value)
    }

    /// Set 5G-EA`algo` (0 to 15), extending the value to four octets.
    pub fn set_ea(
        &mut self,
        algo: u8,
        supported: bool,
    ) -> core::result::Result<&mut Self, ValueError> {
        within("5g-ea", algo, 0, 15)?;
        self.set_bit(usize::from(algo), supported);
        Ok(self)
    }

    /// Set 5G-IA`algo` (0 to 15), extending the value to four octets.
    pub fn set_ia(
        &mut self,
        algo: u8,
        supported: bool,
    ) -> core::result::Result<&mut Self, ValueError> {
        within("5g-ia", algo, 0, 15)?;
        self.set_bit(16 + usize::from(algo), supported);
        Ok(self)
    }

    fn set_bit(&mut self, index: usize, supported: bool) {
        if self.value.len() < 4 {
            self.value.resize(4, 0);
        }
        let mask = 0x80 >> (index % 8);
        if supported {
            self.value[index / 8] |= mask;
        } else {
            self.value[index / 8] &= !mask;
        }
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "exactly four octets";
    /// Sender check: exactly four octets.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 4
    }
}

// ── MS network capability (TS 24.008 §10.5.5.12) ────────────────────────────

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl MsNetworkCapability (value) "10.5.5.12" octets 8 {
        gea1 "GEA1": 0 8 1,
        sm_dedicated "SM-DEDICATED": 0 7 1,
        sm_gprs "SM-GPRS": 0 6 1,
        ucs2 "UCS2": 0 5 1,
        solsa "SOLSA": 0 2 1,
        revision_level_indicator "REVISION-LEVEL-INDICATOR": 0 1 1,
        pfc "PFC": 1 8 1,
        lcs_va "LCS-VA": 1 1 1,
        ps_ho_utran "PS-HO-UTRAN": 2 8 1,
        ps_ho_eutran "PS-HO-EUTRAN": 2 7 1,
        emm_combined "EMM-COMBINED": 2 6 1,
        isr "ISR": 2 5 1,
        srvcc "SRVCC": 2 4 1,
        epc "EPC": 2 3 1,
        nf "NF": 2 2 1,
        geran_network_sharing "GERAN-NETWORK-SHARING": 2 1 1,
        up_integrity_protection "UP-INTEGRITY-PROTECTION": 3 8 1,
        epco "EPCO": 3 3 1,
        restrict_ec "RESTRICT-EC": 3 2 1,
        dcnr "DCNR": 3 1 1,
    }
}
crate::common::field_table::table_ie!(MsNetworkCapability, octets, 2..=8, receives 0, trailing);

impl MsNetworkCapability {
    /// SS screening indicator (octet 3, bits 4-3).
    pub fn ss_screening_indicator(&self) -> Option<u8> {
        self.value.first().map(|octet| (octet >> 2) & 0x03)
    }

    /// Whether GEA/`algo` (2 to 7) is available (octet 4, bits 7-2).
    pub fn supports_gea(&self, algo: u8) -> bool {
        (2..=7).contains(&algo)
            && self
                .value
                .get(1)
                .is_some_and(|octet| octet & (0x80 >> (algo - 1)) != 0)
    }

    /// Whether GIA/`algo` (4 to 7) is available (octet 6, bits 7-4).
    pub fn supports_gia(&self, algo: u8) -> bool {
        (4..=7).contains(&algo)
            && self
                .value
                .get(3)
                .is_some_and(|octet| octet & (0x80 >> (algo - 3)) != 0)
    }

    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str =
        "2 to 8 octets with GEA/1 clear and trailing spare octets zero";
    /// Sender check: 2 to 8 octets with GEA/1 clear and trailing spare octets zero.
    pub fn is_well_formed(&self) -> bool {
        (2..=8).contains(&self.value.len())
            && !self.gea1()
            && self
                .value
                .get(4..)
                .is_none_or(|spare| spare.iter().all(|&octet| octet == 0))
    }
}

impl MobileStationClassmark3 {
    /// The sender rule that [`Self::is_well_formed`] checks, as `validate()` says it.
    pub(crate) const SENDER_RULE: &'static str = "at most 32 octets";
    /// Sender check: at most 32 octets. The CSN.1 content is not decoded.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() <= 32
    }
}

// ── Replayed NAS message container (TS 24.301 §9.9.3.51) ────────────────────

impl ReplayedNasMessageContainer {
    /// Decode the replayed ATTACH REQUEST or TRACKING AREA UPDATE REQUEST,
    /// which is carried without a NAS security header.
    pub fn decode_as_emm_message(&self) -> crate::common::Result<crate::nas_eps::Message> {
        use crate::nas_eps::{EmmMessage, Message};
        let message = Message::decode(&self.value)?;
        if matches!(
            message,
            Message::Emm(
                _,
                EmmMessage::AttachRequest(_) | EmmMessage::TrackingAreaUpdateRequest(_)
            )
        ) {
            Ok(message)
        } else {
            Err(Error::DecodingError(
                "replayed NAS message container requires a plain ATTACH or TAU REQUEST".into(),
            ))
        }
    }

    /// Build the container from a plain ATTACH REQUEST or TRACKING AREA UPDATE REQUEST.
    pub fn from_emm_message(message: &crate::nas_eps::Message) -> crate::common::Result<Self> {
        use crate::nas_eps::{EmmMessage, Message};
        if !matches!(
            message,
            Message::Emm(
                _,
                EmmMessage::AttachRequest(_) | EmmMessage::TrackingAreaUpdateRequest(_)
            )
        ) {
            return Err(Error::EncodingError(
                "replayed NAS message container requires a plain ATTACH or TAU REQUEST".into(),
            ));
        }
        Ok(Self::new(message.encode()?))
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl AdditionalInformationRequested (value) "9.9.3.55" octets 1 {
        cipher_key_data_requested "CipherKey": 0 1 1,
    }
}
crate::common::field_table::table_ie!(AdditionalInformationRequested, octet, 1..=1, receives 1);

impl AdditionalInformationRequested {
    /// Build with spare bits clear.
    pub fn from_cipher_key_data_requested(requested: bool) -> Self {
        Self::new(u8::from(requested))
    }

    /// Sender check: bits 8 to 2 spare and clear.
    pub fn is_well_formed(&self) -> bool {
        self.value & 0xfe == 0
    }
}

pub use crate::common::ts24301::PreferredCiotBehavior;

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl AdditionalUpdateType (value) "9.9.3.0B" octets 1 {
        sms_only "SMS-ONLY": 0 1 1,
        signalling_active "SIGNALLING-ACTIVE": 0 2 1,
        preferred_ciot_behavior "PREFERRED-CIOT-BEHAVIOR": 0 3 2 as PreferredCiotBehavior,
    }
}
crate::common::field_table::table_ie!(AdditionalUpdateType, octet, 1..=1, receives 1);

impl AdditionalUpdateType {
    /// Build all three fields in one half octet.
    pub fn from_fields(
        sms_only: bool,
        signalling_active: bool,
        ciot: PreferredCiotBehavior,
    ) -> Self {
        Self::new(u8::from(sms_only) | (u8::from(signalling_active) << 1) | ((u8::from(ciot)) << 2))
    }
}

crate::common::ts24301::control_plane_only_indication_ie!(ControlPlaneOnlyIndication);

impl CsfbResponse {
    /// Whether the UE accepted CS fallback paging (§9.9.3.5).
    /// Reserved three-bit values return `None`.
    pub fn accepted(&self) -> Option<bool> {
        match self.value & 0x07 {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// Raw three-bit response value for exact wire preservation.
    pub fn accepted_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Build a response with spare bits clear.
    pub fn from_accepted(accepted: bool) -> Self {
        Self::new(u8::from(accepted))
    }
}

impl ConnectivityType {
    /// Whether the PDN connection is LIPA (TS 24.008 §10.5.6.19).
    /// Other received values indicate that no connection type was supplied.
    pub fn is_lipa(&self) -> bool {
        self.value & 0x0f == 1
    }

    /// Build the LIPA or unspecified connection type.
    pub fn from_lipa(lipa: bool) -> Self {
        Self::new(u8::from(lipa))
    }

    /// Raw connectivity type (bits 4-1).
    pub fn connectivity_type_raw(&self) -> u8 {
        self.value & 0x0f
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl DeviceProperties (value) "10.5.7.8" octets 1 {
        low_priority "Low priority": 0 1 1,
    }
}
crate::common::field_table::table_ie!(DeviceProperties, octet, 1..=1, receives 1);

impl DeviceProperties {
    /// Build with spare bits clear.
    pub fn from_low_priority(low_priority: bool) -> Self {
        Self::new(u8::from(low_priority))
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl WlanOffloadAcceptability (value) "10.5.6.20" octets 1 {
        s1_offload_acceptable "E-UTRAN offload acceptability value": 0 1 1,
        iu_offload_acceptable "UTRAN offload acceptability value": 0 2 1,
    }
}
crate::common::field_table::table_ie!(WlanOffloadAcceptability, octet, 1..=1, receives 1);

impl WlanOffloadAcceptability {
    /// Build from the two access-mode flags with spare bits clear.
    pub fn from_acceptability(s1: bool, iu: bool) -> Self {
        Self::new(u8::from(s1) | (u8::from(iu) << 1))
    }
}

impl LinkedEpsBearerIdentity {
    /// Raw linked EPS bearer identity in bits 1–4 (§9.9.4.6).
    pub fn bearer_identity(&self) -> u8 {
        self.value & 0x0f
    }

    /// EPS bearer identity 1 to 15, or `None` for the reserved value 0.
    pub fn ebi(&self) -> Option<u8> {
        Some(self.bearer_identity()).filter(|&ebi| ebi != 0)
    }

    /// Build a linked bearer identity from 1 through 15.
    pub fn from_bearer_identity(identity: u8) -> core::result::Result<Self, ValueError> {
        within("linked-eps-bearer-identity", identity, 1, 15)?;
        Ok(Self::new(identity))
    }

    /// Set an identity from 1 through 15; an error leaves the IE unchanged.
    pub fn set_bearer_identity(
        &mut self,
        identity: u8,
    ) -> core::result::Result<&mut Self, ValueError> {
        *self = Self::from_bearer_identity(identity)?;
        Ok(self)
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl ExtendedEmmCause (value) "9.9.3.26A" octets 1 {
        eutran_not_allowed "E-UTRAN allowed": 0 1 1,
        eps_optimization_not_supported "EPS optimization info": 0 2 1,
        nb_iot_not_allowed "NB-IoT allowed": 0 3 1,
        satellite_eutran_not_allowed "Satellite E-UTRAN allowed": 0 4 1,
    }
}
crate::common::field_table::table_ie!(ExtendedEmmCause, octet, 1..=1, receives 1);

impl ExtendedEmmCause {
    /// Build all four specified flags.
    pub fn from_flags(eutran: bool, eps_optimization: bool, nb_iot: bool, satellite: bool) -> Self {
        Self::new(
            u8::from(eutran)
                | (u8::from(eps_optimization) << 1)
                | (u8::from(nb_iot) << 2)
                | (u8::from(satellite) << 3),
        )
    }
}

oxirush_utils::named_values! {
    /// Defined generic message container types (§9.9.3.42).
    pub enum GenericMessageContainerTypeValue "§9.9.3.42" bits 8 {
        1 Lpp "lpp" tree "lpp",
        2 Lcs "lcs" tree "lcs",
    }
}
crate::common::enums::values_readable!(GenericMessageContainerTypeValue);

impl GenericMessageContainerType {
    /// Typed container type; reserved and unused values return `None`.
    pub fn container_type(&self) -> Option<GenericMessageContainerTypeValue> {
        GenericMessageContainerTypeValue::named(self.value)
    }

    /// Whether the value is reserved (0 or 128 to 255) rather than unused.
    pub fn is_reserved(&self) -> bool {
        self.value == 0 || self.value >= 128
    }

    /// Build a defined container type.
    pub fn from_container_type(kind: GenericMessageContainerTypeValue) -> Self {
        Self::new(u8::from(kind))
    }

    /// Replace the container type.
    pub fn set_container_type(&mut self, kind: GenericMessageContainerTypeValue) {
        self.value = u8::from(kind);
    }
}

impl LcsIndicator {
    /// Whether the message originated from a mobile-terminated location request (§9.9.3.40).
    pub fn is_mt_lr(&self) -> bool {
        self.value == 1
    }

    /// Build the mobile-terminated location request indication.
    pub fn mt_lr() -> Self {
        Self::new(1)
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl NetworkPolicy (value) "9.9.3.52" octets 1 {
        unsecured_redirection_forbidden "redir-policy": 0 1 1,
    }
}
crate::common::field_table::table_ie!(NetworkPolicy, octet, 1..=1, receives 1);

impl NetworkPolicy {
    /// Build with spare bits clear.
    pub fn from_unsecured_redirection_forbidden(forbidden: bool) -> Self {
        Self::new(u8::from(forbidden))
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl GutiType (value) "9.9.3.45" octets 1 {
        is_mapped "GUTI type": 0 1 1,
    }
}
crate::common::field_table::table_ie!(GutiType, octet, 1..=1, receives 1);

impl GutiType {
    /// Build with spare bits clear.
    pub fn from_mapped(mapped: bool) -> Self {
        Self::new(u8::from(mapped))
    }
}

oxirush_utils::named_values! {
    /// The identity that the network pages with for non-EPS services (Table
    /// 9.9.3.25A.1).
    pub enum PagingIdentityValue "" bits 8 {
        0 Imsi "imsi" tree "imsi",
        1 Tmsi "tmsi" tree "tmsi",
    }
}
crate::common::enums::values_readable!(PagingIdentityValue);

impl PagingIdentity {
    /// The paging identity value of bit 1 (§9.9.3.25A).
    pub fn paging_identity(&self) -> PagingIdentityValue {
        if self.value & 0x01 != 0 {
            PagingIdentityValue::Tmsi
        } else {
            PagingIdentityValue::Imsi
        }
    }

    /// The IE of a paging identity, with the spare bits zero.
    pub fn from_paging_identity(identity: PagingIdentityValue) -> Self {
        Self::new(u8::from(identity))
    }
}

oxirush_utils::named_values! {
    /// Defined SMS service status values (§9.9.3.4B).
    pub enum SmsServicesStatusValue "§9.9.3.4B" bits 3 {
        0 Unavailable "unavailable" tree "unavailable",
        1 UnavailableInPlmn "unavailable in plmn" tree "unavailable-in-plmn",
        2 NetworkFailure "network failure" tree "network-failure",
        3 Congestion "congestion" tree "congestion",
    }
}
crate::common::enums::values_readable!(SmsServicesStatusValue);

impl SmsServicesStatus {
    /// Typed status; values 4–7 are abnormal on reception.
    pub fn status(&self) -> Option<SmsServicesStatusValue> {
        SmsServicesStatusValue::named(self.value & 0x07)
    }

    /// Raw status (bits 3-1).
    pub fn status_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Build a defined status with spare bit clear.
    pub fn from_status(status: SmsServicesStatusValue) -> Self {
        Self::new(u8::from(status))
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl UeInformationRequest (value) "9.9.3.71" octets 1 {
        requested "UCLIR": 0 1 1,
    }
}
crate::common::field_table::table_ie!(UeInformationRequest, octet, 1..=1, receives 1);

impl UeInformationRequest {
    /// Build with spare bits clear.
    pub fn from_requested(requested: bool) -> Self {
        Self::new(u8::from(requested))
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl UeRadioCapabilityInformationUpdateNeeded (value) "9.9.3.35" octets 1 {
        update_needed "URC upd": 0 1 1,
    }
}
crate::common::field_table::table_ie!(UeRadioCapabilityInformationUpdateNeeded, octet, 1..=1, receives 1);

impl UeRadioCapabilityInformationUpdateNeeded {
    /// Build with spare bits clear.
    pub fn from_update_needed(needed: bool) -> Self {
        Self::new(u8::from(needed))
    }
}

impl Default for CipheringKeySequenceNumber {
    /// No key available.
    fn default() -> Self {
        Self::from_no_key()
    }
}

impl CipheringKeySequenceNumber {
    /// Key sequence number in bits 1–3 (TS 24.008 §10.5.1.2).
    /// Value 7 means no key is available in UE-to-network messages.
    pub fn key_sequence_number(&self) -> u8 {
        self.value & 0x07
    }

    /// Key sequence number 0 to 6, or `None` when no key is available.
    pub fn key_sequence_number_strict(&self) -> Option<u8> {
        let value = self.key_sequence_number();
        (value != 7).then_some(value)
    }

    /// Whether no key is available (value 111).
    pub fn no_key_available(&self) -> bool {
        self.key_sequence_number() == 7
    }

    /// Build a three-bit key sequence number with the spare bit clear.
    pub fn from_key_sequence_number(sequence: u8) -> core::result::Result<Self, ValueError> {
        within("key-sequence", sequence, 0, 7)?;
        Ok(Self::new(sequence))
    }

    /// Build the "no key is available" value.
    pub fn from_no_key() -> Self {
        Self::new(7)
    }

    /// Set the key sequence number, which has three bits.
    pub fn set_key_sequence_number(
        &mut self,
        sequence: u8,
    ) -> core::result::Result<(), ValueError> {
        within("key-sequence", sequence, 0, 7)?;
        self.value = sequence;
        Ok(())
    }
}

oxirush_utils::bits! {
    over [crate::common::field_table::Row, field_row]
    impl MsNetworkFeatureSupport (value) "10.5.1.15" octets 1 {
        extended_periodic_timers_supported "extended periodic timers": 0 1 1,
    }
}
crate::common::field_table::table_ie!(MsNetworkFeatureSupport, octet, 1..=1, receives 1);

impl MsNetworkFeatureSupport {
    /// Build with spare bits clear.
    pub fn from_extended_periodic_timers_supported(supported: bool) -> Self {
        Self::new(u8::from(supported))
    }
}

oxirush_utils::named_values! {
    /// LLC SAPI (TS 24.008 Table 10.5.165).
    pub enum LlcSapi "Table 10.5.165" bits 4 {
        0 NotAssigned "not assigned" tree "not-assigned",
        3 Sapi3 "sapi3" tree "sapi3",
        5 Sapi5 "sapi5" tree "sapi5",
        9 Sapi9 "sapi9" tree "sapi9",
        11 Sapi11 "sapi11" tree "sapi11",
    }
}
crate::common::enums::values_readable!(LlcSapi);

impl LlcServiceAccessPointIdentifier {
    /// LLC SAPI in bits 1–4 (TS 24.008 §10.5.6.9).
    pub fn sapi(&self) -> Option<u8> {
        self.llc_sapi().map(u8::from)
    }

    /// Typed LLC SAPI; reserved codes return `None`.
    pub fn llc_sapi(&self) -> Option<LlcSapi> {
        LlcSapi::named(self.value & 0x0f)
    }

    /// Raw LLC SAPI (bits 4-1).
    pub fn sapi_raw(&self) -> u8 {
        self.value & 0x0f
    }

    /// Build an assigned LLC SAPI, or zero for an unassigned SAPI.
    pub fn from_sapi(sapi: u8) -> core::result::Result<Self, ValueError> {
        LlcSapi::named(sapi & 0x0f)
            .filter(|_| sapi <= 0x0f)
            .map(Self::from_llc_sapi)
            .ok_or(ValueError::value(
                "llc-sapi",
                sapi,
                "an assigned SAPI, or 0 for none",
            ))
    }

    /// Build from a typed LLC SAPI with the spare bits clear.
    pub fn from_llc_sapi(sapi: LlcSapi) -> Self {
        Self::new(u8::from(sapi))
    }
}

impl SsCode {
    /// Supplementary service code (TS 24.301 §9.9.3.39).
    pub fn code(&self) -> u8 {
        self.value
    }

    /// Build from the TS 29.002 service code byte.
    pub fn from_code(code: u8) -> Self {
        Self::new(code)
    }
}

// Raw value access for IEs whose counterpart in the other protocol has it.

/// The `Display` of the IEs that have one of their own, which the `Display` of
/// a message shows: a cause by its number and its name, `#22 (Congestion)`; a
/// timer with its unit; RAND, AUTN and AUTS whole, as they travel in clear, and
/// a key by its length alone; an identity whole, as the service based
/// interfaces write it; the message that a container carries.
mod shown {
    use crate::common::display;
    use crate::nas_eps::*;
    use crate::prelude::*;
    use core::fmt;

    // ============================================================================
    // IEs
    // ============================================================================

    /// An EMM cause by its number and its name: `#22 (Congestion)`.
    impl fmt::Display for EmmCause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            display::cause(f, self.value, self.cause().and_then(EmmCauseValue::name))
        }
    }

    /// An ESM cause by its number and its name: `#26 (Insufficient resources)`.
    impl fmt::Display for EsmCause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            display::cause(f, self.value, self.cause().and_then(EsmCauseValue::name))
        }
    }

    /// A NAS key set identifier: `0`, `mapped 3` or `no key`.
    impl fmt::Display for KeySetIdentifier {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.key_set_identifier().fmt(f)
        }
    }

    /// The selected algorithms: `EEA2 EIA2`.
    impl fmt::Display for SecurityAlgorithms {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let (ciphering, integrity) = (self.ciphering_raw(), self.integrity_raw());
            let ciphering = Coded(CipheringAlgorithm::named(ciphering), ciphering);
            let integrity = Coded(IntegrityAlgorithm::named(integrity), integrity);
            write!(f, "{ciphering} {integrity}")
        }
    }

    /// The EPS algorithms of a UE network capability: `EEA0 EEA2 / EIA2`.
    impl fmt::Display for UeNetworkCapability {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let eea = |number| self.supports_eea(number);
            let eia = |number| self.supports_eia(number);
            display::algorithms(f, ("EEA", "EIA"), eea, eia)
        }
    }

    /// The EPS algorithms of a UE security capability: `EEA0 EEA2 / EIA2`.
    impl fmt::Display for UeSecurityCapability {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let eea = |number| self.supports_eea(number);
            let eia = |number| self.supports_eia(number);
            display::algorithms(f, ("EEA", "EIA"), eea, eia)
        }
    }

    /// An EPS mobile identity, whole, as the service based interfaces write
    /// it: `4g-guti-...`, `imsi-...` or `imei-...`. One whose octets do not
    /// read as its type shows them.
    impl fmt::Display for EpsMobileIdentity {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if let Some(guti) = self.as_guti() {
                guti.fmt(f)
            } else if let Some(imsi) = self.as_imsi() {
                write!(f, "imsi-{imsi}")
            } else if let Some(imei) = self.as_imei() {
                write!(f, "imei-{imei}")
            } else {
                let kind = match self.identity_type() {
                    Some(MobileIdentityTypeEps::Guti) => "GUTI",
                    Some(MobileIdentityTypeEps::Imsi) => "IMSI",
                    Some(MobileIdentityTypeEps::Imei) => "IMEI",
                    _ => "identity",
                };
                display::unread_identity(f, kind, &self.value)
            }
        }
    }

    /// A mobile identity of TS 24.008, whole: `imsi-...`, `imei-...`,
    /// `imeisv-...`, `tmsi-c0000001` or `no identity`. One of another type, as
    /// a TMGI, shows its octets.
    impl fmt::Display for MobileIdentity {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            if let Some(imsi) = self.as_imsi() {
                write!(f, "imsi-{imsi}")
            } else if let Some(imei) = self.as_imei() {
                write!(f, "imei-{imei}")
            } else if let Some(imeisv) = self.as_imeisv() {
                write!(f, "imeisv-{imeisv}")
            } else if let Some(tmsi) = self.as_tmsi() {
                write!(f, "tmsi-{tmsi:08x}")
            } else if self.is_no_identity() {
                f.write_str("no identity")
            } else {
                let kind = match self.identity_type_raw() {
                    Some(1) => "IMSI",
                    Some(2) => "IMEI",
                    Some(3) => "IMEISV",
                    Some(4) => "TMSI",
                    Some(5) => "TMGI",
                    _ => "identity",
                };
                display::unread_identity(f, kind, &self.value)
            }
        }
    }

    /// A list of tracking areas: `[208-93-0001, 208-93-0002]`.
    impl fmt::Display for TrackingAreaIdentityList {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let tais: Vec<TaiEps> = (self.entries().iter())
                .flat_map(TaiListEntry::tracking_area_identities)
                .collect();
            match tais.is_empty() {
                true => display::Octets(&self.value).fmt(f),
                false => display::List(&tais).fmt(f),
            }
        }
    }

    /// A tracking area identity: `208-93-0001`.
    impl fmt::Display for TrackingAreaIdentity {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.tai() {
                Some(tai) => tai.fmt(f),
                None => display::Octets(&self.value).fmt(f),
            }
        }
    }

    /// A T3412 value: `9 min`, `deactivated`.
    impl fmt::Display for T3412Value {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.value().fmt(f)
        }
    }

    /// A T3412 extended value, as a UE reads it in an integrity protected
    /// message: `54 min`, `deactivated`, or `not included` for unit 111.
    impl fmt::Display for T3412ExtendedValue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.value_for_ue(true) {
                Some(T3412ExtendedTimer::Seconds(seconds)) => display::Duration(seconds).fmt(f),
                Some(T3412ExtendedTimer::Deactivated) => f.write_str("deactivated"),
                Some(T3412ExtendedTimer::NotIncluded) => f.write_str("not included"),
                None => display::Octets(&self.value).fmt(f),
            }
        }
    }

    /// An access point name: `internet`.
    impl fmt::Display for AccessPointName {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.as_string() {
                Some(name) => f.write_str(&name),
                None => display::Octets(&self.value).fmt(f),
            }
        }
    }

    /// A PDN address: `IPv4 10.0.0.1`, `non-IP`, `Ethernet`.
    impl fmt::Display for PdnAddress {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.pdn_address() {
                Some(PdnAddressValue::Ipv4(ipv4)) => display::address(f, Some(ipv4), None),
                Some(PdnAddressValue::Ipv6InterfaceId(identifier)) => {
                    display::address(f, None, Some(identifier))
                }
                Some(PdnAddressValue::Ipv4v6 {
                    ipv6_interface_id,
                    ipv4,
                }) => display::address(f, Some(ipv4), Some(ipv6_interface_id)),
                Some(PdnAddressValue::NonIp) => f.write_str("non-IP"),
                Some(PdnAddressValue::Ethernet) => f.write_str("Ethernet"),
                None => display::Octets(&self.value).fmt(f),
            }
        }
    }

    /// An APN-AMBR: `DL 100 Mbps UL 50 Mbps`.
    impl fmt::Display for ApnAggregateMaximumBitRate {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            display::rates(f, self.downlink_kbps(), self.uplink_kbps(), &self.value)
        }
    }

    /// An EPS QoS by its QCI: `QCI 9`.
    impl fmt::Display for EpsQualityOfService {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.qos() {
                Some(qos) => write!(f, "QCI {}", qos.qci),
                None => display::Octets(&self.value).fmt(f),
            }
        }
    }

    /// A traffic flow template: its operation and its packet filters,
    /// `Create, 2 filters`.
    impl fmt::Display for TrafficFlowTemplate {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.tft() {
                Some(tft) => tft_shown(f, &tft),
                None => display::Octets(&self.value).fmt(f),
            }
        }
    }

    /// A traffic flow aggregate: its operation and its packet filters.
    impl fmt::Display for TrafficFlowAggregateDescription {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.tft() {
                Some(tft) => tft_shown(f, &tft),
                None => display::Octets(&self.value).fmt(f),
            }
        }
    }

    fn tft_shown(f: &mut fmt::Formatter<'_>, tft: &Tft) -> fmt::Result {
        match tft.packet_filters.len() {
            0 => write!(f, "{:?}", tft.operation),
            1 => write!(f, "{:?} 1 filter", tft.operation),
            filters => write!(f, "{:?} {filters} filters", tft.operation),
        }
    }

    /// A linked EPS bearer identity: `5`.
    impl fmt::Display for LinkedEpsBearerIdentity {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.ebi() {
                Some(ebi) => ebi.fmt(f),
                None => write!(f, "{:#04x}", self.bearer_identity()),
            }
        }
    }

    /// A coded value by its name, or its code when it has none.
    struct Coded<T>(Option<T>, u8);

    impl<T: fmt::Debug> fmt::Display for Coded<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match &self.0 {
                Some(value) => write!(f, "{value:?}"),
                None => write!(f, "{:#04x}", self.1),
            }
        }
    }

    /// What an ESM message container carries: the ESM message, or its octets.
    impl fmt::Display for EsmMessageContainer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.decode_as_esm_message() {
                Ok(message) => message.fmt(f),
                Err(_) => display::Octets(&self.value).fmt(f),
            }
        }
    }

    /// What a replayed NAS message container carries: the ATTACH REQUEST or
    /// the TRACKING AREA UPDATE REQUEST, or its octets.
    impl fmt::Display for ReplayedNasMessageContainer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.decode_as_emm_message() {
                Ok(message) => message.fmt(f),
                Err(_) => display::Octets(&self.value).fmt(f),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxirush_utils::identity::Algorithm;

    #[test]
    fn remaining_scalar_eps_ie_wire_values() {
        let tai = TaiEps::new(Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap(), 0x1234);
        let last_tai = TrackingAreaIdentity::from_tai(tai);
        assert_eq!(last_tai.value, [0x02, 0xf8, 0x39, 0x12, 0x34]);
        assert_eq!(last_tai.tai(), Some(tai));

        let update = UeRadioCapabilityInformationUpdateNeeded::from_update_needed(true);
        assert_eq!(update.value, 0x01);
        assert!(update.update_needed());

        let ss = SsCode::from_code(0x2b);
        assert_eq!(ss.code(), 0x2b);

        let lcs = LcsIndicator::mt_lr();
        assert_eq!(lcs.value, 0x01);
        assert!(lcs.is_mt_lr());

        let old_guti = GutiType::from_mapped(true);
        assert_eq!(old_guti.value, 0x01);
        assert!(old_guti.is_mapped());

        let coarse = UeInformationRequest::from_requested(true);
        assert_eq!(coarse.value, 0x01);
        assert!(coarse.requested());
    }

    #[test]
    fn ciphering_key_data_sets_round_trip_and_keep_first_sixteen() {
        let set = CipheringDataSet {
            set_id: 0x0102,
            ciphering_key: [0x11; 16],
            c0: vec![0xaa, 0xbb],
            pos_sib_types: [0xfe, 0x00, 0x00, 0x80],
            validity_start_time: [0x62, 0x90, 0x62, 0x21, 0x00],
            validity_duration: 1440,
            tai_list: vec![0x00, 0x02, 0xf8, 0x39, 0x00, 0x01],
        };
        let ie = CipheringKeyData::from_data_sets(core::slice::from_ref(&set)).unwrap();
        assert!(ie.is_well_formed());
        assert_eq!(ie.data_sets(), core::slice::from_ref(&set));
        assert_eq!(ie.data_sets()[0].tai_list_value().unwrap().tais().len(), 1);

        // Spare bits of the c0 length octet are ignored on receipt.
        let mut spare = ie.value.clone();
        spare[18] |= 0x80;
        assert_eq!(
            CipheringKeyData::new(spare.clone()).data_sets(),
            core::slice::from_ref(&set)
        );
        assert!(!CipheringKeyData::new(spare).is_well_formed());

        // Seventeen sets: the receiver keeps the first sixteen.
        let seventeen: Vec<u8> = core::iter::repeat_n(ie.value.to_vec(), 17)
            .flatten()
            .collect();
        let received = CipheringKeyData::new(seventeen);
        assert_eq!(received.data_sets().len(), 16);
        assert!(!received.is_well_formed());
        assert!(CipheringKeyData::from_data_sets(&[]).is_err());
    }

    #[test]
    fn gprs_timers_distinguish_zero_deactivated_and_undefined_units() {
        // T3402 zero means "act as on expiry"; T3412 zero is deactivated (§5.3.5).
        assert_eq!(GprsTimer::new(0x20).value(), GprsTimerValue::Seconds(0));
        assert_eq!(T3412Value::new(0x20).value(), GprsTimerValue::Deactivated);
        assert_eq!(T3412Value::new(0xe5).value(), GprsTimerValue::Deactivated);
        // Units 011-110 of GPRS timer are read as minutes.
        assert_eq!(GprsTimer::new(0x62).to_seconds(), Some(120));
        assert_eq!(GprsTimer::new(0x62).unit_raw(), 3);
        assert_eq!(GprsTimer::from_seconds(12 * 60).unwrap().value, 0x2c);
        assert_eq!(GprsTimer::from_seconds(62).unwrap().value, 0x1f);
        assert!(GprsTimer::from_seconds(63).is_err());
        assert_eq!(GprsTimer::deactivated().value, 0xe0);

        // GPRS timer 2 and 3: extra value octets are ignored on receipt.
        assert_eq!(GprsTimer2::new(vec![0x21, 0x99]).to_seconds(), Some(60));
        assert!(!GprsTimer2::new(vec![0x21, 0x99]).is_well_formed());
        assert_eq!(
            GprsTimer2::new(vec![0x00]).value(),
            Some(GprsTimerValue::Seconds(0))
        );
        assert_eq!(GprsTimer3::new(vec![0x21, 0]).to_seconds(), Some(3_600));
        // T3396 deactivated and the undefined 320-hour unit are distinct.
        assert_eq!(
            GprsTimer3::new(vec![0xe0]).value(),
            Some(GprsTimerValue::Deactivated)
        );
        assert_eq!(GprsTimer3::new(vec![0xc1]).value(), None);
        assert!(!GprsTimer3::new(vec![0xc1]).is_well_formed());
        assert_eq!(GprsTimer3::from_seconds(90).unwrap().value, [0x83]);
        assert_eq!(
            GprsTimer3::from_unit_value(GprsTimer3Unit::Deactivated, 9)
                .unwrap()
                .value,
            [0xe9]
        );

        // T3412 extended value: unit 111 means "not included", value 0 deactivates,
        // and unit 110 depends on integrity protection for the UE.
        let extended = |octet| T3412ExtendedValue::new(vec![octet]);
        assert_eq!(
            extended(0xe3).value_for_ue(true),
            Some(T3412ExtendedTimer::NotIncluded)
        );
        assert_eq!(
            extended(0x40).value_for_ue(true),
            Some(T3412ExtendedTimer::Deactivated)
        );
        assert_eq!(
            extended(0xc2).value_for_ue(false),
            Some(T3412ExtendedTimer::Seconds(7_200))
        );
        assert_eq!(
            extended(0xc2).value_for_network(),
            Some(T3412ExtendedTimer::Seconds(2_304_000))
        );
        assert_eq!(
            extended(0xc2).to_seconds_with_integrity(true),
            Some(2_304_000)
        );
    }

    #[test]
    fn apn_ambr_and_eps_qos_decode_bit_rate_tables() {
        // Table 9.9.4.2.1 boundaries.
        let ambr = |value: Vec<u8>| ApnAggregateMaximumBitRate::new(value).parse().unwrap();
        assert_eq!(
            ambr(vec![0x3f, 0x40]),
            ApnAmbrValue {
                dl_kbps: 63,
                ul_kbps: 64
            }
        );
        assert_eq!(
            ambr(vec![0x7f, 0xfe]),
            ApnAmbrValue {
                dl_kbps: 568,
                ul_kbps: 8_640
            }
        );
        assert_eq!(ambr(vec![0xff, 0xfe, 0x00, 0x4a]).ul_kbps, 16_000);
        assert_eq!(ambr(vec![0xfe, 0xfe, 0xfa, 0xff]).ul_kbps, 256_000);
        // Extended-2: 1 * 256 Mbps + 8640 kbps is the 264.64 Mbps lower bound;
        // 11111111 is read as 00000000.
        assert_eq!(ambr(vec![0xfe, 0xfe, 0, 0, 0x01, 0xff]).dl_kbps, 264_640);
        assert_eq!(ambr(vec![0xfe, 0xfe, 0, 0, 0x01, 0xff]).ul_kbps, 8_640);
        // Receivers ignore octets after the three pairs.
        assert_eq!(ambr(vec![0x01, 0x01, 0, 0, 0, 0, 9]).dl_kbps, 1);
        assert!(
            ApnAggregateMaximumBitRate::new(vec![0, 1])
                .parse()
                .is_none()
        );
        let built = ApnAggregateMaximumBitRate::from_kbps(300_000, 8_640).unwrap();
        assert_eq!(built.value, [0xfe, 0xfe, 0x66, 0x00, 0x01, 0x00]);
        assert_eq!(
            built.parse(),
            Some(ApnAmbrValue {
                dl_kbps: 300_000,
                ul_kbps: 8_640
            })
        );
        assert!(ApnAggregateMaximumBitRate::from_kbps(65_280_001, 0).is_err());

        // Table 9.9.4.3.1: a 10 Gbps rate needs octets 12-15.
        let qos = EpsQos::from_kbps(1, [10_000_000, 1_024, 0, 520_000]).unwrap();
        assert_eq!(qos.to_bytes().unwrap().len(), 13);
        assert_eq!(qos.mbr_ul(), Some(EpsBitRate::Kbps(10_000_000)));
        assert_eq!(qos.mbr_dl(), Some(EpsBitRate::Kbps(1_024)));
        assert!(EpsQos::from_kbps(1, [1_000, 0, 0, 0]).is_err());
        assert_eq!(qos.gbr_ul(), Some(EpsBitRate::Kbps(0)));
        assert_eq!(qos.gbr_dl(), Some(EpsBitRate::Kbps(520_000)));
        assert!(qos.is_gbr());
        assert!(EpsQos::from_kbps(1, [10_100_000, 0, 0, 0]).is_err());
        let subscribed = EpsQos::from_bytes(&[5, 0, 0, 0, 0]).unwrap();
        assert_eq!(subscribed.mbr_ul(), Some(EpsBitRate::SubscribedOrReserved));
        // The UE maps undefined extended-2 codes onto 10 Gbps.
        let undefined =
            EpsQos::from_bytes(&[1, 0xfe, 0xfe, 0xfe, 0xfe, 0xfa, 0, 0, 0, 0xf7, 0, 0, 0]).unwrap();
        assert_eq!(undefined.mbr_ul(), Some(EpsBitRate::Kbps(10_000_000)));
        assert!(EpsQualityOfService::from_qos(qos).unwrap().is_well_formed());
        assert!(!EpsQualityOfService::new(vec![1, 0, 0]).is_well_formed());
    }

    #[test]
    fn apn_ambr_and_eps_qos_follow_the_sender_rules() {
        // Above 8640 kbps octet 3 is 11111110, so an
        // extended-2 rate adds 8640 kbps or an octet 5 rate (§9.9.4.2).
        let built =
            |dl, ul| ApnAggregateMaximumBitRate::from_kbps(dl, ul).map(|ie| ie.value.to_vec());
        assert_eq!(
            built(512_000, 65_024_000),
            Ok(vec![0xfe, 0xfe, 0xfa, 0xfa, 0x01, 0xfd])
        );
        assert_eq!(
            built(65_280_000, 65_280_000),
            Ok(vec![0xfe, 0xfe, 0xfa, 0xfa, 0xfe, 0xfe])
        );
        assert_eq!(
            built(264_640, 1),
            Ok(vec![0xfe, 0x01, 0x00, 0x00, 0x01, 0x00])
        );
        assert!(built(260_000, 1).is_err());
        for value in [
            &[0xfe, 0xfe, 0xfa, 0xfa, 0xfe, 0xfe][..],
            &[0xfe, 0x01, 0x10, 0x00],
        ] {
            assert!(ApnAggregateMaximumBitRate::new(value).is_well_formed());
        }
        for value in [
            &[0x01, 0x01, 0x10, 0x10][..],
            &[0xff, 0xff, 0x00, 0x00, 0x02, 0x02],
            &[0xfe, 0xfe, 0xfb, 0x00],
            &[0xfe, 0xfe, 0xfa, 0xfa, 0xff, 0x00],
        ] {
            assert!(
                !ApnAggregateMaximumBitRate::new(value).is_well_formed(),
                "{value:02x?}"
            );
        }
        // An extended octet overrides a reserved base octet.
        assert_eq!(
            ApnAggregateMaximumBitRate::new(vec![0x00, 0x01, 0x10, 0x00]).parse(),
            Some(ApnAmbrValue {
                dl_kbps: 10_200,
                ul_kbps: 1
            })
        );
        assert!(!ApnAggregateMaximumBitRate::new(vec![0x00, 0x01, 0x10, 0x00]).is_well_formed());

        // §9.9.4.3: octet 8 needs octet 4 = 11111110, octet 12 needs octet 8
        // = 11111010.
        assert!(
            !EpsQualityOfService::new(vec![1, 1, 1, 1, 1, 0x10, 0x10, 0x10, 0x10]).is_well_formed()
        );
        assert!(
            !EpsQualityOfService::new(vec![1, 0xfe, 0xfe, 0xfe, 0xfe, 0x10, 0, 0, 0, 1, 0, 0, 0])
                .is_well_formed()
        );
        assert!(
            EpsQualityOfService::new(vec![1, 0xfe, 0xfe, 0xfe, 0xfe, 0xfa, 0, 0, 0, 1, 0, 0, 0])
                .is_well_formed()
        );
        // 0 kbps for both maximum bit rates.
        assert!(
            EpsQualityOfService::new(vec![1, 0xff, 0xff, 0x01, 0x01]).has_zero_maximum_bit_rates()
        );
        assert!(
            !EpsQualityOfService::new(vec![1, 0xff, 0x01, 0x01, 0x01]).has_zero_maximum_bit_rates()
        );
        assert!(!EpsQualityOfService::new(vec![9]).has_zero_maximum_bit_rates());
        use crate::common::Validate;
        let request = crate::nas_eps::Message::decode(&[
            0x02, 0x05, 0xd4, 0x05, 0x01, 0x00, 0x05, 0x01, 0xff, 0xff, 0x01, 0x01,
        ])
        .unwrap();
        assert!(
            request
                .validate()
                .iter()
                .any(|error| error.field == "required_traffic_flow_qos")
        );
    }

    #[test]
    fn extended_rates_ignore_values_the_base_ies_carry() {
        let extended = ExtendedEpsQos::from_kbps(20_000_000, 5_000_000, 0, 0).unwrap();
        assert_eq!(
            (extended.mbr_unit, extended.mbr_ul, extended.mbr_dl),
            (2, 20_000, 0)
        );
        assert_eq!(extended.mbr_ul_kbps(), Some(20_000_000));
        assert_eq!(extended.mbr_dl_kbps(), None);
        let ie = ExtendedQualityOfService::from_qos(extended);
        assert!(ie.is_well_formed());
        assert_eq!(ie.qos(), Some(extended));

        let ambr = ExtendedApnAggregateMaximumBitRate::from_kbps(100_000_000, 4_000).unwrap();
        assert_eq!(ambr.value, [3, 0x61, 0xa8, 3, 0x00, 0x01]);
        assert_eq!(ambr.downlink_kbps(), Some(100_000_000));
        // The unused units 0-2 are read as 4 Mbps.
        assert_eq!(
            ExtendedApnAggregateMaximumBitRate::new(vec![0, 0, 1, 3, 0, 1]).downlink_kbps(),
            Some(4_000)
        );
        assert!(!ExtendedApnAggregateMaximumBitRate::new(vec![0, 0, 1, 3, 0, 1]).is_well_formed());
        let base = ApnAggregateMaximumBitRate::from_kbps(8_640, 8_640).unwrap();
        let effective = base.effective_kbps(Some(&ambr)).unwrap();
        assert_eq!(
            effective,
            ApnAmbrValue {
                dl_kbps: 100_000_000,
                ul_kbps: 8_640
            }
        );
    }

    #[test]
    fn bearer_ies_ignore_spare_bits_and_extra_octets_on_receipt() {
        // PDN address: spare bits 8-4, spare non-IP octets, and a trailing
        // octet are ignored; the strict form rejects each of them.
        let received = PdnAddress::new(vec![0xf9, 10, 0, 0, 1, 0xff]);
        assert_eq!(
            received.pdn_address(),
            Some(PdnAddressValue::Ipv4([10, 0, 0, 1]))
        );
        assert!(!received.is_well_formed());
        let dual = PdnAddress::from_pdn_address(PdnAddressValue::Ipv4v6 {
            ipv6_interface_id: [1; 8],
            ipv4: [0; 4],
        });
        assert!(dual.is_well_formed() && dual.uses_dhcpv4());
        assert_eq!(dual.ipv6_interface_id(), Some([1; 8]));
        assert_eq!(
            PdnAddressValue::from_bytes(&[0x05, 1, 2, 3, 4]),
            Some(PdnAddressValue::NonIp)
        );
        assert_eq!(
            PdnAddressValue::from_bytes_strict(&[0x05, 1, 2, 3, 4]),
            None
        );
        assert_eq!(
            PdnAddressValue::from_bytes(&[0x03, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            None
        );

        // PDN type 4 is read as IPv6 by the network only in the tolerant form.
        let mut pdn_type = PdnType::new(0x0c);
        assert_eq!(pdn_type.pdn_type().effective(), PdnTypeValue::Ipv6);
        assert_eq!(
            (pdn_type.pdn_type_strict(), pdn_type.pdn_type_raw()),
            (None, 4)
        );
        pdn_type.set_pdn_type(PdnTypeValue::Ipv4v6);
        assert_eq!(pdn_type.value, 3);

        let mut request = RequestType::new(0x0e);
        request.set_request_type(RequestTypeValue::Emergency);
        assert!(request.is_emergency() && request.value == 4);
        assert_eq!(RequestType::new(0x0d).request_type_raw(), 5);
        assert_eq!(RequestType::new(5).request_type().effective().name(), None);

        let mut lbi = LinkedEpsBearerIdentity::new(0);
        assert_eq!(lbi.ebi(), None);
        assert!(lbi.set_bearer_identity(16).is_err());
        assert_eq!(lbi.set_bearer_identity(5).unwrap().ebi(), Some(5));

        assert_eq!(
            LlcServiceAccessPointIdentifier::new(0x93).llc_sapi(),
            Some(LlcSapi::Sapi3)
        );
        assert_eq!(LlcServiceAccessPointIdentifier::new(0x04).sapi(), None);
        assert!(LlcServiceAccessPointIdentifier::from_sapi(0x13).is_err());

        let radio = RadioPriority::new(0x0f);
        assert_eq!(radio.priority_level(), RadioPriorityLevel::Four);
        assert_eq!(RadioPriorityLevel::named(radio.value & 0x07), None);
        let mut radio = radio;
        radio.set_priority_level(RadioPriorityLevel::One);
        assert_eq!(radio.value, 1);

        assert!(ConnectivityType::new(0x01).is_lipa());
        assert!(!ConnectivityType::new(0x02).is_lipa());

        let mut wlan = WlanOffloadAcceptability::new(0x0c);
        wlan.set_iu_offload_acceptable(true);
        assert!(wlan.iu_offload_acceptable() && !wlan.s1_offload_acceptable());

        let mut reattempt = ReAttemptIndicator::new(vec![]);
        reattempt.set_eplmnc_not_allowed(true);
        assert_eq!(
            (reattempt.value.len(), reattempt.value.as_slice()),
            (1, [0x02].as_slice())
        );
        assert!(reattempt.is_well_formed());
        let received = ReAttemptIndicator::new(vec![0xfd, 0xff]);
        assert!(received.ratc_not_allowed() && !received.eplmnc_not_allowed());
        assert!(!received.is_well_formed());
    }

    #[test]
    fn identifier_ies_follow_24007_and_24008_codings() {
        // TS 24.007 §11.2.3.1.3: TIO 0-6 in one octet, TIE 7-127 in the
        // extension, and the TIO is ignored when the extension is present.
        let short = TransactionIdentifier::from_ti(true, 3).unwrap();
        assert_eq!(short.value, [0xb0]);
        assert_eq!((short.ti_flag(), short.ti_value()), (Some(true), Some(3)));
        let long = TransactionIdentifier::from_ti(false, 100).unwrap();
        assert_eq!(long.value, [0x70, 0xe4]);
        assert!(long.is_well_formed());
        assert_eq!(
            TransactionIdentifier::new(vec![0x20, 0x88]).ti_value(),
            Some(8)
        );
        assert_eq!(
            TransactionIdentifier::new(vec![0x70, 0x86]).ti_value(),
            None
        );
        assert_eq!(TransactionIdentifier::new(vec![0x70]).ti_value(), None);
        assert!(!TransactionIdentifier::new(vec![0x31]).is_well_formed());
        assert!(!TransactionIdentifier::new(vec![0x10, 0x88]).is_well_formed());

        let pfi = PacketFlowIdentifier::from_pfi(PacketFlowId::Dynamic(8)).unwrap();
        assert!(pfi.is_well_formed());
        assert_eq!(
            PacketFlowIdentifier::new(vec![0x82]).pfi(),
            Some(PacketFlowId::Sms)
        );
        assert_eq!(PacketFlowIdentifier::new(vec![0x05]).pfi(), None);
        assert!(PacketFlowIdentifier::from_pfi(PacketFlowId::Dynamic(4)).is_err());

        let notification = NotificationIndicator::new(vec![0x02]);
        assert!(notification.indicator().is_none() && notification.is_ignorable());
        assert!(!NotificationIndicator::new(vec![0x80]).is_ignorable());

        let pkmf = PkmfAddress::new(vec![0xf9, 192, 0, 2, 1, 0]);
        assert_eq!(pkmf.address(), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(pkmf.address_type(), Some(PkmfAddressType::Ipv4));
        assert!(!pkmf.is_well_formed());
        assert!(PkmfAddress::new(vec![2, 0, 0]).address().is_none());

        let apn = AccessPointName::new(vec![3, b'a', b'_', b'b', 1, b'c']);
        assert_eq!(apn.as_string(), None);
        assert_eq!(apn.labels(), Some(vec![b"a_b".as_slice(), b"c"]));
        assert!(!apn.is_well_formed());
        assert!(AccessPointName::new(vec![4, b'a']).labels().is_none());
    }

    #[test]
    fn emm_value_ies_apply_receive_fallbacks() {
        // Unused attach type 0 is read as EPS attach by the network.
        let attach = EpsAttachType::new(0x08);
        assert_eq!(attach.attach_type(), AttachType::EpsAttach);
        assert_eq!(
            (attach.attach_type_strict(), attach.attach_type_raw()),
            (None, 0)
        );
        let mut attach = attach;
        attach.set_attach_type(AttachType::EpsEmergencyAttach);
        assert_eq!(attach.value, 6);

        let mut update = EpsUpdateType::new(0x0c);
        assert_eq!(update.update_type().effective(), UpdateType::TaUpdating);
        assert_eq!(update.update_type().name(), None);
        update
            .set_update_type(UpdateType::PeriodicUpdating)
            .set_active(false);
        assert_eq!(update.value, 3);
        assert_eq!(EpsUpdateType::new(7).update_type().effective().name(), None);

        let service = ServiceType::new(0x0a);
        assert_eq!(
            service.service_type().effective(),
            ServiceTypeValue::PacketServicesViaS1
        );
        assert_eq!(
            (service.service_type_strict(), service.service_type_raw()),
            (None, 10)
        );
        assert_eq!(
            ServiceType::new(0x05).service_type().effective().name(),
            None
        );

        assert_eq!(
            EpsUpdateResult::new(0x0c).update_result(),
            Some(UpdateResult::TaUpdatedAndIsrActivated)
        );
        assert_eq!(EpsAttachResult::new(3).attach_result(), None);

        // Table 9.9.3.7.1: fallbacks differ by direction, and bit 4 is
        // spare from the network.
        let detach = DetachType::new(0x0d);
        assert_eq!(
            detach.ue_detach_kind().effective(),
            UeDetachKind::CombinedEpsImsiDetach
        );
        assert_eq!(
            detach.network_detach_kind().effective(),
            NetworkDetachKind::ReattachNotRequired
        );
        assert_eq!(UeDetachKind::named(detach.value & 0x07), None);
        assert!(detach.switch_off());
        let network = DetachType::from_network_detach_kind(NetworkDetachKind::ImsiDetach);
        assert_eq!((network.value, network.ue_detach_kind_raw()), (3, 3));
    }

    #[test]
    fn mobile_identities_check_type_bits_on_receipt() {
        // TS 24.008 Table 10.5.4: an EMM IDENTITY RESPONSE sends "No
        // Identity" as three zero octets.
        let none = MobileIdentity::from_no_identity();
        assert!(none.is_no_identity() && none.is_well_formed());
        assert!(MobileIdentity::new(vec![0]).is_no_identity());

        let tmsi = MobileIdentity::new(vec![0xf4, 1, 2, 3, 4, 0xff]);
        assert_eq!(tmsi.as_tmsi(), Some(0x0102_0304));
        // A receiver reads the type of identity only: bits 8 to 5 are coded
        // "1111" but a TMSI without them is still a TMSI, as in 5GS.
        let unfilled = MobileIdentity::new(vec![0x04, 1, 2, 3, 4]);
        assert_eq!(unfilled.as_tmsi(), Some(0x0102_0304));
        assert!(!unfilled.is_well_formed());
        assert_eq!(MobileIdentity::new(vec![0xf1, 1, 2, 3, 4]).as_tmsi(), None);
        assert!(!tmsi.is_well_formed());
        assert!(MobileIdentity::from_tmsi(7).is_well_formed());

        let plmn = Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap();
        let guti = GutiEps::new(plmn, 0x8001, 1, 0xc000_0001);
        let mut received = guti.to_nas_octets().to_vec();
        received.push(0);
        let identity = EpsMobileIdentity::new(received);
        assert_eq!(identity.as_guti(), Some(guti));
        assert_eq!(identity.plmn(), Some(guti.plmn()));
        assert!(!identity.is_well_formed());

        let mut unfilled = guti.to_nas_octets().to_vec();
        unfilled[0] = 0x06;
        let identity = EpsMobileIdentity::new(unfilled);
        assert_eq!(identity.as_guti(), Some(guti));
        assert_eq!(identity.plmn(), Some(guti.plmn()));
        assert!(!identity.is_well_formed());
        let mut imsi = guti.to_nas_octets().to_vec();
        imsi[0] = 0xf1;
        assert_eq!(EpsMobileIdentity::new(imsi).as_guti(), None);
        assert!(EpsMobileIdentity::from_guti(guti).is_well_formed());
        assert_eq!(identity.identity_type_raw(), Some(6));
    }

    #[test]
    fn location_and_calling_party_ies_decode() {
        let lai = Lai {
            plmn: Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap(),
            lac: 0x1234,
        };
        let ie = LocationAreaIdentification::from_lai(lai);
        assert_eq!(ie.value, [0x02, 0xf8, 0x39, 0x12, 0x34]);
        assert_eq!(ie.lai(), Some(lai));

        // International number +33 1 23 with octet 3a (restricted, network provided).
        let number = CallingPartyNumber {
            type_of_number: 1,
            numbering_plan: 1,
            presentation_screening: Some((1, 3)),
            digits: "33123".into(),
        };
        let cli = Cli::from_number(&number).unwrap();
        assert_eq!(cli.value, [0x11, 0xa3, 0x33, 0x21, 0xf3]);
        assert_eq!(cli.number(), Some(number));
        assert_eq!(
            Cli::new(vec![0x91, 0x21])
                .number()
                .unwrap()
                .presentation_screening,
            None
        );
        // Bits 5 to 3 of octet 3a are spare (Wireshark: "Spare bit(s)"): the
        // CLI of a received CS SERVICE NOTIFICATION keeps them.
        let message =
            crate::nas_eps::Message::decode(&hex::decode("076401600401bc214365").unwrap()).unwrap();
        let crate::nas_eps::Message::Emm(
            _,
            crate::nas_eps::EmmMessage::CsServiceNotification(notification),
        ) = message
        else {
            panic!("expected CS SERVICE NOTIFICATION");
        };
        let cli = notification.cli.unwrap();
        assert_eq!(cli.number().unwrap().digits, "1234");
        assert!(!cli.is_well_formed());

        let nri = NetworkResourceIdentifierContainer::from_nri(0x3ff).unwrap();
        assert_eq!(
            (nri.value.as_slice(), nri.nri()),
            ([0xff, 0xc0].as_slice(), Some(0x3ff))
        );
        assert_eq!(
            NetworkResourceIdentifierContainer::new(vec![0x01, 0x7f]).nri(),
            Some(0x05)
        );
        assert_eq!(SmsServicesStatus::new(0x0d).status(), None);
        assert_eq!(SmsServicesStatus::new(0x0d).status_raw(), 5);
    }

    #[test]
    fn paging_and_drx_ies_apply_receive_rules() {
        // DRX parameter: SPLIT PG CYCLE CODE 70 is 79; reserved 99 reads as 1;
        // S1 DRX 1010 reads as "not specified".
        let drx = DrxParameter::new(vec![70, 0xab]);
        assert_eq!(drx.split_pg_cycle(), Some(79));
        assert_eq!(DrxParameter::new(vec![99, 0]).split_pg_cycle(), Some(1));
        assert_eq!(DrxParameter::new(vec![0, 0]).split_pg_cycle(), Some(704));
        assert_eq!(drx.s1_drx_value().effective(), S1DrxValue::NotSpecified);
        assert_eq!((drx.split_on_ccch(), drx.non_drx_timer()), (true, 3));
        let built = DrxParameter::from_fields(10, S1DrxValue::T128, false, 0).unwrap();
        assert_eq!(built.value, [10, 0x80]);
        assert!(built.is_well_formed() && !drx.is_well_formed());

        let nb = NbS1DrxParameter::new(vec![0xf7]);
        assert_eq!(nb.drx_value(), Some(NbS1DrxValue::NotSpecified));
        assert_eq!(nb.drx_value_raw(), Some(7));
        assert!(!nb.is_well_formed());
        assert!(NbS1DrxParameter::from_drx_value(NbS1DrxValue::T1024).is_well_formed());
        assert_eq!(
            ImsiOffset::from_imsi_offset(0x1234).imsi_offset(),
            Some(0x1234)
        );
        assert_eq!(DcnId::from_dcn_id(7).dcn_id(), Some(7));

        let restriction = PagingRestriction::from_restriction(
            PagingRestrictionType::AllRestrictedExceptSpecifiedPdnConnections,
            &[5, 9],
        )
        .unwrap();
        assert_eq!(restriction.value, [3, 0x20, 0x02]);
        assert_eq!(restriction.unrestricted_ebis(), Some(vec![5, 9]));
        assert!(restriction.is_well_formed());
        assert!(
            PagingRestriction::from_restriction(PagingRestrictionType::AllRestricted, &[5])
                .is_err()
        );
        assert_eq!(
            EpsAdditionalRequestResult::new(vec![0xfe]).paging_restriction_decision(),
            Some(PagingRestrictionDecision::PagingRestrictionIsRejected)
        );

        let availability = UeRadioCapabilityIdAvailability::new(vec![0x05]);
        assert_eq!(availability.is_available(), Some(false));
        assert!(UeRadioCapabilityIdRequest::from_requested(true).is_requested());

        let voice = VoiceDomainPreferenceAndUeUsageSetting::from_fields(
            VoiceDomainPreference::ImsPsVoicePreferred,
            true,
        );
        assert_eq!(voice.value, [0x07]);
        assert_eq!(
            voice.voice_domain_preference().effective(),
            VoiceDomainPreference::ImsPsVoicePreferred
        );

        let list = SAndFMonitoringList::Present(vec![3, 4]);
        let parameters =
            SAndFSatelliteOperationParameters::from_fields(Some(600), Some(70_000), &list).unwrap();
        assert!(parameters.is_well_formed());
        assert_eq!(parameters.wait_time(), Some(600));
        assert_eq!(parameters.uplink_delivery_time(), Some(70_000));
        assert_eq!(parameters.monitoring_list(), Some(list));
        // SFMLI 11 is unused and read as "not present".
        assert_eq!(
            SAndFSatelliteOperationParameters::new(vec![0x0c]).monitoring_list(),
            Some(SAndFMonitoringList::NotPresent)
        );
    }

    #[test]
    fn cause_values_apply_receive_rules() {
        // Table 9.9.3.9.1: unlisted EMM causes are treated as #111.
        let emm = EmmCause::new(0x04);
        assert_eq!(emm.cause(), None);
        assert_eq!(
            emm.cause_received(),
            EmmCauseValue::ProtocolErrorUnspecified
        );
        assert_eq!(emm.description(), "Unknown EMM cause 0x04");
        assert_eq!(EmmCauseValue::named(0x04), None);
        let mut emm = EmmCause::new(0);
        emm.set_cause(EmmCauseValue::IllegalUe);
        assert_eq!((emm.value, emm.description()), (3, "Illegal UE".into()));

        // Table 9.9.4.4.1: the UE uses #34 and the network #111, including
        // for the unused value 0x2E (NOTE 2).
        let esm = EsmCause::new(0x2e);
        assert_eq!(
            esm.cause_for_ue(),
            EsmCauseValue::ServiceOptionTemporarilyOutOfOrder
        );
        assert_eq!(
            esm.cause_for_network(),
            EsmCauseValue::ProtocolErrorUnspecified
        );
        assert_eq!(
            EsmCause::new(0x1a).cause_for_ue(),
            EsmCauseValue::InsufficientResources
        );
    }

    #[test]
    fn negotiated_qos_applies_24008_receive_rules() {
        // Delay 6, reliability 1; peak 12, precedence 5; mean 20; interactive;
        // MBR UL 64 kbps; MBR DL 8640 kbps with extended-2 0x01; GBR UL 0 kbps;
        // GBR DL 0 kbps with extended 0x4b.
        let mut value = vec![
            0x31, 0xc5, 0x14, 0x63, 0x96, 0x40, 0xfe, 0x74, 0x4b, 0xff, 0xfe, 0x13,
        ];
        value.extend([0x4b, 0x4b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        let qos = QualityOfService::new(value);
        // Receivers apply the documented fallback rules, but a network sender
        // must not emit these reserved and unused assignments.
        assert!(!qos.is_well_formed());
        assert_eq!(
            (qos.delay_class(), qos.reliability_class()),
            (Some(4), Some(2))
        );
        assert_eq!(
            (qos.peak_throughput(), qos.precedence_class()),
            (Some(1), Some(2))
        );
        assert_eq!(qos.mean_throughput(), Some(31));
        assert_eq!(qos.traffic_class_raw(), Some(3));
        assert_eq!(qos.transfer_delay_raw(), Some(0x12));
        assert_eq!(qos.signalling_indication(), Some(true));
        assert_eq!(qos.source_statistics_descriptor_raw(), Some(3));
        assert_eq!(qos.mbr_ul(), Some(EpsBitRate::Kbps(64)));
        assert_eq!(qos.mbr_dl(), Some(EpsBitRate::Kbps(260_000)));
        assert_eq!(qos.gbr_ul(), Some(EpsBitRate::Kbps(0)));
        assert_eq!(qos.gbr_dl(), Some(EpsBitRate::Kbps(17_000)));

        // Reserved codes, spare bits, and an odd extension length.
        let reserved = QualityOfService::new(vec![0xff, 0xff, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            (reserved.delay_class(), reserved.reliability_class()),
            (None, None)
        );
        assert_eq!(
            (reserved.peak_throughput(), reserved.precedence_class()),
            (None, None)
        );
        assert_eq!(reserved.mean_throughput(), None);
        assert_eq!(reserved.mbr_ul(), Some(EpsBitRate::SubscribedOrReserved));
        assert!(!reserved.is_well_formed());
        assert_eq!(QualityOfService::new(vec![0x23]).mbr_ul(), None);

        // TS 24.008 table 10.5.156 network-assigned values, including all
        // three bitrate tiers.  Each non-zero extension requires the sentinel
        // in the preceding tier.
        let valid = QualityOfService::new(vec![
            0x0b, 0x11, 0x01, 0x29, 0x96, 0xfe, 0xfe, 0x11, 0x05, 0xfe, 0xfe, 0x10, 0xfa, 0xfa,
            0xfa, 0xfa, 0x01, 0x01, 0x01, 0x01,
        ]);
        assert!(valid.is_well_formed());

        let all_zero = QualityOfService::new(vec![0; 12]);
        assert!(!all_zero.is_well_formed());
        let mut invalid_extension = valid.clone();
        invalid_extension.value[12] = 0xfb;
        assert!(!invalid_extension.is_well_formed());
        let mut missing_base_sentinel = valid;
        missing_base_sentinel.value[6] = 0xfd;
        assert!(!missing_base_sentinel.is_well_formed());
    }

    #[test]
    fn key_set_identifiers_expose_ksi_tsc_and_no_key() {
        let ksi = KeySetIdentifier::default();
        assert!(ksi.no_key_available());
        let mut mapped = ksi;
        mapped.set_ksi(3).unwrap();
        mapped.set_tsc(true);
        assert_eq!((mapped.ksi(), mapped.tsc(), mapped.value), (3, true, 0x0b));
        assert_eq!(
            mapped.key_set_identifier(),
            KeySetIdentifierValue::Mapped(3)
        );
        let non_current = KeySetIdentifier::new(0x0a);
        assert!(non_current.tsc());

        let cksn = CipheringKeySequenceNumber::default();
        assert!(cksn.no_key_available());
        assert_eq!(cksn.key_sequence_number_strict(), None);
        let mut cksn = cksn;
        cksn.set_key_sequence_number(4).unwrap();
        assert_eq!(cksn.key_sequence_number_strict(), Some(4));
        assert!(CipheringKeySequenceNumber::from_key_sequence_number(8).is_err());
    }

    #[test]
    fn selected_algorithms_ignore_spare_bits_on_receipt() {
        // TS 24.007 §11.1.4: spare bits 8 and 4 are accepted as 0 or 1.
        let received = SecurityAlgorithms::new(0xaa);
        assert_eq!(received.ciphering(), Ok(Algorithm::Aes));
        assert_eq!(received.integrity(), Ok(Algorithm::Aes));
        assert!(!received.is_well_formed());
        let mut built = SecurityAlgorithms::from_algorithms(Algorithm::Null, Algorithm::Aes);
        built.set_ciphering(Algorithm::Zuc);
        assert_eq!(built.value, 0x32);
        assert!(built.is_well_formed());
    }

    #[test]
    fn n1_and_ms_network_capabilities_decode_their_bits() {
        let mut n1 = N1UeNetworkCapability::default();
        n1.set_cp_ciot(true);
        n1.set_pnb_ciot(PreferredCiotBehavior::UserPlane);
        assert_eq!(n1.value, [0x21]);
        assert!(n1.n3_data_transfer_supported());
        assert_eq!(n1.pnb_ciot(), PreferredCiotBehavior::UserPlane);
        // Longer TLV 3-15 values are valid; only octet 3 is defined.
        assert!(N1UeNetworkCapability::new(vec![0x7f, 0x00]).is_well_formed());
        assert!(!N1UeNetworkCapability::new(vec![0x80]).is_well_formed());
        assert!(!N1UeNetworkCapability::new(vec![0x02]).n3_data_transfer_supported());

        // UCS2, SS 01, R99 / GEA2-GEA3 / EMM combined, ISR, EPC.
        let ms = MsNetworkCapability::new(vec![0x15, 0x60, 0x34, 0x00]);
        assert!(ms.ucs2() && ms.revision_level_indicator() && !ms.gea1());
        assert_eq!(ms.ss_screening_indicator(), Some(1));
        assert!(ms.supports_gea(2) && ms.supports_gea(3) && !ms.supports_gea(4));
        assert!(ms.emm_combined() && ms.isr() && ms.epc() && !ms.srvcc());
        assert!(ms.is_well_formed());
        assert!(!MsNetworkCapability::new(vec![0x80, 0x00]).is_well_formed());
        let mut dcnr = MsNetworkCapability::new(vec![0x10, 0x00]);
        dcnr.set_dcnr(true);
        assert_eq!(
            (dcnr.value.as_slice(), dcnr.value.len()),
            (&[0x10, 0, 0, 0x01][..], 4)
        );
    }

    #[test]
    fn additional_security_capability_nonces_and_hashes() {
        let mut additional = UeAdditionalSecurityCapability::from_capabilities(0xe000, 0x6000);
        assert!(additional.supports_ea(2) && !additional.supports_ea(3));
        assert!(additional.supports_ia(1) && !additional.supports_ia(0));
        additional.set_ea(15, true).unwrap();
        assert_eq!(additional.value, [0xe0, 0x01, 0x60, 0x00]);
        assert!(additional.is_well_formed());

        assert_eq!(Nonce::from_nonce(0x0102_0304).value, [1, 2, 3, 4]);
        assert_eq!(Nonce::new(vec![1, 2, 3, 4]).nonce(), Some(0x0102_0304));
        assert_eq!(Nonce::new(vec![1, 2, 3]).nonce(), None);
        let signature = PTmsiSignature::from_p_tmsi_signature(0x00ab_cdef).unwrap();
        assert_eq!(signature.p_tmsi_signature(), Some(0x00ab_cdef));
        assert!(PTmsiSignature::from_p_tmsi_signature(0x0100_0000).is_err());

        // HashMME of capture packet 37.
        let hash = HashMme::from_hash_mme([0xb1, 0xe1, 0x11, 0x5a, 0x6c, 0x47, 0xa7, 0x50]);
        assert_eq!(hash.hash_mme().unwrap()[0], 0xb1);
        assert!(hash.is_well_formed());
    }

    #[test]
    fn replayed_nas_message_container_carries_plain_attach_or_tau_request() {
        let attach = crate::nas_eps::Message::decode(
            &hex::decode("07410108991007000020160605e0e000000000250243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1").unwrap(),
        )
        .unwrap();
        let container = ReplayedNasMessageContainer::from_emm_message(&attach).unwrap();
        assert_eq!(container.decode_as_emm_message().unwrap(), attach);
        let protected = ReplayedNasMessageContainer::new(
            hex::decode("17830224400307410108991007000020160605e0e000000000250243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1").unwrap(),
        );
        assert!(protected.decode_as_emm_message().is_err());
    }

    #[test]
    fn small_flag_ies_have_setters_and_generic_container_type_ranges() {
        let mut properties = DeviceProperties::new(0);
        properties.set_low_priority(true);
        assert_eq!(properties.value, 1);
        assert!(NetworkPolicy::new(0x0f).unsecured_redirection_forbidden());
        let mut features = MsNetworkFeatureSupport::new(0);
        features.set_extended_periodic_timers_supported(true);
        assert!(features.extended_periodic_timers_supported());
        let requested = AdditionalInformationRequested::from_cipher_key_data_requested(true);
        assert!(requested.cipher_key_data_requested() && requested.is_well_formed());
        let container = GenericMessageContainerType::new(0x80);
        assert!(container.is_reserved() && container.container_type().is_none());
        let mut lcs = container;
        lcs.set_container_type(GenericMessageContainerTypeValue::Lcs);
        assert_eq!((lcs.value, lcs.is_reserved()), (2, false));
    }

    #[test]
    fn release_assistance_and_ue_status_match_5gs_helpers() {
        let release = ReleaseAssistanceIndication::from_ddx(DownlinkDataExpected::SingleDlThenNone);
        assert_eq!(release.ddx(), Some(DownlinkDataExpected::SingleDlThenNone));
        assert_eq!(release.ddx_raw(), 2);
        assert_eq!(ReleaseAssistanceIndication::new(3).ddx(), None);

        let status = UeStatus::from_status(true, false);
        assert!(status.n1_mode_reg());
        assert!(!status.s1_mode_reg());
        assert_eq!(status.value, [0x02]);
    }

    #[test]
    fn additional_result_tmsi_priority_and_musim_request_helpers() {
        let result = AdditionalUpdateResult::from_result(AdditionalUpdateResultValue::SmsOnly);
        assert_eq!(result.result(), Some(AdditionalUpdateResultValue::SmsOnly));
        assert_eq!(AdditionalUpdateResult::new(3).result(), None);

        let tmsi = TmsiStatus::from_valid_tmsi(true);
        assert!(tmsi.has_valid_tmsi());
        assert_eq!(tmsi.value, 1);

        let priority = RadioPriority::from_priority_level(RadioPriorityLevel::Two);
        assert_eq!(priority.priority_level(), RadioPriorityLevel::Two);
        assert_eq!(
            RadioPriority::new(0).priority_level(),
            RadioPriorityLevel::Four
        );

        let request = UeRequestType::from_request_type(UeRequestTypeValue::RejectionOfPaging);
        assert_eq!(
            request.request_type(),
            Some(UeRequestTypeValue::RejectionOfPaging)
        );
        assert_eq!(request.request_type_raw(), Some(2));
        assert_eq!(UeRequestType::new(vec![3]).request_type(), None);
    }

    #[test]
    fn update_type_and_authentication_rand_helpers() {
        let update =
            AdditionalUpdateType::from_fields(true, true, PreferredCiotBehavior::ControlPlane);
        assert_eq!(update.value, 0x07);
        assert!(update.sms_only());
        assert!(update.signalling_active());
        assert_eq!(
            update.preferred_ciot_behavior().effective(),
            PreferredCiotBehavior::ControlPlane
        );
        assert_eq!(
            AdditionalUpdateType::new(0x0c)
                .preferred_ciot_behavior()
                .effective()
                .name(),
            None
        );

        let rand = [0xa5; 16];
        assert_eq!(
            AuthenticationParameterRand::from_rand(rand).rand(),
            Some(&rand)
        );
        assert_eq!(AuthenticationParameterRand::new(vec![0; 15]).rand(), None);
        assert!(ControlPlaneOnlyIndication::control_plane_only().cpoi());
        assert_eq!(CsfbResponse::from_accepted(true).accepted(), Some(true));
        assert_eq!(CsfbResponse::new(3).accepted(), None);
        assert_eq!(CsfbResponse::new(3).accepted_raw(), 3);
    }

    #[test]
    fn scalar_ie_accessors_preserve_reserved_wire_values() {
        use crate::common::{Decode, Encode};

        let cause = ExtendedEmmCause::from_flags(true, false, true, false);
        assert_eq!(cause.value, 0x05);
        assert!(cause.eutran_not_allowed());
        assert!(!cause.eps_optimization_not_supported());
        assert!(cause.nb_iot_not_allowed());
        assert!(!cause.satellite_eutran_not_allowed());

        // A half octet in an octet of its own keeps the other half.
        let status = SmsServicesStatus::decode(&[0xe5]).unwrap();
        assert_eq!(status.status(), None);
        assert_eq!(status.encode().unwrap(), [0xe5]);
        assert_eq!(
            SmsServicesStatus::from_status(SmsServicesStatusValue::Congestion).value,
            3
        );

        assert_eq!(
            GenericMessageContainerType::new(0x80).container_type(),
            None
        );
        assert_eq!(
            GenericMessageContainerType::from_container_type(GenericMessageContainerTypeValue::Lpp)
                .value,
            1
        );
        assert_eq!(
            UeRadioCapabilityIdDeletionIndication::new(7).deletion_request(),
            Some(RadioCapabilityIdDeletionRequest::NotRequested)
        );
        assert_eq!(
            UeRadioCapabilityIdDeletionIndication::new(7).deletion_request_raw(),
            7
        );
        assert_eq!(RadioCapabilityIdDeletionRequest::named(7), None);
        // A non-current native identifier is checked by its message.
        assert_eq!(
            KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Mapped(1))
                .unwrap()
                .value,
            0x09
        );
        assert_eq!(
            KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::NoKey)
                .unwrap()
                .value,
            7
        );
        assert_eq!(
            LlcServiceAccessPointIdentifier::from_sapi(3)
                .unwrap()
                .sapi(),
            Some(3)
        );
        assert!(LlcServiceAccessPointIdentifier::from_sapi(4).is_err());
        assert_eq!(
            TimeZone::from_quarter_hours(-14).unwrap().quarter_hours(),
            -14
        );
        assert!(TimeZone::from_quarter_hours(80).is_err());
        assert!(TimeZone::from_quarter_hours(-128).is_err());
    }

    #[test]
    fn requested_identity_security_and_feature_bits() {
        assert_eq!(
            IdentityType2::from_identity_type(IdentityType::Imeisv)
                .unwrap()
                .identity_type(),
            IdentityType::Imeisv
        );
        // No identity and a TMGI are not asked for
        assert!(IdentityType2::from_identity_type(IdentityType::NoIdentity).is_err());
        assert!(IdentityType2::from_identity_type(IdentityType::Tmgi).is_err());
        assert_eq!(IdentityType2::new(0xf7).identity_type_raw(), 7);
        // TS 24.008 Table 10.5.142: other values are interpreted as IMSI.
        assert_eq!(IdentityType2::new(7).identity_type(), IdentityType::Imsi);
        assert_eq!(IdentityType2::new(5).identity_type_strict(), None);
        assert_eq!(IdentityType2::new(7).identity_type_strict(), None);
        assert!(ImeisvRequest::from_requested(true).is_requested());
        assert!(!ImeisvRequest::new(2).is_requested());
        assert_eq!(
            RequestType::from_request_type(RequestTypeValue::EmergencyHandover)
                .request_type()
                .effective(),
            RequestTypeValue::EmergencyHandover
        );
        assert_eq!(RequestType::new(5).request_type().effective().name(), None);
        assert!(EsmInformationTransferFlag::from_required(true).is_required());

        let feature = EpsNetworkFeatureSupport::new(vec![0x83, 0x09, 0x01]);
        assert!(feature.ims_vops() && feature.emc_bs() && feature.cp_ciot());
        assert!(feature.up_ciot() && feature.epco() && feature.ncr());
        assert!(!EpsNetworkFeatureSupport::new(vec![0]).epco());
        // CS-LCS, S1-U data and OHR-CP CIoT receiver rules (Table 9.9.3.12A.1).
        let lcs = EpsNetworkFeatureSupport::new(vec![0x10, 0x00, 0x40]);
        assert_eq!(lcs.cs_lcs(), CsLcsSupport::NotSupported);
        assert!(lcs.s1u_data_supported() && !lcs.ohr_cp_ciot_supported());
        assert!(lcs.is_well_formed());
        let reserved = EpsNetworkFeatureSupport::new(vec![0x18, 0x00, 0x80]);
        assert_eq!((reserved.cs_lcs().name(), reserved.cs_lcs_raw()), (None, 3));
        assert!(!reserved.is_well_formed());
        let mut built = EpsNetworkFeatureSupport::default();
        built.set_cs_lcs(CsLcsSupport::Supported);
        built.set_iwk_n26(true);
        built.set_ptcc(true);
        assert_eq!(built.value, [0x08, 0x40, 0x10]);
        assert_eq!(built.value.len(), 3);

        let mut replayed = UeSecurityCapability::new(vec![0, 0]);
        replayed.set_eea(Algorithm::Aes as u8, true).unwrap();
        replayed.set_eia(Algorithm::Snow3g as u8, true).unwrap();
        assert!(replayed.supports_eea(Algorithm::Aes as u8));
        assert!(replayed.supports_eia(Algorithm::Snow3g as u8));
    }

    #[test]
    fn extended_drx_retry_and_eps_rate_helpers() {
        let mut drx = ExtendedDrxParameters::new(vec![]);
        drx.set_paging_time_window(0xa).unwrap();
        drx.set_edrx_value(3).unwrap();
        assert_eq!(drx.value, [0xa3]);
        assert_eq!(drx.value.len(), 1);
        assert_eq!((drx.paging_time_window(), drx.edrx_value()), (10, 3));

        let retry = ReAttemptIndicator::from_flags(true, false);
        assert_eq!(retry.value, [0x02]);
        assert!(retry.eplmnc_not_allowed());
        assert!(!retry.ratc_not_allowed());

        assert!(ServingPlmnRateControl::from_rate(9).is_err());
        let limited = ServingPlmnRateControl::from_rate(10).unwrap();
        assert_eq!(limited.value, [0, 10]);
        assert_eq!(limited.rate(), Some(10));
        assert!(!limited.is_unrestricted());
        let unlimited = ServingPlmnRateControl::from_rate(u16::MAX).unwrap();
        assert!(unlimited.is_unrestricted());
        assert_eq!(ServingPlmnRateControl::new(vec![0, 9]).rate(), None);
    }

    #[test]
    fn paging_and_unavailability_flags_match_payload_lengths() {
        assert!(PagingRestriction::new(vec![1]).is_well_formed());
        assert!(PagingRestriction::new(vec![3, 0x02, 0xff]).is_well_formed());
        assert!(!PagingRestriction::new(vec![3]).is_well_formed());
        assert!(!PagingRestriction::new(vec![3, 0x01, 0xff]).is_well_formed());
        assert!(EpsAdditionalRequestResult::new(vec![2]).is_well_formed());
        assert!(!EpsAdditionalRequestResult::new(vec![3]).is_well_formed());

        for flags in [0, 0x08, 0x10, 0x18] {
            let mut value = vec![flags];
            value.resize(
                1 + 3 * ((flags & 0x08 != 0) as usize + (flags & 0x10 != 0) as usize),
                0,
            );
            assert!(UnavailabilityInformation::new(value.clone()).is_well_formed());
            value.push(0);
            assert!(!UnavailabilityInformation::new(value).is_well_formed());
        }
        for flags in [0, 0x02, 0x04, 0x06] {
            let mut value = vec![flags];
            value.resize(
                1 + 3 * ((flags & 0x02 != 0) as usize + (flags & 0x04 != 0) as usize),
                0,
            );
            assert!(UnavailabilityConfiguration::new(value.clone()).is_well_formed());
            value.pop();
            assert!(!UnavailabilityConfiguration::new(value).is_well_formed());
        }
    }

    #[test]
    fn delegated_codec_drx_and_daylight_fields_follow_24_008() {
        let codecs = SupportedCodecList::new(vec![0, 1, 0xff, 4, 2, 0x12, 0x34]);
        assert_eq!(
            codecs.codec_bitmaps(),
            Some(vec![(0, vec![0xff]), (4, vec![0x12, 0x34])])
        );
        assert!(
            SupportedCodecList::new(vec![0, 2, 0xff])
                .codec_bitmaps()
                .is_none()
        );
        assert!(DrxParameter::new(vec![98, 0x90]).is_well_formed());
        assert!(!DrxParameter::new(vec![99, 0x90]).is_well_formed());
        assert!(!DrxParameter::new(vec![98, 0x50]).is_well_formed());
        assert!(DaylightSavingTime::new(vec![2]).is_well_formed());
        assert!(!DaylightSavingTime::new(vec![0xff]).is_well_formed());
    }

    #[test]
    fn emergency_and_spare_bit_fields_follow_delegated_rules() {
        assert!(EmergencyNumberList::new(vec![2, 0, 0x11]).is_well_formed());
        assert!(!EmergencyNumberList::new(vec![5, 0, 0x11]).is_well_formed());
        assert!(ExtendedEmergencyNumberList::new(vec![0, 1, 0x11, 0]).is_well_formed());
        assert!(!ExtendedEmergencyNumberList::new(vec![0, 5, 0x11, 0]).is_well_formed());
        assert!(VoiceDomainPreferenceAndUeUsageSetting::new(vec![7]).is_well_formed());
        assert!(!VoiceDomainPreferenceAndUeUsageSetting::new(vec![0xf8]).is_well_formed());
        assert!(N1UeNetworkCapability::new(vec![0x7f]).is_well_formed());
        assert!(!N1UeNetworkCapability::new(vec![0x80]).is_well_formed());
        assert!(NetworkResourceIdentifierContainer::new(vec![0x12, 0xc0]).is_well_formed());
        assert!(!NetworkResourceIdentifierContainer::new(vec![0x12, 1]).is_well_formed());
        assert!(NetworkName::new(vec![0x80]).is_well_formed());
        assert!(!NetworkName::new(vec![0xa0]).is_well_formed());
    }

    #[test]
    fn service_type_helpers_keep_receiver_fallbacks_separate_from_builders() {
        assert_eq!(
            ServiceTypeValue::from_value(3).effective(),
            ServiceTypeValue::MobileOriginatingCsFallbackOr1xCsFallback
        );
        assert_eq!(
            ServiceTypeValue::from_value(9).effective(),
            ServiceTypeValue::PacketServicesViaS1
        );
        assert_eq!(ServiceTypeValue::from_value(7).effective().name(), None);
        assert_eq!(
            ServiceType::from_service_type(ServiceTypeValue::PacketServicesViaS1).value,
            8
        );

        let cp = ControlPlaneServiceType::from_service_type(
            ControlPlaneServiceTypeValue::MobileTerminatingRequest,
            true,
        );
        assert_eq!(cp.value, 9);
        assert_eq!(
            cp.service_type(),
            ControlPlaneServiceTypeValue::MobileTerminatingRequest
        );
        assert!(cp.active());
        assert_eq!(
            ControlPlaneServiceTypeValue::from_value(7).effective(),
            ControlPlaneServiceTypeValue::MobileOriginatingRequest
        );
        assert_eq!(ControlPlaneServiceTypeValue::named(7), None);
        assert_eq!(
            ControlPlaneServiceType::new(0x0f).service_type().name(),
            None
        );
    }

    #[test]
    fn typed_network_and_relay_ie_accessors_preserve_valid_payloads() {
        let plmn = crate::common::plmn_at(&[0x02, 0xf8, 0x39]).unwrap();
        let list = PlmnList::from_plmns(&[plmn]).unwrap();
        assert_eq!(list.plmns(), [plmn]);
        let disaster_list = ListOfPlmnsToBeUsedInDisasterCondition::from_plmns(&[plmn]).unwrap();
        assert_eq!(disaster_list.plmns(), [plmn]);
        // Receivers ignore a truncated entry and skip an undecodable one;
        // the sender check rejects both.
        let truncated = ListOfPlmnsToBeUsedInDisasterCondition::new(vec![0x02, 0xf8, 0x39, 0x02]);
        assert_eq!(truncated.plmns(), [plmn]);
        assert!(!truncated.is_well_formed());
        let undecodable = PlmnList::new(vec![0xff, 0xff, 0xff, 0x02, 0xf8, 0x39]);
        assert_eq!(undecodable.plmns(), [plmn]);
        assert!(!undecodable.is_well_formed());
        assert!(PlmnList::from_plmns(&[plmn; 16]).is_err());
        // A PLMN identity whose digits are not decimal cannot be made.
        assert!(Plmn::from_digits([10, 0, 8], &[9, 3]).is_err());
        let sixteen = PlmnList::new([0x02, 0xf8, 0x39].repeat(16));
        assert_eq!(sixteen.plmns().len(), 15);
        assert!(ListOfPlmnsToBeUsedInDisasterCondition::new(vec![]).is_well_formed());
        assert!(MobileStationClassmark2::new(vec![0, 0, 0]).is_well_formed());
        assert!(!MobileStationClassmark2::new(vec![0x80, 0, 0]).is_well_formed());
        assert!(NbifomContainer::new(vec![1, 1, 1]).is_well_formed());
        assert!(!NbifomContainer::new(vec![]).is_well_formed());
        let nbifom = NbifomContainer::from_parameters(&[
            NbifomParameter {
                identifier: 0x09,
                contents: vec![0xff],
            },
            NbifomParameter {
                identifier: u8::from(NbifomParameterId::Status),
                contents: vec![0x07],
            },
        ])
        .unwrap();
        // An unassigned status is read as "protocol error, unspecified".
        assert_eq!(
            nbifom.status(),
            Some(NbifomStatus::ProtocolErrorUnspecified)
        );
        assert_eq!(nbifom.parameter(NbifomParameterId::Mode), None);
        assert!(!NbifomContainer::new(vec![1]).is_well_formed());
        assert!(!NbifomContainer::new(vec![1, 10]).is_well_formed());
        assert!(!NbifomContainer::new(vec![2, 1, 0]).is_well_formed());
        let default_access = NbifomContainer::new(vec![2, 1, 1]);
        assert!(default_access.is_well_formed_for(NbifomDirection::UeToNetwork));
        assert!(default_access.is_well_formed_for(NbifomDirection::NetworkToUe));
        let ip_flow_mapping = NbifomContainer::new(vec![5, 8, 7, 1, 0x41, 0, 0, 0, 0, 0]);
        assert!(ip_flow_mapping.is_well_formed_for(NbifomDirection::UeToNetwork));
        assert!(!ip_flow_mapping.is_well_formed_for(NbifomDirection::NetworkToUe));
        let wrong_h_length =
            NbifomContainer::new(vec![4, 12, 11, 1, 0x41, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!wrong_h_length.is_well_formed_for(NbifomDirection::UeToNetwork));
        let mixed_ipv4_ipv6 = NbifomContainer::new(
            [vec![4, 28, 27, 1, 0x41, 0, 0x05, 0, 0, 0], vec![0; 20]].concat(),
        );
        assert!(!mixed_ipv4_ipv6.is_well_formed_for(NbifomDirection::UeToNetwork));
        let mut ciphering_set = vec![0; 32];
        ciphering_set[18] = 1;
        assert!(CipheringKeyData::new(ciphering_set.clone()).is_well_formed());
        ciphering_set[18] = 31;
        assert!(!CipheringKeyData::new(ciphering_set.clone()).is_well_formed());
        ciphering_set[18] = 1;
        ciphering_set[23] = 1;
        assert!(!CipheringKeyData::new(ciphering_set).is_well_formed());
        assert!(!PlmnList::new(vec![0x02, 0xf8, 0x39, 0]).is_well_formed());

        assert!(SAndFSatelliteOperationParameters::new(vec![0x01, 0, 1]).is_well_formed());
        assert!(SAndFSatelliteOperationParameters::new(vec![0x08, 2, 7, 8]).is_well_formed());
        assert!(!SAndFSatelliteOperationParameters::new(vec![0x01]).is_well_formed());

        let contexts = RemoteUeContextList::new(vec![1, 2, 0, 0]);
        assert_eq!(contexts.context_octets(), Some(vec![&[0, 0][..]]));
        let context = &contexts.contexts().unwrap()[0];
        assert_eq!(context.address, RemoteUeAddress::NoIpInfo);
        assert!(contexts.is_well_formed());
        let empty_identity = RemoteUeContextList::new(vec![1, 3, 1, 0, 0]);
        assert!(empty_identity.contexts().is_none());
        assert!(!empty_identity.is_well_formed());
        // §9.9.4.20 sets the minimum IE length to 5 octets: one context.
        assert_eq!(RemoteUeContextList::new(vec![0]).contexts(), Some(vec![]));
        assert!(!RemoteUeContextList::new(vec![0]).is_well_formed());
        assert!(RemoteUeContextList::from_contexts(&[]).is_err());
        let reserved_identity = RemoteUeContextList::new(vec![1, 4, 1, 1, 0, 0]);
        assert!(reserved_identity.contexts().is_some());
        assert!(!reserved_identity.is_well_formed());
        let reserved_address = RemoteUeContextList::new(vec![1, 2, 0, 3]);
        assert!(reserved_address.contexts().is_some());
        assert!(!reserved_address.is_well_formed());
        let mut short_encrypted_imsi = vec![0x01];
        short_encrypted_imsi.extend([0; 15]);
        assert!(
            !RemoteUeUserIdentity {
                octets: short_encrypted_imsi
            }
            .is_well_formed()
        );
        assert!(RemoteUeContextList::new(vec![1, 0]).contexts().is_none());

        // IMSI 208930000000001 and an IPv4 address with a UDP port range.
        let context = RemoteUeContext {
            user_identities: vec![
                RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imsi, "208930000000001")
                    .unwrap(),
                RemoteUeUserIdentity::from_encrypted_imsi([0xab; 16]),
            ],
            address: RemoteUeAddress::Ipv4 {
                address: [10, 0, 0, 2],
                port: 1500,
                udp_port_range: Some(PortRange {
                    low: 1000,
                    high: 2000,
                }),
                tcp_port_range: None,
            },
        };
        let list = RemoteUeContextList::from_contexts(core::slice::from_ref(&context)).unwrap();
        assert!(list.is_well_formed());
        let decoded = &list.contexts().unwrap()[0];
        assert_eq!(decoded, &context);
        assert_eq!(
            decoded.user_identities[0].digits().as_deref(),
            Some("208930000000001")
        );
        assert_eq!(
            decoded.user_identities[1].encrypted_imsi(),
            Some([0xab; 16])
        );
        assert_eq!(decoded.user_identities[1].digits(), None);
        // Spare bits of octet j are ignored, and port-range indicators set
        // for an IPv6 prefix are not followed.
        let ipv6 = RemoteUeContext::from_bytes(&[0, 0xfa, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(
            ipv6.address,
            RemoteUeAddress::Ipv6Prefix([1, 2, 3, 4, 5, 6, 7, 8])
        );

        let address = core::net::IpAddr::V4(core::net::Ipv4Addr::new(192, 0, 2, 1));
        let ie = PkmfAddress::from_address(address);
        assert_eq!(ie.address(), Some(address));
    }

    #[test]
    fn mobile_identities_and_guti_follow_eps_wire_layout() {
        let imsi = EpsMobileIdentity::from_imsi("208930000000001").unwrap();
        assert_eq!(hex::encode(&imsi.value), "2980390000000010");
        assert_eq!(
            imsi.as_imsi()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some("208930000000001")
        );
        let even = EpsMobileIdentity::from_imsi("208930").unwrap();
        assert_eq!(
            even.as_imsi()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some("208930")
        );
        assert!(EpsMobileIdentity::from_imsi("1").is_err());
        assert!(EpsMobileIdentity::from_imei("12").is_err());
        assert!(EpsMobileIdentity::new(vec![0x29, 0x0a]).as_imsi().is_none());
        let imei = EpsMobileIdentity::from_imei("123456789012345");
        assert_eq!(
            imei.unwrap()
                .as_imei()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some("123456789012345")
        );
        let guti = GutiEps::new(
            Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap(),
            0x1234,
            0x56,
            0x789a_bcde,
        );
        assert_eq!(hex::encode(guti.to_nas_octets()), "f602f839123456789abcde");
        assert_eq!(EpsMobileIdentity::from_guti(guti).as_guti(), Some(guti));
    }

    #[test]
    fn tai_lists_parse_all_three_partial_list_types() {
        let plmn = Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap();
        let a = TaiEps::new(plmn, 0x1234);
        let b = TaiEps::new(plmn, 0x1235);
        assert_eq!(tai_of(&a.to_nas_octets()), Some(a));
        let different = TrackingAreaIdentityList::from_tais(&[a, b]).unwrap();
        assert_eq!(
            different.value,
            [
                0x41, 0x02, 0xf8, 0x39, 0x12, 0x34, 0x02, 0xf8, 0x39, 0x12, 0x35
            ]
        );
        assert_eq!(different.tais(), [a, b]);
        let one =
            TrackingAreaIdentityList::new(vec![0x01, 0x02, 0xf8, 0x39, 0x12, 0x34, 0x12, 0x35]);
        assert_eq!(
            one.entries(),
            [TaiListEntry::OnePlmnNonConsecutive {
                plmn,
                tacs: vec![0x1234, 0x1235]
            }]
        );
        assert_eq!(one.tais(), [a, b]);
        let range = TrackingAreaIdentityList::new(vec![0x21, 0x02, 0xf8, 0x39, 0x12, 0x34]);
        assert_eq!(
            range.entries(),
            [TaiListEntry::OnePlmnConsecutive {
                plmn,
                first_tac: 0x1234,
                count: 2
            }]
        );
        assert_eq!(range.tais(), [a, b]);
        assert!(range.is_well_formed());
        for refused in [
            [0x61, 0x02, 0xf8, 0x39, 0x12, 0x34],
            [0x81, 0x02, 0xf8, 0x39, 0x12, 0x34],
        ] {
            assert!(!TrackingAreaIdentityList::new(refused).receiver_syntax_is_valid());
        }
    }

    #[test]
    fn pdn_qos_ambr_bearer_and_capability_accessors() {
        let pdn = PdnAddressValue::Ipv4v6 {
            ipv6_interface_id: [1; 8],
            ipv4: [192, 0, 2, 1],
        };
        assert_eq!(PdnAddress::from_pdn_address(pdn).pdn_address(), Some(pdn));
        assert!(PdnAddressValue::from_bytes(&[3, 0, 0, 0, 0]).is_none());
        let ambr = ApnAmbr {
            downlink: 1,
            uplink: 2,
            extension: Some([3, 4]),
            extension2: Some([5, 6]),
        };
        assert_eq!(
            ApnAggregateMaximumBitRate::from_ambr(ambr).unwrap().ambr(),
            Some(ambr)
        );
        assert!(ApnAmbr::from_bytes_strict(&[1, 2, 3]).is_none());
        assert_eq!(ApnAmbr::from_bytes(&[1, 2, 3]).unwrap().extension, None);
        let qos = EpsQos {
            qci: 9,
            bit_rates: Some([1, 2, 3, 4]),
            extension: None,
            extension2: None,
        };
        assert_eq!(EpsQualityOfService::from_qos(qos).unwrap().qos(), Some(qos));
        assert!(qos.qci_is_network_valid());
        assert!(!EpsQos { qci: 11, ..qos }.qci_is_network_valid());
        assert!(EpsQos { qci: 65, ..qos }.qci_is_network_valid());
        assert!(EpsQos::from_bytes_strict(&[9, 1, 2]).is_none());
        assert_eq!(EpsQos::from_bytes(&[9, 1, 2]).unwrap().bit_rates, None);
        let mut status = EpsBearerContextStatus::from_bearers(&[1, 5, 15]).unwrap();
        assert_eq!(status.value, [0x22, 0x80]);
        assert_eq!(status.active_bearers(), [1, 5, 15]);
        status.set_active(1, false).unwrap();
        assert!(status.is_well_formed() && !status.is_active(1));
        assert!(EpsBearerContextStatus::from_bearers(&[0]).is_err());
        // TS 24.007 §11.1.4 and §11.4.2: the spare EBI(0) bit and extra
        // octets are ignored on receipt.
        let received = EpsBearerContextStatus::new(vec![0x21, 0x00, 0xff]);
        assert_eq!(received.active_bearers(), [5]);
        assert!(!received.is_well_formed());
        let mut short = EpsBearerContextStatus::new(vec![]);
        short.set_active(9, true).unwrap();
        assert_eq!(
            (short.value.len(), short.value.as_slice()),
            (2, [0x00, 0x02].as_slice())
        );
        let hc = HeaderCompressionConfigurationStatus::from_not_used_ebis(&[6, 8]).unwrap();
        assert_eq!(hc.value, [0x40, 0x01]);
        assert_eq!(hc.is_configuration_used(5), Some(true));
        assert_eq!(hc.not_used_ebis(), [6, 8]);
        assert_eq!(hc.is_configuration_used(0), None);
        let mut capability = UeNetworkCapability::new(vec![0, 0]);
        capability.set_eea(Algorithm::Aes as u8, true).unwrap();
        capability.set_eia(Algorithm::Aes as u8, true).unwrap();
        assert_eq!(capability.value, [0x20, 0x20]);
        assert!(capability.supports_eea(Algorithm::Aes as u8));
        assert!(!capability.supports_eia(Algorithm::Snow3g as u8));
    }

    #[test]
    fn typed_eps_ie_accessors_follow_spec_fallbacks() {
        assert_eq!(EpsAttachType::new(0).attach_type(), AttachType::EpsAttach);
        assert_eq!(PdnType::new(4).pdn_type().effective(), PdnTypeValue::Ipv6);
        assert_eq!(PdnType::from_pdn_type(PdnTypeValue::Ethernet).value, 6);
    }

    #[test]
    fn apn_labels_match_the_5gs_dnn_wire_form() {
        let apn = AccessPointName::from_string("internet.example").unwrap();
        let dnn = crate::nas_5gs::Dnn::new(apn.value.clone());
        assert_eq!(apn.as_string().as_deref(), Some("internet.example"));
        assert_eq!(dnn.as_string(), apn.as_string());
        assert_eq!(
            AccessPointName::from_string("internet.example")
                .unwrap()
                .value,
            apn.value
        );
        assert!(AccessPointName::from_string("invalid..apn").is_err());
    }

    /// A SECURITY MODE COMMAND repeats the algorithms that the UE sent
    /// (TS 24.301 §5.4.3.2).
    #[test]
    fn replayed_capabilities_are_made_from_what_the_ue_sent() {
        // EEA0-2, EIA0-2, UEA0-1 and UIA1, with UCS2 beside UIA.
        let sent = UeNetworkCapability::new(vec![0xe0, 0xe0, 0xc0, 0xc0]);
        let replayed = UeSecurityCapability::from_ue_network_capability(&sent);
        assert_eq!(replayed.value, [0xe0, 0xe0, 0xc0, 0x40]);
        assert!(replayed.matches_ue_network_capability(&sent));
        assert!(replayed.is_well_formed());
        // Without UMTS algorithms, the EPS octets alone.
        let eps = UeNetworkCapability::new(vec![0xf0, 0x70]);
        assert_eq!(
            UeSecurityCapability::from_ue_network_capability(&eps).value,
            [0xf0, 0x70]
        );
        // GEA2 and GEA3 of an MS network capability.
        let ms = MsNetworkCapability::new(vec![0x00, 0x60]);
        let mut gprs = UeSecurityCapability::from_ue_network_capability(&eps);
        gprs.set_gea_of(&ms);
        assert_eq!(gprs.value, [0xf0, 0x70, 0x00, 0x00, 0x30]);
        assert!(gprs.supports_gea(2) && gprs.supports_gea(3) && gprs.is_well_formed());
    }

    #[test]
    fn eps_cause_tables_preserve_unknown_values() {
        assert_eq!(EmmCause::new(3).cause(), Some(EmmCauseValue::IllegalUe));
        assert_eq!(
            EsmCause::new(0x1B).cause(),
            Some(EsmCauseValue::MissingOrUnknownApn)
        );
        // A value that the table does not list is kept by the IE.
        let unknown = EmmCause::new(0xFE);
        assert_eq!((unknown.cause(), unknown.value), (None, 0xFE));
        assert_eq!(unknown.encode().unwrap(), [0xFE]);
    }

    #[test]
    fn eps_bit_fields_follow_chapter_9_tables() {
        assert_eq!(
            EpsUpdateType::new(4).update_type().effective(),
            UpdateType::TaUpdating
        );
        let mut update = EpsUpdateType::new(0);
        update.set_active(true);
        assert!(update.active());
        assert_eq!(
            EpsUpdateResult::new(5).update_result(),
            Some(UpdateResult::CombinedTaLaUpdatedAndIsrActivated)
        );
        assert_eq!(
            EpsMobileIdentity::new(vec![0xF6]).identity_type(),
            Some(MobileIdentityTypeEps::Guti)
        );
        assert_eq!(
            KeySetIdentifier::new(0x0A).key_set_identifier(),
            KeySetIdentifierValue::Mapped(2)
        );
        assert!(
            KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Native(7)).is_err()
        );
        assert!(DetachType::from_ue_detach_kind(UeDetachKind::EpsDetach, true).switch_off());
    }

    #[test]
    fn pco_lengths_depend_on_message_direction() {
        let pco = Pco {
            configuration_protocol: 0,
            entries: vec![
                PcoEntry {
                    identifier: 0x0023,
                    contents: vec![0xaa, 0xbb],
                },
                PcoEntry {
                    identifier: 0x0041,
                    contents: vec![0xcc],
                },
            ],
        };
        let downlink = pco.to_bytes(PcoDirection::Downlink).unwrap();
        assert_eq!(
            downlink,
            [0x80, 0, 0x23, 0, 2, 0xaa, 0xbb, 0, 0x41, 0, 1, 0xcc]
        );
        assert_eq!(
            Pco::from_bytes(&downlink, PcoDirection::Downlink),
            Some(pco.clone())
        );
        assert_eq!(
            ExtendedProtocolConfigurationOptions::from_pco(&pco, PcoDirection::Downlink)
                .unwrap()
                .pco(PcoDirection::Downlink),
            Some(pco)
        );
        assert!(Pco::from_bytes(&downlink, PcoDirection::Uplink).is_none());
        assert!(
            ProtocolConfigurationOptions::from_pco(
                &Pco {
                    configuration_protocol: 0,
                    entries: vec![PcoEntry {
                        identifier: 0x0041,
                        contents: vec![0; 250]
                    }]
                },
                PcoDirection::Uplink
            )
            .is_err()
        );
    }

    #[test]
    fn received_pco_selector_fallback_cannot_be_built_for_sending() {
        let pco = Pco::from_bytes(&[0x81], PcoDirection::Uplink).unwrap();
        assert_eq!(pco.configuration_protocol, 1);
        assert!(pco.to_bytes(PcoDirection::Uplink).is_err());
        assert!(ProtocolConfigurationOptions::from_pco(&pco, PcoDirection::Uplink).is_err());
    }

    #[test]
    fn pco_ignores_invalid_units_without_losing_valid_units() {
        // TS 24.008 §10.5.6.3: uplink address requests are empty, IPv4
        // Link MTU is exactly two octets in downlink, and NBIFOM mode is 0/1.
        let uplink = [
            0x80, 0x00, 0x0c, 0x01, 0xff, // invalid P-CSCF IPv4 request
            0x00, 0x0d, 0x00, // valid DNS IPv4 request
            0x00, 0x14, 0x01, 0x02, // invalid NBIFOM mode
        ];
        let parsed = Pco::from_bytes(&uplink, PcoDirection::Uplink).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].identifier, 0x000c);
        assert_eq!(parsed.entries[1].identifier, 0x000d);

        let downlink = [
            0x80, 0x00, 0x10, 0x01, 0x05, // invalid IPv4 Link MTU
            0x00, 0x0c, 0x04, 192, 0, 2, 1, // valid P-CSCF IPv4 address
        ];
        let parsed = Pco::from_bytes(&downlink, PcoDirection::Downlink).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].identifier, 0x000c);

        let invalid_sender = Pco {
            configuration_protocol: 0,
            entries: vec![PcoEntry {
                identifier: 0x0010,
                contents: vec![0x05],
            }],
        };
        assert!(invalid_sender.to_bytes(PcoDirection::Downlink).is_err());
    }

    #[test]
    fn eps_timers_distinguish_zero_from_deactivated_and_t3412_integrity() {
        assert_eq!(
            T3412Value::from_unit_value(GprsTimerUnit::OneMinute, 0)
                .unwrap()
                .to_seconds(),
            None
        );
        assert_eq!(
            GprsTimer::from_unit_value(GprsTimerUnit::OneMinute, 0)
                .unwrap()
                .to_seconds(),
            Some(0)
        );
        assert_eq!(
            T3412Value::from_unit_value(GprsTimerUnit::Deactivated, 1)
                .unwrap()
                .to_seconds(),
            None
        );
        let extended =
            T3412ExtendedValue::from_unit_value(GprsTimer3Unit::ThreeHundredTwentyHours, 1)
                .unwrap();
        assert_eq!(extended.to_seconds_with_integrity(false), Some(3_600));
        assert_eq!(extended.to_seconds_with_integrity(true), Some(1_152_000));
        assert_eq!(
            GprsTimer3::from_unit_value(GprsTimer3Unit::ThreeHundredTwentyHours, 1)
                .unwrap()
                .to_seconds(),
            None
        );
        assert_eq!(
            T3412ExtendedValue::from_unit_value(GprsTimer3Unit::OneMinute, 0)
                .unwrap()
                .to_seconds_with_integrity(true),
            None
        );
    }

    #[test]
    fn tai_list_ignores_spare_bits_and_reads_large_counts_as_sixteen() {
        // Table 9.9.3.33.1: bit 8 of octet 1 is spare.
        let spare = TrackingAreaIdentityList::new(vec![0x80, 0x02, 0xf8, 0x39, 0x12, 0x34]);
        assert_eq!(spare.tais().len(), 1);
        assert!(!spare.is_well_formed());
        // Count 11111 is unused and read as 16 by the UE.
        let mut value = vec![0x1f, 0x02, 0xf8, 0x39];
        value.extend((0..16u16).flat_map(u16::to_be_bytes));
        let list = TrackingAreaIdentityList::new(value);
        assert_eq!(list.tais().len(), 16);
        assert!(!list.is_well_formed());
        let trailing = TrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 1, 0xff]);
        assert!(!trailing.is_well_formed());
    }

    #[test]
    fn tai_list_receiver_keeps_first_sixteen_entries() {
        let plmn = Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap();
        let tai = TaiEps::new(plmn, 1);
        let mut value = TrackingAreaIdentityList::from_tais(&[tai; 16])
            .unwrap()
            .value
            .to_vec();
        value.extend_from_slice(&[0x40]);
        value.extend_from_slice(&tai.to_nas_octets());
        assert_eq!(TrackingAreaIdentityList::new(value).tais().len(), 16);
    }

    #[test]
    fn tft_receiver_rules_and_error_classes() {
        // Spare bits 8-7 of the filter header, bits 8-5 of a deleted
        // filter identifier, and the flow label spare nibble are ignored.
        let received = [0x21, 0xf2, 7, 4, 0x80, 0xf1, 0x23, 0x45];
        let tft = Tft::parse(&received).unwrap();
        let filter = &tft.packet_filters[0];
        assert_eq!(
            (filter.identifier, filter.direction_value()),
            (2, TftPacketFilterDirection::Bidirectional)
        );
        assert_eq!(
            filter.components(),
            Some(vec![TftPacketFilterComponent::FlowLabel(0x12345)])
        );
        assert!(!TrafficFlowTemplate::new(received).is_well_formed());
        assert_eq!(
            Tft::parse(&[0xa2, 0xf1, 0x01])
                .unwrap()
                .packet_filters
                .len(),
            2
        );
        // "Delete existing TFT" with a parameters list is accepted on receipt.
        let delete = Tft::parse(&[0x50, 0x02, 0x04, 0, 1, 0, 2]).unwrap();
        assert_eq!(
            delete.parameters[0].value(),
            TftParameterValue::FlowIdentifier {
                media_component: 1,
                ip_flow: 2
            }
        );
        assert!(delete.to_bytes().is_err());

        // §6.4.3.4: operation and count errors are #42, filter errors #45.
        assert_eq!(Tft::parse(&[0xe0]), Err(TftError::SyntacticalTftOperation));
        assert_eq!(
            Tft::parse(&[0x40, 0x01]),
            Err(TftError::SyntacticalTftOperation)
        );
        assert_eq!(
            Tft::parse(&[0x22, 0x21, 1, 2, 0x30, 6]),
            Err(TftError::SyntacticalTftOperation)
        );
        let reserved = Tft::parse(&[0x21, 0x21, 1, 2, 0x31, 6]).unwrap_err();
        assert_eq!(
            reserved.esm_cause(),
            EsmCauseValue::SyntacticalErrorsInPacketFilters
        );
        // A non-IP Ethertype with an IP component, and IPv4 with IPv6 remote.
        let ether = [0x21, 0x21, 1, 5, 0x87, 0x88, 0xa8, 0x30, 6];
        assert_eq!(Tft::parse(&ether), Err(TftError::SyntacticalPacketFilter));
        let mut both = vec![0x21, 0x21, 1, 26, 0x10];
        both.extend([0; 8]);
        both.extend([0x21]);
        both.extend([0; 17]);
        assert_eq!(Tft::parse(&both), Err(TftError::SyntacticalPacketFilter));
        // Consecutive Authorization Tokens are a semantical
        // TFT error (TS 24.008 Table 10.5.162), ESM cause #41.
        let tokens = [
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0x01, 0x01, 0xaa,
            0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ];
        let error = Tft::parse(&tokens).unwrap_err();
        assert_eq!(error, TftError::SemanticTftOperation);
        assert_eq!(
            error.esm_cause(),
            EsmCauseValue::SemanticErrorInTheTftOperation
        );
        // A token without a following Flow Identifier stays syntactical.
        assert_eq!(
            Tft::parse(&tokens[..16]),
            Err(TftError::SyntacticalTftOperation)
        );

        // A received traffic flow aggregate may use assigned identifiers;
        // only the UE sender rule requires identifier 0 for new filters.
        let aggregate = TrafficFlowAggregateDescription::new(vec![0x21, 0x25, 1, 2, 0x30, 17]);
        assert!(aggregate.tft().is_some() && !aggregate.is_well_formed());
        assert!(TrafficFlowAggregateDescription::ignore().is_well_formed());
        // The network's TFT never uses "Ignore this IE".
        assert!(TrafficFlowTemplate::new(vec![0x00]).tft().is_some());
        assert!(!TrafficFlowTemplate::new(vec![0x00]).is_well_formed());

        let filter = TftPacketFilter::from_components(
            1,
            TftPacketFilterDirection::Uplink,
            3,
            &[
                TftPacketFilterComponent::Ipv4RemoteAddress {
                    address: [192, 0, 2, 0],
                    mask: [255, 255, 255, 0],
                },
                TftPacketFilterComponent::RemotePortRange {
                    low: 5060,
                    high: 5061,
                },
                TftPacketFilterComponent::CTagPcpDei { pcp: 5, dei: true },
            ],
        )
        .unwrap();
        assert_eq!(
            &filter.contents[9..],
            [0x51, 0x13, 0xc4, 0x13, 0xc5, 0x85, 0x0b]
        );
        let tft = Tft {
            operation: TftOperation::Create,
            packet_filters: vec![filter],
            parameters: vec![],
        };
        assert!(
            TrafficFlowTemplate::from_tft(&tft)
                .unwrap()
                .is_well_formed()
        );
        assert!(
            TftPacketFilterComponent::FlowLabel(0x10_0000)
                .to_bytes()
                .is_err()
        );
    }

    #[test]
    fn tft_packet_filters_and_parameters_round_trip() {
        let tft = Tft {
            operation: TftOperation::Create,
            packet_filters: vec![TftPacketFilter {
                identifier: 2,
                direction: 3,
                precedence: Some(10),
                contents: vec![0x30, 0x11],
            }],
            parameters: vec![TftParameter {
                identifier: 2,
                contents: vec![0, 0, 0, 1],
            }],
        };
        let wire = tft.to_bytes().unwrap();
        assert_eq!(wire, [0x31, 0x32, 10, 2, 0x30, 0x11, 2, 4, 0, 0, 0, 1]);
        assert_eq!(Tft::from_bytes(&wire), Some(tft.clone()));
        assert_eq!(
            TrafficFlowTemplate::from_tft(&tft).unwrap().tft(),
            Some(tft)
        );
        // "No TFT operation" without parameters is a sender error only.
        assert!(Tft::from_bytes(&[0xc0]).is_some());
        assert!(Tft::from_bytes_strict(&[0xc0]).is_none());
        assert!(Tft::from_bytes(&[0x20]).is_none());
        assert!(Tft::from_bytes(&[0xd0]).is_none());
        assert!(Tft::from_bytes(&[0x31, 0x32, 10, 2, 0x10]).is_none());
        assert!(Tft::from_bytes(&[0x21, 0x10, 1, 1, 0x10]).is_none());
        assert!(Tft::from_bytes(&[0x22, 0x32, 1, 2, 0x30, 0x11, 0x32, 2, 2, 0x30, 0x11]).is_none());
        assert!(Tft::from_bytes(&[0x31, 0x32, 1, 2, 0x30, 0x11, 2, 1, 0]).is_none());
        // Packet filter identifier parameters use bits 4-1 only.
        let spare = [0x31, 0x32, 1, 2, 0x30, 0x11, 3, 1, 0xf1];
        assert!(Tft::from_bytes(&spare).is_some() && Tft::from_bytes_strict(&spare).is_none());
        let aggregate = [0x22, 0x30, 1, 2, 0x30, 0x11, 0x30, 2, 2, 0x30, 0x11];
        assert!(Tft::from_bytes(&aggregate).is_none());
        let aggregate_ie = TrafficFlowAggregateDescription::new(aggregate);
        let parsed = aggregate_ie.tft().unwrap();
        assert_eq!(
            TrafficFlowAggregateDescription::from_tft(&parsed)
                .unwrap()
                .value,
            aggregate
        );
        // TS 24.008 Table 10.5.162: the contents after "Ignore this IE" are ignored.
        assert_eq!(
            Tft::from_bytes(&[0x00, 0xff]).unwrap().operation,
            TftOperation::Ignore
        );
        assert!(Tft::from_bytes(&[0x10, 0xff]).is_none());
        let ignore = Tft::from_bytes(&[0x00]).unwrap();
        assert_eq!(ignore.operation, TftOperation::Ignore);
        assert_eq!(ignore.to_bytes(), Ok(vec![0x00]));
        assert!(Tft::from_bytes(&[0x10]).is_none());
        assert_eq!(
            TrafficFlowAggregateDescription::from_tft(&ignore)
                .unwrap()
                .value,
            [0x00]
        );
    }

    #[test]
    fn identity_response_mobile_identity_uses_classic_type_codes() {
        let imsi = MobileIdentity::from_imsi("208930000000001").unwrap();
        assert_eq!(
            imsi.as_imsi()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some("208930000000001")
        );
        let imei = MobileIdentity::from_imei("490154203237518").unwrap();
        assert_eq!(imei.value[0] & 7, 2);
        assert_eq!(
            imei.as_imei()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some("490154203237518")
        );
        assert_eq!(
            MobileIdentity::from_imei_tac_snr("49015420323751")
                .unwrap()
                .as_imei()
                .map(|imei| imei.to_string())
                .as_deref(),
            Some("490154203237510")
        );
        assert_eq!(
            EpsMobileIdentity::from_imei_tac_snr("49015420323751")
                .unwrap()
                .as_imei()
                .map(|imei| imei.to_string())
                .as_deref(),
            Some("490154203237510")
        );
        let imeisv = MobileIdentity::from_imeisv("4901542032375183").unwrap();
        assert_eq!(imeisv.value.len(), 9);
        assert_eq!(
            imeisv
                .as_imeisv()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some("4901542032375183")
        );
        let tmsi = MobileIdentity::from_tmsi(0x1234_5678);
        assert_eq!(tmsi.value, [0xf4, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(tmsi.as_tmsi(), Some(0x1234_5678));
        assert!(MobileIdentity::new(vec![0]).is_no_identity());
    }
}
