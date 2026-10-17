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

//! Raw wire-format Information Element types and codec traits.
//!
//! This is **Layer 1** of the crate. Every information element (IE) struct
//! here holds the value of its IE in a `pub value` field, and implements
//! [`Encode`]/[`Decode`] for the format that 3GPP TS 24.007 &sect;11.2 gives
//! the IE without its information element identifier (IEI). The IEI is that
//! of the place the IE has in a message: the message writes and reads it,
//! and an IE type is the same whether its field is mandatory or optional.
//!
//! For typed, semantic access to these bytes (enums, parsers, builders), see the
//! [`ie`](crate::nas_5gs::ie) module (Layer 3).
//!
//! # IE format summary
//!
//! | Format | Length indicator | `value` | Example |
//! |--------|------------------|---------|---------|
//! | V      | none             | `u8`, `u16`, or [`Octets`] of a fixed length | [`NasFGmmCause`], [`NasGprsTimer`] |
//! | Half octet | none         | `u8`, four bits | [`NasMicoIndication`] |
//! | LV     | one octet        | [`Octets`] | [`NasNssai`], [`NasDnn`], [`NasAbba`] |
//! | LV-E   | two octets       | [`Octets`] | [`NasFGsMobileIdentity`], [`NasEapMessage`] |

// `Result` is not re-exported: `use oxirush_nas::nas_5gs::*` would replace the
// `Result` of the standard library with an alias that takes one type.
use crate::common::Reader;
pub(crate) use crate::common::Result;
pub use crate::common::{
    Decode, Encode, IeFault, MAX_IE_VALUE_LENGTH, NasError, Octets, ValueError, ValueFault,
};
use crate::common::{nas_ie_lv, nas_ie_lve, nas_ie_tv1, nas_ie_v, nas_ie_v_fixed, nas_ie_v_u16};
use crate::prelude::*;

// The IE types that TS 24.008, TS 24.301 or TS 24.501 defines and the other
// specification reuses.
pub use crate::common::types::{
    NasAccessTechnologyUtilizationControl, NasAuthenticationFailureParameter,
    NasAuthenticationParameterAutn, NasAuthenticationParameterRand,
    NasAuthenticationResponseParameter, NasDaylightSavingTime, NasEmergencyNumberList,
    NasEpsBearerContextStatus, NasExtendedDrxParameters, NasExtendedEmergencyNumberList,
    NasExtendedProtocolConfigurationOptions, NasGprsTimer, NasGprsTimer2, NasGprsTimer3,
    NasImeisvRequest, NasListOfPlmnsToBeUsedInDisasterCondition, NasMobileStationClassmark2,
    NasNetworkName, NasNon3GppNwProvidedPolicies, NasPlmnIdentity, NasPlmnList,
    NasRegistrationWaitRange, NasReleaseAssistanceIndication, NasServingPlmnRateControl,
    NasSupportedCodecList, NasTimeZone, NasTimeZoneAndTime, NasUeRadioCapabilityId,
    NasUeRadioCapabilityIdDeletionIndication, NasUeRequestType, NasUeStatus,
    NasUnavailabilityConfiguration, NasUnavailabilityInformation, NasWusAssistanceInformation,
};

/// Extended Protocol Discriminator for 5GS Session Management (0x2E).
pub const EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM: u8 = 0x2e;
/// Extended Protocol Discriminator for 5GS Mobility Management (0x7E).
pub const EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM: u8 = 0x7e;

// ── V format (value only) ────────────────────────────────────────────────────

nas_ie_v!(
    /// De-Registration Type (TS 24.501 §9.11.3.20). V format (1 byte).
    NasDeRegistrationType
);
nas_ie_v!(
    /// 5GMM Cause (TS 24.501 §9.11.3.2). V format (1 byte).
    NasFGmmCause
);
nas_ie_v!(
    /// Control Plane Service Type (TS 24.501 §9.11.3.18D). V format (1 byte).
    NasControlPlaneServiceType
);
nas_ie_v!(
    /// 5GS Identity Type (TS 24.501 §9.11.3.3). Type 3, one octet.
    ///
    /// Only the lower 3 bits are significant. Use [`MobileIdentityType`](crate::nas_5gs::ie::MobileIdentityType)
    /// for typed access via the `identity_type()` method defined in the [`ie`](crate::nas_5gs::ie) module.
    NasFGsIdentityType
);
nas_ie_v!(
    /// 5GS Registration Type (TS 24.501 §9.11.3.7). Half octet.
    NasFGsRegistrationType
);
nas_ie_v!(
    /// Service type (TS 24.501 §9.11.3.50). Half octet.
    NasServiceType
);
nas_ie_lv!(
    /// T3512 value and requested T3512 value (TS 24.501 §8.2.7.16,
    /// §8.2.6.39): a GPRS timer 3 (§9.11.2.5) whose unit may be 320 hours
    /// (TS 24.008 Table 10.5.163a NOTE 1). LV format.
    NasT3512Value
);
nas_ie_v!(
    /// NAS Key Set Identifier (TS 24.501 §9.11.3.32). V format (1 byte).
    NasKeySetIdentifier
);
nas_ie_v!(
    /// Payload Container Type (TS 24.501 §9.11.3.40). Type 1 or, with spare
    /// bits, one octet.
    ///
    /// Only the lower 4 bits are significant. Use [`PayloadContainerKind`](crate::nas_5gs::ie::PayloadContainerKind)
    /// for typed access via the `kind()` method defined in the [`ie`](crate::nas_5gs::ie) module.
    NasPayloadContainerType
);
nas_ie_v!(
    /// NAS Security Algorithms (TS 24.501 §9.11.3.34). V format (1 byte).
    NasSecurityAlgorithms
);
nas_ie_v_u16!(
    /// Integrity Protection Maximum Data Rate (TS 24.501 §9.11.4.7). V format (2 bytes).
    NasIntegrityProtectionMaximumDataRate
);
nas_ie_v_fixed!(
    /// Maximum Number of Supported Packet Filters (TS 24.501 §9.11.4.9).
    ///
    /// Type 3 IE per TS 24.007 §11.2.4: a **fixed 2-octet value** (an 11-bit
    /// count and 5 spare bits) after the IEI, without a length octet.
    NasMaximumNumberOfSupportedPacketFilters, 2
);

// ── LV format (variable-length) ──────────────────────────────────────────────

nas_ie_lv!(
    /// ABBA (TS 24.501 §9.11.3.10). LV format.
    NasAbba
);
nas_ie_lv!(
    /// 5GS Registration Result (TS 24.501 §9.11.3.6). LV format.
    NasFGsRegistrationResult
);
nas_ie_lv!(
    /// Session-AMBR (TS 24.501 §9.11.4.14). LV format.
    NasSessionAmbr
);
nas_ie_lv!(
    /// UE Security Capability (TS 24.501 §9.11.3.54). LV format.
    NasUeSecurityCapability
);

// ── LV-E format (extended variable-length) ───────────────────────────────────

nas_ie_lve!(
    /// 5GS Mobile Identity (TS 24.501 §9.11.3.4). LV-E format.
    NasFGsMobileIdentity
);
nas_ie_lve!(
    /// Payload Container (TS 24.501 §9.11.3.39). LV-E format.
    NasPayloadContainer
);
nas_ie_lve!(
    /// QoS Rules (TS 24.501 §9.11.4.13). LV-E format.
    NasQosRules
);

// ── Half octet ───────────────────────────────────────────────────────────────

nas_ie_tv1!(
    /// Access Type (TS 24.501 §9.11.2.1A). Half octet.
    NasAccessType
);
nas_ie_tv1!(
    /// Additional Configuration Indication (TS 24.501 §9.11.3.74). Half octet.
    NasAdditionalConfigurationIndication
);
nas_ie_tv1!(
    /// Allowed SSC Mode (TS 24.501 §9.11.4.5). Half octet.
    NasAllowedSscMode
);
nas_ie_tv1!(
    /// Always-on PDU Session Indication (TS 24.501 §9.11.4.3). Half octet.
    NasAlwaysOnPduSessionIndication
);
nas_ie_tv1!(
    /// Always-on PDU Session Requested (TS 24.501 §9.11.4.4). Half octet.
    NasAlwaysOnPduSessionRequested
);
nas_ie_tv1!(
    /// Configuration Update Indication (TS 24.501 §9.11.3.18). Half octet.
    NasConfigurationUpdateIndication
);
nas_ie_tv1!(
    /// Control Plane Only Indication (TS 24.501 §9.11.4.23). Half octet.
    NasControlPlaneOnlyIndication
);
nas_ie_tv1!(
    /// LP-WUS Status (TS 24.501 §9.11.3.112). Half octet.
    NasLpWusStatus
);
nas_ie_tv1!(
    /// MA PDU Session Information (TS 24.501 §9.11.3.31A). Half octet.
    NasMaPduSessionInformation
);
nas_ie_tv1!(
    /// MICO Indication (TS 24.501 §9.11.3.31). Half octet.
    NasMicoIndication
);
nas_ie_tv1!(
    /// N5GC Indication (TS 24.501 §9.11.3.72). Half octet.
    NasN5gcIndication
);
nas_ie_tv1!(
    /// Network Slicing Indication (TS 24.501 §9.11.3.36). Half octet.
    NasNetworkSlicingIndication
);
nas_ie_tv1!(
    /// NSSAI Inclusion Mode (TS 24.501 §9.11.3.37A). Half octet.
    NasNssaiInclusionMode
);
nas_ie_tv1!(
    /// PDU Session Type (TS 24.501 §9.11.4.11). Half octet.
    NasPduSessionType
);
nas_ie_tv1!(
    /// Priority Indicator (TS 24.501 §9.11.3.91). Half octet.
    NasPriorityIndicator
);
nas_ie_tv1!(
    /// Request Type (TS 24.501 §9.11.3.47). Half octet.
    NasRequestType
);
nas_ie_tv1!(
    /// SMS Indication (TS 24.501 §9.11.3.50A). Half octet.
    NasSmsIndication
);
nas_ie_tv1!(
    /// SSC Mode (TS 24.501 §9.11.4.16). Half octet.
    NasSscMode
);

// ── V format (one octet) ─────────────────────────────────────────────────────

nas_ie_v!(
    /// EPS NAS Security Algorithms (TS 24.501 §9.11.3.25). V format (1 byte).
    NasEpsNasSecurityAlgorithms
);
nas_ie_v!(
    /// N1 mode to S1 mode NAS transparent container (TS 24.501 §9.11.2.7). V format (1 byte).
    NasN1ModeToS1ModeNasTransparentContainer
);
nas_ie_v!(
    /// PDU Session Identity 2 (TS 24.501 §9.11.3.41). V format (1 byte).
    NasPduSessionIdentity2
);

// ── V format (fixed length) ──────────────────────────────────────────────────

nas_ie_v_fixed!(
    /// 5GS Tracking Area Identity (TS 24.501 §9.11.3.8). V format (6 bytes: PLMN + TAC).
    NasFGsTrackingAreaIdentity, 6
);

// ── LV format (variable-length) ──────────────────────────────────────────────

nas_ie_lv!(
    /// Additional 5G Security Information (TS 24.501 §9.11.3.12). LV format.
    NasAdditional5gSecurityInformation
);
nas_ie_lv!(
    /// Additional Information (TS 24.501 §9.11.2.1). LV format.
    NasAdditionalInformation
);
nas_ie_lv!(
    /// Additional Information Requested (TS 24.501 §9.11.3.12A). LV format.
    NasAdditionalInformationRequested
);
nas_ie_lv!(
    /// Allowed PDU Session Status (TS 24.501 §9.11.3.13). LV format.
    NasAllowedPduSessionStatus
);
nas_ie_lv!(
    /// DNN (TS 24.501 §9.11.2.1B). LV format.
    NasDnn
);
nas_ie_lv!(
    /// Intra N1 mode NAS transparent container (TS 24.501 §9.11.2.6). LV format.
    NasIntraN1ModeNasTransparentContainer
);
nas_ie_lv!(
    /// DS-TT Ethernet Port MAC Address (TS 24.501 §9.11.4.25). LV format.
    NasDsTtEthernetPortMacAddress
);
nas_ie_lv!(
    /// Ethernet Header Compression Configuration (TS 24.501 §9.11.4.28). LV format.
    NasEthernetHeaderCompressionConfiguration
);
nas_ie_lv!(
    /// Extended Rejected NSSAI (TS 24.501 §9.11.3.75). LV format.
    NasExtendedRejectedNssai
);
nas_ie_lv!(
    /// 5GMM Capability (TS 24.501 §9.11.3.1). LV format.
    NasFGmmCapability
);
nas_ie_lv!(
    /// 5GS Additional Request Result (TS 24.501 §9.11.3.81). LV format.
    NasFGsAdditionalRequestResult
);
nas_ie_lv!(
    /// 5GS DRX Parameters (TS 24.501 §9.11.3.2A). LV format.
    NasFGsDrxParameters
);
nas_ie_lv!(
    /// 5GS Network Feature Support (TS 24.501 §9.11.3.5). LV format.
    NasFGsNetworkFeatureSupport
);
nas_ie_lv!(
    /// 5GS Tracking Area Identity List (TS 24.501 §9.11.3.9). LV format.
    NasFGsTrackingAreaIdentityList
);
nas_ie_lv!(
    /// 5GS Update Type (TS 24.501 §9.11.3.9A). LV format.
    NasFGsUpdateType
);
nas_ie_lv!(
    /// 5GSM Capability (TS 24.501 §9.11.4.1). LV format.
    NasFGsmCapability
);
nas_ie_lv!(
    /// 5GSM Congestion Re-attempt Indicator (TS 24.501 §9.11.4.21). LV format.
    NasFGsmCongestionReAttemptIndicator
);
nas_ie_lv!(
    /// 5GSM Network Feature Support (TS 24.501 §9.11.4.18). LV format.
    NasFGsmNetworkFeatureSupport
);
nas_ie_lv!(
    /// IP Header Compression Configuration (TS 24.501 §9.11.4.24). LV format.
    NasIpHeaderCompressionConfiguration
);
nas_ie_lv!(
    /// Mapped NSSAI (TS 24.501 §9.11.3.31B). LV format.
    NasMappedNssai
);
nas_ie_lv!(
    /// NB-N1 Mode DRX Parameters (TS 24.501 §9.11.3.73). LV format.
    NasNbN1ModeDrxParameters
);
nas_ie_lv!(
    /// NID (TS 24.501 §9.11.3.79). LV format.
    NasNid
);
nas_ie_lv!(
    /// NSSAI (TS 24.501 §9.11.3.37). LV format.
    NasNssai
);
nas_ie_lv!(
    /// Paging Restriction (TS 24.501 §9.11.3.77). LV format.
    NasPagingRestriction
);
nas_ie_lv!(
    /// PDU Address (TS 24.501 §9.11.4.10). LV format.
    NasPduAddress
);
nas_ie_lv!(
    /// PDU Session Pair ID (TS 24.501 §9.11.4.32). LV format.
    NasPduSessionPairId
);
nas_ie_lv!(
    /// PDU Session Reactivation Result (TS 24.501 §9.11.3.42). LV format.
    NasPduSessionReactivationResult
);
nas_ie_lv!(
    /// PDU Session Status (TS 24.501 §9.11.3.44). LV format.
    NasPduSessionStatus
);
nas_ie_lv!(
    /// PEIPS Assistance Information (TS 24.501 §9.11.3.80). LV format.
    NasPeipsAssistanceInformation
);
nas_ie_lv!(
    /// Re-attempt Indicator (TS 24.501 §9.11.4.17). LV format.
    NasReAttemptIndicator
);
nas_ie_lv!(
    /// Rejected NSSAI (TS 24.501 §9.11.3.46). LV format.
    NasRejectedNssai
);
nas_ie_lv!(
    /// S1 mode to N1 mode NAS transparent container (TS 24.501 §9.11.2.9). LV format.
    NasS1ModeToN1ModeNasTransparentContainer
);
nas_ie_lv!(
    /// RSN (TS 24.501 §9.11.4.33). LV format.
    NasRsn
);
nas_ie_lv!(
    /// S1 UE Network Capability (TS 24.501 §9.11.3.48). LV format.
    NasS1UeNetworkCapability
);
nas_ie_lv!(
    /// S1 UE Security Capability (TS 24.501 §9.11.3.48A). LV format.
    NasS1UeSecurityCapability
);
nas_ie_lv!(
    /// S-NSSAI (TS 24.501 §9.11.2.8). LV format.
    NasSNssai
);
nas_ie_lv!(
    /// Service Area List (TS 24.501 §9.11.3.49). LV format.
    NasServiceAreaList
);
nas_ie_lv!(
    /// SM PDU DN Request Container (TS 24.501 §9.11.4.15). LV format.
    NasSmPduDnRequestContainer
);
nas_ie_lv!(
    /// Time duration (TS 24.501 §9.11.2.19, referring to TS 24.301 §9.9.3.68). LV format.
    NasTimeDuration
);
nas_ie_lv!(
    /// Truncated 5G-S-TMSI Configuration (TS 24.501 §9.11.3.70). LV format.
    NasTruncatedFGSTmsiConfiguration
);
nas_ie_lv!(
    /// UE DS-TT Residence Time (TS 24.501 §9.11.4.26). LV format.
    NasUeDsTtResidenceTime
);
nas_ie_lv!(
    /// UE Usage Setting (TS 24.501 §9.11.3.55). LV format.
    NasUeUsageSetting
);
nas_ie_lv!(
    /// Uplink Data Status (TS 24.501 §9.11.3.57). LV format.
    NasUplinkDataStatus
);

// ── LV-E format (extended variable-length) ───────────────────────────────────

nas_ie_lve!(
    /// ATSSS Container (TS 24.501 §9.11.4.22). LV-E format.
    NasAtsssContainer
);
nas_ie_lve!(
    /// CAG Information List (TS 24.501 §9.11.3.18A). LV-E format.
    NasCagInformationList
);
nas_ie_lve!(
    /// Ciphering Key Data (TS 24.501 §9.11.3.18C). LV-E format.
    NasCipheringKeyData
);
nas_ie_lve!(
    /// EAP Message (TS 24.501 §9.11.2.2). LV-E format.
    NasEapMessage
);
nas_ie_lve!(
    /// EPS NAS Message Container (TS 24.501 §9.11.3.24). LV-E format.
    NasEpsNasMessageContainer
);
nas_ie_lve!(
    /// Extended CAG Information List (TS 24.501 §9.11.3.86). LV-E format.
    NasExtendedCagInformationList
);
nas_ie_lve!(
    /// LADN Indication (TS 24.501 §9.11.3.29). LV-E format.
    NasLadnIndication
);
nas_ie_lve!(
    /// LADN Information (TS 24.501 §9.11.3.30). LV-E format.
    NasLadnInformation
);
nas_ie_lve!(
    /// Mapped EPS Bearer Contexts (TS 24.501 §9.11.4.8). LV-E format.
    NasMappedEpsBearerContexts
);
nas_ie_lve!(
    /// NAS Message Container (TS 24.501 §9.11.3.33). LV-E format.
    NasMessageContainer
);
nas_ie_lve!(
    /// NSAG Information (TS 24.501 §9.11.3.87). LV-E format.
    NasNsagInformation
);
nas_ie_lve!(
    /// NSSRG Information (TS 24.501 §9.11.3.82). LV-E format.
    NasNssrgInformation
);
nas_ie_lve!(
    /// Operator-defined Access Category Definitions (TS 24.501 §9.11.3.38). LV-E format.
    NasOperatorDefinedAccessCategoryDefinitions
);
nas_ie_lve!(
    /// PDU Session Reactivation Result Error Cause (TS 24.501 §9.11.3.43). LV-E format.
    NasPduSessionReactivationResultErrorCause
);
nas_ie_lve!(
    /// Port Management Information Container (TS 24.501 §9.11.4.27). LV-E format.
    NasPortManagementInformationContainer
);
nas_ie_lve!(
    /// QoS Flow Descriptions (TS 24.501 §9.11.4.12). LV-E format.
    NasQosFlowDescriptions
);
nas_ie_lve!(
    /// Received MBS Container (TS 24.501 §9.11.4.31). LV-E format.
    NasReceivedMbsContainer
);
nas_ie_lve!(
    /// Requested MBS Container (TS 24.501 §9.11.4.30). LV-E format.
    NasRequestedMbsContainer
);
nas_ie_lve!(
    /// Service-level-AA Container (TS 24.501 §9.11.2.10). LV-E format.
    NasServiceLevelAaContainer
);
nas_ie_lve!(
    /// SOR Transparent Container (TS 24.501 §9.11.3.51). LV-E format.
    NasSorTransparentContainer
);

// ── Later-release and extended IEs ──────────────────────────────────────────
//
// These IEs are exposed here with their raw TS 24.501 wire shapes; the helpers
// in `crate::nas_5gs::ie` provide getters/setters where this crate exposes typed
// structure.

nas_ie_lv!(
    /// Extended 5GMM Cause (TS 24.501 §9.11.3.109). LV format.
    NasExtendedFGmmCause
);
nas_ie_lv!(
    /// Alternative NSSAI (TS 24.501 §9.11.3.97). LV format.
    NasAlternativeNssai
);
nas_ie_lv!(
    /// AUN3 indication (TS 24.501 §9.11.3.104). LV format.
    NasAun3Indication
);
nas_ie_lv!(
    /// AUN3 device security key (TS 24.501 §9.11.3.107). LV format.
    NasAun3DeviceSecurityKey
);
nas_ie_lv!(
    /// CIoT small data container (TS 24.501 §9.11.3.18B). LV format.
    NasCiotSmallDataContainer
);
nas_ie_lve!(
    /// Extended LADN information (TS 24.501 §9.11.3.96). LV-E format.
    NasExtendedLadnInformation
);
nas_ie_lv!(
    /// Feature authorization indication (TS 24.501 §9.11.3.105). LV format.
    NasFeatureAuthorizationIndication
);
nas_ie_lv!(
    /// LP-WUSPS assistance information (TS 24.501 §9.11.3.111). LV format.
    NasLpWuspsAssistanceInformation
);
nas_ie_lv!(
    /// Non-3GPP access path switching indication (TS 24.501 §9.11.3.99). LV format.
    NasNon3GppAccessPathSwitchingIndication
);
nas_ie_lv!(
    /// Non-3GPP path switching information (TS 24.501 §9.11.3.102). LV format.
    NasNon3GppPathSwitchingInformation
);
nas_ie_lv!(
    /// N3IWF identifier (TS 24.501 §9.11.3.93). LV format.
    NasN3iwfIdentifier
);
nas_ie_lv!(
    /// On-demand NSSAI (TS 24.501 §9.11.3.108). LV format.
    NasOnDemandNssai
);
nas_ie_lve!(
    /// Partial NSSAI (TS 24.501 §9.11.3.103). LV-E format.
    NasPartialNssai
);
nas_ie_tv1!(
    /// Payload container information (TS 24.501 §9.11.3.106). Half octet.
    NasPayloadContainerInformation
);
nas_ie_lv!(
    /// RAN timing synchronization (TS 24.501 §9.11.3.95). LV format.
    NasRanTimingSynchronization
);
nas_ie_lve!(
    /// Relay key request parameters (TS 24.501 §9.11.3.89). LV-E format.
    NasRelayKeyRequestParameters
);
nas_ie_lve!(
    /// Relay key response parameters (TS 24.501 §9.11.3.90). LV-E format.
    NasRelayKeyResponseParameters
);
nas_ie_lv!(
    /// SNPN list (TS 24.501 §9.11.3.92). LV format.
    NasSnpnList
);
nas_ie_lve!(
    /// S-NSSAI location validity information (TS 24.501 §9.11.3.100). LV-E format.
    NasSNssaiLocationValidityInformation
);
nas_ie_lv!(
    /// S-NSSAI time validity information (TS 24.501 §9.11.3.101). LV format.
    NasSNssaiTimeValidityInformation
);
nas_ie_lv!(
    /// TNAN information (TS 24.501 §9.11.3.94). LV format.
    NasTnanInformation
);
nas_ie_lve!(
    /// Type-6 IE container (TS 24.501 §9.11.3.98). LV-E format.
    NasType6IeContainer
);
nas_ie_lve!(
    /// UE parameters update transparent container (TS 24.501 §9.11.3.53A). LV-E format.
    NasUeParametersUpdateTransparentContainer
);
nas_ie_lv!(
    /// ECN marking for L4S indication (TS 24.501 §9.11.4.40). LV format.
    NasEcnMarkingForL4sIndication
);
nas_ie_lve!(
    /// ECS address (TS 24.501 §9.11.4.34). LV-E format.
    NasEcsAddress
);
nas_ie_lve!(
    /// Non-3GPP delay budget (TS 24.501 §9.11.4.37). LV-E format.
    NasNon3GppDelayBudget
);
nas_ie_lve!(
    /// Non-3GPP device information (TS 24.501 §9.11.4.41). LV-E format.
    NasNon3GppDeviceInformation
);
nas_ie_lve!(
    /// N3 QAI (TS 24.501 §9.11.4.36). LV-E format.
    NasN3Qai
);
nas_ie_lve!(
    /// Protocol description (TS 24.501 §9.11.4.39). LV-E format.
    NasProtocolDescription
);
nas_ie_lve!(
    /// Remote UE context list (TS 24.501 §9.11.4.29). LV-E format.
    NasRemoteUeContextList
);
nas_ie_lv!(
    /// URSP rule enforcement reports (TS 24.501 §9.11.4.38). LV format.
    NasUrspRuleEnforcementReports
);

// ── IEs of one octet that a message has with or without an IEI ──────────────

nas_ie_v!(
    /// 5G ProSe relay transaction identity (TS 24.501 §9.11.3.88). Type 3,
    /// one octet.
    NasProseRelayTransactionIdentity
);
nas_ie_v!(
    /// 5GSM Cause (TS 24.501 §9.11.4.2). Type 3, one octet.
    ///
    /// Use the `cause()` method (defined in the [`ie`](crate::nas_5gs::ie)
    /// module) for typed access via [`GsmCause`](crate::nas_5gs::ie::GsmCause).
    NasFGsmCause
);
