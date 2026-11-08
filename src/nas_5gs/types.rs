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
//! | V      | none             | `u8`, `u16`, or [`Octets`] of a fixed length | [`GmmCause`], [`GprsTimer`] |
//! | Half octet | none         | `u8`, four bits | [`MicoIndication`] |
//! | LV     | one octet        | [`Octets`] | [`Nssai`], [`Dnn`], [`Abba`] |
//! | LV-E   | two octets       | [`Octets`] | [`MobileIdentity`], [`EapMessage`] |

// `Result` is not re-exported: `use oxirush_nas::nas_5gs::*` would replace the
// `Result` of the standard library with an alias that takes one type.
use crate::common::Reader;
pub(crate) use crate::common::Result;
pub(crate) use crate::common::{Decode, Encode, Error, Octets, ValueError};
use crate::common::{nas_ie_lv, nas_ie_lve, nas_ie_tv1, nas_ie_v, nas_ie_v_fixed, nas_ie_v_u16};
use crate::prelude::*;

// The IE types that TS 24.008, TS 24.301 or TS 24.501 defines and the other
// specification reuses.
pub use crate::common::types::{
    AccessTechnologyUtilizationControl, AuthenticationFailureParameter,
    AuthenticationParameterAutn, AuthenticationParameterRand, AuthenticationResponseParameter,
    DaylightSavingTime, EmergencyNumberList, EpsBearerContextStatus, ExtendedDrxParameters,
    ExtendedEmergencyNumberList, ExtendedProtocolConfigurationOptions, GprsTimer, GprsTimer2,
    GprsTimer3, ImeisvRequest, ListOfPlmnsToBeUsedInDisasterCondition, MobileStationClassmark2,
    NetworkName, Non3GppNwProvidedPolicies, PlmnIdentity, PlmnList, RegistrationWaitRange,
    ReleaseAssistanceIndication, ServingPlmnRateControl, SupportedCodecList, TimeZone,
    TimeZoneAndTime, UeRadioCapabilityId, UeRadioCapabilityIdDeletionIndication, UeRequestType,
    UeStatus, UnavailabilityConfiguration, UnavailabilityInformation, WusAssistanceInformation,
};

/// Extended Protocol Discriminator for 5GS Session Management (0x2E).
pub const EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM: u8 = 0x2e;
/// Extended Protocol Discriminator for 5GS Mobility Management (0x7E).
pub const EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM: u8 = 0x7e;

// ── V format (value only) ────────────────────────────────────────────────────

nas_ie_v!(
    /// De-Registration Type (TS 24.501 §9.11.3.20). V format (1 byte).
    DeRegistrationType
);
nas_ie_v!(
    /// 5GMM Cause (TS 24.501 §9.11.3.2). V format (1 byte).
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::{GmmCauseValue, GmmCause};
    ///
    /// let cause = GmmCause::from_cause(GmmCauseValue::Congestion);
    /// assert_eq!((cause.value, cause.cause()), (22, Some(GmmCauseValue::Congestion)));
    /// assert_eq!(cause.to_string(), "#22 (Congestion)");
    ///
    /// // A receiver reads a value that the table does not have as #111
    /// let unknown = GmmCause::new(4);
    /// assert_eq!(unknown.cause(), None);
    /// assert_eq!(unknown.cause_received(), GmmCauseValue::ProtocolErrorUnspecified);
    /// ```
    GmmCause
);
nas_ie_v!(
    /// Control Plane Service Type (TS 24.501 §9.11.3.18D). V format (1 byte).
    ControlPlaneServiceType
);
nas_ie_v!(
    /// 5GS Identity Type (TS 24.501 §9.11.3.3). Type 3, one octet.
    ///
    /// Only the lower 3 bits are significant. Use [`MobileIdentityType5gs`](crate::identity::MobileIdentityType5gs)
    /// for typed access through its `identity_type()` method.
    IdentityType
);
nas_ie_v!(
    /// 5GS Registration Type (TS 24.501 §9.11.3.7). Half octet.
    RegistrationType
);
nas_ie_v!(
    /// Service type (TS 24.501 §9.11.3.50). Half octet.
    ServiceType
);
nas_ie_lv!(
    /// T3512 value and requested T3512 value (TS 24.501 §8.2.7.16,
    /// §8.2.6.39): a GPRS timer 3 (§9.11.2.5) whose unit may be 320 hours
    /// (TS 24.008 Table 10.5.163a NOTE 1). LV format.
    T3512Value
);
nas_ie_v!(
    /// NAS Key Set Identifier (TS 24.501 §9.11.3.32). V format (1 byte).
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::{KeySetIdentifierValue, KeySetIdentifier};
    ///
    /// // The ngKSI of a native security context, and the one of "no key"
    /// let ngksi = KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Native(2));
    /// let ngksi = ngksi.unwrap();
    /// assert_eq!((ngksi.value, ngksi.to_string()), (0x02, "2".to_string()));
    /// assert_eq!(KeySetIdentifier::new(0x07).key_set_identifier(), KeySetIdentifierValue::NoKey);
    /// ```
    KeySetIdentifier
);
nas_ie_v!(
    /// Payload Container Type (TS 24.501 §9.11.3.40). Type 1 or, with spare
    /// bits, one octet.
    ///
    /// Only the lower 4 bits are significant. Use [`PayloadContainerKind`](crate::nas_5gs::PayloadContainerKind)
    /// for typed access through its `kind()` method.
    PayloadContainerType
);
nas_ie_v!(
    /// NAS Security Algorithms (TS 24.501 §9.11.3.34). V format (1 byte).
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::SecurityAlgorithms;
    ///
    /// let (nea, nia) = (Algorithm::Aes, Algorithm::Aes);
    /// let algorithms = SecurityAlgorithms::from_algorithms(nea, nia);
    /// assert_eq!(algorithms.value, 0x22);
    /// assert_eq!(algorithms.integrity(), Ok(Algorithm::Aes));
    /// assert_eq!(algorithms.to_string(), "NEA2 NIA2");
    /// ```
    SecurityAlgorithms
);
nas_ie_v_u16!(
    /// Integrity Protection Maximum Data Rate (TS 24.501 §9.11.4.7). V format (2 bytes).
    IntegrityProtectionMaximumDataRate
);
nas_ie_v_fixed!(
    /// Maximum Number of Supported Packet Filters (TS 24.501 §9.11.4.9).
    ///
    /// Type 3 IE per TS 24.007 §11.2.4: a **fixed 2-octet value** (an 11-bit
    /// count and 5 spare bits) after the IEI, without a length octet.
    MaximumNumberOfSupportedPacketFilters, 2
);

// ── LV format (variable-length) ──────────────────────────────────────────────

nas_ie_lv!(
    /// ABBA (TS 24.501 §9.11.3.10). LV format.
    Abba
);
nas_ie_lv!(
    /// 5GS Registration Result (TS 24.501 §9.11.3.6). LV format.
    RegistrationResult
);
nas_ie_lv!(
    /// Session-AMBR (TS 24.501 §9.11.4.14). LV format.
    SessionAmbr
);
nas_ie_lv!(
    /// UE Security Capability (TS 24.501 §9.11.3.54). LV format.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::UeSecurityCapability;
    ///
    /// // 5G-EA0 and 128-5G-EA2, and 128-5G-IA2: a bit for each, from the left
    /// let capability = UeSecurityCapability::new(vec![0xa0, 0x20]);
    /// assert!(capability.supports_ea(2) && !capability.supports_ea(1));
    /// assert!(capability.supports_ia(2));
    /// assert_eq!(capability.to_string(), "EA0 EA2 / IA2");
    /// ```
    UeSecurityCapability
);

// ── LV-E format (extended variable-length) ───────────────────────────────────

nas_ie_lve!(
    /// 5GS Mobile Identity (TS 24.501 §9.11.3.4). LV-E format.
    ///
    /// The identity has a reader and a builder for each type: `as_suci`,
    /// `as_guti`, `as_s_tmsi`, `as_imei`, `as_imeisv`, `as_mac_address`,
    /// `as_eui64`, and the `from_` of each. `Display` prints it whole, as the
    /// service based interfaces write it.
    ///
    /// ```
    /// use oxirush_nas::identity::{Guti5g, MobileIdentityType5gs, Plmn};
    /// use oxirush_nas::nas_5gs::MobileIdentity;
    ///
    /// let guti = Guti5g::new(Plmn::new("208", "93").unwrap(), 0xca, 0x3fe, 0, 0x1122_3344).unwrap();
    /// let identity = MobileIdentity::from_guti(guti);
    /// assert_eq!(hex::encode(&identity.value), "f202f839caff8011223344");
    /// assert_eq!(identity.identity_type(), Some(MobileIdentityType5gs::Guti));
    /// assert_eq!(identity.as_guti(), Some(guti));
    /// assert_eq!(identity.to_string(), "5g-guti-20893caff8011223344");
    /// ```
    MobileIdentity
);
nas_ie_lve!(
    /// Payload Container (TS 24.501 §9.11.3.39). LV-E format.
    PayloadContainer
);
nas_ie_lve!(
    /// QoS Rules (TS 24.501 §9.11.4.13). LV-E format.
    QosRules
);

// ── Half octet ───────────────────────────────────────────────────────────────

nas_ie_tv1!(
    /// Access Type (TS 24.501 §9.11.2.1A). Half octet.
    AccessType
);
nas_ie_tv1!(
    /// Additional Configuration Indication (TS 24.501 §9.11.3.74). Half octet.
    AdditionalConfigurationIndication
);
nas_ie_tv1!(
    /// Allowed SSC Mode (TS 24.501 §9.11.4.5). Half octet.
    AllowedSscMode
);
nas_ie_tv1!(
    /// Always-on PDU Session Indication (TS 24.501 §9.11.4.3). Half octet.
    AlwaysOnPduSessionIndication
);
nas_ie_tv1!(
    /// Always-on PDU Session Requested (TS 24.501 §9.11.4.4). Half octet.
    AlwaysOnPduSessionRequested
);
nas_ie_tv1!(
    /// Configuration Update Indication (TS 24.501 §9.11.3.18). Half octet.
    ConfigurationUpdateIndication
);
nas_ie_tv1!(
    /// Control Plane Only Indication (TS 24.501 §9.11.4.23). Half octet.
    ControlPlaneOnlyIndication
);
nas_ie_tv1!(
    /// LP-WUS Status (TS 24.501 §9.11.3.112). Half octet.
    LpWusStatus
);
nas_ie_tv1!(
    /// MA PDU Session Information (TS 24.501 §9.11.3.31A). Half octet.
    MaPduSessionInformation
);
nas_ie_tv1!(
    /// MICO Indication (TS 24.501 §9.11.3.31). Half octet.
    MicoIndication
);
nas_ie_tv1!(
    /// N5GC Indication (TS 24.501 §9.11.3.72). Half octet.
    N5gcIndication
);
nas_ie_tv1!(
    /// Network Slicing Indication (TS 24.501 §9.11.3.36). Half octet.
    NetworkSlicingIndication
);
nas_ie_tv1!(
    /// NSSAI Inclusion Mode (TS 24.501 §9.11.3.37A). Half octet.
    NssaiInclusionMode
);
nas_ie_tv1!(
    /// PDU Session Type (TS 24.501 §9.11.4.11). Half octet.
    PduSessionType
);
nas_ie_tv1!(
    /// Priority Indicator (TS 24.501 §9.11.3.91). Half octet.
    PriorityIndicator
);
nas_ie_tv1!(
    /// Request Type (TS 24.501 §9.11.3.47). Half octet.
    RequestType
);
nas_ie_tv1!(
    /// SMS Indication (TS 24.501 §9.11.3.50A). Half octet.
    SmsIndication
);
nas_ie_tv1!(
    /// SSC Mode (TS 24.501 §9.11.4.16). Half octet.
    SscMode
);

// ── V format (one octet) ─────────────────────────────────────────────────────

nas_ie_v!(
    /// EPS NAS Security Algorithms (TS 24.501 §9.11.3.25). V format (1 byte).
    EpsNasSecurityAlgorithms
);
nas_ie_v!(
    /// N1 mode to S1 mode NAS transparent container (TS 24.501 §9.11.2.7). V format (1 byte).
    N1ModeToS1ModeNasTransparentContainer
);
nas_ie_v!(
    /// PDU Session Identity 2 (TS 24.501 §9.11.3.41). V format (1 byte).
    PduSessionIdentity2
);

// ── V format (fixed length) ──────────────────────────────────────────────────

nas_ie_v_fixed!(
    /// 5GS Tracking Area Identity (TS 24.501 §9.11.3.8). V format (6 bytes: PLMN + TAC).
    TrackingAreaIdentity, 6
);

// ── LV format (variable-length) ──────────────────────────────────────────────

nas_ie_lv!(
    /// Additional 5G Security Information (TS 24.501 §9.11.3.12). LV format.
    Additional5gSecurityInformation
);
nas_ie_lv!(
    /// Additional Information (TS 24.501 §9.11.2.1). LV format.
    AdditionalInformation
);
nas_ie_lv!(
    /// Additional Information Requested (TS 24.501 §9.11.3.12A). LV format.
    AdditionalInformationRequested
);
nas_ie_lv!(
    /// Allowed PDU Session Status (TS 24.501 §9.11.3.13). LV format.
    AllowedPduSessionStatus
);
nas_ie_lv!(
    /// DNN (TS 24.501 §9.11.2.1B). LV format.
    Dnn
);
nas_ie_lv!(
    /// Intra N1 mode NAS transparent container (TS 24.501 §9.11.2.6). LV format.
    IntraN1ModeNasTransparentContainer
);
nas_ie_lv!(
    /// DS-TT Ethernet Port MAC Address (TS 24.501 §9.11.4.25). LV format.
    DsTtEthernetPortMacAddress
);
nas_ie_lv!(
    /// Ethernet Header Compression Configuration (TS 24.501 §9.11.4.28). LV format.
    EthernetHeaderCompressionConfiguration
);
nas_ie_lv!(
    /// Extended Rejected NSSAI (TS 24.501 §9.11.3.75). LV format.
    ExtendedRejectedNssai
);
nas_ie_lv!(
    /// 5GMM Capability (TS 24.501 §9.11.3.1). LV format.
    GmmCapability
);
nas_ie_lv!(
    /// 5GS Additional Request Result (TS 24.501 §9.11.3.81). LV format.
    AdditionalRequestResult
);
nas_ie_lv!(
    /// 5GS DRX Parameters (TS 24.501 §9.11.3.2A). LV format.
    DrxParameters
);
nas_ie_lv!(
    /// 5GS Network Feature Support (TS 24.501 §9.11.3.5). LV format.
    NetworkFeatureSupport
);
nas_ie_lv!(
    /// 5GS Tracking Area Identity List (TS 24.501 §9.11.3.9). LV format.
    TrackingAreaIdentityList
);
nas_ie_lv!(
    /// 5GS Update Type (TS 24.501 §9.11.3.9A). LV format.
    UpdateType
);
nas_ie_lv!(
    /// 5GSM Capability (TS 24.501 §9.11.4.1). LV format.
    GsmCapability
);
nas_ie_lv!(
    /// 5GSM Congestion Re-attempt Indicator (TS 24.501 §9.11.4.21). LV format.
    GsmCongestionReAttemptIndicator
);
nas_ie_lv!(
    /// 5GSM Network Feature Support (TS 24.501 §9.11.4.18). LV format.
    GsmNetworkFeatureSupport
);
nas_ie_lv!(
    /// IP Header Compression Configuration (TS 24.501 §9.11.4.24). LV format.
    IpHeaderCompressionConfiguration
);
nas_ie_lv!(
    /// Mapped NSSAI (TS 24.501 §9.11.3.31B). LV format.
    MappedNssai
);
nas_ie_lv!(
    /// NB-N1 Mode DRX Parameters (TS 24.501 §9.11.3.73). LV format.
    NbN1ModeDrxParameters
);
nas_ie_lv!(
    /// NID (TS 24.501 §9.11.3.79). LV format.
    Nid
);
nas_ie_lv!(
    /// NSSAI (TS 24.501 §9.11.3.37). LV format.
    Nssai
);
nas_ie_lv!(
    /// Paging Restriction (TS 24.501 §9.11.3.77). LV format.
    PagingRestriction
);
nas_ie_lv!(
    /// PDU Address (TS 24.501 §9.11.4.10). LV format.
    PduAddress
);
nas_ie_lv!(
    /// PDU Session Pair ID (TS 24.501 §9.11.4.32). LV format.
    PduSessionPairId
);
nas_ie_lv!(
    /// PDU Session Reactivation Result (TS 24.501 §9.11.3.42). LV format.
    PduSessionReactivationResult
);
nas_ie_lv!(
    /// PDU Session Status (TS 24.501 §9.11.3.44). LV format.
    PduSessionStatus
);
nas_ie_lv!(
    /// PEIPS Assistance Information (TS 24.501 §9.11.3.80). LV format.
    PeipsAssistanceInformation
);
nas_ie_lv!(
    /// Re-attempt Indicator (TS 24.501 §9.11.4.17). LV format.
    ReAttemptIndicator
);
nas_ie_lv!(
    /// Rejected NSSAI (TS 24.501 §9.11.3.46). LV format.
    RejectedNssai
);
nas_ie_lv!(
    /// S1 mode to N1 mode NAS transparent container (TS 24.501 §9.11.2.9). LV format.
    S1ModeToN1ModeNasTransparentContainer
);
nas_ie_lv!(
    /// RSN (TS 24.501 §9.11.4.33). LV format.
    Rsn
);
nas_ie_lv!(
    /// S1 UE Network Capability (TS 24.501 §9.11.3.48). LV format.
    S1UeNetworkCapability
);
nas_ie_lv!(
    /// S1 UE Security Capability (TS 24.501 §9.11.3.48A). LV format.
    S1UeSecurityCapability
);
nas_ie_lv!(
    /// S-NSSAI (TS 24.501 §9.11.2.8). LV format.
    SNssai
);
nas_ie_lv!(
    /// Service Area List (TS 24.501 §9.11.3.49). LV format.
    ServiceAreaList
);
nas_ie_lv!(
    /// SM PDU DN Request Container (TS 24.501 §9.11.4.15). LV format.
    SmPduDnRequestContainer
);
nas_ie_lv!(
    /// Time duration (TS 24.501 §9.11.2.19, referring to TS 24.301 §9.9.3.68). LV format.
    TimeDuration
);
nas_ie_lv!(
    /// Truncated 5G-S-TMSI Configuration (TS 24.501 §9.11.3.70). LV format.
    Truncated5gSTmsiConfiguration
);
nas_ie_lv!(
    /// UE DS-TT Residence Time (TS 24.501 §9.11.4.26). LV format.
    UeDsTtResidenceTime
);
nas_ie_lv!(
    /// UE Usage Setting (TS 24.501 §9.11.3.55). LV format.
    UeUsageSetting
);
nas_ie_lv!(
    /// Uplink Data Status (TS 24.501 §9.11.3.57). LV format.
    UplinkDataStatus
);

// ── LV-E format (extended variable-length) ───────────────────────────────────

nas_ie_lve!(
    /// ATSSS Container (TS 24.501 §9.11.4.22). LV-E format.
    AtsssContainer
);
nas_ie_lve!(
    /// CAG Information List (TS 24.501 §9.11.3.18A). LV-E format.
    CagInformationList
);
nas_ie_lve!(
    /// Ciphering Key Data (TS 24.501 §9.11.3.18C). LV-E format.
    ///
    /// Its sets hold the ciphering keys of the positioning SIBs: `Debug`
    /// prints the length of its octets alone.
    CipheringKeyData, own_debug
);
/// The ciphering keys of the positioning SIBs, by the length of their IE.
impl core::fmt::Debug for CipheringKeyData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        crate::common::display::hidden_octets(f, "CipheringKeyData", &self.value)
    }
}
nas_ie_lve!(
    /// EAP Message (TS 24.501 §9.11.2.2). LV-E format.
    ///
    /// `Debug` prints the header of the EAP packet and its length, and not its
    /// attributes: those of an EAP-AKA' response hold RES (AT_RES, RFC 4187
    /// §9.4), and other methods carry keys in theirs.
    EapMessage, own_debug
);
nas_ie_lve!(
    /// EPS NAS Message Container (TS 24.501 §9.11.3.24). LV-E format.
    EpsNasMessageContainer
);
nas_ie_lve!(
    /// Extended CAG Information List (TS 24.501 §9.11.3.86). LV-E format.
    ExtendedCagInformationList
);
nas_ie_lve!(
    /// LADN Indication (TS 24.501 §9.11.3.29). LV-E format.
    LadnIndication
);
nas_ie_lve!(
    /// LADN Information (TS 24.501 §9.11.3.30). LV-E format.
    LadnInformation
);
nas_ie_lve!(
    /// Mapped EPS Bearer Contexts (TS 24.501 §9.11.4.8). LV-E format.
    MappedEpsBearerContexts
);
nas_ie_lve!(
    /// NAS Message Container (TS 24.501 §9.11.3.33). LV-E format.
    MessageContainer
);
nas_ie_lve!(
    /// NSAG Information (TS 24.501 §9.11.3.87). LV-E format.
    NsagInformation
);
nas_ie_lve!(
    /// NSSRG Information (TS 24.501 §9.11.3.82). LV-E format.
    NssrgInformation
);
nas_ie_lve!(
    /// Operator-defined Access Category Definitions (TS 24.501 §9.11.3.38). LV-E format.
    OperatorDefinedAccessCategoryDefinitions
);
nas_ie_lve!(
    /// PDU Session Reactivation Result Error Cause (TS 24.501 §9.11.3.43). LV-E format.
    PduSessionReactivationResultErrorCause
);
nas_ie_lve!(
    /// Port Management Information Container (TS 24.501 §9.11.4.27). LV-E format.
    PortManagementInformationContainer
);
nas_ie_lve!(
    /// QoS Flow Descriptions (TS 24.501 §9.11.4.12). LV-E format.
    QosFlowDescriptions
);
nas_ie_lve!(
    /// Received MBS Container (TS 24.501 §9.11.4.31). LV-E format.
    ///
    /// Its MBS security key sets hold the MSK: `Debug` prints the length of
    /// its octets alone.
    ReceivedMbsContainer, own_debug
);
/// The MSKs of its sessions, by the length of the IE.
impl core::fmt::Debug for ReceivedMbsContainer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        crate::common::display::hidden_octets(f, "ReceivedMbsContainer", &self.value)
    }
}
nas_ie_lve!(
    /// Requested MBS Container (TS 24.501 §9.11.4.30). LV-E format.
    RequestedMbsContainer
);
nas_ie_lve!(
    /// Service-level-AA Container (TS 24.501 §9.11.2.10). LV-E format.
    ServiceLevelAaContainer
);
nas_ie_lve!(
    /// SOR Transparent Container (TS 24.501 §9.11.3.51). LV-E format.
    SorTransparentContainer
);

// ── Later-release and extended IEs ──────────────────────────────────────────
//
// These IEs are exposed here with their raw TS 24.501 wire shapes; the helpers
// in `crate::nas_5gs::ie` provide getters/setters where this crate exposes typed
// structure.

nas_ie_lv!(
    /// Extended 5GMM Cause (TS 24.501 §9.11.3.109). LV format.
    ExtendedGmmCause
);
nas_ie_lv!(
    /// Alternative NSSAI (TS 24.501 §9.11.3.97). LV format.
    AlternativeNssai
);
nas_ie_lv!(
    /// AUN3 indication (TS 24.501 §9.11.3.104). LV format.
    Aun3Indication
);
nas_ie_lv!(
    /// AUN3 device security key (TS 24.501 §9.11.3.107). LV format.
    Aun3DeviceSecurityKey
);
nas_ie_lv!(
    /// CIoT small data container (TS 24.501 §9.11.3.18B). LV format.
    CiotSmallDataContainer
);
nas_ie_lve!(
    /// Extended LADN information (TS 24.501 §9.11.3.96). LV-E format.
    ExtendedLadnInformation
);
nas_ie_lv!(
    /// Feature authorization indication (TS 24.501 §9.11.3.105). LV format.
    FeatureAuthorizationIndication
);
nas_ie_lv!(
    /// LP-WUSPS assistance information (TS 24.501 §9.11.3.111). LV format.
    LpWuspsAssistanceInformation
);
nas_ie_lv!(
    /// Non-3GPP access path switching indication (TS 24.501 §9.11.3.99). LV format.
    Non3GppAccessPathSwitchingIndication
);
nas_ie_lv!(
    /// Non-3GPP path switching information (TS 24.501 §9.11.3.102). LV format.
    Non3GppPathSwitchingInformation
);
nas_ie_lv!(
    /// N3IWF identifier (TS 24.501 §9.11.3.93). LV format.
    N3iwfIdentifier
);
nas_ie_lv!(
    /// On-demand NSSAI (TS 24.501 §9.11.3.108). LV format.
    OnDemandNssai
);
nas_ie_lve!(
    /// Partial NSSAI (TS 24.501 §9.11.3.103). LV-E format.
    PartialNssai
);
nas_ie_tv1!(
    /// Payload container information (TS 24.501 §9.11.3.106). Half octet.
    PayloadContainerInformation
);
nas_ie_lv!(
    /// RAN timing synchronization (TS 24.501 §9.11.3.95). LV format.
    RanTimingSynchronization
);
nas_ie_lve!(
    /// Relay key request parameters (TS 24.501 §9.11.3.89). LV-E format.
    RelayKeyRequestParameters
);
nas_ie_lve!(
    /// Relay key response parameters (TS 24.501 §9.11.3.90). LV-E format.
    ///
    /// They hold K_NR_ProSe: `Debug` prints the length of their octets alone.
    RelayKeyResponseParameters, own_debug
);
/// K_NR_ProSe, by the length of the IE.
impl core::fmt::Debug for RelayKeyResponseParameters {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        crate::common::display::hidden_octets(f, "RelayKeyResponseParameters", &self.value)
    }
}
nas_ie_lv!(
    /// SNPN list (TS 24.501 §9.11.3.92). LV format.
    SnpnList
);
nas_ie_lve!(
    /// S-NSSAI location validity information (TS 24.501 §9.11.3.100). LV-E format.
    SNssaiLocationValidityInformation
);
nas_ie_lv!(
    /// S-NSSAI time validity information (TS 24.501 §9.11.3.101). LV format.
    SNssaiTimeValidityInformation
);
nas_ie_lv!(
    /// TNAN information (TS 24.501 §9.11.3.94). LV format.
    TnanInformation
);
nas_ie_lve!(
    /// Type-6 IE container (TS 24.501 §9.11.3.98). LV-E format.
    Type6IeContainer
);
nas_ie_lve!(
    /// UE parameters update transparent container (TS 24.501 §9.11.3.53A). LV-E format.
    UeParametersUpdateTransparentContainer
);
nas_ie_lv!(
    /// ECN marking for L4S indication (TS 24.501 §9.11.4.40). LV format.
    EcnMarkingForL4sIndication
);
nas_ie_lve!(
    /// ECS address (TS 24.501 §9.11.4.34). LV-E format.
    EcsAddress
);
nas_ie_lve!(
    /// Non-3GPP delay budget (TS 24.501 §9.11.4.37). LV-E format.
    Non3GppDelayBudget
);
nas_ie_lve!(
    /// Non-3GPP device information (TS 24.501 §9.11.4.41). LV-E format.
    Non3GppDeviceInformation
);
nas_ie_lve!(
    /// N3 QAI (TS 24.501 §9.11.4.36). LV-E format.
    N3Qai
);
nas_ie_lve!(
    /// Protocol description (TS 24.501 §9.11.4.39). LV-E format.
    ProtocolDescription
);
nas_ie_lve!(
    /// Remote UE context list (TS 24.501 §9.11.4.29). LV-E format.
    RemoteUeContextList
);
nas_ie_lv!(
    /// URSP rule enforcement reports (TS 24.501 §9.11.4.38). LV format.
    UrspRuleEnforcementReports
);

// ── IEs of one octet that a message has with or without an IEI ──────────────

nas_ie_v!(
    /// 5G ProSe relay transaction identity (TS 24.501 §9.11.3.88). Type 3,
    /// one octet.
    ProseRelayTransactionIdentity
);
nas_ie_v!(
    /// 5GSM Cause (TS 24.501 §9.11.4.2). Type 3, one octet.
    ///
    /// Its `cause()` method reads it as a [`GsmCauseValue`](crate::nas_5gs::GsmCauseValue).
    GsmCause
);
