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

//! Raw wire-format EPS NAS Information Element types and codec traits.
//!
//! This is **Layer 1** of the EPS codec. An information element (IE) struct
//! holds the value of its IE in a public `value` field, and implements
//! [`Encode`]/[`Decode`] for the format that 3GPP TS 24.007 &sect;11.2 gives
//! the IE without its information element identifier (IEI). The IEI is that
//! of the place the IE has in a message: the message writes and reads it.
//! The IE inventory follows TS 24.301 chapter 9.
//!
//! For typed access to bit fields and cause codes, see [`crate::nas_eps::ie`]
//! (Layer 3).
//!
//! A type is named after the IE type of its clause 9.9 (`GprsTimer2` for
//! every GPRS timer 2 of the message tables), and the member of a message
//! after the IE of the message's table (`t3346_value`); the message
//! definitions supply the IEI.
//!
//! # IE format summary
//!
//! | Format | Length indicator | `value` | Example |
//! |--------|------------------|---------|---------|
//! | V      | none             | `u8`, or [`Octets`] of a fixed length | [`EmmCause`] |
//! | Half octet | none         | `u8`, four bits | [`AdditionalUpdateType`] |
//! | LV     | one octet        | [`Octets`] | [`EpsMobileIdentity`], [`UeAdditionalSecurityCapability`] |
//! | LV-E   | two octets       | [`Octets`] | [`EsmMessageContainer`], [`CipheringKeyData`] |

// `Result` is not re-exported: `use oxirush_nas::nas_eps::*` would replace the
// `Result` of the standard library with an alias that takes one type.
use crate::common::Reader;
pub(crate) use crate::common::Result;
pub(crate) use crate::common::{Decode, Encode, Error, ValueError};
use crate::common::{nas_ie_lv, nas_ie_lve, nas_ie_tv1, nas_ie_v, nas_ie_v_fixed};
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

// BEGIN TS24301 TYPES
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

nas_ie_lv!(
    /// Access point name (TS 24.301 §9.9.4.1). LV format.
    AccessPointName
);
nas_ie_lv!(
    /// Additional information (TS 24.301 §9.9.2.0). LV format.
    AdditionalInformation
);
nas_ie_v!(
    /// Additional information requested (TS 24.301 §9.9.3.55). V format.
    AdditionalInformationRequested
);
nas_ie_tv1!(
    /// Additional update result (TS 24.301 §9.9.3.0A). Half octet.
    AdditionalUpdateResult
);
nas_ie_tv1!(
    /// Additional update type (TS 24.301 §9.9.3.0B). Half octet.
    AdditionalUpdateType
);
nas_ie_lv!(
    /// APN aggregate maximum bit rate (TS 24.301 §9.9.4.2). LV format.
    ApnAggregateMaximumBitRate
);
nas_ie_lve!(
    /// Ciphering key data (TS 24.301 §9.9.3.56). LV-E format.
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

/// A key by its length alone: `hidden (16 octets)`.
impl core::fmt::Display for CipheringKeyData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&crate::common::display::Hidden(self.value.len()), f)
    }
}
nas_ie_lv!(
    /// CLI (TS 24.301 §9.9.3.38). LV format.
    Cli
);
nas_ie_tv1!(
    /// Connectivity type (TS 24.301 §9.9.4.2A). Half octet.
    ConnectivityType
);
nas_ie_tv1!(
    /// Control plane only indication (TS 24.301 §9.9.4.23). Half octet.
    ControlPlaneOnlyIndication
);
nas_ie_v!(
    /// Control plane service type (TS 24.301 §9.9.3.47). V format.
    ControlPlaneServiceType
);
nas_ie_tv1!(
    /// CSFB response (TS 24.301 §9.9.3.5). Half octet.
    CsfbResponse
);
nas_ie_lv!(
    /// DCN-ID (TS 24.301 §9.9.3.48). LV format.
    DcnId
);
nas_ie_v!(
    /// Detach type (TS 24.301 §9.9.3.7). V format.
    DetachType
);
nas_ie_tv1!(
    /// Device properties (TS 24.301 §9.9.2.0A). Half octet.
    DeviceProperties
);
nas_ie_v_fixed!(
    /// DRX parameter (TS 24.301 §9.9.3.8). V format.
    DrxParameter, 2
);
nas_ie_lv!(
    /// NB-S1 DRX parameter (TS 24.301 §9.9.3.63). LV format.
    NbS1DrxParameter
);
nas_ie_v!(
    /// EMM cause (TS 24.301 §9.9.3.9). V format.
    EmmCause
);
nas_ie_lv!(
    /// EPS additional request result (TS 24.301 §9.9.3.67). LV format.
    EpsAdditionalRequestResult
);
nas_ie_v!(
    /// EPS attach result (TS 24.301 §9.9.3.10). V format.
    EpsAttachResult
);
nas_ie_v!(
    /// EPS attach type (TS 24.301 §9.9.3.11). V format.
    EpsAttachType
);
nas_ie_lv!(
    /// EPS mobile identity (TS 24.301 §9.9.3.12). LV format.
    EpsMobileIdentity
);
nas_ie_lv!(
    /// EPS network feature support (TS 24.301 §9.9.3.12A). LV format.
    EpsNetworkFeatureSupport
);
nas_ie_lv!(
    /// EPS quality of service (TS 24.301 §9.9.4.3). LV format.
    EpsQualityOfService
);
nas_ie_v!(
    /// EPS update result (TS 24.301 §9.9.3.13). V format.
    EpsUpdateResult
);
nas_ie_v!(
    /// EPS update type (TS 24.301 §9.9.3.14). V format.
    EpsUpdateType
);
nas_ie_v!(
    /// ESM cause (TS 24.301 §9.9.4.4). V format.
    EsmCause
);
nas_ie_tv1!(
    /// ESM information transfer flag (TS 24.301 §9.9.4.5). Half octet.
    EsmInformationTransferFlag
);
nas_ie_lve!(
    /// ESM message container (TS 24.301 §9.9.3.15). LV-E format.
    EsmMessageContainer
);
nas_ie_lv!(
    /// Extended APN aggregate maximum bit rate (TS 24.301 §9.9.4.29). LV format.
    ExtendedApnAggregateMaximumBitRate
);
nas_ie_tv1!(
    /// Extended EMM cause (TS 24.301 §9.9.3.26A). Half octet.
    ExtendedEmmCause
);
nas_ie_lv!(
    /// Extended quality of service (TS 24.301 §9.9.4.30). LV format.
    ExtendedQualityOfService
);
nas_ie_lv!(
    /// Tracking area identity list (TS 24.301 §9.9.3.33). LV format.
    TrackingAreaIdentityList
);
nas_ie_lve!(
    /// Generic message container (TS 24.301 §9.9.3.43). LV-E format.
    GenericMessageContainer
);
nas_ie_v!(
    /// Generic message container type (TS 24.301 §9.9.3.42). V format.
    GenericMessageContainerType
);
nas_ie_tv1!(
    /// Ciphering key sequence number (TS 24.301 §9.9.3.4A). Half octet.
    CipheringKeySequenceNumber
);
nas_ie_lv!(
    /// HashMME (TS 24.301 §9.9.3.50). LV format.
    HashMme
);
nas_ie_lv!(
    /// Header compression configuration (TS 24.301 §9.9.4.22). LV format.
    HeaderCompressionConfiguration
);
nas_ie_lv!(
    /// Header compression configuration status (TS 24.301 §9.9.4.27). LV format.
    HeaderCompressionConfigurationStatus
);
nas_ie_v!(
    /// Identity type 2 (TS 24.301 §9.9.3.17). V format.
    IdentityType2
);
nas_ie_v!(
    /// NAS key set identifier (TS 24.301 §9.9.3.21). V format.
    KeySetIdentifier
);
nas_ie_v_fixed!(
    /// Tracking area identity (TS 24.301 §9.9.3.32). V format.
    TrackingAreaIdentity, 5
);
nas_ie_lv!(
    /// LCS client identity (TS 24.301 §9.9.3.41). LV format.
    LcsClientIdentity
);
nas_ie_v!(
    /// LCS indicator (TS 24.301 §9.9.3.40). V format.
    LcsIndicator
);
nas_ie_v!(
    /// Linked EPS bearer identity (TS 24.301 §9.9.4.6). V format.
    LinkedEpsBearerIdentity
);
nas_ie_v_fixed!(
    /// Location area identification (TS 24.301 §9.9.2.2). V format.
    LocationAreaIdentification, 5
);
nas_ie_lv!(
    /// NAS message container (TS 24.301 §9.9.3.22). LV format.
    MessageContainer
);
nas_ie_lv!(
    /// Mobile identity (TS 24.301 §9.9.2.3). LV format.
    ///
    /// The identity of TS 24.008 §10.5.1.4 that an IDENTITY RESPONSE and a
    /// SECURITY MODE COMPLETE of EPS carry: an IMSI, an IMEI, an IMEISV or a
    /// TMSI.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::MobileIdentity;
    ///
    /// let identity = MobileIdentity::from_imsi("208930000000001").unwrap();
    /// assert_eq!(hex::encode(&identity.value), "2980390000000010");
    /// assert_eq!(identity.as_imsi().unwrap().to_string(), "208930000000001");
    /// assert_eq!(identity.to_string(), "imsi-208930000000001");
    /// ```
    MobileIdentity
);
nas_ie_lv!(
    /// Mobile station classmark 3 (TS 24.301 §9.9.2.5). LV format.
    MobileStationClassmark3
);
nas_ie_lv!(
    /// MS network capability (TS 24.301 §9.9.3.20). LV format.
    MsNetworkCapability
);
nas_ie_tv1!(
    /// MS network feature support (TS 24.301 §9.9.3.20A). Half octet.
    MsNetworkFeatureSupport
);
nas_ie_lv!(
    /// N1 UE network capability (TS 24.301 §9.9.3.57). LV format.
    N1UeNetworkCapability
);
nas_ie_lv!(
    /// NBIFOM container (TS 24.301 §9.9.4.19). LV format.
    NbifomContainer
);
nas_ie_lv!(
    /// IMSI offset (TS 24.301 §9.9.3.64). LV format.
    ImsiOffset
);
nas_ie_v!(
    /// LLC service access point identifier (TS 24.301 §9.9.4.7). V format.
    LlcServiceAccessPointIdentifier
);
nas_ie_lv!(
    /// Quality of service (TS 24.301 §9.9.4.12). LV format.
    QualityOfService
);
nas_ie_tv1!(
    /// Network policy (TS 24.301 §9.9.3.52). Half octet.
    NetworkPolicy
);
nas_ie_v_fixed!(
    /// Nonce (TS 24.301 §9.9.3.25). V format.
    Nonce, 4
);
nas_ie_lv!(
    /// Notification indicator (TS 24.301 §9.9.4.7A). LV format.
    NotificationIndicator
);
nas_ie_tv1!(
    /// GUTI type (TS 24.301 §9.9.3.45). Half octet.
    GutiType
);
nas_ie_v_fixed!(
    /// P-TMSI signature (TS 24.301 §9.9.3.26). V format.
    PTmsiSignature, 3
);
nas_ie_lv!(
    /// Packet flow Identifier (TS 24.301 §9.9.4.8). LV format.
    PacketFlowIdentifier
);
nas_ie_v!(
    /// Paging identity (TS 24.301 §9.9.3.25A). V format.
    PagingIdentity
);
nas_ie_lv!(
    /// Paging restriction (TS 24.301 §9.9.3.66). LV format.
    PagingRestriction
);
nas_ie_lv!(
    /// PDN address (TS 24.301 §9.9.4.9). LV format.
    PdnAddress
);
nas_ie_v!(
    /// PDN type (TS 24.301 §9.9.4.10). V format.
    PdnType
);
nas_ie_lv!(
    /// PKMF address (TS 24.301 §9.9.4.21). LV format.
    PkmfAddress
);
nas_ie_lv!(
    /// Protocol configuration options (TS 24.301 §9.9.4.11). LV format.
    ProtocolConfigurationOptions
);
nas_ie_tv1!(
    /// Radio priority (TS 24.301 §9.9.4.13). Half octet.
    RadioPriority
);
nas_ie_lv!(
    /// Re-attempt indicator (TS 24.301 §9.9.4.13A). LV format.
    ReAttemptIndicator
);
nas_ie_lve!(
    /// Remote UE context list (TS 24.301 §9.9.4.20). LV-E format.
    RemoteUeContextList
);
nas_ie_lve!(
    /// Replayed NAS message container (TS 24.301 §9.9.3.51). LV-E format.
    ReplayedNasMessageContainer
);
nas_ie_lv!(
    /// UE security capability (TS 24.301 §9.9.3.36). LV format.
    UeSecurityCapability
);
nas_ie_v!(
    /// Request type (TS 24.301 §9.9.4.14). V format.
    RequestType
);
nas_ie_lv!(
    /// S&F satellite operation parameters (TS 24.301 §9.9.3.73). LV format.
    SAndFSatelliteOperationParameters
);
nas_ie_v!(
    /// NAS security algorithms (TS 24.301 §9.9.3.23). V format.
    SecurityAlgorithms
);
nas_ie_v!(
    /// Service type (TS 24.301 §9.9.3.27). V format.
    ServiceType
);
nas_ie_tv1!(
    /// SMS services status (TS 24.301 §9.9.3.4B). Half octet.
    SmsServicesStatus
);
nas_ie_v!(
    /// SS Code (TS 24.301 §9.9.3.39). V format.
    SsCode
);
nas_ie_lv!(
    /// T3412 extended value (TS 24.301 §9.9.3.16B). LV format.
    T3412ExtendedValue
);
nas_ie_v!(
    /// T3412 value (TS 24.301 §9.9.3.16). V format.
    T3412Value
);
nas_ie_lv!(
    /// Traffic flow template (TS 24.301 §9.9.4.16). LV format.
    TrafficFlowTemplate
);
nas_ie_lv!(
    /// Network resource identifier container (TS 24.301 §9.9.3.24A). LV format.
    NetworkResourceIdentifierContainer
);
nas_ie_tv1!(
    /// TMSI status (TS 24.301 §9.9.3.31). Half octet.
    TmsiStatus
);
nas_ie_lv!(
    /// Traffic flow aggregate description (TS 24.301 §9.9.4.15). LV format.
    TrafficFlowAggregateDescription
);
nas_ie_lv!(
    /// Transaction identifier (TS 24.301 §9.9.4.17). LV format.
    TransactionIdentifier
);
nas_ie_lv!(
    /// UE additional security capability (TS 24.301 §9.9.3.53). LV format.
    UeAdditionalSecurityCapability
);
nas_ie_lv!(
    /// UE coarse location information (TS 24.301 §9.9.3.72). LV format.
    UeCoarseLocationInformation
);
nas_ie_tv1!(
    /// UE information request (TS 24.301 §9.9.3.71). Half octet.
    UeInformationRequest
);
nas_ie_lv!(
    /// UE network capability (TS 24.301 §9.9.3.34). LV format.
    UeNetworkCapability
);
nas_ie_lv!(
    /// UE radio capability ID availability (TS 24.301 §9.9.3.58). LV format.
    UeRadioCapabilityIdAvailability
);
nas_ie_lv!(
    /// UE radio capability ID request (TS 24.301 §9.9.3.59). LV format.
    UeRadioCapabilityIdRequest
);
nas_ie_tv1!(
    /// UE radio capability information update needed (TS 24.301 §9.9.3.35). Half octet.
    UeRadioCapabilityInformationUpdateNeeded
);
nas_ie_lve!(
    /// User data container (TS 24.301 §9.9.4.24). LV-E format.
    UserDataContainer
);
nas_ie_lv!(
    /// Voice domain preference and UE's usage setting (TS 24.301 §9.9.3.44). LV format.
    VoiceDomainPreferenceAndUeUsageSetting
);
nas_ie_tv1!(
    /// WLAN offload acceptability (TS 24.301 §9.9.4.18). Half octet.
    WlanOffloadAcceptability
);

// END TS24301 TYPES
