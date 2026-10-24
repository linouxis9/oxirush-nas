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
//! A type is named after the IE type of its clause 9.9 (`NasGprsTimer2` for
//! every GPRS timer 2 of the message tables), and the member of a message
//! after the IE of the message's table (`t3346_value`); the message
//! definitions supply the IEI.
//!
//! # IE format summary
//!
//! | Format | Length indicator | `value` | Example |
//! |--------|------------------|---------|---------|
//! | V      | none             | `u8`, or [`Octets`] of a fixed length | [`NasEmmCause`] |
//! | Half octet | none         | `u8`, four bits | [`NasAdditionalUpdateType`] |
//! | LV     | one octet        | [`Octets`] | [`NasEpsMobileIdentity`], [`NasUeAdditionalSecurityCapability`] |
//! | LV-E   | two octets       | [`Octets`] | [`NasEsmMessageContainer`], [`NasCipheringKeyData`] |

// `Result` is not re-exported: `use oxirush_nas::nas_eps::*` would replace the
// `Result` of the standard library with an alias that takes one type.
use crate::common::Reader;
pub(crate) use crate::common::Result;
pub use crate::common::{
    Decode, Encode, IeFault, IeName, MAX_IE_VALUE_LENGTH, NasError, Octets, ValueError, ValueFault,
};
use crate::common::{nas_ie_lv, nas_ie_lve, nas_ie_tv1, nas_ie_v, nas_ie_v_fixed};
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

// BEGIN TS24301 TYPES
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

nas_ie_lv!(
    /// Access point name (TS 24.301 §9.9.4.1). LV format.
    NasAccessPointName
);
nas_ie_lv!(
    /// Additional information (TS 24.301 §9.9.2.0). LV format.
    NasAdditionalInformation
);
nas_ie_v!(
    /// Additional information requested (TS 24.301 §9.9.3.55). V format.
    NasAdditionalInformationRequested
);
nas_ie_tv1!(
    /// Additional update result (TS 24.301 §9.9.3.0A). Half octet.
    NasAdditionalUpdateResult
);
nas_ie_tv1!(
    /// Additional update type (TS 24.301 §9.9.3.0B). Half octet.
    NasAdditionalUpdateType
);
nas_ie_lv!(
    /// APN aggregate maximum bit rate (TS 24.301 §9.9.4.2). LV format.
    NasApnAggregateMaximumBitRate
);
nas_ie_lve!(
    /// Ciphering key data (TS 24.301 §9.9.3.56). LV-E format.
    ///
    /// Its sets hold the ciphering keys of the positioning SIBs: `Debug`
    /// prints the length of its octets alone.
    NasCipheringKeyData, own_debug
);
/// The ciphering keys of the positioning SIBs, by the length of their IE.
impl core::fmt::Debug for NasCipheringKeyData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        crate::common::display::hidden_octets(f, "NasCipheringKeyData", &self.value)
    }
}
nas_ie_lv!(
    /// CLI (TS 24.301 §9.9.3.38). LV format.
    NasCli
);
nas_ie_tv1!(
    /// Connectivity type (TS 24.301 §9.9.4.2A). Half octet.
    NasConnectivityType
);
nas_ie_tv1!(
    /// Control plane only indication (TS 24.301 §9.9.4.23). Half octet.
    NasControlPlaneOnlyIndication
);
nas_ie_v!(
    /// Control plane service type (TS 24.301 §9.9.3.47). V format.
    NasControlPlaneServiceType
);
nas_ie_tv1!(
    /// CSFB response (TS 24.301 §9.9.3.5). Half octet.
    NasCsfbResponse
);
nas_ie_lv!(
    /// DCN-ID (TS 24.301 §9.9.3.48). LV format.
    NasDcnId
);
nas_ie_v!(
    /// Detach type (TS 24.301 §9.9.3.7). V format.
    NasDetachType
);
nas_ie_tv1!(
    /// Device properties (TS 24.301 §9.9.2.0A). Half octet.
    NasDeviceProperties
);
nas_ie_v_fixed!(
    /// DRX parameter (TS 24.301 §9.9.3.8). V format.
    NasDrxParameter, 2
);
nas_ie_lv!(
    /// NB-S1 DRX parameter (TS 24.301 §9.9.3.63). LV format.
    NasNbS1DrxParameter
);
nas_ie_v!(
    /// EMM cause (TS 24.301 §9.9.3.9). V format.
    NasEmmCause
);
nas_ie_lv!(
    /// EPS additional request result (TS 24.301 §9.9.3.67). LV format.
    NasEpsAdditionalRequestResult
);
nas_ie_v!(
    /// EPS attach result (TS 24.301 §9.9.3.10). V format.
    NasEpsAttachResult
);
nas_ie_v!(
    /// EPS attach type (TS 24.301 §9.9.3.11). V format.
    NasEpsAttachType
);
nas_ie_lv!(
    /// EPS mobile identity (TS 24.301 §9.9.3.12). LV format.
    NasEpsMobileIdentity
);
nas_ie_lv!(
    /// EPS network feature support (TS 24.301 §9.9.3.12A). LV format.
    NasEpsNetworkFeatureSupport
);
nas_ie_lv!(
    /// EPS quality of service (TS 24.301 §9.9.4.3). LV format.
    NasEpsQualityOfService
);
nas_ie_v!(
    /// EPS update result (TS 24.301 §9.9.3.13). V format.
    NasEpsUpdateResult
);
nas_ie_v!(
    /// EPS update type (TS 24.301 §9.9.3.14). V format.
    NasEpsUpdateType
);
nas_ie_v!(
    /// ESM cause (TS 24.301 §9.9.4.4). V format.
    NasEsmCause
);
nas_ie_tv1!(
    /// ESM information transfer flag (TS 24.301 §9.9.4.5). Half octet.
    NasEsmInformationTransferFlag
);
nas_ie_lve!(
    /// ESM message container (TS 24.301 §9.9.3.15). LV-E format.
    NasEsmMessageContainer
);
nas_ie_lv!(
    /// Extended APN aggregate maximum bit rate (TS 24.301 §9.9.4.29). LV format.
    NasExtendedApnAggregateMaximumBitRate
);
nas_ie_tv1!(
    /// Extended EMM cause (TS 24.301 §9.9.3.26A). Half octet.
    NasExtendedEmmCause
);
nas_ie_lv!(
    /// Extended quality of service (TS 24.301 §9.9.4.30). LV format.
    NasExtendedQualityOfService
);
nas_ie_lv!(
    /// Tracking area identity list (TS 24.301 §9.9.3.33). LV format.
    NasTrackingAreaIdentityList
);
nas_ie_lve!(
    /// Generic message container (TS 24.301 §9.9.3.43). LV-E format.
    NasGenericMessageContainer
);
nas_ie_v!(
    /// Generic message container type (TS 24.301 §9.9.3.42). V format.
    NasGenericMessageContainerType
);
nas_ie_tv1!(
    /// Ciphering key sequence number (TS 24.301 §9.9.3.4A). Half octet.
    NasCipheringKeySequenceNumber
);
nas_ie_lv!(
    /// HashMME (TS 24.301 §9.9.3.50). LV format.
    NasHashMme
);
nas_ie_lv!(
    /// Header compression configuration (TS 24.301 §9.9.4.22). LV format.
    NasHeaderCompressionConfiguration
);
nas_ie_lv!(
    /// Header compression configuration status (TS 24.301 §9.9.4.27). LV format.
    NasHeaderCompressionConfigurationStatus
);
nas_ie_v!(
    /// Identity type 2 (TS 24.301 §9.9.3.17). V format.
    NasIdentityType2
);
nas_ie_v!(
    /// NAS key set identifier (TS 24.301 §9.9.3.21). V format.
    NasKeySetIdentifier
);
nas_ie_v_fixed!(
    /// Tracking area identity (TS 24.301 §9.9.3.32). V format.
    NasTrackingAreaIdentity, 5
);
nas_ie_lv!(
    /// LCS client identity (TS 24.301 §9.9.3.41). LV format.
    NasLcsClientIdentity
);
nas_ie_v!(
    /// LCS indicator (TS 24.301 §9.9.3.40). V format.
    NasLcsIndicator
);
nas_ie_v!(
    /// Linked EPS bearer identity (TS 24.301 §9.9.4.6). V format.
    NasLinkedEpsBearerIdentity
);
nas_ie_v_fixed!(
    /// Location area identification (TS 24.301 §9.9.2.2). V format.
    NasLocationAreaIdentification, 5
);
nas_ie_lv!(
    /// NAS message container (TS 24.301 §9.9.3.22). LV format.
    NasMessageContainer
);
nas_ie_lv!(
    /// Mobile identity (TS 24.301 §9.9.2.3). LV format.
    ///
    /// The identity of TS 24.008 §10.5.1.4 that an IDENTITY RESPONSE and a
    /// SECURITY MODE COMPLETE of EPS carry: an IMSI, an IMEI, an IMEISV or a
    /// TMSI.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::NasMobileIdentity;
    ///
    /// let identity = NasMobileIdentity::from_imsi("208930000000001").unwrap();
    /// assert_eq!(hex::encode(&identity.value), "2980390000000010");
    /// assert_eq!(identity.as_imsi().unwrap().to_string(), "208930000000001");
    /// assert_eq!(identity.to_string(), "imsi-208930000000001");
    /// ```
    NasMobileIdentity
);
nas_ie_lv!(
    /// Mobile station classmark 3 (TS 24.301 §9.9.2.5). LV format.
    NasMobileStationClassmark3
);
nas_ie_lv!(
    /// MS network capability (TS 24.301 §9.9.3.20). LV format.
    NasMsNetworkCapability
);
nas_ie_tv1!(
    /// MS network feature support (TS 24.301 §9.9.3.20A). Half octet.
    NasMsNetworkFeatureSupport
);
nas_ie_lv!(
    /// N1 UE network capability (TS 24.301 §9.9.3.57). LV format.
    NasN1UeNetworkCapability
);
nas_ie_lv!(
    /// NBIFOM container (TS 24.301 §9.9.4.19). LV format.
    NasNbifomContainer
);
nas_ie_lv!(
    /// IMSI offset (TS 24.301 §9.9.3.64). LV format.
    NasImsiOffset
);
nas_ie_v!(
    /// LLC service access point identifier (TS 24.301 §9.9.4.7). V format.
    NasLlcServiceAccessPointIdentifier
);
nas_ie_lv!(
    /// Quality of service (TS 24.301 §9.9.4.12). LV format.
    NasQualityOfService
);
nas_ie_tv1!(
    /// Network policy (TS 24.301 §9.9.3.52). Half octet.
    NasNetworkPolicy
);
nas_ie_v_fixed!(
    /// Nonce (TS 24.301 §9.9.3.25). V format.
    NasNonce, 4
);
nas_ie_lv!(
    /// Notification indicator (TS 24.301 §9.9.4.7A). LV format.
    NasNotificationIndicator
);
nas_ie_tv1!(
    /// GUTI type (TS 24.301 §9.9.3.45). Half octet.
    NasGutiType
);
nas_ie_v_fixed!(
    /// P-TMSI signature (TS 24.301 §9.9.3.26). V format.
    NasPTmsiSignature, 3
);
nas_ie_lv!(
    /// Packet flow Identifier (TS 24.301 §9.9.4.8). LV format.
    NasPacketFlowIdentifier
);
nas_ie_v!(
    /// Paging identity (TS 24.301 §9.9.3.25A). V format.
    NasPagingIdentity
);
nas_ie_lv!(
    /// Paging restriction (TS 24.301 §9.9.3.66). LV format.
    NasPagingRestriction
);
nas_ie_lv!(
    /// PDN address (TS 24.301 §9.9.4.9). LV format.
    NasPdnAddress
);
nas_ie_v!(
    /// PDN type (TS 24.301 §9.9.4.10). V format.
    NasPdnType
);
nas_ie_lv!(
    /// PKMF address (TS 24.301 §9.9.4.21). LV format.
    NasPkmfAddress
);
nas_ie_lv!(
    /// Protocol configuration options (TS 24.301 §9.9.4.11). LV format.
    NasProtocolConfigurationOptions
);
nas_ie_tv1!(
    /// Radio priority (TS 24.301 §9.9.4.13). Half octet.
    NasRadioPriority
);
nas_ie_lv!(
    /// Re-attempt indicator (TS 24.301 §9.9.4.13A). LV format.
    NasReAttemptIndicator
);
nas_ie_lve!(
    /// Remote UE context list (TS 24.301 §9.9.4.20). LV-E format.
    NasRemoteUeContextList
);
nas_ie_lve!(
    /// Replayed NAS message container (TS 24.301 §9.9.3.51). LV-E format.
    NasReplayedNasMessageContainer
);
nas_ie_lv!(
    /// UE security capability (TS 24.301 §9.9.3.36). LV format.
    NasUeSecurityCapability
);
nas_ie_v!(
    /// Request type (TS 24.301 §9.9.4.14). V format.
    NasRequestType
);
nas_ie_lv!(
    /// S&F satellite operation parameters (TS 24.301 §9.9.3.73). LV format.
    NasSAndFSatelliteOperationParameters
);
nas_ie_v!(
    /// NAS security algorithms (TS 24.301 §9.9.3.23). V format.
    NasSecurityAlgorithms
);
nas_ie_v!(
    /// Service type (TS 24.301 §9.9.3.27). V format.
    NasServiceType
);
nas_ie_tv1!(
    /// SMS services status (TS 24.301 §9.9.3.4B). Half octet.
    NasSmsServicesStatus
);
nas_ie_v!(
    /// SS Code (TS 24.301 §9.9.3.39). V format.
    NasSsCode
);
nas_ie_lv!(
    /// T3412 extended value (TS 24.301 §9.9.3.16B). LV format.
    NasT3412ExtendedValue
);
nas_ie_v!(
    /// T3412 value (TS 24.301 §9.9.3.16). V format.
    NasT3412Value
);
nas_ie_lv!(
    /// Traffic flow template (TS 24.301 §9.9.4.16). LV format.
    NasTrafficFlowTemplate
);
nas_ie_lv!(
    /// Network resource identifier container (TS 24.301 §9.9.3.24A). LV format.
    NasNetworkResourceIdentifierContainer
);
nas_ie_tv1!(
    /// TMSI status (TS 24.301 §9.9.3.31). Half octet.
    NasTmsiStatus
);
nas_ie_lv!(
    /// Traffic flow aggregate description (TS 24.301 §9.9.4.15). LV format.
    NasTrafficFlowAggregateDescription
);
nas_ie_lv!(
    /// Transaction identifier (TS 24.301 §9.9.4.17). LV format.
    NasTransactionIdentifier
);
nas_ie_lv!(
    /// UE additional security capability (TS 24.301 §9.9.3.53). LV format.
    NasUeAdditionalSecurityCapability
);
nas_ie_lv!(
    /// UE coarse location information (TS 24.301 §9.9.3.72). LV format.
    NasUeCoarseLocationInformation
);
nas_ie_tv1!(
    /// UE information request (TS 24.301 §9.9.3.71). Half octet.
    NasUeInformationRequest
);
nas_ie_lv!(
    /// UE network capability (TS 24.301 §9.9.3.34). LV format.
    NasUeNetworkCapability
);
nas_ie_lv!(
    /// UE radio capability ID availability (TS 24.301 §9.9.3.58). LV format.
    NasUeRadioCapabilityIdAvailability
);
nas_ie_lv!(
    /// UE radio capability ID request (TS 24.301 §9.9.3.59). LV format.
    NasUeRadioCapabilityIdRequest
);
nas_ie_tv1!(
    /// UE radio capability information update needed (TS 24.301 §9.9.3.35). Half octet.
    NasUeRadioCapabilityInformationUpdateNeeded
);
nas_ie_lve!(
    /// User data container (TS 24.301 §9.9.4.24). LV-E format.
    NasUserDataContainer
);
nas_ie_lv!(
    /// Voice domain preference and UE's usage setting (TS 24.301 §9.9.3.44). LV format.
    NasVoiceDomainPreferenceAndUeUsageSetting
);
nas_ie_tv1!(
    /// WLAN offload acceptability (TS 24.301 §9.9.4.18). Half octet.
    NasWlanOffloadAcceptability
);

// END TS24301 TYPES
