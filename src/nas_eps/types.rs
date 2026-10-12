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
//! Raw IE names follow the 5GS semantic `NasFoo` convention and are taken
//! from the message tables: fields with the same name share one type, and
//! message definitions supply the IEI. A chapter 9 clause used under several names (for
//! example the GPRS timer 2 fields `NasT3346Value` and `NasT3448Value`) has
//! one type per name; those types share one grammar implementation.
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
    Decode, Encode, IeFault, MAX_IE_VALUE_LENGTH, NasError, Octets, ValueError, ValueFault,
};
use crate::common::{nas_ie_lv, nas_ie_lve, nas_ie_tv1, nas_ie_v, nas_ie_v_fixed};
use crate::prelude::*;

// BEGIN TS24301 TYPES
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

nas_ie_lv!(
    /// Access point name (TS 24.301 §9.9.4.1). LV format.
    NasAccessPointName
);
nas_ie_lv!(
    /// Access technology utilization control (TS 24.301 §9.9.3.3A). LV format.
    NasAccessTechnologyUtilizationControl
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
    /// APN-AMBR (TS 24.301 §9.9.4.2). LV format.
    NasApnAmbr
);
nas_ie_lv!(
    /// Authentication failure parameter (TS 24.301 §9.9.3.1). LV format.
    NasAuthenticationFailureParameter
);
nas_ie_lv!(
    /// Authentication parameter AUTN (EPS challenge) (TS 24.301 §9.9.3.2). LV format.
    NasAuthenticationParameterAutnEpsChallenge
);
nas_ie_v_fixed!(
    /// Authentication parameter RAND (EPS challenge) (TS 24.301 §9.9.3.3). V format.
    NasAuthenticationParameterRandEpsChallenge, 16
);
nas_ie_lv!(
    /// Authentication response parameter (TS 24.301 §9.9.3.4). LV format.
    NasAuthenticationResponseParameter
);
nas_ie_lv!(
    /// Back-off timer value (TS 24.301 §9.9.3.16B). LV format.
    NasBackOffTimerValue
);
nas_ie_lve!(
    /// Ciphering key data (TS 24.301 §9.9.3.56). LV-E format.
    NasCipheringKeyData
);
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
nas_ie_lv!(
    /// Disaster return wait range (TS 24.301 §9.9.3.75). LV format.
    NasDisasterReturnWaitRange
);
nas_ie_lv!(
    /// Disaster roaming wait range (TS 24.301 §9.9.3.75). LV format.
    NasDisasterRoamingWaitRange
);
nas_ie_v_fixed!(
    /// DRX parameter (TS 24.301 §9.9.3.8). V format.
    NasDrxParameter, 2
);
nas_ie_lv!(
    /// DRX parameter in NB-S1 mode (TS 24.301 §9.9.3.63). LV format.
    NasDrxParameterInNbS1Mode
);
nas_ie_lv!(
    /// Emergency number list (TS 24.301 §9.9.3.37). LV format.
    NasEmergencyNumberList
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
    /// EPS bearer context status (TS 24.301 §9.9.2.1). LV format.
    NasEpsBearerContextStatus
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
    /// EPS QoS (TS 24.301 §9.9.4.3). LV format.
    NasEpsQos
);
nas_ie_v!(
    /// EPS update result (TS 24.301 §9.9.3.13). V format.
    NasEpsUpdateResult
);
nas_ie_v!(
    /// EPS update type (TS 24.301 §9.9.3.14). V format.
    NasEpsUpdateType
);
nas_ie_lv!(
    /// Equivalent PLMNs (TS 24.301 §9.9.2.8). LV format.
    NasEquivalentPlmns
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
    /// Extended APN-AMBR (TS 24.301 §9.9.4.29). LV format.
    NasExtendedApnAmbr
);
nas_ie_lv!(
    /// Extended DRX parameters (TS 24.301 §9.9.3.46). LV format.
    NasExtendedDrxParameters
);
nas_ie_lve!(
    /// Extended emergency number list (TS 24.301 §9.9.3.37A). LV-E format.
    NasExtendedEmergencyNumberList
);
nas_ie_tv1!(
    /// Extended EMM cause (TS 24.301 §9.9.3.26A). Half octet.
    NasExtendedEmmCause
);
nas_ie_lv!(
    /// Extended EPS QoS (TS 24.301 §9.9.4.30). LV format.
    NasExtendedEpsQos
);
nas_ie_lve!(
    /// Extended protocol configuration options (TS 24.301 §9.9.4.26). LV-E format.
    NasExtendedProtocolConfigurationOptions
);
nas_ie_lv!(
    /// Forbidden TAI(s) for the list of "forbidden tracking areas for regional provision of service" (TS 24.301 §9.9.3.33). LV format.
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService
);
nas_ie_lv!(
    /// Forbidden TAI(s) for the list of "forbidden tracking areas for roaming" (TS 24.301 §9.9.3.33). LV format.
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming
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
    /// GPRS ciphering key sequence number (TS 24.301 §9.9.3.4A). Half octet.
    NasGprsCipheringKeySequenceNumber
);
nas_ie_lv!(
    /// GPRS timer 2 (TS 24.301 §9.9.3.16A). LV format.
    NasGprsTimer2
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
    /// Identity type (TS 24.301 §9.9.3.17). V format.
    NasIdentityType
);
nas_ie_tv1!(
    /// IMEISV request (TS 24.301 §9.9.3.18). Half octet.
    NasImeisvRequest
);
nas_ie_v!(
    /// NAS key set identifier (TS 24.301 §9.9.3.21). V format.
    NasKeySetIdentifier
);
nas_ie_v_fixed!(
    /// Last visited registered TAI (TS 24.301 §9.9.3.32). V format.
    NasLastVisitedRegisteredTai, 5
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
nas_ie_lv!(
    /// List of PLMNs to be used in disaster condition (TS 24.301 §9.9.3.76). LV format.
    NasListOfPlmnsToBeUsedInDisasterCondition
);
nas_ie_v!(
    /// Local time zone (TS 24.301 §9.9.3.29). V format.
    NasLocalTimeZone
);
nas_ie_v_fixed!(
    /// Location area identification (TS 24.301 §9.9.2.2). V format.
    NasLocationAreaIdentification, 5
);
nas_ie_lv!(
    /// Lower bound timer value (TS 24.301 §9.9.3.16B). LV format.
    NasLowerBoundTimerValue
);
nas_ie_lv!(
    /// Maximum time offset (TS 24.301 §9.9.3.16B). LV format.
    NasMaximumTimeOffset
);
nas_ie_lv!(
    /// NAS message container (TS 24.301 §9.9.3.22). LV format.
    NasMessageContainer
);
nas_ie_lv!(
    /// Mobile identity (TS 24.301 §9.9.2.3). LV format.
    NasMobileIdentity
);
nas_ie_lv!(
    /// Mobile station classmark 2 (TS 24.301 §9.9.2.4). LV format.
    NasMobileStationClassmark2
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
    /// Negotiated DRX parameter in NB-S1 mode (TS 24.301 §9.9.3.63). LV format.
    NasNegotiatedDrxParameterInNbS1Mode
);
nas_ie_lv!(
    /// Negotiated IMSI offset (TS 24.301 §9.9.3.64). LV format.
    NasNegotiatedImsiOffset
);
nas_ie_v!(
    /// Negotiated LLC SAPI (TS 24.301 §9.9.4.7). V format.
    NasNegotiatedLlcSapi
);
nas_ie_lv!(
    /// Negotiated QoS (TS 24.301 §9.9.4.12). LV format.
    NasNegotiatedQos
);
nas_ie_lv!(
    /// Negotiated WUS assistance information (TS 24.301 §9.9.3.62). LV format.
    NasNegotiatedWusAssistanceInformation
);
nas_ie_lv!(
    /// Network daylight saving time (TS 24.301 §9.9.3.6). LV format.
    NasNetworkDaylightSavingTime
);
nas_ie_lv!(
    /// Network name, full or short (TS 24.301 §9.9.3.24). LV format.
    NasNetworkName
);
nas_ie_tv1!(
    /// Network policy (TS 24.301 §9.9.3.52). Half octet.
    NasNetworkPolicy
);
nas_ie_lv!(
    /// New EPS QoS (TS 24.301 §9.9.4.3). LV format.
    NasNewEpsQos
);
nas_ie_lv!(
    /// New QoS (TS 24.301 §9.9.4.12). LV format.
    NasNewQos
);
nas_ie_tv1!(
    /// Non-3GPP NW provided policies (TS 24.301 §9.9.3.49). Half octet.
    NasNon3GppNwProvidedPolicies
);
nas_ie_tv1!(
    /// Non-current native NAS key set identifier (TS 24.301 §9.9.3.21). Half octet.
    NasNonCurrentNativeNasKeySetIdentifier
);
nas_ie_v_fixed!(
    /// NonceMME (TS 24.301 §9.9.3.25). V format.
    NasNonceMme, 4
);
nas_ie_v_fixed!(
    /// NonceUE (TS 24.301 §9.9.3.25). V format.
    NasNonceUe, 4
);
nas_ie_lv!(
    /// Notification indicator (TS 24.301 §9.9.4.7A). LV format.
    NasNotificationIndicator
);
nas_ie_tv1!(
    /// Old GUTI type (TS 24.301 §9.9.3.45). Half octet.
    NasOldGutiType
);
nas_ie_v_fixed!(
    /// Old P-TMSI signature (TS 24.301 §9.9.3.26). V format.
    NasOldPTmsiSignature, 3
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
    /// ProSe Key Management Function address (TS 24.301 §9.9.4.21). LV format.
    NasProseKeyManagementFunctionAddress
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
nas_ie_tv1!(
    /// Release assistance indication (TS 24.301 §9.9.4.25). Half octet.
    NasReleaseAssistanceIndication
);
nas_ie_lve!(
    /// Remote UE Context Connected (TS 24.301 §9.9.4.20). LV-E format.
    NasRemoteUeContextConnected
);
nas_ie_lve!(
    /// Remote UE Context Disconnected (TS 24.301 §9.9.4.20). LV-E format.
    NasRemoteUeContextDisconnected
);
nas_ie_lve!(
    /// Replayed NAS message container (TS 24.301 §9.9.3.51). LV-E format.
    NasReplayedNasMessageContainer
);
nas_ie_v_fixed!(
    /// Replayed nonceUE (TS 24.301 §9.9.3.25). V format.
    NasReplayedNonceUe, 4
);
nas_ie_lv!(
    /// Replayed UE security capabilities (TS 24.301 §9.9.3.36). LV format.
    NasReplayedUeSecurityCapabilities
);
nas_ie_v!(
    /// Request type (TS 24.301 §9.9.4.14). V format.
    NasRequestType
);
nas_ie_lv!(
    /// Requested IMSI offset (TS 24.301 §9.9.3.64). LV format.
    NasRequestedImsiOffset
);
nas_ie_lv!(
    /// Requested WUS assistance information (TS 24.301 §9.9.3.62). LV format.
    NasRequestedWusAssistanceInformation
);
nas_ie_lv!(
    /// Required traffic flow QoS (TS 24.301 §9.9.4.3). LV format.
    NasRequiredTrafficFlowQos
);
nas_ie_lv!(
    /// S&F satellite operation parameters (TS 24.301 §9.9.3.73). LV format.
    NasSAndFSatelliteOperationParameters
);
nas_ie_v!(
    /// Selected NAS security algorithms (TS 24.301 §9.9.3.23). V format.
    NasSelectedNasSecurityAlgorithms
);
nas_ie_v!(
    /// Service type (TS 24.301 §9.9.3.27). V format.
    NasServiceType
);
nas_ie_lv!(
    /// Serving PLMN rate control (TS 24.301 §9.9.4.28). LV format.
    NasServingPlmnRateControl
);
nas_ie_tv1!(
    /// SMS services status (TS 24.301 §9.9.3.4B). Half octet.
    NasSmsServicesStatus
);
nas_ie_v!(
    /// Spare half octet (TS 24.301 §9.9.2.9). V format.
    NasSpareHalfOctet
);
nas_ie_v!(
    /// SS Code (TS 24.301 §9.9.3.39). V format.
    NasSsCode
);
nas_ie_lv!(
    /// Supported Codecs (TS 24.301 §9.9.2.10). LV format.
    NasSupportedCodecs
);
nas_ie_lv!(
    /// T3324 value (TS 24.301 §9.9.3.16A). LV format.
    NasT3324Value
);
nas_ie_lv!(
    /// T3346 value (TS 24.301 §9.9.3.16A). LV format.
    NasT3346Value
);
nas_ie_lv!(
    /// T3396 value (TS 24.301 §9.9.3.16B). LV format.
    NasT3396Value
);
nas_ie_v!(
    /// T3402 value (TS 24.301 §9.9.3.16). V format (1 byte).
    NasT3402Value
);
nas_ie_lv!(
    /// T3412 extended value (TS 24.301 §9.9.3.16B). LV format.
    NasT3412ExtendedValue
);
nas_ie_v!(
    /// T3412 value (TS 24.301 §9.9.3.16). V format.
    NasT3412Value
);
nas_ie_v!(
    /// T3423 value (TS 24.301 §9.9.3.16). V format.
    NasT3423Value
);
nas_ie_v!(
    /// T3442 value (TS 24.301 §9.9.3.16). V format.
    NasT3442Value
);
nas_ie_lv!(
    /// T3447 value (TS 24.301 §9.9.3.16B). LV format.
    NasT3447Value
);
nas_ie_lv!(
    /// T3448 value (TS 24.301 §9.9.3.16A). LV format.
    NasT3448Value
);
nas_ie_lv!(
    /// TAI list (TS 24.301 §9.9.3.33). LV format.
    NasTaiList
);
nas_ie_lv!(
    /// TFT (TS 24.301 §9.9.4.16). LV format.
    NasTft
);
nas_ie_lv!(
    /// TMSI based NRI container (TS 24.301 §9.9.3.24A). LV format.
    NasTmsiBasedNriContainer
);
nas_ie_tv1!(
    /// TMSI status (TS 24.301 §9.9.3.31). Half octet.
    NasTmsiStatus
);
nas_ie_lv!(
    /// Traffic flow aggregate (TS 24.301 §9.9.4.15). LV format.
    NasTrafficFlowAggregate
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
    /// UE coarse location information request (TS 24.301 §9.9.3.71). Half octet.
    NasUeCoarseLocationInformationRequest
);
nas_ie_lv!(
    /// UE determined PLMN with disaster condition (TS 24.301 §9.9.3.77). LV format.
    NasUeDeterminedPlmnWithDisasterCondition
);
nas_ie_lv!(
    /// UE network capability (TS 24.301 §9.9.3.34). LV format.
    NasUeNetworkCapability
);
nas_ie_lv!(
    /// UE radio capability ID (TS 24.301 §9.9.3.60). LV format.
    NasUeRadioCapabilityId
);
nas_ie_lv!(
    /// UE radio capability ID availability (TS 24.301 §9.9.3.58). LV format.
    NasUeRadioCapabilityIdAvailability
);
nas_ie_tv1!(
    /// UE radio capability ID deletion indication (TS 24.301 §9.9.3.61). Half octet.
    NasUeRadioCapabilityIdDeletionIndication
);
nas_ie_lv!(
    /// UE radio capability ID request (TS 24.301 §9.9.3.59). LV format.
    NasUeRadioCapabilityIdRequest
);
nas_ie_tv1!(
    /// UE radio capability information update needed (TS 24.301 §9.9.3.35). Half octet.
    NasUeRadioCapabilityInformationUpdateNeeded
);
nas_ie_lv!(
    /// UE request type (TS 24.301 §9.9.3.65). LV format.
    NasUeRequestType
);
nas_ie_lv!(
    /// UE status (TS 24.301 §9.9.3.54). LV format.
    NasUeStatus
);
nas_ie_lv!(
    /// Unavailability configuration (TS 24.301 §9.9.3.70). LV format.
    NasUnavailabilityConfiguration
);
nas_ie_lv!(
    /// Unavailability information (TS 24.301 §9.9.3.69). LV format.
    NasUnavailabilityInformation
);
nas_ie_v_fixed!(
    /// Universal time and local time zone (TS 24.301 §9.9.3.30). V format.
    NasUniversalTimeAndLocalTimeZone, 7
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
    /// WLAN offload indication (TS 24.301 §9.9.4.18). Half octet.
    NasWlanOffloadIndication
);

// END TS24301 TYPES
