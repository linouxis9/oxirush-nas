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

//! Raw wire-format EPS NAS Information Element types and codec traits.
//!
//! This is **Layer 1** of the EPS codec. IE structs hold raw bytes in public
//! value fields and implement [`Encode`]/[`Decode`] for the wire formats in
//! 3GPP TS 24.007 &sect;11.2. The IE inventory follows TS 24.301 chapter 9.
//!
//! For typed access to bit fields and cause codes, see [`crate::nas_eps::ie`]
//! (Layer 3).
//!
//! Raw IE names follow the 5GS semantic `NasFoo` convention and are taken
//! from the message tables: fields with the same name share one type, and
//! message definitions supply the IEI and length when a message uses
//! another wire format. A chapter 9 clause used under several names (for
//! example the GPRS timer 2 fields `NasT3346Value` and `NasT3448Value`) has
//! one type per name; those types share one grammar implementation.
//!
//! # IE format summary
//!
//! | Format | Type field | Length field | Example |
//! |--------|-----------|--------------|---------|
//! | V      | none      | none         | [`NasEmmCause`] |
//! | LV     | none      | u8           | [`NasEpsMobileIdentity`] |
//! | LV-E   | none      | u16          | [`NasEsmMessageContainer`] |
//! | TV-1   | 4 bits    | none         | [`NasAdditionalUpdateType`] |
//! | TV     | u8        | none         | [`NasAdditionalInformationRequested`] |
//! | TLV    | u8        | u8           | [`NasUeAdditionalSecurityCapability`] |
//! | TLV-E  | u8        | u16          | [`NasCipheringKeyData`] |

pub use crate::common::{Decode, Encode, MAX_IE_VALUE_LENGTH, NasError, Result, helpers};
use crate::common::{
    nas_ie_lv, nas_ie_lve, nas_ie_tlv, nas_ie_tlve, nas_ie_tv, nas_ie_tv_fixed, nas_ie_tv1,
    nas_ie_v, nas_ie_v_fixed,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

// BEGIN TS24301 TYPES
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

nas_ie_lv!(
    /// Access point name (TS 24.301 §9.9.4.1). LV format.
    NasAccessPointName
);
nas_ie_tlv!(
    /// Access technology utilization control (TS 24.301 §9.9.3.3A). TLV format.
    NasAccessTechnologyUtilizationControl
);
nas_ie_tlv!(
    /// Additional information (TS 24.301 §9.9.2.0). TLV format.
    NasAdditionalInformation
);
nas_ie_tv!(
    /// Additional information requested (TS 24.301 §9.9.3.55). TV format.
    NasAdditionalInformationRequested
);
nas_ie_tv1!(
    /// Additional update result (TS 24.301 §9.9.3.0A). TV-1 format.
    NasAdditionalUpdateResult
);
nas_ie_tv1!(
    /// Additional update type (TS 24.301 §9.9.3.0B). TV-1 format.
    NasAdditionalUpdateType
);
nas_ie_tlv!(
    /// APN-AMBR (TS 24.301 §9.9.4.2). TLV format.
    NasApnAmbr
);
nas_ie_tlv!(
    /// Authentication failure parameter (TS 24.301 §9.9.3.1). TLV format.
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
nas_ie_tlv!(
    /// Back-off timer value (TS 24.301 §9.9.3.16B). TLV format.
    NasBackOffTimerValue
);
nas_ie_tlve!(
    /// Ciphering key data (TS 24.301 §9.9.3.56). TLV-E format.
    NasCipheringKeyData
);
nas_ie_tlv!(
    /// CLI (TS 24.301 §9.9.3.38). TLV format.
    NasCli
);
nas_ie_tv1!(
    /// Connectivity type (TS 24.301 §9.9.4.2A). TV-1 format.
    NasConnectivityType
);
nas_ie_tv1!(
    /// Control plane only indication (TS 24.301 §9.9.4.23). TV-1 format.
    NasControlPlaneOnlyIndication
);
nas_ie_v!(
    /// Control plane service type (TS 24.301 §9.9.3.47). V format.
    NasControlPlaneServiceType
);
nas_ie_tv1!(
    /// CSFB response (TS 24.301 §9.9.3.5). TV-1 format.
    NasCsfbResponse
);
nas_ie_tlv!(
    /// DCN-ID (TS 24.301 §9.9.3.48). TLV format.
    NasDcnId
);
nas_ie_v!(
    /// Detach type (TS 24.301 §9.9.3.7). V format.
    NasDetachType
);
nas_ie_tv1!(
    /// Device properties (TS 24.301 §9.9.2.0A). TV-1 format.
    NasDeviceProperties
);
nas_ie_tlv!(
    /// Disaster return wait range (TS 24.301 §9.9.3.75). TLV format.
    NasDisasterReturnWaitRange
);
nas_ie_tlv!(
    /// Disaster roaming wait range (TS 24.301 §9.9.3.75). TLV format.
    NasDisasterRoamingWaitRange
);
nas_ie_tv_fixed!(
    /// DRX parameter (TS 24.301 §9.9.3.8). TV format.
    NasDrxParameter, 2
);
nas_ie_tlv!(
    /// DRX parameter in NB-S1 mode (TS 24.301 §9.9.3.63). TLV format.
    NasDrxParameterInNbS1Mode
);
nas_ie_tlv!(
    /// Emergency number list (TS 24.301 §9.9.3.37). TLV format.
    NasEmergencyNumberList
);
nas_ie_v!(
    /// EMM cause (TS 24.301 §9.9.3.9). V format.
    NasEmmCause
);
nas_ie_tlv!(
    /// EPS additional request result (TS 24.301 §9.9.3.67). TLV format.
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
nas_ie_tlv!(
    /// EPS bearer context status (TS 24.301 §9.9.2.1). TLV format.
    NasEpsBearerContextStatus
);
nas_ie_lv!(
    /// EPS mobile identity (TS 24.301 §9.9.3.12). LV format.
    NasEpsMobileIdentity
);
nas_ie_tlv!(
    /// EPS network feature support (TS 24.301 §9.9.3.12A). TLV format.
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
nas_ie_tlv!(
    /// Equivalent PLMNs (TS 24.301 §9.9.2.8). TLV format.
    NasEquivalentPlmns
);
nas_ie_v!(
    /// ESM cause (TS 24.301 §9.9.4.4). V format.
    NasEsmCause
);
nas_ie_tv1!(
    /// ESM information transfer flag (TS 24.301 §9.9.4.5). TV-1 format.
    NasEsmInformationTransferFlag
);
nas_ie_lve!(
    /// ESM message container (TS 24.301 §9.9.3.15). LV-E format.
    NasEsmMessageContainer
);
nas_ie_tlv!(
    /// Extended APN-AMBR (TS 24.301 §9.9.4.29). TLV format.
    NasExtendedApnAmbr
);
nas_ie_tlv!(
    /// Extended DRX parameters (TS 24.301 §9.9.3.46). TLV format.
    NasExtendedDrxParameters
);
nas_ie_tlve!(
    /// Extended emergency number list (TS 24.301 §9.9.3.37A). TLV-E format.
    NasExtendedEmergencyNumberList
);
nas_ie_tv1!(
    /// Extended EMM cause (TS 24.301 §9.9.3.26A). TV-1 format.
    NasExtendedEmmCause
);
nas_ie_tlv!(
    /// Extended EPS QoS (TS 24.301 §9.9.4.30). TLV format.
    NasExtendedEpsQos
);
nas_ie_tlve!(
    /// Extended protocol configuration options (TS 24.301 §9.9.4.26). TLV-E format.
    NasExtendedProtocolConfigurationOptions
);
nas_ie_tlv!(
    /// Forbidden TAI(s) for the list of "forbidden tracking areas for regional provision of service" (TS 24.301 §9.9.3.33). TLV format.
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService
);
nas_ie_tlv!(
    /// Forbidden TAI(s) for the list of "forbidden tracking areas for roaming" (TS 24.301 §9.9.3.33). TLV format.
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
    /// GPRS ciphering key sequence number (TS 24.301 §9.9.3.4A). TV-1 format.
    NasGprsCipheringKeySequenceNumber
);
nas_ie_tlv!(
    /// GPRS timer 2 (TS 24.301 §9.9.3.16A). TLV format.
    NasGprsTimer2
);
nas_ie_tlv!(
    /// HashMME (TS 24.301 §9.9.3.50). TLV format.
    NasHashMme
);
nas_ie_tlv!(
    /// Header compression configuration (TS 24.301 §9.9.4.22). TLV format.
    NasHeaderCompressionConfiguration
);
nas_ie_tlv!(
    /// Header compression configuration status (TS 24.301 §9.9.4.27). TLV format.
    NasHeaderCompressionConfigurationStatus
);
nas_ie_v!(
    /// Identity type (TS 24.301 §9.9.3.17). V format.
    NasIdentityType
);
nas_ie_tv1!(
    /// IMEISV request (TS 24.301 §9.9.3.18). TV-1 format.
    NasImeisvRequest
);
nas_ie_v!(
    /// NAS key set identifier (TS 24.301 §9.9.3.21). V format.
    NasKeySetIdentifier
);
nas_ie_tv_fixed!(
    /// Last visited registered TAI (TS 24.301 §9.9.3.32). TV format.
    NasLastVisitedRegisteredTai, 5
);
nas_ie_tlv!(
    /// LCS client identity (TS 24.301 §9.9.3.41). TLV format.
    NasLcsClientIdentity
);
nas_ie_tv!(
    /// LCS indicator (TS 24.301 §9.9.3.40). TV format.
    NasLcsIndicator
);
nas_ie_v!(
    /// Linked EPS bearer identity (TS 24.301 §9.9.4.6). V format.
    NasLinkedEpsBearerIdentity
);
nas_ie_tlv!(
    /// List of PLMNs to be used in disaster condition (TS 24.301 §9.9.3.76). TLV format.
    NasListOfPlmnsToBeUsedInDisasterCondition
);
nas_ie_tv!(
    /// Local time zone (TS 24.301 §9.9.3.29). TV format.
    NasLocalTimeZone
);
nas_ie_tv_fixed!(
    /// Location area identification (TS 24.301 §9.9.2.2). TV format.
    NasLocationAreaIdentification, 5
);
nas_ie_tlv!(
    /// Lower bound timer value (TS 24.301 §9.9.3.16B). TLV format.
    NasLowerBoundTimerValue
);
nas_ie_tlv!(
    /// Maximum time offset (TS 24.301 §9.9.3.16B). TLV format.
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
nas_ie_tlv!(
    /// Mobile station classmark 2 (TS 24.301 §9.9.2.4). TLV format.
    NasMobileStationClassmark2
);
nas_ie_tlv!(
    /// Mobile station classmark 3 (TS 24.301 §9.9.2.5). TLV format.
    NasMobileStationClassmark3
);
nas_ie_tlv!(
    /// MS network capability (TS 24.301 §9.9.3.20). TLV format.
    NasMsNetworkCapability
);
nas_ie_tv1!(
    /// MS network feature support (TS 24.301 §9.9.3.20A). TV-1 format.
    NasMsNetworkFeatureSupport
);
nas_ie_tlv!(
    /// N1 UE network capability (TS 24.301 §9.9.3.57). TLV format.
    NasN1UeNetworkCapability
);
nas_ie_tlv!(
    /// NBIFOM container (TS 24.301 §9.9.4.19). TLV format.
    NasNbifomContainer
);
nas_ie_tlv!(
    /// Negotiated DRX parameter in NB-S1 mode (TS 24.301 §9.9.3.63). TLV format.
    NasNegotiatedDrxParameterInNbS1Mode
);
nas_ie_tlv!(
    /// Negotiated IMSI offset (TS 24.301 §9.9.3.64). TLV format.
    NasNegotiatedImsiOffset
);
nas_ie_tv!(
    /// Negotiated LLC SAPI (TS 24.301 §9.9.4.7). TV format.
    NasNegotiatedLlcSapi
);
nas_ie_tlv!(
    /// Negotiated QoS (TS 24.301 §9.9.4.12). TLV format.
    NasNegotiatedQos
);
nas_ie_tlv!(
    /// Negotiated WUS assistance information (TS 24.301 §9.9.3.62). TLV format.
    NasNegotiatedWusAssistanceInformation
);
nas_ie_tlv!(
    /// Network daylight saving time (TS 24.301 §9.9.3.6). TLV format.
    NasNetworkDaylightSavingTime
);
nas_ie_tlv!(
    /// Network name, full or short (TS 24.301 §9.9.3.24). TLV format.
    NasNetworkName
);
nas_ie_tv1!(
    /// Network policy (TS 24.301 §9.9.3.52). TV-1 format.
    NasNetworkPolicy
);
nas_ie_tlv!(
    /// New EPS QoS (TS 24.301 §9.9.4.3). TLV format.
    NasNewEpsQos
);
nas_ie_tlv!(
    /// New QoS (TS 24.301 §9.9.4.12). TLV format.
    NasNewQos
);
nas_ie_tv1!(
    /// Non-3GPP NW provided policies (TS 24.301 §9.9.3.49). TV-1 format.
    NasNon3GppNwProvidedPolicies
);
nas_ie_tv1!(
    /// Non-current native NAS key set identifier (TS 24.301 §9.9.3.21). TV-1 format.
    NasNonCurrentNativeNasKeySetIdentifier
);
nas_ie_tv_fixed!(
    /// NonceMME (TS 24.301 §9.9.3.25). TV format.
    NasNonceMme, 4
);
nas_ie_tv_fixed!(
    /// NonceUE (TS 24.301 §9.9.3.25). TV format.
    NasNonceUe, 4
);
nas_ie_lv!(
    /// Notification indicator (TS 24.301 §9.9.4.7A). LV format.
    NasNotificationIndicator
);
nas_ie_tv1!(
    /// Old GUTI type (TS 24.301 §9.9.3.45). TV-1 format.
    NasOldGutiType
);
nas_ie_tv_fixed!(
    /// Old P-TMSI signature (TS 24.301 §9.9.3.26). TV format.
    NasOldPTmsiSignature, 3
);
nas_ie_tlv!(
    /// Packet flow Identifier (TS 24.301 §9.9.4.8). TLV format.
    NasPacketFlowIdentifier
);
nas_ie_v!(
    /// Paging identity (TS 24.301 §9.9.3.25A). V format.
    NasPagingIdentity
);
nas_ie_tlv!(
    /// Paging restriction (TS 24.301 §9.9.3.66). TLV format.
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
nas_ie_tlv!(
    /// ProSe Key Management Function address (TS 24.301 §9.9.4.21). TLV format.
    NasProseKeyManagementFunctionAddress
);
nas_ie_tlv!(
    /// Protocol configuration options (TS 24.301 §9.9.4.11). TLV format.
    NasProtocolConfigurationOptions
);
nas_ie_tv1!(
    /// Radio priority (TS 24.301 §9.9.4.13). TV-1 format.
    NasRadioPriority
);
nas_ie_tlv!(
    /// Re-attempt indicator (TS 24.301 §9.9.4.13A). TLV format.
    NasReAttemptIndicator
);
nas_ie_tv1!(
    /// Release assistance indication (TS 24.301 §9.9.4.25). TV-1 format.
    NasReleaseAssistanceIndication
);
nas_ie_tlve!(
    /// Remote UE Context Connected (TS 24.301 §9.9.4.20). TLV-E format.
    NasRemoteUeContextConnected
);
nas_ie_tlve!(
    /// Remote UE Context Disconnected (TS 24.301 §9.9.4.20). TLV-E format.
    NasRemoteUeContextDisconnected
);
nas_ie_tlve!(
    /// Replayed NAS message container (TS 24.301 §9.9.3.51). TLV-E format.
    NasReplayedNasMessageContainer
);
nas_ie_tv_fixed!(
    /// Replayed nonceUE (TS 24.301 §9.9.3.25). TV format.
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
nas_ie_tlv!(
    /// Requested IMSI offset (TS 24.301 §9.9.3.64). TLV format.
    NasRequestedImsiOffset
);
nas_ie_tlv!(
    /// Requested WUS assistance information (TS 24.301 §9.9.3.62). TLV format.
    NasRequestedWusAssistanceInformation
);
nas_ie_lv!(
    /// Required traffic flow QoS (TS 24.301 §9.9.4.3). LV format.
    NasRequiredTrafficFlowQos
);
nas_ie_tlv!(
    /// S&F satellite operation parameters (TS 24.301 §9.9.3.73). TLV format.
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
nas_ie_tlv!(
    /// Serving PLMN rate control (TS 24.301 §9.9.4.28). TLV format.
    NasServingPlmnRateControl
);
nas_ie_tv1!(
    /// SMS services status (TS 24.301 §9.9.3.4B). TV-1 format.
    NasSmsServicesStatus
);
nas_ie_v!(
    /// Spare half octet (TS 24.301 §9.9.2.9). V format.
    NasSpareHalfOctet
);
nas_ie_tv!(
    /// SS Code (TS 24.301 §9.9.3.39). TV format.
    NasSsCode
);
nas_ie_tlv!(
    /// Supported Codecs (TS 24.301 §9.9.2.10). TLV format.
    NasSupportedCodecs
);
nas_ie_tlv!(
    /// T3324 value (TS 24.301 §9.9.3.16A). TLV format.
    NasT3324Value
);
nas_ie_tlv!(
    /// T3346 value (TS 24.301 §9.9.3.16A). TLV format.
    NasT3346Value
);
nas_ie_tlv!(
    /// T3396 value (TS 24.301 §9.9.3.16B). TLV format.
    NasT3396Value
);
nas_ie_v!(
    /// T3402 value (TS 24.301 §9.9.3.16). One-octet value; message fields use TV format.
    NasT3402Value
);
nas_ie_tlv!(
    /// T3412 extended value (TS 24.301 §9.9.3.16B). TLV format.
    NasT3412ExtendedValue
);
nas_ie_v!(
    /// T3412 value (TS 24.301 §9.9.3.16). V format.
    NasT3412Value
);
nas_ie_tv!(
    /// T3423 value (TS 24.301 §9.9.3.16). TV format.
    NasT3423Value
);
nas_ie_tv!(
    /// T3442 value (TS 24.301 §9.9.3.16). TV format.
    NasT3442Value
);
nas_ie_tlv!(
    /// T3447 value (TS 24.301 §9.9.3.16B). TLV format.
    NasT3447Value
);
nas_ie_tlv!(
    /// T3448 value (TS 24.301 §9.9.3.16A). TLV format.
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
nas_ie_tlv!(
    /// TMSI based NRI container (TS 24.301 §9.9.3.24A). TLV format.
    NasTmsiBasedNriContainer
);
nas_ie_tv1!(
    /// TMSI status (TS 24.301 §9.9.3.31). TV-1 format.
    NasTmsiStatus
);
nas_ie_lv!(
    /// Traffic flow aggregate (TS 24.301 §9.9.4.15). LV format.
    NasTrafficFlowAggregate
);
nas_ie_tlv!(
    /// Transaction identifier (TS 24.301 §9.9.4.17). TLV format.
    NasTransactionIdentifier
);
nas_ie_tlv!(
    /// UE additional security capability (TS 24.301 §9.9.3.53). TLV format.
    NasUeAdditionalSecurityCapability
);
nas_ie_tlv!(
    /// UE coarse location information (TS 24.301 §9.9.3.72). TLV format.
    NasUeCoarseLocationInformation
);
nas_ie_tv1!(
    /// UE coarse location information request (TS 24.301 §9.9.3.71). TV-1 format.
    NasUeCoarseLocationInformationRequest
);
nas_ie_tlv!(
    /// UE determined PLMN with disaster condition (TS 24.301 §9.9.3.77). TLV format.
    NasUeDeterminedPlmnWithDisasterCondition
);
nas_ie_lv!(
    /// UE network capability (TS 24.301 §9.9.3.34). LV format.
    NasUeNetworkCapability
);
nas_ie_tlv!(
    /// UE radio capability ID (TS 24.301 §9.9.3.60). TLV format.
    NasUeRadioCapabilityId
);
nas_ie_tlv!(
    /// UE radio capability ID availability (TS 24.301 §9.9.3.58). TLV format.
    NasUeRadioCapabilityIdAvailability
);
nas_ie_tv1!(
    /// UE radio capability ID deletion indication (TS 24.301 §9.9.3.61). TV-1 format.
    NasUeRadioCapabilityIdDeletionIndication
);
nas_ie_tlv!(
    /// UE radio capability ID request (TS 24.301 §9.9.3.59). TLV format.
    NasUeRadioCapabilityIdRequest
);
nas_ie_tv1!(
    /// UE radio capability information update needed (TS 24.301 §9.9.3.35). TV-1 format.
    NasUeRadioCapabilityInformationUpdateNeeded
);
nas_ie_tlv!(
    /// UE request type (TS 24.301 §9.9.3.65). TLV format.
    NasUeRequestType
);
nas_ie_tlv!(
    /// UE status (TS 24.301 §9.9.3.54). TLV format.
    NasUeStatus
);
nas_ie_tlv!(
    /// Unavailability configuration (TS 24.301 §9.9.3.70). TLV format.
    NasUnavailabilityConfiguration
);
nas_ie_tlv!(
    /// Unavailability information (TS 24.301 §9.9.3.69). TLV format.
    NasUnavailabilityInformation
);
nas_ie_tv_fixed!(
    /// Universal time and local time zone (TS 24.301 §9.9.3.30). TV format.
    NasUniversalTimeAndLocalTimeZone, 7
);
nas_ie_lve!(
    /// User data container (TS 24.301 §9.9.4.24). LV-E format.
    NasUserDataContainer
);
nas_ie_tlv!(
    /// Voice domain preference and UE's usage setting (TS 24.301 §9.9.3.44). TLV format.
    NasVoiceDomainPreferenceAndUeUsageSetting
);
nas_ie_tv1!(
    /// WLAN offload indication (TS 24.301 §9.9.4.18). TV-1 format.
    NasWlanOffloadIndication
);

// END TS24301 TYPES
