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

//! Raw wire-format Information Element types and codec traits.
//!
//! This is **Layer 1** of the crate. Every IE struct here holds raw bytes in a
//! `pub value` field and implements [`Encode`]/[`Decode`] for the wire format
//! defined in 3GPP TS 24.007 &sect;11.2.
//!
//! For typed, semantic access to these bytes (enums, parsers, builders), see the
//! [`ie`](crate::nas_5gs::ie) module (Layer 3).
//!
//! # IE format summary
//!
//! | Format | Type field | Length field | Example |
//! |--------|-----------|-------------|---------|
//! | V      | none      | none        | [`NasFGmmCause`] |
//! | LV     | none      | u8          | [`NasAbba`], [`NasUeSecurityCapability`] |
//! | LV-E   | none      | u16         | [`NasFGsMobileIdentity`] |
//! | TV-1   | 4 bits    | none        | [`NasMicoIndication`] |
//! | TV     | u8        | none        | [`NasGprsTimer`] |
//! | TLV    | u8        | u8          | [`NasNssai`], [`NasDnn`] |
//! | TLV-E  | u8        | u16         | [`NasEapMessage`], [`NasMessageContainer`] |

pub use crate::common::{Decode, Encode, MAX_IE_VALUE_LENGTH, NasError, Result, helpers};
use crate::common::{
    nas_ie_lv, nas_ie_lve, nas_ie_tlv, nas_ie_tlve, nas_ie_tv, nas_ie_tv_fixed, nas_ie_tv1,
    nas_ie_v, nas_ie_v_u16,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

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
/// 5GS Identity Type (TS 24.501 &sect;9.11.3.3).
///
/// Only the lower 3 bits are significant. Use [`MobileIdentityType`](crate::nas_5gs::ie::MobileIdentityType)
/// for typed access via the `identity_type()` method defined in the [`ie`](crate::nas_5gs::ie) module.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasFGsIdentityType {
    /// Value octet, spare bits included.
    pub value: u8,
}
impl NasFGsIdentityType {
    /// Build the IE from its value octet.
    pub fn new(value: u8) -> Self {
        Self { value }
    }
}
impl Encode for NasFGsIdentityType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        buffer.put_u8(self.value);
        Ok(())
    }
}
impl Decode for NasFGsIdentityType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        Ok(Self {
            value: buffer.get_u8(),
        })
    }
}
nas_ie_v!(
    /// 5GS Registration Type (TS 24.501 §9.11.3.7). V format (1 byte).
    NasFGsRegistrationType
);
nas_ie_v!(
    /// NAS Key Set Identifier (TS 24.501 §9.11.3.32). V format (1 byte).
    NasKeySetIdentifier
);
/// Payload Container Type (TS 24.501 &sect;9.11.3.40).
///
/// Only the lower 4 bits are significant. Use [`PayloadContainerKind`](crate::nas_5gs::ie::PayloadContainerKind)
/// for typed access via the `kind()` method defined in the [`ie`](crate::nas_5gs::ie) module.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasPayloadContainerType {
    /// Value octet, spare bits included.
    pub value: u8,
}
impl NasPayloadContainerType {
    /// Build the IE from its value octet.
    pub fn new(value: u8) -> Self {
        Self { value }
    }
}
impl Encode for NasPayloadContainerType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        buffer.put_u8(self.value);
        Ok(())
    }
}
impl Decode for NasPayloadContainerType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        Ok(Self {
            value: buffer.get_u8(),
        })
    }
}
nas_ie_v!(
    /// NAS Security Algorithms (TS 24.501 §9.11.3.34). V format (1 byte).
    NasSecurityAlgorithms
);
nas_ie_v_u16!(
    /// Integrity Protection Maximum Data Rate (TS 24.501 §9.11.4.7). V format (2 bytes).
    NasIntegrityProtectionMaximumDataRate
);
nas_ie_tv_fixed!(
    /// Maximum Number of Supported Packet Filters (TS 24.501 §9.11.4.9).
    ///
    /// Type 3 IE per TS 24.007 §11.2.4: TV with a **fixed 2-octet value** (IEI +
    /// 11-bit count + 5 spare bits = 3 octets total). It is **not** a TLV — there
    /// is no length octet on the wire. This was previously declared as TLV which
    /// caused PDU Session Establishment/Modification Request roundtrips against
    /// the free5gc test corpus to corrupt the byte stream after this IE.
    NasMaximumNumberOfSupportedPacketFilters, 2
);

// ── LV format (mandatory variable-length) ────────────────────────────────────

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

// ── LV-E format (mandatory extended variable-length) ─────────────────────────

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

// ── TV-1 format (half-byte optional) ─────────────────────────────────────────

nas_ie_tv1!(
    /// Access Type (TS 24.501 §9.11.2.1A). TV-1 format.
    NasAccessType
);
nas_ie_tv1!(
    /// Additional Configuration Indication (TS 24.501 §9.11.3.74). TV-1 format.
    NasAdditionalConfigurationIndication
);
nas_ie_tv1!(
    /// Allowed SSC Mode (TS 24.501 §9.11.4.5). TV-1 format.
    NasAllowedSscMode
);
nas_ie_tv1!(
    /// Always-on PDU Session Indication (TS 24.501 §9.11.4.3). TV-1 format.
    NasAlwaysOnPduSessionIndication
);
nas_ie_tv1!(
    /// Always-on PDU Session Requested (TS 24.501 §9.11.4.4). TV-1 format.
    NasAlwaysOnPduSessionRequested
);
nas_ie_tv1!(
    /// Configuration Update Indication (TS 24.501 §9.11.3.18). TV-1 format.
    NasConfigurationUpdateIndication
);
nas_ie_tv1!(
    /// Control Plane Only Indication (TS 24.501 §9.11.4.23). TV-1 format.
    NasControlPlaneOnlyIndication
);
nas_ie_tv1!(
    /// IMEISV Request (TS 24.501 §9.11.3.28). TV-1 format.
    NasImeisvRequest
);
nas_ie_tv1!(
    /// LP-WUS Status (TS 24.501 §9.11.3.112). TV-1 format.
    NasLpWusStatus
);
nas_ie_tv1!(
    /// MA PDU Session Information (TS 24.501 §9.11.3.31A). TV-1 format.
    NasMaPduSessionInformation
);
nas_ie_tv1!(
    /// MICO Indication (TS 24.501 §9.11.3.31). TV-1 format.
    NasMicoIndication
);
nas_ie_tv1!(
    /// N5GC Indication (TS 24.501 §9.11.3.72). TV-1 format.
    NasN5gcIndication
);
nas_ie_tv1!(
    /// Network Slicing Indication (TS 24.501 §9.11.3.36). TV-1 format.
    NasNetworkSlicingIndication
);
nas_ie_tv1!(
    /// Non-3GPP NW Provided Policies (TS 24.501 §9.11.3.36A). TV-1 format.
    NasNon3GppNwProvidedPolicies
);
nas_ie_tv1!(
    /// NSSAI Inclusion Mode (TS 24.501 §9.11.3.37A). TV-1 format.
    NasNssaiInclusionMode
);
nas_ie_tv1!(
    /// PDU Session Type (TS 24.501 §9.11.4.11). TV-1 format.
    NasPduSessionType
);
nas_ie_tv1!(
    /// Priority Indicator (TS 24.501 §9.11.3.91). TV-1 format.
    NasPriorityIndicator
);
nas_ie_tv1!(
    /// Release Assistance Indication (TS 24.501 §9.11.3.46A). TV-1 format.
    NasReleaseAssistanceIndication
);
nas_ie_tv1!(
    /// Request Type (TS 24.501 §9.11.3.47). TV-1 format.
    NasRequestType
);
nas_ie_tv1!(
    /// SMS Indication (TS 24.501 §9.11.3.50A). TV-1 format.
    NasSmsIndication
);
nas_ie_tv1!(
    /// SSC Mode (TS 24.501 §9.11.4.16). TV-1 format.
    NasSscMode
);
nas_ie_tv1!(
    /// UE Radio Capability ID Deletion Indication (TS 24.501 §9.11.3.69). TV-1 format.
    NasUeRadioCapabilityIdDeletionIndication
);

// ── TV format (optional fixed 1-byte) ────────────────────────────────────────

nas_ie_tv!(
    /// EPS NAS Security Algorithms (TS 24.501 §9.11.3.25). TV format (1+1 bytes).
    NasEpsNasSecurityAlgorithms
);
nas_ie_tv!(
    /// GPRS Timer (TS 24.501 §9.11.2.3). TV format (1+1 bytes).
    NasGprsTimer
);
nas_ie_tv!(
    /// N1 mode to S1 mode NAS transparent container (TS 24.501 §9.11.2.7). Type 3 / TV format (1+1 bytes).
    NasN1ModeToS1ModeNasTransparentContainer
);
nas_ie_tv!(
    /// PDU Session Identity 2 (TS 24.501 §9.11.3.41). TV format (1+1 bytes).
    NasPduSessionIdentity2
);
nas_ie_tv!(
    /// Time Zone (TS 24.501 §9.11.3.52). TV format (1+1 bytes).
    NasTimeZone
);

// ── TV format (fixed-length Vec) ─────────────────────────────────────────────

nas_ie_tv_fixed!(
    /// Authentication Parameter RAND (TS 24.501 §9.11.3.16). TV format (1+16 bytes).
    NasAuthenticationParameterRand, 16
);
nas_ie_tv_fixed!(
    /// 5GS Tracking Area Identity (TS 24.501 §9.11.3.8). TV format (1+6 bytes: PLMN + TAC).
    NasFGsTrackingAreaIdentity, 6
);
nas_ie_tv_fixed!(
    /// Time Zone and Time (TS 24.501 §9.11.3.53). TV format (1+7 bytes: Y/M/D/H/M/S/TZ).
    NasTimeZoneAndTime, 7
);

// ── TLV format (optional variable-length) ────────────────────────────────────

nas_ie_tlv!(
    /// Access Technology Utilization Control (TS 24.501 §9.11.3.110). TLV format.
    NasAccessTechnologyUtilizationControl
);
nas_ie_tlv!(
    /// Additional 5G Security Information (TS 24.501 §9.11.3.12). TLV format.
    NasAdditional5gSecurityInformation
);
nas_ie_tlv!(
    /// Additional Information (TS 24.501 §9.11.2.1). TLV format.
    NasAdditionalInformation
);
nas_ie_tlv!(
    /// Additional Information Requested (TS 24.501 §9.11.3.12A). TLV format.
    NasAdditionalInformationRequested
);
nas_ie_tlv!(
    /// Allowed PDU Session Status (TS 24.501 §9.11.3.13). TLV format.
    NasAllowedPduSessionStatus
);
nas_ie_tlv!(
    /// Authentication Failure Parameter (TS 24.501 §9.11.3.14). TLV format.
    NasAuthenticationFailureParameter
);
nas_ie_tlv!(
    /// Authentication Parameter AUTN (TS 24.501 §9.11.3.15). TLV format.
    NasAuthenticationParameterAutn
);
nas_ie_tlv!(
    /// Authentication Response Parameter (TS 24.501 §9.11.3.17). TLV format.
    NasAuthenticationResponseParameter
);
nas_ie_tlv!(
    /// Daylight Saving Time (TS 24.501 §9.11.3.19). TLV format.
    NasDaylightSavingTime
);
nas_ie_tlv!(
    /// DNN (TS 24.501 §9.11.2.1B). TLV format.
    NasDnn
);
nas_ie_tlv!(
    /// Intra N1 mode NAS transparent container (TS 24.501 §9.11.2.6). TLV format.
    NasIntraN1ModeNasTransparentContainer
);
nas_ie_tlv!(
    /// DS-TT Ethernet Port MAC Address (TS 24.501 §9.11.4.25). TLV format.
    NasDsTtEthernetPortMacAddress
);
nas_ie_tlv!(
    /// Emergency Number List (TS 24.501 §9.11.3.23). TLV format.
    NasEmergencyNumberList
);
nas_ie_tlv!(
    /// EPS Bearer Context Status (TS 24.501 §9.11.3.23A). TLV format.
    NasEpsBearerContextStatus
);
nas_ie_tlv!(
    /// Ethernet Header Compression Configuration (TS 24.501 §9.11.4.28). TLV format.
    NasEthernetHeaderCompressionConfiguration
);
nas_ie_tlv!(
    /// Extended DRX Parameters (TS 24.501 §9.11.3.26A). TLV format.
    NasExtendedDrxParameters
);
nas_ie_tlv!(
    /// Extended Rejected NSSAI (TS 24.501 §9.11.3.75). TLV format.
    NasExtendedRejectedNssai
);
nas_ie_tlv!(
    /// 5GMM Capability (TS 24.501 §9.11.3.1). TLV format.
    NasFGmmCapability
);
nas_ie_tlv!(
    /// 5GS Additional Request Result (TS 24.501 §9.11.3.81). TLV format.
    NasFGsAdditionalRequestResult
);
nas_ie_tlv!(
    /// 5GS DRX Parameters (TS 24.501 §9.11.3.2A). TLV format.
    NasFGsDrxParameters
);
nas_ie_tlv!(
    /// 5GS Network Feature Support (TS 24.501 §9.11.3.5). TLV format.
    NasFGsNetworkFeatureSupport
);
nas_ie_tlv!(
    /// 5GS Tracking Area Identity List (TS 24.501 §9.11.3.9). TLV format.
    NasFGsTrackingAreaIdentityList
);
nas_ie_tlv!(
    /// 5GS Update Type (TS 24.501 §9.11.3.9A). TLV format.
    NasFGsUpdateType
);
nas_ie_tlv!(
    /// 5GSM Capability (TS 24.501 §9.11.4.1). TLV format.
    NasFGsmCapability
);
nas_ie_tlv!(
    /// 5GSM Congestion Re-attempt Indicator (TS 24.501 §9.11.4.21). TLV format.
    NasFGsmCongestionReAttemptIndicator
);
nas_ie_tlv!(
    /// 5GSM Network Feature Support (TS 24.501 §9.11.4.18). TLV format.
    NasFGsmNetworkFeatureSupport
);
nas_ie_tlv!(
    /// GPRS Timer 2 (TS 24.501 §9.11.2.4). TLV format.
    NasGprsTimer2
);
nas_ie_tlv!(
    /// GPRS Timer 3 (TS 24.501 §9.11.2.5). TLV format.
    NasGprsTimer3
);
nas_ie_tlv!(
    /// IP Header Compression Configuration (TS 24.501 §9.11.4.24). TLV format.
    NasIpHeaderCompressionConfiguration
);
nas_ie_tlv!(
    /// List of PLMNs to be Used in Disaster Condition (TS 24.501 §9.11.3.83). TLV format.
    NasListOfPlmnsToBeUsedInDisasterCondition
);
nas_ie_tlv!(
    /// Mapped NSSAI (TS 24.501 §9.11.3.31B). TLV format.
    NasMappedNssai
);
nas_ie_tlv!(
    /// Mobile Station Classmark 2 (TS 24.501 §9.11.3.31C). TLV format.
    NasMobileStationClassmark2
);
nas_ie_tlv!(
    /// NB-N1 Mode DRX Parameters (TS 24.501 §9.11.3.73). TLV format.
    NasNbN1ModeDrxParameters
);
nas_ie_tlv!(
    /// Network Name (TS 24.501 §9.11.3.35). TLV format.
    NasNetworkName
);
nas_ie_tlv!(
    /// NID (TS 24.501 §9.11.3.79). TLV format.
    NasNid
);
nas_ie_tlv!(
    /// NSSAI (TS 24.501 §9.11.3.37). TLV format.
    NasNssai
);
nas_ie_tlv!(
    /// Paging Restriction (TS 24.501 §9.11.3.77). TLV format.
    NasPagingRestriction
);
nas_ie_tlv!(
    /// PDU Address (TS 24.501 §9.11.4.10). TLV format.
    NasPduAddress
);
nas_ie_tlv!(
    /// PDU Session Pair ID (TS 24.501 §9.11.4.32). TLV format.
    NasPduSessionPairId
);
nas_ie_tlv!(
    /// PDU Session Reactivation Result (TS 24.501 §9.11.3.42). TLV format.
    NasPduSessionReactivationResult
);
nas_ie_tlv!(
    /// PDU Session Status (TS 24.501 §9.11.3.44). TLV format.
    NasPduSessionStatus
);
nas_ie_tlv!(
    /// PEIPS Assistance Information (TS 24.501 §9.11.3.80). TLV format.
    NasPeipsAssistanceInformation
);
nas_ie_tlv!(
    /// PLMN Identity (TS 24.501 §9.11.3.85). TLV format.
    NasPlmnIdentity
);
nas_ie_tlv!(
    /// PLMN List (TS 24.501 §9.11.3.45). TLV format.
    NasPlmnList
);
nas_ie_tlv!(
    /// Re-attempt Indicator (TS 24.501 §9.11.4.17). TLV format.
    NasReAttemptIndicator
);
nas_ie_tlv!(
    /// Registration Wait Range (TS 24.501 §9.11.3.84). TLV format.
    NasRegistrationWaitRange
);
nas_ie_tlv!(
    /// Rejected NSSAI (TS 24.501 §9.11.3.46). TLV format.
    NasRejectedNssai
);
nas_ie_tlv!(
    /// S1 mode to N1 mode NAS transparent container (TS 24.501 §9.11.2.9). TLV format.
    NasS1ModeToN1ModeNasTransparentContainer
);
nas_ie_tlv!(
    /// RSN (TS 24.501 §9.11.4.33). TLV format.
    NasRsn
);
nas_ie_tlv!(
    /// S1 UE Network Capability (TS 24.501 §9.11.3.48). TLV format.
    NasS1UeNetworkCapability
);
nas_ie_tlv!(
    /// S1 UE Security Capability (TS 24.501 §9.11.3.48A). TLV format.
    NasS1UeSecurityCapability
);
nas_ie_tlv!(
    /// S-NSSAI (TS 24.501 §9.11.2.8). TLV format.
    NasSNssai
);
nas_ie_tlv!(
    /// Service Area List (TS 24.501 §9.11.3.49). TLV format.
    NasServiceAreaList
);
nas_ie_tlv!(
    /// Serving PLMN Rate Control (TS 24.501 §9.11.4.20). TLV format.
    NasServingPlmnRateControl
);
nas_ie_tlv!(
    /// SM PDU DN Request Container (TS 24.501 §9.11.4.15). TLV format.
    NasSmPduDnRequestContainer
);
nas_ie_tlv!(
    /// Supported Codec List (TS 24.501 §9.11.3.51A). TLV format.
    NasSupportedCodecList
);
nas_ie_tlv!(
    /// Time duration (TS 24.501 §9.11.2.19, referring to TS 24.301 §9.9.3.68). TLV format.
    NasTimeDuration
);
nas_ie_tlv!(
    /// Truncated 5G-S-TMSI Configuration (TS 24.501 §9.11.3.70). TLV format.
    NasTruncatedFGSTmsiConfiguration
);
nas_ie_tlv!(
    /// UE DS-TT Residence Time (TS 24.501 §9.11.4.26). TLV format.
    NasUeDsTtResidenceTime
);
nas_ie_tlv!(
    /// UE Radio Capability ID (TS 24.501 §9.11.3.68). TLV format.
    NasUeRadioCapabilityId
);
nas_ie_tlv!(
    /// UE Request Type (TS 24.501 §9.11.3.76). TLV format.
    NasUeRequestType
);
nas_ie_tlv!(
    /// UE Status (TS 24.501 §9.11.3.56). TLV format.
    NasUeStatus
);
nas_ie_tlv!(
    /// UE Usage Setting (TS 24.501 §9.11.3.55). TLV format.
    NasUeUsageSetting
);
nas_ie_tlv!(
    /// Unavailability Configuration (TS 24.501 §9.11.2.21). TLV format.
    NasUnavailabilityConfiguration
);
nas_ie_tlv!(
    /// Unavailability Information (TS 24.501 §9.11.2.20). TLV format.
    NasUnavailabilityInformation
);
nas_ie_tlv!(
    /// Uplink Data Status (TS 24.501 §9.11.3.57). TLV format.
    NasUplinkDataStatus
);
nas_ie_tlv!(
    /// WUS Assistance Information (TS 24.501 §9.11.3.71). TLV format.
    NasWusAssistanceInformation
);

// ── TLV-E format (optional extended variable-length) ─────────────────────────

nas_ie_tlve!(
    /// ATSSS Container (TS 24.501 §9.11.4.22). TLV-E format.
    NasAtsssContainer
);
nas_ie_tlve!(
    /// CAG Information List (TS 24.501 §9.11.3.18A). TLV-E format.
    NasCagInformationList
);
nas_ie_tlve!(
    /// Ciphering Key Data (TS 24.501 §9.11.3.18C). TLV-E format.
    NasCipheringKeyData
);
nas_ie_lve!(
    /// EAP Message (TS 24.501 §9.11.2.2). LV-E format (mandatory) / TLV-E via \[opt_type\] (optional).
    NasEapMessage
);
nas_ie_tlve!(
    /// EPS NAS Message Container (TS 24.501 §9.11.3.24). TLV-E format.
    NasEpsNasMessageContainer
);
nas_ie_tlve!(
    /// Extended CAG Information List (TS 24.501 §9.11.3.86). TLV-E format.
    NasExtendedCagInformationList
);
nas_ie_tlve!(
    /// Extended Emergency Number List (TS 24.501 §9.11.3.26). TLV-E format.
    NasExtendedEmergencyNumberList
);
nas_ie_tlve!(
    /// Extended Protocol Configuration Options (TS 24.501 §9.11.4.6). TLV-E format.
    NasExtendedProtocolConfigurationOptions
);
nas_ie_tlve!(
    /// LADN Indication (TS 24.501 §9.11.3.29). TLV-E format.
    NasLadnIndication
);
nas_ie_tlve!(
    /// LADN Information (TS 24.501 §9.11.3.30). TLV-E format.
    NasLadnInformation
);
nas_ie_tlve!(
    /// Mapped EPS Bearer Contexts (TS 24.501 §9.11.4.8). TLV-E format.
    NasMappedEpsBearerContexts
);
nas_ie_tlve!(
    /// NAS Message Container (TS 24.501 §9.11.3.33). TLV-E format.
    NasMessageContainer
);
nas_ie_tlve!(
    /// NSAG Information (TS 24.501 §9.11.3.87). TLV-E format.
    NasNsagInformation
);
nas_ie_tlve!(
    /// NSSRG Information (TS 24.501 §9.11.3.82). TLV-E format.
    NasNssrgInformation
);
nas_ie_tlve!(
    /// Operator-defined Access Category Definitions (TS 24.501 §9.11.3.38). TLV-E format.
    NasOperatorDefinedAccessCategoryDefinitions
);
nas_ie_tlve!(
    /// PDU Session Reactivation Result Error Cause (TS 24.501 §9.11.3.43). TLV-E format.
    NasPduSessionReactivationResultErrorCause
);
nas_ie_tlve!(
    /// Port Management Information Container (TS 24.501 §9.11.4.27). TLV-E format.
    NasPortManagementInformationContainer
);
nas_ie_tlve!(
    /// QoS Flow Descriptions (TS 24.501 §9.11.4.12). TLV-E format.
    NasQosFlowDescriptions
);
nas_ie_tlve!(
    /// Received MBS Container (TS 24.501 §9.11.4.31). TLV-E format.
    NasReceivedMbsContainer
);
nas_ie_tlve!(
    /// Requested MBS Container (TS 24.501 §9.11.4.30). TLV-E format.
    NasRequestedMbsContainer
);
nas_ie_tlve!(
    /// Service-level-AA Container (TS 24.501 §9.11.2.10). TLV-E format.
    NasServiceLevelAaContainer
);
nas_ie_tlve!(
    /// SOR Transparent Container (TS 24.501 §9.11.3.51). TLV-E format.
    NasSorTransparentContainer
);

// ── Later-release and extended IEs ──────────────────────────────────────────
//
// These IEs are exposed here with their raw TS 24.501 wire shapes; the helpers
// in `crate::nas_5gs::ie` provide getters/setters where this crate exposes typed
// structure.

nas_ie_tlv!(
    /// Extended 5GMM Cause (TS 24.501 §9.11.3.109). TLV format.
    NasExtendedFGmmCause
);
nas_ie_tlv!(
    /// Alternative NSSAI (TS 24.501 §9.11.3.97). TLV format.
    NasAlternativeNssai
);
nas_ie_tlv!(
    /// AUN3 indication (TS 24.501 §9.11.3.104). TLV format.
    NasAun3Indication
);
nas_ie_tlv!(
    /// AUN3 device security key (TS 24.501 §9.11.3.107). TLV format.
    NasAun3DeviceSecurityKey
);
nas_ie_tlv!(
    /// CIoT small data container (TS 24.501 §9.11.3.18B). TLV format.
    NasCiotSmallDataContainer
);
nas_ie_tlve!(
    /// Extended LADN information (TS 24.501 §9.11.3.96). TLV-E format.
    NasExtendedLadnInformation
);
nas_ie_tlv!(
    /// Feature authorization indication (TS 24.501 §9.11.3.105). TLV format.
    NasFeatureAuthorizationIndication
);
nas_ie_tlv!(
    /// LP-WUSPS assistance information (TS 24.501 §9.11.3.111). TLV format.
    NasLpWuspsAssistanceInformation
);
nas_ie_tlv!(
    /// Non-3GPP access path switching indication (TS 24.501 §9.11.3.99). TLV format.
    NasNon3GppAccessPathSwitchingIndication
);
nas_ie_tlv!(
    /// Non-3GPP path switching information (TS 24.501 §9.11.3.102). TLV format.
    NasNon3GppPathSwitchingInformation
);
nas_ie_tlv!(
    /// N3IWF identifier (TS 24.501 §9.11.3.93). TLV format.
    NasN3iwfIdentifier
);
nas_ie_tlv!(
    /// On-demand NSSAI (TS 24.501 §9.11.3.108). TLV format.
    NasOnDemandNssai
);
nas_ie_tlve!(
    /// Partial NSSAI (TS 24.501 §9.11.3.103). TLV-E format.
    NasPartialNssai
);
nas_ie_tv1!(
    /// Payload container information (TS 24.501 §9.11.3.106). TV-1 format.
    NasPayloadContainerInformation
);
nas_ie_tlv!(
    /// RAN timing synchronization (TS 24.501 §9.11.3.95). TLV format.
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
nas_ie_tlv!(
    /// SNPN list (TS 24.501 §9.11.3.92). TLV format.
    NasSnpnList
);
nas_ie_tlve!(
    /// S-NSSAI location validity information (TS 24.501 §9.11.3.100). TLV-E format.
    NasSNssaiLocationValidityInformation
);
nas_ie_tlv!(
    /// S-NSSAI time validity information (TS 24.501 §9.11.3.101). TLV format.
    NasSNssaiTimeValidityInformation
);
nas_ie_tlv!(
    /// TNAN information (TS 24.501 §9.11.3.94). TLV format.
    NasTnanInformation
);
nas_ie_tlve!(
    /// Type-6 IE container (TS 24.501 §9.11.3.98). TLV-E format.
    NasType6IeContainer
);
nas_ie_tlve!(
    /// UE parameters update transparent container (TS 24.501 §9.11.3.53A). TLV-E format.
    NasUeParametersUpdateTransparentContainer
);
nas_ie_tlv!(
    /// ECN marking for L4S indication (TS 24.501 §9.11.4.40). TLV format.
    NasEcnMarkingL4sIndication
);
nas_ie_tlve!(
    /// ECS address (TS 24.501 §9.11.4.34). TLV-E format.
    NasEcsAddress
);
nas_ie_tlve!(
    /// Non-3GPP delay budget (TS 24.501 §9.11.4.37). TLV-E format.
    NasNon3GppDelayBudget
);
nas_ie_tlve!(
    /// Non-3GPP device information (TS 24.501 §9.11.4.41). TLV-E format.
    NasNon3GppDeviceInformation
);
nas_ie_tlve!(
    /// N3 QAI (TS 24.501 §9.11.4.36). TLV-E format.
    NasN3Qai
);
nas_ie_tlve!(
    /// Protocol description (TS 24.501 §9.11.4.39). TLV-E format.
    NasProtocolDescription
);
nas_ie_tlve!(
    /// Remote UE context list (TS 24.501 §9.11.4.29). TLV-E format.
    NasRemoteUeContextList
);
nas_ie_tlv!(
    /// URSP rule enforcement reports (TS 24.501 §9.11.4.38). TLV format.
    NasUrspRuleEnforcementReports
);

// ── Type 3 / dual-mode IEs — manual impl ───────────────────────────────────

/// 5G ProSe relay transaction identity (TS 24.501 &sect;9.11.3.88).
///
/// Type 3 IE: V format when mandatory (`type_field == 0`), TV format when
/// optional (`type_field != 0`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasProseRelayTransactionIdentity {
    /// Type field (IEI); 0 for the mandatory V form.
    pub type_field: u8,
    /// Value octet.
    pub value: u8,
}

impl NasProseRelayTransactionIdentity {
    /// Build the IE from its value octet.
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0,
            value,
        }
    }

    /// Decode as a mandatory (V) IE: read the identity value octet only.
    pub fn decode_value_only(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        Ok(Self {
            type_field: 0,
            value: buffer.get_u8(),
        })
    }
}

impl Encode for NasProseRelayTransactionIdentity {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.type_field != 0 {
            buffer.put_u8(self.type_field);
        }
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasProseRelayTransactionIdentity {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(NasError::BufferTooShort);
        }
        Ok(Self {
            type_field: buffer.get_u8(),
            value: buffer.get_u8(),
        })
    }
}

// ── Dual-mode (V/TV) — manual impl ──────────────────────────────────────────

/// 5GSM Cause (TS 24.501 &sect;9.11.4.2).
///
/// Dual-mode IE: V format when mandatory (`type_field == 0`), TV format when
/// optional (`type_field != 0`). Use the `cause()` method (defined in the
/// [`ie`](crate::nas_5gs::ie) module) for typed access via [`GsmCause`](crate::nas_5gs::ie::GsmCause).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasFGsmCause {
    /// Type field (IEI); 0 for the mandatory V form.
    pub type_field: u8,
    /// Cause value.
    pub value: u8,
}

impl NasFGsmCause {
    /// Build the IE from its cause value.
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0,
            value,
        }
    }

    /// Decode as a mandatory (V) IE: read value byte only, type_field set to 0.
    pub fn decode_value_only(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            type_field: 0,
            value,
        })
    }
}

impl Encode for NasFGsmCause {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.type_field != 0 {
            buffer.put_u8(self.type_field);
        }
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasFGsmCause {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let value = buffer.get_u8();
        Ok(Self { type_field, value })
    }
}
