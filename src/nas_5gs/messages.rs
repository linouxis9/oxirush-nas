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

//! NAS message structs, headers, and codec functions.
//!
//! This is **Layer 2** of the crate. Each NAS message is a struct defined by the
//! `nas_message!` macro with:
//!
//! - **Mandatory fields** — passed to `new()` and exposed via explicit getters
//!   plus `set_*_value()` / `with_*_value()` helpers.
//! - **Optional fields** — set via `set_*()` builder methods (e.g., `set_tai_list()`).
//! - **`Encode`/`Decode` implementations** — encode/decode with IEI-based dispatch.
//!
//! The top-level type is [`Nas5gsMessage`], which wraps either a 5GMM or 5GSM message
//! (or a security-protected envelope). Use [`decode_nas_5gs_message()`] and
//! [`encode_nas_5gs_message()`] as the main entry points.

use crate::nas_5gs::message_types::*;
use crate::nas_5gs::types::helpers;
use crate::nas_5gs::types::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

// TS 24.007 §11.2.4 assigns 0x70..=0x7f to 5GS TLV-E IEs.
const UNKNOWN_TLVE_START: u8 = 0x70;

/// PDU Session Identity value indicating "unassigned" (0x00).
pub const PDU_SESSION_IDENTITY_UNASSIGNED: u8 = 0;

pub use crate::common::UnknownIe;
use crate::common::{
    nas_message, nas_message_empty, nas_message_impl_default, nas_message_optional_alias,
};

// ── Framework types (kept exactly as original) ─────────────────────────────────

/// 5GMM message header (3 bytes on the wire).
///
/// Contains the Extended Protocol Discriminator (always 0x7E for 5GMM),
/// the spare half octet plus the Security Header Type (`§9.3`, Table `9.3.1`),
/// and the message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nas5gmmHeader {
    /// Extended protocol discriminator (0x7E, 5GMM).
    pub extended_protocol_discriminator: u8,
    /// Security header type; plain for a plain message.
    pub security_header_type: Nas5gsSecurityHeaderType,
    /// Message type.
    pub message_type: Nas5gmmMessageType,
}

impl Nas5gmmHeader {
    /// Build a plain 5GMM header.
    pub fn new(message_type: Nas5gmmMessageType) -> Self {
        Self {
            extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM,
            security_header_type: Nas5gsSecurityHeaderType::PlainNasMessage,
            message_type,
        }
    }
}

impl Encode for Nas5gmmHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(NasError::EncodingError(format!(
                "Plain 5GMM header shall use EPD=0x7E, got 0x{:02X}",
                self.extended_protocol_discriminator
            )));
        }
        if self.security_header_type != Nas5gsSecurityHeaderType::PlainNasMessage {
            return Err(NasError::EncodingError(format!(
                "Plain 5GMM header shall use SHT=PlainNasMessage, got {:?}",
                self.security_header_type
            )));
        }

        buffer.put_u8(self.extended_protocol_discriminator);
        buffer.put_u8(self.security_header_type as u8);
        buffer.put_u8(self.message_type.as_u8());
        Ok(())
    }
}

impl Decode for Nas5gmmHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 3 {
            return Err(NasError::MessageTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let security_header_type_octet = buffer.get_u8();
        let message_type_value = buffer.get_u8();

        let security_header_type =
            Nas5gsSecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;
        let message_type = Nas5gmmMessageType::try_from(message_type_value)?;

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(NasError::DecodingError(format!(
                "Plain 5GMM header shall use EPD=0x7E, got 0x{extended_protocol_discriminator:02X}"
            )));
        }
        if security_header_type != Nas5gsSecurityHeaderType::PlainNasMessage {
            return Err(NasError::DecodingError(format!(
                "Plain 5GMM header shall use SHT=PlainNasMessage, got {security_header_type:?}"
            )));
        }

        Ok(Self {
            extended_protocol_discriminator,
            security_header_type,
            message_type,
        })
    }
}

/// 5GSM message header (4 bytes on the wire).
///
/// Contains the Extended Protocol Discriminator (always 0x2E for 5GSM),
/// the PDU Session Identity, Procedure Transaction Identity, and message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nas5gsmHeader {
    /// Extended protocol discriminator (0x2E, 5GSM).
    pub extended_protocol_discriminator: u8,
    /// PDU session identity.
    pub pdu_session_identity: u8,
    /// Procedure transaction identity.
    pub procedure_transaction_identity: u8,
    /// Message type.
    pub message_type: Nas5gsmMessageType,
}

impl Nas5gsmHeader {
    /// Build a 5GSM header.
    pub fn new(
        message_type: Nas5gsmMessageType,
        pdu_session_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        Self {
            extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM,
            pdu_session_identity,
            procedure_transaction_identity,
            message_type,
        }
    }
}

impl Encode for Nas5gsmHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM {
            return Err(NasError::EncodingError(format!(
                "5GSM header shall use EPD=0x2E, got 0x{:02X}",
                self.extended_protocol_discriminator
            )));
        }
        // The reserved PTI 255 is encodable for negative tests; receivers
        // reject it on decode.
        buffer.put_u8(self.extended_protocol_discriminator);
        buffer.put_u8(self.pdu_session_identity);
        buffer.put_u8(self.procedure_transaction_identity);
        buffer.put_u8(self.message_type.as_u8());
        Ok(())
    }
}

impl Decode for Nas5gsmHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 4 {
            return Err(NasError::MessageTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let pdu_session_identity = buffer.get_u8();
        let procedure_transaction_identity = buffer.get_u8();
        let message_type_value = buffer.get_u8();

        let message_type = Nas5gsmMessageType::try_from(message_type_value)?;

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM {
            return Err(NasError::DecodingError(format!(
                "5GSM header shall use EPD=0x2E, got 0x{extended_protocol_discriminator:02X}"
            )));
        }
        if pdu_session_identity > 15 {
            return Err(NasError::DecodingError(
                "Reserved 5GSM PDU session identity".into(),
            ));
        }
        if procedure_transaction_identity == 255 {
            return Err(NasError::DecodingError(
                "Reserved 5GSM procedure transaction identity".into(),
            ));
        }

        Ok(Self {
            extended_protocol_discriminator,
            pdu_session_identity,
            procedure_transaction_identity,
            message_type,
        })
    }
}

/// Check whether raw NAS PDU bytes are security-protected (integrity and/or ciphered).
///
/// Returns `true` if the PDU has a 5GMM EPD (0x7E) and a non-plain security header type.
/// Returns `false` for plain 5GMM, 5GSM messages, or truncated PDUs.
pub fn is_security_protected(pdu: &[u8]) -> bool {
    if pdu.len() < SECURITY_HEADER_LEN + 2 || pdu.first().copied() != Some(0x7E) {
        return false;
    }

    matches!(
        Nas5gsSecurityHeaderType::try_from(pdu[1] & 0x0F),
        Ok(sht) if sht != Nas5gsSecurityHeaderType::PlainNasMessage
    )
}

/// NAS security header length in bytes (EPD + SHT + MAC + SN = 7).
pub const SECURITY_HEADER_LEN: usize = 7;

/// NAS security header (7 bytes on the wire).
///
/// Wraps a plain NAS message with integrity protection and optional ciphering.
/// Contains the MAC (4 bytes) and sequence number (1 byte) used for NAS COUNT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nas5gsSecurityHeader {
    /// Extended protocol discriminator (0x7E).
    pub extended_protocol_discriminator: u8,
    /// Security header type.
    pub security_header_type: Nas5gsSecurityHeaderType,
    /// Message authentication code.
    pub message_authentication_code: u32,
    /// Sequence number: the eight least significant bits of the NAS COUNT.
    pub sequence_number: u8,
}

impl Encode for Nas5gsSecurityHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(NasError::EncodingError(format!(
                "Security-protected outer header shall use EPD=0x7E, got 0x{:02X}",
                self.extended_protocol_discriminator
            )));
        }
        if self.security_header_type == Nas5gsSecurityHeaderType::PlainNasMessage {
            return Err(NasError::EncodingError(
                "Security-protected outer header cannot use SHT=PlainNasMessage".into(),
            ));
        }

        buffer.put_u8(self.extended_protocol_discriminator);
        buffer.put_u8(self.security_header_type as u8);
        buffer.put_u32(self.message_authentication_code);
        buffer.put_u8(self.sequence_number);
        Ok(())
    }
}

impl Decode for Nas5gsSecurityHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 7 {
            return Err(NasError::MessageTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let security_header_type_octet = buffer.get_u8();
        let message_authentication_code = buffer.get_u32();
        let sequence_number = buffer.get_u8();

        let security_header_type =
            Nas5gsSecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(NasError::DecodingError(format!(
                "Security-protected outer header shall use EPD=0x7E, got 0x{extended_protocol_discriminator:02X}"
            )));
        }
        if security_header_type == Nas5gsSecurityHeaderType::PlainNasMessage {
            return Err(NasError::DecodingError(
                "Security-protected outer header cannot use SHT=PlainNasMessage".into(),
            ));
        }

        Ok(Self {
            extended_protocol_discriminator,
            security_header_type,
            message_authentication_code,
            sequence_number,
        })
    }
}

// ── 5GMM Messages ──────────────────────────────────────────────────────────────

nas_message! {
    /// Registration Request (TS 24.501 §8.2.6).
    pub struct NasRegistrationRequest {
        mandatory {
            fgs_registration_type: NasFGsRegistrationType {wire_len 1, 1},
            fgs_mobile_identity: NasFGsMobileIdentity {wire_len 6, usize::MAX}
        }
        optional {
            0xC0 => non_current_native_nas_key_set_identifier: NasKeySetIdentifier [v_as_tv1] {wire_len 1, 1},
            0x10 => fgmm_capability: NasFGmmCapability {wire_len 3, 15},
            0x2E => ue_security_capability: NasUeSecurityCapability [opt_type] {wire_len 4, 10},
            0x2F => requested_nssai: NasNssai {wire_len 4, 74},
            0x52 => last_visited_registered_tai: NasFGsTrackingAreaIdentity {wire_len 7, 7},
            0x17 => s1_ue_network_capability: NasS1UeNetworkCapability {wire_len 4, 15},
            0x40 => uplink_data_status: NasUplinkDataStatus {wire_len 4, 34},
            0x50 => pdu_session_status: NasPduSessionStatus {wire_len 4, 34},
            0xB0 => mico_indication: NasMicoIndication [tv1] {wire_len 1, 1},
            0x2B => ue_status: NasUeStatus {wire_len 3, 3},
            0x77 => additional_guti: NasFGsMobileIdentity [opt_type] {wire_len 14, 14},
            0x25 => allowed_pdu_session_status: NasAllowedPduSessionStatus {wire_len 4, 34},
            0x18 => ue_usage_setting: NasUeUsageSetting {wire_len 3, 3},
            0x51 => requested_drx_parameters: NasFGsDrxParameters {wire_len 3, 3},
            0x70 => eps_nas_message_container: NasEpsNasMessageContainer {wire_len 4, usize::MAX},
            0x74 => ladn_indication: NasLadnIndication {wire_len 3, 811},
            0x80 => payload_container_type: NasPayloadContainerType [v_as_tv1] {wire_len 1, 1},
            0x7B => payload_container: NasPayloadContainer [opt_type] {wire_len 4, 65538},
            0x90 => network_slicing_indication: NasNetworkSlicingIndication [tv1] {wire_len 1, 1},
            0x53 => fgs_update_type: NasFGsUpdateType {wire_len 3, 3},
            0x41 => mobile_station_classmark_2: NasMobileStationClassmark2 {wire_len 5, 5},
            0x42 => supported_codecs: NasSupportedCodecList {wire_len 5, usize::MAX},
            0x71 => nas_message_container: NasMessageContainer {wire_len 4, usize::MAX},
            0x60 => eps_bearer_context_status: NasEpsBearerContextStatus {wire_len 4, 4},
            0x6E => requested_extended_drx_parameters: NasExtendedDrxParameters {wire_len 3, 4},
            0x6A => t3324_value: NasGprsTimer3 {wire_len 3, 3},
            0x67 => ue_radio_capability_id: NasUeRadioCapabilityId {wire_len 3, usize::MAX},
            0x35 => requested_mapped_nssai: NasMappedNssai {wire_len 3, 42},
            0x48 => additional_information_requested: NasAdditionalInformationRequested {wire_len 3, 3},
            0x1A => requested_wus_assistance_information: NasWusAssistanceInformation {wire_len 3, 3},
            0xA0 => n5gc_indication: NasN5gcIndication [tv1] {wire_len 1, 1},
            0x30 => requested_nb_n1_mode_drx_parameters: NasNbN1ModeDrxParameters {wire_len 3, 3},
            0x29 => ue_request_type: NasUeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: NasPagingRestriction {wire_len 3, 35},
            0x72 => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x32 => nid: NasNid {wire_len 8, 8},
            0x16 => ms_determined_plmn_with_disaster_condition: NasPlmnIdentity {wire_len 5, 5},
            0x2A => requested_peips_assistance_information: NasPeipsAssistanceInformation {wire_len 3, 3},
            0x3B => requested_t3512_value: NasGprsTimer3 {wire_len 3, 3},
            0x3C => unavailability_information: NasUnavailabilityInformation {wire_len 3, 9},
            0x3F => non_3gpp_path_switching_information: NasNon3GppPathSwitchingInformation {wire_len 3, 3},
            0x56 => aun3_indication: NasAun3Indication {wire_len 3, 3},
            0x64 => requested_lp_wusps_assistance_information: NasLpWuspsAssistanceInformation {wire_len 3, 3}
        }
    }
}

nas_message! {
    /// Registration Accept (TS 24.501 §8.2.7).
    pub struct NasRegistrationAccept {
        mandatory {
            fgs_registration_result: NasFGsRegistrationResult {wire_len 2, 2}
        }
        optional {
            0x77 => fg_guti: NasFGsMobileIdentity [opt_type] {wire_len 14, 14},
            0x4A => equivalent_plmns: NasPlmnList {wire_len 5, 47},
            0x54 => tai_list: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x15 => allowed_nssai: NasNssai {wire_len 4, 74},
            0x11 => rejected_nssai: NasRejectedNssai {wire_len 4, 42},
            0x31 => configured_nssai: NasNssai {wire_len 4, 146},
            0x21 => fgs_network_feature_support: NasFGsNetworkFeatureSupport {wire_len 3, 6},
            0x50 => pdu_session_status: NasPduSessionStatus {wire_len 4, 34},
            0x26 => pdu_session_reactivation_result: NasPduSessionReactivationResult {wire_len 4, 34},
            0x72 => pdu_session_reactivation_result_error_cause: NasPduSessionReactivationResultErrorCause {wire_len 5, 515},
            0x79 => ladn_information: NasLadnInformation {wire_len 13, 1715},
            0xB0 => mico_indication: NasMicoIndication [tv1] {wire_len 1, 1},
            0x90 => network_slicing_indication: NasNetworkSlicingIndication [tv1] {wire_len 1, 1},
            0x27 => service_area_list: NasServiceAreaList {wire_len 6, 114},
            0x5E => t3512_value: NasGprsTimer3 {wire_len 3, 3},
            0x5D => non_3gpp_de_registration_timer_value: NasGprsTimer2 {wire_len 3, 3},
            0x16 => t3502_value: NasGprsTimer2 {wire_len 3, 3},
            0x34 => emergency_number_list: NasEmergencyNumberList {wire_len 5, 50},
            0x7A => extended_emergency_number_list: NasExtendedEmergencyNumberList {wire_len 7, 65538},
            0x73 => sor_transparent_container: NasSorTransparentContainer {wire_len 20, usize::MAX},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0xA0 => nssai_inclusion_mode: NasNssaiInclusionMode [tv1] {wire_len 1, 1},
            0x76 => operator_defined_access_category_definitions: NasOperatorDefinedAccessCategoryDefinitions {wire_len 3, 8323},
            0x51 => negotiated_drx_parameters: NasFGsDrxParameters {wire_len 3, 3},
            0xD0 => non_3gpp_nw_policies: NasNon3GppNwProvidedPolicies [tv1] {wire_len 1, 1},
            0x60 => eps_bearer_context_status: NasEpsBearerContextStatus {wire_len 4, 4},
            0x6E => negotiated_extended_drx_parameters: NasExtendedDrxParameters {wire_len 3, 4},
            0x6C => t3447_value: NasGprsTimer3 {wire_len 3, 3},
            0x6B => t3448_value: NasGprsTimer2 {wire_len 3, 3},
            0x6A => t3324_value: NasGprsTimer3 {wire_len 3, 3},
            0x67 => ue_radio_capability_id: NasUeRadioCapabilityId {wire_len 3, usize::MAX},
            0xE0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x39 => pending_nssai: NasNssai {wire_len 4, 146},
            0x74 => ciphering_key_data: NasCipheringKeyData {wire_len 34, usize::MAX},
            0x75 => cag_information_list: NasCagInformationList {wire_len 3, usize::MAX},
            0x1B => truncated_fg_s_tmsi_configuration: NasTruncatedFGSTmsiConfiguration {wire_len 3, 3},
            0x1C => negotiated_wus_assistance_information: NasWusAssistanceInformation {wire_len 3, 3},
            0x29 => negotiated_nb_n1_mode_drx_parameters: NasNbN1ModeDrxParameters {wire_len 3, 3},
            0x68 => extended_rejected_nssai: NasExtendedRejectedNssai {wire_len 5, 90},
            0x7B => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x33 => negotiated_peips_assistance_information: NasPeipsAssistanceInformation {wire_len 3, 3},
            0x35 => fgs_additional_request_result: NasFGsAdditionalRequestResult {wire_len 3, 3},
            0x70 => nssrg_information: NasNssrgInformation {wire_len 7, 4099},
            0x14 => disaster_roaming_wait_range: NasRegistrationWaitRange {wire_len 4, 4},
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange {wire_len 4, 4},
            0x13 => list_of_plmns_to_be_used_in_disaster_condition: NasListOfPlmnsToBeUsedInDisasterCondition {wire_len 2, usize::MAX},
            0x1D => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x1E => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x71 => extended_cag_information_list: NasExtendedCagInformationList {wire_len 3, usize::MAX},
            0x7C => nsag_information: NasNsagInformation {wire_len 9, 3143},
            0x3D => equivalent_snpns: NasSnpnList {wire_len 11, 137},
            0x32 => nid: NasNid {wire_len 8, 8},
            0x7D => type_6_ie_container: NasType6IeContainer {wire_len 6, 65538},
            0x4B => ran_timing_synchronization: NasRanTimingSynchronization {wire_len 3, 3},
            0x4C => alternative_nssai: NasAlternativeNssai {wire_len 2, 146},
            0x4F => discontinuous_coverage_max_time_offset: NasGprsTimer3 {wire_len 3, 3},
            0x5B => s_nssai_time_validity_information: NasSNssaiTimeValidityInformation {wire_len 23, 257},
            0x3C => unavailability_configuration: NasUnavailabilityConfiguration {wire_len 3, 6},
            0x5C => feature_authorization_indication: NasFeatureAuthorizationIndication {wire_len 3, 257},
            0x61 => on_demand_nssai: NasOnDemandNssai {wire_len 5, 210},
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 4, 5},
            0x64 => negotiated_lp_wusps_assistance_information: NasLpWuspsAssistanceInformation {wire_len 3, 3},
            0x80 => lp_wus_status: NasLpWusStatus [tv1] {wire_len 1, 1}
        }
    }
}

nas_message_optional_alias!(
    NasRegistrationRequest,
    ue_determined_plmn_with_disaster_condition,
    ms_determined_plmn_with_disaster_condition,
    NasPlmnIdentity
);

nas_message! {
    /// Registration Complete (TS 24.501 §8.2.8).
    pub struct NasRegistrationComplete {
        mandatory { }
        optional {
            0x73 => sor_transparent_container: NasSorTransparentContainer {wire_len 20, 20}
        }
    }
}

nas_message! {
    /// Registration Reject (TS 24.501 §8.2.9).
    pub struct NasRegistrationReject {
        mandatory {
            fgmm_cause: NasFGmmCause {wire_len 1, 1}
        }
        optional {
            0x5F => t3346_value: NasGprsTimer2 {wire_len 3, 3},
            0x16 => t3502_value: NasGprsTimer2 {wire_len 3, 3},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0x69 => rejected_nssai: NasRejectedNssai {wire_len 4, 42},
            0x75 => cag_information_list: NasCagInformationList {wire_len 3, usize::MAX},
            0x68 => extended_rejected_nssai: NasExtendedRejectedNssai {wire_len 5, 90},
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange {wire_len 4, 4},
            0x71 => extended_cag_information_list: NasExtendedCagInformationList {wire_len 3, usize::MAX},
            0x3A => lower_bound_timer_value: NasGprsTimer3 {wire_len 3, 3},
            0x1D | 0x3B => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x1E | 0x3C => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x3E => n3iwf_identifier: NasN3iwfIdentifier {wire_len 7, usize::MAX},
            0x4D => tnan_information: NasTnanInformation {wire_len 3, usize::MAX},
            0x62 => extended_5gmm_cause: NasExtendedFGmmCause {wire_len 3, 3},
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 4, 5}
        }
    }
}

nas_message! {
    /// Deregistration Request from UE (TS 24.501 §8.2.12).
    pub struct NasDeregistrationRequestFromUe {
        mandatory {
            de_registration_type: NasDeRegistrationType {wire_len 1, 1},
            fgs_mobile_identity: NasFGsMobileIdentity {wire_len 6, usize::MAX}
        }
        optional {
            0x3C => unavailability_information: NasUnavailabilityInformation {wire_len 3, 9},
            0x71 => nas_message_container: NasMessageContainer {wire_len 4, usize::MAX}
        }
    }
}

impl NasDeregistrationRequestFromUe {
    /// NAS key set identifier packed into the upper nibble of the first mandatory octet.
    pub fn nas_key_set_identifier(&self) -> NasKeySetIdentifier {
        NasKeySetIdentifier::new((self.de_registration_type.value >> 4) & 0x0F)
    }

    /// Set the packed NAS key set identifier while preserving the de-registration type bits.
    pub fn with_nas_key_set_identifier(mut self, ksi: NasKeySetIdentifier) -> Self {
        self.set_nas_key_set_identifier(ksi);
        self
    }

    /// Mutating setter for the packed NAS key set identifier.
    pub fn set_nas_key_set_identifier(&mut self, ksi: NasKeySetIdentifier) {
        self.de_registration_type.value =
            (self.de_registration_type.value & 0x0F) | ((ksi.value & 0x0F) << 4);
    }

    /// ngKSI bits from the packed NAS key set identifier.
    pub fn ngksi(&self) -> u8 {
        self.nas_key_set_identifier().ngksi()
    }

    /// Set ngKSI while preserving TSC and the de-registration type bits.
    pub fn with_ngksi(mut self, ngksi: u8) -> Self {
        self.set_ngksi(ngksi);
        self
    }

    /// Mutating setter for ngKSI in the packed NAS key set identifier.
    pub fn set_ngksi(&mut self, ngksi: u8) {
        let mut ksi = self.nas_key_set_identifier();
        ksi.set_ngksi(ngksi);
        self.set_nas_key_set_identifier(ksi);
    }

    /// TSC bit from the packed NAS key set identifier.
    pub fn tsc(&self) -> bool {
        self.nas_key_set_identifier().tsc()
    }

    /// Set TSC while preserving ngKSI and the de-registration type bits.
    pub fn with_tsc(mut self, tsc: bool) -> Self {
        self.set_tsc(tsc);
        self
    }

    /// Mutating setter for TSC in the packed NAS key set identifier.
    pub fn set_tsc(&mut self, tsc: bool) {
        let mut ksi = self.nas_key_set_identifier();
        ksi.set_tsc(tsc);
        self.set_nas_key_set_identifier(ksi);
    }
}

nas_message! {
    /// Deregistration Request to UE (TS 24.501 §8.2.14).
    pub struct NasDeregistrationRequestToUe {
        mandatory {
            de_registration_type: NasDeRegistrationType {wire_len 1, 1}
        }
        optional {
            0x58 => fgmm_cause: NasFGmmCause [opt_type] {wire_len 2, 2},
            0x5F => t3346_value: NasGprsTimer2 {wire_len 3, 3},
            0x6D => rejected_nssai: NasRejectedNssai {wire_len 4, 42},
            0x75 => cag_information_list: NasCagInformationList {wire_len 3, usize::MAX},
            0x68 => extended_rejected_nssai: NasExtendedRejectedNssai {wire_len 5, 90},
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange {wire_len 4, 4},
            0x71 => extended_cag_information_list: NasExtendedCagInformationList {wire_len 3, usize::MAX},
            0x3A => lower_bound_timer_value: NasGprsTimer3 {wire_len 3, 3},
            0x1D | 0x3B => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x1E | 0x3C => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 4, 5}
        }
    }
}

nas_message_empty!(
    /// Deregistration Accept from UE (TS 24.501 §8.2.13).
    NasDeregistrationAcceptFromUe
);
nas_message_empty!(
    /// Deregistration Accept to UE (TS 24.501 §8.2.15).
    NasDeregistrationAcceptToUe
);
nas_message_empty!(
    /// Configuration Update Complete (TS 24.501 §8.2.20).
    NasConfigurationUpdateComplete
);

nas_message! {
    /// Service Request (TS 24.501 §8.2.16).
    pub struct NasServiceRequest {
        mandatory {
            ngksi: NasKeySetIdentifier {wire_len 1, 1},
            fg_s_tmsi: NasFGsMobileIdentity {wire_len 9, 9}
        }
        optional {
            0x40 => uplink_data_status: NasUplinkDataStatus {wire_len 4, 34},
            0x50 => pdu_session_status: NasPduSessionStatus {wire_len 4, 34},
            0x25 => allowed_pdu_session_status: NasAllowedPduSessionStatus {wire_len 4, 34},
            0x71 => nas_message_container: NasMessageContainer {wire_len 4, usize::MAX},
            0x29 => ue_request_type: NasUeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: NasPagingRestriction {wire_len 3, 35}
        }
    }
}

impl NasServiceRequest {
    /// Service type from the upper nibble of the packed mandatory octet
    /// (§9.11.3.50).
    ///
    /// In ServiceRequest, the first mandatory byte packs ngKSI (lower nibble)
    /// and all four service-type bits (upper nibble).
    pub fn service_type(&self) -> Option<crate::nas_5gs::ie::ServiceType> {
        crate::nas_5gs::ie::ServiceType::from_u8((self.ngksi.value >> 4) & 0x0F)
    }

    /// Raw service type value (upper nibble of the ngKSI byte).
    pub fn service_type_raw(&self) -> u8 {
        (self.ngksi.value >> 4) & 0x0F
    }

    /// Set the service type while preserving ngKSI/TSC bits.
    pub fn with_service_type(mut self, service_type: crate::nas_5gs::ie::ServiceType) -> Self {
        self.set_service_type(service_type);
        self
    }

    /// Mutating setter for the service type.
    pub fn set_service_type(&mut self, service_type: crate::nas_5gs::ie::ServiceType) {
        self.ngksi.value = (self.ngksi.value & 0x0F) | ((service_type as u8 & 0x0F) << 4);
    }
}

nas_message! {
    /// Service Reject (TS 24.501 §8.2.18).
    pub struct NasServiceReject {
        mandatory {
            fgmm_cause: NasFGmmCause {wire_len 1, 1}
        }
        optional {
            0x50 => pdu_session_status: NasPduSessionStatus {wire_len 4, 34},
            0x5F => t3346_value: NasGprsTimer2 {wire_len 3, 3},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0x6B => t3448_value: NasGprsTimer2 {wire_len 3, 3},
            0x75 => cag_information_list: NasCagInformationList {wire_len 3, usize::MAX},
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange {wire_len 4, 4},
            0x71 => extended_cag_information_list: NasExtendedCagInformationList {wire_len 3, usize::MAX},
            0x3A => lower_bound_timer_value: NasGprsTimer3 {wire_len 3, 3},
            0x1D | 0x3B => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x1E | 0x3C => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 4, 5}
        }
    }
}

nas_message! {
    /// Service Accept (TS 24.501 §8.2.17).
    pub struct NasServiceAccept {
        mandatory { }
        optional {
            0x50 => pdu_session_status: NasPduSessionStatus {wire_len 4, 34},
            0x26 => pdu_session_reactivation_result: NasPduSessionReactivationResult {wire_len 4, 34},
            0x72 => pdu_session_reactivation_result_error_cause: NasPduSessionReactivationResultErrorCause {wire_len 5, 515},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0x6B => t3448_value: NasGprsTimer2 {wire_len 3, 3},
            0x34 => fgs_additional_request_result: NasFGsAdditionalRequestResult {wire_len 3, 3},
            0x1D => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x1E => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList {wire_len 9, 114}
        }
    }
}

nas_message! {
    /// Configuration Update Command (TS 24.501 §8.2.19).
    pub struct NasConfigurationUpdateCommand {
        mandatory { }
        optional {
            0xD0 => configuration_update_indication: NasConfigurationUpdateIndication [tv1] {wire_len 1, 1},
            0x77 => fg_guti: NasFGsMobileIdentity [opt_type] {wire_len 14, 14},
            0x54 => tai_list: NasFGsTrackingAreaIdentityList {wire_len 9, 114},
            0x15 => allowed_nssai: NasNssai {wire_len 4, 74},
            0x27 => service_area_list: NasServiceAreaList {wire_len 6, 114},
            0x43 => full_name_for_network: NasNetworkName {wire_len 3, usize::MAX},
            0x45 => short_name_for_network: NasNetworkName {wire_len 3, usize::MAX},
            0x46 => local_time_zone: NasTimeZone {wire_len 2, 2},
            0x47 => universal_time_and_local_time_zone: NasTimeZoneAndTime {wire_len 8, 8},
            0x49 => network_daylight_saving_time: NasDaylightSavingTime {wire_len 3, 3},
            0x79 => ladn_information: NasLadnInformation {wire_len 3, 1715},
            0xB0 => mico_indication: NasMicoIndication [tv1] {wire_len 1, 1},
            0x90 => network_slicing_indication: NasNetworkSlicingIndication [tv1] {wire_len 1, 1},
            0x31 => configured_nssai: NasNssai {wire_len 4, 146},
            0x11 => rejected_nssai: NasRejectedNssai {wire_len 4, 42},
            0x76 => operator_defined_access_category_definitions: NasOperatorDefinedAccessCategoryDefinitions {wire_len 3, 8323},
            0xF0 => sms_indication: NasSmsIndication [tv1] {wire_len 1, 1},
            0x6C => t3447_value: NasGprsTimer3 {wire_len 3, 3},
            0x75 => cag_information_list: NasCagInformationList {wire_len 3, usize::MAX},
            0x67 => ue_radio_capability_id: NasUeRadioCapabilityId {wire_len 3, usize::MAX},
            0xA0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x44 => fgs_registration_result: NasFGsRegistrationResult [opt_type] {wire_len 3, 3},
            0x1B => truncated_fg_s_tmsi_configuration: NasTruncatedFGSTmsiConfiguration {wire_len 3, 3},
            0xC0 => additional_configuration_indication: NasAdditionalConfigurationIndication [tv1] {wire_len 1, 1},
            0x68 => extended_rejected_nssai: NasExtendedRejectedNssai {wire_len 5, 90},
            0x72 => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x70 => nssrg_information: NasNssrgInformation {wire_len 7, 4099},
            0x14 => disaster_roaming_wait_range: NasRegistrationWaitRange {wire_len 4, 4},
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange {wire_len 4, 4},
            0x13 => list_of_plmns_to_be_used_in_disaster_condition: NasListOfPlmnsToBeUsedInDisasterCondition {wire_len 2, usize::MAX},
            0x71 => extended_cag_information_list: NasExtendedCagInformationList {wire_len 3, usize::MAX},
            0x1F => updated_peips_assistance_information: NasPeipsAssistanceInformation {wire_len 3, 3},
            0x73 => nsag_information: NasNsagInformation {wire_len 9, 3143},
            0xE0 => priority_indicator: NasPriorityIndicator [tv1] {wire_len 1, 1},
            0x4B => ran_timing_synchronization: NasRanTimingSynchronization {wire_len 3, 3},
            0x78 => extended_ladn_information: NasExtendedLadnInformation {wire_len 3, 1787},
            0x4C => alternative_nssai: NasAlternativeNssai {wire_len 2, 146},
            0x7B => s_nssai_location_validity_information: NasSNssaiLocationValidityInformation {wire_len 17, 38611},
            0x5B => s_nssai_time_validity_information: NasSNssaiTimeValidityInformation {wire_len 23, 257},
            0x4F => discontinuous_coverage_max_time_offset: NasGprsTimer3 {wire_len 3, 3},
            0x74 => partially_allowed_nssai: NasPartialNssai {wire_len 3, 808},
            0x7A => partially_rejected_nssai: NasPartialNssai {wire_len 3, 808},
            0x5C => feature_authorization_indication: NasFeatureAuthorizationIndication {wire_len 3, 257},
            0x61 => on_demand_nssai: NasOnDemandNssai {wire_len 5, 210},
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 2, 5},
            0x64 => updated_lp_wusps_assistance_information: NasLpWuspsAssistanceInformation {wire_len 2, 3},
            0x80 => lp_wus_status: NasLpWusStatus [tv1] {wire_len 1, 1}
        }
    }
}

nas_message! {
    /// Authentication Request (TS 24.501 §8.2.1).
    pub struct NasAuthenticationRequest {
        mandatory {
            ngksi: NasKeySetIdentifier {wire_len 1, 1},
            abba: NasAbba {wire_len 3, usize::MAX}
        }
        optional {
            0x21 => authentication_parameter_rand: NasAuthenticationParameterRand {wire_len 17, 17},
            0x20 => authentication_parameter_autn: NasAuthenticationParameterAutn {wire_len 18, 18},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Authentication Response (TS 24.501 §8.2.2).
    pub struct NasAuthenticationResponse {
        mandatory { }
        optional {
            0x2D => authentication_response_parameter: NasAuthenticationResponseParameter {wire_len 18, 18},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Authentication Reject (TS 24.501 §8.2.5).
    pub struct NasAuthenticationReject {
        mandatory { }
        optional {
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Authentication Failure (TS 24.501 §8.2.4).
    pub struct NasAuthenticationFailure {
        mandatory {
            fgmm_cause: NasFGmmCause {wire_len 1, 1}
        }
        optional {
            0x30 => authentication_failure_parameter: NasAuthenticationFailureParameter {wire_len 16, 16}
        }
    }
}

nas_message! {
    /// Authentication Result (TS 24.501 §8.2.3).
    pub struct NasAuthenticationResult {
        mandatory {
            ngksi: NasKeySetIdentifier {wire_len 1, 1},
            eap_message: NasEapMessage {wire_len 6, 1502}
        }
        optional {
            0x38 => abba: NasAbba [opt_type] {wire_len 4, usize::MAX},
            0x55 => aun3_device_security_key: NasAun3DeviceSecurityKey {wire_len 36, usize::MAX}
        }
    }
}

nas_message! {
    /// Identity Request (TS 24.501 §8.2.21).
    pub struct NasIdentityRequest {
        mandatory {
            identity_type: NasFGsIdentityType {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// Identity Response (TS 24.501 §8.2.22).
    pub struct NasIdentityResponse {
        mandatory {
            mobile_identity: NasFGsMobileIdentity {wire_len 3, usize::MAX}
        }
        optional { }
    }
}

nas_message! {
    /// Security Mode Command (TS 24.501 §8.2.25).
    pub struct NasSecurityModeCommand {
        mandatory {
            selected_nas_security_algorithms: NasSecurityAlgorithms {wire_len 1, 1},
            ngksi: NasKeySetIdentifier {wire_len 1, 1},
            replayed_ue_security_capabilities: NasUeSecurityCapability {wire_len 3, 9}
        }
        optional {
            0xE0 => imeisv_request: NasImeisvRequest [tv1] {wire_len 1, 1},
            0x57 => selected_eps_nas_security_algorithms: NasEpsNasSecurityAlgorithms {wire_len 2, 2},
            0x36 => additional_5g_security_information: NasAdditional5gSecurityInformation {wire_len 3, 3},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0x38 => abba: NasAbba [opt_type] {wire_len 4, usize::MAX},
            0x19 => replayed_s1_ue_security_capabilities: NasS1UeSecurityCapability {wire_len 4, 7},
            0x55 => aun3_device_security_key: NasAun3DeviceSecurityKey {wire_len 36, 257}
        }
    }
}

nas_message! {
    /// Security Mode Complete (TS 24.501 §8.2.26).
    pub struct NasSecurityModeComplete {
        mandatory { }
        optional {
            0x77 => imeisv: NasFGsMobileIdentity [opt_type] {wire_len 12, 12},
            0x71 => nas_message_container: NasMessageContainer {wire_len 4, usize::MAX},
            0x78 => non_imeisv_pei: NasFGsMobileIdentity [opt_type] {wire_len 7, usize::MAX}
        }
    }
}

nas_message! {
    /// Security Mode Reject (TS 24.501 §8.2.27).
    pub struct NasSecurityModeReject {
        mandatory {
            fgmm_cause: NasFGmmCause {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// 5GMM Status (TS 24.501 §8.2.29).
    pub struct NasFGmmStatus {
        mandatory {
            fgmm_cause: NasFGmmCause {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// Notification (TS 24.501 §8.2.23).
    pub struct NasNotification {
        mandatory {
            access_type: NasAccessType {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// Notification Response (TS 24.501 §8.2.24).
    pub struct NasNotificationResponse {
        mandatory { }
        optional {
            0x50 => pdu_session_status: NasPduSessionStatus {wire_len 4, 34}
        }
    }
}

nas_message! {
    /// UL NAS Transport (TS 24.501 §8.2.10).
    pub struct NasUlNasTransport {
        mandatory {
            payload_container_type: NasPayloadContainerType {wire_len 1, 1},
            payload_container: NasPayloadContainer {wire_len 3, 65537}
        }
        optional {
            0x12 => pdu_session_id: NasPduSessionIdentity2 {wire_len 2, 2},
            0x59 => old_pdu_session_id: NasPduSessionIdentity2 {wire_len 2, 2},
            0x80 => request_type: NasRequestType [tv1] {wire_len 1, 1},
            0x22 => s_nssai: NasSNssai {wire_len 3, 10},
            0x25 => dnn: NasDnn {wire_len 3, 102},
            0x24 => additional_information: NasAdditionalInformation {wire_len 3, usize::MAX},
            0xA0 => ma_pdu_session_information: NasMaPduSessionInformation [tv1] {wire_len 1, 1},
            0xF0 => release_assistance_indication: NasReleaseAssistanceIndication [tv1] {wire_len 1, 1},
            0x4E => non_3gpp_access_path_switching_indication: NasNon3GppAccessPathSwitchingIndication {wire_len 3, 3},
            0x5A => alternative_s_nssai: NasSNssai {wire_len 3, 10},
            0x90 => payload_container_information: NasPayloadContainerInformation [tv1] {wire_len 1, 1}
        }
    }
}

nas_message! {
    /// DL NAS Transport (TS 24.501 §8.2.11).
    pub struct NasDlNasTransport {
        mandatory {
            payload_container_type: NasPayloadContainerType {wire_len 1, 1},
            payload_container: NasPayloadContainer {wire_len 3, 65537}
        }
        optional {
            0x12 => pdu_session_id: NasPduSessionIdentity2 {wire_len 2, 2},
            0x24 => additional_information: NasAdditionalInformation {wire_len 3, usize::MAX},
            0x58 => fgmm_cause: NasFGmmCause [opt_type] {wire_len 2, 2},
            0x37 => back_off_timer_value: NasGprsTimer3 {wire_len 3, 3},
            0x3A => lower_bound_timer_value: NasGprsTimer3 {wire_len 3, 3}
        }
    }
}

nas_message! {
    /// Control Plane Service Request (TS 24.501 §8.2.30).
    pub struct NasControlPlaneServiceRequest {
        mandatory {
            control_plane_service_type: NasControlPlaneServiceType {wire_len 1, 1}
        }
        optional {
            0x6F => ciot_small_data_container: NasCiotSmallDataContainer {wire_len 4, 257},
            0x80 => payload_container_type: NasPayloadContainerType [v_as_tv1] {wire_len 1, 1},
            0x7B => payload_container: NasPayloadContainer [opt_type] {wire_len 4, 65538},
            0x12 => pdu_session_id: NasPduSessionIdentity2 {wire_len 2, 2},
            0x50 => pdu_session_status: NasPduSessionStatus {wire_len 4, 34},
            0xF0 => release_assistance_indication: NasReleaseAssistanceIndication [tv1] {wire_len 1, 1},
            0x40 => uplink_data_status: NasUplinkDataStatus {wire_len 4, 34},
            0x71 => nas_message_container: NasMessageContainer {wire_len 4, usize::MAX},
            0x24 => additional_information: NasAdditionalInformation {wire_len 3, usize::MAX},
            0x25 => allowed_pdu_session_status: NasAllowedPduSessionStatus {wire_len 4, 34},
            0x29 => ue_request_type: NasUeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: NasPagingRestriction {wire_len 3, 35}
        }
    }
}

impl NasControlPlaneServiceRequest {
    /// Packed NAS key set identifier from the upper nibble of the mandatory octet.
    pub fn nas_key_set_identifier(&self) -> NasKeySetIdentifier {
        NasKeySetIdentifier::new((self.control_plane_service_type.value >> 4) & 0x0F)
    }

    /// Set the packed NAS key set identifier while preserving the service-type bits.
    pub fn with_nas_key_set_identifier(mut self, ksi: NasKeySetIdentifier) -> Self {
        self.set_nas_key_set_identifier(ksi);
        self
    }

    /// Mutating setter for the packed NAS key set identifier.
    pub fn set_nas_key_set_identifier(&mut self, ksi: NasKeySetIdentifier) {
        self.control_plane_service_type.value =
            (self.control_plane_service_type.value & 0x0F) | ((ksi.value & 0x0F) << 4);
    }

    /// ngKSI bits from the packed NAS key set identifier.
    pub fn ngksi(&self) -> u8 {
        self.nas_key_set_identifier().ngksi()
    }

    /// Set ngKSI while preserving TSC and the service-type bits.
    pub fn with_ngksi(mut self, ngksi: u8) -> Self {
        self.set_ngksi(ngksi);
        self
    }

    /// Mutating setter for ngKSI in the packed NAS key set identifier.
    pub fn set_ngksi(&mut self, ngksi: u8) {
        let mut ksi = self.nas_key_set_identifier();
        ksi.set_ngksi(ngksi);
        self.set_nas_key_set_identifier(ksi);
    }

    /// TSC bit from the packed NAS key set identifier.
    pub fn tsc(&self) -> bool {
        self.nas_key_set_identifier().tsc()
    }

    /// Set TSC while preserving ngKSI and the service-type bits.
    pub fn with_tsc(mut self, tsc: bool) -> Self {
        self.set_tsc(tsc);
        self
    }

    /// Mutating setter for TSC in the packed NAS key set identifier.
    pub fn set_tsc(&mut self, tsc: bool) {
        let mut ksi = self.nas_key_set_identifier();
        ksi.set_tsc(tsc);
        self.set_nas_key_set_identifier(ksi);
    }

    /// Whether the message uses the CIoT small data container without any other optional IE.
    pub fn ciot_small_data_container_is_exclusive(&self) -> bool {
        self.ciot_small_data_container.is_none()
            || (self.payload_container_type.is_none()
                && self.payload_container.is_none()
                && self.pdu_session_id.is_none()
                && self.pdu_session_status.is_none()
                && self.release_assistance_indication.is_none()
                && self.uplink_data_status.is_none()
                && self.nas_message_container.is_none()
                && self.additional_information.is_none()
                && self.allowed_pdu_session_status.is_none()
                && self.ue_request_type.is_none()
                && self.paging_restriction.is_none())
    }
}

nas_message! {
    /// Network Slice-Specific Authentication Command (TS 24.501 §8.2.31).
    pub struct NasNetworkSliceSpecificAuthenticationCommand {
        mandatory {
            s_nssai: NasSNssai [tlv_as_lv] {wire_len 2, 5},
            eap_message: NasEapMessage {wire_len 6, 1502}
        }
        optional { }
    }
}

nas_message! {
    /// Network Slice-Specific Authentication Complete (TS 24.501 §8.2.32).
    pub struct NasNetworkSliceSpecificAuthenticationComplete {
        mandatory {
            s_nssai: NasSNssai [tlv_as_lv] {wire_len 2, 5},
            eap_message: NasEapMessage {wire_len 6, 1502}
        }
        optional { }
    }
}

nas_message! {
    /// Network Slice-Specific Authentication Result (TS 24.501 §8.2.33).
    pub struct NasNetworkSliceSpecificAuthenticationResult {
        mandatory {
            s_nssai: NasSNssai [tlv_as_lv] {wire_len 2, 5},
            eap_message: NasEapMessage {wire_len 6, 1502}
        }
        optional { }
    }
}

nas_message! {
    /// Relay Key Request (TS 24.501 §8.2.34).
    pub struct NasRelayKeyRequest {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only] {wire_len 1, 1},
            relay_key_request_parameters: NasRelayKeyRequestParameters {wire_len 22, 65537}
        }
        optional { }
    }
}

nas_message! {
    /// Relay Key Accept (TS 24.501 §8.2.35).
    pub struct NasRelayKeyAccept {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only] {wire_len 1, 1},
            relay_key_response_parameters: NasRelayKeyResponseParameters {wire_len 51, 65537}
        }
        optional {
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Relay Key Reject (TS 24.501 §8.2.36).
    pub struct NasRelayKeyReject {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only] {wire_len 1, 1}
        }
        optional {
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Relay Authentication Request (TS 24.501 §8.2.37).
    pub struct NasRelayAuthenticationRequest {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only] {wire_len 1, 1},
            eap_message: NasEapMessage {wire_len 7, 1503}
        }
        optional { }
    }
}

nas_message! {
    /// Relay Authentication Response (TS 24.501 §8.2.38).
    pub struct NasRelayAuthenticationResponse {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only] {wire_len 1, 1},
            eap_message: NasEapMessage {wire_len 6, 1502}
        }
        optional { }
    }
}

// ── 5GSM Messages ──────────────────────────────────────────────────────────────

nas_message! {
    /// PDU Session Establishment Request (TS 24.501 §8.3.1).
    pub struct NasPduSessionEstablishmentRequest {
        mandatory {
            integrity_protection_maximum_data_rate: NasIntegrityProtectionMaximumDataRate {wire_len 2, 2}
        }
        optional {
            0x90 => pdu_session_type: NasPduSessionType [tv1] {wire_len 1, 1},
            0xA0 => ssc_mode: NasSscMode [tv1] {wire_len 1, 1},
            0x28 => fgsm_capability: NasFGsmCapability {wire_len 3, 15},
            0x55 => maximum_number_of_supported_packet_filters: NasMaximumNumberOfSupportedPacketFilters {wire_len 3, 3},
            0xB0 => always_on_pdu_session_requested: NasAlwaysOnPduSessionRequested [tv1] {wire_len 1, 1},
            0x39 => sm_pdu_dn_request_container: NasSmPduDnRequestContainer {wire_len 3, 255},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x66 => ip_header_compression_configuration: NasIpHeaderCompressionConfiguration {wire_len 5, 257},
            0x6E => ds_tt_ethernet_port_mac_address: NasDsTtEthernetPortMacAddress {wire_len 8, 8},
            0x6F => ue_ds_tt_residence_time: NasUeDsTtResidenceTime {wire_len 10, 10},
            0x74 => port_management_information_container: NasPortManagementInformationContainer {wire_len 8, 65538},
            0x1F => ethernet_header_compression_configuration: NasEthernetHeaderCompressionConfiguration {wire_len 3, 3},
            0x29 => suggested_interface_identifier: NasPduAddress {wire_len 11, 11},
            0x72 => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x70 => requested_mbs_container: NasRequestedMbsContainer {wire_len 8, 65538},
            0x34 => pdu_session_pair_id: NasPduSessionPairId {wire_len 3, 3},
            0x35 => rsn: NasRsn {wire_len 3, 3},
            0x36 => ursp_rule_enforcement_reports: NasUrspRuleEnforcementReports {wire_len 4, usize::MAX}
        }
    }
}

nas_message! {
    /// PDU Session Establishment Accept (TS 24.501 §8.3.2).
    pub struct NasPduSessionEstablishmentAccept {
        mandatory {
            selected_pdu_session_type: NasPduSessionType {wire_len 1, 1},
            authorized_qos_rules: NasQosRules {wire_len 6, 65538},
            session_ambr: NasSessionAmbr {wire_len 7, 7}
        }
        optional {
            0x59 => fgsm_cause: NasFGsmCause {wire_len 2, 2},
            0x29 => pdu_address: NasPduAddress {wire_len 7, 31},
            0x56 => rq_timer_value: NasGprsTimer {wire_len 2, 2},
            0x22 => s_nssai: NasSNssai {wire_len 3, 10},
            0x80 => always_on_pdu_session_indication: NasAlwaysOnPduSessionIndication [tv1] {wire_len 1, 1},
            0x75 => mapped_eps_bearer_contexts: NasMappedEpsBearerContexts {wire_len 7, 65538},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0x79 => authorized_qos_flow_descriptions: NasQosFlowDescriptions {wire_len 6, 65538},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x25 => dnn: NasDnn {wire_len 3, 102},
            0x17 => fgsm_network_feature_support: NasFGsmNetworkFeatureSupport {wire_len 3, 15},
            0x18 => serving_plmn_rate_control: NasServingPlmnRateControl {wire_len 4, 4},
            0x77 => atsss_container: NasAtsssContainer {wire_len 3, 65538},
            0xC0 => control_plane_only_indication: NasControlPlaneOnlyIndication [tv1] {wire_len 1, 1},
            0x66 => ip_header_compression_configuration: NasIpHeaderCompressionConfiguration {wire_len 5, 257},
            0x1F => ethernet_header_compression_configuration: NasEthernetHeaderCompressionConfiguration {wire_len 3, 3},
            0x72 => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x71 => received_mbs_container: NasReceivedMbsContainer {wire_len 9, 65538},
            0x70 => n3_qai: NasN3Qai {wire_len 9, usize::MAX},
            0x73 => protocol_description: NasProtocolDescription {wire_len 6, usize::MAX},
            0x38 => ecn_marking_l4s_indication: NasEcnMarkingL4sIndication {wire_len 2, 257}
        }
    }
}

impl NasPduSessionEstablishmentAccept {
    /// Selected SSC mode from the upper nibble of the PDU session type byte (§9.11.4.16).
    ///
    /// In PDU Session Establishment Accept, the first mandatory byte packs
    /// selected PDU session type (lower nibble) and selected SSC mode (upper nibble).
    pub fn selected_ssc_mode(&self) -> u8 {
        self.selected_pdu_session_type.type_field & 0x07
    }

    /// Typed selected SSC mode from the upper nibble of the first mandatory byte.
    pub fn selected_ssc_mode_value(&self) -> Option<crate::nas_5gs::ie::SscModeValue> {
        crate::nas_5gs::ie::SscModeValue::from_u8(self.selected_ssc_mode())
    }

    /// Selected PDU session type (lower nibble).
    pub fn pdu_session_type(&self) -> u8 {
        self.selected_pdu_session_type.value & 0x07
    }

    /// Typed selected PDU session type from the lower nibble of the first mandatory byte.
    pub fn selected_pdu_session_type_value(
        &self,
    ) -> Option<crate::nas_5gs::ie::PduSessionTypeValue> {
        crate::nas_5gs::ie::PduSessionTypeValue::from_u8(self.pdu_session_type())
    }

    /// Set the selected SSC mode while preserving the spare bit in the upper nibble.
    pub fn with_selected_ssc_mode(mut self, ssc_mode: crate::nas_5gs::ie::SscModeValue) -> Self {
        self.set_selected_ssc_mode(ssc_mode);
        self
    }

    /// Mutating setter for the selected SSC mode.
    pub fn set_selected_ssc_mode(&mut self, ssc_mode: crate::nas_5gs::ie::SscModeValue) {
        self.selected_pdu_session_type.type_field =
            (self.selected_pdu_session_type.type_field & 0x08) | (ssc_mode as u8 & 0x07);
    }

    /// Set the selected PDU session type while preserving the spare bits in the lower nibble.
    pub fn with_selected_pdu_session_type(
        mut self,
        session_type: crate::nas_5gs::ie::PduSessionTypeValue,
    ) -> Self {
        self.set_selected_pdu_session_type(session_type);
        self
    }

    /// Mutating setter for the selected PDU session type.
    pub fn set_selected_pdu_session_type(
        &mut self,
        session_type: crate::nas_5gs::ie::PduSessionTypeValue,
    ) {
        self.selected_pdu_session_type.value =
            (self.selected_pdu_session_type.value & !0x07) | (session_type as u8 & 0x07);
    }
}

nas_message! {
    /// PDU Session Establishment Reject (TS 24.501 §8.3.3).
    pub struct NasPduSessionEstablishmentReject {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only] {wire_len 1, 1}
        }
        optional {
            0x37 => back_off_timer_value: NasGprsTimer3 {wire_len 3, 3},
            0xF0 => allowed_ssc_mode: NasAllowedSscMode [tv1] {wire_len 1, 1},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0x61 => fgsm_congestion_re_attempt_indicator: NasFGsmCongestionReAttemptIndicator {wire_len 3, 3},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x1D => re_attempt_indicator: NasReAttemptIndicator {wire_len 3, 3},
            0x72 => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x77 => atsss_container: NasAtsssContainer {wire_len 3, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Authentication Command (TS 24.501 §8.3.4).
    pub struct NasPduSessionAuthenticationCommand {
        mandatory {
            eap_message: NasEapMessage {wire_len 6, 1502}
        }
        optional {
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Authentication Complete (TS 24.501 §8.3.5).
    pub struct NasPduSessionAuthenticationComplete {
        mandatory {
            eap_message: NasEapMessage {wire_len 6, 1502}
        }
        optional {
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Authentication Result (TS 24.501 §8.3.6).
    pub struct NasPduSessionAuthenticationResult {
        mandatory { }
        optional {
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Modification Request (TS 24.501 §8.3.7).
    pub struct NasPduSessionModificationRequest {
        mandatory { }
        optional {
            0x28 => fgsm_capability: NasFGsmCapability {wire_len 3, 15},
            0x59 => fgsm_cause: NasFGsmCause {wire_len 2, 2},
            0x55 => maximum_number_of_supported_packet_filters: NasMaximumNumberOfSupportedPacketFilters {wire_len 3, 3},
            0xB0 => always_on_pdu_session_requested: NasAlwaysOnPduSessionRequested [tv1] {wire_len 1, 1},
            0x13 => integrity_protection_maximum_data_rate: NasIntegrityProtectionMaximumDataRate [opt_type] {wire_len 3, 3},
            0x7A => requested_qos_rules: NasQosRules [opt_type] {wire_len 7, 65538},
            0x79 => requested_qos_flow_descriptions: NasQosFlowDescriptions {wire_len 6, 65538},
            0x75 => mapped_eps_bearer_contexts: NasMappedEpsBearerContexts {wire_len 7, 65538},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x74 => port_management_information_container: NasPortManagementInformationContainer {wire_len 4, 65538},
            0x66 => ip_header_compression_configuration: NasIpHeaderCompressionConfiguration {wire_len 5, 257},
            0x1F => ethernet_header_compression_configuration: NasEthernetHeaderCompressionConfiguration {wire_len 3, 3},
            0x70 => requested_mbs_container: NasRequestedMbsContainer {wire_len 8, 65538},
            0x72 => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x73 => non_3gpp_delay_budget: NasNon3GppDelayBudget {wire_len 6, usize::MAX},
            0x36 => ursp_rule_enforcement_reports: NasUrspRuleEnforcementReports {wire_len 4, usize::MAX},
            0x7C => non_3gpp_device_information: NasNon3GppDeviceInformation {wire_len 7, usize::MAX}
        }
    }
}

nas_message! {
    /// PDU Session Modification Reject (TS 24.501 §8.3.8).
    pub struct NasPduSessionModificationReject {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only] {wire_len 1, 1}
        }
        optional {
            0x37 => back_off_timer_value: NasGprsTimer3 {wire_len 3, 3},
            0x61 => fgsm_congestion_re_attempt_indicator: NasFGsmCongestionReAttemptIndicator {wire_len 3, 3},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x1D => re_attempt_indicator: NasReAttemptIndicator {wire_len 3, 3}
        }
    }
}

nas_message! {
    /// PDU Session Modification Command (TS 24.501 §8.3.9).
    pub struct NasPduSessionModificationCommand {
        mandatory { }
        optional {
            0x59 => fgsm_cause: NasFGsmCause {wire_len 2, 2},
            0x2A => session_ambr: NasSessionAmbr [opt_type] {wire_len 8, 8},
            0x56 => rq_timer_value: NasGprsTimer {wire_len 2, 2},
            0x80 => always_on_pdu_session_indication: NasAlwaysOnPduSessionIndication [tv1] {wire_len 1, 1},
            0x7A => authorized_qos_rules: NasQosRules [opt_type] {wire_len 7, 65538},
            0x75 => mapped_eps_bearer_contexts: NasMappedEpsBearerContexts {wire_len 7, 65538},
            0x79 => authorized_qos_flow_descriptions: NasQosFlowDescriptions {wire_len 6, 65538},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x77 => atsss_container: NasAtsssContainer {wire_len 3, 65538},
            0x66 => ip_header_compression_configuration: NasIpHeaderCompressionConfiguration {wire_len 5, 257},
            0x74 => port_management_information_container: NasPortManagementInformationContainer {wire_len 4, 65538},
            0x1E => serving_plmn_rate_control: NasServingPlmnRateControl {wire_len 4, 4},
            0x1F => ethernet_header_compression_configuration: NasEthernetHeaderCompressionConfiguration {wire_len 3, 3},
            0x71 => received_mbs_container: NasReceivedMbsContainer {wire_len 9, 65538},
            0x72 => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x5A => alternative_s_nssai: NasSNssai {wire_len 3, 10},
            0x70 => n3_qai: NasN3Qai {wire_len 9, usize::MAX},
            0x73 => protocol_description: NasProtocolDescription {wire_len 6, usize::MAX},
            0x38 => ecn_marking_l4s_indication: NasEcnMarkingL4sIndication {wire_len 2, 257}
        }
    }
}

nas_message! {
    /// PDU Session Modification Complete (TS 24.501 §8.3.10).
    pub struct NasPduSessionModificationComplete {
        mandatory { }
        optional {
            0x59 => fgsm_cause: NasFGsmCause,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x74 => port_management_information_container: NasPortManagementInformationContainer {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Modification Command Reject (TS 24.501 §8.3.11).
    pub struct NasPduSessionModificationCommandReject {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only] {wire_len 1, 1}
        }
        optional {
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Release Request (TS 24.501 §8.3.12).
    pub struct NasPduSessionReleaseRequest {
        mandatory { }
        optional {
            0x59 => fgsm_cause: NasFGsmCause {wire_len 2, 2},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Release Reject (TS 24.501 §8.3.13).
    pub struct NasPduSessionReleaseReject {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only] {wire_len 1, 1}
        }
        optional {
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Release Command (TS 24.501 §8.3.14).
    pub struct NasPduSessionReleaseCommand {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only] {wire_len 1, 1}
        }
        optional {
            0x37 => back_off_timer_value: NasGprsTimer3 {wire_len 3, 3},
            0x78 => eap_message: NasEapMessage [opt_type] {wire_len 7, 1503},
            0x61 => fgsm_congestion_re_attempt_indicator: NasFGsmCongestionReAttemptIndicator {wire_len 3, 3},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0xD0 => access_type: NasAccessType [tv1] {wire_len 1, 1},
            0x72 => service_level_aa_container: NasServiceLevelAaContainer {wire_len 4, 65538},
            0x5A => alternative_s_nssai: NasSNssai {wire_len 3, 10}
        }
    }
}

nas_message! {
    /// PDU Session Release Complete (TS 24.501 §8.3.15).
    pub struct NasPduSessionReleaseComplete {
        mandatory { }
        optional {
            0x59 => fgsm_cause: NasFGsmCause {wire_len 2, 2},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// 5GSM Status (TS 24.501 §8.3.16).
    pub struct NasFGsmStatus {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only] {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// Service-Level Authentication Command (TS 24.501 §8.3.17).
    pub struct NasServiceLevelAuthenticationCommand {
        mandatory {
            service_level_aa_container: NasServiceLevelAaContainer [tlve_as_lve] {wire_len 5, 65538}
        }
        optional { }
    }
}

nas_message! {
    /// Service-Level Authentication Complete (TS 24.501 §8.3.18).
    pub struct NasServiceLevelAuthenticationComplete {
        mandatory {
            service_level_aa_container: NasServiceLevelAaContainer [tlve_as_lve] {wire_len 5, 65538}
        }
        optional { }
    }
}

nas_message! {
    /// Remote UE Report (TS 24.501 §8.3.19).
    pub struct NasRemoteUeReport {
        mandatory { }
        optional {
            0x76 => connected_remote_ue_context_list: NasRemoteUeContextList {wire_len 16, 65538},
            0x70 => disconnected_remote_ue_context_list: NasRemoteUeContextList {wire_len 16, 65538}
        }
    }
}

nas_message_empty!(
    /// Remote UE Report Response (TS 24.501 §8.3.20).
    NasRemoteUeReportResponse
);

// ── Message enums and dispatch (kept exactly as original) ──────────────────────

/// Enum over all 5G Mobility Management (5GMM) message types.
///
/// Each variant wraps a message struct defined by the `nas_message!` macro.
/// Pattern-match to access the inner message fields.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Nas5gmmMessage {
    /// Registration request (TS 24.501 §8.2.6).
    RegistrationRequest(NasRegistrationRequest),
    /// Registration accept (TS 24.501 §8.2.7).
    RegistrationAccept(NasRegistrationAccept),
    /// Registration complete (TS 24.501 §8.2.8).
    RegistrationComplete(NasRegistrationComplete),
    /// Registration reject (TS 24.501 §8.2.9).
    RegistrationReject(NasRegistrationReject),
    /// De-registration request (UE originating de-registration) (TS 24.501 §8.2.12).
    DeregistrationRequestFromUe(NasDeregistrationRequestFromUe),
    /// De-registration request (UE terminated de-registration) (TS 24.501 §8.2.14).
    DeregistrationRequestToUe(NasDeregistrationRequestToUe),
    /// De-registration accept (UE originating de-registration) (TS 24.501 §8.2.13).
    DeregistrationAcceptFromUe(NasDeregistrationAcceptFromUe),
    /// De-registration accept (UE terminated de-registration) (TS 24.501 §8.2.15).
    DeregistrationAcceptToUe(NasDeregistrationAcceptToUe),
    /// Configuration update complete (TS 24.501 §8.2.20).
    ConfigurationUpdateComplete(NasConfigurationUpdateComplete),
    /// Service request (TS 24.501 §8.2.16).
    ServiceRequest(NasServiceRequest),
    /// Service reject (TS 24.501 §8.2.18).
    ServiceReject(NasServiceReject),
    /// Service accept (TS 24.501 §8.2.17).
    ServiceAccept(NasServiceAccept),
    /// Configuration update command (TS 24.501 §8.2.19).
    ConfigurationUpdateCommand(NasConfigurationUpdateCommand),
    /// Authentication request (TS 24.501 §8.2.1).
    AuthenticationRequest(NasAuthenticationRequest),
    /// Authentication response (TS 24.501 §8.2.2).
    AuthenticationResponse(NasAuthenticationResponse),
    /// Authentication reject (TS 24.501 §8.2.5).
    AuthenticationReject(NasAuthenticationReject),
    /// Authentication failure (TS 24.501 §8.2.4).
    AuthenticationFailure(NasAuthenticationFailure),
    /// Authentication result (TS 24.501 §8.2.3).
    AuthenticationResult(NasAuthenticationResult),
    /// Identity request (TS 24.501 §8.2.21).
    IdentityRequest(NasIdentityRequest),
    /// Identity response (TS 24.501 §8.2.22).
    IdentityResponse(NasIdentityResponse),
    /// Security mode command (TS 24.501 §8.2.25).
    SecurityModeCommand(NasSecurityModeCommand),
    /// Security mode complete (TS 24.501 §8.2.26).
    SecurityModeComplete(NasSecurityModeComplete),
    /// Security mode reject (TS 24.501 §8.2.27).
    SecurityModeReject(NasSecurityModeReject),
    /// 5GMM status (TS 24.501 §8.2.29).
    FGmmStatus(NasFGmmStatus),
    /// Notification (TS 24.501 §8.2.23).
    Notification(NasNotification),
    /// Notification response (TS 24.501 §8.2.24).
    NotificationResponse(NasNotificationResponse),
    /// UL NAS transport (TS 24.501 §8.2.10).
    UlNasTransport(NasUlNasTransport),
    /// DL NAS transport (TS 24.501 §8.2.11).
    DlNasTransport(NasDlNasTransport),
    /// Control Plane Service request (TS 24.501 §8.2.30).
    ControlPlaneServiceRequest(NasControlPlaneServiceRequest),
    /// Network slice-specific authentication command (TS 24.501 §8.2.31).
    NetworkSliceSpecificAuthenticationCommand(NasNetworkSliceSpecificAuthenticationCommand),
    /// Network slice-specific authentication complete (TS 24.501 §8.2.32).
    NetworkSliceSpecificAuthenticationComplete(NasNetworkSliceSpecificAuthenticationComplete),
    /// Network slice-specific authentication result (TS 24.501 §8.2.33).
    NetworkSliceSpecificAuthenticationResult(NasNetworkSliceSpecificAuthenticationResult),
    /// Relay key request (TS 24.501 §8.2.34).
    RelayKeyRequest(NasRelayKeyRequest),
    /// Relay key accept (TS 24.501 §8.2.35).
    RelayKeyAccept(NasRelayKeyAccept),
    /// Relay key reject (TS 24.501 §8.2.36).
    RelayKeyReject(NasRelayKeyReject),
    /// Relay authentication request (TS 24.501 §8.2.37).
    RelayAuthenticationRequest(NasRelayAuthenticationRequest),
    /// Relay authentication response (TS 24.501 §8.2.38).
    RelayAuthenticationResponse(NasRelayAuthenticationResponse),
}

impl Nas5gmmMessage {
    /// Message type of the body.
    pub fn message_type(&self) -> Nas5gmmMessageType {
        self.get_message_type()
    }

    /// Alias of [`Self::message_type`].
    pub fn get_message_type(&self) -> Nas5gmmMessageType {
        match self {
            Nas5gmmMessage::RegistrationRequest(_) => Nas5gmmMessageType::RegistrationRequest,
            Nas5gmmMessage::RegistrationAccept(_) => Nas5gmmMessageType::RegistrationAccept,
            Nas5gmmMessage::RegistrationComplete(_) => Nas5gmmMessageType::RegistrationComplete,
            Nas5gmmMessage::RegistrationReject(_) => Nas5gmmMessageType::RegistrationReject,
            Nas5gmmMessage::DeregistrationRequestFromUe(_) => {
                Nas5gmmMessageType::DeregistrationRequestFromUe
            }
            Nas5gmmMessage::DeregistrationRequestToUe(_) => {
                Nas5gmmMessageType::DeregistrationRequestToUe
            }
            Nas5gmmMessage::DeregistrationAcceptFromUe(_) => {
                Nas5gmmMessageType::DeregistrationAcceptFromUe
            }
            Nas5gmmMessage::DeregistrationAcceptToUe(_) => {
                Nas5gmmMessageType::DeregistrationAcceptToUe
            }
            Nas5gmmMessage::ConfigurationUpdateComplete(_) => {
                Nas5gmmMessageType::ConfigurationUpdateComplete
            }
            Nas5gmmMessage::ServiceRequest(_) => Nas5gmmMessageType::ServiceRequest,
            Nas5gmmMessage::ServiceReject(_) => Nas5gmmMessageType::ServiceReject,
            Nas5gmmMessage::ServiceAccept(_) => Nas5gmmMessageType::ServiceAccept,
            Nas5gmmMessage::ConfigurationUpdateCommand(_) => {
                Nas5gmmMessageType::ConfigurationUpdateCommand
            }
            Nas5gmmMessage::AuthenticationRequest(_) => Nas5gmmMessageType::AuthenticationRequest,
            Nas5gmmMessage::AuthenticationResponse(_) => Nas5gmmMessageType::AuthenticationResponse,
            Nas5gmmMessage::AuthenticationReject(_) => Nas5gmmMessageType::AuthenticationReject,
            Nas5gmmMessage::AuthenticationFailure(_) => Nas5gmmMessageType::AuthenticationFailure,
            Nas5gmmMessage::AuthenticationResult(_) => Nas5gmmMessageType::AuthenticationResult,
            Nas5gmmMessage::IdentityRequest(_) => Nas5gmmMessageType::IdentityRequest,
            Nas5gmmMessage::IdentityResponse(_) => Nas5gmmMessageType::IdentityResponse,
            Nas5gmmMessage::SecurityModeCommand(_) => Nas5gmmMessageType::SecurityModeCommand,
            Nas5gmmMessage::SecurityModeComplete(_) => Nas5gmmMessageType::SecurityModeComplete,
            Nas5gmmMessage::SecurityModeReject(_) => Nas5gmmMessageType::SecurityModeReject,
            Nas5gmmMessage::FGmmStatus(_) => Nas5gmmMessageType::FGmmStatus,
            Nas5gmmMessage::Notification(_) => Nas5gmmMessageType::Notification,
            Nas5gmmMessage::NotificationResponse(_) => Nas5gmmMessageType::NotificationResponse,
            Nas5gmmMessage::UlNasTransport(_) => Nas5gmmMessageType::UlNasTransport,
            Nas5gmmMessage::DlNasTransport(_) => Nas5gmmMessageType::DlNasTransport,
            Nas5gmmMessage::ControlPlaneServiceRequest(_) => {
                Nas5gmmMessageType::ControlPlaneServiceRequest
            }
            Nas5gmmMessage::NetworkSliceSpecificAuthenticationCommand(_) => {
                Nas5gmmMessageType::NetworkSliceSpecificAuthenticationCommand
            }
            Nas5gmmMessage::NetworkSliceSpecificAuthenticationComplete(_) => {
                Nas5gmmMessageType::NetworkSliceSpecificAuthenticationComplete
            }
            Nas5gmmMessage::NetworkSliceSpecificAuthenticationResult(_) => {
                Nas5gmmMessageType::NetworkSliceSpecificAuthenticationResult
            }
            Nas5gmmMessage::RelayKeyRequest(_) => Nas5gmmMessageType::RelayKeyRequest,
            Nas5gmmMessage::RelayKeyAccept(_) => Nas5gmmMessageType::RelayKeyAccept,
            Nas5gmmMessage::RelayKeyReject(_) => Nas5gmmMessageType::RelayKeyReject,
            Nas5gmmMessage::RelayAuthenticationRequest(_) => {
                Nas5gmmMessageType::RelayAuthenticationRequest
            }
            Nas5gmmMessage::RelayAuthenticationResponse(_) => {
                Nas5gmmMessageType::RelayAuthenticationResponse
            }
        }
    }
}

impl Encode for Nas5gmmMessage {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        match self {
            Nas5gmmMessage::RegistrationRequest(msg) => msg.encode(buffer),
            Nas5gmmMessage::RegistrationAccept(msg) => msg.encode(buffer),
            Nas5gmmMessage::RegistrationComplete(msg) => msg.encode(buffer),
            Nas5gmmMessage::RegistrationReject(msg) => msg.encode(buffer),
            Nas5gmmMessage::DeregistrationRequestFromUe(msg) => msg.encode(buffer),
            Nas5gmmMessage::DeregistrationRequestToUe(msg) => msg.encode(buffer),
            Nas5gmmMessage::DeregistrationAcceptFromUe(msg) => msg.encode(buffer),
            Nas5gmmMessage::DeregistrationAcceptToUe(msg) => msg.encode(buffer),
            Nas5gmmMessage::ConfigurationUpdateComplete(msg) => msg.encode(buffer),
            Nas5gmmMessage::ServiceRequest(msg) => msg.encode(buffer),
            Nas5gmmMessage::ServiceReject(msg) => msg.encode(buffer),
            Nas5gmmMessage::ServiceAccept(msg) => msg.encode(buffer),
            Nas5gmmMessage::ConfigurationUpdateCommand(msg) => msg.encode(buffer),
            Nas5gmmMessage::AuthenticationRequest(msg) => msg.encode(buffer),
            Nas5gmmMessage::AuthenticationResponse(msg) => msg.encode(buffer),
            Nas5gmmMessage::AuthenticationReject(msg) => msg.encode(buffer),
            Nas5gmmMessage::AuthenticationFailure(msg) => msg.encode(buffer),
            Nas5gmmMessage::AuthenticationResult(msg) => msg.encode(buffer),
            Nas5gmmMessage::IdentityRequest(msg) => msg.encode(buffer),
            Nas5gmmMessage::IdentityResponse(msg) => msg.encode(buffer),
            Nas5gmmMessage::SecurityModeCommand(msg) => msg.encode(buffer),
            Nas5gmmMessage::SecurityModeComplete(msg) => msg.encode(buffer),
            Nas5gmmMessage::SecurityModeReject(msg) => msg.encode(buffer),
            Nas5gmmMessage::FGmmStatus(msg) => msg.encode(buffer),
            Nas5gmmMessage::Notification(msg) => msg.encode(buffer),
            Nas5gmmMessage::NotificationResponse(msg) => msg.encode(buffer),
            Nas5gmmMessage::UlNasTransport(msg) => msg.encode(buffer),
            Nas5gmmMessage::DlNasTransport(msg) => msg.encode(buffer),
            Nas5gmmMessage::ControlPlaneServiceRequest(msg) => msg.encode(buffer),
            Nas5gmmMessage::NetworkSliceSpecificAuthenticationCommand(msg) => msg.encode(buffer),
            Nas5gmmMessage::NetworkSliceSpecificAuthenticationComplete(msg) => msg.encode(buffer),
            Nas5gmmMessage::NetworkSliceSpecificAuthenticationResult(msg) => msg.encode(buffer),
            Nas5gmmMessage::RelayKeyRequest(msg) => msg.encode(buffer),
            Nas5gmmMessage::RelayKeyAccept(msg) => msg.encode(buffer),
            Nas5gmmMessage::RelayKeyReject(msg) => msg.encode(buffer),
            Nas5gmmMessage::RelayAuthenticationRequest(msg) => msg.encode(buffer),
            Nas5gmmMessage::RelayAuthenticationResponse(msg) => msg.encode(buffer),
        }
    }
}

impl TryFrom<(Nas5gmmMessageType, &mut Bytes)> for Nas5gmmMessage {
    type Error = NasError;

    fn try_from(value: (Nas5gmmMessageType, &mut Bytes)) -> Result<Self> {
        let (message_type, buffer) = value;

        match message_type {
            Nas5gmmMessageType::RegistrationRequest => Ok(Nas5gmmMessage::RegistrationRequest(
                NasRegistrationRequest::decode(buffer)?,
            )),
            Nas5gmmMessageType::RegistrationAccept => Ok(Nas5gmmMessage::RegistrationAccept(
                NasRegistrationAccept::decode(buffer)?,
            )),
            Nas5gmmMessageType::RegistrationComplete => Ok(Nas5gmmMessage::RegistrationComplete(
                NasRegistrationComplete::decode(buffer)?,
            )),
            Nas5gmmMessageType::RegistrationReject => Ok(Nas5gmmMessage::RegistrationReject(
                NasRegistrationReject::decode(buffer)?,
            )),
            Nas5gmmMessageType::DeregistrationRequestFromUe => {
                Ok(Nas5gmmMessage::DeregistrationRequestFromUe(
                    NasDeregistrationRequestFromUe::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::DeregistrationRequestToUe => {
                Ok(Nas5gmmMessage::DeregistrationRequestToUe(
                    NasDeregistrationRequestToUe::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::ServiceRequest => Ok(Nas5gmmMessage::ServiceRequest(
                NasServiceRequest::decode(buffer)?,
            )),
            Nas5gmmMessageType::ServiceReject => Ok(Nas5gmmMessage::ServiceReject(
                NasServiceReject::decode(buffer)?,
            )),
            Nas5gmmMessageType::ServiceAccept => Ok(Nas5gmmMessage::ServiceAccept(
                NasServiceAccept::decode(buffer)?,
            )),
            Nas5gmmMessageType::ConfigurationUpdateCommand => {
                Ok(Nas5gmmMessage::ConfigurationUpdateCommand(
                    NasConfigurationUpdateCommand::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::AuthenticationRequest => Ok(Nas5gmmMessage::AuthenticationRequest(
                NasAuthenticationRequest::decode(buffer)?,
            )),
            Nas5gmmMessageType::AuthenticationResponse => Ok(
                Nas5gmmMessage::AuthenticationResponse(NasAuthenticationResponse::decode(buffer)?),
            ),
            Nas5gmmMessageType::AuthenticationReject => Ok(Nas5gmmMessage::AuthenticationReject(
                NasAuthenticationReject::decode(buffer)?,
            )),
            Nas5gmmMessageType::AuthenticationFailure => Ok(Nas5gmmMessage::AuthenticationFailure(
                NasAuthenticationFailure::decode(buffer)?,
            )),
            Nas5gmmMessageType::AuthenticationResult => Ok(Nas5gmmMessage::AuthenticationResult(
                NasAuthenticationResult::decode(buffer)?,
            )),
            Nas5gmmMessageType::IdentityRequest => Ok(Nas5gmmMessage::IdentityRequest(
                NasIdentityRequest::decode(buffer)?,
            )),
            Nas5gmmMessageType::IdentityResponse => Ok(Nas5gmmMessage::IdentityResponse(
                NasIdentityResponse::decode(buffer)?,
            )),
            Nas5gmmMessageType::SecurityModeCommand => Ok(Nas5gmmMessage::SecurityModeCommand(
                NasSecurityModeCommand::decode(buffer)?,
            )),
            Nas5gmmMessageType::SecurityModeComplete => Ok(Nas5gmmMessage::SecurityModeComplete(
                NasSecurityModeComplete::decode(buffer)?,
            )),
            Nas5gmmMessageType::SecurityModeReject => Ok(Nas5gmmMessage::SecurityModeReject(
                NasSecurityModeReject::decode(buffer)?,
            )),
            Nas5gmmMessageType::FGmmStatus => {
                Ok(Nas5gmmMessage::FGmmStatus(NasFGmmStatus::decode(buffer)?))
            }
            Nas5gmmMessageType::Notification => Ok(Nas5gmmMessage::Notification(
                NasNotification::decode(buffer)?,
            )),
            Nas5gmmMessageType::NotificationResponse => Ok(Nas5gmmMessage::NotificationResponse(
                NasNotificationResponse::decode(buffer)?,
            )),
            Nas5gmmMessageType::UlNasTransport => Ok(Nas5gmmMessage::UlNasTransport(
                NasUlNasTransport::decode(buffer)?,
            )),
            Nas5gmmMessageType::DlNasTransport => Ok(Nas5gmmMessage::DlNasTransport(
                NasDlNasTransport::decode(buffer)?,
            )),
            Nas5gmmMessageType::DeregistrationAcceptFromUe => {
                Ok(Nas5gmmMessage::DeregistrationAcceptFromUe(
                    NasDeregistrationAcceptFromUe::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::DeregistrationAcceptToUe => {
                Ok(Nas5gmmMessage::DeregistrationAcceptToUe(
                    NasDeregistrationAcceptToUe::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::ConfigurationUpdateComplete => {
                Ok(Nas5gmmMessage::ConfigurationUpdateComplete(
                    NasConfigurationUpdateComplete::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::ControlPlaneServiceRequest => {
                Ok(Nas5gmmMessage::ControlPlaneServiceRequest(
                    NasControlPlaneServiceRequest::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::NetworkSliceSpecificAuthenticationCommand => {
                Ok(Nas5gmmMessage::NetworkSliceSpecificAuthenticationCommand(
                    NasNetworkSliceSpecificAuthenticationCommand::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::NetworkSliceSpecificAuthenticationComplete => {
                Ok(Nas5gmmMessage::NetworkSliceSpecificAuthenticationComplete(
                    NasNetworkSliceSpecificAuthenticationComplete::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::NetworkSliceSpecificAuthenticationResult => {
                Ok(Nas5gmmMessage::NetworkSliceSpecificAuthenticationResult(
                    NasNetworkSliceSpecificAuthenticationResult::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::RelayKeyRequest => Ok(Nas5gmmMessage::RelayKeyRequest(
                NasRelayKeyRequest::decode(buffer)?,
            )),
            Nas5gmmMessageType::RelayKeyAccept => Ok(Nas5gmmMessage::RelayKeyAccept(
                NasRelayKeyAccept::decode(buffer)?,
            )),
            Nas5gmmMessageType::RelayKeyReject => Ok(Nas5gmmMessage::RelayKeyReject(
                NasRelayKeyReject::decode(buffer)?,
            )),
            Nas5gmmMessageType::RelayAuthenticationRequest => {
                Ok(Nas5gmmMessage::RelayAuthenticationRequest(
                    NasRelayAuthenticationRequest::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::RelayAuthenticationResponse => {
                Ok(Nas5gmmMessage::RelayAuthenticationResponse(
                    NasRelayAuthenticationResponse::decode(buffer)?,
                ))
            }
            Nas5gmmMessageType::Unknown(v) => Err(NasError::UnknownMessageType(v)),
        }
    }
}

/// Enum over all 5G Session Management (5GSM) message types.
///
/// Each variant wraps a message struct defined by the `nas_message!` macro.
#[derive(Debug, Clone, PartialEq)]
pub enum Nas5gsmMessage {
    /// PDU session establishment request (TS 24.501 §8.3.1).
    PduSessionEstablishmentRequest(NasPduSessionEstablishmentRequest),
    /// PDU session establishment accept (TS 24.501 §8.3.2).
    PduSessionEstablishmentAccept(NasPduSessionEstablishmentAccept),
    /// PDU session establishment reject (TS 24.501 §8.3.3).
    PduSessionEstablishmentReject(NasPduSessionEstablishmentReject),
    /// PDU session authentication command (TS 24.501 §8.3.4).
    PduSessionAuthenticationCommand(NasPduSessionAuthenticationCommand),
    /// PDU session authentication complete (TS 24.501 §8.3.5).
    PduSessionAuthenticationComplete(NasPduSessionAuthenticationComplete),
    /// PDU session authentication result (TS 24.501 §8.3.6).
    PduSessionAuthenticationResult(NasPduSessionAuthenticationResult),
    /// PDU session modification request (TS 24.501 §8.3.7).
    PduSessionModificationRequest(NasPduSessionModificationRequest),
    /// PDU session modification reject (TS 24.501 §8.3.8).
    PduSessionModificationReject(NasPduSessionModificationReject),
    /// PDU session modification command (TS 24.501 §8.3.9).
    PduSessionModificationCommand(NasPduSessionModificationCommand),
    /// PDU session modification complete (TS 24.501 §8.3.10).
    PduSessionModificationComplete(NasPduSessionModificationComplete),
    /// PDU session modification command reject (TS 24.501 §8.3.11).
    PduSessionModificationCommandReject(NasPduSessionModificationCommandReject),
    /// PDU session release request (TS 24.501 §8.3.12).
    PduSessionReleaseRequest(NasPduSessionReleaseRequest),
    /// PDU session release reject (TS 24.501 §8.3.13).
    PduSessionReleaseReject(NasPduSessionReleaseReject),
    /// PDU session release command (TS 24.501 §8.3.14).
    PduSessionReleaseCommand(NasPduSessionReleaseCommand),
    /// PDU session release complete (TS 24.501 §8.3.15).
    PduSessionReleaseComplete(NasPduSessionReleaseComplete),
    /// 5GSM status (TS 24.501 §8.3.16).
    FGsmStatus(NasFGsmStatus),
    /// Service-level authentication command (TS 24.501 §8.3.17).
    ServiceLevelAuthenticationCommand(NasServiceLevelAuthenticationCommand),
    /// Service-level authentication complete (TS 24.501 §8.3.18).
    ServiceLevelAuthenticationComplete(NasServiceLevelAuthenticationComplete),
    /// Remote UE report (TS 24.501 §8.3.19).
    RemoteUeReport(NasRemoteUeReport),
    /// Remote UE report response (TS 24.501 §8.3.20).
    RemoteUeReportResponse(NasRemoteUeReportResponse),
}

impl Nas5gsmMessage {
    /// Message type of the body.
    pub fn message_type(&self) -> Nas5gsmMessageType {
        self.get_message_type()
    }

    /// Alias of [`Self::message_type`].
    pub fn get_message_type(&self) -> Nas5gsmMessageType {
        match self {
            Nas5gsmMessage::PduSessionEstablishmentRequest(_) => {
                Nas5gsmMessageType::PduSessionEstablishmentRequest
            }
            Nas5gsmMessage::PduSessionEstablishmentAccept(_) => {
                Nas5gsmMessageType::PduSessionEstablishmentAccept
            }
            Nas5gsmMessage::PduSessionEstablishmentReject(_) => {
                Nas5gsmMessageType::PduSessionEstablishmentReject
            }
            Nas5gsmMessage::PduSessionAuthenticationCommand(_) => {
                Nas5gsmMessageType::PduSessionAuthenticationCommand
            }
            Nas5gsmMessage::PduSessionAuthenticationComplete(_) => {
                Nas5gsmMessageType::PduSessionAuthenticationComplete
            }
            Nas5gsmMessage::PduSessionAuthenticationResult(_) => {
                Nas5gsmMessageType::PduSessionAuthenticationResult
            }
            Nas5gsmMessage::PduSessionModificationRequest(_) => {
                Nas5gsmMessageType::PduSessionModificationRequest
            }
            Nas5gsmMessage::PduSessionModificationReject(_) => {
                Nas5gsmMessageType::PduSessionModificationReject
            }
            Nas5gsmMessage::PduSessionModificationCommand(_) => {
                Nas5gsmMessageType::PduSessionModificationCommand
            }
            Nas5gsmMessage::PduSessionModificationComplete(_) => {
                Nas5gsmMessageType::PduSessionModificationComplete
            }
            Nas5gsmMessage::PduSessionModificationCommandReject(_) => {
                Nas5gsmMessageType::PduSessionModificationCommandReject
            }
            Nas5gsmMessage::PduSessionReleaseRequest(_) => {
                Nas5gsmMessageType::PduSessionReleaseRequest
            }
            Nas5gsmMessage::PduSessionReleaseReject(_) => {
                Nas5gsmMessageType::PduSessionReleaseReject
            }
            Nas5gsmMessage::PduSessionReleaseCommand(_) => {
                Nas5gsmMessageType::PduSessionReleaseCommand
            }
            Nas5gsmMessage::PduSessionReleaseComplete(_) => {
                Nas5gsmMessageType::PduSessionReleaseComplete
            }
            Nas5gsmMessage::FGsmStatus(_) => Nas5gsmMessageType::FGsmStatus,
            Nas5gsmMessage::ServiceLevelAuthenticationCommand(_) => {
                Nas5gsmMessageType::ServiceLevelAuthenticationCommand
            }
            Nas5gsmMessage::ServiceLevelAuthenticationComplete(_) => {
                Nas5gsmMessageType::ServiceLevelAuthenticationComplete
            }
            Nas5gsmMessage::RemoteUeReport(_) => Nas5gsmMessageType::RemoteUeReport,
            Nas5gsmMessage::RemoteUeReportResponse(_) => Nas5gsmMessageType::RemoteUeReportResponse,
        }
    }
}

impl Encode for Nas5gsmMessage {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        match self {
            Nas5gsmMessage::PduSessionEstablishmentRequest(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionEstablishmentAccept(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionEstablishmentReject(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionAuthenticationCommand(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionAuthenticationComplete(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionAuthenticationResult(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionModificationRequest(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionModificationReject(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionModificationCommand(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionModificationComplete(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionModificationCommandReject(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionReleaseRequest(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionReleaseReject(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionReleaseCommand(msg) => msg.encode(buffer),
            Nas5gsmMessage::PduSessionReleaseComplete(msg) => msg.encode(buffer),
            Nas5gsmMessage::FGsmStatus(msg) => msg.encode(buffer),
            Nas5gsmMessage::ServiceLevelAuthenticationCommand(msg) => msg.encode(buffer),
            Nas5gsmMessage::ServiceLevelAuthenticationComplete(msg) => msg.encode(buffer),
            Nas5gsmMessage::RemoteUeReport(msg) => msg.encode(buffer),
            Nas5gsmMessage::RemoteUeReportResponse(msg) => msg.encode(buffer),
        }
    }
}

impl TryFrom<(Nas5gsmMessageType, &mut Bytes)> for Nas5gsmMessage {
    type Error = NasError;

    fn try_from(value: (Nas5gsmMessageType, &mut Bytes)) -> Result<Self> {
        let (message_type, buffer) = value;

        match message_type {
            Nas5gsmMessageType::PduSessionEstablishmentRequest => {
                Ok(Nas5gsmMessage::PduSessionEstablishmentRequest(
                    NasPduSessionEstablishmentRequest::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionEstablishmentAccept => {
                Ok(Nas5gsmMessage::PduSessionEstablishmentAccept(
                    NasPduSessionEstablishmentAccept::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionEstablishmentReject => {
                Ok(Nas5gsmMessage::PduSessionEstablishmentReject(
                    NasPduSessionEstablishmentReject::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionAuthenticationCommand => {
                Ok(Nas5gsmMessage::PduSessionAuthenticationCommand(
                    NasPduSessionAuthenticationCommand::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionAuthenticationComplete => {
                Ok(Nas5gsmMessage::PduSessionAuthenticationComplete(
                    NasPduSessionAuthenticationComplete::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionAuthenticationResult => {
                Ok(Nas5gsmMessage::PduSessionAuthenticationResult(
                    NasPduSessionAuthenticationResult::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionModificationRequest => {
                Ok(Nas5gsmMessage::PduSessionModificationRequest(
                    NasPduSessionModificationRequest::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionModificationReject => {
                Ok(Nas5gsmMessage::PduSessionModificationReject(
                    NasPduSessionModificationReject::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionModificationCommand => {
                Ok(Nas5gsmMessage::PduSessionModificationCommand(
                    NasPduSessionModificationCommand::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionModificationComplete => {
                Ok(Nas5gsmMessage::PduSessionModificationComplete(
                    NasPduSessionModificationComplete::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionModificationCommandReject => {
                Ok(Nas5gsmMessage::PduSessionModificationCommandReject(
                    NasPduSessionModificationCommandReject::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionReleaseRequest => {
                Ok(Nas5gsmMessage::PduSessionReleaseRequest(
                    NasPduSessionReleaseRequest::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionReleaseReject => {
                Ok(Nas5gsmMessage::PduSessionReleaseReject(
                    NasPduSessionReleaseReject::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionReleaseCommand => {
                Ok(Nas5gsmMessage::PduSessionReleaseCommand(
                    NasPduSessionReleaseCommand::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::PduSessionReleaseComplete => {
                Ok(Nas5gsmMessage::PduSessionReleaseComplete(
                    NasPduSessionReleaseComplete::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::FGsmStatus => {
                Ok(Nas5gsmMessage::FGsmStatus(NasFGsmStatus::decode(buffer)?))
            }
            Nas5gsmMessageType::ServiceLevelAuthenticationCommand => {
                Ok(Nas5gsmMessage::ServiceLevelAuthenticationCommand(
                    NasServiceLevelAuthenticationCommand::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::ServiceLevelAuthenticationComplete => {
                Ok(Nas5gsmMessage::ServiceLevelAuthenticationComplete(
                    NasServiceLevelAuthenticationComplete::decode(buffer)?,
                ))
            }
            Nas5gsmMessageType::RemoteUeReport => Ok(Nas5gsmMessage::RemoteUeReport(
                NasRemoteUeReport::decode(buffer)?,
            )),
            Nas5gsmMessageType::RemoteUeReportResponse => Ok(
                Nas5gsmMessage::RemoteUeReportResponse(NasRemoteUeReportResponse::decode(buffer)?),
            ),
            Nas5gsmMessageType::Unknown(v) => Err(NasError::UnknownMessageType(v)),
        }
    }
}

/// Top-level 5G NAS message.
///
/// Every NAS PDU decodes into one of the following variants:
/// - [`Gmm`](Nas5gsMessage::Gmm) — a 5G Mobility Management message (EPD 0x7E)
/// - [`Gsm`](Nas5gsMessage::Gsm) — a 5G Session Management message (EPD 0x2E)
/// - [`SecurityProtected`](Nas5gsMessage::SecurityProtected) — a security envelope wrapping an inner message
/// - [`Opaque`](Nas5gsMessage::Opaque) — ciphertext inside a security envelope
///
/// # Examples
///
/// ```rust
/// use oxirush_nas::{decode_nas_5gs_message, Nas5gsMessage, Nas5gmmMessage};
///
/// let bytes = hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
/// let msg = decode_nas_5gs_message(&bytes).unwrap();
/// match msg {
///     Nas5gsMessage::Gmm(hdr, Nas5gmmMessage::RegistrationRequest(reg)) => {
///         println!("Got registration request");
///     }
///     _ => {}
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Nas5gsMessage {
    /// A 5G Mobility Management message (registration, authentication, security, etc.).
    Gmm(Nas5gmmHeader, Nas5gmmMessage),
    /// A 5G Session Management message (PDU session establishment, modification, release).
    Gsm(Nas5gsmHeader, Nas5gsmMessage),
    /// A security-protected envelope containing an inner plain 5GMM message.
    SecurityProtected(Nas5gsSecurityHeader, Box<Nas5gsMessage>),
    /// Ciphertext carried by a security-protected 5GMM envelope.
    Opaque(Vec<u8>),
}

pub(crate) fn validate_security_protected_inner_message(
    message: &Nas5gsMessage,
    security_header_type: Nas5gsSecurityHeaderType,
) -> Result<()> {
    if security_header_type == Nas5gsSecurityHeaderType::PlainNasMessage {
        return Err(NasError::EncodingError(
            "Security-protected NAS message cannot use PlainNasMessage security header type".into(),
        ));
    }

    let (header, inner) = match message {
        Nas5gsMessage::Gmm(header, inner) => (header, inner),
        Nas5gsMessage::Gsm(_, _) => {
            return Err(NasError::EncodingError(
                "Security-protected 5GS NAS message shall carry a plain 5GMM message; 5GSM messages are protected only via the enclosing 5GMM message"
                    .into(),
            ));
        }
        Nas5gsMessage::SecurityProtected(_, _) | Nas5gsMessage::Opaque(_) => {
            return Err(NasError::EncodingError(
                "Security-protected 5GS NAS message shall carry a plain 5GMM message".into(),
            ));
        }
    };

    if header.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
        return Err(NasError::EncodingError(format!(
            "Inner plain 5GMM message shall use EPD=0x7E, got 0x{:02X}",
            header.extended_protocol_discriminator
        )));
    }
    if header.security_header_type != Nas5gsSecurityHeaderType::PlainNasMessage {
        return Err(NasError::EncodingError(format!(
            "Inner plain 5GMM message shall use SHT=PlainNasMessage, got {:?}",
            header.security_header_type
        )));
    }
    if header.message_type != inner.message_type() {
        return Err(NasError::EncodingError(format!(
            "Inner 5GMM header message type {:?} does not match payload {:?}",
            header.message_type,
            inner.message_type()
        )));
    }

    match security_header_type {
        _ if matches!(inner, Nas5gmmMessage::SecurityModeCommand(_))
            && security_header_type
                != Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext =>
        {
            Err(NasError::EncodingError(
                "SecurityModeCommand requires integrity protection with new context".into(),
            ))
        }
        _ if matches!(inner, Nas5gmmMessage::SecurityModeComplete(_))
            && security_header_type
                != Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext =>
        {
            Err(NasError::EncodingError(
                "SecurityModeComplete requires ciphering with new context".into(),
            ))
        }
        Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext
            if !matches!(inner, Nas5gmmMessage::SecurityModeCommand(_)) =>
        {
            Err(NasError::EncodingError(
                "Security header type IntegrityProtectedWithNewContext is only valid for SecurityModeCommand per TS 24.501 Table 9.3.1 note 1"
                    .into(),
            ))
        }
        Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
            if !matches!(inner, Nas5gmmMessage::SecurityModeComplete(_)) =>
        {
            Err(NasError::EncodingError(
                "Security header type IntegrityProtectedAndCipheredWithNewContext is only valid for SecurityModeComplete per TS 24.501 Table 9.3.1 note 2"
                    .into(),
            ))
        }
        _ => Ok(()),
    }
}

impl Nas5gsMessage {
    /// Create a new 5GMM message.
    pub fn new_5gmm(message: Nas5gmmMessage) -> Self {
        let header = Nas5gmmHeader::new(message.message_type());
        Nas5gsMessage::Gmm(header, message)
    }

    /// Decode the plain 5GMM message inside a security envelope that uses NEA0.
    ///
    /// NEA0 produces an all-zero keystream (TS 33.501 §D.2.1), so the
    /// ciphered payload is the plain 5GMM message. An integrity-only envelope
    /// returns its already decoded message. The MAC is not verified; use
    /// `NasSecurityContext` (feature `security`) when the
    /// NAS keys are known.
    pub fn decode_null_ciphered_payload(&self) -> Result<Nas5gsMessage> {
        let Self::SecurityProtected(_, inner) = self else {
            return Err(NasError::DecodingError(
                "5GS message has no security envelope".into(),
            ));
        };
        let Self::Opaque(payload) = inner.as_ref() else {
            return Ok(inner.as_ref().clone());
        };
        decode_nas_5gs_message(payload)
    }

    /// Create a new 5GMM message with the type inferred from the enum variant.
    pub fn from_5gmm(message: Nas5gmmMessage) -> Self {
        Self::new_5gmm(message)
    }

    /// Create a new 5GSM message.
    pub fn new_5gsm(
        message: Nas5gsmMessage,
        pdu_session_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        let header = Nas5gsmHeader::new(
            message.message_type(),
            pdu_session_identity,
            procedure_transaction_identity,
        );
        Nas5gsMessage::Gsm(header, message)
    }

    /// Create a new 5GSM message with the type inferred from the enum variant.
    pub fn from_5gsm(
        message: Nas5gsmMessage,
        pdu_session_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        Self::new_5gsm(
            message,
            pdu_session_identity,
            procedure_transaction_identity,
        )
    }

    /// Wrap a plain 5GMM message with security protection per TS 24.501 `§8.2.28` / `§9.9`.
    pub fn protect(
        message: Nas5gsMessage,
        security_header_type: Nas5gsSecurityHeaderType,
        message_authentication_code: u32,
        sequence_number: u8,
    ) -> Result<Self> {
        if matches!(
            security_header_type,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
        ) {
            return Err(NasError::EncodingError(
                "Use NasSecurityContext to cipher a 5GS NAS message".into(),
            ));
        }
        validate_security_protected_inner_message(&message, security_header_type)?;

        let security_header = Nas5gsSecurityHeader {
            // TS 24.501 §9.1.1 and §9.2 require the outer header of a
            // security-protected 5GS NAS message to use the 5GMM EPD.
            extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM,
            security_header_type,
            message_authentication_code,
            sequence_number,
        };

        Ok(Nas5gsMessage::SecurityProtected(
            security_header,
            Box::new(message),
        ))
    }

    fn decode_plain(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::MessageTooShort);
        }

        match buffer[0] {
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM => {
                if buffer.remaining() < 2 {
                    return Err(NasError::MessageTooShort);
                }

                let security_header_type_octet = buffer[1];
                let security_header_type =
                    Nas5gsSecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;
                if security_header_type != Nas5gsSecurityHeaderType::PlainNasMessage {
                    return Err(NasError::DecodingError(format!(
                        "Plain 5GS NAS message cannot carry security header type {security_header_type:?}"
                    )));
                }

                let header = Nas5gmmHeader::decode(buffer)?;
                let message = Nas5gmmMessage::try_from((header.message_type, buffer))?;

                Ok(Nas5gsMessage::Gmm(header, message))
            }
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM => {
                let header = Nas5gsmHeader::decode(buffer)?;
                if let Nas5gsmMessageType::Unknown(message_type) = header.message_type {
                    return Err(NasError::UnknownSessionMessageType {
                        identity: header.pdu_session_identity,
                        pti: header.procedure_transaction_identity,
                        message_type,
                    });
                }
                let message = Nas5gsmMessage::try_from((header.message_type, buffer))?;

                Ok(Nas5gsMessage::Gsm(header, message))
            }
            epd => Err(NasError::UnknownProtocolDiscriminator(epd)),
        }
    }
}

impl Encode for Nas5gsMessage {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        match self {
            Nas5gsMessage::Gmm(header, message) => {
                if header.message_type != message.message_type() {
                    return Err(NasError::EncodingError(format!(
                        "5GMM header message type {:?} does not match payload {:?}",
                        header.message_type,
                        message.message_type()
                    )));
                }
                header.encode(buffer)?;
                message.encode(buffer)?;
            }
            Nas5gsMessage::Gsm(header, message) => {
                if header.message_type != message.message_type() {
                    return Err(NasError::EncodingError(format!(
                        "5GSM header message type {:?} does not match payload {:?}",
                        header.message_type,
                        message.message_type()
                    )));
                }
                header.encode(buffer)?;
                message.encode(buffer)?;
            }
            Nas5gsMessage::SecurityProtected(header, message) => {
                let ciphered = matches!(
                    header.security_header_type,
                    Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                        | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                );
                match message.as_ref() {
                    Nas5gsMessage::Opaque(data) if ciphered && !data.is_empty() => {}
                    Nas5gsMessage::Opaque(_) => {
                        return Err(NasError::EncodingError(
                            "Opaque 5GS payload requires a ciphered security header and nonempty ciphertext".into(),
                        ));
                    }
                    _ if ciphered => {
                        return Err(NasError::EncodingError(
                            "Ciphered 5GS security envelope requires opaque ciphertext".into(),
                        ));
                    }
                    Nas5gsMessage::SecurityProtected(_, _) => {
                        return Err(NasError::EncodingError(
                            "Security-protected 5GS NAS message cannot contain another security envelope"
                                .into(),
                        ));
                    }
                    Nas5gsMessage::Gmm(_, _) | Nas5gsMessage::Gsm(_, _) => {}
                }
                header.encode(buffer)?;

                // For security-protected messages, we encode the inner message
                // into a temporary buffer, then copy it to the output buffer
                let mut inner_buffer = BytesMut::new();
                message.encode(&mut inner_buffer)?;
                buffer.put_slice(&inner_buffer);
            }
            Nas5gsMessage::Opaque(data) => buffer.put_slice(data),
        }

        Ok(())
    }
}

impl Decode for Nas5gsMessage {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::MessageTooShort);
        }

        match buffer[0] {
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM => {
                if buffer.remaining() < 2 {
                    return Err(NasError::MessageTooShort);
                }

                let security_header_type_octet = buffer[1];
                match Nas5gsSecurityHeaderType::try_from(security_header_type_octet & 0x0F)? {
                    Nas5gsSecurityHeaderType::PlainNasMessage => Self::decode_plain(buffer),
                    sht => {
                        let security_header = Nas5gsSecurityHeader::decode(buffer)?;
                        let inner = if matches!(
                            sht,
                            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
                                | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                        ) {
                            if !buffer.has_remaining() {
                                return Err(NasError::MessageTooShort);
                            }
                            Self::Opaque(buffer.copy_to_bytes(buffer.remaining()).to_vec())
                        } else {
                            Self::decode_plain(buffer)?
                        };

                        Ok(Nas5gsMessage::SecurityProtected(
                            security_header,
                            Box::new(inner),
                        ))
                    }
                }
            }
            _ => Self::decode_plain(buffer),
        }
    }
}

/// Encode a [`Nas5gsMessage`] to its wire-format byte representation.
///
/// This is the main encoding entry point. The returned bytes are ready to be
/// sent over SCTP (inside an NGAP NAS-PDU IE) or written to a pcap.
pub fn encode_nas_5gs_message(message: &Nas5gsMessage) -> Result<Vec<u8>> {
    // Create a buffer with enough capacity for most messages
    let mut buffer = BytesMut::with_capacity(256);

    // Encode the message
    message.encode(&mut buffer)?;

    // Convert to Vec<u8>
    Ok(buffer.to_vec())
}

/// Decode a [`Nas5gsMessage`] from raw wire-format bytes.
///
/// Automatically dispatches based on the Extended Protocol Discriminator
/// (0x7E for 5GMM, 0x2E for 5GSM) and Security Header Type.
pub fn decode_nas_5gs_message(data: &[u8]) -> Result<Nas5gsMessage> {
    let mut buffer = Bytes::copy_from_slice(data);
    let message = Nas5gsMessage::decode(&mut buffer)?;
    if buffer.has_remaining() {
        return Err(NasError::DecodingError(
            "Trailing bytes after 5GS NAS message".into(),
        ));
    }
    Ok(message)
}

impl Nas5gsMessage {
    /// Encode this message to NAS wire-format bytes.
    ///
    /// Convenience wrapper around [`encode_nas_5gs_message()`]. Named `to_bytes()`
    /// to avoid collision with the [`Encode`] trait method.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_nas_5gs_message(self)
    }

    /// Decode a NAS message from wire-format bytes.
    ///
    /// Convenience wrapper around [`decode_nas_5gs_message()`]. Named `from_bytes()`
    /// to avoid collision with the [`Decode`] trait method.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        decode_nas_5gs_message(data)
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::*;
    use crate::common::Validate;

    #[test]
    fn spare_half_octets_are_ignored_on_receipt() {
        for (wire, canonical) in [
            (&[0x7e, 0xf0, 0x43][..], &[0x7e, 0x00, 0x43][..]),
            (
                &[0x7e, 0xf1, 0, 0, 0, 0, 0, 0x7e, 0xf0, 0x43][..],
                &[0x7e, 0x01, 0, 0, 0, 0, 0, 0x7e, 0x00, 0x43][..],
            ),
        ] {
            let message = Nas5gsMessage::from_bytes(wire).unwrap();
            assert_eq!(message.to_bytes().unwrap(), canonical);
        }
    }

    #[test]
    fn security_header_pairing_is_validation_not_wire_decoding() {
        let mut wire = vec![0x7e, 0x01, 0, 0, 0, 0, 0];
        wire.extend_from_slice(&hex::decode("7e005d020002a020e1360102").unwrap());
        let message = Nas5gsMessage::from_bytes(&wire).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|finding| finding.field == "5GS NAS header" || finding.field == "SHT")
        );
        assert_eq!(message.to_bytes().unwrap(), wire);
    }

    #[test]
    fn registration_request_carries_protected_eps_attach_request() {
        // TS 24.501 §8.2.6.16: the EPS NAS message container holds the complete
        // integrity protected ATTACH REQUEST. This one is packet 33 of the
        // S1AP capture used by the EPS tests.
        let attach = hex::decode(
            "17830224400307410108991007000020160605e0e000000000250243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1",
        )
        .unwrap();
        let mut wire =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        wire.push(0x70);
        wire.extend_from_slice(&(attach.len() as u16).to_be_bytes());
        wire.extend_from_slice(&attach);

        let message = Nas5gsMessage::from_bytes(&wire).unwrap();
        assert_eq!(message.to_bytes().unwrap(), wire);
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(request)) = &message else {
            panic!("expected REGISTRATION REQUEST");
        };
        let container = request.eps_nas_message_container.as_ref().unwrap();
        let eps = container.decode_as_eps_message().unwrap();
        let crate::nas_eps::NasEpsMessage::SecurityProtected(header, inner) = &eps else {
            panic!("expected an integrity protected EPS message");
        };
        assert_eq!(header.sequence_number, 3);
        let crate::nas_eps::NasEpsMessage::Emm(
            _,
            crate::nas_eps::NasEmmMessage::AttachRequest(attach_request),
        ) = inner.as_ref()
        else {
            panic!("expected ATTACH REQUEST");
        };
        assert_eq!(
            attach_request.eps_mobile_identity.as_imsi().as_deref(),
            Some("901700000026160")
        );
        assert_eq!(
            NasEpsNasMessageContainer::from_eps_message(&eps)
                .unwrap()
                .value,
            attach
        );

        let status = crate::nas_eps::decode_nas_eps_message(&[0x07, 0x60, 0x03]).unwrap();
        assert!(NasEpsNasMessageContainer::from_eps_message(&status).is_err());
        assert!(
            NasEpsNasMessageContainer::from_eps_nas_data(vec![0x07, 0x60, 0x03])
                .decode_as_eps_message()
                .is_err()
        );
    }

    #[test]
    fn truncated_and_bit_flipped_pdus_never_panic() {
        // Every accepted mutation must also format, validate, and re-encode to
        // a canonical form that decodes to the same structure.
        fn check(wire: &[u8]) {
            let Ok(message) = decode_nas_5gs_message(wire) else {
                return;
            };
            let _ = message.to_string();
            let _ = message.validate();
            if let Ok(inner) = message.decode_null_ciphered_payload() {
                let _ = inner.to_string();
                let _ = inner.validate();
            }
            let bytes = encode_nas_5gs_message(&message).expect("decodable PDU re-encodes");
            let again = decode_nas_5gs_message(&bytes).expect("canonical PDU decodes");
            assert_eq!(again, message, "structural round trip of {wire:02x?}");
            assert_eq!(encode_nas_5gs_message(&again).unwrap(), bytes);
        }
        for hex in [
            "7e004179000d0199f9070000000000000010022e08a020000000000000",
            "7e0042010177000bf299f907020040c00002df54074099f90700000115020101210201005e01a9",
            "7e004509000bf299f907020040c00002df",
            "7e004c100007040040c00002df7100157e004c100007040040c00002df4002020050020200",
            "7e004e5002020026020000",
            "7e0054430f90004f00700065006e00350047005346004742306202647100490100",
            "7e00560002000021ab6f2a1cc5c5938d38cba14dfe26b0012010a820e67b8896800076a638e98eed4747",
            "7e005d020002a020e1360102",
            "7e005e7700091511000000000000007100207e004109000d0199f9070000000000000010021001072e08a020000000000000",
            "7e00670100142e0101c1ffff917b000a80000a00000d00000300120181220101250908696e7465726e6574",
            "7e006801006d2e0101c211000901000631310101ff010603f42403f4242905010a2d00bd2201017900060120410101097b003580000d0408080808000d04080804040003102001486048600000000000000000888800031020014860486000000000000000008844250908696e7465726e65741201",
            "7e02123456780b7e005d020002a020e1360102",
        ] {
            let wire = hex::decode(hex).unwrap();
            for length in 0..wire.len() {
                check(&wire[..length]);
            }
            for bit in 0..wire.len() * 8 {
                let mut mutated = wire.clone();
                mutated[bit / 8] ^= 0x80 >> (bit % 8);
                check(&mutated);
            }
        }
    }

    #[test]
    fn unknown_comprehension_required_ies_are_reported() {
        // TS 24.007 §11.2.5: type 4 IEIs 0x00-0x0F and type 6 IEIs 0x7E-0x7F.
        for (wire, flagged) in [
            (&[0x7e, 0x00, 0x44, 0x16, 0x49, 0x01, 0xaa][..], false),
            (&[0x7e, 0x00, 0x44, 0x16, 0x0f, 0x01, 0xaa][..], true),
            (&[0x7e, 0x00, 0x44, 0x16, 0x7f, 0x00, 0x01, 0xaa][..], true),
            (&[0x7e, 0x00, 0x44, 0x16, 0x7b, 0x00, 0x01, 0xaa][..], false),
        ] {
            let message = Nas5gsMessage::from_bytes(wire).unwrap();
            assert_eq!(message.to_bytes().unwrap(), wire);
            assert_eq!(
                message
                    .validate()
                    .iter()
                    .any(|error| error.field == "unknown_ies"),
                flagged,
                "{wire:02x?}"
            );
        }
    }

    #[test]
    fn repeated_optional_ies_keep_first_occurrence() {
        // TS 24.501 §7.6.3: only the first repetition is handled. Later
        // repetitions are kept as ignored octets so relayed bytes are unchanged.
        let wire = [0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x21, 0x5f, 0x01, 0x22];
        let message = Nas5gsMessage::from_bytes(&wire).unwrap();
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(reject)) = &message else {
            panic!("expected REGISTRATION REJECT");
        };
        assert_eq!(reject.t3346_value.as_ref().unwrap().value, [0x21]);
        assert_eq!(
            reject.unknown_ies,
            [UnknownIe {
                iei: 0x5f,
                data: vec![0x01, 0x22],
            }]
        );
        assert_eq!(message.to_bytes().unwrap(), wire);

        let wire = [0x7e, 0x00, 0x44, 0x16, 0x5f, 0x00, 0x5f, 0x01, 0x21];
        let message = Nas5gsMessage::from_bytes(&wire).unwrap();
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(reject)) = &message else {
            panic!("expected REGISTRATION REJECT");
        };
        assert!(reject.t3346_value.is_none());
        assert_eq!(reject.unknown_ies.len(), 2);
        assert_eq!(message.to_bytes().unwrap(), wire);
    }

    #[test]
    fn relay_key_parameters_use_mandatory_lve_wire_format() {
        for (kind, value_len) in [(0x69, 20usize), (0x6a, 49)] {
            let mut wire = vec![0x7e, 0x00, kind, 0x01];
            wire.extend_from_slice(&(value_len as u16).to_be_bytes());
            wire.extend_from_slice(&vec![0; value_len]);
            let decoded = Nas5gsMessage::from_bytes(&wire).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), wire);
        }
    }

    #[test]
    fn shared_optional_ie_types_use_untagged_mandatory_wire_format() {
        let slice_auth = [
            0x7e, 0x00, 0x50, 0x01, 0x01, 0x00, 0x04, 0x03, 0x01, 0x00, 0x04,
        ];
        let service_auth = [0x2e, 0x01, 0x00, 0xd8, 0x00, 0x03, 0x00, 0x00, 0x00];
        for wire in [&slice_auth[..], &service_auth[..]] {
            let decoded = Nas5gsMessage::from_bytes(wire).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), wire);
        }
    }

    #[test]
    fn interleaved_optional_ies_keep_original_order() {
        let wire = [
            0x7e, 0x00, 0x54, 0x40, 0x01, 0xaa, 0x49, 0x01, 0x00, 0x43, 0x01, 0x80,
        ];
        let message = decode_nas_5gs_message(&wire).unwrap();
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), wire);
    }

    #[test]
    fn malformed_n3qai_is_ignored_and_preserved_verbatim() {
        let wire = hex::decode("2e0101c211000901000631310101ff010603f42403f42470000601010101ff00")
            .unwrap();
        let message = decode_nas_5gs_message(&wire).unwrap();
        let Nas5gsMessage::Gsm(_, Nas5gsmMessage::PduSessionEstablishmentAccept(accept)) = &message
        else {
            panic!("expected PDU SESSION ESTABLISHMENT ACCEPT");
        };
        assert!(accept.n3_qai.is_none());
        assert!(accept.unknown_ies.iter().any(|ie| ie.iei == 0x70));
        assert!(message.validate().iter().any(|finding| {
            finding.field == "unknown_ies" && finding.message.contains("malformed")
        }));
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), wire);
    }

    #[test]
    fn ciphered_envelope_round_trips_without_keys() {
        let wire = [0x7e, 0x02, 0, 0, 0, 0, 0, 0xff, 0xee];
        let message = decode_nas_5gs_message(&wire).unwrap();
        assert!(matches!(
            message,
            Nas5gsMessage::SecurityProtected(_, ref inner)
                if matches!(inner.as_ref(), Nas5gsMessage::Opaque(data) if data == &[0xff, 0xee])
        ));
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), wire);
    }

    #[test]
    fn ciphered_header_cannot_carry_cleartext() {
        let plain = Nas5gsMessage::new_5gmm(Nas5gmmMessage::DeregistrationAcceptFromUe(
            NasDeregistrationAcceptFromUe::new(),
        ));
        let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
        assert!(Nas5gsMessage::protect(plain.clone(), sht, 0, 0).is_err());
        let wrapped = Nas5gsMessage::SecurityProtected(
            Nas5gsSecurityHeader {
                extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM,
                security_header_type: sht,
                message_authentication_code: 0,
                sequence_number: 0,
            },
            Box::new(plain),
        );
        assert!(encode_nas_5gs_message(&wrapped).is_err());
    }

    #[test]
    fn empty_message_preserves_unknown_optional_ie() {
        let wire = [0x7e, 0x00, 0x46, 0xff];
        let message = decode_nas_5gs_message(&wire).unwrap();
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), wire);
    }

    #[test]
    fn service_request_uses_all_four_service_type_bits() {
        let wire = hex::decode("7e004ca1000704000000000000").unwrap();
        let mut message = decode_nas_5gs_message(&wire).unwrap();
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceRequest(request)) = &mut message else {
            panic!("expected SERVICE REQUEST");
        };
        assert_eq!(request.service_type_raw(), 0x0a);
        assert_eq!(
            request.service_type(),
            Some(crate::nas_5gs::ie::ServiceType::Data)
        );

        request.set_service_type(crate::nas_5gs::ie::ServiceType::Data);
        assert_eq!(request.ngksi.value, 0x11);
        let mut canonical = wire;
        canonical[3] = 0x11;
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), canonical);
    }

    #[test]
    fn malformed_known_optional_ie_is_ignored_by_receiver() {
        let wire = hex::decode("7e004201015e00").unwrap();
        let message = decode_nas_5gs_message(&wire).unwrap();
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = message else {
            panic!("expected REGISTRATION ACCEPT");
        };
        assert!(accept.t3512_value.is_none());
    }

    #[test]
    fn message_table_minimum_ignores_contextually_short_optional_ie() {
        // Access technology utilization control has a whole-IE minimum of 4
        // here, but the same type has a valid two-octet removal form elsewhere.
        let wire = hex::decode("7e004201016300").unwrap();
        let message = decode_nas_5gs_message(&wire).unwrap();
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) = message else {
            panic!("expected REGISTRATION ACCEPT");
        };
        assert!(accept.access_technology_utilization_control.is_none());
        assert!(accept.unknown_ies.iter().any(|ie| ie.iei == 0x63));
    }

    #[test]
    fn message_table_maximum_is_checked_per_occurrence() {
        let wire =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        let mut message = decode_nas_5gs_message(&wire).unwrap();
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(request)) = &mut message
        else {
            panic!("expected REGISTRATION REQUEST");
        };
        // 37 valid length-one S-NSSAIs occupy 74 value octets. That fits the
        // type-wide configured-NSSAI maximum, but exceeds Requested NSSAI's
        // message-table maximum of 74 whole octets (72 value octets).
        request.requested_nssai = Some(NasNssai::new([1, 1].repeat(37)));
        assert!(request.requested_nssai.as_ref().unwrap().is_well_formed());
        assert!(message.validate().iter().any(|finding| {
            finding.severity == crate::common::Severity::Error
                && finding.field == "requested_nssai"
                && finding.message.contains("message-table length")
        }));
    }

    #[test]
    fn malformed_mandatory_suci_is_rejected() {
        for wire in [
            // Reserved protection-scheme identifier 3.
            "7e00417900090102f839f0ff0301aa",
            // Network-specific SUCI with two at-signs in the NAI.
            "7e004179000b1162616440407265616c6d",
            // Null-scheme MSIN containing non-BCD nibbles.
            "7e00417900090102f839f0ff0000aa",
            // Binary NAS HNPKI 255, reserved by TS 24.501 table 9.11.3.4.1.
            "7e00417900090102f839f0ff01ff21",
        ] {
            assert!(matches!(
                Nas5gsMessage::from_bytes(&hex::decode(wire).unwrap()),
                Err(NasError::InvalidMandatoryIe(_))
            ));
        }
    }

    #[test]
    fn malformed_mandatory_registration_result_is_rejected() {
        let wire = hex::decode("7e004200").unwrap();
        assert!(matches!(
            decode_nas_5gs_message(&wire),
            Err(NasError::InvalidMandatoryIe(_))
        ));
    }

    #[test]
    fn sender_validation_rejects_excess_network_feature_support() {
        let wire = hex::decode("7e0042010121050000000000").unwrap();
        let message = decode_nas_5gs_message(&wire).unwrap();
        assert!(message.validate().iter().any(|finding| {
            finding.severity == crate::common::Severity::Error
                && finding.field == "fgs_network_feature_support"
        }));
    }

    #[test]
    fn mobile_originated_qos_flow_description_rejects_eps_bearer_identity() {
        let wire = hex::decode("2e0101c9790006012041070150").unwrap();
        let message = decode_nas_5gs_message(&wire).unwrap();
        assert!(message.validate().iter().any(|finding| {
            finding.field == "Requested QoS flow descriptions"
                && finding.severity == crate::common::Severity::Error
        }));
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), wire);
    }

    #[test]
    fn malformed_qos_flow_description_is_ignored_by_receiver() {
        let wire = hex::decode("2e0101c979000701204101020900").unwrap();
        let message = decode_nas_5gs_message(&wire).unwrap();
        let Nas5gsMessage::Gsm(_, Nas5gsmMessage::PduSessionModificationRequest(request)) = message
        else {
            panic!("expected PDU SESSION MODIFICATION REQUEST");
        };
        assert!(request.requested_qos_flow_descriptions.is_none());
    }

    #[test]
    fn legacy_modification_complete_cause_is_receive_only() {
        let wire = hex::decode("2e0101cc591a").unwrap();
        let message = decode_nas_5gs_message(&wire).unwrap();
        assert!(message.validate().iter().any(|finding| {
            finding.severity == crate::common::Severity::Error && finding.field == "5GSM cause"
        }));
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), wire);
    }

    #[test]
    fn reserved_service_type_is_receiver_fallback_but_sender_error() {
        let wire = hex::decode("7e004ca1000704000000000000").unwrap();
        let mut message = decode_nas_5gs_message(&wire).unwrap();
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceRequest(request)) = &mut message else {
            panic!("expected SERVICE REQUEST");
        };
        request.ngksi.value = 0xc1;
        assert_eq!(request.service_type(), None);
        assert!(message.validate().iter().any(|finding| {
            finding.severity == crate::common::Severity::Error && finding.field == "Service type"
        }));
    }

    #[test]
    fn reserved_5gsm_pti_is_encodable_but_rejected_on_receipt() {
        // Negative tests can send PTI 255; a receiver rejects it on decode.
        let header = Nas5gsmHeader::new(Nas5gsmMessageType::PduSessionEstablishmentRequest, 1, 255);
        let mut buffer = BytesMut::new();
        header.encode(&mut buffer).unwrap();
        assert_eq!(buffer.as_ref(), [0x2e, 1, 255, 193]);
        assert!(Nas5gsmHeader::decode(&mut Bytes::from_static(&[0x2e, 1, 255, 193])).is_err());
    }

    #[test]
    fn reserved_5gsm_pdu_session_identity_is_rejected_on_receipt() {
        let wire = hex::decode("2e1001d4").unwrap();
        assert!(decode_nas_5gs_message(&wire).is_err());

        let message = Nas5gsMessage::Gsm(
            Nas5gsmHeader::new(Nas5gsmMessageType::PduSessionReleaseComplete, 16, 1),
            Nas5gsmMessage::PduSessionReleaseComplete(NasPduSessionReleaseComplete::new()),
        );
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), wire);
    }
}
