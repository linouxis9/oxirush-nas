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

//! EPS NAS message structs, headers, and codec functions.
//!
//! This is **Layer 2** of the EPS codec. Each EMM and ESM message is a struct
//! defined by the shared `nas_message!` macro with:
//!
//! - **Mandatory fields** — passed to `new()` with getters and value helpers.
//! - **Optional fields** — set through `set_*()` builder methods.
//! - **`Encode`/`Decode` implementations** — IEI-based dispatch on the wire.
//!
//! [`NasEpsMessage`] wraps EMM, ESM, a security envelope, or a special EMM
//! header form. Use [`decode_nas_eps_message()`] and
//! [`encode_nas_eps_message()`] as the main entry points.

pub use crate::common::UnknownIe;
use crate::common::{Decode, Direction, Encode, NasError, Result, helpers};
use crate::common::{nas_message, nas_message_impl_default};
use crate::nas_eps::message_types::*;
use crate::nas_eps::types::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

// TS 24.007 §11.2.4 assigns 0x78..=0x7f to EPS TLV-E IEs.
const UNKNOWN_TLVE_START: u8 = 0x78;

/// Length of an EPS security header including MAC and sequence number.
pub const EPS_SECURITY_HEADER_LEN: usize = 6;

/// EPS security header. The payload following it may be encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasEpsSecurityHeader {
    /// Security header type.
    pub security_header_type: NasEpsSecurityHeaderType,
    /// Message authentication code.
    pub message_authentication_code: u32,
    /// Sequence number (eight LSBs of the NAS COUNT).
    pub sequence_number: u8,
}

impl Encode for NasEpsSecurityHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if matches!(
            self.security_header_type,
            NasEpsSecurityHeaderType::PlainNasMessage | NasEpsSecurityHeaderType::ServiceRequest
        ) {
            return Err(NasError::EncodingError(
                "Invalid EPS security envelope type".into(),
            ));
        }
        buffer.put_u8(((self.security_header_type as u8) << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR);
        buffer.put_u32(self.message_authentication_code);
        buffer.put_u8(self.sequence_number);
        Ok(())
    }
}

impl Decode for NasEpsSecurityHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < EPS_SECURITY_HEADER_LEN {
            return Err(NasError::MessageTooShort);
        }
        let first = buffer.get_u8();
        if first & 0x0F != EPS_EMM_PROTOCOL_DISCRIMINATOR {
            return Err(NasError::DecodingError(format!(
                "Invalid EPS security header 0x{first:02X}"
            )));
        }
        let security_header_type = NasEpsSecurityHeaderType::try_from(first >> 4)?;
        if matches!(
            security_header_type,
            NasEpsSecurityHeaderType::PlainNasMessage | NasEpsSecurityHeaderType::ServiceRequest
        ) {
            return Err(NasError::DecodingError(
                "Invalid EPS security envelope type".into(),
            ));
        }
        Ok(Self {
            security_header_type,
            message_authentication_code: buffer.get_u32(),
            sequence_number: buffer.get_u8(),
        })
    }
}

// BEGIN TS24301 MESSAGES
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

nas_message! {
    /// Attach Accept (TS 24.301 §8.2.1).
    pub struct NasAttachAccept {
        mandatory {
            eps_attach_result: NasEpsAttachResult [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            t3412_value: NasT3412Value {wire_len 1, 1},
            tai_list: NasTaiList {wire_len 7, 97},
            esm_message_container: NasEsmMessageContainer {wire_len 5, usize::MAX},
        }
        optional {
            0x50 => guti: NasEpsMobileIdentity [opt_type] {wire_len 13, 13},
            0x13 => location_area_identification: NasLocationAreaIdentification {wire_len 6, 6},
            0x23 => ms_identity: NasMobileIdentity [opt_type] {wire_len 7, 10},
            0x53 => emm_cause: NasEmmCause [opt_type] {wire_len 2, 2},
            0x17 => t3402_value: NasT3402Value [opt_type] {wire_len 2, 2},
            0x59 => t3423_value: NasT3423Value {wire_len 2, 2},
            0x4A => equivalent_plmns: NasEquivalentPlmns {wire_len 5, 47},
            0x34 => emergency_number_list: NasEmergencyNumberList {wire_len 5, 50},
            0x64 => eps_network_feature_support: NasEpsNetworkFeatureSupport {wire_len 3, 5},
            0xF0 => additional_update_result: NasAdditionalUpdateResult [tv1] {wire_len 1, 1},
            0x5E => t3412_extended_value: NasT3412ExtendedValue {wire_len 3, 3},
            0x6A => t3324_value: NasT3324Value {wire_len 3, 3},
            0x6E => extended_drx_parameters: NasExtendedDrxParameters {wire_len 3, 3},
            0x65 => dcn_id: NasDcnId {wire_len 4, 4},
            0xE0 => sms_services_status: NasSmsServicesStatus [tv1] {wire_len 1, 1},
            0xD0 => non_3gpp_nw_provided_policies: NasNon3GppNwProvidedPolicies [tv1] {wire_len 1, 1},
            0x6B => t3448_value: NasT3448Value {wire_len 3, 3},
            0xC0 => network_policy: NasNetworkPolicy [tv1] {wire_len 1, 1},
            0x6C => t3447_value: NasT3447Value {wire_len 3, 3},
            0x7A => extended_emergency_number_list: NasExtendedEmergencyNumberList {wire_len 7, 65538},
            0x7C => ciphering_key_data: NasCipheringKeyData {wire_len 35, 2291},
            0x66 => ue_radio_capability_id: NasUeRadioCapabilityId {wire_len 3, usize::MAX},
            0xB0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x35 => negotiated_wus_assistance_information: NasNegotiatedWusAssistanceInformation {wire_len 3, 3},
            0x36 => negotiated_drx_parameter_in_nb_s1_mode: NasNegotiatedDrxParameterInNbS1Mode {wire_len 3, 3},
            0x38 => negotiated_imsi_offset: NasNegotiatedImsiOffset {wire_len 4, 4},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService {wire_len 8, 98},
            0x1F => unavailability_configuration: NasUnavailabilityConfiguration {wire_len 3, 9},
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 2, 5},
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters {wire_len 3, 257},
            0x22 => disaster_roaming_wait_range: NasDisasterRoamingWaitRange {wire_len 4, 4},
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange {wire_len 4, 4},
            0x25 => list_of_plmns_to_be_used_in_disaster_condition: NasListOfPlmnsToBeUsedInDisasterCondition {wire_len 2, usize::MAX},
        }
    }
}

nas_message! {
    /// Attach Complete (TS 24.301 §8.2.2).
    pub struct NasAttachComplete {
        mandatory {
            esm_message_container: NasEsmMessageContainer {wire_len 5, usize::MAX},
        }
        optional {
        }
    }
}

nas_message! {
    /// Attach Reject (TS 24.301 §8.2.3).
    pub struct NasAttachReject {
        mandatory {
            emm_cause: NasEmmCause {wire_len 1, 1},
        }
        optional {
            0x78 => esm_message_container: NasEsmMessageContainer [opt_type] {wire_len 6, usize::MAX},
            0x5F => t3346_value: NasT3346Value {wire_len 3, 3},
            0x16 => t3402_value: NasGprsTimer2 {wire_len 3, 3},
            0xA0 => extended_emm_cause: NasExtendedEmmCause [tv1] {wire_len 1, 1},
            0x1C => lower_bound_timer_value: NasLowerBoundTimerValue {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService {wire_len 8, 98},
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 2, 5},
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters {wire_len 3, 257},
        }
    }
}

nas_message! {
    /// Attach Request (TS 24.301 §8.2.4).
    pub struct NasAttachRequest {
        mandatory {
            eps_attach_type: NasEpsAttachType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
            eps_mobile_identity: NasEpsMobileIdentity {wire_len 5, 12},
            ue_network_capability: NasUeNetworkCapability {wire_len 3, 14},
            esm_message_container: NasEsmMessageContainer {wire_len 5, usize::MAX},
        }
        optional {
            0x19 => old_p_tmsi_signature: NasOldPTmsiSignature {wire_len 4, 4},
            0x50 => additional_guti: NasEpsMobileIdentity [opt_type] {wire_len 13, 13},
            0x52 => last_visited_registered_tai: NasLastVisitedRegisteredTai {wire_len 6, 6},
            0x5C => drx_parameter: NasDrxParameter {wire_len 3, 3},
            0x31 => ms_network_capability: NasMsNetworkCapability {wire_len 4, 10},
            0x13 => old_location_area_identification: NasLocationAreaIdentification {wire_len 6, 6},
            0x90 => tmsi_status: NasTmsiStatus [tv1] {wire_len 1, 1},
            0x11 => mobile_station_classmark_2: NasMobileStationClassmark2 {wire_len 5, 5},
            0x20 => mobile_station_classmark_3: NasMobileStationClassmark3 {wire_len 2, 34},
            0x40 => supported_codecs: NasSupportedCodecs {wire_len 5, usize::MAX},
            0xF0 => additional_update_type: NasAdditionalUpdateType [tv1] {wire_len 1, 1},
            0x5D => voice_domain_preference_and_ue_usage_setting: NasVoiceDomainPreferenceAndUeUsageSetting {wire_len 3, 3},
            0xD0 => device_properties: NasDeviceProperties [tv1] {wire_len 1, 1},
            0xE0 => old_guti_type: NasOldGutiType [tv1] {wire_len 1, 1},
            0xC0 => ms_network_feature_support: NasMsNetworkFeatureSupport [tv1] {wire_len 1, 1},
            0x10 => tmsi_based_nri_container: NasTmsiBasedNriContainer {wire_len 4, 4},
            0x6A => t3324_value: NasT3324Value {wire_len 3, 3},
            0x5E => t3412_extended_value: NasT3412ExtendedValue {wire_len 3, 3},
            0x6E => extended_drx_parameters: NasExtendedDrxParameters {wire_len 3, 3},
            0x6F => ue_additional_security_capability: NasUeAdditionalSecurityCapability {wire_len 6, 6},
            0x6D => ue_status: NasUeStatus {wire_len 3, 3},
            0x17 => additional_information_requested: NasAdditionalInformationRequested {wire_len 2, 2},
            0x32 => n1_ue_network_capability: NasN1UeNetworkCapability {wire_len 3, 15},
            0x34 => ue_radio_capability_id_availability: NasUeRadioCapabilityIdAvailability {wire_len 3, 3},
            0x35 => requested_wus_assistance_information: NasRequestedWusAssistanceInformation {wire_len 3, 3},
            0x36 => drx_parameter_in_nb_s1_mode: NasDrxParameterInNbS1Mode {wire_len 3, 3},
            0x38 => requested_imsi_offset: NasRequestedImsiOffset {wire_len 4, 4},
            0x26 => ue_determined_plmn_with_disaster_condition: NasUeDeterminedPlmnWithDisasterCondition {wire_len 5, 5},
        }
    }
}

nas_message! {
    /// Authentication Failure (TS 24.301 §8.2.5).
    pub struct NasAuthenticationFailure {
        mandatory {
            emm_cause: NasEmmCause {wire_len 1, 1},
        }
        optional {
            0x30 => authentication_failure_parameter: NasAuthenticationFailureParameter {wire_len 16, 16},
        }
    }
}

nas_message! {
    /// Authentication Reject (TS 24.301 §8.2.6).
    pub struct NasAuthenticationReject {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// Authentication Request (TS 24.301 §8.2.7).
    pub struct NasAuthenticationRequest {
        mandatory {
            nas_key_set_identifier_asme: NasKeySetIdentifier [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            authentication_parameter_rand_eps_challenge: NasAuthenticationParameterRandEpsChallenge {wire_len 16, 16},
            authentication_parameter_autn_eps_challenge: NasAuthenticationParameterAutnEpsChallenge {wire_len 17, 17},
        }
        optional {
        }
    }
}

nas_message! {
    /// Authentication Response (TS 24.301 §8.2.8).
    pub struct NasAuthenticationResponse {
        mandatory {
            authentication_response_parameter: NasAuthenticationResponseParameter {wire_len 5, 17},
        }
        optional {
        }
    }
}

nas_message! {
    /// CS Service Notification (TS 24.301 §8.2.9).
    pub struct NasCsServiceNotification {
        mandatory {
            paging_identity: NasPagingIdentity {wire_len 1, 1},
        }
        optional {
            0x60 => cli: NasCli {wire_len 3, 14},
            0x61 => ss_code: NasSsCode {wire_len 2, 2},
            0x62 => lcs_indicator: NasLcsIndicator {wire_len 2, 2},
            0x63 => lcs_client_identity: NasLcsClientIdentity {wire_len 3, 257},
        }
    }
}

nas_message! {
    /// Detach Accept (TS 24.301 §8.2.10.1).
    pub struct NasDetachAccept {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// Detach Request (UE originating) (TS 24.301 §8.2.11.1).
    pub struct NasDetachRequestFromUe {
        mandatory {
            detach_type: NasDetachType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
            eps_mobile_identity: NasEpsMobileIdentity {wire_len 5, 12},
        }
        optional {
        }
    }
}

nas_message! {
    /// Detach Request (UE terminated) (TS 24.301 §8.2.11.2).
    pub struct NasDetachRequestToUe {
        mandatory {
            detach_type: NasDetachType [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
        }
        optional {
            0x53 => emm_cause: NasEmmCause [opt_type] {wire_len 2, 2},
            0x1C => lower_bound_timer_value: NasLowerBoundTimerValue {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService {wire_len 8, 98},
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 2, 5},
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters {wire_len 3, 257},
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange {wire_len 4, 4},
        }
    }
}

nas_message! {
    /// Downlink NAS Transport (TS 24.301 §8.2.12).
    pub struct NasDownlinkNasTransport {
        mandatory {
            nas_message_container: NasMessageContainer {wire_len 3, 252},
        }
        optional {
        }
    }
}

nas_message! {
    /// EMM Information (TS 24.301 §8.2.13).
    pub struct NasEmmInformation {
        mandatory {
        }
        optional {
            0x43 => full_name_for_network: NasNetworkName {wire_len 3, usize::MAX},
            0x45 => short_name_for_network: NasNetworkName {wire_len 3, usize::MAX},
            0x46 => local_time_zone: NasLocalTimeZone {wire_len 2, 2},
            0x47 => universal_time_and_local_time_zone: NasUniversalTimeAndLocalTimeZone {wire_len 8, 8},
            0x49 => network_daylight_saving_time: NasNetworkDaylightSavingTime {wire_len 3, 3},
        }
    }
}

nas_message! {
    /// EMM Status (TS 24.301 §8.2.14).
    pub struct NasEmmStatus {
        mandatory {
            emm_cause: NasEmmCause {wire_len 1, 1},
        }
        optional {
        }
    }
}

nas_message! {
    /// Extended Service Request (TS 24.301 §8.2.15).
    pub struct NasExtendedServiceRequest {
        mandatory {
            service_type: NasServiceType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
            m_tmsi: NasMobileIdentity {wire_len 6, 6},
        }
        optional {
            0xB0 => csfb_response: NasCsfbResponse [tv1] {wire_len 1, 1},
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus {wire_len 4, 4},
            0xD0 => device_properties: NasDeviceProperties [tv1] {wire_len 1, 1},
            0x29 => ue_request_type: NasUeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: NasPagingRestriction {wire_len 3, 5},
        }
    }
}

nas_message! {
    /// GUTI Reallocation Command (TS 24.301 §8.2.16).
    pub struct NasGutiReallocationCommand {
        mandatory {
            guti: NasEpsMobileIdentity {wire_len 12, 12},
        }
        optional {
            0x54 => tai_list: NasTaiList [opt_type] {wire_len 8, 98},
            0x65 => dcn_id: NasDcnId {wire_len 4, 4},
            0x66 => ue_radio_capability_id: NasUeRadioCapabilityId {wire_len 3, usize::MAX},
            0xB0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 2, 5},
        }
    }
}

nas_message! {
    /// GUTI Reallocation Complete (TS 24.301 §8.2.17).
    pub struct NasGutiReallocationComplete {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// Identity Request (TS 24.301 §8.2.18).
    pub struct NasIdentityRequest {
        mandatory {
            identity_type: NasIdentityType [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
        }
        optional {
        }
    }
}

nas_message! {
    /// Identity Response (TS 24.301 §8.2.19).
    pub struct NasIdentityResponse {
        mandatory {
            mobile_identity: NasMobileIdentity {wire_len 4, 10},
        }
        optional {
        }
    }
}

nas_message! {
    /// Security Mode Command (TS 24.301 §8.2.20).
    pub struct NasSecurityModeCommand {
        mandatory {
            selected_nas_security_algorithms: NasSelectedNasSecurityAlgorithms {wire_len 1, 1},
            nas_key_set_identifier: NasKeySetIdentifier [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            replayed_ue_security_capabilities: NasReplayedUeSecurityCapabilities {wire_len 3, 6},
        }
        optional {
            0xC0 => imeisv_request: NasImeisvRequest [tv1] {wire_len 1, 1},
            0x55 => replayed_nonce_ue: NasReplayedNonceUe {wire_len 5, 5},
            0x56 => nonce_mme: NasNonceMme {wire_len 5, 5},
            0x4F => hash_mme: NasHashMme {wire_len 10, 10},
            0x6F => replayed_ue_additional_security_capability: NasUeAdditionalSecurityCapability {wire_len 6, 6},
            0x37 => ue_radio_capability_id_request: NasUeRadioCapabilityIdRequest {wire_len 3, 3},
            0xD0 => ue_coarse_location_information_request: NasUeCoarseLocationInformationRequest [tv1] {wire_len 1, 1},
        }
    }
}

nas_message! {
    /// Security Mode Complete (TS 24.301 §8.2.21).
    pub struct NasSecurityModeComplete {
        mandatory {
        }
        optional {
            0x23 => imeisv: NasMobileIdentity [opt_type] {wire_len 11, 11},
            0x79 => replayed_nas_message_container: NasReplayedNasMessageContainer {wire_len 3, usize::MAX},
            0x66 => ue_radio_capability_id: NasUeRadioCapabilityId {wire_len 3, usize::MAX},
            0x67 => ue_coarse_location_information: NasUeCoarseLocationInformation {wire_len 8, 8},
        }
    }
}

nas_message! {
    /// Security Mode Reject (TS 24.301 §8.2.22).
    pub struct NasSecurityModeReject {
        mandatory {
            emm_cause: NasEmmCause {wire_len 1, 1},
        }
        optional {
        }
    }
}

nas_message! {
    /// Service Reject (TS 24.301 §8.2.24).
    pub struct NasServiceReject {
        mandatory {
            emm_cause: NasEmmCause {wire_len 1, 1},
        }
        optional {
            0x5B => t3442_value: NasT3442Value {wire_len 2, 2},
            0x5F => t3346_value: NasT3346Value {wire_len 3, 3},
            0x6B => t3448_value: NasT3448Value {wire_len 3, 3},
            0x1C => lower_bound_timer_value: NasLowerBoundTimerValue {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService {wire_len 8, 98},
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 2, 5},
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters {wire_len 3, 257},
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange {wire_len 4, 4},
        }
    }
}

nas_message! {
    /// Tracking Area Update Accept (TS 24.301 §8.2.26).
    pub struct NasTrackingAreaUpdateAccept {
        mandatory {
            eps_update_result: NasEpsUpdateResult [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
        }
        optional {
            0x5A => t3412_value: NasT3412Value [opt_type] {wire_len 2, 2},
            0x50 => guti: NasEpsMobileIdentity [opt_type] {wire_len 13, 13},
            0x54 => tai_list: NasTaiList [opt_type] {wire_len 8, 98},
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus {wire_len 4, 4},
            0x13 => location_area_identification: NasLocationAreaIdentification {wire_len 6, 6},
            0x23 => ms_identity: NasMobileIdentity [opt_type] {wire_len 7, 10},
            0x53 => emm_cause: NasEmmCause [opt_type] {wire_len 2, 2},
            0x17 => t3402_value: NasT3402Value [opt_type] {wire_len 2, 2},
            0x59 => t3423_value: NasT3423Value {wire_len 2, 2},
            0x4A => equivalent_plmns: NasEquivalentPlmns {wire_len 5, 47},
            0x34 => emergency_number_list: NasEmergencyNumberList {wire_len 5, 50},
            0x64 => eps_network_feature_support: NasEpsNetworkFeatureSupport {wire_len 3, 5},
            0xF0 => additional_update_result: NasAdditionalUpdateResult [tv1] {wire_len 1, 1},
            0x5E => t3412_extended_value: NasT3412ExtendedValue {wire_len 3, 3},
            0x6A => t3324_value: NasT3324Value {wire_len 3, 3},
            0x6E => extended_drx_parameters: NasExtendedDrxParameters {wire_len 3, 3},
            0x68 => header_compression_configuration_status: NasHeaderCompressionConfigurationStatus {wire_len 4, 4},
            0x65 => dcn_id: NasDcnId {wire_len 4, 4},
            0xE0 => sms_services_status: NasSmsServicesStatus [tv1] {wire_len 1, 1},
            0xD0 => non_3gpp_nw_policies: NasNon3GppNwProvidedPolicies [tv1] {wire_len 1, 1},
            0x6B => t3448_value: NasT3448Value {wire_len 3, 3},
            0xC0 => network_policy: NasNetworkPolicy [tv1] {wire_len 1, 1},
            0x6C => t3447_value: NasT3447Value {wire_len 3, 3},
            0x7A => extended_emergency_number_list: NasExtendedEmergencyNumberList {wire_len 7, 65538},
            0x7C => ciphering_key_data: NasCipheringKeyData {wire_len 35, 2291},
            0x66 => ue_radio_capability_id: NasUeRadioCapabilityId {wire_len 3, usize::MAX},
            0xB0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x35 => negotiated_wus_assistance_information: NasNegotiatedWusAssistanceInformation {wire_len 3, 3},
            0x36 => negotiated_drx_parameter_in_nb_s1_mode: NasNegotiatedDrxParameterInNbS1Mode {wire_len 3, 3},
            0x38 => negotiated_imsi_offset: NasNegotiatedImsiOffset {wire_len 4, 4},
            0x37 => eps_additional_request_result: NasEpsAdditionalRequestResult {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService {wire_len 8, 98},
            0x39 => maximum_time_offset: NasMaximumTimeOffset {wire_len 3, 3},
            0x1F => unavailability_configuration: NasUnavailabilityConfiguration {wire_len 3, 9},
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 2, 5},
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters {wire_len 3, 257},
            0x22 => disaster_roaming_wait_range: NasDisasterRoamingWaitRange {wire_len 4, 4},
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange {wire_len 4, 4},
            0x25 => list_of_plmns_to_be_used_in_disaster_condition: NasListOfPlmnsToBeUsedInDisasterCondition {wire_len 2, usize::MAX},
        }
    }
}

nas_message! {
    /// Tracking Area Update Complete (TS 24.301 §8.2.27).
    pub struct NasTrackingAreaUpdateComplete {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// Tracking Area Update Reject (TS 24.301 §8.2.28).
    pub struct NasTrackingAreaUpdateReject {
        mandatory {
            emm_cause: NasEmmCause {wire_len 1, 1},
        }
        optional {
            0x5F => t3346_value: NasT3346Value {wire_len 3, 3},
            0xA0 => extended_emm_cause: NasExtendedEmmCause [tv1] {wire_len 1, 1},
            0x1C => lower_bound_timer_value: NasLowerBoundTimerValue {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService {wire_len 8, 98},
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl {wire_len 2, 5},
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters {wire_len 3, 257},
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange {wire_len 4, 4},
        }
    }
}

nas_message! {
    /// Tracking Area Update Request (TS 24.301 §8.2.29).
    pub struct NasTrackingAreaUpdateRequest {
        mandatory {
            eps_update_type: NasEpsUpdateType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
            old_guti: NasEpsMobileIdentity {wire_len 12, 12},
        }
        optional {
            0xB0 => non_current_native_nas_key_set_identifier: NasNonCurrentNativeNasKeySetIdentifier [tv1] {wire_len 1, 1},
            0x80 => gprs_ciphering_key_sequence_number: NasGprsCipheringKeySequenceNumber [tv1] {wire_len 1, 1},
            0x19 => old_p_tmsi_signature: NasOldPTmsiSignature {wire_len 4, 4},
            0x50 => additional_guti: NasEpsMobileIdentity [opt_type] {wire_len 13, 13},
            0x55 => nonce_ue: NasNonceUe {wire_len 5, 5},
            0x58 => ue_network_capability: NasUeNetworkCapability [opt_type] {wire_len 4, 15},
            0x52 => last_visited_registered_tai: NasLastVisitedRegisteredTai {wire_len 6, 6},
            0x5C => drx_parameter: NasDrxParameter {wire_len 3, 3},
            0xA0 => ue_radio_capability_information_update_needed: NasUeRadioCapabilityInformationUpdateNeeded [tv1] {wire_len 1, 1},
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus {wire_len 4, 4},
            0x31 => ms_network_capability: NasMsNetworkCapability {wire_len 4, 10},
            0x13 => old_location_area_identification: NasLocationAreaIdentification {wire_len 6, 6},
            0x90 => tmsi_status: NasTmsiStatus [tv1] {wire_len 1, 1},
            0x11 => mobile_station_classmark_2: NasMobileStationClassmark2 {wire_len 5, 5},
            0x20 => mobile_station_classmark_3: NasMobileStationClassmark3 {wire_len 2, 34},
            0x40 => supported_codecs: NasSupportedCodecs {wire_len 5, usize::MAX},
            0xF0 => additional_update_type: NasAdditionalUpdateType [tv1] {wire_len 1, 1},
            0x5D => voice_domain_preference_and_ue_usage_setting: NasVoiceDomainPreferenceAndUeUsageSetting {wire_len 3, 3},
            0xE0 => old_guti_type: NasOldGutiType [tv1] {wire_len 1, 1},
            0xD0 => device_properties: NasDeviceProperties [tv1] {wire_len 1, 1},
            0xC0 => ms_network_feature_support: NasMsNetworkFeatureSupport [tv1] {wire_len 1, 1},
            0x10 => tmsi_based_nri_container: NasTmsiBasedNriContainer {wire_len 4, 4},
            0x6A => t3324_value: NasT3324Value {wire_len 3, 3},
            0x5E => t3412_extended_value: NasT3412ExtendedValue {wire_len 3, 3},
            0x6E => extended_drx_parameters: NasExtendedDrxParameters {wire_len 3, 3},
            0x6F => ue_additional_security_capability: NasUeAdditionalSecurityCapability {wire_len 6, 6},
            0x6D => ue_status: NasUeStatus {wire_len 3, 3},
            0x17 => additional_information_requested: NasAdditionalInformationRequested {wire_len 2, 2},
            0x32 => n1_ue_network_capability: NasN1UeNetworkCapability {wire_len 3, 15},
            0x34 => ue_radio_capability_id_availability: NasUeRadioCapabilityIdAvailability {wire_len 3, 3},
            0x35 => requested_wus_assistance_information: NasRequestedWusAssistanceInformation {wire_len 3, 3},
            0x36 => drx_parameter_in_nb_s1_mode: NasDrxParameterInNbS1Mode {wire_len 3, 3},
            0x38 => requested_imsi_offset: NasRequestedImsiOffset {wire_len 4, 4},
            0x29 => ue_request_type: NasUeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: NasPagingRestriction {wire_len 3, 5},
            0x30 => unavailability_information: NasUnavailabilityInformation {wire_len 3, 9},
            0x26 => ue_determined_plmn_with_disaster_condition: NasUeDeterminedPlmnWithDisasterCondition {wire_len 5, 5},
        }
    }
}

nas_message! {
    /// Uplink NAS Transport (TS 24.301 §8.2.30).
    pub struct NasUplinkNasTransport {
        mandatory {
            nas_message_container: NasMessageContainer {wire_len 3, 252},
        }
        optional {
        }
    }
}

nas_message! {
    /// Downlink Generic NAS Transport (TS 24.301 §8.2.31).
    pub struct NasDownlinkGenericNasTransport {
        mandatory {
            generic_message_container_type: NasGenericMessageContainerType {wire_len 1, 1},
            generic_message_container: NasGenericMessageContainer {wire_len 3, usize::MAX},
        }
        optional {
            0x65 => additional_information: NasAdditionalInformation {wire_len 3, usize::MAX},
        }
    }
}

nas_message! {
    /// Uplink Generic NAS Transport (TS 24.301 §8.2.32).
    pub struct NasUplinkGenericNasTransport {
        mandatory {
            generic_message_container_type: NasGenericMessageContainerType {wire_len 1, 1},
            generic_message_container: NasGenericMessageContainer {wire_len 3, usize::MAX},
        }
        optional {
            0x65 => additional_information: NasAdditionalInformation {wire_len 3, usize::MAX},
        }
    }
}

nas_message! {
    /// Control Plane Service Request (TS 24.301 §8.2.33).
    pub struct NasControlPlaneServiceRequest {
        mandatory {
            control_plane_service_type: NasControlPlaneServiceType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
        }
        optional {
            0x78 => esm_message_container: NasEsmMessageContainer [opt_type] {wire_len 3, usize::MAX},
            0x67 => nas_message_container: NasMessageContainer [opt_type] {wire_len 4, 253},
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus {wire_len 4, 4},
            0xD0 => device_properties: NasDeviceProperties [tv1] {wire_len 1, 1},
            0x29 => ue_request_type: NasUeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: NasPagingRestriction {wire_len 3, 5},
        }
    }
}

nas_message! {
    /// Service Accept (TS 24.301 §8.2.34).
    pub struct NasServiceAccept {
        mandatory {
        }
        optional {
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus {wire_len 4, 4},
            0x6B => t3448_value: NasT3448Value {wire_len 3, 3},
            0x37 => eps_additional_request_result: NasEpsAdditionalRequestResult {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService {wire_len 8, 98},
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters {wire_len 3, 257},
        }
    }
}

nas_message! {
    /// Activate Dedicated EPS Bearer Context Accept (TS 24.301 §8.3.1).
    pub struct NasActivateDedicatedEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Activate Dedicated EPS Bearer Context Reject (TS 24.301 §8.3.2).
    pub struct NasActivateDedicatedEpsBearerContextReject {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Activate Dedicated EPS Bearer Context Request (TS 24.301 §8.3.3).
    pub struct NasActivateDedicatedEpsBearerContextRequest {
        mandatory {
            linked_eps_bearer_identity: NasLinkedEpsBearerIdentity [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            eps_qos: NasEpsQos {wire_len 2, 14},
            tft: NasTft {wire_len 2, 256},
        }
        optional {
            0x5D => transaction_identifier: NasTransactionIdentifier {wire_len 3, 4},
            0x30 => negotiated_qos: NasNegotiatedQos {wire_len 5, 22},
            0x32 => negotiated_llc_sapi: NasNegotiatedLlcSapi {wire_len 2, 2},
            0x80 => radio_priority: NasRadioPriority [tv1] {wire_len 1, 1},
            0x34 => packet_flow_identifier: NasPacketFlowIdentifier {wire_len 3, 3},
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => wlan_offload_indication: NasWlanOffloadIndication [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x5C => extended_eps_qos: NasExtendedEpsQos {wire_len 12, 12},
        }
    }
}

nas_message! {
    /// Activate Default EPS Bearer Context Accept (TS 24.301 §8.3.4).
    pub struct NasActivateDefaultEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Activate Default EPS Bearer Context Reject (TS 24.301 §8.3.5).
    pub struct NasActivateDefaultEpsBearerContextReject {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Activate Default EPS Bearer Context Request (TS 24.301 §8.3.6).
    pub struct NasActivateDefaultEpsBearerContextRequest {
        mandatory {
            eps_qos: NasEpsQos {wire_len 2, 14},
            access_point_name: NasAccessPointName {wire_len 2, 101},
            pdn_address: NasPdnAddress {wire_len 6, 14},
        }
        optional {
            0x5D => transaction_identifier: NasTransactionIdentifier {wire_len 3, 4},
            0x30 => negotiated_qos: NasNegotiatedQos {wire_len 5, 22},
            0x32 => negotiated_llc_sapi: NasNegotiatedLlcSapi {wire_len 2, 2},
            0x80 => radio_priority: NasRadioPriority [tv1] {wire_len 1, 1},
            0x34 => packet_flow_identifier: NasPacketFlowIdentifier {wire_len 3, 3},
            0x5E => apn_ambr: NasApnAmbr {wire_len 4, 8},
            0x58 => esm_cause: NasEsmCause [opt_type] {wire_len 2, 2},
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0xB0 => connectivity_type: NasConnectivityType [tv1] {wire_len 1, 1},
            0xC0 => wlan_offload_indication: NasWlanOffloadIndication [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x66 => header_compression_configuration: NasHeaderCompressionConfiguration {wire_len 5, 257},
            0x90 => control_plane_only_indication: NasControlPlaneOnlyIndication [tv1] {wire_len 1, 1},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x6E => serving_plmn_rate_control: NasServingPlmnRateControl {wire_len 4, 4},
            0x5F => extended_apn_ambr: NasExtendedApnAmbr {wire_len 8, 8},
        }
    }
}

nas_message! {
    /// Bearer Resource Allocation Reject (TS 24.301 §8.3.7).
    pub struct NasBearerResourceAllocationReject {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x37 => back_off_timer_value: NasBackOffTimerValue {wire_len 3, 3},
            0x6B => re_attempt_indicator: NasReAttemptIndicator {wire_len 3, 3},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Bearer Resource Allocation Request (TS 24.301 §8.3.8).
    pub struct NasBearerResourceAllocationRequest {
        mandatory {
            linked_eps_bearer_identity: NasLinkedEpsBearerIdentity [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            traffic_flow_aggregate: NasTrafficFlowAggregate {wire_len 2, 256},
            required_traffic_flow_qos: NasRequiredTrafficFlowQos {wire_len 2, 14},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => device_properties: NasDeviceProperties [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x5C => extended_eps_qos: NasExtendedEpsQos {wire_len 12, 12},
        }
    }
}

nas_message! {
    /// Bearer Resource Modification Reject (TS 24.301 §8.3.9).
    pub struct NasBearerResourceModificationReject {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x37 => back_off_timer_value: NasBackOffTimerValue {wire_len 3, 3},
            0x6B => re_attempt_indicator: NasReAttemptIndicator {wire_len 3, 3},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Bearer Resource Modification Request (TS 24.301 §8.3.10).
    pub struct NasBearerResourceModificationRequest {
        mandatory {
            eps_bearer_identity_for_packet_filter: NasLinkedEpsBearerIdentity [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            traffic_flow_aggregate: NasTrafficFlowAggregate {wire_len 2, 256},
        }
        optional {
            0x5B => required_traffic_flow_qos: NasRequiredTrafficFlowQos [opt_type] {wire_len 3, 15},
            0x58 => esm_cause: NasEsmCause [opt_type] {wire_len 2, 2},
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => device_properties: NasDeviceProperties [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x66 => header_compression_configuration: NasHeaderCompressionConfiguration {wire_len 5, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x5C => extended_eps_qos: NasExtendedEpsQos {wire_len 12, 12},
        }
    }
}

nas_message! {
    /// Deactivate EPS Bearer Context Accept (TS 24.301 §8.3.11).
    pub struct NasDeactivateEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Deactivate EPS Bearer Context Request (TS 24.301 §8.3.12).
    pub struct NasDeactivateEpsBearerContextRequest {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x37 => t3396_value: NasT3396Value {wire_len 3, 3},
            0xC0 => wlan_offload_indication: NasWlanOffloadIndication [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// ESM Dummy Message (TS 24.301 §8.3.12A).
    pub struct NasEsmDummyMessage {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM Information Request (TS 24.301 §8.3.13).
    pub struct NasEsmInformationRequest {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM Information Response (TS 24.301 §8.3.14).
    pub struct NasEsmInformationResponse {
        mandatory {
        }
        optional {
            0x28 => access_point_name: NasAccessPointName [opt_type] {wire_len 3, 102},
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// ESM Status (TS 24.301 §8.3.15).
    pub struct NasEsmStatus {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
        }
    }
}

nas_message! {
    /// Modify EPS Bearer Context Accept (TS 24.301 §8.3.16).
    pub struct NasModifyEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Modify EPS Bearer Context Reject (TS 24.301 §8.3.17).
    pub struct NasModifyEpsBearerContextReject {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Modify EPS Bearer Context Request (TS 24.301 §8.3.18).
    pub struct NasModifyEpsBearerContextRequest {
        mandatory {
        }
        optional {
            0x5B => new_eps_qos: NasNewEpsQos {wire_len 3, 15},
            0x36 => tft: NasTft [opt_type] {wire_len 3, 257},
            0x30 => new_qos: NasNewQos {wire_len 5, 22},
            0x32 => negotiated_llc_sapi: NasNegotiatedLlcSapi {wire_len 2, 2},
            0x80 => radio_priority: NasRadioPriority [tv1] {wire_len 1, 1},
            0x34 => packet_flow_identifier: NasPacketFlowIdentifier {wire_len 3, 3},
            0x5E => apn_ambr: NasApnAmbr {wire_len 4, 8},
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => wlan_offload_indication: NasWlanOffloadIndication [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x66 => header_compression_configuration: NasHeaderCompressionConfiguration {wire_len 5, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x5F => extended_apn_ambr: NasExtendedApnAmbr {wire_len 8, 8},
            0x5C => extended_eps_qos: NasExtendedEpsQos {wire_len 12, 12},
        }
    }
}

nas_message! {
    /// Notification (TS 24.301 §8.3.18A).
    pub struct NasNotification {
        mandatory {
            notification_indicator: NasNotificationIndicator {wire_len 2, 2},
        }
        optional {
        }
    }
}

nas_message! {
    /// PDN Connectivity Reject (TS 24.301 §8.3.19).
    pub struct NasPdnConnectivityReject {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x37 => back_off_timer_value: NasBackOffTimerValue {wire_len 3, 3},
            0x6B => re_attempt_indicator: NasReAttemptIndicator {wire_len 3, 3},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// PDN Connectivity Request (TS 24.301 §8.3.20).
    pub struct NasPdnConnectivityRequest {
        mandatory {
            request_type: NasRequestType [low_half_first],
            pdn_type: NasPdnType [high_half_last],
        }
        optional {
            0xD0 => esm_information_transfer_flag: NasEsmInformationTransferFlag [tv1] {wire_len 1, 1},
            0x28 => access_point_name: NasAccessPointName [opt_type] {wire_len 3, 102},
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => device_properties: NasDeviceProperties [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NasNbifomContainer {wire_len 3, 257},
            0x66 => header_compression_configuration: NasHeaderCompressionConfiguration {wire_len 5, 257},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// PDN Disconnect Reject (TS 24.301 §8.3.21).
    pub struct NasPdnDisconnectReject {
        mandatory {
            esm_cause: NasEsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// PDN Disconnect Request (TS 24.301 §8.3.22).
    pub struct NasPdnDisconnectRequest {
        mandatory {
            linked_eps_bearer_identity: NasLinkedEpsBearerIdentity [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Remote UE Report (TS 24.301 §8.3.23).
    pub struct NasRemoteUeReport {
        mandatory {
        }
        optional {
            0x79 => remote_ue_context_connected: NasRemoteUeContextConnected {wire_len 5, 65538},
            0x7A => remote_ue_context_disconnected: NasRemoteUeContextDisconnected {wire_len 5, 65538},
            0x6F => prose_key_management_function_address: NasProseKeyManagementFunctionAddress {wire_len 3, 19},
        }
    }
}

nas_message! {
    /// Remote UE Report Response (TS 24.301 §8.3.24).
    pub struct NasRemoteUeReportResponse {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM Data Transport (TS 24.301 §8.3.25).
    pub struct NasEsmDataTransport {
        mandatory {
            user_data_container: NasUserDataContainer {wire_len 2, usize::MAX},
        }
        optional {
            0xF0 => release_assistance_indication: NasReleaseAssistanceIndication [tv1] {wire_len 1, 1},
        }
    }
}

/// EMM message bodies (TS 24.301 §8.2).
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum NasEmmMessage {
    /// Attach Accept (§8.2.1).
    AttachAccept(NasAttachAccept),
    /// Attach Complete (§8.2.2).
    AttachComplete(NasAttachComplete),
    /// Attach Reject (§8.2.3).
    AttachReject(NasAttachReject),
    /// Attach Request (§8.2.4).
    AttachRequest(NasAttachRequest),
    /// Authentication Failure (§8.2.5).
    AuthenticationFailure(NasAuthenticationFailure),
    /// Authentication Reject (§8.2.6).
    AuthenticationReject(NasAuthenticationReject),
    /// Authentication Request (§8.2.7).
    AuthenticationRequest(NasAuthenticationRequest),
    /// Authentication Response (§8.2.8).
    AuthenticationResponse(NasAuthenticationResponse),
    /// CS Service Notification (§8.2.9).
    CsServiceNotification(NasCsServiceNotification),
    /// Detach Accept (§8.2.10.1).
    DetachAccept(NasDetachAccept),
    /// Detach Request (UE originating) (§8.2.11.1).
    DetachRequestFromUe(NasDetachRequestFromUe),
    /// Detach Request (UE terminated) (§8.2.11.2).
    DetachRequestToUe(NasDetachRequestToUe),
    /// Downlink NAS Transport (§8.2.12).
    DownlinkNasTransport(NasDownlinkNasTransport),
    /// EMM Information (§8.2.13).
    EmmInformation(NasEmmInformation),
    /// EMM Status (§8.2.14).
    EmmStatus(NasEmmStatus),
    /// Extended Service Request (§8.2.15).
    ExtendedServiceRequest(NasExtendedServiceRequest),
    /// GUTI Reallocation Command (§8.2.16).
    GutiReallocationCommand(NasGutiReallocationCommand),
    /// GUTI Reallocation Complete (§8.2.17).
    GutiReallocationComplete(NasGutiReallocationComplete),
    /// Identity Request (§8.2.18).
    IdentityRequest(NasIdentityRequest),
    /// Identity Response (§8.2.19).
    IdentityResponse(NasIdentityResponse),
    /// Security Mode Command (§8.2.20).
    SecurityModeCommand(NasSecurityModeCommand),
    /// Security Mode Complete (§8.2.21).
    SecurityModeComplete(NasSecurityModeComplete),
    /// Security Mode Reject (§8.2.22).
    SecurityModeReject(NasSecurityModeReject),
    /// Service Reject (§8.2.24).
    ServiceReject(NasServiceReject),
    /// Tracking Area Update Accept (§8.2.26).
    TrackingAreaUpdateAccept(NasTrackingAreaUpdateAccept),
    /// Tracking Area Update Complete (§8.2.27).
    TrackingAreaUpdateComplete(NasTrackingAreaUpdateComplete),
    /// Tracking Area Update Reject (§8.2.28).
    TrackingAreaUpdateReject(NasTrackingAreaUpdateReject),
    /// Tracking Area Update Request (§8.2.29).
    TrackingAreaUpdateRequest(NasTrackingAreaUpdateRequest),
    /// Uplink NAS Transport (§8.2.30).
    UplinkNasTransport(NasUplinkNasTransport),
    /// Downlink Generic NAS Transport (§8.2.31).
    DownlinkGenericNasTransport(NasDownlinkGenericNasTransport),
    /// Uplink Generic NAS Transport (§8.2.32).
    UplinkGenericNasTransport(NasUplinkGenericNasTransport),
    /// Control Plane Service Request (§8.2.33).
    ControlPlaneServiceRequest(NasControlPlaneServiceRequest),
    /// Service Accept (§8.2.34).
    ServiceAccept(NasServiceAccept),
}
impl NasEmmMessage {
    /// Message type of the body.
    pub fn message_type(&self) -> NasEmmMessageType {
        match self {
            Self::AttachAccept(..) => NasEmmMessageType::AttachAccept,
            Self::AttachComplete(..) => NasEmmMessageType::AttachComplete,
            Self::AttachReject(..) => NasEmmMessageType::AttachReject,
            Self::AttachRequest(..) => NasEmmMessageType::AttachRequest,
            Self::AuthenticationFailure(..) => NasEmmMessageType::AuthenticationFailure,
            Self::AuthenticationReject(..) => NasEmmMessageType::AuthenticationReject,
            Self::AuthenticationRequest(..) => NasEmmMessageType::AuthenticationRequest,
            Self::AuthenticationResponse(..) => NasEmmMessageType::AuthenticationResponse,
            Self::CsServiceNotification(..) => NasEmmMessageType::CsServiceNotification,
            Self::DetachAccept(..) => NasEmmMessageType::DetachAccept,
            Self::DetachRequestFromUe(..) => NasEmmMessageType::DetachRequest,
            Self::DetachRequestToUe(..) => NasEmmMessageType::DetachRequest,
            Self::DownlinkNasTransport(..) => NasEmmMessageType::DownlinkNasTransport,
            Self::EmmInformation(..) => NasEmmMessageType::EmmInformation,
            Self::EmmStatus(..) => NasEmmMessageType::EmmStatus,
            Self::ExtendedServiceRequest(..) => NasEmmMessageType::ExtendedServiceRequest,
            Self::GutiReallocationCommand(..) => NasEmmMessageType::GutiReallocationCommand,
            Self::GutiReallocationComplete(..) => NasEmmMessageType::GutiReallocationComplete,
            Self::IdentityRequest(..) => NasEmmMessageType::IdentityRequest,
            Self::IdentityResponse(..) => NasEmmMessageType::IdentityResponse,
            Self::SecurityModeCommand(..) => NasEmmMessageType::SecurityModeCommand,
            Self::SecurityModeComplete(..) => NasEmmMessageType::SecurityModeComplete,
            Self::SecurityModeReject(..) => NasEmmMessageType::SecurityModeReject,
            Self::ServiceReject(..) => NasEmmMessageType::ServiceReject,
            Self::TrackingAreaUpdateAccept(..) => NasEmmMessageType::TrackingAreaUpdateAccept,
            Self::TrackingAreaUpdateComplete(..) => NasEmmMessageType::TrackingAreaUpdateComplete,
            Self::TrackingAreaUpdateReject(..) => NasEmmMessageType::TrackingAreaUpdateReject,
            Self::TrackingAreaUpdateRequest(..) => NasEmmMessageType::TrackingAreaUpdateRequest,
            Self::UplinkNasTransport(..) => NasEmmMessageType::UplinkNasTransport,
            Self::DownlinkGenericNasTransport(..) => NasEmmMessageType::DownlinkGenericNasTransport,
            Self::UplinkGenericNasTransport(..) => NasEmmMessageType::UplinkGenericNasTransport,
            Self::ControlPlaneServiceRequest(..) => NasEmmMessageType::ControlPlaneServiceRequest,
            Self::ServiceAccept(..) => NasEmmMessageType::ServiceAccept,
        }
    }
    /// Alias of [`Self::message_type`].
    pub fn get_message_type(&self) -> NasEmmMessageType {
        self.message_type()
    }
}
impl Encode for NasEmmMessage {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        match self {
            Self::AttachAccept(message) => message.encode(buffer),
            Self::AttachComplete(message) => message.encode(buffer),
            Self::AttachReject(message) => message.encode(buffer),
            Self::AttachRequest(message) => message.encode(buffer),
            Self::AuthenticationFailure(message) => message.encode(buffer),
            Self::AuthenticationReject(message) => message.encode(buffer),
            Self::AuthenticationRequest(message) => message.encode(buffer),
            Self::AuthenticationResponse(message) => message.encode(buffer),
            Self::CsServiceNotification(message) => message.encode(buffer),
            Self::DetachAccept(message) => message.encode(buffer),
            Self::DetachRequestFromUe(message) => message.encode(buffer),
            Self::DetachRequestToUe(message) => message.encode(buffer),
            Self::DownlinkNasTransport(message) => message.encode(buffer),
            Self::EmmInformation(message) => message.encode(buffer),
            Self::EmmStatus(message) => message.encode(buffer),
            Self::ExtendedServiceRequest(message) => message.encode(buffer),
            Self::GutiReallocationCommand(message) => message.encode(buffer),
            Self::GutiReallocationComplete(message) => message.encode(buffer),
            Self::IdentityRequest(message) => message.encode(buffer),
            Self::IdentityResponse(message) => message.encode(buffer),
            Self::SecurityModeCommand(message) => message.encode(buffer),
            Self::SecurityModeComplete(message) => message.encode(buffer),
            Self::SecurityModeReject(message) => message.encode(buffer),
            Self::ServiceReject(message) => message.encode(buffer),
            Self::TrackingAreaUpdateAccept(message) => message.encode(buffer),
            Self::TrackingAreaUpdateComplete(message) => message.encode(buffer),
            Self::TrackingAreaUpdateReject(message) => message.encode(buffer),
            Self::TrackingAreaUpdateRequest(message) => message.encode(buffer),
            Self::UplinkNasTransport(message) => message.encode(buffer),
            Self::DownlinkGenericNasTransport(message) => message.encode(buffer),
            Self::UplinkGenericNasTransport(message) => message.encode(buffer),
            Self::ControlPlaneServiceRequest(message) => message.encode(buffer),
            Self::ServiceAccept(message) => message.encode(buffer),
        }
    }
}
impl TryFrom<(NasEmmMessageType, &mut Bytes)> for NasEmmMessage {
    type Error = NasError;
    fn try_from((kind, buffer): (NasEmmMessageType, &mut Bytes)) -> Result<Self> {
        match kind {
            NasEmmMessageType::AttachAccept => {
                Ok(Self::AttachAccept(NasAttachAccept::decode(buffer)?))
            }
            NasEmmMessageType::AttachComplete => {
                Ok(Self::AttachComplete(NasAttachComplete::decode(buffer)?))
            }
            NasEmmMessageType::AttachReject => {
                Ok(Self::AttachReject(NasAttachReject::decode(buffer)?))
            }
            NasEmmMessageType::AttachRequest => {
                Ok(Self::AttachRequest(NasAttachRequest::decode(buffer)?))
            }
            NasEmmMessageType::AuthenticationFailure => Ok(Self::AuthenticationFailure(
                NasAuthenticationFailure::decode(buffer)?,
            )),
            NasEmmMessageType::AuthenticationReject => Ok(Self::AuthenticationReject(
                NasAuthenticationReject::decode(buffer)?,
            )),
            NasEmmMessageType::AuthenticationRequest => Ok(Self::AuthenticationRequest(
                NasAuthenticationRequest::decode(buffer)?,
            )),
            NasEmmMessageType::AuthenticationResponse => Ok(Self::AuthenticationResponse(
                NasAuthenticationResponse::decode(buffer)?,
            )),
            NasEmmMessageType::CsServiceNotification => Ok(Self::CsServiceNotification(
                NasCsServiceNotification::decode(buffer)?,
            )),
            NasEmmMessageType::DetachAccept => {
                Ok(Self::DetachAccept(NasDetachAccept::decode(buffer)?))
            }
            NasEmmMessageType::DownlinkNasTransport => Ok(Self::DownlinkNasTransport(
                NasDownlinkNasTransport::decode(buffer)?,
            )),
            NasEmmMessageType::EmmInformation => {
                Ok(Self::EmmInformation(NasEmmInformation::decode(buffer)?))
            }
            NasEmmMessageType::EmmStatus => Ok(Self::EmmStatus(NasEmmStatus::decode(buffer)?)),
            NasEmmMessageType::ExtendedServiceRequest => Ok(Self::ExtendedServiceRequest(
                NasExtendedServiceRequest::decode(buffer)?,
            )),
            NasEmmMessageType::GutiReallocationCommand => Ok(Self::GutiReallocationCommand(
                NasGutiReallocationCommand::decode(buffer)?,
            )),
            NasEmmMessageType::GutiReallocationComplete => Ok(Self::GutiReallocationComplete(
                NasGutiReallocationComplete::decode(buffer)?,
            )),
            NasEmmMessageType::IdentityRequest => {
                Ok(Self::IdentityRequest(NasIdentityRequest::decode(buffer)?))
            }
            NasEmmMessageType::IdentityResponse => {
                Ok(Self::IdentityResponse(NasIdentityResponse::decode(buffer)?))
            }
            NasEmmMessageType::SecurityModeCommand => Ok(Self::SecurityModeCommand(
                NasSecurityModeCommand::decode(buffer)?,
            )),
            NasEmmMessageType::SecurityModeComplete => Ok(Self::SecurityModeComplete(
                NasSecurityModeComplete::decode(buffer)?,
            )),
            NasEmmMessageType::SecurityModeReject => Ok(Self::SecurityModeReject(
                NasSecurityModeReject::decode(buffer)?,
            )),
            NasEmmMessageType::ServiceReject => {
                Ok(Self::ServiceReject(NasServiceReject::decode(buffer)?))
            }
            NasEmmMessageType::TrackingAreaUpdateAccept => Ok(Self::TrackingAreaUpdateAccept(
                NasTrackingAreaUpdateAccept::decode(buffer)?,
            )),
            NasEmmMessageType::TrackingAreaUpdateComplete => Ok(Self::TrackingAreaUpdateComplete(
                NasTrackingAreaUpdateComplete::decode(buffer)?,
            )),
            NasEmmMessageType::TrackingAreaUpdateReject => Ok(Self::TrackingAreaUpdateReject(
                NasTrackingAreaUpdateReject::decode(buffer)?,
            )),
            NasEmmMessageType::TrackingAreaUpdateRequest => Ok(Self::TrackingAreaUpdateRequest(
                NasTrackingAreaUpdateRequest::decode(buffer)?,
            )),
            NasEmmMessageType::UplinkNasTransport => Ok(Self::UplinkNasTransport(
                NasUplinkNasTransport::decode(buffer)?,
            )),
            NasEmmMessageType::DownlinkGenericNasTransport => Ok(
                Self::DownlinkGenericNasTransport(NasDownlinkGenericNasTransport::decode(buffer)?),
            ),
            NasEmmMessageType::UplinkGenericNasTransport => Ok(Self::UplinkGenericNasTransport(
                NasUplinkGenericNasTransport::decode(buffer)?,
            )),
            NasEmmMessageType::ControlPlaneServiceRequest => Ok(Self::ControlPlaneServiceRequest(
                NasControlPlaneServiceRequest::decode(buffer)?,
            )),
            NasEmmMessageType::ServiceAccept => {
                Ok(Self::ServiceAccept(NasServiceAccept::decode(buffer)?))
            }
            NasEmmMessageType::DetachRequest => {
                // Both forms share the message type. The UE form needs an LV
                // EPS mobile identity of 4 to 11 octets holding an IMSI, IMEI,
                // or GUTI (Table 8.2.11.1.1, §9.9.3.12); when it only parses
                // by reading IEs as unknown, the network form is preferred.
                let mut ue_probe = buffer.clone();
                let from_ue = NasDetachRequestFromUe::decode(&mut ue_probe)
                    .ok()
                    .filter(|_| !ue_probe.has_remaining());
                if let Some(request) = &from_ue
                    && request.unknown_ies.is_empty()
                    && (4..=11).contains(&request.eps_mobile_identity.value.len())
                    && matches!(request.eps_mobile_identity.value[0] & 0x07, 1 | 3 | 6)
                {
                    *buffer = ue_probe;
                    return Ok(Self::DetachRequestFromUe(request.clone()));
                }
                let mut network_probe = buffer.clone();
                match (NasDetachRequestToUe::decode(&mut network_probe), from_ue) {
                    (Ok(request), _) => {
                        *buffer = network_probe;
                        Ok(Self::DetachRequestToUe(request))
                    }
                    (Err(_), Some(request)) => {
                        *buffer = ue_probe;
                        Ok(Self::DetachRequestFromUe(request))
                    }
                    (Err(error), None) => Err(error),
                }
            }
            NasEmmMessageType::Unknown(value) => Err(NasError::UnknownMessageType(value)),
        }
    }
}

/// ESM message bodies (TS 24.301 §8.3).
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum NasEsmMessage {
    /// Activate Dedicated EPS Bearer Context Accept (§8.3.1).
    ActivateDedicatedEpsBearerContextAccept(NasActivateDedicatedEpsBearerContextAccept),
    /// Activate Dedicated EPS Bearer Context Reject (§8.3.2).
    ActivateDedicatedEpsBearerContextReject(NasActivateDedicatedEpsBearerContextReject),
    /// Activate Dedicated EPS Bearer Context Request (§8.3.3).
    ActivateDedicatedEpsBearerContextRequest(NasActivateDedicatedEpsBearerContextRequest),
    /// Activate Default EPS Bearer Context Accept (§8.3.4).
    ActivateDefaultEpsBearerContextAccept(NasActivateDefaultEpsBearerContextAccept),
    /// Activate Default EPS Bearer Context Reject (§8.3.5).
    ActivateDefaultEpsBearerContextReject(NasActivateDefaultEpsBearerContextReject),
    /// Activate Default EPS Bearer Context Request (§8.3.6).
    ActivateDefaultEpsBearerContextRequest(NasActivateDefaultEpsBearerContextRequest),
    /// Bearer Resource Allocation Reject (§8.3.7).
    BearerResourceAllocationReject(NasBearerResourceAllocationReject),
    /// Bearer Resource Allocation Request (§8.3.8).
    BearerResourceAllocationRequest(NasBearerResourceAllocationRequest),
    /// Bearer Resource Modification Reject (§8.3.9).
    BearerResourceModificationReject(NasBearerResourceModificationReject),
    /// Bearer Resource Modification Request (§8.3.10).
    BearerResourceModificationRequest(NasBearerResourceModificationRequest),
    /// Deactivate EPS Bearer Context Accept (§8.3.11).
    DeactivateEpsBearerContextAccept(NasDeactivateEpsBearerContextAccept),
    /// Deactivate EPS Bearer Context Request (§8.3.12).
    DeactivateEpsBearerContextRequest(NasDeactivateEpsBearerContextRequest),
    /// ESM Dummy Message (§8.3.12A).
    EsmDummyMessage(NasEsmDummyMessage),
    /// ESM Information Request (§8.3.13).
    EsmInformationRequest(NasEsmInformationRequest),
    /// ESM Information Response (§8.3.14).
    EsmInformationResponse(NasEsmInformationResponse),
    /// ESM Status (§8.3.15).
    EsmStatus(NasEsmStatus),
    /// Modify EPS Bearer Context Accept (§8.3.16).
    ModifyEpsBearerContextAccept(NasModifyEpsBearerContextAccept),
    /// Modify EPS Bearer Context Reject (§8.3.17).
    ModifyEpsBearerContextReject(NasModifyEpsBearerContextReject),
    /// Modify EPS Bearer Context Request (§8.3.18).
    ModifyEpsBearerContextRequest(NasModifyEpsBearerContextRequest),
    /// Notification (§8.3.18A).
    Notification(NasNotification),
    /// PDN Connectivity Reject (§8.3.19).
    PdnConnectivityReject(NasPdnConnectivityReject),
    /// PDN Connectivity Request (§8.3.20).
    PdnConnectivityRequest(NasPdnConnectivityRequest),
    /// PDN Disconnect Reject (§8.3.21).
    PdnDisconnectReject(NasPdnDisconnectReject),
    /// PDN Disconnect Request (§8.3.22).
    PdnDisconnectRequest(NasPdnDisconnectRequest),
    /// Remote UE Report (§8.3.23).
    RemoteUeReport(NasRemoteUeReport),
    /// Remote UE Report Response (§8.3.24).
    RemoteUeReportResponse(NasRemoteUeReportResponse),
    /// ESM Data Transport (§8.3.25).
    EsmDataTransport(NasEsmDataTransport),
}
impl NasEsmMessage {
    /// Message type of the body.
    pub fn message_type(&self) -> NasEsmMessageType {
        match self {
            Self::ActivateDedicatedEpsBearerContextAccept(..) => {
                NasEsmMessageType::ActivateDedicatedEpsBearerContextAccept
            }
            Self::ActivateDedicatedEpsBearerContextReject(..) => {
                NasEsmMessageType::ActivateDedicatedEpsBearerContextReject
            }
            Self::ActivateDedicatedEpsBearerContextRequest(..) => {
                NasEsmMessageType::ActivateDedicatedEpsBearerContextRequest
            }
            Self::ActivateDefaultEpsBearerContextAccept(..) => {
                NasEsmMessageType::ActivateDefaultEpsBearerContextAccept
            }
            Self::ActivateDefaultEpsBearerContextReject(..) => {
                NasEsmMessageType::ActivateDefaultEpsBearerContextReject
            }
            Self::ActivateDefaultEpsBearerContextRequest(..) => {
                NasEsmMessageType::ActivateDefaultEpsBearerContextRequest
            }
            Self::BearerResourceAllocationReject(..) => {
                NasEsmMessageType::BearerResourceAllocationReject
            }
            Self::BearerResourceAllocationRequest(..) => {
                NasEsmMessageType::BearerResourceAllocationRequest
            }
            Self::BearerResourceModificationReject(..) => {
                NasEsmMessageType::BearerResourceModificationReject
            }
            Self::BearerResourceModificationRequest(..) => {
                NasEsmMessageType::BearerResourceModificationRequest
            }
            Self::DeactivateEpsBearerContextAccept(..) => {
                NasEsmMessageType::DeactivateEpsBearerContextAccept
            }
            Self::DeactivateEpsBearerContextRequest(..) => {
                NasEsmMessageType::DeactivateEpsBearerContextRequest
            }
            Self::EsmDummyMessage(..) => NasEsmMessageType::EsmDummyMessage,
            Self::EsmInformationRequest(..) => NasEsmMessageType::EsmInformationRequest,
            Self::EsmInformationResponse(..) => NasEsmMessageType::EsmInformationResponse,
            Self::EsmStatus(..) => NasEsmMessageType::EsmStatus,
            Self::ModifyEpsBearerContextAccept(..) => {
                NasEsmMessageType::ModifyEpsBearerContextAccept
            }
            Self::ModifyEpsBearerContextReject(..) => {
                NasEsmMessageType::ModifyEpsBearerContextReject
            }
            Self::ModifyEpsBearerContextRequest(..) => {
                NasEsmMessageType::ModifyEpsBearerContextRequest
            }
            Self::Notification(..) => NasEsmMessageType::Notification,
            Self::PdnConnectivityReject(..) => NasEsmMessageType::PdnConnectivityReject,
            Self::PdnConnectivityRequest(..) => NasEsmMessageType::PdnConnectivityRequest,
            Self::PdnDisconnectReject(..) => NasEsmMessageType::PdnDisconnectReject,
            Self::PdnDisconnectRequest(..) => NasEsmMessageType::PdnDisconnectRequest,
            Self::RemoteUeReport(..) => NasEsmMessageType::RemoteUeReport,
            Self::RemoteUeReportResponse(..) => NasEsmMessageType::RemoteUeReportResponse,
            Self::EsmDataTransport(..) => NasEsmMessageType::EsmDataTransport,
        }
    }
    /// Alias of [`Self::message_type`].
    pub fn get_message_type(&self) -> NasEsmMessageType {
        self.message_type()
    }
}
impl Encode for NasEsmMessage {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        match self {
            Self::ActivateDedicatedEpsBearerContextAccept(message) => message.encode(buffer),
            Self::ActivateDedicatedEpsBearerContextReject(message) => message.encode(buffer),
            Self::ActivateDedicatedEpsBearerContextRequest(message) => message.encode(buffer),
            Self::ActivateDefaultEpsBearerContextAccept(message) => message.encode(buffer),
            Self::ActivateDefaultEpsBearerContextReject(message) => message.encode(buffer),
            Self::ActivateDefaultEpsBearerContextRequest(message) => message.encode(buffer),
            Self::BearerResourceAllocationReject(message) => message.encode(buffer),
            Self::BearerResourceAllocationRequest(message) => message.encode(buffer),
            Self::BearerResourceModificationReject(message) => message.encode(buffer),
            Self::BearerResourceModificationRequest(message) => message.encode(buffer),
            Self::DeactivateEpsBearerContextAccept(message) => message.encode(buffer),
            Self::DeactivateEpsBearerContextRequest(message) => message.encode(buffer),
            Self::EsmDummyMessage(message) => message.encode(buffer),
            Self::EsmInformationRequest(message) => message.encode(buffer),
            Self::EsmInformationResponse(message) => message.encode(buffer),
            Self::EsmStatus(message) => message.encode(buffer),
            Self::ModifyEpsBearerContextAccept(message) => message.encode(buffer),
            Self::ModifyEpsBearerContextReject(message) => message.encode(buffer),
            Self::ModifyEpsBearerContextRequest(message) => message.encode(buffer),
            Self::Notification(message) => message.encode(buffer),
            Self::PdnConnectivityReject(message) => message.encode(buffer),
            Self::PdnConnectivityRequest(message) => message.encode(buffer),
            Self::PdnDisconnectReject(message) => message.encode(buffer),
            Self::PdnDisconnectRequest(message) => message.encode(buffer),
            Self::RemoteUeReport(message) => message.encode(buffer),
            Self::RemoteUeReportResponse(message) => message.encode(buffer),
            Self::EsmDataTransport(message) => message.encode(buffer),
        }
    }
}
impl TryFrom<(NasEsmMessageType, &mut Bytes)> for NasEsmMessage {
    type Error = NasError;
    fn try_from((kind, buffer): (NasEsmMessageType, &mut Bytes)) -> Result<Self> {
        match kind {
            NasEsmMessageType::ActivateDedicatedEpsBearerContextAccept => {
                Ok(Self::ActivateDedicatedEpsBearerContextAccept(
                    NasActivateDedicatedEpsBearerContextAccept::decode(buffer)?,
                ))
            }
            NasEsmMessageType::ActivateDedicatedEpsBearerContextReject => {
                Ok(Self::ActivateDedicatedEpsBearerContextReject(
                    NasActivateDedicatedEpsBearerContextReject::decode(buffer)?,
                ))
            }
            NasEsmMessageType::ActivateDedicatedEpsBearerContextRequest => {
                Ok(Self::ActivateDedicatedEpsBearerContextRequest(
                    NasActivateDedicatedEpsBearerContextRequest::decode(buffer)?,
                ))
            }
            NasEsmMessageType::ActivateDefaultEpsBearerContextAccept => {
                Ok(Self::ActivateDefaultEpsBearerContextAccept(
                    NasActivateDefaultEpsBearerContextAccept::decode(buffer)?,
                ))
            }
            NasEsmMessageType::ActivateDefaultEpsBearerContextReject => {
                Ok(Self::ActivateDefaultEpsBearerContextReject(
                    NasActivateDefaultEpsBearerContextReject::decode(buffer)?,
                ))
            }
            NasEsmMessageType::ActivateDefaultEpsBearerContextRequest => {
                Ok(Self::ActivateDefaultEpsBearerContextRequest(
                    NasActivateDefaultEpsBearerContextRequest::decode(buffer)?,
                ))
            }
            NasEsmMessageType::BearerResourceAllocationReject => {
                Ok(Self::BearerResourceAllocationReject(
                    NasBearerResourceAllocationReject::decode(buffer)?,
                ))
            }
            NasEsmMessageType::BearerResourceAllocationRequest => {
                Ok(Self::BearerResourceAllocationRequest(
                    NasBearerResourceAllocationRequest::decode(buffer)?,
                ))
            }
            NasEsmMessageType::BearerResourceModificationReject => {
                Ok(Self::BearerResourceModificationReject(
                    NasBearerResourceModificationReject::decode(buffer)?,
                ))
            }
            NasEsmMessageType::BearerResourceModificationRequest => {
                Ok(Self::BearerResourceModificationRequest(
                    NasBearerResourceModificationRequest::decode(buffer)?,
                ))
            }
            NasEsmMessageType::DeactivateEpsBearerContextAccept => {
                Ok(Self::DeactivateEpsBearerContextAccept(
                    NasDeactivateEpsBearerContextAccept::decode(buffer)?,
                ))
            }
            NasEsmMessageType::DeactivateEpsBearerContextRequest => {
                Ok(Self::DeactivateEpsBearerContextRequest(
                    NasDeactivateEpsBearerContextRequest::decode(buffer)?,
                ))
            }
            NasEsmMessageType::EsmDummyMessage => {
                Ok(Self::EsmDummyMessage(NasEsmDummyMessage::decode(buffer)?))
            }
            NasEsmMessageType::EsmInformationRequest => Ok(Self::EsmInformationRequest(
                NasEsmInformationRequest::decode(buffer)?,
            )),
            NasEsmMessageType::EsmInformationResponse => Ok(Self::EsmInformationResponse(
                NasEsmInformationResponse::decode(buffer)?,
            )),
            NasEsmMessageType::EsmStatus => Ok(Self::EsmStatus(NasEsmStatus::decode(buffer)?)),
            NasEsmMessageType::ModifyEpsBearerContextAccept => {
                Ok(Self::ModifyEpsBearerContextAccept(
                    NasModifyEpsBearerContextAccept::decode(buffer)?,
                ))
            }
            NasEsmMessageType::ModifyEpsBearerContextReject => {
                Ok(Self::ModifyEpsBearerContextReject(
                    NasModifyEpsBearerContextReject::decode(buffer)?,
                ))
            }
            NasEsmMessageType::ModifyEpsBearerContextRequest => {
                Ok(Self::ModifyEpsBearerContextRequest(
                    NasModifyEpsBearerContextRequest::decode(buffer)?,
                ))
            }
            NasEsmMessageType::Notification => {
                Ok(Self::Notification(NasNotification::decode(buffer)?))
            }
            NasEsmMessageType::PdnConnectivityReject => Ok(Self::PdnConnectivityReject(
                NasPdnConnectivityReject::decode(buffer)?,
            )),
            NasEsmMessageType::PdnConnectivityRequest => Ok(Self::PdnConnectivityRequest(
                NasPdnConnectivityRequest::decode(buffer)?,
            )),
            NasEsmMessageType::PdnDisconnectReject => Ok(Self::PdnDisconnectReject(
                NasPdnDisconnectReject::decode(buffer)?,
            )),
            NasEsmMessageType::PdnDisconnectRequest => Ok(Self::PdnDisconnectRequest(
                NasPdnDisconnectRequest::decode(buffer)?,
            )),
            NasEsmMessageType::RemoteUeReport => {
                Ok(Self::RemoteUeReport(NasRemoteUeReport::decode(buffer)?))
            }
            NasEsmMessageType::RemoteUeReportResponse => Ok(Self::RemoteUeReportResponse(
                NasRemoteUeReportResponse::decode(buffer)?,
            )),
            NasEsmMessageType::EsmDataTransport => {
                Ok(Self::EsmDataTransport(NasEsmDataTransport::decode(buffer)?))
            }
            NasEsmMessageType::Unknown(value) => Err(NasError::UnknownMessageType(value)),
        }
    }
}

#[cfg(test)]
mod table_round_trip_tests {
    use super::*;

    #[test]
    fn every_chapter_8_message_body_round_trips() {
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::AttachAccept(NasAttachAccept::new(
                NasEpsAttachResult::new(0),
                NasSpareHalfOctet::new(0),
                NasT3412Value::new(0),
                NasTaiList::new(vec![0; 6]),
                NasEsmMessageContainer::new(vec![0; 3]),
            )));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "AttachAccept");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::AttachComplete(
                NasAttachComplete::new(NasEsmMessageContainer::new(vec![0; 3])),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "AttachComplete");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::AttachReject(NasAttachReject::new(
                NasEmmCause::new(0),
            )));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "AttachReject");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::AttachRequest(NasAttachRequest::new(
                NasEpsAttachType::new(0),
                NasKeySetIdentifier::new(0),
                NasEpsMobileIdentity::from_imsi("001010123456789").unwrap(),
                NasUeNetworkCapability::new(vec![0; 2]),
                NasEsmMessageContainer::new(vec![0; 3]),
            )));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "AttachRequest");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::AuthenticationFailure(
                NasAuthenticationFailure::new(NasEmmCause::new(0)),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "AuthenticationFailure");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::AuthenticationReject(
                NasAuthenticationReject::new(),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "AuthenticationReject");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::AuthenticationRequest(
                NasAuthenticationRequest::new(
                    NasKeySetIdentifier::new(0),
                    NasSpareHalfOctet::new(0),
                    NasAuthenticationParameterRandEpsChallenge::new(vec![0; 16]),
                    NasAuthenticationParameterAutnEpsChallenge::new(vec![0; 16]),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "AuthenticationRequest");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::AuthenticationResponse(
                NasAuthenticationResponse::new(NasAuthenticationResponseParameter::new(vec![0; 4])),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "AuthenticationResponse");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::CsServiceNotification(
                NasCsServiceNotification::new(NasPagingIdentity::new(0)),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "CsServiceNotification");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::DetachAccept(NasDetachAccept::new()));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "DetachAccept");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::DetachRequestFromUe(
                NasDetachRequestFromUe::new(
                    NasDetachType::new(0),
                    NasKeySetIdentifier::new(0),
                    NasEpsMobileIdentity::from_imsi("001010123456789").unwrap(),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "DetachRequestFromUe");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::DetachRequestToUe(
                NasDetachRequestToUe::new(NasDetachType::new(0), NasSpareHalfOctet::new(0)),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "DetachRequestToUe");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::DownlinkNasTransport(
                NasDownlinkNasTransport::new(NasMessageContainer::new(vec![0; 2])),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "DownlinkNasTransport");
        }
        {
            let pdu =
                NasEpsMessage::new_emm(NasEmmMessage::EmmInformation(NasEmmInformation::new()));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "EmmInformation");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::EmmStatus(NasEmmStatus::new(
                NasEmmCause::new(0),
            )));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "EmmStatus");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::ExtendedServiceRequest(
                NasExtendedServiceRequest::new(
                    NasServiceType::new(0),
                    NasKeySetIdentifier::new(0),
                    NasMobileIdentity::from_tmsi(0),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "ExtendedServiceRequest");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::GutiReallocationCommand(
                NasGutiReallocationCommand::new(NasEpsMobileIdentity::new(vec![
                    0xf6, 0x02, 0xf8, 0x39, 0, 0, 0, 0, 0, 0, 0,
                ])),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "GutiReallocationCommand"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::GutiReallocationComplete(
                NasGutiReallocationComplete::new(),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "GutiReallocationComplete"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::IdentityRequest(
                NasIdentityRequest::new(NasIdentityType::new(0), NasSpareHalfOctet::new(0)),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "IdentityRequest");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::IdentityResponse(
                NasIdentityResponse::new(NasMobileIdentity::from_imsi("001010123456789").unwrap()),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "IdentityResponse");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::SecurityModeCommand(
                NasSecurityModeCommand::new(
                    NasSelectedNasSecurityAlgorithms::new(0),
                    NasKeySetIdentifier::new(0),
                    NasSpareHalfOctet::new(0),
                    NasReplayedUeSecurityCapabilities::new(vec![0; 2]),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "SecurityModeCommand");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::SecurityModeComplete(
                NasSecurityModeComplete::new(),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "SecurityModeComplete");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::SecurityModeReject(
                NasSecurityModeReject::new(NasEmmCause::new(0)),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "SecurityModeReject");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::ServiceReject(NasServiceReject::new(
                NasEmmCause::new(0),
            )));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "ServiceReject");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::TrackingAreaUpdateAccept(
                NasTrackingAreaUpdateAccept::new(
                    NasEpsUpdateResult::new(0),
                    NasSpareHalfOctet::new(0),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "TrackingAreaUpdateAccept"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::TrackingAreaUpdateComplete(
                NasTrackingAreaUpdateComplete::new(),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "TrackingAreaUpdateComplete"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::TrackingAreaUpdateReject(
                NasTrackingAreaUpdateReject::new(NasEmmCause::new(0)),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "TrackingAreaUpdateReject"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::TrackingAreaUpdateRequest(
                NasTrackingAreaUpdateRequest::new(
                    NasEpsUpdateType::new(0),
                    NasKeySetIdentifier::new(0),
                    NasEpsMobileIdentity::new(vec![0xf6, 0x02, 0xf8, 0x39, 0, 0, 0, 0, 0, 0, 0]),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "TrackingAreaUpdateRequest"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::UplinkNasTransport(
                NasUplinkNasTransport::new(NasMessageContainer::new(vec![0; 2])),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "UplinkNasTransport");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::DownlinkGenericNasTransport(
                NasDownlinkGenericNasTransport::new(
                    NasGenericMessageContainerType::new(0),
                    NasGenericMessageContainer::new(vec![0; 1]),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "DownlinkGenericNasTransport"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::UplinkGenericNasTransport(
                NasUplinkGenericNasTransport::new(
                    NasGenericMessageContainerType::new(0),
                    NasGenericMessageContainer::new(vec![0; 1]),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "UplinkGenericNasTransport"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::ControlPlaneServiceRequest(
                NasControlPlaneServiceRequest::new(
                    NasControlPlaneServiceType::new(0),
                    NasKeySetIdentifier::new(0),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ControlPlaneServiceRequest"
            );
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::ServiceAccept(NasServiceAccept::new()));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "ServiceAccept");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ActivateDedicatedEpsBearerContextAccept(
                    NasActivateDedicatedEpsBearerContextAccept::new(),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ActivateDedicatedEpsBearerContextAccept"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ActivateDedicatedEpsBearerContextReject(
                    NasActivateDedicatedEpsBearerContextReject::new(NasEsmCause::new(0)),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ActivateDedicatedEpsBearerContextReject"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ActivateDedicatedEpsBearerContextRequest(
                    NasActivateDedicatedEpsBearerContextRequest::new(
                        NasLinkedEpsBearerIdentity::new(0),
                        NasSpareHalfOctet::new(0),
                        NasEpsQos::new(vec![0; 1]),
                        NasTft::new(vec![0; 1]),
                    ),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ActivateDedicatedEpsBearerContextRequest"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ActivateDefaultEpsBearerContextAccept(
                    NasActivateDefaultEpsBearerContextAccept::new(),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ActivateDefaultEpsBearerContextAccept"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ActivateDefaultEpsBearerContextReject(
                    NasActivateDefaultEpsBearerContextReject::new(NasEsmCause::new(0)),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ActivateDefaultEpsBearerContextReject"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ActivateDefaultEpsBearerContextRequest(
                    NasActivateDefaultEpsBearerContextRequest::new(
                        NasEpsQos::new(vec![0; 1]),
                        NasAccessPointName::from_string("internet").unwrap(),
                        NasPdnAddress::from_pdn_address(crate::nas_eps::ie::PdnAddress::Ipv4(
                            [0; 4],
                        )),
                    ),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ActivateDefaultEpsBearerContextRequest"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::BearerResourceAllocationReject(
                    NasBearerResourceAllocationReject::new(NasEsmCause::new(0)),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "BearerResourceAllocationReject"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::BearerResourceAllocationRequest(
                    NasBearerResourceAllocationRequest::new(
                        NasLinkedEpsBearerIdentity::new(0),
                        NasSpareHalfOctet::new(0),
                        NasTrafficFlowAggregate::new(vec![0; 1]),
                        NasRequiredTrafficFlowQos::new(vec![0; 1]),
                    ),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "BearerResourceAllocationRequest"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::BearerResourceModificationReject(
                    NasBearerResourceModificationReject::new(NasEsmCause::new(0)),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "BearerResourceModificationReject"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::BearerResourceModificationRequest(
                    NasBearerResourceModificationRequest::new(
                        NasLinkedEpsBearerIdentity::new(0),
                        NasSpareHalfOctet::new(0),
                        NasTrafficFlowAggregate::new(vec![0; 1]),
                    ),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "BearerResourceModificationRequest"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::DeactivateEpsBearerContextAccept(
                    NasDeactivateEpsBearerContextAccept::new(),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "DeactivateEpsBearerContextAccept"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::DeactivateEpsBearerContextRequest(
                    NasDeactivateEpsBearerContextRequest::new(NasEsmCause::new(0)),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "DeactivateEpsBearerContextRequest"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::EsmDummyMessage(NasEsmDummyMessage::new()),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "EsmDummyMessage");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::EsmInformationRequest(NasEsmInformationRequest::new()),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "EsmInformationRequest");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::EsmInformationResponse(NasEsmInformationResponse::new()),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "EsmInformationResponse");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::EsmStatus(NasEsmStatus::new(NasEsmCause::new(0))),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "EsmStatus");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ModifyEpsBearerContextAccept(NasModifyEpsBearerContextAccept::new()),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ModifyEpsBearerContextAccept"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ModifyEpsBearerContextReject(NasModifyEpsBearerContextReject::new(
                    NasEsmCause::new(0),
                )),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ModifyEpsBearerContextReject"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::ModifyEpsBearerContextRequest(
                    NasModifyEpsBearerContextRequest::new(),
                ),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(
                decoded.to_bytes().unwrap(),
                bytes,
                "ModifyEpsBearerContextRequest"
            );
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::Notification(NasNotification::new(NasNotificationIndicator::new(
                    vec![0; 1],
                ))),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "Notification");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::PdnConnectivityReject(NasPdnConnectivityReject::new(
                    NasEsmCause::new(0),
                )),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "PdnConnectivityReject");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::PdnConnectivityRequest(NasPdnConnectivityRequest::new(
                    NasRequestType::new(0),
                    NasPdnType::new(0),
                )),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "PdnConnectivityRequest");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::PdnDisconnectReject(NasPdnDisconnectReject::new(NasEsmCause::new(
                    0,
                ))),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "PdnDisconnectReject");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::PdnDisconnectRequest(NasPdnDisconnectRequest::new(
                    NasLinkedEpsBearerIdentity::new(0),
                    NasSpareHalfOctet::new(0),
                )),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "PdnDisconnectRequest");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::RemoteUeReport(NasRemoteUeReport::new()),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "RemoteUeReport");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::RemoteUeReportResponse(NasRemoteUeReportResponse::new()),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "RemoteUeReportResponse");
        }
        {
            let pdu = NasEpsMessage::new_esm(
                NasEsmMessage::EsmDataTransport(NasEsmDataTransport::new(
                    NasUserDataContainer::new(vec![0; 0]),
                )),
                0,
                1,
            );
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "EsmDataTransport");
        }
    }
}

// END TS24301 MESSAGES

/// Plain EMM header (two octets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NasEmmHeader {
    /// Protocol discriminator (0111, EMM).
    pub protocol_discriminator: u8,
    /// Security header type; 0 for a plain message.
    pub security_header_type: NasEpsSecurityHeaderType,
    /// Message type.
    pub message_type: NasEmmMessageType,
}

impl NasEmmHeader {
    /// Build a plain EMM header.
    pub fn new(message_type: NasEmmMessageType) -> Self {
        Self {
            protocol_discriminator: EPS_EMM_PROTOCOL_DISCRIMINATOR,
            security_header_type: NasEpsSecurityHeaderType::PlainNasMessage,
            message_type,
        }
    }
}

impl Encode for NasEmmHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.protocol_discriminator != EPS_EMM_PROTOCOL_DISCRIMINATOR
            || self.security_header_type != NasEpsSecurityHeaderType::PlainNasMessage
        {
            return Err(NasError::EncodingError(
                "Invalid plain EPS EMM header".into(),
            ));
        }
        buffer.put_u8(self.protocol_discriminator);
        buffer.put_u8(self.message_type.as_u8());
        Ok(())
    }
}

impl Decode for NasEmmHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(NasError::MessageTooShort);
        }
        let first = buffer.get_u8();
        if first != EPS_EMM_PROTOCOL_DISCRIMINATOR {
            return Err(NasError::DecodingError(format!(
                "Invalid plain EPS EMM header 0x{first:02X}"
            )));
        }
        Ok(Self::new(NasEmmMessageType::try_from(buffer.get_u8())?))
    }
}

/// ESM header (three octets), with the bearer identity in the high nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NasEsmHeader {
    /// Protocol discriminator (0010, ESM).
    pub protocol_discriminator: u8,
    /// EPS bearer identity; 0 means no EPS bearer identity assigned.
    pub eps_bearer_identity: u8,
    /// Procedure transaction identity; 0 means none assigned, 255 is reserved.
    pub procedure_transaction_identity: u8,
    /// Message type.
    pub message_type: NasEsmMessageType,
}

impl NasEsmHeader {
    /// Build an ESM header.
    pub fn new(
        message_type: NasEsmMessageType,
        eps_bearer_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        Self {
            protocol_discriminator: EPS_ESM_PROTOCOL_DISCRIMINATOR,
            eps_bearer_identity,
            procedure_transaction_identity,
            message_type,
        }
    }
}

impl Encode for NasEsmHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // The reserved PTI 255 is encodable; `validate()` reports it.
        if self.protocol_discriminator != EPS_ESM_PROTOCOL_DISCRIMINATOR
            || self.eps_bearer_identity > 15
        {
            return Err(NasError::EncodingError("Invalid EPS ESM header".into()));
        }
        buffer.put_u8((self.eps_bearer_identity << 4) | self.protocol_discriminator);
        buffer.put_u8(self.procedure_transaction_identity);
        buffer.put_u8(self.message_type.as_u8());
        Ok(())
    }
}

impl Decode for NasEsmHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 3 {
            return Err(NasError::MessageTooShort);
        }
        let first = buffer.get_u8();
        if first & 0x0F != EPS_ESM_PROTOCOL_DISCRIMINATOR {
            return Err(NasError::DecodingError(format!(
                "Invalid EPS ESM header 0x{first:02X}"
            )));
        }
        let pti = buffer.get_u8();
        let kind = NasEsmMessageType::try_from(buffer.get_u8())?;
        Ok(Self::new(kind, first >> 4, pti))
    }
}

/// Short EPS SERVICE REQUEST header from TS 24.301 table 8.2.25.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasServiceRequest {
    /// Received security header type (12..=15); newly built messages use 12.
    pub security_header_type: u8,
    /// KSI (bits 8-6) and the five LSBs of the NAS COUNT (bits 5-1).
    pub ksi_and_sequence_number: u8,
    /// Short MAC: the two least significant octets of the NAS-MAC.
    pub message_authentication_code: u16,
}

impl NasServiceRequest {
    /// Build a SERVICE REQUEST with security header type 12.
    pub fn new(ksi_and_sequence_number: u8, message_authentication_code: u16) -> Self {
        Self {
            security_header_type: 12,
            ksi_and_sequence_number,
            message_authentication_code,
        }
    }
}

impl Encode for NasServiceRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if !(12..=15).contains(&self.security_header_type) {
            return Err(NasError::EncodingError(
                "Invalid EPS SERVICE REQUEST security header type".into(),
            ));
        }
        buffer.put_u8((self.security_header_type << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR);
        buffer.put_u8(self.ksi_and_sequence_number);
        buffer.put_u16(self.message_authentication_code);
        Ok(())
    }
}

impl Decode for NasServiceRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 4 {
            return Err(NasError::MessageTooShort);
        }
        let first = buffer.get_u8();
        if first & 0x0f != EPS_EMM_PROTOCOL_DISCRIMINATOR || first >> 4 < 12 {
            return Err(NasError::DecodingError(
                "Invalid EPS SERVICE REQUEST header".into(),
            ));
        }
        Ok(Self {
            security_header_type: first >> 4,
            ksi_and_sequence_number: buffer.get_u8(),
            message_authentication_code: buffer.get_u16(),
        })
    }
}

/// Receiver check of an EMM TRANSPORT data container: the container type
/// is known and its structure complete; spare bits are ignored (TS 24.007
/// §11.1.4), including the DDX bits in the downlink.
#[cfg(feature = "security")]
pub(crate) fn received_emm_data_container_is_valid(data: &[u8], downlink: bool) -> bool {
    let Some(&first) = data.first() else {
        return false;
    };
    let ddx_valid = downlink || (first >> 3) & 0x03 != 3;
    match first >> 5 {
        0 => data.len() >= 2 && ddx_valid && first & 0x07 != 0,
        1 => data.len() >= 2,
        2 => {
            ddx_valid
                && data
                    .get(1)
                    .is_some_and(|&length| data.len() >= 3 + length as usize)
        }
        _ => false,
    }
}

/// Sender check of the leading fields of an EMM TRANSPORT data container.
pub(crate) fn valid_emm_data_container(data: &[u8], downlink: bool) -> bool {
    let Some(&first) = data.first() else {
        return false;
    };
    match first >> 5 {
        // Control-plane user data: DDX 11 and EBI code 000 are reserved.
        0 => {
            data.len() >= 2
                && (first >> 3) & 0x03 != 3
                && (!downlink || first & 0x18 == 0)
                && first & 0x07 != 0
        }
        // SMS: the five remaining bits are spare.
        1 => data.len() >= 2 && first & 0x1f == 0,
        // Location service: low three bits are spare, followed by a length.
        2 => {
            (first >> 3) & 0x03 != 3
                && (!downlink || first & 0x18 == 0)
                && first & 0x07 == 0
                && data
                    .get(1)
                    .is_some_and(|&length| data.len() >= 3 + length as usize)
        }
        _ => false,
    }
}

/// EMM TRANSPORT with its optional data container occupying the remaining PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasEmmTransport {
    /// Security header with SHT 11.
    pub security_header: NasEpsSecurityHeader,
    /// Plain data container, for a message that is not ciphered.
    pub data_container: Option<Vec<u8>>,
    /// Bytes following the security header before deciphering, if opaque.
    pub protected_payload: Option<Vec<u8>>,
}

impl NasEmmTransport {
    /// Build an EMM TRANSPORT without a container.
    pub fn new(message_authentication_code: u32, sequence_number: u8) -> Self {
        Self {
            security_header: NasEpsSecurityHeader {
                security_header_type: NasEpsSecurityHeaderType::EmmTransport,
                message_authentication_code,
                sequence_number,
            },
            data_container: None,
            protected_payload: None,
        }
    }

    /// Attach the deciphered container for inspection after security verification.
    pub fn set_data_container(mut self, value: Vec<u8>) -> Self {
        self.data_container = Some(value);
        self.protected_payload = None;
        self
    }
}

impl Encode for NasEmmTransport {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.security_header.security_header_type != NasEpsSecurityHeaderType::EmmTransport {
            return Err(NasError::EncodingError(
                "Invalid EMM TRANSPORT header".into(),
            ));
        }
        self.security_header.encode(buffer)?;
        if let Some(payload) = &self.protected_payload {
            buffer.put_slice(payload);
        } else if self.data_container.is_some() {
            return Err(NasError::EncodingError(
                "Use NasSecurityContext to protect an EMM TRANSPORT data container".into(),
            ));
        }
        Ok(())
    }
}

impl Decode for NasEmmTransport {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let security_header = NasEpsSecurityHeader::decode(buffer)?;
        if security_header.security_header_type != NasEpsSecurityHeaderType::EmmTransport {
            return Err(NasError::DecodingError(
                "Invalid EMM TRANSPORT header".into(),
            ));
        }
        let (data_container, protected_payload) = if buffer.has_remaining() {
            (
                None,
                Some(buffer.copy_to_bytes(buffer.remaining()).to_vec()),
            )
        } else {
            (None, None)
        };
        Ok(Self {
            security_header,
            data_container,
            protected_payload,
        })
    }
}

/// Top-level EPS NAS PDU.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum NasEpsMessage {
    /// Plain EMM message.
    Emm(NasEmmHeader, NasEmmMessage),
    /// Plain ESM message.
    Esm(NasEsmHeader, NasEsmMessage),
    /// Security-protected message (SHT 1 to 5) and its plain or opaque body.
    SecurityProtected(NasEpsSecurityHeader, Box<NasEpsMessage>),
    /// SERVICE REQUEST, which has its own short header (SHT 12 to 15).
    ServiceRequest(NasServiceRequest),
    /// EMM TRANSPORT (SHT 11).
    EmmTransport(NasEmmTransport),
    /// Encrypted or otherwise opaque body of a security-protected PDU.
    Opaque(Vec<u8>),
}

/// Sender rules pairing a security header type with the message it
/// protects (§5.4.3.2, §5.4.3.3, Table 9.3.1 NOTE 4). Decoding accepts other
/// pairings; `validate()` and [`NasEpsMessage::protect`] apply these rules.
pub(crate) fn check_protected_inner(
    sht: NasEpsSecurityHeaderType,
    inner: &NasEpsMessage,
) -> Result<()> {
    if let NasEpsMessage::Emm(_, message) = inner {
        match message {
            NasEmmMessage::SecurityModeCommand(_)
                if sht != NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext =>
            {
                return Err(NasError::EncodingError(
                    "SECURITY MODE COMMAND requires integrity protection with new context".into(),
                ));
            }
            NasEmmMessage::SecurityModeComplete(_)
                if sht != NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext =>
            {
                return Err(NasError::EncodingError(
                    "SECURITY MODE COMPLETE requires ciphering with new context".into(),
                ));
            }
            _ => {}
        }
    }
    if let NasEpsMessage::Emm(_, NasEmmMessage::ControlPlaneServiceRequest(request)) = inner
        && sht
            != if request.esm_message_container.is_some() || request.nas_message_container.is_some()
            {
                NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered
            } else {
                NasEpsSecurityHeaderType::IntegrityProtected
            }
    {
        return Err(NasError::EncodingError(
            "CONTROL PLANE SERVICE REQUEST security header type does not match its container"
                .into(),
        ));
    }
    let valid = match sht {
        NasEpsSecurityHeaderType::IntegrityProtected => {
            matches!(inner, NasEpsMessage::Emm(..) | NasEpsMessage::Esm(..))
        }
        NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext => matches!(
            inner,
            NasEpsMessage::Emm(_, NasEmmMessage::SecurityModeCommand(_))
        ),
        NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext => matches!(
            inner,
            NasEpsMessage::Emm(_, NasEmmMessage::SecurityModeComplete(_))
                | NasEpsMessage::Opaque(_)
        ),
        NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered => matches!(
            inner,
            NasEpsMessage::Emm(_, NasEmmMessage::ControlPlaneServiceRequest(_))
                | NasEpsMessage::Opaque(_)
        ),
        NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered => !matches!(
            inner,
            NasEpsMessage::Emm(
                _,
                NasEmmMessage::AttachRequest(_) | NasEmmMessage::TrackingAreaUpdateRequest(_)
            )
        ),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(NasError::EncodingError(
            "EPS security header type does not match message type".into(),
        ))
    }
}

impl NasEpsMessage {
    /// Create a plain EMM message with the type inferred from the body.
    pub fn new_emm(message: NasEmmMessage) -> Self {
        Self::Emm(NasEmmHeader::new(message.message_type()), message)
    }

    /// Decode the plain message inside a security envelope that uses EEA0.
    ///
    /// EEA0 has the effect of an all-zero keystream (TS 33.401 §B.1.1), so
    /// the ciphered payload is the plain EMM or ESM message. An integrity-only
    /// envelope returns its already decoded message. The MAC is not verified.
    /// To validate security-header/message pairing, reconstruct an envelope
    /// with the returned message and the original header before calling
    /// `validate()`; use `NasSecurityContext` (feature `security`)
    /// when the NAS keys are known.
    pub fn decode_null_ciphered_payload(&self) -> Result<NasEpsMessage> {
        let Self::SecurityProtected(_, inner) = self else {
            return Err(NasError::DecodingError(
                "EPS message has no security envelope".into(),
            ));
        };
        let Self::Opaque(payload) = inner.as_ref() else {
            return Ok(inner.as_ref().clone());
        };
        let mut buffer = Bytes::copy_from_slice(payload);
        let message = Self::decode_plain(&mut buffer)?;
        if buffer.has_remaining() {
            return Err(NasError::DecodingError("Trailing EPS NAS bytes".into()));
        }
        Ok(message)
    }

    /// Alias of [`Self::new_emm`].
    pub fn from_emm(message: NasEmmMessage) -> Self {
        Self::new_emm(message)
    }

    /// Create a plain ESM message with the type inferred from the body.
    pub fn new_esm(
        message: NasEsmMessage,
        eps_bearer_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        Self::Esm(
            NasEsmHeader::new(
                message.message_type(),
                eps_bearer_identity,
                procedure_transaction_identity,
            ),
            message,
        )
    }

    /// Alias of [`Self::new_esm`].
    pub fn from_esm(
        message: NasEsmMessage,
        eps_bearer_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        Self::new_esm(message, eps_bearer_identity, procedure_transaction_identity)
    }

    /// Build a security envelope from a caller-supplied MAC and body.
    /// Ciphered header types require already ciphered opaque body bytes;
    /// use `NasSecurityContext` with the `security` feature to compute them.
    pub fn protect(
        message: NasEpsMessage,
        security_header_type: NasEpsSecurityHeaderType,
        message_authentication_code: u32,
        sequence_number: u8,
    ) -> Result<Self> {
        if !matches!(message, Self::Emm(..) | Self::Esm(..))
            || matches!(
                security_header_type,
                NasEpsSecurityHeaderType::PlainNasMessage
                    | NasEpsSecurityHeaderType::ServiceRequest
                    | NasEpsSecurityHeaderType::EmmTransport
            )
        {
            return Err(NasError::EncodingError(
                "Invalid EPS protected message".into(),
            ));
        }
        if matches!(
            security_header_type,
            NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                | NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered
        ) {
            return Err(NasError::EncodingError(
                "Use NasSecurityContext to cipher an EPS message".into(),
            ));
        }
        check_protected_inner(security_header_type, &message)?;
        Ok(Self::SecurityProtected(
            NasEpsSecurityHeader {
                security_header_type,
                message_authentication_code,
                sequence_number,
            },
            Box::new(message),
        ))
    }

    /// Encode this message to NAS wire-format bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_nas_eps_message(self)
    }

    /// Decode a message from NAS wire-format bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        decode_nas_eps_message(data)
    }

    /// Decode using direction to disambiguate DETACH REQUEST.
    pub fn from_bytes_with_direction(data: &[u8], direction: Direction) -> Result<Self> {
        decode_nas_eps_message_with_direction(data, direction)
    }
}

impl Encode for NasEpsMessage {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        match self {
            Self::Emm(header, message) => {
                if header.message_type != message.message_type() {
                    return Err(NasError::EncodingError(
                        "EPS EMM header/message type mismatch".into(),
                    ));
                }
                header.encode(buffer)?;
                message.encode(buffer)
            }
            Self::Esm(header, message) => {
                if header.message_type != message.message_type() {
                    return Err(NasError::EncodingError(
                        "EPS ESM header/message type mismatch".into(),
                    ));
                }
                header.encode(buffer)?;
                message.encode(buffer)
            }
            Self::SecurityProtected(header, message) => {
                if header.security_header_type == NasEpsSecurityHeaderType::EmmTransport
                    || !matches!(
                        message.as_ref(),
                        Self::Emm(..) | Self::Esm(..) | Self::Opaque(..)
                    )
                {
                    return Err(NasError::EncodingError(
                        "Invalid EPS protected message body".into(),
                    ));
                }
                if matches!(
                    header.security_header_type,
                    NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
                        | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
                        | NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered
                ) && !matches!(message.as_ref(), Self::Opaque(_))
                {
                    return Err(NasError::EncodingError(
                        "Ciphered EPS security envelope requires opaque ciphertext".into(),
                    ));
                }
                if matches!(message.as_ref(), Self::Opaque(data) if data.is_empty()) {
                    return Err(NasError::EncodingError("Empty EPS security payload".into()));
                }
                header.encode(buffer)?;
                message.encode(buffer)
            }
            Self::ServiceRequest(message) => message.encode(buffer),
            Self::EmmTransport(message) => message.encode(buffer),
            Self::Opaque(data) => {
                buffer.put_slice(data);
                Ok(())
            }
        }
    }
}

impl NasEpsMessage {
    /// Decode a plain EMM or ESM message, as carried inside a security envelope.
    /// Nested envelopes and the special SERVICE REQUEST and EMM TRANSPORT
    /// headers are rejected before any recursion.
    fn decode_plain(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::MessageTooShort);
        }
        if buffer[0] & 0x0f == EPS_EMM_PROTOCOL_DISCRIMINATOR && buffer[0] >> 4 != 0 {
            return Err(NasError::DecodingError(
                "Plain EPS NAS message cannot carry a security header".into(),
            ));
        }
        Self::decode(buffer)
    }
}

impl Decode for NasEpsMessage {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::MessageTooShort);
        }
        match buffer[0] & 0x0F {
            EPS_ESM_PROTOCOL_DISCRIMINATOR => {
                let header = NasEsmHeader::decode(buffer)?;
                if let NasEsmMessageType::Unknown(message_type) = header.message_type {
                    return Err(NasError::UnknownSessionMessageType {
                        identity: header.eps_bearer_identity,
                        pti: header.procedure_transaction_identity,
                        message_type,
                    });
                }
                let message = NasEsmMessage::try_from((header.message_type, buffer))?;
                Ok(Self::Esm(header, message))
            }
            EPS_EMM_PROTOCOL_DISCRIMINATOR => {
                let sht = NasEpsSecurityHeaderType::try_from(buffer[0] >> 4)?;
                match sht {
                    NasEpsSecurityHeaderType::PlainNasMessage => {
                        let header = NasEmmHeader::decode(buffer)?;
                        let message = NasEmmMessage::try_from((header.message_type, buffer))?;
                        Ok(Self::Emm(header, message))
                    }
                    NasEpsSecurityHeaderType::ServiceRequest => {
                        Ok(Self::ServiceRequest(NasServiceRequest::decode(buffer)?))
                    }
                    NasEpsSecurityHeaderType::EmmTransport => {
                        Ok(Self::EmmTransport(NasEmmTransport::decode(buffer)?))
                    }
                    _ => {
                        let header = NasEpsSecurityHeader::decode(buffer)?;
                        let payload = if matches!(
                            sht,
                            NasEpsSecurityHeaderType::IntegrityProtected
                                | NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext
                        ) {
                            Box::new(Self::decode_plain(buffer)?)
                        } else {
                            if !buffer.has_remaining() {
                                return Err(NasError::MessageTooShort);
                            }
                            Box::new(Self::Opaque(
                                buffer.copy_to_bytes(buffer.remaining()).to_vec(),
                            ))
                        };
                        Ok(Self::SecurityProtected(header, payload))
                    }
                }
            }
            discriminator => Err(NasError::UnknownProtocolDiscriminator(discriminator)),
        }
    }
}

/// Return true if the PDU has an EPS EMM security header.
pub fn is_security_protected(pdu: &[u8]) -> bool {
    if pdu
        .first()
        .is_none_or(|first| first & 0x0f != EPS_EMM_PROTOCOL_DISCRIMINATOR)
    {
        return false;
    }
    match pdu[0] >> 4 {
        1..=5 | 11 => pdu.len() >= EPS_SECURITY_HEADER_LEN,
        12..=15 => pdu.len() >= 4,
        _ => false,
    }
}

/// Encode an EPS NAS PDU.
pub fn encode_nas_eps_message(message: &NasEpsMessage) -> Result<Vec<u8>> {
    let mut buffer = BytesMut::with_capacity(256);
    message.encode(&mut buffer)?;
    Ok(buffer.to_vec())
}

/// Decode an EPS NAS PDU.
pub fn decode_nas_eps_message(data: &[u8]) -> Result<NasEpsMessage> {
    let mut buffer = Bytes::copy_from_slice(data);
    let message = NasEpsMessage::decode(&mut buffer)?;
    if buffer.has_remaining() {
        return Err(NasError::DecodingError("Trailing EPS NAS bytes".into()));
    }
    Ok(message)
}

/// Decode an EPS PDU with explicit DETACH REQUEST direction.
/// Both DETACH REQUEST forms use message type 0x45, so their body alone
/// cannot distinguish every valid optional-IE combination.
pub fn decode_nas_eps_message_with_direction(
    data: &[u8],
    direction: Direction,
) -> Result<NasEpsMessage> {
    if data.len() >= EPS_SECURITY_HEADER_LEN
        && data[0] & 0x0f == EPS_EMM_PROTOCOL_DISCRIMINATOR
        && matches!(data[0] >> 4, 1 | 3)
    {
        let mut buffer = Bytes::copy_from_slice(data);
        let header = NasEpsSecurityHeader::decode(&mut buffer)?;
        let payload = &data[EPS_SECURITY_HEADER_LEN..];
        if payload
            .first()
            .is_some_and(|first| first & 0x0f == EPS_EMM_PROTOCOL_DISCRIMINATOR && first >> 4 != 0)
        {
            return Err(NasError::DecodingError(
                "Plain EPS NAS message cannot carry a security header".into(),
            ));
        }
        let inner = decode_nas_eps_message_with_direction(payload, direction)?;
        return Ok(NasEpsMessage::SecurityProtected(header, Box::new(inner)));
    }
    if data.len() >= 2 && data[0] == EPS_EMM_PROTOCOL_DISCRIMINATOR && data[1] == 0x45 {
        let mut body = Bytes::copy_from_slice(&data[2..]);
        let message = match direction {
            Direction::Uplink => {
                NasEmmMessage::DetachRequestFromUe(NasDetachRequestFromUe::decode(&mut body)?)
            }
            Direction::Downlink => {
                NasEmmMessage::DetachRequestToUe(NasDetachRequestToUe::decode(&mut body)?)
            }
        };
        if body.has_remaining() {
            return Err(NasError::DecodingError(
                "Trailing EPS DETACH REQUEST bytes".into(),
            ));
        }
        Ok(NasEpsMessage::new_emm(message))
    } else {
        decode_nas_eps_message(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Validate;
    use crate::nas_eps::ie::PdnType;

    #[test]
    fn security_mode_complete_imeisv_reuses_mobile_identity_wire_type() {
        let identity = NasMobileIdentity::from_imeisv("4901542032375183").unwrap();
        let message = NasEpsMessage::new_emm(NasEmmMessage::SecurityModeComplete(
            NasSecurityModeComplete::new().set_imeisv(identity),
        ));
        let wire = hex::decode("075e23094309512430325781f3").unwrap();
        assert_eq!(message.to_bytes().unwrap(), wire);
        assert_eq!(
            NasEpsMessage::from_bytes(&wire)
                .unwrap()
                .to_bytes()
                .unwrap(),
            wire
        );
        assert!(message.validate().is_empty());
        let wrong_type =
            NasSecurityModeComplete::new().set_imeisv(NasMobileIdentity::new(vec![0; 9]));
        assert!(
            wrong_type
                .validate()
                .iter()
                .any(|error| error.field == "imeisv")
        );
    }

    #[test]
    fn guti_and_tmsi_fields_reuse_identity_wire_types() {
        let guti = NasEpsMobileIdentity::new(hex::decode("f602f839123456789abcde").unwrap());
        let command = NasEpsMessage::new_emm(NasEmmMessage::GutiReallocationCommand(
            NasGutiReallocationCommand::new(guti),
        ));
        let wire = hex::decode("07500bf602f839123456789abcde").unwrap();
        assert_eq!(command.to_bytes().unwrap(), wire);
        assert_eq!(
            NasEpsMessage::from_bytes(&wire)
                .unwrap()
                .to_bytes()
                .unwrap(),
            wire
        );

        let request = NasExtendedServiceRequest::new(
            NasServiceType::new(1),
            NasKeySetIdentifier::new(0),
            NasMobileIdentity::from_tmsi(0x1234_5678),
        );
        assert!(
            !request
                .validate()
                .iter()
                .any(|error| error.field == "m_tmsi")
        );
        let invalid = NasExtendedServiceRequest::new(
            NasServiceType::new(1),
            NasKeySetIdentifier::new(0),
            NasMobileIdentity::new(vec![0; 5]),
        );
        assert!(
            invalid
                .validate()
                .iter()
                .any(|error| error.field == "m_tmsi")
        );

        let invalid_guti = NasAttachRequest::new(
            NasEpsAttachType::new(1),
            NasKeySetIdentifier::new(7),
            NasEpsMobileIdentity::from_imsi("1234567").unwrap(),
            NasUeNetworkCapability::new(vec![0xe0, 0xe0]),
            NasEsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x31]),
        )
        .set_additional_guti(NasEpsMobileIdentity::new(vec![0; 11]));
        assert!(
            invalid_guti
                .validate()
                .iter()
                .any(|error| error.field == "additional_guti")
        );
    }

    // NAS-PDU values extracted from SCTP/S1AP packets in s1ap_errors.pcap.
    const CAPTURE_NAS: [(u8, &str); 14] = [
        (
            33,
            "17830224400307410108991007000020160605e0e000000000250243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1",
        ),
        (
            34,
            "075200ecfd815b7eb246cb199ab1743a4cc03e102c05040b170d80002180b9f277ae4fb4",
        ),
        (36, "170597954d04075308a98ca40cffa02a0e"),
        (37, "375dba65ba00075d020002e0e0c14f08b1e1115a6c47a750"),
        (38, "479943d9c300075e23098356970903139204f0"),
        (39, "2728a3d01b010243d9"),
        (40, "271e4c2f09010243da280908696e7465726e6574"),
        (
            83,
            "1795d4180b0207410108991007000020160605e0e000000000250244d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1",
        ),
        (
            84,
            "07520062c822e2a4192867014353bfcdff0dbc10cf444def73b280007c623bf485f96a07",
        ),
        (86, "17d25f6e70030753087caddc3d70411ec7"),
        (87, "371a673eb900075d020002e0e0c14f086b9a4755adf9bf7e"),
        (88, "4708eecbd900075e23098356970903139204f0"),
        (89, "27d9f62c22010244d9"),
        (90, "27d1237e92010244da280908696e7465726e6574"),
    ];

    fn capture_bytes(packet: u8) -> Vec<u8> {
        let hex = CAPTURE_NAS
            .iter()
            .find_map(|(number, hex)| (*number == packet).then_some(*hex))
            .expect("capture packet exists");
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    fn protected_inner(packet: u8) -> (NasEpsSecurityHeader, NasEpsMessage) {
        let NasEpsMessage::SecurityProtected(header, inner) =
            decode_nas_eps_message(&capture_bytes(packet)).unwrap()
        else {
            panic!("packet {packet} has no security envelope");
        };
        let message = NasEpsMessage::SecurityProtected(header.clone(), inner)
            .decode_null_ciphered_payload()
            .unwrap();
        (header, message)
    }

    #[test]
    fn capture_attach_attempts_decode_with_typed_contents() {
        use crate::nas_eps::ie::{AttachType, CipheringAlgorithm, IntegrityAlgorithm};
        use NasEpsSecurityHeaderType::*;
        // Frames 33-40 and 83-90: two attach attempts. Each ends after the
        // ESM INFORMATION RESPONSE with an SCTP SHUTDOWN from the MME (frames
        // 42 and 92); no NAS or S1AP message gives a cause.
        for (attach, ue_sn, pti) in [(33, 3, 0x43), (83, 2, 0x44)] {
            let (header, message) = protected_inner(attach);
            assert_eq!(
                (header.security_header_type, header.sequence_number),
                (IntegrityProtected, ue_sn)
            );
            let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = message else {
                panic!("frame {attach} is not an ATTACH REQUEST");
            };
            assert_eq!(request.eps_attach_type.attach_type(), AttachType::EpsAttach);
            assert!(request.eps_mobile_identity.as_imsi().is_some());
            let capability = &request.ue_network_capability;
            assert!(
                (0..=2).all(|algo| capability.supports_eea(algo) && capability.supports_eia(algo))
            );
            let NasEpsMessage::Esm(esm, NasEsmMessage::PdnConnectivityRequest(pdn)) = request
                .esm_message_container
                .decode_as_esm_message()
                .unwrap()
            else {
                panic!("frame {attach} does not carry PDN CONNECTIVITY REQUEST");
            };
            assert_eq!(esm.procedure_transaction_identity, pti);
            // The APN follows in the ESM INFORMATION RESPONSE.
            assert!(pdn.esm_information_transfer_flag.unwrap().is_required());
            assert!(pdn.access_point_name.is_none());

            // AUTHENTICATION REQUEST (plain) and RESPONSE (integrity protected
            // with the context of the previous attempt).
            let NasEpsMessage::Emm(_, NasEmmMessage::AuthenticationRequest(challenge)) =
                decode_nas_eps_message(&capture_bytes(attach + 1)).unwrap()
            else {
                panic!("frame {} is not an AUTHENTICATION REQUEST", attach + 1);
            };
            assert!(
                challenge
                    .authentication_parameter_autn_eps_challenge
                    .amf_separation_bit()
                    == Some(true)
            );
            let (header, response) = protected_inner(attach + 3);
            assert_eq!(header.sequence_number, ue_sn + 1);
            assert!(matches!(
                response,
                NasEpsMessage::Emm(_, NasEmmMessage::AuthenticationResponse(ref r))
                    if r.authentication_response_parameter.res().len() == 8
            ));

            // SECURITY MODE COMMAND selects EEA0 with EIA2 and requests the IMEISV.
            let (header, command) = protected_inner(attach + 4);
            assert_eq!(
                (header.security_header_type, header.sequence_number),
                (IntegrityProtectedWithNewContext, 0)
            );
            let NasEpsMessage::Emm(_, NasEmmMessage::SecurityModeCommand(command)) = command else {
                panic!("frame {} is not a SECURITY MODE COMMAND", attach + 4);
            };
            let algorithms = &command.selected_nas_security_algorithms;
            assert_eq!(algorithms.ciphering(), Some(CipheringAlgorithm::EEA0));
            assert_eq!(algorithms.integrity(), Some(IntegrityAlgorithm::EIA2));
            assert!(
                command
                    .replayed_ue_security_capabilities
                    .matches_ue_network_capability(capability)
            );
            assert!(command.imeisv_request.unwrap().is_requested());
            let hash = command.hash_mme.unwrap();
            #[cfg(feature = "security")]
            {
                // TS 33.401 Annex I.2: HashMME over the plain ATTACH REQUEST.
                let plain = &capture_bytes(attach)[EPS_SECURITY_HEADER_LEN..];
                assert_eq!(
                    hash.value,
                    oxirush_security::nas_eps::compute_hash_mme(plain)
                );
            }
            let _ = hash;

            // With EEA0 the ciphered envelopes (SHT 4 and 2) carry plain NAS.
            let (header, complete) = protected_inner(attach + 5);
            assert_eq!(
                (header.security_header_type, header.sequence_number),
                (IntegrityProtectedAndCipheredWithNewContext, 0)
            );
            let NasEpsMessage::Emm(_, NasEmmMessage::SecurityModeComplete(complete)) = complete
            else {
                panic!("frame {} is not a SECURITY MODE COMPLETE", attach + 5);
            };
            assert_eq!(
                complete
                    .imeisv
                    .unwrap()
                    .as_imeisv()
                    .map(|imeisv| imeisv.len()),
                Some(16)
            );
            assert!(complete.replayed_nas_message_container.is_none());
            let (header, request) = protected_inner(attach + 6);
            assert_eq!(
                (header.security_header_type, header.sequence_number),
                (IntegrityProtectedAndCiphered, 1)
            );
            assert!(matches!(
                request,
                NasEpsMessage::Esm(ref h, NasEsmMessage::EsmInformationRequest(_))
                    if h.procedure_transaction_identity == pti
            ));
            let (header, response) = protected_inner(attach + 7);
            assert_eq!(header.sequence_number, 1);
            let NasEpsMessage::Esm(h, NasEsmMessage::EsmInformationResponse(response)) = response
            else {
                panic!("frame {} is not an ESM INFORMATION RESPONSE", attach + 7);
            };
            assert_eq!(h.procedure_transaction_identity, pti);
            assert_eq!(
                response.access_point_name.unwrap().as_string().as_deref(),
                Some("internet")
            );
        }
    }

    #[test]
    fn capture_nas_pdus_round_trip_byte_for_byte() {
        for &(packet, _) in &CAPTURE_NAS {
            let wire = capture_bytes(packet);
            let decoded = decode_nas_eps_message(&wire).unwrap();
            assert_eq!(
                encode_nas_eps_message(&decoded).unwrap(),
                wire,
                "packet {packet}"
            );
            assert!(decoded.validate().is_empty(), "packet {packet}");
        }
    }

    #[test]
    fn malformed_nested_plmn_list_and_spare_qci_are_reported() {
        for wire in [
            &[0x07, 0x49, 0x01, 0x25, 0x02, 0x02, 0xf8][..],
            &[0x07, 0x49, 0x01, 0x25, 0x03, 0xff, 0xff, 0xff][..],
        ] {
            let message = decode_nas_eps_message(wire).unwrap();
            assert!(
                message.validate().iter().any(|error| {
                    error.field == "list_of_plmns_to_be_used_in_disaster_condition"
                })
            );
            assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        }
        let wire = [0x52, 0x01, 0xc5, 0x05, 0x01, 0x0b, 0x01, 0x00];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "eps_qos")
        );
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
    }

    #[test]
    fn bearer_resource_allocation_accepts_ignore_traffic_flow_aggregate() {
        // TS 24.008 §10.5.6.12 requires E=0 and filter count=0 for Ignore.
        let wire = [0x02, 0x01, 0xd4, 0x05, 0x01, 0x00, 0x01, 0x09];
        let message = decode_nas_eps_message(&wire).unwrap();
        let NasEpsMessage::Esm(_, NasEsmMessage::BearerResourceAllocationRequest(request)) =
            &message
        else {
            panic!("wrong EPS message type");
        };
        assert_eq!(
            request.traffic_flow_aggregate.tft().unwrap().operation,
            crate::nas_eps::ie::TftOperation::Ignore
        );
        assert!(message.validate().is_empty());
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
    }

    #[test]
    fn malformed_nbifom_parameter_unit_is_reported() {
        let wire = [0x52, 0x01, 0xc6, 0x33, 0x01, 0x01];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "nbifom_container")
        );
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
    }

    #[test]
    fn classmark_two_spare_bit_is_reported() {
        let mut request = NasAttachRequest::new(
            NasEpsAttachType::new(1),
            NasKeySetIdentifier::new(0),
            NasEpsMobileIdentity::new(vec![0xf4, 0, 0, 0, 1]),
            NasUeNetworkCapability::new(vec![0, 0]),
            NasEsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        );
        request.mobile_station_classmark_2 =
            Some(NasMobileStationClassmark2::new(vec![0x80, 0, 0]));
        assert!(
            request
                .validate()
                .iter()
                .any(|error| error.field == "mobile_station_classmark_2")
        );
    }

    #[test]
    fn transmitted_imei_requires_zero_spare_digit() {
        let conforming = NasIdentityResponse::new(
            NasMobileIdentity::from_imei_tac_snr("49015420323751").unwrap(),
        );
        assert!(conforming.validate().is_empty());
        let interoperable =
            NasIdentityResponse::new(NasMobileIdentity::from_imei("490154203237518").unwrap());
        assert!(
            interoperable
                .validate()
                .iter()
                .any(|error| error.field == "mobile_identity")
        );
    }

    #[test]
    fn nested_security_protected_message_is_rejected() {
        // An envelope carries only a plain EMM or ESM message. Deep nesting
        // must fail at the first inner header instead of recursing.
        let plain = [0x07, 0x60, 0x03];
        for depth in [1usize, 2, 2000] {
            let mut wire = Vec::with_capacity(depth * EPS_SECURITY_HEADER_LEN + plain.len());
            for _ in 0..depth {
                wire.extend_from_slice(&[0x17, 0, 0, 0, 0, 0]);
            }
            wire.extend_from_slice(&plain);
            let result = std::thread::Builder::new()
                .stack_size(256 * 1024)
                .spawn(move || {
                    (
                        decode_nas_eps_message(&wire).is_ok(),
                        [Direction::Uplink, Direction::Downlink]
                            .into_iter()
                            .map(|direction| {
                                decode_nas_eps_message_with_direction(&wire, direction).is_ok()
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .unwrap()
                .join()
                .expect("decoder must not overflow the stack");
            assert_eq!(result, (depth == 1, vec![depth == 1; 2]), "depth {depth}");
        }
        for inner in [&[0xc7, 0, 0, 0][..], &[0xb7, 0, 0, 0, 0, 0][..]] {
            let mut wire = vec![0x17, 0, 0, 0, 0, 0];
            wire.extend_from_slice(inner);
            assert!(decode_nas_eps_message(&wire).is_err(), "{wire:02x?}");
        }
    }

    #[test]
    fn truncated_and_bit_flipped_capture_pdus_never_panic() {
        // Every accepted mutation must also format, validate, and re-encode to
        // a canonical form that decodes to the same structure.
        fn check(wire: &[u8]) {
            let Ok(message) = decode_nas_eps_message(wire) else {
                return;
            };
            let _ = message.to_string();
            let _ = message.validate();
            if let Ok(inner) = message.decode_null_ciphered_payload() {
                let _ = inner.to_string();
                let _ = inner.validate();
            }
            let bytes = encode_nas_eps_message(&message).expect("decodable PDU re-encodes");
            let again = decode_nas_eps_message(&bytes).expect("canonical PDU decodes");
            assert_eq!(again, message, "structural round trip of {wire:02x?}");
            assert_eq!(encode_nas_eps_message(&again).unwrap(), bytes);
        }
        for &(packet, _) in &CAPTURE_NAS {
            let wire = capture_bytes(packet);
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
    fn capture_readable_inner_nas_pdus_round_trip() {
        // The ciphering selection is EEA0 in the captured SECURITY MODE COMMANDs.
        // These bytes can be decoded; MAC-I still requires the session keys.
        for packet in [38, 39, 40, 88, 89, 90] {
            let wire = capture_bytes(packet);
            assert!(matches!(
                decode_nas_eps_message(&wire).unwrap(),
                NasEpsMessage::SecurityProtected(_, inner)
                    if matches!(*inner, NasEpsMessage::Opaque(_))
            ));
            let inner = decode_nas_eps_message(&wire[EPS_SECURITY_HEADER_LEN..]).unwrap();
            assert_eq!(
                encode_nas_eps_message(&inner).unwrap(),
                &wire[EPS_SECURITY_HEADER_LEN..],
                "packet {packet} inner NAS"
            );
        }

        for (packet, pti) in [(33, 0x43), (83, 0x44)] {
            let wire = capture_bytes(packet);
            let NasEpsMessage::SecurityProtected(_, inner) = decode_nas_eps_message(&wire).unwrap()
            else {
                panic!("packet {packet} is not protected");
            };
            let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = *inner else {
                panic!("packet {packet} is not an ATTACH REQUEST");
            };
            let esm = request
                .esm_message_container
                .decode_as_esm_message()
                .unwrap();
            assert_eq!(
                NasEsmMessageContainer::from_esm_message(&esm)
                    .unwrap()
                    .value,
                request.esm_message_container.value
            );
            assert!(matches!(
                esm,
                NasEpsMessage::Esm(
                    NasEsmHeader {
                        procedure_transaction_identity,
                        ..
                    },
                    NasEsmMessage::PdnConnectivityRequest(_)
                ) if procedure_transaction_identity == pti
            ));
        }
    }

    #[test]
    fn reserved_service_request_header_is_reported_and_relayed() {
        // Table 9.3.1: SHT 1101-1111 is read as 1100. The received octets
        // re-encode unchanged, and validate() reports the sender rule.
        let wire = [0xd7, 0x12, 0x34, 0x56];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert!(matches!(message, NasEpsMessage::ServiceRequest(_)));
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "security_header_type")
        );
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
    }

    #[test]
    fn security_mode_command_under_another_header_type_is_reported() {
        // Codec audit F-13: §5.4.3.2 is a sender rule, so the message decodes
        // and validate() reports the pairing.
        let wire = [
            0x17, 0, 0, 0, 0, 0, 0x07, 0x5d, 0x11, 0x01, 0x02, 0xe0, 0xe0,
        ];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "security_header_type")
        );
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        let NasEpsMessage::SecurityProtected(_, inner) = message else {
            panic!("security envelope expected");
        };
        assert!(
            NasEpsMessage::protect(*inner, NasEpsSecurityHeaderType::IntegrityProtected, 0, 0)
                .is_err()
        );
    }

    #[test]
    fn repeated_and_out_of_sequence_ies_are_reported() {
        use crate::common::Severity;
        // Codec review C-3: §9.1 allows one occurrence; §7.6.3 keeps the first.
        let repeated = decode_nas_eps_message(&pdu("0744 03 5F0121 5F0122")).unwrap();
        assert_eq!(findings_of(&repeated), [("unknown_ies", Severity::Error)]);
        // Codec review C-4: 1C follows 5F in Table 8.2.3.1. The IE is kept
        // as raw evidence, ignored by receiver semantics (§7.6.2), and
        // re-encoded where it was.
        let wire = pdu("0744 16 1C0121 5F0121");
        let out_of_sequence = decode_nas_eps_message(&wire).unwrap();
        assert_eq!(
            findings_of(&out_of_sequence),
            [("unknown_ies", Severity::Error)]
        );
        assert_eq!(encode_nas_eps_message(&out_of_sequence).unwrap(), wire);
        let NasEpsMessage::Emm(_, NasEmmMessage::AttachReject(reject)) = out_of_sequence else {
            panic!("ATTACH REJECT expected");
        };
        assert!(reject.lower_bound_timer_value.is_some());
        assert!(reject.t3346_value.is_none());
        let in_order = decode_nas_eps_message(&pdu("0744 16 5F0121 1C0121")).unwrap();
        assert!(in_order.validate().is_empty());

        // A syntactically incorrect first occurrence still wins. The later
        // valid-looking repetition is ignored, so receiver semantics remain
        // absent while both occurrences are retained for relay.
        let wire = pdu("0744 03 5F00 5F0121");
        let malformed_first = decode_nas_eps_message(&wire).unwrap();
        let NasEpsMessage::Emm(_, NasEmmMessage::AttachReject(reject)) = &malformed_first else {
            panic!("ATTACH REJECT expected");
        };
        assert!(reject.t3346_value.is_none());
        assert_eq!(reject.unknown_ies.len(), 2);
        assert_eq!(encode_nas_eps_message(&malformed_first).unwrap(), wire);
    }

    #[test]
    fn truncated_known_optional_ie_is_absent_but_preserved() {
        // T3402 declares two value octets but only one remains. §7.7.1
        // treats it as absent; the raw occurrence remains available for
        // diagnostics and lossless relay.
        let wire = pdu("0744 02 160221");
        let message = decode_nas_eps_message(&wire).unwrap();
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        let NasEpsMessage::Emm(_, NasEmmMessage::AttachReject(reject)) = message else {
            panic!("ATTACH REJECT expected");
        };
        assert!(reject.t3402_value.is_none());
        assert_eq!(reject.unknown_ies.len(), 1);
    }

    #[test]
    fn mandatory_receiver_syntax_rejects_short_values() {
        fn encoded(message: NasEpsMessage) -> Vec<u8> {
            encode_nas_eps_message(&message).unwrap()
        }

        let authentication_request = NasEpsMessage::new_emm(NasEmmMessage::AuthenticationRequest(
            NasAuthenticationRequest::new(
                NasKeySetIdentifier::new(0),
                NasSpareHalfOctet::new(0),
                NasAuthenticationParameterRandEpsChallenge::new(vec![0; 16]),
                NasAuthenticationParameterAutnEpsChallenge::new(vec![0; 15]),
            ),
        ));
        assert_eq!(
            decode_nas_eps_message(&encoded(authentication_request)),
            Err(NasError::InvalidMandatoryIe(
                "authentication_parameter_autn_eps_challenge"
            ))
        );

        let authentication_response =
            NasEpsMessage::new_emm(NasEmmMessage::AuthenticationResponse(
                NasAuthenticationResponse::new(NasAuthenticationResponseParameter::new(vec![0; 3])),
            ));
        assert_eq!(
            decode_nas_eps_message(&encoded(authentication_response)),
            Err(NasError::InvalidMandatoryIe(
                "authentication_response_parameter"
            ))
        );

        let attach_complete = NasEpsMessage::new_emm(NasEmmMessage::AttachComplete(
            NasAttachComplete::new(NasEsmMessageContainer::new(vec![0; 2])),
        ));
        assert_eq!(
            decode_nas_eps_message(&encoded(attach_complete)),
            Err(NasError::InvalidMandatoryIe("esm_message_container"))
        );

        let downlink_transport = NasEpsMessage::new_emm(NasEmmMessage::DownlinkNasTransport(
            NasDownlinkNasTransport::new(NasMessageContainer::new(vec![0])),
        ));
        assert_eq!(
            decode_nas_eps_message(&encoded(downlink_transport)),
            Err(NasError::InvalidMandatoryIe("nas_message_container"))
        );

        for (traffic_flow, qos, field) in [
            (vec![], vec![0], "traffic_flow_aggregate"),
            (vec![0], vec![], "required_traffic_flow_qos"),
        ] {
            let request = NasEpsMessage::new_esm(
                NasEsmMessage::BearerResourceAllocationRequest(
                    NasBearerResourceAllocationRequest::new(
                        NasLinkedEpsBearerIdentity::new(0),
                        NasSpareHalfOctet::new(0),
                        NasTrafficFlowAggregate::new(traffic_flow),
                        NasRequiredTrafficFlowQos::new(qos),
                    ),
                ),
                0,
                1,
            );
            assert_eq!(
                decode_nas_eps_message(&encoded(request)),
                Err(NasError::InvalidMandatoryIe(field))
            );
        }
    }

    #[test]
    fn mobile_identity_receiver_ignores_excess_value_octets() {
        let imsi = "208930000000001";
        let mut mobile_value = NasMobileIdentity::from_imsi(imsi).unwrap().value;
        mobile_value.extend_from_slice(&[0xaa, 0xbb]);
        let mobile = NasMobileIdentity::new(mobile_value);
        assert_eq!(mobile.as_imsi().as_deref(), Some(imsi));
        assert!(!mobile.is_well_formed());

        let mut eps_value = NasEpsMobileIdentity::from_imsi(imsi).unwrap().value;
        eps_value.extend_from_slice(&[0xaa, 0xbb]);
        let eps_identity = NasEpsMobileIdentity::new(eps_value);
        assert_eq!(eps_identity.as_imsi().as_deref(), Some(imsi));
        assert!(!eps_identity.is_well_formed());

        let attach = NasEpsMessage::new_emm(NasEmmMessage::AttachRequest(NasAttachRequest::new(
            NasEpsAttachType::new(1),
            NasKeySetIdentifier::new(0),
            eps_identity,
            NasUeNetworkCapability::new(vec![0, 0]),
            NasEsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        )));
        let wire = encode_nas_eps_message(&attach).unwrap();
        let decoded = decode_nas_eps_message(&wire).unwrap();
        assert!(
            decoded
                .validate()
                .iter()
                .any(|finding| finding.field == "eps_mobile_identity")
        );
    }

    fn findings_of(message: &NasEpsMessage) -> Vec<(&'static str, crate::common::Severity)> {
        message
            .validate()
            .into_iter()
            .map(|finding| (finding.field, finding.severity))
            .collect()
    }

    #[test]
    fn null_ciphered_payload_defers_header_pairing_to_validation() {
        // Security review F11: §4.4.5 sends ATTACH REQUEST unciphered, and
        // SHT 4 carries only SECURITY MODE COMPLETE (Table 9.3.1 NOTE 2).
        let attach = &capture_bytes(33)[EPS_SECURITY_HEADER_LEN..];
        for sht in [0x27, 0x47] {
            let mut wire = vec![sht, 0, 0, 0, 0, 0];
            wire.extend_from_slice(attach);
            let message = decode_nas_eps_message(&wire).unwrap();
            let decoded = message.decode_null_ciphered_payload().unwrap();
            let NasEpsMessage::SecurityProtected(header, _) = &message else {
                unreachable!()
            };
            let decoded_envelope =
                NasEpsMessage::SecurityProtected(header.clone(), Box::new(decoded));
            assert!(
                decoded_envelope
                    .validate()
                    .iter()
                    .any(|finding| finding.field == "security_header_type")
            );
        }
        // The capture's SHT 4 and SHT 2 payloads still decode.
        for packet in [38, 39, 40] {
            let message = decode_nas_eps_message(&capture_bytes(packet)).unwrap();
            assert!(message.decode_null_ciphered_payload().is_ok());
        }
    }

    #[test]
    fn attach_complete_esm_container_is_only_checked_as_a_warning() {
        // §7.5.2: no diagnosis beyond presence and length at the EMM level.
        let wire = [0x07, 0x43, 0x00, 0x03, 0xff, 0xff, 0xff];
        let message = decode_nas_eps_message(&wire).unwrap();
        let findings = message.validate();
        assert!(
            findings
                .iter()
                .all(|error| error.severity == crate::common::Severity::Warning)
        );
        assert!(
            findings
                .iter()
                .any(|error| error.field == "esm_message_container")
        );
    }

    #[test]
    fn received_pdn_type_fallback_is_invalid_for_sending() {
        let wire = [0x02, 0x01, 0xd0, 0x41];
        let message = decode_nas_eps_message(&wire).unwrap();
        let NasEpsMessage::Esm(_, NasEsmMessage::PdnConnectivityRequest(request)) = &message else {
            panic!("expected PDN CONNECTIVITY REQUEST");
        };
        assert_eq!(request.pdn_type.pdn_type(), Some(PdnType::Ipv6));
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "pdn_type")
        );
    }

    #[test]
    fn received_attach_and_update_type_fallbacks_are_invalid_for_sending() {
        let mut attach_wire = capture_bytes(33)[EPS_SECURITY_HEADER_LEN..].to_vec();
        attach_wire[2] = 0x04;
        let attach = decode_nas_eps_message(&attach_wire).unwrap();
        assert!(
            attach
                .validate()
                .iter()
                .any(|error| error.field == "eps_attach_type")
        );

        let update = NasTrackingAreaUpdateRequest::new(
            NasEpsUpdateType::new(4),
            NasKeySetIdentifier::new(0),
            NasEpsMobileIdentity::new(vec![0; 11]),
        );
        assert!(
            update
                .validate()
                .iter()
                .any(|error| error.field == "eps_update_type")
        );
    }

    #[test]
    fn apn_with_invalid_label_is_rejected_by_typed_helpers_and_validation() {
        let wire = [0x02, 0x01, 0xd0, 0x11, 0x28, 0x04, 0x03, b'a', b'_', b'b'];
        let message = decode_nas_eps_message(&wire).unwrap();
        let NasEpsMessage::Esm(_, NasEsmMessage::PdnConnectivityRequest(request)) = &message else {
            panic!("expected PDN CONNECTIVITY REQUEST");
        };
        assert!(request.access_point_name.is_none());
        assert_eq!(request.unknown_ies.len(), 1);
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        assert!(NasAccessPointName::from_string("a_b").is_none());
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "unknown_ies")
        );
    }

    #[test]
    fn received_reserved_pco_selector_is_invalid_for_sending() {
        let wire = [0x02, 0x01, 0xd0, 0x11, 0x27, 0x01, 0x81];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "protocol_configuration_options")
        );
    }

    #[test]
    fn received_timer_unit_six_is_invalid_for_t3396() {
        let wire = [0x52, 0x00, 0xcd, 0x24, 0x37, 0x01, 0xc1];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "t3396_value")
        );
    }

    #[test]
    fn received_radio_priority_fallback_is_invalid_for_sending() {
        let wire = [
            0x52, 0x01, 0xc1, 0x01, 0x09, 0x02, 0x01, 0x61, 0x05, 0x01, 0x0a, 0x00, 0x00, 0x01,
            0x80,
        ];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "radio_priority")
        );
    }

    #[test]
    fn spare_bits_in_network_feature_and_access_control_are_invalid_for_sending() {
        let wire = [
            0x07, 0x42, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02,
            0x01, 0xd0, 0x11, 0x64, 0x03, 0x00, 0x00, 0x80, 0x20, 0x02, 0xff, 0xff,
        ];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        let errors = message.validate();
        assert!(
            errors
                .iter()
                .any(|error| error.field == "eps_network_feature_support")
        );
        assert!(
            errors
                .iter()
                .any(|error| error.field == "access_technology_utilization_control")
        );
    }

    #[test]
    fn spare_bits_in_replayed_ue_security_capabilities_are_invalid_for_sending() {
        let wire = [0x07, 0x5d, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x80];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "replayed_ue_security_capabilities")
        );
    }

    #[test]
    fn optional_esm_container_is_checked_for_a_complete_esm_pdu() {
        let mut request = NasControlPlaneServiceRequest::new(
            NasControlPlaneServiceType::new(0),
            NasKeySetIdentifier::new(0),
        );
        request.esm_message_container = Some(NasEsmMessageContainer::new(vec![0xff; 3]));
        assert!(
            request
                .validate()
                .iter()
                .any(|error| error.field == "esm_message_container")
        );
    }

    #[test]
    fn delegated_ie_payload_lengths_and_values_are_checked() {
        for (wire, field) in [
            (
                vec![
                    0x07, 0x42, 0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x02, 0x01, 0xd0,
                    0x11, 0x21, 0x01, 0x01,
                ],
                "s_and_f_satellite_operation_parameters",
            ),
            (
                vec![
                    0x07, 0x42, 0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x02, 0x01, 0xd0,
                    0x11, 0x4a, 0x04, 0x02, 0xf8, 0x39, 0x00,
                ],
                "equivalent_plmns",
            ),
            (
                vec![0x02, 0x01, 0xe9, 0x79, 0x00, 0x02, 0x01, 0x00],
                "remote_ue_context_connected",
            ),
            (
                vec![0x02, 0x01, 0xe9, 0x6f, 0x01, 0x01],
                "prose_key_management_function_address",
            ),
            (
                vec![0x07, 0x4c, 0, 5, 0xf4, 0, 0, 0, 0, 0x28, 1, 3],
                "paging_restriction",
            ),
            (
                vec![0x07, 0x4f, 0x37, 1, 0xff],
                "eps_additional_request_result",
            ),
            (vec![0x02, 0x01, 0xdb, 0x01, 0x02], "notification_indicator"),
            (
                vec![0x02, 0x01, 0xd1, 0x1b, 0x37, 0x01, 0x21, 0x6b, 0x01, 0xfc],
                "re_attempt_indicator",
            ),
            (
                vec![
                    0x07, 0x41, 0x71, 0x04, 0x19, 0x32, 0x54, 0x76, 0x02, 0xe0, 0xe0, 0x00, 0x04,
                    0x02, 0x01, 0xd0, 0x31, 0x40, 0x03, 0x00, 0x02, 0xff,
                ],
                "supported_codecs",
            ),
            (
                vec![0x07, 0x61, 0x49, 0x01, 0xff],
                "network_daylight_saving_time",
            ),
            (
                vec![
                    0x07, 0x42, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 4, 2, 1, 0xd0, 0x11, 0x34, 3, 5, 0,
                    0x11,
                ],
                "emergency_number_list",
            ),
            (
                vec![
                    0x07, 0x42, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 4, 2, 1, 0xd0, 0x11, 0x7a, 0, 4, 0,
                    5, 0x11, 0,
                ],
                "extended_emergency_number_list",
            ),
            (
                vec![
                    0x07, 0x41, 0x71, 4, 0x19, 0x32, 0x54, 0x76, 2, 0xe0, 0xe0, 0, 4, 2, 1, 0xd0,
                    0x31, 0x5d, 1, 0xf8,
                ],
                "voice_domain_preference_and_ue_usage_setting",
            ),
            (
                vec![
                    0x07, 0x41, 0x71, 4, 0x19, 0x32, 0x54, 0x76, 2, 0xe0, 0xe0, 0, 4, 2, 1, 0xd0,
                    0x31, 0x32, 1, 0x80,
                ],
                "n1_ue_network_capability",
            ),
            (
                vec![
                    0x07, 0x41, 0x71, 4, 0x19, 0x32, 0x54, 0x76, 2, 0xe0, 0xe0, 0, 4, 2, 1, 0xd0,
                    0x31, 0x10, 2, 0x12, 1,
                ],
                "tmsi_based_nri_container",
            ),
            (vec![0x07, 0x61, 0x43, 1, 0xa0], "full_name_for_network"),
            (
                vec![
                    0x07, 0x42, 1, 0, 6, 0, 0, 0, 0, 0, 0, 0, 4, 2, 1, 0xd0, 0x11, 0x1f, 1, 2,
                ],
                "unavailability_configuration",
            ),
        ] {
            let message = decode_nas_eps_message(&wire).unwrap();
            assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
            assert!(
                message.validate().iter().any(|error| error.field == field),
                "{field}"
            );
        }
    }

    #[test]
    fn attach_request_uses_packed_fields_and_optional_ie_formats() {
        let message = NasAttachRequest::new(
            NasEpsAttachType::new(1),
            NasKeySetIdentifier::new(7),
            NasEpsMobileIdentity::from_imsi("1234567").unwrap(),
            NasUeNetworkCapability::new(vec![0xE0, 0xE0]),
            NasEsmMessageContainer::new(vec![0x02, 0x01, 0xD0, 0x31]),
        )
        .set_tmsi_status(NasTmsiStatus::new(1))
        .set_drx_parameter(NasDrxParameter::new(vec![0x40, 0x60]));
        let pdu = NasEpsMessage::new_emm(NasEmmMessage::AttachRequest(message));
        let expected = [
            0x07, 0x41, 0x71, 0x04, 0x19, 0x32, 0x54, 0x76, 0x02, 0xE0, 0xE0, 0x00, 0x04, 0x02,
            0x01, 0xD0, 0x31, 0x5C, 0x40, 0x60, 0x91,
        ];
        // Optional IEs follow chapter 8 table order, not builder call order.
        assert_eq!(pdu.to_bytes().unwrap(), expected);
        assert!(pdu.validate().is_empty());
        assert_eq!(
            NasEpsMessage::from_bytes(&expected)
                .unwrap()
                .to_bytes()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn pdn_connectivity_request_uses_esm_header_and_tlve() {
        let message = NasPdnConnectivityRequest::new(NasRequestType::new(1), NasPdnType::new(3))
            .set_access_point_name(NasAccessPointName::new(vec![3, b'i', b'm', b's']))
            .set_extended_protocol_configuration_options(
                NasExtendedProtocolConfigurationOptions::new(vec![0x80, 0x00]),
            );
        let pdu = NasEpsMessage::new_esm(NasEsmMessage::PdnConnectivityRequest(message), 0, 1);
        let expected = [
            0x02, 0x01, 0xD0, 0x31, 0x28, 0x04, 3, b'i', b'm', b's', 0x7B, 0x00, 0x02, 0x80, 0x00,
        ];
        assert_eq!(pdu.to_bytes().unwrap(), expected);
        assert_eq!(
            NasEpsMessage::from_bytes(&expected)
                .unwrap()
                .to_bytes()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn eps_special_headers_round_trip() {
        let service = [0xC7, 0x12, 0xAB, 0xCD];
        assert_eq!(
            NasEpsMessage::from_bytes(&service)
                .unwrap()
                .to_bytes()
                .unwrap(),
            service
        );

        let transport = [0xB7, 1, 2, 3, 4, 5, 0x79, 0xAA, 0xBB];
        assert_eq!(
            NasEpsMessage::from_bytes(&transport)
                .unwrap()
                .to_bytes()
                .unwrap(),
            transport
        );

        let protected = [0x27, 1, 2, 3, 4, 5, 0xAA, 0xBB];
        assert_eq!(
            NasEpsMessage::from_bytes(&protected)
                .unwrap()
                .to_bytes()
                .unwrap(),
            protected
        );
        assert!(is_security_protected(&protected));

        let integrity_only = [0x17, 1, 2, 3, 4, 5, 0x07, 0x60, 0x02];
        assert_eq!(
            NasEpsMessage::from_bytes(&integrity_only)
                .unwrap()
                .to_bytes()
                .unwrap(),
            integrity_only
        );
    }

    #[test]
    fn detach_request_forms_dispatch_by_mobile_identity_length() {
        let from_ue = NasEpsMessage::new_emm(NasEmmMessage::DetachRequestFromUe(
            NasDetachRequestFromUe::new(
                NasDetachType::new(1),
                NasKeySetIdentifier::new(1),
                NasEpsMobileIdentity::from_imsi("001010123456789").unwrap(),
            ),
        ))
        .to_bytes()
        .unwrap();
        let to_ue = [0x07, 0x45, 0x01, 0x53, 0x02];
        assert!(matches!(
            NasEpsMessage::from_bytes(&from_ue).unwrap(),
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestFromUe(_))
        ));
        assert!(matches!(
            NasEpsMessage::from_bytes(&to_ue).unwrap(),
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestToUe(_))
        ));
    }

    fn pdu(text: &str) -> Vec<u8> {
        hex::decode(text.replace(' ', "")).unwrap()
    }

    fn findings(bytes: &[u8]) -> Vec<(&'static str, crate::common::Severity)> {
        decode_nas_eps_message(bytes)
            .unwrap()
            .validate()
            .into_iter()
            .map(|finding| (finding.field, finding.severity))
            .collect()
    }

    #[test]
    fn chapter_seven_receiver_cases_from_the_codec_audit() {
        use crate::common::Severity::{Error, Warning};
        // Codec review C-9: an envelope without a message is too short
        // (§7.2) on both decoders.
        let empty = [0x17, 0, 0, 0, 0, 0];
        assert_eq!(
            decode_nas_eps_message(&empty),
            Err(NasError::MessageTooShort)
        );
        assert_eq!(
            decode_nas_eps_message_with_direction(&empty, Direction::Uplink),
            Err(NasError::MessageTooShort)
        );
        // T1, T2: unknown type 1/2 and TLV-E IEs are skipped by their format
        // and re-emitted unchanged; they are not comprehension required.
        for text in [
            "07 60 03 B5",
            "07 60 03 A1",
            "07 60 03 78 00 02 AA BB",
            "07 60 03 7D 00 00",
        ] {
            let bytes = pdu(text);
            let message = decode_nas_eps_message(&bytes).unwrap();
            assert_eq!(encode_nas_eps_message(&message).unwrap(), bytes, "{text}");
            assert!(message.validate().is_empty(), "{text}");
        }
        // T3: an unknown non-comprehension-required IE that overruns the PDU
        // is ignored and consumes the unknowable remainder (§7.6.1).
        for text in ["07 60 03 49 05 80", "07 60 03 78 00"] {
            let bytes = pdu(text);
            let message = decode_nas_eps_message(&bytes).unwrap();
            assert_eq!(encode_nas_eps_message(&message).unwrap(), bytes, "{text}");
        }
        // A known syntactically incorrect optional IE is treated as absent
        // (§7.7.1), while its bytes remain available for lossless relay.
        for text in ["07 61 47 01 02", "07 61 45 01 80 45 05 80"] {
            let bytes = pdu(text);
            let message = decode_nas_eps_message(&bytes).unwrap();
            assert_eq!(encode_nas_eps_message(&message).unwrap(), bytes, "{text}");
        }
        let bytes = pdu("07 4F 57 00");
        let message = decode_nas_eps_message(&bytes).unwrap();
        assert_eq!(encode_nas_eps_message(&message).unwrap(), bytes);
        let NasEpsMessage::Emm(_, NasEmmMessage::ServiceAccept(accept)) = message else {
            panic!("SERVICE ACCEPT expected");
        };
        assert!(accept.eps_bearer_context_status.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);
        assert!(matches!(
            accept.optional_ie_order.as_slice(),
            [crate::common::OptionalIeOrder::Ignored(
                0,
                crate::common::IgnoredIeReason::Malformed
            )]
        ));
        // T4: a truncated mandatory IE names the field (§7.5.1).
        assert_eq!(
            decode_nas_eps_message(&pdu("07 56 08 09")).unwrap_err(),
            NasError::InvalidMandatoryIe("mobile_identity")
        );
        assert_eq!(
            decode_nas_eps_message(&pdu("07 43 00 05 52 01")).unwrap_err(),
            NasError::InvalidMandatoryIe("esm_message_container")
        );
        // T5, T6: longer and empty optional TLVs decode.
        assert!(decode_nas_eps_message(&pdu("07 44 02 5F 02 21 00")).is_ok());
        assert!(decode_nas_eps_message(&pdu("07 49 00 4A 00")).is_ok());
        // T7, T8: a repetition is skipped whatever its content (§7.6.3).
        for text in [
            "07 44 02 16 01 21 16 02 21 22",
            "02 01 D0 11 7B 00 01 80 7B 00 01 80",
        ] {
            let bytes = pdu(text);
            let message = decode_nas_eps_message(&bytes).unwrap();
            assert_eq!(encode_nas_eps_message(&message).unwrap(), bytes, "{text}");
        }
        // T9: a non-comprehension-required out-of-sequence IE is ignored
        // for receiver semantics (§7.6.2) and retained as raw evidence.
        let NasEpsMessage::Emm(_, NasEmmMessage::EmmInformation(information)) =
            decode_nas_eps_message(&pdu("07 61 49 01 00 43 01 80")).unwrap()
        else {
            panic!("EMM INFORMATION expected");
        };
        assert!(information.network_daylight_saving_time.is_some());
        assert!(information.full_name_for_network.is_none());
        assert_eq!(information.unknown_ies.len(), 1);
        // T10, T12, T13, T14, T15: header errors keep what STATUS needs.
        assert_eq!(
            decode_nas_eps_message(&pdu("67 00 00 00 00 00 07 60 03")).unwrap_err(),
            NasError::ReservedSecurityHeaderType(6)
        );
        assert!(decode_nas_eps_message(&pdu("17 00 00 00 00 00 C7 12 AB CD")).is_err());
        assert_eq!(
            decode_nas_eps_message(&pdu("07 40")).unwrap_err(),
            NasError::UnknownMessageType(0x40)
        );
        assert_eq!(
            decode_nas_eps_message(&pdu("52 01 FF")).unwrap_err(),
            NasError::UnknownSessionMessageType {
                identity: 5,
                pti: 1,
                message_type: 0xff
            }
        );
        assert_eq!(
            decode_nas_eps_message(&pdu("02 01 41")).unwrap_err(),
            NasError::UnknownSessionMessageType {
                identity: 0,
                pti: 1,
                message_type: 0x41
            }
        );
        for text in ["07", "52 01", "C7 12 AB", "17 00 00 00 00"] {
            assert_eq!(
                decode_nas_eps_message(&pdu(text)).unwrap_err(),
                NasError::MessageTooShort,
                "{text}"
            );
        }
        assert_eq!(
            decode_nas_eps_message(&pdu("05 41")).unwrap_err(),
            NasError::UnknownProtocolDiscriminator(5)
        );
        // T17: spare bits are ignored by the receiver (TS 24.007 §11.1.4)
        // and retained for relay; sender validation still reports them.
        let spare = decode_nas_eps_message(&pdu("07 55 F1")).unwrap();
        assert_eq!(encode_nas_eps_message(&spare).unwrap(), pdu("07 55 F1"));
        assert!(
            spare
                .validate()
                .iter()
                .any(|finding| finding.field == "spare_half_octet")
        );
        // T18 (F-12): a one-octet EMM TRANSPORT container is too short.
        assert!(findings(&pdu("B7 01 02 03 04 05 79")).contains(&("protected_payload", Error)));
        // T19 (F-10): an IE set after decoding goes to its table position.
        let mut message = decode_nas_eps_message(&pdu("07 61 49 01 00")).unwrap();
        let NasEpsMessage::Emm(_, NasEmmMessage::EmmInformation(information)) = &mut message else {
            panic!("EMM INFORMATION expected");
        };
        information.set_full_name_for_network_mut(NasNetworkName::new(vec![0x80]));
        assert_eq!(
            encode_nas_eps_message(&message).unwrap(),
            pdu("07 61 43 01 80 49 01 00")
        );
        // T21-T25 (F-09): chapter 8 conditions decided by content alone.
        assert!(
            findings(&pdu("07 4C 08 05 F4 12 34 56 78 28 01 01"))
                .contains(&("paging_restriction", Error))
        );
        let tau = findings(&pdu(
            "07 48 00 0B F6 02 F8 39 80 01 01 12 34 56 78 E0 29 01 02 28 01 01",
        ));
        assert!(
            tau.contains(&("ue_request_type", Error))
                && tau.contains(&("paging_restriction", Error))
        );
        assert_eq!(
            findings(&pdu("02 01 D5 41 37 01 21")),
            [("back_off_timer_value", Warning)]
        );
        assert_eq!(
            findings(&pdu("02 01 D1 32 37 01 21")),
            [("back_off_timer_value", Warning)]
        );
        assert_eq!(
            findings(&pdu("52 00 CD 24 37 01 21")),
            [("t3396_value", Warning)]
        );
        let periodic = findings(&pdu(
            "07 48 03 0B F6 02 F8 39 80 01 01 12 34 56 78 E0 36 01 00",
        ));
        assert!(periodic.contains(&("drx_parameter_in_nb_s1_mode", Warning)));
        let both = findings(&pdu(
            "52 01 C1 01 09 09 08 69 6E 74 65 72 6E 65 74 05 01 0A 00 00 01 27 01 80 7B 00 01 80",
        ));
        assert!(both.contains(&("extended_protocol_configuration_options", Warning)));
    }

    #[test]
    fn network_detach_with_optional_ies_is_not_read_as_the_ue_form() {
        // Codec audit F-01: "re-attach required" with a 27-octet forbidden
        // TAI list (IEI 1D) and a disaster return wait range (IEI 24).
        let bytes = hex::decode(
            "07450 11D1B02F83900010002000300000000000000000000000000000000000000002402 0105"
                .replace(' ', ""),
        )
        .unwrap();
        assert!(matches!(
            decode_nas_eps_message(&bytes).unwrap(),
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestToUe(_))
        ));
        // Codec review C-2: the network IEs fill exactly 28 octets, so the UE
        // form would read them as an EPS mobile identity longer than the 11
        // value octets TS 24.301 §9.9.3.12 allows.
        let bytes = pdu("0745 01 1C0121 1D0600F839000001 1E0600F839000002 2008 0000000000000000");
        let message = decode_nas_eps_message(&bytes).unwrap();
        assert!(matches!(
            message,
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestToUe(_))
        ));
        // Its IE contents are arbitrary, but no identity is reported.
        assert!(
            message
                .validate()
                .iter()
                .all(|finding| finding.field != "eps_mobile_identity")
        );
        // A UE form keeps winning when its identity is plausible.
        let from_ue = pdu("0745 09 0BF602F83900010203040506");
        assert!(matches!(
            decode_nas_eps_message(&from_ue).unwrap(),
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestFromUe(_))
        ));
    }

    #[test]
    fn truncated_fixed_authentication_parameter_is_rejected() {
        let pdu = [0x07, 0x52, 0x01, 0xAA];
        assert_eq!(
            NasEpsMessage::from_bytes(&pdu).unwrap_err(),
            NasError::InvalidMandatoryIe("authentication_parameter_rand_eps_challenge")
        );
    }

    #[test]
    fn unknown_optional_ie_round_trips() {
        let pdu = [0x07, 0x60, 0x02, 0x49, 0x01, 0xAA];
        let decoded = NasEpsMessage::from_bytes(&pdu).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), pdu);

        let interleaved = [
            0x07, 0x61, 0x40, 0x01, 0xaa, 0x49, 0x01, 0x00, 0x43, 0x01, 0x80,
        ];
        let decoded = NasEpsMessage::from_bytes(&interleaved).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), interleaved);
    }

    #[test]
    fn adversarial_eps_ie_vectors_keep_receiver_tolerance_separate_from_sender_rules() {
        // TS 24.008 §10.5.6.5: a received Release-99 QoS IE may use the
        // three-octet legacy form, although an EPS sender emits at least twelve
        // value octets. The decoder retains it; sender validation reports it.
        let legacy_qos = pdu("52 01 C9 30 03 0B 11 01");
        let message = NasEpsMessage::from_bytes(&legacy_qos).unwrap();
        let NasEpsMessage::Esm(_, NasEsmMessage::ModifyEpsBearerContextRequest(request)) = &message
        else {
            panic!("MODIFY EPS BEARER CONTEXT REQUEST expected");
        };
        assert_eq!(request.new_qos.as_ref().unwrap().value, [0x0b, 0x11, 0x01]);
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "new_qos")
        );
        assert_eq!(message.to_bytes().unwrap(), legacy_qos);

        // TS 24.301 §9.9.4.20: identity type 000 is reserved. Its raw context
        // remains relayable, but it is not a sender-valid Remote UE Context.
        let remote = pdu("52 01 E9 79 00 06 01 04 01 01 00 00");
        let message = NasEpsMessage::from_bytes(&remote).unwrap();
        let NasEpsMessage::Esm(_, NasEsmMessage::RemoteUeReport(report)) = &message else {
            panic!("REMOTE UE REPORT expected");
        };
        assert!(report.remote_ue_context_connected.is_some());
        assert!(
            message
                .validate()
                .iter()
                .any(|error| { error.field == "remote_ue_context_connected" })
        );
        assert_eq!(message.to_bytes().unwrap(), remote);

        // TS 24.008 §10.5.4.9: presentation indicator 11 is reserved. An
        // optional malformed CLI is treated as absent while its bytes remain
        // in the unknown-IE stream for byte-exact forwarding.
        let cli = pdu("07 64 00 60 02 11 E0");
        let message = NasEpsMessage::from_bytes(&cli).unwrap();
        let NasEpsMessage::Emm(_, NasEmmMessage::CsServiceNotification(notification)) = &message
        else {
            panic!("CS SERVICE NOTIFICATION expected");
        };
        assert!(notification.cli.is_none());
        assert_eq!(notification.unknown_ies.len(), 1);
        assert_eq!(message.to_bytes().unwrap(), cli);

        // TS 24.008 §10.5.6.65: additional setup type 9 is reserved.
        let header_compression = pdu("02 01 D0 11 66 04 00 00 01 09");
        let message = NasEpsMessage::from_bytes(&header_compression).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| { error.field == "header_compression_configuration" })
        );
        assert_eq!(message.to_bytes().unwrap(), header_compression);
    }

    #[test]
    fn unknown_comprehension_required_ies_are_reported() {
        // TS 24.007 §11.2.5: type 4 IEIs 0x00-0x0F and type 6 IEIs 0x7E-0x7F.
        for (wire, flagged) in [
            (&[0x07, 0x60, 0x02, 0x49, 0x01, 0xaa][..], false),
            (&[0x07, 0x60, 0x02, 0x0f, 0x01, 0xaa][..], true),
            (&[0x07, 0x60, 0x02, 0x7e, 0x00, 0x01, 0xaa][..], true),
            (&[0x07, 0x60, 0x02, 0x7c, 0x00, 0x01, 0xaa][..], false),
        ] {
            let message = NasEpsMessage::from_bytes(wire).unwrap();
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
    fn table_length_validation_reports_bad_ie() {
        let mut request = NasAttachRequest::new(
            NasEpsAttachType::new(1),
            NasKeySetIdentifier::new(7),
            NasEpsMobileIdentity::from_imsi("1234567").unwrap(),
            NasUeNetworkCapability::new(vec![0, 0]),
            NasEsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        );
        request.eps_mobile_identity.length = 1;
        let errors = request.validate();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].field, "eps_mobile_identity");
    }

    #[test]
    fn conditional_eps_ies_follow_chapter_eight_rules() {
        for pdu in [
            &[0x02, 0x01, 0xD5, 0x20, 0x6B, 0x01, 0x00][..],
            &[0x02, 0x01, 0xD7, 0x20, 0x6B, 0x01, 0x00],
            &[0x02, 0x01, 0xD1, 0x20, 0x6B, 0x01, 0x00],
            &[0x07, 0x49, 0x00, 0x5E, 0x01, 0x21],
            &[
                0x02, 0x01, 0xD0, 0x11, 0x27, 0x01, 0x80, 0x7B, 0x00, 0x01, 0x80,
            ],
        ] {
            let message = NasEpsMessage::from_bytes(pdu).unwrap();
            assert!(!message.validate().is_empty(), "accepted {pdu:02x?}");
        }
    }

    #[test]
    fn explicit_direction_disambiguates_detach_in_plain_and_integrity_envelopes() {
        let downlink = [0x07, 0x45, 0x01, 0x05, 0x04, 0x11, 0x22, 0x33, 0x44];
        assert!(matches!(
            decode_nas_eps_message_with_direction(&downlink, Direction::Downlink).unwrap(),
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestToUe(_))
        ));
        let mut protected = vec![0x17, 0, 0, 0, 0, 0];
        protected.extend_from_slice(&downlink);
        assert!(matches!(
            decode_nas_eps_message_with_direction(&protected, Direction::Downlink).unwrap(),
            NasEpsMessage::SecurityProtected(_, inner) if matches!(*inner, NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestToUe(_)))
        ));
    }

    #[test]
    fn malformed_eps_headers_do_not_encode_or_decode() {
        assert!(NasEpsMessage::from_bytes(&[0x27, 0, 0, 0, 0, 0]).is_err());
        assert!(
            !NasEpsMessage::from_bytes(&[0x12, 0x01, 0xD0, 0x11])
                .unwrap()
                .validate()
                .is_empty()
        );
        let header = NasEsmHeader::new(NasEsmMessageType::PdnConnectivityRequest, 3, 1);
        let mut buffer = BytesMut::new();
        header.encode(&mut buffer).unwrap();
        assert_eq!(NasEsmHeader::decode(&mut buffer.freeze()).unwrap(), header);
        let reserved_pti = NasEpsMessage::from_bytes(&[0x02, 0xff, 0xd0, 0x11]).unwrap();
        assert!(matches!(
            reserved_pti,
            NasEpsMessage::Esm(
                NasEsmHeader {
                    procedure_transaction_identity: 0xff,
                    ..
                },
                NasEsmMessage::PdnConnectivityRequest(_)
            )
        ));
        assert!(
            reserved_pti
                .validate()
                .iter()
                .any(|error| error.field == "procedure_transaction_identity")
        );
        assert_eq!(reserved_pti.to_bytes().unwrap(), [0x02, 0xff, 0xd0, 0x11]);
    }

    #[test]
    fn repeated_optional_ies_keep_first_occurrence() {
        // TS 24.301 §7.6.3: only the first repetition is handled. Later
        // repetitions are kept as ignored octets so relayed bytes are unchanged.
        let repeated_pco = [
            0x02, 0x01, 0xd0, 0x11, 0x27, 0x01, 0x80, 0x27, 0x02, 0x80, 0x00,
        ];
        let message = NasEpsMessage::from_bytes(&repeated_pco).unwrap();
        let NasEpsMessage::Esm(_, NasEsmMessage::PdnConnectivityRequest(request)) = &message else {
            panic!("expected PDN CONNECTIVITY REQUEST");
        };
        assert_eq!(
            request
                .protocol_configuration_options
                .as_ref()
                .unwrap()
                .value,
            [0x80]
        );
        assert_eq!(
            request.unknown_ies,
            [UnknownIe {
                iei: 0x27,
                data: vec![0x02, 0x80, 0x00],
            }]
        );
        assert_eq!(message.to_bytes().unwrap(), repeated_pco);

        // Type 1 and LV fields carried with an IEI follow the same rule.
        let repeated_half_and_guti = [
            0x07, 0x42, 0x01, 0x00, 0x06, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x00, 0x04, 0x02,
            0x01, 0xd1, 0x00, 0x50, 0x0b, 0xf6, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x50, 0x0b, 0xf6, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x02, 0xf1, 0xf2,
        ];
        let message = NasEpsMessage::from_bytes(&repeated_half_and_guti).unwrap();
        let NasEpsMessage::Emm(_, NasEmmMessage::AttachAccept(accept)) = &message else {
            panic!("expected ATTACH ACCEPT");
        };
        assert_eq!(accept.guti.as_ref().unwrap().as_guti().unwrap().m_tmsi, 1);
        assert_eq!(accept.unknown_ies.len(), 2);
        assert_eq!(message.to_bytes().unwrap(), repeated_half_and_guti);
    }

    #[test]
    fn esm_header_validation_uses_procedure_family() {
        let request = NasPdnConnectivityRequest::new(NasRequestType::new(1), NasPdnType::new(1));
        let wrong_ebi =
            NasEpsMessage::new_esm(NasEsmMessage::PdnConnectivityRequest(request.clone()), 5, 1);
        assert!(
            wrong_ebi
                .validate()
                .iter()
                .any(|error| error.field == "eps_bearer_identity")
        );
        let missing_pti =
            NasEpsMessage::new_esm(NasEsmMessage::PdnConnectivityRequest(request), 0, 0);
        assert!(
            missing_pti
                .validate()
                .iter()
                .any(|error| error.field == "procedure_transaction_identity")
        );
        let dummy = NasEpsMessage::new_esm(
            NasEsmMessage::EsmDummyMessage(NasEsmDummyMessage::new()),
            5,
            0,
        );
        assert!(
            dummy
                .validate()
                .iter()
                .any(|error| error.field == "eps_bearer_identity")
        );
    }

    #[test]
    fn identity_and_authentication_ksi_follow_eps_value_rules() {
        assert!(matches!(
            NasEpsMessage::from_bytes_with_direction(
                &[0x07, 0x45, 0x01, 0x04, 0, 0, 0, 0],
                Direction::Uplink,
            ),
            Err(NasError::InvalidMandatoryIe("eps_mobile_identity"))
        ));

        let mut invalid_ksi = vec![0x07, 0x52, 0x07];
        invalid_ksi.extend_from_slice(&[0; 16]);
        invalid_ksi.push(16);
        invalid_ksi.extend_from_slice(&[0; 16]);
        let message = NasEpsMessage::from_bytes(&invalid_ksi).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "nas_key_set_identifier_asme")
        );
    }

    #[test]
    fn t3402_follows_its_ie_type_in_each_message() {
        use crate::nas_eps::ie::{GprsTimerUnit, GprsTimerValue};
        // GPRS timer (TV) in ATTACH ACCEPT, GPRS timer 2 (TLV) in ATTACH
        // REJECT (Tables 8.2.1.1 and 8.2.3.1).
        let tv = [
            0x07, 0x42, 0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x02, 0x01, 0xd0, 0x11, 0x17,
            0x21,
        ];
        let tlv = [0x07, 0x44, 0x02, 0x16, 0x01, 0x21];
        for wire in [tv.as_slice(), tlv.as_slice()] {
            let decoded = decode_nas_eps_message(wire).unwrap();
            assert_eq!(encode_nas_eps_message(&decoded).unwrap(), wire);
            assert!(decoded.validate().is_empty());
        }
        // Codec review C-1: octets beyond the defined value are ignored by
        // the typed getters (TS 24.007 §11.4.2) but kept for re-encoding,
        // and validate() reports the sender error.
        let wire = &[0x07, 0x44, 0x02, 0x16, 0x03, 0x21, 0xaa, 0xbb][..];
        {
            let message = decode_nas_eps_message(wire).unwrap();
            assert_eq!(encode_nas_eps_message(&message).unwrap(), wire);
            assert!(
                message
                    .validate()
                    .iter()
                    .any(|error| error.field == "t3402_value")
            );
            let NasEpsMessage::Emm(_, NasEmmMessage::AttachReject(reject)) = message else {
                panic!("ATTACH REJECT expected");
            };
            let timer = reject.t3402_value.unwrap();
            assert_eq!(timer.unit(), Some(GprsTimerUnit::OneMinute));
            assert_eq!(timer.value(), Some(GprsTimerValue::Seconds(60)));
        }
        let empty = &[0x07, 0x44, 0x02, 0x16, 0x00][..];
        let message = decode_nas_eps_message(empty).unwrap();
        assert_eq!(encode_nas_eps_message(&message).unwrap(), empty);
        let NasEpsMessage::Emm(_, NasEmmMessage::AttachReject(reject)) = message else {
            panic!("ATTACH REJECT expected");
        };
        assert!(reject.t3402_value.is_none());
        assert_eq!(reject.unknown_ies.len(), 1);
    }
}
