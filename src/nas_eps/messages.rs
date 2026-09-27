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

use crate::common::{Decode, Encode, NasError, Result, helpers};
use crate::common::{UnknownIe, nas_message, nas_message_impl_default};
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
    pub security_header_type: NasEpsSecurityHeaderType,
    pub message_authentication_code: u32,
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
            return Err(NasError::BufferTooShort);
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
// TS 24.301 V19.6.0 chapter 8/9 table definitions.

nas_message! {
    /// ATTACH ACCEPT (Table 8.2.1.1).
    pub struct NasAttachAccept {
        mandatory {
            eps_attach_result: NasEpsAttachResult [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            t3412_value: NasT3412Value,
            tai_list: NasTaiList,
            esm_message_container: NasEsmMessageContainer,
        }
        optional {
            0x50 => guti: NasGuti [opt_type],
            0x13 => location_area_identification: NasLocationAreaIdentification,
            0x23 => ms_identity: NasMsIdentity,
            0x53 => emm_cause: NasEmmCause [opt_type],
            0x17 => t3402_value: NasT3402Value [opt_type],
            0x59 => t3423_value: NasT3423Value,
            0x4A => equivalent_plmns: NasEquivalentPlmns,
            0x34 => emergency_number_list: NasEmergencyNumberList,
            0x64 => eps_network_feature_support: NasEpsNetworkFeatureSupport,
            0xF0 => additional_update_result: NasAdditionalUpdateResult [tv1],
            0x5E => t3412_extended_value: NasT3412ExtendedValue,
            0x6A => t3324_value: NasT3324Value,
            0x6E => extended_drx_parameters: NasExtendedDrxParameters,
            0x65 => dcn_id: NasDcnId,
            0xE0 => sms_services_status: NasSmsServicesStatus [tv1],
            0xD0 => non_3gpp_nw_provided_policies: NasNon3gppNwProvidedPolicies [tv1],
            0x6B => t3448_value: NasT3448Value,
            0xC0 => network_policy: NasNetworkPolicy [tv1],
            0x6C => t3447_value: NasT3447Value,
            0x7A => extended_emergency_number_list: NasExtendedEmergencyNumberList,
            0x7C => ciphering_key_data: NasCipheringKeyData,
            0x66 => ue_radio_capability_id: NasUeRadioCapabilityId,
            0xB0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1],
            0x35 => negotiated_wus_assistance_information: NasNegotiatedWusAssistanceInformation,
            0x36 => negotiated_drx_parameter_in_nb_s1_mode: NasNegotiatedDrxParameterInNbS1Mode,
            0x38 => negotiated_imsi_offset: NasNegotiatedImsiOffset,
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
            0x1F => unavailability_configuration: NasUnavailabilityConfiguration,
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters,
            0x22 => disaster_roaming_wait_range: NasDisasterRoamingWaitRange,
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange,
            0x25 => list_of_plmns_to_be_used_in_disaster_condition: NasListOfPlmnsToBeUsedInDisasterCondition,
        }
    }
}

nas_message! {
    /// ATTACH COMPLETE (Table 8.2.2.1).
    pub struct NasAttachComplete {
        mandatory {
            esm_message_container: NasEsmMessageContainer,
        }
        optional {
        }
    }
}

nas_message! {
    /// ATTACH REJECT (Table 8.2.3.1).
    pub struct NasAttachReject {
        mandatory {
            emm_cause: NasEmmCause,
        }
        optional {
            0x78 => esm_message_container: NasEsmMessageContainer [opt_type],
            0x5F => t3346_value: NasT3346Value,
            0x16 => t3402_value: NasT3402Value [v_as_tlv],
            0xA0 => extended_emm_cause: NasExtendedEmmCause [tv1],
            0x1C => lower_bound_timer_value: NasLowerBoundTimerValue,
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters,
        }
    }
}

nas_message! {
    /// ATTACH REQUEST (Table 8.2.4.1).
    pub struct NasAttachRequest {
        mandatory {
            eps_attach_type: NasEpsAttachType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
            eps_mobile_identity: NasEpsMobileIdentity,
            ue_network_capability: NasUeNetworkCapability,
            esm_message_container: NasEsmMessageContainer,
        }
        optional {
            0x19 => old_p_tmsi_signature: NasOldPTmsiSignature,
            0x50 => additional_guti: NasAdditionalGuti,
            0x52 => last_visited_registered_tai: NasLastVisitedRegisteredTai,
            0x5C => drx_parameter: NasDrxParameter,
            0x31 => ms_network_capability: NasMsNetworkCapability,
            0x13 => old_location_area_identification: NasOldLocationAreaIdentification,
            0x90 => tmsi_status: NasTmsiStatus [tv1],
            0x11 => mobile_station_classmark_2: NasMobileStationClassmark2,
            0x20 => mobile_station_classmark_3: NasMobileStationClassmark3,
            0x40 => supported_codecs: NasSupportedCodecs,
            0xF0 => additional_update_type: NasAdditionalUpdateType [tv1],
            0x5D => voice_domain_preference_and_ue_usage_setting: NasVoiceDomainPreferenceAndUeUsageSetting,
            0xD0 => device_properties: NasDeviceProperties [tv1],
            0xE0 => old_guti_type: NasOldGutiType [tv1],
            0xC0 => ms_network_feature_support: NasMsNetworkFeatureSupport [tv1],
            0x10 => tmsi_based_nri_container: NasTmsiBasedNriContainer,
            0x6A => t3324_value: NasT3324Value,
            0x5E => t3412_extended_value: NasT3412ExtendedValue,
            0x6E => extended_drx_parameters: NasExtendedDrxParameters,
            0x6F => ue_additional_security_capability: NasUeAdditionalSecurityCapability,
            0x6D => ue_status: NasUeStatus,
            0x17 => additional_information_requested: NasAdditionalInformationRequested,
            0x32 => n1_ue_network_capability: NasN1UeNetworkCapability,
            0x34 => ue_radio_capability_id_availability: NasUeRadioCapabilityIdAvailability,
            0x35 => requested_wus_assistance_information: NasRequestedWusAssistanceInformation,
            0x36 => drx_parameter_in_nb_s1_mode: NasDrxParameterInNbS1Mode,
            0x38 => requested_imsi_offset: NasRequestedImsiOffset,
            0x26 => ue_determined_plmn_with_disaster_condition: NasUeDeterminedPlmnWithDisasterCondition,
        }
    }
}

nas_message! {
    /// AUTHENTICATION FAILURE (Table 8.2.5.1).
    pub struct NasAuthenticationFailure {
        mandatory {
            emm_cause: NasEmmCause,
        }
        optional {
            0x30 => authentication_failure_parameter: NasAuthenticationFailureParameter,
        }
    }
}

nas_message! {
    /// AUTHENTICATION REJECT (Table 8.2.6.1).
    pub struct NasAuthenticationReject {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// AUTHENTICATION REQUEST (Table 8.2.7.1).
    pub struct NasAuthenticationRequest {
        mandatory {
            nas_key_set_identifier_asme: NasKeySetIdentifierAsme [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            authentication_parameter_rand_eps_challenge: NasAuthenticationParameterRandEpsChallenge,
            authentication_parameter_autn_eps_challenge: NasAuthenticationParameterAutnEpsChallenge,
        }
        optional {
        }
    }
}

nas_message! {
    /// AUTHENTICATION RESPONSE (Table 8.2.8.1).
    pub struct NasAuthenticationResponse {
        mandatory {
            authentication_response_parameter: NasAuthenticationResponseParameter,
        }
        optional {
        }
    }
}

nas_message! {
    /// CS SERVICE NOTIFICATION (Table 8.2.9.1).
    pub struct NasCsServiceNotification {
        mandatory {
            paging_identity: NasPagingIdentity,
        }
        optional {
            0x60 => cli: NasCli,
            0x61 => ss_code: NasSsCode,
            0x62 => lcs_indicator: NasLcsIndicator,
            0x63 => lcs_client_identity: NasLcsClientIdentity,
        }
    }
}

nas_message! {
    /// DETACH ACCEPT (Table 8.2.10.1.1).
    pub struct NasDetachAccept {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// DETACH REQUEST (Table 8.2.11.1.1).
    pub struct NasDetachRequestFromUe {
        mandatory {
            detach_type: NasDetachType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
            eps_mobile_identity: NasEpsMobileIdentity,
        }
        optional {
        }
    }
}

nas_message! {
    /// DETACH REQUEST (Table 8.2.11.2.1).
    pub struct NasDetachRequestToUe {
        mandatory {
            detach_type: NasDetachType [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
        }
        optional {
            0x53 => emm_cause: NasEmmCause [opt_type],
            0x1C => lower_bound_timer_value: NasLowerBoundTimerValue,
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters,
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange,
        }
    }
}

nas_message! {
    /// DOWNLINK NAS TRANSPORT (Table 8.2.12.1).
    pub struct NasDownlinkNasTransport {
        mandatory {
            nas_message_container: NasMessageContainer,
        }
        optional {
        }
    }
}

nas_message! {
    /// EMM INFORMATION (Table 8.2.13.1).
    pub struct NasEmmInformation {
        mandatory {
        }
        optional {
            0x43 => full_name_for_network: NasFullNameForNetwork,
            0x45 => short_name_for_network: NasShortNameForNetwork,
            0x46 => local_time_zone: NasLocalTimeZone,
            0x47 => universal_time_and_local_time_zone: NasUniversalTimeAndLocalTimeZone,
            0x49 => network_daylight_saving_time: NasNetworkDaylightSavingTime,
        }
    }
}

nas_message! {
    /// EMM STATUS (Table 8.2.14.1).
    pub struct NasEmmStatus {
        mandatory {
            emm_cause: NasEmmCause,
        }
        optional {
        }
    }
}

nas_message! {
    /// EXTENDED SERVICE REQUEST (Table 8.2.15.1).
    pub struct NasExtendedServiceRequest {
        mandatory {
            service_type: NasServiceType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
            m_tmsi: NasMTmsi,
        }
        optional {
            0xB0 => csfb_response: NasCsfbResponse [tv1],
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus,
            0xD0 => device_properties: NasDeviceProperties [tv1],
            0x29 => ue_request_type: NasUeRequestType,
            0x28 => paging_restriction: NasPagingRestriction,
        }
    }
}

nas_message! {
    /// GUTI REALLOCATION COMMAND (Table 8.2.16.1).
    pub struct NasGutiReallocationCommand {
        mandatory {
            guti: NasGuti,
        }
        optional {
            0x54 => tai_list: NasTaiList [opt_type],
            0x65 => dcn_id: NasDcnId,
            0x66 => ue_radio_capability_id: NasUeRadioCapabilityId,
            0xB0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1],
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
        }
    }
}

nas_message! {
    /// GUTI REALLOCATION COMPLETE (Table 8.2.17.1).
    pub struct NasGutiReallocationComplete {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// IDENTITY REQUEST (Table 8.2.18.1).
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
    /// IDENTITY RESPONSE (Table 8.2.19.1).
    pub struct NasIdentityResponse {
        mandatory {
            mobile_identity: NasMobileIdentity,
        }
        optional {
        }
    }
}

nas_message! {
    /// SECURITY MODE COMMAND (Table 8.2.20.1).
    pub struct NasSecurityModeCommand {
        mandatory {
            selected_nas_security_algorithms: NasSelectedNasSecurityAlgorithms,
            nas_key_set_identifier: NasKeySetIdentifier [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            replayed_ue_security_capabilities: NasReplayedUeSecurityCapabilities,
        }
        optional {
            0xC0 => imeisv_request: NasImeisvRequest [tv1],
            0x55 => replayed_nonce_ue: NasReplayedNonceUe,
            0x56 => nonce_mme: NasNonceMme,
            0x4F => hash_mme: NasHashMme,
            0x6F => replayed_ue_additional_security_capability: NasReplayedUeAdditionalSecurityCapability,
            0x37 => ue_radio_capability_id_request: NasUeRadioCapabilityIdRequest,
            0xD0 => ue_coarse_location_information_request: NasUeCoarseLocationInformationRequest [tv1],
        }
    }
}

nas_message! {
    /// SECURITY MODE COMPLETE (Table 8.2.21.1).
    pub struct NasSecurityModeComplete {
        mandatory {
        }
        optional {
            0x23 => imeisv: NasImeisv,
            0x79 => replayed_nas_message_container: NasReplayedNasMessageContainer,
            0x66 => ue_radio_capability_id: NasUeRadioCapabilityId,
            0x67 => ue_coarse_location_information: NasUeCoarseLocationInformation,
        }
    }
}

nas_message! {
    /// SECURITY MODE REJECT (Table 8.2.22.1).
    pub struct NasSecurityModeReject {
        mandatory {
            emm_cause: NasEmmCause,
        }
        optional {
        }
    }
}

nas_message! {
    /// SERVICE REJECT (Table 8.2.24.1).
    pub struct NasServiceReject {
        mandatory {
            emm_cause: NasEmmCause,
        }
        optional {
            0x5B => t3442_value: NasT3442Value,
            0x5F => t3346_value: NasT3346Value,
            0x6B => t3448_value: NasT3448Value,
            0x1C => lower_bound_timer_value: NasLowerBoundTimerValue,
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters,
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange,
        }
    }
}

nas_message! {
    /// TRACKING AREA UPDATE ACCEPT (Table 8.2.26.1).
    pub struct NasTrackingAreaUpdateAccept {
        mandatory {
            eps_update_result: NasEpsUpdateResult [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
        }
        optional {
            0x5A => t3412_value: NasT3412Value [opt_type],
            0x50 => guti: NasGuti [opt_type],
            0x54 => tai_list: NasTaiList [opt_type],
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus,
            0x13 => location_area_identification: NasLocationAreaIdentification,
            0x23 => ms_identity: NasMsIdentity,
            0x53 => emm_cause: NasEmmCause [opt_type],
            0x17 => t3402_value: NasT3402Value [opt_type],
            0x59 => t3423_value: NasT3423Value,
            0x4A => equivalent_plmns: NasEquivalentPlmns,
            0x34 => emergency_number_list: NasEmergencyNumberList,
            0x64 => eps_network_feature_support: NasEpsNetworkFeatureSupport,
            0xF0 => additional_update_result: NasAdditionalUpdateResult [tv1],
            0x5E => t3412_extended_value: NasT3412ExtendedValue,
            0x6A => t3324_value: NasT3324Value,
            0x6E => extended_drx_parameters: NasExtendedDrxParameters,
            0x68 => header_compression_configuration_status: NasHeaderCompressionConfigurationStatus,
            0x65 => dcn_id: NasDcnId,
            0xE0 => sms_services_status: NasSmsServicesStatus [tv1],
            0xD0 => non_3gpp_nw_policies: NasNon3gppNwPolicies [tv1],
            0x6B => t3448_value: NasT3448Value,
            0xC0 => network_policy: NasNetworkPolicy [tv1],
            0x6C => t3447_value: NasT3447Value,
            0x7A => extended_emergency_number_list: NasExtendedEmergencyNumberList,
            0x7C => ciphering_key_data: NasCipheringKeyData,
            0x66 => ue_radio_capability_id: NasUeRadioCapabilityId,
            0xB0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1],
            0x35 => negotiated_wus_assistance_information: NasNegotiatedWusAssistanceInformation,
            0x36 => negotiated_drx_parameter_in_nb_s1_mode: NasNegotiatedDrxParameterInNbS1Mode,
            0x38 => negotiated_imsi_offset: NasNegotiatedImsiOffset,
            0x37 => eps_additional_request_result: NasEpsAdditionalRequestResult,
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
            0x39 => maximum_time_offset: NasMaximumTimeOffset,
            0x1F => unavailability_configuration: NasUnavailabilityConfiguration,
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters,
            0x22 => disaster_roaming_wait_range: NasDisasterRoamingWaitRange,
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange,
            0x25 => list_of_plmns_to_be_used_in_disaster_condition: NasListOfPlmnsToBeUsedInDisasterCondition,
        }
    }
}

nas_message! {
    /// TRACKING AREA UPDATE COMPLETE (Table 8.2.27.1).
    pub struct NasTrackingAreaUpdateComplete {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// TRACKING AREA UPDATE REJECT (Table 8.2.28.1).
    pub struct NasTrackingAreaUpdateReject {
        mandatory {
            emm_cause: NasEmmCause,
        }
        optional {
            0x5F => t3346_value: NasT3346Value,
            0xA0 => extended_emm_cause: NasExtendedEmmCause [tv1],
            0x1C => lower_bound_timer_value: NasLowerBoundTimerValue,
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
            0x20 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters,
            0x24 => disaster_return_wait_range: NasDisasterReturnWaitRange,
        }
    }
}

nas_message! {
    /// TRACKING AREA UPDATE REQUEST (Table 8.2.29.1).
    pub struct NasTrackingAreaUpdateRequest {
        mandatory {
            eps_update_type: NasEpsUpdateType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
            old_guti: NasOldGuti,
        }
        optional {
            0xB0 => non_current_native_nas_key_set_identifier: NasNonCurrentNativeNasKeySetIdentifier [tv1],
            0x80 => gprs_ciphering_key_sequence_number: NasGprsCipheringKeySequenceNumber [tv1],
            0x19 => old_p_tmsi_signature: NasOldPTmsiSignature,
            0x50 => additional_guti: NasAdditionalGuti,
            0x55 => nonce_ue: NasNonceUe,
            0x58 => ue_network_capability: NasUeNetworkCapability [opt_type],
            0x52 => last_visited_registered_tai: NasLastVisitedRegisteredTai,
            0x5C => drx_parameter: NasDrxParameter,
            0xA0 => ue_radio_capability_information_update_needed: NasUeRadioCapabilityInformationUpdateNeeded [tv1],
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus,
            0x31 => ms_network_capability: NasMsNetworkCapability,
            0x13 => old_location_area_identification: NasOldLocationAreaIdentification,
            0x90 => tmsi_status: NasTmsiStatus [tv1],
            0x11 => mobile_station_classmark_2: NasMobileStationClassmark2,
            0x20 => mobile_station_classmark_3: NasMobileStationClassmark3,
            0x40 => supported_codecs: NasSupportedCodecs,
            0xF0 => additional_update_type: NasAdditionalUpdateType [tv1],
            0x5D => voice_domain_preference_and_ue_usage_setting: NasVoiceDomainPreferenceAndUeUsageSetting,
            0xE0 => old_guti_type: NasOldGutiType [tv1],
            0xD0 => device_properties: NasDeviceProperties [tv1],
            0xC0 => ms_network_feature_support: NasMsNetworkFeatureSupport [tv1],
            0x10 => tmsi_based_nri_container: NasTmsiBasedNriContainer,
            0x6A => t3324_value: NasT3324Value,
            0x5E => t3412_extended_value: NasT3412ExtendedValue,
            0x6E => extended_drx_parameters: NasExtendedDrxParameters,
            0x6F => ue_additional_security_capability: NasUeAdditionalSecurityCapability,
            0x6D => ue_status: NasUeStatus,
            0x17 => additional_information_requested: NasAdditionalInformationRequested,
            0x32 => n1_ue_network_capability: NasN1UeNetworkCapability,
            0x34 => ue_radio_capability_id_availability: NasUeRadioCapabilityIdAvailability,
            0x35 => requested_wus_assistance_information: NasRequestedWusAssistanceInformation,
            0x36 => drx_parameter_in_nb_s1_mode: NasDrxParameterInNbS1Mode,
            0x38 => requested_imsi_offset: NasRequestedImsiOffset,
            0x29 => ue_request_type: NasUeRequestType,
            0x28 => paging_restriction: NasPagingRestriction,
            0x30 => unavailability_information: NasUnavailabilityInformation,
            0x26 => ue_determined_plmn_with_disaster_condition: NasUeDeterminedPlmnWithDisasterCondition,
        }
    }
}

nas_message! {
    /// UPLINK NAS TRANSPORT (Table 8.2.30.1).
    pub struct NasUplinkNasTransport {
        mandatory {
            nas_message_container: NasMessageContainer,
        }
        optional {
        }
    }
}

nas_message! {
    /// DOWNLINK GENERIC NAS TRANSPORT (Table 8.2.31.1).
    pub struct NasDownlinkGenericNasTransport {
        mandatory {
            generic_message_container_type: NasGenericMessageContainerType,
            generic_message_container: NasGenericMessageContainer,
        }
        optional {
            0x65 => additional_information: NasAdditionalInformation,
        }
    }
}

nas_message! {
    /// UPLINK GENERIC NAS TRANSPORT (Table 8.2.32.1).
    pub struct NasUplinkGenericNasTransport {
        mandatory {
            generic_message_container_type: NasGenericMessageContainerType,
            generic_message_container: NasGenericMessageContainer,
        }
        optional {
            0x65 => additional_information: NasAdditionalInformation,
        }
    }
}

nas_message! {
    /// CONTROL PLANE SERVICE REQUEST (Table 8.2.33.1).
    pub struct NasControlPlaneServiceRequest {
        mandatory {
            control_plane_service_type: NasControlPlaneServiceType [low_half_first],
            nas_key_set_identifier: NasKeySetIdentifier [high_half_last],
        }
        optional {
            0x78 => esm_message_container: NasEsmMessageContainer [opt_type],
            0x67 => nas_message_container: NasMessageContainer [opt_type],
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus,
            0xD0 => device_properties: NasDeviceProperties [tv1],
            0x29 => ue_request_type: NasUeRequestType,
            0x28 => paging_restriction: NasPagingRestriction,
        }
    }
}

nas_message! {
    /// SERVICE ACCEPT (Table 8.2.34.1).
    pub struct NasServiceAccept {
        mandatory {
        }
        optional {
            0x57 => eps_bearer_context_status: NasEpsBearerContextStatus,
            0x6B => t3448_value: NasT3448Value,
            0x37 => eps_additional_request_result: NasEpsAdditionalRequestResult,
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
            0x21 => s_and_f_satellite_operation_parameters: NasSAndFSatelliteOperationParameters,
        }
    }
}

nas_message! {
    /// ACTIVATE DEDICATED EPS BEARER CONTEXT ACCEPT (Table 8.3.1.1).
    pub struct NasActivateDedicatedEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// ACTIVATE DEDICATED EPS BEARER CONTEXT REJECT (Table 8.3.2.1).
    pub struct NasActivateDedicatedEpsBearerContextReject {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST (Table 8.3.3.1).
    pub struct NasActivateDedicatedEpsBearerContextRequest {
        mandatory {
            linked_eps_bearer_identity: NasLinkedEpsBearerIdentity [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            eps_qos: NasEpsQos,
            tft: NasTft,
        }
        optional {
            0x5D => transaction_identifier: NasTransactionIdentifier,
            0x30 => negotiated_qos: NasNegotiatedQos,
            0x32 => negotiated_llc_sapi: NasNegotiatedLlcSapi,
            0x80 => radio_priority: NasRadioPriority [tv1],
            0x34 => packet_flow_identifier: NasPacketFlowIdentifier,
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0xC0 => wlan_offload_indication: NasWlanOffloadIndication [tv1],
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x5C => extended_eps_qos: NasExtendedEpsQos,
        }
    }
}

nas_message! {
    /// ACTIVATE DEFAULT EPS BEARER CONTEXT ACCEPT (Table 8.3.4.1).
    pub struct NasActivateDefaultEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// ACTIVATE DEFAULT EPS BEARER CONTEXT REJECT (Table 8.3.5.1).
    pub struct NasActivateDefaultEpsBearerContextReject {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST (Table 8.3.6.1).
    pub struct NasActivateDefaultEpsBearerContextRequest {
        mandatory {
            eps_qos: NasEpsQos,
            access_point_name: NasAccessPointName,
            pdn_address: NasPdnAddress,
        }
        optional {
            0x5D => transaction_identifier: NasTransactionIdentifier,
            0x30 => negotiated_qos: NasNegotiatedQos,
            0x32 => negotiated_llc_sapi: NasNegotiatedLlcSapi,
            0x80 => radio_priority: NasRadioPriority [tv1],
            0x34 => packet_flow_identifier: NasPacketFlowIdentifier,
            0x5E => apn_ambr: NasApnAmbr,
            0x58 => esm_cause: NasEsmCause [opt_type],
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0xB0 => connectivity_type: NasConnectivityType [tv1],
            0xC0 => wlan_offload_indication: NasWlanOffloadIndication [tv1],
            0x33 => nbifom_container: NasNbifomContainer,
            0x66 => header_compression_configuration: NasHeaderCompressionConfiguration,
            0x90 => control_plane_only_indication: NasControlPlaneOnlyIndication [tv1],
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x6E => serving_plmn_rate_control: NasServingPlmnRateControl,
            0x5F => extended_apn_ambr: NasExtendedApnAmbr,
        }
    }
}

nas_message! {
    /// BEARER RESOURCE ALLOCATION REJECT (Table 8.3.7.1).
    pub struct NasBearerResourceAllocationReject {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x37 => back_off_timer_value: NasBackOffTimerValue,
            0x6B => re_attempt_indicator: NasReAttemptIndicator,
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// BEARER RESOURCE ALLOCATION REQUEST (Table 8.3.8.1).
    pub struct NasBearerResourceAllocationRequest {
        mandatory {
            linked_eps_bearer_identity: NasLinkedEpsBearerIdentity [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            traffic_flow_aggregate: NasTrafficFlowAggregate,
            required_traffic_flow_qos: NasRequiredTrafficFlowQos,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0xC0 => device_properties: NasDeviceProperties [tv1],
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x5C => extended_eps_qos: NasExtendedEpsQos,
        }
    }
}

nas_message! {
    /// BEARER RESOURCE MODIFICATION REJECT (Table 8.3.9.1).
    pub struct NasBearerResourceModificationReject {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x37 => back_off_timer_value: NasBackOffTimerValue,
            0x6B => re_attempt_indicator: NasReAttemptIndicator,
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// BEARER RESOURCE MODIFICATION REQUEST (Table 8.3.10.1).
    pub struct NasBearerResourceModificationRequest {
        mandatory {
            eps_bearer_identity_for_packet_filter: NasEpsBearerIdentityForPacketFilter [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
            traffic_flow_aggregate: NasTrafficFlowAggregate,
        }
        optional {
            0x5B => required_traffic_flow_qos: NasRequiredTrafficFlowQos [opt_type],
            0x58 => esm_cause: NasEsmCause [opt_type],
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0xC0 => device_properties: NasDeviceProperties [tv1],
            0x33 => nbifom_container: NasNbifomContainer,
            0x66 => header_compression_configuration: NasHeaderCompressionConfiguration,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x5C => extended_eps_qos: NasExtendedEpsQos,
        }
    }
}

nas_message! {
    /// DEACTIVATE EPS BEARER CONTEXT ACCEPT (Table 8.3.11.1).
    pub struct NasDeactivateEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// DEACTIVATE EPS BEARER CONTEXT REQUEST (Table 8.3.12.1).
    pub struct NasDeactivateEpsBearerContextRequest {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x37 => t3396_value: NasT3396Value,
            0xC0 => wlan_offload_indication: NasWlanOffloadIndication [tv1],
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// ESM DUMMY MESSAGE (Table 8.3.12A.1).
    pub struct NasEsmDummyMessage {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM INFORMATION REQUEST (Table 8.3.13.1).
    pub struct NasEsmInformationRequest {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM INFORMATION RESPONSE (Table 8.3.14.1).
    pub struct NasEsmInformationResponse {
        mandatory {
        }
        optional {
            0x28 => access_point_name: NasAccessPointName [opt_type],
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// ESM STATUS (Table 8.3.15.1).
    pub struct NasEsmStatus {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
        }
    }
}

nas_message! {
    /// MODIFY EPS BEARER CONTEXT ACCEPT (Table 8.3.16.1).
    pub struct NasModifyEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// MODIFY EPS BEARER CONTEXT REJECT (Table 8.3.17.1).
    pub struct NasModifyEpsBearerContextReject {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// MODIFY EPS BEARER CONTEXT REQUEST (Table 8.3.18.1).
    pub struct NasModifyEpsBearerContextRequest {
        mandatory {
        }
        optional {
            0x5B => new_eps_qos: NasNewEpsQos,
            0x36 => tft: NasTft [opt_type],
            0x30 => new_qos: NasNewQos,
            0x32 => negotiated_llc_sapi: NasNegotiatedLlcSapi,
            0x80 => radio_priority: NasRadioPriority [tv1],
            0x34 => packet_flow_identifier: NasPacketFlowIdentifier,
            0x5E => apn_ambr: NasApnAmbr,
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0xC0 => wlan_offload_indication: NasWlanOffloadIndication [tv1],
            0x33 => nbifom_container: NasNbifomContainer,
            0x66 => header_compression_configuration: NasHeaderCompressionConfiguration,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x5F => extended_apn_ambr: NasExtendedApnAmbr,
            0x5C => extended_eps_qos: NasExtendedEpsQos,
        }
    }
}

nas_message! {
    /// NOTIFICATION (Table 8.3.18A.1).
    pub struct NasNotification {
        mandatory {
            notification_indicator: NasNotificationIndicator,
        }
        optional {
        }
    }
}

nas_message! {
    /// PDN CONNECTIVITY REJECT (Table 8.3.19.1).
    pub struct NasPdnConnectivityReject {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x37 => back_off_timer_value: NasBackOffTimerValue,
            0x6B => re_attempt_indicator: NasReAttemptIndicator,
            0x33 => nbifom_container: NasNbifomContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// PDN CONNECTIVITY REQUEST (Table 8.3.20.1).
    pub struct NasPdnConnectivityRequest {
        mandatory {
            request_type: NasRequestType [low_half_first],
            pdn_type: NasPdnType [high_half_last],
        }
        optional {
            0xD0 => esm_information_transfer_flag: NasEsmInformationTransferFlag [tv1],
            0x28 => access_point_name: NasAccessPointName [opt_type],
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0xC0 => device_properties: NasDeviceProperties [tv1],
            0x33 => nbifom_container: NasNbifomContainer,
            0x66 => header_compression_configuration: NasHeaderCompressionConfiguration,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// PDN DISCONNECT REJECT (Table 8.3.21.1).
    pub struct NasPdnDisconnectReject {
        mandatory {
            esm_cause: NasEsmCause,
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// PDN DISCONNECT REQUEST (Table 8.3.22.1).
    pub struct NasPdnDisconnectRequest {
        mandatory {
            linked_eps_bearer_identity: NasLinkedEpsBearerIdentity [low_half_first],
            spare_half_octet: NasSpareHalfOctet [high_half_last],
        }
        optional {
            0x27 => protocol_configuration_options: NasProtocolConfigurationOptions,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
        }
    }
}

nas_message! {
    /// REMOTE UE REPORT (Table 8.3.23.1).
    pub struct NasRemoteUeReport {
        mandatory {
        }
        optional {
            0x79 => remote_ue_context_connected: NasRemoteUeContextConnected,
            0x7A => remote_ue_context_disconnected: NasRemoteUeContextDisconnected,
            0x6F => prose_key_management_function_address: NasProseKeyManagementFunctionAddress,
        }
    }
}

nas_message! {
    /// REMOTE UE REPORT RESPONSE (Table 8.3.24.1).
    pub struct NasRemoteUeReportResponse {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM DATA TRANSPORT (Table 8.3.25.1).
    pub struct NasEsmDataTransport {
        mandatory {
            user_data_container: NasUserDataContainer,
        }
        optional {
            0xF0 => release_assistance_indication: NasReleaseAssistanceIndication [tv1],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum NasEmmMessage {
    AttachAccept(NasAttachAccept),
    AttachComplete(NasAttachComplete),
    AttachReject(NasAttachReject),
    AttachRequest(NasAttachRequest),
    AuthenticationFailure(NasAuthenticationFailure),
    AuthenticationReject(NasAuthenticationReject),
    AuthenticationRequest(NasAuthenticationRequest),
    AuthenticationResponse(NasAuthenticationResponse),
    CsServiceNotification(NasCsServiceNotification),
    DetachAccept(NasDetachAccept),
    DetachRequestFromUe(NasDetachRequestFromUe),
    DetachRequestToUe(NasDetachRequestToUe),
    DownlinkNasTransport(NasDownlinkNasTransport),
    EmmInformation(NasEmmInformation),
    EmmStatus(NasEmmStatus),
    ExtendedServiceRequest(NasExtendedServiceRequest),
    GutiReallocationCommand(NasGutiReallocationCommand),
    GutiReallocationComplete(NasGutiReallocationComplete),
    IdentityRequest(NasIdentityRequest),
    IdentityResponse(NasIdentityResponse),
    SecurityModeCommand(NasSecurityModeCommand),
    SecurityModeComplete(NasSecurityModeComplete),
    SecurityModeReject(NasSecurityModeReject),
    ServiceReject(NasServiceReject),
    TrackingAreaUpdateAccept(NasTrackingAreaUpdateAccept),
    TrackingAreaUpdateComplete(NasTrackingAreaUpdateComplete),
    TrackingAreaUpdateReject(NasTrackingAreaUpdateReject),
    TrackingAreaUpdateRequest(NasTrackingAreaUpdateRequest),
    UplinkNasTransport(NasUplinkNasTransport),
    DownlinkGenericNasTransport(NasDownlinkGenericNasTransport),
    UplinkGenericNasTransport(NasUplinkGenericNasTransport),
    ControlPlaneServiceRequest(NasControlPlaneServiceRequest),
    ServiceAccept(NasServiceAccept),
}
impl NasEmmMessage {
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
                // The UE form has an LV identity. Probe it before the network form.
                let mut probe = buffer.clone();
                if let Ok(request) = NasDetachRequestFromUe::decode(&mut probe)
                    && !probe.has_remaining()
                {
                    *buffer = probe;
                    return Ok(Self::DetachRequestFromUe(request));
                }
                Ok(Self::DetachRequestToUe(NasDetachRequestToUe::decode(
                    buffer,
                )?))
            }
            NasEmmMessageType::Unknown(value) => Err(NasError::UnknownMessageType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum NasEsmMessage {
    ActivateDedicatedEpsBearerContextAccept(NasActivateDedicatedEpsBearerContextAccept),
    ActivateDedicatedEpsBearerContextReject(NasActivateDedicatedEpsBearerContextReject),
    ActivateDedicatedEpsBearerContextRequest(NasActivateDedicatedEpsBearerContextRequest),
    ActivateDefaultEpsBearerContextAccept(NasActivateDefaultEpsBearerContextAccept),
    ActivateDefaultEpsBearerContextReject(NasActivateDefaultEpsBearerContextReject),
    ActivateDefaultEpsBearerContextRequest(NasActivateDefaultEpsBearerContextRequest),
    BearerResourceAllocationReject(NasBearerResourceAllocationReject),
    BearerResourceAllocationRequest(NasBearerResourceAllocationRequest),
    BearerResourceModificationReject(NasBearerResourceModificationReject),
    BearerResourceModificationRequest(NasBearerResourceModificationRequest),
    DeactivateEpsBearerContextAccept(NasDeactivateEpsBearerContextAccept),
    DeactivateEpsBearerContextRequest(NasDeactivateEpsBearerContextRequest),
    EsmDummyMessage(NasEsmDummyMessage),
    EsmInformationRequest(NasEsmInformationRequest),
    EsmInformationResponse(NasEsmInformationResponse),
    EsmStatus(NasEsmStatus),
    ModifyEpsBearerContextAccept(NasModifyEpsBearerContextAccept),
    ModifyEpsBearerContextReject(NasModifyEpsBearerContextReject),
    ModifyEpsBearerContextRequest(NasModifyEpsBearerContextRequest),
    Notification(NasNotification),
    PdnConnectivityReject(NasPdnConnectivityReject),
    PdnConnectivityRequest(NasPdnConnectivityRequest),
    PdnDisconnectReject(NasPdnDisconnectReject),
    PdnDisconnectRequest(NasPdnDisconnectRequest),
    RemoteUeReport(NasRemoteUeReport),
    RemoteUeReportResponse(NasRemoteUeReportResponse),
    EsmDataTransport(NasEsmDataTransport),
}
impl NasEsmMessage {
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
                NasEpsMobileIdentity::new(vec![0; 4]),
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
                    NasKeySetIdentifierAsme::new(0),
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
                    NasEpsMobileIdentity::new(vec![0; 4]),
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
                    NasMTmsi::new(vec![0; 5]),
                ),
            ));
            let bytes = pdu.to_bytes().unwrap();
            let decoded = NasEpsMessage::from_bytes(&bytes).unwrap();
            assert_eq!(decoded.to_bytes().unwrap(), bytes, "ExtendedServiceRequest");
        }
        {
            let pdu = NasEpsMessage::new_emm(NasEmmMessage::GutiReallocationCommand(
                NasGutiReallocationCommand::new(NasGuti::new(vec![0; 11])),
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
                NasIdentityResponse::new(NasMobileIdentity::new(vec![0; 3])),
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
                    NasOldGuti::new(vec![0; 11]),
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
                        NasAccessPointName::new(vec![0; 1]),
                        NasPdnAddress::new(vec![0; 5]),
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
                        NasEpsBearerIdentityForPacketFilter::new(0),
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
pub struct NasEpsEmmHeader {
    pub protocol_discriminator: u8,
    pub security_header_type: NasEpsSecurityHeaderType,
    pub message_type: NasEmmMessageType,
}

impl NasEpsEmmHeader {
    pub fn new(message_type: NasEmmMessageType) -> Self {
        Self {
            protocol_discriminator: EPS_EMM_PROTOCOL_DISCRIMINATOR,
            security_header_type: NasEpsSecurityHeaderType::PlainNasMessage,
            message_type,
        }
    }
}

impl Encode for NasEpsEmmHeader {
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

impl Decode for NasEpsEmmHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(NasError::BufferTooShort);
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
pub struct NasEpsEsmHeader {
    pub protocol_discriminator: u8,
    pub eps_bearer_identity: u8,
    pub procedure_transaction_identity: u8,
    pub message_type: NasEsmMessageType,
}

impl NasEpsEsmHeader {
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

impl Encode for NasEpsEsmHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.protocol_discriminator != EPS_ESM_PROTOCOL_DISCRIMINATOR
            || self.eps_bearer_identity > 15
            || self.procedure_transaction_identity == 255
        {
            return Err(NasError::EncodingError("Invalid EPS ESM header".into()));
        }
        buffer.put_u8((self.eps_bearer_identity << 4) | self.protocol_discriminator);
        buffer.put_u8(self.procedure_transaction_identity);
        buffer.put_u8(self.message_type.as_u8());
        Ok(())
    }
}

impl Decode for NasEpsEsmHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 3 {
            return Err(NasError::BufferTooShort);
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
    pub ksi_and_sequence_number: u8,
    pub message_authentication_code: u16,
}

impl NasServiceRequest {
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
        if self.security_header_type != 12 {
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
            return Err(NasError::BufferTooShort);
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

/// Check the leading fields of an EMM TRANSPORT data container.
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
    pub security_header: NasEpsSecurityHeader,
    pub data_container: Option<Vec<u8>>,
    /// Bytes following the security header before deciphering, if opaque.
    pub protected_payload: Option<Vec<u8>>,
}

impl NasEmmTransport {
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
    Emm(NasEpsEmmHeader, NasEmmMessage),
    Esm(NasEpsEsmHeader, NasEsmMessage),
    SecurityProtected(NasEpsSecurityHeader, Box<NasEpsMessage>),
    ServiceRequest(NasServiceRequest),
    EmmTransport(NasEmmTransport),
    /// Encrypted or otherwise opaque body of a security-protected PDU.
    Opaque(Vec<u8>),
}

fn check_protected_inner(sht: NasEpsSecurityHeaderType, inner: &NasEpsMessage) -> Result<()> {
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
    pub fn new_emm(message: NasEmmMessage) -> Self {
        Self::Emm(NasEpsEmmHeader::new(message.message_type()), message)
    }

    pub fn from_emm(message: NasEmmMessage) -> Self {
        Self::new_emm(message)
    }

    pub fn new_esm(
        message: NasEsmMessage,
        eps_bearer_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        Self::Esm(
            NasEpsEsmHeader::new(
                message.message_type(),
                eps_bearer_identity,
                procedure_transaction_identity,
            ),
            message,
        )
    }

    pub fn from_esm(
        message: NasEsmMessage,
        eps_bearer_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        Self::new_esm(message, eps_bearer_identity, procedure_transaction_identity)
    }

    /// Build a security envelope from a caller-supplied MAC and body.
    /// Ciphered header types require already ciphered opaque body bytes;
    /// use [`crate::nas_eps::NasSecurityContext`] with the `security` feature to compute them.
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

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_nas_eps_message(self)
    }
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        decode_nas_eps_message(data)
    }

    /// Decode using direction to disambiguate DETACH REQUEST.
    pub fn from_bytes_with_direction(
        data: &[u8],
        direction: NasEpsDecodeDirection,
    ) -> Result<Self> {
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
                check_protected_inner(header.security_header_type, message)?;
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

impl Decode for NasEpsMessage {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        match buffer[0] & 0x0F {
            EPS_ESM_PROTOCOL_DISCRIMINATOR => {
                let header = NasEpsEsmHeader::decode(buffer)?;
                let message = NasEsmMessage::try_from((header.message_type, buffer))?;
                Ok(Self::Esm(header, message))
            }
            EPS_EMM_PROTOCOL_DISCRIMINATOR => {
                let sht = NasEpsSecurityHeaderType::try_from(buffer[0] >> 4)?;
                match sht {
                    NasEpsSecurityHeaderType::PlainNasMessage => {
                        let header = NasEpsEmmHeader::decode(buffer)?;
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
                            Box::new(Self::decode(buffer)?)
                        } else {
                            if !buffer.has_remaining() {
                                return Err(NasError::BufferTooShort);
                            }
                            Box::new(Self::Opaque(
                                buffer.copy_to_bytes(buffer.remaining()).to_vec(),
                            ))
                        };
                        check_protected_inner(sht, &payload).map_err(|_| {
                            NasError::DecodingError(
                                "EPS security header type does not match message type".into(),
                            )
                        })?;
                        Ok(Self::SecurityProtected(header, payload))
                    }
                }
            }
            discriminator => Err(NasError::DecodingError(format!(
                "Unknown EPS protocol discriminator {discriminator}"
            ))),
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

/// Compatibility alias for [`is_security_protected`].
pub fn is_eps_security_protected(pdu: &[u8]) -> bool {
    is_security_protected(pdu)
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
    direction: NasEpsDecodeDirection,
) -> Result<NasEpsMessage> {
    if data.len() >= EPS_SECURITY_HEADER_LEN
        && data[0] & 0x0f == EPS_EMM_PROTOCOL_DISCRIMINATOR
        && matches!(data[0] >> 4, 1 | 3)
    {
        let mut buffer = Bytes::copy_from_slice(data);
        let header = NasEpsSecurityHeader::decode(&mut buffer)?;
        let inner =
            decode_nas_eps_message_with_direction(&data[EPS_SECURITY_HEADER_LEN..], direction)?;
        check_protected_inner(header.security_header_type, &inner).map_err(|_| {
            NasError::DecodingError("EPS security header type does not match message type".into())
        })?;
        return Ok(NasEpsMessage::SecurityProtected(header, Box::new(inner)));
    }
    if data.len() >= 2 && data[0] == EPS_EMM_PROTOCOL_DISCRIMINATOR && data[1] == 0x45 {
        let mut body = Bytes::copy_from_slice(&data[2..]);
        let message = match direction {
            NasEpsDecodeDirection::Uplink => {
                NasEmmMessage::DetachRequestFromUe(NasDetachRequestFromUe::decode(&mut body)?)
            }
            NasEpsDecodeDirection::Downlink => {
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
        let wire = [0x52, 0x01, 0xc5, 0x05, 0x01, 0x0b, 0x01, 0x10];
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
                    NasEpsEsmHeader {
                        procedure_transaction_identity,
                        ..
                    },
                    NasEsmMessage::PdnConnectivityRequest(_)
                ) if procedure_transaction_identity == pti
            ));
        }
    }

    #[test]
    fn reserved_service_request_header_is_receive_only() {
        let wire = [0xd7, 0x12, 0x34, 0x56];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert!(matches!(message, NasEpsMessage::ServiceRequest(_)));
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "security_header_type")
        );
        assert!(encode_nas_eps_message(&message).is_err());
    }

    #[test]
    fn attach_complete_requires_one_complete_esm_pdu() {
        let wire = [0x07, 0x43, 0x00, 0x03, 0xff, 0xff, 0xff];
        let message = decode_nas_eps_message(&wire).unwrap();
        assert!(
            message
                .validate()
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
            NasOldGuti::new(vec![0; 11]),
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
        assert!(
            request
                .access_point_name
                .as_ref()
                .unwrap()
                .as_string()
                .is_none()
        );
        assert!(NasAccessPointName::from_string("a_b").is_none());
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "access_point_name")
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
    fn optional_esm_container_requires_a_complete_esm_pdu() {
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
                vec![0x07, 0x4c, 0, 5, 0, 0, 0, 0, 0, 0x28, 1, 3],
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
        assert!(is_eps_security_protected(&protected));

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
        let from_ue = [0x07, 0x45, 0x11, 0x04, 1, 2, 3, 4];
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

    #[test]
    fn truncated_fixed_authentication_parameter_is_rejected() {
        let pdu = [0x07, 0x52, 0x01, 0xAA];
        assert!(matches!(
            NasEpsMessage::from_bytes(&pdu),
            Err(NasError::BufferTooShort)
        ));
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
            decode_nas_eps_message_with_direction(&downlink, NasEpsDecodeDirection::Downlink)
                .unwrap(),
            NasEpsMessage::Emm(_, NasEmmMessage::DetachRequestToUe(_))
        ));
        let mut protected = vec![0x17, 0, 0, 0, 0, 0];
        protected.extend_from_slice(&downlink);
        assert!(matches!(
            decode_nas_eps_message_with_direction(&protected, NasEpsDecodeDirection::Downlink).unwrap(),
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
        let header = NasEpsEsmHeader::new(NasEsmMessageType::PdnConnectivityRequest, 3, 1);
        let mut buffer = BytesMut::new();
        header.encode(&mut buffer).unwrap();
        assert_eq!(
            NasEpsEsmHeader::decode(&mut buffer.freeze()).unwrap(),
            header
        );
        let reserved_pti = NasEpsMessage::from_bytes(&[0x02, 0xff, 0xd0, 0x11]).unwrap();
        assert!(matches!(
            reserved_pti,
            NasEpsMessage::Esm(
                NasEpsEsmHeader {
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
        assert!(reserved_pti.to_bytes().is_err());
    }

    #[test]
    fn duplicate_known_optional_ie_is_rejected() {
        let duplicate_pco = [0x02, 0x01, 0xd0, 0x11, 0x27, 0x01, 0x80, 0x27, 0x01, 0x80];
        assert!(NasEpsMessage::from_bytes(&duplicate_pco).is_err());
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
        let invalid_identity =
            NasEpsMessage::from_bytes(&[0x07, 0x45, 0x01, 0x04, 0, 0, 0, 0]).unwrap();
        assert!(
            invalid_identity
                .validate()
                .iter()
                .any(|error| error.field == "eps_mobile_identity")
        );

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
    fn t3402_uses_one_type_in_both_optional_wire_formats() {
        let tv = [
            0x07, 0x42, 0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x02, 0x01, 0xd0, 0x11, 0x17,
            0x21,
        ];
        let tlv = [0x07, 0x44, 0x02, 0x16, 0x01, 0x21];
        for wire in [tv.as_slice(), tlv.as_slice()] {
            let decoded = decode_nas_eps_message(wire).unwrap();
            assert_eq!(encode_nas_eps_message(&decoded).unwrap(), wire);
        }
        assert!(decode_nas_eps_message(&[0x07, 0x44, 0x02, 0x16, 0x02, 0x21, 0x22]).is_err());
    }
}
