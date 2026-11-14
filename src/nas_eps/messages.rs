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

//! EPS NAS message structs, headers, and codec functions.
//!
//! This is **Layer 2** of the EPS codec. Each EMM and ESM message is a struct
//! defined by the shared `nas_message!` macro with:
//!
//! - **Mandatory fields** — passed to `new()` with getters and value helpers.
//! - **Optional fields** — set through `set_*()` builder methods.
//! - **`Encode`/`Decode` implementations** — IEI-based dispatch on the wire.
//!
//! [`Message`] wraps EMM, ESM, a security envelope, or a special EMM
//! header form. [`Message::decode`] and [`Message::encode`] are
//! the main entry points.

pub(crate) use crate::common::UnknownIes;
use crate::common::{Decode, Direction, Encode, Error, Reader, Result, Writer};
use crate::common::{nas_message, nas_message_impl_default};
use crate::nas_eps::*;
use crate::prelude::*;
use core::convert::TryFrom;

// TS 24.007 §11.2.4 assigns 0x78..=0x7f to EPS TLV-E IEs.
pub(crate) const UNKNOWN_TLVE_START: u8 = 0x78;

/// Length of an EPS security header including MAC and sequence number.
pub const EPS_SECURITY_HEADER_LEN: usize = 6;

/// EPS security header. The payload following it may be encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHeader {
    /// Security header type.
    pub security_header_type: SecurityHeaderType,
    /// Message authentication code.
    pub message_authentication_code: u32,
    /// Sequence number (eight LSBs of the NAS COUNT).
    pub sequence_number: u8,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct SecurityHeader { security_header_type, message_authentication_code, sequence_number });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(SecurityHeader);

impl Encode for SecurityHeader {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if matches!(
            self.security_header_type,
            SecurityHeaderType::PlainNasMessageNotSecurityProtected
                | SecurityHeaderType::SecurityHeaderForTheServiceRequestMessage
        ) {
            return Err(Error::EncodingError(
                "invalid EPS security envelope type".into(),
            ));
        }
        buffer.put_u8(((self.security_header_type as u8) << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR);
        buffer.put_u32(self.message_authentication_code);
        buffer.put_u8(self.sequence_number);
        Ok(())
    }
}

impl Decode for SecurityHeader {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        if buffer.remaining() < EPS_SECURITY_HEADER_LEN {
            return Err(Error::MessageTooShort);
        }
        let first = buffer.get_u8();
        if first & 0x0F != EPS_EMM_PROTOCOL_DISCRIMINATOR {
            return Err(Error::DecodingError(format!(
                "invalid EPS security header 0x{first:02x}"
            )));
        }
        let security_header_type = SecurityHeaderType::try_from(first >> 4)?;
        if matches!(
            security_header_type,
            SecurityHeaderType::PlainNasMessageNotSecurityProtected
                | SecurityHeaderType::SecurityHeaderForTheServiceRequestMessage
        ) {
            return Err(Error::DecodingError(
                "invalid EPS security envelope type".into(),
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
    pub struct AttachAccept {
        mandatory {
            eps_attach_result: EpsAttachResult {wire_len 1, 1},
            t3412_value: T3412Value {wire_len 1, 1},
            tai_list: TrackingAreaIdentityList {wire_len 7, 97},
            esm_message_container: EsmMessageContainer {wire_len 5, usize::MAX},
        }
        optional {
            0x50 => guti: EpsMobileIdentity {wire_len 13, 13},
            0x13 => location_area_identification: LocationAreaIdentification {wire_len 6, 6},
            0x23 => ms_identity: MobileIdentity {wire_len 7, 10},
            0x53 => emm_cause: EmmCause {wire_len 2, 2},
            0x17 => t3402_value: GprsTimer {wire_len 2, 2},
            0x59 => t3423_value: GprsTimer {wire_len 2, 2},
            0x4A => equivalent_plmns: PlmnList {wire_len 5, 47},
            0x34 => emergency_number_list: EmergencyNumberList {wire_len 5, 50},
            0x64 => eps_network_feature_support: EpsNetworkFeatureSupport {wire_len 3, 5},
            0xF0 => additional_update_result: AdditionalUpdateResult [tv1] {wire_len 1, 1},
            0x5E => t3412_extended_value: T3412ExtendedValue {wire_len 3, 3},
            0x6A => t3324_value: GprsTimer2 {wire_len 3, 3},
            0x6E => extended_drx_parameters: ExtendedDrxParameters {wire_len 3, 3},
            0x65 => dcn_id: DcnId {wire_len 4, 4},
            0xE0 => sms_services_status: SmsServicesStatus [tv1] {wire_len 1, 1},
            0xD0 => non_3gpp_nw_provided_policies: Non3GppNwProvidedPolicies [tv1] {wire_len 1, 1},
            0x6B => t3448_value: GprsTimer2 {wire_len 3, 3},
            0xC0 => network_policy: NetworkPolicy [tv1] {wire_len 1, 1},
            0x6C => t3447_value: GprsTimer3 {wire_len 3, 3},
            0x7A => extended_emergency_number_list: ExtendedEmergencyNumberList {wire_len 7, 65538},
            0x7C => ciphering_key_data: CipheringKeyData {wire_len 35, 2291},
            0x66 => ue_radio_capability_id: UeRadioCapabilityId {wire_len 3, usize::MAX},
            0xB0 => ue_radio_capability_id_deletion_indication: UeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x35 => negotiated_wus_assistance_information: WusAssistanceInformation {wire_len 3, 3},
            0x36 => negotiated_drx_parameter_in_nb_s1_mode: NbS1DrxParameter {wire_len 3, 3},
            0x38 => negotiated_imsi_offset: ImsiOffset {wire_len 4, 4},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 8, 98},
            0x1F => unavailability_configuration: UnavailabilityConfiguration {wire_len 3, 9},
            0x20 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5},
            0x21 => s_and_f_satellite_operation_parameters: SAndFSatelliteOperationParameters {wire_len 3, 257},
            0x22 => disaster_roaming_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x24 => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x25 => list_of_plmns_to_be_used_in_disaster_condition: ListOfPlmnsToBeUsedInDisasterCondition {wire_len 2, usize::MAX},
        }
    }
}

nas_message! {
    /// Attach Complete (TS 24.301 §8.2.2).
    pub struct AttachComplete {
        mandatory {
            esm_message_container: EsmMessageContainer {wire_len 5, usize::MAX},
        }
        optional {
        }
    }
}

nas_message! {
    /// Attach Reject (TS 24.301 §8.2.3).
    pub struct AttachReject {
        mandatory {
            emm_cause: EmmCause {wire_len 1, 1},
        }
        optional {
            0x78 => esm_message_container: EsmMessageContainer {wire_len 6, usize::MAX},
            0x5F => t3346_value: GprsTimer2 {wire_len 3, 3},
            0x16 => t3402_value: GprsTimer2 {wire_len 3, 3},
            0xA0 => extended_emm_cause: ExtendedEmmCause [tv1] {wire_len 1, 1},
            0x1C => lower_bound_timer_value: GprsTimer3 {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 8, 98},
            0x20 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5},
            0x21 => s_and_f_satellite_operation_parameters: SAndFSatelliteOperationParameters {wire_len 3, 257},
        }
    }
}

nas_message! {
    /// Attach Request (TS 24.301 §8.2.4).
    ///
    /// ```
    /// use oxirush_nas::nas_eps::*;
    ///
    /// // An EPS attach with an IMSI, and a PDN CONNECTIVITY REQUEST in its
    /// // ESM message container
    /// let octets = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
    /// let Message::Emm(_, EmmMessage::AttachRequest(request)) =
    ///     Message::decode(&octets).unwrap()
    /// else {
    ///     unreachable!()
    /// };
    /// assert_eq!(request.eps_attach_type.attach_type(), AttachType::EpsAttach);
    /// assert_eq!(request.eps_mobile_identity.to_string(), "imsi-208930000000001");
    /// assert!(request.ue_network_capability.supports_eea(2));
    /// let esm = request.esm_message_container.decode_as_esm_message().unwrap();
    /// assert!(matches!(esm, Message::Esm(_, EsmMessage::PdnConnectivityRequest(_))));
    /// ```
    pub struct AttachRequest {
        mandatory {
            eps_attach_type: EpsAttachType [low_half_first],
            nas_key_set_identifier: KeySetIdentifier [high_half_last],
            eps_mobile_identity: EpsMobileIdentity {wire_len 5, 12},
            ue_network_capability: UeNetworkCapability {wire_len 3, 14},
            esm_message_container: EsmMessageContainer {wire_len 5, usize::MAX},
        }
        optional {
            0x19 => old_p_tmsi_signature: PTmsiSignature {wire_len 4, 4},
            0x50 => additional_guti: EpsMobileIdentity {wire_len 13, 13},
            0x52 => last_visited_registered_tai: TrackingAreaIdentity {wire_len 6, 6},
            0x5C => drx_parameter: DrxParameter {wire_len 3, 3},
            0x31 => ms_network_capability: MsNetworkCapability {wire_len 4, 10},
            0x13 => old_location_area_identification: LocationAreaIdentification {wire_len 6, 6},
            0x90 => tmsi_status: TmsiStatus [tv1] {wire_len 1, 1},
            0x11 => mobile_station_classmark_2: MobileStationClassmark2 {wire_len 5, 5},
            0x20 => mobile_station_classmark_3: MobileStationClassmark3 {wire_len 2, 34},
            0x40 => supported_codecs: SupportedCodecList {wire_len 5, usize::MAX},
            0xF0 => additional_update_type: AdditionalUpdateType [tv1] {wire_len 1, 1},
            0x5D => voice_domain_preference_and_ue_usage_setting: VoiceDomainPreferenceAndUeUsageSetting {wire_len 3, 3},
            0xD0 => device_properties: DeviceProperties [tv1] {wire_len 1, 1},
            0xE0 => old_guti_type: GutiType [tv1] {wire_len 1, 1},
            0xC0 => ms_network_feature_support: MsNetworkFeatureSupport [tv1] {wire_len 1, 1},
            0x10 => tmsi_based_nri_container: NetworkResourceIdentifierContainer {wire_len 4, 4},
            0x6A => t3324_value: GprsTimer2 {wire_len 3, 3},
            0x5E => t3412_extended_value: T3412ExtendedValue {wire_len 3, 3},
            0x6E => extended_drx_parameters: ExtendedDrxParameters {wire_len 3, 3},
            0x6F => ue_additional_security_capability: UeAdditionalSecurityCapability {wire_len 6, 6},
            0x6D => ue_status: UeStatus {wire_len 3, 3},
            0x17 => additional_information_requested: AdditionalInformationRequested {wire_len 2, 2},
            0x32 => n1_ue_network_capability: N1UeNetworkCapability {wire_len 3, 15},
            0x34 => ue_radio_capability_id_availability: UeRadioCapabilityIdAvailability {wire_len 3, 3},
            0x35 => requested_wus_assistance_information: WusAssistanceInformation {wire_len 3, 3},
            0x36 => drx_parameter_in_nb_s1_mode: NbS1DrxParameter {wire_len 3, 3},
            0x38 => requested_imsi_offset: ImsiOffset {wire_len 4, 4},
            0x26 => ue_determined_plmn_with_disaster_condition: PlmnIdentity {wire_len 5, 5},
        }
    }
}

nas_message! {
    /// Authentication Failure (TS 24.301 §8.2.5).
    pub struct AuthenticationFailure {
        mandatory {
            emm_cause: EmmCause {wire_len 1, 1},
        }
        optional {
            0x30 => authentication_failure_parameter: AuthenticationFailureParameter {wire_len 16, 16},
        }
    }
}

nas_message! {
    /// Authentication Reject (TS 24.301 §8.2.6).
    pub struct AuthenticationReject {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// Authentication Request (TS 24.301 §8.2.7).
    ///
    /// ```
    /// use oxirush_nas::nas_eps::*;
    ///
    /// // A challenge of EPS AKA under KSI 0: RAND, then AUTN after its length
    /// let ksi = KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Native(0)).unwrap();
    /// let request = AuthenticationRequest::new(
    ///     ksi,
    ///     AuthenticationParameterRand::from_rand([0x23; 16]),
    ///     AuthenticationParameterAutn::from_autn([0x55; 16]),
    /// );
    /// let octets = Message::new_emm(request).encode().unwrap();
    /// assert_eq!(hex::encode(&octets[..4]), "07520023");
    /// assert_eq!(hex::encode(&octets[19..21]), "1055");
    /// assert_eq!(octets.len(), 36);
    /// ```
    pub struct AuthenticationRequest {
        mandatory {
            nas_key_set_identifier_asme: KeySetIdentifier {wire_len 1, 1},
            authentication_parameter_rand: AuthenticationParameterRand {wire_len 16, 16},
            authentication_parameter_autn: AuthenticationParameterAutn {wire_len 17, 17},
        }
        optional {
        }
    }
}

nas_message! {
    /// Authentication Response (TS 24.301 §8.2.8).
    pub struct AuthenticationResponse {
        mandatory {
            authentication_response_parameter: AuthenticationResponseParameter {wire_len 5, 17},
        }
        optional {
        }
    }
}

nas_message! {
    /// CS Service Notification (TS 24.301 §8.2.9).
    pub struct CsServiceNotification {
        mandatory {
            paging_identity: PagingIdentity {wire_len 1, 1},
        }
        optional {
            0x60 => cli: Cli {wire_len 3, 14},
            0x61 => ss_code: SsCode {wire_len 2, 2},
            0x62 => lcs_indicator: LcsIndicator {wire_len 2, 2},
            0x63 => lcs_client_identity: LcsClientIdentity {wire_len 3, 257},
        }
    }
}

nas_message! {
    /// Detach Accept (TS 24.301 §8.2.10.1).
    pub struct DetachAccept {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// Detach Request (UE originating) (TS 24.301 §8.2.11.1).
    pub struct DetachRequestUeOriginating {
        mandatory {
            detach_type: DetachType [low_half_first],
            nas_key_set_identifier: KeySetIdentifier [high_half_last],
            eps_mobile_identity: EpsMobileIdentity {wire_len 5, 12},
        }
        optional {
        }
    }
}

nas_message! {
    /// Detach Request (UE terminated) (TS 24.301 §8.2.11.2).
    pub struct DetachRequestUeTerminated {
        mandatory {
            detach_type: DetachType {wire_len 1, 1},
        }
        optional {
            0x53 => emm_cause: EmmCause {wire_len 2, 2},
            0x1C => lower_bound_timer_value: GprsTimer3 {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 8, 98},
            0x20 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5},
            0x21 => s_and_f_satellite_operation_parameters: SAndFSatelliteOperationParameters {wire_len 3, 257},
            0x24 => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
        }
    }
}

nas_message! {
    /// Downlink NAS Transport (TS 24.301 §8.2.12).
    pub struct DownlinkNasTransport {
        mandatory {
            nas_message_container: MessageContainer {wire_len 3, 252},
        }
        optional {
        }
    }
}

nas_message! {
    /// EMM Information (TS 24.301 §8.2.13).
    pub struct EmmInformation {
        mandatory {
        }
        optional {
            0x43 => full_name_for_network: NetworkName {wire_len 3, usize::MAX},
            0x45 => short_name_for_network: NetworkName {wire_len 3, usize::MAX},
            0x46 => local_time_zone: TimeZone {wire_len 2, 2},
            0x47 => universal_time_and_local_time_zone: TimeZoneAndTime {wire_len 8, 8},
            0x49 => network_daylight_saving_time: DaylightSavingTime {wire_len 3, 3},
        }
    }
}

nas_message! {
    /// EMM Status (TS 24.301 §8.2.14).
    pub struct EmmStatus {
        mandatory {
            emm_cause: EmmCause {wire_len 1, 1},
        }
        optional {
        }
    }
}

nas_message! {
    /// Extended Service Request (TS 24.301 §8.2.15).
    pub struct ExtendedServiceRequest {
        mandatory {
            service_type: ServiceType [low_half_first],
            nas_key_set_identifier: KeySetIdentifier [high_half_last],
            m_tmsi: MobileIdentity {wire_len 6, 6},
        }
        optional {
            0xB0 => csfb_response: CsfbResponse [tv1] {wire_len 1, 1},
            0x57 => eps_bearer_context_status: EpsBearerContextStatus {wire_len 4, 4},
            0xD0 => device_properties: DeviceProperties [tv1] {wire_len 1, 1},
            0x29 => ue_request_type: UeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: PagingRestriction {wire_len 3, 5},
        }
    }
}

nas_message! {
    /// GUTI Reallocation Command (TS 24.301 §8.2.16).
    pub struct GutiReallocationCommand {
        mandatory {
            guti: EpsMobileIdentity {wire_len 12, 12},
        }
        optional {
            0x54 => tai_list: TrackingAreaIdentityList {wire_len 8, 98},
            0x65 => dcn_id: DcnId {wire_len 4, 4},
            0x66 => ue_radio_capability_id: UeRadioCapabilityId {wire_len 3, usize::MAX},
            0xB0 => ue_radio_capability_id_deletion_indication: UeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x20 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 2, 5},
        }
    }
}

nas_message! {
    /// GUTI Reallocation Complete (TS 24.301 §8.2.17).
    pub struct GutiReallocationComplete {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// Identity Request (TS 24.301 §8.2.18).
    pub struct IdentityRequest {
        mandatory {
            identity_type: IdentityType2 {wire_len 1, 1},
        }
        optional {
        }
    }
}

nas_message! {
    /// Identity Response (TS 24.301 §8.2.19).
    pub struct IdentityResponse {
        mandatory {
            mobile_identity: MobileIdentity {wire_len 4, 10},
        }
        optional {
        }
    }
}

nas_message! {
    /// Security Mode Command (TS 24.301 §8.2.20).
    pub struct SecurityModeCommand {
        mandatory {
            selected_nas_security_algorithms: SecurityAlgorithms {wire_len 1, 1},
            nas_key_set_identifier: KeySetIdentifier {wire_len 1, 1},
            replayed_ue_security_capabilities: UeSecurityCapability {wire_len 3, 6},
        }
        optional {
            0xC0 => imeisv_request: ImeisvRequest [tv1] {wire_len 1, 1},
            0x55 => replayed_nonce_ue: Nonce {wire_len 5, 5},
            0x56 => nonce_mme: Nonce {wire_len 5, 5},
            0x4F => hash_mme: HashMme {wire_len 10, 10},
            0x6F => replayed_ue_additional_security_capability: UeAdditionalSecurityCapability {wire_len 6, 6},
            0x37 => ue_radio_capability_id_request: UeRadioCapabilityIdRequest {wire_len 3, 3},
            0xD0 => ue_coarse_location_information_request: UeInformationRequest [tv1] {wire_len 1, 1},
        }
    }
}

nas_message! {
    /// Security Mode Complete (TS 24.301 §8.2.21).
    pub struct SecurityModeComplete {
        mandatory {
        }
        optional {
            0x23 => imeisv: MobileIdentity {wire_len 11, 11},
            0x79 => replayed_nas_message_container: ReplayedNasMessageContainer {wire_len 3, usize::MAX},
            0x66 => ue_radio_capability_id: UeRadioCapabilityId {wire_len 3, usize::MAX},
            0x67 => ue_coarse_location_information: UeCoarseLocationInformation {wire_len 8, 8},
        }
    }
}

nas_message! {
    /// Security Mode Reject (TS 24.301 §8.2.22).
    pub struct SecurityModeReject {
        mandatory {
            emm_cause: EmmCause {wire_len 1, 1},
        }
        optional {
        }
    }
}

nas_message! {
    /// Service Reject (TS 24.301 §8.2.24).
    pub struct ServiceReject {
        mandatory {
            emm_cause: EmmCause {wire_len 1, 1},
        }
        optional {
            0x5B => t3442_value: GprsTimer {wire_len 2, 2},
            0x5F => t3346_value: GprsTimer2 {wire_len 3, 3},
            0x6B => t3448_value: GprsTimer2 {wire_len 3, 3},
            0x1C => lower_bound_timer_value: GprsTimer3 {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 8, 98},
            0x20 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5},
            0x21 => s_and_f_satellite_operation_parameters: SAndFSatelliteOperationParameters {wire_len 3, 257},
            0x24 => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
        }
    }
}

nas_message! {
    /// Tracking Area Update Accept (TS 24.301 §8.2.26).
    pub struct TrackingAreaUpdateAccept {
        mandatory {
            eps_update_result: EpsUpdateResult {wire_len 1, 1},
        }
        optional {
            0x5A => t3412_value: T3412Value {wire_len 2, 2},
            0x50 => guti: EpsMobileIdentity {wire_len 13, 13},
            0x54 => tai_list: TrackingAreaIdentityList {wire_len 8, 98},
            0x57 => eps_bearer_context_status: EpsBearerContextStatus {wire_len 4, 4},
            0x13 => location_area_identification: LocationAreaIdentification {wire_len 6, 6},
            0x23 => ms_identity: MobileIdentity {wire_len 7, 10},
            0x53 => emm_cause: EmmCause {wire_len 2, 2},
            0x17 => t3402_value: GprsTimer {wire_len 2, 2},
            0x59 => t3423_value: GprsTimer {wire_len 2, 2},
            0x4A => equivalent_plmns: PlmnList {wire_len 5, 47},
            0x34 => emergency_number_list: EmergencyNumberList {wire_len 5, 50},
            0x64 => eps_network_feature_support: EpsNetworkFeatureSupport {wire_len 3, 5},
            0xF0 => additional_update_result: AdditionalUpdateResult [tv1] {wire_len 1, 1},
            0x5E => t3412_extended_value: T3412ExtendedValue {wire_len 3, 3},
            0x6A => t3324_value: GprsTimer2 {wire_len 3, 3},
            0x6E => extended_drx_parameters: ExtendedDrxParameters {wire_len 3, 3},
            0x68 => header_compression_configuration_status: HeaderCompressionConfigurationStatus {wire_len 4, 4},
            0x65 => dcn_id: DcnId {wire_len 4, 4},
            0xE0 => sms_services_status: SmsServicesStatus [tv1] {wire_len 1, 1},
            0xD0 => non_3gpp_nw_policies: Non3GppNwProvidedPolicies [tv1] {wire_len 1, 1},
            0x6B => t3448_value: GprsTimer2 {wire_len 3, 3},
            0xC0 => network_policy: NetworkPolicy [tv1] {wire_len 1, 1},
            0x6C => t3447_value: GprsTimer3 {wire_len 3, 3},
            0x7A => extended_emergency_number_list: ExtendedEmergencyNumberList {wire_len 7, 65538},
            0x7C => ciphering_key_data: CipheringKeyData {wire_len 35, 2291},
            0x66 => ue_radio_capability_id: UeRadioCapabilityId {wire_len 3, usize::MAX},
            0xB0 => ue_radio_capability_id_deletion_indication: UeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x35 => negotiated_wus_assistance_information: WusAssistanceInformation {wire_len 3, 3},
            0x36 => negotiated_drx_parameter_in_nb_s1_mode: NbS1DrxParameter {wire_len 3, 3},
            0x38 => negotiated_imsi_offset: ImsiOffset {wire_len 4, 4},
            0x37 => eps_additional_request_result: EpsAdditionalRequestResult {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 8, 98},
            0x39 => maximum_time_offset: GprsTimer3 {wire_len 3, 3},
            0x1F => unavailability_configuration: UnavailabilityConfiguration {wire_len 3, 9},
            0x20 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5},
            0x21 => s_and_f_satellite_operation_parameters: SAndFSatelliteOperationParameters {wire_len 3, 257},
            0x22 => disaster_roaming_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x24 => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x25 => list_of_plmns_to_be_used_in_disaster_condition: ListOfPlmnsToBeUsedInDisasterCondition {wire_len 2, usize::MAX},
        }
    }
}

nas_message! {
    /// Tracking Area Update Complete (TS 24.301 §8.2.27).
    pub struct TrackingAreaUpdateComplete {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// Tracking Area Update Reject (TS 24.301 §8.2.28).
    pub struct TrackingAreaUpdateReject {
        mandatory {
            emm_cause: EmmCause {wire_len 1, 1},
        }
        optional {
            0x5F => t3346_value: GprsTimer2 {wire_len 3, 3},
            0xA0 => extended_emm_cause: ExtendedEmmCause [tv1] {wire_len 1, 1},
            0x1C => lower_bound_timer_value: GprsTimer3 {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 8, 98},
            0x20 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5},
            0x21 => s_and_f_satellite_operation_parameters: SAndFSatelliteOperationParameters {wire_len 3, 257},
            0x24 => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
        }
    }
}

nas_message! {
    /// Tracking Area Update Request (TS 24.301 §8.2.29).
    pub struct TrackingAreaUpdateRequest {
        mandatory {
            eps_update_type: EpsUpdateType [low_half_first],
            nas_key_set_identifier: KeySetIdentifier [high_half_last],
            old_guti: EpsMobileIdentity {wire_len 12, 12},
        }
        optional {
            0xB0 => non_current_native_nas_key_set_identifier: KeySetIdentifier [tv1] {wire_len 1, 1},
            0x80 => gprs_ciphering_key_sequence_number: CipheringKeySequenceNumber [tv1] {wire_len 1, 1},
            0x19 => old_p_tmsi_signature: PTmsiSignature {wire_len 4, 4},
            0x50 => additional_guti: EpsMobileIdentity {wire_len 13, 13},
            0x55 => nonce_ue: Nonce {wire_len 5, 5},
            0x58 => ue_network_capability: UeNetworkCapability {wire_len 4, 15},
            0x52 => last_visited_registered_tai: TrackingAreaIdentity {wire_len 6, 6},
            0x5C => drx_parameter: DrxParameter {wire_len 3, 3},
            0xA0 => ue_radio_capability_information_update_needed: UeRadioCapabilityInformationUpdateNeeded [tv1] {wire_len 1, 1},
            0x57 => eps_bearer_context_status: EpsBearerContextStatus {wire_len 4, 4},
            0x31 => ms_network_capability: MsNetworkCapability {wire_len 4, 10},
            0x13 => old_location_area_identification: LocationAreaIdentification {wire_len 6, 6},
            0x90 => tmsi_status: TmsiStatus [tv1] {wire_len 1, 1},
            0x11 => mobile_station_classmark_2: MobileStationClassmark2 {wire_len 5, 5},
            0x20 => mobile_station_classmark_3: MobileStationClassmark3 {wire_len 2, 34},
            0x40 => supported_codecs: SupportedCodecList {wire_len 5, usize::MAX},
            0xF0 => additional_update_type: AdditionalUpdateType [tv1] {wire_len 1, 1},
            0x5D => voice_domain_preference_and_ue_usage_setting: VoiceDomainPreferenceAndUeUsageSetting {wire_len 3, 3},
            0xE0 => old_guti_type: GutiType [tv1] {wire_len 1, 1},
            0xD0 => device_properties: DeviceProperties [tv1] {wire_len 1, 1},
            0xC0 => ms_network_feature_support: MsNetworkFeatureSupport [tv1] {wire_len 1, 1},
            0x10 => tmsi_based_nri_container: NetworkResourceIdentifierContainer {wire_len 4, 4},
            0x6A => t3324_value: GprsTimer2 {wire_len 3, 3},
            0x5E => t3412_extended_value: T3412ExtendedValue {wire_len 3, 3},
            0x6E => extended_drx_parameters: ExtendedDrxParameters {wire_len 3, 3},
            0x6F => ue_additional_security_capability: UeAdditionalSecurityCapability {wire_len 6, 6},
            0x6D => ue_status: UeStatus {wire_len 3, 3},
            0x17 => additional_information_requested: AdditionalInformationRequested {wire_len 2, 2},
            0x32 => n1_ue_network_capability: N1UeNetworkCapability {wire_len 3, 15},
            0x34 => ue_radio_capability_id_availability: UeRadioCapabilityIdAvailability {wire_len 3, 3},
            0x35 => requested_wus_assistance_information: WusAssistanceInformation {wire_len 3, 3},
            0x36 => drx_parameter_in_nb_s1_mode: NbS1DrxParameter {wire_len 3, 3},
            0x38 => requested_imsi_offset: ImsiOffset {wire_len 4, 4},
            0x29 => ue_request_type: UeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: PagingRestriction {wire_len 3, 5},
            0x30 => unavailability_information: UnavailabilityInformation {wire_len 3, 9},
            0x26 => ue_determined_plmn_with_disaster_condition: PlmnIdentity {wire_len 5, 5},
        }
    }
}

nas_message! {
    /// Uplink NAS Transport (TS 24.301 §8.2.30).
    pub struct UplinkNasTransport {
        mandatory {
            nas_message_container: MessageContainer {wire_len 3, 252},
        }
        optional {
        }
    }
}

nas_message! {
    /// Downlink Generic NAS Transport (TS 24.301 §8.2.31).
    pub struct DownlinkGenericNasTransport {
        mandatory {
            generic_message_container_type: GenericMessageContainerType {wire_len 1, 1},
            generic_message_container: GenericMessageContainer {wire_len 3, usize::MAX},
        }
        optional {
            0x65 => additional_information: AdditionalInformation {wire_len 3, usize::MAX},
        }
    }
}

nas_message! {
    /// Uplink Generic NAS Transport (TS 24.301 §8.2.32).
    pub struct UplinkGenericNasTransport {
        mandatory {
            generic_message_container_type: GenericMessageContainerType {wire_len 1, 1},
            generic_message_container: GenericMessageContainer {wire_len 3, usize::MAX},
        }
        optional {
            0x65 => additional_information: AdditionalInformation {wire_len 3, usize::MAX},
        }
    }
}

nas_message! {
    /// Control Plane Service Request (TS 24.301 §8.2.33).
    pub struct ControlPlaneServiceRequest {
        mandatory {
            control_plane_service_type: ControlPlaneServiceType [low_half_first],
            nas_key_set_identifier: KeySetIdentifier [high_half_last],
        }
        optional {
            0x78 => esm_message_container: EsmMessageContainer {wire_len 3, usize::MAX},
            0x67 => nas_message_container: MessageContainer {wire_len 4, 253},
            0x57 => eps_bearer_context_status: EpsBearerContextStatus {wire_len 4, 4},
            0xD0 => device_properties: DeviceProperties [tv1] {wire_len 1, 1},
            0x29 => ue_request_type: UeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: PagingRestriction {wire_len 3, 5},
        }
    }
}

nas_message! {
    /// Service Accept (TS 24.301 §8.2.34).
    pub struct ServiceAccept {
        mandatory {
        }
        optional {
            0x57 => eps_bearer_context_status: EpsBearerContextStatus {wire_len 4, 4},
            0x6B => t3448_value: GprsTimer2 {wire_len 3, 3},
            0x37 => eps_additional_request_result: EpsAdditionalRequestResult {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 8, 98},
            0x1E => forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 8, 98},
            0x21 => s_and_f_satellite_operation_parameters: SAndFSatelliteOperationParameters {wire_len 3, 257},
        }
    }
}

nas_message! {
    /// Activate Dedicated EPS Bearer Context Accept (TS 24.301 §8.3.1).
    pub struct ActivateDedicatedEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Activate Dedicated EPS Bearer Context Reject (TS 24.301 §8.3.2).
    pub struct ActivateDedicatedEpsBearerContextReject {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Activate Dedicated EPS Bearer Context Request (TS 24.301 §8.3.3).
    pub struct ActivateDedicatedEpsBearerContextRequest {
        mandatory {
            linked_eps_bearer_identity: LinkedEpsBearerIdentity {wire_len 1, 1},
            eps_qos: EpsQualityOfService {wire_len 2, 14},
            tft: TrafficFlowTemplate {wire_len 2, 256},
        }
        optional {
            0x5D => transaction_identifier: TransactionIdentifier {wire_len 3, 4},
            0x30 => negotiated_qos: QualityOfService {wire_len 5, 22},
            0x32 => negotiated_llc_sapi: LlcServiceAccessPointIdentifier {wire_len 2, 2},
            0x80 => radio_priority: RadioPriority [tv1] {wire_len 1, 1},
            0x34 => packet_flow_identifier: PacketFlowIdentifier {wire_len 3, 3},
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => wlan_offload_indication: WlanOffloadAcceptability [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x5C => extended_eps_qos: ExtendedQualityOfService {wire_len 12, 12},
        }
    }
}

nas_message! {
    /// Activate Default EPS Bearer Context Accept (TS 24.301 §8.3.4).
    pub struct ActivateDefaultEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Activate Default EPS Bearer Context Reject (TS 24.301 §8.3.5).
    pub struct ActivateDefaultEpsBearerContextReject {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Activate Default EPS Bearer Context Request (TS 24.301 §8.3.6).
    pub struct ActivateDefaultEpsBearerContextRequest {
        mandatory {
            eps_qos: EpsQualityOfService {wire_len 2, 14},
            access_point_name: AccessPointName {wire_len 2, 101},
            pdn_address: PdnAddress {wire_len 6, 14},
        }
        optional {
            0x5D => transaction_identifier: TransactionIdentifier {wire_len 3, 4},
            0x30 => negotiated_qos: QualityOfService {wire_len 5, 22},
            0x32 => negotiated_llc_sapi: LlcServiceAccessPointIdentifier {wire_len 2, 2},
            0x80 => radio_priority: RadioPriority [tv1] {wire_len 1, 1},
            0x34 => packet_flow_identifier: PacketFlowIdentifier {wire_len 3, 3},
            0x5E => apn_ambr: ApnAggregateMaximumBitRate {wire_len 4, 8},
            0x58 => esm_cause: EsmCause {wire_len 2, 2},
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0xB0 => connectivity_type: ConnectivityType [tv1] {wire_len 1, 1},
            0xC0 => wlan_offload_indication: WlanOffloadAcceptability [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x66 => header_compression_configuration: HeaderCompressionConfiguration {wire_len 5, 257},
            0x90 => control_plane_only_indication: ControlPlaneOnlyIndication [tv1] {wire_len 1, 1},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x6E => serving_plmn_rate_control: ServingPlmnRateControl {wire_len 4, 4},
            0x5F => extended_apn_ambr: ExtendedApnAggregateMaximumBitRate {wire_len 8, 8},
        }
    }
}

nas_message! {
    /// Bearer Resource Allocation Reject (TS 24.301 §8.3.7).
    pub struct BearerResourceAllocationReject {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x37 => back_off_timer_value: GprsTimer3 {wire_len 3, 3},
            0x6B => re_attempt_indicator: ReAttemptIndicator {wire_len 3, 3},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Bearer Resource Allocation Request (TS 24.301 §8.3.8).
    pub struct BearerResourceAllocationRequest {
        mandatory {
            linked_eps_bearer_identity: LinkedEpsBearerIdentity {wire_len 1, 1},
            traffic_flow_aggregate: TrafficFlowAggregateDescription {wire_len 2, 256},
            required_traffic_flow_qos: EpsQualityOfService {wire_len 2, 14},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => device_properties: DeviceProperties [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x5C => extended_eps_qos: ExtendedQualityOfService {wire_len 12, 12},
        }
    }
}

nas_message! {
    /// Bearer Resource Modification Reject (TS 24.301 §8.3.9).
    pub struct BearerResourceModificationReject {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x37 => back_off_timer_value: GprsTimer3 {wire_len 3, 3},
            0x6B => re_attempt_indicator: ReAttemptIndicator {wire_len 3, 3},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Bearer Resource Modification Request (TS 24.301 §8.3.10).
    pub struct BearerResourceModificationRequest {
        mandatory {
            eps_bearer_identity_for_packet_filter: LinkedEpsBearerIdentity {wire_len 1, 1},
            traffic_flow_aggregate: TrafficFlowAggregateDescription {wire_len 2, 256},
        }
        optional {
            0x5B => required_traffic_flow_qos: EpsQualityOfService {wire_len 3, 15},
            0x58 => esm_cause: EsmCause {wire_len 2, 2},
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => device_properties: DeviceProperties [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x66 => header_compression_configuration: HeaderCompressionConfiguration {wire_len 5, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x5C => extended_eps_qos: ExtendedQualityOfService {wire_len 12, 12},
        }
    }
}

nas_message! {
    /// Deactivate EPS Bearer Context Accept (TS 24.301 §8.3.11).
    pub struct DeactivateEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Deactivate EPS Bearer Context Request (TS 24.301 §8.3.12).
    pub struct DeactivateEpsBearerContextRequest {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x37 => t3396_value: GprsTimer3 {wire_len 3, 3},
            0xC0 => wlan_offload_indication: WlanOffloadAcceptability [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// ESM Dummy Message (TS 24.301 §8.3.12A).
    pub struct EsmDummyMessage {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM Information Request (TS 24.301 §8.3.13).
    pub struct EsmInformationRequest {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM Information Response (TS 24.301 §8.3.14).
    pub struct EsmInformationResponse {
        mandatory {
        }
        optional {
            0x28 => access_point_name: AccessPointName {wire_len 3, 102},
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// ESM Status (TS 24.301 §8.3.15).
    pub struct EsmStatus {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
        }
    }
}

nas_message! {
    /// Modify EPS Bearer Context Accept (TS 24.301 §8.3.16).
    pub struct ModifyEpsBearerContextAccept {
        mandatory {
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Modify EPS Bearer Context Reject (TS 24.301 §8.3.17).
    pub struct ModifyEpsBearerContextReject {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Modify EPS Bearer Context Request (TS 24.301 §8.3.18).
    pub struct ModifyEpsBearerContextRequest {
        mandatory {
        }
        optional {
            0x5B => new_eps_qos: EpsQualityOfService {wire_len 3, 15},
            0x36 => tft: TrafficFlowTemplate {wire_len 3, 257},
            0x30 => new_qos: QualityOfService {wire_len 5, 22},
            0x32 => negotiated_llc_sapi: LlcServiceAccessPointIdentifier {wire_len 2, 2},
            0x80 => radio_priority: RadioPriority [tv1] {wire_len 1, 1},
            0x34 => packet_flow_identifier: PacketFlowIdentifier {wire_len 3, 3},
            0x5E => apn_ambr: ApnAggregateMaximumBitRate {wire_len 4, 8},
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => wlan_offload_indication: WlanOffloadAcceptability [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x66 => header_compression_configuration: HeaderCompressionConfiguration {wire_len 5, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x5F => extended_apn_ambr: ExtendedApnAggregateMaximumBitRate {wire_len 8, 8},
            0x5C => extended_eps_qos: ExtendedQualityOfService {wire_len 12, 12},
        }
    }
}

nas_message! {
    /// Notification (TS 24.301 §8.3.18A).
    pub struct Notification {
        mandatory {
            notification_indicator: NotificationIndicator {wire_len 2, 2},
        }
        optional {
        }
    }
}

nas_message! {
    /// PDN Connectivity Reject (TS 24.301 §8.3.19).
    pub struct PdnConnectivityReject {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x37 => back_off_timer_value: GprsTimer3 {wire_len 3, 3},
            0x6B => re_attempt_indicator: ReAttemptIndicator {wire_len 3, 3},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// PDN Connectivity Request (TS 24.301 §8.3.20).
    pub struct PdnConnectivityRequest {
        mandatory {
            request_type: RequestType [low_half_first],
            pdn_type: PdnType [high_half_last],
        }
        optional {
            0xD0 => esm_information_transfer_flag: EsmInformationTransferFlag [tv1] {wire_len 1, 1},
            0x28 => access_point_name: AccessPointName {wire_len 3, 102},
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0xC0 => device_properties: DeviceProperties [tv1] {wire_len 1, 1},
            0x33 => nbifom_container: NbifomContainer {wire_len 3, 257},
            0x66 => header_compression_configuration: HeaderCompressionConfiguration {wire_len 5, 257},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// PDN Disconnect Reject (TS 24.301 §8.3.21).
    pub struct PdnDisconnectReject {
        mandatory {
            esm_cause: EsmCause {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// PDN Disconnect Request (TS 24.301 §8.3.22).
    pub struct PdnDisconnectRequest {
        mandatory {
            linked_eps_bearer_identity: LinkedEpsBearerIdentity {wire_len 1, 1},
        }
        optional {
            0x27 => protocol_configuration_options: ProtocolConfigurationOptions {wire_len 3, 253},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
        }
    }
}

nas_message! {
    /// Remote UE Report (TS 24.301 §8.3.23).
    pub struct RemoteUeReport {
        mandatory {
        }
        optional {
            0x79 => remote_ue_context_connected: RemoteUeContextList {wire_len 3, 65538},
            0x7A => remote_ue_context_disconnected: RemoteUeContextList {wire_len 3, 65538},
            0x6F => prose_key_management_function_address: PkmfAddress {wire_len 3, 19},
        }
    }
}

nas_message! {
    /// Remote UE Report Response (TS 24.301 §8.3.24).
    pub struct RemoteUeReportResponse {
        mandatory {
        }
        optional {
        }
    }
}

nas_message! {
    /// ESM Data Transport (TS 24.301 §8.3.25).
    pub struct EsmDataTransport {
        mandatory {
            user_data_container: UserDataContainer {wire_len 2, usize::MAX},
        }
        optional {
            0xF0 => release_assistance_indication: ReleaseAssistanceIndication [tv1] {wire_len 1, 1},
        }
    }
}

crate::common::nas_messages! {
    /// EMM message bodies (TS 24.301 §8.2).
    pub enum EmmMessage;
    /// EMM message types (TS 24.301 Table 9.8.1).
    pub enum EmmMessageType;
    {
        /// Attach Request (0x41).
        AttachRequest = 65 => AttachRequest,
        /// Attach Accept (0x42).
        AttachAccept = 66 => AttachAccept,
        /// Attach Complete (0x43).
        AttachComplete = 67 => AttachComplete,
        /// Attach Reject (0x44).
        AttachReject = 68 => AttachReject,
        /// Detach Accept (0x46).
        DetachAccept = 70 => DetachAccept,
        /// Tracking Area Update Request (0x48).
        TrackingAreaUpdateRequest = 72 => TrackingAreaUpdateRequest,
        /// Tracking Area Update Accept (0x49).
        TrackingAreaUpdateAccept = 73 => TrackingAreaUpdateAccept,
        /// Tracking Area Update Complete (0x4A).
        TrackingAreaUpdateComplete = 74 => TrackingAreaUpdateComplete,
        /// Tracking Area Update Reject (0x4B).
        TrackingAreaUpdateReject = 75 => TrackingAreaUpdateReject,
        /// Extended Service Request (0x4C).
        ExtendedServiceRequest = 76 => ExtendedServiceRequest,
        /// Control Plane Service Request (0x4D).
        ControlPlaneServiceRequest = 77 => ControlPlaneServiceRequest,
        /// Service Reject (0x4E).
        ServiceReject = 78 => ServiceReject,
        /// Service Accept (0x4F).
        ServiceAccept = 79 => ServiceAccept,
        /// GUTI Reallocation Command (0x50).
        GutiReallocationCommand = 80 => GutiReallocationCommand,
        /// GUTI Reallocation Complete (0x51).
        GutiReallocationComplete = 81 => GutiReallocationComplete,
        /// Authentication Request (0x52).
        AuthenticationRequest = 82 => AuthenticationRequest,
        /// Authentication Response (0x53).
        AuthenticationResponse = 83 => AuthenticationResponse,
        /// Authentication Reject (0x54).
        AuthenticationReject = 84 => AuthenticationReject,
        /// Identity Request (0x55).
        IdentityRequest = 85 => IdentityRequest,
        /// Identity Response (0x56).
        IdentityResponse = 86 => IdentityResponse,
        /// Authentication Failure (0x5C).
        AuthenticationFailure = 92 => AuthenticationFailure,
        /// Security Mode Command (0x5D).
        SecurityModeCommand = 93 => SecurityModeCommand,
        /// Security Mode Complete (0x5E).
        SecurityModeComplete = 94 => SecurityModeComplete,
        /// Security Mode Reject (0x5F).
        SecurityModeReject = 95 => SecurityModeReject,
        /// EMM Status (0x60).
        EmmStatus = 96 => EmmStatus,
        /// EMM Information (0x61).
        EmmInformation = 97 => EmmInformation,
        /// Downlink NAS Transport (0x62).
        DownlinkNasTransport = 98 => DownlinkNasTransport,
        /// Uplink NAS Transport (0x63).
        UplinkNasTransport = 99 => UplinkNasTransport,
        /// CS Service Notification (0x64).
        CsServiceNotification = 100 => CsServiceNotification,
        /// Downlink Generic NAS Transport (0x68).
        DownlinkGenericNasTransport = 104 => DownlinkGenericNasTransport,
        /// Uplink Generic NAS Transport (0x69).
        UplinkGenericNasTransport = 105 => UplinkGenericNasTransport,
    }
    /// Detach Request (0x45).
    DetachRequest = 69 by decode_detach_request {
        /// Detach Request (UE originating) (§8.2.11.1).
        DetachRequestUeOriginating => DetachRequestUeOriginating,
        /// Detach Request (UE terminated) (§8.2.11.2).
        DetachRequestUeTerminated => DetachRequestUeTerminated,
    }
}

/// A DETACH REQUEST of either direction, which share the message type. The UE
/// form needs an LV EPS mobile identity of 4 to 11 octets holding an IMSI, an
/// IMEI or a GUTI (Table 8.2.11.1.1, §9.9.3.12); when it only parses by
/// reading IEs as unknown, the network form is preferred.
fn decode_detach_request(
    buffer: &mut &[u8],
    _: crate::common::Faults<'_, '_>,
) -> Result<EmmMessage> {
    let mut ue_probe = *buffer;
    let from_ue = DetachRequestUeOriginating::decode_from(&mut ue_probe)
        .ok()
        .filter(|_| !ue_probe.has_remaining());
    if let Some(request) = &from_ue
        && request.unknown_ies.is_empty()
        && (4..=11).contains(&request.eps_mobile_identity.value.len())
        && matches!(request.eps_mobile_identity.value[0] & 0x07, 1 | 3 | 6)
    {
        *buffer = ue_probe;
        return Ok(EmmMessage::DetachRequestUeOriginating(Box::new(
            request.clone(),
        )));
    }
    let mut network_probe = *buffer;
    match (
        DetachRequestUeTerminated::decode_from(&mut network_probe),
        from_ue,
    ) {
        (Ok(request), _) => {
            *buffer = network_probe;
            Ok(EmmMessage::DetachRequestUeTerminated(Box::new(request)))
        }
        (Err(_), Some(request)) => {
            *buffer = ue_probe;
            Ok(EmmMessage::DetachRequestUeOriginating(Box::new(request)))
        }
        (Err(error), None) => Err(error),
    }
}

impl EmmMessage {
    /// IEs the decoder did not recognize in the message body, and known IEs
    /// it ignored. An unknown IE encoded as "comprehension required" is
    /// flagged by [`UnknownIe::is_comprehension_required`](crate::UnknownIe::is_comprehension_required): the receiver
    /// answers it as TS 24.301 §7.5.1 requires.
    pub fn unknown_ies(&self) -> &UnknownIes {
        self.body().unknown_ies()
    }
}

impl Encode for EmmMessage {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        self.body().encode_into(buffer)
    }
}
impl TryFrom<(EmmMessageType, &mut &[u8])> for EmmMessage {
    type Error = Error;

    fn try_from((kind, buffer): (EmmMessageType, &mut &[u8])) -> Result<Self> {
        Self::decode_keeping(kind, buffer, &mut crate::common::Reading::strict())
    }
}

crate::common::nas_messages! {
    /// ESM message bodies (TS 24.301 §8.3).
    pub enum EsmMessage;
    /// ESM message types (TS 24.301 Table 9.8.2).
    pub enum EsmMessageType;
    {
        /// Activate Default EPS Bearer Context Request (0xC1).
        ActivateDefaultEpsBearerContextRequest = 193 => ActivateDefaultEpsBearerContextRequest,
        /// Activate Default EPS Bearer Context Accept (0xC2).
        ActivateDefaultEpsBearerContextAccept = 194 => ActivateDefaultEpsBearerContextAccept,
        /// Activate Default EPS Bearer Context Reject (0xC3).
        ActivateDefaultEpsBearerContextReject = 195 => ActivateDefaultEpsBearerContextReject,
        /// Activate Dedicated EPS Bearer Context Request (0xC5).
        ActivateDedicatedEpsBearerContextRequest = 197 => ActivateDedicatedEpsBearerContextRequest,
        /// Activate Dedicated EPS Bearer Context Accept (0xC6).
        ActivateDedicatedEpsBearerContextAccept = 198 => ActivateDedicatedEpsBearerContextAccept,
        /// Activate Dedicated EPS Bearer Context Reject (0xC7).
        ActivateDedicatedEpsBearerContextReject = 199 => ActivateDedicatedEpsBearerContextReject,
        /// Modify EPS Bearer Context Request (0xC9).
        ModifyEpsBearerContextRequest = 201 => ModifyEpsBearerContextRequest,
        /// Modify EPS Bearer Context Accept (0xCA).
        ModifyEpsBearerContextAccept = 202 => ModifyEpsBearerContextAccept,
        /// Modify EPS Bearer Context Reject (0xCB).
        ModifyEpsBearerContextReject = 203 => ModifyEpsBearerContextReject,
        /// Deactivate EPS Bearer Context Request (0xCD).
        DeactivateEpsBearerContextRequest = 205 => DeactivateEpsBearerContextRequest,
        /// Deactivate EPS Bearer Context Accept (0xCE).
        DeactivateEpsBearerContextAccept = 206 => DeactivateEpsBearerContextAccept,
        /// PDN Connectivity Request (0xD0).
        PdnConnectivityRequest = 208 => PdnConnectivityRequest,
        /// PDN Connectivity Reject (0xD1).
        PdnConnectivityReject = 209 => PdnConnectivityReject,
        /// PDN Disconnect Request (0xD2).
        PdnDisconnectRequest = 210 => PdnDisconnectRequest,
        /// PDN Disconnect Reject (0xD3).
        PdnDisconnectReject = 211 => PdnDisconnectReject,
        /// Bearer Resource Allocation Request (0xD4).
        BearerResourceAllocationRequest = 212 => BearerResourceAllocationRequest,
        /// Bearer Resource Allocation Reject (0xD5).
        BearerResourceAllocationReject = 213 => BearerResourceAllocationReject,
        /// Bearer Resource Modification Request (0xD6).
        BearerResourceModificationRequest = 214 => BearerResourceModificationRequest,
        /// Bearer Resource Modification Reject (0xD7).
        BearerResourceModificationReject = 215 => BearerResourceModificationReject,
        /// ESM Information Request (0xD9).
        EsmInformationRequest = 217 => EsmInformationRequest,
        /// ESM Information Response (0xDA).
        EsmInformationResponse = 218 => EsmInformationResponse,
        /// Notification (0xDB).
        Notification = 219 => Notification,
        /// ESM Dummy Message (0xDC).
        EsmDummyMessage = 220 => EsmDummyMessage,
        /// ESM Status (0xE8).
        EsmStatus = 232 => EsmStatus,
        /// Remote UE Report (0xE9).
        RemoteUeReport = 233 => RemoteUeReport,
        /// Remote UE Report Response (0xEA).
        RemoteUeReportResponse = 234 => RemoteUeReportResponse,
        /// ESM Data Transport (0xEB).
        EsmDataTransport = 235 => EsmDataTransport,
    }
}

impl EsmMessage {
    /// IEs the decoder did not recognize in the message body, and known IEs
    /// it ignored. An unknown IE encoded as "comprehension required" is
    /// flagged by [`UnknownIe::is_comprehension_required`](crate::UnknownIe::is_comprehension_required): the receiver
    /// answers it as TS 24.301 §7.5.1 requires.
    pub fn unknown_ies(&self) -> &UnknownIes {
        self.body().unknown_ies()
    }
}

impl Encode for EsmMessage {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        self.body().encode_into(buffer)
    }
}
impl TryFrom<(EsmMessageType, &mut &[u8])> for EsmMessage {
    type Error = Error;

    fn try_from((kind, buffer): (EsmMessageType, &mut &[u8])) -> Result<Self> {
        Self::decode_keeping(kind, buffer, &mut crate::common::Reading::strict())
    }
}

/// The system and the header of a message, then the message.
impl core::fmt::Display for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Emm(_, message) => write!(f, "EMM {message}"),
            Self::Esm(header, message) => write!(
                f,
                "ESM (EBI={}, PTI={}) {message}",
                header.eps_bearer_identity, header.procedure_transaction_identity
            ),
            Self::SecurityProtected(header, inner) => write!(
                f,
                "SecurityProtected (SHT={:?}, MAC={:#010x}, SN={}) {inner}",
                header.security_header_type,
                header.message_authentication_code,
                header.sequence_number
            ),
            Self::ServiceRequest(message) => write!(f, "EMM {message}"),
            Self::EmmTransport(message) => write!(f, "EMM {message}"),
            Self::Opaque(data) => write!(f, "Opaque ({} octets)", data.len()),
        }
    }
}

impl core::fmt::Display for ServiceRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ServiceRequest")?;
        let mut items = crate::common::display::Items::new(f);
        items.item("KSI", self.ksi_and_sequence_number >> 5)?;
        items.item("SN", self.ksi_and_sequence_number & 0x1f)?;
        let mac = self.message_authentication_code;
        items.item("short-MAC", format_args!("{mac:#06x}"))?;
        items.end()
    }
}

impl core::fmt::Display for EmmTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Transport")?;
        let mut items = crate::common::display::Items::new(f);
        items.item("SN", self.security_header.sequence_number)?;
        match &self.protected_payload {
            Some(opaque) => items.item("protected", crate::common::display::Octets(opaque))?,
            None => {
                let container = self.data_container.as_deref().unwrap_or_default();
                items.item("container", crate::common::display::Octets(container))?
            }
        }
        items.end()
    }
}

#[cfg(test)]
mod table_round_trip_tests {
    use super::*;

    #[test]
    fn every_chapter_8_message_body_round_trips() {
        {
            let pdu = Message::new_emm(AttachAccept::new(
                EpsAttachResult::new(0),
                T3412Value::new(0),
                TrackingAreaIdentityList::new(vec![0; 6]),
                EsmMessageContainer::new(vec![0; 3]),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "AttachAccept");
        }
        {
            let pdu = Message::new_emm(AttachComplete::new(EsmMessageContainer::new(vec![0; 3])));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "AttachComplete");
        }
        {
            let pdu = Message::new_emm(AttachReject::new(EmmCause::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "AttachReject");
        }
        {
            let pdu = Message::new_emm(AttachRequest::new(
                EpsAttachType::new(0),
                KeySetIdentifier::new(0),
                EpsMobileIdentity::from_imsi("001010123456789").unwrap(),
                UeNetworkCapability::new(vec![0; 2]),
                EsmMessageContainer::new(vec![0; 3]),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "AttachRequest");
        }
        {
            let pdu = Message::new_emm(AuthenticationFailure::new(EmmCause::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "AuthenticationFailure");
        }
        {
            let pdu = Message::new_emm(AuthenticationReject::new());
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "AuthenticationReject");
        }
        {
            let pdu = Message::new_emm(AuthenticationRequest::new(
                KeySetIdentifier::new(0),
                AuthenticationParameterRand::new(vec![0; 16]),
                AuthenticationParameterAutn::new(vec![0; 16]),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "AuthenticationRequest");
        }
        {
            let pdu = Message::new_emm(AuthenticationResponse::new(
                AuthenticationResponseParameter::new(vec![0; 4]),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "AuthenticationResponse");
        }
        {
            let pdu = Message::new_emm(CsServiceNotification::new(PagingIdentity::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "CsServiceNotification");
        }
        {
            let pdu = Message::new_emm(DetachAccept::new());
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "DetachAccept");
        }
        {
            let pdu = Message::new_emm(DetachRequestUeOriginating::new(
                DetachType::new(0),
                KeySetIdentifier::new(0),
                EpsMobileIdentity::from_imsi("001010123456789").unwrap(),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "DetachRequestUeOriginating"
            );
        }
        {
            let pdu = Message::new_emm(DetachRequestUeTerminated::new(DetachType::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "DetachRequestUeTerminated"
            );
        }
        {
            let pdu =
                Message::new_emm(DownlinkNasTransport::new(MessageContainer::new(vec![0; 2])));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "DownlinkNasTransport");
        }
        {
            let pdu = Message::new_emm(EmmInformation::new());
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "EmmInformation");
        }
        {
            let pdu = Message::new_emm(EmmStatus::new(EmmCause::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "EmmStatus");
        }
        {
            let pdu = Message::new_emm(ExtendedServiceRequest::new(
                ServiceType::new(0),
                KeySetIdentifier::new(0),
                MobileIdentity::from_tmsi(0),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "ExtendedServiceRequest");
        }
        {
            let pdu = Message::new_emm(GutiReallocationCommand::new(EpsMobileIdentity::new(vec![
                0xf6, 0x02, 0xf8, 0x39, 0, 0, 0, 0, 0, 0, 0,
            ])));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "GutiReallocationCommand");
        }
        {
            let pdu = Message::new_emm(GutiReallocationComplete::new());
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "GutiReallocationComplete");
        }
        {
            let pdu = Message::new_emm(IdentityRequest::new(IdentityType2::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "IdentityRequest");
        }
        {
            let pdu = Message::new_emm(IdentityResponse::new(
                MobileIdentity::from_imsi("001010123456789").unwrap(),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "IdentityResponse");
        }
        {
            let pdu = Message::new_emm(SecurityModeCommand::new(
                SecurityAlgorithms::new(0),
                KeySetIdentifier::new(0),
                UeSecurityCapability::new(vec![0; 2]),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "SecurityModeCommand");
        }
        {
            let pdu = Message::new_emm(SecurityModeComplete::new());
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "SecurityModeComplete");
        }
        {
            let pdu = Message::new_emm(SecurityModeReject::new(EmmCause::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "SecurityModeReject");
        }
        {
            let pdu = Message::new_emm(ServiceReject::new(EmmCause::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "ServiceReject");
        }
        {
            let pdu = Message::new_emm(TrackingAreaUpdateAccept::new(EpsUpdateResult::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "TrackingAreaUpdateAccept");
        }
        {
            let pdu = Message::new_emm(TrackingAreaUpdateComplete::new());
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "TrackingAreaUpdateComplete"
            );
        }
        {
            let pdu = Message::new_emm(TrackingAreaUpdateReject::new(EmmCause::new(0)));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "TrackingAreaUpdateReject");
        }
        {
            let pdu = Message::new_emm(TrackingAreaUpdateRequest::new(
                EpsUpdateType::new(0),
                KeySetIdentifier::new(0),
                EpsMobileIdentity::new(vec![0xf6, 0x02, 0xf8, 0x39, 0, 0, 0, 0, 0, 0, 0]),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "TrackingAreaUpdateRequest"
            );
        }
        {
            let pdu = Message::new_emm(UplinkNasTransport::new(MessageContainer::new(vec![0; 2])));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "UplinkNasTransport");
        }
        {
            let pdu = Message::new_emm(DownlinkGenericNasTransport::new(
                GenericMessageContainerType::new(0),
                GenericMessageContainer::new(vec![0; 1]),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "DownlinkGenericNasTransport"
            );
        }
        {
            let pdu = Message::new_emm(UplinkGenericNasTransport::new(
                GenericMessageContainerType::new(0),
                GenericMessageContainer::new(vec![0; 1]),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "UplinkGenericNasTransport"
            );
        }
        {
            let pdu = Message::new_emm(ControlPlaneServiceRequest::new(
                ControlPlaneServiceType::new(0),
                KeySetIdentifier::new(0),
            ));
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ControlPlaneServiceRequest"
            );
        }
        {
            let pdu = Message::new_emm(ServiceAccept::new());
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "ServiceAccept");
        }
        {
            let pdu = Message::new_esm(ActivateDedicatedEpsBearerContextAccept::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ActivateDedicatedEpsBearerContextAccept"
            );
        }
        {
            let pdu = Message::new_esm(
                ActivateDedicatedEpsBearerContextReject::new(EsmCause::new(0)),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ActivateDedicatedEpsBearerContextReject"
            );
        }
        {
            let pdu = Message::new_esm(
                ActivateDedicatedEpsBearerContextRequest::new(
                    LinkedEpsBearerIdentity::new(0),
                    EpsQualityOfService::new(vec![0; 1]),
                    TrafficFlowTemplate::new(vec![0; 1]),
                ),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ActivateDedicatedEpsBearerContextRequest"
            );
        }
        {
            let pdu = Message::new_esm(ActivateDefaultEpsBearerContextAccept::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ActivateDefaultEpsBearerContextAccept"
            );
        }
        {
            let pdu = Message::new_esm(
                ActivateDefaultEpsBearerContextReject::new(EsmCause::new(0)),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ActivateDefaultEpsBearerContextReject"
            );
        }
        {
            let pdu = Message::new_esm(
                ActivateDefaultEpsBearerContextRequest::new(
                    EpsQualityOfService::new(vec![0; 1]),
                    AccessPointName::from_string("internet").unwrap(),
                    PdnAddress::from_pdn_address(crate::nas_eps::PdnAddressValue::Ipv4([0; 4])),
                ),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ActivateDefaultEpsBearerContextRequest"
            );
        }
        {
            let pdu = Message::new_esm(BearerResourceAllocationReject::new(EsmCause::new(0)), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "BearerResourceAllocationReject"
            );
        }
        {
            let pdu = Message::new_esm(
                BearerResourceAllocationRequest::new(
                    LinkedEpsBearerIdentity::new(0),
                    TrafficFlowAggregateDescription::new(vec![0; 1]),
                    EpsQualityOfService::new(vec![0; 1]),
                ),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "BearerResourceAllocationRequest"
            );
        }
        {
            let pdu = Message::new_esm(
                BearerResourceModificationReject::new(EsmCause::new(0)),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "BearerResourceModificationReject"
            );
        }
        {
            let pdu = Message::new_esm(
                BearerResourceModificationRequest::new(
                    LinkedEpsBearerIdentity::new(0),
                    TrafficFlowAggregateDescription::new(vec![0; 1]),
                ),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "BearerResourceModificationRequest"
            );
        }
        {
            let pdu = Message::new_esm(DeactivateEpsBearerContextAccept::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "DeactivateEpsBearerContextAccept"
            );
        }
        {
            let pdu = Message::new_esm(
                DeactivateEpsBearerContextRequest::new(EsmCause::new(0)),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "DeactivateEpsBearerContextRequest"
            );
        }
        {
            let pdu = Message::new_esm(EsmDummyMessage::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "EsmDummyMessage");
        }
        {
            let pdu = Message::new_esm(EsmInformationRequest::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "EsmInformationRequest");
        }
        {
            let pdu = Message::new_esm(EsmInformationResponse::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "EsmInformationResponse");
        }
        {
            let pdu = Message::new_esm(EsmStatus::new(EsmCause::new(0)), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "EsmStatus");
        }
        {
            let pdu = Message::new_esm(ModifyEpsBearerContextAccept::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ModifyEpsBearerContextAccept"
            );
        }
        {
            let pdu = Message::new_esm(ModifyEpsBearerContextReject::new(EsmCause::new(0)), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ModifyEpsBearerContextReject"
            );
        }
        {
            let pdu = Message::new_esm(ModifyEpsBearerContextRequest::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(
                decoded.encode().unwrap(),
                bytes,
                "ModifyEpsBearerContextRequest"
            );
        }
        {
            let pdu = Message::new_esm(
                Notification::new(NotificationIndicator::new(vec![0; 1])),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "Notification");
        }
        {
            let pdu = Message::new_esm(PdnConnectivityReject::new(EsmCause::new(0)), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "PdnConnectivityReject");
        }
        {
            let pdu = Message::new_esm(
                PdnConnectivityRequest::new(RequestType::new(0), PdnType::new(0)),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "PdnConnectivityRequest");
        }
        {
            let pdu = Message::new_esm(PdnDisconnectReject::new(EsmCause::new(0)), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "PdnDisconnectReject");
        }
        {
            let pdu = Message::new_esm(
                PdnDisconnectRequest::new(LinkedEpsBearerIdentity::new(0)),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "PdnDisconnectRequest");
        }
        {
            let pdu = Message::new_esm(RemoteUeReport::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "RemoteUeReport");
        }
        {
            let pdu = Message::new_esm(RemoteUeReportResponse::new(), 0, 1);
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "RemoteUeReportResponse");
        }
        {
            let pdu = Message::new_esm(
                EsmDataTransport::new(UserDataContainer::new(vec![0; 0])),
                0,
                1,
            );
            let bytes = pdu.encode().unwrap();
            let decoded = Message::decode(&bytes).unwrap();
            assert_eq!(decoded.encode().unwrap(), bytes, "EsmDataTransport");
        }
    }
}

// END TS24301 MESSAGES

/// Plain EMM header (two octets).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmmHeader {
    /// Protocol discriminator (0111, EMM).
    pub protocol_discriminator: u8,
    /// Security header type; 0 for a plain message.
    pub security_header_type: SecurityHeaderType,
    /// Message type.
    pub message_type: EmmMessageType,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct EmmHeader { protocol_discriminator, security_header_type, message_type });

impl EmmHeader {
    /// Build a plain EMM header.
    pub fn new(message_type: EmmMessageType) -> Self {
        Self {
            protocol_discriminator: EPS_EMM_PROTOCOL_DISCRIMINATOR,
            security_header_type: SecurityHeaderType::PlainNasMessageNotSecurityProtected,
            message_type,
        }
    }
}

impl Encode for EmmHeader {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if self.protocol_discriminator != EPS_EMM_PROTOCOL_DISCRIMINATOR
            || self.security_header_type != SecurityHeaderType::PlainNasMessageNotSecurityProtected
        {
            return Err(Error::EncodingError(
                "a plain EMM header has the protocol discriminator 7 and the security header \
                 type of a plain NAS message"
                    .into(),
            ));
        }
        buffer.put_u8(self.protocol_discriminator);
        buffer.put_u8(u8::from(self.message_type));
        Ok(())
    }
}

impl Decode for EmmHeader {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(Error::MessageTooShort);
        }
        let first = buffer.get_u8();
        if first != EPS_EMM_PROTOCOL_DISCRIMINATOR {
            return Err(Error::DecodingError(format!(
                "invalid plain EPS EMM header 0x{first:02x}"
            )));
        }
        Ok(Self::new(EmmMessageType::from(buffer.get_u8())))
    }
}

/// ESM header (three octets), with the bearer identity in the high nibble.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EsmHeader {
    /// Protocol discriminator (0010, ESM).
    pub protocol_discriminator: u8,
    /// EPS bearer identity; 0 means no EPS bearer identity assigned.
    pub eps_bearer_identity: u8,
    /// Procedure transaction identity; 0 means none assigned, 255 is reserved.
    pub procedure_transaction_identity: u8,
    /// Message type.
    pub message_type: EsmMessageType,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct EsmHeader { protocol_discriminator, eps_bearer_identity, procedure_transaction_identity, message_type });

impl EsmHeader {
    /// Build an ESM header.
    pub fn new(
        message_type: EsmMessageType,
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

impl Encode for EsmHeader {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        // The reserved PTI 255 is encodable; `validate()` reports it.
        if self.protocol_discriminator != EPS_ESM_PROTOCOL_DISCRIMINATOR
            || self.eps_bearer_identity > 15
        {
            return Err(Error::EncodingError(
                "an ESM header has the protocol discriminator 2 and an EPS bearer identity of 0 \
                 to 15"
                    .into(),
            ));
        }
        buffer.put_u8((self.eps_bearer_identity << 4) | self.protocol_discriminator);
        buffer.put_u8(self.procedure_transaction_identity);
        buffer.put_u8(u8::from(self.message_type));
        Ok(())
    }
}

impl Decode for EsmHeader {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        if buffer.remaining() < 3 {
            return Err(Error::MessageTooShort);
        }
        let first = buffer.get_u8();
        if first & 0x0F != EPS_ESM_PROTOCOL_DISCRIMINATOR {
            return Err(Error::DecodingError(format!(
                "invalid EPS ESM header 0x{first:02x}"
            )));
        }
        let pti = buffer.get_u8();
        let kind = EsmMessageType::from(buffer.get_u8());
        Ok(Self::new(kind, first >> 4, pti))
    }
}

/// Short EPS SERVICE REQUEST header from TS 24.301 table 8.2.25.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRequest {
    /// Received security header type (12..=15); newly built messages use 12.
    pub security_header_type: u8,
    /// KSI (bits 8-6) and the five LSBs of the NAS COUNT (bits 5-1).
    pub ksi_and_sequence_number: u8,
    /// Short MAC: the two least significant octets of the NAS-MAC.
    pub message_authentication_code: u16,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct ServiceRequest { security_header_type, ksi_and_sequence_number, message_authentication_code });

impl ServiceRequest {
    /// Build a SERVICE REQUEST with security header type 12.
    pub fn new(ksi_and_sequence_number: u8, message_authentication_code: u16) -> Self {
        Self {
            security_header_type: 12,
            ksi_and_sequence_number,
            message_authentication_code,
        }
    }
}

impl Encode for ServiceRequest {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if !(12..=15).contains(&self.security_header_type) {
            return Err(Error::EncodingError(
                "invalid EPS SERVICE REQUEST security header type".into(),
            ));
        }
        buffer.put_u8((self.security_header_type << 4) | EPS_EMM_PROTOCOL_DISCRIMINATOR);
        buffer.put_u8(self.ksi_and_sequence_number);
        buffer.put_u16(self.message_authentication_code);
        Ok(())
    }
}

impl Decode for ServiceRequest {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        if buffer.remaining() < 4 {
            return Err(Error::MessageTooShort);
        }
        let first = buffer.get_u8();
        if first & 0x0f != EPS_EMM_PROTOCOL_DISCRIMINATOR || first >> 4 < 12 {
            return Err(Error::DecodingError(
                "invalid EPS SERVICE REQUEST header".into(),
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
pub struct EmmTransport {
    /// Security header with SHT 11.
    pub security_header: SecurityHeader,
    /// Plain data container, for a message that is not ciphered.
    pub data_container: Option<Vec<u8>>,
    /// Bytes following the security header before deciphering, if opaque.
    pub protected_payload: Option<Vec<u8>>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct EmmTransport { security_header, data_container, protected_payload });

impl EmmTransport {
    /// Build an EMM TRANSPORT without a container.
    pub fn new(message_authentication_code: u32, sequence_number: u8) -> Self {
        Self {
            security_header: SecurityHeader {
                security_header_type: SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage,
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

impl Encode for EmmTransport {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if self.security_header.security_header_type
            != SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        {
            return Err(Error::EncodingError("invalid EMM TRANSPORT header".into()));
        }
        self.security_header.encode_into(buffer)?;
        if let Some(payload) = &self.protected_payload {
            buffer.put_slice(payload);
        } else if self.data_container.is_some() {
            return Err(Error::EncodingError(
                "use SecurityContext to protect an EMM TRANSPORT data container".into(),
            ));
        }
        Ok(())
    }
}

impl Decode for EmmTransport {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        let security_header = SecurityHeader::decode_from(buffer)?;
        if security_header.security_header_type
            != SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        {
            return Err(Error::DecodingError("invalid EMM TRANSPORT header".into()));
        }
        let (data_container, protected_payload) = if buffer.has_remaining() {
            (None, Some(buffer.split_to(buffer.remaining()).to_vec()))
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
///
/// ```
/// use oxirush_nas::nas_eps::{EmmCauseValue, EmmMessage, Message};
///
/// // ATTACH REJECT, cause #3: a plain EMM message
/// let message = Message::decode(&[0x07, 0x44, 0x03]).unwrap();
/// let Message::Emm(_, EmmMessage::AttachReject(reject)) = &message else {
///     unreachable!()
/// };
/// assert_eq!(reject.emm_cause.cause(), Some(EmmCauseValue::IllegalUe));
/// assert_eq!(message.encode().unwrap(), [0x07, 0x44, 0x03]);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// Plain EMM message.
    Emm(EmmHeader, EmmMessage),
    /// Plain ESM message.
    Esm(EsmHeader, EsmMessage),
    /// Security-protected message (SHT 1 to 5) and its plain or opaque body.
    SecurityProtected(SecurityHeader, Box<Message>),
    /// SERVICE REQUEST, which has its own short header (SHT 12 to 15).
    ServiceRequest(ServiceRequest),
    /// EMM TRANSPORT (SHT 11).
    EmmTransport(EmmTransport),
    /// Encrypted or otherwise opaque body of a security-protected PDU.
    Opaque(Vec<u8>),
}

/// Sender rules pairing a security header type with the message it
/// protects (§5.4.3.2, §5.4.3.3, Table 9.3.1 NOTE 4). Decoding accepts other
/// pairings; `validate()` and [`Message::protect`] apply these rules.
pub(crate) fn check_protected_inner(sht: SecurityHeaderType, inner: &Message) -> Result<()> {
    if let Message::Emm(_, message) = inner {
        match message {
            EmmMessage::SecurityModeCommand(_)
                if sht != SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext =>
            {
                return Err(Error::EncodingError(
                    "SECURITY MODE COMMAND requires integrity protection with new context".into(),
                ));
            }
            EmmMessage::SecurityModeComplete(_)
                if sht != SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext =>
            {
                return Err(Error::EncodingError(
                    "SECURITY MODE COMPLETE requires ciphering with new context".into(),
                ));
            }
            _ => {}
        }
    }
    if let Message::Emm(_, EmmMessage::ControlPlaneServiceRequest(request)) = inner
        && sht
            != if request.esm_message_container.is_some() || request.nas_message_container.is_some()
            {
                SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
            } else {
                SecurityHeaderType::IntegrityProtected
            }
    {
        return Err(Error::EncodingError(
            "CONTROL PLANE SERVICE REQUEST security header type does not match its container"
                .into(),
        ));
    }
    let valid = match sht {
        SecurityHeaderType::IntegrityProtected => {
            matches!(inner, Message::Emm(..) | Message::Esm(..))
        }
        SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext => {
            matches!(inner, Message::Emm(_, EmmMessage::SecurityModeCommand(_)))
        }
        SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext => {
            matches!(
                inner,
                Message::Emm(_, EmmMessage::SecurityModeComplete(_)) | Message::Opaque(_)
            )
        }
        SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage => matches!(
            inner,
            Message::Emm(_, EmmMessage::ControlPlaneServiceRequest(_)) | Message::Opaque(_)
        ),
        SecurityHeaderType::IntegrityProtectedAndCiphered => !matches!(
            inner,
            Message::Emm(
                _,
                EmmMessage::AttachRequest(_) | EmmMessage::TrackingAreaUpdateRequest(_)
            )
        ),
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::EncodingError(
            "EPS security header type does not match message type".into(),
        ))
    }
}

impl Message {
    /// Create a plain EMM message with the type inferred from the body.
    pub fn new_emm(message: impl Into<EmmMessage>) -> Self {
        let message = message.into();
        Self::Emm(EmmHeader::new(message.message_type()), message)
    }

    /// Decode the plain message inside a security envelope that uses EEA0.
    ///
    /// EEA0 has the effect of an all-zero keystream (TS 33.401 §B.1.1), so
    /// the ciphered payload is the plain EMM or ESM message. An integrity-only
    /// envelope returns its already decoded message. The MAC is not verified.
    /// To validate security-header/message pairing, reconstruct an envelope
    /// with the returned message and the original header before calling
    /// `validate()`; use `SecurityContext` (feature `security`)
    /// when the NAS keys are known.
    pub fn decode_null_ciphered_payload(&self) -> Result<Message> {
        let Self::SecurityProtected(_, inner) = self else {
            return Err(Error::DecodingError(
                "EPS message has no security envelope".into(),
            ));
        };
        let Self::Opaque(payload) = inner.as_ref() else {
            return Ok(inner.as_ref().clone());
        };
        let mut buffer = payload.as_slice();
        let message = Self::decode_plain(&mut buffer, &mut crate::common::Reading::strict())?;
        if buffer.has_remaining() {
            return Err(crate::common::trailing(buffer.len()));
        }
        Ok(message)
    }

    /// Create a plain ESM message with the type inferred from the body.
    pub fn new_esm(
        message: impl Into<EsmMessage>,
        eps_bearer_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        let message = message.into();
        Self::Esm(
            EsmHeader::new(
                message.message_type(),
                eps_bearer_identity,
                procedure_transaction_identity,
            ),
            message,
        )
    }

    /// Build a security envelope from a caller-supplied MAC and body.
    /// Ciphered header types require already ciphered opaque body bytes;
    /// use `SecurityContext` with the `security` feature to compute them.
    pub fn protect(
        message: Message,
        security_header_type: SecurityHeaderType,
        message_authentication_code: u32,
        sequence_number: u8,
    ) -> Result<Self> {
        if !matches!(message, Self::Emm(..) | Self::Esm(..))
            || matches!(
                security_header_type,
                SecurityHeaderType::PlainNasMessageNotSecurityProtected
                    | SecurityHeaderType::SecurityHeaderForTheServiceRequestMessage
                    | SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
            )
        {
            return Err(Error::EncodingError("invalid EPS protected message".into()));
        }
        if matches!(
            security_header_type,
            SecurityHeaderType::IntegrityProtectedAndCiphered
                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
                | SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
        ) {
            return Err(Error::EncodingError(
                "use SecurityContext to cipher an EPS message".into(),
            ));
        }
        check_protected_inner(security_header_type, &message)?;
        Ok(Self::SecurityProtected(
            SecurityHeader {
                security_header_type,
                message_authentication_code,
                sequence_number,
            },
            Box::new(message),
        ))
    }
}

impl Message {
    /// Unknown and ignored IEs of the EMM or ESM message body, read through
    /// a security header: see [`EmmMessage::unknown_ies`]. SERVICE
    /// REQUEST, EMM TRANSPORT and an opaque payload have none.
    pub fn unknown_ies(&self) -> &UnknownIes {
        match self {
            Self::Emm(_, message) => message.unknown_ies(),
            Self::Esm(_, message) => message.unknown_ies(),
            Self::SecurityProtected(_, inner) => inner.unknown_ies(),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => {
                &crate::common::NO_UNKNOWN_IES
            }
        }
    }

    /// The message inside the security envelopes: the plain message of an
    /// integrity protected one, the ciphertext ([`Self::Opaque`]) of a
    /// ciphered one, and the message itself when it has no security header
    /// or a header of its own (SERVICE REQUEST, EMM TRANSPORT).
    ///
    /// ```
    /// use oxirush_nas::nas_eps::{EmmMessage, Message};
    ///
    /// // An ATTACH REJECT, cause #3, integrity protected
    /// let message = Message::decode(&[0x17, 1, 2, 3, 4, 5, 0x07, 0x44, 0x03]).unwrap();
    /// assert!(matches!(
    ///     message.innermost(),
    ///     Message::Emm(_, EmmMessage::AttachReject(_))
    /// ));
    /// ```
    pub fn innermost(&self) -> &Self {
        let mut message = self;
        while let Self::SecurityProtected(_, inner) = message {
            message = inner;
        }
        message
    }
}

impl Encode for Message {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::ENCODED);
        self.encode_into(&mut out)?;
        Ok(out)
    }

    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Emm(header, message) => {
                if header.message_type != message.message_type() {
                    return Err(Error::EncodingError(
                        "EPS EMM header/message type mismatch".into(),
                    ));
                }
                header.encode_into(buffer)?;
                message.encode_into(buffer)
            }
            Self::Esm(header, message) => {
                if header.message_type != message.message_type() {
                    return Err(Error::EncodingError(
                        "EPS ESM header/message type mismatch".into(),
                    ));
                }
                header.encode_into(buffer)?;
                message.encode_into(buffer)
            }
            Self::SecurityProtected(header, message) => {
                if header.security_header_type
                    == SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
                    || !matches!(
                        message.as_ref(),
                        Self::Emm(..) | Self::Esm(..) | Self::Opaque(..)
                    )
                {
                    return Err(Error::EncodingError(
                        "invalid EPS protected message body".into(),
                    ));
                }
                if matches!(
                    header.security_header_type,
                    SecurityHeaderType::IntegrityProtectedAndCiphered
                        | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
                        | SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
                ) && !matches!(message.as_ref(), Self::Opaque(_))
                {
                    return Err(Error::EncodingError(
                        "ciphered EPS security envelope requires opaque ciphertext".into(),
                    ));
                }
                if matches!(message.as_ref(), Self::Opaque(data) if data.is_empty()) {
                    return Err(Error::EncodingError("empty EPS security payload".into()));
                }
                header.encode_into(buffer)?;
                message.encode_into(buffer)
            }
            Self::ServiceRequest(message) => message.encode_into(buffer),
            Self::EmmTransport(message) => message.encode_into(buffer),
            Self::Opaque(data) => {
                buffer.put_slice(data);
                Ok(())
            }
        }
    }
}

impl Message {
    /// Decode a plain EMM or ESM message, as carried inside a security envelope.
    /// Nested envelopes and the special SERVICE REQUEST and EMM TRANSPORT
    /// headers are rejected before any recursion.
    fn decode_plain(buffer: &mut &[u8], faults: crate::common::Faults<'_, '_>) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(Error::MessageTooShort);
        }
        if buffer[0] & 0x0f == EPS_EMM_PROTOCOL_DISCRIMINATOR && buffer[0] >> 4 != 0 {
            return Err(Error::DecodingError(
                "plain EPS NAS message cannot carry a security header".into(),
            ));
        }
        Self::decode_keeping(buffer, faults)
    }
}

impl Decode for Message {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        Self::decode_keeping(buffer, &mut crate::common::Reading::strict())
    }

    fn decode_lenient_from(buffer: &mut &[u8], faults: &mut Vec<Error>) -> Result<Self> {
        Self::decode_keeping(
            buffer,
            &mut crate::common::Reading::keeping(faults, crate::common::DecodeOptions::STRICT),
        )
    }
}

impl Message {
    /// Decode a message with or without a security header, strictly or
    /// keeping the faults of its mandatory IEs.
    fn decode_keeping(buffer: &mut &[u8], faults: crate::common::Faults<'_, '_>) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(Error::MessageTooShort);
        }
        match buffer[0] & 0x0F {
            EPS_ESM_PROTOCOL_DISCRIMINATOR => {
                let header = EsmHeader::decode_from(buffer)?;
                if let EsmMessageType::Unknown(message_type) = header.message_type {
                    return Err(Error::UnknownSessionMessageType {
                        identity: header.eps_bearer_identity,
                        pti: header.procedure_transaction_identity,
                        message_type,
                    });
                }
                let message = EsmMessage::decode_keeping(header.message_type, buffer, faults)?;
                Ok(Self::Esm(header, message))
            }
            EPS_EMM_PROTOCOL_DISCRIMINATOR => {
                let sht = SecurityHeaderType::try_from(buffer[0] >> 4)?;
                match sht {
                    SecurityHeaderType::PlainNasMessageNotSecurityProtected => {
                        let header = EmmHeader::decode_from(buffer)?;
                        let message =
                            EmmMessage::decode_keeping(header.message_type, buffer, faults)?;
                        Ok(Self::Emm(header, message))
                    }
                    SecurityHeaderType::SecurityHeaderForTheServiceRequestMessage => {
                        Ok(Self::ServiceRequest(ServiceRequest::decode_from(buffer)?))
                    }
                    SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage => {
                        Ok(Self::EmmTransport(EmmTransport::decode_from(buffer)?))
                    }
                    _ => {
                        let header = SecurityHeader::decode_from(buffer)?;
                        let payload = if matches!(
                            sht,
                            SecurityHeaderType::IntegrityProtected
                                | SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
                        ) {
                            Box::new(Self::decode_plain(buffer, faults)?)
                        } else {
                            if !buffer.has_remaining() {
                                return Err(Error::MessageTooShort);
                            }
                            Box::new(Self::Opaque(buffer.split_to(buffer.remaining()).to_vec()))
                        };
                        Ok(Self::SecurityProtected(header, payload))
                    }
                }
            }
            _ => Err(Error::UnknownProtocolDiscriminator(buffer[0])),
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

impl Message {
    /// The message that `octets` are: one whole NAS message, as it is
    /// carried in the NAS-PDU IE of an S1AP message.
    ///
    /// The protocol discriminator in bits 4 to 1 of the first octet says
    /// what is decoded: an EMM message (7), with or without a security
    /// header, or an ESM message (2). Octets after the message are an error.
    /// A DETACH REQUEST, which has one message type for both directions, is
    /// read as the one that its octets fit: [`Self::decode_with`] reads it
    /// as the one of the direction of its options.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::*;
    ///
    /// // An ATTACH REQUEST with an IMSI, as the INITIAL UE MESSAGE of an eNB has it
    /// let octets = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
    /// let attach = Message::decode(&octets).unwrap();
    /// let Message::Emm(_, EmmMessage::AttachRequest(request)) = &attach else {
    ///     unreachable!()
    /// };
    /// assert_eq!(request.eps_mobile_identity.as_imsi().unwrap().to_string(), "208930000000001");
    ///
    /// // An ATTACH REJECT, cause #3, encodes to the octets it was read from
    /// let reject = Message::decode(&[0x07, 0x44, 0x03]).unwrap();
    /// assert_eq!(reject.encode().unwrap(), [0x07, 0x44, 0x03]);
    /// ```
    ///
    /// This is [`Decode::decode`], which needs no import here.
    pub fn decode(octets: &[u8]) -> Result<Self> {
        <Self as Decode>::decode(octets)
    }

    /// The message that `octets` are, read by `options`: as one sent in
    /// their direction, which tells the two DETACH REQUESTs apart, and with
    /// what a receiver takes beyond the rules of TS 24.301, as a known
    /// optional IE out of the order of its table, which §7.6.2 has a
    /// receiver ignore and other implementations take.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::{EmmMessage, Message};
    /// use oxirush_nas::{DecodeOptions, Direction};
    ///
    /// // ATTACH REQUEST whose last visited registered TAI comes after its
    /// // DRX parameter, which its table places after it
    /// let octets = hex::decode("07410108298039000000001002e0e000040201d0315c0a005202f8390001")
    ///     .unwrap();
    /// let tai = |message: &Message| match message {
    ///     Message::Emm(_, EmmMessage::AttachRequest(attach)) => {
    ///         attach.last_visited_registered_tai.clone()
    ///     }
    ///     _ => None,
    /// };
    /// assert!(tai(&Message::decode(&octets).unwrap()).is_none());
    /// let options = DecodeOptions::STRICT.with_out_of_sequence();
    /// let taken = Message::decode_with(&octets, options.with_direction(Direction::Uplink)).unwrap();
    /// assert!(tai(&taken).is_some());
    /// assert_eq!(taken.encode().unwrap(), octets);
    /// ```
    pub fn decode_with(octets: &[u8], options: crate::common::DecodeOptions) -> Result<Self> {
        Self::decode_by(octets, &mut crate::common::Reading::with(options))
    }

    /// The octets of the message, header first.
    ///
    /// This is [`Encode::encode`], which needs no import here.
    pub fn encode(&self) -> Result<Vec<u8>> {
        <Self as Encode>::encode(self)
    }

    /// What a message is first given to be encoded in: most signalling
    /// messages are shorter, and one that is longer takes more.
    pub(crate) const ENCODED: usize = 64;

    /// The message that TS 24.301 clause 7 has a receiver answer with, to
    /// `octets` that [`Self::decode`] refused with `error`. `direction` is
    /// that of `octets`: `Uplink` for what a network received, `Downlink`
    /// for what a UE received. The answer is plain, for the caller to
    /// protect, and `None` where the clause has the message ignored.
    ///
    /// | `error` | Answer |
    /// |---------|--------|
    /// | `MessageTooShort` | None: the message is ignored (§7.2) |
    /// | `UnknownMessageType`, `UnknownSessionMessageType` | EMM STATUS, or ESM STATUS with the identities of the message, with cause #97 "message type non-existent or not implemented" (§7.4) |
    /// | `InvalidMandatoryIe`, `UnknownIeCutShort` | Cause #96 "invalid mandatory information" (§7.5): EMM STATUS for an EMM message; for an ESM message the answer of §7.5.3 where it names one, and ESM STATUS otherwise |
    /// | `AuthenticMessageRefused` | That of the error inside, for the plain octets that it has, ciphered or not |
    /// | any other | None |
    ///
    /// §7.5.3 has a UE answer the three requests ACTIVATE DEFAULT EPS
    /// BEARER CONTEXT, ACTIVATE DEDICATED EPS BEARER CONTEXT and MODIFY EPS
    /// BEARER CONTEXT with their reject and a DEACTIVATE EPS BEARER CONTEXT
    /// REQUEST with its accept, and a network answer the four requests PDN
    /// CONNECTIVITY, PDN DISCONNECT, BEARER RESOURCE ALLOCATION and BEARER
    /// RESOURCE MODIFICATION with their reject.
    ///
    /// For a network the clause says "should" of a status message, lets it
    /// try to treat a message with a faulty mandatory IE instead
    /// ([`Self::decode_lenient`] reads one), and leaves to the
    /// implementation a state in which no message is foreseen: whether the
    /// answer is sent is the caller's decision.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::Message;
    /// use oxirush_nas::Direction;
    ///
    /// // PDN CONNECTIVITY REQUEST (PTI 1) that ends after its header
    /// let octets = [0x02, 0x01, 0xd0];
    /// let error = Message::decode(&octets).unwrap_err();
    /// let answer = Message::answer_to_refused(&octets, &error, Direction::Uplink).unwrap();
    /// // PDN CONNECTIVITY REJECT, cause #96
    /// assert_eq!(answer.encode().unwrap(), [0x02, 0x01, 0xd1, 0x60]);
    /// ```
    pub fn answer_to_refused(octets: &[u8], error: &Error, direction: Direction) -> Option<Self> {
        use crate::nas_eps::{EmmCauseValue, EsmCauseValue};
        // The plain message: the one that the refusal of an authentic
        // message has deciphered, or `octets`, under their security header
        // if they have one.
        let protected =
            |first: u8| first & 0x0f == EPS_EMM_PROTOCOL_DISCRIMINATOR && first >> 4 != 0;
        let (error, plain) = match error {
            Error::AuthenticMessageRefused { error, plain } => (error.as_ref(), &plain[..]),
            error => match octets {
                [first, ..] if protected(*first) => (error, octets.get(EPS_SECURITY_HEADER_LEN..)?),
                plain => (error, plain),
            },
        };
        let status = |cause| Self::new_emm(EmmStatus::new(EmmCause::from_cause(cause)));
        match (plain.first()? & 0x0f, error) {
            (EPS_EMM_PROTOCOL_DISCRIMINATOR, Error::UnknownMessageType(_)) => Some(status(
                EmmCauseValue::MessageTypeNonExistentOrNotImplemented,
            )),
            (_, Error::InvalidMandatoryIe { .. } | Error::UnknownIeCutShort { .. }) => {
                Self::invalid_mandatory(plain, direction)
            }
            (_, &Error::UnknownSessionMessageType { identity, pti, .. }) => {
                let cause = EsmCauseValue::MessageTypeNonExistentOrNotImplemented;
                let status = EsmStatus::new(EsmCause::from_cause(cause));
                Some(Self::new_esm(status, identity, pti))
            }
            _ => None,
        }
    }

    /// The message that TS 24.301 clause 7 has a receiver answer with, to
    /// `octets` that it read as `received`, whatever was wrong: for an
    /// error, the answer of [`Self::answer_to_refused`]; for a message that
    /// was read, cause #96 "invalid mandatory information" where it has an
    /// unknown IE that is encoded as "comprehension required" (§7.6.1,
    /// TS 24.007 §11.2.5), as for a faulty mandatory IE (§7.5). `None`
    /// where there is nothing to answer. `received` is what
    /// [`Self::decode`] returned, or a security context, with the message of
    /// its `Verified`.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::Message;
    /// use oxirush_nas::Direction;
    ///
    /// // ATTACH COMPLETE with an unknown IE 0x05, comprehension required,
    /// // after its ESM message container
    /// let octets = [0x07, 0x43, 0x00, 0x03, 0x52, 0x01, 0xc2, 0x05, 0x01, 0x00];
    /// let received = Message::decode(&octets);
    /// assert!(received.is_ok());
    /// let answer = Message::answer_to(&octets, &received, Direction::Uplink).unwrap();
    /// // EMM STATUS, cause #96
    /// assert_eq!(answer.encode().unwrap(), [0x07, 0x60, 0x60]);
    /// ```
    pub fn answer_to(octets: &[u8], received: &Result<Self>, direction: Direction) -> Option<Self> {
        let message = match received {
            Err(error) => return Self::answer_to_refused(octets, error, direction),
            Ok(message) => message,
        };
        let required = (message.unknown_ies().iter()).any(|ie| ie.is_comprehension_required());
        // The plain message, whose header the answer to an ESM message has
        let plain = match message {
            Self::SecurityProtected(_, inner) => inner.as_ref(),
            plain => plain,
        };
        match required {
            true => Self::invalid_mandatory(&plain.encode().ok()?, direction),
            false => None,
        }
    }

    /// The answer of cause #96 "invalid mandatory information" to the plain
    /// message `plain` (TS 24.301 §7.5): EMM STATUS for an EMM message, and
    /// for an ESM message the answer of §7.5.3 where it names one, ESM STATUS
    /// otherwise.
    fn invalid_mandatory(plain: &[u8], direction: Direction) -> Option<Self> {
        use crate::nas_eps::{EmmCauseValue, EsmCauseValue};
        use EsmMessageType as Type;
        let from_ue = direction == Direction::Uplink;
        match plain.first()? & 0x0f {
            EPS_EMM_PROTOCOL_DISCRIMINATOR => {
                let cause = EmmCause::from_cause(EmmCauseValue::InvalidMandatoryInformation);
                Some(Self::new_emm(EmmStatus::new(cause)))
            }
            EPS_ESM_PROTOCOL_DISCRIMINATOR => {
                let &[first, pti, kind, ..] = plain else {
                    return None;
                };
                let cause = EsmCause::from_cause(EsmCauseValue::InvalidMandatoryInformation);
                let answer: EsmMessage = match (from_ue, Type::from(kind)) {
                    (false, Type::ActivateDefaultEpsBearerContextRequest) => {
                        ActivateDefaultEpsBearerContextReject::new(cause).into()
                    }
                    (false, Type::ActivateDedicatedEpsBearerContextRequest) => {
                        ActivateDedicatedEpsBearerContextReject::new(cause).into()
                    }
                    (false, Type::ModifyEpsBearerContextRequest) => {
                        ModifyEpsBearerContextReject::new(cause).into()
                    }
                    (false, Type::DeactivateEpsBearerContextRequest) => {
                        DeactivateEpsBearerContextAccept::new().into()
                    }
                    (true, Type::PdnConnectivityRequest) => {
                        PdnConnectivityReject::new(cause).into()
                    }
                    (true, Type::PdnDisconnectRequest) => PdnDisconnectReject::new(cause).into(),
                    (true, Type::BearerResourceAllocationRequest) => {
                        BearerResourceAllocationReject::new(cause).into()
                    }
                    (true, Type::BearerResourceModificationRequest) => {
                        BearerResourceModificationReject::new(cause).into()
                    }
                    _ => EsmStatus::new(cause).into(),
                };
                Some(Self::new_esm(answer, first >> 4, pti))
            }
            _ => None,
        }
    }

    /// The message that `octets` are, as [`Self::decode`] reads it, with
    /// what `decode` refuses of a mandatory IE: an IE that has its octets
    /// and is shorter than its message has it, or is not one of its type.
    /// The IE is in the message as it came, and each refusal is in the
    /// list, the [`Error::InvalidMandatoryIe`] that `decode` returns
    /// for it. A list without an error is a message that `decode` reads.
    ///
    /// A receiver rejects such a message (TS 24.301 §7.5.1), and this is how
    /// it reads what it rejects: its type, the IEs that are sound and the
    /// octets of the one that is not, to log them and to choose its answer.
    /// Every other error is one of `decode`: a mandatory IE that is missing
    /// or cut short leaves no message to read.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::{EmmMessage, Message};
    /// use oxirush_nas::{IeFault, IeName, Error};
    ///
    /// // AUTHENTICATION RESPONSE whose parameter has three octets, where
    /// // Table 8.2.8.1 has four at least
    /// let octets = [0x07, 0x53, 0x03, 0xa1, 0xa2, 0xa3];
    /// let refusal = Error::InvalidMandatoryIe {
    ///     ie: IeName::of("authentication_response_parameter"),
    ///     fault: IeFault::TooShort,
    ///     reason: None,
    /// };
    /// assert_eq!(Message::decode(&octets), Err(refusal.clone()));
    ///
    /// let (message, faults) = Message::decode_lenient(&octets, oxirush_nas::DecodeOptions::STRICT).unwrap();
    /// assert_eq!(faults, [refusal]);
    /// let Message::Emm(_, EmmMessage::AuthenticationResponse(response)) = &message else {
    ///     panic!("another message")
    /// };
    /// assert_eq!(response.authentication_response_parameter.value, [0xa1, 0xa2, 0xa3]);
    /// ```
    pub fn decode_lenient(
        octets: &[u8],
        options: crate::common::DecodeOptions,
    ) -> Result<(Self, Vec<Error>)> {
        let mut faults = Vec::new();
        let message = Self::decode_by(
            octets,
            &mut crate::common::Reading::keeping(&mut faults, options),
        )?;
        Ok((message, faults))
    }

    /// The message that `octets` are, read by `reading`: as one of the
    /// direction of its options, or as the one that the octets fit.
    fn decode_by(mut octets: &[u8], reading: crate::common::Faults<'_, '_>) -> Result<Self> {
        if let Some(direction) = reading.options.direction {
            return Self::decode_directed(octets, direction, reading);
        }
        let message = Self::decode_keeping(&mut octets, reading)?;
        match octets.len() {
            0 => Ok(message),
            more => Err(crate::common::trailing(more)),
        }
    }

    /// A message of the direction `direction`, decoded strictly or keeping
    /// the faults of its mandatory IEs.
    fn decode_directed(
        data: &[u8],
        direction: Direction,
        faults: crate::common::Faults<'_, '_>,
    ) -> Result<Message> {
        if data.len() >= EPS_SECURITY_HEADER_LEN
            && data[0] & 0x0f == EPS_EMM_PROTOCOL_DISCRIMINATOR
            && matches!(data[0] >> 4, 1 | 3)
        {
            let mut buffer = data;
            let header = SecurityHeader::decode_from(&mut buffer)?;
            let payload = &data[EPS_SECURITY_HEADER_LEN..];
            if payload.first().is_some_and(|first| {
                first & 0x0f == EPS_EMM_PROTOCOL_DISCRIMINATOR && first >> 4 != 0
            }) {
                return Err(Error::DecodingError(
                    "plain EPS NAS message cannot carry a security header".into(),
                ));
            }
            let inner = Message::decode_directed(payload, direction, faults)?;
            return Ok(Message::SecurityProtected(header, Box::new(inner)));
        }
        if data.len() >= 2 && data[0] == EPS_EMM_PROTOCOL_DISCRIMINATOR && data[1] == 0x45 {
            let mut body = &data[2..];
            let message = match direction {
                Direction::Uplink => EmmMessage::DetachRequestUeOriginating(Box::new(
                    crate::common::decode_keeping(&mut body, faults)?,
                )),
                Direction::Downlink => EmmMessage::DetachRequestUeTerminated(Box::new(
                    crate::common::decode_keeping(&mut body, faults)?,
                )),
            };
            if body.has_remaining() {
                return Err(crate::common::trailing(body.len()));
            }
            Ok(Message::new_emm(message))
        } else {
            let mut octets = data;
            let message = Self::decode_keeping(&mut octets, faults)?;
            match octets.len() {
                0 => Ok(message),
                more => Err(crate::common::trailing(more)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{Error, IeFault, IeName, UnknownIe, Validate};
    use crate::nas_eps::PdnTypeValue;
    use oxirush_utils::identity::Algorithm;

    #[test]
    fn security_mode_complete_imeisv_reuses_mobile_identity_wire_type() {
        let identity = MobileIdentity::from_imeisv("4901542032375183").unwrap();
        let message = Message::new_emm(SecurityModeComplete::new().with_imeisv(identity));
        let wire = hex::decode("075e23094309512430325781f3").unwrap();
        assert_eq!(message.encode().unwrap(), wire);
        assert_eq!(Message::decode(&wire).unwrap().encode().unwrap(), wire);
        assert!(message.validate().is_empty());
        let wrong_type = SecurityModeComplete::new().with_imeisv(MobileIdentity::new(vec![0; 9]));
        assert!(
            wrong_type
                .validate()
                .iter()
                .any(|error| error.field == "imeisv")
        );
    }

    #[test]
    fn guti_and_tmsi_fields_reuse_identity_wire_types() {
        let guti = EpsMobileIdentity::new(hex::decode("f602f839123456789abcde").unwrap());
        let command = Message::new_emm(GutiReallocationCommand::new(guti));
        let wire = hex::decode("07500bf602f839123456789abcde").unwrap();
        assert_eq!(command.encode().unwrap(), wire);
        assert_eq!(Message::decode(&wire).unwrap().encode().unwrap(), wire);

        let request = ExtendedServiceRequest::new(
            ServiceType::new(1),
            KeySetIdentifier::new(0),
            MobileIdentity::from_tmsi(0x1234_5678),
        );
        assert!(
            !request
                .validate()
                .iter()
                .any(|error| error.field == "m_tmsi")
        );
        let invalid = ExtendedServiceRequest::new(
            ServiceType::new(1),
            KeySetIdentifier::new(0),
            MobileIdentity::new(vec![0; 5]),
        );
        assert!(
            invalid
                .validate()
                .iter()
                .any(|error| error.field == "m_tmsi")
        );

        let invalid_guti = AttachRequest::new(
            EpsAttachType::new(1),
            KeySetIdentifier::new(7),
            EpsMobileIdentity::from_imsi("1234567").unwrap(),
            UeNetworkCapability::new(vec![0xe0, 0xe0]),
            EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x31]),
        )
        .with_additional_guti(EpsMobileIdentity::new(vec![0; 11]));
        assert!(
            invalid_guti
                .validate()
                .iter()
                .any(|error| error.field == "additional_guti")
        );
    }

    // Embedded NAS-PDU values from two SCTP/S1AP-carried attach attempts.
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

    fn protected_inner(packet: u8) -> (SecurityHeader, Message) {
        let Message::SecurityProtected(header, inner) =
            Message::decode(&capture_bytes(packet)).unwrap()
        else {
            panic!("packet {packet} has no security envelope");
        };
        let message = Message::SecurityProtected(header.clone(), inner)
            .decode_null_ciphered_payload()
            .unwrap();
        (header, message)
    }

    #[test]
    fn capture_attach_attempts_decode_with_typed_contents() {
        use crate::nas_eps::AttachType;
        use SecurityHeaderType::*;
        // Frames 33-40 and 83-90: two attach attempts. Each ends after the
        // ESM INFORMATION RESPONSE with an SCTP SHUTDOWN from the MME (frames
        // 42 and 92); no NAS or S1AP message gives a cause.
        for (attach, ue_sn, pti) in [(33, 3, 0x43), (83, 2, 0x44)] {
            let (header, message) = protected_inner(attach);
            assert_eq!(
                (header.security_header_type, header.sequence_number),
                (IntegrityProtected, ue_sn)
            );
            let Message::Emm(_, EmmMessage::AttachRequest(request)) = message else {
                panic!("frame {attach} is not an ATTACH REQUEST");
            };
            assert_eq!(request.eps_attach_type.attach_type(), AttachType::EpsAttach);
            assert!(request.eps_mobile_identity.as_imsi().is_some());
            let capability = &request.ue_network_capability;
            assert!(
                (0..=2).all(|algo| capability.supports_eea(algo) && capability.supports_eia(algo))
            );
            let Message::Esm(esm, EsmMessage::PdnConnectivityRequest(pdn)) = request
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
            let Message::Emm(_, EmmMessage::AuthenticationRequest(challenge)) =
                Message::decode(&capture_bytes(attach + 1)).unwrap()
            else {
                panic!("frame {} is not an AUTHENTICATION REQUEST", attach + 1);
            };
            assert!(challenge.authentication_parameter_autn.amf_separation_bit() == Some(true));
            let (header, response) = protected_inner(attach + 3);
            assert_eq!(header.sequence_number, ue_sn + 1);
            assert!(matches!(
                response,
                Message::Emm(_, EmmMessage::AuthenticationResponse(ref r))
                    if r.authentication_response_parameter.res().len() == 8
            ));

            // SECURITY MODE COMMAND selects EEA0 with EIA2 and requests the IMEISV.
            let (header, command) = protected_inner(attach + 4);
            assert_eq!(
                (header.security_header_type, header.sequence_number),
                (IntegrityProtectedWithNewEpsSecurityContext, 0)
            );
            let Message::Emm(_, EmmMessage::SecurityModeCommand(command)) = command else {
                panic!("frame {} is not a SECURITY MODE COMMAND", attach + 4);
            };
            let algorithms = &command.selected_nas_security_algorithms;
            assert_eq!(algorithms.ciphering(), Ok(Algorithm::Null));
            assert_eq!(algorithms.integrity(), Ok(Algorithm::Aes));
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
                (IntegrityProtectedAndCipheredWithNewEpsSecurityContext, 0)
            );
            let Message::Emm(_, EmmMessage::SecurityModeComplete(complete)) = complete else {
                panic!("frame {} is not a SECURITY MODE COMPLETE", attach + 5);
            };
            assert_eq!(
                complete
                    .imeisv
                    .unwrap()
                    .as_imeisv()
                    .map(|imeisv| imeisv.as_str().len()),
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
                Message::Esm(ref h, EsmMessage::EsmInformationRequest(_))
                    if h.procedure_transaction_identity == pti
            ));
            let (header, response) = protected_inner(attach + 7);
            assert_eq!(header.sequence_number, 1);
            let Message::Esm(h, EsmMessage::EsmInformationResponse(response)) = response else {
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
    fn received_apn_labels_need_only_their_framing() {
        // TS 24.301 §9.9.4.1: the APN is labels coded as in TS 23.003 §9.1.
        // Its character rules bind a sender; a receiver takes the labels as
        // framed, so a mandatory APN such as "my_apn" does not fail the
        // ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST.
        let wire = [
            0x52, 0x01, 0xc1, 0x01, 0x09, 0x07, 0x06, b'm', b'y', b'_', b'a', b'p', b'n', 0x05,
            0x01, 0x0a, 0x2d, 0x00, 0x02,
        ];
        let message = Message::decode(&wire).unwrap();
        let Message::Esm(_, EsmMessage::ActivateDefaultEpsBearerContextRequest(request)) = &message
        else {
            panic!("expected ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST");
        };
        assert_eq!(
            request.access_point_name.labels(),
            Some(vec![&b"my_apn"[..]])
        );
        assert_eq!(request.access_point_name.as_string(), None);
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "access_point_name")
        );
        assert_eq!(message.encode().unwrap(), wire);

        // A label that overruns the value is still a syntax error.
        let mut overrun = wire;
        overrun[6] = 0x07;
        assert!(matches!(
            Message::decode(&overrun),
            Err(Error::InvalidMandatoryIe {
                ie,
                fault: IeFault::Syntax,
                reason: None,
            }) if ie == IeName::of("access_point_name")
        ));
    }

    #[test]
    fn capture_nas_pdus_round_trip_byte_for_byte() {
        for &(packet, _) in &CAPTURE_NAS {
            let wire = capture_bytes(packet);
            let decoded = Message::decode(&wire).unwrap();
            assert_eq!(decoded.encode().unwrap(), wire, "packet {packet}");
            assert!(decoded.validate().is_empty(), "packet {packet}");
        }
    }

    #[test]
    fn malformed_nested_plmn_list_and_spare_qci_are_reported() {
        for wire in [
            &[0x07, 0x49, 0x01, 0x25, 0x02, 0x02, 0xf8][..],
            &[0x07, 0x49, 0x01, 0x25, 0x03, 0xff, 0xff, 0xff][..],
        ] {
            let message = Message::decode(wire).unwrap();
            assert!(
                message.validate().iter().any(|error| {
                    error.field == "list_of_plmns_to_be_used_in_disaster_condition"
                })
            );
            assert_eq!(message.encode().unwrap(), wire);
        }
        let wire = [0x52, 0x01, 0xc5, 0x05, 0x01, 0x0b, 0x01, 0x00];
        let message = Message::decode(&wire).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "eps_qos")
        );
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn bearer_resource_allocation_accepts_ignore_traffic_flow_aggregate() {
        // TS 24.008 §10.5.6.12 requires E=0 and filter count=0 for Ignore.
        let wire = [0x02, 0x01, 0xd4, 0x05, 0x01, 0x00, 0x01, 0x09];
        let message = Message::decode(&wire).unwrap();
        let Message::Esm(_, EsmMessage::BearerResourceAllocationRequest(request)) = &message else {
            panic!("wrong EPS message type");
        };
        assert_eq!(
            request.traffic_flow_aggregate.tft().unwrap().operation,
            crate::nas_eps::TftOperation::Ignore
        );
        assert!(message.validate().is_empty());
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn malformed_nbifom_parameter_unit_is_reported() {
        let wire = [0x52, 0x01, 0xc6, 0x33, 0x01, 0x01];
        let message = Message::decode(&wire).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "nbifom_container")
        );
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn classmark_two_spare_bit_is_reported() {
        let mut request = AttachRequest::new(
            EpsAttachType::new(1),
            KeySetIdentifier::new(0),
            EpsMobileIdentity::new(vec![0xf4, 0, 0, 0, 1]),
            UeNetworkCapability::new(vec![0, 0]),
            EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        );
        request.mobile_station_classmark_2 = Some(MobileStationClassmark2::new(vec![0x80, 0, 0]));
        assert!(
            request
                .validate()
                .iter()
                .any(|error| error.field == "mobile_station_classmark_2")
        );
    }

    #[test]
    fn transmitted_imei_requires_zero_spare_digit() {
        let conforming =
            IdentityResponse::new(MobileIdentity::from_imei_tac_snr("49015420323751").unwrap());
        assert!(conforming.validate().is_empty());
        let interoperable =
            IdentityResponse::new(MobileIdentity::from_imei("490154203237518").unwrap());
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
                        Message::decode(&wire).is_ok(),
                        [Direction::Uplink, Direction::Downlink]
                            .into_iter()
                            .map(|direction| {
                                Message::decode_with(
                                    &wire,
                                    crate::DecodeOptions::STRICT.with_direction(direction),
                                )
                                .is_ok()
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
            assert!(Message::decode(&wire).is_err(), "{wire:02x?}");
        }
    }

    #[test]
    fn truncated_and_bit_flipped_capture_pdus_never_panic() {
        // Every accepted mutation must also format, validate, and re-encode to
        // a canonical form that decodes to the same structure.
        fn check(wire: &[u8]) {
            let Ok(message) = Message::decode(wire) else {
                return;
            };
            let _ = message.to_string();
            let _ = message.validate();
            if let Ok(inner) = message.decode_null_ciphered_payload() {
                let _ = inner.to_string();
                let _ = inner.validate();
            }
            let bytes = message.encode().expect("decodable PDU re-encodes");
            let again = Message::decode(&bytes).expect("canonical PDU decodes");
            assert_eq!(again, message, "structural round trip of {wire:02x?}");
            assert_eq!(again.encode().unwrap(), bytes);
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
                Message::decode(&wire).unwrap(),
                Message::SecurityProtected(_, inner)
                    if matches!(*inner, Message::Opaque(_))
            ));
            let inner = Message::decode(&wire[EPS_SECURITY_HEADER_LEN..]).unwrap();
            assert_eq!(
                inner.encode().unwrap(),
                &wire[EPS_SECURITY_HEADER_LEN..],
                "packet {packet} inner NAS"
            );
        }

        for (packet, pti) in [(33, 0x43), (83, 0x44)] {
            let wire = capture_bytes(packet);
            let Message::SecurityProtected(_, inner) = Message::decode(&wire).unwrap() else {
                panic!("packet {packet} is not protected");
            };
            let Message::Emm(_, EmmMessage::AttachRequest(request)) = *inner else {
                panic!("packet {packet} is not an ATTACH REQUEST");
            };
            let esm = request
                .esm_message_container
                .decode_as_esm_message()
                .unwrap();
            assert_eq!(
                EsmMessageContainer::from_esm_message(&esm).unwrap().value,
                request.esm_message_container.value
            );
            assert!(matches!(
                esm,
                Message::Esm(
                    EsmHeader {
                        procedure_transaction_identity,
                        ..
                    },
                    EsmMessage::PdnConnectivityRequest(_)
                ) if procedure_transaction_identity == pti
            ));
        }
    }

    #[test]
    fn reserved_service_request_header_is_reported_and_relayed() {
        // Table 9.3.1: SHT 1101-1111 is read as 1100. The received octets
        // re-encode unchanged, and validate() reports the sender rule.
        let wire = [0xd7, 0x12, 0x34, 0x56];
        let message = Message::decode(&wire).unwrap();
        assert!(matches!(message, Message::ServiceRequest(_)));
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "security_header_type")
        );
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn security_mode_command_under_another_header_type_is_reported() {
        // §5.4.3.2 is a sender rule, so the message decodes
        // and validate() reports the pairing.
        let wire = [
            0x17, 0, 0, 0, 0, 0, 0x07, 0x5d, 0x11, 0x01, 0x02, 0xe0, 0xe0,
        ];
        let message = Message::decode(&wire).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "security_header_type")
        );
        assert_eq!(message.encode().unwrap(), wire);
        let Message::SecurityProtected(_, inner) = message else {
            panic!("security envelope expected");
        };
        assert!(Message::protect(*inner, SecurityHeaderType::IntegrityProtected, 0, 0).is_err());
    }

    #[test]
    fn repeated_and_out_of_sequence_ies_are_reported() {
        use crate::common::Severity;
        // §9.1 allows one occurrence; §7.6.3 keeps the first.
        let repeated = Message::decode(&pdu("0744 03 5F0121 5F0122")).unwrap();
        assert_eq!(findings_of(&repeated), [("unknown_ies", Severity::Error)]);
        // 1C follows 5F in Table 8.2.3.1. The IE is kept
        // as raw evidence, ignored by receiver semantics (§7.6.2), and
        // re-encoded where it was.
        let wire = pdu("0744 16 1C0121 5F0121");
        let out_of_sequence = Message::decode(&wire).unwrap();
        assert_eq!(
            findings_of(&out_of_sequence),
            [("unknown_ies", Severity::Error)]
        );
        assert_eq!(out_of_sequence.encode().unwrap(), wire);
        let Message::Emm(_, EmmMessage::AttachReject(reject)) = out_of_sequence else {
            panic!("ATTACH REJECT expected");
        };
        assert!(reject.lower_bound_timer_value.is_some());
        assert!(reject.t3346_value.is_none());
        let in_order = Message::decode(&pdu("0744 16 5F0121 1C0121")).unwrap();
        assert!(in_order.validate().is_empty());

        // A syntactically incorrect first occurrence still wins. The later
        // valid-looking repetition is ignored, so receiver semantics remain
        // absent while both occurrences are retained for relay.
        let wire = pdu("0744 03 5F00 5F0121");
        let malformed_first = Message::decode(&wire).unwrap();
        let Message::Emm(_, EmmMessage::AttachReject(reject)) = &malformed_first else {
            panic!("ATTACH REJECT expected");
        };
        assert!(reject.t3346_value.is_none());
        assert_eq!(reject.unknown_ies.len(), 2);
        assert_eq!(malformed_first.encode().unwrap(), wire);
    }

    #[test]
    fn truncated_known_optional_ie_is_absent_but_preserved() {
        // T3402 declares two value octets but only one remains. §7.7.1
        // treats it as absent; the raw occurrence remains available for
        // diagnostics and lossless relay.
        let wire = pdu("0744 02 160221");
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
        let Message::Emm(_, EmmMessage::AttachReject(reject)) = message else {
            panic!("ATTACH REJECT expected");
        };
        assert!(reject.t3402_value.is_none());
        assert_eq!(reject.unknown_ies.len(), 1);
    }

    #[test]
    fn mandatory_receiver_syntax_rejects_short_values() {
        fn encoded(message: Message) -> Vec<u8> {
            message.encode().unwrap()
        }

        let authentication_request = Message::new_emm(AuthenticationRequest::new(
            KeySetIdentifier::new(0),
            AuthenticationParameterRand::new(vec![0; 16]),
            AuthenticationParameterAutn::new(vec![0; 15]),
        ));
        assert_eq!(
            Message::decode(&encoded(authentication_request)),
            Err(Error::InvalidMandatoryIe {
                ie: IeName::of("authentication_parameter_autn"),
                fault: IeFault::TooShort,
                reason: None,
            })
        );

        let authentication_response = Message::new_emm(AuthenticationResponse::new(
            AuthenticationResponseParameter::new(vec![0; 3]),
        ));
        assert_eq!(
            Message::decode(&encoded(authentication_response)),
            Err(Error::InvalidMandatoryIe {
                ie: IeName::of("authentication_response_parameter"),
                fault: IeFault::TooShort,
                reason: None,
            })
        );

        let attach_complete =
            Message::new_emm(AttachComplete::new(EsmMessageContainer::new(vec![0; 2])));
        assert_eq!(
            Message::decode(&encoded(attach_complete)),
            Err(Error::InvalidMandatoryIe {
                ie: IeName::of("esm_message_container"),
                fault: IeFault::TooShort,
                reason: None,
            })
        );

        let downlink_transport =
            Message::new_emm(DownlinkNasTransport::new(MessageContainer::new(vec![0])));
        assert_eq!(
            Message::decode(&encoded(downlink_transport)),
            Err(Error::InvalidMandatoryIe {
                ie: IeName::of("nas_message_container"),
                fault: IeFault::TooShort,
                reason: None,
            })
        );

        for (traffic_flow, qos, field) in [
            (vec![], vec![0], "traffic_flow_aggregate"),
            (vec![0], vec![], "required_traffic_flow_qos"),
        ] {
            let request = Message::new_esm(
                BearerResourceAllocationRequest::new(
                    LinkedEpsBearerIdentity::new(0),
                    TrafficFlowAggregateDescription::new(traffic_flow),
                    EpsQualityOfService::new(qos),
                ),
                0,
                1,
            );
            assert_eq!(
                Message::decode(&encoded(request)),
                Err(Error::InvalidMandatoryIe {
                    ie: IeName::of(field),
                    fault: IeFault::TooShort,
                    reason: None,
                })
            );
        }
    }

    #[test]
    fn mobile_identity_receiver_ignores_excess_value_octets() {
        let imsi = "208930000000001";
        let mut mobile_value = MobileIdentity::from_imsi(imsi).unwrap().value;
        mobile_value.extend_from_slice(&[0xaa, 0xbb]);
        let mobile = MobileIdentity::new(mobile_value);
        assert_eq!(
            mobile
                .as_imsi()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some(imsi)
        );
        assert!(!mobile.is_well_formed());

        let mut eps_value = EpsMobileIdentity::from_imsi(imsi).unwrap().value;
        eps_value.extend_from_slice(&[0xaa, 0xbb]);
        let eps_identity = EpsMobileIdentity::new(eps_value);
        assert_eq!(
            eps_identity
                .as_imsi()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some(imsi)
        );
        assert!(!eps_identity.is_well_formed());

        let attach = Message::new_emm(AttachRequest::new(
            EpsAttachType::new(1),
            KeySetIdentifier::new(0),
            eps_identity,
            UeNetworkCapability::new(vec![0, 0]),
            EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        ));
        let wire = attach.encode().unwrap();
        let decoded = Message::decode(&wire).unwrap();
        assert!(
            decoded
                .validate()
                .iter()
                .any(|finding| finding.field == "eps_mobile_identity")
        );
    }

    fn findings_of(message: &Message) -> Vec<(&'static str, crate::common::Severity)> {
        message
            .validate()
            .into_iter()
            .map(|finding| (finding.field, finding.severity))
            .collect()
    }

    #[test]
    fn null_ciphered_payload_defers_header_pairing_to_validation() {
        // §4.4.5 sends ATTACH REQUEST unciphered, and
        // SHT 4 carries only SECURITY MODE COMPLETE (Table 9.3.1 NOTE 2).
        let attach = &capture_bytes(33)[EPS_SECURITY_HEADER_LEN..];
        for sht in [0x27, 0x47] {
            let mut wire = vec![sht, 0, 0, 0, 0, 0];
            wire.extend_from_slice(attach);
            let message = Message::decode(&wire).unwrap();
            let decoded = message.decode_null_ciphered_payload().unwrap();
            let Message::SecurityProtected(header, _) = &message else {
                unreachable!()
            };
            let decoded_envelope = Message::SecurityProtected(header.clone(), Box::new(decoded));
            assert!(
                decoded_envelope
                    .validate()
                    .iter()
                    .any(|finding| finding.field == "security_header_type")
            );
        }
        // The capture's SHT 4 and SHT 2 payloads still decode.
        for packet in [38, 39, 40] {
            let message = Message::decode(&capture_bytes(packet)).unwrap();
            assert!(message.decode_null_ciphered_payload().is_ok());
        }
    }

    #[test]
    fn attach_complete_esm_container_is_only_checked_as_a_warning() {
        // §7.5.2: no diagnosis beyond presence and length at the EMM level.
        let wire = [0x07, 0x43, 0x00, 0x03, 0xff, 0xff, 0xff];
        let message = Message::decode(&wire).unwrap();
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
        let message = Message::decode(&wire).unwrap();
        let Message::Esm(_, EsmMessage::PdnConnectivityRequest(request)) = &message else {
            panic!("expected PDN CONNECTIVITY REQUEST");
        };
        assert_eq!(request.pdn_type.pdn_type(), Some(PdnTypeValue::Ipv6));
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
        let attach = Message::decode(&attach_wire).unwrap();
        assert!(
            attach
                .validate()
                .iter()
                .any(|error| error.field == "eps_attach_type")
        );

        let update = TrackingAreaUpdateRequest::new(
            EpsUpdateType::new(4),
            KeySetIdentifier::new(0),
            EpsMobileIdentity::new(vec![0; 11]),
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
        // A receiver keeps the framed labels; the typed name and the sender
        // checks apply the TS 23.003 character rules.
        let wire = [0x02, 0x01, 0xd0, 0x11, 0x28, 0x04, 0x03, b'a', b'_', b'b'];
        let message = Message::decode(&wire).unwrap();
        let Message::Esm(_, EsmMessage::PdnConnectivityRequest(request)) = &message else {
            panic!("expected PDN CONNECTIVITY REQUEST");
        };
        let apn = request.access_point_name.as_ref().expect("framed APN kept");
        assert_eq!(apn.labels(), Some(vec![&b"a_b"[..]]));
        assert_eq!(apn.as_string(), None);
        assert!(request.unknown_ies.is_empty());
        assert_eq!(message.encode().unwrap(), wire);
        assert!(AccessPointName::from_string("a_b").is_err());
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
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
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
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
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
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
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
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
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
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "replayed_ue_security_capabilities")
        );
    }

    #[test]
    fn optional_esm_container_is_checked_for_a_complete_esm_pdu() {
        let mut request = ControlPlaneServiceRequest::new(
            ControlPlaneServiceType::new(0),
            KeySetIdentifier::new(0),
        );
        request.esm_message_container = Some(EsmMessageContainer::new(vec![0xff; 3]));
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
            let message = Message::decode(&wire).unwrap();
            assert_eq!(message.encode().unwrap(), wire);
            assert!(
                message.validate().iter().any(|error| error.field == field),
                "{field}"
            );
        }
    }

    #[test]
    fn attach_request_uses_packed_fields_and_optional_ie_formats() {
        let message = AttachRequest::new(
            EpsAttachType::new(1),
            KeySetIdentifier::new(7),
            EpsMobileIdentity::from_imsi("1234567").unwrap(),
            UeNetworkCapability::new(vec![0xE0, 0xE0]),
            EsmMessageContainer::new(vec![0x02, 0x01, 0xD0, 0x31]),
        )
        .with_tmsi_status(TmsiStatus::new(1))
        .with_drx_parameter(DrxParameter::new(vec![0x40, 0x60]));
        let pdu = Message::new_emm(message);
        let expected = [
            0x07, 0x41, 0x71, 0x04, 0x19, 0x32, 0x54, 0x76, 0x02, 0xE0, 0xE0, 0x00, 0x04, 0x02,
            0x01, 0xD0, 0x31, 0x5C, 0x40, 0x60, 0x91,
        ];
        // Optional IEs follow chapter 8 table order, not builder call order.
        assert_eq!(pdu.encode().unwrap(), expected);
        assert!(pdu.validate().is_empty());
        assert_eq!(
            Message::decode(&expected).unwrap().encode().unwrap(),
            expected
        );
    }

    #[test]
    fn pdn_connectivity_request_uses_esm_header_and_tlve() {
        let message = PdnConnectivityRequest::new(RequestType::new(1), PdnType::new(3))
            .with_access_point_name(AccessPointName::new(vec![3, b'i', b'm', b's']))
            .with_extended_protocol_configuration_options(
                ExtendedProtocolConfigurationOptions::new(vec![0x80, 0x00]),
            );
        let pdu = Message::new_esm(message, 0, 1);
        let expected = [
            0x02, 0x01, 0xD0, 0x31, 0x28, 0x04, 3, b'i', b'm', b's', 0x7B, 0x00, 0x02, 0x80, 0x00,
        ];
        assert_eq!(pdu.encode().unwrap(), expected);
        assert_eq!(
            Message::decode(&expected).unwrap().encode().unwrap(),
            expected
        );
    }

    #[test]
    fn eps_special_headers_round_trip() {
        let service = [0xC7, 0x12, 0xAB, 0xCD];
        assert_eq!(
            Message::decode(&service).unwrap().encode().unwrap(),
            service
        );

        let transport = [0xB7, 1, 2, 3, 4, 5, 0x79, 0xAA, 0xBB];
        assert_eq!(
            Message::decode(&transport).unwrap().encode().unwrap(),
            transport
        );

        let protected = [0x27, 1, 2, 3, 4, 5, 0xAA, 0xBB];
        assert_eq!(
            Message::decode(&protected).unwrap().encode().unwrap(),
            protected
        );
        assert!(is_security_protected(&protected));

        let integrity_only = [0x17, 1, 2, 3, 4, 5, 0x07, 0x60, 0x02];
        assert_eq!(
            Message::decode(&integrity_only).unwrap().encode().unwrap(),
            integrity_only
        );
    }

    #[test]
    fn detach_request_forms_dispatch_by_mobile_identity_length() {
        let from_ue = Message::new_emm(DetachRequestUeOriginating::new(
            DetachType::new(1),
            KeySetIdentifier::new(1),
            EpsMobileIdentity::from_imsi("001010123456789").unwrap(),
        ))
        .encode()
        .unwrap();
        let to_ue = [0x07, 0x45, 0x01, 0x53, 0x02];
        assert!(matches!(
            Message::decode(&from_ue).unwrap(),
            Message::Emm(_, EmmMessage::DetachRequestUeOriginating(_))
        ));
        assert!(matches!(
            Message::decode(&to_ue).unwrap(),
            Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_))
        ));
    }

    fn pdu(text: &str) -> Vec<u8> {
        hex::decode(text.replace(' ', "")).unwrap()
    }

    fn findings(bytes: &[u8]) -> Vec<(&'static str, crate::common::Severity)> {
        Message::decode(bytes)
            .unwrap()
            .validate()
            .into_iter()
            .map(|finding| (finding.field, finding.severity))
            .collect()
    }

    #[test]
    fn chapter_seven_receiver_cases() {
        use crate::common::Severity::{Error, Warning};
        // An envelope without a message is too short
        // (§7.2) on both decoders.
        let empty = [0x17, 0, 0, 0, 0, 0];
        assert_eq!(Message::decode(&empty), Err(crate::Error::MessageTooShort));
        assert_eq!(
            Message::decode_with(
                &empty,
                crate::DecodeOptions::STRICT.with_direction(Direction::Uplink)
            ),
            Err(crate::Error::MessageTooShort)
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
            let message = Message::decode(&bytes).unwrap();
            assert_eq!(message.encode().unwrap(), bytes, "{text}");
            assert!(message.validate().is_empty(), "{text}");
        }
        // T3: an unknown non-comprehension-required IE that overruns the PDU
        // is ignored and consumes the unknowable remainder (§7.6.1).
        for text in ["07 60 03 49 05 80", "07 60 03 78 00"] {
            let bytes = pdu(text);
            let message = Message::decode(&bytes).unwrap();
            assert_eq!(message.encode().unwrap(), bytes, "{text}");
        }
        // A known syntactically incorrect optional IE is treated as absent
        // (§7.7.1), while its bytes remain available for lossless relay.
        for text in ["07 61 47 01 02", "07 61 45 01 80 45 05 80"] {
            let bytes = pdu(text);
            let message = Message::decode(&bytes).unwrap();
            assert_eq!(message.encode().unwrap(), bytes, "{text}");
        }
        let bytes = pdu("07 4F 57 00");
        let message = Message::decode(&bytes).unwrap();
        assert_eq!(message.encode().unwrap(), bytes);
        let Message::Emm(_, EmmMessage::ServiceAccept(accept)) = message else {
            panic!("SERVICE ACCEPT expected");
        };
        assert!(accept.eps_bearer_context_status.is_none());
        assert_eq!(accept.unknown_ies.len(), 1);
        let order: Vec<_> = accept.optional_ie_order.iter().collect();
        assert_eq!(
            order,
            [crate::common::Placed::Ignored(
                crate::common::IgnoredIeReason::Malformed
            )]
        );
        // T4: a truncated mandatory IE names the field (§7.5.1).
        assert_eq!(
            Message::decode(&pdu("07 56 08 09")).unwrap_err(),
            crate::Error::InvalidMandatoryIe {
                ie: IeName::of("mobile_identity"),
                fault: IeFault::Truncated,
                reason: None,
            }
        );
        assert_eq!(
            Message::decode(&pdu("07 43 00 05 52 01")).unwrap_err(),
            crate::Error::InvalidMandatoryIe {
                ie: IeName::of("esm_message_container"),
                fault: IeFault::Truncated,
                reason: None,
            }
        );
        // T5, T6: longer and empty optional TLVs decode.
        assert!(Message::decode(&pdu("07 44 02 5F 02 21 00")).is_ok());
        assert!(Message::decode(&pdu("07 49 00 4A 00")).is_ok());
        // T7, T8: a repetition is skipped whatever its content (§7.6.3).
        for text in [
            "07 44 02 16 01 21 16 02 21 22",
            "02 01 D0 11 7B 00 01 80 7B 00 01 80",
        ] {
            let bytes = pdu(text);
            let message = Message::decode(&bytes).unwrap();
            assert_eq!(message.encode().unwrap(), bytes, "{text}");
        }
        // T9: a non-comprehension-required out-of-sequence IE is ignored
        // for receiver semantics (§7.6.2) and retained as raw evidence.
        let Message::Emm(_, EmmMessage::EmmInformation(information)) =
            Message::decode(&pdu("07 61 49 01 00 43 01 80")).unwrap()
        else {
            panic!("EMM INFORMATION expected");
        };
        assert!(information.network_daylight_saving_time.is_some());
        assert!(information.full_name_for_network.is_none());
        assert_eq!(information.unknown_ies.len(), 1);
        // T10, T12, T13, T14, T15: header errors keep what STATUS needs.
        assert_eq!(
            Message::decode(&pdu("67 00 00 00 00 00 07 60 03")).unwrap_err(),
            crate::Error::ReservedSecurityHeaderType(6)
        );
        assert!(Message::decode(&pdu("17 00 00 00 00 00 C7 12 AB CD")).is_err());
        assert_eq!(
            Message::decode(&pdu("07 40")).unwrap_err(),
            crate::Error::UnknownMessageType(0x40)
        );
        assert_eq!(
            Message::decode(&pdu("52 01 FF")).unwrap_err(),
            crate::Error::UnknownSessionMessageType {
                identity: 5,
                pti: 1,
                message_type: 0xff
            }
        );
        assert_eq!(
            Message::decode(&pdu("02 01 41")).unwrap_err(),
            crate::Error::UnknownSessionMessageType {
                identity: 0,
                pti: 1,
                message_type: 0x41
            }
        );
        for text in ["07", "52 01", "C7 12 AB", "17 00 00 00 00"] {
            assert_eq!(
                Message::decode(&pdu(text)).unwrap_err(),
                crate::Error::MessageTooShort,
                "{text}"
            );
        }
        assert_eq!(
            Message::decode(&pdu("15 41")).unwrap_err(),
            crate::Error::UnknownProtocolDiscriminator(0x15)
        );
        // T17: spare bits are ignored by the receiver (TS 24.007 §11.1.4)
        // and retained for relay; sender validation still reports them.
        let spare = Message::decode(&pdu("07 55 F1")).unwrap();
        assert_eq!(spare.encode().unwrap(), pdu("07 55 F1"));
        assert!(
            spare
                .validate()
                .iter()
                .any(|finding| finding.field == "identity_type")
        );
        // T18 (F-12): a one-octet EMM TRANSPORT container is too short.
        assert!(findings(&pdu("B7 01 02 03 04 05 79")).contains(&("protected_payload", Error)));
        // T19 (F-10): an IE set after decoding goes to its table position.
        let mut message = Message::decode(&pdu("07 61 49 01 00")).unwrap();
        let Message::Emm(_, EmmMessage::EmmInformation(information)) = &mut message else {
            panic!("EMM INFORMATION expected");
        };
        information.set_full_name_for_network(NetworkName::new(vec![0x80]));
        assert_eq!(message.encode().unwrap(), pdu("07 61 43 01 80 49 01 00"));
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
        // "re-attach required" with a 27-octet forbidden
        // TAI list (IEI 1D) and a disaster return wait range (IEI 24).
        let mut bytes = pdu("0745 01 1D1B 02F839000100020003");
        bytes.resize(32, 0); // Fill the declared 27-octet TAI list value.
        bytes.extend_from_slice(&[0x24, 0x02, 0x01, 0x05]);
        assert!(matches!(
            Message::decode(&bytes).unwrap(),
            Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_))
        ));
        // The network IEs fill exactly 28 octets, so the UE
        // form would read them as an EPS mobile identity longer than the 11
        // value octets TS 24.301 §9.9.3.12 allows.
        let bytes = pdu("0745 01 1C0121 1D0600F839000001 1E0600F839000002 2008 0000000000000000");
        let message = Message::decode(&bytes).unwrap();
        assert!(matches!(
            message,
            Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_))
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
            Message::decode(&from_ue).unwrap(),
            Message::Emm(_, EmmMessage::DetachRequestUeOriginating(_))
        ));
    }

    #[test]
    fn truncated_fixed_authentication_parameter_is_rejected() {
        let pdu = [0x07, 0x52, 0x01, 0xAA];
        assert_eq!(
            Message::decode(&pdu).unwrap_err(),
            Error::InvalidMandatoryIe {
                ie: IeName::of("authentication_parameter_rand"),
                fault: IeFault::Truncated,
                reason: None,
            }
        );
    }

    #[test]
    fn unknown_optional_ie_round_trips() {
        let pdu = [0x07, 0x60, 0x02, 0x49, 0x01, 0xAA];
        let decoded = Message::decode(&pdu).unwrap();
        assert_eq!(decoded.encode().unwrap(), pdu);

        let interleaved = [
            0x07, 0x61, 0x40, 0x01, 0xaa, 0x49, 0x01, 0x00, 0x43, 0x01, 0x80,
        ];
        let decoded = Message::decode(&interleaved).unwrap();
        assert_eq!(decoded.encode().unwrap(), interleaved);
    }

    /// The length of an IE is that of the table of the message that
    /// carries it, where four of them were compared with the tables of
    /// TS 24.301 clause 8 and found different.
    #[test]
    fn the_lengths_of_four_ies_are_those_of_the_tables_of_their_messages() {
        let optional = |octets: &[u8]| {
            let message = Message::decode(octets).unwrap();
            assert_eq!(message.encode().unwrap(), octets, "{octets:02x?}");
            let ignored = message.unknown_ies().len();
            let fields: Vec<_> = message
                .validate()
                .iter()
                .map(|finding| finding.field)
                .collect();
            (ignored, fields)
        };

        // Access technology utilization control: 4 to 5 octets in six
        // tables, 2 to 5 in that of GUTI REALLOCATION COMMAND, where one
        // without contents tells the UE to remove what it stored
        // (§5.4.1.3). ATTACH REJECT with cause #15, then with the IE
        // without contents, which that message does not have.
        assert_eq!(optional(&pdu("07 44 0f 20 02 00 08")), (0, vec![]));
        assert_eq!(optional(&pdu("07 44 0f 20 00")), (1, vec!["unknown_ies"]));
        for (message, with_two, with_four) in [
            ("ATTACH REJECT", "07 44 0f 20 00", "07 44 0f 20 02 00 08"),
            ("DETACH REQUEST", "07 45 01 20 00", "07 45 01 20 02 00 08"),
            ("SERVICE REJECT", "07 4e 0f 20 00", "07 4e 0f 20 02 00 08"),
            (
                "TRACKING AREA UPDATE REJECT",
                "07 4b 0f 20 00",
                "07 4b 0f 20 02 00 08",
            ),
        ] {
            let direction = Direction::Downlink;
            let short = Message::decode_with(
                &pdu(with_two),
                crate::DecodeOptions::STRICT.with_direction(direction),
            )
            .unwrap();
            assert_eq!(short.unknown_ies().len(), 1, "{message}");
            let whole = Message::decode_with(
                &pdu(with_four),
                crate::DecodeOptions::STRICT.with_direction(direction),
            )
            .unwrap();
            assert_eq!(whole.unknown_ies().len(), 0, "{message}");
            assert_eq!(whole.encode().unwrap(), pdu(with_four), "{message}");
        }
        let command = "07 50 0b f6 02 f8 39 00 01 02 00 00 00 01 20 00";
        let message = Message::decode(&pdu(command)).unwrap();
        let Message::Emm(_, EmmMessage::GutiReallocationCommand(command)) = &message else {
            panic!("GUTI REALLOCATION COMMAND expected");
        };
        let control = command
            .access_technology_utilization_control
            .as_ref()
            .unwrap();
        assert!(control.is_removal() && message.unknown_ies().is_empty());

        // Remote UE context list: 3 to 65538 octets in Table 8.3.23.1, so
        // one without contents is the IE of the message. Clause 9.9.4.20
        // has 5 octets at least, which is what a sender is held to.
        let report = pdu("52 01 e9 79 00 00");
        let message = Message::decode(&report).unwrap();
        let Message::Esm(_, EsmMessage::RemoteUeReport(body)) = &message else {
            panic!("REMOTE UE REPORT expected");
        };
        let list = body.remote_ue_context_connected.as_ref().unwrap();
        assert!(list.value.is_empty() && list.contexts().is_none());
        assert_eq!(optional(&report), (0, vec!["remote_ue_context_connected"]));

        // Negotiated QoS and new QoS: 14 to 22 octets in three tables. A
        // receiver takes the shorter forms of the earlier versions, down to
        // 5 octets (TS 24.008 §10.5.6.5: "shall be accepted by the receiving
        // entity"), and a sender is held to the table.
        assert_eq!(
            optional(&pdu("52 01 c9 30 03 0b 11 01")),
            (0, vec!["new_qos"])
        );
        assert_eq!(
            optional(&pdu("52 01 c9 30 02 0b 11")),
            (1, vec!["unknown_ies"])
        );

        // Forbidden TAIs: 9 to 98 octets in three tables and 8 to 98 in
        // three others, for one IE type whose clause has 8 octets at least
        // (§9.9.3.33), which a list of one tracking area is. SERVICE
        // REJECT, one of the tables that say 9.
        let reject = pdu("07 4e 0f 1d 06 00 02 f8 39 00 01");
        let message = Message::decode(&reject).unwrap();
        let Message::Emm(_, EmmMessage::ServiceReject(body)) = &message else {
            panic!("SERVICE REJECT expected");
        };
        let list = body
            .forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming
            .as_ref();
        assert_eq!(list.unwrap().tais().len(), 1);
        assert_eq!(optional(&reject), (0, vec![]));
    }

    #[test]
    fn adversarial_eps_ie_vectors_keep_receiver_tolerance_separate_from_sender_rules() {
        // TS 24.008 §10.5.6.5: a received Release-99 QoS IE may use the
        // three-octet legacy form, although an EPS sender emits at least twelve
        // value octets. The decoder retains it; sender validation reports it.
        let legacy_qos = pdu("52 01 C9 30 03 0B 11 01");
        let message = Message::decode(&legacy_qos).unwrap();
        let Message::Esm(_, EsmMessage::ModifyEpsBearerContextRequest(request)) = &message else {
            panic!("MODIFY EPS BEARER CONTEXT REQUEST expected");
        };
        assert_eq!(request.new_qos.as_ref().unwrap().value, [0x0b, 0x11, 0x01]);
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "new_qos")
        );
        assert_eq!(message.encode().unwrap(), legacy_qos);

        // TS 24.301 §9.9.4.20: identity type 000 is reserved. Its raw context
        // remains relayable, but it is not a sender-valid Remote UE Context.
        let remote = pdu("52 01 E9 79 00 06 01 04 01 01 00 00");
        let message = Message::decode(&remote).unwrap();
        let Message::Esm(_, EsmMessage::RemoteUeReport(report)) = &message else {
            panic!("REMOTE UE REPORT expected");
        };
        assert!(report.remote_ue_context_connected.is_some());
        assert!(
            message
                .validate()
                .iter()
                .any(|error| { error.field == "remote_ue_context_connected" })
        );
        assert_eq!(message.encode().unwrap(), remote);

        // TS 24.008 §10.5.4.9: presentation indicator 11 is reserved. An
        // optional malformed CLI is treated as absent while its bytes remain
        // in the unknown-IE stream for byte-exact forwarding.
        let cli = pdu("07 64 00 60 02 11 E0");
        let message = Message::decode(&cli).unwrap();
        let Message::Emm(_, EmmMessage::CsServiceNotification(notification)) = &message else {
            panic!("CS SERVICE NOTIFICATION expected");
        };
        assert!(notification.cli.is_none());
        assert_eq!(notification.unknown_ies.len(), 1);
        assert_eq!(message.encode().unwrap(), cli);

        // TS 24.008 §10.5.6.65: additional setup type 9 is reserved.
        let header_compression = pdu("02 01 D0 11 66 04 00 00 01 09");
        let message = Message::decode(&header_compression).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| { error.field == "header_compression_configuration" })
        );
        assert_eq!(message.encode().unwrap(), header_compression);
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
            // A well-framed one is kept: the receiver applies TS 24.301
            // §7.5.1 to the flag, and a tool can inspect the message.
            let message = Message::decode(wire).unwrap();
            assert_eq!(message.encode().unwrap(), wire);
            assert_eq!(
                message
                    .unknown_ies()
                    .iter()
                    .any(|ie| ie.is_comprehension_required()),
                flagged,
                "{wire:02x?}"
            );
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
        // A UE network capability of one octet: Table 8.2.4.1 has two or more.
        let request = AttachRequest::new(
            EpsAttachType::new(1),
            KeySetIdentifier::new(7),
            EpsMobileIdentity::from_imsi("1234567").unwrap(),
            UeNetworkCapability::new(vec![0]),
            EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        );
        let errors = request.validate();
        assert!(!errors.is_empty());
        assert!(
            (errors.iter()).all(|error| error.field == "ue_network_capability"),
            "{errors:?}"
        );
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
            let message = Message::decode(pdu).unwrap();
            assert!(!message.validate().is_empty(), "accepted {pdu:02x?}");
        }
    }

    #[test]
    fn explicit_direction_disambiguates_detach_in_plain_and_integrity_envelopes() {
        // The direction selects the network form also when the octets read
        // as a UE identity; its unknown comprehension-required IE is kept.
        let unknown_required = [0x07, 0x45, 0x01, 0x05, 0x04, 0x11, 0x22, 0x33, 0x44];
        let message = Message::decode_with(
            &unknown_required,
            crate::DecodeOptions::STRICT.with_direction(Direction::Downlink),
        )
        .unwrap();
        assert!(matches!(
            message,
            Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_))
        ));
        let first = message.unknown_ies().get(0).unwrap();
        assert!(first.is_comprehension_required());
        let downlink = [0x07, 0x45, 0x01, 0x53, 0x03];
        assert!(matches!(
            Message::decode_with(
                &downlink,
                crate::DecodeOptions::STRICT.with_direction(Direction::Downlink)
            )
            .unwrap(),
            Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_))
        ));
        let mut protected = vec![0x17, 0, 0, 0, 0, 0];
        protected.extend_from_slice(&downlink);
        assert!(matches!(
            Message::decode_with(&protected, crate::DecodeOptions::STRICT.with_direction(Direction::Downlink)).unwrap(),
            Message::SecurityProtected(_, inner) if matches!(*inner, Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_)))
        ));
    }

    #[test]
    fn malformed_eps_headers_do_not_encode_or_decode() {
        assert!(Message::decode(&[0x27, 0, 0, 0, 0, 0]).is_err());
        assert!(
            !Message::decode(&[0x12, 0x01, 0xD0, 0x11])
                .unwrap()
                .validate()
                .is_empty()
        );
        let header = EsmHeader::new(EsmMessageType::PdnConnectivityRequest, 3, 1);
        let mut buffer = Vec::new();
        header.encode_into(&mut buffer).unwrap();
        assert_eq!(EsmHeader::decode(&buffer).unwrap(), header);
        let reserved_pti = Message::decode(&[0x02, 0xff, 0xd0, 0x11]).unwrap();
        assert!(matches!(
            reserved_pti,
            Message::Esm(
                EsmHeader {
                    procedure_transaction_identity: 0xff,
                    ..
                },
                EsmMessage::PdnConnectivityRequest(_)
            )
        ));
        assert!(
            reserved_pti
                .validate()
                .iter()
                .any(|error| error.field == "procedure_transaction_identity")
        );
        assert_eq!(reserved_pti.encode().unwrap(), [0x02, 0xff, 0xd0, 0x11]);
    }

    #[test]
    fn repeated_optional_ies_keep_first_occurrence() {
        // TS 24.301 §7.6.3: only the first repetition is handled. Later
        // repetitions are kept as ignored octets so relayed bytes are unchanged.
        let repeated_pco = [
            0x02, 0x01, 0xd0, 0x11, 0x27, 0x01, 0x80, 0x27, 0x02, 0x80, 0x00,
        ];
        let message = Message::decode(&repeated_pco).unwrap();
        let Message::Esm(_, EsmMessage::PdnConnectivityRequest(request)) = &message else {
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
            request.unknown_ies.iter().collect::<Vec<_>>(),
            [UnknownIe {
                iei: 0x27,
                data: &[0x02, 0x80, 0x00],
            }]
        );
        assert_eq!(message.encode().unwrap(), repeated_pco);

        // Type 1 and LV fields carried with an IEI follow the same rule.
        let repeated_half_and_guti = [
            0x07, 0x42, 0x01, 0x00, 0x06, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x00, 0x04, 0x02,
            0x01, 0xd1, 0x00, 0x50, 0x0b, 0xf6, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x50, 0x0b, 0xf6, 0x00, 0xf1, 0x10, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00,
            0x02, 0xf1, 0xf2,
        ];
        let message = Message::decode(&repeated_half_and_guti).unwrap();
        let Message::Emm(_, EmmMessage::AttachAccept(accept)) = &message else {
            panic!("expected ATTACH ACCEPT");
        };
        assert_eq!(accept.guti.as_ref().unwrap().as_guti().unwrap().m_tmsi(), 1);
        assert_eq!(accept.unknown_ies.len(), 2);
        assert_eq!(message.encode().unwrap(), repeated_half_and_guti);
    }

    #[test]
    fn esm_header_validation_uses_procedure_family() {
        let request = PdnConnectivityRequest::new(RequestType::new(1), PdnType::new(1));
        let wrong_ebi = Message::new_esm(request.clone(), 5, 1);
        assert!(
            wrong_ebi
                .validate()
                .iter()
                .any(|error| error.field == "eps_bearer_identity")
        );
        let missing_pti = Message::new_esm(request, 0, 0);
        assert!(
            missing_pti
                .validate()
                .iter()
                .any(|error| error.field == "procedure_transaction_identity")
        );
        let dummy = Message::new_esm(EsmDummyMessage::new(), 5, 0);
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
            Message::decode_with(&[0x07, 0x45, 0x01, 0x04, 0, 0, 0, 0], crate::DecodeOptions::STRICT.with_direction(Direction::Uplink)),
            Err(Error::InvalidMandatoryIe {
                ie,
                fault: IeFault::Syntax,
                ..
            }) if ie == IeName::of("eps_mobile_identity")
        ));

        let mut invalid_ksi = vec![0x07, 0x52, 0x07];
        invalid_ksi.extend_from_slice(&[0; 16]);
        invalid_ksi.push(16);
        invalid_ksi.extend_from_slice(&[0; 16]);
        let message = Message::decode(&invalid_ksi).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|error| error.field == "nas_key_set_identifier_asme")
        );
    }

    #[test]
    fn t3402_follows_its_ie_type_in_each_message() {
        use crate::nas_eps::{GprsTimerUnit, GprsTimerValue};
        // GPRS timer (TV) in ATTACH ACCEPT, GPRS timer 2 (TLV) in ATTACH
        // REJECT (Tables 8.2.1.1 and 8.2.3.1).
        let tv = [
            0x07, 0x42, 0x01, 0x00, 0x06, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x02, 0x01, 0xd0, 0x11, 0x17,
            0x21,
        ];
        let tlv = [0x07, 0x44, 0x02, 0x16, 0x01, 0x21];
        for wire in [tv.as_slice(), tlv.as_slice()] {
            let decoded = Message::decode(wire).unwrap();
            assert_eq!(decoded.encode().unwrap(), wire);
            assert!(decoded.validate().is_empty());
        }
        // Octets beyond the defined value are ignored by
        // the typed getters (TS 24.007 §11.4.2) but kept for re-encoding,
        // and validate() reports the sender error.
        let wire = &[0x07, 0x44, 0x02, 0x16, 0x03, 0x21, 0xaa, 0xbb][..];
        {
            let message = Message::decode(wire).unwrap();
            assert_eq!(message.encode().unwrap(), wire);
            assert!(
                message
                    .validate()
                    .iter()
                    .any(|error| error.field == "t3402_value")
            );
            let Message::Emm(_, EmmMessage::AttachReject(reject)) = message else {
                panic!("ATTACH REJECT expected");
            };
            let timer = reject.t3402_value.unwrap();
            assert_eq!(timer.unit(), Some(GprsTimerUnit::OneMinute));
            assert_eq!(timer.value(), Some(GprsTimerValue::Seconds(60)));
        }
        let empty = &[0x07, 0x44, 0x02, 0x16, 0x00][..];
        let message = Message::decode(empty).unwrap();
        assert_eq!(message.encode().unwrap(), empty);
        let Message::Emm(_, EmmMessage::AttachReject(reject)) = message else {
            panic!("ATTACH REJECT expected");
        };
        assert!(reject.t3402_value.is_none());
        assert_eq!(reject.unknown_ies.len(), 1);
    }

    /// A plain EMM header has the protocol discriminator of EMM and no security header
    /// type; a SERVICE REQUEST has one of 12 to 15.
    #[test]
    fn the_headers_of_emm_have_their_discriminator_and_type() {
        use SecurityHeaderType as Sht;
        let header = |protocol_discriminator, security_header_type| EmmHeader {
            protocol_discriminator,
            security_header_type,
            message_type: EmmMessageType::SecurityModeComplete,
        };
        let encoded = |header: EmmHeader| {
            let mut out = Vec::new();
            header.encode_into(&mut out).map(|()| out)
        };
        assert_eq!(
            encoded(header(7, Sht::PlainNasMessageNotSecurityProtected)),
            Ok(vec![0x07, 0x5e])
        );
        assert!(encoded(header(2, Sht::PlainNasMessageNotSecurityProtected)).is_err());
        assert!(encoded(header(7, Sht::IntegrityProtected)).is_err());
        assert!(ServiceRequest::decode(&[0xc7, 0x01, 0x02, 0x03]).is_ok());
        for refused in [
            [0xc2, 0x01, 0x02, 0x03],
            [0x07, 0x01, 0x02, 0x03],
            [0xb7, 0, 0, 0],
        ] {
            assert!(ServiceRequest::decode(&refused).is_err(), "{refused:02x?}");
        }
        // Each is a protected message of its length
        assert!(is_security_protected(&[0xc7, 0, 0, 0]));
        assert!(!is_security_protected(&[0xc7, 0, 0]));
        assert!(is_security_protected(&[0x17, 0, 0, 0, 0, 0]));
        assert!(!is_security_protected(&[0x07, 0x5e, 0, 0, 0, 0]));
    }

    /// An EMM TRANSPORT data container is of a known type, and is as long as its type
    /// says; the DDX bits of an uplink one are not both set (TS 24.301 §9.9.3.60).
    #[cfg(feature = "security")]
    #[test]
    fn an_emm_data_container_is_as_long_as_its_type_says() {
        for (data, uplink, downlink) in [
            (&[0x01, 0xaa][..], true, true),
            (&[0x00, 0xaa], false, false),
            (&[0x19, 0xaa], false, true),
            (&[0x40, 1, 0xaa, 0xbb], true, true),
            (&[0x40, 1, 0xaa], false, false),
            (&[0x40, 2, 0xaa, 0xbb], false, false),
            (&[0x58, 1, 0xaa, 0xbb], false, true),
            (&[0x60, 0xaa], false, false),
        ] {
            assert_eq!(
                received_emm_data_container_is_valid(data, false),
                uplink,
                "{data:02x?}"
            );
            assert_eq!(
                received_emm_data_container_is_valid(data, true),
                downlink,
                "{data:02x?}"
            );
        }
    }

    /// Each security header type protects the messages that it may, and the SECURITY
    /// MODE messages and the CONTROL PLANE SERVICE REQUEST theirs alone (TS 24.301
    /// §5.4.3.2, §5.4.3.3 and Table 9.3.1).
    #[test]
    fn each_security_header_type_protects_its_messages() {
        use SecurityHeaderType as Sht;
        let command = Message::decode(&[0x07, 0x5d, 0x02, 0x00, 0x02, 0xe0, 0xe0]).unwrap();
        let complete = Message::new_emm(SecurityModeComplete::new());
        let service = |esm: bool, nas: bool| {
            let mut request = ControlPlaneServiceRequest::new(
                ControlPlaneServiceType::new(0),
                KeySetIdentifier::new(0),
            );
            if esm {
                request.esm_message_container =
                    Some(EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]));
            }
            if nas {
                request.nas_message_container = Some(MessageContainer::new(vec![0x11]));
            }
            Message::new_emm(request)
        };
        let status = Message::new_emm(EmmStatus::new(EmmCause::new(0x60)));
        let partially = Sht::IntegrityProtectedAndPartiallyCipheredNasMessage;
        for (sht, inner, valid) in [
            (
                Sht::IntegrityProtectedWithNewEpsSecurityContext,
                &command,
                true,
            ),
            (Sht::IntegrityProtected, &command, false),
            (
                Sht::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
                &complete,
                true,
            ),
            (Sht::IntegrityProtected, &complete, false),
            (Sht::IntegrityProtected, &service(false, false), true),
            (partially, &service(true, false), true),
            (partially, &service(false, true), true),
            (Sht::IntegrityProtected, &service(false, true), false),
            (Sht::IntegrityProtected, &Message::Opaque(vec![1]), false),
            (
                Sht::IntegrityProtectedWithNewEpsSecurityContext,
                &status,
                false,
            ),
            (partially, &status, false),
        ] {
            assert_eq!(
                check_protected_inner(sht, inner).is_ok(),
                valid,
                "{sht:?} {inner:?}"
            );
        }
        // A message is protected by a type that protects it, and by no other
        assert!(Message::protect(status.clone(), Sht::IntegrityProtected, 0, 0).is_ok());
        for refused in [
            Sht::PlainNasMessageNotSecurityProtected,
            Sht::SecurityHeaderForTheEmmTransportMessage,
        ] {
            assert!(Message::protect(status.clone(), refused, 0, 0).is_err());
        }
        let header = SecurityHeader {
            security_header_type: Sht::SecurityHeaderForTheEmmTransportMessage,
            message_authentication_code: 0,
            sequence_number: 0,
        };
        let transported = Message::SecurityProtected(header, Box::new(status));
        assert!(transported.encode().is_err());
    }

    /// A message under a security header is decoded in its direction, and refused, or
    /// answered, as the plain message under it.
    #[test]
    fn a_protected_message_is_read_and_answered_as_its_plain_message() {
        let detach = [0x17, 0, 0, 0, 0, 0, 0x07, 0x45, 0x01];
        let message = Message::decode_with(
            &detach,
            crate::DecodeOptions::STRICT.with_direction(Direction::Downlink),
        )
        .unwrap();
        let Message::SecurityProtected(_, inner) = message else {
            panic!("a protected message");
        };
        assert!(matches!(
            *inner,
            Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_))
        ));
        // In the uplink the same octets are a DETACH REQUEST without its identity
        let refused = Message::decode_with(
            &detach,
            crate::DecodeOptions::STRICT.with_direction(Direction::Uplink),
        );
        assert!(
            matches!(refused, Err(Error::InvalidMandatoryIe { ie, .. }) if ie.to_string() == "eps-mobile-identity"),
            "{refused:?}"
        );
        // A message of one octet is refused by its protocol discriminator, also under a
        // security header
        for octets in [&[0x00][..], &[0x17, 0, 0, 0, 0, 5, 0x00]] {
            let refused = Message::decode(octets);
            assert_eq!(refused, Err(Error::UnknownProtocolDiscriminator(0)));
        }
        let invalid = Error::InvalidMandatoryIe {
            ie: crate::common::IeName::of("x"),
            fault: crate::common::IeFault::Syntax,
            reason: None,
        };
        let answered = |octets: &[u8], direction| {
            Message::answer_to_refused(octets, &invalid, direction)
                .map(|answer| answer.encode().unwrap())
        };
        // ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST under a security header: its REJECT
        assert_eq!(
            answered(
                &[0x17, 0, 0, 0, 0, 0, 0x52, 0x01, 0xc1],
                Direction::Downlink
            ),
            Some(vec![0x52, 0x01, 0xc3, 0x60])
        );
        // Each ESM request or command that has a REJECT is answered by it, cause #96
        for (direction, request, reject) in [
            (Direction::Downlink, 0xc5, 0xc7),
            (Direction::Downlink, 0xc9, 0xcb),
            (Direction::Uplink, 0xd2, 0xd3),
            (Direction::Uplink, 0xd4, 0xd5),
            (Direction::Uplink, 0xd6, 0xd7),
        ] {
            assert_eq!(
                answered(&[0x52, 0x01, request], direction),
                Some(vec![0x52, 0x01, reject, 0x60]),
                "{request:#04x}"
            );
        }
    }

    #[test]
    fn innermost_is_the_message_inside_the_security_envelopes() {
        // An ATTACH REJECT, cause #3, plain and integrity protected
        let plain = Message::decode(&[0x07, 0x44, 0x03]).unwrap();
        assert_eq!(plain.innermost(), &plain);
        let protected = Message::decode(&[0x17, 1, 2, 3, 4, 5, 0x07, 0x44, 0x03]).unwrap();
        assert_eq!(protected.innermost(), &plain);

        // An envelope in an envelope, which a program can build
        let Message::SecurityProtected(header, _) = &protected else {
            panic!("expected a security protected message");
        };
        let nested = Message::SecurityProtected(header.clone(), Box::new(protected.clone()));
        assert_eq!(nested.innermost(), &plain);

        // A ciphered message: its ciphertext; a SERVICE REQUEST: itself
        let ciphered = Message::decode(&[0x27, 1, 2, 3, 4, 5, 0xaa, 0xbb]).unwrap();
        assert_eq!(ciphered.innermost(), &Message::Opaque(vec![0xaa, 0xbb]));
        let service = Message::decode(&[0xc7, 0x05, 0x01, 0x02]).unwrap();
        assert_eq!(service.innermost(), &service);
    }
}
