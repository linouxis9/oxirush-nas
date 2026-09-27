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
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nas5gmmHeader {
    pub extended_protocol_discriminator: u8,
    pub security_header_type: Nas5gsSecurityHeaderType,
    pub message_type: Nas5gmmMessageType,
}

impl Nas5gmmHeader {
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
            return Err(NasError::BufferTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let security_header_type_octet = buffer.get_u8();
        let message_type_value = buffer.get_u8();

        if security_header_type_octet & 0xF0 != 0 {
            return Err(NasError::DecodingError(format!(
                "5GMM plain header spare half octet shall be zero, got 0x{:02X}",
                security_header_type_octet
            )));
        }

        let security_header_type =
            Nas5gsSecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;
        let message_type = Nas5gmmMessageType::try_from(message_type_value)?;

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(NasError::DecodingError(format!(
                "Plain 5GMM header shall use EPD=0x7E, got 0x{:02X}",
                extended_protocol_discriminator
            )));
        }
        if security_header_type != Nas5gsSecurityHeaderType::PlainNasMessage {
            return Err(NasError::DecodingError(format!(
                "Plain 5GMM header shall use SHT=PlainNasMessage, got {:?}",
                security_header_type
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
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nas5gsmHeader {
    pub extended_protocol_discriminator: u8,
    pub pdu_session_identity: u8,
    pub procedure_transaction_identity: u8,
    pub message_type: Nas5gsmMessageType,
}

impl Nas5gsmHeader {
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
        if self.procedure_transaction_identity == 255 {
            return Err(NasError::EncodingError(
                "Reserved 5GSM procedure transaction identity".into(),
            ));
        }

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
            return Err(NasError::BufferTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let pdu_session_identity = buffer.get_u8();
        let procedure_transaction_identity = buffer.get_u8();
        let message_type_value = buffer.get_u8();

        let message_type = Nas5gsmMessageType::try_from(message_type_value)?;

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM {
            return Err(NasError::DecodingError(format!(
                "5GSM header shall use EPD=0x2E, got 0x{:02X}",
                extended_protocol_discriminator
            )));
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

    if pdu[1] & 0xF0 != 0 {
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
#[derive(Debug, Clone, PartialEq)]
pub struct Nas5gsSecurityHeader {
    pub extended_protocol_discriminator: u8,
    pub security_header_type: Nas5gsSecurityHeaderType,
    pub message_authentication_code: u32,
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
            return Err(NasError::BufferTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let security_header_type_octet = buffer.get_u8();
        let message_authentication_code = buffer.get_u32();
        let sequence_number = buffer.get_u8();

        if security_header_type_octet & 0xF0 != 0 {
            return Err(NasError::DecodingError(format!(
                "5GS security header spare half octet shall be zero, got 0x{:02X}",
                security_header_type_octet
            )));
        }

        let security_header_type =
            Nas5gsSecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(NasError::DecodingError(format!(
                "Security-protected outer header shall use EPD=0x7E, got 0x{:02X}",
                extended_protocol_discriminator
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
            fgs_registration_type: NasFGsRegistrationType,
            fgs_mobile_identity: NasFGsMobileIdentity
        }
        optional {
            0xC0 => non_current_native_nas_key_set_identifier: NasKeySetIdentifier [v_as_tv1],
            0x10 => fgmm_capability: NasFGmmCapability,
            0x2E => ue_security_capability: NasUeSecurityCapability [opt_type],
            0x2F => requested_nssai: NasNssai,
            0x52 => last_visited_registered_tai: NasFGsTrackingAreaIdentity,
            0x17 => s1_ue_network_capability: NasS1UeNetworkCapability,
            0x40 => uplink_data_status: NasUplinkDataStatus,
            0x50 => pdu_session_status: NasPduSessionStatus,
            0xB0 => mico_indication: NasMicoIndication [tv1],
            0x2B => ue_status: NasUeStatus,
            0x77 => additional_guti: NasFGsMobileIdentity [opt_type],
            0x25 => allowed_pdu_session_status: NasAllowedPduSessionStatus,
            0x18 => ue_usage_setting: NasUeUsageSetting,
            0x51 => requested_drx_parameters: NasFGsDrxParameters,
            0x70 => eps_nas_message_container: NasEpsNasMessageContainer,
            0x74 => ladn_indication: NasLadnIndication,
            0x80 => payload_container_type: NasPayloadContainerType [v_as_tv1],
            0x7B => payload_container: NasPayloadContainer [opt_type],
            0x90 => network_slicing_indication: NasNetworkSlicingIndication [tv1],
            0x53 => fgs_update_type: NasFGsUpdateType,
            0x41 => mobile_station_classmark_2: NasMobileStationClassmark2,
            0x42 => supported_codecs: NasSupportedCodecList,
            0x71 => nas_message_container: NasMessageContainer,
            0x60 => eps_bearer_context_status: NasEpsBearerContextStatus,
            0x6E => requested_extended_drx_parameters: NasExtendedDrxParameters,
            0x6A => t3324_value: NasGprsTimer3,
            0x67 => ue_radio_capability_id: NasUeRadioCapabilityId,
            0x35 => requested_mapped_nssai: NasMappedNssai,
            0x48 => additional_information_requested: NasAdditionalInformationRequested,
            0x1A => requested_wus_assistance_information: NasWusAssistanceInformation,
            0xA0 => n5gc_indication: NasN5gcIndication [tv1],
            0x30 => requested_nb_n1_mode_drx_parameters: NasNbN1ModeDrxParameters,
            0x29 => ue_request_type: NasUeRequestType,
            0x28 => paging_restriction: NasPagingRestriction,
            0x72 => service_level_aa_container: NasServiceLevelAaContainer,
            0x32 => nid: NasNid,
            0x16 => ms_determined_plmn_with_disaster_condition: NasPlmnIdentity,
            0x2A => requested_peips_assistance_information: NasPeipsAssistanceInformation,
            0x3B => requested_t3512_value: NasGprsTimer3,
            0x3C => unavailability_information: NasUnavailabilityInformation,
            0x3F => non_3gpp_path_switching_information: NasNon3GppPathSwitchingInformation,
            0x56 => aun3_indication: NasAun3Indication,
            0x64 => requested_lp_wusps_assistance_information: NasLpWuspsAssistanceInformation
        }
    }
}

nas_message! {
    /// Registration Accept (TS 24.501 §8.2.7).
    pub struct NasRegistrationAccept {
        mandatory {
            fgs_registration_result: NasFGsRegistrationResult
        }
        optional {
            0x77 => fg_guti: NasFGsMobileIdentity [opt_type],
            0x4A => equivalent_plmns: NasPlmnList,
            0x54 => tai_list: NasFGsTrackingAreaIdentityList,
            0x15 => allowed_nssai: NasNssai,
            0x11 => rejected_nssai: NasRejectedNssai,
            0x31 => configured_nssai: NasNssai,
            0x21 => fgs_network_feature_support: NasFGsNetworkFeatureSupport,
            0x50 => pdu_session_status: NasPduSessionStatus,
            0x26 => pdu_session_reactivation_result: NasPduSessionReactivationResult,
            0x72 => pdu_session_reactivation_result_error_cause: NasPduSessionReactivationResultErrorCause,
            0x79 => ladn_information: NasLadnInformation,
            0xB0 => mico_indication: NasMicoIndication [tv1],
            0x90 => network_slicing_indication: NasNetworkSlicingIndication [tv1],
            0x27 => service_area_list: NasServiceAreaList,
            0x5E => t3512_value: NasGprsTimer3,
            0x5D => non_3gpp_de_registration_timer_value: NasGprsTimer2,
            0x16 => t3502_value: NasGprsTimer2,
            0x34 => emergency_number_list: NasEmergencyNumberList,
            0x7A => extended_emergency_number_list: NasExtendedEmergencyNumberList,
            0x73 => sor_transparent_container: NasSorTransparentContainer,
            0x78 => eap_message: NasEapMessage [opt_type],
            0xA0 => nssai_inclusion_mode: NasNssaiInclusionMode [tv1],
            0x76 => operator_defined_access_category_definitions: NasOperatorDefinedAccessCategoryDefinitions,
            0x51 => negotiated_drx_parameters: NasFGsDrxParameters,
            0xD0 => non_3gpp_nw_policies: NasNon3GppNwProvidedPolicies [tv1],
            0x60 => eps_bearer_context_status: NasEpsBearerContextStatus,
            0x6E => negotiated_extended_drx_parameters: NasExtendedDrxParameters,
            0x6C => t3447_value: NasGprsTimer3,
            0x6B => t3448_value: NasGprsTimer2,
            0x6A => t3324_value: NasGprsTimer3,
            0x67 => ue_radio_capability_id: NasUeRadioCapabilityId,
            0xE0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1],
            0x39 => pending_nssai: NasNssai,
            0x74 => ciphering_key_data: NasCipheringKeyData,
            0x75 => cag_information_list: NasCagInformationList,
            0x1B => truncated_fg_s_tmsi_configuration: NasTruncatedFGSTmsiConfiguration,
            0x1C => negotiated_wus_assistance_information: NasWusAssistanceInformation,
            0x29 => negotiated_nb_n1_mode_drx_parameters: NasNbN1ModeDrxParameters,
            0x68 => extended_rejected_nssai: NasExtendedRejectedNssai,
            0x7B => service_level_aa_container: NasServiceLevelAaContainer,
            0x33 => negotiated_peips_assistance_information: NasPeipsAssistanceInformation,
            0x35 => fgs_additional_request_result: NasFGsAdditionalRequestResult,
            0x70 => nssrg_information: NasNssrgInformation,
            0x14 => disaster_roaming_wait_range: NasRegistrationWaitRange,
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange,
            0x13 => list_of_plmns_to_be_used_in_disaster_condition: NasListOfPlmnsToBeUsedInDisasterCondition,
            0x1D => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList,
            0x1E => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList,
            0x71 => extended_cag_information_list: NasExtendedCagInformationList,
            0x7C => nsag_information: NasNsagInformation,
            0x3D => equivalent_snpns: NasSnpnList,
            0x32 => nid: NasNid,
            0x7D => type_6_ie_container: NasType6IeContainer,
            0x4B => ran_timing_synchronization: NasRanTimingSynchronization,
            0x4C => alternative_nssai: NasAlternativeNssai,
            0x4F => discontinuous_coverage_max_time_offset: NasGprsTimer3,
            0x5B => s_nssai_time_validity_information: NasSNssaiTimeValidityInformation,
            0x3C => unavailability_configuration: NasUnavailabilityConfiguration,
            0x5C => feature_authorization_indication: NasFeatureAuthorizationIndication,
            0x61 => on_demand_nssai: NasOnDemandNssai,
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
            0x64 => negotiated_lp_wusps_assistance_information: NasLpWuspsAssistanceInformation,
            0x80 => lp_wus_status: NasLpWusStatus [tv1]
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
            0x73 => sor_transparent_container: NasSorTransparentContainer
        }
    }
}

nas_message! {
    /// Registration Reject (TS 24.501 §8.2.9).
    pub struct NasRegistrationReject {
        mandatory {
            fgmm_cause: NasFGmmCause
        }
        optional {
            0x5F => t3346_value: NasGprsTimer2,
            0x16 => t3502_value: NasGprsTimer2,
            0x78 => eap_message: NasEapMessage [opt_type],
            0x69 => rejected_nssai: NasRejectedNssai,
            0x75 => cag_information_list: NasCagInformationList,
            0x68 => extended_rejected_nssai: NasExtendedRejectedNssai,
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange,
            0x71 => extended_cag_information_list: NasExtendedCagInformationList,
            0x3A => lower_bound_timer_value: NasGprsTimer3,
            0x1D | 0x3B => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList,
            0x1E | 0x3C => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList,
            0x3E => n3iwf_identifier: NasN3iwfIdentifier,
            0x4D => tnan_information: NasTnanInformation,
            0x62 => extended_5gmm_cause: NasExtendedFGmmCause,
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl
        }
    }
}

nas_message! {
    /// Deregistration Request from UE (TS 24.501 §8.2.12).
    pub struct NasDeregistrationRequestFromUe {
        mandatory {
            de_registration_type: NasDeRegistrationType,
            fgs_mobile_identity: NasFGsMobileIdentity
        }
        optional {
            0x3C => unavailability_information: NasUnavailabilityInformation,
            0x71 => nas_message_container: NasMessageContainer
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
            de_registration_type: NasDeRegistrationType
        }
        optional {
            0x58 => fgmm_cause: NasFGmmCause [opt_type],
            0x5F => t3346_value: NasGprsTimer2,
            0x6D => rejected_nssai: NasRejectedNssai,
            0x75 => cag_information_list: NasCagInformationList,
            0x68 => extended_rejected_nssai: NasExtendedRejectedNssai,
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange,
            0x71 => extended_cag_information_list: NasExtendedCagInformationList,
            0x3A => lower_bound_timer_value: NasGprsTimer3,
            0x1D | 0x3B => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList,
            0x1E | 0x3C => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList,
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl
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
            ngksi: NasKeySetIdentifier,
            fg_s_tmsi: NasFGsMobileIdentity
        }
        optional {
            0x40 => uplink_data_status: NasUplinkDataStatus,
            0x50 => pdu_session_status: NasPduSessionStatus,
            0x25 => allowed_pdu_session_status: NasAllowedPduSessionStatus,
            0x71 => nas_message_container: NasMessageContainer,
            0x29 => ue_request_type: NasUeRequestType,
            0x28 => paging_restriction: NasPagingRestriction
        }
    }
}

impl NasServiceRequest {
    /// Service type from the upper nibble of the ngKSI byte (§9.11.3.50).
    ///
    /// In ServiceRequest, the first mandatory byte packs ngKSI (lower nibble)
    /// and service type (upper nibble).
    pub fn service_type(&self) -> Option<crate::nas_5gs::ie::ServiceType> {
        // Bits 5-7 of the byte = bits 1-3 of the upper nibble. Bit 8 (TSC) is
        // separate. The 3-bit value sits in the low bits after the shift.
        crate::nas_5gs::ie::ServiceType::from_u8((self.ngksi.value >> 4) & 0x07)
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
        self.ngksi.value = (self.ngksi.value & 0x8F) | ((service_type as u8 & 0x07) << 4);
    }
}

nas_message! {
    /// Service Reject (TS 24.501 §8.2.18).
    pub struct NasServiceReject {
        mandatory {
            fgmm_cause: NasFGmmCause
        }
        optional {
            0x50 => pdu_session_status: NasPduSessionStatus,
            0x5F => t3346_value: NasGprsTimer2,
            0x78 => eap_message: NasEapMessage [opt_type],
            0x6B => t3448_value: NasGprsTimer2,
            0x75 => cag_information_list: NasCagInformationList,
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange,
            0x71 => extended_cag_information_list: NasExtendedCagInformationList,
            0x3A => lower_bound_timer_value: NasGprsTimer3,
            0x1D | 0x3B => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList,
            0x1E | 0x3C => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList,
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl
        }
    }
}

nas_message! {
    /// Service Accept (TS 24.501 §8.2.17).
    pub struct NasServiceAccept {
        mandatory { }
        optional {
            0x50 => pdu_session_status: NasPduSessionStatus,
            0x26 => pdu_session_reactivation_result: NasPduSessionReactivationResult,
            0x72 => pdu_session_reactivation_result_error_cause: NasPduSessionReactivationResultErrorCause,
            0x78 => eap_message: NasEapMessage [opt_type],
            0x6B => t3448_value: NasGprsTimer2,
            0x34 => fgs_additional_request_result: NasFGsAdditionalRequestResult,
            0x1D => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: NasFGsTrackingAreaIdentityList,
            0x1E => forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: NasFGsTrackingAreaIdentityList
        }
    }
}

nas_message! {
    /// Configuration Update Command (TS 24.501 §8.2.19).
    pub struct NasConfigurationUpdateCommand {
        mandatory { }
        optional {
            0xD0 => configuration_update_indication: NasConfigurationUpdateIndication [tv1],
            0x77 => fg_guti: NasFGsMobileIdentity [opt_type],
            0x54 => tai_list: NasFGsTrackingAreaIdentityList,
            0x15 => allowed_nssai: NasNssai,
            0x27 => service_area_list: NasServiceAreaList,
            0x43 => full_name_for_network: NasNetworkName,
            0x45 => short_name_for_network: NasNetworkName,
            0x46 => local_time_zone: NasTimeZone,
            0x47 => universal_time_and_local_time_zone: NasTimeZoneAndTime,
            0x49 => network_daylight_saving_time: NasDaylightSavingTime,
            0x79 => ladn_information: NasLadnInformation,
            0xB0 => mico_indication: NasMicoIndication [tv1],
            0x90 => network_slicing_indication: NasNetworkSlicingIndication [tv1],
            0x31 => configured_nssai: NasNssai,
            0x11 => rejected_nssai: NasRejectedNssai,
            0x76 => operator_defined_access_category_definitions: NasOperatorDefinedAccessCategoryDefinitions,
            0xF0 => sms_indication: NasSmsIndication [tv1],
            0x6C => t3447_value: NasGprsTimer3,
            0x75 => cag_information_list: NasCagInformationList,
            0x67 => ue_radio_capability_id: NasUeRadioCapabilityId,
            0xA0 => ue_radio_capability_id_deletion_indication: NasUeRadioCapabilityIdDeletionIndication [tv1],
            0x44 => fgs_registration_result: NasFGsRegistrationResult [opt_type],
            0x1B => truncated_fg_s_tmsi_configuration: NasTruncatedFGSTmsiConfiguration,
            0xC0 => additional_configuration_indication: NasAdditionalConfigurationIndication [tv1],
            0x68 => extended_rejected_nssai: NasExtendedRejectedNssai,
            0x72 => service_level_aa_container: NasServiceLevelAaContainer,
            0x70 => nssrg_information: NasNssrgInformation,
            0x14 => disaster_roaming_wait_range: NasRegistrationWaitRange,
            0x2C => disaster_return_wait_range: NasRegistrationWaitRange,
            0x13 => list_of_plmns_to_be_used_in_disaster_condition: NasListOfPlmnsToBeUsedInDisasterCondition,
            0x71 => extended_cag_information_list: NasExtendedCagInformationList,
            0x1F => updated_peips_assistance_information: NasPeipsAssistanceInformation,
            0x73 => nsag_information: NasNsagInformation,
            0xE0 => priority_indicator: NasPriorityIndicator [tv1],
            0x4B => ran_timing_synchronization: NasRanTimingSynchronization,
            0x78 => extended_ladn_information: NasExtendedLadnInformation,
            0x4C => alternative_nssai: NasAlternativeNssai,
            0x7B => s_nssai_location_validity_information: NasSNssaiLocationValidityInformation,
            0x5B => s_nssai_time_validity_information: NasSNssaiTimeValidityInformation,
            0x4F => discontinuous_coverage_max_time_offset: NasGprsTimer3,
            0x74 => partially_allowed_nssai: NasPartialNssai,
            0x7A => partially_rejected_nssai: NasPartialNssai,
            0x5C => feature_authorization_indication: NasFeatureAuthorizationIndication,
            0x61 => on_demand_nssai: NasOnDemandNssai,
            0x63 => access_technology_utilization_control: NasAccessTechnologyUtilizationControl,
            0x64 => updated_lp_wusps_assistance_information: NasLpWuspsAssistanceInformation,
            0x80 => lp_wus_status: NasLpWusStatus [tv1]
        }
    }
}

nas_message! {
    /// Authentication Request (TS 24.501 §8.2.1).
    pub struct NasAuthenticationRequest {
        mandatory {
            ngksi: NasKeySetIdentifier,
            abba: NasAbba
        }
        optional {
            0x21 => authentication_parameter_rand: NasAuthenticationParameterRand,
            0x20 => authentication_parameter_autn: NasAuthenticationParameterAutn,
            0x78 => eap_message: NasEapMessage [opt_type]
        }
    }
}

nas_message! {
    /// Authentication Response (TS 24.501 §8.2.2).
    pub struct NasAuthenticationResponse {
        mandatory { }
        optional {
            0x2D => authentication_response_parameter: NasAuthenticationResponseParameter,
            0x78 => eap_message: NasEapMessage [opt_type]
        }
    }
}

nas_message! {
    /// Authentication Reject (TS 24.501 §8.2.5).
    pub struct NasAuthenticationReject {
        mandatory { }
        optional {
            0x78 => eap_message: NasEapMessage [opt_type]
        }
    }
}

nas_message! {
    /// Authentication Failure (TS 24.501 §8.2.4).
    pub struct NasAuthenticationFailure {
        mandatory {
            fgmm_cause: NasFGmmCause
        }
        optional {
            0x30 => authentication_failure_parameter: NasAuthenticationFailureParameter
        }
    }
}

nas_message! {
    /// Authentication Result (TS 24.501 §8.2.3).
    pub struct NasAuthenticationResult {
        mandatory {
            ngksi: NasKeySetIdentifier,
            eap_message: NasEapMessage
        }
        optional {
            0x38 => abba: NasAbba [opt_type],
            0x55 => aun3_device_security_key: NasAun3DeviceSecurityKey
        }
    }
}

nas_message! {
    /// Identity Request (TS 24.501 §8.2.21).
    pub struct NasIdentityRequest {
        mandatory {
            identity_type: NasFGsIdentityType
        }
        optional { }
    }
}

nas_message! {
    /// Identity Response (TS 24.501 §8.2.22).
    pub struct NasIdentityResponse {
        mandatory {
            mobile_identity: NasFGsMobileIdentity
        }
        optional { }
    }
}

nas_message! {
    /// Security Mode Command (TS 24.501 §8.2.25).
    pub struct NasSecurityModeCommand {
        mandatory {
            selected_nas_security_algorithms: NasSecurityAlgorithms,
            ngksi: NasKeySetIdentifier,
            replayed_ue_security_capabilities: NasUeSecurityCapability
        }
        optional {
            0xE0 => imeisv_request: NasImeisvRequest [tv1],
            0x57 => selected_eps_nas_security_algorithms: NasEpsNasSecurityAlgorithms,
            0x36 => additional_5g_security_information: NasAdditional5gSecurityInformation,
            0x78 => eap_message: NasEapMessage [opt_type],
            0x38 => abba: NasAbba [opt_type],
            0x19 => replayed_s1_ue_security_capabilities: NasS1UeSecurityCapability,
            0x55 => aun3_device_security_key: NasAun3DeviceSecurityKey
        }
    }
}

nas_message! {
    /// Security Mode Complete (TS 24.501 §8.2.26).
    pub struct NasSecurityModeComplete {
        mandatory { }
        optional {
            0x77 => imeisv: NasFGsMobileIdentity [opt_type],
            0x71 => nas_message_container: NasMessageContainer,
            0x78 => non_imeisv_pei: NasFGsMobileIdentity [opt_type]
        }
    }
}

nas_message! {
    /// Security Mode Reject (TS 24.501 §8.2.27).
    pub struct NasSecurityModeReject {
        mandatory {
            fgmm_cause: NasFGmmCause
        }
        optional { }
    }
}

nas_message! {
    /// 5GMM Status (TS 24.501 §8.2.29).
    pub struct NasFGmmStatus {
        mandatory {
            fgmm_cause: NasFGmmCause
        }
        optional { }
    }
}

nas_message! {
    /// Notification (TS 24.501 §8.2.23).
    pub struct NasNotification {
        mandatory {
            access_type: NasAccessType
        }
        optional { }
    }
}

nas_message! {
    /// Notification Response (TS 24.501 §8.2.24).
    pub struct NasNotificationResponse {
        mandatory { }
        optional {
            0x50 => pdu_session_status: NasPduSessionStatus
        }
    }
}

nas_message! {
    /// UL NAS Transport (TS 24.501 §8.2.10).
    pub struct NasUlNasTransport {
        mandatory {
            payload_container_type: NasPayloadContainerType,
            payload_container: NasPayloadContainer
        }
        optional {
            0x12 => pdu_session_id: NasPduSessionIdentity2,
            0x59 => old_pdu_session_id: NasPduSessionIdentity2,
            0x80 => request_type: NasRequestType [tv1],
            0x22 => s_nssai: NasSNssai,
            0x25 => dnn: NasDnn,
            0x24 => additional_information: NasAdditionalInformation,
            0xA0 => ma_pdu_session_information: NasMaPduSessionInformation [tv1],
            0xF0 => release_assistance_indication: NasReleaseAssistanceIndication [tv1],
            0x4E => non_3gpp_access_path_switching_indication: NasNon3GppAccessPathSwitchingIndication,
            0x5A => alternative_s_nssai: NasSNssai,
            0x90 => payload_container_information: NasPayloadContainerInformation [tv1]
        }
    }
}

nas_message! {
    /// DL NAS Transport (TS 24.501 §8.2.11).
    pub struct NasDlNasTransport {
        mandatory {
            payload_container_type: NasPayloadContainerType,
            payload_container: NasPayloadContainer
        }
        optional {
            0x12 => pdu_session_id: NasPduSessionIdentity2,
            0x24 => additional_information: NasAdditionalInformation,
            0x58 => fgmm_cause: NasFGmmCause [opt_type],
            0x37 => back_off_timer_value: NasGprsTimer3,
            0x3A => lower_bound_timer_value: NasGprsTimer3
        }
    }
}

nas_message! {
    /// Control Plane Service Request (TS 24.501 §8.2.30).
    pub struct NasControlPlaneServiceRequest {
        mandatory {
            control_plane_service_type: NasControlPlaneServiceType
        }
        optional {
            0x6F => ciot_small_data_container: NasCiotSmallDataContainer,
            0x80 => payload_container_type: NasPayloadContainerType [v_as_tv1],
            0x7B => payload_container: NasPayloadContainer [opt_type],
            0x12 => pdu_session_id: NasPduSessionIdentity2,
            0x50 => pdu_session_status: NasPduSessionStatus,
            0xF0 => release_assistance_indication: NasReleaseAssistanceIndication [tv1],
            0x40 => uplink_data_status: NasUplinkDataStatus,
            0x71 => nas_message_container: NasMessageContainer,
            0x24 => additional_information: NasAdditionalInformation,
            0x25 => allowed_pdu_session_status: NasAllowedPduSessionStatus,
            0x29 => ue_request_type: NasUeRequestType,
            0x28 => paging_restriction: NasPagingRestriction
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
            s_nssai: NasSNssai [tlv_as_lv],
            eap_message: NasEapMessage
        }
        optional { }
    }
}

nas_message! {
    /// Network Slice-Specific Authentication Complete (TS 24.501 §8.2.32).
    pub struct NasNetworkSliceSpecificAuthenticationComplete {
        mandatory {
            s_nssai: NasSNssai [tlv_as_lv],
            eap_message: NasEapMessage
        }
        optional { }
    }
}

nas_message! {
    /// Network Slice-Specific Authentication Result (TS 24.501 §8.2.33).
    pub struct NasNetworkSliceSpecificAuthenticationResult {
        mandatory {
            s_nssai: NasSNssai [tlv_as_lv],
            eap_message: NasEapMessage
        }
        optional { }
    }
}

nas_message! {
    /// Relay Key Request (TS 24.501 §8.2.34).
    pub struct NasRelayKeyRequest {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only],
            relay_key_request_parameters: NasRelayKeyRequestParameters
        }
        optional { }
    }
}

nas_message! {
    /// Relay Key Accept (TS 24.501 §8.2.35).
    pub struct NasRelayKeyAccept {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only],
            relay_key_response_parameters: NasRelayKeyResponseParameters
        }
        optional {
            0x78 => eap_message: NasEapMessage [opt_type]
        }
    }
}

nas_message! {
    /// Relay Key Reject (TS 24.501 §8.2.36).
    pub struct NasRelayKeyReject {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only]
        }
        optional {
            0x78 => eap_message: NasEapMessage [opt_type]
        }
    }
}

nas_message! {
    /// Relay Authentication Request (TS 24.501 §8.2.37).
    pub struct NasRelayAuthenticationRequest {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only],
            eap_message: NasEapMessage
        }
        optional { }
    }
}

nas_message! {
    /// Relay Authentication Response (TS 24.501 §8.2.38).
    pub struct NasRelayAuthenticationResponse {
        mandatory {
            prose_relay_transaction_identity: NasProseRelayTransactionIdentity [decode_value_only],
            eap_message: NasEapMessage
        }
        optional { }
    }
}

// ── 5GSM Messages ──────────────────────────────────────────────────────────────

nas_message! {
    /// PDU Session Establishment Request (TS 24.501 §8.3.1).
    pub struct NasPduSessionEstablishmentRequest {
        mandatory {
            integrity_protection_maximum_data_rate: NasIntegrityProtectionMaximumDataRate
        }
        optional {
            0x90 => pdu_session_type: NasPduSessionType [tv1],
            0xA0 => ssc_mode: NasSscMode [tv1],
            0x28 => fgsm_capability: NasFGsmCapability,
            0x55 => maximum_number_of_supported_packet_filters: NasMaximumNumberOfSupportedPacketFilters,
            0xB0 => always_on_pdu_session_requested: NasAlwaysOnPduSessionRequested [tv1],
            0x39 => sm_pdu_dn_request_container: NasSmPduDnRequestContainer,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x66 => ip_header_compression_configuration: NasIpHeaderCompressionConfiguration,
            0x6E => ds_tt_ethernet_port_mac_address: NasDsTtEthernetPortMacAddress,
            0x6F => ue_ds_tt_residence_time: NasUeDsTtResidenceTime,
            0x74 => port_management_information_container: NasPortManagementInformationContainer,
            0x1F => ethernet_header_compression_configuration: NasEthernetHeaderCompressionConfiguration,
            0x29 => suggested_interface_identifier: NasPduAddress,
            0x72 => service_level_aa_container: NasServiceLevelAaContainer,
            0x70 => requested_mbs_container: NasRequestedMbsContainer,
            0x34 => pdu_session_pair_id: NasPduSessionPairId,
            0x35 => rsn: NasRsn,
            0x36 => ursp_rule_enforcement_reports: NasUrspRuleEnforcementReports
        }
    }
}

nas_message! {
    /// PDU Session Establishment Accept (TS 24.501 §8.3.2).
    pub struct NasPduSessionEstablishmentAccept {
        mandatory {
            selected_pdu_session_type: NasPduSessionType,
            authorized_qos_rules: NasQosRules,
            session_ambr: NasSessionAmbr
        }
        optional {
            0x59 => fgsm_cause: NasFGsmCause,
            0x29 => pdu_address: NasPduAddress,
            0x56 => rq_timer_value: NasGprsTimer,
            0x22 => s_nssai: NasSNssai,
            0x80 => always_on_pdu_session_indication: NasAlwaysOnPduSessionIndication [tv1],
            0x75 => mapped_eps_bearer_contexts: NasMappedEpsBearerContexts,
            0x78 => eap_message: NasEapMessage [opt_type],
            0x79 => authorized_qos_flow_descriptions: NasQosFlowDescriptions,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x25 => dnn: NasDnn,
            0x17 => fgsm_network_feature_support: NasFGsmNetworkFeatureSupport,
            0x18 => serving_plmn_rate_control: NasServingPlmnRateControl,
            0x77 => atsss_container: NasAtsssContainer,
            0xC0 => control_plane_only_indication: NasControlPlaneOnlyIndication [tv1],
            0x66 => ip_header_compression_configuration: NasIpHeaderCompressionConfiguration,
            0x1F => ethernet_header_compression_configuration: NasEthernetHeaderCompressionConfiguration,
            0x72 => service_level_aa_container: NasServiceLevelAaContainer,
            0x71 => received_mbs_container: NasReceivedMbsContainer,
            0x70 => n3_qai: NasN3Qai,
            0x73 => protocol_description: NasProtocolDescription,
            0x38 => ecn_marking_l4s_indication: NasEcnMarkingL4sIndication
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
            fgsm_cause: NasFGsmCause [decode_value_only]
        }
        optional {
            0x37 => back_off_timer_value: NasGprsTimer3,
            0xF0 => allowed_ssc_mode: NasAllowedSscMode [tv1],
            0x78 => eap_message: NasEapMessage [opt_type],
            0x61 => fgsm_congestion_re_attempt_indicator: NasFGsmCongestionReAttemptIndicator,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x1D => re_attempt_indicator: NasReAttemptIndicator,
            0x72 => service_level_aa_container: NasServiceLevelAaContainer,
            0x77 => atsss_container: NasAtsssContainer
        }
    }
}

nas_message! {
    /// PDU Session Authentication Command (TS 24.501 §8.3.4).
    pub struct NasPduSessionAuthenticationCommand {
        mandatory {
            eap_message: NasEapMessage
        }
        optional {
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions
        }
    }
}

nas_message! {
    /// PDU Session Authentication Complete (TS 24.501 §8.3.5).
    pub struct NasPduSessionAuthenticationComplete {
        mandatory {
            eap_message: NasEapMessage
        }
        optional {
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions
        }
    }
}

nas_message! {
    /// PDU Session Authentication Result (TS 24.501 §8.3.6).
    pub struct NasPduSessionAuthenticationResult {
        mandatory { }
        optional {
            0x78 => eap_message: NasEapMessage [opt_type],
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions
        }
    }
}

nas_message! {
    /// PDU Session Modification Request (TS 24.501 §8.3.7).
    pub struct NasPduSessionModificationRequest {
        mandatory { }
        optional {
            0x28 => fgsm_capability: NasFGsmCapability,
            0x59 => fgsm_cause: NasFGsmCause,
            0x55 => maximum_number_of_supported_packet_filters: NasMaximumNumberOfSupportedPacketFilters,
            0xB0 => always_on_pdu_session_requested: NasAlwaysOnPduSessionRequested [tv1],
            0x13 => integrity_protection_maximum_data_rate: NasIntegrityProtectionMaximumDataRate [opt_type],
            0x7A => requested_qos_rules: NasQosRules [opt_type],
            0x79 => requested_qos_flow_descriptions: NasQosFlowDescriptions,
            0x75 => mapped_eps_bearer_contexts: NasMappedEpsBearerContexts,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x74 => port_management_information_container: NasPortManagementInformationContainer,
            0x66 => ip_header_compression_configuration: NasIpHeaderCompressionConfiguration,
            0x1F => ethernet_header_compression_configuration: NasEthernetHeaderCompressionConfiguration,
            0x70 => requested_mbs_container: NasRequestedMbsContainer,
            0x72 => service_level_aa_container: NasServiceLevelAaContainer,
            0x73 => non_3gpp_delay_budget: NasNon3GppDelayBudget,
            0x36 => ursp_rule_enforcement_reports: NasUrspRuleEnforcementReports,
            0x7C => non_3gpp_device_information: NasNon3GppDeviceInformation
        }
    }
}

nas_message! {
    /// PDU Session Modification Reject (TS 24.501 §8.3.8).
    pub struct NasPduSessionModificationReject {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only]
        }
        optional {
            0x37 => back_off_timer_value: NasGprsTimer3,
            0x61 => fgsm_congestion_re_attempt_indicator: NasFGsmCongestionReAttemptIndicator,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x1D => re_attempt_indicator: NasReAttemptIndicator
        }
    }
}

nas_message! {
    /// PDU Session Modification Command (TS 24.501 §8.3.9).
    pub struct NasPduSessionModificationCommand {
        mandatory { }
        optional {
            0x59 => fgsm_cause: NasFGsmCause,
            0x2A => session_ambr: NasSessionAmbr [opt_type],
            0x56 => rq_timer_value: NasGprsTimer,
            0x80 => always_on_pdu_session_indication: NasAlwaysOnPduSessionIndication [tv1],
            0x7A => authorized_qos_rules: NasQosRules [opt_type],
            0x75 => mapped_eps_bearer_contexts: NasMappedEpsBearerContexts,
            0x79 => authorized_qos_flow_descriptions: NasQosFlowDescriptions,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x77 => atsss_container: NasAtsssContainer,
            0x66 => ip_header_compression_configuration: NasIpHeaderCompressionConfiguration,
            0x74 => port_management_information_container: NasPortManagementInformationContainer,
            0x1E => serving_plmn_rate_control: NasServingPlmnRateControl,
            0x1F => ethernet_header_compression_configuration: NasEthernetHeaderCompressionConfiguration,
            0x71 => received_mbs_container: NasReceivedMbsContainer,
            0x72 => service_level_aa_container: NasServiceLevelAaContainer,
            0x5A => alternative_s_nssai: NasSNssai,
            0x70 => n3_qai: NasN3Qai,
            0x73 => protocol_description: NasProtocolDescription,
            0x38 => ecn_marking_l4s_indication: NasEcnMarkingL4sIndication
        }
    }
}

nas_message! {
    /// PDU Session Modification Complete (TS 24.501 §8.3.10).
    pub struct NasPduSessionModificationComplete {
        mandatory { }
        optional {
            0x59 => fgsm_cause: NasFGsmCause,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0x74 => port_management_information_container: NasPortManagementInformationContainer
        }
    }
}

nas_message! {
    /// PDU Session Modification Command Reject (TS 24.501 §8.3.11).
    pub struct NasPduSessionModificationCommandReject {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only]
        }
        optional {
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions
        }
    }
}

nas_message! {
    /// PDU Session Release Request (TS 24.501 §8.3.12).
    pub struct NasPduSessionReleaseRequest {
        mandatory { }
        optional {
            0x59 => fgsm_cause: NasFGsmCause,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions
        }
    }
}

nas_message! {
    /// PDU Session Release Reject (TS 24.501 §8.3.13).
    pub struct NasPduSessionReleaseReject {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only]
        }
        optional {
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions
        }
    }
}

nas_message! {
    /// PDU Session Release Command (TS 24.501 §8.3.14).
    pub struct NasPduSessionReleaseCommand {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only]
        }
        optional {
            0x37 => back_off_timer_value: NasGprsTimer3,
            0x78 => eap_message: NasEapMessage [opt_type],
            0x61 => fgsm_congestion_re_attempt_indicator: NasFGsmCongestionReAttemptIndicator,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions,
            0xD0 => access_type: NasAccessType [tv1],
            0x72 => service_level_aa_container: NasServiceLevelAaContainer,
            0x5A => alternative_s_nssai: NasSNssai
        }
    }
}

nas_message! {
    /// PDU Session Release Complete (TS 24.501 §8.3.15).
    pub struct NasPduSessionReleaseComplete {
        mandatory { }
        optional {
            0x59 => fgsm_cause: NasFGsmCause,
            0x7B => extended_protocol_configuration_options: NasExtendedProtocolConfigurationOptions
        }
    }
}

nas_message! {
    /// 5GSM Status (TS 24.501 §8.3.16).
    pub struct NasFGsmStatus {
        mandatory {
            fgsm_cause: NasFGsmCause [decode_value_only]
        }
        optional { }
    }
}

nas_message! {
    /// Service-Level Authentication Command (TS 24.501 §8.3.17).
    pub struct NasServiceLevelAuthenticationCommand {
        mandatory {
            service_level_aa_container: NasServiceLevelAaContainer [tlve_as_lve]
        }
        optional { }
    }
}

nas_message! {
    /// Service-Level Authentication Complete (TS 24.501 §8.3.18).
    pub struct NasServiceLevelAuthenticationComplete {
        mandatory {
            service_level_aa_container: NasServiceLevelAaContainer [tlve_as_lve]
        }
        optional { }
    }
}

nas_message! {
    /// Remote UE Report (TS 24.501 §8.3.19).
    pub struct NasRemoteUeReport {
        mandatory { }
        optional {
            0x76 => connected_remote_ue_context_list: NasRemoteUeContextList,
            0x70 => disconnected_remote_ue_context_list: NasRemoteUeContextList
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
    RegistrationRequest(NasRegistrationRequest),
    RegistrationAccept(NasRegistrationAccept),
    RegistrationComplete(NasRegistrationComplete),
    RegistrationReject(NasRegistrationReject),
    DeregistrationRequestFromUe(NasDeregistrationRequestFromUe),
    DeregistrationRequestToUe(NasDeregistrationRequestToUe),
    DeregistrationAcceptFromUe(NasDeregistrationAcceptFromUe),
    DeregistrationAcceptToUe(NasDeregistrationAcceptToUe),
    ConfigurationUpdateComplete(NasConfigurationUpdateComplete),
    ServiceRequest(NasServiceRequest),
    ServiceReject(NasServiceReject),
    ServiceAccept(NasServiceAccept),
    ConfigurationUpdateCommand(NasConfigurationUpdateCommand),
    AuthenticationRequest(NasAuthenticationRequest),
    AuthenticationResponse(NasAuthenticationResponse),
    AuthenticationReject(NasAuthenticationReject),
    AuthenticationFailure(NasAuthenticationFailure),
    AuthenticationResult(NasAuthenticationResult),
    IdentityRequest(NasIdentityRequest),
    IdentityResponse(NasIdentityResponse),
    SecurityModeCommand(NasSecurityModeCommand),
    SecurityModeComplete(NasSecurityModeComplete),
    SecurityModeReject(NasSecurityModeReject),
    FGmmStatus(NasFGmmStatus),
    Notification(NasNotification),
    NotificationResponse(NasNotificationResponse),
    UlNasTransport(NasUlNasTransport),
    DlNasTransport(NasDlNasTransport),
    ControlPlaneServiceRequest(NasControlPlaneServiceRequest),
    NetworkSliceSpecificAuthenticationCommand(NasNetworkSliceSpecificAuthenticationCommand),
    NetworkSliceSpecificAuthenticationComplete(NasNetworkSliceSpecificAuthenticationComplete),
    NetworkSliceSpecificAuthenticationResult(NasNetworkSliceSpecificAuthenticationResult),
    RelayKeyRequest(NasRelayKeyRequest),
    RelayKeyAccept(NasRelayKeyAccept),
    RelayKeyReject(NasRelayKeyReject),
    RelayAuthenticationRequest(NasRelayAuthenticationRequest),
    RelayAuthenticationResponse(NasRelayAuthenticationResponse),
}

impl Nas5gmmMessage {
    pub fn message_type(&self) -> Nas5gmmMessageType {
        self.get_message_type()
    }

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
    PduSessionEstablishmentRequest(NasPduSessionEstablishmentRequest),
    PduSessionEstablishmentAccept(NasPduSessionEstablishmentAccept),
    PduSessionEstablishmentReject(NasPduSessionEstablishmentReject),
    PduSessionAuthenticationCommand(NasPduSessionAuthenticationCommand),
    PduSessionAuthenticationComplete(NasPduSessionAuthenticationComplete),
    PduSessionAuthenticationResult(NasPduSessionAuthenticationResult),
    PduSessionModificationRequest(NasPduSessionModificationRequest),
    PduSessionModificationReject(NasPduSessionModificationReject),
    PduSessionModificationCommand(NasPduSessionModificationCommand),
    PduSessionModificationComplete(NasPduSessionModificationComplete),
    PduSessionModificationCommandReject(NasPduSessionModificationCommandReject),
    PduSessionReleaseRequest(NasPduSessionReleaseRequest),
    PduSessionReleaseReject(NasPduSessionReleaseReject),
    PduSessionReleaseCommand(NasPduSessionReleaseCommand),
    PduSessionReleaseComplete(NasPduSessionReleaseComplete),
    FGsmStatus(NasFGsmStatus),
    ServiceLevelAuthenticationCommand(NasServiceLevelAuthenticationCommand),
    ServiceLevelAuthenticationComplete(NasServiceLevelAuthenticationComplete),
    RemoteUeReport(NasRemoteUeReport),
    RemoteUeReportResponse(NasRemoteUeReportResponse),
}

impl Nas5gsmMessage {
    pub fn message_type(&self) -> Nas5gsmMessageType {
        self.get_message_type()
    }

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
            return Err(NasError::BufferTooShort);
        }

        match buffer[0] {
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM => {
                if buffer.remaining() < 2 {
                    return Err(NasError::BufferTooShort);
                }

                let security_header_type_octet = buffer[1];
                if security_header_type_octet & 0xF0 != 0 {
                    return Err(NasError::DecodingError(format!(
                        "5GMM plain header spare half octet shall be zero, got 0x{:02X}",
                        security_header_type_octet
                    )));
                }

                let security_header_type =
                    Nas5gsSecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;
                if security_header_type != Nas5gsSecurityHeaderType::PlainNasMessage {
                    return Err(NasError::DecodingError(format!(
                        "Plain 5GS NAS message cannot carry security header type {:?}",
                        security_header_type
                    )));
                }

                let header = Nas5gmmHeader::decode(buffer)?;
                let message = Nas5gmmMessage::try_from((header.message_type, buffer))?;

                Ok(Nas5gsMessage::Gmm(header, message))
            }
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM => {
                let header = Nas5gsmHeader::decode(buffer)?;
                let message = Nas5gsmMessage::try_from((header.message_type, buffer))?;

                Ok(Nas5gsMessage::Gsm(header, message))
            }
            epd => Err(NasError::DecodingError(format!(
                "Unknown Extended Protocol Discriminator: {}",
                epd
            ))),
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
                    _ => validate_security_protected_inner_message(
                        message,
                        header.security_header_type,
                    )?,
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
            return Err(NasError::BufferTooShort);
        }

        match buffer[0] {
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM => {
                if buffer.remaining() < 2 {
                    return Err(NasError::BufferTooShort);
                }

                let security_header_type_octet = buffer[1];
                if security_header_type_octet & 0xF0 != 0 {
                    return Err(NasError::DecodingError(format!(
                        "5GMM header spare half octet shall be zero, got 0x{:02X}",
                        security_header_type_octet
                    )));
                }

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
                                return Err(NasError::BufferTooShort);
                            }
                            Self::Opaque(buffer.copy_to_bytes(buffer.remaining()).to_vec())
                        } else {
                            let plain_message = Self::decode_plain(buffer)?;
                            validate_security_protected_inner_message(&plain_message, sht)
                                .map_err(|err| match err {
                                    NasError::EncodingError(message)
                                    | NasError::DecodingError(message) => {
                                        NasError::DecodingError(message)
                                    }
                                    other => other,
                                })?;
                            plain_message
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
    fn reserved_5gsm_pti_is_rejected() {
        let header = Nas5gsmHeader::new(Nas5gsmMessageType::PduSessionEstablishmentRequest, 1, 255);
        assert!(header.encode(&mut BytesMut::new()).is_err());
        assert!(Nas5gsmHeader::decode(&mut Bytes::from_static(&[0x2e, 1, 255, 193])).is_err());
    }
}
