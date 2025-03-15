/*
    OxiRush
    Copyright 2025 Valentin D'Emmanuele

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

use crate::types::*;
use crate::message_types::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;
use crate::types::helpers;

/// PDU Session Identity value for unassigned
pub const PDU_SESSION_IDENTITY_UNASSIGNED: u8 = 0;

/// 5GMM Header
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nas5gmmHeader {
    pub extended_protocol_discriminator: u8,
    pub security_header_type: u8,
    pub message_type: Nas5gmmMessageType,
}

impl Nas5gmmHeader {
    pub fn new(message_type: Nas5gmmMessageType) -> Self {
        Self {
            extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM,
            security_header_type: 0,
            message_type,
        }
    }
}

impl Encode for Nas5gmmHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        buffer.put_u8(self.extended_protocol_discriminator);
        buffer.put_u8(self.security_header_type);
        buffer.put_u8(self.message_type as u8);
        Ok(())
    }
}

impl Decode for Nas5gmmHeader {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 3 {
            return Err(NasError::BufferTooShort);
        }
        
        let extended_protocol_discriminator = buffer.get_u8();
        let security_header_type = buffer.get_u8();
        let message_type_value = buffer.get_u8();
        
        let message_type = Nas5gmmMessageType::try_from(message_type_value)?;
        
        Ok(Self {
            extended_protocol_discriminator,
            security_header_type,
            message_type,
        })
    }
}

/// 5GSM Header
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Nas5gsmHeader {
    pub extended_protocol_discriminator: u8,
    pub pdu_session_identity: u8,
    pub procedure_transaction_identity: u8,
    pub message_type: Nas5gsmMessageType,
}

impl Nas5gsmHeader {
    pub fn new(message_type: Nas5gsmMessageType, pdu_session_identity: u8, procedure_transaction_identity: u8) -> Self {
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
        buffer.put_u8(self.extended_protocol_discriminator);
        buffer.put_u8(self.pdu_session_identity);
        buffer.put_u8(self.procedure_transaction_identity);
        buffer.put_u8(self.message_type as u8);
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
        
        Ok(Self {
            extended_protocol_discriminator,
            pdu_session_identity,
            procedure_transaction_identity,
            message_type,
        })
    }
}

/// 5GS Security Header
#[derive(Debug, Clone, PartialEq)]
pub struct Nas5gsSecurityHeader {
    pub extended_protocol_discriminator: u8,
    pub security_header_type: Nas5gsSecurityHeaderType,
    pub message_authentication_code: u32,
    pub sequence_number: u8,
}

impl Encode for Nas5gsSecurityHeader {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
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
        let security_header_type_value = buffer.get_u8();
        let message_authentication_code = buffer.get_u32();
        let sequence_number = buffer.get_u8();
        
        let security_header_type = Nas5gsSecurityHeaderType::try_from(security_header_type_value)?;
        
        Ok(Self {
            extended_protocol_discriminator,
            security_header_type,
            message_authentication_code,
            sequence_number,
        })
    }
}

/// REGISTRATION REQUEST Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasRegistrationRequest {
    // Mandatory fields
    pub fgs_registration_type: NasFGsRegistrationType,
    pub fgs_mobile_identity: NasFGsMobileIdentity,

    // Optional fields
    pub non_current_native_nas_key_set_identifier: Option<NasKeySetIdentifier>,
    pub fgmm_capability: Option<NasFGmmCapability>,
    pub ue_security_capability: Option<NasUeSecurityCapability>,
    pub requested_nssai: Option<NasNssai>,
    pub last_visited_registered_tai: Option<NasFGsTrackingAreaIdentity>,
    pub s1_ue_network_capability: Option<NasS1UeNetworkCapability>,
    pub uplink_data_status: Option<NasUplinkDataStatus>,
    pub pdu_session_status: Option<NasPduSessionStatus>,
    pub mico_indication: Option<NasMicoIndication>,
    pub ue_status: Option<NasUeStatus>,
    pub additional_guti: Option<NasFGsMobileIdentity>,
    pub allowed_pdu_session_status: Option<NasAllowedPduSessionStatus>,
    pub ue_usage_setting: Option<NasUeUsageSetting>,
    pub requested_drx_parameters: Option<NasFGsDrxParameters>,
    pub eps_nas_message_container: Option<NasEpsNasMessageContainer>,
    pub ladn_indication: Option<NasLadnIndication>,
    pub payload_container_type: Option<NasPayloadContainerType>,
    pub payload_container: Option<NasPayloadContainer>,
    pub network_slicing_indication: Option<NasNetworkSlicingIndication>,
    pub fgs_update_type: Option<NasFGsUpdateType>,
    pub mobile_station_classmark_2: Option<NasMobileStationClassmark2>,
    pub supported_codecs: Option<NasSupportedCodecList>,
    pub nas_message_container: Option<NasMessageContainer>,
    pub eps_bearer_context_status: Option<NasEpsBearerContextStatus>,
    pub requested_extended_drx_parameters: Option<NasExtendedDrxParameters>,
    pub t3324_value: Option<NasGprsTimer3>,
    pub ue_radio_capability_id: Option<NasUeRadioCapabilityId>,
    pub requested_mapped_nssai: Option<NasMappedNssai>,
    pub additional_information_requested: Option<NasAdditionalInformationRequested>,
    pub requested_wus_assistance_information: Option<NasWusAssistanceInformation>,
    pub nfgc_indication: Option<NasNFGcIndication>,
    pub requested_nb_n1_mode_drx_parameters: Option<NasNbN1ModeDrxParameters>,
    pub ue_request_type: Option<NasUeRequestType>,
    pub paging_restriction: Option<NasPagingRestriction>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
    pub nid: Option<NasNid>,
    pub ms_determined_plmn_with_disaster_condition: Option<NasPlmnIdentity>,
    pub requested_peips_assistance_information: Option<NasPeipsAssistanceInformation>,
    pub requested_t3512_value: Option<NasGprsTimer3>,
}

impl NasRegistrationRequest {
    pub fn new(
        fgs_registration_type: NasFGsRegistrationType,
        fgs_mobile_identity: NasFGsMobileIdentity,
    ) -> Self {
        Self {
            fgs_registration_type,
            fgs_mobile_identity,
            non_current_native_nas_key_set_identifier: None,
            fgmm_capability: None,
            ue_security_capability: None,
            requested_nssai: None,
            last_visited_registered_tai: None,
            s1_ue_network_capability: None,
            uplink_data_status: None,
            pdu_session_status: None,
            mico_indication: None,
            ue_status: None,
            additional_guti: None,
            allowed_pdu_session_status: None,
            ue_usage_setting: None,
            requested_drx_parameters: None,
            eps_nas_message_container: None,
            ladn_indication: None,
            payload_container_type: None,
            payload_container: None,
            network_slicing_indication: None,
            fgs_update_type: None,
            mobile_station_classmark_2: None,
            supported_codecs: None,
            nas_message_container: None,
            eps_bearer_context_status: None,
            requested_extended_drx_parameters: None,
            t3324_value: None,
            ue_radio_capability_id: None,
            requested_mapped_nssai: None,
            additional_information_requested: None,
            requested_wus_assistance_information: None,
            nfgc_indication: None,
            requested_nb_n1_mode_drx_parameters: None,
            ue_request_type: None,
            paging_restriction: None,
            service_level_aa_container: None,
            nid: None,
            ms_determined_plmn_with_disaster_condition: None,
            requested_peips_assistance_information: None,
            requested_t3512_value: None,
        }
    }

    pub fn set_non_current_native_nas_key_set_identifier(mut self, value: NasKeySetIdentifier) -> Self {
        self.non_current_native_nas_key_set_identifier = Some(value);
        self
    }

    pub fn set_fgmm_capability(mut self, value: NasFGmmCapability) -> Self {
        self.fgmm_capability = Some(value);
        self
    }

    pub fn set_ue_security_capability(mut self, value: NasUeSecurityCapability) -> Self {
        self.ue_security_capability = Some(value);
        self
    }

    pub fn set_requested_nssai(mut self, value: NasNssai) -> Self {
        self.requested_nssai = Some(value);
        self
    }

    pub fn set_last_visited_registered_tai(mut self, value: NasFGsTrackingAreaIdentity) -> Self {
        self.last_visited_registered_tai = Some(value);
        self
    }

    pub fn set_s1_ue_network_capability(mut self, value: NasS1UeNetworkCapability) -> Self {
        self.s1_ue_network_capability = Some(value);
        self
    }

    pub fn set_uplink_data_status(mut self, value: NasUplinkDataStatus) -> Self {
        self.uplink_data_status = Some(value);
        self
    }

    pub fn set_pdu_session_status(mut self, value: NasPduSessionStatus) -> Self {
        self.pdu_session_status = Some(value);
        self
    }

    pub fn set_mico_indication(mut self, value: NasMicoIndication) -> Self {
        self.mico_indication = Some(value);
        self
    }

    pub fn set_ue_status(mut self, value: NasUeStatus) -> Self {
        self.ue_status = Some(value);
        self
    }

    pub fn set_additional_guti(mut self, value: NasFGsMobileIdentity) -> Self {
        self.additional_guti = Some(value);
        self
    }

    pub fn set_allowed_pdu_session_status(mut self, value: NasAllowedPduSessionStatus) -> Self {
        self.allowed_pdu_session_status = Some(value);
        self
    }

    pub fn set_ue_usage_setting(mut self, value: NasUeUsageSetting) -> Self {
        self.ue_usage_setting = Some(value);
        self
    }

    pub fn set_requested_drx_parameters(mut self, value: NasFGsDrxParameters) -> Self {
        self.requested_drx_parameters = Some(value);
        self
    }

    pub fn set_eps_nas_message_container(mut self, value: NasEpsNasMessageContainer) -> Self {
        self.eps_nas_message_container = Some(value);
        self
    }

    pub fn set_ladn_indication(mut self, value: NasLadnIndication) -> Self {
        self.ladn_indication = Some(value);
        self
    }

    pub fn set_payload_container_type(mut self, value: NasPayloadContainerType) -> Self {
        self.payload_container_type = Some(value);
        self
    }

    pub fn set_payload_container(mut self, value: NasPayloadContainer) -> Self {
        self.payload_container = Some(value);
        self
    }

    pub fn set_network_slicing_indication(mut self, value: NasNetworkSlicingIndication) -> Self {
        self.network_slicing_indication = Some(value);
        self
    }

    pub fn set_fgs_update_type(mut self, value: NasFGsUpdateType) -> Self {
        self.fgs_update_type = Some(value);
        self
    }

    pub fn set_mobile_station_classmark_2(mut self, value: NasMobileStationClassmark2) -> Self {
        self.mobile_station_classmark_2 = Some(value);
        self
    }

    pub fn set_supported_codecs(mut self, value: NasSupportedCodecList) -> Self {
        self.supported_codecs = Some(value);
        self
    }

    pub fn set_nas_message_container(mut self, value: NasMessageContainer) -> Self {
        self.nas_message_container = Some(value);
        self
    }

    pub fn set_eps_bearer_context_status(mut self, value: NasEpsBearerContextStatus) -> Self {
        self.eps_bearer_context_status = Some(value);
        self
    }

    pub fn set_requested_extended_drx_parameters(mut self, value: NasExtendedDrxParameters) -> Self {
        self.requested_extended_drx_parameters = Some(value);
        self
    }

    pub fn set_t3324_value(mut self, value: NasGprsTimer3) -> Self {
        self.t3324_value = Some(value);
        self
    }

    pub fn set_ue_radio_capability_id(mut self, value: NasUeRadioCapabilityId) -> Self {
        self.ue_radio_capability_id = Some(value);
        self
    }

    pub fn set_requested_mapped_nssai(mut self, value: NasMappedNssai) -> Self {
        self.requested_mapped_nssai = Some(value);
        self
    }

    pub fn set_additional_information_requested(mut self, value: NasAdditionalInformationRequested) -> Self {
        self.additional_information_requested = Some(value);
        self
    }

    pub fn set_requested_wus_assistance_information(mut self, value: NasWusAssistanceInformation) -> Self {
        self.requested_wus_assistance_information = Some(value);
        self
    }

    pub fn set_nfgc_indication(mut self, value: NasNFGcIndication) -> Self {
        self.nfgc_indication = Some(value);
        self
    }

    pub fn set_requested_nb_n1_mode_drx_parameters(mut self, value: NasNbN1ModeDrxParameters) -> Self {
        self.requested_nb_n1_mode_drx_parameters = Some(value);
        self
    }

    pub fn set_ue_request_type(mut self, value: NasUeRequestType) -> Self {
        self.ue_request_type = Some(value);
        self
    }

    pub fn set_paging_restriction(mut self, value: NasPagingRestriction) -> Self {
        self.paging_restriction = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }

    pub fn set_nid(mut self, value: NasNid) -> Self {
        self.nid = Some(value);
        self
    }

    pub fn set_ms_determined_plmn_with_disaster_condition(mut self, value: NasPlmnIdentity) -> Self {
        self.ms_determined_plmn_with_disaster_condition = Some(value);
        self
    }

    pub fn set_requested_peips_assistance_information(mut self, value: NasPeipsAssistanceInformation) -> Self {
        self.requested_peips_assistance_information = Some(value);
        self
    }

    pub fn set_requested_t3512_value(mut self, value: NasGprsTimer3) -> Self {
        self.requested_t3512_value = Some(value);
        self
    }
}

impl Encode for NasRegistrationRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgs_registration_type.encode(buffer)?;
        self.fgs_mobile_identity.encode(buffer)?;
        if let Some(ref value) = self.non_current_native_nas_key_set_identifier {
            helpers::encode_optional_type(buffer, 0xC0)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.fgmm_capability {
            let mut ie = value.clone();
            ie.type_field = 0x10;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_security_capability {
            helpers::encode_optional_type(buffer, 0x2E)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x2F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.last_visited_registered_tai {
            let mut ie = value.clone();
            ie.type_field = 0x52;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.s1_ue_network_capability {
            let mut ie = value.clone();
            ie.type_field = 0x17;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.uplink_data_status {
            let mut ie = value.clone();
            ie.type_field = 0x40;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_session_status {
            let mut ie = value.clone();
            ie.type_field = 0x50;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.mico_indication {
            let mut ie = value.clone();
            ie.type_field = 0xB0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_status {
            let mut ie = value.clone();
            ie.type_field = 0x2B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.additional_guti {
            helpers::encode_optional_type(buffer, 0x77)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.allowed_pdu_session_status {
            let mut ie = value.clone();
            ie.type_field = 0x25;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_usage_setting {
            let mut ie = value.clone();
            ie.type_field = 0x18;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_drx_parameters {
            let mut ie = value.clone();
            ie.type_field = 0x51;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eps_nas_message_container {
            let mut ie = value.clone();
            ie.type_field = 0x70;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ladn_indication {
            let mut ie = value.clone();
            ie.type_field = 0x74;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.payload_container_type {
            helpers::encode_optional_type(buffer, 0x80)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.payload_container {
            helpers::encode_optional_type(buffer, 0x7B)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.network_slicing_indication {
            let mut ie = value.clone();
            ie.type_field = 0x90;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgs_update_type {
            let mut ie = value.clone();
            ie.type_field = 0x53;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.mobile_station_classmark_2 {
            let mut ie = value.clone();
            ie.type_field = 0x41;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.supported_codecs {
            let mut ie = value.clone();
            ie.type_field = 0x42;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nas_message_container {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eps_bearer_context_status {
            let mut ie = value.clone();
            ie.type_field = 0x60;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_extended_drx_parameters {
            let mut ie = value.clone();
            ie.type_field = 0x6E;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3324_value {
            let mut ie = value.clone();
            ie.type_field = 0x6A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_radio_capability_id {
            let mut ie = value.clone();
            ie.type_field = 0x67;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_mapped_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x35;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.additional_information_requested {
            let mut ie = value.clone();
            ie.type_field = 0x48;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_wus_assistance_information {
            let mut ie = value.clone();
            ie.type_field = 0x1A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nfgc_indication {
            let mut ie = value.clone();
            ie.type_field = 0xA0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_nb_n1_mode_drx_parameters {
            let mut ie = value.clone();
            ie.type_field = 0x30;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_request_type {
            let mut ie = value.clone();
            ie.type_field = 0x29;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.paging_restriction {
            let mut ie = value.clone();
            ie.type_field = 0x28;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nid {
            let mut ie = value.clone();
            ie.type_field = 0x32;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ms_determined_plmn_with_disaster_condition {
            let mut ie = value.clone();
            ie.type_field = 0x16;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_peips_assistance_information {
            let mut ie = value.clone();
            ie.type_field = 0x2A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_t3512_value {
            let mut ie = value.clone();
            ie.type_field = 0x3B;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasRegistrationRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgs_registration_type = NasFGsRegistrationType::decode(buffer)?;
        let fgs_mobile_identity = NasFGsMobileIdentity::decode(buffer)?;

        let mut message = Self::new(
            fgs_registration_type,
            fgs_mobile_identity,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0xC0 => {
                    buffer.advance(1); // Skip IEI
                    message.non_current_native_nas_key_set_identifier = Some(NasKeySetIdentifier::decode(buffer)?);
                },
                0x10 => {
                    message.fgmm_capability = Some(NasFGmmCapability::decode(buffer)?);
                },
                0x2E => {
                    buffer.advance(1); // Skip IEI
                    message.ue_security_capability = Some(NasUeSecurityCapability::decode(buffer)?);
                },
                0x2F => {
                    message.requested_nssai = Some(NasNssai::decode(buffer)?);
                },
                0x52 => {
                    message.last_visited_registered_tai = Some(NasFGsTrackingAreaIdentity::decode(buffer)?);
                },
                0x17 => {
                    message.s1_ue_network_capability = Some(NasS1UeNetworkCapability::decode(buffer)?);
                },
                0x40 => {
                    message.uplink_data_status = Some(NasUplinkDataStatus::decode(buffer)?);
                },
                0x50 => {
                    message.pdu_session_status = Some(NasPduSessionStatus::decode(buffer)?);
                },
                0xB0 => {
                    message.mico_indication = Some(NasMicoIndication::decode(buffer)?);
                },
                0x2B => {
                    message.ue_status = Some(NasUeStatus::decode(buffer)?);
                },
                0x77 => {
                    buffer.advance(1); // Skip IEI
                    message.additional_guti = Some(NasFGsMobileIdentity::decode(buffer)?);
                },
                0x25 => {
                    message.allowed_pdu_session_status = Some(NasAllowedPduSessionStatus::decode(buffer)?);
                },
                0x18 => {
                    message.ue_usage_setting = Some(NasUeUsageSetting::decode(buffer)?);
                },
                0x51 => {
                    message.requested_drx_parameters = Some(NasFGsDrxParameters::decode(buffer)?);
                },
                0x70 => {
                    message.eps_nas_message_container = Some(NasEpsNasMessageContainer::decode(buffer)?);
                },
                0x74 => {
                    message.ladn_indication = Some(NasLadnIndication::decode(buffer)?);
                },
                0x80 => {
                    buffer.advance(1); // Skip IEI
                    message.payload_container_type = Some(NasPayloadContainerType::decode(buffer)?);
                },
                0x7B => {
                    buffer.advance(1); // Skip IEI
                    message.payload_container = Some(NasPayloadContainer::decode(buffer)?);
                },
                0x90 => {
                    message.network_slicing_indication = Some(NasNetworkSlicingIndication::decode(buffer)?);
                },
                0x53 => {
                    message.fgs_update_type = Some(NasFGsUpdateType::decode(buffer)?);
                },
                0x41 => {
                    message.mobile_station_classmark_2 = Some(NasMobileStationClassmark2::decode(buffer)?);
                },
                0x42 => {
                    message.supported_codecs = Some(NasSupportedCodecList::decode(buffer)?);
                },
                0x71 => {
                    message.nas_message_container = Some(NasMessageContainer::decode(buffer)?);
                },
                0x60 => {
                    message.eps_bearer_context_status = Some(NasEpsBearerContextStatus::decode(buffer)?);
                },
                0x6E => {
                    message.requested_extended_drx_parameters = Some(NasExtendedDrxParameters::decode(buffer)?);
                },
                0x6A => {
                    message.t3324_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x67 => {
                    message.ue_radio_capability_id = Some(NasUeRadioCapabilityId::decode(buffer)?);
                },
                0x35 => {
                    message.requested_mapped_nssai = Some(NasMappedNssai::decode(buffer)?);
                },
                0x48 => {
                    message.additional_information_requested = Some(NasAdditionalInformationRequested::decode(buffer)?);
                },
                0x1A => {
                    message.requested_wus_assistance_information = Some(NasWusAssistanceInformation::decode(buffer)?);
                },
                0xA0 => {
                    message.nfgc_indication = Some(NasNFGcIndication::decode(buffer)?);
                },
                0x30 => {
                    message.requested_nb_n1_mode_drx_parameters = Some(NasNbN1ModeDrxParameters::decode(buffer)?);
                },
                0x29 => {
                    message.ue_request_type = Some(NasUeRequestType::decode(buffer)?);
                },
                0x28 => {
                    message.paging_restriction = Some(NasPagingRestriction::decode(buffer)?);
                },
                0x72 => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                0x32 => {
                    message.nid = Some(NasNid::decode(buffer)?);
                },
                0x16 => {
                    message.ms_determined_plmn_with_disaster_condition = Some(NasPlmnIdentity::decode(buffer)?);
                },
                0x2A => {
                    message.requested_peips_assistance_information = Some(NasPeipsAssistanceInformation::decode(buffer)?);
                },
                0x3B => {
                    message.requested_t3512_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// REGISTRATION ACCEPT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasRegistrationAccept {
    // Mandatory fields
    pub fgs_registration_result: NasFGsRegistrationResult,

    // Optional fields
    pub fg_guti: Option<NasFGsMobileIdentity>,
    pub equivalent_plmns: Option<NasPlmnList>,
    pub tai_list: Option<NasFGsTrackingAreaIdentityList>,
    pub allowed_nssai: Option<NasNssai>,
    pub rejected_nssai: Option<NasRejectedNssai>,
    pub configured_nssai: Option<NasNssai>,
    pub fgs_network_feature_support: Option<NasFGsNetworkFeatureSupport>,
    pub pdu_session_status: Option<NasPduSessionStatus>,
    pub pdu_session_reactivation_result: Option<NasPduSessionReactivationResult>,
    pub pdu_session_reactivation_result_error_cause: Option<NasPduSessionReactivationResultErrorCause>,
    pub ladn_information: Option<NasLadnInformation>,
    pub mico_indication: Option<NasMicoIndication>,
    pub network_slicing_indication: Option<NasNetworkSlicingIndication>,
    pub service_area_list: Option<NasServiceAreaList>,
    pub t3512_value: Option<NasGprsTimer3>,
    pub non_3gpp_de_registration_timer_value: Option<NasGprsTimer2>,
    pub t3502_value: Option<NasGprsTimer2>,
    pub emergency_number_list: Option<NasEmergencyNumberList>,
    pub extended_emergency_number_list: Option<NasExtendedEmergencyNumberList>,
    pub sor_transparent_container: Option<NasSorTransparentContainer>,
    pub eap_message: Option<NasEapMessage>,
    pub nssai_inclusion_mode: Option<NasNssaiInclusionMode>,
    pub operator_defined_access_category_definitions: Option<NasOperatorDefinedAccessCategoryDefinitions>,
    pub negotiated_drx_parameters: Option<NasFGsDrxParameters>,
    pub non_3gpp_nw_policies: Option<NasNon3GppNwProvidedPolicies>,
    pub eps_bearer_context_status: Option<NasEpsBearerContextStatus>,
    pub negotiated_extended_drx_parameters: Option<NasExtendedDrxParameters>,
    pub t3447_value: Option<NasGprsTimer3>,
    pub t3448_value: Option<NasGprsTimer2>,
    pub t3324_value: Option<NasGprsTimer3>,
    pub ue_radio_capability_id: Option<NasUeRadioCapabilityId>,
    pub ue_radio_capability_id_deletion_indication: Option<NasUeRadioCapabilityIdDeletionIndication>,
    pub pending_nssai: Option<NasNssai>,
    pub ciphering_key_data: Option<NasCipheringKeyData>,
    pub cag_information_list: Option<NasCagInformationList>,
    pub truncated_fg_s_tmsi_configuration: Option<NasTruncatedFGSTmsiConfiguration>,
    pub negotiated_wus_assistance_information: Option<NasWusAssistanceInformation>,
    pub negotiated_nb_n1_mode_drx_parameters: Option<NasNbN1ModeDrxParameters>,
    pub extended_rejected_nssai: Option<NasExtendedRejectedNssai>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
    pub negotiated_peips_assistance_information: Option<NasPeipsAssistanceInformation>,
    pub fgs_additional_request_result: Option<NasFGsAdditionalRequestResult>,
    pub nssrg_information: Option<NasNssrgInformation>,
    pub disaster_roaming_wait_range: Option<NasRegistrationWaitRange>,
    pub disaster_return_wait_range: Option<NasRegistrationWaitRange>,
    pub list_of_plmns_to_be_used_in_disaster_condition: Option<NasListOfPlmnsToBeUsedInDisasterCondition>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: Option<NasFGsTrackingAreaIdentityList>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: Option<NasFGsTrackingAreaIdentityList>,
    pub extended_cag_information_list: Option<NasExtendedCagInformationList>,
    pub nsag_information: Option<NasNsagInformation>,
}

impl NasRegistrationAccept {
    pub fn new(
        fgs_registration_result: NasFGsRegistrationResult,
    ) -> Self {
        Self {
            fgs_registration_result,
            fg_guti: None,
            equivalent_plmns: None,
            tai_list: None,
            allowed_nssai: None,
            rejected_nssai: None,
            configured_nssai: None,
            fgs_network_feature_support: None,
            pdu_session_status: None,
            pdu_session_reactivation_result: None,
            pdu_session_reactivation_result_error_cause: None,
            ladn_information: None,
            mico_indication: None,
            network_slicing_indication: None,
            service_area_list: None,
            t3512_value: None,
            non_3gpp_de_registration_timer_value: None,
            t3502_value: None,
            emergency_number_list: None,
            extended_emergency_number_list: None,
            sor_transparent_container: None,
            eap_message: None,
            nssai_inclusion_mode: None,
            operator_defined_access_category_definitions: None,
            negotiated_drx_parameters: None,
            non_3gpp_nw_policies: None,
            eps_bearer_context_status: None,
            negotiated_extended_drx_parameters: None,
            t3447_value: None,
            t3448_value: None,
            t3324_value: None,
            ue_radio_capability_id: None,
            ue_radio_capability_id_deletion_indication: None,
            pending_nssai: None,
            ciphering_key_data: None,
            cag_information_list: None,
            truncated_fg_s_tmsi_configuration: None,
            negotiated_wus_assistance_information: None,
            negotiated_nb_n1_mode_drx_parameters: None,
            extended_rejected_nssai: None,
            service_level_aa_container: None,
            negotiated_peips_assistance_information: None,
            fgs_additional_request_result: None,
            nssrg_information: None,
            disaster_roaming_wait_range: None,
            disaster_return_wait_range: None,
            list_of_plmns_to_be_used_in_disaster_condition: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: None,
            extended_cag_information_list: None,
            nsag_information: None,
        }
    }

    pub fn set_fg_guti(mut self, value: NasFGsMobileIdentity) -> Self {
        self.fg_guti = Some(value);
        self
    }

    pub fn set_equivalent_plmns(mut self, value: NasPlmnList) -> Self {
        self.equivalent_plmns = Some(value);
        self
    }

    pub fn set_tai_list(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.tai_list = Some(value);
        self
    }

    pub fn set_allowed_nssai(mut self, value: NasNssai) -> Self {
        self.allowed_nssai = Some(value);
        self
    }

    pub fn set_rejected_nssai(mut self, value: NasRejectedNssai) -> Self {
        self.rejected_nssai = Some(value);
        self
    }

    pub fn set_configured_nssai(mut self, value: NasNssai) -> Self {
        self.configured_nssai = Some(value);
        self
    }

    pub fn set_fgs_network_feature_support(mut self, value: NasFGsNetworkFeatureSupport) -> Self {
        self.fgs_network_feature_support = Some(value);
        self
    }

    pub fn set_pdu_session_status(mut self, value: NasPduSessionStatus) -> Self {
        self.pdu_session_status = Some(value);
        self
    }

    pub fn set_pdu_session_reactivation_result(mut self, value: NasPduSessionReactivationResult) -> Self {
        self.pdu_session_reactivation_result = Some(value);
        self
    }

    pub fn set_pdu_session_reactivation_result_error_cause(mut self, value: NasPduSessionReactivationResultErrorCause) -> Self {
        self.pdu_session_reactivation_result_error_cause = Some(value);
        self
    }

    pub fn set_ladn_information(mut self, value: NasLadnInformation) -> Self {
        self.ladn_information = Some(value);
        self
    }

    pub fn set_mico_indication(mut self, value: NasMicoIndication) -> Self {
        self.mico_indication = Some(value);
        self
    }

    pub fn set_network_slicing_indication(mut self, value: NasNetworkSlicingIndication) -> Self {
        self.network_slicing_indication = Some(value);
        self
    }

    pub fn set_service_area_list(mut self, value: NasServiceAreaList) -> Self {
        self.service_area_list = Some(value);
        self
    }

    pub fn set_t3512_value(mut self, value: NasGprsTimer3) -> Self {
        self.t3512_value = Some(value);
        self
    }

    pub fn set_non_3gpp_de_registration_timer_value(mut self, value: NasGprsTimer2) -> Self {
        self.non_3gpp_de_registration_timer_value = Some(value);
        self
    }

    pub fn set_t3502_value(mut self, value: NasGprsTimer2) -> Self {
        self.t3502_value = Some(value);
        self
    }

    pub fn set_emergency_number_list(mut self, value: NasEmergencyNumberList) -> Self {
        self.emergency_number_list = Some(value);
        self
    }

    pub fn set_extended_emergency_number_list(mut self, value: NasExtendedEmergencyNumberList) -> Self {
        self.extended_emergency_number_list = Some(value);
        self
    }

    pub fn set_sor_transparent_container(mut self, value: NasSorTransparentContainer) -> Self {
        self.sor_transparent_container = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_nssai_inclusion_mode(mut self, value: NasNssaiInclusionMode) -> Self {
        self.nssai_inclusion_mode = Some(value);
        self
    }

    pub fn set_operator_defined_access_category_definitions(mut self, value: NasOperatorDefinedAccessCategoryDefinitions) -> Self {
        self.operator_defined_access_category_definitions = Some(value);
        self
    }

    pub fn set_negotiated_drx_parameters(mut self, value: NasFGsDrxParameters) -> Self {
        self.negotiated_drx_parameters = Some(value);
        self
    }

    pub fn set_non_3gpp_nw_policies(mut self, value: NasNon3GppNwProvidedPolicies) -> Self {
        self.non_3gpp_nw_policies = Some(value);
        self
    }

    pub fn set_eps_bearer_context_status(mut self, value: NasEpsBearerContextStatus) -> Self {
        self.eps_bearer_context_status = Some(value);
        self
    }

    pub fn set_negotiated_extended_drx_parameters(mut self, value: NasExtendedDrxParameters) -> Self {
        self.negotiated_extended_drx_parameters = Some(value);
        self
    }

    pub fn set_t3447_value(mut self, value: NasGprsTimer3) -> Self {
        self.t3447_value = Some(value);
        self
    }

    pub fn set_t3448_value(mut self, value: NasGprsTimer2) -> Self {
        self.t3448_value = Some(value);
        self
    }

    pub fn set_t3324_value(mut self, value: NasGprsTimer3) -> Self {
        self.t3324_value = Some(value);
        self
    }

    pub fn set_ue_radio_capability_id(mut self, value: NasUeRadioCapabilityId) -> Self {
        self.ue_radio_capability_id = Some(value);
        self
    }

    pub fn set_ue_radio_capability_id_deletion_indication(mut self, value: NasUeRadioCapabilityIdDeletionIndication) -> Self {
        self.ue_radio_capability_id_deletion_indication = Some(value);
        self
    }

    pub fn set_pending_nssai(mut self, value: NasNssai) -> Self {
        self.pending_nssai = Some(value);
        self
    }

    pub fn set_ciphering_key_data(mut self, value: NasCipheringKeyData) -> Self {
        self.ciphering_key_data = Some(value);
        self
    }

    pub fn set_cag_information_list(mut self, value: NasCagInformationList) -> Self {
        self.cag_information_list = Some(value);
        self
    }

    pub fn set_truncated_fg_s_tmsi_configuration(mut self, value: NasTruncatedFGSTmsiConfiguration) -> Self {
        self.truncated_fg_s_tmsi_configuration = Some(value);
        self
    }

    pub fn set_negotiated_wus_assistance_information(mut self, value: NasWusAssistanceInformation) -> Self {
        self.negotiated_wus_assistance_information = Some(value);
        self
    }

    pub fn set_negotiated_nb_n1_mode_drx_parameters(mut self, value: NasNbN1ModeDrxParameters) -> Self {
        self.negotiated_nb_n1_mode_drx_parameters = Some(value);
        self
    }

    pub fn set_extended_rejected_nssai(mut self, value: NasExtendedRejectedNssai) -> Self {
        self.extended_rejected_nssai = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }

    pub fn set_negotiated_peips_assistance_information(mut self, value: NasPeipsAssistanceInformation) -> Self {
        self.negotiated_peips_assistance_information = Some(value);
        self
    }

    pub fn set_fgs_additional_request_result(mut self, value: NasFGsAdditionalRequestResult) -> Self {
        self.fgs_additional_request_result = Some(value);
        self
    }

    pub fn set_nssrg_information(mut self, value: NasNssrgInformation) -> Self {
        self.nssrg_information = Some(value);
        self
    }

    pub fn set_disaster_roaming_wait_range(mut self, value: NasRegistrationWaitRange) -> Self {
        self.disaster_roaming_wait_range = Some(value);
        self
    }

    pub fn set_disaster_return_wait_range(mut self, value: NasRegistrationWaitRange) -> Self {
        self.disaster_return_wait_range = Some(value);
        self
    }

    pub fn set_list_of_plmns_to_be_used_in_disaster_condition(mut self, value: NasListOfPlmnsToBeUsedInDisasterCondition) -> Self {
        self.list_of_plmns_to_be_used_in_disaster_condition = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(value);
        self
    }

    pub fn set_extended_cag_information_list(mut self, value: NasExtendedCagInformationList) -> Self {
        self.extended_cag_information_list = Some(value);
        self
    }

    pub fn set_nsag_information(mut self, value: NasNsagInformation) -> Self {
        self.nsag_information = Some(value);
        self
    }
}

impl Encode for NasRegistrationAccept {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgs_registration_result.encode(buffer)?;
        if let Some(ref value) = self.fg_guti {
            helpers::encode_optional_type(buffer, 0x77)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.equivalent_plmns {
            let mut ie = value.clone();
            ie.type_field = 0x4A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.tai_list {
            let mut ie = value.clone();
            ie.type_field = 0x54;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.allowed_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x15;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.rejected_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x11;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.configured_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x31;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgs_network_feature_support {
            let mut ie = value.clone();
            ie.type_field = 0x21;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_session_status {
            let mut ie = value.clone();
            ie.type_field = 0x50;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_session_reactivation_result {
            let mut ie = value.clone();
            ie.type_field = 0x26;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_session_reactivation_result_error_cause {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ladn_information {
            let mut ie = value.clone();
            ie.type_field = 0x79;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.mico_indication {
            let mut ie = value.clone();
            ie.type_field = 0xB0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.network_slicing_indication {
            let mut ie = value.clone();
            ie.type_field = 0x90;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_area_list {
            let mut ie = value.clone();
            ie.type_field = 0x27;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3512_value {
            let mut ie = value.clone();
            ie.type_field = 0x5E;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.non_3gpp_de_registration_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x5D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3502_value {
            let mut ie = value.clone();
            ie.type_field = 0x16;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.emergency_number_list {
            let mut ie = value.clone();
            ie.type_field = 0x34;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_emergency_number_list {
            let mut ie = value.clone();
            ie.type_field = 0x7A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.sor_transparent_container {
            let mut ie = value.clone();
            ie.type_field = 0x73;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nssai_inclusion_mode {
            let mut ie = value.clone();
            ie.type_field = 0xA0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.operator_defined_access_category_definitions {
            let mut ie = value.clone();
            ie.type_field = 0x76;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.negotiated_drx_parameters {
            let mut ie = value.clone();
            ie.type_field = 0x51;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.non_3gpp_nw_policies {
            let mut ie = value.clone();
            ie.type_field = 0xD0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eps_bearer_context_status {
            let mut ie = value.clone();
            ie.type_field = 0x60;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.negotiated_extended_drx_parameters {
            let mut ie = value.clone();
            ie.type_field = 0x6E;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3447_value {
            let mut ie = value.clone();
            ie.type_field = 0x6C;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3448_value {
            let mut ie = value.clone();
            ie.type_field = 0x6B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3324_value {
            let mut ie = value.clone();
            ie.type_field = 0x6A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_radio_capability_id {
            let mut ie = value.clone();
            ie.type_field = 0x67;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_radio_capability_id_deletion_indication {
            let mut ie = value.clone();
            ie.type_field = 0xE0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pending_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x39;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ciphering_key_data {
            let mut ie = value.clone();
            ie.type_field = 0x74;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x75;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.truncated_fg_s_tmsi_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x1B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.negotiated_wus_assistance_information {
            let mut ie = value.clone();
            ie.type_field = 0x1C;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.negotiated_nb_n1_mode_drx_parameters {
            let mut ie = value.clone();
            ie.type_field = 0x29;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_rejected_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x68;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.negotiated_peips_assistance_information {
            let mut ie = value.clone();
            ie.type_field = 0x33;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgs_additional_request_result {
            let mut ie = value.clone();
            ie.type_field = 0x34;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nssrg_information {
            let mut ie = value.clone();
            ie.type_field = 0x70;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.disaster_roaming_wait_range {
            let mut ie = value.clone();
            ie.type_field = 0x14;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.disaster_return_wait_range {
            let mut ie = value.clone();
            ie.type_field = 0x2C;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.list_of_plmns_to_be_used_in_disaster_condition {
            let mut ie = value.clone();
            ie.type_field = 0x13;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming {
            let mut ie = value.clone();
            ie.type_field = 0x1D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service {
            let mut ie = value.clone();
            ie.type_field = 0x1E;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nsag_information {
            let mut ie = value.clone();
            ie.type_field = 0x7C;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasRegistrationAccept {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgs_registration_result = NasFGsRegistrationResult::decode(buffer)?;

        let mut message = Self::new(
            fgs_registration_result,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x77 => {
                    buffer.advance(1); // Skip IEI
                    message.fg_guti = Some(NasFGsMobileIdentity::decode(buffer)?);
                },
                0x4A => {
                    message.equivalent_plmns = Some(NasPlmnList::decode(buffer)?);
                },
                0x54 => {
                    message.tai_list = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                0x15 => {
                    message.allowed_nssai = Some(NasNssai::decode(buffer)?);
                },
                0x11 => {
                    message.rejected_nssai = Some(NasRejectedNssai::decode(buffer)?);
                },
                0x31 => {
                    message.configured_nssai = Some(NasNssai::decode(buffer)?);
                },
                0x21 => {
                    message.fgs_network_feature_support = Some(NasFGsNetworkFeatureSupport::decode(buffer)?);
                },
                0x50 => {
                    message.pdu_session_status = Some(NasPduSessionStatus::decode(buffer)?);
                },
                0x26 => {
                    message.pdu_session_reactivation_result = Some(NasPduSessionReactivationResult::decode(buffer)?);
                },
                0x72 => {
                    message.pdu_session_reactivation_result_error_cause = Some(NasPduSessionReactivationResultErrorCause::decode(buffer)?);
                },
                0x79 => {
                    message.ladn_information = Some(NasLadnInformation::decode(buffer)?);
                },
                0xB0 => {
                    message.mico_indication = Some(NasMicoIndication::decode(buffer)?);
                },
                0x90 => {
                    message.network_slicing_indication = Some(NasNetworkSlicingIndication::decode(buffer)?);
                },
                0x27 => {
                    message.service_area_list = Some(NasServiceAreaList::decode(buffer)?);
                },
                0x5E => {
                    message.t3512_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x5D => {
                    message.non_3gpp_de_registration_timer_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x16 => {
                    message.t3502_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x34 => {
                    message.emergency_number_list = Some(NasEmergencyNumberList::decode(buffer)?);
                },
                0x7A => {
                    message.extended_emergency_number_list = Some(NasExtendedEmergencyNumberList::decode(buffer)?);
                },
                0x73 => {
                    message.sor_transparent_container = Some(NasSorTransparentContainer::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0xA0 => {
                    message.nssai_inclusion_mode = Some(NasNssaiInclusionMode::decode(buffer)?);
                },
                0x76 => {
                    message.operator_defined_access_category_definitions = Some(NasOperatorDefinedAccessCategoryDefinitions::decode(buffer)?);
                },
                0x51 => {
                    message.negotiated_drx_parameters = Some(NasFGsDrxParameters::decode(buffer)?);
                },
                0xD0 => {
                    message.non_3gpp_nw_policies = Some(NasNon3GppNwProvidedPolicies::decode(buffer)?);
                },
                0x60 => {
                    message.eps_bearer_context_status = Some(NasEpsBearerContextStatus::decode(buffer)?);
                },
                0x6E => {
                    message.negotiated_extended_drx_parameters = Some(NasExtendedDrxParameters::decode(buffer)?);
                },
                0x6C => {
                    message.t3447_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x6B => {
                    message.t3448_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x6A => {
                    message.t3324_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x67 => {
                    message.ue_radio_capability_id = Some(NasUeRadioCapabilityId::decode(buffer)?);
                },
                0xE0 => {
                    message.ue_radio_capability_id_deletion_indication = Some(NasUeRadioCapabilityIdDeletionIndication::decode(buffer)?);
                },
                0x39 => {
                    message.pending_nssai = Some(NasNssai::decode(buffer)?);
                },
                0x74 => {
                    message.ciphering_key_data = Some(NasCipheringKeyData::decode(buffer)?);
                },
                0x75 => {
                    message.cag_information_list = Some(NasCagInformationList::decode(buffer)?);
                },
                0x1B => {
                    message.truncated_fg_s_tmsi_configuration = Some(NasTruncatedFGSTmsiConfiguration::decode(buffer)?);
                },
                0x1C => {
                    message.negotiated_wus_assistance_information = Some(NasWusAssistanceInformation::decode(buffer)?);
                },
                0x29 => {
                    message.negotiated_nb_n1_mode_drx_parameters = Some(NasNbN1ModeDrxParameters::decode(buffer)?);
                },
                0x68 => {
                    message.extended_rejected_nssai = Some(NasExtendedRejectedNssai::decode(buffer)?);
                },
                0x7B => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                0x33 => {
                    message.negotiated_peips_assistance_information = Some(NasPeipsAssistanceInformation::decode(buffer)?);
                },
                0x34 => {
                    message.fgs_additional_request_result = Some(NasFGsAdditionalRequestResult::decode(buffer)?);
                },
                0x70 => {
                    message.nssrg_information = Some(NasNssrgInformation::decode(buffer)?);
                },
                0x14 => {
                    message.disaster_roaming_wait_range = Some(NasRegistrationWaitRange::decode(buffer)?);
                },
                0x2C => {
                    message.disaster_return_wait_range = Some(NasRegistrationWaitRange::decode(buffer)?);
                },
                0x13 => {
                    message.list_of_plmns_to_be_used_in_disaster_condition = Some(NasListOfPlmnsToBeUsedInDisasterCondition::decode(buffer)?);
                },
                0x1D => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                0x1E => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                0x71 => {
                    message.extended_cag_information_list = Some(NasExtendedCagInformationList::decode(buffer)?);
                },
                0x7C => {
                    message.nsag_information = Some(NasNsagInformation::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// REGISTRATION COMPLETE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasRegistrationComplete {
    // Mandatory fields

    // Optional fields
    pub sor_transparent_container: Option<NasSorTransparentContainer>,
}

impl NasRegistrationComplete {
    pub fn new(
    ) -> Self {
        Self {
            sor_transparent_container: None,
        }
    }

    pub fn set_sor_transparent_container(mut self, value: NasSorTransparentContainer) -> Self {
        self.sor_transparent_container = Some(value);
        self
    }
}

impl Encode for NasRegistrationComplete {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.sor_transparent_container {
            let mut ie = value.clone();
            ie.type_field = 0x73;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasRegistrationComplete {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x73 => {
                    message.sor_transparent_container = Some(NasSorTransparentContainer::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// REGISTRATION REJECT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasRegistrationReject {
    // Mandatory fields
    pub fgmm_cause: NasFGmmCause,

    // Optional fields
    pub t3346_value: Option<NasGprsTimer2>,
    pub t3502_value: Option<NasGprsTimer2>,
    pub eap_message: Option<NasEapMessage>,
    pub rejected_nssai: Option<NasRejectedNssai>,
    pub cag_information_list: Option<NasCagInformationList>,
    pub extended_rejected_nssai: Option<NasExtendedRejectedNssai>,
    pub disaster_return_wait_range: Option<NasRegistrationWaitRange>,
    pub extended_cag_information_list: Option<NasExtendedCagInformationList>,
    pub lower_bound_timer_value: Option<NasGprsTimer3>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: Option<NasFGsTrackingAreaIdentityList>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: Option<NasFGsTrackingAreaIdentityList>,
}

impl NasRegistrationReject {
    pub fn new(
        fgmm_cause: NasFGmmCause,
    ) -> Self {
        Self {
            fgmm_cause,
            t3346_value: None,
            t3502_value: None,
            eap_message: None,
            rejected_nssai: None,
            cag_information_list: None,
            extended_rejected_nssai: None,
            disaster_return_wait_range: None,
            extended_cag_information_list: None,
            lower_bound_timer_value: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: None,
        }
    }

    pub fn set_t3346_value(mut self, value: NasGprsTimer2) -> Self {
        self.t3346_value = Some(value);
        self
    }

    pub fn set_t3502_value(mut self, value: NasGprsTimer2) -> Self {
        self.t3502_value = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_rejected_nssai(mut self, value: NasRejectedNssai) -> Self {
        self.rejected_nssai = Some(value);
        self
    }

    pub fn set_cag_information_list(mut self, value: NasCagInformationList) -> Self {
        self.cag_information_list = Some(value);
        self
    }

    pub fn set_extended_rejected_nssai(mut self, value: NasExtendedRejectedNssai) -> Self {
        self.extended_rejected_nssai = Some(value);
        self
    }

    pub fn set_disaster_return_wait_range(mut self, value: NasRegistrationWaitRange) -> Self {
        self.disaster_return_wait_range = Some(value);
        self
    }

    pub fn set_extended_cag_information_list(mut self, value: NasExtendedCagInformationList) -> Self {
        self.extended_cag_information_list = Some(value);
        self
    }

    pub fn set_lower_bound_timer_value(mut self, value: NasGprsTimer3) -> Self {
        self.lower_bound_timer_value = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(value);
        self
    }
}

impl Encode for NasRegistrationReject {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgmm_cause.encode(buffer)?;
        if let Some(ref value) = self.t3346_value {
            let mut ie = value.clone();
            ie.type_field = 0x5F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3502_value {
            let mut ie = value.clone();
            ie.type_field = 0x16;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.rejected_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x69;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x75;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_rejected_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x68;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.disaster_return_wait_range {
            let mut ie = value.clone();
            ie.type_field = 0x2C;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.lower_bound_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x3A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming {
            let mut ie = value.clone();
            ie.type_field = 0x1D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service {
            let mut ie = value.clone();
            ie.type_field = 0x1E;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasRegistrationReject {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgmm_cause = NasFGmmCause::decode(buffer)?;

        let mut message = Self::new(
            fgmm_cause,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x5F => {
                    message.t3346_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x16 => {
                    message.t3502_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0x69 => {
                    message.rejected_nssai = Some(NasRejectedNssai::decode(buffer)?);
                },
                0x75 => {
                    message.cag_information_list = Some(NasCagInformationList::decode(buffer)?);
                },
                0x68 => {
                    message.extended_rejected_nssai = Some(NasExtendedRejectedNssai::decode(buffer)?);
                },
                0x2C => {
                    message.disaster_return_wait_range = Some(NasRegistrationWaitRange::decode(buffer)?);
                },
                0x71 => {
                    message.extended_cag_information_list = Some(NasExtendedCagInformationList::decode(buffer)?);
                },
                0x3A => {
                    message.lower_bound_timer_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x1D => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                0x1E => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// DEREGISTRATION REQUEST FROM UE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasDeregistrationRequestFromUe {
    // Mandatory fields
    pub de_registration_type: NasDeRegistrationType,
    pub fgs_mobile_identity: NasFGsMobileIdentity,
}

impl NasDeregistrationRequestFromUe {
    pub fn new(
        de_registration_type: NasDeRegistrationType,
        fgs_mobile_identity: NasFGsMobileIdentity,
    ) -> Self {
        Self {
            de_registration_type,
            fgs_mobile_identity,
        }
    }
}

impl Encode for NasDeregistrationRequestFromUe {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.de_registration_type.encode(buffer)?;
        self.fgs_mobile_identity.encode(buffer)?;
        Ok(())
    }
}

impl Decode for NasDeregistrationRequestFromUe {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let de_registration_type = NasDeRegistrationType::decode(buffer)?;
        let fgs_mobile_identity = NasFGsMobileIdentity::decode(buffer)?;

        let  message = Self::new(
            de_registration_type,
            fgs_mobile_identity,
        );


        Ok(message)
    }
}

/// DEREGISTRATION REQUEST TO UE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasDeregistrationRequestToUe {
    // Mandatory fields
    pub de_registration_type: NasDeRegistrationType,

    // Optional fields
    pub fgmm_cause: Option<NasFGmmCause>,
    pub t3346_value: Option<NasGprsTimer2>,
    pub rejected_nssai: Option<NasRejectedNssai>,
    pub cag_information_list: Option<NasCagInformationList>,
    pub extended_rejected_nssai: Option<NasExtendedRejectedNssai>,
    pub disaster_return_wait_range: Option<NasRegistrationWaitRange>,
    pub extended_cag_information_list: Option<NasExtendedCagInformationList>,
    pub lower_bound_timer_value: Option<NasGprsTimer3>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: Option<NasFGsTrackingAreaIdentityList>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: Option<NasFGsTrackingAreaIdentityList>,
}

impl NasDeregistrationRequestToUe {
    pub fn new(
        de_registration_type: NasDeRegistrationType,
    ) -> Self {
        Self {
            de_registration_type,
            fgmm_cause: None,
            t3346_value: None,
            rejected_nssai: None,
            cag_information_list: None,
            extended_rejected_nssai: None,
            disaster_return_wait_range: None,
            extended_cag_information_list: None,
            lower_bound_timer_value: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: None,
        }
    }

    pub fn set_fgmm_cause(mut self, value: NasFGmmCause) -> Self {
        self.fgmm_cause = Some(value);
        self
    }

    pub fn set_t3346_value(mut self, value: NasGprsTimer2) -> Self {
        self.t3346_value = Some(value);
        self
    }

    pub fn set_rejected_nssai(mut self, value: NasRejectedNssai) -> Self {
        self.rejected_nssai = Some(value);
        self
    }

    pub fn set_cag_information_list(mut self, value: NasCagInformationList) -> Self {
        self.cag_information_list = Some(value);
        self
    }

    pub fn set_extended_rejected_nssai(mut self, value: NasExtendedRejectedNssai) -> Self {
        self.extended_rejected_nssai = Some(value);
        self
    }

    pub fn set_disaster_return_wait_range(mut self, value: NasRegistrationWaitRange) -> Self {
        self.disaster_return_wait_range = Some(value);
        self
    }

    pub fn set_extended_cag_information_list(mut self, value: NasExtendedCagInformationList) -> Self {
        self.extended_cag_information_list = Some(value);
        self
    }

    pub fn set_lower_bound_timer_value(mut self, value: NasGprsTimer3) -> Self {
        self.lower_bound_timer_value = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(value);
        self
    }
}

impl Encode for NasDeregistrationRequestToUe {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.de_registration_type.encode(buffer)?;
        if let Some(ref value) = self.fgmm_cause {
            helpers::encode_optional_type(buffer, 0x58)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.t3346_value {
            let mut ie = value.clone();
            ie.type_field = 0x5F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.rejected_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x6D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x75;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_rejected_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x68;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.disaster_return_wait_range {
            let mut ie = value.clone();
            ie.type_field = 0x2C;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.lower_bound_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x3A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming {
            let mut ie = value.clone();
            ie.type_field = 0x1D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service {
            let mut ie = value.clone();
            ie.type_field = 0x1E;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasDeregistrationRequestToUe {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let de_registration_type = NasDeRegistrationType::decode(buffer)?;

        let mut message = Self::new(
            de_registration_type,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x58 => {
                    buffer.advance(1); // Skip IEI
                    message.fgmm_cause = Some(NasFGmmCause::decode(buffer)?);
                },
                0x5F => {
                    message.t3346_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x6D => {
                    message.rejected_nssai = Some(NasRejectedNssai::decode(buffer)?);
                },
                0x75 => {
                    message.cag_information_list = Some(NasCagInformationList::decode(buffer)?);
                },
                0x68 => {
                    message.extended_rejected_nssai = Some(NasExtendedRejectedNssai::decode(buffer)?);
                },
                0x2C => {
                    message.disaster_return_wait_range = Some(NasRegistrationWaitRange::decode(buffer)?);
                },
                0x71 => {
                    message.extended_cag_information_list = Some(NasExtendedCagInformationList::decode(buffer)?);
                },
                0x3A => {
                    message.lower_bound_timer_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x1D => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                0x1E => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// SERVICE REQUEST Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasServiceRequest {
    // Mandatory fields
    pub ngksi: NasKeySetIdentifier,
    pub fg_s_tmsi: NasFGsMobileIdentity,

    // Optional fields
    pub uplink_data_status: Option<NasUplinkDataStatus>,
    pub pdu_session_status: Option<NasPduSessionStatus>,
    pub allowed_pdu_session_status: Option<NasAllowedPduSessionStatus>,
    pub nas_message_container: Option<NasMessageContainer>,
    pub ue_request_type: Option<NasUeRequestType>,
    pub paging_restriction: Option<NasPagingRestriction>,
}

impl NasServiceRequest {
    pub fn new(
        ngksi: NasKeySetIdentifier,
        fg_s_tmsi: NasFGsMobileIdentity,
    ) -> Self {
        Self {
            ngksi,
            fg_s_tmsi,
            uplink_data_status: None,
            pdu_session_status: None,
            allowed_pdu_session_status: None,
            nas_message_container: None,
            ue_request_type: None,
            paging_restriction: None,
        }
    }

    pub fn set_uplink_data_status(mut self, value: NasUplinkDataStatus) -> Self {
        self.uplink_data_status = Some(value);
        self
    }

    pub fn set_pdu_session_status(mut self, value: NasPduSessionStatus) -> Self {
        self.pdu_session_status = Some(value);
        self
    }

    pub fn set_allowed_pdu_session_status(mut self, value: NasAllowedPduSessionStatus) -> Self {
        self.allowed_pdu_session_status = Some(value);
        self
    }

    pub fn set_nas_message_container(mut self, value: NasMessageContainer) -> Self {
        self.nas_message_container = Some(value);
        self
    }

    pub fn set_ue_request_type(mut self, value: NasUeRequestType) -> Self {
        self.ue_request_type = Some(value);
        self
    }

    pub fn set_paging_restriction(mut self, value: NasPagingRestriction) -> Self {
        self.paging_restriction = Some(value);
        self
    }
}

impl Encode for NasServiceRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.ngksi.encode(buffer)?;
        self.fg_s_tmsi.encode(buffer)?;
        if let Some(ref value) = self.uplink_data_status {
            let mut ie = value.clone();
            ie.type_field = 0x40;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_session_status {
            let mut ie = value.clone();
            ie.type_field = 0x50;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.allowed_pdu_session_status {
            let mut ie = value.clone();
            ie.type_field = 0x25;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nas_message_container {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_request_type {
            let mut ie = value.clone();
            ie.type_field = 0x29;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.paging_restriction {
            let mut ie = value.clone();
            ie.type_field = 0x28;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasServiceRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let ngksi = NasKeySetIdentifier::decode(buffer)?;
        let fg_s_tmsi = NasFGsMobileIdentity::decode(buffer)?;

        let mut message = Self::new(
            ngksi,
            fg_s_tmsi,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x40 => {
                    message.uplink_data_status = Some(NasUplinkDataStatus::decode(buffer)?);
                },
                0x50 => {
                    message.pdu_session_status = Some(NasPduSessionStatus::decode(buffer)?);
                },
                0x25 => {
                    message.allowed_pdu_session_status = Some(NasAllowedPduSessionStatus::decode(buffer)?);
                },
                0x71 => {
                    message.nas_message_container = Some(NasMessageContainer::decode(buffer)?);
                },
                0x29 => {
                    message.ue_request_type = Some(NasUeRequestType::decode(buffer)?);
                },
                0x28 => {
                    message.paging_restriction = Some(NasPagingRestriction::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// SERVICE REJECT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasServiceReject {
    // Mandatory fields
    pub fgmm_cause: NasFGmmCause,

    // Optional fields
    pub pdu_session_status: Option<NasPduSessionStatus>,
    pub t3346_value: Option<NasGprsTimer2>,
    pub eap_message: Option<NasEapMessage>,
    pub t3448_value: Option<NasGprsTimer2>,
    pub cag_information_list: Option<NasCagInformationList>,
    pub disaster_return_wait_range: Option<NasRegistrationWaitRange>,
    pub extended_cag_information_list: Option<NasExtendedCagInformationList>,
    pub lower_bound_timer_value: Option<NasGprsTimer3>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: Option<NasFGsTrackingAreaIdentityList>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: Option<NasFGsTrackingAreaIdentityList>,
}

impl NasServiceReject {
    pub fn new(
        fgmm_cause: NasFGmmCause,
    ) -> Self {
        Self {
            fgmm_cause,
            pdu_session_status: None,
            t3346_value: None,
            eap_message: None,
            t3448_value: None,
            cag_information_list: None,
            disaster_return_wait_range: None,
            extended_cag_information_list: None,
            lower_bound_timer_value: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: None,
        }
    }

    pub fn set_pdu_session_status(mut self, value: NasPduSessionStatus) -> Self {
        self.pdu_session_status = Some(value);
        self
    }

    pub fn set_t3346_value(mut self, value: NasGprsTimer2) -> Self {
        self.t3346_value = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_t3448_value(mut self, value: NasGprsTimer2) -> Self {
        self.t3448_value = Some(value);
        self
    }

    pub fn set_cag_information_list(mut self, value: NasCagInformationList) -> Self {
        self.cag_information_list = Some(value);
        self
    }

    pub fn set_disaster_return_wait_range(mut self, value: NasRegistrationWaitRange) -> Self {
        self.disaster_return_wait_range = Some(value);
        self
    }

    pub fn set_extended_cag_information_list(mut self, value: NasExtendedCagInformationList) -> Self {
        self.extended_cag_information_list = Some(value);
        self
    }

    pub fn set_lower_bound_timer_value(mut self, value: NasGprsTimer3) -> Self {
        self.lower_bound_timer_value = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(value);
        self
    }
}

impl Encode for NasServiceReject {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgmm_cause.encode(buffer)?;
        if let Some(ref value) = self.pdu_session_status {
            let mut ie = value.clone();
            ie.type_field = 0x50;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3346_value {
            let mut ie = value.clone();
            ie.type_field = 0x5F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3448_value {
            let mut ie = value.clone();
            ie.type_field = 0x6B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x75;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.disaster_return_wait_range {
            let mut ie = value.clone();
            ie.type_field = 0x2C;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.lower_bound_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x3A;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming {
            let mut ie = value.clone();
            ie.type_field = 0x1D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service {
            let mut ie = value.clone();
            ie.type_field = 0x1E;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasServiceReject {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgmm_cause = NasFGmmCause::decode(buffer)?;

        let mut message = Self::new(
            fgmm_cause,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x50 => {
                    message.pdu_session_status = Some(NasPduSessionStatus::decode(buffer)?);
                },
                0x5F => {
                    message.t3346_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0x6B => {
                    message.t3448_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x75 => {
                    message.cag_information_list = Some(NasCagInformationList::decode(buffer)?);
                },
                0x2C => {
                    message.disaster_return_wait_range = Some(NasRegistrationWaitRange::decode(buffer)?);
                },
                0x71 => {
                    message.extended_cag_information_list = Some(NasExtendedCagInformationList::decode(buffer)?);
                },
                0x3A => {
                    message.lower_bound_timer_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x1D => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                0x1E => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// SERVICE ACCEPT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasServiceAccept {
    // Mandatory fields

    // Optional fields
    pub pdu_session_status: Option<NasPduSessionStatus>,
    pub pdu_session_reactivation_result: Option<NasPduSessionReactivationResult>,
    pub pdu_session_reactivation_result_error_cause: Option<NasPduSessionReactivationResultErrorCause>,
    pub eap_message: Option<NasEapMessage>,
    pub t3448_value: Option<NasGprsTimer2>,
    pub fgs_additional_request_result: Option<NasFGsAdditionalRequestResult>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: Option<NasFGsTrackingAreaIdentityList>,
    pub forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: Option<NasFGsTrackingAreaIdentityList>,
}

impl NasServiceAccept {
    pub fn new(
    ) -> Self {
        Self {
            pdu_session_status: None,
            pdu_session_reactivation_result: None,
            pdu_session_reactivation_result_error_cause: None,
            eap_message: None,
            t3448_value: None,
            fgs_additional_request_result: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: None,
            forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service: None,
        }
    }

    pub fn set_pdu_session_status(mut self, value: NasPduSessionStatus) -> Self {
        self.pdu_session_status = Some(value);
        self
    }

    pub fn set_pdu_session_reactivation_result(mut self, value: NasPduSessionReactivationResult) -> Self {
        self.pdu_session_reactivation_result = Some(value);
        self
    }

    pub fn set_pdu_session_reactivation_result_error_cause(mut self, value: NasPduSessionReactivationResultErrorCause) -> Self {
        self.pdu_session_reactivation_result_error_cause = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_t3448_value(mut self, value: NasGprsTimer2) -> Self {
        self.t3448_value = Some(value);
        self
    }

    pub fn set_fgs_additional_request_result(mut self, value: NasFGsAdditionalRequestResult) -> Self {
        self.fgs_additional_request_result = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(value);
        self
    }

    pub fn set_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(value);
        self
    }
}

impl Encode for NasServiceAccept {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.pdu_session_status {
            let mut ie = value.clone();
            ie.type_field = 0x50;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_session_reactivation_result {
            let mut ie = value.clone();
            ie.type_field = 0x26;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_session_reactivation_result_error_cause {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3448_value {
            let mut ie = value.clone();
            ie.type_field = 0x6B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgs_additional_request_result {
            let mut ie = value.clone();
            ie.type_field = 0x34;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming {
            let mut ie = value.clone();
            ie.type_field = 0x1D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service {
            let mut ie = value.clone();
            ie.type_field = 0x1E;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasServiceAccept {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x50 => {
                    message.pdu_session_status = Some(NasPduSessionStatus::decode(buffer)?);
                },
                0x26 => {
                    message.pdu_session_reactivation_result = Some(NasPduSessionReactivationResult::decode(buffer)?);
                },
                0x72 => {
                    message.pdu_session_reactivation_result_error_cause = Some(NasPduSessionReactivationResultErrorCause::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0x6B => {
                    message.t3448_value = Some(NasGprsTimer2::decode(buffer)?);
                },
                0x34 => {
                    message.fgs_additional_request_result = Some(NasFGsAdditionalRequestResult::decode(buffer)?);
                },
                0x1D => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                0x1E => {
                    message.forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_forregional_provision_of_service = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// CONFIGURATION UPDATE COMMAND Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasConfigurationUpdateCommand {
    // Mandatory fields

    // Optional fields
    pub configuration_update_indication: Option<NasConfigurationUpdateIndication>,
    pub fg_guti: Option<NasFGsMobileIdentity>,
    pub tai_list: Option<NasFGsTrackingAreaIdentityList>,
    pub allowed_nssai: Option<NasNssai>,
    pub service_area_list: Option<NasServiceAreaList>,
    pub full_name_for_network: Option<NasNetworkName>,
    pub short_name_for_network: Option<NasNetworkName>,
    pub local_time_zone: Option<NasTimeZone>,
    pub universal_time_and_local_time_zone: Option<NasTimeZoneAndTime>,
    pub network_daylight_saving_time: Option<NasDaylightSavingTime>,
    pub ladn_information: Option<NasLadnInformation>,
    pub mico_indication: Option<NasMicoIndication>,
    pub network_slicing_indication: Option<NasNetworkSlicingIndication>,
    pub configured_nssai: Option<NasNssai>,
    pub rejected_nssai: Option<NasRejectedNssai>,
    pub operator_defined_access_category_definitions: Option<NasOperatorDefinedAccessCategoryDefinitions>,
    pub sms_indication: Option<NasSmsIndication>,
    pub t3447_value: Option<NasGprsTimer3>,
    pub cag_information_list: Option<NasCagInformationList>,
    pub ue_radio_capability_id: Option<NasUeRadioCapabilityId>,
    pub ue_radio_capability_id_deletion_indication: Option<NasUeRadioCapabilityIdDeletionIndication>,
    pub fgs_registration_result: Option<NasFGsRegistrationResult>,
    pub truncated_fg_s_tmsi_configuration: Option<NasTruncatedFGSTmsiConfiguration>,
    pub additional_configuration_indication: Option<NasAdditionalConfigurationIndication>,
    pub extended_rejected_nssai: Option<NasExtendedRejectedNssai>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
    pub nssrg_information: Option<NasNssrgInformation>,
    pub disaster_roaming_wait_range: Option<NasRegistrationWaitRange>,
    pub disaster_return_wait_range: Option<NasRegistrationWaitRange>,
    pub list_of_plmns_to_be_used_in_disaster_condition: Option<NasListOfPlmnsToBeUsedInDisasterCondition>,
    pub extended_cag_information_list: Option<NasExtendedCagInformationList>,
    pub updated_peips_assistance_information: Option<NasPeipsAssistanceInformation>,
    pub nsag_information: Option<NasNsagInformation>,
    pub priority_indicator: Option<NasPriorityIndicator>,
}

impl NasConfigurationUpdateCommand {
    pub fn new(
    ) -> Self {
        Self {
            configuration_update_indication: None,
            fg_guti: None,
            tai_list: None,
            allowed_nssai: None,
            service_area_list: None,
            full_name_for_network: None,
            short_name_for_network: None,
            local_time_zone: None,
            universal_time_and_local_time_zone: None,
            network_daylight_saving_time: None,
            ladn_information: None,
            mico_indication: None,
            network_slicing_indication: None,
            configured_nssai: None,
            rejected_nssai: None,
            operator_defined_access_category_definitions: None,
            sms_indication: None,
            t3447_value: None,
            cag_information_list: None,
            ue_radio_capability_id: None,
            ue_radio_capability_id_deletion_indication: None,
            fgs_registration_result: None,
            truncated_fg_s_tmsi_configuration: None,
            additional_configuration_indication: None,
            extended_rejected_nssai: None,
            service_level_aa_container: None,
            nssrg_information: None,
            disaster_roaming_wait_range: None,
            disaster_return_wait_range: None,
            list_of_plmns_to_be_used_in_disaster_condition: None,
            extended_cag_information_list: None,
            updated_peips_assistance_information: None,
            nsag_information: None,
            priority_indicator: None,
        }
    }

    pub fn set_configuration_update_indication(mut self, value: NasConfigurationUpdateIndication) -> Self {
        self.configuration_update_indication = Some(value);
        self
    }

    pub fn set_fg_guti(mut self, value: NasFGsMobileIdentity) -> Self {
        self.fg_guti = Some(value);
        self
    }

    pub fn set_tai_list(mut self, value: NasFGsTrackingAreaIdentityList) -> Self {
        self.tai_list = Some(value);
        self
    }

    pub fn set_allowed_nssai(mut self, value: NasNssai) -> Self {
        self.allowed_nssai = Some(value);
        self
    }

    pub fn set_service_area_list(mut self, value: NasServiceAreaList) -> Self {
        self.service_area_list = Some(value);
        self
    }

    pub fn set_full_name_for_network(mut self, value: NasNetworkName) -> Self {
        self.full_name_for_network = Some(value);
        self
    }

    pub fn set_short_name_for_network(mut self, value: NasNetworkName) -> Self {
        self.short_name_for_network = Some(value);
        self
    }

    pub fn set_local_time_zone(mut self, value: NasTimeZone) -> Self {
        self.local_time_zone = Some(value);
        self
    }

    pub fn set_universal_time_and_local_time_zone(mut self, value: NasTimeZoneAndTime) -> Self {
        self.universal_time_and_local_time_zone = Some(value);
        self
    }

    pub fn set_network_daylight_saving_time(mut self, value: NasDaylightSavingTime) -> Self {
        self.network_daylight_saving_time = Some(value);
        self
    }

    pub fn set_ladn_information(mut self, value: NasLadnInformation) -> Self {
        self.ladn_information = Some(value);
        self
    }

    pub fn set_mico_indication(mut self, value: NasMicoIndication) -> Self {
        self.mico_indication = Some(value);
        self
    }

    pub fn set_network_slicing_indication(mut self, value: NasNetworkSlicingIndication) -> Self {
        self.network_slicing_indication = Some(value);
        self
    }

    pub fn set_configured_nssai(mut self, value: NasNssai) -> Self {
        self.configured_nssai = Some(value);
        self
    }

    pub fn set_rejected_nssai(mut self, value: NasRejectedNssai) -> Self {
        self.rejected_nssai = Some(value);
        self
    }

    pub fn set_operator_defined_access_category_definitions(mut self, value: NasOperatorDefinedAccessCategoryDefinitions) -> Self {
        self.operator_defined_access_category_definitions = Some(value);
        self
    }

    pub fn set_sms_indication(mut self, value: NasSmsIndication) -> Self {
        self.sms_indication = Some(value);
        self
    }

    pub fn set_t3447_value(mut self, value: NasGprsTimer3) -> Self {
        self.t3447_value = Some(value);
        self
    }

    pub fn set_cag_information_list(mut self, value: NasCagInformationList) -> Self {
        self.cag_information_list = Some(value);
        self
    }

    pub fn set_ue_radio_capability_id(mut self, value: NasUeRadioCapabilityId) -> Self {
        self.ue_radio_capability_id = Some(value);
        self
    }

    pub fn set_ue_radio_capability_id_deletion_indication(mut self, value: NasUeRadioCapabilityIdDeletionIndication) -> Self {
        self.ue_radio_capability_id_deletion_indication = Some(value);
        self
    }

    pub fn set_fgs_registration_result(mut self, value: NasFGsRegistrationResult) -> Self {
        self.fgs_registration_result = Some(value);
        self
    }

    pub fn set_truncated_fg_s_tmsi_configuration(mut self, value: NasTruncatedFGSTmsiConfiguration) -> Self {
        self.truncated_fg_s_tmsi_configuration = Some(value);
        self
    }

    pub fn set_additional_configuration_indication(mut self, value: NasAdditionalConfigurationIndication) -> Self {
        self.additional_configuration_indication = Some(value);
        self
    }

    pub fn set_extended_rejected_nssai(mut self, value: NasExtendedRejectedNssai) -> Self {
        self.extended_rejected_nssai = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }

    pub fn set_nssrg_information(mut self, value: NasNssrgInformation) -> Self {
        self.nssrg_information = Some(value);
        self
    }

    pub fn set_disaster_roaming_wait_range(mut self, value: NasRegistrationWaitRange) -> Self {
        self.disaster_roaming_wait_range = Some(value);
        self
    }

    pub fn set_disaster_return_wait_range(mut self, value: NasRegistrationWaitRange) -> Self {
        self.disaster_return_wait_range = Some(value);
        self
    }

    pub fn set_list_of_plmns_to_be_used_in_disaster_condition(mut self, value: NasListOfPlmnsToBeUsedInDisasterCondition) -> Self {
        self.list_of_plmns_to_be_used_in_disaster_condition = Some(value);
        self
    }

    pub fn set_extended_cag_information_list(mut self, value: NasExtendedCagInformationList) -> Self {
        self.extended_cag_information_list = Some(value);
        self
    }

    pub fn set_updated_peips_assistance_information(mut self, value: NasPeipsAssistanceInformation) -> Self {
        self.updated_peips_assistance_information = Some(value);
        self
    }

    pub fn set_nsag_information(mut self, value: NasNsagInformation) -> Self {
        self.nsag_information = Some(value);
        self
    }

    pub fn set_priority_indicator(mut self, value: NasPriorityIndicator) -> Self {
        self.priority_indicator = Some(value);
        self
    }
}

impl Encode for NasConfigurationUpdateCommand {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.configuration_update_indication {
            let mut ie = value.clone();
            ie.type_field = 0xD0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fg_guti {
            helpers::encode_optional_type(buffer, 0x77)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.tai_list {
            let mut ie = value.clone();
            ie.type_field = 0x54;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.allowed_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x15;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_area_list {
            let mut ie = value.clone();
            ie.type_field = 0x27;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.full_name_for_network {
            let mut ie = value.clone();
            ie.type_field = 0x43;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.short_name_for_network {
            let mut ie = value.clone();
            ie.type_field = 0x45;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.local_time_zone {
            let mut ie = value.clone();
            ie.type_field = 0x46;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.universal_time_and_local_time_zone {
            let mut ie = value.clone();
            ie.type_field = 0x47;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.network_daylight_saving_time {
            let mut ie = value.clone();
            ie.type_field = 0x49;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ladn_information {
            let mut ie = value.clone();
            ie.type_field = 0x79;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.mico_indication {
            let mut ie = value.clone();
            ie.type_field = 0xB0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.network_slicing_indication {
            let mut ie = value.clone();
            ie.type_field = 0x90;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.configured_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x31;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.rejected_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x11;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.operator_defined_access_category_definitions {
            let mut ie = value.clone();
            ie.type_field = 0x76;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.sms_indication {
            let mut ie = value.clone();
            ie.type_field = 0xF0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.t3447_value {
            let mut ie = value.clone();
            ie.type_field = 0x6C;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x75;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_radio_capability_id {
            let mut ie = value.clone();
            ie.type_field = 0x67;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_radio_capability_id_deletion_indication {
            let mut ie = value.clone();
            ie.type_field = 0xA0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgs_registration_result {
            helpers::encode_optional_type(buffer, 0x44)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.truncated_fg_s_tmsi_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x1B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.additional_configuration_indication {
            let mut ie = value.clone();
            ie.type_field = 0xC0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_rejected_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x68;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nssrg_information {
            let mut ie = value.clone();
            ie.type_field = 0x70;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.disaster_roaming_wait_range {
            let mut ie = value.clone();
            ie.type_field = 0x14;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.disaster_return_wait_range {
            let mut ie = value.clone();
            ie.type_field = 0x2C;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.list_of_plmns_to_be_used_in_disaster_condition {
            let mut ie = value.clone();
            ie.type_field = 0x13;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_cag_information_list {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.updated_peips_assistance_information {
            let mut ie = value.clone();
            ie.type_field = 0x1F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.nsag_information {
            let mut ie = value.clone();
            ie.type_field = 0x73;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.priority_indicator {
            let mut ie = value.clone();
            ie.type_field = 0xE0;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasConfigurationUpdateCommand {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0xD0 => {
                    message.configuration_update_indication = Some(NasConfigurationUpdateIndication::decode(buffer)?);
                },
                0x77 => {
                    buffer.advance(1); // Skip IEI
                    message.fg_guti = Some(NasFGsMobileIdentity::decode(buffer)?);
                },
                0x54 => {
                    message.tai_list = Some(NasFGsTrackingAreaIdentityList::decode(buffer)?);
                },
                0x15 => {
                    message.allowed_nssai = Some(NasNssai::decode(buffer)?);
                },
                0x27 => {
                    message.service_area_list = Some(NasServiceAreaList::decode(buffer)?);
                },
                0x43 => {
                    message.full_name_for_network = Some(NasNetworkName::decode(buffer)?);
                },
                0x45 => {
                    message.short_name_for_network = Some(NasNetworkName::decode(buffer)?);
                },
                0x46 => {
                    message.local_time_zone = Some(NasTimeZone::decode(buffer)?);
                },
                0x47 => {
                    message.universal_time_and_local_time_zone = Some(NasTimeZoneAndTime::decode(buffer)?);
                },
                0x49 => {
                    message.network_daylight_saving_time = Some(NasDaylightSavingTime::decode(buffer)?);
                },
                0x79 => {
                    message.ladn_information = Some(NasLadnInformation::decode(buffer)?);
                },
                0xB0 => {
                    message.mico_indication = Some(NasMicoIndication::decode(buffer)?);
                },
                0x90 => {
                    message.network_slicing_indication = Some(NasNetworkSlicingIndication::decode(buffer)?);
                },
                0x31 => {
                    message.configured_nssai = Some(NasNssai::decode(buffer)?);
                },
                0x11 => {
                    message.rejected_nssai = Some(NasRejectedNssai::decode(buffer)?);
                },
                0x76 => {
                    message.operator_defined_access_category_definitions = Some(NasOperatorDefinedAccessCategoryDefinitions::decode(buffer)?);
                },
                0xF0 => {
                    message.sms_indication = Some(NasSmsIndication::decode(buffer)?);
                },
                0x6C => {
                    message.t3447_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x75 => {
                    message.cag_information_list = Some(NasCagInformationList::decode(buffer)?);
                },
                0x67 => {
                    message.ue_radio_capability_id = Some(NasUeRadioCapabilityId::decode(buffer)?);
                },
                0xA0 => {
                    message.ue_radio_capability_id_deletion_indication = Some(NasUeRadioCapabilityIdDeletionIndication::decode(buffer)?);
                },
                0x44 => {
                    buffer.advance(1); // Skip IEI
                    message.fgs_registration_result = Some(NasFGsRegistrationResult::decode(buffer)?);
                },
                0x1B => {
                    message.truncated_fg_s_tmsi_configuration = Some(NasTruncatedFGSTmsiConfiguration::decode(buffer)?);
                },
                0xC0 => {
                    message.additional_configuration_indication = Some(NasAdditionalConfigurationIndication::decode(buffer)?);
                },
                0x68 => {
                    message.extended_rejected_nssai = Some(NasExtendedRejectedNssai::decode(buffer)?);
                },
                0x72 => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                0x70 => {
                    message.nssrg_information = Some(NasNssrgInformation::decode(buffer)?);
                },
                0x14 => {
                    message.disaster_roaming_wait_range = Some(NasRegistrationWaitRange::decode(buffer)?);
                },
                0x2C => {
                    message.disaster_return_wait_range = Some(NasRegistrationWaitRange::decode(buffer)?);
                },
                0x13 => {
                    message.list_of_plmns_to_be_used_in_disaster_condition = Some(NasListOfPlmnsToBeUsedInDisasterCondition::decode(buffer)?);
                },
                0x71 => {
                    message.extended_cag_information_list = Some(NasExtendedCagInformationList::decode(buffer)?);
                },
                0x1F => {
                    message.updated_peips_assistance_information = Some(NasPeipsAssistanceInformation::decode(buffer)?);
                },
                0x73 => {
                    message.nsag_information = Some(NasNsagInformation::decode(buffer)?);
                },
                0xE0 => {
                    message.priority_indicator = Some(NasPriorityIndicator::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// AUTHENTICATION REQUEST Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasAuthenticationRequest {
    // Mandatory fields
    pub ngksi: NasKeySetIdentifier,
    pub abba: NasAbba,

    // Optional fields
    pub authentication_parameter_rand: Option<NasAuthenticationParameterRand>,
    pub authentication_parameter_autn: Option<NasAuthenticationParameterAutn>,
    pub eap_message: Option<NasEapMessage>,
}

impl NasAuthenticationRequest {
    pub fn new(
        ngksi: NasKeySetIdentifier,
        abba: NasAbba,
    ) -> Self {
        Self {
            ngksi,
            abba,
            authentication_parameter_rand: None,
            authentication_parameter_autn: None,
            eap_message: None,
        }
    }

    pub fn set_authentication_parameter_rand(mut self, value: NasAuthenticationParameterRand) -> Self {
        self.authentication_parameter_rand = Some(value);
        self
    }

    pub fn set_authentication_parameter_autn(mut self, value: NasAuthenticationParameterAutn) -> Self {
        self.authentication_parameter_autn = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }
}

impl Encode for NasAuthenticationRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.ngksi.encode(buffer)?;
        self.abba.encode(buffer)?;
        if let Some(ref value) = self.authentication_parameter_rand {
            let mut ie = value.clone();
            ie.type_field = 0x21;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.authentication_parameter_autn {
            let mut ie = value.clone();
            ie.type_field = 0x20;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasAuthenticationRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let ngksi = NasKeySetIdentifier::decode(buffer)?;
        let abba = NasAbba::decode(buffer)?;

        let mut message = Self::new(
            ngksi,
            abba,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x21 => {
                    message.authentication_parameter_rand = Some(NasAuthenticationParameterRand::decode(buffer)?);
                },
                0x20 => {
                    message.authentication_parameter_autn = Some(NasAuthenticationParameterAutn::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// AUTHENTICATION RESPONSE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasAuthenticationResponse {
    // Mandatory fields

    // Optional fields
    pub authentication_response_parameter: Option<NasAuthenticationResponseParameter>,
    pub eap_message: Option<NasEapMessage>,
}

impl NasAuthenticationResponse {
    pub fn new(
    ) -> Self {
        Self {
            authentication_response_parameter: None,
            eap_message: None,
        }
    }

    pub fn set_authentication_response_parameter(mut self, value: NasAuthenticationResponseParameter) -> Self {
        self.authentication_response_parameter = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }
}

impl Encode for NasAuthenticationResponse {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.authentication_response_parameter {
            let mut ie = value.clone();
            ie.type_field = 0x2D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasAuthenticationResponse {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x2D => {
                    message.authentication_response_parameter = Some(NasAuthenticationResponseParameter::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// AUTHENTICATION REJECT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasAuthenticationReject {
    // Mandatory fields

    // Optional fields
    pub eap_message: Option<NasEapMessage>,
}

impl NasAuthenticationReject {
    pub fn new(
    ) -> Self {
        Self {
            eap_message: None,
        }
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }
}

impl Encode for NasAuthenticationReject {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasAuthenticationReject {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// AUTHENTICATION FAILURE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasAuthenticationFailure {
    // Mandatory fields
    pub fgmm_cause: NasFGmmCause,

    // Optional fields
    pub authentication_failure_parameter: Option<NasAuthenticationFailureParameter>,
}

impl NasAuthenticationFailure {
    pub fn new(
        fgmm_cause: NasFGmmCause,
    ) -> Self {
        Self {
            fgmm_cause,
            authentication_failure_parameter: None,
        }
    }

    pub fn set_authentication_failure_parameter(mut self, value: NasAuthenticationFailureParameter) -> Self {
        self.authentication_failure_parameter = Some(value);
        self
    }
}

impl Encode for NasAuthenticationFailure {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgmm_cause.encode(buffer)?;
        if let Some(ref value) = self.authentication_failure_parameter {
            let mut ie = value.clone();
            ie.type_field = 0x30;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasAuthenticationFailure {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgmm_cause = NasFGmmCause::decode(buffer)?;

        let mut message = Self::new(
            fgmm_cause,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x30 => {
                    message.authentication_failure_parameter = Some(NasAuthenticationFailureParameter::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// AUTHENTICATION RESULT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasAuthenticationResult {
    // Mandatory fields
    pub ngksi: NasKeySetIdentifier,
    pub eap_message: NasEapMessage,

    // Optional fields
    pub abba: Option<NasAbba>,
}

impl NasAuthenticationResult {
    pub fn new(
        ngksi: NasKeySetIdentifier,
        eap_message: NasEapMessage,
    ) -> Self {
        Self {
            ngksi,
            eap_message,
            abba: None,
        }
    }

    pub fn set_abba(mut self, value: NasAbba) -> Self {
        self.abba = Some(value);
        self
    }
}

impl Encode for NasAuthenticationResult {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.ngksi.encode(buffer)?;
        self.eap_message.encode(buffer)?;
        if let Some(ref value) = self.abba {
            helpers::encode_optional_type(buffer, 0x38)?;
            value.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasAuthenticationResult {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let ngksi = NasKeySetIdentifier::decode(buffer)?;
        let eap_message = NasEapMessage::decode(buffer)?;

        let mut message = Self::new(
            ngksi,
            eap_message,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x38 => {
                    buffer.advance(1); // Skip IEI
                    message.abba = Some(NasAbba::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// IDENTITY REQUEST Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasIdentityRequest {
    // Mandatory fields
    pub identity_type: NasFGsIdentityType,
}

impl NasIdentityRequest {
    pub fn new(
        identity_type: NasFGsIdentityType,
    ) -> Self {
        Self {
            identity_type,
        }
    }
}

impl Encode for NasIdentityRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.identity_type.encode(buffer)?;
        Ok(())
    }
}

impl Decode for NasIdentityRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let identity_type = NasFGsIdentityType::decode(buffer)?;

        let  message = Self::new(
            identity_type,
        );


        Ok(message)
    }
}

/// IDENTITY RESPONSE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasIdentityResponse {
    // Mandatory fields
    pub mobile_identity: NasFGsMobileIdentity,
}

impl NasIdentityResponse {
    pub fn new(
        mobile_identity: NasFGsMobileIdentity,
    ) -> Self {
        Self {
            mobile_identity,
        }
    }
}

impl Encode for NasIdentityResponse {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.mobile_identity.encode(buffer)?;
        Ok(())
    }
}

impl Decode for NasIdentityResponse {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let mobile_identity = NasFGsMobileIdentity::decode(buffer)?;

        let  message = Self::new(
            mobile_identity,
        );


        Ok(message)
    }
}

/// SECURITY MODE COMMAND Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasSecurityModeCommand {
    // Mandatory fields
    pub selected_nas_security_algorithms: NasSecurityAlgorithms,
    pub ngksi: NasKeySetIdentifier,
    pub replayed_ue_security_capabilities: NasUeSecurityCapability,

    // Optional fields
    pub imeisv_request: Option<NasImeisvRequest>,
    pub selected_eps_nas_security_algorithms: Option<NasEpsNasSecurityAlgorithms>,
    pub additional_fg_security_information: Option<NasAdditionalFGSecurityInformation>,
    pub eap_message: Option<NasEapMessage>,
    pub abba: Option<NasAbba>,
    pub replayed_s1_ue_security_capabilities: Option<NasS1UeSecurityCapability>,
}

impl NasSecurityModeCommand {
    pub fn new(
        selected_nas_security_algorithms: NasSecurityAlgorithms,
        ngksi: NasKeySetIdentifier,
        replayed_ue_security_capabilities: NasUeSecurityCapability,
    ) -> Self {
        Self {
            selected_nas_security_algorithms,
            ngksi,
            replayed_ue_security_capabilities,
            imeisv_request: None,
            selected_eps_nas_security_algorithms: None,
            additional_fg_security_information: None,
            eap_message: None,
            abba: None,
            replayed_s1_ue_security_capabilities: None,
        }
    }

    pub fn set_imeisv_request(mut self, value: NasImeisvRequest) -> Self {
        self.imeisv_request = Some(value);
        self
    }

    pub fn set_selected_eps_nas_security_algorithms(mut self, value: NasEpsNasSecurityAlgorithms) -> Self {
        self.selected_eps_nas_security_algorithms = Some(value);
        self
    }

    pub fn set_additional_fg_security_information(mut self, value: NasAdditionalFGSecurityInformation) -> Self {
        self.additional_fg_security_information = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_abba(mut self, value: NasAbba) -> Self {
        self.abba = Some(value);
        self
    }

    pub fn set_replayed_s1_ue_security_capabilities(mut self, value: NasS1UeSecurityCapability) -> Self {
        self.replayed_s1_ue_security_capabilities = Some(value);
        self
    }
}

impl Encode for NasSecurityModeCommand {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.selected_nas_security_algorithms.encode(buffer)?;
        self.ngksi.encode(buffer)?;
        self.replayed_ue_security_capabilities.encode(buffer)?;
        if let Some(ref value) = self.imeisv_request {
            let mut ie = value.clone();
            ie.type_field = 0xE0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.selected_eps_nas_security_algorithms {
            let mut ie = value.clone();
            ie.type_field = 0x57;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.additional_fg_security_information {
            let mut ie = value.clone();
            ie.type_field = 0x36;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.abba {
            helpers::encode_optional_type(buffer, 0x38)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.replayed_s1_ue_security_capabilities {
            let mut ie = value.clone();
            ie.type_field = 0x19;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasSecurityModeCommand {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let selected_nas_security_algorithms = NasSecurityAlgorithms::decode(buffer)?;
        let ngksi = NasKeySetIdentifier::decode(buffer)?;
        let replayed_ue_security_capabilities = NasUeSecurityCapability::decode(buffer)?;

        let mut message = Self::new(
            selected_nas_security_algorithms,
            ngksi,
            replayed_ue_security_capabilities,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0xE0 => {
                    message.imeisv_request = Some(NasImeisvRequest::decode(buffer)?);
                },
                0x57 => {
                    message.selected_eps_nas_security_algorithms = Some(NasEpsNasSecurityAlgorithms::decode(buffer)?);
                },
                0x36 => {
                    message.additional_fg_security_information = Some(NasAdditionalFGSecurityInformation::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0x38 => {
                    buffer.advance(1); // Skip IEI
                    message.abba = Some(NasAbba::decode(buffer)?);
                },
                0x19 => {
                    message.replayed_s1_ue_security_capabilities = Some(NasS1UeSecurityCapability::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// SECURITY MODE COMPLETE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasSecurityModeComplete {
    // Mandatory fields

    // Optional fields
    pub imeisv: Option<NasFGsMobileIdentity>,
    pub nas_message_container: Option<NasMessageContainer>,
    pub non_imeisv_pei: Option<NasFGsMobileIdentity>,
}

impl NasSecurityModeComplete {
    pub fn new(
    ) -> Self {
        Self {
            imeisv: None,
            nas_message_container: None,
            non_imeisv_pei: None,
        }
    }

    pub fn set_imeisv(mut self, value: NasFGsMobileIdentity) -> Self {
        self.imeisv = Some(value);
        self
    }

    pub fn set_nas_message_container(mut self, value: NasMessageContainer) -> Self {
        self.nas_message_container = Some(value);
        self
    }

    pub fn set_non_imeisv_pei(mut self, value: NasFGsMobileIdentity) -> Self {
        self.non_imeisv_pei = Some(value);
        self
    }
}

impl Encode for NasSecurityModeComplete {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.imeisv {
            helpers::encode_optional_type(buffer, 0x77)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.nas_message_container {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.non_imeisv_pei {
            helpers::encode_optional_type(buffer, 0x78)?;
            value.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasSecurityModeComplete {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x77 => {
                    buffer.advance(1); // Skip IEI
                    message.imeisv = Some(NasFGsMobileIdentity::decode(buffer)?);
                },
                0x71 => {
                    message.nas_message_container = Some(NasMessageContainer::decode(buffer)?);
                },
                0x78 => {
                    buffer.advance(1); // Skip IEI
                    message.non_imeisv_pei = Some(NasFGsMobileIdentity::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// SECURITY MODE REJECT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasSecurityModeReject {
    // Mandatory fields
    pub fgmm_cause: NasFGmmCause,
}

impl NasSecurityModeReject {
    pub fn new(
        fgmm_cause: NasFGmmCause,
    ) -> Self {
        Self {
            fgmm_cause,
        }
    }
}

impl Encode for NasSecurityModeReject {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgmm_cause.encode(buffer)?;
        Ok(())
    }
}

impl Decode for NasSecurityModeReject {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgmm_cause = NasFGmmCause::decode(buffer)?;

        let  message = Self::new(
            fgmm_cause,
        );


        Ok(message)
    }
}

/// 5GMM STATUS Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasFGmmStatus {
    // Mandatory fields
    pub fgmm_cause: NasFGmmCause,
}

impl NasFGmmStatus {
    pub fn new(
        fgmm_cause: NasFGmmCause,
    ) -> Self {
        Self {
            fgmm_cause,
        }
    }
}

impl Encode for NasFGmmStatus {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgmm_cause.encode(buffer)?;
        Ok(())
    }
}

impl Decode for NasFGmmStatus {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgmm_cause = NasFGmmCause::decode(buffer)?;

        let  message = Self::new(
            fgmm_cause,
        );


        Ok(message)
    }
}

/// NOTIFICATION Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasNotification {
    // Mandatory fields
    pub access_type: NasAccessType,
}

impl NasNotification {
    pub fn new(
        access_type: NasAccessType,
    ) -> Self {
        Self {
            access_type,
        }
    }
}

impl Encode for NasNotification {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.access_type.encode(buffer)?;
        Ok(())
    }
}

impl Decode for NasNotification {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let access_type = NasAccessType::decode(buffer)?;

        let  message = Self::new(
            access_type,
        );


        Ok(message)
    }
}

/// NOTIFICATION RESPONSE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasNotificationResponse {
    // Mandatory fields

    // Optional fields
    pub pdu_session_status: Option<NasPduSessionStatus>,
}

impl NasNotificationResponse {
    pub fn new(
    ) -> Self {
        Self {
            pdu_session_status: None,
        }
    }

    pub fn set_pdu_session_status(mut self, value: NasPduSessionStatus) -> Self {
        self.pdu_session_status = Some(value);
        self
    }
}

impl Encode for NasNotificationResponse {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.pdu_session_status {
            let mut ie = value.clone();
            ie.type_field = 0x50;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasNotificationResponse {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x50 => {
                    message.pdu_session_status = Some(NasPduSessionStatus::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// UL NAS TRANSPORT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasUlNasTransport {
    // Mandatory fields
    pub payload_container_type: NasPayloadContainerType,
    pub payload_container: NasPayloadContainer,

    // Optional fields
    pub pdu_session_id: Option<NasPduSessionIdentity2>,
    pub old_pdu_session_id: Option<NasPduSessionIdentity2>,
    pub request_type: Option<NasRequestType>,
    pub s_nssai: Option<NasSNssai>,
    pub dnn: Option<NasDnn>,
    pub additional_information: Option<NasAdditionalInformation>,
    pub ma_pdu_session_information: Option<NasMaPduSessionInformation>,
    pub release_assistance_indication: Option<NasReleaseAssistanceIndication>,
}

impl NasUlNasTransport {
    pub fn new(
        payload_container_type: NasPayloadContainerType,
        payload_container: NasPayloadContainer,
    ) -> Self {
        Self {
            payload_container_type,
            payload_container,
            pdu_session_id: None,
            old_pdu_session_id: None,
            request_type: None,
            s_nssai: None,
            dnn: None,
            additional_information: None,
            ma_pdu_session_information: None,
            release_assistance_indication: None,
        }
    }

    pub fn set_pdu_session_id(mut self, value: NasPduSessionIdentity2) -> Self {
        self.pdu_session_id = Some(value);
        self
    }

    pub fn set_old_pdu_session_id(mut self, value: NasPduSessionIdentity2) -> Self {
        self.old_pdu_session_id = Some(value);
        self
    }

    pub fn set_request_type(mut self, value: NasRequestType) -> Self {
        self.request_type = Some(value);
        self
    }

    pub fn set_s_nssai(mut self, value: NasSNssai) -> Self {
        self.s_nssai = Some(value);
        self
    }

    pub fn set_dnn(mut self, value: NasDnn) -> Self {
        self.dnn = Some(value);
        self
    }

    pub fn set_additional_information(mut self, value: NasAdditionalInformation) -> Self {
        self.additional_information = Some(value);
        self
    }

    pub fn set_ma_pdu_session_information(mut self, value: NasMaPduSessionInformation) -> Self {
        self.ma_pdu_session_information = Some(value);
        self
    }

    pub fn set_release_assistance_indication(mut self, value: NasReleaseAssistanceIndication) -> Self {
        self.release_assistance_indication = Some(value);
        self
    }
}

impl Encode for NasUlNasTransport {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.payload_container_type.encode(buffer)?;
        self.payload_container.encode(buffer)?;
        if let Some(ref value) = self.pdu_session_id {
            let mut ie = value.clone();
            ie.type_field = 0x12;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.old_pdu_session_id {
            let mut ie = value.clone();
            ie.type_field = 0x59;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.request_type {
            let mut ie = value.clone();
            ie.type_field = 0x80;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.s_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x22;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.dnn {
            let mut ie = value.clone();
            ie.type_field = 0x25;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.additional_information {
            let mut ie = value.clone();
            ie.type_field = 0x24;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ma_pdu_session_information {
            let mut ie = value.clone();
            ie.type_field = 0xA0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.release_assistance_indication {
            let mut ie = value.clone();
            ie.type_field = 0xF0;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasUlNasTransport {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let payload_container_type = NasPayloadContainerType::decode(buffer)?;
        let payload_container = NasPayloadContainer::decode(buffer)?;

        let mut message = Self::new(
            payload_container_type,
            payload_container,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x12 => {
                    message.pdu_session_id = Some(NasPduSessionIdentity2::decode(buffer)?);
                },
                0x59 => {
                    message.old_pdu_session_id = Some(NasPduSessionIdentity2::decode(buffer)?);
                },
                0x80 => {
                    message.request_type = Some(NasRequestType::decode(buffer)?);
                },
                0x22 => {
                    message.s_nssai = Some(NasSNssai::decode(buffer)?);
                },
                0x25 => {
                    message.dnn = Some(NasDnn::decode(buffer)?);
                },
                0x24 => {
                    message.additional_information = Some(NasAdditionalInformation::decode(buffer)?);
                },
                0xA0 => {
                    message.ma_pdu_session_information = Some(NasMaPduSessionInformation::decode(buffer)?);
                },
                0xF0 => {
                    message.release_assistance_indication = Some(NasReleaseAssistanceIndication::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// DL NAS TRANSPORT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasDlNasTransport {
    // Mandatory fields
    pub payload_container_type: NasPayloadContainerType,
    pub payload_container: NasPayloadContainer,

    // Optional fields
    pub pdu_session_id: Option<NasPduSessionIdentity2>,
    pub additional_information: Option<NasAdditionalInformation>,
    pub fgmm_cause: Option<NasFGmmCause>,
    pub back_off_timer_value: Option<NasGprsTimer3>,
    pub lower_bound_timer_value: Option<NasGprsTimer3>,
}

impl NasDlNasTransport {
    pub fn new(
        payload_container_type: NasPayloadContainerType,
        payload_container: NasPayloadContainer,
    ) -> Self {
        Self {
            payload_container_type,
            payload_container,
            pdu_session_id: None,
            additional_information: None,
            fgmm_cause: None,
            back_off_timer_value: None,
            lower_bound_timer_value: None,
        }
    }

    pub fn set_pdu_session_id(mut self, value: NasPduSessionIdentity2) -> Self {
        self.pdu_session_id = Some(value);
        self
    }

    pub fn set_additional_information(mut self, value: NasAdditionalInformation) -> Self {
        self.additional_information = Some(value);
        self
    }

    pub fn set_fgmm_cause(mut self, value: NasFGmmCause) -> Self {
        self.fgmm_cause = Some(value);
        self
    }

    pub fn set_back_off_timer_value(mut self, value: NasGprsTimer3) -> Self {
        self.back_off_timer_value = Some(value);
        self
    }

    pub fn set_lower_bound_timer_value(mut self, value: NasGprsTimer3) -> Self {
        self.lower_bound_timer_value = Some(value);
        self
    }
}

impl Encode for NasDlNasTransport {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.payload_container_type.encode(buffer)?;
        self.payload_container.encode(buffer)?;
        if let Some(ref value) = self.pdu_session_id {
            let mut ie = value.clone();
            ie.type_field = 0x12;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.additional_information {
            let mut ie = value.clone();
            ie.type_field = 0x24;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgmm_cause {
            helpers::encode_optional_type(buffer, 0x58)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.back_off_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x37;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.lower_bound_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x3A;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasDlNasTransport {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let payload_container_type = NasPayloadContainerType::decode(buffer)?;
        let payload_container = NasPayloadContainer::decode(buffer)?;

        let mut message = Self::new(
            payload_container_type,
            payload_container,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x12 => {
                    message.pdu_session_id = Some(NasPduSessionIdentity2::decode(buffer)?);
                },
                0x24 => {
                    message.additional_information = Some(NasAdditionalInformation::decode(buffer)?);
                },
                0x58 => {
                    buffer.advance(1); // Skip IEI
                    message.fgmm_cause = Some(NasFGmmCause::decode(buffer)?);
                },
                0x37 => {
                    message.back_off_timer_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x3A => {
                    message.lower_bound_timer_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION ESTABLISHMENT REQUEST Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionEstablishmentRequest {
    // Mandatory fields
    pub integrity_protection_maximum_data_rate: NasIntegrityProtectionMaximumDataRate,

    // Optional fields
    pub pdu_session_type: Option<NasPduSessionType>,
    pub ssc_mode: Option<NasSscMode>,
    pub fgsm_capability: Option<NasFGsmCapability>,
    pub maximum_number_of_supported_packet_filters: Option<NasMaximumNumberOfSupportedPacketFilters>,
    pub always_on_pdu_session_requested: Option<NasAlwaysOnPduSessionRequested>,
    pub sm_pdu_dn_request_container: Option<NasSmPduDnRequestContainer>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
    pub ip_header_compression_configuration: Option<NasIpHeaderCompressionConfiguration>,
    pub ds_tt_ethernet_port_mac_address: Option<NasDsTtEthernetPortMacAddress>,
    pub ue_ds_tt_residence_time: Option<NasUeDsTtResidenceTime>,
    pub port_management_information_container: Option<NasPortManagementInformationContainer>,
    pub ethernet_header_compression_configuration: Option<NasEthernetHeaderCompressionConfiguration>,
    pub suggested_interface_identifier: Option<NasPduAddress>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
    pub requested_mbs_container: Option<NasRequestedMbsContainer>,
    pub pdu_session_pair_id: Option<NasPduSessionPairId>,
    pub rsn: Option<NasRsn>,
}

impl NasPduSessionEstablishmentRequest {
    pub fn new(
        integrity_protection_maximum_data_rate: NasIntegrityProtectionMaximumDataRate,
    ) -> Self {
        Self {
            integrity_protection_maximum_data_rate,
            pdu_session_type: None,
            ssc_mode: None,
            fgsm_capability: None,
            maximum_number_of_supported_packet_filters: None,
            always_on_pdu_session_requested: None,
            sm_pdu_dn_request_container: None,
            extended_protocol_configuration_options: None,
            ip_header_compression_configuration: None,
            ds_tt_ethernet_port_mac_address: None,
            ue_ds_tt_residence_time: None,
            port_management_information_container: None,
            ethernet_header_compression_configuration: None,
            suggested_interface_identifier: None,
            service_level_aa_container: None,
            requested_mbs_container: None,
            pdu_session_pair_id: None,
            rsn: None,
        }
    }

    pub fn set_pdu_session_type(mut self, value: NasPduSessionType) -> Self {
        self.pdu_session_type = Some(value);
        self
    }

    pub fn set_ssc_mode(mut self, value: NasSscMode) -> Self {
        self.ssc_mode = Some(value);
        self
    }

    pub fn set_fgsm_capability(mut self, value: NasFGsmCapability) -> Self {
        self.fgsm_capability = Some(value);
        self
    }

    pub fn set_maximum_number_of_supported_packet_filters(mut self, value: NasMaximumNumberOfSupportedPacketFilters) -> Self {
        self.maximum_number_of_supported_packet_filters = Some(value);
        self
    }

    pub fn set_always_on_pdu_session_requested(mut self, value: NasAlwaysOnPduSessionRequested) -> Self {
        self.always_on_pdu_session_requested = Some(value);
        self
    }

    pub fn set_sm_pdu_dn_request_container(mut self, value: NasSmPduDnRequestContainer) -> Self {
        self.sm_pdu_dn_request_container = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }

    pub fn set_ip_header_compression_configuration(mut self, value: NasIpHeaderCompressionConfiguration) -> Self {
        self.ip_header_compression_configuration = Some(value);
        self
    }

    pub fn set_ds_tt_ethernet_port_mac_address(mut self, value: NasDsTtEthernetPortMacAddress) -> Self {
        self.ds_tt_ethernet_port_mac_address = Some(value);
        self
    }

    pub fn set_ue_ds_tt_residence_time(mut self, value: NasUeDsTtResidenceTime) -> Self {
        self.ue_ds_tt_residence_time = Some(value);
        self
    }

    pub fn set_port_management_information_container(mut self, value: NasPortManagementInformationContainer) -> Self {
        self.port_management_information_container = Some(value);
        self
    }

    pub fn set_ethernet_header_compression_configuration(mut self, value: NasEthernetHeaderCompressionConfiguration) -> Self {
        self.ethernet_header_compression_configuration = Some(value);
        self
    }

    pub fn set_suggested_interface_identifier(mut self, value: NasPduAddress) -> Self {
        self.suggested_interface_identifier = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }

    pub fn set_requested_mbs_container(mut self, value: NasRequestedMbsContainer) -> Self {
        self.requested_mbs_container = Some(value);
        self
    }

    pub fn set_pdu_session_pair_id(mut self, value: NasPduSessionPairId) -> Self {
        self.pdu_session_pair_id = Some(value);
        self
    }

    pub fn set_rsn(mut self, value: NasRsn) -> Self {
        self.rsn = Some(value);
        self
    }
}

impl Encode for NasPduSessionEstablishmentRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.integrity_protection_maximum_data_rate.encode(buffer)?;
        if let Some(ref value) = self.pdu_session_type {
            let mut ie = value.clone();
            ie.type_field = 0x90;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ssc_mode {
            let mut ie = value.clone();
            ie.type_field = 0xA0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgsm_capability {
            let mut ie = value.clone();
            ie.type_field = 0x28;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.maximum_number_of_supported_packet_filters {
            helpers::encode_optional_type(buffer, 0x55)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.always_on_pdu_session_requested {
            let mut ie = value.clone();
            ie.type_field = 0xB0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.sm_pdu_dn_request_container {
            let mut ie = value.clone();
            ie.type_field = 0x39;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ip_header_compression_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x66;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ds_tt_ethernet_port_mac_address {
            let mut ie = value.clone();
            ie.type_field = 0x6E;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ue_ds_tt_residence_time {
            let mut ie = value.clone();
            ie.type_field = 0x6F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.port_management_information_container {
            let mut ie = value.clone();
            ie.type_field = 0x74;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ethernet_header_compression_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x1F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.suggested_interface_identifier {
            let mut ie = value.clone();
            ie.type_field = 0x29;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_mbs_container {
            let mut ie = value.clone();
            ie.type_field = 0x70;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_session_pair_id {
            let mut ie = value.clone();
            ie.type_field = 0x34;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.rsn {
            let mut ie = value.clone();
            ie.type_field = 0x35;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionEstablishmentRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let integrity_protection_maximum_data_rate = NasIntegrityProtectionMaximumDataRate::decode(buffer)?;

        let mut message = Self::new(
            integrity_protection_maximum_data_rate,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x90 => {
                    message.pdu_session_type = Some(NasPduSessionType::decode(buffer)?);
                },
                0xA0 => {
                    message.ssc_mode = Some(NasSscMode::decode(buffer)?);
                },
                0x28 => {
                    message.fgsm_capability = Some(NasFGsmCapability::decode(buffer)?);
                },
                0x55 => {
                    buffer.advance(1); // Skip IEI
                    message.maximum_number_of_supported_packet_filters = Some(NasMaximumNumberOfSupportedPacketFilters::decode(buffer)?);
                },
                0xB0 => {
                    message.always_on_pdu_session_requested = Some(NasAlwaysOnPduSessionRequested::decode(buffer)?);
                },
                0x39 => {
                    message.sm_pdu_dn_request_container = Some(NasSmPduDnRequestContainer::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                0x66 => {
                    message.ip_header_compression_configuration = Some(NasIpHeaderCompressionConfiguration::decode(buffer)?);
                },
                0x6E => {
                    message.ds_tt_ethernet_port_mac_address = Some(NasDsTtEthernetPortMacAddress::decode(buffer)?);
                },
                0x6F => {
                    message.ue_ds_tt_residence_time = Some(NasUeDsTtResidenceTime::decode(buffer)?);
                },
                0x74 => {
                    message.port_management_information_container = Some(NasPortManagementInformationContainer::decode(buffer)?);
                },
                0x1F => {
                    message.ethernet_header_compression_configuration = Some(NasEthernetHeaderCompressionConfiguration::decode(buffer)?);
                },
                0x29 => {
                    message.suggested_interface_identifier = Some(NasPduAddress::decode(buffer)?);
                },
                0x72 => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                0x70 => {
                    message.requested_mbs_container = Some(NasRequestedMbsContainer::decode(buffer)?);
                },
                0x34 => {
                    message.pdu_session_pair_id = Some(NasPduSessionPairId::decode(buffer)?);
                },
                0x35 => {
                    message.rsn = Some(NasRsn::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION ESTABLISHMENT ACCEPT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionEstablishmentAccept {
    // Mandatory fields
    pub selected_pdu_session_type: NasPduSessionType,
    pub authorized_qos_rules: NasQosRules,
    pub session_ambr: NasSessionAmbr,

    // Optional fields
    pub fgsm_cause: Option<NasFGsmCause>,
    pub pdu_address: Option<NasPduAddress>,
    pub rq_timer_value: Option<NasGprsTimer>,
    pub s_nssai: Option<NasSNssai>,
    pub always_on_pdu_session_indication: Option<NasAlwaysOnPduSessionIndication>,
    pub mapped_eps_bearer_contexts: Option<NasMappedEpsBearerContexts>,
    pub eap_message: Option<NasEapMessage>,
    pub authorized_qos_flow_descriptions: Option<NasQosFlowDescriptions>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
    pub dnn: Option<NasDnn>,
    pub fgsm_network_feature_support: Option<NasFGsmNetworkFeatureSupport>,
    pub serving_plmn_rate_control: Option<NasServingPlmnRateControl>,
    pub atsss_container: Option<NasAtsssContainer>,
    pub control_plane_only_indication: Option<NasControlPlaneOnlyIndication>,
    pub ip_header_compression_configuration: Option<NasIpHeaderCompressionConfiguration>,
    pub ethernet_header_compression_configuration: Option<NasEthernetHeaderCompressionConfiguration>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
    pub received_mbs_container: Option<NasReceivedMbsContainer>,
}

impl NasPduSessionEstablishmentAccept {
    pub fn new(
        selected_pdu_session_type: NasPduSessionType,
        authorized_qos_rules: NasQosRules,
        session_ambr: NasSessionAmbr,
    ) -> Self {
        Self {
            selected_pdu_session_type,
            authorized_qos_rules,
            session_ambr,
            fgsm_cause: None,
            pdu_address: None,
            rq_timer_value: None,
            s_nssai: None,
            always_on_pdu_session_indication: None,
            mapped_eps_bearer_contexts: None,
            eap_message: None,
            authorized_qos_flow_descriptions: None,
            extended_protocol_configuration_options: None,
            dnn: None,
            fgsm_network_feature_support: None,
            serving_plmn_rate_control: None,
            atsss_container: None,
            control_plane_only_indication: None,
            ip_header_compression_configuration: None,
            ethernet_header_compression_configuration: None,
            service_level_aa_container: None,
            received_mbs_container: None,
        }
    }

    pub fn set_fgsm_cause(mut self, value: NasFGsmCause) -> Self {
        self.fgsm_cause = Some(value);
        self
    }

    pub fn set_pdu_address(mut self, value: NasPduAddress) -> Self {
        self.pdu_address = Some(value);
        self
    }

    pub fn set_rq_timer_value(mut self, value: NasGprsTimer) -> Self {
        self.rq_timer_value = Some(value);
        self
    }

    pub fn set_s_nssai(mut self, value: NasSNssai) -> Self {
        self.s_nssai = Some(value);
        self
    }

    pub fn set_always_on_pdu_session_indication(mut self, value: NasAlwaysOnPduSessionIndication) -> Self {
        self.always_on_pdu_session_indication = Some(value);
        self
    }

    pub fn set_mapped_eps_bearer_contexts(mut self, value: NasMappedEpsBearerContexts) -> Self {
        self.mapped_eps_bearer_contexts = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_authorized_qos_flow_descriptions(mut self, value: NasQosFlowDescriptions) -> Self {
        self.authorized_qos_flow_descriptions = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }

    pub fn set_dnn(mut self, value: NasDnn) -> Self {
        self.dnn = Some(value);
        self
    }

    pub fn set_fgsm_network_feature_support(mut self, value: NasFGsmNetworkFeatureSupport) -> Self {
        self.fgsm_network_feature_support = Some(value);
        self
    }

    pub fn set_serving_plmn_rate_control(mut self, value: NasServingPlmnRateControl) -> Self {
        self.serving_plmn_rate_control = Some(value);
        self
    }

    pub fn set_atsss_container(mut self, value: NasAtsssContainer) -> Self {
        self.atsss_container = Some(value);
        self
    }

    pub fn set_control_plane_only_indication(mut self, value: NasControlPlaneOnlyIndication) -> Self {
        self.control_plane_only_indication = Some(value);
        self
    }

    pub fn set_ip_header_compression_configuration(mut self, value: NasIpHeaderCompressionConfiguration) -> Self {
        self.ip_header_compression_configuration = Some(value);
        self
    }

    pub fn set_ethernet_header_compression_configuration(mut self, value: NasEthernetHeaderCompressionConfiguration) -> Self {
        self.ethernet_header_compression_configuration = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }

    pub fn set_received_mbs_container(mut self, value: NasReceivedMbsContainer) -> Self {
        self.received_mbs_container = Some(value);
        self
    }
}

impl Encode for NasPduSessionEstablishmentAccept {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.selected_pdu_session_type.encode(buffer)?;
        self.authorized_qos_rules.encode(buffer)?;
        self.session_ambr.encode(buffer)?;
        if let Some(ref value) = self.fgsm_cause {
            let mut ie = value.clone();
            ie.type_field = 0x59;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.pdu_address {
            let mut ie = value.clone();
            ie.type_field = 0x29;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.rq_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x56;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.s_nssai {
            let mut ie = value.clone();
            ie.type_field = 0x22;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.always_on_pdu_session_indication {
            let mut ie = value.clone();
            ie.type_field = 0x80;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.mapped_eps_bearer_contexts {
            let mut ie = value.clone();
            ie.type_field = 0x75;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.authorized_qos_flow_descriptions {
            let mut ie = value.clone();
            ie.type_field = 0x79;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.dnn {
            let mut ie = value.clone();
            ie.type_field = 0x25;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgsm_network_feature_support {
            let mut ie = value.clone();
            ie.type_field = 0x17;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.serving_plmn_rate_control {
            let mut ie = value.clone();
            ie.type_field = 0x18;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.atsss_container {
            let mut ie = value.clone();
            ie.type_field = 0x77;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.control_plane_only_indication {
            let mut ie = value.clone();
            ie.type_field = 0xC0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ip_header_compression_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x66;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ethernet_header_compression_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x1F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.received_mbs_container {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionEstablishmentAccept {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let selected_pdu_session_type = NasPduSessionType::decode(buffer)?;
        let authorized_qos_rules = NasQosRules::decode(buffer)?;
        let session_ambr = NasSessionAmbr::decode(buffer)?;

        let mut message = Self::new(
            selected_pdu_session_type,
            authorized_qos_rules,
            session_ambr,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x59 => {
                    message.fgsm_cause = Some(NasFGsmCause::decode(buffer)?);
                },
                0x29 => {
                    message.pdu_address = Some(NasPduAddress::decode(buffer)?);
                },
                0x56 => {
                    message.rq_timer_value = Some(NasGprsTimer::decode(buffer)?);
                },
                0x22 => {
                    message.s_nssai = Some(NasSNssai::decode(buffer)?);
                },
                0x80 => {
                    message.always_on_pdu_session_indication = Some(NasAlwaysOnPduSessionIndication::decode(buffer)?);
                },
                0x75 => {
                    message.mapped_eps_bearer_contexts = Some(NasMappedEpsBearerContexts::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0x79 => {
                    message.authorized_qos_flow_descriptions = Some(NasQosFlowDescriptions::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                0x25 => {
                    message.dnn = Some(NasDnn::decode(buffer)?);
                },
                0x17 => {
                    message.fgsm_network_feature_support = Some(NasFGsmNetworkFeatureSupport::decode(buffer)?);
                },
                0x18 => {
                    message.serving_plmn_rate_control = Some(NasServingPlmnRateControl::decode(buffer)?);
                },
                0x77 => {
                    message.atsss_container = Some(NasAtsssContainer::decode(buffer)?);
                },
                0xC0 => {
                    message.control_plane_only_indication = Some(NasControlPlaneOnlyIndication::decode(buffer)?);
                },
                0x66 => {
                    message.ip_header_compression_configuration = Some(NasIpHeaderCompressionConfiguration::decode(buffer)?);
                },
                0x1F => {
                    message.ethernet_header_compression_configuration = Some(NasEthernetHeaderCompressionConfiguration::decode(buffer)?);
                },
                0x72 => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                0x71 => {
                    message.received_mbs_container = Some(NasReceivedMbsContainer::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION ESTABLISHMENT REJECT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionEstablishmentReject {
    // Mandatory fields
    pub fgsm_cause: NasFGsmCause,

    // Optional fields
    pub back_off_timer_value: Option<NasGprsTimer3>,
    pub allowed_ssc_mode: Option<NasAllowedSscMode>,
    pub eap_message: Option<NasEapMessage>,
    pub fgsm_congestion_re_attempt_indicator: Option<NasFGsmCongestionReAttemptIndicator>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
    pub re_attempt_indicator: Option<NasReAttemptIndicator>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
}

impl NasPduSessionEstablishmentReject {
    pub fn new(
        fgsm_cause: NasFGsmCause,
    ) -> Self {
        Self {
            fgsm_cause,
            back_off_timer_value: None,
            allowed_ssc_mode: None,
            eap_message: None,
            fgsm_congestion_re_attempt_indicator: None,
            extended_protocol_configuration_options: None,
            re_attempt_indicator: None,
            service_level_aa_container: None,
        }
    }

    pub fn set_back_off_timer_value(mut self, value: NasGprsTimer3) -> Self {
        self.back_off_timer_value = Some(value);
        self
    }

    pub fn set_allowed_ssc_mode(mut self, value: NasAllowedSscMode) -> Self {
        self.allowed_ssc_mode = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_fgsm_congestion_re_attempt_indicator(mut self, value: NasFGsmCongestionReAttemptIndicator) -> Self {
        self.fgsm_congestion_re_attempt_indicator = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }

    pub fn set_re_attempt_indicator(mut self, value: NasReAttemptIndicator) -> Self {
        self.re_attempt_indicator = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }
}

impl Encode for NasPduSessionEstablishmentReject {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgsm_cause.encode(buffer)?;
        if let Some(ref value) = self.back_off_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x37;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.allowed_ssc_mode {
            let mut ie = value.clone();
            ie.type_field = 0xF0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgsm_congestion_re_attempt_indicator {
            let mut ie = value.clone();
            ie.type_field = 0x61;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.re_attempt_indicator {
            let mut ie = value.clone();
            ie.type_field = 0x1D;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionEstablishmentReject {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgsm_cause = NasFGsmCause::decode(buffer)?;

        let mut message = Self::new(
            fgsm_cause,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x37 => {
                    message.back_off_timer_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0xF0 => {
                    message.allowed_ssc_mode = Some(NasAllowedSscMode::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0x61 => {
                    message.fgsm_congestion_re_attempt_indicator = Some(NasFGsmCongestionReAttemptIndicator::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                0x1D => {
                    message.re_attempt_indicator = Some(NasReAttemptIndicator::decode(buffer)?);
                },
                0x72 => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION AUTHENTICATION COMMAND Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionAuthenticationCommand {
    // Mandatory fields
    pub eap_message: NasEapMessage,

    // Optional fields
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
}

impl NasPduSessionAuthenticationCommand {
    pub fn new(
        eap_message: NasEapMessage,
    ) -> Self {
        Self {
            eap_message,
            extended_protocol_configuration_options: None,
        }
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }
}

impl Encode for NasPduSessionAuthenticationCommand {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.eap_message.encode(buffer)?;
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionAuthenticationCommand {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let eap_message = NasEapMessage::decode(buffer)?;

        let mut message = Self::new(
            eap_message,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION AUTHENTICATION COMPLETE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionAuthenticationComplete {
    // Mandatory fields
    pub eap_message: NasEapMessage,

    // Optional fields
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
}

impl NasPduSessionAuthenticationComplete {
    pub fn new(
        eap_message: NasEapMessage,
    ) -> Self {
        Self {
            eap_message,
            extended_protocol_configuration_options: None,
        }
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }
}

impl Encode for NasPduSessionAuthenticationComplete {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.eap_message.encode(buffer)?;
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionAuthenticationComplete {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let eap_message = NasEapMessage::decode(buffer)?;

        let mut message = Self::new(
            eap_message,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION AUTHENTICATION RESULT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionAuthenticationResult {
    // Mandatory fields

    // Optional fields
    pub eap_message: Option<NasEapMessage>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
}

impl NasPduSessionAuthenticationResult {
    pub fn new(
    ) -> Self {
        Self {
            eap_message: None,
            extended_protocol_configuration_options: None,
        }
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }
}

impl Encode for NasPduSessionAuthenticationResult {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionAuthenticationResult {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION MODIFICATION REQUEST Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionModificationRequest {
    // Mandatory fields

    // Optional fields
    pub fgsm_capability: Option<NasFGsmCapability>,
    pub fgsm_cause: Option<NasFGsmCause>,
    pub maximum_number_of_supported_packet_filters: Option<NasMaximumNumberOfSupportedPacketFilters>,
    pub always_on_pdu_session_requested: Option<NasAlwaysOnPduSessionRequested>,
    pub integrity_protection_maximum_data_rate: Option<NasIntegrityProtectionMaximumDataRate>,
    pub requested_qos_rules: Option<NasQosRules>,
    pub requested_qos_flow_descriptions: Option<NasQosFlowDescriptions>,
    pub mapped_eps_bearer_contexts: Option<NasMappedEpsBearerContexts>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
    pub port_management_information_container: Option<NasPortManagementInformationContainer>,
    pub ip_header_compression_configuration: Option<NasHeaderCompressionConfiguration>,
    pub ethernet_header_compression_configuration: Option<NasEthernetHeaderCompressionConfiguration>,
    pub requested_mbs_container: Option<NasRequestedMbsContainer>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
}

impl NasPduSessionModificationRequest {
    pub fn new(
    ) -> Self {
        Self {
            fgsm_capability: None,
            fgsm_cause: None,
            maximum_number_of_supported_packet_filters: None,
            always_on_pdu_session_requested: None,
            integrity_protection_maximum_data_rate: None,
            requested_qos_rules: None,
            requested_qos_flow_descriptions: None,
            mapped_eps_bearer_contexts: None,
            extended_protocol_configuration_options: None,
            port_management_information_container: None,
            ip_header_compression_configuration: None,
            ethernet_header_compression_configuration: None,
            requested_mbs_container: None,
            service_level_aa_container: None,
        }
    }

    pub fn set_fgsm_capability(mut self, value: NasFGsmCapability) -> Self {
        self.fgsm_capability = Some(value);
        self
    }

    pub fn set_fgsm_cause(mut self, value: NasFGsmCause) -> Self {
        self.fgsm_cause = Some(value);
        self
    }

    pub fn set_maximum_number_of_supported_packet_filters(mut self, value: NasMaximumNumberOfSupportedPacketFilters) -> Self {
        self.maximum_number_of_supported_packet_filters = Some(value);
        self
    }

    pub fn set_always_on_pdu_session_requested(mut self, value: NasAlwaysOnPduSessionRequested) -> Self {
        self.always_on_pdu_session_requested = Some(value);
        self
    }

    pub fn set_integrity_protection_maximum_data_rate(mut self, value: NasIntegrityProtectionMaximumDataRate) -> Self {
        self.integrity_protection_maximum_data_rate = Some(value);
        self
    }

    pub fn set_requested_qos_rules(mut self, value: NasQosRules) -> Self {
        self.requested_qos_rules = Some(value);
        self
    }

    pub fn set_requested_qos_flow_descriptions(mut self, value: NasQosFlowDescriptions) -> Self {
        self.requested_qos_flow_descriptions = Some(value);
        self
    }

    pub fn set_mapped_eps_bearer_contexts(mut self, value: NasMappedEpsBearerContexts) -> Self {
        self.mapped_eps_bearer_contexts = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }

    pub fn set_port_management_information_container(mut self, value: NasPortManagementInformationContainer) -> Self {
        self.port_management_information_container = Some(value);
        self
    }

    pub fn set_ip_header_compression_configuration(mut self, value: NasHeaderCompressionConfiguration) -> Self {
        self.ip_header_compression_configuration = Some(value);
        self
    }

    pub fn set_ethernet_header_compression_configuration(mut self, value: NasEthernetHeaderCompressionConfiguration) -> Self {
        self.ethernet_header_compression_configuration = Some(value);
        self
    }

    pub fn set_requested_mbs_container(mut self, value: NasRequestedMbsContainer) -> Self {
        self.requested_mbs_container = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }
}

impl Encode for NasPduSessionModificationRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.fgsm_capability {
            let mut ie = value.clone();
            ie.type_field = 0x28;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgsm_cause {
            let mut ie = value.clone();
            ie.type_field = 0x59;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.maximum_number_of_supported_packet_filters {
            helpers::encode_optional_type(buffer, 0x55)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.always_on_pdu_session_requested {
            let mut ie = value.clone();
            ie.type_field = 0xB0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.integrity_protection_maximum_data_rate {
            helpers::encode_optional_type(buffer, 0x13)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_qos_rules {
            helpers::encode_optional_type(buffer, 0x7A)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_qos_flow_descriptions {
            let mut ie = value.clone();
            ie.type_field = 0x79;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.mapped_eps_bearer_contexts {
            let mut ie = value.clone();
            ie.type_field = 0x75;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.port_management_information_container {
            let mut ie = value.clone();
            ie.type_field = 0x74;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ip_header_compression_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x66;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ethernet_header_compression_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x1F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.requested_mbs_container {
            let mut ie = value.clone();
            ie.type_field = 0x70;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionModificationRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x28 => {
                    message.fgsm_capability = Some(NasFGsmCapability::decode(buffer)?);
                },
                0x59 => {
                    message.fgsm_cause = Some(NasFGsmCause::decode(buffer)?);
                },
                0x55 => {
                    buffer.advance(1); // Skip IEI
                    message.maximum_number_of_supported_packet_filters = Some(NasMaximumNumberOfSupportedPacketFilters::decode(buffer)?);
                },
                0xB0 => {
                    message.always_on_pdu_session_requested = Some(NasAlwaysOnPduSessionRequested::decode(buffer)?);
                },
                0x13 => {
                    buffer.advance(1); // Skip IEI
                    message.integrity_protection_maximum_data_rate = Some(NasIntegrityProtectionMaximumDataRate::decode(buffer)?);
                },
                0x7A => {
                    buffer.advance(1); // Skip IEI
                    message.requested_qos_rules = Some(NasQosRules::decode(buffer)?);
                },
                0x79 => {
                    message.requested_qos_flow_descriptions = Some(NasQosFlowDescriptions::decode(buffer)?);
                },
                0x75 => {
                    message.mapped_eps_bearer_contexts = Some(NasMappedEpsBearerContexts::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                0x74 => {
                    message.port_management_information_container = Some(NasPortManagementInformationContainer::decode(buffer)?);
                },
                0x66 => {
                    message.ip_header_compression_configuration = Some(NasHeaderCompressionConfiguration::decode(buffer)?);
                },
                0x1F => {
                    message.ethernet_header_compression_configuration = Some(NasEthernetHeaderCompressionConfiguration::decode(buffer)?);
                },
                0x70 => {
                    message.requested_mbs_container = Some(NasRequestedMbsContainer::decode(buffer)?);
                },
                0x72 => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION MODIFICATION REJECT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionModificationReject {
    // Mandatory fields
    pub fgsm_cause: NasFGsmCause,

    // Optional fields
    pub back_off_timer_value: Option<NasGprsTimer3>,
    pub fgsm_congestion_re_attempt_indicator: Option<NasFGsmCongestionReAttemptIndicator>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
    pub re_attempt_indicator: Option<NasReAttemptIndicator>,
}

impl NasPduSessionModificationReject {
    pub fn new(
        fgsm_cause: NasFGsmCause,
    ) -> Self {
        Self {
            fgsm_cause,
            back_off_timer_value: None,
            fgsm_congestion_re_attempt_indicator: None,
            extended_protocol_configuration_options: None,
            re_attempt_indicator: None,
        }
    }

    pub fn set_back_off_timer_value(mut self, value: NasGprsTimer3) -> Self {
        self.back_off_timer_value = Some(value);
        self
    }

    pub fn set_fgsm_congestion_re_attempt_indicator(mut self, value: NasFGsmCongestionReAttemptIndicator) -> Self {
        self.fgsm_congestion_re_attempt_indicator = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }

    pub fn set_re_attempt_indicator(mut self, value: NasReAttemptIndicator) -> Self {
        self.re_attempt_indicator = Some(value);
        self
    }
}

impl Encode for NasPduSessionModificationReject {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgsm_cause.encode(buffer)?;
        if let Some(ref value) = self.back_off_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x37;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgsm_congestion_re_attempt_indicator {
            let mut ie = value.clone();
            ie.type_field = 0x61;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.re_attempt_indicator {
            let mut ie = value.clone();
            ie.type_field = 0x1D;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionModificationReject {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgsm_cause = NasFGsmCause::decode(buffer)?;

        let mut message = Self::new(
            fgsm_cause,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x37 => {
                    message.back_off_timer_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x61 => {
                    message.fgsm_congestion_re_attempt_indicator = Some(NasFGsmCongestionReAttemptIndicator::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                0x1D => {
                    message.re_attempt_indicator = Some(NasReAttemptIndicator::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION MODIFICATION COMMAND Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionModificationCommand {
    // Mandatory fields

    // Optional fields
    pub fgsm_cause: Option<NasFGsmCause>,
    pub session_ambr: Option<NasSessionAmbr>,
    pub rq_timer_value: Option<NasGprsTimer>,
    pub always_on_pdu_session_indication: Option<NasAlwaysOnPduSessionIndication>,
    pub authorized_qos_rules: Option<NasQosRules>,
    pub mapped_eps_bearer_contexts: Option<NasMappedEpsBearerContexts>,
    pub authorized_qos_flow_descriptions: Option<NasQosFlowDescriptions>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
    pub atsss_container: Option<NasAtsssContainer>,
    pub ip_header_compression_configuration: Option<NasIpHeaderCompressionConfiguration>,
    pub port_management_information_container: Option<NasPortManagementInformationContainer>,
    pub serving_plmn_rate_control: Option<NasServingPlmnRateControl>,
    pub ethernet_header_compression_configuration: Option<NasEthernetHeaderCompressionConfiguration>,
    pub received_mbs_container: Option<NasReceivedMbsContainer>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
}

impl NasPduSessionModificationCommand {
    pub fn new(
    ) -> Self {
        Self {
            fgsm_cause: None,
            session_ambr: None,
            rq_timer_value: None,
            always_on_pdu_session_indication: None,
            authorized_qos_rules: None,
            mapped_eps_bearer_contexts: None,
            authorized_qos_flow_descriptions: None,
            extended_protocol_configuration_options: None,
            atsss_container: None,
            ip_header_compression_configuration: None,
            port_management_information_container: None,
            serving_plmn_rate_control: None,
            ethernet_header_compression_configuration: None,
            received_mbs_container: None,
            service_level_aa_container: None,
        }
    }

    pub fn set_fgsm_cause(mut self, value: NasFGsmCause) -> Self {
        self.fgsm_cause = Some(value);
        self
    }

    pub fn set_session_ambr(mut self, value: NasSessionAmbr) -> Self {
        self.session_ambr = Some(value);
        self
    }

    pub fn set_rq_timer_value(mut self, value: NasGprsTimer) -> Self {
        self.rq_timer_value = Some(value);
        self
    }

    pub fn set_always_on_pdu_session_indication(mut self, value: NasAlwaysOnPduSessionIndication) -> Self {
        self.always_on_pdu_session_indication = Some(value);
        self
    }

    pub fn set_authorized_qos_rules(mut self, value: NasQosRules) -> Self {
        self.authorized_qos_rules = Some(value);
        self
    }

    pub fn set_mapped_eps_bearer_contexts(mut self, value: NasMappedEpsBearerContexts) -> Self {
        self.mapped_eps_bearer_contexts = Some(value);
        self
    }

    pub fn set_authorized_qos_flow_descriptions(mut self, value: NasQosFlowDescriptions) -> Self {
        self.authorized_qos_flow_descriptions = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }

    pub fn set_atsss_container(mut self, value: NasAtsssContainer) -> Self {
        self.atsss_container = Some(value);
        self
    }

    pub fn set_ip_header_compression_configuration(mut self, value: NasIpHeaderCompressionConfiguration) -> Self {
        self.ip_header_compression_configuration = Some(value);
        self
    }

    pub fn set_port_management_information_container(mut self, value: NasPortManagementInformationContainer) -> Self {
        self.port_management_information_container = Some(value);
        self
    }

    pub fn set_serving_plmn_rate_control(mut self, value: NasServingPlmnRateControl) -> Self {
        self.serving_plmn_rate_control = Some(value);
        self
    }

    pub fn set_ethernet_header_compression_configuration(mut self, value: NasEthernetHeaderCompressionConfiguration) -> Self {
        self.ethernet_header_compression_configuration = Some(value);
        self
    }

    pub fn set_received_mbs_container(mut self, value: NasReceivedMbsContainer) -> Self {
        self.received_mbs_container = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }
}

impl Encode for NasPduSessionModificationCommand {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.fgsm_cause {
            let mut ie = value.clone();
            ie.type_field = 0x59;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.session_ambr {
            helpers::encode_optional_type(buffer, 0x2A)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.rq_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x56;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.always_on_pdu_session_indication {
            let mut ie = value.clone();
            ie.type_field = 0x80;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.authorized_qos_rules {
            helpers::encode_optional_type(buffer, 0x7A)?;
            value.encode(buffer)?;
        }
        if let Some(ref value) = self.mapped_eps_bearer_contexts {
            let mut ie = value.clone();
            ie.type_field = 0x75;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.authorized_qos_flow_descriptions {
            let mut ie = value.clone();
            ie.type_field = 0x79;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.atsss_container {
            let mut ie = value.clone();
            ie.type_field = 0x77;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ip_header_compression_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x66;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.port_management_information_container {
            let mut ie = value.clone();
            ie.type_field = 0x74;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.serving_plmn_rate_control {
            let mut ie = value.clone();
            ie.type_field = 0x1E;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.ethernet_header_compression_configuration {
            let mut ie = value.clone();
            ie.type_field = 0x1F;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.received_mbs_container {
            let mut ie = value.clone();
            ie.type_field = 0x71;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionModificationCommand {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x59 => {
                    message.fgsm_cause = Some(NasFGsmCause::decode(buffer)?);
                },
                0x2A => {
                    buffer.advance(1); // Skip IEI
                    message.session_ambr = Some(NasSessionAmbr::decode(buffer)?);
                },
                0x56 => {
                    message.rq_timer_value = Some(NasGprsTimer::decode(buffer)?);
                },
                0x80 => {
                    message.always_on_pdu_session_indication = Some(NasAlwaysOnPduSessionIndication::decode(buffer)?);
                },
                0x7A => {
                    buffer.advance(1); // Skip IEI
                    message.authorized_qos_rules = Some(NasQosRules::decode(buffer)?);
                },
                0x75 => {
                    message.mapped_eps_bearer_contexts = Some(NasMappedEpsBearerContexts::decode(buffer)?);
                },
                0x79 => {
                    message.authorized_qos_flow_descriptions = Some(NasQosFlowDescriptions::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                0x77 => {
                    message.atsss_container = Some(NasAtsssContainer::decode(buffer)?);
                },
                0x66 => {
                    message.ip_header_compression_configuration = Some(NasIpHeaderCompressionConfiguration::decode(buffer)?);
                },
                0x74 => {
                    message.port_management_information_container = Some(NasPortManagementInformationContainer::decode(buffer)?);
                },
                0x1E => {
                    message.serving_plmn_rate_control = Some(NasServingPlmnRateControl::decode(buffer)?);
                },
                0x1F => {
                    message.ethernet_header_compression_configuration = Some(NasEthernetHeaderCompressionConfiguration::decode(buffer)?);
                },
                0x71 => {
                    message.received_mbs_container = Some(NasReceivedMbsContainer::decode(buffer)?);
                },
                0x72 => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION MODIFICATION COMPLETE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionModificationComplete {
    // Mandatory fields

    // Optional fields
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
    pub port_management_information_container: Option<NasPortManagementInformationContainer>,
}

impl NasPduSessionModificationComplete {
    pub fn new(
    ) -> Self {
        Self {
            extended_protocol_configuration_options: None,
            port_management_information_container: None,
        }
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }

    pub fn set_port_management_information_container(mut self, value: NasPortManagementInformationContainer) -> Self {
        self.port_management_information_container = Some(value);
        self
    }
}

impl Encode for NasPduSessionModificationComplete {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.port_management_information_container {
            let mut ie = value.clone();
            ie.type_field = 0x74;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionModificationComplete {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                0x74 => {
                    message.port_management_information_container = Some(NasPortManagementInformationContainer::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION MODIFICATION COMMAND REJECT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionModificationCommandReject {
    // Mandatory fields
    pub fgsm_cause: NasFGsmCause,

    // Optional fields
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
}

impl NasPduSessionModificationCommandReject {
    pub fn new(
        fgsm_cause: NasFGsmCause,
    ) -> Self {
        Self {
            fgsm_cause,
            extended_protocol_configuration_options: None,
        }
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }
}

impl Encode for NasPduSessionModificationCommandReject {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgsm_cause.encode(buffer)?;
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionModificationCommandReject {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgsm_cause = NasFGsmCause::decode(buffer)?;

        let mut message = Self::new(
            fgsm_cause,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION RELEASE REQUEST Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionReleaseRequest {
    // Mandatory fields

    // Optional fields
    pub fgsm_cause: Option<NasFGsmCause>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
}

impl NasPduSessionReleaseRequest {
    pub fn new(
    ) -> Self {
        Self {
            fgsm_cause: None,
            extended_protocol_configuration_options: None,
        }
    }

    pub fn set_fgsm_cause(mut self, value: NasFGsmCause) -> Self {
        self.fgsm_cause = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }
}

impl Encode for NasPduSessionReleaseRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.fgsm_cause {
            let mut ie = value.clone();
            ie.type_field = 0x59;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionReleaseRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x59 => {
                    message.fgsm_cause = Some(NasFGsmCause::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION RELEASE REJECT Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionReleaseReject {
    // Mandatory fields
    pub fgsm_cause: NasFGsmCause,

    // Optional fields
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
}

impl NasPduSessionReleaseReject {
    pub fn new(
        fgsm_cause: NasFGsmCause,
    ) -> Self {
        Self {
            fgsm_cause,
            extended_protocol_configuration_options: None,
        }
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }
}

impl Encode for NasPduSessionReleaseReject {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgsm_cause.encode(buffer)?;
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionReleaseReject {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgsm_cause = NasFGsmCause::decode(buffer)?;

        let mut message = Self::new(
            fgsm_cause,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION RELEASE COMMAND Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionReleaseCommand {
    // Mandatory fields
    pub fgsm_cause: NasFGsmCause,

    // Optional fields
    pub back_off_timer_value: Option<NasGprsTimer3>,
    pub eap_message: Option<NasEapMessage>,
    pub fgsm_congestion_re_attempt_indicator: Option<NasFGsmCongestionReAttemptIndicator>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
    pub access_type: Option<NasAccessType>,
    pub service_level_aa_container: Option<NasServiceLevelAaContainer>,
}

impl NasPduSessionReleaseCommand {
    pub fn new(
        fgsm_cause: NasFGsmCause,
    ) -> Self {
        Self {
            fgsm_cause,
            back_off_timer_value: None,
            eap_message: None,
            fgsm_congestion_re_attempt_indicator: None,
            extended_protocol_configuration_options: None,
            access_type: None,
            service_level_aa_container: None,
        }
    }

    pub fn set_back_off_timer_value(mut self, value: NasGprsTimer3) -> Self {
        self.back_off_timer_value = Some(value);
        self
    }

    pub fn set_eap_message(mut self, value: NasEapMessage) -> Self {
        self.eap_message = Some(value);
        self
    }

    pub fn set_fgsm_congestion_re_attempt_indicator(mut self, value: NasFGsmCongestionReAttemptIndicator) -> Self {
        self.fgsm_congestion_re_attempt_indicator = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }

    pub fn set_access_type(mut self, value: NasAccessType) -> Self {
        self.access_type = Some(value);
        self
    }

    pub fn set_service_level_aa_container(mut self, value: NasServiceLevelAaContainer) -> Self {
        self.service_level_aa_container = Some(value);
        self
    }
}

impl Encode for NasPduSessionReleaseCommand {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgsm_cause.encode(buffer)?;
        if let Some(ref value) = self.back_off_timer_value {
            let mut ie = value.clone();
            ie.type_field = 0x37;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.eap_message {
            let mut ie = value.clone();
            ie.type_field = 0x78;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.fgsm_congestion_re_attempt_indicator {
            let mut ie = value.clone();
            ie.type_field = 0x61;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.access_type {
            let mut ie = value.clone();
            ie.type_field = 0xD0;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.service_level_aa_container {
            let mut ie = value.clone();
            ie.type_field = 0x72;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionReleaseCommand {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgsm_cause = NasFGsmCause::decode(buffer)?;

        let mut message = Self::new(
            fgsm_cause,
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x37 => {
                    message.back_off_timer_value = Some(NasGprsTimer3::decode(buffer)?);
                },
                0x78 => {
                    message.eap_message = Some(NasEapMessage::decode(buffer)?);
                },
                0x61 => {
                    message.fgsm_congestion_re_attempt_indicator = Some(NasFGsmCongestionReAttemptIndicator::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                0xD0 => {
                    message.access_type = Some(NasAccessType::decode(buffer)?);
                },
                0x72 => {
                    message.service_level_aa_container = Some(NasServiceLevelAaContainer::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// PDU SESSION RELEASE COMPLETE Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasPduSessionReleaseComplete {
    // Mandatory fields

    // Optional fields
    pub fgsm_cause: Option<NasFGsmCause>,
    pub extended_protocol_configuration_options: Option<NasExtendedProtocolConfigurationOptions>,
}

impl NasPduSessionReleaseComplete {
    pub fn new(
    ) -> Self {
        Self {
            fgsm_cause: None,
            extended_protocol_configuration_options: None,
        }
    }

    pub fn set_fgsm_cause(mut self, value: NasFGsmCause) -> Self {
        self.fgsm_cause = Some(value);
        self
    }

    pub fn set_extended_protocol_configuration_options(mut self, value: NasExtendedProtocolConfigurationOptions) -> Self {
        self.extended_protocol_configuration_options = Some(value);
        self
    }
}

impl Encode for NasPduSessionReleaseComplete {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if let Some(ref value) = self.fgsm_cause {
            let mut ie = value.clone();
            ie.type_field = 0x59;
            ie.encode(buffer)?;
        }
        if let Some(ref value) = self.extended_protocol_configuration_options {
            let mut ie = value.clone();
            ie.type_field = 0x7B;
            ie.encode(buffer)?;
        }
        Ok(())
    }
}

impl Decode for NasPduSessionReleaseComplete {
    fn decode(buffer: &mut Bytes) -> Result<Self> {

        let mut message = Self::new(
        );

        // Decode optional fields
        while buffer.has_remaining() {
            if buffer.remaining() < 1 {
                break;
            }

            let peek = buffer[0];
            let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };

            match iei {
                0x59 => {
                    message.fgsm_cause = Some(NasFGsmCause::decode(buffer)?);
                },
                0x7B => {
                    message.extended_protocol_configuration_options = Some(NasExtendedProtocolConfigurationOptions::decode(buffer)?);
                },
                _ => {
                    // Unknown IEI, skip this IE
                    debug_assert!(false, "unknown iei!");
                },
            }
        }

        Ok(message)
    }
}

/// 5GSM STATUS Message
#[derive(Debug, Clone, PartialEq)]
pub struct NasFGsmStatus {
    // Mandatory fields
    pub fgsm_cause: NasFGsmCause,
}

impl NasFGsmStatus {
    pub fn new(
        fgsm_cause: NasFGsmCause,
    ) -> Self {
        Self {
            fgsm_cause,
        }
    }
}

impl Encode for NasFGsmStatus {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        self.fgsm_cause.encode(buffer)?;
        Ok(())
    }
}

impl Decode for NasFGsmStatus {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        let fgsm_cause = NasFGsmCause::decode(buffer)?;

        let  message = Self::new(
            fgsm_cause,
        );


        Ok(message)
    }
}

/// 5GMM Message container
#[derive(Debug, Clone, PartialEq)]
pub enum Nas5gmmMessage {
    RegistrationRequest(NasRegistrationRequest),
    RegistrationAccept(NasRegistrationAccept),
    RegistrationComplete(NasRegistrationComplete),
    RegistrationReject(NasRegistrationReject),
    DeregistrationRequestFromUe(NasDeregistrationRequestFromUe),
    DeregistrationRequestToUe(NasDeregistrationRequestToUe),
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
    // might be missing 5GMM messages
}

impl Nas5gmmMessage {
    pub fn get_message_type(&self) -> Nas5gmmMessageType {
        match self {
            Nas5gmmMessage::RegistrationRequest(_) => Nas5gmmMessageType::RegistrationRequest,
            Nas5gmmMessage::RegistrationAccept(_) => Nas5gmmMessageType::RegistrationAccept,
            Nas5gmmMessage::RegistrationComplete(_) => Nas5gmmMessageType::RegistrationComplete,
            Nas5gmmMessage::RegistrationReject(_) => Nas5gmmMessageType::RegistrationReject,
            Nas5gmmMessage::DeregistrationRequestFromUe(_) => Nas5gmmMessageType::DeregistrationRequestFromUe,
            Nas5gmmMessage::DeregistrationRequestToUe(_) => Nas5gmmMessageType::DeregistrationRequestToUe,
            Nas5gmmMessage::ServiceRequest(_) => Nas5gmmMessageType::ServiceRequest,
            Nas5gmmMessage::ServiceReject(_) => Nas5gmmMessageType::ServiceReject,
            Nas5gmmMessage::ServiceAccept(_) => Nas5gmmMessageType::ServiceAccept,
            Nas5gmmMessage::ConfigurationUpdateCommand(_) => Nas5gmmMessageType::ConfigurationUpdateCommand,
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
        }
    }
}

impl TryFrom<(Nas5gmmMessageType, &mut Bytes)> for Nas5gmmMessage {
    type Error = NasError;

    fn try_from(value: (Nas5gmmMessageType, &mut Bytes)) -> Result<Self> {
        let (message_type, buffer) = value;
        
        match message_type {
            Nas5gmmMessageType::RegistrationRequest => Ok(Nas5gmmMessage::RegistrationRequest(NasRegistrationRequest::decode(buffer)?)),
            Nas5gmmMessageType::RegistrationAccept => Ok(Nas5gmmMessage::RegistrationAccept(NasRegistrationAccept::decode(buffer)?)),
            Nas5gmmMessageType::RegistrationComplete => Ok(Nas5gmmMessage::RegistrationComplete(NasRegistrationComplete::decode(buffer)?)),
            Nas5gmmMessageType::RegistrationReject => Ok(Nas5gmmMessage::RegistrationReject(NasRegistrationReject::decode(buffer)?)),
            Nas5gmmMessageType::DeregistrationRequestFromUe => Ok(Nas5gmmMessage::DeregistrationRequestFromUe(NasDeregistrationRequestFromUe::decode(buffer)?)),
            Nas5gmmMessageType::DeregistrationRequestToUe => Ok(Nas5gmmMessage::DeregistrationRequestToUe(NasDeregistrationRequestToUe::decode(buffer)?)),
            Nas5gmmMessageType::ServiceRequest => Ok(Nas5gmmMessage::ServiceRequest(NasServiceRequest::decode(buffer)?)),
            Nas5gmmMessageType::ServiceReject => Ok(Nas5gmmMessage::ServiceReject(NasServiceReject::decode(buffer)?)),
            Nas5gmmMessageType::ServiceAccept => Ok(Nas5gmmMessage::ServiceAccept(NasServiceAccept::decode(buffer)?)),
            Nas5gmmMessageType::ConfigurationUpdateCommand => Ok(Nas5gmmMessage::ConfigurationUpdateCommand(NasConfigurationUpdateCommand::decode(buffer)?)),
            Nas5gmmMessageType::AuthenticationRequest => Ok(Nas5gmmMessage::AuthenticationRequest(NasAuthenticationRequest::decode(buffer)?)),
            Nas5gmmMessageType::AuthenticationResponse => Ok(Nas5gmmMessage::AuthenticationResponse(NasAuthenticationResponse::decode(buffer)?)),
            Nas5gmmMessageType::AuthenticationReject => Ok(Nas5gmmMessage::AuthenticationReject(NasAuthenticationReject::decode(buffer)?)),
            Nas5gmmMessageType::AuthenticationFailure => Ok(Nas5gmmMessage::AuthenticationFailure(NasAuthenticationFailure::decode(buffer)?)),
            Nas5gmmMessageType::AuthenticationResult => Ok(Nas5gmmMessage::AuthenticationResult(NasAuthenticationResult::decode(buffer)?)),
            Nas5gmmMessageType::IdentityRequest => Ok(Nas5gmmMessage::IdentityRequest(NasIdentityRequest::decode(buffer)?)),
            Nas5gmmMessageType::IdentityResponse => Ok(Nas5gmmMessage::IdentityResponse(NasIdentityResponse::decode(buffer)?)),
            Nas5gmmMessageType::SecurityModeCommand => Ok(Nas5gmmMessage::SecurityModeCommand(NasSecurityModeCommand::decode(buffer)?)),
            Nas5gmmMessageType::SecurityModeComplete => Ok(Nas5gmmMessage::SecurityModeComplete(NasSecurityModeComplete::decode(buffer)?)),
            Nas5gmmMessageType::SecurityModeReject => Ok(Nas5gmmMessage::SecurityModeReject(NasSecurityModeReject::decode(buffer)?)),
            Nas5gmmMessageType::FGmmStatus => Ok(Nas5gmmMessage::FGmmStatus(NasFGmmStatus::decode(buffer)?)),
            Nas5gmmMessageType::Notification => Ok(Nas5gmmMessage::Notification(NasNotification::decode(buffer)?)),
            Nas5gmmMessageType::NotificationResponse => Ok(Nas5gmmMessage::NotificationResponse(NasNotificationResponse::decode(buffer)?)),
            Nas5gmmMessageType::UlNasTransport => Ok(Nas5gmmMessage::UlNasTransport(NasUlNasTransport::decode(buffer)?)),
            Nas5gmmMessageType::DlNasTransport => Ok(Nas5gmmMessage::DlNasTransport(NasDlNasTransport::decode(buffer)?)),
            Nas5gmmMessageType::DeregistrationAcceptFromUe | Nas5gmmMessageType::DeregistrationAcceptToUe | Nas5gmmMessageType::ConfigurationUpdateComplete => todo!()
        }
    }
}

/// 5GSM Message container
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
    // might be missing 5GSM messages
}

impl Nas5gsmMessage {
    pub fn get_message_type(&self) -> Nas5gsmMessageType {
        match self {
            Nas5gsmMessage::PduSessionEstablishmentRequest(_) => Nas5gsmMessageType::PduSessionEstablishmentRequest,
            Nas5gsmMessage::PduSessionEstablishmentAccept(_) => Nas5gsmMessageType::PduSessionEstablishmentAccept,
            Nas5gsmMessage::PduSessionEstablishmentReject(_) => Nas5gsmMessageType::PduSessionEstablishmentReject,
            Nas5gsmMessage::PduSessionAuthenticationCommand(_) => Nas5gsmMessageType::PduSessionAuthenticationCommand,
            Nas5gsmMessage::PduSessionAuthenticationComplete(_) => Nas5gsmMessageType::PduSessionAuthenticationComplete,
            Nas5gsmMessage::PduSessionAuthenticationResult(_) => Nas5gsmMessageType::PduSessionAuthenticationResult,
            Nas5gsmMessage::PduSessionModificationRequest(_) => Nas5gsmMessageType::PduSessionModificationRequest,
            Nas5gsmMessage::PduSessionModificationReject(_) => Nas5gsmMessageType::PduSessionModificationReject,
            Nas5gsmMessage::PduSessionModificationCommand(_) => Nas5gsmMessageType::PduSessionModificationCommand,
            Nas5gsmMessage::PduSessionModificationComplete(_) => Nas5gsmMessageType::PduSessionModificationComplete,
            Nas5gsmMessage::PduSessionModificationCommandReject(_) => Nas5gsmMessageType::PduSessionModificationCommandReject,
            Nas5gsmMessage::PduSessionReleaseRequest(_) => Nas5gsmMessageType::PduSessionReleaseRequest,
            Nas5gsmMessage::PduSessionReleaseReject(_) => Nas5gsmMessageType::PduSessionReleaseReject,
            Nas5gsmMessage::PduSessionReleaseCommand(_) => Nas5gsmMessageType::PduSessionReleaseCommand,
            Nas5gsmMessage::PduSessionReleaseComplete(_) => Nas5gsmMessageType::PduSessionReleaseComplete,
            Nas5gsmMessage::FGsmStatus(_) => Nas5gsmMessageType::FGsmStatus,
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
        }
    }
}

impl TryFrom<(Nas5gsmMessageType, &mut Bytes)> for Nas5gsmMessage {
    type Error = NasError;

    fn try_from(value: (Nas5gsmMessageType, &mut Bytes)) -> Result<Self> {
        let (message_type, buffer) = value;
        
        match message_type {
            Nas5gsmMessageType::PduSessionEstablishmentRequest => Ok(Nas5gsmMessage::PduSessionEstablishmentRequest(NasPduSessionEstablishmentRequest::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionEstablishmentAccept => Ok(Nas5gsmMessage::PduSessionEstablishmentAccept(NasPduSessionEstablishmentAccept::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionEstablishmentReject => Ok(Nas5gsmMessage::PduSessionEstablishmentReject(NasPduSessionEstablishmentReject::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionAuthenticationCommand => Ok(Nas5gsmMessage::PduSessionAuthenticationCommand(NasPduSessionAuthenticationCommand::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionAuthenticationComplete => Ok(Nas5gsmMessage::PduSessionAuthenticationComplete(NasPduSessionAuthenticationComplete::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionAuthenticationResult => Ok(Nas5gsmMessage::PduSessionAuthenticationResult(NasPduSessionAuthenticationResult::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionModificationRequest => Ok(Nas5gsmMessage::PduSessionModificationRequest(NasPduSessionModificationRequest::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionModificationReject => Ok(Nas5gsmMessage::PduSessionModificationReject(NasPduSessionModificationReject::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionModificationCommand => Ok(Nas5gsmMessage::PduSessionModificationCommand(NasPduSessionModificationCommand::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionModificationComplete => Ok(Nas5gsmMessage::PduSessionModificationComplete(NasPduSessionModificationComplete::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionModificationCommandReject => Ok(Nas5gsmMessage::PduSessionModificationCommandReject(NasPduSessionModificationCommandReject::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionReleaseRequest => Ok(Nas5gsmMessage::PduSessionReleaseRequest(NasPduSessionReleaseRequest::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionReleaseReject => Ok(Nas5gsmMessage::PduSessionReleaseReject(NasPduSessionReleaseReject::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionReleaseCommand => Ok(Nas5gsmMessage::PduSessionReleaseCommand(NasPduSessionReleaseCommand::decode(buffer)?)),
            Nas5gsmMessageType::PduSessionReleaseComplete => Ok(Nas5gsmMessage::PduSessionReleaseComplete(NasPduSessionReleaseComplete::decode(buffer)?)),
            Nas5gsmMessageType::FGsmStatus => Ok(Nas5gsmMessage::FGsmStatus(NasFGsmStatus::decode(buffer)?)),

        }
    }
}

/// Top-level NAS message container
#[derive(Debug, Clone, PartialEq)]
pub enum Nas5gsMessage {
    Gmm(Nas5gmmHeader, Nas5gmmMessage),
    Gsm(Nas5gsmHeader, Nas5gsmMessage),
    SecurityProtected(Nas5gsSecurityHeader, Box<Nas5gsMessage>),
}

impl Nas5gsMessage {
    /// Create a new 5GMM message
    pub fn new_5gmm(message_type: Nas5gmmMessageType, message: Nas5gmmMessage) -> Self {
        let header = Nas5gmmHeader::new(message_type);
        Nas5gsMessage::Gmm(header, message)
    }
    
    /// Create a new 5GSM message
    pub fn new_5gsm(
        message_type: Nas5gsmMessageType,
        message: Nas5gsmMessage,
        pdu_session_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        let header = Nas5gsmHeader::new(message_type, pdu_session_identity, procedure_transaction_identity);
        Nas5gsMessage::Gsm(header, message)
    }
    
    /// Wrap a message with security protection
    pub fn protect(
        message: Nas5gsMessage,
        security_header_type: Nas5gsSecurityHeaderType,
        message_authentication_code: u32,
        sequence_number: u8,
    ) -> Self {
        let extended_protocol_discriminator = match &message {
            Nas5gsMessage::Gmm(h, _) => h.extended_protocol_discriminator,
            Nas5gsMessage::Gsm(h, _) => h.extended_protocol_discriminator,
            Nas5gsMessage::SecurityProtected(h, _) => h.extended_protocol_discriminator,
        };
        
        let security_header = Nas5gsSecurityHeader {
            extended_protocol_discriminator,
            security_header_type,
            message_authentication_code,
            sequence_number,
        };
        
        Nas5gsMessage::SecurityProtected(security_header, Box::new(message))
    }
}

impl Encode for Nas5gsMessage {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        match self {
            Nas5gsMessage::Gmm(header, message) => {
                header.encode(buffer)?;
                message.encode(buffer)?;
            },
            Nas5gsMessage::Gsm(header, message) => {
                header.encode(buffer)?;
                message.encode(buffer)?;
            },
            Nas5gsMessage::SecurityProtected(header, message) => {
                header.encode(buffer)?;
                
                // For security-protected messages, we encode the inner message
                // into a temporary buffer, then copy it to the output buffer
                let mut inner_buffer = BytesMut::new();
                message.encode(&mut inner_buffer)?;
                buffer.put_slice(&inner_buffer);
            },
        }
        
        Ok(())
    }
}

impl Decode for Nas5gsMessage {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        
        // Check extended protocol discriminator (first byte)
        let epd = buffer[0];
        
        // Check security header type (second byte, for 5GMM)
        let security_header_type = if epd == EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            if buffer.remaining() < 2 {
                return Err(NasError::BufferTooShort);
            }
            buffer[1]
        } else {
            0 // Not relevant for 5GSM
        };
        
        match epd {
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM => {
                // Check if it's a security-protected message
                if security_header_type >= 0x01 && security_header_type <= 0x04 {
                    // Security-protected message
                    let security_header = Nas5gsSecurityHeader::decode(buffer)?;
                    
                    // The rest of the buffer contains the plain NAS message
                    let plain_message = Nas5gsMessage::decode(buffer)?;
                    
                    Ok(Nas5gsMessage::SecurityProtected(security_header, Box::new(plain_message)))
                } else {
                    // Plain 5GMM message
                    let header = Nas5gmmHeader::decode(buffer)?;
                    let message = Nas5gmmMessage::try_from((header.message_type, buffer))?;
                    
                    Ok(Nas5gsMessage::Gmm(header, message))
                }
            },
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM => {
                // Plain 5GSM message
                let header = Nas5gsmHeader::decode(buffer)?;
                let message = Nas5gsmMessage::try_from((header.message_type, buffer))?;
                
                Ok(Nas5gsMessage::Gsm(header, message))
            },
            _ => Err(NasError::DecodingError(format!("Unknown Extended Protocol Discriminator: {}", epd))),
        }
    }
}

/// Encode a NAS 5GS message to bytes
pub fn encode_nas_5gs_message(message: &Nas5gsMessage) -> Result<Vec<u8>> {
    // Create a buffer with enough capacity for most messages
    let mut buffer = BytesMut::with_capacity(256);
    
    // Encode the message
    message.encode(&mut buffer)?;
    
    // Convert to Vec<u8>
    Ok(buffer.to_vec())
}

/// Decode a NAS 5GS message from bytes
pub fn decode_nas_5gs_message(data: &[u8]) -> Result<Nas5gsMessage> {
    let mut buffer = Bytes::copy_from_slice(data);
    Nas5gsMessage::decode(&mut buffer)
}

