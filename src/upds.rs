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

//! UE Policy Delivery Service (UPDS) payload codec per 3GPP TS 24.501 Annex D.
//!
//! UPDS messages are carried inside NAS payload containers with payload container
//! type set to `UE policy container`; they are not top-level 5GS NAS PDUs with
//! an EPD header.

use crate::types::{Decode, Encode, NasError, Result, helpers};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

const IEI_UE_OS_ID: u8 = 0x41;
const IEI_UE_POLICY_NETWORK_CLASSMARK: u8 = 0x42;
const IEI_VPS_URSP_CONFIGURATION: u8 = 0x70;

macro_rules! upds_raw_ie {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Default)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            pub value: Vec<u8>,
        }

        impl $name {
            pub fn new(value: Vec<u8>) -> Self {
                Self { value }
            }

            pub fn data(&self) -> &[u8] {
                &self.value
            }

            pub fn from_data(data: Vec<u8>) -> Self {
                Self::new(data)
            }

            pub fn set_data(&mut self, data: Vec<u8>) -> &mut Self {
                self.value = data;
                self
            }

            pub fn with_data(mut self, data: Vec<u8>) -> Self {
                self.value = data;
                self
            }
        }
    };
}

upds_raw_ie!(NasUePolicySectionManagementList);
upds_raw_ie!(NasUePolicySectionManagementResult);
upds_raw_ie!(NasUpsiList);
upds_raw_ie!(NasUePolicyClassmark);
upds_raw_ie!(NasUeOsId);
upds_raw_ie!(NasUePolicyNetworkClassmark);
upds_raw_ie!(NasVpsUrspConfiguration);

impl NasUePolicyClassmark {
    pub fn support_andsp(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    pub fn eps_ursp(&self) -> bool {
        self.value.first().map(|b| b & 0x02 != 0).unwrap_or(false)
    }

    pub fn svpsu(&self) -> bool {
        self.value.first().map(|b| b & 0x04 != 0).unwrap_or(false)
    }

    pub fn support_rure(&self) -> bool {
        self.value.first().map(|b| b & 0x08 != 0).unwrap_or(false)
    }

    pub fn from_flags(
        support_andsp: bool,
        eps_ursp: bool,
        svpsu: bool,
        support_rure: bool,
    ) -> Self {
        let mut byte = 0u8;
        if support_andsp {
            byte |= 0x01;
        }
        if eps_ursp {
            byte |= 0x02;
        }
        if svpsu {
            byte |= 0x04;
        }
        if support_rure {
            byte |= 0x08;
        }
        Self::new(vec![byte])
    }
}

impl NasUePolicyNetworkClassmark {
    pub fn nssui(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    pub fn from_nssui(nssui: bool) -> Self {
        Self::new(vec![if nssui { 0x01 } else { 0x00 }])
    }
}

impl NasUeOsId {
    pub fn os_ids(&self) -> Vec<[u8; 16]> {
        self.value
            .chunks_exact(16)
            .map(|chunk| {
                let mut out = [0u8; 16];
                out.copy_from_slice(chunk);
                out
            })
            .collect()
    }

    pub fn from_os_ids(os_ids: &[[u8; 16]]) -> Self {
        let mut value = Vec::with_capacity(os_ids.len() * 16);
        for os_id in os_ids {
            value.extend_from_slice(os_id);
        }
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdsUnknownIe {
    pub iei: u8,
    pub data: Vec<u8>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NasUpdsMessageType {
    ManageUePolicyCommand,
    ManageUePolicyComplete,
    ManageUePolicyCommandReject,
    UeStateIndication,
}

impl NasUpdsMessageType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::ManageUePolicyCommand => 0x01,
            Self::ManageUePolicyComplete => 0x02,
            Self::ManageUePolicyCommandReject => 0x03,
            Self::UeStateIndication => 0x04,
        }
    }
}

impl TryFrom<u8> for NasUpdsMessageType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::ManageUePolicyCommand),
            0x02 => Ok(Self::ManageUePolicyComplete),
            0x03 => Ok(Self::ManageUePolicyCommandReject),
            0x04 => Ok(Self::UeStateIndication),
            _ => Err(NasError::UnknownMessageType(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasManageUePolicyCommand {
    pub ue_policy_section_management_list: NasUePolicySectionManagementList,
    pub ue_policy_network_classmark: Option<NasUePolicyNetworkClassmark>,
    pub vps_ursp_configuration: Option<NasVpsUrspConfiguration>,
    pub unknown_ies: Vec<UpdsUnknownIe>,
}

impl NasManageUePolicyCommand {
    pub fn new(ue_policy_section_management_list: NasUePolicySectionManagementList) -> Self {
        Self {
            ue_policy_section_management_list,
            ue_policy_network_classmark: None,
            vps_ursp_configuration: None,
            unknown_ies: Vec::new(),
        }
    }

    pub fn with_ue_policy_network_classmark(
        mut self,
        ue_policy_network_classmark: NasUePolicyNetworkClassmark,
    ) -> Self {
        self.ue_policy_network_classmark = Some(ue_policy_network_classmark);
        self
    }

    pub fn set_ue_policy_network_classmark(
        &mut self,
        ue_policy_network_classmark: NasUePolicyNetworkClassmark,
    ) -> &mut Self {
        self.ue_policy_network_classmark = Some(ue_policy_network_classmark);
        self
    }

    pub fn with_vps_ursp_configuration(
        mut self,
        vps_ursp_configuration: NasVpsUrspConfiguration,
    ) -> Self {
        self.vps_ursp_configuration = Some(vps_ursp_configuration);
        self
    }

    pub fn set_vps_ursp_configuration(
        &mut self,
        vps_ursp_configuration: NasVpsUrspConfiguration,
    ) -> &mut Self {
        self.vps_ursp_configuration = Some(vps_ursp_configuration);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasManageUePolicyComplete {
    pub unknown_ies: Vec<UpdsUnknownIe>,
}

impl NasManageUePolicyComplete {
    pub fn new() -> Self {
        Self {
            unknown_ies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasManageUePolicyCommandReject {
    pub ue_policy_section_management_result: NasUePolicySectionManagementResult,
    pub unknown_ies: Vec<UpdsUnknownIe>,
}

impl NasManageUePolicyCommandReject {
    pub fn new(ue_policy_section_management_result: NasUePolicySectionManagementResult) -> Self {
        Self {
            ue_policy_section_management_result,
            unknown_ies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasUeStateIndication {
    pub upsi_list: NasUpsiList,
    pub ue_policy_classmark: NasUePolicyClassmark,
    pub ue_os_id: Option<NasUeOsId>,
    pub unknown_ies: Vec<UpdsUnknownIe>,
}

impl NasUeStateIndication {
    pub fn new(upsi_list: NasUpsiList, ue_policy_classmark: NasUePolicyClassmark) -> Self {
        Self {
            upsi_list,
            ue_policy_classmark,
            ue_os_id: None,
            unknown_ies: Vec::new(),
        }
    }

    pub fn with_ue_os_id(mut self, ue_os_id: NasUeOsId) -> Self {
        self.ue_os_id = Some(ue_os_id);
        self
    }

    pub fn set_ue_os_id(&mut self, ue_os_id: NasUeOsId) -> &mut Self {
        self.ue_os_id = Some(ue_os_id);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NasUpdsMessage {
    ManageUePolicyCommand(NasManageUePolicyCommand),
    ManageUePolicyComplete(NasManageUePolicyComplete),
    ManageUePolicyCommandReject(NasManageUePolicyCommandReject),
    UeStateIndication(NasUeStateIndication),
}

impl NasUpdsMessage {
    pub fn message_type(&self) -> NasUpdsMessageType {
        match self {
            Self::ManageUePolicyCommand(_) => NasUpdsMessageType::ManageUePolicyCommand,
            Self::ManageUePolicyComplete(_) => NasUpdsMessageType::ManageUePolicyComplete,
            Self::ManageUePolicyCommandReject(_) => NasUpdsMessageType::ManageUePolicyCommandReject,
            Self::UeStateIndication(_) => NasUpdsMessageType::UeStateIndication,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasUpdsEnvelope {
    pub procedure_transaction_identity: u8,
    pub message: NasUpdsMessage,
}

impl NasUpdsEnvelope {
    pub fn new(procedure_transaction_identity: u8, message: NasUpdsMessage) -> Self {
        Self {
            procedure_transaction_identity,
            message,
        }
    }

    pub fn message_type(&self) -> NasUpdsMessageType {
        self.message.message_type()
    }

    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::new();
        self.encode(&mut buffer)?;
        Ok(buffer.to_vec())
    }

    pub fn decode_from_slice(data: &[u8]) -> Result<Self> {
        let mut buffer = Bytes::copy_from_slice(data);
        Self::decode(&mut buffer)
    }
}

impl Encode for NasUpdsEnvelope {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        buffer.put_u8(self.procedure_transaction_identity);
        buffer.put_u8(self.message.message_type().as_u8());

        match &self.message {
            NasUpdsMessage::ManageUePolicyCommand(message) => {
                encode_lve(buffer, &message.ue_policy_section_management_list.value)?;
                if let Some(ie) = &message.ue_policy_network_classmark {
                    encode_tlv(buffer, IEI_UE_POLICY_NETWORK_CLASSMARK, &ie.value)?;
                }
                if let Some(ie) = &message.vps_ursp_configuration {
                    encode_tlve(buffer, IEI_VPS_URSP_CONFIGURATION, &ie.value)?;
                }
                encode_unknown_ies(buffer, &message.unknown_ies)?;
            }
            NasUpdsMessage::ManageUePolicyComplete(message) => {
                encode_unknown_ies(buffer, &message.unknown_ies)?;
            }
            NasUpdsMessage::ManageUePolicyCommandReject(message) => {
                encode_lve(buffer, &message.ue_policy_section_management_result.value)?;
                encode_unknown_ies(buffer, &message.unknown_ies)?;
            }
            NasUpdsMessage::UeStateIndication(message) => {
                encode_lve(buffer, &message.upsi_list.value)?;
                encode_lv(buffer, &message.ue_policy_classmark.value)?;
                if let Some(ie) = &message.ue_os_id {
                    encode_tlv(buffer, IEI_UE_OS_ID, &ie.value)?;
                }
                encode_unknown_ies(buffer, &message.unknown_ies)?;
            }
        }

        Ok(())
    }
}

impl Decode for NasUpdsEnvelope {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(NasError::BufferTooShort);
        }

        let procedure_transaction_identity = buffer.get_u8();
        let message_type = NasUpdsMessageType::try_from(buffer.get_u8())?;

        let message = match message_type {
            NasUpdsMessageType::ManageUePolicyCommand => {
                let mut message = NasManageUePolicyCommand::new(
                    NasUePolicySectionManagementList::new(decode_lve(buffer)?),
                );
                while buffer.has_remaining() {
                    match buffer[0] {
                        IEI_UE_POLICY_NETWORK_CLASSMARK => {
                            message.ue_policy_network_classmark =
                                Some(NasUePolicyNetworkClassmark::new(decode_tlv(
                                    buffer,
                                    IEI_UE_POLICY_NETWORK_CLASSMARK,
                                )?));
                        }
                        IEI_VPS_URSP_CONFIGURATION => {
                            message.vps_ursp_configuration = Some(NasVpsUrspConfiguration::new(
                                decode_tlve(buffer, IEI_VPS_URSP_CONFIGURATION)?,
                            ));
                        }
                        _ => message.unknown_ies.push(decode_unknown_ie(buffer)?),
                    }
                }
                NasUpdsMessage::ManageUePolicyCommand(message)
            }
            NasUpdsMessageType::ManageUePolicyComplete => {
                let mut message = NasManageUePolicyComplete::new();
                while buffer.has_remaining() {
                    message.unknown_ies.push(decode_unknown_ie(buffer)?);
                }
                NasUpdsMessage::ManageUePolicyComplete(message)
            }
            NasUpdsMessageType::ManageUePolicyCommandReject => {
                let mut message = NasManageUePolicyCommandReject::new(
                    NasUePolicySectionManagementResult::new(decode_lve(buffer)?),
                );
                while buffer.has_remaining() {
                    message.unknown_ies.push(decode_unknown_ie(buffer)?);
                }
                NasUpdsMessage::ManageUePolicyCommandReject(message)
            }
            NasUpdsMessageType::UeStateIndication => {
                let mut message = NasUeStateIndication::new(
                    NasUpsiList::new(decode_lve(buffer)?),
                    NasUePolicyClassmark::new(decode_lv(buffer)?),
                );
                while buffer.has_remaining() {
                    match buffer[0] {
                        IEI_UE_OS_ID => {
                            message.ue_os_id =
                                Some(NasUeOsId::new(decode_tlv(buffer, IEI_UE_OS_ID)?));
                        }
                        _ => message.unknown_ies.push(decode_unknown_ie(buffer)?),
                    }
                }
                NasUpdsMessage::UeStateIndication(message)
            }
        };

        Ok(Self {
            procedure_transaction_identity,
            message,
        })
    }
}

fn encode_lv(buffer: &mut BytesMut, value: &[u8]) -> Result<()> {
    let len = u8::try_from(value.len()).map_err(|_| {
        NasError::EncodingError(format!("LV IE length {} exceeds 255", value.len()))
    })?;
    buffer.put_u8(len);
    buffer.put_slice(value);
    Ok(())
}

fn encode_lve(buffer: &mut BytesMut, value: &[u8]) -> Result<()> {
    let len = u16::try_from(value.len()).map_err(|_| {
        NasError::EncodingError(format!("LV-E IE length {} exceeds 65535", value.len()))
    })?;
    buffer.put_slice(&helpers::u16_to_be16(len));
    buffer.put_slice(value);
    Ok(())
}

fn encode_tlv(buffer: &mut BytesMut, iei: u8, value: &[u8]) -> Result<()> {
    let len = u8::try_from(value.len()).map_err(|_| {
        NasError::EncodingError(format!("TLV IE length {} exceeds 255", value.len()))
    })?;
    buffer.put_u8(iei);
    buffer.put_u8(len);
    buffer.put_slice(value);
    Ok(())
}

fn encode_tlve(buffer: &mut BytesMut, iei: u8, value: &[u8]) -> Result<()> {
    let len = u16::try_from(value.len()).map_err(|_| {
        NasError::EncodingError(format!("TLV-E IE length {} exceeds 65535", value.len()))
    })?;
    buffer.put_u8(iei);
    buffer.put_slice(&helpers::u16_to_be16(len));
    buffer.put_slice(value);
    Ok(())
}

fn encode_unknown_ies(buffer: &mut BytesMut, unknown_ies: &[UpdsUnknownIe]) -> Result<()> {
    for ie in unknown_ies {
        buffer.put_u8(ie.iei);
        buffer.put_slice(&ie.data);
    }
    Ok(())
}

fn decode_lv(buffer: &mut Bytes) -> Result<Vec<u8>> {
    if buffer.remaining() < 1 {
        return Err(NasError::BufferTooShort);
    }
    let len = buffer.get_u8() as usize;
    if buffer.remaining() < len {
        return Err(NasError::BufferTooShort);
    }
    Ok(buffer.copy_to_bytes(len).to_vec())
}

fn decode_lve(buffer: &mut Bytes) -> Result<Vec<u8>> {
    if buffer.remaining() < 2 {
        return Err(NasError::BufferTooShort);
    }
    let len = usize::from(buffer.get_u16());
    if buffer.remaining() < len {
        return Err(NasError::BufferTooShort);
    }
    Ok(buffer.copy_to_bytes(len).to_vec())
}

fn decode_tlv(buffer: &mut Bytes, expected_iei: u8) -> Result<Vec<u8>> {
    if buffer.remaining() < 2 {
        return Err(NasError::BufferTooShort);
    }
    let iei = buffer.get_u8();
    if iei != expected_iei {
        return Err(NasError::DecodingError(format!(
            "expected IEI 0x{expected_iei:02X}, got 0x{iei:02X}"
        )));
    }
    let len = buffer.get_u8() as usize;
    if buffer.remaining() < len {
        return Err(NasError::BufferTooShort);
    }
    Ok(buffer.copy_to_bytes(len).to_vec())
}

fn decode_tlve(buffer: &mut Bytes, expected_iei: u8) -> Result<Vec<u8>> {
    if buffer.remaining() < 3 {
        return Err(NasError::BufferTooShort);
    }
    let iei = buffer.get_u8();
    if iei != expected_iei {
        return Err(NasError::DecodingError(format!(
            "expected IEI 0x{expected_iei:02X}, got 0x{iei:02X}"
        )));
    }
    let len = usize::from(buffer.get_u16());
    if buffer.remaining() < len {
        return Err(NasError::BufferTooShort);
    }
    Ok(buffer.copy_to_bytes(len).to_vec())
}

fn decode_unknown_ie(buffer: &mut Bytes) -> Result<UpdsUnknownIe> {
    if buffer.remaining() < 2 {
        return Err(NasError::BufferTooShort);
    }

    let iei = buffer.get_u8();
    if (iei & 0x70) == 0x70 {
        if buffer.remaining() < 2 {
            return Err(NasError::BufferTooShort);
        }
        let len_bytes = buffer.copy_to_bytes(2);
        let len = helpers::be16_to_u16([len_bytes[0], len_bytes[1]]) as usize;
        if buffer.remaining() < len {
            return Err(NasError::BufferTooShort);
        }
        let mut data = len_bytes.to_vec();
        data.extend_from_slice(&buffer.copy_to_bytes(len));
        Ok(UpdsUnknownIe { iei, data })
    } else {
        let len = buffer.get_u8() as usize;
        if buffer.remaining() < len {
            return Err(NasError::BufferTooShort);
        }
        let mut data = vec![len as u8];
        data.extend_from_slice(&buffer.copy_to_bytes(len));
        Ok(UpdsUnknownIe { iei, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NasPayloadContainer;

    #[test]
    fn test_ue_policy_classmark_helpers() {
        let classmark = NasUePolicyClassmark::from_flags(true, false, true, true);
        assert!(classmark.support_andsp());
        assert!(!classmark.eps_ursp());
        assert!(classmark.svpsu());
        assert!(classmark.support_rure());
    }

    #[test]
    fn test_upds_command_roundtrip() {
        let message = NasUpdsEnvelope::new(
            7,
            NasUpdsMessage::ManageUePolicyCommand(
                NasManageUePolicyCommand::new(NasUePolicySectionManagementList::from_data(vec![
                    0x00, 0x01, 0x02, 0x03,
                ]))
                .with_ue_policy_network_classmark(NasUePolicyNetworkClassmark::from_nssui(true))
                .with_vps_ursp_configuration(NasVpsUrspConfiguration::from_data(vec![
                    0x00, 0xAA, 0xBB,
                ])),
            ),
        );

        let encoded = message.encode_to_vec().unwrap();
        let decoded = NasUpdsEnvelope::decode_from_slice(&encoded).unwrap();

        assert_eq!(message, decoded);
    }

    #[test]
    fn test_payload_container_ue_policy_helpers() {
        let message = NasUpdsEnvelope::new(
            3,
            NasUpdsMessage::UeStateIndication(
                NasUeStateIndication::new(
                    NasUpsiList::from_data(vec![0x00, 0x00]),
                    NasUePolicyClassmark::from_flags(true, true, false, false),
                )
                .with_ue_os_id(NasUeOsId::from_os_ids(&[[0x11; 16], [0x22; 16]])),
            ),
        );

        let container = NasPayloadContainer::from_ue_policy_message(&message).unwrap();
        let decoded = container.decode_as_ue_policy_message().unwrap();

        assert_eq!(message, decoded);
    }
}
