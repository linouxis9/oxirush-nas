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

//! UE Policy Delivery Service (UPDS) payload codec per 3GPP TS 24.501 Annex D.
//!
//! UPDS messages are carried inside NAS payload containers with payload container
//! type set to `UE policy container`; they are not top-level 5GS NAS PDUs with
//! an EPD header.

use crate::{
    NasDnn, NasFGmmCause, NasGprsTimer3, NasMaPduSessionInformation, NasPduSessionIdentity2,
    NasReleaseAssistanceIndication, NasRequestType, NasSNssai, PlmnId,
    types::{Decode, Encode, NasError, Result, helpers},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{convert::TryFrom, fmt};

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

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NonSubscribedSnpnUrspHandling {
    Allow,
    Disallow,
}

impl NasUePolicyNetworkClassmark {
    pub fn nssui(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    pub fn handling(&self) -> NonSubscribedSnpnUrspHandling {
        if self.nssui() {
            NonSubscribedSnpnUrspHandling::Disallow
        } else {
            NonSubscribedSnpnUrspHandling::Allow
        }
    }

    pub fn from_nssui(nssui: bool) -> Self {
        Self::new(vec![if nssui { 0x01 } else { 0x00 }])
    }

    pub fn from_handling(handling: NonSubscribedSnpnUrspHandling) -> Self {
        Self::from_nssui(matches!(handling, NonSubscribedSnpnUrspHandling::Disallow))
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

    pub fn from_os_ids(os_ids: &[[u8; 16]]) -> Option<Self> {
        if os_ids.is_empty() || os_ids.len() > 15 {
            return None;
        }
        let mut value = Vec::with_capacity(os_ids.len() * 16);
        for os_id in os_ids {
            value.extend_from_slice(os_id);
        }
        Some(Self::new(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdsUnknownIe {
    pub iei: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasUpdsProcedureTransactionIdentity {
    value: u8,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpdsProcedureTransactionIdentityKind {
    Unassigned,
    UeInitiated,
    NetworkInitiated,
    Reserved,
}

impl NasUpdsProcedureTransactionIdentity {
    pub fn new_raw(value: u8) -> Self {
        Self { value }
    }

    pub fn raw(self) -> u8 {
        self.value
    }

    pub fn kind(self) -> UpdsProcedureTransactionIdentityKind {
        match self.value {
            0x00 => UpdsProcedureTransactionIdentityKind::Unassigned,
            0x01..=0x77 => UpdsProcedureTransactionIdentityKind::UeInitiated,
            0x80..=0xFE => UpdsProcedureTransactionIdentityKind::NetworkInitiated,
            _ => UpdsProcedureTransactionIdentityKind::Reserved,
        }
    }

    pub fn is_reserved(self) -> bool {
        self.kind() == UpdsProcedureTransactionIdentityKind::Reserved
    }

    pub fn is_ue_initiated(self) -> bool {
        self.kind() == UpdsProcedureTransactionIdentityKind::UeInitiated
    }

    pub fn is_network_initiated(self) -> bool {
        self.kind() == UpdsProcedureTransactionIdentityKind::NetworkInitiated
    }

    pub fn is_unassigned(self) -> bool {
        self.kind() == UpdsProcedureTransactionIdentityKind::Unassigned
    }

    pub fn from_ue_initiated(value: u8) -> Option<Self> {
        (0x01..=0x77).contains(&value).then_some(Self { value })
    }

    pub fn from_network_initiated(value: u8) -> Option<Self> {
        (0x80..=0xFE).contains(&value).then_some(Self { value })
    }

    pub fn echo_response_pti(self) -> Self {
        self
    }
}

impl From<u8> for NasUpdsProcedureTransactionIdentity {
    fn from(value: u8) -> Self {
        Self::new_raw(value)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpdsProcedureInitiator {
    Ue,
    Network,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpdsProcedureRole {
    Command,
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdsMessageSemantics {
    pub initiator: UpdsProcedureInitiator,
    pub role: UpdsProcedureRole,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UePolicyPartType {
    Reserved,
    Ursp,
    Andsp,
    V2xp,
    ProSePolicy,
    A2xp,
    Rslpp,
    Unknown(u8),
}

impl UePolicyPartType {
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0F {
            0x00 => Self::Reserved,
            0x01 => Self::Ursp,
            0x02 => Self::Andsp,
            0x03 => Self::V2xp,
            0x04 => Self::ProSePolicy,
            0x05 => Self::A2xp,
            0x06 => Self::Rslpp,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Reserved => 0x00,
            Self::Ursp => 0x01,
            Self::Andsp => 0x02,
            Self::V2xp => 0x03,
            Self::ProSePolicy => 0x04,
            Self::A2xp => 0x05,
            Self::Rslpp => 0x06,
            Self::Unknown(value) => value & 0x0F,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UePolicyPart {
    pub part_type: UePolicyPartType,
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UePolicySectionManagementInstruction {
    pub upsc: u16,
    pub policy_parts: Vec<UePolicyPart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UePolicySectionManagementSublist {
    pub plmn: PlmnId,
    pub instructions: Vec<UePolicySectionManagementInstruction>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UePolicySectionManagementResultCause {
    ProtocolErrorUnspecified,
    Other(u8),
}

impl UePolicySectionManagementResultCause {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x6F => Self::ProtocolErrorUnspecified,
            other => Self::Other(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::ProtocolErrorUnspecified => 0x6F,
            Self::Other(value) => value,
        }
    }

    pub fn normalized(self) -> Self {
        match self {
            Self::ProtocolErrorUnspecified => Self::ProtocolErrorUnspecified,
            Self::Other(_) => Self::ProtocolErrorUnspecified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UePolicySectionManagementResultEntry {
    pub upsc: u16,
    pub failed_instruction_order: u16,
    pub cause: UePolicySectionManagementResultCause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UePolicySectionManagementSubresult {
    pub plmn: PlmnId,
    pub results: Vec<UePolicySectionManagementResultEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpsiSublist {
    pub plmn: PlmnId,
    pub upscs: Vec<u16>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VpsUrspReplacementType {
    PerTupleReplacement,
    FullListOfTuples,
    Reserved(u8),
}

impl VpsUrspReplacementType {
    pub fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0x01 => Self::PerTupleReplacement,
            0x02 => Self::FullListOfTuples,
            other => Self::Reserved(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::PerTupleReplacement => 0x01,
            Self::FullListOfTuples => 0x02,
            Self::Reserved(value) => value & 0x03,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VpsUrspNetworkDescriptorEntry {
    OneOrMoreVplmns(Vec<PlmnId>),
    OneOrMoreMccs(Vec<[u8; 3]>),
    AnyVplmn,
    Unknown { entry_type: u8, contents: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VpsUrspTuple {
    pub tuple_id: u8,
    pub network_descriptor: Vec<VpsUrspNetworkDescriptorEntry>,
    pub upscs: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VpsUrspConfigurationContents {
    pub replacement_type: VpsUrspReplacementType,
    pub tuples: Vec<VpsUrspTuple>,
}

impl NasUePolicySectionManagementList {
    pub fn sublists(&self) -> Vec<UePolicySectionManagementSublist> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 5 <= data.len() {
            let sublist_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if sublist_len < 3 || pos + sublist_len > data.len() {
                break;
            }
            let sublist_end = pos + sublist_len;
            let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                Some(plmn) => plmn,
                None => break,
            };
            pos += 3;
            let mut instructions = Vec::new();
            while pos + 2 <= sublist_end {
                let instruction_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                if instruction_len < 2 || pos + instruction_len > sublist_end {
                    break;
                }
                let instruction_end = pos + instruction_len;
                let upsc = u16::from_be_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                let mut policy_parts = Vec::new();
                while pos + 3 <= instruction_end {
                    let part_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if part_len < 1 || pos + part_len > instruction_end {
                        break;
                    }
                    let type_octet = data[pos];
                    pos += 1;
                    let contents_len = part_len - 1;
                    let contents = data[pos..pos + contents_len].to_vec();
                    pos += contents_len;
                    policy_parts.push(UePolicyPart {
                        part_type: UePolicyPartType::from_u8(type_octet & 0x0F),
                        contents,
                    });
                }
                pos = instruction_end;
                instructions.push(UePolicySectionManagementInstruction { upsc, policy_parts });
            }
            pos = sublist_end;
            out.push(UePolicySectionManagementSublist { plmn, instructions });
        }
        out
    }

    pub fn from_sublists(sublists: &[UePolicySectionManagementSublist]) -> Option<Self> {
        let mut value = Vec::new();
        for sublist in sublists {
            let mut sublist_body = sublist.plmn.to_tbcd().to_vec();
            for instruction in &sublist.instructions {
                let mut instruction_body = instruction.upsc.to_be_bytes().to_vec();
                for policy_part in &instruction.policy_parts {
                    let part_len = 1usize.checked_add(policy_part.contents.len())?;
                    let part_len = u16::try_from(part_len).ok()?;
                    instruction_body.extend_from_slice(&part_len.to_be_bytes());
                    instruction_body.push(policy_part.part_type.as_u8() & 0x0F);
                    instruction_body.extend_from_slice(&policy_part.contents);
                }
                let instruction_len = u16::try_from(instruction_body.len()).ok()?;
                sublist_body.extend_from_slice(&instruction_len.to_be_bytes());
                sublist_body.extend_from_slice(&instruction_body);
            }
            let sublist_len = u16::try_from(sublist_body.len()).ok()?;
            value.extend_from_slice(&sublist_len.to_be_bytes());
            value.extend_from_slice(&sublist_body);
        }
        Some(Self::new(value))
    }
}

impl NasUePolicySectionManagementResult {
    pub fn subresults(&self) -> Vec<UePolicySectionManagementSubresult> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let result_count = data[pos] as usize;
            let plmn = match PlmnId::from_tbcd(&data[pos + 1..pos + 4]) {
                Some(plmn) => plmn,
                None => break,
            };
            pos += 4;
            if pos + result_count * 5 > data.len() {
                break;
            }
            let mut results = Vec::with_capacity(result_count);
            for _ in 0..result_count {
                let upsc = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let failed_instruction_order = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                let cause = UePolicySectionManagementResultCause::from_u8(data[pos + 4]);
                pos += 5;
                results.push(UePolicySectionManagementResultEntry {
                    upsc,
                    failed_instruction_order,
                    cause,
                });
            }
            out.push(UePolicySectionManagementSubresult { plmn, results });
        }
        out
    }

    pub fn from_subresults(subresults: &[UePolicySectionManagementSubresult]) -> Option<Self> {
        let mut value = Vec::new();
        for subresult in subresults {
            value.push(subresult.results.len().try_into().ok()?);
            value.extend_from_slice(&subresult.plmn.to_tbcd());
            for result in &subresult.results {
                value.extend_from_slice(&result.upsc.to_be_bytes());
                value.extend_from_slice(&result.failed_instruction_order.to_be_bytes());
                value.push(result.cause.as_u8());
            }
        }
        Some(Self::new(value))
    }
}

impl NasUpsiList {
    pub fn sublists(&self) -> Vec<UpsiSublist> {
        let data = &self.value;
        let mut out = Vec::new();
        let mut pos = 0;
        while pos + 5 <= data.len() {
            let sublist_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if sublist_len < 3 || pos + sublist_len > data.len() {
                break;
            }
            let end = pos + sublist_len;
            let plmn = match PlmnId::from_tbcd(&data[pos..pos + 3]) {
                Some(plmn) => plmn,
                None => break,
            };
            pos += 3;
            let mut upscs = Vec::new();
            while pos + 2 <= end {
                upscs.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
                pos += 2;
            }
            pos = end;
            out.push(UpsiSublist { plmn, upscs });
        }
        out
    }

    pub fn from_sublists(sublists: &[UpsiSublist]) -> Option<Self> {
        let mut value = Vec::new();
        for sublist in sublists {
            let mut body = sublist.plmn.to_tbcd().to_vec();
            for upsc in &sublist.upscs {
                body.extend_from_slice(&upsc.to_be_bytes());
            }
            let body_len = u16::try_from(body.len()).ok()?;
            value.extend_from_slice(&body_len.to_be_bytes());
            value.extend_from_slice(&body);
        }
        Some(Self::new(value))
    }
}

impl NasVpsUrspConfiguration {
    pub fn parse(&self) -> Option<VpsUrspConfigurationContents> {
        let data = &self.value;
        let first = *data.first()?;
        let replacement_type = VpsUrspReplacementType::from_u8(first & 0x03);
        let mut pos = 1usize;
        let mut tuples = Vec::new();
        while pos + 3 <= data.len() {
            let tuple_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if tuple_len < 2 || pos + tuple_len > data.len() {
                return None;
            }
            let tuple_end = pos + tuple_len;
            let tuple_id = data[pos];
            pos += 1;
            let descriptor_entry_count = data[pos] as usize;
            pos += 1;
            let mut network_descriptor = Vec::with_capacity(descriptor_entry_count);
            for _ in 0..descriptor_entry_count {
                let entry_type = data.get(pos).copied()?;
                pos += 1;
                let entry = match entry_type {
                    0x01 => {
                        let plmn_count = data.get(pos).copied()? as usize;
                        pos += 1;
                        if pos + plmn_count * 3 > tuple_end {
                            return None;
                        }
                        let mut vplmns = Vec::with_capacity(plmn_count);
                        for _ in 0..plmn_count {
                            let plmn = PlmnId::from_tbcd(&data[pos..pos + 3])?;
                            pos += 3;
                            vplmns.push(plmn);
                        }
                        VpsUrspNetworkDescriptorEntry::OneOrMoreVplmns(vplmns)
                    }
                    0x02 => {
                        let mcc_count = data.get(pos).copied()? as usize;
                        pos += 1;
                        let pair_count = mcc_count / 2;
                        let has_odd = !mcc_count.is_multiple_of(2);
                        let required_len = pair_count * 3 + if has_odd { 2 } else { 0 };
                        if pos + required_len > tuple_end {
                            return None;
                        }
                        let mut mccs = Vec::with_capacity(mcc_count);
                        for _ in 0..pair_count {
                            let (first_mcc, second_mcc) = decode_mcc_pair(&data[pos..pos + 3]);
                            pos += 3;
                            mccs.push(first_mcc);
                            mccs.push(second_mcc);
                        }
                        if has_odd {
                            let odd_mcc = decode_odd_mcc(&data[pos..pos + 2]);
                            pos += 2;
                            mccs.push(odd_mcc);
                        }
                        VpsUrspNetworkDescriptorEntry::OneOrMoreMccs(mccs)
                    }
                    0x03 => VpsUrspNetworkDescriptorEntry::AnyVplmn,
                    other => {
                        let contents = data[pos..tuple_end].to_vec();
                        pos = tuple_end;
                        VpsUrspNetworkDescriptorEntry::Unknown {
                            entry_type: other,
                            contents,
                        }
                    }
                };
                network_descriptor.push(entry);
                if pos > tuple_end {
                    return None;
                }
            }
            let mut upscs = Vec::new();
            while pos + 2 <= tuple_end {
                upscs.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
                pos += 2;
            }
            pos = tuple_end;
            tuples.push(VpsUrspTuple {
                tuple_id,
                network_descriptor,
                upscs,
            });
        }
        Some(VpsUrspConfigurationContents {
            replacement_type,
            tuples,
        })
    }

    pub fn from_parsed(parsed: &VpsUrspConfigurationContents) -> Option<Self> {
        let mut value = vec![parsed.replacement_type.as_u8() & 0x03];
        for tuple in &parsed.tuples {
            let mut body = vec![tuple.tuple_id];
            body.push(tuple.network_descriptor.len().try_into().ok()?);
            for entry in &tuple.network_descriptor {
                match entry {
                    VpsUrspNetworkDescriptorEntry::OneOrMoreVplmns(vplmns) => {
                        body.push(0x01);
                        body.push(vplmns.len().try_into().ok()?);
                        for plmn in vplmns {
                            body.extend_from_slice(&plmn.to_tbcd());
                        }
                    }
                    VpsUrspNetworkDescriptorEntry::OneOrMoreMccs(mccs) => {
                        body.push(0x02);
                        body.push(mccs.len().try_into().ok()?);
                        let mut mcc_index = 0usize;
                        while mcc_index + 1 < mccs.len() {
                            body.extend_from_slice(&encode_mcc_pair(
                                mccs[mcc_index],
                                mccs[mcc_index + 1],
                            ));
                            mcc_index += 2;
                        }
                        if let Some(last) = mccs.get(mcc_index) {
                            body.extend_from_slice(&encode_odd_mcc(*last));
                        }
                    }
                    VpsUrspNetworkDescriptorEntry::AnyVplmn => body.push(0x03),
                    VpsUrspNetworkDescriptorEntry::Unknown {
                        entry_type,
                        contents,
                    } => {
                        body.push(*entry_type);
                        body.extend_from_slice(contents);
                    }
                }
            }
            for upsc in &tuple.upscs {
                body.extend_from_slice(&upsc.to_be_bytes());
            }
            let body_len = u16::try_from(body.len()).ok()?;
            value.extend_from_slice(&body_len.to_be_bytes());
            value.extend_from_slice(&body);
        }
        Some(Self::new(value))
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MultiplePayloadOptionalIe {
    PduSessionId(NasPduSessionIdentity2),
    AdditionalInformation(crate::NasAdditionalInformation),
    FiveGmmCause(NasFGmmCause),
    BackOffTimerValue(NasGprsTimer3),
    OldPduSessionId(NasPduSessionIdentity2),
    RequestType(NasRequestType),
    SNssai(NasSNssai),
    Dnn(NasDnn),
    ReleaseAssistanceIndication(NasReleaseAssistanceIndication),
    MaPduSessionInformation(NasMaPduSessionInformation),
    Unknown { iei: u8, value: Vec<u8> },
}

impl MultiplePayloadOptionalIe {
    pub fn iei(&self) -> u8 {
        match self {
            Self::PduSessionId(_) => 0x12,
            Self::AdditionalInformation(_) => 0x24,
            Self::FiveGmmCause(_) => 0x3A,
            Self::BackOffTimerValue(_) => 0x25,
            Self::OldPduSessionId(_) => 0x3B,
            Self::RequestType(_) => 0x50,
            Self::SNssai(_) => 0x16,
            Self::Dnn(_) => 0x19,
            Self::ReleaseAssistanceIndication(_) => 0xF0,
            Self::MaPduSessionInformation(_) => 0xA0,
            Self::Unknown { iei, .. } => *iei,
        }
    }

    pub fn value(&self) -> Vec<u8> {
        match self {
            Self::PduSessionId(ie) => vec![ie.value],
            Self::AdditionalInformation(ie) => ie.value.clone(),
            Self::FiveGmmCause(ie) => vec![ie.value],
            Self::BackOffTimerValue(ie) => ie.value.clone(),
            Self::OldPduSessionId(ie) => vec![ie.value],
            Self::RequestType(ie) => vec![ie.value],
            Self::SNssai(ie) => ie.value.clone(),
            Self::Dnn(ie) => ie.value.clone(),
            Self::ReleaseAssistanceIndication(ie) => vec![ie.value],
            Self::MaPduSessionInformation(ie) => vec![ie.value],
            Self::Unknown { value, .. } => value.clone(),
        }
    }

    pub fn from_raw(iei: u8, value: Vec<u8>) -> Self {
        match iei {
            0x12 => Self::PduSessionId(NasPduSessionIdentity2::new(
                value.first().copied().unwrap_or(0),
            )),
            0x24 => Self::AdditionalInformation(crate::NasAdditionalInformation::new(value)),
            0x3A => Self::FiveGmmCause(NasFGmmCause::new(value.first().copied().unwrap_or(0))),
            0x25 => Self::BackOffTimerValue(NasGprsTimer3::new(value)),
            0x3B => Self::OldPduSessionId(NasPduSessionIdentity2::new(
                value.first().copied().unwrap_or(0),
            )),
            0x50 => Self::RequestType(NasRequestType::new(value.first().copied().unwrap_or(0))),
            0x16 => Self::SNssai(NasSNssai::new(value)),
            0x19 => Self::Dnn(NasDnn::new(value)),
            0xF0 => Self::ReleaseAssistanceIndication(NasReleaseAssistanceIndication::new(
                value.first().copied().unwrap_or(0),
            )),
            0xA0 => Self::MaPduSessionInformation(NasMaPduSessionInformation::new(
                value.first().copied().unwrap_or(0),
            )),
            _ => Self::Unknown { iei, value },
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpdsEventNotificationIndicatorType {
    SrvccHandoverCancelledImsSessionReEstablishmentRequired,
    Unknown(u8),
}

impl UpdsEventNotificationIndicatorType {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::SrvccHandoverCancelledImsSessionReEstablishmentRequired,
            other => Self::Unknown(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::SrvccHandoverCancelledImsSessionReEstablishmentRequired => 0x00,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdsEventNotificationIndicator {
    pub indicator_type: UpdsEventNotificationIndicatorType,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdsEventNotificationContainer {
    pub indicators: Vec<UpdsEventNotificationIndicator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdsMultiplePayloadEntry {
    pub payload_container_type: crate::NasPayloadContainerType,
    pub optional_ies: Vec<MultiplePayloadOptionalIe>,
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UpdsMultiplePayloadContainer {
    pub entries: Vec<UpdsMultiplePayloadEntry>,
}

impl UpdsEventNotificationContainer {
    pub fn decode_from_slice(data: &[u8]) -> Result<Self> {
        let mut buffer = Bytes::copy_from_slice(data);
        if !buffer.has_remaining() {
            return Ok(Self::default());
        }
        let indicator_count = buffer.get_u8() as usize;
        let mut indicators = Vec::with_capacity(indicator_count);
        for _ in 0..indicator_count {
            if buffer.remaining() < 2 {
                return Err(NasError::BufferTooShort);
            }
            let indicator_type = UpdsEventNotificationIndicatorType::from_u8(buffer.get_u8());
            let length = buffer.get_u8() as usize;
            if buffer.remaining() < length {
                return Err(NasError::BufferTooShort);
            }
            let value = buffer.copy_to_bytes(length).to_vec();
            if matches!(
                indicator_type,
                UpdsEventNotificationIndicatorType::SrvccHandoverCancelledImsSessionReEstablishmentRequired
            ) && !value.is_empty()
            {
                return Err(NasError::DecodingError(
                    "SRVCC handover cancelled indicator shall not include a value field".into(),
                ));
            }
            indicators.push(UpdsEventNotificationIndicator {
                indicator_type,
                value,
            });
        }
        Ok(Self { indicators })
    }

    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + self.indicators.len() * 2);
        out.push(self.indicators.len().try_into().map_err(|_| {
            NasError::EncodingError("event notification indicator count exceeds 255".into())
        })?);
        for indicator in &self.indicators {
            if matches!(
                indicator.indicator_type,
                UpdsEventNotificationIndicatorType::SrvccHandoverCancelledImsSessionReEstablishmentRequired
            ) && !indicator.value.is_empty()
            {
                return Err(NasError::EncodingError(
                    "SRVCC handover cancelled indicator shall not include a value field".into(),
                ));
            }
            out.push(indicator.indicator_type.as_u8());
            out.push(indicator.value.len().try_into().map_err(|_| {
                NasError::EncodingError(
                    "event notification indicator value exceeds 255 octets".into(),
                )
            })?);
            out.extend_from_slice(&indicator.value);
        }
        Ok(out)
    }
}

impl UpdsMultiplePayloadContainer {
    pub fn decode_from_slice(data: &[u8]) -> Result<Self> {
        let mut buffer = Bytes::copy_from_slice(data);
        if !buffer.has_remaining() {
            return Ok(Self::default());
        }
        let entry_count = buffer.get_u8() as usize;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            if buffer.remaining() < 3 {
                return Err(NasError::BufferTooShort);
            }
            let entry_len = usize::from(buffer.get_u16());
            if buffer.remaining() < entry_len {
                return Err(NasError::BufferTooShort);
            }
            let mut entry_bytes = buffer.copy_to_bytes(entry_len);
            if !entry_bytes.has_remaining() {
                return Err(NasError::BufferTooShort);
            }
            let header = entry_bytes.get_u8();
            let optional_ie_count = (header >> 4) as usize;
            let payload_container_type = crate::NasPayloadContainerType::new(header & 0x0F);
            let mut optional_ies = Vec::with_capacity(optional_ie_count);
            for _ in 0..optional_ie_count {
                if entry_bytes.remaining() < 2 {
                    return Err(NasError::BufferTooShort);
                }
                let iei = entry_bytes.get_u8();
                let length = entry_bytes.get_u8() as usize;
                if entry_bytes.remaining() < length {
                    return Err(NasError::BufferTooShort);
                }
                let value = entry_bytes.copy_to_bytes(length).to_vec();
                optional_ies.push(MultiplePayloadOptionalIe::from_raw(iei, value));
            }
            let contents = entry_bytes.copy_to_bytes(entry_bytes.remaining()).to_vec();
            entries.push(UpdsMultiplePayloadEntry {
                payload_container_type,
                optional_ies,
                contents,
            });
        }
        Ok(Self { entries })
    }

    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(self.entries.len().try_into().map_err(|_| {
            NasError::EncodingError("multiple payload entry count exceeds 255".into())
        })?);
        for entry in &self.entries {
            let mut body = Vec::new();
            let optional_ie_count = u8::try_from(entry.optional_ies.len()).map_err(|_| {
                NasError::EncodingError("multiple payload optional IE count exceeds 15".into())
            })?;
            if optional_ie_count > 0x0F {
                return Err(NasError::EncodingError(
                    "multiple payload optional IE count exceeds 15".into(),
                ));
            }
            body.push((optional_ie_count << 4) | (entry.payload_container_type.value & 0x0F));
            for optional_ie in &entry.optional_ies {
                let value = optional_ie.value();
                body.push(optional_ie.iei());
                body.push(value.len().try_into().map_err(|_| {
                    NasError::EncodingError(
                        "multiple payload optional IE length exceeds 255 octets".into(),
                    )
                })?);
                body.extend_from_slice(&value);
            }
            body.extend_from_slice(&entry.contents);
            out.extend_from_slice(
                &(u16::try_from(body.len()).map_err(|_| {
                    NasError::EncodingError(
                        "multiple payload entry length exceeds 65535 octets".into(),
                    )
                })?)
                .to_be_bytes(),
            );
            out.extend_from_slice(&body);
        }
        Ok(out)
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NasUpdsMessageType {
    ManageUePolicyCommand,
    ManageUePolicyComplete,
    ManageUePolicyCommandReject,
    UeStateIndication,
    UePolicyProvisioningRequest,
    UePolicyProvisioningReject,
}

impl NasUpdsMessageType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::ManageUePolicyCommand => 0x01,
            Self::ManageUePolicyComplete => 0x02,
            Self::ManageUePolicyCommandReject => 0x03,
            Self::UeStateIndication => 0x04,
            Self::UePolicyProvisioningRequest => 0x05,
            Self::UePolicyProvisioningReject => 0x06,
        }
    }

    pub fn semantics(self) -> UpdsMessageSemantics {
        match self {
            Self::ManageUePolicyCommand => UpdsMessageSemantics {
                initiator: UpdsProcedureInitiator::Network,
                role: UpdsProcedureRole::Command,
            },
            Self::ManageUePolicyComplete | Self::ManageUePolicyCommandReject => {
                UpdsMessageSemantics {
                    initiator: UpdsProcedureInitiator::Ue,
                    role: UpdsProcedureRole::Response,
                }
            }
            Self::UeStateIndication | Self::UePolicyProvisioningRequest => UpdsMessageSemantics {
                initiator: UpdsProcedureInitiator::Ue,
                role: UpdsProcedureRole::Request,
            },
            Self::UePolicyProvisioningReject => UpdsMessageSemantics {
                initiator: UpdsProcedureInitiator::Network,
                role: UpdsProcedureRole::Response,
            },
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
            0x05 => Ok(Self::UePolicyProvisioningRequest),
            0x06 => Ok(Self::UePolicyProvisioningReject),
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasUePolicyProvisioningRequest {
    pub payload: Vec<u8>,
}

impl NasUePolicyProvisioningRequest {
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasUePolicyProvisioningReject {
    pub payload: Vec<u8>,
}

impl NasUePolicyProvisioningReject {
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NasUnsupportedUpdsMessage {
    pub message_type: u8,
    pub body: Vec<u8>,
}

impl NasUnsupportedUpdsMessage {
    pub fn new(message_type: u8, body: Vec<u8>) -> Self {
        Self { message_type, body }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NasUpdsMessage {
    ManageUePolicyCommand(NasManageUePolicyCommand),
    ManageUePolicyComplete(NasManageUePolicyComplete),
    ManageUePolicyCommandReject(NasManageUePolicyCommandReject),
    UeStateIndication(NasUeStateIndication),
    UePolicyProvisioningRequest(NasUePolicyProvisioningRequest),
    UePolicyProvisioningReject(NasUePolicyProvisioningReject),
    Unsupported(NasUnsupportedUpdsMessage),
}

impl NasUpdsMessage {
    pub fn message_type(&self) -> Option<NasUpdsMessageType> {
        match self {
            Self::ManageUePolicyCommand(_) => Some(NasUpdsMessageType::ManageUePolicyCommand),
            Self::ManageUePolicyComplete(_) => Some(NasUpdsMessageType::ManageUePolicyComplete),
            Self::ManageUePolicyCommandReject(_) => {
                Some(NasUpdsMessageType::ManageUePolicyCommandReject)
            }
            Self::UeStateIndication(_) => Some(NasUpdsMessageType::UeStateIndication),
            Self::UePolicyProvisioningRequest(_) => {
                Some(NasUpdsMessageType::UePolicyProvisioningRequest)
            }
            Self::UePolicyProvisioningReject(_) => {
                Some(NasUpdsMessageType::UePolicyProvisioningReject)
            }
            Self::Unsupported(_) => None,
        }
    }

    pub fn message_type_code(&self) -> u8 {
        match self {
            Self::Unsupported(message) => message.message_type,
            _ => self
                .message_type()
                .expect("all non-unsupported UPDS messages have a known message type")
                .as_u8(),
        }
    }

    pub fn semantics(&self) -> Option<UpdsMessageSemantics> {
        self.message_type().map(NasUpdsMessageType::semantics)
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

    pub fn new_with_pti(
        procedure_transaction_identity: NasUpdsProcedureTransactionIdentity,
        message: NasUpdsMessage,
    ) -> Self {
        Self::new(procedure_transaction_identity.raw(), message)
    }

    pub fn procedure_transaction_identity_value(&self) -> NasUpdsProcedureTransactionIdentity {
        NasUpdsProcedureTransactionIdentity::new_raw(self.procedure_transaction_identity)
    }

    pub fn set_procedure_transaction_identity(
        &mut self,
        procedure_transaction_identity: NasUpdsProcedureTransactionIdentity,
    ) -> &mut Self {
        self.procedure_transaction_identity = procedure_transaction_identity.raw();
        self
    }

    pub fn with_procedure_transaction_identity(
        mut self,
        procedure_transaction_identity: NasUpdsProcedureTransactionIdentity,
    ) -> Self {
        self.procedure_transaction_identity = procedure_transaction_identity.raw();
        self
    }

    pub fn message_type(&self) -> Option<NasUpdsMessageType> {
        self.message.message_type()
    }

    pub fn message_type_code(&self) -> u8 {
        self.message.message_type_code()
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
        buffer.put_u8(self.message.message_type_code());

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
            NasUpdsMessage::UePolicyProvisioningRequest(message) => {
                buffer.extend_from_slice(&message.payload);
            }
            NasUpdsMessage::UePolicyProvisioningReject(message) => {
                buffer.extend_from_slice(&message.payload);
            }
            NasUpdsMessage::Unsupported(message) => {
                buffer.extend_from_slice(&message.body);
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
        let message_type_code = buffer.get_u8();

        let message = match NasUpdsMessageType::try_from(message_type_code) {
            Ok(NasUpdsMessageType::ManageUePolicyCommand) => {
                let mut message = NasManageUePolicyCommand::new(
                    NasUePolicySectionManagementList::new(decode_lve(buffer)?),
                );
                while buffer.has_remaining() {
                    match buffer[0] {
                        IEI_UE_POLICY_NETWORK_CLASSMARK => {
                            if message.ue_policy_network_classmark.is_some() {
                                if skip_optional_tlv(buffer, IEI_UE_POLICY_NETWORK_CLASSMARK)
                                    .is_none()
                                {
                                    break;
                                }
                            } else if let Some(contents) =
                                decode_optional_tlv(buffer, IEI_UE_POLICY_NETWORK_CLASSMARK)
                            {
                                message.ue_policy_network_classmark =
                                    Some(NasUePolicyNetworkClassmark::new(contents));
                            } else {
                                break;
                            }
                        }
                        IEI_VPS_URSP_CONFIGURATION => {
                            if message.vps_ursp_configuration.is_some() {
                                if skip_optional_tlve(buffer, IEI_VPS_URSP_CONFIGURATION).is_none()
                                {
                                    break;
                                }
                            } else if let Some(contents) =
                                decode_optional_tlve(buffer, IEI_VPS_URSP_CONFIGURATION)
                            {
                                message.vps_ursp_configuration =
                                    Some(NasVpsUrspConfiguration::new(contents));
                            } else {
                                break;
                            }
                        }
                        _ => {
                            if let Some(unknown_ie) = decode_unknown_ie_lossy(buffer) {
                                message.unknown_ies.push(unknown_ie);
                            } else {
                                break;
                            }
                        }
                    }
                }
                NasUpdsMessage::ManageUePolicyCommand(message)
            }
            Ok(NasUpdsMessageType::ManageUePolicyComplete) => {
                let mut message = NasManageUePolicyComplete::new();
                while buffer.has_remaining() {
                    if let Some(unknown_ie) = decode_unknown_ie_lossy(buffer) {
                        message.unknown_ies.push(unknown_ie);
                    } else {
                        break;
                    }
                }
                NasUpdsMessage::ManageUePolicyComplete(message)
            }
            Ok(NasUpdsMessageType::ManageUePolicyCommandReject) => {
                let mut message = NasManageUePolicyCommandReject::new(
                    NasUePolicySectionManagementResult::new(decode_lve(buffer)?),
                );
                while buffer.has_remaining() {
                    if let Some(unknown_ie) = decode_unknown_ie_lossy(buffer) {
                        message.unknown_ies.push(unknown_ie);
                    } else {
                        break;
                    }
                }
                NasUpdsMessage::ManageUePolicyCommandReject(message)
            }
            Ok(NasUpdsMessageType::UeStateIndication) => {
                let mut message = NasUeStateIndication::new(
                    NasUpsiList::new(decode_lve(buffer)?),
                    NasUePolicyClassmark::new(decode_lv(buffer)?),
                );
                while buffer.has_remaining() {
                    match buffer[0] {
                        IEI_UE_OS_ID => {
                            if message.ue_os_id.is_some() {
                                if skip_optional_tlv(buffer, IEI_UE_OS_ID).is_none() {
                                    break;
                                }
                            } else if let Some(contents) = decode_optional_tlv(buffer, IEI_UE_OS_ID)
                            {
                                message.ue_os_id = Some(NasUeOsId::new(contents));
                            } else {
                                break;
                            }
                        }
                        _ => {
                            if let Some(unknown_ie) = decode_unknown_ie_lossy(buffer) {
                                message.unknown_ies.push(unknown_ie);
                            } else {
                                break;
                            }
                        }
                    }
                }
                NasUpdsMessage::UeStateIndication(message)
            }
            Ok(NasUpdsMessageType::UePolicyProvisioningRequest) => {
                NasUpdsMessage::UePolicyProvisioningRequest(NasUePolicyProvisioningRequest::new(
                    buffer.copy_to_bytes(buffer.remaining()).to_vec(),
                ))
            }
            Ok(NasUpdsMessageType::UePolicyProvisioningReject) => {
                NasUpdsMessage::UePolicyProvisioningReject(NasUePolicyProvisioningReject::new(
                    buffer.copy_to_bytes(buffer.remaining()).to_vec(),
                ))
            }
            Err(_) => NasUpdsMessage::Unsupported(NasUnsupportedUpdsMessage::new(
                message_type_code,
                buffer.copy_to_bytes(buffer.remaining()).to_vec(),
            )),
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

fn decode_optional_tlv(buffer: &mut Bytes, expected_iei: u8) -> Option<Vec<u8>> {
    let mut lookahead = buffer.clone();
    match decode_tlv(&mut lookahead, expected_iei) {
        Ok(contents) => {
            *buffer = lookahead;
            Some(contents)
        }
        Err(_) => {
            buffer.advance(buffer.remaining());
            None
        }
    }
}

fn decode_optional_tlve(buffer: &mut Bytes, expected_iei: u8) -> Option<Vec<u8>> {
    let mut lookahead = buffer.clone();
    match decode_tlve(&mut lookahead, expected_iei) {
        Ok(contents) => {
            *buffer = lookahead;
            Some(contents)
        }
        Err(_) => {
            buffer.advance(buffer.remaining());
            None
        }
    }
}

fn skip_optional_tlv(buffer: &mut Bytes, expected_iei: u8) -> Option<()> {
    decode_optional_tlv(buffer, expected_iei).map(|_| ())
}

fn skip_optional_tlve(buffer: &mut Bytes, expected_iei: u8) -> Option<()> {
    decode_optional_tlve(buffer, expected_iei).map(|_| ())
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

fn decode_unknown_ie_lossy(buffer: &mut Bytes) -> Option<UpdsUnknownIe> {
    let mut lookahead = buffer.clone();
    match decode_unknown_ie(&mut lookahead) {
        Ok(unknown_ie) => {
            *buffer = lookahead;
            Some(unknown_ie)
        }
        Err(_) => {
            buffer.advance(buffer.remaining());
            None
        }
    }
}

fn decode_mcc_pair(bytes: &[u8]) -> ([u8; 3], [u8; 3]) {
    (
        [bytes[0] & 0x0F, (bytes[0] >> 4) & 0x0F, bytes[1] & 0x0F],
        [
            bytes[2] & 0x0F,
            (bytes[2] >> 4) & 0x0F,
            (bytes[1] >> 4) & 0x0F,
        ],
    )
}

fn encode_mcc_pair(first: [u8; 3], second: [u8; 3]) -> [u8; 3] {
    [
        ((first[1] & 0x0F) << 4) | (first[0] & 0x0F),
        ((second[2] & 0x0F) << 4) | (first[2] & 0x0F),
        ((second[1] & 0x0F) << 4) | (second[0] & 0x0F),
    ]
}

fn decode_odd_mcc(bytes: &[u8]) -> [u8; 3] {
    [bytes[0] & 0x0F, (bytes[0] >> 4) & 0x0F, bytes[1] & 0x0F]
}

fn encode_odd_mcc(mcc: [u8; 3]) -> [u8; 2] {
    [((mcc[1] & 0x0F) << 4) | (mcc[0] & 0x0F), mcc[2] & 0x0F]
}

impl fmt::Display for NasUpdsProcedureTransactionIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind() {
            UpdsProcedureTransactionIdentityKind::Unassigned => write!(f, "0x00 (unassigned)"),
            UpdsProcedureTransactionIdentityKind::UeInitiated => {
                write!(f, "0x{:02X} (UE-initiated)", self.value)
            }
            UpdsProcedureTransactionIdentityKind::NetworkInitiated => {
                write!(f, "0x{:02X} (network-initiated)", self.value)
            }
            UpdsProcedureTransactionIdentityKind::Reserved => {
                write!(f, "0x{:02X} (reserved)", self.value)
            }
        }
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
        let message = NasUpdsEnvelope::new_with_pti(
            NasUpdsProcedureTransactionIdentity::from_network_initiated(0x80).unwrap(),
            NasUpdsMessage::ManageUePolicyCommand(
                NasManageUePolicyCommand::new(
                    NasUePolicySectionManagementList::from_sublists(&[
                        UePolicySectionManagementSublist {
                            plmn: PlmnId {
                                mcc: [2, 0, 8],
                                mnc: [9, 3, 0x0F],
                            },
                            instructions: vec![UePolicySectionManagementInstruction {
                                upsc: 0x0102,
                                policy_parts: vec![UePolicyPart {
                                    part_type: UePolicyPartType::Ursp,
                                    contents: vec![0xAA, 0xBB],
                                }],
                            }],
                        },
                    ])
                    .unwrap(),
                )
                .with_ue_policy_network_classmark(NasUePolicyNetworkClassmark::from_handling(
                    NonSubscribedSnpnUrspHandling::Disallow,
                ))
                .with_vps_ursp_configuration(
                    NasVpsUrspConfiguration::from_parsed(&VpsUrspConfigurationContents {
                        replacement_type: VpsUrspReplacementType::PerTupleReplacement,
                        tuples: vec![VpsUrspTuple {
                            tuple_id: 1,
                            network_descriptor: vec![VpsUrspNetworkDescriptorEntry::AnyVplmn],
                            upscs: vec![0x0102],
                        }],
                    })
                    .unwrap(),
                ),
            ),
        );

        let encoded = message.encode_to_vec().unwrap();
        let decoded = NasUpdsEnvelope::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_upds_state_indication_roundtrip() {
        let message = NasUpdsEnvelope::new_with_pti(
            NasUpdsProcedureTransactionIdentity::from_ue_initiated(0x01).unwrap(),
            NasUpdsMessage::UeStateIndication(
                NasUeStateIndication::new(
                    NasUpsiList::from_sublists(&[UpsiSublist {
                        plmn: PlmnId {
                            mcc: [2, 0, 8],
                            mnc: [9, 3, 0x0F],
                        },
                        upscs: vec![0x0102, 0x0103],
                    }])
                    .unwrap(),
                    NasUePolicyClassmark::from_flags(true, false, true, false),
                )
                .with_ue_os_id(NasUeOsId::from_os_ids(&[[0x11; 16], [0x22; 16]]).unwrap()),
            ),
        );

        let encoded = message.encode_to_vec().unwrap();
        let decoded = NasUpdsEnvelope::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_upds_container_roundtrip() {
        let message = NasUpdsEnvelope::new(
            7,
            NasUpdsMessage::ManageUePolicyComplete(NasManageUePolicyComplete::new()),
        );
        let container = NasPayloadContainer::from_ue_policy_message(&message).unwrap();
        let decoded = container.decode_as_ue_policy_message().unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_upds_provisioning_message_roundtrip() {
        let message = NasUpdsEnvelope::new(
            0x01,
            NasUpdsMessage::UePolicyProvisioningRequest(NasUePolicyProvisioningRequest::new(vec![
                0xAA, 0xBB, 0xCC,
            ])),
        );
        let encoded = message.encode_to_vec().unwrap();
        let decoded = NasUpdsEnvelope::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn test_upds_unknown_message_type_is_preserved() {
        let decoded = NasUpdsEnvelope::decode_from_slice(&[0x01, 0x99, 0xAA, 0xBB]).unwrap();
        assert_eq!(
            decoded.message,
            NasUpdsMessage::Unsupported(NasUnsupportedUpdsMessage::new(0x99, vec![0xAA, 0xBB]))
        );
    }

    #[test]
    fn test_upds_repeated_optional_ie_first_wins() {
        let encoded = vec![
            0x80, 0x01, 0x00, 0x09, 0x00, 0x06, 0x20, 0x89, 0xF3, 0x00, 0x02, 0x00, 0x01, 0x42,
            0x01, 0x00, 0x42, 0x01, 0x01,
        ];
        let decoded = NasUpdsEnvelope::decode_from_slice(&encoded).unwrap();
        let NasUpdsMessage::ManageUePolicyCommand(message) = decoded.message else {
            panic!("expected MANAGE UE POLICY COMMAND");
        };
        assert_eq!(
            message.ue_policy_network_classmark.unwrap().handling(),
            NonSubscribedSnpnUrspHandling::Allow
        );
    }

    #[test]
    fn test_upds_malformed_optional_ie_is_ignored() {
        let encoded = vec![
            0x01, 0x04, 0x00, 0x05, 0x00, 0x03, 0x20, 0x89, 0xF3, 0x01, 0x42, 0x02, 0xFF,
        ];
        let decoded = NasUpdsEnvelope::decode_from_slice(&encoded).unwrap();
        let NasUpdsMessage::UeStateIndication(message) = decoded.message else {
            panic!("expected UE STATE INDICATION");
        };
        assert!(message.ue_os_id.is_none());
    }

    #[test]
    fn test_event_notification_container_roundtrip() {
        let container = UpdsEventNotificationContainer {
            indicators: vec![UpdsEventNotificationIndicator {
                indicator_type:
                    UpdsEventNotificationIndicatorType::SrvccHandoverCancelledImsSessionReEstablishmentRequired,
                value: Vec::new(),
            }],
        };
        let encoded = container.encode_to_vec().unwrap();
        let decoded = UpdsEventNotificationContainer::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, container);
    }

    #[test]
    fn test_multiple_payload_container_roundtrip() {
        let container = UpdsMultiplePayloadContainer {
            entries: vec![UpdsMultiplePayloadEntry {
                payload_container_type: crate::NasPayloadContainerType::from_kind(
                    crate::PayloadContainerKind::N1SmInformation,
                ),
                optional_ies: vec![
                    MultiplePayloadOptionalIe::PduSessionId(NasPduSessionIdentity2::new(5)),
                    MultiplePayloadOptionalIe::RequestType(NasRequestType::from_request_type(
                        crate::RequestTypeValue::InitialRequest,
                    )),
                ],
                contents: vec![0x2E, 0x01, 0x01, 0xC1],
            }],
        };
        let encoded = container.encode_to_vec().unwrap();
        let decoded = UpdsMultiplePayloadContainer::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, container);
    }
}
