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
    common::{IgnoredIeReason, OptionalIeOrder, generic_ie_length},
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
        /// Typed representation of raw UPDS information element.
        pub struct $name {
            /// Raw information-element contents.
            pub value: Vec<u8>,
        }

        impl $name {
            /// Construct a new value.
            pub fn new(value: Vec<u8>) -> Self {
                Self { value }
            }

            /// Return the raw encoded octets.
            pub fn data(&self) -> &[u8] {
                &self.value
            }

            /// Construct a value from data.
            pub fn from_data(data: Vec<u8>) -> Self {
                Self::new(data)
            }

            /// Set data.
            pub fn set_data(&mut self, data: Vec<u8>) -> &mut Self {
                self.value = data;
                self
            }

            /// Set data and return the updated value.
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
    /// Return whether ANDSP.
    pub fn support_andsp(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Return EPS URSP.
    pub fn eps_ursp(&self) -> bool {
        self.value.first().map(|b| b & 0x02 != 0).unwrap_or(false)
    }

    /// Return svpsu.
    pub fn svpsu(&self) -> bool {
        self.value.first().map(|b| b & 0x04 != 0).unwrap_or(false)
    }

    /// Return whether rure.
    pub fn support_rure(&self) -> bool {
        self.value.first().map(|b| b & 0x08 != 0).unwrap_or(false)
    }

    /// Construct a value from flags.
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
/// Non subscribed SNPN URSP handling values.
pub enum NonSubscribedSnpnUrspHandling {
    /// Allow.
    Allow,
    /// Disallow.
    Disallow,
}

impl NasUePolicyNetworkClassmark {
    /// Return NSSUI.
    pub fn nssui(&self) -> bool {
        self.value.first().map(|b| b & 0x01 != 0).unwrap_or(false)
    }

    /// Return handling.
    pub fn handling(&self) -> NonSubscribedSnpnUrspHandling {
        if self.nssui() {
            NonSubscribedSnpnUrspHandling::Disallow
        } else {
            NonSubscribedSnpnUrspHandling::Allow
        }
    }

    /// Construct a value from NSSUI.
    pub fn from_nssui(nssui: bool) -> Self {
        Self::new(vec![if nssui { 0x01 } else { 0x00 }])
    }

    /// Construct a value from handling.
    pub fn from_handling(handling: NonSubscribedSnpnUrspHandling) -> Self {
        Self::from_nssui(matches!(handling, NonSubscribedSnpnUrspHandling::Disallow))
    }
}

impl NasUeOsId {
    /// Return OS identifiers.
    pub fn os_ids(&self) -> Vec<[u8; 16]> {
        self.value
            .as_chunks::<16>()
            .0
            .iter()
            .map(|chunk| {
                let mut out = [0u8; 16];
                out.copy_from_slice(chunk);
                out
            })
            .collect()
    }

    /// Construct a value from OS identifiers.
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
/// Typed representation of UPDS unknown IE.
pub struct UpdsUnknownIe {
    /// Information-element identifier.
    pub iei: u8,
    /// Raw encoded octets.
    pub data: Vec<u8>,
}

impl UpdsUnknownIe {
    /// Whether this unknown IE is comprehension-required by the TS 24.007 rule.
    pub fn is_comprehension_required(&self) -> bool {
        self.iei <= 0x0f || matches!(self.iei, 0x7e | 0x7f)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS UPDS procedure transaction identity.
pub struct NasUpdsProcedureTransactionIdentity {
    value: u8,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// UPDS procedure transaction identity kind values.
pub enum UpdsProcedureTransactionIdentityKind {
    /// Unassigned.
    Unassigned,
    /// UE initiated.
    UeInitiated,
    /// Network initiated.
    NetworkInitiated,
    /// Reserved.
    Reserved,
}

impl NasUpdsProcedureTransactionIdentity {
    /// Return new raw.
    pub fn new_raw(value: u8) -> Self {
        Self { value }
    }

    /// Return raw.
    pub fn raw(self) -> u8 {
        self.value
    }

    /// Return kind.
    pub fn kind(self) -> UpdsProcedureTransactionIdentityKind {
        match self.value {
            0x00 => UpdsProcedureTransactionIdentityKind::Unassigned,
            0x01..=0x77 => UpdsProcedureTransactionIdentityKind::UeInitiated,
            0x80..=0xFE => UpdsProcedureTransactionIdentityKind::NetworkInitiated,
            _ => UpdsProcedureTransactionIdentityKind::Reserved,
        }
    }

    /// Return whether reserved.
    pub fn is_reserved(self) -> bool {
        self.kind() == UpdsProcedureTransactionIdentityKind::Reserved
    }

    /// Return whether UE initiated.
    pub fn is_ue_initiated(self) -> bool {
        self.kind() == UpdsProcedureTransactionIdentityKind::UeInitiated
    }

    /// Return whether network initiated.
    pub fn is_network_initiated(self) -> bool {
        self.kind() == UpdsProcedureTransactionIdentityKind::NetworkInitiated
    }

    /// Return whether unassigned.
    pub fn is_unassigned(self) -> bool {
        self.kind() == UpdsProcedureTransactionIdentityKind::Unassigned
    }

    /// Construct a value from UE initiated.
    pub fn from_ue_initiated(value: u8) -> Option<Self> {
        (0x01..=0x77).contains(&value).then_some(Self { value })
    }

    /// Construct a value from network initiated.
    pub fn from_network_initiated(value: u8) -> Option<Self> {
        (0x80..=0xFE).contains(&value).then_some(Self { value })
    }

    /// Return echo response PTI.
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
/// UPDS procedure initiator values.
pub enum UpdsProcedureInitiator {
    /// UE.
    Ue,
    /// Network.
    Network,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// UPDS procedure role values.
pub enum UpdsProcedureRole {
    /// Command.
    Command,
    /// Request.
    Request,
    /// Response.
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UPDS message semantics.
pub struct UpdsMessageSemantics {
    /// Initiator.
    pub initiator: UpdsProcedureInitiator,
    /// Role.
    pub role: UpdsProcedureRole,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// UE policy part type values.
pub enum UePolicyPartType {
    /// Reserved.
    Reserved,
    /// URSP.
    Ursp,
    /// ANDSP.
    Andsp,
    /// V 2 xp.
    V2xp,
    /// Pro se policy.
    ProSePolicy,
    /// A 2 xp.
    A2xp,
    /// Rslpp.
    Rslpp,
    /// Unknown.
    Unknown(u8),
}

impl UePolicyPartType {
    /// Decode a value from its wire octet.
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

    /// Return the wire octet.
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
/// Typed representation of UE policy part.
pub struct UePolicyPart {
    /// Part type.
    pub part_type: UePolicyPartType,
    /// Encoded contents.
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UE policy section management instruction.
pub struct UePolicySectionManagementInstruction {
    /// Upsc.
    pub upsc: u16,
    /// Policy parts.
    pub policy_parts: Vec<UePolicyPart>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UE policy section management sublist.
pub struct UePolicySectionManagementSublist {
    /// PLMN.
    pub plmn: PlmnId,
    /// Instructions.
    pub instructions: Vec<UePolicySectionManagementInstruction>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// UE policy section management result cause values.
pub enum UePolicySectionManagementResultCause {
    /// Protocol error unspecified.
    ProtocolErrorUnspecified,
    /// Other.
    Other(u8),
}

impl UePolicySectionManagementResultCause {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x6F => Self::ProtocolErrorUnspecified,
            other => Self::Other(other),
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::ProtocolErrorUnspecified => 0x6F,
            Self::Other(value) => value,
        }
    }

    /// Return normalized.
    pub fn normalized(self) -> Self {
        match self {
            Self::ProtocolErrorUnspecified => Self::ProtocolErrorUnspecified,
            Self::Other(_) => Self::ProtocolErrorUnspecified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UE policy section management result entry.
pub struct UePolicySectionManagementResultEntry {
    /// Upsc.
    pub upsc: u16,
    /// Failed instruction order.
    pub failed_instruction_order: u16,
    /// Cause.
    pub cause: UePolicySectionManagementResultCause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UE policy section management subresult.
pub struct UePolicySectionManagementSubresult {
    /// PLMN.
    pub plmn: PlmnId,
    /// Results.
    pub results: Vec<UePolicySectionManagementResultEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UPSI sublist.
pub struct UpsiSublist {
    /// PLMN.
    pub plmn: PlmnId,
    /// UPSCs.
    pub upscs: Vec<u16>,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// VPS URSP replacement type values.
pub enum VpsUrspReplacementType {
    /// Per tuple replacement.
    PerTupleReplacement,
    /// Full list of tuples.
    FullListOfTuples,
    /// Reserved.
    Reserved(u8),
}

impl VpsUrspReplacementType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x03 {
            0x01 => Self::PerTupleReplacement,
            0x02 => Self::FullListOfTuples,
            other => Self::Reserved(other),
        }
    }

    /// Return the wire octet.
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
/// VPS URSP network descriptor entry values.
pub enum VpsUrspNetworkDescriptorEntry {
    /// One or more VPLMNs.
    OneOrMoreVplmns(Vec<PlmnId>),
    /// One or more mccs.
    OneOrMoreMccs(Vec<[u8; 3]>),
    /// Any VPLMN.
    AnyVplmn,
    /// Unknown.
    Unknown {
        /// Entry type.
        entry_type: u8,
        /// Encoded contents.
        contents: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of VPS URSP tuple.
pub struct VpsUrspTuple {
    /// Tuple identifier.
    pub tuple_id: u8,
    /// Network descriptor.
    pub network_descriptor: Vec<VpsUrspNetworkDescriptorEntry>,
    /// UPSCs.
    pub upscs: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of VPS URSP configuration contents.
pub struct VpsUrspConfigurationContents {
    /// Replacement type.
    pub replacement_type: VpsUrspReplacementType,
    /// Tuples.
    pub tuples: Vec<VpsUrspTuple>,
}

impl NasUePolicySectionManagementList {
    /// Parse all sublists, returning `None` for malformed internal framing.
    pub fn try_sublists(&self) -> Option<Vec<UePolicySectionManagementSublist>> {
        let data = &self.value;
        if !(9..=65531).contains(&data.len()) {
            return None;
        }
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos + 5 > data.len() {
                return None;
            }
            let sublist_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if sublist_len < 7 || pos + sublist_len > data.len() {
                return None;
            }
            let sublist_end = pos + sublist_len;
            let plmn = PlmnId::from_tbcd(&data[pos..pos + 3])?;
            pos += 3;
            let mut instructions = Vec::new();
            while pos < sublist_end {
                if pos + 4 > sublist_end {
                    return None;
                }
                let instruction_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += 2;
                if instruction_len < 2 || pos + instruction_len > sublist_end {
                    return None;
                }
                let instruction_end = pos + instruction_len;
                let upsc = u16::from_be_bytes([data[pos], data[pos + 1]]);
                pos += 2;
                let mut policy_parts = Vec::new();
                while pos < instruction_end {
                    if pos + 3 > instruction_end {
                        return None;
                    }
                    let part_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if part_len < 1 || pos + part_len > instruction_end {
                        return None;
                    }
                    let type_octet = data[pos];
                    pos += 1;
                    let contents = data[pos..pos + part_len - 1].to_vec();
                    pos += part_len - 1;
                    policy_parts.push(UePolicyPart {
                        part_type: UePolicyPartType::from_u8(type_octet),
                        contents,
                    });
                }
                instructions.push(UePolicySectionManagementInstruction { upsc, policy_parts });
            }
            if instructions.is_empty() {
                return None;
            }
            out.push(UePolicySectionManagementSublist { plmn, instructions });
        }
        (!out.is_empty()).then_some(out)
    }

    /// Return all structurally valid sublists, or an empty list for malformed data.
    pub fn sublists(&self) -> Vec<UePolicySectionManagementSublist> {
        self.try_sublists().unwrap_or_default()
    }

    /// Construct a sender-valid value from typed sublists.
    pub fn from_sublists(sublists: &[UePolicySectionManagementSublist]) -> Option<Self> {
        if sublists.is_empty() {
            return None;
        }
        let mut value = Vec::new();
        for sublist in sublists {
            let mut sublist_body = sublist.plmn.try_to_tbcd()?.to_vec();
            if sublist.instructions.is_empty() {
                return None;
            }
            for instruction in &sublist.instructions {
                let mut instruction_body = instruction.upsc.to_be_bytes().to_vec();
                for policy_part in &instruction.policy_parts {
                    if !matches!(
                        policy_part.part_type,
                        UePolicyPartType::Ursp
                            | UePolicyPartType::Andsp
                            | UePolicyPartType::V2xp
                            | UePolicyPartType::ProSePolicy
                            | UePolicyPartType::A2xp
                            | UePolicyPartType::Rslpp
                    ) {
                        return None;
                    }
                    let part_len = 1usize.checked_add(policy_part.contents.len())?;
                    let part_len = u16::try_from(part_len).ok()?;
                    instruction_body.extend_from_slice(&part_len.to_be_bytes());
                    instruction_body.push(policy_part.part_type.as_u8());
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
        (value.len() <= 65531).then(|| Self::new(value))
    }

    /// Whether the value is valid for transmission.
    pub fn is_well_formed(&self) -> bool {
        self.try_sublists().is_some_and(|sublists| {
            Self::from_sublists(&sublists).is_some_and(|rebuilt| rebuilt.value == self.value)
        })
    }
}

impl NasUePolicySectionManagementResult {
    /// Parse all subresults, returning `None` for malformed internal framing.
    pub fn try_subresults(&self) -> Option<Vec<UePolicySectionManagementSubresult>> {
        let data = &self.value;
        if !(9..=65531).contains(&data.len()) {
            return None;
        }
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos + 4 > data.len() {
                return None;
            }
            let result_count = data[pos] as usize;
            if result_count == 0 {
                return None;
            }
            let plmn = PlmnId::from_tbcd(&data[pos + 1..pos + 4])?;
            pos += 4;
            let results_len = result_count.checked_mul(5)?;
            if pos + results_len > data.len() {
                return None;
            }
            let mut results = Vec::with_capacity(result_count);
            for _ in 0..result_count {
                let upsc = u16::from_be_bytes([data[pos], data[pos + 1]]);
                let failed_instruction_order = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
                let cause =
                    UePolicySectionManagementResultCause::from_u8(data[pos + 4]).normalized();
                pos += 5;
                results.push(UePolicySectionManagementResultEntry {
                    upsc,
                    failed_instruction_order,
                    cause,
                });
            }
            out.push(UePolicySectionManagementSubresult { plmn, results });
        }
        (!out.is_empty()).then_some(out)
    }

    /// Return all structurally valid subresults, or an empty list for malformed data.
    pub fn subresults(&self) -> Vec<UePolicySectionManagementSubresult> {
        self.try_subresults().unwrap_or_default()
    }

    /// Construct a sender-valid value from typed subresults.
    pub fn from_subresults(subresults: &[UePolicySectionManagementSubresult]) -> Option<Self> {
        if subresults.is_empty() {
            return None;
        }
        let mut value = Vec::new();
        for subresult in subresults {
            if subresult.results.is_empty() {
                return None;
            }
            value.push(subresult.results.len().try_into().ok()?);
            value.extend_from_slice(&subresult.plmn.try_to_tbcd()?);
            for result in &subresult.results {
                if result.failed_instruction_order == 0
                    || result.cause
                        != UePolicySectionManagementResultCause::ProtocolErrorUnspecified
                {
                    return None;
                }
                value.extend_from_slice(&result.upsc.to_be_bytes());
                value.extend_from_slice(&result.failed_instruction_order.to_be_bytes());
                value.push(result.cause.as_u8());
            }
        }
        (value.len() <= 65531).then(|| Self::new(value))
    }

    /// Whether the value is valid for transmission.
    pub fn is_well_formed(&self) -> bool {
        self.try_subresults().is_some_and(|subresults| {
            Self::from_subresults(&subresults).is_some_and(|rebuilt| rebuilt.value == self.value)
        })
    }
}

impl NasUpsiList {
    /// Parse all UPSI sublists, returning `None` for malformed internal framing.
    pub fn try_sublists(&self) -> Option<Vec<UpsiSublist>> {
        let data = &self.value;
        if data.len() > 65529 {
            return None;
        }
        if data.is_empty() {
            return Some(Vec::new());
        }
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            if pos + 5 > data.len() {
                return None;
            }
            let sublist_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if sublist_len < 5
                || !(sublist_len - 3).is_multiple_of(2)
                || pos + sublist_len > data.len()
            {
                return None;
            }
            let end = pos + sublist_len;
            let plmn = PlmnId::from_tbcd(&data[pos..pos + 3])?;
            pos += 3;
            let mut upscs = Vec::new();
            while pos < end {
                upscs.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
                pos += 2;
            }
            out.push(UpsiSublist { plmn, upscs });
        }
        Some(out)
    }

    /// Return all structurally valid sublists, or an empty list for malformed data.
    pub fn sublists(&self) -> Vec<UpsiSublist> {
        self.try_sublists().unwrap_or_default()
    }

    /// Construct a sender-valid UPSI list. An empty slice encodes the specified
    /// zero-length list meaning that no UPSIs are included.
    pub fn from_sublists(sublists: &[UpsiSublist]) -> Option<Self> {
        let mut value = Vec::new();
        for sublist in sublists {
            if sublist.upscs.is_empty() {
                return None;
            }
            let mut body = sublist.plmn.try_to_tbcd()?.to_vec();
            for upsc in &sublist.upscs {
                body.extend_from_slice(&upsc.to_be_bytes());
            }
            let body_len = u16::try_from(body.len()).ok()?;
            value.extend_from_slice(&body_len.to_be_bytes());
            value.extend_from_slice(&body);
        }
        (value.len() <= 65529).then(|| Self::new(value))
    }

    /// Whether the value is valid for transmission.
    pub fn is_well_formed(&self) -> bool {
        self.try_sublists().is_some_and(|sublists| {
            Self::from_sublists(&sublists).is_some_and(|rebuilt| rebuilt.value == self.value)
        })
    }
}

impl NasVpsUrspConfiguration {
    /// Parse the typed contents, requiring exact Annex D.6.8 framing.
    pub fn parse(&self) -> Option<VpsUrspConfigurationContents> {
        let data = &self.value;
        if data.len() > 65530 {
            return None;
        }
        // Bits 8 to 3 of octet 4 are spare (Figure D.6.8.1).
        let first = *data.first()?;
        let replacement_type = VpsUrspReplacementType::from_u8(first);
        if matches!(replacement_type, VpsUrspReplacementType::Reserved(_)) {
            return None;
        }
        let mut pos = 1usize;
        let mut tuples = Vec::new();
        while pos < data.len() {
            if pos + 4 > data.len() {
                return None;
            }
            let tuple_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;
            if tuple_len < 3 || pos + tuple_len > data.len() {
                return None;
            }
            let tuple_end = pos + tuple_len;
            let tuple_id = data[pos];
            pos += 1;
            let descriptor_entry_count = data[pos] as usize;
            pos += 1;
            if descriptor_entry_count == 0 {
                return None;
            }
            let mut network_descriptor = Vec::with_capacity(descriptor_entry_count);
            for _ in 0..descriptor_entry_count {
                let entry_type = *data.get(pos).filter(|_| pos < tuple_end)?;
                pos += 1;
                let entry = match entry_type {
                    0x01 => {
                        let plmn_count = *data.get(pos).filter(|_| pos < tuple_end)? as usize;
                        pos += 1;
                        let required_len = plmn_count.checked_mul(3)?;
                        if plmn_count == 0 || pos + required_len > tuple_end {
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
                        let mcc_count = *data.get(pos).filter(|_| pos < tuple_end)? as usize;
                        pos += 1;
                        if mcc_count == 0 {
                            return None;
                        }
                        let pair_count = mcc_count / 2;
                        let has_odd = !mcc_count.is_multiple_of(2);
                        let required_len = pair_count * 3 + if has_odd { 2 } else { 0 };
                        if pos + required_len > tuple_end {
                            return None;
                        }
                        let mut mccs = Vec::with_capacity(mcc_count);
                        for _ in 0..pair_count {
                            let (first_mcc, second_mcc) = decode_mcc_pair(&data[pos..pos + 3]);
                            if first_mcc.iter().any(|digit| *digit > 9)
                                || second_mcc.iter().any(|digit| *digit > 9)
                            {
                                return None;
                            }
                            pos += 3;
                            mccs.push(first_mcc);
                            mccs.push(second_mcc);
                        }
                        if has_odd {
                            // The high nibble after an odd MCC is spare.
                            let odd_mcc = decode_odd_mcc(&data[pos..pos + 2]);
                            if odd_mcc.iter().any(|digit| *digit > 9) {
                                return None;
                            }
                            pos += 2;
                            mccs.push(odd_mcc);
                        }
                        VpsUrspNetworkDescriptorEntry::OneOrMoreMccs(mccs)
                    }
                    0x03 => VpsUrspNetworkDescriptorEntry::AnyVplmn,
                    _ => return None,
                };
                network_descriptor.push(entry);
            }
            if !(tuple_end - pos).is_multiple_of(2) {
                return None;
            }
            let mut upscs = Vec::new();
            while pos < tuple_end {
                upscs.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
                pos += 2;
            }
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

    /// Construct a sender-valid value from typed contents.
    pub fn from_parsed(parsed: &VpsUrspConfigurationContents) -> Option<Self> {
        if matches!(parsed.replacement_type, VpsUrspReplacementType::Reserved(_)) {
            return None;
        }
        let mut value = vec![parsed.replacement_type.as_u8()];
        for tuple in &parsed.tuples {
            if tuple.network_descriptor.is_empty() {
                return None;
            }
            let mut body = vec![tuple.tuple_id];
            body.push(tuple.network_descriptor.len().try_into().ok()?);
            for entry in &tuple.network_descriptor {
                match entry {
                    VpsUrspNetworkDescriptorEntry::OneOrMoreVplmns(vplmns) => {
                        if vplmns.is_empty() {
                            return None;
                        }
                        body.push(0x01);
                        body.push(vplmns.len().try_into().ok()?);
                        for plmn in vplmns {
                            body.extend_from_slice(&plmn.try_to_tbcd()?);
                        }
                    }
                    VpsUrspNetworkDescriptorEntry::OneOrMoreMccs(mccs) => {
                        if mccs.is_empty() || mccs.iter().flatten().any(|digit| *digit > 9) {
                            return None;
                        }
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
                    VpsUrspNetworkDescriptorEntry::Unknown { .. } => return None,
                }
            }
            for upsc in &tuple.upscs {
                body.extend_from_slice(&upsc.to_be_bytes());
            }
            let body_len = u16::try_from(body.len()).ok()?;
            value.extend_from_slice(&body_len.to_be_bytes());
            value.extend_from_slice(&body);
        }
        (value.len() <= 65530).then(|| Self::new(value))
    }

    /// Whether the value has exact, sender-valid Annex D.6.8 contents.
    pub fn is_well_formed(&self) -> bool {
        self.parse().is_some_and(|parsed| {
            Self::from_parsed(&parsed).is_some_and(|rebuilt| rebuilt.value == self.value)
        })
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Multiple payload optional IE values.
pub enum MultiplePayloadOptionalIe {
    /// PDU session identifier.
    PduSessionId(NasPduSessionIdentity2),
    /// Additional information.
    AdditionalInformation(crate::NasAdditionalInformation),
    /// Five gmm cause.
    FiveGmmCause(NasFGmmCause),
    /// Back off timer value.
    BackOffTimerValue(NasGprsTimer3),
    /// Old PDU session identifier.
    OldPduSessionId(NasPduSessionIdentity2),
    /// Request type.
    RequestType(NasRequestType),
    /// S NSSAI.
    SNssai(NasSNssai),
    /// DNN.
    Dnn(NasDnn),
    /// Release assistance indication.
    ReleaseAssistanceIndication(NasReleaseAssistanceIndication),
    /// Ma PDU session information.
    MaPduSessionInformation(NasMaPduSessionInformation),
    /// Unknown.
    Unknown {
        /// Information-element identifier.
        iei: u8,
        /// Raw information-element contents.
        value: Vec<u8>,
    },
}

impl MultiplePayloadOptionalIe {
    /// Return IEI.
    pub fn iei(&self) -> u8 {
        match self {
            Self::PduSessionId(_) => 0x12,
            Self::AdditionalInformation(_) => 0x24,
            Self::FiveGmmCause(_) => 0x58,
            Self::BackOffTimerValue(_) => 0x37,
            Self::OldPduSessionId(_) => 0x59,
            Self::RequestType(_) => 0x80,
            Self::SNssai(_) => 0x22,
            Self::Dnn(_) => 0x25,
            Self::ReleaseAssistanceIndication(_) => 0xF0,
            Self::MaPduSessionInformation(_) => 0xA0,
            Self::Unknown { iei, .. } => *iei,
        }
    }

    /// Return the decoded value.
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

    /// Construct a value from raw.
    pub fn from_raw(iei: u8, value: Vec<u8>) -> Self {
        match iei {
            0x12 => Self::PduSessionId(NasPduSessionIdentity2::new(
                value.first().copied().unwrap_or(0),
            )),
            0x24 => Self::AdditionalInformation(crate::NasAdditionalInformation::new(value)),
            0x58 => Self::FiveGmmCause(NasFGmmCause::new(value.first().copied().unwrap_or(0))),
            0x37 => Self::BackOffTimerValue(NasGprsTimer3::new(value)),
            0x59 => Self::OldPduSessionId(NasPduSessionIdentity2::new(
                value.first().copied().unwrap_or(0),
            )),
            0x80 => Self::RequestType(NasRequestType::new(value.first().copied().unwrap_or(0))),
            0x22 => Self::SNssai(NasSNssai::new(value)),
            0x25 => Self::Dnn(NasDnn::new(value)),
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
/// UPDS event notification indicator type values.
pub enum UpdsEventNotificationIndicatorType {
    /// Srvcc handover cancelled IMS session re establishment required.
    SrvccHandoverCancelledImsSessionReEstablishmentRequired,
    /// Unknown.
    Unknown(u8),
}

impl UpdsEventNotificationIndicatorType {
    /// Decode a value from its wire octet.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x00 => Self::SrvccHandoverCancelledImsSessionReEstablishmentRequired,
            other => Self::Unknown(other),
        }
    }

    /// Return the wire octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::SrvccHandoverCancelledImsSessionReEstablishmentRequired => 0x00,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UPDS event notification indicator.
pub struct UpdsEventNotificationIndicator {
    /// Indicator type.
    pub indicator_type: UpdsEventNotificationIndicatorType,
    /// Raw information-element contents.
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UPDS event notification container.
pub struct UpdsEventNotificationContainer {
    /// Indicators.
    pub indicators: Vec<UpdsEventNotificationIndicator>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UPDS multiple payload entry.
pub struct UpdsMultiplePayloadEntry {
    /// Payload container type.
    pub payload_container_type: crate::NasPayloadContainerType,
    /// Optional ies.
    pub optional_ies: Vec<MultiplePayloadOptionalIe>,
    /// Encoded contents.
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of UPDS multiple payload container.
pub struct UpdsMultiplePayloadContainer {
    /// Entries.
    pub entries: Vec<UpdsMultiplePayloadEntry>,
}

impl UpdsEventNotificationContainer {
    /// Decode the value from its wire representation.
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

    /// Encode the value into its wire representation.
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
    /// Decode the value from its wire representation.
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

    /// Encode the value into its wire representation.
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
/// NAS UPDS message type values.
pub enum NasUpdsMessageType {
    /// Manage UE policy command.
    ManageUePolicyCommand,
    /// Manage UE policy complete.
    ManageUePolicyComplete,
    /// Manage UE policy command reject.
    ManageUePolicyCommandReject,
    /// UE state indication.
    UeStateIndication,
    /// UE policy provisioning request.
    UePolicyProvisioningRequest,
    /// UE policy provisioning reject.
    UePolicyProvisioningReject,
}

impl NasUpdsMessageType {
    /// Return the wire octet.
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

    /// Return semantics.
    pub fn semantics(self) -> UpdsMessageSemantics {
        match self {
            Self::ManageUePolicyCommand => UpdsMessageSemantics {
                initiator: UpdsProcedureInitiator::Network,
                role: UpdsProcedureRole::Command,
            },
            Self::ManageUePolicyComplete | Self::ManageUePolicyCommandReject => {
                UpdsMessageSemantics {
                    initiator: UpdsProcedureInitiator::Network,
                    role: UpdsProcedureRole::Response,
                }
            }
            Self::UeStateIndication | Self::UePolicyProvisioningRequest => UpdsMessageSemantics {
                initiator: UpdsProcedureInitiator::Ue,
                role: UpdsProcedureRole::Request,
            },
            Self::UePolicyProvisioningReject => UpdsMessageSemantics {
                initiator: UpdsProcedureInitiator::Ue,
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

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS manage UE policy command.
pub struct NasManageUePolicyCommand {
    /// UE policy section management list.
    pub ue_policy_section_management_list: NasUePolicySectionManagementList,
    /// UE policy network classmark.
    pub ue_policy_network_classmark: Option<NasUePolicyNetworkClassmark>,
    /// VPS URSP configuration.
    pub vps_ursp_configuration: Option<NasVpsUrspConfiguration>,
    /// Unrecognized and receiver-ignored information elements preserved verbatim.
    pub unknown_ies: Vec<UpdsUnknownIe>,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) optional_ie_order: Vec<OptionalIeOrder>,
}

impl PartialEq for NasManageUePolicyCommand {
    fn eq(&self, other: &Self) -> bool {
        self.ue_policy_section_management_list == other.ue_policy_section_management_list
            && self.ue_policy_network_classmark == other.ue_policy_network_classmark
            && self.vps_ursp_configuration == other.vps_ursp_configuration
            && self.unknown_ies == other.unknown_ies
    }
}

impl Eq for NasManageUePolicyCommand {}

impl NasManageUePolicyCommand {
    /// Construct a new value.
    pub fn new(ue_policy_section_management_list: NasUePolicySectionManagementList) -> Self {
        Self {
            ue_policy_section_management_list,
            ue_policy_network_classmark: None,
            vps_ursp_configuration: None,
            unknown_ies: Vec::new(),
            optional_ie_order: Vec::new(),
        }
    }

    /// Set UE policy network classmark and return the updated value.
    pub fn with_ue_policy_network_classmark(
        mut self,
        ue_policy_network_classmark: NasUePolicyNetworkClassmark,
    ) -> Self {
        self.ue_policy_network_classmark = Some(ue_policy_network_classmark);
        self
    }

    /// Set UE policy network classmark.
    pub fn set_ue_policy_network_classmark(
        &mut self,
        ue_policy_network_classmark: NasUePolicyNetworkClassmark,
    ) -> &mut Self {
        self.ue_policy_network_classmark = Some(ue_policy_network_classmark);
        self
    }

    /// Set VPS URSP configuration and return the updated value.
    pub fn with_vps_ursp_configuration(
        mut self,
        vps_ursp_configuration: NasVpsUrspConfiguration,
    ) -> Self {
        self.vps_ursp_configuration = Some(vps_ursp_configuration);
        self
    }

    /// Set VPS URSP configuration.
    pub fn set_vps_ursp_configuration(
        &mut self,
        vps_ursp_configuration: NasVpsUrspConfiguration,
    ) -> &mut Self {
        self.vps_ursp_configuration = Some(vps_ursp_configuration);
        self
    }

    fn encode_optional_ies(&self, buffer: &mut BytesMut) -> Result<()> {
        let mut plan = self.optional_ie_order.clone();
        if self.ue_policy_network_classmark.is_some()
            && !plan.iter().any(|order| {
                matches!(
                    order,
                    OptionalIeOrder::Known(IEI_UE_POLICY_NETWORK_CLASSMARK)
                )
            })
        {
            let at = plan
                .iter()
                .position(|order| {
                    matches!(order, OptionalIeOrder::Known(IEI_VPS_URSP_CONFIGURATION))
                })
                .unwrap_or(plan.len());
            plan.insert(at, OptionalIeOrder::Known(IEI_UE_POLICY_NETWORK_CLASSMARK));
        }
        if self.vps_ursp_configuration.is_some()
            && !plan
                .iter()
                .any(|order| matches!(order, OptionalIeOrder::Known(IEI_VPS_URSP_CONFIGURATION)))
        {
            plan.push(OptionalIeOrder::Known(IEI_VPS_URSP_CONFIGURATION));
        }
        for order in &plan {
            match *order {
                OptionalIeOrder::Known(IEI_UE_POLICY_NETWORK_CLASSMARK) => {
                    if let Some(ie) = &self.ue_policy_network_classmark {
                        encode_tlv(buffer, IEI_UE_POLICY_NETWORK_CLASSMARK, &ie.value)?;
                    }
                }
                OptionalIeOrder::Known(IEI_VPS_URSP_CONFIGURATION) => {
                    if let Some(ie) = &self.vps_ursp_configuration {
                        encode_tlve(buffer, IEI_VPS_URSP_CONFIGURATION, &ie.value)?;
                    }
                }
                OptionalIeOrder::Known(_) => {}
                OptionalIeOrder::Unknown(index) | OptionalIeOrder::Ignored(index, _) => {
                    if let Some(ie) = self.unknown_ies.get(index) {
                        encode_unknown_ie(buffer, ie);
                    }
                }
            }
        }
        encode_unordered_unknown_ies(buffer, &self.unknown_ies, &self.optional_ie_order);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS manage UE policy complete.
pub struct NasManageUePolicyComplete {
    /// Unrecognized information elements preserved for round-trip encoding.
    pub unknown_ies: Vec<UpdsUnknownIe>,
}

impl NasManageUePolicyComplete {
    /// Construct a new value.
    pub fn new() -> Self {
        Self {
            unknown_ies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS manage UE policy command reject.
pub struct NasManageUePolicyCommandReject {
    /// UE policy section management result.
    pub ue_policy_section_management_result: NasUePolicySectionManagementResult,
    /// Unrecognized information elements preserved for round-trip encoding.
    pub unknown_ies: Vec<UpdsUnknownIe>,
}

impl NasManageUePolicyCommandReject {
    /// Construct a new value.
    pub fn new(ue_policy_section_management_result: NasUePolicySectionManagementResult) -> Self {
        Self {
            ue_policy_section_management_result,
            unknown_ies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS UE state indication.
pub struct NasUeStateIndication {
    /// UPSI list.
    pub upsi_list: NasUpsiList,
    /// UE policy classmark.
    pub ue_policy_classmark: NasUePolicyClassmark,
    /// UE OS identifier.
    pub ue_os_id: Option<NasUeOsId>,
    /// Unrecognized and receiver-ignored information elements preserved verbatim.
    pub unknown_ies: Vec<UpdsUnknownIe>,
    #[cfg_attr(feature = "serde", serde(skip))]
    pub(crate) optional_ie_order: Vec<OptionalIeOrder>,
}

impl PartialEq for NasUeStateIndication {
    fn eq(&self, other: &Self) -> bool {
        self.upsi_list == other.upsi_list
            && self.ue_policy_classmark == other.ue_policy_classmark
            && self.ue_os_id == other.ue_os_id
            && self.unknown_ies == other.unknown_ies
    }
}

impl Eq for NasUeStateIndication {}

impl NasUeStateIndication {
    /// Construct a new value.
    pub fn new(upsi_list: NasUpsiList, ue_policy_classmark: NasUePolicyClassmark) -> Self {
        Self {
            upsi_list,
            ue_policy_classmark,
            ue_os_id: None,
            unknown_ies: Vec::new(),
            optional_ie_order: Vec::new(),
        }
    }

    /// Set UE OS identifier and return the updated value.
    pub fn with_ue_os_id(mut self, ue_os_id: NasUeOsId) -> Self {
        self.ue_os_id = Some(ue_os_id);
        self
    }

    /// Set UE OS identifier.
    pub fn set_ue_os_id(&mut self, ue_os_id: NasUeOsId) -> &mut Self {
        self.ue_os_id = Some(ue_os_id);
        self
    }

    fn encode_optional_ies(&self, buffer: &mut BytesMut) -> Result<()> {
        let mut plan = self.optional_ie_order.clone();
        if self.ue_os_id.is_some()
            && !plan
                .iter()
                .any(|order| matches!(order, OptionalIeOrder::Known(IEI_UE_OS_ID)))
        {
            plan.push(OptionalIeOrder::Known(IEI_UE_OS_ID));
        }
        for order in &plan {
            match *order {
                OptionalIeOrder::Known(IEI_UE_OS_ID) => {
                    if let Some(ie) = &self.ue_os_id {
                        encode_tlv(buffer, IEI_UE_OS_ID, &ie.value)?;
                    }
                }
                OptionalIeOrder::Known(_) => {}
                OptionalIeOrder::Unknown(index) | OptionalIeOrder::Ignored(index, _) => {
                    if let Some(ie) = self.unknown_ies.get(index) {
                        encode_unknown_ie(buffer, ie);
                    }
                }
            }
        }
        encode_unordered_unknown_ies(buffer, &self.unknown_ies, &self.optional_ie_order);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS UE policy provisioning request.
pub struct NasUePolicyProvisioningRequest {
    /// Opaque payload contents.
    pub payload: Vec<u8>,
}

impl NasUePolicyProvisioningRequest {
    /// Construct a new value.
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS UE policy provisioning reject.
pub struct NasUePolicyProvisioningReject {
    /// Opaque payload contents.
    pub payload: Vec<u8>,
}

impl NasUePolicyProvisioningReject {
    /// Construct a new value.
    pub fn new(payload: Vec<u8>) -> Self {
        Self { payload }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS unsupported UPDS message.
pub struct NasUnsupportedUpdsMessage {
    /// Message type.
    pub message_type: u8,
    /// Body.
    pub body: Vec<u8>,
}

impl NasUnsupportedUpdsMessage {
    /// Construct a new value.
    pub fn new(message_type: u8, body: Vec<u8>) -> Self {
        Self { message_type, body }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// NAS UPDS message values.
pub enum NasUpdsMessage {
    /// Manage UE policy command.
    ManageUePolicyCommand(NasManageUePolicyCommand),
    /// Manage UE policy complete.
    ManageUePolicyComplete(NasManageUePolicyComplete),
    /// Manage UE policy command reject.
    ManageUePolicyCommandReject(NasManageUePolicyCommandReject),
    /// UE state indication.
    UeStateIndication(NasUeStateIndication),
    /// UE policy provisioning request.
    UePolicyProvisioningRequest(NasUePolicyProvisioningRequest),
    /// UE policy provisioning reject.
    UePolicyProvisioningReject(NasUePolicyProvisioningReject),
    /// Unsupported.
    Unsupported(NasUnsupportedUpdsMessage),
}

impl NasUpdsMessage {
    /// Return message type.
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

    /// Return message type code.
    pub fn message_type_code(&self) -> u8 {
        match self {
            Self::Unsupported(message) => message.message_type,
            _ => self
                .message_type()
                .expect("all non-unsupported UPDS messages have a known message type")
                .as_u8(),
        }
    }

    /// Return semantics.
    pub fn semantics(&self) -> Option<UpdsMessageSemantics> {
        self.message_type().map(NasUpdsMessageType::semantics)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Typed representation of NAS UPDS envelope.
pub struct NasUpdsEnvelope {
    /// Procedure transaction identity.
    pub procedure_transaction_identity: u8,
    /// Decoded UPDS message.
    pub message: NasUpdsMessage,
}

impl NasUpdsEnvelope {
    /// Construct a new value.
    pub fn new(procedure_transaction_identity: u8, message: NasUpdsMessage) -> Self {
        Self {
            procedure_transaction_identity,
            message,
        }
    }

    /// Return new with PTI.
    pub fn new_with_pti(
        procedure_transaction_identity: NasUpdsProcedureTransactionIdentity,
        message: NasUpdsMessage,
    ) -> Self {
        Self::new(procedure_transaction_identity.raw(), message)
    }

    /// Return procedure transaction identity value.
    pub fn procedure_transaction_identity_value(&self) -> NasUpdsProcedureTransactionIdentity {
        NasUpdsProcedureTransactionIdentity::new_raw(self.procedure_transaction_identity)
    }

    /// Set procedure transaction identity.
    pub fn set_procedure_transaction_identity(
        &mut self,
        procedure_transaction_identity: NasUpdsProcedureTransactionIdentity,
    ) -> &mut Self {
        self.procedure_transaction_identity = procedure_transaction_identity.raw();
        self
    }

    /// Set procedure transaction identity and return the updated value.
    pub fn with_procedure_transaction_identity(
        mut self,
        procedure_transaction_identity: NasUpdsProcedureTransactionIdentity,
    ) -> Self {
        self.procedure_transaction_identity = procedure_transaction_identity.raw();
        self
    }

    /// Return message type.
    pub fn message_type(&self) -> Option<NasUpdsMessageType> {
        self.message.message_type()
    }

    /// Return message type code.
    pub fn message_type_code(&self) -> u8 {
        self.message.message_type_code()
    }

    /// Encode the value into its wire representation.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::new();
        self.encode(&mut buffer)?;
        Ok(buffer.to_vec())
    }

    /// Decode the value from its wire representation.
    pub fn decode_from_slice(data: &[u8]) -> Result<Self> {
        let mut buffer = Bytes::copy_from_slice(data);
        Self::decode(&mut buffer)
    }
}

impl Encode for NasUpdsEnvelope {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        let start = buffer.len();
        buffer.put_u8(self.procedure_transaction_identity);
        buffer.put_u8(self.message.message_type_code());

        match &self.message {
            NasUpdsMessage::ManageUePolicyCommand(message) => {
                encode_lve(buffer, &message.ue_policy_section_management_list.value)?;
                message.encode_optional_ies(buffer)?;
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
                message.encode_optional_ies(buffer)?;
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

        if buffer.len() - start > 65535 {
            buffer.truncate(start);
            return Err(NasError::EncodingError(
                "UPDS message exceeds 65535 octets".into(),
            ));
        }
        Ok(())
    }
}

impl Decode for NasUpdsEnvelope {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() > 65535 {
            return Err(NasError::DecodingError(
                "UPDS message exceeds 65535 octets".into(),
            ));
        }
        if buffer.remaining() < 2 {
            return Err(NasError::BufferTooShort);
        }

        let procedure_transaction_identity = buffer.get_u8();
        let message_type_code = buffer.get_u8();

        let message = match NasUpdsMessageType::try_from(message_type_code) {
            Ok(NasUpdsMessageType::ManageUePolicyCommand) => {
                let list = NasUePolicySectionManagementList::new(decode_lve(buffer)?);
                if list.try_sublists().is_none() {
                    return Err(NasError::InvalidMandatoryIe(
                        "UE policy section management list",
                    ));
                }
                let mut message = NasManageUePolicyCommand::new(list);
                let mut furthest_rank = 0usize;
                while buffer.has_remaining() {
                    match buffer[0] {
                        IEI_UE_POLICY_NETWORK_CLASSMARK => {
                            let mut probe = buffer.clone();
                            let contents =
                                decode_optional_tlv(&mut probe, IEI_UE_POLICY_NETWORK_CLASSMARK);
                            let exact_length = contents
                                .as_ref()
                                .map(|_| buffer.remaining() - probe.remaining());
                            let reason = if message.ue_policy_network_classmark.is_some() {
                                Some(IgnoredIeReason::Repeated)
                            } else if furthest_rank > 1 {
                                Some(IgnoredIeReason::OutOfSequence)
                            } else if contents.as_ref().is_none_or(Vec::is_empty) {
                                Some(IgnoredIeReason::Malformed)
                            } else {
                                None
                            };
                            if let Some(reason) = reason {
                                preserve_ignored_ie(
                                    buffer,
                                    exact_length,
                                    &mut message.unknown_ies,
                                    &mut message.optional_ie_order,
                                    reason,
                                );
                            } else {
                                *buffer = probe;
                                message.ue_policy_network_classmark =
                                    contents.map(NasUePolicyNetworkClassmark::new);
                                message
                                    .optional_ie_order
                                    .push(OptionalIeOrder::Known(IEI_UE_POLICY_NETWORK_CLASSMARK));
                                furthest_rank = 1;
                            }
                        }
                        IEI_VPS_URSP_CONFIGURATION => {
                            let mut probe = buffer.clone();
                            let contents =
                                decode_optional_tlve(&mut probe, IEI_VPS_URSP_CONFIGURATION);
                            let exact_length = contents
                                .as_ref()
                                .map(|_| buffer.remaining() - probe.remaining());
                            let parsed = contents
                                .as_ref()
                                .map(|value| NasVpsUrspConfiguration::new(value.clone()));
                            let reason = if message.vps_ursp_configuration.is_some() {
                                Some(IgnoredIeReason::Repeated)
                            } else if parsed.as_ref().is_none_or(|value| value.parse().is_none()) {
                                Some(IgnoredIeReason::Malformed)
                            } else {
                                None
                            };
                            if let Some(reason) = reason {
                                preserve_ignored_ie(
                                    buffer,
                                    exact_length,
                                    &mut message.unknown_ies,
                                    &mut message.optional_ie_order,
                                    reason,
                                );
                            } else {
                                *buffer = probe;
                                message.vps_ursp_configuration = parsed;
                                message
                                    .optional_ie_order
                                    .push(OptionalIeOrder::Known(IEI_VPS_URSP_CONFIGURATION));
                                furthest_rank = 2;
                            }
                        }
                        _ => preserve_unknown_ie(
                            buffer,
                            &mut message.unknown_ies,
                            &mut message.optional_ie_order,
                        ),
                    }
                }
                NasUpdsMessage::ManageUePolicyCommand(message)
            }
            Ok(NasUpdsMessageType::ManageUePolicyComplete) => {
                let mut message = NasManageUePolicyComplete::new();
                while buffer.has_remaining() {
                    message.unknown_ies.push(consume_raw_ie(buffer, None));
                }
                NasUpdsMessage::ManageUePolicyComplete(message)
            }
            Ok(NasUpdsMessageType::ManageUePolicyCommandReject) => {
                let result = NasUePolicySectionManagementResult::new(decode_lve(buffer)?);
                if result.try_subresults().is_none() {
                    return Err(NasError::InvalidMandatoryIe(
                        "UE policy section management result",
                    ));
                }
                let mut message = NasManageUePolicyCommandReject::new(result);
                while buffer.has_remaining() {
                    message.unknown_ies.push(consume_raw_ie(buffer, None));
                }
                NasUpdsMessage::ManageUePolicyCommandReject(message)
            }
            Ok(NasUpdsMessageType::UeStateIndication) => {
                let upsi_list = NasUpsiList::new(decode_lve(buffer)?);
                if upsi_list.try_sublists().is_none() {
                    return Err(NasError::InvalidMandatoryIe("UPSI list"));
                }
                let ue_policy_classmark = NasUePolicyClassmark::new(decode_lv(buffer)?);
                if ue_policy_classmark.value.is_empty() {
                    return Err(NasError::InvalidMandatoryIe("UE policy classmark"));
                }
                let mut message = NasUeStateIndication::new(upsi_list, ue_policy_classmark);
                while buffer.has_remaining() {
                    match buffer[0] {
                        IEI_UE_OS_ID => {
                            let mut probe = buffer.clone();
                            let contents = decode_optional_tlv(&mut probe, IEI_UE_OS_ID);
                            let exact_length = contents
                                .as_ref()
                                .map(|_| buffer.remaining() - probe.remaining());
                            let reason = if message.ue_os_id.is_some() {
                                Some(IgnoredIeReason::Repeated)
                            } else if contents.as_ref().is_none_or(|value| value.len() < 16) {
                                Some(IgnoredIeReason::Malformed)
                            } else {
                                None
                            };
                            if let Some(reason) = reason {
                                preserve_ignored_ie(
                                    buffer,
                                    exact_length,
                                    &mut message.unknown_ies,
                                    &mut message.optional_ie_order,
                                    reason,
                                );
                            } else {
                                *buffer = probe;
                                message.ue_os_id = contents.map(NasUeOsId::new);
                                message
                                    .optional_ie_order
                                    .push(OptionalIeOrder::Known(IEI_UE_OS_ID));
                            }
                        }
                        _ => preserve_unknown_ie(
                            buffer,
                            &mut message.unknown_ies,
                            &mut message.optional_ie_order,
                        ),
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

fn encode_unknown_ie(buffer: &mut BytesMut, ie: &UpdsUnknownIe) {
    buffer.put_u8(ie.iei);
    buffer.put_slice(&ie.data);
}

fn encode_unknown_ies(buffer: &mut BytesMut, unknown_ies: &[UpdsUnknownIe]) -> Result<()> {
    for ie in unknown_ies {
        encode_unknown_ie(buffer, ie);
    }
    Ok(())
}

fn encode_unordered_unknown_ies(
    buffer: &mut BytesMut,
    unknown_ies: &[UpdsUnknownIe],
    order: &[OptionalIeOrder],
) {
    for (index, ie) in unknown_ies.iter().enumerate() {
        if !order.iter().any(|entry| {
            matches!(
                entry,
                OptionalIeOrder::Unknown(known_index)
                    | OptionalIeOrder::Ignored(known_index, _)
                    if *known_index == index
            )
        }) {
            encode_unknown_ie(buffer, ie);
        }
    }
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
        Err(_) => None,
    }
}

fn decode_optional_tlve(buffer: &mut Bytes, expected_iei: u8) -> Option<Vec<u8>> {
    let mut lookahead = buffer.clone();
    match decode_tlve(&mut lookahead, expected_iei) {
        Ok(contents) => {
            *buffer = lookahead;
            Some(contents)
        }
        Err(_) => None,
    }
}

fn consume_raw_ie(buffer: &mut Bytes, exact_length: Option<usize>) -> UpdsUnknownIe {
    let length = exact_length
        .or_else(|| generic_ie_length(buffer, 0x70).ok())
        .unwrap_or_else(|| buffer.remaining());
    let raw = buffer.split_to(length);
    UpdsUnknownIe {
        iei: raw[0],
        data: raw[1..].to_vec(),
    }
}

fn preserve_unknown_ie(
    buffer: &mut Bytes,
    unknown_ies: &mut Vec<UpdsUnknownIe>,
    order: &mut Vec<OptionalIeOrder>,
) {
    order.push(OptionalIeOrder::Unknown(unknown_ies.len()));
    unknown_ies.push(consume_raw_ie(buffer, None));
}

fn preserve_ignored_ie(
    buffer: &mut Bytes,
    exact_length: Option<usize>,
    unknown_ies: &mut Vec<UpdsUnknownIe>,
    order: &mut Vec<OptionalIeOrder>,
    reason: IgnoredIeReason,
) {
    order.push(OptionalIeOrder::Ignored(unknown_ies.len(), reason));
    unknown_ies.push(consume_raw_ie(buffer, exact_length));
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
    use crate::{NasPayloadContainer, Validate};

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
            0x80, 0x01, 0x00, 0x09, 0x00, 0x07, 0x02, 0xF8, 0x39, 0x00, 0x02, 0x00, 0x01, 0x42,
            0x01, 0x00, 0x42, 0x01, 0x01,
        ];
        let decoded = NasUpdsEnvelope::decode_from_slice(&encoded).unwrap();
        let NasUpdsMessage::ManageUePolicyCommand(message) = &decoded.message else {
            panic!("expected MANAGE UE POLICY COMMAND");
        };
        assert_eq!(
            message
                .ue_policy_network_classmark
                .as_ref()
                .unwrap()
                .handling(),
            NonSubscribedSnpnUrspHandling::Allow
        );
        assert_eq!(message.unknown_ies.len(), 1);
        assert_eq!(decoded.encode_to_vec().unwrap(), encoded);
    }

    #[test]
    fn test_upds_malformed_optional_ie_is_ignored() {
        let encoded = vec![0x01, 0x04, 0x00, 0x00, 0x01, 0x00, 0x41, 0x01, 0xFF];
        let decoded = NasUpdsEnvelope::decode_from_slice(&encoded).unwrap();
        let NasUpdsMessage::UeStateIndication(message) = &decoded.message else {
            panic!("expected UE STATE INDICATION");
        };
        assert!(message.ue_os_id.is_none());
        assert_eq!(message.unknown_ies.len(), 1);
        assert_eq!(decoded.encode_to_vec().unwrap(), encoded);
    }

    #[test]
    fn annex_d_pti_echo_ranges_accept_valid_responses_and_triggered_command() {
        for wire in [
            vec![0x80, 0x02],
            vec![0x01, 0x06, 0xaa],
            vec![
                0x01, 0x01, 0x00, 0x09, 0x00, 0x07, 0x02, 0xf8, 0x39, 0x00, 0x02, 0x01, 0xaa,
            ],
        ] {
            let message = NasUpdsEnvelope::decode_from_slice(&wire).unwrap();
            assert!(
                message.validate().is_empty(),
                "{wire:02x?}: {:?}",
                message.validate()
            );
            assert_eq!(message.encode_to_vec().unwrap(), wire);
        }
    }

    #[test]
    fn annex_d_short_mandatory_structures_are_invalid_mandatory_ies() {
        for wire in [
            &[0x80, 0x01, 0x00, 0x01, 0xff][..],
            &[0x01, 0x03, 0x00, 0x01, 0xff][..],
        ] {
            assert!(matches!(
                NasUpdsEnvelope::decode_from_slice(wire),
                Err(NasError::InvalidMandatoryIe(_))
            ));
        }
    }

    #[test]
    fn annex_d_unknown_type_one_ie_preserves_following_known_ie() {
        let wire = [
            0x80, 0x01, 0x00, 0x09, 0x00, 0x07, 0x02, 0xf8, 0x39, 0x00, 0x02, 0x01, 0xaa, 0xf0,
            0x42, 0x01, 0x00,
        ];
        let decoded = NasUpdsEnvelope::decode_from_slice(&wire).unwrap();
        let NasUpdsMessage::ManageUePolicyCommand(command) = &decoded.message else {
            panic!("expected MANAGE UE POLICY COMMAND");
        };
        assert_eq!(
            command.unknown_ies,
            [UpdsUnknownIe {
                iei: 0xf0,
                data: vec![]
            }]
        );
        assert_eq!(
            command.ue_policy_network_classmark.as_ref().unwrap().value,
            [0x00]
        );
        assert_eq!(decoded.encode_to_vec().unwrap(), wire);
    }

    #[test]
    fn annex_d_empty_upsi_and_extended_classmark_are_sender_valid() {
        let wire = [0x01, 0x04, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];
        let message = NasUpdsEnvelope::decode_from_slice(&wire).unwrap();
        assert!(message.validate().is_empty(), "{:?}", message.validate());
        assert_eq!(message.encode_to_vec().unwrap(), wire);
    }

    #[test]
    fn annex_d_result_cause_uses_receiver_fallback() {
        let result =
            NasUePolicySectionManagementResult::new(hex::decode("0102f8390001000100").unwrap());
        let parsed = result.try_subresults().unwrap();
        assert_eq!(
            parsed[0].results[0].cause,
            UePolicySectionManagementResultCause::ProtocolErrorUnspecified
        );
        assert!(!result.is_well_formed());
    }

    #[test]
    fn annex_d_out_of_sequence_known_ie_is_absent_and_preserved() {
        let wire = hex::decode("8001000d000b02f83900060102000201aa70000101420100").unwrap();
        let decoded = NasUpdsEnvelope::decode_from_slice(&wire).unwrap();
        let NasUpdsMessage::ManageUePolicyCommand(command) = &decoded.message else {
            panic!("expected MANAGE UE POLICY COMMAND");
        };
        assert!(command.vps_ursp_configuration.is_some());
        assert!(command.ue_policy_network_classmark.is_none());
        assert_eq!(command.unknown_ies.len(), 1);
        assert_eq!(decoded.encode_to_vec().unwrap(), wire);
    }

    #[test]
    fn annex_d_vps_ursp_rejects_reserved_and_trailing_values() {
        for value in [vec![0x00, 0xaa], vec![0x03]] {
            let configuration = NasVpsUrspConfiguration::new(value);
            assert!(configuration.parse().is_none());
            assert!(!configuration.is_well_formed());
        }
        // Spare bit 8 is ignored on receipt and reported to the sender.
        let spare = NasVpsUrspConfiguration::new(vec![0x81]);
        assert!(spare.parse().is_some());
        assert!(!spare.is_well_formed());
        let empty_full_list = NasVpsUrspConfiguration::from_parsed(&VpsUrspConfigurationContents {
            replacement_type: VpsUrspReplacementType::FullListOfTuples,
            tuples: Vec::new(),
        })
        .unwrap();
        assert_eq!(empty_full_list.value, [0x02]);
        assert!(empty_full_list.is_well_formed());
    }

    #[test]
    fn annex_d_classmark_spares_and_message_length_are_sender_checked() {
        let spare = NasUpdsEnvelope::decode_from_slice(
            &hex::decode("8001000d000b02f83900060102000201aa420102").unwrap(),
        )
        .unwrap();
        assert!(
            spare
                .validate()
                .iter()
                .any(|finding| { finding.field == "UE policy network classmark" })
        );

        let too_long = NasUpdsEnvelope::new(
            0x01,
            NasUpdsMessage::UePolicyProvisioningRequest(NasUePolicyProvisioningRequest::new(
                vec![0; 65534],
            )),
        );
        assert!(too_long.encode_to_vec().is_err());
        assert!(
            too_long
                .validate()
                .iter()
                .any(|finding| { finding.field == "payload" })
        );
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
    fn test_vps_ursp_configuration_ignores_spare_bits() {
        // TS 24.501 Figures D.6.8.1 and D.6.8.9: bits 8 to 3 of octet 4, and
        // bits 8 to 5 after the last digit of an odd MCC count, are spare.
        let envelope = NasUpdsEnvelope::decode_from_slice(
            &hex::decode("80010009000702f83900020001700006810003010103").unwrap(),
        )
        .unwrap();
        let NasUpdsMessage::ManageUePolicyCommand(command) = envelope.message else {
            panic!("expected MANAGE UE POLICY COMMAND");
        };
        let configuration = command.vps_ursp_configuration.unwrap();
        assert!(configuration.parse().is_some());
        assert!(!configuration.is_well_formed());

        let odd_mcc = NasVpsUrspConfiguration::new(
            hex::decode("0100060101020102 18".replace(' ', "")).unwrap(),
        );
        let parsed = odd_mcc.parse().unwrap();
        assert_eq!(
            parsed.tuples[0].network_descriptor,
            [VpsUrspNetworkDescriptorEntry::OneOrMoreMccs(vec![[
                2, 0, 8
            ]])]
        );
        assert!(!odd_mcc.is_well_formed());
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

    #[test]
    fn test_multiple_payload_optional_ies_use_hexadecimal_ieis() {
        // TS 24.501 Table 9.11.3.39.1 lists the optional IEIs 12, 24, 58,
        // 37, 59, 80, 22, 25, F0 and A0, the hexadecimal IEIs of the UL and
        // DL NAS TRANSPORT message tables.
        let optional_ies = vec![
            MultiplePayloadOptionalIe::PduSessionId(NasPduSessionIdentity2::new(5)),
            MultiplePayloadOptionalIe::AdditionalInformation(crate::NasAdditionalInformation::new(
                vec![0x01],
            )),
            MultiplePayloadOptionalIe::FiveGmmCause(NasFGmmCause::new(0x5a)),
            MultiplePayloadOptionalIe::BackOffTimerValue(NasGprsTimer3::new(vec![0x21])),
            MultiplePayloadOptionalIe::OldPduSessionId(NasPduSessionIdentity2::new(6)),
            MultiplePayloadOptionalIe::RequestType(NasRequestType::new(0x01)),
            MultiplePayloadOptionalIe::SNssai(NasSNssai::new(vec![0x01])),
            MultiplePayloadOptionalIe::Dnn(NasDnn::new(vec![0x03, b'i', b'm', b's'])),
            MultiplePayloadOptionalIe::ReleaseAssistanceIndication(
                NasReleaseAssistanceIndication::new(0x01),
            ),
            MultiplePayloadOptionalIe::MaPduSessionInformation(NasMaPduSessionInformation::new(
                0x01,
            )),
        ];
        assert_eq!(
            optional_ies
                .iter()
                .map(MultiplePayloadOptionalIe::iei)
                .collect::<Vec<_>>(),
            [0x12, 0x24, 0x58, 0x37, 0x59, 0x80, 0x22, 0x25, 0xf0, 0xa0]
        );
        for optional_ie in &optional_ies {
            assert_eq!(
                &MultiplePayloadOptionalIe::from_raw(optional_ie.iei(), optional_ie.value()),
                optional_ie
            );
        }

        // One N1 SM entry with a DNN optional IE "ims".
        let wire = hex::decode("01000b1125040369 6d732e0101c1".replace(' ', "")).unwrap();
        let decoded = UpdsMultiplePayloadContainer::decode_from_slice(&wire).unwrap();
        assert_eq!(
            decoded.entries[0].optional_ies,
            [MultiplePayloadOptionalIe::Dnn(NasDnn::new(vec![
                0x03, b'i', b'm', b's'
            ]))]
        );
    }
}
