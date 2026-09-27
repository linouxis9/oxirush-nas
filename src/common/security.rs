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

//! Shared NAS security direction and sequence number handling.

/// NAS transmission direction used by 5GS and EPS security contexts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum Direction {
    /// Uplink: UE to network.
    Uplink = 0,
    /// Downlink: network to UE.
    Downlink = 1,
}

impl Direction {
    /// Raw direction bit for integrity and ciphering algorithms.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Estimate the full COUNT from a stored counter and received sequence number.
pub(crate) fn estimate_count(stored_count: u32, sequence_number: u8) -> u32 {
    estimate_count_bits(stored_count, sequence_number, 8)
}

/// Estimate COUNT using an on-wire sequence number of 5 or 8 bits.
pub(crate) fn estimate_count_bits(stored_count: u32, sequence_number: u8, bits: u32) -> u32 {
    let modulus = 1u32 << bits;
    let mask = modulus - 1;
    let stored_sn = stored_count & mask;
    let received_sn = u32::from(sequence_number) & mask;
    let base = stored_count & !mask;
    if stored_sn > received_sn && stored_sn - received_sn > modulus / 2 {
        base.wrapping_add(modulus) | received_sn
    } else if received_sn > stored_sn && received_sn - stored_sn > modulus / 2 {
        base.saturating_sub(modulus) | received_sn
    } else {
        base | received_sn
    }
}
