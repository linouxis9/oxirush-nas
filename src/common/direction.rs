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

//! Shared NAS transmission direction.

/// NAS transmission direction, used by the security contexts and by decoders
/// whose message forms depend on the sending side.
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
