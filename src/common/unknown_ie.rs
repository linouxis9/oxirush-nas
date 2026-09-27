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

//! Raw information elements preserved while decoding.

/// An IE that was not recognized during decoding.
///
/// Unknown IEs are preserved during decode and re-emitted during encode,
/// enabling pass-through of IEs from newer spec versions or vendor extensions.
#[derive(Debug, Clone, PartialEq)]
pub struct UnknownIe {
    /// The raw IEI byte as it appeared on the wire.
    pub iei: u8,
    /// The raw IE data (everything after the IEI byte, including any length field).
    pub data: Vec<u8>,
}

/// Position of an optional IE in a decoded message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionalIeOrder {
    Known(u8),
    Unknown(usize),
}
