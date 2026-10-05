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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UnknownIe {
    /// The raw IEI byte as it appeared on the wire.
    pub iei: u8,
    /// The raw IE data (everything after the IEI byte, including any length field).
    pub data: Vec<u8>,
}

impl UnknownIe {
    /// Whether the IEI marks an unknown IE as "comprehension required".
    ///
    /// TS 24.007 §11.2.5 applies this to type 4 IEIs with bits 8 to 5 set to
    /// zero and to type 6 IEIs 0x7E and 0x7F. TS 24.301 and TS 24.501 §7.5.1
    /// treat such an unknown IE like a mandatory IE error (cause #96).
    pub fn is_comprehension_required(&self) -> bool {
        self.iei <= 0x0f || matches!(self.iei, 0x7e | 0x7f)
    }
}

/// Position of an optional IE in a decoded message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum OptionalIeOrder {
    Known(u8),
    Unknown(usize),
    Ignored(usize, IgnoredIeReason),
}

/// Why a known optional IE was ignored by the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum IgnoredIeReason {
    Malformed,
    Repeated,
    OutOfSequence,
}

/// Total length of the IE at the start of `buffer`, from the IEI alone, by
/// the TS 24.007 §11.2.4 format rule: bit 8 set is a one-octet type 1 or
/// type 2 IE, IEIs from `tlve_start` to 0x7F are type 6 (TLV-E), and the
/// others are type 4 (TLV).
pub(crate) fn generic_ie_length(buffer: &[u8], tlve_start: u8) -> crate::common::Result<usize> {
    let (&iei, rest) = buffer
        .split_first()
        .ok_or(crate::common::NasError::BufferTooShort)?;
    let length = if iei >= 0x80 {
        1
    } else if (tlve_start..=0x7f).contains(&iei) {
        let [high, low] = *rest
            .first_chunk::<2>()
            .ok_or(crate::common::NasError::BufferTooShort)?;
        3 + usize::from(u16::from_be_bytes([high, low]))
    } else {
        2 + usize::from(
            *rest
                .first()
                .ok_or(crate::common::NasError::BufferTooShort)?,
        )
    };
    if buffer.len() < length {
        return Err(crate::common::NasError::BufferTooShort);
    }
    Ok(length)
}
