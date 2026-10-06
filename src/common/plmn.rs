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

//! PLMN identity shared by 5GS and EPS NAS information elements.

use core::fmt;

/// PLMN as raw TBCD-encoded 3 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PlmnId {
    /// MCC digits.
    pub mcc: [u8; 3],
    /// MNC digits; the third is 0x0F for a two-digit MNC.
    pub mnc: [u8; 3],
}

impl PlmnId {
    /// Filler value for 2-digit MNC (3GPP TBCD convention: 0x0F in `mnc[2]`).
    pub const MNC_2DIGIT_FILLER: u8 = 0x0F;

    /// Decode PLMN from 3 TBCD bytes.
    ///
    /// Returns `None` if the input is too short or any MCC digit exceeds 9.
    /// MNC digits are validated the same way, except mnc\[2\] which may be
    /// 0x0F (the 2-digit MNC filler).
    pub fn from_tbcd(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        let mcc = [bytes[0] & 0x0F, (bytes[0] >> 4) & 0x0F, bytes[1] & 0x0F];
        let mnc = [
            bytes[2] & 0x0F,
            (bytes[2] >> 4) & 0x0F,
            (bytes[1] >> 4) & 0x0F, // 0x0F means 2-digit MNC
        ];
        // Validate MCC digits (must be 0-9)
        if mcc[0] > 9 || mcc[1] > 9 || mcc[2] > 9 {
            return None;
        }
        // Validate MNC digits (0-9, except mnc[2] which may be 0x0F for 2-digit MNC)
        if mnc[0] > 9 || mnc[1] > 9 || (mnc[2] > 9 && mnc[2] != Self::MNC_2DIGIT_FILLER) {
            return None;
        }
        Some(PlmnId { mcc, mnc })
    }

    /// Whether all digits are valid for an ordinary PLMN identity.
    pub fn is_valid(&self) -> bool {
        self.mcc.iter().all(|digit| *digit <= 9)
            && self.mnc[0] <= 9
            && self.mnc[1] <= 9
            && (self.mnc[2] <= 9 || self.mnc[2] == Self::MNC_2DIGIT_FILLER)
    }

    /// Encode a validated PLMN to three TBCD octets.
    pub fn try_to_tbcd(&self) -> Option<[u8; 3]> {
        self.is_valid().then(|| {
            [
                (self.mcc[1] << 4) | self.mcc[0],
                (self.mnc[2] << 4) | self.mcc[2],
                (self.mnc[1] << 4) | self.mnc[0],
            ]
        })
    }

    /// Encode PLMN to three TBCD octets.
    ///
    /// # Panics
    ///
    /// Panics if a public digit field is outside its specified BCD domain.
    /// Use [`Self::try_to_tbcd`] when constructing from untrusted fields.
    pub fn to_tbcd(&self) -> [u8; 3] {
        self.try_to_tbcd().expect("PLMN digits must be valid BCD")
    }

    /// MCC as a numeric string (e.g., "208").
    pub fn mcc_string(&self) -> String {
        format!("{}{}{}", self.mcc[0], self.mcc[1], self.mcc[2])
    }

    /// MNC as a numeric string (e.g., "93" or "093").
    pub fn mnc_string(&self) -> String {
        if self.mnc[2] == 0x0F {
            format!("{}{}", self.mnc[0], self.mnc[1])
        } else {
            format!("{}{}{}", self.mnc[0], self.mnc[1], self.mnc[2])
        }
    }
}

impl fmt::Display for PlmnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.mcc_string(), self.mnc_string())
    }
}

/// Add accessors for a list of 3-octet PLMN identities holding `$min` to
/// `$max` entries. Receivers read at most `$max` complete entries and skip
/// entries that do not decode (TS 24.007 §11.4.2).
macro_rules! plmn_sequence_ie {
    ($name:ident, $min:literal, $max:literal) => {
        impl $name {
            /// PLMN identities in wire order.
            pub fn plmns(&self) -> Vec<PlmnId> {
                self.value
                    .chunks_exact(3)
                    .take($max)
                    .filter_map(PlmnId::from_tbcd)
                    .collect()
            }

            /// Build from PLMN identities; `None` for a count outside the
            /// range or an identity that does not round-trip.
            pub fn from_plmns(plmns: &[PlmnId]) -> Option<Self> {
                if !($min..=$max).contains(&plmns.len()) {
                    return None;
                }
                let mut value = Vec::with_capacity(plmns.len() * 3);
                for plmn in plmns {
                    value.extend_from_slice(&plmn.try_to_tbcd()?);
                }
                Some(Self::new(value))
            }

            /// Sender check: a whole number of decodable entries within the
            /// count range.
            pub fn is_well_formed(&self) -> bool {
                self.value.len().is_multiple_of(3)
                    && ($min..=$max).contains(&(self.value.len() / 3))
                    && self
                        .value
                        .chunks_exact(3)
                        .all(|plmn| PlmnId::from_tbcd(plmn).is_some())
            }
        }
    };
}

pub(crate) use plmn_sequence_ie;
