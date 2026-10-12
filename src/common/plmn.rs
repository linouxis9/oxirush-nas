/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

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

use crate::prelude::*;
use core::fmt;
use core::str::FromStr;

/// A PLMN identity: a mobile country code (MCC) of three decimal digits and
/// a mobile network code (MNC) of two or three (TS 23.003 §2.2).
///
/// Its digits are valid: a `PlmnId` is made from digits that are checked,
/// and always encodes.
///
/// ```
/// use oxirush_nas::common::PlmnId;
///
/// let plmn = PlmnId::new("208", "93").unwrap();
/// assert_eq!(plmn.to_tbcd(), [0x02, 0xf8, 0x39]);
/// assert_eq!(PlmnId::from_tbcd(&[0x02, 0xf8, 0x39]), Some(plmn));
/// assert_eq!(plmn.to_string(), "208-93");
/// assert_eq!("208-93".parse(), Ok(plmn));
/// assert_eq!(PlmnId::new("310", "410").unwrap().to_tbcd(), [0x13, 0x00, 0x14]);
/// assert_eq!(PlmnId::new("20", "93"), None);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(try_from = "PlmnDigits"))]
pub struct PlmnId {
    /// MCC digits.
    mcc: [u8; 3],
    /// MNC digits; the third is 0x0F for a two-digit MNC.
    mnc: [u8; 3],
}

/// The serde form of a [`PlmnId`], whose digits are not checked yet.
#[cfg(feature = "serde")]
#[derive(serde::Deserialize)]
#[serde(rename = "PlmnId")]
struct PlmnDigits {
    mcc: [u8; 3],
    mnc: [u8; 3],
}

#[cfg(feature = "serde")]
impl TryFrom<PlmnDigits> for PlmnId {
    type Error = &'static str;

    fn try_from(digits: PlmnDigits) -> Result<Self, Self::Error> {
        Self::from_digits(digits.mcc, digits.mnc).ok_or("the digits of a PLMN identity are 0 to 9")
    }
}

impl PlmnId {
    /// Filler value for 2-digit MNC (3GPP TBCD convention: 0x0F in `mnc[2]`).
    pub const MNC_2DIGIT_FILLER: u8 = 0x0F;

    /// The PLMN identity of an MCC of three decimal digits and an MNC of two
    /// or three, as text: `PlmnId::new("208", "93")`. `None` for anything
    /// else.
    pub fn new(mcc: &str, mnc: &str) -> Option<Self> {
        let digit = |text: &str, at: usize| text.as_bytes().get(at).map(|digit| digit - b'0');
        if mcc.len() != 3 || !(2..=3).contains(&mnc.len()) {
            return None;
        }
        let all_digits = |text: &str| text.bytes().all(|digit| digit.is_ascii_digit());
        if !all_digits(mcc) || !all_digits(mnc) {
            return None;
        }
        Self::from_digits(
            [digit(mcc, 0)?, digit(mcc, 1)?, digit(mcc, 2)?],
            [
                digit(mnc, 0)?,
                digit(mnc, 1)?,
                digit(mnc, 2).unwrap_or(Self::MNC_2DIGIT_FILLER),
            ],
        )
    }

    /// The PLMN identity of the digits of an MCC and of an MNC, each digit a
    /// number from 0 to 9; the third digit of a two-digit MNC is
    /// [`Self::MNC_2DIGIT_FILLER`]. `None` for anything else.
    pub fn from_digits(mcc: [u8; 3], mnc: [u8; 3]) -> Option<Self> {
        let valid = mcc.iter().all(|digit| *digit <= 9)
            && mnc[0] <= 9
            && mnc[1] <= 9
            && (mnc[2] <= 9 || mnc[2] == Self::MNC_2DIGIT_FILLER);
        valid.then_some(Self { mcc, mnc })
    }

    /// Decode PLMN from 3 TBCD bytes.
    ///
    /// Returns `None` if the input is too short or any MCC digit exceeds 9.
    /// MNC digits are validated the same way, except mnc\[2\] which may be
    /// 0x0F (the 2-digit MNC filler).
    pub fn from_tbcd(bytes: &[u8]) -> Option<Self> {
        let [first, second, third, ..] = *bytes else {
            return None;
        };
        Self::from_digits(
            [first & 0x0F, first >> 4, second & 0x0F],
            // The third digit of the MNC is in the second octet: 0x0F for a
            // two-digit MNC.
            [third & 0x0F, third >> 4, second >> 4],
        )
    }

    /// The three TBCD octets of the PLMN identity, as a NAS IE has them
    /// (TS 24.008 §10.5.1.3).
    pub fn to_tbcd(&self) -> [u8; 3] {
        [
            (self.mcc[1] << 4) | self.mcc[0],
            (self.mnc[2] << 4) | self.mcc[2],
            (self.mnc[1] << 4) | self.mnc[0],
        ]
    }

    /// The three digits of the MCC, each a number from 0 to 9.
    pub fn mcc(&self) -> [u8; 3] {
        self.mcc
    }

    /// The digits of the MNC, each a number from 0 to 9; the third is
    /// [`Self::MNC_2DIGIT_FILLER`] for a two-digit MNC.
    pub fn mnc(&self) -> [u8; 3] {
        self.mnc
    }

    /// MCC as a numeric string (e.g., "208").
    pub fn mcc_string(&self) -> String {
        format!("{}{}{}", self.mcc[0], self.mcc[1], self.mcc[2])
    }

    /// MNC as a numeric string (e.g., "93" or "093").
    pub fn mnc_string(&self) -> String {
        if self.mnc[2] == Self::MNC_2DIGIT_FILLER {
            format!("{}{}", self.mnc[0], self.mnc[1])
        } else {
            format!("{}{}{}", self.mnc[0], self.mnc[1], self.mnc[2])
        }
    }
}

/// A PLMN identity is written "MCC-MNC": `208-93`, `310-410`.
impl fmt::Display for PlmnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.mcc_string(), self.mnc_string())
    }
}

/// What is not a PLMN identity written "MCC-MNC".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPlmnId;

impl fmt::Display for InvalidPlmnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "not a PLMN identity like \"208-93\": three digits, a hyphen, two or three digits",
        )
    }
}

impl core::error::Error for InvalidPlmnId {}

impl FromStr for PlmnId {
    type Err = InvalidPlmnId;

    fn from_str(text: &str) -> Result<Self, InvalidPlmnId> {
        let (mcc, mnc) = text.split_once('-').ok_or(InvalidPlmnId)?;
        Self::new(mcc, mnc).ok_or(InvalidPlmnId)
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
                    value.extend_from_slice(&plmn.to_tbcd());
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
