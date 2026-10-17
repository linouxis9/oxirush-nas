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
pub use oxirush_utils::identity::Plmn;

/// The PLMN identity in the first three of `octets`, in the order of TS 24.008
/// §10.5.1.3: `None` when there are fewer, or when a digit is none.
pub(crate) fn plmn_at(octets: &[u8]) -> Option<Plmn> {
    let octets = <[u8; 3]>::try_from(octets.get(..3)?).ok()?;
    Plmn::from_nas_octets(octets).ok()
}

/// A tracking area identity of one of the two systems, as its PLMN and its
/// TAC, a number: what a tracking area identity list and the serde form of a
/// struct that derives it are made of.
pub(crate) trait TaiParts: Sized {
    /// The PLMN and the TAC.
    fn parts(&self) -> (Plmn, u32);
    /// The TAI of a PLMN and a TAC, or why there is none.
    fn of(plmn: Plmn, tac: u32) -> Result<Self, String>;
}

impl TaiParts for oxirush_utils::identity::Tai5gs {
    fn parts(&self) -> (Plmn, u32) {
        (self.plmn(), self.tac())
    }
    fn of(plmn: Plmn, tac: u32) -> Result<Self, String> {
        Self::new(plmn, tac).map_err(|error| error.to_string())
    }
}

impl TaiParts for oxirush_utils::identity::TaiEps {
    fn parts(&self) -> (Plmn, u32) {
        (self.plmn(), self.tac().into())
    }
    fn of(plmn: Plmn, tac: u32) -> Result<Self, String> {
        match u16::try_from(tac) {
            Ok(tac) => Ok(Self::new(plmn, tac)),
            Err(_) => Err(format!("`tac` is {tac}, and is 0 to 65535")),
        }
    }
}

/// Add accessors for a list of 3-octet PLMN identities holding `$min` to
/// `$max` entries. Receivers read at most `$max` complete entries and skip
/// entries that do not decode (TS 24.007 §11.4.2).
macro_rules! plmn_sequence_ie {
    ($name:ident, $min:literal, $max:literal) => {
        impl $name {
            /// PLMN identities in wire order.
            pub fn plmns(&self) -> Vec<crate::common::Plmn> {
                self.value
                    .chunks_exact(3)
                    .take($max)
                    .filter_map(crate::common::plmn_at)
                    .collect()
            }

            /// Build from PLMN identities.
            pub fn from_plmns(
                plmns: &[crate::common::Plmn],
            ) -> core::result::Result<Self, crate::common::ValueError> {
                crate::common::counted("plmns", plmns.len(), $min, $max)?;
                let mut value = Vec::with_capacity(plmns.len() * 3);
                for plmn in plmns {
                    value.extend_from_slice(&plmn.to_nas_octets());
                }
                Ok(Self::new(value))
            }

            /// Sender check: a whole number of decodable entries within the
            /// count range.
            pub fn is_well_formed(&self) -> bool {
                self.value.len().is_multiple_of(3)
                    && ($min..=$max).contains(&(self.value.len() / 3))
                    && self
                        .value
                        .chunks_exact(3)
                        .all(|plmn| crate::common::plmn_at(plmn).is_some())
            }
        }
    };
}

pub(crate) use plmn_sequence_ie;
