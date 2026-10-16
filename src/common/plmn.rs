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

#[cfg(feature = "serde")]
use crate::prelude::*;
pub use oxirush_utils::identity::Plmn;

/// The PLMN identity in the first three of `octets`, in the order of TS 24.008
/// §10.5.1.3: `None` when there are fewer, or when a digit is none.
pub(crate) fn plmn_at(octets: &[u8]) -> Option<Plmn> {
    let octets = <[u8; 3]>::try_from(octets.get(..3)?).ok()?;
    Plmn::from_nas_octets(octets).ok()
}

/// The serde form of a [`Plmn`] in a struct that derives it: its text, `208-93`, which
/// is what the readable form of a view shows.
#[cfg(feature = "serde")]
pub(crate) mod plmn_text {
    use super::Plmn;
    use crate::prelude::*;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub(crate) fn serialize<S: Serializer>(plmn: &Plmn, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(plmn)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Plmn, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(|_| {
            de::Error::custom(format!("\"{text}\" is not a PLMN identity like \"208-93\""))
        })
    }

    /// An optional PLMN identity.
    pub(crate) mod option {
        use super::Plmn;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        #[derive(Serialize, Deserialize)]
        struct Text(#[serde(with = "super")] Plmn);

        pub(crate) fn serialize<S: Serializer>(
            plmn: &Option<Plmn>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            plmn.map(Text).serialize(serializer)
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Plmn>, D::Error> {
            Ok(Option::<Text>::deserialize(deserializer)?.map(|Text(plmn)| plmn))
        }
    }

    /// A list of PLMN identities.
    pub(crate) mod list {
        use super::Plmn;
        use crate::prelude::*;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        #[derive(Serialize, Deserialize)]
        struct Text(#[serde(with = "super")] Plmn);

        pub(crate) fn serialize<S: Serializer>(
            plmns: &[Plmn],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.collect_seq(plmns.iter().map(|plmn| Text(*plmn)))
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<Plmn>, D::Error> {
            let texts = Vec::<Text>::deserialize(deserializer)?;
            Ok(texts.into_iter().map(|Text(plmn)| plmn).collect())
        }
    }
}

/// A tracking area identity of one of the two systems, as the serde form of a
/// struct that derives it writes it: its PLMN and its TAC, a number.
#[cfg(feature = "serde")]
pub(crate) trait TaiParts: Sized {
    /// The PLMN and the TAC.
    fn parts(&self) -> (Plmn, u32);
    /// The TAI of a PLMN and a TAC, or why there is none.
    fn of(plmn: Plmn, tac: u32) -> Result<Self, String>;
}

#[cfg(feature = "serde")]
impl TaiParts for oxirush_utils::identity::Tai5gs {
    fn parts(&self) -> (Plmn, u32) {
        (self.plmn(), self.tac())
    }
    fn of(plmn: Plmn, tac: u32) -> Result<Self, String> {
        Self::new(plmn, tac).map_err(|error| error.to_string())
    }
}

#[cfg(feature = "serde")]
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

/// The serde form of a tracking area identity in a struct that derives it:
/// `{"plmn": "208-93", "tac": 1}`.
#[cfg(feature = "serde")]
pub(crate) mod tai_members {
    use super::{Plmn, TaiParts};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

    /// The members of a TAI, whose TAC is not checked yet.
    #[derive(Serialize, Deserialize)]
    #[serde(rename = "TrackingAreaIdentity")]
    struct Members {
        #[serde(with = "super::plmn_text")]
        plmn: Plmn,
        tac: u32,
    }

    pub(crate) fn serialize<T: TaiParts, S: Serializer>(
        tai: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let (plmn, tac) = tai.parts();
        Members { plmn, tac }.serialize(serializer)
    }

    pub(crate) fn deserialize<'de, T: TaiParts, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<T, D::Error> {
        let Members { plmn, tac } = Members::deserialize(deserializer)?;
        T::of(plmn, tac).map_err(de::Error::custom)
    }

    /// A list of TAIs.
    pub(crate) mod list {
        use super::TaiParts;
        use crate::prelude::*;
        use serde::{Deserialize, Deserializer, Serialize, Serializer};

        struct Shown<'a, T: TaiParts>(&'a T);

        impl<T: TaiParts> Serialize for Shown<'_, T> {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                super::serialize(self.0, serializer)
            }
        }

        #[derive(Deserialize)]
        #[serde(bound = "T: TaiParts")]
        struct Read<T: TaiParts>(#[serde(with = "super")] T);

        pub(crate) fn serialize<T: TaiParts, S: Serializer>(
            tais: &[T],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.collect_seq(tais.iter().map(Shown))
        }

        pub(crate) fn deserialize<'de, T: TaiParts, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<T>, D::Error> {
            let read = Vec::<Read<T>>::deserialize(deserializer)?;
            Ok(read.into_iter().map(|Read(tai)| tai).collect())
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
