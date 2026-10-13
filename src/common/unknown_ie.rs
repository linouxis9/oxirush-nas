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

//! Raw information elements preserved while decoding.

use crate::prelude::*;

/// An IE that a decoder kept without reading it: its IEI, and the octets
/// after the IEI as they came, with their length indicator if the IE has
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownIe<'a> {
    /// The raw IEI byte as it appeared on the wire.
    pub iei: u8,
    /// The raw IE data (everything after the IEI byte, including any length field).
    pub data: &'a [u8],
}

impl UnknownIe<'_> {
    /// Whether the IEI marks an unknown IE as "comprehension required".
    ///
    /// TS 24.007 §11.2.5 applies this to type 4 IEIs with bits 8 to 5 set to
    /// zero and to type 6 IEIs 0x7E and 0x7F. TS 24.301 and TS 24.501 §7.5.1
    /// treat such an unknown IE like a mandatory IE error (cause #96).
    /// Decoding keeps a well-framed one, so the receiver decides what to
    /// answer: check the `unknown_ies()` of a decoded message. One that is
    /// cut short fails to decode with `NasError::InvalidMandatoryIe`.
    pub fn is_comprehension_required(&self) -> bool {
        self.iei <= 0x0f || matches!(self.iei, 0x7e | 0x7f)
    }
}

/// The IEs of a message that its table has no place for, in the order they
/// came in: an IEI that the table does not have, and what a receiver
/// ignores of one that it has (a repetition, an IE out of sequence, one
/// whose value is not one of its type). They are kept during decode and
/// written again during encode, which is how an IE of a later release or
/// of a vendor passes through.
///
/// They are kept in one buffer, each after its length, so that a message
/// of many of them costs little more than its octets: a hostile message
/// is one of thousands of IEs of one octet.
///
/// ```
/// use oxirush_nas::nas_5gs::Nas5gsMessage;
///
/// // REGISTRATION COMPLETE, then an IE that its table does not have
/// let mut message = Nas5gsMessage::decode(&[0x7e, 0x00, 0x43, 0x6a, 0x01, 0x05]).unwrap();
/// let unknown: Vec<_> = message.unknown_ies().iter().collect();
/// assert_eq!((unknown[0].iei, unknown[0].data), (0x6a, &[0x01, 0x05][..]));
/// # let _ = &mut message;
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
pub struct UnknownIes {
    /// Each IE after its length: the length of the IEI and the data, seven
    /// bits an octet with the lowest first and bit 8 set on all but the
    /// last, then the IEI and the data.
    octets: Vec<u8>,
}

impl UnknownIes {
    /// No IE.
    pub const fn new() -> Self {
        Self { octets: Vec::new() }
    }

    /// How many IEs there are. They are counted: the IEs are kept one
    /// after the other, without a table of them.
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Whether there is none.
    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }

    /// Add the IE of the IEI `iei` whose octets after the IEI are `data`,
    /// after those that are there.
    pub fn push(&mut self, iei: u8, data: &[u8]) {
        self.length(1 + data.len());
        self.octets.push(iei);
        self.octets.extend_from_slice(data);
    }

    /// Add the IE `ie`, its IEI first: one octet at least.
    pub(crate) fn push_raw(&mut self, ie: &[u8]) {
        if let Some((iei, data)) = ie.split_first() {
            self.push(*iei, data);
        }
    }

    /// Write the length `length` of an IE.
    fn length(&mut self, mut length: usize) {
        while length >= 0x80 {
            self.octets.push(length as u8 | 0x80);
            length >>= 7;
        }
        self.octets.push(length as u8);
    }

    /// The IEs, in the order they came in.
    pub fn iter(&self) -> UnknownIesIter<'_> {
        UnknownIesIter {
            octets: &self.octets,
        }
    }

    /// The IE at the place `at`, counted from zero. The IEs are read one
    /// after the other: this reads those before it.
    pub fn get(&self, at: usize) -> Option<UnknownIe<'_>> {
        self.iter().nth(at)
    }

    /// Take every IE out.
    pub fn clear(&mut self) {
        self.octets.clear();
    }
}

impl core::fmt::Debug for UnknownIes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<'a> IntoIterator for &'a UnknownIes {
    type Item = UnknownIe<'a>;
    type IntoIter = UnknownIesIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> FromIterator<UnknownIe<'a>> for UnknownIes {
    fn from_iter<T: IntoIterator<Item = UnknownIe<'a>>>(ies: T) -> Self {
        let mut all = Self::new();
        for ie in ies {
            all.push(ie.iei, ie.data);
        }
        all
    }
}

/// No IE: what a message that keeps none has.
pub(crate) static NO_UNKNOWN_IES: UnknownIes = UnknownIes::new();

/// The IEs of an [`UnknownIes`], one after the other.
#[derive(Debug, Clone)]
pub struct UnknownIesIter<'a> {
    octets: &'a [u8],
}

impl<'a> Iterator for UnknownIesIter<'a> {
    type Item = UnknownIe<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (mut length, mut shift) = (0usize, 0);
        loop {
            let (octet, rest) = self.octets.split_first()?;
            self.octets = rest;
            length |= usize::from(octet & 0x7f) << shift;
            shift += 7;
            if octet & 0x80 == 0 {
                break;
            }
        }
        let (ie, rest) = self.octets.split_at_checked(length)?;
        self.octets = rest;
        let (iei, data) = ie.split_first()?;
        Some(UnknownIe { iei: *iei, data })
    }
}

/// The serde form of the IEs is a list of `{"iei": .., "data": [..]}`, as
/// that of a list of structs.
#[cfg(feature = "serde")]
mod serialized {
    use super::UnknownIes;
    use crate::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize)]
    #[serde(rename = "UnknownIe")]
    struct Shown<'a> {
        iei: u8,
        data: &'a [u8],
    }

    #[derive(Deserialize)]
    #[serde(rename = "UnknownIe")]
    struct Read {
        iei: u8,
        data: Vec<u8>,
    }

    impl Serialize for UnknownIes {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let ies = self.iter().map(|ie| Shown {
                iei: ie.iei,
                data: ie.data,
            });
            serializer.collect_seq(ies)
        }
    }

    impl<'de> Deserialize<'de> for UnknownIes {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let read = Vec::<Read>::deserialize(deserializer)?;
            let mut ies = UnknownIes::new();
            for ie in &read {
                ies.push(ie.iei, &ie.data);
            }
            Ok(ies)
        }
    }
}

/// Position of an optional IE in a decoded user equipment policy message,
/// whose IEs are few: an entry has the place of its IE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) enum OptionalIeOrder {
    Known(u8),
    Unknown(usize),
    Ignored(usize, IgnoredIeReason),
}

/// Where an optional IE of a decoded message came, among the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Placed {
    /// The IE of the table that has this IEI.
    Known(u8),
    /// The next of the IEs that the table has no place for: an IEI that it
    /// does not have.
    Unknown,
    /// The next of those IEs: one of an IEI of the table, which the
    /// receiver ignored.
    Ignored(IgnoredIeReason),
}

/// The order in which the optional IEs of a decoded message came, when it
/// is another than that of the table: one or two octets an IE.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct IeOrder(Vec<u8>);

impl IeOrder {
    /// The order of no IE: that of the table.
    pub(crate) const fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn push(&mut self, entry: Placed) {
        match entry {
            Placed::Known(iei) => self.0.extend_from_slice(&[0, iei]),
            Placed::Unknown => self.0.push(1),
            Placed::Ignored(IgnoredIeReason::Malformed) => self.0.push(2),
            Placed::Ignored(IgnoredIeReason::Repeated) => self.0.push(3),
            Placed::Ignored(IgnoredIeReason::OutOfSequence) => self.0.push(4),
        }
    }

    /// The entries, in the order of the message. What is no entry ends
    /// them: an order is read from a document too.
    pub(crate) fn iter(&self) -> impl Iterator<Item = Placed> + '_ {
        let mut octets = self.0.iter().copied();
        core::iter::from_fn(move || {
            Some(match octets.next()? {
                0 => Placed::Known(octets.next()?),
                1 => Placed::Unknown,
                2 => Placed::Ignored(IgnoredIeReason::Malformed),
                3 => Placed::Ignored(IgnoredIeReason::Repeated),
                4 => Placed::Ignored(IgnoredIeReason::OutOfSequence),
                _ => return None,
            })
        })
    }
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
