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

//! The octets of an information element.

use crate::prelude::*;
use core::borrow::Borrow;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::ops::{Deref, DerefMut};

/// How many octets an [`Octets`] holds without an allocation.
const INLINE: usize = 22;

/// The value of an information element: a string of octets.
///
/// It reads as a slice of octets and is written as a `Vec<u8>` is: it
/// dereferences to `[u8]`, compares with slices, arrays and vectors, and has
/// `push`, `extend_from_slice`, `resize`, `truncate` and `clear`. A value of
/// up to 22 octets is kept in the `Octets` itself, so that decoding and
/// cloning most IEs allocates nothing; a longer one is allocated at its
/// exact length. An `Octets` is 24 octets large, as a `Vec<u8>` is.
///
/// ```
/// use oxirush_nas::common::Octets;
///
/// let mut octets = Octets::from([0x02, 0xf8, 0x39]);
/// octets.push(0x01);
/// assert_eq!(octets, [0x02, 0xf8, 0x39, 0x01]);
/// assert_eq!(octets.len(), 4);
/// assert_eq!(octets[1..3], [0xf8, 0x39]);
/// assert_eq!(Vec::from(octets), vec![0x02, 0xf8, 0x39, 0x01]);
/// ```
#[derive(Clone)]
pub struct Octets(Repr);

#[derive(Clone)]
enum Repr {
    /// The first `length` octets of `octets`.
    Inline { length: u8, octets: [u8; INLINE] },
    /// More than [`INLINE`] octets.
    Heap(Box<[u8]>),
}

impl Octets {
    /// No octets.
    pub const fn new() -> Self {
        Self(Repr::Inline {
            length: 0,
            octets: [0; INLINE],
        })
    }

    /// The octets as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            Repr::Inline { length, octets } => &octets[..usize::from(*length)],
            Repr::Heap(octets) => octets,
        }
    }

    /// The octets as a slice that can be written.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.0 {
            Repr::Inline { length, octets } => &mut octets[..usize::from(*length)],
            Repr::Heap(octets) => octets,
        }
    }

    /// The octets as a vector.
    pub fn into_vec(self) -> Vec<u8> {
        match self.0 {
            Repr::Inline { length, octets } => octets[..usize::from(length)].to_vec(),
            Repr::Heap(octets) => octets.into_vec(),
        }
    }

    /// Change the octets as those of a vector, which `change` gets.
    fn as_vec<T>(&mut self, change: impl FnOnce(&mut Vec<u8>) -> T) -> T {
        let mut octets = core::mem::take(self).into_vec();
        let result = change(&mut octets);
        *self = octets.into();
        result
    }

    /// Add an octet at the end.
    pub fn push(&mut self, octet: u8) {
        self.extend_from_slice(&[octet]);
    }

    /// Add octets at the end.
    pub fn extend_from_slice(&mut self, more: &[u8]) {
        if let Repr::Inline { length, octets } = &mut self.0
            && let Some(end) = usize::from(*length).checked_add(more.len())
            && end <= INLINE
        {
            octets[usize::from(*length)..end].copy_from_slice(more);
            *length = end as u8;
            return;
        }
        self.as_vec(|octets| octets.extend_from_slice(more));
    }

    /// Make the value `length` octets long: octets beyond are taken off, and
    /// `octet` fills what is missing.
    pub fn resize(&mut self, length: usize, octet: u8) {
        if let Repr::Inline {
            length: current,
            octets,
        } = &mut self.0
            && length <= INLINE
        {
            if let Some(added) = octets.get_mut(usize::from(*current)..length) {
                added.fill(octet);
            }
            *current = length as u8;
            return;
        }
        self.as_vec(|octets| octets.resize(length, octet));
    }

    /// Keep the first `length` octets; a value that is shorter is left as it
    /// is.
    pub fn truncate(&mut self, length: usize) {
        if length < self.len() {
            self.resize(length, 0);
        }
    }

    /// Take every octet off.
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Default for Octets {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Octets {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DerefMut for Octets {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl AsRef<[u8]> for Octets {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Borrow<[u8]> for Octets {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<&[u8]> for Octets {
    #[inline]
    fn from(slice: &[u8]) -> Self {
        let length = slice.len();
        if length > INLINE {
            return Self(Repr::Heap(slice.into()));
        }
        // A few octets are copied as one or two groups of a constant length,
        // which overlap: a copy of a length that is not known when this is
        // compiled is a call, which costs more than the octets.
        let mut octets = [0; INLINE];
        if length >= 16 {
            octets[..16].copy_from_slice(&slice[..16]);
            octets[length - 16..length].copy_from_slice(&slice[length - 16..]);
        } else if length >= 8 {
            octets[..8].copy_from_slice(&slice[..8]);
            octets[length - 8..length].copy_from_slice(&slice[length - 8..]);
        } else if length >= 4 {
            octets[..4].copy_from_slice(&slice[..4]);
            octets[length - 4..length].copy_from_slice(&slice[length - 4..]);
        } else if length >= 2 {
            octets[..2].copy_from_slice(&slice[..2]);
            octets[length - 2..length].copy_from_slice(&slice[length - 2..]);
        } else if length == 1 {
            octets[0] = slice[0];
        }
        Self(Repr::Inline {
            length: length as u8,
            octets,
        })
    }
}

impl From<Vec<u8>> for Octets {
    fn from(octets: Vec<u8>) -> Self {
        match octets.len() <= INLINE {
            true => octets.as_slice().into(),
            false => Self(Repr::Heap(octets.into_boxed_slice())),
        }
    }
}

impl From<Box<[u8]>> for Octets {
    fn from(octets: Box<[u8]>) -> Self {
        match octets.len() <= INLINE {
            true => octets.as_ref().into(),
            false => Self(Repr::Heap(octets)),
        }
    }
}

impl From<&Vec<u8>> for Octets {
    fn from(octets: &Vec<u8>) -> Self {
        octets.as_slice().into()
    }
}

impl<const N: usize> From<[u8; N]> for Octets {
    fn from(octets: [u8; N]) -> Self {
        octets.as_slice().into()
    }
}

impl<const N: usize> From<&[u8; N]> for Octets {
    fn from(octets: &[u8; N]) -> Self {
        octets.as_slice().into()
    }
}

impl From<Octets> for Vec<u8> {
    fn from(octets: Octets) -> Self {
        octets.into_vec()
    }
}

impl FromIterator<u8> for Octets {
    fn from_iter<I: IntoIterator<Item = u8>>(octets: I) -> Self {
        let mut octets = octets.into_iter();
        let mut inline = [0; INLINE];
        for length in 0..INLINE {
            match octets.next() {
                Some(octet) => inline[length] = octet,
                None => return inline[..length].into(),
            }
        }
        match octets.next() {
            None => inline.into(),
            Some(next) => {
                let mut all = inline.to_vec();
                all.push(next);
                all.extend(octets);
                all.into()
            }
        }
    }
}

impl<'a> IntoIterator for &'a Octets {
    type Item = &'a u8;
    type IntoIter = core::slice::Iter<'a, u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl fmt::Debug for Octets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_slice(), f)
    }
}

impl PartialEq for Octets {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Octets {}

impl PartialOrd for Octets {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Octets {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

impl Hash for Octets {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl PartialEq<[u8]> for Octets {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<&[u8]> for Octets {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl PartialEq<Vec<u8>> for Octets {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Octets {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for Octets {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<Octets> for [u8] {
    fn eq(&self, other: &Octets) -> bool {
        self == other.as_slice()
    }
}

impl PartialEq<Octets> for &[u8] {
    fn eq(&self, other: &Octets) -> bool {
        *self == other.as_slice()
    }
}

impl PartialEq<Octets> for Vec<u8> {
    fn eq(&self, other: &Octets) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<Octets> for [u8; N] {
    fn eq(&self, other: &Octets) -> bool {
        self.as_slice() == other.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Octets of each length around the one that is kept without an
    /// allocation.
    fn lengths() -> impl Iterator<Item = Vec<u8>> {
        [0, 1, 2, INLINE - 1, INLINE, INLINE + 1, 2 * INLINE, 300]
            .into_iter()
            .map(|length| (0..length).map(|octet| octet as u8).collect())
    }

    #[test]
    fn octets_are_as_large_as_a_vector() {
        assert_eq!(size_of::<Octets>(), size_of::<Vec<u8>>());
        assert_eq!(size_of::<Option<Octets>>(), size_of::<Vec<u8>>());
    }

    #[test]
    fn octets_read_as_the_slice_they_were_made_from() {
        for vector in lengths() {
            let from = [
                Octets::from(vector.clone()),
                Octets::from(vector.as_slice()),
                Octets::from(&vector),
                Octets::from(vector.clone().into_boxed_slice()),
                vector.iter().copied().collect(),
            ];
            for octets in from {
                assert_eq!(octets.as_slice(), vector.as_slice());
                assert_eq!(octets.len(), vector.len());
                assert_eq!(octets, vector);
                assert_eq!(vector, octets);
                assert_eq!(octets, vector.as_slice());
                assert_eq!(octets.clone(), octets);
                assert_eq!(octets.first(), vector.first());
                assert_eq!(format!("{octets:?}"), format!("{vector:?}"));
                assert_eq!(octets.clone().into_vec(), vector);
                assert_eq!(Vec::from(octets), vector);
            }
        }
        assert_eq!(Octets::from([1, 2, 3]), [1, 2, 3]);
        assert_eq!(Octets::from(&[1, 2, 3]), &[1, 2, 3]);
        assert_ne!(Octets::from([1, 2, 3]), [1, 2]);
        assert!(Octets::new().is_empty());
        assert_eq!(Octets::default(), Octets::new());
    }

    #[test]
    fn octets_are_written_as_a_vector_is() {
        for vector in lengths() {
            // One octet at a time, across the length that is kept inline.
            let mut octets = Octets::new();
            for octet in &vector {
                octets.push(*octet);
            }
            assert_eq!(octets, vector);

            for more in lengths() {
                let (mut octets, mut expected) = (Octets::from(&vector), vector.clone());
                octets.extend_from_slice(&more);
                expected.extend_from_slice(&more);
                assert_eq!(octets, expected);
            }
            for length in [0, 1, INLINE - 1, INLINE, INLINE + 1, 400] {
                let (mut octets, mut expected) = (Octets::from(&vector), vector.clone());
                octets.resize(length, 0xaa);
                expected.resize(length, 0xaa);
                assert_eq!(octets, expected);

                let (mut octets, mut expected) = (Octets::from(&vector), vector.clone());
                octets.truncate(length);
                expected.truncate(length);
                assert_eq!(octets, expected);
            }
            let mut octets = Octets::from(&vector);
            if let Some(first) = octets.first_mut() {
                *first = 0xff;
                assert_eq!(octets[0], 0xff);
            }
            octets.clear();
            assert!(octets.is_empty());
        }
    }

    #[test]
    fn octets_that_were_longer_take_no_allocation_once_short() {
        // The octets that a value keeps without an allocation are those of
        // its length, whatever it held before.
        let mut octets = Octets::from(vec![7; 100]);
        octets.truncate(3);
        assert!(matches!(octets.0, Repr::Inline { length: 3, .. }));
        assert_eq!(octets, [7, 7, 7]);
        octets.resize(INLINE, 1);
        assert!(matches!(octets.0, Repr::Inline { .. }));
        octets.push(2);
        assert!(matches!(octets.0, Repr::Heap(_)));
        assert_eq!(octets.len(), INLINE + 1);
    }

    #[test]
    fn octets_compare_and_hash_by_their_content() {
        use std::collections::HashSet;
        let short = Octets::from([1, 2]);
        let long = Octets::from(vec![1; 40]);
        let lower = Octets::from([1, 1, 9]);
        assert!(short > lower && short > long);
        let set: HashSet<Octets> = [short.clone(), long.clone(), short.clone()].into();
        assert_eq!(set.len(), 2);
        assert!(set.contains([1_u8, 2].as_slice()));
    }
}
