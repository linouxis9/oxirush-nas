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

//! What the two systems read of an identity as a receiver.

/// Whether the type of identity in bits 3 to 1 of the first octet of
/// `value` is `kind`: what a reader of an identity of that type checks
/// first, so that one of another type is not read for nothing.
pub(crate) fn of_type(value: &[u8], kind: u8) -> bool {
    value
        .first()
        .is_some_and(|octet| octet & 0x07 == kind & 0x07)
}

/// The identity that `read` finds in the first `octets` of `value` at most,
/// or in the longest of its beginnings that has one: a receiver reads the
/// octets of an identity and not those after them (TS 24.007 §11.4.2).
pub(crate) fn receiver_identity<T>(
    value: &[u8],
    octets: usize,
    read: impl Fn(&[u8]) -> Option<T>,
) -> Option<T> {
    (2..=value.len().min(octets))
        .rev()
        .find_map(|end| read(&value[..end]))
}
