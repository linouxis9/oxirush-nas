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

//! Shared NAS sequence number handling.

/// Estimate the full COUNT from the next expected COUNT and a received
/// sequence number.
pub(crate) fn estimate_count(next_expected: u32, sequence_number: u8) -> u32 {
    estimate_count_bits(next_expected, sequence_number, 8)
}

/// Estimate COUNT from an on-wire sequence number of 5 or 8 bits.
///
/// The result is the smallest COUNT at or above `next_expected` whose low
/// `bits` bits equal the sequence number. A received sequence number below
/// the expected one therefore means the overflow counter advanced
/// (TS 24.301 and TS 24.501 §4.4.3.1). A replayed PDU maps to a COUNT that
/// differs from the one it was protected with, so its MAC check fails.
pub(crate) fn estimate_count_bits(next_expected: u32, sequence_number: u8, bits: u32) -> u32 {
    let mask = (1u32 << bits) - 1;
    let delta = (u32::from(sequence_number) & mask).wrapping_sub(next_expected & mask) & mask;
    next_expected.wrapping_add(delta)
}

/// Estimate a full NAS COUNT from its `bits` least significant bits, as the
/// smallest COUNT at or above `next_expected` with those bits.
///
/// This covers the 8-bit NAS sequence number, the 5-bit SERVICE REQUEST
/// sequence number, and the 4 or 8 LSBs of a downlink NAS COUNT sent at
/// handover or SRVCC (TS 33.501 §8.3.2 step 8, Annex J step 10; TS 24.301
/// §9.9.2.6), where the estimate must exceed the stored COUNT.
/// `next_expected` is the lowest acceptable COUNT: a security context's
/// receive-side count (`dl_count` in the UE) already holds it, while a
/// COUNT stored as the last one received (TS 24.301 §4.4.3.1) needs one
/// added. Returns `None` unless `bits` is 1 to 8, or when the estimate
/// exceeds the 24-bit COUNT space.
pub fn estimate_nas_count(next_expected: u32, low_bits: u8, bits: u32) -> Option<u32> {
    if !(1..=8).contains(&bits) {
        return None;
    }
    let count = estimate_count_bits(next_expected, low_bits, bits);
    (next_expected <= 0x00ff_ffff && count <= 0x00ff_ffff).then_some(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_estimate_covers_short_downlink_counts() {
        // Four LSBs at SRVCC: stored downlink COUNT 0x1f7, received 0x2.
        assert_eq!(estimate_nas_count(0x1f8, 0x2, 4), Some(0x202));
        assert_eq!(estimate_nas_count(0x1f8, 0xf8, 8), Some(0x1f8));
        assert_eq!(estimate_nas_count(0, 0, 9), None);
        // Security review F3: no estimate beyond the 24-bit COUNT space.
        assert_eq!(estimate_nas_count(0x00ff_ffff, 0x00, 8), None);
        assert_eq!(estimate_nas_count(0x00ff_ffff, 0x0f, 4), Some(0x00ff_ffff));
        assert_eq!(estimate_nas_count(0x0100_0000, 0x00, 8), None);
    }

    #[test]
    fn count_estimate_is_the_next_matching_count() {
        // Fresh messages after a gap keep their overflow, including after
        // earlier overflows.
        assert_eq!(estimate_count(0x0000_0105, 0x90), 0x0000_0190);
        assert_eq!(estimate_count(0x0000_0005, 0x90), 0x0000_0090);
        assert_eq!(estimate_count(0x0000_01f0, 0x02), 0x0000_0202);
        assert_eq!(estimate_count(0x00ff_ffff, 0xff), 0x00ff_ffff);
        assert_eq!(estimate_count(0x00ff_ffff, 0x00), 0x0100_0000);
        // Five-bit SERVICE REQUEST sequence numbers.
        assert_eq!(estimate_count_bits(32, 17, 5), 49);
        assert_eq!(estimate_count_bits(49, 2, 5), 66);
        // A replayed sequence number never maps below the expected COUNT.
        assert_eq!(estimate_count(0x0000_0101, 0x00), 0x0000_0200);
    }
}
