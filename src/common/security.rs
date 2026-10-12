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

//! What the security contexts of the two systems have alike: where their
//! keys are, how they are made without a copy, and their NAS COUNTs.

use crate::common::NasError;
use oxirush_security::NasCount;

/// The two NAS keys of a context.
///
/// A context has them in one place of the heap, from their derivation to
/// the drop that wipes them: a context that is moved, into a map or out of
/// a `Result`, takes the address along and leaves no copy of a key where
/// it was.
#[derive(Clone)]
pub(crate) struct Keys<I, E> {
    /// The NAS integrity key.
    pub(crate) integrity: I,
    /// The NAS ciphering key.
    pub(crate) ciphering: E,
}

/// The octets of stack that are set to zero after keys were made: more
/// than a key derivation of oxirush-security and the frames of this crate
/// above it use.
const WIPED: usize = 8192;

/// Run `work`, which makes or replaces keys, in a frame of its own, then
/// set to zero the stack below the caller.
///
/// A key is a type that is wiped when it is dropped, and a value that is
/// moved is not dropped where it was: what a derivation returns goes over
/// the stack on its way to the heap. Those octets are below the caller
/// once `work` has returned, and are cleared there.
#[inline(always)]
pub(crate) fn wiped<R>(work: impl FnOnce() -> R) -> R {
    let _clear = ClearStack;
    below(work)
}

/// `work`, in a frame that is not that of the caller.
#[inline(never)]
fn below<R>(work: impl FnOnce() -> R) -> R {
    work()
}

/// Clears the stack below the function that holds it, when it is dropped:
/// after the result of the work is where the caller wants it.
struct ClearStack;

impl Drop for ClearStack {
    #[inline(always)]
    fn drop(&mut self) {
        clear_stack();
    }
}

/// Set to zero [`WIPED`] octets of the stack below the caller: the frame of
/// this function is where those of the work were.
#[inline(never)]
fn clear_stack() {
    let mut area = [0u8; WIPED];
    // The compiler cannot tell that nothing reads the zeros
    core::hint::black_box(&mut area);
}

/// The next NAS COUNT of a direction as a context keeps it, in four octets:
/// one that is exhausted is kept as 2^24, the first number that is no COUNT.
/// The arithmetic is that of [`NasCount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NextCount(u32);

/// For the tests of the contexts, which set and read a COUNT as a context
/// keeps it: 2^24 is one that is exhausted.
#[cfg(test)]
impl From<u32> for NextCount {
    fn from(next: u32) -> Self {
        Self(next)
    }
}

#[cfg(test)]
impl PartialEq<u32> for NextCount {
    fn eq(&self, next: &u32) -> bool {
        self.0 == *next
    }
}

impl NextCount {
    /// The first COUNT of a security context.
    pub(crate) const ZERO: Self = Self(0);

    /// What a context keeps of the next COUNT `count`: `None` is exhausted.
    pub(crate) fn of(count: Option<NasCount>) -> Self {
        Self(count.map_or(NasCount::MAX.get() + 1, NasCount::get))
    }

    /// The next COUNT; `None` when every COUNT of the direction was used.
    pub(crate) fn get(self) -> Option<NasCount> {
        NasCount::new(self.0).ok()
    }

    /// The COUNT of the message that is sent next.
    pub(crate) fn to_send(self) -> Result<NasCount, NasError> {
        self.get().ok_or(NasError::NasCountExhausted)
    }

    /// The COUNT of a received message that carries the `bits` low bits
    /// `low_bits` of it: the smallest from the next COUNT on that ends with
    /// them. `wraps` is for the null integrity algorithm, whose COUNT goes
    /// on from zero after 2^24 - 1 (TS 24.501 and TS 24.301 §4.4.3.5).
    pub(crate) fn received(
        self,
        low_bits: u8,
        bits: u32,
        wraps: bool,
    ) -> Result<NasCount, NasError> {
        let lowest = self.to_send()?;
        match wraps {
            true => lowest.wrapping_estimate_from_low_bits(low_bits, bits),
            false => lowest.estimate_from_low_bits(low_bits, bits),
        }
        .map_err(|_| NasError::NasCountExhausted)
    }

    /// The next COUNT after the message of `count`.
    pub(crate) fn after(count: NasCount, wraps: bool) -> Self {
        match wraps {
            true => Self(count.wrapping_next().get()),
            false => Self::of(count.next().ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::*;

    /// What this crate computed before it took the arithmetic of
    /// [`NasCount`]: the smallest number at or above `next_expected` whose
    /// `bits` low bits are those of `low_bits`.
    fn estimate_count_bits(next_expected: u32, low_bits: u8, bits: u32) -> u32 {
        let mask = (1u32 << bits) - 1;
        let delta = (u32::from(low_bits) & mask).wrapping_sub(next_expected & mask) & mask;
        next_expected.wrapping_add(delta)
    }

    #[test]
    fn the_counts_of_the_security_crate_are_those_that_this_crate_computed() {
        const LAST: u32 = 0x00ff_ffff;
        // 4 bits at SRVCC and at a handover from E-UTRAN, 5 in the EPS
        // SERVICE REQUEST, 8 in a security header
        for bits in [4, 5, 8] {
            let period = 1u32 << bits;
            // Around zero, around each of the first wraps of the low bits and
            // of the last, and around 2^24 - 1
            let mut nexts: Vec<u32> = (0..3 * period + 3).collect();
            nexts.extend(0x0001_0000 - 2 * period..0x0001_0000 + 2 * period);
            nexts.extend(LAST - 3 * period..=LAST);
            for next in nexts {
                let lowest = NextCount(next);
                for low_bits in 0..=u8::MAX {
                    let before = estimate_count_bits(next, low_bits, bits);
                    // A context that may not wrap: no COUNT above 2^24 - 1
                    let stops = lowest.received(low_bits, bits, false);
                    match before <= LAST {
                        true => assert_eq!(stops.map(NasCount::get), Ok(before)),
                        false => assert_eq!(stops, Err(NasError::NasCountExhausted)),
                    }
                    // The null integrity algorithm: on from zero
                    let wraps = lowest.received(low_bits, bits, true);
                    assert_eq!(wraps.map(NasCount::get), Ok(before & LAST));
                }
            }
        }
        // The estimates of the security crate itself, which its callers use
        let count = |count: u32| NasCount::new(count).unwrap();
        assert_eq!(
            count(0x1f8).estimate_from_low_bits(0x2, 4),
            Ok(count(0x202))
        );
        assert_eq!(count(0x1f8).estimate(0xf8), Ok(count(0x1f8)));
        assert!(count(0).estimate_from_low_bits(0, 9).is_err());
        assert!(count(LAST).estimate(0x00).is_err());
        assert_eq!(
            count(LAST).estimate_from_low_bits(0x0f, 4),
            Ok(NasCount::MAX)
        );
    }

    #[test]
    fn the_next_count_stops_or_wraps_after_the_last() {
        let last = NasCount::MAX;
        assert_eq!(NextCount::after(last, false).get(), None);
        assert_eq!(NextCount::after(last, true).get(), Some(NasCount::ZERO));
        assert_eq!(
            NextCount::of(None).to_send(),
            Err(NasError::NasCountExhausted)
        );
        assert_eq!(
            NextCount::of(None).received(0, 8, false),
            Err(NasError::NasCountExhausted)
        );
        assert_eq!(NextCount::ZERO.to_send(), Ok(NasCount::ZERO));
        assert_eq!(NextCount::of(Some(last)).get(), Some(last));
        assert_eq!(core::mem::size_of::<NextCount>(), 4);
    }
}
