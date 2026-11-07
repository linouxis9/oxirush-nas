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

//! The NAS COUNTs of one direction of a security context, as TS 24.501 and
//! TS 24.301 §4.4.3 have them, written apart from the crate: the targets of
//! the security contexts compare what a context does with what this says.
//!
//! A COUNT is a number below 2^24. The next one of a direction that has
//! used them all is 2^24, after which nothing is sent or verified in it,
//! but with the null integrity algorithm, where the COUNT goes on from zero
//! (§4.4.3.5). A receiver estimates the COUNT of a message from its
//! sequence number, the low bits of it (§4.4.3.1): the least from the next
//! COUNT on that ends with them. With a replay window of `size`, it also
//! takes a message of one of the `size` COUNTs below the highest that it
//! accepted, once: the COUNTs that it took, and those below the window
//! when the window was set or changed, are taken, and are refused as
//! replays (§4.4.3.2).

use std::collections::BTreeSet;

/// The first number that is no COUNT: the next COUNT of a direction that
/// used them all.
pub const LIMIT: u32 = 1 << 24;

/// One direction of a context, as its receiver keeps it.
#[derive(Debug, Clone)]
pub struct Receiving {
    /// The next COUNT: one more than the highest that was accepted, or the
    /// one that the context was restored with.
    pub next: u32,
    /// Each COUNT below it is taken as accepted.
    floor: u32,
    /// The COUNTs at or above `floor`, below `next`, that were accepted.
    taken: BTreeSet<u32>,
}

impl Receiving {
    /// A direction whose next COUNT is `next`.
    pub fn new(next: u32) -> Self {
        Self {
            next,
            floor: 0,
            taken: BTreeSet::new(),
        }
    }

    /// The COUNT below the highest that a message with the sequence number
    /// `sequence_number` has, if a window of `size` holds it and did not
    /// take it.
    pub fn below(&self, size: u8, sequence_number: u8) -> Option<u32> {
        let highest = self.next.checked_sub(1)?;
        // The nearest COUNT below the highest that ends with the number
        let distance = highest.wrapping_sub(u32::from(sequence_number)) & 0xff;
        let count = highest.checked_sub(distance)?;
        let within = (1..=u32::from(size)).contains(&distance);
        (within && count >= self.floor && !self.taken.contains(&count)).then_some(count)
    }

    /// The COUNT of a message whose sequence number has the `bits` low bits
    /// `low`: the least from the next one on that ends with them, modulo
    /// 2^24 when the COUNTs wrap; none when every COUNT was used, or the
    /// least is past the last.
    pub fn estimate(&self, low: u8, bits: u32, wraps: bool) -> Option<u32> {
        if self.next >= LIMIT {
            return None;
        }
        let mask = (1 << bits) - 1;
        let estimate = self.next + ((u32::from(low) & mask).wrapping_sub(self.next) & mask);
        match wraps {
            true => Some(estimate % LIMIT),
            false => (estimate < LIMIT).then_some(estimate),
        }
    }

    /// The message of `count` is accepted as one from the next COUNT on:
    /// the next is the one after it, and the highest before it is taken.
    pub fn advance(&mut self, count: u32, wraps: bool) {
        if !wraps && let Some(highest) = self.next.checked_sub(1) {
            self.taken.insert(highest);
        }
        self.next = next_after(count, wraps);
    }

    /// The message of `count`, which a window held, is accepted: once.
    pub fn take(&mut self, count: u32) {
        self.taken.insert(count);
    }

    /// The window goes from `old` COUNTs to another number: those that it
    /// did not hold are taken.
    pub fn resize(&mut self, old: u8) {
        let held = self.next.saturating_sub(1).saturating_sub(u32::from(old));
        self.floor = self.floor.max(held);
        let floor = self.floor;
        self.taken.retain(|&count| count >= floor);
    }
}

/// The next COUNT after the one of a message that was sent or accepted.
pub fn next_after(count: u32, wraps: bool) -> u32 {
    match wraps {
        true => (count + 1) % LIMIT,
        false => count + 1,
    }
}

/// The next COUNT that a context restored with `count` has: 2^24 for none.
pub fn restored(count: Option<u32>) -> u32 {
    count.unwrap_or(LIMIT)
}
