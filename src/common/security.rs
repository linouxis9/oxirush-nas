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

use crate::common::{Direction, NasError};
use crate::prelude::*;
use core::fmt;
use oxirush_security::{CipheringAlgorithm, IntegrityAlgorithm, NasCount, constant_time_eq};

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

/// A context starts at the COUNT zero.
impl Default for NextCount {
    fn default() -> Self {
        Self::ZERO
    }
}

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

/// What a system gives the core of its NAS security contexts: its keys, its
/// codes of the algorithms, its NAS connections and the two algorithms of
/// the security crate with the inputs that it gives them.
pub(crate) trait System {
    /// The NAS integrity key.
    type IntegrityKey: Clone;
    /// The NAS ciphering key.
    type CipheringKey: Clone;
    /// The code of an integrity algorithm, as the IEs of the system have it.
    type Integrity: Copy + PartialEq + fmt::Debug;
    /// The code of a ciphering algorithm.
    type Ciphering: Copy + PartialEq + fmt::Debug;
    /// A NAS connection, which has COUNTs of its own: an access of 5GS. EPS
    /// has one.
    type Connection: Copy;
    /// The next COUNTs of the connections, uplink then downlink for each:
    /// `[[NextCount; 2]; N]` for `N` connections.
    type Counts: AsRef<[[NextCount; 2]]> + AsMut<[[NextCount; 2]]> + Copy + Default;
    /// The name of the system in an error.
    const NAME: &'static str;
    /// The null algorithms, of which the integrity one goes with the
    /// ciphering one alone.
    const NULL_INTEGRITY: Self::Integrity;
    const NULL_CIPHERING: Self::Ciphering;

    /// The place of the COUNTs of `connection`.
    fn place(connection: Self::Connection) -> usize;
    /// The algorithms of the security crate that the codes select.
    fn algorithms(
        integrity: Self::Integrity,
        ciphering: Self::Ciphering,
    ) -> Result<(IntegrityAlgorithm, CipheringAlgorithm), NasError>;
    /// The message authentication code of `octets`.
    fn mac(
        key: &Self::IntegrityKey,
        count: NasCount,
        connection: Self::Connection,
        direction: Direction,
        octets: &[u8],
        algorithm: IntegrityAlgorithm,
    ) -> u32;
    /// Cipher or decipher `octets`.
    fn cipher(
        key: &Self::CipheringKey,
        count: NasCount,
        connection: Self::Connection,
        direction: Direction,
        octets: &mut [u8],
        algorithm: CipheringAlgorithm,
    );
}

/// What a NAS security context of either system is: its keys, its two
/// algorithms and the next NAS COUNT of each direction of each NAS
/// connection, and what TS 24.501 §4.4.3 and TS 24.301 §4.4.3 do with them
/// alike. Each system builds its messages and its headers around it.
pub(crate) struct Core<S: System> {
    /// KNASint and KNASenc, in one place of the heap.
    pub(crate) keys: Box<Keys<S::IntegrityKey, S::CipheringKey>>,
    /// The algorithms by their codes, as they were selected.
    pub(crate) integrity_code: S::Integrity,
    pub(crate) ciphering_code: S::Ciphering,
    /// The algorithms that the codes select.
    pub(crate) integrity: IntegrityAlgorithm,
    pub(crate) ciphering: CipheringAlgorithm,
    /// The next COUNT of each NAS connection: uplink, then downlink.
    counts: S::Counts,
}

impl<S: System> Clone for Core<S> {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            integrity_code: self.integrity_code,
            ciphering_code: self.ciphering_code,
            integrity: self.integrity,
            ciphering: self.ciphering,
            counts: self.counts,
        }
    }
}

impl<S: System> Core<S> {
    /// The algorithms that the codes select: a reserved code selects none,
    /// and the null integrity algorithm is only used for unauthenticated
    /// emergency sessions, which select the null cipher (TS 33.501 §5.2.3,
    /// TS 33.401 §5.1.4.1).
    pub(crate) fn algorithms(
        integrity: S::Integrity,
        ciphering: S::Ciphering,
    ) -> Result<(IntegrityAlgorithm, CipheringAlgorithm), NasError> {
        let algorithms = S::algorithms(integrity, ciphering)?;
        if integrity == S::NULL_INTEGRITY && ciphering != S::NULL_CIPHERING {
            return Err(NasError::EncodingError(format!(
                "{} {integrity:?} requires {:?}",
                S::NAME,
                S::NULL_CIPHERING
            )));
        }
        Ok(algorithms)
    }

    /// A context of keys that are in their place, with every COUNT at zero.
    pub(crate) fn new(
        keys: Box<Keys<S::IntegrityKey, S::CipheringKey>>,
        integrity_code: S::Integrity,
        ciphering_code: S::Ciphering,
    ) -> Result<Self, NasError> {
        let (integrity, ciphering) = Self::algorithms(integrity_code, ciphering_code)?;
        Ok(Self {
            keys,
            integrity_code,
            ciphering_code,
            integrity,
            ciphering,
            counts: S::Counts::default(),
        })
    }

    /// A context of fresh keys that `derive` makes for the algorithms that
    /// the codes select, with every COUNT at zero. What the way of the keys
    /// to their place leaves on the stack is cleared.
    pub(crate) fn derived(
        integrity_code: S::Integrity,
        ciphering_code: S::Ciphering,
        derive: impl FnOnce(
            IntegrityAlgorithm,
            CipheringAlgorithm,
        ) -> Keys<S::IntegrityKey, S::CipheringKey>,
    ) -> Result<Self, NasError> {
        let (integrity, ciphering) = Self::algorithms(integrity_code, ciphering_code)?;
        let keys = wiped(|| Box::new(derive(integrity, ciphering)));
        Self::new(keys, integrity_code, ciphering_code)
    }

    /// The keys that `derive` makes for other algorithms, in the place of the
    /// keys of the context, which are wiped as they are dropped. The COUNTs
    /// stay.
    pub(crate) fn reselect(
        &mut self,
        integrity_code: S::Integrity,
        ciphering_code: S::Ciphering,
        derive: impl FnOnce(
            IntegrityAlgorithm,
            CipheringAlgorithm,
        ) -> Keys<S::IntegrityKey, S::CipheringKey>,
    ) -> Result<(), NasError> {
        let (integrity, ciphering) = Self::algorithms(integrity_code, ciphering_code)?;
        let keys = &mut *self.keys;
        wiped(|| *keys = derive(integrity, ciphering));
        self.integrity_code = integrity_code;
        self.ciphering_code = ciphering_code;
        self.integrity = integrity;
        self.ciphering = ciphering;
        Ok(())
    }

    /// Whether the COUNTs wrap around: with the null integrity algorithm
    /// alone (TS 24.501 and TS 24.301 §4.4.3.5).
    pub(crate) fn wraps(&self) -> bool {
        self.integrity_code == S::NULL_INTEGRITY
    }

    /// The next COUNT of a direction of a connection.
    pub(crate) fn count(&self, direction: Direction, connection: S::Connection) -> NextCount {
        self.counts.as_ref()[S::place(connection)][direction as usize]
    }

    /// The next COUNT of a direction of a connection, to set it.
    pub(crate) fn count_mut(
        &mut self,
        direction: Direction,
        connection: S::Connection,
    ) -> &mut NextCount {
        &mut self.counts.as_mut()[S::place(connection)][direction as usize]
    }

    /// The message of `count` is sent or verified: the next COUNT of its
    /// direction is the one after it.
    pub(crate) fn advance(
        &mut self,
        direction: Direction,
        connection: S::Connection,
        count: NasCount,
    ) {
        *self.count_mut(direction, connection) = NextCount::after(count, self.wraps());
    }

    /// The code of `octets` with `count`.
    pub(crate) fn mac(
        &self,
        count: NasCount,
        connection: S::Connection,
        direction: Direction,
        octets: &[u8],
    ) -> u32 {
        S::mac(
            &self.keys.integrity,
            count,
            connection,
            direction,
            octets,
            self.integrity,
        )
    }

    /// Cipher or decipher `octets` with `count`.
    pub(crate) fn cipher(
        &self,
        count: NasCount,
        connection: S::Connection,
        direction: Direction,
        octets: &mut [u8],
    ) {
        S::cipher(
            &self.keys.ciphering,
            count,
            connection,
            direction,
            octets,
            self.ciphering,
        );
    }

    /// Whether `received` is the code that `expected` is, in a time that does
    /// not depend on where they differ: always with the null integrity
    /// algorithm, which has no code. The expected code is not reported: it
    /// would let an observer of the error send the same octets with it.
    pub(crate) fn check(&self, received: &[u8], expected: &[u8]) -> Result<(), NasError> {
        match self.wraps() || constant_time_eq(received, expected) {
            true => Ok(()),
            false => Err(NasError::IntegrityCheckFailed),
        }
    }

    /// The message of `prefix`, then the code, the sequence number and
    /// `payload`, protected with the next COUNT of the direction: `cipher`
    /// ciphers the payload first, if it is to be, and the code is that of
    /// the sequence number and of what follows it (TS 33.501 §6.4.3.1, TS
    /// 33.401 §8.1.1). The COUNT advances once the message is made.
    pub(crate) fn seal(
        &mut self,
        prefix: &[u8],
        mut payload: Vec<u8>,
        direction: Direction,
        connection: S::Connection,
        cipher: impl FnOnce(&Self, NasCount, &mut Vec<u8>) -> Result<(), NasError>,
    ) -> Result<Vec<u8>, NasError> {
        let count = self.count(direction, connection).to_send()?;
        cipher(self, count, &mut payload)?;
        let mut message = Vec::with_capacity(prefix.len() + 5 + payload.len());
        message.extend_from_slice(prefix);
        message.extend_from_slice(&[0; 4]);
        message.push(count.sequence_number());
        message.extend_from_slice(&payload);
        let at = prefix.len();
        let mac = self.mac(count, connection, direction, &message[at + 4..]);
        message[at..at + 4].copy_from_slice(&mac.to_be_bytes());
        self.advance(direction, connection, count);
        Ok(message)
    }

    /// Verify a received message whose code is after the `prefix` octets of
    /// its header, then its sequence number: the COUNT of the message is the
    /// least from the next one of the direction that ends with the number.
    /// The COUNT advances once the code is verified (TS 24.501 and TS 24.301
    /// §4.4.3.3), whatever is then found in the message; it is returned.
    pub(crate) fn open(
        &mut self,
        message: &[u8],
        prefix: usize,
        direction: Direction,
        connection: S::Connection,
    ) -> Result<NasCount, NasError> {
        let (Some(received), Some(&sequence_number)) =
            (message.get(prefix..prefix + 4), message.get(prefix + 4))
        else {
            return Err(NasError::BufferTooShort);
        };
        let wraps = self.wraps();
        let count = self
            .count(direction, connection)
            .received(sequence_number, 8, wraps)?;
        let expected = self.mac(count, connection, direction, &message[prefix + 4..]);
        self.check(received, &expected.to_be_bytes())?;
        self.advance(direction, connection, count);
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
