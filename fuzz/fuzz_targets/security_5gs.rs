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

#![no_main]
//! The two ends of one direction of a 5GS link, each a security context of
//! the same KAMF, and what passes between them: messages of the fixtures
//! and octets of the fuzzer, protected for either access, then delivered
//! once, again, out of order, changed, cut short, or not at all.
//!
//! The ends start at any NAS COUNT, near the last one too, and the receiver
//! with a replay window of any size, which the fuzzer changes; the two ends
//! select other algorithms of the same KAMF on the way. Each context is
//! held to what `counts.rs` says of its COUNTs, and its codes to those
//! that oxirush-security computes for them, so that every octet that is
//! delivered has one outcome:
//!
//! - a context is made of algorithms that exist, and NIA0 with NEA0 alone;
//! - the sender gives each message the next COUNT of its access, once, and
//!   none after the last but with NIA0, whose COUNT wraps; a message that
//!   it refuses takes none. What it sends has the header, the sequence
//!   number and the code of that COUNT, and its payload deciphers to the
//!   message;
//! - the receiver takes a message whose code is that of the COUNT that it
//!   estimates from its sequence number, or of one below the highest that
//!   its window holds and did not take, and no other: a replay, a change
//!   of a covered octet, a message of the other access or of keys that are
//!   no longer the context's are refused, and leave the context as it was.
//!   A message that it takes is the one that was sent, or one that it
//!   refuses for what it is (`AuthenticMessageRefused`) with its COUNT
//!   used.

mod counts;

use counts::{LIMIT, Receiving, next_after, restored};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use oxirush_nas::nas_5gs::{
    KAmf, Nas5gsMessage, Nas5gsSecurityHeaderType, NasConnection, NasSecurityContext,
};
use oxirush_nas::{Direction, NasCount, NasError};
use oxirush_security::nas_5gs::{KNasEnc, KNasInt, derive_knas_enc, derive_knas_int};
use std::sync::LazyLock;

/// The plain messages of the fixtures, which the sender protects.
static PLAIN: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    let fixtures = include_str!("../../tests/fixtures/nas-5gs.tsv");
    (fixtures.lines())
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split('\t').nth(1))
        .map(unhex)
        .collect()
});

fn unhex(text: &str) -> Vec<u8> {
    let digit = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    (text.as_bytes().chunks(2))
        .map(|pair| digit(pair[0]) << 4 | pair.get(1).map_or(0, |low| digit(*low)))
        .collect()
}

/// The link and what passes on it.
#[derive(Arbitrary, Debug)]
struct Link {
    kamf: [u8; 32],
    integrity: u8,
    ciphering: u8,
    downlink: bool,
    /// The next COUNT of the direction at the sender, for each access
    sender: [Start; 2],
    /// The next COUNT of the direction at the receiver, for each access
    receiver: [Start; 2],
    window: u8,
    steps: Vec<Step>,
}

/// The next COUNT that an end starts with.
#[derive(Arbitrary, Debug, Clone, Copy)]
enum Start {
    Zero,
    Low(u16),
    /// Below the last COUNT, by less than two sequence numbers
    High(u16),
    /// Every COUNT used
    Exhausted,
}

impl Start {
    fn count(self) -> Option<u32> {
        match self {
            Start::Zero => Some(0),
            Start::Low(count) => Some(u32::from(count)),
            Start::High(below) => Some(LIMIT - 1 - u32::from(below) % 512),
            Start::Exhausted => None,
        }
    }
}

/// What happens on the link. A message is one that was sent, which the
/// number picks.
#[derive(Arbitrary, Debug)]
enum Step {
    /// The sender protects a message of the fixtures
    Send {
        message: u16,
        header: u8,
        non_3gpp: bool,
    },
    /// The sender protects a message of the fixtures again and again
    Burst {
        message: u16,
        header: u8,
        non_3gpp: bool,
        times: u8,
    },
    /// The sender protects octets as they are
    Opaque {
        octets: Vec<u8>,
        header: u8,
        non_3gpp: bool,
    },
    /// A message is delivered, on its access or on the other one
    Deliver { sent: u16, other_access: bool },
    /// Messages that were sent one after the other are delivered in the
    /// other order, from the last
    Reorder { sent: u16, times: u8 },
    /// A message with an octet changed
    Corrupt { sent: u16, at: u16, xor: u8 },
    /// A message cut short
    Cut { sent: u16, length: u16 },
    /// Octets of the fuzzer
    Octets { octets: Vec<u8>, non_3gpp: bool },
    /// The receiver sets its replay window
    Window(u8),
    /// Both ends select other algorithms of the KAMF
    Reselect { integrity: u8, ciphering: u8 },
}

/// A message that the sender protected.
struct Sent {
    octets: Vec<u8>,
    count: u32,
    access: usize,
    header: Nas5gsSecurityHeaderType,
    /// The keys it was protected with, by their number
    keys: u32,
    /// The plain message, when it was one that the sender checked
    plain: Option<Vec<u8>>,
}

const ACCESSES: [NasConnection; 2] = [NasConnection::ThreeGpp, NasConnection::Non3Gpp];

/// The two ends, and what they are by `counts.rs` and oxirush-security.
struct Ends {
    kamf: KAmf,
    sender: NasSecurityContext,
    receiver: NasSecurityContext,
    direction: Direction,
    /// The next COUNT of the direction at the sender, for each access
    sending: [u32; 2],
    receiving: [Receiving; 2],
    window: u8,
    wraps: bool,
    integrity: oxirush_security::identity::Algorithm,
    ciphering: oxirush_security::identity::Algorithm,
    knas_int: KNasInt,
    knas_enc: KNasEnc,
    keys: u32,
    sent: Vec<Sent>,
}

/// The algorithms that the codes select, as a context is made of them: a
/// reserved code is none, and NIA0 goes with NEA0 alone.
fn algorithms(
    integrity: u8,
    ciphering: u8,
) -> Option<(
    oxirush_security::identity::Algorithm,
    oxirush_security::identity::Algorithm,
)> {
    let pair = (
        oxirush_security::identity::Algorithm::try_from(integrity).ok()?,
        oxirush_security::identity::Algorithm::try_from(ciphering).ok()?,
    );
    (integrity != 0 || ciphering == 0).then_some(pair)
}

/// The algorithms of the codes, whatever goes with what: a reserved code is
/// none, and no context can be asked for it.
fn codes(
    integrity: u8,
    ciphering: u8,
) -> Option<(
    oxirush_security::identity::Algorithm,
    oxirush_security::identity::Algorithm,
)> {
    Some((
        oxirush_security::identity::Algorithm::try_from(integrity).ok()?,
        oxirush_security::identity::Algorithm::try_from(ciphering).ok()?,
    ))
}

/// A header type by a number of the fuzzer: the plain one too, which
/// protects nothing.
fn header(number: u8) -> Nas5gsSecurityHeaderType {
    Nas5gsSecurityHeaderType::try_from(number % 5).unwrap()
}

fn ciphers(header: Nas5gsSecurityHeaderType) -> bool {
    matches!(
        header,
        Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered
            | Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
    )
}

impl Ends {
    fn security_direction(&self) -> oxirush_security::Direction {
        match self.direction {
            Direction::Uplink => oxirush_security::Direction::Uplink,
            Direction::Downlink => oxirush_security::Direction::Downlink,
        }
    }

    /// The code of `covered` with `count` on `access`.
    fn mac(&self, count: u32, access: usize, covered: &[u8]) -> u32 {
        let count = NasCount::new(count).unwrap();
        let direction = self.security_direction();
        oxirush_security::nas_5gs::nas_mac(
            &self.knas_int,
            count,
            ACCESSES[access],
            direction,
            covered,
            self.integrity,
        )
    }

    /// Each next COUNT of the two ends is the one of the model.
    fn check_counts(&self) {
        let other = match self.direction {
            Direction::Uplink => Direction::Downlink,
            Direction::Downlink => Direction::Uplink,
        };
        let some = |count: u32| NasCount::new(count).ok();
        for (access, connection) in ACCESSES.into_iter().enumerate() {
            let sending = self.sender.nas_count(self.direction, connection);
            assert_eq!(
                sending,
                some(self.sending[access]),
                "sender, {connection:?}"
            );
            let receiving = self.receiver.nas_count(self.direction, connection);
            let next = self.receiving[access].next;
            assert_eq!(receiving, some(next), "receiver, {connection:?}");
            // The other direction is that of the restored contexts
            assert_eq!(
                self.sender.nas_count(other, connection),
                Some(NasCount::ZERO)
            );
            assert_eq!(
                self.receiver.nas_count(other, connection),
                Some(NasCount::ZERO)
            );
        }
        assert_eq!(self.receiver.replay_window(), self.window);
    }

    /// What the sender gives back for a message of `header` on `access`:
    /// the COUNT that it took, its header, sequence number and code, and a
    /// payload that deciphers to `plain`.
    fn sent(
        &mut self,
        result: Result<Vec<u8>, NasError>,
        header: Nas5gsSecurityHeaderType,
        access: usize,
        plain: Vec<u8>,
        checked: bool,
    ) {
        let next = self.sending[access];
        let octets = match result {
            Ok(octets) => octets,
            Err(NasError::NasCountExhausted) => {
                assert_eq!(next, LIMIT, "exhausted at COUNT {next}");
                return;
            }
            Err(_) => return,
        };
        assert!(next < LIMIT, "a message sent after the last COUNT");
        assert_eq!(octets[..2], [0x7e, header as u8]);
        assert_eq!(octets[6], next as u8, "sequence number of COUNT {next}");
        let mac = u32::from_be_bytes(octets[2..6].try_into().unwrap());
        assert_eq!(
            mac,
            self.mac(next, access, &octets[6..]),
            "code of COUNT {next}"
        );
        let mut payload = octets[7..].to_vec();
        if ciphers(header) {
            oxirush_security::nas_5gs::nas_cipher(
                &self.knas_enc,
                NasCount::new(next).unwrap(),
                ACCESSES[access],
                self.security_direction(),
                &mut payload,
                self.ciphering,
            );
        }
        assert_eq!(payload, plain, "the payload of COUNT {next}");
        self.sending[access] = next_after(next, self.wraps);
        self.sent.push(Sent {
            octets,
            count: next,
            access,
            header,
            keys: self.keys,
            plain: checked.then_some(plain),
        });
    }

    /// The COUNT that the receiver takes `octets` with on `access`, and
    /// whether its window holds it; none for octets that it refuses.
    fn predict(&self, octets: &[u8], access: usize) -> Option<(u32, bool)> {
        // The security header: the discriminator of 5GMM, a header type
        // that protects, a code, a sequence number, and a payload
        if octets.len() <= 7 || octets[0] != 0x7e || !(1..=4).contains(&(octets[1] & 0x0f)) {
            return None;
        }
        let mac = u32::from_be_bytes(octets[2..6].try_into().unwrap());
        let (sequence_number, covered) = (octets[6], &octets[6..]);
        let receiving = &self.receiving[access];
        if !self.wraps
            && let Some(count) = receiving.below(self.window, sequence_number)
            && self.mac(count, access, covered) == mac
        {
            return Some((count, true));
        }
        let count = receiving.estimate(sequence_number, 8, self.wraps)?;
        (self.wraps || self.mac(count, access, covered) == mac).then_some((count, false))
    }

    /// The receiver is given `octets` on `access`, which may be the message
    /// `sent` as it was sent.
    fn deliver(&mut self, octets: &[u8], access: usize, sent: Option<usize>) {
        let predicted = self.predict(octets, access);
        let result = self
            .receiver
            .unprotect_for_access(octets, self.direction, ACCESSES[access]);
        match (predicted, &result) {
            (Some((count, _)), Ok(verified)) => assert_eq!(verified.count.get(), count),
            (Some(_), Err(NasError::AuthenticMessageRefused { .. })) => {}
            (Some((count, _)), Err(error)) => {
                panic!("octets whose code is that of COUNT {count} are refused: {error}")
            }
            (None, Ok(verified)) => panic!("octets that no COUNT verifies are taken: {verified:?}"),
            (None, Err(error @ NasError::AuthenticMessageRefused { .. })) => {
                panic!("octets that no COUNT verifies use one: {error}")
            }
            (None, Err(_)) => {}
        }
        let Some((count, held)) = predicted else {
            return;
        };
        match held {
            true => self.receiving[access].take(count),
            false => self.receiving[access].advance(count, self.wraps),
        }

        // The message that was sent, with the keys and on the access it was
        // sent with
        let Some(sent) = sent.map(|at| &self.sent[at]) else {
            return;
        };
        let genuine = sent.keys == self.keys && sent.access == access;
        let (Some(plain), true) = (&sent.plain, genuine && (count == sent.count || self.wraps))
        else {
            return;
        };
        match &result {
            Ok(verified) => {
                let message = Nas5gsMessage::decode(plain).unwrap();
                assert_eq!(
                    verified.sent.as_ref().unwrap_or(&verified.message),
                    &message
                );
                assert_eq!(verified.security_header_type, sent.header);
            }
            // An initial NAS message whose container is not one, from a UE
            Err(error) => assert!(
                self.direction == Direction::Uplink
                    && sent.header == Nas5gsSecurityHeaderType::IntegrityProtected,
                "a message that the sender checked is refused: {error}"
            ),
        }
    }

    fn step(&mut self, step: &Step) {
        let pick = |sent: &[Sent], number: u16| {
            (!sent.is_empty()).then(|| usize::from(number) % sent.len())
        };
        match step {
            Step::Send {
                message,
                header: number,
                non_3gpp,
            } => {
                let plain = PLAIN[usize::from(*message) % PLAIN.len()].clone();
                let (access, header) = (usize::from(*non_3gpp), header(*number));
                let result = self.sender.protect_bytes_for_access(
                    plain.clone(),
                    header,
                    self.direction,
                    ACCESSES[access],
                );
                self.sent(result, header, access, plain, true);
            }
            Step::Burst {
                message,
                header,
                non_3gpp,
                times,
            } => {
                for _ in 0..times % 80 {
                    let send = Step::Send {
                        message: *message,
                        header: *header,
                        non_3gpp: *non_3gpp,
                    };
                    self.step(&send);
                }
            }
            Step::Reorder { sent, times } => {
                if let Some(first) = pick(&self.sent, *sent) {
                    let last = (first + usize::from(*times % 80)).min(self.sent.len() - 1);
                    for at in (first..=last).rev() {
                        let (octets, access) = (self.sent[at].octets.clone(), self.sent[at].access);
                        self.deliver(&octets, access, Some(at));
                    }
                }
            }
            Step::Opaque {
                octets,
                header: number,
                non_3gpp,
            } => {
                let (access, header) = (usize::from(*non_3gpp), header(*number));
                let result = self.sender.protect_opaque_payload_for_access(
                    octets.clone(),
                    header,
                    self.direction,
                    ACCESSES[access],
                );
                if header == Nas5gsSecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected {
                    assert!(result.is_err(), "opaque octets sent plain");
                }
                self.sent(result, header, access, octets.clone(), false);
            }
            Step::Deliver { sent, other_access } => {
                if let Some(at) = pick(&self.sent, *sent) {
                    let (octets, access) = (self.sent[at].octets.clone(), self.sent[at].access);
                    self.deliver(&octets, access ^ usize::from(*other_access), Some(at));
                }
            }
            Step::Corrupt { sent, at, xor } => {
                if let Some(which) = pick(&self.sent, *sent) {
                    let mut octets = self.sent[which].octets.clone();
                    let at = usize::from(*at) % octets.len();
                    octets[at] ^= (*xor).max(1);
                    self.deliver(&octets, self.sent[which].access, None);
                }
            }
            Step::Cut { sent, length } => {
                if let Some(which) = pick(&self.sent, *sent) {
                    let mut octets = self.sent[which].octets.clone();
                    octets.truncate(usize::from(*length) % octets.len());
                    self.deliver(&octets, self.sent[which].access, None);
                }
            }
            Step::Octets { octets, non_3gpp } => self.deliver(octets, usize::from(*non_3gpp), None),
            Step::Window(size) => {
                let size = size % 72;
                let result = self.receiver.set_replay_window(size);
                assert_eq!(result.is_ok(), size <= 64, "a window of {size}");
                if result.is_ok() {
                    for receiving in &mut self.receiving {
                        receiving.resize(self.window);
                    }
                    self.window = size;
                }
            }
            Step::Reselect {
                integrity,
                ciphering,
            } => {
                let (integrity, ciphering) = (integrity % 8, ciphering % 8);
                // The null integrity algorithm is for a context of its own,
                // and stays its algorithm
                if (integrity == 0) != self.wraps {
                    return;
                }
                let Some((i, c)) = codes(integrity, ciphering) else {
                    return;
                };
                let sender = self.sender.reselect_algorithms(&self.kamf, i, c);
                let receiver = self.receiver.reselect_algorithms(&self.kamf, i, c);
                let expected = algorithms(integrity, ciphering);
                assert_eq!(sender.is_ok(), expected.is_some(), "{i:?} {c:?}");
                assert_eq!(receiver.is_ok(), expected.is_some(), "{i:?} {c:?}");
                if let Some((integrity, ciphering)) = expected {
                    self.integrity = integrity;
                    self.ciphering = ciphering;
                    self.knas_int = derive_knas_int(&self.kamf, integrity);
                    self.knas_enc = derive_knas_enc(&self.kamf, ciphering);
                    self.keys += 1;
                }
            }
        }
    }
}

/// A context restored with the next COUNT `count` of `direction` on each
/// access, and zero in the other direction.
fn context(
    kamf: &KAmf,
    (integrity, ciphering): (
        oxirush_security::identity::Algorithm,
        oxirush_security::identity::Algorithm,
    ),
    direction: Direction,
    starts: [Start; 2],
) -> Result<NasSecurityContext, NasError> {
    let counts = starts.map(|start| {
        let count = start.count().map(|count| NasCount::new(count).unwrap());
        match direction {
            Direction::Uplink => (count, Some(NasCount::ZERO)),
            Direction::Downlink => (Some(NasCount::ZERO), count),
        }
    });
    NasSecurityContext::restore_from_kamf(kamf, integrity, ciphering, counts[0], counts[1])
}

fuzz_target!(|link: Link| {
    let (integrity, ciphering) = (link.integrity % 8, link.ciphering % 8);
    let kamf = KAmf::new(&link.kamf);
    let direction = match link.downlink {
        true => Direction::Downlink,
        false => Direction::Uplink,
    };
    let Some(selected) = codes(integrity, ciphering) else {
        return;
    };
    let sender = context(&kamf, selected, direction, link.sender);
    let receiver = context(&kamf, selected, direction, link.receiver);
    let expected = algorithms(integrity, ciphering);
    assert_eq!(sender.is_ok(), expected.is_some(), "{selected:?}");
    assert_eq!(receiver.is_ok(), expected.is_some(), "{selected:?}");
    let (Ok(sender), Ok(mut receiver), Some((integrity, ciphering))) = (sender, receiver, expected)
    else {
        return;
    };
    let window = link.window % 65;
    receiver.set_replay_window(window).unwrap();
    let mut ends = Ends {
        knas_int: derive_knas_int(&kamf, integrity),
        knas_enc: derive_knas_enc(&kamf, ciphering),
        kamf,
        sender,
        receiver,
        direction,
        sending: link.sender.map(|start| restored(start.count())),
        receiving: link.receiver.map(|start| {
            let mut receiving = Receiving::new(restored(start.count()));
            receiving.resize(0);
            receiving
        }),
        window,
        wraps: integrity == oxirush_security::identity::Algorithm::Null,
        integrity,
        ciphering,
        keys: 0,
        sent: Vec::new(),
    };
    ends.check_counts();
    for step in link.steps.iter().take(64) {
        ends.step(step);
        ends.check_counts();
    }
});
