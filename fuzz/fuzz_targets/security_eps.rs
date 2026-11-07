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
//! The two ends of one direction of an EPS link, each a security context of
//! the same KASME, and what passes between them: messages of the fixtures
//! and octets of the fuzzer, protected, then delivered once, again, out of
//! order, changed, cut short, or not at all, and in the uplink the short
//! SERVICE REQUEST, whose sequence number has five bits and whose code
//! sixteen.
//!
//! The ends start at any NAS COUNT, near the last one too, and the receiver
//! with a replay window of any size, which the fuzzer changes; the two ends
//! select other algorithms of the same KAMF on the way. Each context is
//! held to what `counts.rs` says of its COUNTs, and its codes to those
//! that oxirush-security computes for them, so that every octet that is
//! delivered has one outcome:
//!
//! - a context is made of algorithms that exist, and EIA0 with EEA0 alone;
//! - the sender gives each message the next COUNT, once, and none after the
//!   last but with EIA0, whose COUNT wraps; a message that
//!   it refuses takes none. What it sends has the header, the sequence
//!   number and the code of that COUNT, and its payload deciphers to the
//!   message;
//! - the receiver takes a message whose code is that of the COUNT that it
//!   estimates from its sequence number, or of one below the highest that
//!   its window holds and did not take, and no other: a replay, a change
//!   of a covered octet or a message of keys that are no longer the
//!   context's are refused, and leave the context as it was. A SERVICE
//!   REQUEST is estimated from its five bits, and no window holds one.
//!   A message that it takes is the one that was sent, or one that it
//!   refuses for what it is (`AuthenticMessageRefused`) with its COUNT
//!   used.

mod counts;

use counts::{LIMIT, Receiving, next_after, restored};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use oxirush_nas::nas_eps::{CipheringAlgorithm, IntegrityAlgorithm, KAsme, NasEpsMessage, NasEpsSecurityHeaderType, NasSecurityContext, NasServiceRequest};
use oxirush_nas::{Direction, NasCount, NasError};
use oxirush_security::nas_eps::{KNasEnc, KNasInt, derive_knas_enc, derive_knas_int};
use std::sync::LazyLock;

/// The plain messages of the fixtures, which the sender protects.
static PLAIN: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    let fixtures = include_str!("../../tests/fixtures/nas-eps.tsv");
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
    kasme: [u8; 32],
    integrity: u8,
    ciphering: u8,
    downlink: bool,
    /// The next COUNT of the direction at the sender
    sender: Start,
    /// The next COUNT of the direction at the receiver
    receiver: Start,
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
    Send { message: u16, header: u8 },
    /// The sender protects a message of the fixtures again and again
    Burst { message: u16, header: u8, times: u8 },
    /// The sender protects octets as they are
    Opaque { octets: Vec<u8>, header: u8 },
    /// A message is delivered
    Deliver { sent: u16 },
    /// Messages that were sent one after the other are delivered in the
    /// other order, from the last
    Reorder { sent: u16, times: u8 },
    /// A message with an octet changed
    Corrupt { sent: u16, at: u16, xor: u8 },
    /// A message cut short
    Cut { sent: u16, length: u16 },
    /// Octets of the fuzzer
    Octets(Vec<u8>),
    /// The UE sends a SERVICE REQUEST of a key set identifier
    ServiceRequest { ksi: u8 },
    /// A SERVICE REQUEST is delivered, with a field changed or not
    DeliverServiceRequest {
        sent: u16,
        change: Option<(u8, u16)>,
    },
    /// The receiver sets its replay window
    Window(u8),
    /// Both ends select other algorithms of the KASME
    Reselect { integrity: u8, ciphering: u8 },
}

/// A message that the sender protected.
struct Sent {
    octets: Vec<u8>,
    count: u32,
    header: NasEpsSecurityHeaderType,
    /// The keys it was protected with, by their number
    keys: u32,
    /// The plain message, when it was one that the sender checked
    plain: Option<Vec<u8>>,
}

/// The two ends, and what they are by `counts.rs` and oxirush-security.
struct Ends {
    kasme: KAsme,
    sender: NasSecurityContext,
    receiver: NasSecurityContext,
    direction: Direction,
    /// The next COUNT of the direction at the sender
    sending: u32,
    receiving: Receiving,
    window: u8,
    wraps: bool,
    integrity: oxirush_security::IntegrityAlgorithm,
    ciphering: oxirush_security::CipheringAlgorithm,
    knas_int: KNasInt,
    knas_enc: KNasEnc,
    keys: u32,
    sent: Vec<Sent>,
    requests: Vec<NasServiceRequest>,
}

/// The algorithms that the codes select, as a context is made of them: a
/// reserved code is none, and EIA0 goes with EEA0 alone.
fn algorithms(
    integrity: u8,
    ciphering: u8,
) -> Option<(
    oxirush_security::IntegrityAlgorithm,
    oxirush_security::CipheringAlgorithm,
)> {
    let pair = (
        oxirush_security::IntegrityAlgorithm::try_from(integrity).ok()?,
        oxirush_security::CipheringAlgorithm::try_from(ciphering).ok()?,
    );
    (integrity != 0 || ciphering == 0).then_some(pair)
}

fn codes(integrity: u8, ciphering: u8) -> (IntegrityAlgorithm, CipheringAlgorithm) {
    (
        IntegrityAlgorithm::from_u8(integrity % 8).unwrap(),
        CipheringAlgorithm::from_u8(ciphering % 8).unwrap(),
    )
}

/// A header type of a message by a number of the fuzzer: the plain one
/// too, which protects nothing, and that of a partially ciphered CONTROL
/// PLANE SERVICE REQUEST.
fn header(number: u8) -> NasEpsSecurityHeaderType {
    NasEpsSecurityHeaderType::try_from(number % 6).unwrap()
}

fn ciphers(header: NasEpsSecurityHeaderType) -> bool {
    matches!(
        header,
        NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered
            | NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
    )
}

impl Ends {
    fn security_direction(&self) -> oxirush_security::Direction {
        match self.direction {
            Direction::Uplink => oxirush_security::Direction::Uplink,
            Direction::Downlink => oxirush_security::Direction::Downlink,
        }
    }

    /// The code of `covered` with `count`.
    fn mac(&self, count: u32, covered: &[u8]) -> u32 {
        let count = NasCount::new(count).unwrap();
        let direction = self.security_direction();
        oxirush_security::nas_eps::nas_mac(
            &self.knas_int,
            count,
            direction,
            covered,
            self.integrity,
        )
    }

    /// The short code of a SERVICE REQUEST with `count`, whose first two
    /// octets are `first` and `ksi_and_sequence_number`.
    fn short_mac(&self, count: u32, first: u8, ksi_and_sequence_number: u8) -> u16 {
        oxirush_security::nas_eps::service_request_short_mac_with_header(
            &self.knas_int,
            NasCount::new(count).unwrap(),
            oxirush_security::Direction::Uplink,
            first,
            ksi_and_sequence_number,
            self.integrity,
        )
        .unwrap()
    }

    /// Each next COUNT of the two ends is the one of the model.
    fn check_counts(&self) {
        let other = match self.direction {
            Direction::Uplink => Direction::Downlink,
            Direction::Downlink => Direction::Uplink,
        };
        let some = |count: u32| NasCount::new(count).ok();
        assert_eq!(
            self.sender.nas_count(self.direction),
            some(self.sending),
            "sender"
        );
        let next = self.receiving.next;
        assert_eq!(
            self.receiver.nas_count(self.direction),
            some(next),
            "receiver"
        );
        // The other direction is that of the restored contexts
        assert_eq!(self.sender.nas_count(other), Some(NasCount::ZERO));
        assert_eq!(self.receiver.nas_count(other), Some(NasCount::ZERO));
        assert_eq!(self.receiver.replay_window(), self.window);
    }

    /// What the sender gives back for a message of `header`: the COUNT that
    /// it took, its header, sequence number and code, and a payload that
    /// deciphers to `plain`.
    fn sent(
        &mut self,
        result: Result<Vec<u8>, NasError>,
        header: NasEpsSecurityHeaderType,
        plain: Vec<u8>,
        checked: bool,
    ) {
        let next = self.sending;
        let octets = match result {
            Ok(octets) => octets,
            Err(NasError::NasCountExhausted) => {
                assert_eq!(next, LIMIT, "exhausted at COUNT {next}");
                return;
            }
            Err(_) => return,
        };
        assert!(next < LIMIT, "a message sent after the last COUNT");
        assert_eq!(octets[0], (header as u8) << 4 | 0x07);
        assert_eq!(octets[5], next as u8, "sequence number of COUNT {next}");
        let mac = u32::from_be_bytes(octets[1..5].try_into().unwrap());
        assert_eq!(mac, self.mac(next, &octets[5..]), "code of COUNT {next}");
        let mut payload = octets[6..].to_vec();
        if ciphers(header) {
            oxirush_security::nas_eps::nas_cipher(
                &self.knas_enc,
                NasCount::new(next).unwrap(),
                self.security_direction(),
                &mut payload,
                self.ciphering,
            );
        }
        // A partially ciphered message has the value of its container
        // ciphered alone
        if header != NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage {
            assert_eq!(payload, plain, "the payload of COUNT {next}");
        }
        self.sending = next_after(next, self.wraps);
        self.sent.push(Sent {
            octets,
            count: next,
            header,
            keys: self.keys,
            plain: checked.then_some(plain),
        });
    }

    /// The COUNT that the receiver takes `octets` with, and whether its
    /// window holds it; none for octets that it refuses.
    fn predict(&self, octets: &[u8]) -> Option<(u32, bool)> {
        // The security header: the discriminator of EMM, a header type that
        // protects a message, a code and a sequence number
        let protects = |header: u8| matches!(header, 1..=5 | 11);
        if octets.len() < 6 || octets[0] & 0x0f != 0x07 || !protects(octets[0] >> 4) {
            return None;
        }
        let mac = u32::from_be_bytes(octets[1..5].try_into().unwrap());
        let (sequence_number, covered) = (octets[5], &octets[5..]);
        if !self.wraps
            && let Some(count) = self.receiving.below(self.window, sequence_number)
            && self.mac(count, covered) == mac
        {
            return Some((count, true));
        }
        let count = self.receiving.estimate(sequence_number, 8, self.wraps)?;
        (self.wraps || self.mac(count, covered) == mac).then_some((count, false))
    }

    /// The receiver is given `octets`, which may be the message `sent` as
    /// it was sent.
    fn deliver(&mut self, octets: &[u8], sent: Option<usize>) {
        let predicted = self.predict(octets);
        let result = self.receiver.unprotect(octets, self.direction);
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
            true => self.receiving.take(count),
            false => self.receiving.advance(count, self.wraps),
        }

        // The message that was sent, with the keys it was sent with
        let Some(sent) = sent.map(|at| &self.sent[at]) else {
            return;
        };
        let genuine = sent.keys == self.keys && (count == sent.count || self.wraps);
        let (Some(plain), true) = (&sent.plain, genuine) else {
            return;
        };
        match &result {
            Ok(verified) => {
                let message = NasEpsMessage::decode_with_direction(plain, self.direction).unwrap();
                assert_eq!(verified.message, message);
                assert_eq!(verified.security_header_type, sent.header);
            }
            Err(error) => panic!("a message that the sender checked is refused: {error}"),
        }
    }

    /// The receiver is given a SERVICE REQUEST.
    fn deliver_service_request(&mut self, request: &NasServiceRequest) {
        let header = request.security_header_type;
        let first = header << 4 | 0x07;
        let ksi_and_sequence_number = request.ksi_and_sequence_number;
        let predicted = match (12..=15).contains(&header) && ksi_and_sequence_number >> 5 != 7 {
            true => (self.receiving)
                .estimate(ksi_and_sequence_number & 0x1f, 5, self.wraps)
                .filter(|&count| {
                    self.wraps
                        || self.short_mac(count, first, ksi_and_sequence_number)
                            == request.message_authentication_code
                }),
            false => None,
        };
        let result = self.receiver.unprotect_service_request(request);
        match (predicted, result) {
            (Some(count), Ok(verified)) => assert_eq!(verified.get(), count),
            (Some(count), Err(error)) => {
                panic!("a SERVICE REQUEST whose code is that of COUNT {count} is refused: {error}")
            }
            (None, Ok(count)) => {
                panic!("a SERVICE REQUEST that no COUNT verifies is taken: {count:?}")
            }
            (None, Err(_)) => {}
        }
        if let Some(count) = predicted {
            self.receiving.advance(count, self.wraps);
        }
    }

    fn step(&mut self, step: &Step) {
        let pick = |length: usize, number: u16| (length > 0).then(|| usize::from(number) % length);
        match step {
            Step::Send {
                message,
                header: number,
            } => {
                let plain = PLAIN[usize::from(*message) % PLAIN.len()].clone();
                let header = header(*number);
                let result = self
                    .sender
                    .protect_bytes(plain.clone(), header, self.direction);
                self.sent(result, header, plain, true);
            }
            Step::Burst {
                message,
                header,
                times,
            } => {
                for _ in 0..times % 80 {
                    let send = Step::Send {
                        message: *message,
                        header: *header,
                    };
                    self.step(&send);
                }
            }
            Step::Reorder { sent, times } => {
                if let Some(first) = pick(self.sent.len(), *sent) {
                    let last = (first + usize::from(*times % 80)).min(self.sent.len() - 1);
                    for at in (first..=last).rev() {
                        let octets = self.sent[at].octets.clone();
                        self.deliver(&octets, Some(at));
                    }
                }
            }
            Step::Opaque {
                octets,
                header: number,
            } => {
                let header = header(*number);
                let result =
                    (self.sender).protect_opaque_payload(octets.clone(), header, self.direction);
                if !(1..=4).contains(&(header as u8)) {
                    assert!(result.is_err(), "opaque octets sent under {header:?}");
                }
                self.sent(result, header, octets.clone(), false);
            }
            Step::Deliver { sent } => {
                if let Some(at) = pick(self.sent.len(), *sent) {
                    let octets = self.sent[at].octets.clone();
                    self.deliver(&octets, Some(at));
                }
            }
            Step::Corrupt { sent, at, xor } => {
                if let Some(which) = pick(self.sent.len(), *sent) {
                    let mut octets = self.sent[which].octets.clone();
                    let at = usize::from(*at) % octets.len();
                    octets[at] ^= (*xor).max(1);
                    self.deliver(&octets, None);
                }
            }
            Step::Cut { sent, length } => {
                if let Some(which) = pick(self.sent.len(), *sent) {
                    let mut octets = self.sent[which].octets.clone();
                    octets.truncate(usize::from(*length) % octets.len());
                    self.deliver(&octets, None);
                }
            }
            Step::Octets(octets) => self.deliver(octets, None),
            Step::ServiceRequest { ksi } => {
                if self.direction != Direction::Uplink {
                    return;
                }
                let ksi = ksi % 8;
                let next = self.sending;
                match self.sender.protect_service_request(ksi) {
                    Ok(request) => {
                        assert!(ksi < 7 && next < LIMIT, "KSI {ksi}, COUNT {next}");
                        let ksi_and_sequence_number = ksi << 5 | (next & 0x1f) as u8;
                        assert_eq!(request.security_header_type, 12);
                        assert_eq!(request.ksi_and_sequence_number, ksi_and_sequence_number);
                        let mac = self.short_mac(next, 0xc7, ksi_and_sequence_number);
                        assert_eq!(request.message_authentication_code, mac, "COUNT {next}");
                        self.sending = next_after(next, self.wraps);
                        self.requests.push(request);
                    }
                    Err(NasError::NasCountExhausted) => assert!(ksi < 7 && next == LIMIT),
                    Err(error) => assert!(ksi == 7, "{error}"),
                }
            }
            Step::DeliverServiceRequest { sent, change } => {
                if let Some(at) = pick(self.requests.len(), *sent) {
                    let mut request = self.requests[at].clone();
                    match change {
                        Some((0, xor)) => request.security_header_type ^= (*xor as u8) & 0x0f,
                        Some((1, xor)) => request.ksi_and_sequence_number ^= *xor as u8,
                        Some((_, xor)) => request.message_authentication_code ^= *xor,
                        None => {}
                    }
                    self.deliver_service_request(&request);
                }
            }
            Step::Window(size) => {
                let size = size % 72;
                let result = self.receiver.set_replay_window(size);
                assert_eq!(result.is_ok(), size <= 64, "a window of {size}");
                if result.is_ok() {
                    self.receiving.resize(self.window);
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
                let (i, c) = codes(integrity, ciphering);
                let sender = self.sender.reselect_algorithms(&self.kasme, i, c);
                let receiver = self.receiver.reselect_algorithms(&self.kasme, i, c);
                let expected = algorithms(integrity, ciphering);
                assert_eq!(sender.is_ok(), expected.is_some(), "{i:?} {c:?}");
                assert_eq!(receiver.is_ok(), expected.is_some(), "{i:?} {c:?}");
                if let Some((integrity, ciphering)) = expected {
                    self.integrity = integrity;
                    self.ciphering = ciphering;
                    self.knas_int = derive_knas_int(&self.kasme, integrity);
                    self.knas_enc = derive_knas_enc(&self.kasme, ciphering);
                    self.keys += 1;
                }
            }
        }
    }
}

/// A context restored with the next COUNT `start` of `direction`, and zero
/// in the other direction.
fn context(
    kasme: &KAsme,
    (integrity, ciphering): (IntegrityAlgorithm, CipheringAlgorithm),
    direction: Direction,
    start: Start,
) -> Result<NasSecurityContext, NasError> {
    let count = start.count().map(|count| NasCount::new(count).unwrap());
    let counts = match direction {
        Direction::Uplink => (count, Some(NasCount::ZERO)),
        Direction::Downlink => (Some(NasCount::ZERO), count),
    };
    NasSecurityContext::restore_from_kasme(kasme, integrity, ciphering, counts)
}

fuzz_target!(|link: Link| {
    let (integrity, ciphering) = (link.integrity % 8, link.ciphering % 8);
    let kasme = KAsme::new(&link.kasme);
    let direction = match link.downlink {
        true => Direction::Downlink,
        false => Direction::Uplink,
    };
    let selected = codes(integrity, ciphering);
    let sender = context(&kasme, selected, direction, link.sender);
    let receiver = context(&kasme, selected, direction, link.receiver);
    let expected = algorithms(integrity, ciphering);
    assert_eq!(sender.is_ok(), expected.is_some(), "{selected:?}");
    assert_eq!(receiver.is_ok(), expected.is_some(), "{selected:?}");
    let (Ok(sender), Ok(mut receiver), Some((integrity, ciphering))) = (sender, receiver, expected)
    else {
        return;
    };
    let window = link.window % 65;
    receiver.set_replay_window(window).unwrap();
    let mut receiving = Receiving::new(restored(link.receiver.count()));
    receiving.resize(0);
    let mut ends = Ends {
        knas_int: derive_knas_int(&kasme, integrity),
        knas_enc: derive_knas_enc(&kasme, ciphering),
        kasme,
        sender,
        receiver,
        direction,
        sending: restored(link.sender.count()),
        receiving,
        window,
        wraps: integrity == oxirush_security::IntegrityAlgorithm::Null,
        integrity,
        ciphering,
        keys: 0,
        sent: Vec::new(),
        requests: Vec::new(),
    };
    ends.check_counts();
    for step in link.steps.iter().take(64) {
        ends.step(step);
        ends.check_counts();
    }
});
