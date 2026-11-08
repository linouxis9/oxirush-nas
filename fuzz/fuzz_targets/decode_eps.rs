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
//! Whatever the octets, decoding returns, and what it returns is a message
//! that the codec keeps: it encodes to the octets that it was decoded from.
//!
//! Octets that are the same after a decode and an encode would only show
//! that the encoder writes what the decoder happened to read. This target
//! also holds the message: `decode(encode(decode(octets)))` is the message
//! that `decode(octets)` gave, so that an IE that the decoder drops or the
//! encoder writes otherwise makes the two differ. A message that was
//! decoded is validated and displayed without a panic.
//!
//! The receiver of TS 24.301 clause 7 reads the same octets:
//! `decode_lenient` reads what `decode` reads, and a message whose
//! mandatory IEs `decode` refuses with the IEs as they came, so that it
//! encodes to its octets, with the refusal of `decode` first among its
//! faults; and the answer that `answer_to` gives, in either direction, is a
//! plain message that encodes, decodes to itself and has no `validate()`
//! error but for the identities of a session message, which it copies from
//! the message that it answers.
//!
//! A DETACH REQUEST has one message type for the two directions: read as a
//! message of each, octets that decode give their octets back, and any other
//! message is the one that `decode` reads.

use libfuzzer_sys::fuzz_target;
use oxirush_nas::nas_eps::{EmmMessage, Message};
use oxirush_nas::{Direction, Error, Severity, Validate};

fuzz_target!(|octets: &[u8]| {
    let decoded = Message::decode(octets);
    receive(octets, &decoded);
    let Ok(message) = decoded else {
        return;
    };
    let encoded = match message.encode() {
        Ok(encoded) => encoded,
        Err(error) => panic!("a decoded message does not encode: {error}: {message:?}"),
    };
    assert_eq!(
        encoded, octets,
        "a decoded message encodes to other octets: {message:?}"
    );
    let again = match Message::decode(&encoded) {
        Ok(again) => again,
        Err(error) => panic!("{error}: {encoded:02x?} of {message:?}"),
    };
    assert_eq!(message, again, "after {encoded:02x?}");
    assert_eq!(again.encode().as_ref(), Ok(&encoded));
    let _ = message.validate();
    let _ = message.to_string();
});

/// The fields of the header of a session message that an answer copies from
/// the message that it answers (the EPS bearer identity and the PTI), whatever they are.
const IDENTITIES: [&str; 2] = ["eps_bearer_identity", "procedure_transaction_identity"];

/// What a receiver reads of `octets`, which `decode` read as `decoded`, and
/// what it answers.
fn receive(octets: &[u8], decoded: &Result<Message, Error>) {
    match (Message::decode_lenient(octets), decoded) {
        (Ok((lenient, faults)), Ok(message)) => {
            assert_eq!(faults, [], "faults of a message that decode reads");
            assert_eq!(&lenient, message);
        }
        (Ok((lenient, faults)), Err(error)) => {
            assert_eq!(faults.first(), Some(error), "{lenient:?}");
            match lenient.encode() {
                Ok(encoded) => assert_eq!(encoded, octets, "{lenient:?}"),
                Err(error) => {
                    panic!("a message read leniently does not encode: {error}: {lenient:?}")
                }
            }
        }
        (Err(_), Err(_)) => {}
        (Err(error), Ok(message)) => {
            panic!("decode_lenient refuses what decode reads: {error}: {message:?}")
        }
    }
    for direction in [Direction::Uplink, Direction::Downlink] {
        let Some(answer) = Message::answer_to(octets, decoded, direction) else {
            continue;
        };
        assert!(
            !matches!(answer, Message::SecurityProtected(..)),
            "{answer:?}"
        );
        let encoded = match answer.encode() {
            Ok(encoded) => encoded,
            Err(error) => panic!("an answer does not encode: {error}: {answer:?}"),
        };
        assert_eq!(
            Message::decode(&encoded).as_ref(),
            Ok(&answer),
            "{encoded:02x?}"
        );
        let errors: Vec<_> = (answer.validate().into_iter())
            .filter(|finding| finding.severity == Severity::Error)
            .filter(|finding| !IDENTITIES.contains(&finding.field))
            .collect();
        assert!(errors.is_empty(), "the answer {answer} has {errors:?}");
    }
    for direction in [Direction::Uplink, Direction::Downlink] {
        let Ok(message) = Message::decode_with_direction(octets, direction) else {
            continue;
        };
        match message.encode() {
            Ok(encoded) => assert_eq!(encoded, octets, "{message:?}"),
            Err(error) => panic!("a decoded message does not encode: {error}: {message:?}"),
        }
        let plain = match &message {
            Message::SecurityProtected(_, inner) => inner.as_ref(),
            plain => plain,
        };
        let detach = matches!(
            plain,
            Message::Emm(_, EmmMessage::DetachRequestUeOriginating(_))
                | Message::Emm(_, EmmMessage::DetachRequestUeTerminated(_))
        );
        if !detach {
            assert_eq!(decoded.as_ref(), Ok(&message), "{direction:?}");
        }
    }
}
