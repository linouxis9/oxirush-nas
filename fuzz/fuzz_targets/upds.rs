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
//! Whatever the octets, a message of the UE policy delivery service (TS
//! 24.501 Annex D) decodes or is refused, and what decodes is what the codec
//! keeps: it encodes to the octets that it was decoded from, and those decode
//! to it again. It validates and displays without a panic, a payload container
//! of these octets reads it as a UE policy container, and its serde form reads
//! back to the same message, which encodes: its optional IEs in the order of
//! their table and the unknown IEs after them, as a tree writes a message.
//!
//! No decoder of a NAS message reads these octets: a payload container says
//! that it holds them, and the program reads them.

use libfuzzer_sys::fuzz_target;
use oxirush_nas::Validate;
use oxirush_nas::nas_5gs::{PayloadContainer, UpdsEnvelope};

fuzz_target!(|octets: &[u8]| {
    let Ok(envelope) = UpdsEnvelope::decode(octets) else {
        return;
    };
    let written = match envelope.encode() {
        Ok(written) => written,
        Err(error) => panic!("a message that was decoded does not encode: {error}: {envelope:?}"),
    };
    assert_eq!(written, octets, "{envelope:?}");
    assert_eq!(UpdsEnvelope::decode(&written).as_ref(), Ok(&envelope));
    let _ = (
        envelope.validate(),
        envelope.to_string(),
        envelope.message_type(),
    );

    let container = PayloadContainer::new(octets.to_vec());
    assert_eq!(
        container.decode_as_ue_policy_message().as_ref(),
        Ok(&envelope)
    );

    let form = serde_json::to_value(&envelope).expect("a message has a serde form");
    let read: UpdsEnvelope = match serde_json::from_value(form.clone()) {
        Ok(read) => read,
        Err(error) => panic!("the serde form {form} of a message is refused: {error}"),
    };
    assert_eq!(read, envelope, "{form}");
    if let Err(error) = read.encode() {
        panic!("the message of the serde form {form} does not encode: {error}");
    }
});
