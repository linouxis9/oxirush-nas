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
//! that the codec keeps.
//!
//! Octets that are the same after a decode and an encode would only show
//! that the encoder writes what the decoder happened to read. This target
//! holds the message instead: `decode(encode(decode(octets)))` is the
//! message that `decode(octets)` gave, so that an IE that the decoder drops
//! or the encoder writes otherwise makes the two differ. A message that was
//! decoded also encodes, to octets that encode again to themselves, and is
//! validated and displayed without a panic.

use libfuzzer_sys::fuzz_target;
use oxirush_nas::nas_eps::{NasEpsMessage, Validate};

fuzz_target!(|octets: &[u8]| {
    let Ok(message) = NasEpsMessage::decode(octets) else {
        return;
    };
    let encoded = match message.encode() {
        Ok(encoded) => encoded,
        Err(error) => panic!("a decoded message does not encode: {error}: {message:?}"),
    };
    let again = match NasEpsMessage::decode(&encoded) {
        Ok(again) => again,
        Err(error) => panic!("{error}: {encoded:02x?} of {message:?}"),
    };
    assert_eq!(message, again, "after {encoded:02x?}");
    assert_eq!(again.encode().as_ref(), Ok(&encoded));
    let _ = message.validate();
    let _ = message.to_string();
});
