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

#![no_main]
//! Structural round-trip fuzz target.
//!
//! Plain byte-level round-trip (`decode → encode → bytes_equal`) only proves
//! the encoder reproduces whatever the decoder happens to read. It cannot
//! catch the "House → Bed → House" failure: if the decoder silently drops
//! field X and the encoder writes a default for X, byte-equality still holds
//! while the *meaning* of the message is wrong.
//!
//! This target instead asserts:
//!     decode(bytes)  == decode(encode(decode(bytes)))
//! i.e. the decoded *structure* survives a re-encode. Any asymmetry between
//! encode and decode (dropped IE, swapped field, lost enum variant, wrong
//! length semantics) makes the two structs differ via PartialEq.
//!
//! As a secondary check we also verify byte-level idempotence on the second
//! encode pass: once a message has been canonicalised (decoded and re-encoded
//! once), encoding it again must produce identical bytes.

use libfuzzer_sys::fuzz_target;
use oxirush_nas::nas_eps::{decode_nas_eps_message, encode_nas_eps_message};

fuzz_target!(|data: &[u8]| {
    let Ok(msg1) = decode_nas_eps_message(data) else {
        return;
    };
    let Ok(bytes1) = encode_nas_eps_message(&msg1) else {
        // Decoding succeeded but encoding failed: that itself is a bug
        // — every value the decoder accepts should be re-encodable.
        panic!("encode failed for decodable message: {:?}", msg1);
    };
    let msg2 = match decode_nas_eps_message(&bytes1) {
        Ok(m) => m,
        Err(e) => panic!("re-decode failed: {:?}\nmsg1={:?}\nbytes1={:02x?}", e, msg1, bytes1),
    };
    assert_eq!(
        msg1, msg2,
        "structural round-trip mismatch (decoder/encoder asymmetry)\nbytes1={:02x?}",
        bytes1
    );
    let bytes2 = encode_nas_eps_message(&msg2).expect("second encode");
    assert_eq!(
        bytes1, bytes2,
        "encode is not idempotent on canonical form"
    );
});
