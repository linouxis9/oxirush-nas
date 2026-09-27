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

//! Decode an EPS NAS Attach Request from raw bytes, display it,
//! validate it, and round-trip encode it back.

use oxirush_nas::nas_eps::{
    NasEmmMessage, NasEpsMessage, Validate, decode_nas_eps_message, encode_nas_eps_message,
};

fn main() {
    // A plain Attach Request with a mobile identity and ESM container
    let bytes = hex::decode("07410108298039000000001002000000040201d031").expect("invalid hex");
    let msg = decode_nas_eps_message(&bytes).expect("decode failed");

    println!("=== Decoded NAS message ===");
    println!("{msg}");

    // Structural validation per TS 24.301
    let issues = msg.validate();
    assert!(issues.is_empty(), "Validation issues: {issues:?}");

    // Extract the attach type
    if let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &msg {
        println!("Attach type: {:?}", request.eps_attach_type.attach_type());
        println!(
            "IMSI: {}",
            request.eps_mobile_identity.as_imsi().expect("valid IMSI")
        );
    }

    // Round-trip encode
    let re_encoded = encode_nas_eps_message(&msg).expect("encode failed");
    assert_eq!(bytes, re_encoded, "round-trip mismatch!");
    println!("\nRound-trip: OK ({} bytes)", re_encoded.len());
}
