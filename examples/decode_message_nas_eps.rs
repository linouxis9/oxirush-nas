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
    // Attach Request (EPS attach, IMSI 208930000000001, EEA0-2/EIA0-2) with
    // a PDN CONNECTIVITY REQUEST in its ESM container
    let hex_payload = "07410108298039000000001002e0e0000402 01d031".replace(' ', "");
    let bytes = hex::decode(hex_payload).expect("invalid hex");

    // Decode
    let msg = decode_nas_eps_message(&bytes).expect("decode failed");

    // Wireshark-style display
    println!("=== Decoded NAS message ===");
    println!("{msg}");

    // Structural validation per TS 24.301
    let issues = msg.validate();
    if issues.is_empty() {
        println!("\nValidation: OK (no issues)");
    } else {
        for issue in &issues {
            println!("Validation issue: {issue}");
        }
    }

    // Extract typed fields
    if let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &msg {
        println!("\n=== Typed IE accessors ===");
        println!("Attach type: {:?}", request.eps_attach_type.attach_type());

        if let Some(id_type) = request.eps_mobile_identity.identity_type() {
            println!("Identity type: {id_type:?}");
        }

        if let Some(imsi) = request.eps_mobile_identity.as_imsi() {
            println!("IMSI: {imsi}");
        }

        if let Ok(esm) = request.esm_message_container.decode_as_esm_message() {
            println!("ESM container: {esm}");
        }
    }

    // Round-trip encode
    let re_encoded = encode_nas_eps_message(&msg).expect("encode failed");
    assert_eq!(bytes, re_encoded, "round-trip mismatch!");
    println!("\nRound-trip: OK ({} bytes)", re_encoded.len());
}
