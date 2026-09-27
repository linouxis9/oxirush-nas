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

//! Decode a 5G NAS Registration Request from raw bytes, display it,
//! validate it, and round-trip encode it back.

use oxirush_nas::nas_5gs::{Nas5gmmMessage, Nas5gsMessage};
use oxirush_nas::nas_5gs::{Validate, decode_nas_5gs_message, encode_nas_5gs_message};

fn main() {
    // Registration Request (initial, SUCI, PLMN 208/93)
    let hex_payload = "7e004179000d0102f8390000000000000010022e08a020000000000000";
    let bytes = hex::decode(hex_payload).expect("invalid hex");

    // Decode
    let msg = decode_nas_5gs_message(&bytes).expect("decode failed");

    // Wireshark-style display
    println!("=== Decoded NAS message ===");
    println!("{msg}");

    // Structural validation per TS 24.501
    let issues = msg.validate();
    if issues.is_empty() {
        println!("\nValidation: OK (no issues)");
    } else {
        for issue in &issues {
            println!("Validation issue: {issue}");
        }
    }

    // Extract typed fields
    if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = &msg {
        println!("\n=== Typed IE accessors ===");

        if let Some(reg_type) = reg.fgs_registration_type.registration_type() {
            println!("Registration type: {reg_type:?}");
        }

        if let Some(id_type) = reg.fgs_mobile_identity.identity_type() {
            println!("Identity type: {id_type:?}");
        }

        if let Some(plmn) = reg.fgs_mobile_identity.plmn() {
            println!("PLMN: MCC={}, MNC={}", plmn.mcc_string(), plmn.mnc_string());
        }
    }

    // Round-trip encode
    let re_encoded = encode_nas_5gs_message(&msg).expect("encode failed");
    assert_eq!(bytes, re_encoded, "round-trip mismatch!");
    println!("\nRound-trip: OK ({} bytes)", re_encoded.len());
}
