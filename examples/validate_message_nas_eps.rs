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

//! Decode multiple EPS NAS messages, display them, and run structural validation.
//!
//! Shows how to use the shared `Validate` trait and Display formatting
//! for corresponding EMM procedures.

use oxirush_nas::nas_eps::{Validate, decode_nas_eps_message};

fn main() {
    let messages = [
        (
            "Attach Request",
            "07410108298039000000001002000000040201d031",
        ),
        (
            "Authentication Request",
            "075200000000000000000000000000000000001000000000000000000000000000000000",
        ),
        ("Security Mode Command (EIA2/EEA2)", "075d2200022020"),
    ];

    for (label, hex_payload) in &messages {
        let bytes = hex::decode(hex_payload).expect("invalid hex");
        let msg = decode_nas_eps_message(&bytes).expect("decode failed");

        println!("=== {label} ===");
        println!("{msg}");

        // Structural validation per TS 24.301
        let issues = msg.validate();
        if issues.is_empty() {
            println!("Validation: OK\n");
        } else {
            for issue in &issues {
                println!("  Issue: {issue}");
            }
            println!();
        }
    }
}
