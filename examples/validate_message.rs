//! Decode multiple NAS messages, display them, and run structural validation.
//!
//! Shows how to use the `Validate` trait and how Display formatting works
//! for different message types.

use oxirush_nas::{Validate, decode_nas_5gs_message};

fn main() {
    let messages = [
        (
            "Registration Request (initial, SUCI)",
            "7e004179000d0199f9070000000000000010022e08a020000000000000",
        ),
        (
            "Authentication Request (5G-AKA)",
            "7e00560002000021ab6f2a1cc5c5938d38cba14dfe26b0012010a820e67b8896800076a638e98eed4747",
        ),
        (
            "Security Mode Command (NIA2/NEA2)",
            "7e005d020002a020e1360102",
        ),
    ];

    for (label, hex_payload) in &messages {
        let bytes = hex::decode(hex_payload).expect("invalid hex");
        let msg = decode_nas_5gs_message(&bytes).expect("decode failed");

        println!("=== {label} ===");
        println!("{msg}");

        // Structural validation per TS 24.501
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
