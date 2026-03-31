//! Build a UE-initiated Deregistration Request from scratch.
//!
//! Shows how to construct a GUTI, build a deregistration message,
//! encode it, and verify the round-trip.

use oxirush_nas::*;
use oxirush_nas::ie::Guti;
use oxirush_nas::messages::NasDeregistrationRequestFromUe;

fn main() {
    // Build a 5G-GUTI
    let guti = Guti {
        mcc: [2, 0, 8],
        mnc: [9, 3, 0x0F], // 2-digit MNC (93), padded with 0x0F
        amf_region_id: 0x02,
        amf_set_id: 0x0040,
        amf_pointer: 0x00,
        tmsi: 0xCAFEBABE,
    };

    // Deregistration type: switch-off + 3GPP access
    let dereg_type = NasDeRegistrationType::new(0x09);

    // Build the NAS message
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::DeregistrationRequestFromUe,
        Nas5gmmMessage::DeregistrationRequestFromUe(
            NasDeregistrationRequestFromUe::new(
                dereg_type,
                NasFGsMobileIdentity::from_guti(&guti),
            ),
        ),
    );

    // Encode to wire format
    let wire_bytes = encode_nas_5gs_message(&msg).expect("encode failed");
    println!(
        "DeregistrationRequest ({} bytes): {}",
        wire_bytes.len(),
        hex::encode(&wire_bytes)
    );

    // Display in Wireshark-style format
    println!("\n{msg}");

    // Verify round-trip
    let decoded = decode_nas_5gs_message(&wire_bytes).expect("decode failed");
    let re_encoded = encode_nas_5gs_message(&decoded).expect("re-encode failed");
    assert_eq!(wire_bytes, re_encoded, "round-trip mismatch!");
    println!("Round-trip: OK");
}
