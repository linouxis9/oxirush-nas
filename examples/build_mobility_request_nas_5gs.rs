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

//! Build a UE-initiated Deregistration Request from scratch.
//!
//! Shows how to construct a GUTI, build a deregistration message,
//! encode it, and verify the round-trip.

use oxirush_nas::nas_5gs::ie::Guti;
use oxirush_nas::nas_5gs::messages::NasDeregistrationRequestFromUe;
use oxirush_nas::nas_5gs::*;

fn main() {
    // Build a 5G-GUTI
    let guti = Guti {
        plmn: PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        }, // 2-digit MNC (93)
        amf_region_id: 0x02,
        amf_set_id: 0x0040,
        amf_pointer: 0x00,
        tmsi: 0xCAFEBABE,
    };

    // Deregistration type: switch-off + 3GPP access
    let dereg_type = NasDeRegistrationType::new(0x09);

    // Build the NAS message
    let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::DeregistrationRequestFromUe(
        NasDeregistrationRequestFromUe::new(dereg_type, NasFGsMobileIdentity::from_guti(&guti)),
    ));

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
