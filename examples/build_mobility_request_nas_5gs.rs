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

//! Build a mobility registration update Registration Request from scratch.
//!
//! Shows how to construct a GUTI, build the request with the UE security
//! capability, check it with `validate()`, encode it, and verify the round
//! trip. The EPS counterpart is a Tracking Area Update Request.

use oxirush_nas::nas_5gs::ie::Guti;
use oxirush_nas::nas_5gs::messages::NasRegistrationRequest;
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

    // Mobility registration updating with ngKSI 0
    let registration_type = NasFGsRegistrationType::from_registration_type(
        RegistrationType::MobilityRegistrationUpdate,
    )
    .with_ngksi(0);

    // Build the NAS message: 5G-EA0-2 and 5G-IA0-2
    let request =
        NasRegistrationRequest::new(registration_type, NasFGsMobileIdentity::from_guti(&guti))
            .set_ue_security_capability(NasUeSecurityCapability::from_capabilities(0xe0, 0xe0));
    let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationRequest(request));
    assert!(msg.validate().is_empty(), "{:?}", msg.validate());

    // Encode to wire format
    let wire_bytes = encode_nas_5gs_message(&msg).expect("encode failed");
    println!(
        "RegistrationRequest ({} bytes): {}",
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
