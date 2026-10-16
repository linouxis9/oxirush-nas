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
    let plmn = Plmn::new("208", "93").unwrap(); // 2-digit MNC (93)
    let guti = Guti::new(plmn, 0x02, 0x0040, 0x00, 0xCAFEBABE).unwrap();

    // Mobility registration updating with ngKSI 0
    let registration_type = NasFGsRegistrationType::from_registration_type(
        RegistrationType::MobilityRegistrationUpdate,
    )
    .with_ngksi(0)
    .unwrap();

    // Build the NAS message: 5G-EA0-2 and 5G-IA0-2
    let identity = NasFGsMobileIdentity::from_guti(guti);
    let capability = NasUeSecurityCapability::from_capabilities(0xe0, 0xe0);
    let request = NasRegistrationRequest::new(registration_type, identity)
        .with_ue_security_capability(capability);
    let msg = Nas5gsMessage::new_5gmm(request);

    // Check it against the rules of a sender
    assert!(msg.validate().is_empty(), "{:?}", msg.validate());

    // Encode to wire format
    let wire_bytes = msg.encode().expect("encode failed");
    println!(
        "RegistrationRequest ({} bytes): {}",
        wire_bytes.len(),
        hex::encode(&wire_bytes)
    );

    // Display in Wireshark-style format
    println!("\n{msg}");

    // Verify round-trip
    let decoded = Nas5gsMessage::decode(&wire_bytes).expect("decode failed");
    let re_encoded = decoded.encode().expect("re-encode failed");
    assert_eq!(wire_bytes, re_encoded, "round-trip mismatch!");
    println!("Round-trip: OK");
}
