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

//! Build a Tracking Area Update Request from scratch.
//!
//! Shows how to construct a GUTI, build the request with the UE network
//! capability, check it with `validate()`, encode it, and verify the round
//! trip. The 5GS counterpart is a mobility registration update Registration
//! Request.

use oxirush_nas::Validate;
use oxirush_nas::identity::{GutiEps, Plmn};
use oxirush_nas::nas_eps::*;

fn main() {
    // Build an EPS GUTI with the same PLMN and TMSI as the 5GS counterpart.
    let plmn = Plmn::new("208", "93").unwrap();
    let guti = GutiEps::new(plmn, 0x0040, 0, 0xcafe_babe);

    // TA updating with KSI 0; a non-periodic update carries the UE network
    // capability, and every update carries the old GUTI type.
    let update_type = EpsUpdateType::from_update_type(UpdateType::TaUpdating);
    let key_set = KeySetIdentifier::new(0);
    let old_guti = EpsMobileIdentity::from_guti(guti);
    let capability = UeNetworkCapability::from_eea_eia(0xe0, 0xe0);
    let request = TrackingAreaUpdateRequest::new(update_type, key_set, old_guti)
        .with_ue_network_capability(capability)
        .with_old_guti_type(GutiType::from_mapped(false));
    let msg = Message::new_emm(request);

    // Check it against the rules of a sender
    assert!(msg.validate().is_empty(), "{:?}", msg.validate());

    // Encode to wire format
    let wire_bytes = msg.encode().expect("encode failed");
    println!(
        "TrackingAreaUpdateRequest ({} bytes): {}",
        wire_bytes.len(),
        hex::encode(&wire_bytes)
    );

    // Display in Wireshark-style format
    println!("\n{msg}");

    // Verify round-trip
    let decoded = Message::decode(&wire_bytes).expect("decode failed");
    let re_encoded = decoded.encode().expect("re-encode failed");
    assert_eq!(wire_bytes, re_encoded, "round-trip mismatch!");
    println!("Round-trip: OK");
}
