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

//! Build a UE-initiated EPS Detach Request from scratch.
//!
//! Shows how to construct a GUTI, build a detach message, encode it,
//! and verify the round-trip.

use oxirush_nas::nas_eps::*;

fn main() {
    // Build an EPS GUTI with the same PLMN and TMSI as the 5GS counterpart.
    let guti = Guti {
        plmn: PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        },
        mme_group_id: 0x0040,
        mme_code: 0,
        m_tmsi: 0xcafe_babe,
    };

    // Build the NAS message
    let request = NasDetachRequestFromUe::new(
        NasDetachType::from_ue_detach_kind(UeDetachKind::Eps, true),
        NasKeySetIdentifier::new(0),
        NasEpsMobileIdentity::from_guti(guti),
    );
    let msg = NasEpsMessage::new_emm(NasEmmMessage::DetachRequestFromUe(request));

    // Encode to wire format
    let wire_bytes = encode_nas_eps_message(&msg).expect("encode failed");
    println!(
        "DetachRequest ({} bytes): {}",
        wire_bytes.len(),
        hex::encode(&wire_bytes)
    );
    println!("\n{msg}");

    // Verify round-trip
    let decoded = decode_nas_eps_message(&wire_bytes).expect("decode failed");
    let re_encoded = encode_nas_eps_message(&decoded).expect("re-encode failed");
    assert_eq!(wire_bytes, re_encoded, "round-trip mismatch!");
    println!("Round-trip: OK");
}
