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

//! Build a NAS message from scratch and encode it to wire format.

use oxirush_nas::nas_5gs::ie::GmmCause;
use oxirush_nas::nas_5gs::messages::NasRegistrationReject;
use oxirush_nas::nas_5gs::*;

fn main() {
    // Build a RegistrationReject with cause "Illegal UE"
    let reject = NasRegistrationReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe));
    let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationReject(reject));
    let wire_bytes = encode_nas_5gs_message(&msg).expect("encode failed");

    println!(
        "RegistrationReject ({} bytes): {}",
        wire_bytes.len(),
        hex::encode(&wire_bytes)
    );

    // Verify we can decode it back
    let decoded = decode_nas_5gs_message(&wire_bytes).expect("decode failed");
    println!("Decoded: {decoded}");
}
