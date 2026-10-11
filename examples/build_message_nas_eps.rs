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

//! Build an EPS NAS Attach Reject from scratch and encode it to wire format.

use oxirush_nas::nas_eps::{EmmCause, NasAttachReject, NasEmmCause, NasEpsMessage};

fn main() {
    // Build an AttachReject with cause "Illegal UE"
    let cause = NasEmmCause::from_cause(EmmCause::IllegalUe);
    let reject = NasAttachReject::new(cause);
    let msg = NasEpsMessage::new_emm(reject);

    // Encode it to wire format
    let wire_bytes = msg.encode().expect("encode failed");
    println!(
        "AttachReject ({} bytes): {}",
        wire_bytes.len(),
        hex::encode(&wire_bytes)
    );

    // Verify we can decode it back
    let decoded = NasEpsMessage::decode(&wire_bytes).expect("decode failed");
    println!("Decoded: {decoded}");
}
