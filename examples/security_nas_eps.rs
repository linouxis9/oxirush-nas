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

//! Protect and recover a mobility reject with EPS NAS security.
//!
//! The NAS keys are derived from KASME (TS 33.401 Annex A.7). The 5GS
//! counterpart derives them from KAMF.

use oxirush_nas::nas_eps::{
    CipheringAlgorithm, Direction, EmmCause, IntegrityAlgorithm, NasAttachReject, NasEmmCause,
    NasEmmMessage, NasEpsMessage, NasEpsSecurityHeaderType, NasSecurityContext,
};

fn main() {
    // AttachReject with cause "Illegal UE"
    let cause = NasEmmCause::from_cause(EmmCause::IllegalUe);
    let reject = NasAttachReject::new(cause);
    let message = NasEpsMessage::new_emm(NasEmmMessage::AttachReject(reject));

    // The two ends of one link: the same KASME and the same algorithms
    let kasme = [0x11; 32];
    let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
    let context = || NasSecurityContext::from_fresh_kasme(&kasme, eia, eea);
    let mut sender = context().expect("algorithms that are not reserved");
    let mut receiver = context().expect("algorithms that are not reserved");

    // Protect: integrity and ciphering
    let header_type = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
    let wire = sender
        .protect(&message, header_type, Direction::Downlink)
        .expect("protect failed");

    // Unprotect: MAC check, deciphering and decoding
    let (decoded, _) = receiver
        .unprotect(&wire, Direction::Downlink)
        .expect("unprotect failed");
    assert_eq!(decoded, message);

    println!("AttachReject: {}", hex::encode(wire));
}
