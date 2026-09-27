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

//! Protect and recover a mobility reject with 5GS NAS security.
//!
//! The NAS keys are derived from KAMF (TS 33.501 Annex A.8). The EPS
//! counterpart derives them from KASME.

use oxirush_nas::nas_5gs::ie::{CipheringAlgorithm, GmmCause, IntegrityAlgorithm};
use oxirush_nas::nas_5gs::messages::NasRegistrationReject;
use oxirush_nas::nas_5gs::{
    Direction, Nas5gmmMessage, Nas5gsMessage, Nas5gsSecurityHeaderType, NasFGmmCause,
    NasSecurityContext,
};

fn main() {
    let message = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationReject(
        NasRegistrationReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe)),
    ));
    let mut sender = NasSecurityContext::from_fresh_kamf(
        &[0x11; 32],
        IntegrityAlgorithm::NIA2,
        CipheringAlgorithm::NEA2,
    );
    let mut receiver = NasSecurityContext::from_fresh_kamf(
        &[0x11; 32],
        IntegrityAlgorithm::NIA2,
        CipheringAlgorithm::NEA2,
    );
    let wire = sender
        .protect(
            &message,
            Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
            Direction::Downlink,
        )
        .expect("protect failed");
    let (decoded, _) = receiver
        .unprotect(&wire, Direction::Downlink)
        .expect("unprotect failed");
    assert_eq!(decoded, message);
    println!("RegistrationReject: {}", hex::encode(wire));
}
