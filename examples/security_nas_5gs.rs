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

//! Protect and recover a mobility reject with 5GS NAS security, and print
//! each step: the plain message, the protected octets with the fields of
//! their security header, and what the receiver recovers.
//!
//! The NAS keys are derived from KAMF, the key that the UE and the AMF
//! share after authentication (TS 33.501 Annex A.8). The EPS counterpart
//! derives them from KASME.
//!
//! ```text
//! cargo run --example security_nas_5gs --features security
//! ```

use oxirush_nas::nas_5gs::ie::{CipheringAlgorithm, GmmCause, IntegrityAlgorithm};
use oxirush_nas::nas_5gs::messages::NasRegistrationReject;
use oxirush_nas::nas_5gs::security::NasConnection;
use oxirush_nas::nas_5gs::{
    Direction, Nas5gsMessage, Nas5gsSecurityHeaderType, NasFGmmCause, NasSecurityContext,
};

fn main() {
    // RegistrationReject with cause "Illegal UE"
    let cause = NasFGmmCause::from_cause(GmmCause::IllegalUe);
    let reject = NasRegistrationReject::new(cause);
    let message = Nas5gsMessage::new_5gmm(reject);
    let plain = message.encode().expect("encode failed");
    println!("plain message      {message}");
    println!("plain octets       {}", hex::encode(&plain));

    // The two ends of one link: the same KAMF and the same algorithms
    let kamf = [0x11; 32];
    let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
    let context = || NasSecurityContext::from_fresh_kamf(&kamf, nia, nea);
    let mut sender = context().expect("algorithms that are not reserved");
    let mut receiver = context().expect("algorithms that are not reserved");

    // Protect: integrity and ciphering
    let header_type = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
    let wire = sender
        .protect(&message, header_type, Direction::Downlink)
        .expect("protect failed");

    // The security header is seven octets: the discriminator of 5GMM, the
    // security header type, the message authentication code and the
    // sequence number, which is the low octet of the NAS COUNT
    println!("protected octets   {}", hex::encode(&wire));
    println!(
        "  header type      {}: integrity protected and ciphered",
        wire[1]
    );
    println!("  MAC              {}", hex::encode(&wire[2..6]));
    println!("  sequence number  {}", wire[6]);
    println!("  ciphered message {}", hex::encode(&wire[7..]));

    // Unprotect: MAC check, deciphering and decoding
    let (decoded, _) = receiver
        .unprotect(&wire, Direction::Downlink)
        .expect("unprotect failed");
    assert_eq!(decoded, message);
    println!("recovered message  {decoded}");

    // Each end counts the messages of each direction: the next downlink
    // message has the NAS COUNT 1
    let next = |context: &NasSecurityContext| {
        let count = context.nas_count(Direction::Downlink, NasConnection::ThreeGpp);
        count.map(|count| count.get())
    };
    println!(
        "next downlink NAS COUNT of the sender {:?}, of the receiver {:?}",
        next(&sender),
        next(&receiver)
    );

    // A message that was changed on the way is refused
    let mut tampered = sender
        .protect(&message, header_type, Direction::Downlink)
        .expect("protect failed");
    *tampered.last_mut().expect("a protected message") ^= 1;
    let refused = receiver.unprotect(&tampered, Direction::Downlink);
    println!(
        "a changed message  {}",
        refused.expect_err("the MAC does not match")
    );
}
