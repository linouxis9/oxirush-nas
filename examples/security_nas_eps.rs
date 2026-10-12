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

//! Protect and recover a mobility reject with EPS NAS security, and print
//! each step: the plain message, the protected octets with the fields of
//! their security header, and what the receiver recovers.
//!
//! The NAS keys are derived from KASME, the key that the UE and the MME
//! share after authentication (TS 33.401 Annex A.7). The 5GS counterpart
//! derives them from KAMF.
//!
//! ```text
//! cargo run --example security_nas_eps --features security
//! ```

use oxirush_nas::nas_eps::{
    CipheringAlgorithm, Direction, EmmCause, IntegrityAlgorithm, KAsme, NasAttachReject,
    NasEmmCause, NasEpsMessage, NasEpsSecurityHeaderType, NasSecurityContext,
};

fn main() {
    // AttachReject with cause "Illegal UE"
    let cause = NasEmmCause::from_cause(EmmCause::IllegalUe);
    let reject = NasAttachReject::new(cause);
    let message = NasEpsMessage::new_emm(reject);
    let plain = message.encode().expect("encode failed");
    println!("plain message      {message}");
    println!("plain octets       {}", hex::encode(&plain));

    // The two ends of one link: the same KASME and the same algorithms
    let kasme = KAsme::new([0x11; 32]);
    let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
    let context = || NasSecurityContext::from_fresh_kasme(&kasme, eia, eea);
    let mut sender = context().expect("algorithms that are not reserved");
    let mut receiver = context().expect("algorithms that are not reserved");

    // Protect: integrity and ciphering
    let header_type = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
    let wire = sender
        .protect(&message, header_type, Direction::Downlink)
        .expect("protect failed");

    // The security header is six octets: the security header type and the
    // discriminator of EMM in one octet, the message authentication code and
    // the sequence number, which is the low octet of the NAS COUNT
    println!("protected octets   {}", hex::encode(&wire));
    println!(
        "  header type      {}: integrity protected and ciphered",
        wire[0] >> 4
    );
    println!("  MAC              {}", hex::encode(&wire[1..5]));
    println!("  sequence number  {}", wire[5]);
    println!("  ciphered message {}", hex::encode(&wire[6..]));

    // Unprotect: MAC check, deciphering and decoding
    let decoded = receiver
        .unprotect(&wire, Direction::Downlink)
        .expect("unprotect failed")
        .message;
    assert_eq!(decoded, message);
    println!("recovered message  {decoded}");

    // Each end counts the messages of each direction: the next downlink
    // message has the NAS COUNT 1
    let next = |context: &NasSecurityContext| context.downlink_count().map(|count| count.get());
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
