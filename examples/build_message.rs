//! Build a NAS message from scratch and encode it to wire format.

use oxirush_nas::ie::GmmCause;
use oxirush_nas::messages::NasRegistrationReject;
use oxirush_nas::*;

fn main() {
    // Build a RegistrationReject with cause "Illegal UE"
    let reject = NasRegistrationReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe));
    let msg = Nas5gsMessage::new_5gmm(
        Nas5gmmMessageType::RegistrationReject,
        Nas5gmmMessage::RegistrationReject(reject),
    );
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
