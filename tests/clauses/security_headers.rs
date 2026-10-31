//! The security header types that a message is sent under (TS 24.301 §9.3.1):
//! SECURITY MODE COMPLETE alone under "integrity protected and ciphered with new
//! EPS security context", and CONTROL PLANE SERVICE REQUEST alone under
//! "integrity protected and partially ciphered".

use oxirush_nas::nas_eps::{
    CipheringAlgorithm, Direction, IntegrityAlgorithm, KAsme, NasEpsMessage,
    NasEpsSecurityHeaderType as Header, NasSecurityContext,
};

fn context() -> NasSecurityContext {
    let kasme = KAsme::new(&[0x11; 32]);
    NasSecurityContext::from_fresh_kasme(&kasme, IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2)
        .unwrap()
}

#[test]
fn a_header_of_one_message_protects_that_message_alone() {
    // EMM STATUS with the cause #111, and SECURITY MODE COMPLETE
    let status = NasEpsMessage::decode(&[0x07, 0x60, 0x6f]).unwrap();
    let complete = NasEpsMessage::decode(&[0x07, 0x5e]).unwrap();
    for header in [
        Header::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
        Header::IntegrityProtectedAndPartiallyCipheredNasMessage,
    ] {
        let mut sender = context();
        assert!(
            sender.protect(&status, header, Direction::Uplink).is_err(),
            "{header:?}"
        );
        assert_eq!(
            sender.nas_count(Direction::Uplink).map(|count| count.get()),
            Some(0)
        );
    }
    let header = Header::IntegrityProtectedAndCipheredWithNewEpsSecurityContext;
    let (mut sender, mut receiver) = (context(), context());
    let octets = sender
        .protect(&complete, header, Direction::Uplink)
        .unwrap();
    let received = receiver.unprotect(&octets, Direction::Uplink).unwrap();
    assert_eq!(received.message, complete);
    assert_eq!(received.security_header_type, header);
}
