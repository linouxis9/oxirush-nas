//! The security header types that a message is sent under (TS 24.301 §9.3.1):
//! SECURITY MODE COMPLETE alone under "integrity protected and ciphered with new
//! EPS security context", CONTROL PLANE SERVICE REQUEST alone under "integrity
//! protected and partially ciphered", and an ATTACH REQUEST or a TRACKING AREA
//! UPDATE REQUEST, which an MME without the context reads, never ciphered
//! (§4.4.5).

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

#[test]
fn an_attach_or_tracking_area_update_request_is_not_ciphered() {
    let attach = hex::decode("07411108298039103254769802f07000040201d011").unwrap();
    let attach = NasEpsMessage::decode(&attach).unwrap();
    let ciphered = Header::IntegrityProtectedAndCiphered;
    let mut sender = context();
    assert!(
        sender
            .protect(&attach, ciphered, Direction::Uplink)
            .is_err()
    );
    let octets = sender
        .protect(&attach, Header::IntegrityProtected, Direction::Uplink)
        .unwrap();
    let received = context().unprotect(&octets, Direction::Uplink).unwrap();
    assert_eq!(received.message, attach);
    // Another uplink message goes ciphered: EMM STATUS with the cause #111
    let status = NasEpsMessage::decode(&[0x07, 0x60, 0x6f]).unwrap();
    assert!(sender.protect(&status, ciphered, Direction::Uplink).is_ok());
}
