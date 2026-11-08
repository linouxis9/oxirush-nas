//! The containers of another message or of the keys of another system: the intra N1
//! mode and the S1 mode to N1 mode NAS transparent containers (TS 24.501 §9.11.2.6
//! and §9.11.2.7), each field in its octet; the payload container (§9.11.3.39) read
//! as the type of its contents; and the EPS NAS message container (§8.2.6.16), which
//! holds an attach or tracking area update request that is plain or integrity
//! protected.

use oxirush_nas::nas_5gs::{
    EpsNasMessageContainer, IntraN1ModeNasTransparentContainer, KeySetIdentifier, PayloadContainer,
    S1ModeToN1ModeNasTransparentContainer, SecurityAlgorithms,
};
use oxirush_nas::nas_eps::{Message, SecurityHeader, SecurityHeaderType};

#[test]
fn the_intra_n1_mode_container_has_the_k_amf_change_flag_and_the_ngksi_in_its_octet_8() {
    // Octets 3 to 6 the MAC, octet 7 the algorithms, octet 8 the K_AMF change flag
    // in bit 5, TSC and ngKSI in bits 4 to 1 and bits 8 to 6 spare, octet 9 the SQN
    for octet in 0..=u8::MAX {
        let mut value = vec![0x00; 7];
        value[5] = octet;
        let container = IntraN1ModeNasTransparentContainer::new(value);
        assert_eq!(
            container.k_amf_change_flag(),
            Some(octet & 0x10 != 0),
            "{octet}"
        );
        let mut changed = container.clone();
        changed.set_k_amf_change_flag(true);
        assert_eq!(changed.value[5], octet & 0x0f | 0x10, "{octet}");
        changed.set_k_amf_change_flag(false);
        assert_eq!(changed.value[5], octet & 0x0f, "{octet}");
        let mut identified = container.clone();
        identified.set_key_set_identifier(KeySetIdentifier::new(0x0a));
        assert_eq!(identified.value[5], octet & 0x10 | 0x0a, "{octet}");
    }
    let short = IntraN1ModeNasTransparentContainer::new(vec![0x00; 5]);
    assert_eq!(short.k_amf_change_flag(), None);
}

#[test]
fn the_s1_mode_to_n1_mode_container_has_the_ncc_and_the_ngksi_in_its_octet_8() {
    // Octets 3 to 6 the MAC, octet 7 the algorithms, octet 8 NCC in bits 7 to 5 and
    // TSC and ngKSI in bits 4 to 1, octets 9 and 10 spare
    for octet in 0..=u8::MAX {
        let mut value = vec![0x00; 8];
        value[4] = 0x21;
        value[5] = octet;
        let container = S1ModeToN1ModeNasTransparentContainer::new(value);
        assert_eq!(
            container.security_algorithms(),
            Some(SecurityAlgorithms::new(0x21))
        );
        let mut counted = container.clone();
        counted.set_ncc(5).unwrap();
        assert_eq!(counted.value[5], octet & 0x0f | 0x50, "{octet}");
        let mut identified = container.clone();
        identified.set_key_set_identifier(KeySetIdentifier::new(0x0a));
        assert_eq!(identified.value[5], octet & 0x70 | 0x0a, "{octet}");
    }
    for (octet_9, octet_10) in [(0x00, 0x00), (0x01, 0x00), (0x00, 0x01)] {
        let value = vec![0, 0, 0, 0, 0x21, 0x00, octet_9, octet_10];
        let container = S1ModeToN1ModeNasTransparentContainer::new(value);
        let zero = octet_9 == 0 && octet_10 == 0;
        assert_eq!(
            container.spare_octets_are_zero(),
            zero,
            "{octet_9} {octet_10}"
        );
    }
}

#[test]
fn a_payload_container_is_read_as_the_type_of_its_contents() {
    let payload = |octets: &[u8]| PayloadContainer::new(octets.to_vec());
    // A SOR transparent container of a secured packet (§9.11.3.51): its header,
    // SOR-MAC-IAUSF, CounterSOR and the packet; and one cut short
    let mut sor = vec![0x02];
    sor.extend([0xcd; 16]);
    sor.extend([0x00, 0x01, 0x01, 0x02]);
    let container = payload(&sor).decode_as_sor_transparent_container().unwrap();
    assert_eq!(container.value, sor);
    assert!(
        payload(&sor[..10])
            .decode_as_sor_transparent_container()
            .is_err()
    );
    // An event notification: one indicator, "SRVCC handover cancelled, IMS session
    // re-establishment required", of no value
    let events = payload(&[0x01, 0x00, 0x00]).decode_as_event_notification_container();
    assert_eq!(events.unwrap().indicators.len(), 1);
    // Multiple payloads: one entry of N1 SM information without optional IE
    let multiple = payload(&[0x01, 0x00, 0x03, 0x01, 0xaa, 0xbb]);
    let entries = multiple
        .decode_as_multiple_payload_container()
        .unwrap()
        .entries;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].contents, [0xaa, 0xbb]);
}

#[test]
fn the_eps_nas_message_container_holds_a_plain_or_integrity_protected_request() {
    let attach = hex::decode("07411108298039103254769802f07000040201d011").unwrap();
    let plain = Message::decode(&attach).unwrap();
    assert!(EpsNasMessageContainer::from_eps_message(&plain).is_ok());
    let protected = |security_header_type| {
        let header = SecurityHeader {
            security_header_type,
            message_authentication_code: 0,
            sequence_number: 0,
        };
        Message::SecurityProtected(header, Box::new(plain.clone()))
    };
    let integrity = protected(SecurityHeaderType::IntegrityProtected);
    assert!(EpsNasMessageContainer::from_eps_message(&integrity).is_ok());
    // The request of a security mode procedure's new context, or ciphered, is not one
    for security_header_type in [
        SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
    ] {
        let message = protected(security_header_type);
        assert!(EpsNasMessageContainer::from_eps_message(&message).is_err());
    }
}
