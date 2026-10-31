//! The data container of an EMM TRANSPORT (TS 24.301 §9.9.3.74): the data type in the
//! bits 8 to 6 of its first octet, and for control plane user data the DDX in the bits 5
//! and 4 and the EPS bearer identity in the bits 3 to 1; the DDX is spare from the
//! network. A context protects the containers that a sender writes.

use oxirush_nas::nas_eps::{
    CipheringAlgorithm, Direction, IntegrityAlgorithm, KAsme, NasSecurityContext,
};

fn protects(container: &[u8], direction: Direction) -> bool {
    let kasme = KAsme::new(&[0x11; 32]);
    let integrity = IntegrityAlgorithm::EIA2;
    let mut context =
        NasSecurityContext::from_fresh_kasme(&kasme, integrity, CipheringAlgorithm::EEA2).unwrap();
    context
        .protect_emm_transport(Some(container), direction)
        .is_ok()
}

#[test]
fn a_sender_writes_a_data_container_as_its_type_codes_it() {
    let uplink = [
        // Control plane user data of the EPS bearer 5, with each DDX but the reserved 11
        (&[0x01, 0xaa][..], true),
        (&[0x09, 0xaa], true),
        (&[0x11, 0xaa], true),
        (&[0x19, 0xaa], false),
        // The EPS bearer identity 000 is reserved, and data has a payload
        (&[0x00, 0xaa], false),
        (&[0x01], false),
        // SMS, whose five low bits are spare, with its payload
        (&[0x20, 0xaa], true),
        (&[0x21, 0xaa], false),
        (&[0x30, 0xaa], false),
        (&[0x20], false),
        // A location services message container: the DDX, three spare bits, the
        // length of the additional information, the information and the payload
        (&[0x40, 0x00, 0xaa], true),
        (&[0x48, 0x02, 0x01, 0x02, 0xaa], true),
        (&[0x58, 0x00, 0xaa], false),
        (&[0x41, 0x00, 0xaa], false),
        (&[0x40, 0x02, 0x01, 0xaa], false),
        (&[0x40, 0x00], false),
        // The data types 011 to 111 are reserved
        (&[0x60, 0xaa], false),
        (&[0xe0, 0xaa], false),
    ];
    for (container, protected) in uplink {
        assert_eq!(
            protects(container, Direction::Uplink),
            protected,
            "{container:02x?}"
        );
    }
    // From the network the DDX is spare, and zero
    for (container, protected) in [
        (&[0x01, 0xaa][..], true),
        (&[0x09, 0xaa], false),
        (&[0x40, 0x00, 0xaa], true),
        (&[0x48, 0x00, 0xaa], false),
        (&[0x20, 0xaa], true),
    ] {
        assert_eq!(
            protects(container, Direction::Downlink),
            protected,
            "{container:02x?}"
        );
    }
}
