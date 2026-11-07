//! The CIoT small data container (TS 24.501 §9.11.3.18B): its data type in bits 8 to
//! 6 of its first octet, then for control plane user data the DDX and the PDU session
//! identity, for an SMS spare bits, and for a location services message container
//! the DDX, spare bits and the length of the additional information that follows;
//! 255 octets at most.

use oxirush_nas::nas_5gs::{
    CiotSmallDataContainerContents as Contents, CiotSmallDataDownlinkDataExpected as Ddx,
    NasCiotSmallDataContainer as Container,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// `value` decodes to `contents`, which encodes to it, and is sound for a sender.
fn both_ways(value: Vec<u8>, contents: Contents) {
    let container = Container::new(value.clone());
    assert_eq!(container.parse(), Some(contents.clone()), "{value:02x?}");
    assert_eq!(Container::from_parsed(&contents).unwrap().value, value);
    assert!(container.validate_strict().is_ok(), "{value:02x?}");
}

#[test]
fn each_data_type_has_its_fields() {
    // Control plane user data: no further uplink or downlink (01), PDU session 5
    both_ways(
        octets("0d aabb"),
        Contents::ControlPlaneUserData {
            downlink_data_expected: Ddx::NoFurtherUplinkOrDownlink,
            pdu_session_id: 5,
            data: vec![0xaa, 0xbb],
        },
    );
    // An SMS: data type 001 and five spare bits
    both_ways(
        octets("20 aabb"),
        Contents::Sms {
            data: vec![0xaa, 0xbb],
        },
    );
    // A location services message container whose additional information is all
    // that follows its length, then one with data contents after it
    both_ways(
        octets("50 03 010203"),
        Contents::LocationServicesMessageContainer {
            downlink_data_expected: Ddx::SingleDownlinkNoFurtherUplink,
            additional_information: vec![1, 2, 3],
            data: Vec::new(),
        },
    );
    both_ways(
        octets("48 03 010203 aabb"),
        Contents::LocationServicesMessageContainer {
            downlink_data_expected: Ddx::NoFurtherUplinkOrDownlink,
            additional_information: vec![1, 2, 3],
            data: vec![0xaa, 0xbb],
        },
    );
}

#[test]
fn spare_bits_a_short_additional_information_and_a_length_are_refused() {
    for value in [
        // An SMS with a spare bit set
        octets("21 aabb"),
        // Additional information of 3 octets, of which 2 are there
        octets("40 03 0102"),
    ] {
        let container = Container::new(value.clone());
        assert_eq!(container.parse(), None, "{value:02x?}");
        assert!(container.validate_strict().is_err(), "{value:02x?}");
    }
    // Contents of 255 octets at most, and of one at least
    let mut largest = vec![0x20];
    largest.resize(255, 0xaa);
    assert!(Container::new(largest.clone()).parse().is_some());
    assert!(Container::new(largest.clone()).validate_strict().is_ok());
    largest.push(0xaa);
    assert_eq!(Container::new(largest.clone()).parse(), None);
    assert!(Container::new(largest).validate_strict().is_err());
    assert!(Container::new(Vec::new()).validate_strict().is_err());
}

#[test]
fn the_strict_check_says_which_field_of_the_data_type_is_wrong() {
    // An SMS with a spare bit set, refused for its spare bits and not for its parse
    let error = Container::new(octets("21 aabb"))
        .validate_strict()
        .unwrap_err();
    assert!(error.to_string().contains("spare bits"), "{error}");
}
