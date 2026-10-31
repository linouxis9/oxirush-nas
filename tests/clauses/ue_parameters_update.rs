//! The UE parameters update transparent container (TS 24.501 §9.11.3.53A): the
//! header, UPU-MAC-IAUSF, CounterUPU and the data sets of an update list, each of
//! its type, in a field of four bits, and of its length; or the header and
//! UPU-MAC-IUE of an acknowledgement.

use oxirush_nas::nas_5gs::{
    NasNssai, NasUeParametersUpdateTransparentContainer as Container,
    UeParametersUpdateAcknowledgementContents as Acknowledgement, UeParametersUpdateDataSet as Set,
    UeParametersUpdateDataType, UeParametersUpdateDisasterRoamingInformation as DisasterRoaming,
    UeParametersUpdateListContents as UpdateList, UeParametersUpdateProtectedHeaderInformation,
    UeParametersUpdateTransparentContainerContents as Contents,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

#[test]
fn an_update_list_has_each_data_set_with_its_type_and_its_length() {
    let header = UeParametersUpdateProtectedHeaderInformation::new(
        false,
        true,
        UeParametersUpdateDataType::UpdateList,
    );
    let list = UpdateList::new(
        true,
        true,
        [0xab; 16],
        7,
        vec![
            Set::RoutingIndicatorUpdateData(vec![1, 2, 3]),
            Set::DefaultConfiguredNssaiUpdateData(NasNssai::new(vec![0x01, 0x01])),
            Set::DisasterRoamingInformationUpdateData(DisasterRoaming::new(true, false, true)),
            Set::MeRoutingIndicatorUpdateData([0x21, 0x43]),
            Set::ProtectedUeParametersUpdateHeaderInformation(header),
        ],
    );
    // REG in the bit 3 and ACK in the bit 2 of the header; then the secured
    // packet, the default configured NSSAI, DREIEPS and DREI, the routing
    // indicator 1234, and the protected header with REG
    let value = octets(
        "06 abababababababababababababababab 0007 \
         01 0003 010203  02 0002 0101  03 0001 05  04 0002 2143  05 0001 04",
    );
    let contents = Contents::UpdateList(list);
    let container = Container::from_parsed(&contents).unwrap();
    assert_eq!(container.value, value);
    let received = Container::new(value);
    assert_eq!(received.parse(), Some(contents));
    assert_eq!(
        received.data_type(),
        Some(UeParametersUpdateDataType::UpdateList)
    );
    assert_eq!(received.acknowledgement_requested(), Some(true));
    assert_eq!(received.re_registration_requested(), Some(true));
    assert_eq!(received.header_protection_supported(), None);
}

#[test]
fn each_indication_of_the_header_is_its_own_bit() {
    for (ack, reg, header) in [
        (true, false, 0x02),
        (false, true, 0x04),
        (false, false, 0x00),
    ] {
        let contents = Contents::UpdateList(UpdateList::new(ack, reg, [0; 16], 0, vec![]));
        let container = Container::from_parsed(&contents).unwrap();
        assert_eq!(container.header_octet(), Some(header));
        assert_eq!(container.acknowledgement_requested(), Some(ack));
        assert_eq!(container.re_registration_requested(), Some(reg));
        assert_eq!(container.parse(), Some(contents));
    }
    for (roaming, octet) in [
        (DisasterRoaming::new(true, false, false), 0x01),
        (DisasterRoaming::new(false, true, false), 0x02),
        (DisasterRoaming::new(false, false, true), 0x04),
    ] {
        let set = Set::DisasterRoamingInformationUpdateData(roaming);
        let contents = Contents::UpdateList(UpdateList::new(false, false, [0; 16], 0, vec![set]));
        let container = Container::from_parsed(&contents).unwrap();
        assert_eq!(container.value[19..], [0x03, 0x00, 0x01, octet]);
        assert_eq!(container.parse(), Some(contents));
    }
}

#[test]
fn an_acknowledgement_has_the_header_protection_and_upu_mac_iue() {
    // The UPU data type in the bit 1 and UHP in the bit 2
    let value = octets("03 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    let contents = Contents::Acknowledgement(Acknowledgement::new(true, [0xee; 16]));
    assert_eq!(Container::from_parsed(&contents).unwrap().value, value);
    let received = Container::new(value);
    assert_eq!(received.parse(), Some(contents));
    assert_eq!(received.header_protection_supported(), Some(true));
    assert_eq!(received.acknowledgement_requested(), None);
    assert_eq!(received.re_registration_requested(), None);
    let without = Container::new(octets("01 eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"));
    assert_eq!(without.header_protection_supported(), Some(false));
}

#[test]
fn a_receiver_keeps_a_reserved_data_set_and_refuses_one_that_is_not_coded() {
    let start = "00 abababababababababababababababab 0007";
    let reserved = Container::new(octets(&format!("{start} 0f 0002 aabb")));
    let Some(Contents::UpdateList(list)) = reserved.parse() else {
        panic!("{:?}", reserved.parse());
    };
    assert_eq!(
        list.data_sets,
        [Set::Unknown {
            data_set_type: 0x0f,
            contents: vec![0xaa, 0xbb],
        }]
    );
    let refused = [
        // A data set beyond the container, and one without its length
        "01 0004 010203",
        "01 00",
        // An empty secured packet, an NSSAI that does not decode, a disaster
        // roaming information of two octets, a routing indicator of a digit
        // that is no digit, and a protected header of an acknowledgement
        "01 0000",
        "02 0001 05",
        "03 0002 0100",
        "04 0002 2a43",
        "05 0001 01",
    ];
    for data_sets in refused {
        let container = Container::new(octets(&format!("{start} {data_sets}")));
        assert_eq!(container.parse(), None, "{data_sets}");
    }
    // An update list without CounterUPU, and an acknowledgement without all
    // of UPU-MAC-IUE
    assert_eq!(
        Container::new(octets("00 abababababababababababababababab 00")).parse(),
        None
    );
    assert_eq!(
        Container::new(octets("01 eeeeeeeeeeeeeeeeeeeeeeeeeeeeee")).parse(),
        None
    );
}
