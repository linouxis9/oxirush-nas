//! The non-3GPP device information (TS 24.501 §9.11.4.41): the PDU session type,
//! then each device with its identifier and the connection information of that
//! type, whose first octet says which fields follow. The VLAN tag ID of an
//! Ethernet device is the VLAN ID in its high 12 bits, as V20.1.0 has it.

use oxirush_nas::nas_5gs::{
    NasNon3GppDeviceInformation, Non3GppDeviceConnectionInformation as Connection,
    Non3GppDeviceInformationEntry as Device, Non3GppIpv4AddressInformation as Ipv4,
    Non3GppIpv6AddressInformation as Ipv6, PduSessionTypeValue, PortRange,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// The IE of `devices` encodes to `value`, which decodes back to them.
fn assert_coded(session_type: PduSessionTypeValue, devices: &[Device], value: &str) {
    let value = octets(value);
    let ie = NasNon3GppDeviceInformation::from_entries(session_type, devices).unwrap();
    assert_eq!(ie.value, value);
    let received = NasNon3GppDeviceInformation::new(value);
    assert_eq!(received.pdu_session_type(), Some(session_type));
    assert_eq!(received.entries(), devices);
    assert!(received.validate_strict().is_ok());
}

const ADDRESS: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];

fn ranges(ranges: &[(u16, u16)]) -> Vec<PortRange> {
    ranges
        .iter()
        .map(|&(low, high)| PortRange { low, high })
        .collect()
}

#[test]
fn an_ipv4_device_has_an_address_and_port_ranges_or_neither() {
    let devices = [
        Device::new(
            vec![0xaa, 0xbb],
            Some(Connection::Ipv4 {
                ipv4_address: Some([10, 0, 0, 9]),
                ipv4_port_ranges: ranges(&[(1000, 1999), (3000, 3000)]),
            }),
        ),
        Device::new(
            vec![0xcc],
            Some(Connection::Ipv4 {
                ipv4_address: None,
                ipv4_port_ranges: ranges(&[(80, 80)]),
            }),
        ),
        // Without connection information, to suspend the QoS differentiation
        Device::without_connection_information(vec![0xdd]),
    ];
    // The type 001; each device with its length, the length of its
    // identifier, the identifier, then I4PRPI in the bit 2 and I4API in the
    // bit 1, the address, and the number of port ranges with each range
    let value = "01  11 02 aabb 03 0a000009 02 03e807cf 0bb80bb8  \
                 08 01 cc 02 01 00500050  02 01 dd";
    assert_coded(PduSessionTypeValue::Ipv4, &devices, value);
    assert!(devices[2].is_qos_differentiation_suspended());
    assert!(!devices[0].is_qos_differentiation_suspended());
    assert!(devices[0].has_connection_information());
}

#[test]
fn an_ipv6_device_has_an_address_or_a_prefix() {
    let devices = [
        Device::new(
            vec![0x01],
            Some(Connection::Ipv6 {
                ipv6: Ipv6::Prefix {
                    address: ADDRESS,
                    prefix_length: 48,
                },
                ipv6_port_ranges: ranges(&[(80, 80)]),
            }),
        ),
        Device::new(
            vec![0x02],
            Some(Connection::Ipv6 {
                ipv6: Ipv6::Address(ADDRESS),
                ipv6_port_ranges: vec![],
            }),
        ),
    ];
    // I6PRPI in the bit 2, and I6ATI in the bit 1 for a prefix, which has
    // the length after the address
    let value = "02  19 01 01 03 20010db8000000000000000000000001 30 01 00500050  \
                 13 01 02 00 20010db8000000000000000000000001";
    assert_coded(PduSessionTypeValue::Ipv6, &devices, value);
}

#[test]
fn an_ipv4v6_device_says_which_address_applies() {
    let devices = [
        Device::new(
            vec![0x01],
            Some(Connection::Ipv4v6 {
                ipv4: Ipv4::Address([10, 0, 0, 1]),
                ipv4_port_ranges: ranges(&[(1, 2)]),
                ipv6: Some(Ipv6::Prefix {
                    address: ADDRESS,
                    prefix_length: 64,
                }),
                ipv6_port_ranges: ranges(&[(3, 4)]),
            }),
        ),
        Device::new(
            vec![0x02],
            Some(Connection::Ipv4v6 {
                ipv4: Ipv4::PduSessionAddressApplies,
                ipv4_port_ranges: vec![],
                ipv6: Some(Ipv6::Address(ADDRESS)),
                ipv6_port_ranges: vec![],
            }),
        ),
        Device::new(
            vec![0x03],
            Some(Connection::Ipv4v6 {
                ipv4: Ipv4::NotApplicable,
                ipv4_port_ranges: ranges(&[(5, 6)]),
                ipv6: None,
                ipv6_port_ranges: ranges(&[(7, 8)]),
            }),
        ),
    ];
    // I6PRPI in the bit 6, I6APPI in the bits 5 and 4 (01 an address, 10 a
    // prefix), I4PRPI in the bit 3 and I4API in the bits 2 and 1 (01 an
    // address, 10 that of the PDU session)
    let value = "03  22 01 01 35 0a000001 01 00010002 \
                 20010db8000000000000000000000001 40 01 00030004  \
                 13 01 02 0a 20010db8000000000000000000000001  \
                 0d 01 03 24 01 00050006 01 00070008";
    assert_coded(PduSessionTypeValue::Ipv4v6, &devices, value);
}

#[test]
fn an_ethernet_device_has_a_mac_address_and_a_vlan_id() {
    let devices = [
        Device::new(
            vec![0x01],
            Some(Connection::Ethernet {
                mac_address: [0x02, 0, 0, 0, 0, 0x07],
                vlan_tag_id: Some(0x123),
            }),
        ),
        Device::new(
            vec![0x02],
            Some(Connection::Ethernet {
                mac_address: [0x02, 0, 0, 0, 0, 0x08],
                vlan_tag_id: None,
            }),
        ),
    ];
    // VTPI in the bit 1, the MAC address, and the VLAN ID in the 12 high bits
    let value = "05  0b 01 01 01 020000000007 1230  09 01 02 00 020000000008";
    assert_coded(PduSessionTypeValue::Ethernet, &devices, value);
}

#[test]
fn a_receiver_refuses_spare_bits_and_what_the_session_type_does_not_have() {
    let refused = [
        // Spare bits of the PDU session type, of the length of the identifier,
        // and of the indicators of each type
        "09  02 01 dd",
        "01  02 41 dd",
        "01  03 01 dd 04",
        "02  13 01 02 04 20010db8000000000000000000000001",
        "03  04 01 03 40 00",
        "05  0b 01 01 03 020000000007 1230",
        // The low four bits of the VLAN tag ID are spare
        "05  0b 01 01 01 020000000007 1231",
        // A reserved I4API and a reserved I6APPI
        "03  04 01 03 03 00",
        "03  13 01 03 18 20010db8000000000000000000000001",
        // A port range beyond the device
        "01  04 01 dd 02 01",
    ];
    for value in refused {
        let ie = NasNon3GppDeviceInformation::new(octets(value));
        assert!(ie.validate_strict().is_err(), "{value}");
    }
    // The PDU session type "unstructured" has no device information
    let unstructured = NasNon3GppDeviceInformation::new(octets("04  02 01 dd"));
    assert_eq!(unstructured.pdu_session_type(), None);
    assert_eq!(unstructured.entries(), []);
    let devices = [Device::without_connection_information(vec![0xdd])];
    let refusal =
        NasNon3GppDeviceInformation::from_entries(PduSessionTypeValue::Unstructured, &devices);
    assert!(refusal.is_err());
    // Connection information of another PDU session type, and a VLAN ID of
    // more than 12 bits, are refused
    let ipv4 = Connection::Ipv4 {
        ipv4_address: None,
        ipv4_port_ranges: vec![],
    };
    let other = [Device::new(vec![1], Some(ipv4))];
    assert!(NasNon3GppDeviceInformation::from_entries(PduSessionTypeValue::Ipv6, &other).is_err());
    let vlan = Connection::Ethernet {
        mac_address: [0; 6],
        vlan_tag_id: Some(0x1000),
    };
    let wide = [Device::new(vec![1], Some(vlan))];
    let refusal = NasNon3GppDeviceInformation::from_entries(PduSessionTypeValue::Ethernet, &wide);
    assert!(refusal.is_err());
}
