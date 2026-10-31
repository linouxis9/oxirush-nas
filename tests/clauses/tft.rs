//! The packet filter components and the parameters of an EPS traffic flow template
//! (TS 24.008 §10.5.6.12, Table 10.5.162), which TS 24.301 takes.

use oxirush_nas::nas_eps::{
    TftPacketFilter, TftPacketFilterComponent as Component, TftPacketFilterDirection, TftParameter,
    TftParameterValue,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// The filter 1 of `components` has the contents `contents`, which decode back
/// to them.
fn assert_coded(components: &[Component], contents: &str) {
    let filter = TftPacketFilter::from_components(
        1,
        TftPacketFilterDirection::Bidirectional,
        10,
        components,
    )
    .unwrap();
    assert_eq!(filter.contents, octets(contents));
    assert_eq!(filter.components().as_deref(), Some(components));
}

const ADDRESS: [u8; 16] = [
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
];
const PREFIX: &str = "20010db8000000000000000000000001";

#[test]
fn the_ipv4_components_have_addresses_masks_ports_and_the_type_of_service() {
    let components = [
        Component::Ipv4RemoteAddress {
            address: [10, 0, 0, 1],
            mask: [255, 255, 255, 0],
        },
        Component::Ipv4LocalAddress {
            address: [192, 168, 1, 2],
            mask: [255, 255, 0, 0],
        },
        Component::ProtocolIdentifierNextHeader(17),
        Component::SingleLocalPort(5060),
        Component::RemotePortRange {
            low: 1000,
            high: 2000,
        },
        Component::SecurityParameterIndex(0x0102_0304),
        Component::TypeOfServiceTrafficClass {
            value: 0xb8,
            mask: 0xfc,
        },
    ];
    let contents = "10 0a000001 ffffff00  11 c0a80102 ffff0000  30 11  40 13c4  \
                    51 03e8 07d0  60 01020304  70 b8fc";
    assert_coded(&components, contents);
}

#[test]
fn the_ipv6_components_have_an_address_and_its_mask_prefixes_and_the_flow_label() {
    let components = [
        Component::Ipv6RemoteAddress {
            address: ADDRESS,
            mask: [0xff; 16],
        },
        Component::Ipv6LocalAddressPrefix {
            address: ADDRESS,
            prefix_length: 128,
        },
        Component::LocalPortRange { low: 10, high: 20 },
        Component::SingleRemotePort(443),
        Component::FlowLabel(0xabcde),
    ];
    let contents = format!(
        "20 {PREFIX} ffffffffffffffffffffffffffffffff  23 {PREFIX} 80  \
         41 000a 0014  50 01bb  80 0abcde"
    );
    assert_coded(&components, &contents);
    let prefix = [Component::Ipv6RemoteAddressPrefix {
        address: ADDRESS,
        prefix_length: 64,
    }];
    assert_coded(&prefix, &format!("21 {PREFIX} 40"));
}

#[test]
fn the_ethernet_components_have_addresses_tags_and_the_ethertype() {
    let components = [
        Component::DestinationMacAddress([0x02, 0, 0, 0, 0, 0x01]),
        Component::SourceMacAddress([0x02, 0, 0, 0, 0, 0x02]),
        Component::CTagVid(0x123),
        Component::STagVid(0x456),
        // The PCP in the bits 4 to 2, the DEI in the bit 1
        Component::CTagPcpDei { pcp: 5, dei: true },
        Component::STagPcpDei { pcp: 3, dei: false },
        Component::Ethertype(0x88f7),
    ];
    let contents = "81 020000000001  82 020000000002  83 0123  84 0456  85 0b  86 06  87 88f7";
    assert_coded(&components, contents);
    // The ethertypes of IPv4 and IPv6 go with IP components
    for ethertype in [0x0800, 0x86dd] {
        let components = [
            Component::Ethertype(ethertype),
            Component::ProtocolIdentifierNextHeader(6),
        ];
        assert_coded(&components, &format!("87 {ethertype:04x}  30 06"));
    }
}

#[test]
fn a_receiver_ignores_the_spare_bits_of_a_component() {
    let filter = TftPacketFilter::new(1, 3, Some(10), octets("80 fabcde  83 f123  84 e456  85 fb"));
    assert_eq!(
        filter.components(),
        Some(vec![
            Component::FlowLabel(0xabcde),
            Component::CTagVid(0x123),
            Component::STagVid(0x456),
            Component::CTagPcpDei { pcp: 5, dei: true },
        ])
    );
    assert_eq!(
        filter.direction_value(),
        TftPacketFilterDirection::Bidirectional
    );
    for (direction, value) in [
        (0, TftPacketFilterDirection::PreRel7),
        (1, TftPacketFilterDirection::Downlink),
        (2, TftPacketFilterDirection::Uplink),
    ] {
        assert_eq!(
            TftPacketFilter::new(1, direction, None, vec![]).direction_value(),
            value
        );
    }
}

#[test]
fn a_packet_filter_has_components_that_go_together() {
    let v4 = Component::Ipv4RemoteAddress {
        address: [10, 0, 0, 1],
        mask: [255; 4],
    };
    let v6 = Component::Ipv6RemoteAddress {
        address: ADDRESS,
        mask: [0xff; 16],
    };
    let v6_prefix = Component::Ipv6RemoteAddressPrefix {
        address: ADDRESS,
        prefix_length: 64,
    };
    let v4_local = Component::Ipv4LocalAddress {
        address: [10, 0, 0, 1],
        mask: [255; 4],
    };
    let v6_local = Component::Ipv6LocalAddressPrefix {
        address: ADDRESS,
        prefix_length: 64,
    };
    let refused = [
        ("no component", vec![]),
        (
            "two protocols",
            vec![Component::ProtocolIdentifierNextHeader(6); 2],
        ),
        (
            "an IPv4 and an IPv6 remote address",
            vec![v4.clone(), v6.clone()],
        ),
        (
            "an IPv4 remote address and an IPv6 prefix",
            vec![v4, v6_prefix.clone()],
        ),
        ("an IPv6 remote address and prefix", vec![v6, v6_prefix]),
        (
            "an IPv4 and an IPv6 local address",
            vec![v4_local, v6_local],
        ),
        (
            "a single local port and a range",
            vec![
                Component::SingleLocalPort(1),
                Component::LocalPortRange { low: 1, high: 2 },
            ],
        ),
        (
            "a single remote port and a range",
            vec![
                Component::SingleRemotePort(1),
                Component::RemotePortRange { low: 1, high: 2 },
            ],
        ),
        (
            "an ethertype of neither IP with an IP component",
            vec![Component::Ethertype(0x88f7), Component::SingleRemotePort(1)],
        ),
        (
            "a flow label of 21 bits",
            vec![Component::FlowLabel(0x10_0000)],
        ),
        ("a C-TAG VID of 13 bits", vec![Component::CTagVid(0x1000)]),
        ("an S-TAG VID of 13 bits", vec![Component::STagVid(0x1000)]),
        (
            "a C-TAG PCP of 4 bits",
            vec![Component::CTagPcpDei { pcp: 8, dei: false }],
        ),
        (
            "an S-TAG PCP of 4 bits",
            vec![Component::STagPcpDei { pcp: 8, dei: false }],
        ),
    ];
    for (what, components) in refused {
        let filter =
            TftPacketFilter::from_components(1, TftPacketFilterDirection::Uplink, 10, &components);
        assert!(filter.is_err(), "{what}");
    }
    let identifier = TftPacketFilter::from_components(
        16,
        TftPacketFilterDirection::Uplink,
        10,
        &[Component::ProtocolIdentifierNextHeader(6)],
    );
    assert!(identifier.is_err());
    // Received contents of a reserved type, cut short, or with a component
    // twice
    for contents in ["90 00", "10 0a0000", "30 06 30 11", ""] {
        let filter = TftPacketFilter::new(1, 3, Some(10), octets(contents));
        assert_eq!(filter.components(), None, "{contents}");
    }
}

#[test]
fn a_parameter_has_the_value_of_its_identifier() {
    let value = |identifier, contents: &[u8]| TftParameter {
        identifier,
        contents: contents.to_vec(),
    };
    assert_eq!(
        value(1, b"token").value(),
        TftParameterValue::AuthorizationToken(b"token")
    );
    // The media component number, then the IP flow number
    assert_eq!(
        value(2, &[0, 1, 0, 2]).value(),
        TftParameterValue::FlowIdentifier {
            media_component: 1,
            ip_flow: 2,
        }
    );
    // The packet filter identifiers in the bits 4 to 1 of each octet
    assert_eq!(
        value(3, &[0x31, 0x02]).value(),
        TftParameterValue::PacketFilterIdentifiers(vec![1, 2])
    );
    for (identifier, contents) in [(2, &[0, 1, 0][..]), (3, &[][..]), (4, &[1][..])] {
        let parameter = value(identifier, contents);
        assert_eq!(
            parameter.value(),
            TftParameterValue::Unsupported,
            "{identifier}"
        );
    }
}
