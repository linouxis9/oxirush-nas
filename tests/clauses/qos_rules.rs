//! The packet filter components of a QoS rule (TS 24.501 §9.11.4.13, Table
//! 9.11.4.13.1): a type identifier, then a value of a length that the type fixes,
//! or the (S)RTP multiplexed media identification information of figures
//! 9.11.4.13.5 and 9.11.4.13.6.

use oxirush_nas::nas_5gs::{
    NasQosRules, QosPacketFilter, QosPacketFilterComponent as Component, QosPacketFilterDirection,
    QosRule, QosRuleOpCode, QosSrtpMultiplexedMediaIdentificationInformationEntry as SrtpEntry,
};

/// The rule 1 that creates the packet filter 1 of `components`, in both
/// directions, at the precedence 255 for the QFI 1 without segregation; and the
/// octets of the IE that holds it, whose packet filter has the contents
/// `contents`.
fn rule_of(components: Vec<Component>, contents: &str) -> (QosRule, String) {
    let filter = QosPacketFilter::Match {
        direction: QosPacketFilterDirection::Bidirectional,
        identifier: 1,
        components,
    };
    let rule = QosRule::new(1, QosRuleOpCode::Create)
        .with_packet_filters(vec![filter])
        .with_precedence(255)
        .with_qfi(1)
        .with_segregation(false);
    let contents: String = contents.split_whitespace().collect();
    let length = contents.len() / 2;
    // The identifier, the length of the rule, "create new QoS rule" with one
    // packet filter (001 0 0001), the filter of both directions (11) with the
    // identifier 1 and the length of its contents, the precedence and the QFI
    let octets = format!("01{:04x}2131{length:02x}{contents}ff01", length + 5);
    (rule, octets)
}

/// The rule encodes to `octets`, and both readers of the IE give it back.
fn assert_coded(rule: QosRule, octets: &str) {
    let ie = NasQosRules::from_rules(&[rule.clone()]).unwrap();
    assert_eq!(hex::encode(&ie.value), octets);
    let received = NasQosRules::new(hex::decode(octets).unwrap());
    assert_eq!(received.rules(), [rule.clone()]);
    assert_eq!(received.parse_rules(), [Ok(rule)]);
    assert!(received.validate_strict().is_ok());
}

#[test]
fn the_match_all_component_has_no_value() {
    let (rule, octets) = rule_of(vec![Component::MatchAll], "01");
    assert_coded(rule, &octets);
}

#[test]
fn the_ipv4_components_have_addresses_masks_ports_and_the_type_of_service() {
    let components = vec![
        Component::Ipv4RemoteAddress {
            address: [10, 0, 0, 1],
            mask: [255, 255, 255, 0],
        },
        Component::Ipv4LocalAddress {
            address: [192, 168, 1, 2],
            mask: [255, 255, 0, 0],
        },
        Component::ProtocolIdentifierOrNextHeader(17),
        Component::SingleLocalPort(5060),
        Component::RemotePortRange {
            low: 1000,
            high: 2000,
        },
        Component::SecurityParameterIndex(0x0102_0304),
        Component::TypeOfServiceOrTrafficClass {
            value: 0xb8,
            mask: 0xfc,
        },
    ];
    let contents = "10 0a000001 ffffff00  11 c0a80102 ffff0000  30 11  40 13c4  \
                    51 03e8 07d0  60 01020304  70 b8fc";
    let (rule, octets) = rule_of(components, contents);
    assert_coded(rule, &octets);
}

#[test]
fn the_ipv6_components_have_prefixes_ports_and_the_flow_label() {
    let mut remote = [0; 16];
    remote[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    remote[15] = 1;
    let mut local = [0; 16];
    local[..2].copy_from_slice(&[0xfe, 0x80]);
    local[15] = 2;
    let components = vec![
        Component::Ipv6RemoteAddressPrefix {
            address: remote,
            prefix_length: 64,
        },
        Component::Ipv6LocalAddressPrefix {
            address: local,
            prefix_length: 128,
        },
        Component::LocalPortRange { low: 10, high: 20 },
        Component::SingleRemotePort(443),
        // The bits 8 to 5 of the first octet are spare
        Component::FlowLabel([0x0a, 0xbc, 0xde]),
    ];
    let contents = "21 20010db8000000000000000000000001 40  \
                    23 fe800000000000000000000000000002 80  \
                    41 000a 0014  50 01bb  80 0abcde";
    let (rule, octets) = rule_of(components, contents);
    assert_coded(rule, &octets);
}

#[test]
fn the_ethernet_components_have_addresses_tags_and_the_ethertype() {
    let components = vec![
        Component::DestinationMacAddress([0x02, 0, 0, 0, 0, 0x01]),
        Component::SourceMacAddress([0x02, 0, 0, 0, 0, 0x02]),
        Component::CTagVid(0x123),
        Component::STagVid(0x456),
        // The PCP in the bits 4 to 2, the DEI in the bit 1
        Component::CTagPcpDei {
            pcp_present: true,
            dei_present: true,
            pcp: 5,
            dei: true,
        },
        Component::STagPcpDei {
            pcp_present: true,
            dei_present: true,
            pcp: 3,
            dei: false,
        },
        Component::Ethertype(0x88f7),
    ];
    let contents = "81 020000000001  82 020000000002  83 0123  84 0456  85 0b  86 06  87 88f7";
    let (rule, octets) = rule_of(components, contents);
    assert_coded(rule, &octets);
}

#[test]
fn the_mac_address_ranges_and_the_extended_tags_say_what_they_have() {
    let components = vec![
        Component::DestinationMacAddressRange {
            low: [0x02, 0, 0, 0, 0, 0x10],
            high: [0x02, 0, 0, 0, 0, 0x1f],
        },
        Component::SourceMacAddressRange {
            low: [0x02, 0, 0, 0, 0, 0x20],
            high: [0x02, 0, 0, 0, 0, 0x2f],
        },
        // Figures 9.11.4.13.7 and 9.11.4.13.8: the PCP indicator in the bit 6
        // and the DEI indicator in the bit 5, each before a field that is
        // used only when it is set
        Component::ExtendedCTagPcpDei {
            pcp_present: true,
            dei_present: false,
            pcp: 6,
            dei: false,
        },
        Component::ExtendedSTagPcpDei {
            pcp_present: false,
            dei_present: true,
            pcp: 0,
            dei: true,
        },
    ];
    let contents = "88 020000000010 02000000001f  89 020000000020 02000000002f  8a 2c  8b 11";
    let (rule, octets) = rule_of(components, contents);
    assert_coded(rule, &octets);
}

#[test]
fn an_srtp_entry_has_the_fields_that_its_indicators_say() {
    let components = vec![
        Component::Ipv4RemoteAddress {
            address: [10, 0, 0, 1],
            mask: [255; 4],
        },
        Component::SrtpMultiplexedMediaIdentificationInformation {
            entries: vec![
                SrtpEntry::new(Some(0x1122_3344), Some(96), None, None, None),
                SrtpEntry::new(None, None, Some(b"a1".to_vec()), Some(vec![3]), Some(200)),
            ],
        },
    ];
    // Two entries, each with its length and its indicators (RPTPI, RSHEMPI,
    // MITPI, PTPI and SSRCPI from the bit 5 to the bit 1): the SSRC and the
    // payload type; the MID identification-tag with its length, the RTP SDES
    // header extension id for MID and the RTCP packet type
    let contents = "10 0a000001 ffffffff  91 02  06 03 11223344 60  06 1c 02 6131 03 c8";
    let (rule, octets) = rule_of(components, contents);
    assert_coded(rule, &octets);
}

#[test]
fn a_component_may_follow_the_srtp_information() {
    // The (S)RTP information is the one component whose value has no fixed
    // length: its number of entries and the length of each say where it ends,
    // and the clause puts it at no place of its own among the components.
    let components = vec![
        Component::Ipv4RemoteAddress {
            address: [10, 0, 0, 1],
            mask: [255; 4],
        },
        Component::SrtpMultiplexedMediaIdentificationInformation {
            entries: vec![SrtpEntry::new(Some(0x1122_3344), None, None, None, None)],
        },
        Component::ProtocolIdentifierOrNextHeader(17),
    ];
    let contents = "10 0a000001 ffffffff  91 01 05 01 11223344  30 11";
    let (rule, octets) = rule_of(components, contents);
    assert_coded(rule, &octets);
}

/// A packet filter of these components, in a rule that creates it.
fn rule_with(components: Vec<Component>) -> QosRule {
    rule_of(components, "").0
}

#[test]
fn a_packet_filter_has_components_that_go_together() {
    let v4 = Component::Ipv4RemoteAddress {
        address: [10, 0, 0, 1],
        mask: [255; 4],
    };
    let v4_local = Component::Ipv4LocalAddress {
        address: [10, 0, 0, 2],
        mask: [255; 4],
    };
    let v6 = |prefix_length| Component::Ipv6RemoteAddressPrefix {
        address: [0x20; 16],
        prefix_length,
    };
    let v6_local = |prefix_length| Component::Ipv6LocalAddressPrefix {
        address: [0x20; 16],
        prefix_length,
    };
    let mac = Component::DestinationMacAddress([2, 0, 0, 0, 0, 1]);
    let mac_range = Component::DestinationMacAddressRange {
        low: [2, 0, 0, 0, 0, 1],
        high: [2, 0, 0, 0, 0, 9],
    };
    let source_mac = Component::SourceMacAddress([2, 0, 0, 0, 0, 1]);
    let source_mac_range = Component::SourceMacAddressRange {
        low: [2, 0, 0, 0, 0, 1],
        high: [2, 0, 0, 0, 0, 9],
    };
    let tag = |pcp| Component::CTagPcpDei {
        pcp_present: true,
        dei_present: true,
        pcp,
        dei: false,
    };
    let extended_tag = Component::ExtendedCTagPcpDei {
        pcp_present: true,
        dei_present: false,
        pcp: 1,
        dei: false,
    };
    let s_tag = Component::STagPcpDei {
        pcp_present: true,
        dei_present: true,
        pcp: 1,
        dei: false,
    };
    let extended_s_tag = Component::ExtendedSTagPcpDei {
        pcp_present: false,
        dei_present: true,
        pcp: 0,
        dei: true,
    };
    let srtp = |entries| Component::SrtpMultiplexedMediaIdentificationInformation { entries };
    let ssrc = SrtpEntry::new(Some(1), None, None, None, None);

    // Each type at most once, one of each pair that the clause names, the
    // match-all type alone, and values that the clause allows
    let refused = [
        ("no component", vec![]),
        (
            "the match-all type with another",
            vec![Component::MatchAll, v4.clone()],
        ),
        (
            "the match-all type after another",
            vec![v4.clone(), Component::MatchAll],
        ),
        ("two IPv4 remote addresses", vec![v4.clone(), v4.clone()]),
        (
            "two IPv4 local addresses",
            vec![v4_local.clone(), v4_local.clone()],
        ),
        (
            "an IPv4 and an IPv6 remote address",
            vec![v4.clone(), v6(64)],
        ),
        (
            "an IPv6 and an IPv4 remote address",
            vec![v6(64), v4.clone()],
        ),
        (
            "an IPv6 remote and an IPv4 local address",
            vec![v6(64), v4_local.clone()],
        ),
        (
            "an IPv4 remote and an IPv6 local address",
            vec![v4.clone(), v6_local(64)],
        ),
        ("two IPv6 local prefixes", vec![v6_local(64), v6_local(64)]),
        ("two IPv6 remote prefixes", vec![v6(64), v6(64)]),
        ("an IPv6 remote prefix of 129 bits", vec![v6(129)]),
        ("an IPv6 local prefix of 129 bits", vec![v6_local(129)]),
        (
            "two protocols",
            vec![Component::ProtocolIdentifierOrNextHeader(6); 2],
        ),
        (
            "a single local port and a local port range",
            vec![
                Component::SingleLocalPort(1),
                Component::LocalPortRange { low: 2, high: 3 },
            ],
        ),
        (
            "a local port range down",
            vec![Component::LocalPortRange { low: 3, high: 2 }],
        ),
        (
            "a single remote port and a remote port range",
            vec![
                Component::SingleRemotePort(1),
                Component::RemotePortRange { low: 2, high: 3 },
            ],
        ),
        (
            "a remote port range down",
            vec![Component::RemotePortRange { low: 3, high: 2 }],
        ),
        (
            "two security parameter indexes",
            vec![Component::SecurityParameterIndex(1); 2],
        ),
        (
            "two types of service",
            vec![Component::TypeOfServiceOrTrafficClass { value: 1, mask: 1 }; 2],
        ),
        ("two flow labels", vec![Component::FlowLabel([0, 0, 1]); 2]),
        (
            "a flow label with its spare bits",
            vec![Component::FlowLabel([0x10, 0, 1])],
        ),
        (
            "a destination MAC address and a range",
            vec![mac.clone(), mac_range.clone()],
        ),
        (
            "a source MAC address and a range",
            vec![source_mac, source_mac_range],
        ),
        ("two C-TAG VIDs", vec![Component::CTagVid(1); 2]),
        ("a C-TAG VID of 13 bits", vec![Component::CTagVid(0x1000)]),
        ("two S-TAG VIDs", vec![Component::STagVid(1); 2]),
        ("an S-TAG VID of 13 bits", vec![Component::STagVid(0x1000)]),
        (
            "a C-TAG PCP/DEI and its extended form",
            vec![tag(1), extended_tag],
        ),
        (
            "an S-TAG PCP/DEI and its extended form",
            vec![s_tag, extended_s_tag],
        ),
        ("two ethertypes", vec![Component::Ethertype(0x0800); 2]),
        (
            "two (S)RTP informations",
            vec![
                v4.clone(),
                srtp(vec![ssrc.clone()]),
                srtp(vec![ssrc.clone()]),
            ],
        ),
        (
            "an (S)RTP information without entries",
            vec![v4.clone(), srtp(vec![])],
        ),
        (
            "an (S)RTP entry without a field",
            vec![
                v4.clone(),
                srtp(vec![SrtpEntry::new(None, None, None, None, None)]),
            ],
        ),
        (
            "an (S)RTP payload type of 128",
            vec![
                v4.clone(),
                srtp(vec![SrtpEntry::new(None, Some(128), None, None, None)]),
            ],
        ),
        (
            "a component of a reserved type",
            vec![Component::Unknown {
                component_type: 0x92,
                contents: vec![0],
            }],
        ),
    ];
    for (what, components) in refused {
        let refusal = NasQosRules::from_rules(&[rule_with(components)]);
        assert!(refusal.is_err(), "{what}");
    }

    // The bounds that the clause allows
    let allowed = [
        ("an IPv6 remote prefix of 128 bits", vec![v6(128)]),
        ("an IPv6 local prefix of 128 bits", vec![v6_local(128)]),
        (
            "a local port range of one port",
            vec![Component::LocalPortRange { low: 2, high: 2 }],
        ),
        (
            "a remote port range of one port",
            vec![Component::RemotePortRange { low: 2, high: 2 }],
        ),
        (
            "VIDs of 12 bits",
            vec![Component::CTagVid(0xfff), Component::STagVid(0xfff)],
        ),
        (
            "a flow label of 20 bits",
            vec![Component::FlowLabel([0x0f, 0xff, 0xff])],
        ),
        ("a destination MAC address range alone", vec![mac_range]),
        (
            "the C-TAG and the S-TAG",
            vec![
                tag(7),
                Component::ExtendedSTagPcpDei {
                    pcp_present: true,
                    dei_present: true,
                    pcp: 7,
                    dei: true,
                },
            ],
        ),
        (
            "an (S)RTP payload type of 127",
            vec![
                v4,
                srtp(vec![SrtpEntry::new(None, Some(127), None, None, None)]),
            ],
        ),
    ];
    for (what, components) in allowed {
        let rule = rule_with(components);
        let ie = NasQosRules::from_rules(std::slice::from_ref(&rule));
        assert_eq!(ie.map(|ie| ie.rules()).ok(), Some(vec![rule]), "{what}");
    }
}

#[test]
fn a_received_rule_has_what_its_operation_takes() {
    use oxirush_nas::nas_5gs::QosError::{SyntacticalPacketFilter, SyntacticalQosOperation};
    let parsed = |octets: &str| {
        let rules = NasQosRules::new(hex::decode(octets).unwrap()).parse_rules();
        assert_eq!(rules.len(), 1, "{octets}");
        rules.into_iter().next().unwrap()
    };
    let error = |octets: &str| parsed(octets).map(|_| ()).unwrap_err().error;

    // "Delete existing QoS rule" (010) has no packet filter, no precedence
    // and no QFI; "modify existing QoS rule without modifying packet filters"
    // (110) has no packet filter
    assert_eq!(error("01000241ff"), SyntacticalQosOperation);
    assert_eq!(error("01000240ff"), SyntacticalQosOperation);
    assert_eq!(error("010002c100"), SyntacticalQosOperation);
    let deleted = parsed("01000140").unwrap();
    assert_eq!(
        (deleted.op_code, deleted.precedence, deleted.qfi),
        (QosRuleOpCode::Delete, None, None)
    );
    let modified = parsed("010002c00a").unwrap();
    assert_eq!(
        (modified.op_code, modified.precedence, modified.qfi),
        (QosRuleOpCode::ModifyNoFilters, Some(10), None)
    );
    // A packet filter of two protocol components, and one of a reserved
    // direction (00)
    assert_eq!(error("01000921310430063011ff01"), SyntacticalPacketFilter);
    assert_eq!(error("01000621010101ff01"), SyntacticalPacketFilter);
}
