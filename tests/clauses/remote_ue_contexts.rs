//! The remote UE context list (TS 24.501 §9.11.4.29, Table 9.11.4.29.2): the number
//! of contexts, then each context after its length: the remote UE ID type in bits 3
//! to 1 and its format in bit 4, the ID after its length, the protocol used by the
//! remote UE in bits 3 to 1 with TPRI4I in bit 4 and UPRI4I in bit 5, the address
//! information of the protocol, and the HPLMN ID, present for a PRUK ID of the
//! 64-bit string format and absent otherwise.

use oxirush_nas::common::Plmn;
use oxirush_nas::nas_5gs::{
    NasRemoteUeContextList, PortRange, RemoteUeContext, RemoteUeIdFormat as Format, RemoteUeIdType,
    RemoteUeIdentifier as Id, RemoteUeProtocolInformation as Protocol,
};

fn list(octets: &str) -> NasRemoteUeContextList {
    NasRemoteUeContextList::new(hex::decode(octets.split_whitespace().collect::<String>()).unwrap())
}

fn plmn() -> Plmn {
    Plmn::new("208", "93").unwrap()
}

#[test]
fn the_remote_ue_id_type_is_its_three_bits() {
    let types = [
        (RemoteUeIdType::UpPrukId, 1),
        (RemoteUeIdType::CpPrukId, 2),
        (RemoteUeIdType::Imei, 3),
        (RemoteUeIdType::Imeisv, 4),
        (RemoteUeIdType::Unknown(5), 5),
    ];
    for (kind, code) in types {
        assert_eq!(kind.as_u8(), code);
        assert_eq!(RemoteUeIdType::from_u8(code), kind);
    }
}

#[test]
fn a_context_has_the_address_information_of_its_protocol() {
    let range = |low, high| Some(PortRange { low, high });
    let imei = || Id::Imei {
        value: vec![0x21, 0x43],
    };
    let contexts = [
        // IMEI 2143 (two octets), no IP info
        ("01 05 03 02 2143 00", imei(), Protocol::NoIpInfo),
        // IPv4 alone, with the UDP port range (UPRI4I), with the TCP one (TPRI4I),
        // and with both, the UDP range first
        (
            "01 09 03 02 2143 01 0a00002a",
            imei(),
            Protocol::Ipv4 {
                address: [10, 0, 0, 42],
                udp_port_range: None,
                tcp_port_range: None,
            },
        ),
        (
            "01 0d 03 02 2143 11 0a00002a 13881389",
            imei(),
            Protocol::Ipv4 {
                address: [10, 0, 0, 42],
                udp_port_range: range(5000, 5001),
                tcp_port_range: None,
            },
        ),
        (
            "01 0d 03 02 2143 09 0a00002a 17701778",
            imei(),
            Protocol::Ipv4 {
                address: [10, 0, 0, 42],
                udp_port_range: None,
                tcp_port_range: range(6000, 6008),
            },
        ),
        (
            "01 11 03 02 2143 19 0a00002a 13881389 17701778",
            imei(),
            Protocol::Ipv4 {
                address: [10, 0, 0, 42],
                udp_port_range: range(5000, 5001),
                tcp_port_range: range(6000, 6008),
            },
        ),
        // IPv6 prefix, unstructured and Ethernet
        (
            "01 0d 03 02 2143 02 20010db800000001",
            imei(),
            Protocol::Ipv6 {
                prefix: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1],
            },
        ),
        ("01 05 03 02 2143 04", imei(), Protocol::Unstructured),
        (
            "01 0b 03 02 2143 05 020000000001",
            imei(),
            Protocol::Ethernet {
                mac_address: [2, 0, 0, 0, 0, 1],
            },
        ),
        // A protocol of a reserved value, with its octets
        (
            "01 07 03 02 2143 1e 0102",
            imei(),
            Protocol::Unknown {
                protocol_raw: 6,
                udp_port_range_present: true,
                tcp_port_range_present: true,
                address_information: vec![1, 2],
            },
        ),
    ];
    for (octets, identifier, protocol) in contexts {
        let context = RemoteUeContext::new(identifier, protocol, None);
        let received = list(octets);
        assert_eq!(received.contexts(), Some(vec![context.clone()]), "{octets}");
        let written = NasRemoteUeContextList::from_contexts(&[context]).unwrap();
        assert_eq!(written.value, received.value, "{octets}");
    }
    // Address information that the protocol does not have
    for octets in [
        "01 06 03 02 2143 00 01",
        "01 0c 03 02 2143 02 20010db8000000",
        "01 06 03 02 2143 04 01",
        "01 0a 03 02 2143 05 0200000000",
    ] {
        assert_eq!(list(octets).contexts(), None, "{octets}");
    }
}

#[test]
fn a_prukid_of_64_bits_has_the_hplmn_id_after_the_address_information() {
    // UP-PRUK ID of the 64-bit string format (1001), no IP info, HPLMN 208 93; then a
    // CP-PRUK ID of the NAI format, which has none
    let octets = "02  0e 09 08 0102030405060708 00 02f839  04 02 01 61 00";
    let up = Id::UpPrukId {
        format: Format::BitString64,
        value: vec![1, 2, 3, 4, 5, 6, 7, 8],
    };
    let cp = Id::CpPrukId {
        format: Format::Nai,
        value: vec![b'a'],
    };
    let contexts = vec![
        RemoteUeContext::new(up.clone(), Protocol::NoIpInfo, Some(plmn())),
        RemoteUeContext::new(cp.clone(), Protocol::NoIpInfo, None),
    ];
    assert_eq!(list(octets).contexts(), Some(contexts.clone()));
    let written = NasRemoteUeContextList::from_contexts(&contexts).unwrap();
    assert_eq!(written.value, list(octets).value);
    // A PRUK ID of 64 bits without the HPLMN ID
    assert_eq!(list("01 0b 09 08 0102030405060708 00").contexts(), None);
}

#[test]
fn a_context_ends_where_its_length_says() {
    // A list that says two contexts and has one, a context of no octet, and an ID
    // longer than its context
    for octets in [
        "02 05 03 02 2143 00",
        "01 00",
        "01 03 03 09 21",
        // A context longer than the IE, whose ID runs past it
        "01 09 03 05 21",
    ] {
        assert_eq!(list(octets).contexts(), None, "{octets}");
    }
}
