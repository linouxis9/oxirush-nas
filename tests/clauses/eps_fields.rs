//! Fields of an octet that TS 24.301 takes from TS 24.008, and of its own: the
//! T3412 extended value, a GPRS timer 3 (§9.9.3.16B, TS 24.008 §10.5.7.4a), the
//! request type (§9.9.4.14, TS 24.008 §10.5.6.17), the ESM information transfer
//! flag (§9.9.4.5), the CS LCS of the EPS network feature support (§9.9.3.12A),
//! and the PDN address (§9.9.4.9).

use oxirush_nas::nas_eps::{
    CsLcsSupport, GprsTimer3Unit, NasEsmInformationTransferFlag, NasPdnAddress, NasRequestType,
    NasT3412ExtendedValue, PdnAddress, RequestTypeValue,
};

#[test]
fn a_t3412_extended_value_is_a_unit_and_a_value_of_five_bits() {
    // Table 10.5.163a: the unit in bits 8 to 6, 101 for a minute, and the value in
    // bits 5 to 1
    let timer = NasT3412ExtendedValue::new(vec![0b101_00011]);
    assert_eq!(timer.unit(), Some(GprsTimer3Unit::OneMinute));
    assert_eq!(timer.timer_value(), Some(3));
    assert!(timer.is_well_formed());
    let longest = NasT3412ExtendedValue::new(vec![0b000_11111]);
    assert_eq!(longest.unit(), Some(GprsTimer3Unit::TenMinutes));
    assert_eq!(longest.timer_value(), Some(31));
    assert_eq!(NasT3412ExtendedValue::new(Vec::new()).timer_value(), None);
    // A sender writes one octet, and not the unit "deactivated" (NOTE 2)
    assert!(!NasT3412ExtendedValue::new(vec![0b111_00001]).is_well_formed());
    assert!(!NasT3412ExtendedValue::new(vec![0b001_00001, 0]).is_well_formed());
}

#[test]
fn a_request_type_is_one_of_the_five_of_table_10_5_173() {
    let types = [
        (0, None),
        (1, Some(RequestTypeValue::Initial)),
        (2, Some(RequestTypeValue::Handover)),
        (3, Some(RequestTypeValue::Rlos)),
        (4, Some(RequestTypeValue::Emergency)),
        (5, None),
        (6, Some(RequestTypeValue::EmergencyHandover)),
        (7, None),
    ];
    for (value, request_type) in types {
        assert_eq!(
            RequestTypeValue::try_from(value & 0x07).ok(),
            request_type,
            "{value}"
        );
        let emergency = matches!(
            request_type,
            Some(RequestTypeValue::Emergency | RequestTypeValue::EmergencyHandover)
        );
        assert_eq!(
            NasRequestType::new(value).is_emergency(),
            emergency,
            "{value}"
        );
    }
}

#[test]
fn the_esm_information_transfer_flag_is_bit_1() {
    // Bits 2 to 4 are spare
    assert!(NasEsmInformationTransferFlag::new(0b0001).is_required());
    assert!(!NasEsmInformationTransferFlag::new(0b1110).is_required());
}

#[test]
fn cs_lcs_is_no_information_supported_or_not_supported() {
    let support = [
        CsLcsSupport::NoInformation,
        CsLcsSupport::Supported,
        CsLcsSupport::NotSupported,
    ];
    for (value, support) in support.into_iter().enumerate() {
        assert_eq!(
            CsLcsSupport::try_from((value as u8) & 0x03).ok(),
            Some(support)
        );
    }
    assert_eq!(CsLcsSupport::try_from(3).ok(), None);
}

#[test]
fn a_pdn_address_has_the_octets_of_its_pdn_type() {
    let iid = [1, 2, 3, 4, 5, 6, 7, 8];
    let addresses = [
        (vec![1, 10, 0, 0, 1], PdnAddress::Ipv4([10, 0, 0, 1])),
        ([&[2][..], &iid].concat(), PdnAddress::Ipv6InterfaceId(iid)),
        (vec![5, 0, 0, 0, 0], PdnAddress::NonIp),
        (vec![6, 0, 0, 0, 0], PdnAddress::Ethernet),
    ];
    for (value, address) in addresses {
        assert_eq!(PdnAddress::from_bytes(&value), Some(address), "{value:?}");
        assert_eq!(
            PdnAddress::from_bytes_strict(&value),
            Some(address),
            "{value:?}"
        );
    }
    // The PDN type is bits 3 to 1; bits 8 to 4 are spare
    let ipv6 = NasPdnAddress::new([&[0xfa][..], &iid].concat());
    assert_eq!(ipv6.pdn_type_raw(), Some(2));
    assert_eq!(ipv6.ipv6_interface_id(), Some(iid));
    // An IPv4 address of 0.0.0.0 is one that DHCPv4 allocates
    assert!(NasPdnAddress::from_ipv4([0; 4]).uses_dhcpv4());
    assert!(!NasPdnAddress::from_ipv4([10, 0, 0, 1]).uses_dhcpv4());
}
