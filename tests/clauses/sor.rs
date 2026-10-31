//! The SOR transparent container (TS 24.501 §9.11.3.51): its header, SOR-MAC-IAUSF
//! and CounterSOR, then the list or the secured packet; with the additional
//! parameters, the length of the list in one octet (figure 9.11.3.51.2A), and the
//! octet that says which of SOR-CMCI, SOR-SNPN-SI and SOR-SNPN-SI-LS follow.

use oxirush_nas::nas_5gs::{
    NasSorTransparentContainer, SorListType, SorTransparentContainerContents,
    SorTransparentContainerDirection,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// SOR-MAC-IAUSF, then CounterSOR 1.
const MAC_AND_COUNTER: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd 0001";

/// A container of SOR information with the additional parameters (AP in the bit
/// 5) and the body `body`, that a receiver and a sender take, and that
/// `from_information` makes.
fn information(list_indication: bool, body: &str) -> NasSorTransparentContainer {
    // The list type in the bit 3 is a PLMN ID and access technology list
    let header = 0x14 | u8::from(list_indication) << 1;
    let value = octets(&format!("{header:02x} {MAC_AND_COUNTER} {body}"));
    let container = NasSorTransparentContainer::new(value.clone());
    assert!(container.receiver_syntax_is_valid(), "{body}");
    assert!(container.is_well_formed_for(SorTransparentContainerDirection::NetworkToUe));
    let made = NasSorTransparentContainer::from_information(
        list_indication,
        SorListType::PlmnAccessTechnologyList,
        false,
        true,
        [0xcd; 16],
        1,
        &value[19..],
    );
    assert_eq!(made.unwrap().value, value);
    container
}

#[test]
fn the_list_of_the_additional_parameters_has_a_length_of_one_octet() {
    // Two PLMN IDs, each with its access technology identifier, then no
    // additional parameter
    let container = information(true, "0a 02f8394000 1300148000  00");
    let list = octets("02f8394000 1300148000");
    assert_eq!(container.plmn_list_payload(), Some(&list[..]));
    let Some(SorTransparentContainerContents::Information { body, .. }) = container.parse() else {
        panic!("{:?}", container.parse());
    };
    assert_eq!(body, octets("0a 02f8394000 1300148000  00"));
}

#[test]
fn an_sor_cmci_rule_has_a_length_of_two_octets() {
    // SI in the bit 1 of the octet o, then SOR-CMCI with the length of its
    // contents and two rules, each with the length of its contents in two
    // octets (figure 9.11.3.51.8), its Tsor-cm timer value and its criterion:
    // the DNN "internet" as the length and value of a DNN IE, and "match all"
    information(
        false,
        "01  0012  000c 21 01 09 08696e7465726e6574  0002 e0 ff",
    );
}

#[test]
fn an_snpn_info_has_a_length_of_two_octets() {
    // SSSLI in the bit 4, then SOR-SNPN-SI-LS with the length of its contents,
    // CLSLSI in the bit 1, and the list of preferred SNPNs for access for
    // localized services: its length, and an SNPN info of two octets of
    // length, its indicators and its SNPN identity (figure 9.11.3.51.10B)
    information(false, "08  000f 01  000c  000a 00 02f839 01 0102030405");
}

#[test]
fn the_snpn_si_has_lists_of_nine_octet_identities() {
    // SSSI in the bit 3, then SOR-SNPN-SI with CLSI and CLGI, the list of
    // preferred SNPNs and the list of GINs, each identity of nine octets
    information(
        false,
        "04  0017 03  0009 02f839 01 0102030405  0009 130014 01 0a0b0c0d0e",
    );
}
