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
    // Without the list indication, and with the list type of a secured packet,
    // there is no list
    assert_eq!(information(false, "00").plmn_list_payload(), None);
    let secured = NasSorTransparentContainer::new(octets(&format!("02 {MAC_AND_COUNTER} 0102")));
    assert!(secured.receiver_syntax_is_valid());
    assert_eq!(secured.plmn_list_payload(), None);
    assert_eq!(secured.secured_packet(), Some(&[1, 2][..]));
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

/// A container of SOR information of the header `header` and the body `body`.
fn container(header: u8, body: &str) -> NasSorTransparentContainer {
    NasSorTransparentContainer::new(octets(&format!("{header:02x} {MAC_AND_COUNTER} {body}")))
}

/// The additional parameters of SOR-CMCI alone (SI in bit 1), of these rules.
fn cmci(rules: &str) -> String {
    let rules = octets(rules);
    format!("01 {:04x} {}", rules.len(), hex::encode(rules))
}

#[test]
fn an_sor_cmci_rule_has_the_length_of_its_criterion() {
    let receiver = |rules: &str| container(0x14, &cmci(rules)).receiver_syntax_is_valid();
    let sender = |rules: &str| container(0x14, &cmci(rules)).is_well_formed();
    // A PDU session type (02), an S-NSSAI (03) and a criterion of no value (04)
    for rule in ["0003 21 02 01", "0006 21 03 01000001", "0002 21 04"] {
        assert!(receiver(rule) && sender(rule), "{rule}");
    }
    // A criterion that the table does not define is skipped by a receiver, and not
    // written; a rule longer than its criterion likewise
    for rule in ["0002 21 09", "0004 21 02 0100"] {
        assert!(receiver(rule) && !sender(rule), "{rule}");
    }
    // A rule shorter than its criterion, a DNN longer than its rule, and a DNN of a
    // label longer than the DNN
    for rule in ["0003 21 03 01", "0005 21 01 09 0869", "0005 21 01 02 0569"] {
        assert!(!receiver(rule), "{rule}");
    }
}

#[test]
fn the_snpn_lists_are_there_when_their_indicators_say() {
    // SOR-SNPN-SI (SSSI, bit 3) and SOR-SNPN-SI-LS (SSSLI, bit 4) without a list
    for flags in ["04 0001 00", "08 0001 00"] {
        let information = container(0x14, flags);
        assert!(information.receiver_syntax_is_valid(), "{flags}");
    }
    // A list of SOR-SNPN-SI has identities of nine octets
    assert!(!container(0x14, "04 0004 01 0001 00").receiver_syntax_is_valid());
    // The list of preferred SNPNs for access for localized services takes SNPN infos of
    // ten octets at least
    let short = container(0x14, "08  000e 01  000b  0009 00 02f839 01 01020304");
    assert!(!short.receiver_syntax_is_valid());
}

#[test]
fn a_list_of_plmns_has_80_octets_at_most_in_steps_of_five() {
    // With the additional parameters and the list indication: the length of the list,
    // the list, then the octet of the additional parameters without one
    let list = |length: usize| container(0x16, &format!("{length:02x} {} 00", "00".repeat(length)));
    assert!(list(80).receiver_syntax_is_valid());
    for length in [7, 85] {
        assert!(!list(length).receiver_syntax_is_valid(), "{length}");
    }
    // Without the additional parameters nor the list indication, a list of PLMNs has
    // no octet after CounterSOR
    assert!(container(0x04, "").receiver_syntax_is_valid());
    assert!(!container(0x04, "00").receiver_syntax_is_valid());
    // A secured packet has no additional parameters, and a sender writes it without
    // the list indication
    assert!(!container(0x10, "0102").receiver_syntax_is_valid());
    assert!(container(0x00, "0102").is_well_formed());
}

#[test]
fn the_header_says_the_type_of_the_container_and_its_indications() {
    let plmn_list = container(0x04, "");
    assert!(plmn_list.sor_list_type_plmn_list() && !plmn_list.sor_data_type_ack());
    assert!(!container(0x00, "").sor_list_type_plmn_list());
    assert!(container(0x0c, "").ack_requested() && !plmn_list.ack_requested());
    // Bits 8 to 6 of an information header are spare: a receiver ignores them
    let spare = container(0x24, "");
    assert!(spare.receiver_syntax_is_valid() && !spare.is_well_formed());
    // An acknowledgement: MSSNPNSI in bit 3, bits 8 to 5 spare, and no CounterSOR even
    // with octets after SOR-MAC-IUE
    let ack = NasSorTransparentContainer::from_ack(false, true, false, [0xcd; 16]);
    assert_eq!(ack.value[0], 0x05);
    assert!(ack.mssnpnsi() && ack.sor_data_type_ack() && !ack.sor_list_type_plmn_list());
    assert!(ack.is_well_formed());
    let mut longer = ack.value.to_vec();
    longer.extend([0x00, 0x01]);
    let longer = NasSorTransparentContainer::new(longer);
    assert_eq!(longer.counter_sor(), None);
    let mut spare = ack.value.to_vec();
    spare[0] |= 0x10;
    let spare = NasSorTransparentContainer::new(spare);
    assert!(spare.receiver_syntax_is_valid() && !spare.is_well_formed());
}
