//! The UE policy delivery service (TS 24.501 annex D): the procedure transaction
//! identity of its messages (§D.1.2), and the UE policy section management list
//! (§D.6.2), sublists of a PLMN, each of instructions of a UPSC, each of UE policy
//! parts.

use oxirush_nas::common::Plmn;
use oxirush_nas::nas_5gs::{
    NasUePolicySectionManagementList as List, NasUpdsProcedureTransactionIdentity as Pti,
    UePolicyPart, UePolicyPartType, UePolicySectionManagementInstruction as Instruction,
    UePolicySectionManagementSublist as Sublist, UpdsProcedureTransactionIdentityKind as Kind,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

#[test]
fn a_pti_is_unassigned_of_the_ue_of_the_network_or_reserved() {
    // 0 is no PTI and 255 reserved (TS 24.007 table 11.6); the UE starts a
    // procedure with 01H to 77H, the PCF with 80H to FEH (§D.1.2)
    for value in 0..=u8::MAX {
        let pti = Pti::new_raw(value);
        let kind = match value {
            0x00 => Kind::Unassigned,
            0x01..=0x77 => Kind::UeInitiated,
            0x80..=0xfe => Kind::NetworkInitiated,
            _ => Kind::Reserved,
        };
        assert_eq!(pti.kind(), kind, "{value:#04x}");
        assert_eq!(
            pti.is_unassigned(),
            kind == Kind::Unassigned,
            "{value:#04x}"
        );
        assert_eq!(
            pti.is_ue_initiated(),
            kind == Kind::UeInitiated,
            "{value:#04x}"
        );
        assert_eq!(
            pti.is_network_initiated(),
            kind == Kind::NetworkInitiated,
            "{value:#04x}"
        );
        assert_eq!(pti.is_reserved(), kind == Kind::Reserved, "{value:#04x}");
    }
}

/// A sublist of 208 93 with an instruction of `upsc` and a URSP part of `contents`
fn sublist(upsc: u16, contents: &[u8]) -> Sublist {
    Sublist::new(
        Plmn::new("208", "93").unwrap(),
        vec![Instruction::new(
            upsc,
            vec![UePolicyPart {
                part_type: UePolicyPartType::Ursp,
                contents: contents.to_vec(),
            }],
        )],
    )
}

#[test]
fn a_list_has_each_sublist_with_its_length_its_plmn_and_its_instructions() {
    // The length of a sublist counts its PLMN and its instructions, that of an
    // instruction its UPSC and its parts, and that of a part its type and its
    // contents (NOTE 2 of table D.6.2.1)
    let two = octets(
        "000c 02f839 0007 0001 0003 01 aabb
         000b 02f839 0006 0002 0002 01 cc",
    );
    let list = List::new(two.clone());
    let sublists = vec![sublist(1, &[0xaa, 0xbb]), sublist(2, &[0xcc])];
    assert_eq!(list.try_sublists(), Some(sublists.clone()));
    assert_eq!(List::from_sublists(&sublists).unwrap().value, two);

    // An octet after the last sublist is not one of them
    let mut trailing = two.clone();
    trailing.push(0x00);
    assert_eq!(List::new(trailing).try_sublists(), None);
    // Nor are four, which cannot hold a length and a PLMN
    let mut four = two;
    four.extend([0x00, 0x05, 0x02, 0xf8]);
    assert_eq!(List::new(four).try_sublists(), None);
}
