//! The service area list (TS 24.501 §9.11.3.49, Table 9.11.3.49.1): partial lists of
//! one allowed type, in bit 8 of their first octet, each of a type of list in bits 7
//! and 6 and of a number of elements, less one, in bits 5 to 1: TACs of one PLMN
//! (00), consecutive TACs of one PLMN from the first (01), TAIs of PLMNs (10), and
//! every TAI of a PLMN (11). A UE stores the first 16 TAIs and ignores the octets
//! after them.

use oxirush_nas::common::Plmn;
use oxirush_nas::nas_5gs::{
    NasServiceAreaList, ServiceAreaListAllowedType as Allowed, ServiceAreaListEntry as Entry, Tai,
};

fn plmn() -> Plmn {
    Plmn::new("208", "93").unwrap()
}

fn list(octets: &str) -> NasServiceAreaList {
    NasServiceAreaList::new(hex::decode(octets.split_whitespace().collect::<String>()).unwrap())
}

/// A partial list of type 00 of `count` TACs from 1, in octets.
fn tacs(count: u8) -> String {
    let mut octets = format!("{:02x} 02f839", count - 1);
    for tac in 1..=u32::from(count) {
        octets += &format!(" {tac:06x}");
    }
    octets
}

#[test]
fn each_type_of_partial_list_is_read_and_written() {
    let plmn = plmn();
    let tai = |tac| Tai::new(plmn, tac).unwrap();
    let entries = vec![
        Entry::OnePlmnNonConsecutive {
            allowed: Allowed::Allowed,
            plmn,
            tacs: vec![0x12_3456, 0x00_0001],
        },
        Entry::OnePlmnConsecutive {
            allowed: Allowed::Allowed,
            plmn,
            first_tac: 0x00_0010,
            count: 3,
        },
        Entry::DifferentPlmns {
            allowed: Allowed::Allowed,
            tais: vec![tai(0x00_0020), tai(0x00_0021)],
        },
        Entry::PlmnOnly {
            allowed: Allowed::Allowed,
            plmn,
        },
        Entry::OnePlmnNonConsecutive {
            allowed: Allowed::Allowed,
            plmn,
            tacs: vec![0x00_0030],
        },
    ];
    let octets = "01 02f839 123456 000001  22 02f839 000010  41 02f839 000020 02f839 000021  \
                  60 02f839  00 02f839 000030";
    let received = list(octets);
    assert_eq!(received.entries(), entries);
    assert!(received.receiver_syntax_is_valid() && received.is_well_formed());
    assert_eq!(
        NasServiceAreaList::from_entries(&entries).unwrap().value,
        received.value
    );
    // A non-allowed list
    let non_allowed = list("80 02f839 000001");
    let entry = Entry::OnePlmnNonConsecutive {
        allowed: Allowed::NonAllowed,
        plmn,
        tacs: vec![1],
    };
    assert_eq!(non_allowed.entries(), [entry]);
    // A partial list cut after its PLMN has no TAC, and one cut in its PLMN or in a
    // TAC is not read
    let no_tac = Entry::OnePlmnNonConsecutive {
        allowed: Allowed::Allowed,
        plmn,
        tacs: vec![],
    };
    assert_eq!(list("00 02f839").entries(), [no_tac]);
    assert!(list("00 02f8").entries().is_empty());
    let one_tac = Entry::OnePlmnNonConsecutive {
        allowed: Allowed::Allowed,
        plmn,
        tacs: vec![1],
    };
    assert_eq!(list("01 02f839 000001 0000").entries(), [one_tac]);
}

#[test]
fn a_ue_takes_the_first_16_tais_and_ignores_the_octets_after_them() {
    // Fifteen TACs, then two of which the UE takes the first
    let read = list(&format!("{} {}", tacs(15), tacs(2))).entries();
    let count = |entry: &Entry| match entry {
        Entry::OnePlmnNonConsecutive { tacs, .. } => tacs.len(),
        _ => 0,
    };
    assert_eq!(read.iter().map(count).collect::<Vec<_>>(), [15, 1]);
    // Fifteen consecutive TACs or TAIs of PLMNs, then two TACs; and fifteen TACs, then
    // two TAIs of PLMNs
    let two_tais = "41 02f839 000001 02f839 000002";
    let fifteen_tais = format!("4e {}", "02f839 000001 ".repeat(15));
    for (octets, last) in [
        (format!("2e 02f839 000001 {}", tacs(2)), 1),
        (format!("{fifteen_tais} {}", tacs(2)), 1),
        (format!("{} {two_tais}", tacs(15)), 1),
    ] {
        let read = list(&octets).entries();
        let last_count = match read.last() {
            Some(Entry::OnePlmnNonConsecutive { tacs, .. }) => tacs.len(),
            Some(Entry::DifferentPlmns { tais, .. }) => tais.len(),
            other => panic!("{other:?}"),
        };
        assert_eq!(last_count, last, "{octets}");
    }
    // Of each type: what comes after the 16th TAI is ignored, even when it is not a
    // partial list or is cut short
    for first in [
        tacs(16),
        "2f 02f839 000001".to_string(),
        format!("4f {}", "02f839 000001 ".repeat(16)),
    ] {
        let received = list(&format!("{first} ff"));
        assert!(received.receiver_syntax_is_valid(), "{first}");
        assert!(!received.is_well_formed(), "{first}");
    }
    let cut = list(&format!("{} {}", tacs(10), &tacs(10)[..2 + 7 + 6 * 7]));
    assert!(cut.receiver_syntax_is_valid());
    // A list of more than 16 TAIs is not written, of whichever types
    let plmn = plmn();
    let many = |count| Entry::OnePlmnNonConsecutive {
        allowed: Allowed::Allowed,
        plmn,
        tacs: (1..=count).collect(),
    };
    let consecutive = |count| Entry::OnePlmnConsecutive {
        allowed: Allowed::Allowed,
        plmn,
        first_tac: 1,
        count,
    };
    let tais = |count| Entry::DifferentPlmns {
        allowed: Allowed::Allowed,
        tais: (1..=count)
            .map(|tac| Tai::new(plmn, tac).unwrap())
            .collect(),
    };
    assert!(NasServiceAreaList::from_entries(&[many(16)]).is_ok());
    assert!(NasServiceAreaList::from_entries(&[many(16), many(1)]).is_err());
    assert!(NasServiceAreaList::from_entries(&[consecutive(16), consecutive(1)]).is_err());
    assert!(NasServiceAreaList::from_entries(&[tais(16), tais(1)]).is_err());
}

#[test]
fn consecutive_tacs_end_at_the_last_tac_of_24_bits() {
    let plmn = plmn();
    let consecutive = |first_tac, count| {
        NasServiceAreaList::from_consecutive_tacs(Allowed::Allowed, &plmn, first_tac, count)
    };
    assert_eq!(
        consecutive(0, 1).unwrap().value,
        hex::decode("2002f839000000").unwrap()
    );
    assert!(consecutive(0x00ff_ffff, 1).is_ok());
    assert!(consecutive(0x00ff_fffe, 2).is_ok());
    assert!(consecutive(0x00ff_ffff, 2).is_err());
}
