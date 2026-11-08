//! The lists of S-NSSAIs of later features: the extended rejected NSSAI (TS 24.501
//! §9.11.3.75), partial lists of up to eight rejected S-NSSAIs in all, of type 0, or
//! of type 1 with a back-off timer; the NSAG information (§9.11.3.87), up to 32
//! entries of which four have a TAI list; the on-demand NSSAI (§9.11.3.108); the
//! partial NSSAI (§9.11.3.103), up to seven S-NSSAIs each with a TAI list; and the
//! alternative NSSAI (§9.11.3.97), up to eight pairs of a replaced and an alternative
//! S-NSSAI.

use oxirush_nas::nas_5gs::{
    AlternativeNssaiEntry, ExtendedRejectedNssaiPartialList as PartialList,
    ExtendedRejectedSNssai as Rejected, ExtendedRejectedSNssaiCause as Cause, NasAlternativeNssai,
    NasExtendedRejectedNssai, NasGprsTimer3, NasNsagInformation, NasOnDemandNssai, NasPartialNssai,
    NasType6IeContainer, NsagInfoEntry, OnDemandNssaiEntry, Type6IeContainerEntry,
};

fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// A TAI list of one TAC of PLMN 208 93 (§9.11.3.9), in octets.
const TAIS: &str = "00 02f839 000001";

#[test]
fn a_rejected_s_nssai_has_its_cause_and_its_length() {
    let causes = [
        Cause::NotAvailableInPlmn,
        Cause::NotAvailableInRegArea,
        Cause::FailedOrRevokedAuth,
    ];
    for (code, cause) in (0..).zip(causes) {
        assert_eq!(Cause::try_from(code).ok(), Some(cause));
    }
    let rejected = Rejected {
        cause: 1,
        s_nssai: vec![0x01, 0x00, 0x00, 0x07],
    };
    assert_eq!(
        rejected.parsed_s_nssai().map(|s_nssai| s_nssai.sst),
        Some(0x01)
    );
}

#[test]
fn the_extended_rejected_nssai_keeps_eight_rejected_s_nssais() {
    let list = |count: u8| format!("{:02x} {}", count - 1, "11 01 ".repeat(usize::from(count)));
    let read = |text: &str| NasExtendedRejectedNssai::new(octets(text)).partial_lists();
    let counts = |lists: Vec<PartialList>| {
        lists
            .iter()
            .map(|list| list.rejected.len())
            .collect::<Vec<_>>()
    };
    // Two lists within eight, two that go past them, and more after eight
    assert_eq!(counts(read(&format!("{} {}", list(2), list(2)))), [2, 2]);
    assert_eq!(counts(read(&format!("{} {}", list(5), list(5)))), [5, 3]);
    assert_eq!(counts(read(&format!("{} {}", list(8), list(1)))), [8]);
    // A list of type 1 with its back-off timer, and the canonical form
    let timed = NasExtendedRejectedNssai::new(octets("10 21 11 01"));
    let lists = timed.partial_lists();
    assert_eq!(
        lists[0].back_off_timer,
        Some(NasGprsTimer3::new(vec![0x21]))
    );
    assert!(timed.is_well_formed() && timed.receiver_syntax_is_valid());
    assert!(!NasExtendedRejectedNssai::new(octets("20 11 01")).receiver_syntax_is_valid());
    // A back-off timer in a list of type 1 alone
    let rejected = vec![Rejected {
        cause: 1,
        s_nssai: vec![0x01],
    }];
    let timer = Some(NasGprsTimer3::new(vec![0x21]));
    for (type_of_list, back_off_timer, written) in [
        (0, None, true),
        (0, timer.clone(), false),
        (1, timer, true),
        (1, None, false),
    ] {
        let list = PartialList::new(type_of_list, back_off_timer, rejected.clone());
        let result = NasExtendedRejectedNssai::from_partial_lists(&[list]);
        assert_eq!(result.is_ok(), written, "{type_of_list} {written}");
    }
}

/// An NSAG entry of ID 1, of S-NSSAI list `snssais` and TAI list `tais`, in octets.
fn nsag(snssais: &str, tais: &str) -> String {
    let snssais = octets(snssais);
    let tais = octets(tais);
    let mut body = vec![0x01, snssais.len() as u8];
    body.extend(&snssais);
    body.push(0x05);
    if !tais.is_empty() {
        body.push(tais.len() as u8);
        body.extend(&tais);
    }
    format!("{:02x} {}", body.len(), hex::encode(body))
}

#[test]
fn an_nsag_entry_has_its_s_nssais_and_at_most_four_have_a_tai_list() {
    let read = |text: &str| NasNsagInformation::new(octets(text)).entries();
    let entries = read(&format!("{} {}", nsag("01 01", TAIS), nsag("01 02", "")));
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].tai_list, octets(TAIS));
    assert!(entries[1].tai_list.is_empty());
    // S-NSSAIs of an SST, with or without an SD, one at least, within the list
    for snssais in ["02 0102", "", "04 0102"] {
        assert!(read(&nsag(snssais, TAIS)).is_empty(), "{snssais}");
    }
    // Four entries with a TAI list, and 32 entries
    let with_tais = |count| nsag("01 01", TAIS).repeat(count);
    assert_eq!(read(&with_tais(4)).len(), 4);
    assert_eq!(read(&with_tais(5)).len(), 4);
    assert_eq!(read(&nsag("01 01", "").repeat(33)).len(), 32);
    // A sender writes the five entries without a TAI list
    let entry = NsagInfoEntry::new(1, vec![0x01, 0x01], 5, vec![]);
    assert!(NasNsagInformation::from_entries(&vec![entry; 5]).is_ok());
}

#[test]
fn an_on_demand_s_nssai_has_its_timer_or_none() {
    let read = |text: &str| NasOnDemandNssai::new(octets(text)).entries();
    let timed = OnDemandNssaiEntry::new(vec![0x01], Some([0xaa, 0xbb, 0xcc]));
    let untimed = OnDemandNssaiEntry::new(vec![0x02], None);
    assert_eq!(read("05 01 01 aabbcc  02 01 02"), [timed, untimed.clone()]);
    // An entry cut short, an S-NSSAI past its entry, and seventeen entries
    assert!(read("05 01 01 aabb").is_empty());
    assert!(read("02 05 01").is_empty());
    assert_eq!(read(&"02 01 02 ".repeat(17)).len(), 16);
}

/// Whether a type 6 IE container takes `value` as the partially allowed NSSAI.
fn taken(value: &[u8]) -> bool {
    let mut container = vec![0x03];
    container.extend((value.len() as u16).to_be_bytes());
    container.extend(value);
    !NasType6IeContainer::new(container).entries().is_empty()
}

#[test]
fn a_partial_nssai_has_seven_s_nssais_at_most() {
    let entry = |tais: &str| {
        let tais = octets(tais);
        format!("01 01 {:02x} {}", tais.len(), hex::encode(tais))
    };
    for value in [entry(TAIS), entry(""), entry(TAIS).repeat(7)] {
        assert!(taken(&octets(&value)), "{value}");
    }
    for value in [entry(TAIS).repeat(8), "03 010203 00".to_string()] {
        assert!(!taken(&octets(&value)), "{value}");
    }
    let eight = NasPartialNssai::new(octets(&entry("").repeat(8)));
    assert_eq!(eight.entries().len(), 7);
    // A sender writes the entries as they are read
    let partial = NasPartialNssai::new(octets(&entry(TAIS)));
    let written =
        NasType6IeContainer::from_entries(&[Type6IeContainerEntry::PartiallyAllowedNssai(partial)]);
    assert!(written.is_ok());
    let longer = NasPartialNssai::new(octets(&format!("{} ff", entry(""))));
    let refused =
        NasType6IeContainer::from_entries(&[Type6IeContainerEntry::PartiallyAllowedNssai(longer)]);
    assert!(refused.is_err());
}

#[test]
fn an_alternative_s_nssai_follows_the_one_that_it_replaces() {
    let read = |text: &str| NasAlternativeNssai::new(octets(text)).entries();
    let pair = |replaced: u8, alternative: u8| AlternativeNssaiEntry {
        replaced: vec![replaced],
        alternative: vec![alternative],
    };
    assert_eq!(read("01 01 01 02  01 03 01 04"), [pair(1, 2), pair(3, 4)]);
    assert!(read("04 010203").is_empty());
    assert_eq!(read(&"01 01 01 02 ".repeat(9)).len(), 8);
}
