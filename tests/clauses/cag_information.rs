//! The CAG information list (TS 24.501 §9.11.3.18A) and the extended CAG
//! information list (§9.11.3.86): entries of a PLMN, its CAG-only indication
//! and its CAG-IDs, and in the extended list the CAG-IDs with additional
//! information, each with its time validity.

use oxirush_nas::common::Plmn;
use oxirush_nas::nas_5gs::{
    CagIdWithAdditionalInfo, CagInformationEntry, NasCagInformationList,
    NasExtendedCagInformationList,
};

fn plmn(mcc: &str, mnc: &str) -> Plmn {
    Plmn::new(mcc, mnc).unwrap()
}

/// `octets` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

#[test]
fn an_entry_has_its_plmn_its_cag_only_indication_and_its_cag_ids() {
    let entries = [
        CagInformationEntry::new(plmn("208", "93"), true, false, false, vec![1, 2], vec![]),
        // No allowed CAG-ID: the length of the entry is 4 (NOTE 2)
        CagInformationEntry::new(plmn("310", "410"), false, false, false, vec![], vec![]),
    ];
    // The length of the entry, the MCC and MNC digits, CAGonly in the bit 1,
    // then each CAG-ID in four octets
    let value = octets("0c 02f839 01 00000001 00000002  04 130014 00");
    let ie = NasCagInformationList::from_entries(&entries).unwrap();
    assert_eq!(ie.value, value);
    let received = NasCagInformationList::new(value);
    assert_eq!(received.entries(), entries);
    assert!(received.is_well_formed());
}

#[test]
fn an_extended_entry_has_cag_ids_with_their_time_validity() {
    let period = [0x11; 16];
    let with_info = vec![
        CagIdWithAdditionalInfo::new(10, 0, true, vec![period]),
        CagIdWithAdditionalInfo::new(11, 0, false, vec![]),
    ];
    let entries = [
        CagInformationEntry::new(plmn("208", "93"), true, true, true, vec![1, 2], with_info),
        CagInformationEntry::new(
            plmn("310", "410"),
            false,
            false,
            false,
            vec![0x1234_5678],
            vec![],
        ),
    ];
    // An entry of two octets of length, with CAILI in the bit 4, LCI in the
    // bit 3 and CAGonly in the bit 1; the length of the CAG-IDs without
    // additional information and the CAG-IDs; the length of the CAG-IDs with
    // additional information, and each with its length, its CAG-ID, its TVII
    // in the bit 1 and its time periods with their number
    let value = octets(
        "002f 02f839 0d  0008 00000001 00000002  001f \
         0016 0000000a 01 01 11111111111111111111111111111111 \
         0005 0000000b 00 \
         0008 130014 00 12345678",
    );
    let ie = NasExtendedCagInformationList::from_entries(&entries).unwrap();
    assert_eq!(ie.value, value);
    let received = NasExtendedCagInformationList::new(value);
    assert_eq!(received.entries(), entries);
    assert!(received.is_well_formed());
}

#[test]
fn a_receiver_ignores_what_the_clause_tells_it_to() {
    // A CAG-ID with additional information of a spare validity (an SVII bit
    // set) is ignored, and so are the superfluous octets at the end of a
    // CAG-ID with additional information and of an entry
    let value = octets(
        "0021 02f839 0c  0000  0017 \
         0007 0000000a 00 ffff \
         0005 0000000b 02 \
         0005 0000000c 00 \
         eeee",
    );
    let entries = NasExtendedCagInformationList::new(value.clone()).entries();
    let only = CagIdWithAdditionalInfo::new(10, 0, false, vec![]);
    let expected = CagInformationEntry::new(
        plmn("208", "93"),
        false,
        true,
        true,
        vec![],
        vec![only, CagIdWithAdditionalInfo::new(12, 0, false, vec![])],
    );
    assert_eq!(entries, [expected]);
    // These octets are not those that the entries encode to
    assert!(!NasExtendedCagInformationList::new(value).is_well_formed());
}

#[test]
fn a_cag_id_with_additional_information_is_in_the_extended_list_alone() {
    let with_info = vec![CagIdWithAdditionalInfo::new(10, 0, false, vec![])];
    let caili = CagInformationEntry::new(plmn("208", "93"), false, true, true, vec![], with_info);
    assert!(NasCagInformationList::from_entries(std::slice::from_ref(&caili)).is_err());
    assert!(NasExtendedCagInformationList::from_entries(&[caili]).is_ok());
    // CAILI goes with LCI and with CAG-IDs with additional information; TVII
    // with time periods; and SVII is spare
    let refused = [
        CagInformationEntry::new(
            plmn("208", "93"),
            false,
            true,
            false,
            vec![],
            vec![CagIdWithAdditionalInfo::new(10, 0, false, vec![])],
        ),
        CagInformationEntry::new(plmn("208", "93"), false, true, true, vec![], vec![]),
        CagInformationEntry::new(
            plmn("208", "93"),
            false,
            false,
            true,
            vec![],
            vec![CagIdWithAdditionalInfo::new(10, 0, false, vec![])],
        ),
        CagInformationEntry::new(
            plmn("208", "93"),
            false,
            true,
            true,
            vec![],
            vec![CagIdWithAdditionalInfo::new(10, 0, true, vec![])],
        ),
        CagInformationEntry::new(
            plmn("208", "93"),
            false,
            true,
            true,
            vec![],
            vec![CagIdWithAdditionalInfo::new(10, 0, false, vec![[0; 16]])],
        ),
        CagInformationEntry::new(
            plmn("208", "93"),
            false,
            true,
            true,
            vec![],
            vec![CagIdWithAdditionalInfo::new(10, 1, false, vec![])],
        ),
    ];
    for entry in refused {
        let refusal = NasExtendedCagInformationList::from_entries(std::slice::from_ref(&entry));
        assert!(refusal.is_err(), "{entry:?}");
    }
}

#[test]
fn an_entry_whose_cag_ids_are_cut_short_is_not_read() {
    let first = CagInformationEntry::new(plmn("208", "93"), true, false, false, vec![1], vec![]);
    // Two octets after the CAG-IDs of an entry, and a length of the CAG-IDs of an
    // extended entry that is not a multiple of four
    let received = NasCagInformationList::new(octets("08 02f839 01 00000001  06 02f839 00 0102"));
    assert_eq!(received.entries(), std::slice::from_ref(&first));
    let extended = octets("0008 02f839 01 00000001  0008 02f839 04 0002 0102");
    let received = NasExtendedCagInformationList::new(extended);
    assert_eq!(received.entries(), [first]);
}

#[test]
fn a_cag_id_with_additional_information_ends_where_its_length_says() {
    let entry = |with_info| {
        CagInformationEntry::new(plmn("208", "93"), false, true, true, vec![], with_info)
    };
    let read = |text: &str| NasExtendedCagInformationList::new(octets(text)).entries();
    // A CAG-ID of four distinct octets with its time period, then octets that the
    // receiver ignores
    let period = [0x11; 16];
    let with_period = CagIdWithAdditionalInfo::new(0x1234_5678, 0, true, vec![period]);
    assert_eq!(
        read("0021 02f839 0c  0000  0019  0017 12345678 01 01 11111111111111111111111111111111 ee"),
        [entry(vec![with_period])]
    );
    // An item shorter than its CAG-ID and flags, time periods beyond their item,
    // and a time validity without the number of its periods: no entry is read
    for text in [
        "000d 02f839 0c  0000  0005  0003 123456",
        "0020 02f839 0c  0000  0018  0016 12345678 01 02 11111111111111111111111111111111",
        "000f 02f839 0c  0000  0007  0005 12345678 01",
    ] {
        assert!(read(text).is_empty(), "{text}");
    }
    // A long first entry, then an extended entry with its lists, both read
    let long = CagInformationEntry::new(
        plmn("310", "410"),
        false,
        false,
        false,
        (1..=8).collect(),
        vec![],
    );
    let ids: String = (1..=8u32).map(|id| format!("{id:08x}")).collect();
    let text = format!("0024 130014 00 {ids}  000f 02f839 0c  0000  0007  0005 0000000a 00");
    let only = CagIdWithAdditionalInfo::new(10, 0, false, vec![]);
    assert_eq!(read(&text), [long, entry(vec![only])]);
}

#[test]
fn the_cag_information_list_has_no_lci_either() {
    // LCI is in the extended CAG information list alone, as CAILI is
    let lci = CagInformationEntry::new(plmn("208", "93"), false, false, true, vec![1], vec![]);
    assert!(NasCagInformationList::from_entries(std::slice::from_ref(&lci)).is_err());
    assert!(NasExtendedCagInformationList::from_entries(&[lci]).is_ok());
}
