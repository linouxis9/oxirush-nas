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
