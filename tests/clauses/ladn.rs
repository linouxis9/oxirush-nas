//! The LADNs: the LADN indication (TS 24.501 §9.11.3.29), up to eight DNNs each after
//! its length; the LADN information (§9.11.3.30), up to eight DNNs each with its TAI
//! list; and the extended LADN information (§9.11.3.96), each DNN with an S-NSSAI and
//! a TAI list, which a type 6 IE container (§9.11.3.98) carries.

use oxirush_nas::nas_5gs::{
    CipheringDataSet, LadnInfoEntry, NasExtendedLadnInformation, NasLadnIndication,
    NasLadnInformation, NasPartialNssai, NasType6IeContainer, Type6IeContainerEntry,
};

fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// The DNN "ims" and a TAI list of one TAC of PLMN 208 93, each after its length.
const DNN: &str = "04 03696d73";
const TAIS: &str = "07 00 02f839 000001";

#[test]
fn a_ladn_indication_has_eight_dnns_at_most() {
    let indication = |text: &str| NasLadnIndication::new(octets(text));
    assert_eq!(indication(&DNN.repeat(9)).dnn_values().len(), 8);
    assert!(indication(&DNN.repeat(2)).is_well_formed());
    assert!(!indication(&format!("{DNN} 01")).is_well_formed());
}

#[test]
fn a_ladn_has_its_dnn_and_its_tai_list() {
    let information = |text: &str| NasLadnInformation::new(octets(text)).entries();
    let entry = LadnInfoEntry {
        dnn: octets("03696d73"),
        tai_list: octets("00 02f839 000001"),
    };
    let entry_text = format!("{DNN} {TAIS}");
    assert_eq!(information(&entry_text.repeat(2)), [entry.clone(), entry]);
    assert_eq!(information(&entry_text.repeat(9)).len(), 8);
    // A DNN past the end, and a TAI list that is not one
    assert!(information("09 03696d73").is_empty());
    assert!(information(&format!("{DNN} 03 400102")).is_empty());
    // The TAI list of a ciphering data set is that of the IE, when it has one
    let set = |tai_list: Vec<u8>| {
        CipheringDataSet::new(7, [0; 16], vec![], vec![0x80], vec![], [0; 5], 60, tai_list)
    };
    assert_eq!(
        set(octets("00 02f839 000001"))
            .tai_list_value()
            .map(|list| list.value.len()),
        Some(7)
    );
    assert!(set(vec![]).tai_list_value().is_none());
}

/// An extended LADN of the DNN `dnn`, the S-NSSAI `snssai` and the TAI list, in
/// octets, all after their lengths.
fn extended(dnn: &str, snssai: &str) -> String {
    format!("{dnn} {snssai} {TAIS}")
}

/// What a type 6 IE container of the extended LADN information `value` holds.
fn received(value: &[u8]) -> Vec<Type6IeContainerEntry> {
    let mut container = vec![0x01];
    container.extend((value.len() as u16).to_be_bytes());
    container.extend(value);
    NasType6IeContainer::new(container).entries()
}

#[test]
fn an_extended_ladn_has_its_dnn_its_s_nssai_and_its_tai_list() {
    let read = |text: &str| NasExtendedLadnInformation::new(octets(text)).entries();
    let two = extended(DNN, "01 01").repeat(2);
    assert_eq!(read(&two).len(), 2);
    assert_eq!(received(&octets(&two)).len(), 1);
    // A DNN of one octet less than its length, and an S-NSSAI past the end
    assert!(read("04 03696d").is_empty());
    assert!(read("00 04 01").is_empty());
    // A receiver of the container takes neither a DNN of a label longer than the DNN
    // nor an S-NSSAI of three octets
    for value in [extended("02 0561", "01 01"), extended(DNN, "03 010203")] {
        assert!(received(&octets(&value)).is_empty(), "{value}");
    }
    // A sender writes the DNN of its labels
    let bad_label = NasExtendedLadnInformation::new(octets(&extended("02 0561", "01 01")));
    let entry = Type6IeContainerEntry::ExtendedLadnInformation(bad_label);
    assert!(NasType6IeContainer::from_entries(&[entry]).is_err());
}

#[test]
fn a_type_6_ie_container_holds_the_partially_rejected_nssai() {
    // IEI 4, the partially rejected NSSAI of one S-NSSAI and no TAI list
    let container = NasType6IeContainer::new(octets("04 0003 01 01 00"));
    let entries = container.entries();
    assert!(matches!(
        entries.as_slice(),
        [Type6IeContainerEntry::PartiallyRejectedNssai(_)]
    ));
    assert!(container.is_well_formed());
    let written =
        NasType6IeContainer::from_entries(&[Type6IeContainerEntry::PartiallyRejectedNssai(
            NasPartialNssai::new(octets("01 01 00")),
        )]);
    assert_eq!(written.unwrap().value, container.value);
}
