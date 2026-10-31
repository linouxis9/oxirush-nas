//! The VPS URSP configuration (TS 24.501 Annex D.6.8): the replacement type, then
//! tuples of an ID, a network descriptor of VPLMNs, MCCs or any VPLMN, and the
//! UPSCs of the UE policy sections that apply there. MCCs go in pairs of three
//! octets, and an odd one in two (figures D.6.8.8 and D.6.8.9).

use oxirush_nas::common::Plmn;
use oxirush_nas::nas_5gs::{
    NasVpsUrspConfiguration, VpsUrspConfigurationContents as Contents,
    VpsUrspNetworkDescriptorEntry as Entry, VpsUrspReplacementType as Replacement,
    VpsUrspTuple as Tuple,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

#[test]
fn a_tuple_has_its_id_its_network_descriptor_and_its_upscs() {
    let vplmns = vec![
        Plmn::new("208", "93").unwrap(),
        Plmn::new("310", "410").unwrap(),
    ];
    let contents = Contents::new(
        Replacement::FullListOfTuples,
        vec![
            Tuple::new(
                7,
                vec![Entry::OneOrMoreVplmns(vplmns), Entry::AnyVplmn],
                vec![0x0102, 0x0304],
            ),
            // Three MCCs: a pair, then an odd one with a spare half octet
            Tuple::new(
                8,
                vec![Entry::OneOrMoreMccs(vec![[2, 0, 8], [3, 1, 0], [4, 5, 6]])],
                vec![],
            ),
        ],
    );
    // The replacement type 10; each tuple with the length of its contents, its
    // ID and the number of the entries of its network descriptor, each entry
    // with its type: the VPLMNs with their number, any VPLMN, and the MCCs
    // with theirs
    let value = octets(
        "02  000f 07 02 01 02 02f839 130014 03 01020304  \
         0009 08 01 02 03 020813 5406",
    );
    let ie = NasVpsUrspConfiguration::from_parsed(&contents).unwrap();
    assert_eq!(ie.value, value);
    assert_eq!(NasVpsUrspConfiguration::new(value).parse(), Some(contents));
}

#[test]
fn each_digit_of_an_mcc_pair_is_in_its_half_octet() {
    // MCC 1 digit 2 and digit 1, MCC 2 digit 3 and MCC 1 digit 3, MCC 2 digit 2
    // and digit 1 (figure D.6.8.8)
    let mccs = vec![[1, 2, 3], [4, 5, 6]];
    let contents = Contents::new(
        Replacement::PerTupleReplacement,
        vec![Tuple::new(1, vec![Entry::OneOrMoreMccs(mccs)], vec![])],
    );
    let value = octets("01  0007 01 01 02 02 216354");
    assert_eq!(
        NasVpsUrspConfiguration::from_parsed(&contents)
            .unwrap()
            .value,
        value
    );
    assert_eq!(NasVpsUrspConfiguration::new(value).parse(), Some(contents));
}

#[test]
fn a_receiver_refuses_a_configuration_that_is_not_coded_as_the_annex_codes_it() {
    let refused = [
        // A reserved replacement type, and a tuple that is cut short
        "00",
        "03",
        "01  0005 01 01 03",
        "01  0002 01",
        // A network descriptor of no entry, of a reserved type, of no VPLMN,
        // of no MCC, and an MCC of a digit that is no digit
        "01  0003 01 00 03",
        "01  0003 01 01 04",
        "01  0004 01 01 01 00",
        "01  0004 01 01 02 00",
        "01  0006 01 01 02 01 2a03",
        "01  0007 01 01 02 02 2a6354",
        // An odd octet where the UPSCs are
        "01  0004 01 01 03 01",
    ];
    for value in refused {
        assert_eq!(
            NasVpsUrspConfiguration::new(octets(value)).parse(),
            None,
            "{value}"
        );
    }
    let reserved = Contents::new(Replacement::Reserved(3), vec![]);
    assert!(NasVpsUrspConfiguration::from_parsed(&reserved).is_err());
}
