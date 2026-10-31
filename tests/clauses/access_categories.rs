//! The operator-defined access category definitions (TS 24.501 §9.11.3.38): each
//! definition is its length, its precedence, PSAC and its number, the length of its
//! criteria, the criteria, and with PSAC the standardized access category. A
//! criterion is its type and a count of DNNs, of OS Id and OS App Id pairs, or of
//! S-NSSAIs, each an SST alone or an SST and an SD.

use oxirush_nas::nas_5gs::{
    NasOperatorDefinedAccessCategoryDefinitions as Definitions,
    OperatorAccessCategoryCriterion as Criterion, OperatorAccessCategoryDefinition as Definition,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// A definition of each type of criterion: two DNNs and two S-NSSAIs, then two
/// pairs of an OS Id and an OS App Id with the standardized access category 9.
fn two_definitions() -> (Vec<u8>, Vec<Definition>) {
    let value = octets(
        "1d 01 02 1a
            00 02 09 08696e7465726e6574 04 03696d73
            02 02 01 01 04 01000001
         2a 02 9f 26
            01 02 11111111111111111111111111111111 02 6162
                  22222222222222222222222222222222 00
            09",
    );
    let definitions = vec![
        Definition::new(
            0x01,
            false,
            0x02,
            vec![
                Criterion::Dnns(vec![b"\x08internet".to_vec(), b"\x03ims".to_vec()]),
                Criterion::SNssais(vec![vec![0x01], vec![0x01, 0x00, 0x00, 0x01]]),
            ],
            None,
        ),
        Definition::new(
            0x02,
            true,
            0x1f,
            vec![Criterion::OsApps(vec![
                (vec![0x11; 16], b"ab".to_vec()),
                (vec![0x22; 16], Vec::new()),
            ])],
            Some(9),
        ),
    ];
    (value, definitions)
}

#[test]
fn definitions_have_each_criterion_of_its_type() {
    let (value, definitions) = two_definitions();
    assert_eq!(
        Definitions::new(value.clone()).try_definitions(),
        Some(definitions.clone())
    );
    assert_eq!(
        Definitions::from_definitions(&definitions).unwrap().value,
        value
    );
}

#[test]
fn a_dnn_is_labels_and_an_s_nssai_an_sst_or_an_sst_and_an_sd() {
    // A DNN whose label says 5 octets of the 3 that it has
    let dnn = octets("0a 01 02 07 00 01 04 05696d73");
    assert_eq!(Definitions::new(dnn).try_definitions(), None);
    // An SST and a mapped SST, which an S-NSSAI of the IE has but not one of a criterion
    let s_nssai = octets("08 01 02 05 02 01 02 0102");
    assert_eq!(Definitions::new(s_nssai).try_definitions(), None);
    let definition = Definition::new(
        1,
        false,
        2,
        vec![Criterion::SNssais(vec![vec![1, 2]])],
        None,
    );
    assert!(Definitions::from_definitions(&[definition]).is_err());
}
