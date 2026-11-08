//! The ciphering key data (TS 24.501 §9.11.3.18C, Table 9.11.3.18C.1): ciphering data
//! sets, each a set ID, a key of 16 octets, c0 after its length in bits 5 to 1 (16
//! octets at most), the E-UTRA and the NR posSIB types after their lengths in bits 4
//! to 1, the validity start time (octets 2 to 6 of the time zone and time IE of TS
//! 24.008 §10.5.3.9), the validity duration and the TAIs list after its length. A UE
//! keeps sixteen sets, and a set applies to one posSIB type at least.

use oxirush_nas::nas_5gs::{CipheringDataSet, CipheringKeyData};

/// 2026-10-17 12:30, in the swapped BCD digits of TS 24.008 §10.5.3.9.
const START: [u8; 5] = [0x62, 0x01, 0x71, 0x21, 0x03];
/// A partial tracking area identity list of one TAC of PLMN 208 93 (§9.11.3.9).
const TAIS: [u8; 7] = [0x00, 0x02, 0xf8, 0x39, 0x00, 0x00, 0x01];

/// The octets of a ciphering data set of set ID 7, the key ab..ab and the validity
/// duration of 60 minutes.
fn octets(c0: &[u8], eutra: &[u8], nr: &[u8], start: [u8; 5], tais: &[u8]) -> Vec<u8> {
    let mut octets = vec![0x00, 0x07];
    octets.extend([0xab; 16]);
    for field in [c0, eutra, nr] {
        octets.push(field.len() as u8);
        octets.extend(field);
    }
    octets.extend(start);
    octets.extend([0x00, 0x3c]);
    octets.push(tais.len() as u8);
    octets.extend(tais);
    octets
}

/// The set that `octets` writes.
fn set(c0: &[u8], eutra: &[u8], nr: &[u8], start: [u8; 5], tais: &[u8]) -> CipheringDataSet {
    let (c0, eutra, nr, tais) = (c0.to_vec(), eutra.to_vec(), nr.to_vec(), tais.to_vec());
    CipheringDataSet::new(7, [0xab; 16], c0, eutra, nr, start, 60, tais)
}

fn data(octets: Vec<u8>) -> CipheringKeyData {
    CipheringKeyData::new(octets)
}

#[test]
fn a_ciphering_data_set_is_read_field_by_field() {
    // Each field of a length, to the end of the IE and followed by another set
    // c0, the E-UTRA and the NR posSIB types, and the TAIs list
    type Fields<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);
    let fields: [Fields; 4] = [
        (&[0x01, 0x02], &[0x80], &[0x40, 0x00], &TAIS),
        (&[0x5a; 16], &[0x00, 0x00, 0x00, 0x00, 0x00, 0x08], &[], &[]),
        (&[], &[], &[0x01; 7], &TAIS),
        (&[], &[0x80], &[], &[]),
    ];
    for (c0, eutra, nr, tais) in fields {
        let one = octets(c0, eutra, nr, START, tais);
        let written = CipheringKeyData::from_data_sets(&[set(c0, eutra, nr, START, tais)]);
        assert_eq!(written.unwrap().value, one);
        assert_eq!(
            data(one.clone()).data_sets(),
            [set(c0, eutra, nr, START, tais)]
        );
        assert!(data(one.clone()).is_well_formed());
        let two = [one.clone(), octets(&[0x03], &[0x80], &[], START, &[])].concat();
        let read = data(two).data_sets();
        assert_eq!(
            read,
            [
                set(c0, eutra, nr, START, tais),
                set(&[0x03], &[0x80], &[], START, &[])
            ]
        );
    }
    // The shortest set, of no posSIB type, which a sender does not write
    let shortest = octets(&[], &[], &[], START, &[]);
    assert_eq!(shortest.len(), 29);
    assert_eq!(
        data(shortest.clone()).data_sets(),
        [set(&[], &[], &[], START, &[])]
    );
    assert!(!data(shortest).is_well_formed());
    // Sixteen sets at most
    let one = octets(&[], &[0x80], &[], START, &[]);
    assert_eq!(data(one.repeat(17)).data_sets().len(), 16);
}

#[test]
fn a_set_cut_short_is_not_read() {
    // A set of 29 octets at least is read field by field: c0 of 16 octets makes one
    // that is cut in each field after that length
    let c0 = [0x5a; 16];
    let whole = octets(&c0, &[0x80, 0x40], &[0x40, 0x20], START, &TAIS);
    let first = octets(&[], &[0x80], &[], START, &[]);
    // In c0, in the E-UTRA types, in the NR types, in the validity fields and in the
    // TAIs list: the set before is read, and none after it
    for cut in [30, 37, 40, 44, 48, 52, whole.len() - 1] {
        let value = [first.clone(), whole[..cut].to_vec()].concat();
        let read = data(value).data_sets();
        assert_eq!(read, [set(&[], &[0x80], &[], START, &[])], "{cut}");
    }
    // Without NR types, the validity fields cut short
    let no_nr = octets(&c0, &[0x80], &[], START, &[]);
    for cut in [no_nr.len() - 4, no_nr.len() - 2] {
        assert!(data(no_nr[..cut].to_vec()).data_sets().is_empty(), "{cut}");
    }
    // A c0 longer than 16 octets
    let long_c0 = octets(&[0x01; 17], &[0x80], &[], START, &[]);
    assert!(data(long_c0).data_sets().is_empty());
}

#[test]
fn a_sender_writes_the_fields_that_the_table_defines() {
    let written = |c0: &[u8], eutra: &[u8], nr: &[u8], start, tais: &[u8]| {
        CipheringKeyData::from_data_sets(&[set(c0, eutra, nr, start, tais)]).is_ok()
    };
    // One posSIB type at least, of either system
    assert!(written(&[], &[], &[0x80], START, &[]));
    assert!(!written(&[], &[], &[], START, &[]));
    // The three spare bits of the sixth octet of the E-UTRA types
    assert!(!written(&[], &[0, 0, 0, 0, 0, 0x01], &[], START, &[]));
    // A start time in BCD digits: year, month 1 to 12, day 1 to 31, hour to 23,
    // minute to 59, each with its digits swapped
    for start in [
        [0x1a, 0x01, 0x71, 0x21, 0x03],
        [0xa2, 0x01, 0x71, 0x21, 0x03],
        [0x62, 0x00, 0x71, 0x21, 0x03],
        [0x62, 0x31, 0x71, 0x21, 0x03],
        [0x62, 0x01, 0x00, 0x21, 0x03],
        [0x62, 0x01, 0x23, 0x21, 0x03],
        [0x62, 0x01, 0x71, 0x42, 0x03],
        [0x62, 0x01, 0x71, 0x21, 0x06],
    ] {
        assert!(!written(&[], &[0x80], &[], start, &[]), "{start:02x?}");
    }
    assert!(written(
        &[],
        &[0x80],
        &[],
        [0x99, 0x21, 0x13, 0x32, 0x95],
        &[]
    ));
    // A TAIs list as a sender codes it
    assert!(!written(&[], &[0x80], &[], START, &TAIS[..6]));
}
