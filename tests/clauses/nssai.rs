//! The S-NSSAI (TS 24.501 §9.11.2.8) of 1, 2, 4, 5 or 8 octets, and the lists of
//! them: the NSSAI (§9.11.3.37), the mapped NSSAI (§9.11.3.31B) of S-NSSAIs that are
//! an SST with or without its SD, and the rejected NSSAI (§9.11.3.46), each entry the
//! length of its S-NSSAI and its cause in one octet, then the SST with or without its
//! SD. A sender writes eight entries at most, and a rejected S-NSSAI a defined cause.

use oxirush_nas::nas_5gs::{MappedNssai, Nssai, RejectedNssai, SNssai};

#[test]
fn an_s_nssai_has_the_lengths_of_its_members() {
    for length in 0..=9 {
        let snssai = SNssai::new(vec![0x01; length]);
        let defined = matches!(length, 1 | 2 | 4 | 5 | 8);
        assert_eq!(snssai.is_well_formed(), defined, "{length}");
    }
    assert!(Nssai::new(vec![0x01, 0x01, 0x04, 0x01, 0x00, 0x00, 0x01]).is_well_formed());
    assert!(!Nssai::new(vec![0x03, 0x01, 0x00, 0x00]).is_well_formed());
}

#[test]
fn a_mapped_s_nssai_is_an_sst_with_or_without_its_sd() {
    let sst = SNssai::new(vec![0x01]);
    let sst_sd = SNssai::new(vec![0x02, 0x00, 0x00, 0x07]);
    let mapped = MappedNssai::from_snssais(&[sst.clone(), sst_sd]).unwrap();
    assert_eq!(mapped.value, [0x01, 0x01, 0x04, 0x02, 0x00, 0x00, 0x07]);
    assert!(mapped.is_well_formed());
    // An S-NSSAI with a mapped SST is not one of them
    let with_mapped_sst = SNssai::new(vec![0x01, 0x02]);
    assert!(MappedNssai::from_snssais(&[with_mapped_sst]).is_err());
    assert!(!MappedNssai::new(vec![0x02, 0x01, 0x02]).is_well_formed());
    assert!(!MappedNssai::new(vec![]).is_well_formed());
    // Eight S-NSSAIs at most
    assert!(MappedNssai::new([0x01, 0x01].repeat(8)).is_well_formed());
    assert!(!MappedNssai::new([0x01, 0x01].repeat(9)).is_well_formed());
}

#[test]
fn a_rejected_s_nssai_has_its_length_and_a_defined_cause() {
    let sst = SNssai::new(vec![0x01]);
    let sst_sd = SNssai::new(vec![0x02, 0x00, 0x00, 0x07]);
    let rejected = RejectedNssai::from_entries_raw(&[(0x00, &sst), (0x02, &sst_sd)]).unwrap();
    assert_eq!(rejected.value, [0x10, 0x01, 0x42, 0x02, 0x00, 0x00, 0x07]);
    assert!(rejected.is_well_formed());
    // An S-NSSAI with a mapped SST is not one of them, nor a cause that Table
    // 9.11.3.46.1 does not define
    let with_mapped_sst = SNssai::new(vec![0x01, 0x02]);
    assert!(RejectedNssai::from_entries_raw(&[(0x00, &with_mapped_sst)]).is_err());
    assert!(!RejectedNssai::new(vec![0x1f, 0x01]).is_well_formed());
    // Eight rejected S-NSSAIs at most
    assert!(RejectedNssai::new([0x10, 0x01].repeat(8)).is_well_formed());
    assert!(!RejectedNssai::new([0x10, 0x01].repeat(9)).is_well_formed());
}
