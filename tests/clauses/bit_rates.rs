//! The units of the extended APN-AMBR (TS 24.301 §9.9.4.29, Table 9.9.4.29.1) and
//! of the extended quality of service (§9.9.4.30, Table 9.9.4.30.1): each code a
//! multiple of the one before it by four, from 4 Mbps to 256 Pbps.

use oxirush_nas::nas_eps::{ExtendedApnAmbr, ExtendedEpsQos};

const MBPS: u64 = 1_000;
const GBPS: u64 = 1_000 * MBPS;
const TBPS: u64 = 1_000 * GBPS;
const PBPS: u64 = 1_000 * TBPS;

/// The step of each code of the unit, in kbps, as Table 9.9.4.29.1 has it.
const STEPS: [(u8, u64); 19] = [
    (0x03, 4 * MBPS),
    (0x04, 16 * MBPS),
    (0x05, 64 * MBPS),
    (0x06, 256 * MBPS),
    (0x07, GBPS),
    (0x08, 4 * GBPS),
    (0x09, 16 * GBPS),
    (0x0a, 64 * GBPS),
    (0x0b, 256 * GBPS),
    (0x0c, TBPS),
    (0x0d, 4 * TBPS),
    (0x0e, 16 * TBPS),
    (0x0f, 64 * TBPS),
    (0x10, 256 * TBPS),
    (0x11, PBPS),
    (0x12, 4 * PBPS),
    (0x13, 16 * PBPS),
    (0x14, 64 * PBPS),
    (0x15, 256 * PBPS),
];

#[test]
fn each_unit_of_the_extended_apn_ambr_is_its_step() {
    for (unit, step) in STEPS {
        let ambr = ExtendedApnAmbr::from_bytes(&[unit, 0, 1, unit, 0, 3]).unwrap();
        assert_eq!(ambr.downlink_kbps(), Some(step), "{unit}");
        assert_eq!(ambr.uplink_kbps(), Some(3 * step), "{unit}");
    }
    // The codes that are not used are read as 4 Mbps, and the codes after
    // 256 Pbps as 256 Pbps
    for unit in [0, 1, 2] {
        let ambr = ExtendedApnAmbr::from_bytes(&[unit, 0, 1, unit, 0, 1]).unwrap();
        assert_eq!(ambr.downlink_kbps(), Some(4 * MBPS), "{unit}");
    }
    for unit in [0x16, 0xff] {
        let ambr = ExtendedApnAmbr::from_bytes(&[unit, 0, 1, unit, 0, 1]).unwrap();
        assert_eq!(ambr.uplink_kbps(), Some(256 * PBPS), "{unit}");
    }
    // A rate takes the smallest unit that codes it exactly in 16 bits
    let ambr = ExtendedApnAmbr::from_kbps(4 * MBPS, 65_535 * 16 * MBPS).unwrap();
    assert_eq!(ambr.to_bytes(), [0x03, 0x00, 0x01, 0x04, 0xff, 0xff]);
    let ambr = ExtendedApnAmbr::from_kbps(65_536 * 4 * MBPS, 3 * PBPS).unwrap();
    assert_eq!(ambr.to_bytes(), [0x04, 0x40, 0x00, 0x0a, 0xb7, 0x1b]);
    assert!(ExtendedApnAmbr::from_kbps(MBPS, 4 * MBPS).is_err());
}

#[test]
fn each_unit_of_the_extended_quality_of_service_is_its_step() {
    // Above 10 Gbps alone: a rate of 10 Gbps or less is ignored
    for (unit, step) in STEPS {
        let value = 10 * GBPS / step + 1;
        let Ok(value) = u16::try_from(value) else {
            continue;
        };
        let qos = ExtendedEpsQos::from_bytes(&[unit, 0, 0, 0, 0, unit, 0, 0, 0, 0]).unwrap();
        let qos = ExtendedEpsQos {
            mbr_ul: value,
            gbr_dl: value,
            ..qos
        };
        let kbps = u64::from(value) * step;
        assert_eq!(qos.mbr_ul_kbps(), Some(kbps), "{unit}");
        assert_eq!(qos.gbr_dl_kbps(), Some(kbps), "{unit}");
        assert_eq!(qos.mbr_dl_kbps(), None, "{unit}");
        assert_eq!(qos.gbr_ul_kbps(), None, "{unit}");
    }
    // 200 kbps (code 1, and code 0 that is not used) and 1 Mbps (code 2)
    for (unit, step) in [(0, 200), (1, 200), (2, MBPS)] {
        let value = (10 * GBPS / step + 1) as u16;
        let qos = ExtendedEpsQos::from_bytes(&[unit, 0, 0, 0, 0, unit, 0, 0, 0, 0]).unwrap();
        let qos = ExtendedEpsQos {
            mbr_dl: value,
            ..qos
        };
        assert_eq!(qos.mbr_dl_kbps(), Some(u64::from(value) * step), "{unit}");
    }
    let qos = ExtendedEpsQos::from_bytes(&[0x16, 0, 1, 0, 0, 0xff, 0, 0, 0, 1]).unwrap();
    assert_eq!(qos.mbr_ul_kbps(), Some(256 * PBPS));
    assert_eq!(qos.gbr_dl_kbps(), Some(256 * PBPS));
    // Each pair of rates shares its smallest unit
    let qos = ExtendedEpsQos::from_kbps(20 * GBPS, 12 * GBPS, 5 * GBPS, 64 * TBPS).unwrap();
    assert_eq!(
        qos.to_bytes(),
        [0x02, 0x4e, 0x20, 0x2e, 0xe0, 0x07, 0x00, 0x00, 0xfa, 0x00]
    );
}
