//! The units of the extended APN-AMBR (TS 24.301 §9.9.4.29, Table 9.9.4.29.1) and
//! of the extended quality of service (§9.9.4.30, Table 9.9.4.30.1): each code a
//! multiple of the one before it by four, from 4 Mbps to 256 Pbps. The units of the
//! session AMBR and of the bit rates of a QoS flow (TS 24.501 §9.11.4.14, Table
//! 9.11.4.14.1, and §9.11.4.12): the same steps from 1 kbps.

use oxirush_nas::nas_5gs::{NasSessionAmbr, QosFlowBitRate, SessionAmbrUnit};
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

/// The step of each code of the unit of TS 24.501 Table 9.11.4.14.1, in kbps: 1 kbps
/// for the code that is not used (its NOTE: a value received with it is read in
/// multiples of 1 kbps), then four times the step before it, from 1 kbps.
fn step_of(unit: u8) -> u64 {
    match unit {
        0x00 => 1,
        0x01..=0x19 => {
            [1, MBPS, GBPS, TBPS, PBPS][usize::from(unit - 1) / 5]
                * 4u64.pow(u32::from(unit - 1) % 5)
        }
        _ => 256 * PBPS,
    }
}

#[test]
fn each_unit_of_the_session_ambr_is_its_step() {
    assert_eq!(
        (step_of(0x05), step_of(0x06), step_of(0x19)),
        (256, MBPS, 256 * PBPS)
    );
    for unit in 0..=0x19 {
        let multiplier = SessionAmbrUnit::from_u8_strict(unit)
            .unwrap()
            .kbps_multiplier();
        assert_eq!(multiplier, Some(step_of(unit)), "{unit}");
    }
    for unit in 0..=u8::MAX {
        // Downlink in octets 1 to 3 of the value, uplink in octets 4 to 6
        let ambr = NasSessionAmbr::new(vec![unit, 0x00, 0x03, unit, 0x01, 0x00]);
        assert_eq!(ambr.downlink_kbps(), Some(3 * step_of(unit)), "{unit}");
        assert_eq!(ambr.uplink_kbps(), Some(256 * step_of(unit)), "{unit}");
        let parsed = ambr.parse().unwrap();
        assert_eq!(
            (parsed.dl_kbps, parsed.ul_kbps),
            (3 * step_of(unit), 256 * step_of(unit))
        );
        let rate = QosFlowBitRate { unit, value: 5 };
        assert_eq!(rate.kbps(), Some(5 * step_of(unit)), "{unit}");
    }
}

#[test]
fn a_session_ambr_reads_the_fields_that_its_value_has() {
    let ambr = NasSessionAmbr::new(vec![0x06, 0x01, 0x02, 0x0b, 0x03, 0x04]);
    assert_eq!(
        (ambr.downlink_value(), ambr.uplink_value()),
        (0x0102, 0x0304)
    );
    // A value cut short has the fields that it reaches, and no rate
    let short = NasSessionAmbr::new(vec![0x06, 0x01, 0x02]);
    assert_eq!((short.downlink_value(), short.uplink_value()), (0x0102, 0));
    assert_eq!(
        (short.downlink_kbps(), short.uplink_kbps(), short.parse()),
        (None, None, None)
    );
    assert_eq!(NasSessionAmbr::new(vec![0x06, 0x01]).downlink_value(), 0);
    assert_eq!(NasSessionAmbr::new(vec![]).downlink_value(), 0);
    // A setter writes its unit and value, and leaves the other direction
    let mut ambr = NasSessionAmbr::new(vec![]);
    ambr.set_downlink(0x06, 0x0102);
    assert_eq!(ambr.value, [0x06, 0x01, 0x02, 0x00, 0x00, 0x00]);
    ambr.set_uplink(0x0b, 0x0304);
    assert_eq!(ambr.value, [0x06, 0x01, 0x02, 0x0b, 0x03, 0x04]);
    ambr.set_downlink(0x01, 0xffff);
    assert_eq!(ambr.value, [0x01, 0xff, 0xff, 0x0b, 0x03, 0x04]);
    // Octets after the end of the IE that the clause gives are ignored (TS 24.007
    // §11.2.2.1 g)
    let longer = NasSessionAmbr::new(vec![0x06, 0x01, 0x02, 0x0b, 0x03, 0x04, 0xff]);
    let parsed = longer.parse().unwrap();
    assert_eq!(
        (parsed.dl_kbps, parsed.ul_kbps),
        (0x0102 * MBPS, 0x0304 * GBPS)
    );
}
