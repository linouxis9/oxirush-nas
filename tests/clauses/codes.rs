//! The codes of a field of a few bits, as their tables give them (TS 24.501): a
//! receiver reads a value that the table leaves unused as the clause says, and the
//! strict reader, which a sender's check takes, refuses it.

use oxirush_nas::nas_5gs::{DrxValue, EthHdrCompCidLen, NbN1DrxValue, SessionAmbrUnit};

#[test]
fn a_unit_of_the_session_ambr_is_one_of_the_25_steps_of_table_9_11_4_14_1() {
    let units = [
        SessionAmbrUnit::NotUsed,
        SessionAmbrUnit::Kbps1,
        SessionAmbrUnit::Kbps4,
        SessionAmbrUnit::Kbps16,
        SessionAmbrUnit::Kbps64,
        SessionAmbrUnit::Kbps256,
        SessionAmbrUnit::Mbps1,
        SessionAmbrUnit::Mbps4,
        SessionAmbrUnit::Mbps16,
        SessionAmbrUnit::Mbps64,
        SessionAmbrUnit::Mbps256,
        SessionAmbrUnit::Gbps1,
        SessionAmbrUnit::Gbps4,
        SessionAmbrUnit::Gbps16,
        SessionAmbrUnit::Gbps64,
        SessionAmbrUnit::Gbps256,
        SessionAmbrUnit::Tbps1,
        SessionAmbrUnit::Tbps4,
        SessionAmbrUnit::Tbps16,
        SessionAmbrUnit::Tbps64,
        SessionAmbrUnit::Tbps256,
        SessionAmbrUnit::Pbps1,
        SessionAmbrUnit::Pbps4,
        SessionAmbrUnit::Pbps16,
        SessionAmbrUnit::Pbps64,
        SessionAmbrUnit::Pbps256,
    ];
    for (code, unit) in units.into_iter().enumerate() {
        assert_eq!(
            SessionAmbrUnit::from_u8_strict(code as u8),
            Some(unit),
            "{code}"
        );
    }
    // "Other values shall be interpreted as multiples of 256 Pbps"
    for code in [0x1a, 0x80, 0xff] {
        assert_eq!(SessionAmbrUnit::from_u8_strict(code), None, "{code}");
        assert_eq!(
            SessionAmbrUnit::from_u8(code),
            Some(SessionAmbrUnit::Pbps256)
        );
    }
}

#[test]
fn a_drx_value_is_a_cycle_of_its_table_or_not_specified() {
    // Table 9.11.3.2A.1: the cycles 32 to 256, the other codes not specified
    let cycles = [
        DrxValue::NotSpecified,
        DrxValue::Cycle32,
        DrxValue::Cycle64,
        DrxValue::Cycle128,
        DrxValue::Cycle256,
    ];
    for (code, cycle) in cycles.into_iter().enumerate() {
        assert_eq!(DrxValue::from_u8_strict(code as u8), Some(cycle), "{code}");
    }
    for code in 5..16 {
        assert_eq!(DrxValue::from_u8_strict(code), None, "{code}");
        assert_eq!(
            DrxValue::from_u8(code),
            Some(DrxValue::NotSpecified),
            "{code}"
        );
    }
    // Table 9.11.3.73.1: T of 32 to 512 and 1024, with 0110 among the other codes
    let cycles = [
        (0x0, NbN1DrxValue::NotSpecified),
        (0x1, NbN1DrxValue::T32),
        (0x2, NbN1DrxValue::T64),
        (0x3, NbN1DrxValue::T128),
        (0x4, NbN1DrxValue::T256),
        (0x5, NbN1DrxValue::T512),
        (0x7, NbN1DrxValue::T1024),
    ];
    for (code, cycle) in cycles {
        assert_eq!(NbN1DrxValue::from_u8_strict(code), Some(cycle), "{code}");
        assert_eq!(NbN1DrxValue::from_u8(code), Some(cycle), "{code}");
    }
    for code in [0x6, 0x8, 0xf] {
        assert_eq!(NbN1DrxValue::from_u8_strict(code), None, "{code}");
        assert_eq!(
            NbN1DrxValue::from_u8(code),
            Some(NbN1DrxValue::NotSpecified)
        );
    }
}

#[test]
fn a_cid_length_of_11_is_read_as_7_bits() {
    // Figure 9.11.4.28.1: CID Length in the bits 2 and 1
    let lengths = [
        (0, EthHdrCompCidLen::NotUsed),
        (1, EthHdrCompCidLen::SevenBits),
        (2, EthHdrCompCidLen::FifteenBits),
    ];
    for (code, length) in lengths {
        assert_eq!(
            EthHdrCompCidLen::from_u8_strict(code),
            Some(length),
            "{code}"
        );
        assert_eq!(EthHdrCompCidLen::from_u8(code), Some(length), "{code}");
    }
    assert_eq!(EthHdrCompCidLen::from_u8_strict(3), None);
    assert_eq!(
        EthHdrCompCidLen::from_u8(3),
        Some(EthHdrCompCidLen::SevenBits)
    );
}
