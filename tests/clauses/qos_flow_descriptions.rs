//! The QoS flow descriptions (TS 24.501 §9.11.4.12, Table 9.11.4.12.1): a QFI, an
//! operation code in bits 8 to 6 of octet 5, the E bit and the number of parameters
//! in octet 6, and each parameter as an identifier, a length and its contents. An
//! operation takes the E bit and the parameters that its row of the table says, and a
//! MFBR of 0 kbps in both directions is a syntactical error.

use oxirush_nas::nas_5gs::{
    NasQosFlowDescriptions, QosFlowBitRate, QosFlowDescription, QosFlowOpCode, QosFlowParameter,
};

/// Whether the table allows an operation with the E bit and a number of parameters:
/// creation with the E bit and parameters, deletion with neither, modification
/// with parameters.
fn allowed(op_code: u8, e_flag: bool, count: u8) -> bool {
    match op_code {
        1 => e_flag && count > 0,
        2 => !e_flag && count == 0,
        3 => count > 0,
        _ => false,
    }
}

#[test]
fn an_operation_has_the_e_bit_and_the_parameters_of_its_row() {
    for op_code in 0..8u8 {
        for e_flag in [false, true] {
            for count in [0u8, 1, 2] {
                // QFI 5, then 5QI 9 and the averaging window as the parameters
                let mut octets = vec![0x05, op_code << 5, u8::from(e_flag) << 6 | count];
                let parameters = [[0x01, 0x01, 0x09].as_slice(), &[0x06, 0x02, 0x07, 0xd0]];
                octets.extend(parameters[..usize::from(count)].concat());
                let received = NasQosFlowDescriptions::new(octets);
                let expected = allowed(op_code, e_flag, count);
                let parsed = received.parse_descriptions();
                let case = format!("{op_code} {e_flag} {count}");
                assert_eq!(parsed.len(), 1, "{case}");
                assert_eq!(parsed[0].is_ok(), expected, "{case}");
                // The sender has the same rule, for the codes that name an operation
                let Some(code) = [
                    QosFlowOpCode::Reserved,
                    QosFlowOpCode::Create,
                    QosFlowOpCode::Delete,
                    QosFlowOpCode::Modify,
                ]
                .get(usize::from(op_code)) else {
                    continue;
                };
                let parameters = [
                    QosFlowParameter::FiveQi(9),
                    QosFlowParameter::AveragingWindow(2000),
                ];
                let parameters = parameters[..usize::from(count)].to_vec();
                let description = QosFlowDescription::new(5, *code, e_flag, parameters);
                if let Ok(parsed) = &parsed[0] {
                    assert_eq!(parsed, &description, "{case}");
                }
                let sent = NasQosFlowDescriptions::from_descriptions(&[description]);
                assert_eq!(sent.is_ok(), expected, "{case}");
                if let Ok(sent) = sent {
                    assert_eq!(sent.value, received.value, "{case}");
                }
            }
        }
    }
}

/// The octets of one description, as the sender writes them.
fn description_bytes(description: &QosFlowDescription) -> Vec<u8> {
    NasQosFlowDescriptions::from_descriptions(core::slice::from_ref(description))
        .unwrap()
        .value
        .to_vec()
}

/// The one description of these octets.
fn description_of(octets: &[u8]) -> QosFlowDescription {
    let descriptions = NasQosFlowDescriptions::new(octets.to_vec())
        .try_descriptions()
        .unwrap();
    assert_eq!(descriptions.len(), 1);
    descriptions.into_iter().next().unwrap()
}

#[test]
fn each_parameter_is_read_from_its_identifier() {
    let rate = |unit, value| QosFlowBitRate { unit, value };
    let octets = [
        0x3f, 0x20, 0x47, // QFI 63, created with seven parameters
        0x01, 0x01, 0x52, // 5QI 82
        0x02, 0x03, 0x06, 0x00, 0x02, // GFBR uplink, 2 Mbps
        0x03, 0x03, 0x06, 0x00, 0x03, // GFBR downlink, 3 Mbps
        0x04, 0x03, 0x06, 0x00, 0x04, // MFBR uplink, 4 Mbps
        0x05, 0x03, 0x06, 0x00, 0x05, // MFBR downlink, 5 Mbps
        0x06, 0x02, 0x07, 0xd0, // averaging window, 2000 ms
        0x07, 0x01, 0x50, // EPS bearer identity 5, bits 4 to 1 spare
    ];
    let description = description_of(&octets);
    let expected = vec![
        QosFlowParameter::FiveQi(82),
        QosFlowParameter::GfbrUl(rate(0x06, 2)),
        QosFlowParameter::GfbrDl(rate(0x06, 3)),
        QosFlowParameter::MfbrUl(rate(0x06, 4)),
        QosFlowParameter::MfbrDl(rate(0x06, 5)),
        QosFlowParameter::AveragingWindow(2000),
        QosFlowParameter::EpsBearerId(5),
    ];
    assert_eq!(
        (description.qfi, description.op_code),
        (63, QosFlowOpCode::Create)
    );
    assert_eq!(description.params, expected);
    assert_eq!(description_bytes(&description), octets);
    let descriptions = NasQosFlowDescriptions::new(octets.to_vec());
    assert!(descriptions.contains_eps_bearer_identity());
    // Without the EPS bearer identity
    let mut octets = octets[..octets.len() - 3].to_vec();
    octets[2] = 0x46;
    assert!(!NasQosFlowDescriptions::new(octets).contains_eps_bearer_identity());
}

#[test]
fn a_mfbr_of_zero_kbps_is_refused_in_both_directions_only() {
    let rate = |value| QosFlowBitRate { unit: 0x01, value };
    for (uplink, downlink) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
        let parameters = vec![
            QosFlowParameter::MfbrUl(rate(uplink)),
            QosFlowParameter::MfbrDl(rate(downlink)),
        ];
        let description = QosFlowDescription::new(1, QosFlowOpCode::Create, true, parameters);
        let refused = uplink == 0 && downlink == 0;
        let sent = NasQosFlowDescriptions::from_descriptions(&[description]);
        assert_eq!(sent.is_err(), refused, "{uplink} {downlink}");
        let octets = [
            0x01,
            0x20,
            0x42,
            0x04,
            0x03,
            0x01,
            0x00,
            uplink as u8,
            0x05,
            0x03,
            0x01,
            0x00,
            downlink as u8,
        ];
        let received = NasQosFlowDescriptions::new(octets.to_vec()).parse_descriptions();
        assert_eq!(received[0].is_err(), refused, "{uplink} {downlink}");
    }
}
