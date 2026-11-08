//! The N3QAI (TS 24.501 §9.11.4.36): entries of a number of QFIs and the QFIs, then a
//! number of parameters, each an identifier, the length of its contents and the
//! contents, of the length that the identifier gives them.

use oxirush_nas::nas_5gs::{
    N3Qai, N3QaiParameter, N3QaiParameterIdentifier as Id, N3QaiParameterValue as Value,
    N3QaiResourceType as Resource, QosFlowBitRate,
};

#[test]
fn a_parameter_has_the_contents_of_its_identifier() {
    let rate = QosFlowBitRate {
        unit: 0x06,
        value: 0x0102,
    };
    let cases = [
        (0x01, vec![9], Some(Value::FiveQi(9))),
        (0x02, vec![6, 1, 2], Some(Value::GfbrUplink(rate))),
        (0x03, vec![6, 1, 2], Some(Value::GfbrDownlink(rate))),
        (0x04, vec![6, 1, 2], Some(Value::MfbrUplink(rate))),
        (0x05, vec![6, 1, 2], Some(Value::MfbrDownlink(rate))),
        (0x06, vec![0x07, 0xd0], Some(Value::AveragingWindow(2000))),
        (0x07, vec![0], Some(Value::ResourceType(Resource::Gbr))),
        (
            0x07,
            vec![1],
            Some(Value::ResourceType(Resource::DelayedCriticalGbr)),
        ),
        (0x07, vec![2], Some(Value::ResourceType(Resource::NonGbr))),
        (0x07, vec![3], None),
        (0x08, vec![5], Some(Value::PriorityLevel(5))),
        (0x09, vec![0, 100], Some(Value::PacketDelayBudget(100))),
        (
            0x0a,
            vec![1, 6],
            Some(Value::PacketErrorRate {
                scalar: 1,
                exponent: 6,
            }),
        ),
        (
            0x0b,
            vec![0x05, 0xdc],
            Some(Value::MaximumDataBurstVolume(1500)),
        ),
        (
            0x0c,
            vec![0, 10],
            Some(Value::MaximumPacketLossRateDownlink(10)),
        ),
        (
            0x0d,
            vec![0, 20],
            Some(Value::MaximumPacketLossRateUplink(20)),
        ),
        (0x0e, vec![0x41], Some(Value::Arp(0x41))),
        (0x0f, vec![1, 2, 3], Some(Value::Periodicity(vec![1, 2, 3]))),
        (0x0f, vec![], None),
        (
            0x20,
            vec![1],
            Some(Value::Unsupported {
                identifier: 0x20,
                contents: vec![1],
            }),
        ),
    ];
    for (identifier, contents, value) in cases {
        let identifier = Id::from_u8(identifier);
        let parameter = N3QaiParameter {
            identifier,
            contents: contents.clone(),
        };
        assert_eq!(parameter.value(), value, "{identifier:?}");
        // One octet more or less than its length is not a value, but for the
        // periodicity, of any length, and an identifier of no value defined
        if value.is_some() && !matches!(identifier, Id::Periodicity | Id::Unknown(_)) {
            for length in [contents.len() - 1, contents.len() + 1] {
                let parameter = N3QaiParameter {
                    identifier,
                    contents: vec![0; length],
                };
                assert_eq!(parameter.value(), None, "{identifier:?} {length}");
            }
        }
    }
}

#[test]
fn an_entry_has_its_qfis_and_its_parameters() {
    let n3qai = |octets: &[u8]| N3Qai::new(octets.to_vec());
    // QFIs 1 and 2 with 5QI 9 and the priority level 5; then QFI 3 with the ARP
    let value = [
        0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x09, 0x08, 0x01, 0x05, //
        0x01, 0x03, 0x01, 0x0e, 0x01, 0x41,
    ];
    let entries = n3qai(&value).try_entries().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        (entries[0].qfis.as_slice(), entries[1].qfis.as_slice()),
        (&[1, 2][..], &[3][..])
    );
    assert_eq!(entries[0].parameters.len(), 2);
    let arp = entries[1].parameters[0].value();
    assert_eq!(arp, Some(Value::Arp(0x41)));
    // QFIs to the end of the IE, without the number of parameters; and contents cut
    // short
    assert_eq!(
        n3qai(&[0x05, 0x01, 0x02, 0x03, 0x04, 0x05]).try_entries(),
        None
    );
    assert_eq!(
        n3qai(&[0x01, 0x01, 0x01, 0x01, 0x02, 0x00]).try_entries(),
        None
    );
}

#[test]
fn an_n3qai_has_six_octets_at_least_and_parameters_of_their_length() {
    let n3qai = |octets: &[u8]| N3Qai::new(octets.to_vec()).try_entries();
    // Six octets: one QFI and the 5QI; fewer is not an N3QAI, though it decodes
    assert_eq!(
        n3qai(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x09]).map(|e| e.len()),
        Some(1)
    );
    assert_eq!(n3qai(&[0x01, 0x01, 0x00]), None);
    // A parameter of an undefined identifier and no contents, at the end
    let unsupported = n3qai(&[0x02, 0x01, 0x02, 0x01, 0x20, 0x00]).unwrap();
    let value = unsupported[0].parameters[0].value();
    let expected = Value::Unsupported {
        identifier: 0x20,
        contents: vec![],
    };
    assert_eq!(value, Some(expected));
    // A second parameter of its identifier alone, and an averaging window that ends
    // the IE
    assert_eq!(n3qai(&[0x01, 0x01, 0x02, 0x08, 0x01, 0x05, 0x0e]), None);
    let window = n3qai(&[0x01, 0x01, 0x01, 0x06, 0x02, 0x07, 0xd0]).unwrap();
    assert_eq!(
        window[0].parameters[0].value(),
        Some(Value::AveragingWindow(2000))
    );
}
