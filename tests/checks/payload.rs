//! The contents of a payload container of the type "event notification" or
//! "multiple payloads" (TS 24.501 §9.11.3.39).

use oxirush_nas::nas_5gs::*;

fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

#[test]
fn an_event_notification_container_has_each_indicator_with_its_length() {
    // TS 24.501 §9.11.3.39, Figure 9.11.3.39.1B: the event notification indicators,
    // each a type, a length and a value
    let two = EventNotificationContainer::decode(&octets("02 05 01 aa 00 00")).unwrap();
    assert_eq!(
        two.indicators,
        vec![
            EventNotificationIndicator {
                indicator_type: EventNotificationIndicatorType::Unknown(5),
                value: vec![0xaa],
            },
            EventNotificationIndicator {
                indicator_type:
                    EventNotificationIndicatorType::SrvccHandoverCancelledImsSessionReEstablishmentRequired,
                value: vec![],
            },
        ]
    );
    assert_eq!(two.encode().unwrap(), octets("02 05 01 aa 00 00"));
    assert!(EventNotificationContainer::decode(&octets("01 05")).is_err());
    assert!(EventNotificationContainer::decode(&octets("01 05 02 aa")).is_err());
}

#[test]
fn a_multiple_payload_container_has_each_entry_with_its_length() {
    // §9.11.3.39: the number of entries, then each with its length, its
    // number of optional IEs and its payload container type, its optional
    // IEs and its contents
    let decoded =
        MultiplePayloadContainer::decode(&octets("03  0001 05  0003 18 1200  0004 1f 1201 aa"))
            .unwrap();
    assert_eq!(decoded.entries.len(), 3);
    assert_eq!(decoded.entries[0].payload_container_type.value, 5);
    assert!(decoded.entries[0].optional_ies.is_empty());
    assert_eq!(decoded.entries[1].payload_container_type.value, 8);
    assert_eq!(decoded.entries[1].optional_ies.len(), 1);
    assert!(decoded.entries[1].contents.is_empty());
    assert_eq!(decoded.entries[2].payload_container_type.value, 0x0f);
    assert_eq!(decoded.entries[2].optional_ies[0].iei(), 0x12);
    assert_eq!(decoded.entries[2].optional_ies[0].value(), [0xaa]);
    assert!(decoded.entries[2].contents.is_empty());
    assert_eq!(
        decoded.encode().unwrap(),
        octets("03  0001 05  0003 18 1200  0004 1f 1201 aa")
    );
    let one = MultiplePayloadContainer::decode(&octets("01 0001 05")).unwrap();
    assert_eq!(one.entries.len(), 1);
    // An entry longer than the octets, and an optional IE longer than its entry
    assert!(MultiplePayloadContainer::decode(&octets("01 0005 05 aa")).is_err());
    assert!(MultiplePayloadContainer::decode(&octets("01 0003 15 1202")).is_err());
    // Fifteen optional IEs at most, and a type of four bits
    let entry = |optional_ies: usize, kind: u8| {
        MultiplePayloadContainer::new(vec![MultiplePayloadEntry::new(
            PayloadContainerType::new(kind),
            vec![MultiplePayloadOptionalIe::from_raw(0x12, vec![1]); optional_ies],
            vec![],
        )])
        .encode()
    };
    assert!(entry(15, 1).is_ok());
    assert!(entry(16, 1).is_err());
    assert!(entry(0, 0x0f).is_ok());
    assert!(entry(0, 0x10).is_err());
}
