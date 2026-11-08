//! Canonical NAS messages cover every supported message type and nested payload.
//! These independently checked wire vectors need no external test tools.
use std::collections::HashSet;

use oxirush_nas::{Severity, Validate};
use oxirush_nas::{nas_5gs as f, nas_eps as e};

fn rows(messages: &str) -> impl Iterator<Item = (&str, Vec<u8>)> {
    messages
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t');
            let name = fields.next().unwrap();
            (name, hex::decode(fields.next().unwrap()).unwrap())
        })
}

#[test]
fn every_supported_5gs_message_has_a_canonical_exact_byte_fixture() {
    let mut gmm = HashSet::new();
    let mut gsm = HashSet::new();
    for (name, wire) in rows(include_str!("fixtures/nas-5gs.tsv")) {
        let pdu = f::Message::decode(&wire).unwrap_or_else(|e| panic!("{name}: {e}"));
        let errors: Vec<_> = pdu
            .validate()
            .into_iter()
            .filter(|finding| matches!(finding.severity, Severity::Error))
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        assert_eq!(pdu.encode().unwrap(), wire, "{name}");
        match pdu {
            f::Message::Gmm(header, _) => {
                gmm.insert(u8::from(header.message_type));
            }
            f::Message::Gsm(header, _) => {
                gsm.insert(u8::from(header.message_type));
            }
            _ => panic!("plain fixture expected: {name}"),
        }
    }
    for byte in 0..=255 {
        if !matches!(f::GmmMessageType::from(byte), f::GmmMessageType::Unknown(_)) {
            assert!(gmm.contains(&byte), "missing 5GMM type {byte:02x}");
        }
        if !matches!(f::GsmMessageType::from(byte), f::GsmMessageType::Unknown(_)) {
            assert!(gsm.contains(&byte), "missing 5GSM type {byte:02x}");
        }
    }
}

#[test]
fn every_supported_eps_message_has_a_canonical_exact_byte_fixture() {
    let mut emm = HashSet::new();
    let mut esm = HashSet::new();
    for (name, wire) in rows(include_str!("fixtures/nas-eps.tsv")) {
        let direction = if name.starts_with("DetachRequestUeTerminated") {
            oxirush_nas::Direction::Downlink
        } else {
            oxirush_nas::Direction::Uplink
        };
        let pdu = e::Message::decode_with(
            &wire,
            oxirush_nas::DecodeOptions::STRICT.with_direction(direction),
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        let errors: Vec<_> = pdu
            .validate()
            .into_iter()
            .filter(|finding| matches!(finding.severity, Severity::Error))
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        assert_eq!(pdu.encode().unwrap(), wire, "{name}");
        match pdu {
            e::Message::Emm(header, _) => {
                emm.insert(u8::from(header.message_type));
            }
            e::Message::Esm(header, _) => {
                esm.insert(u8::from(header.message_type));
            }
            _ => panic!("plain fixture expected: {name}"),
        }
    }
    for byte in 0..=255 {
        if !matches!(e::EmmMessageType::from(byte), e::EmmMessageType::Unknown(_)) {
            assert!(emm.contains(&byte), "missing EMM type {byte:02x}");
        }
        if !matches!(e::EsmMessageType::from(byte), e::EsmMessageType::Unknown(_)) {
            assert!(esm.contains(&byte), "missing ESM type {byte:02x}");
        }
    }
}

#[test]
fn header_spares_are_kept_as_received() {
    // 24.007 11.4.2: receivers ignore spare bits. The typed headers keep
    // them, so a message is encoded with the octets it was received with.
    for spare in 0..=0x0f {
        let plain = [0x7e, spare << 4, 0x43];
        let message = f::Message::decode(&plain).unwrap();
        assert_eq!(message.encode().unwrap(), plain);

        let protected = [0x7e, (spare << 4) | 1, 0, 0, 0, 0, 0, 0x7e, 0, 0x43];
        let message = f::Message::decode(&protected).unwrap();
        assert_eq!(message.encode().unwrap(), protected);
    }
    // EPS retains received short SERVICE REQUEST header values 12..=15,
    // despite interpreting each as the same security-header class.
    for header in 0xc7..=0xf7 {
        if header & 0x0f == 7 {
            let wire = [header, 0, 0, 0];
            assert_eq!(e::Message::decode(&wire).unwrap().encode().unwrap(), wire);
        }
    }
}

#[test]
fn nas_containers_recursively_decode_to_the_permitted_message_families() {
    fn fivegs_inner(wire: &[u8], message_type: u8) {
        let inner = f::Message::decode(wire).unwrap();
        assert_eq!(inner.encode().unwrap(), wire);
        assert!(
            inner
                .validate()
                .iter()
                .all(|i| i.severity != Severity::Error),
            "nested {}: {:?}",
            hex::encode(wire),
            inner.validate()
        );
        match inner {
            f::Message::Gmm(header, _) => {
                assert_eq!(u8::from(header.message_type), message_type)
            }
            f::Message::Gsm(header, _) => {
                assert_eq!(u8::from(header.message_type), message_type)
            }
            _ => panic!("expected plain inner NAS"),
        }
    }
    fn eps_inner(wire: &[u8], message_type: u8) {
        let inner = e::Message::decode(wire).unwrap();
        assert_eq!(inner.encode().unwrap(), wire);
        assert!(
            inner
                .validate()
                .iter()
                .all(|i| i.severity != Severity::Error),
            "nested {}: {:?}",
            hex::encode(wire),
            inner.validate()
        );
        let e::Message::Esm(header, _) = inner else {
            panic!("expected ESM container")
        };
        assert_eq!(u8::from(header.message_type), message_type);
    }
    let mut f_nested = 0;
    for (_, wire) in rows(include_str!("fixtures/nas-5gs.tsv")) {
        let f::Message::Gmm(_, body) = f::Message::decode(&wire).unwrap() else {
            continue;
        };
        let container = match body {
            f::GmmMessage::RegistrationRequest(m) => {
                m.nas_message_container.map(|c| (c.value, 0x41))
            }
            f::GmmMessage::DeregistrationRequestUeOriginating(m) => {
                m.nas_message_container.map(|c| (c.value, 0x45))
            }
            f::GmmMessage::ServiceRequest(m) => m.nas_message_container.map(|c| (c.value, 0x4c)),
            f::GmmMessage::SecurityModeComplete(m) => {
                m.nas_message_container.map(|c| (c.value, 0x41))
            }
            f::GmmMessage::ControlPlaneServiceRequest(m) => {
                if let Some(payload) = m.payload_container {
                    // 24.501 8.2.30.4: CP service carries CIoT, SMS or LCS,
                    // rather than a PDU session establishment request.
                    assert_eq!(m.payload_container_type.unwrap().value, 8);
                    assert_eq!(
                        payload.decode_as_ciot_user_data_container(),
                        hex::decode("4500001400000000400100000a0000010a000002").unwrap()
                    );
                }
                m.nas_message_container.map(|c| (c.value, 0x4f))
            }
            f::GmmMessage::UlNasTransport(m) => {
                assert_eq!(m.payload_container_type.value, 1);
                Some((m.payload_container.value, 0xc1))
            }
            f::GmmMessage::DlNasTransport(m) => {
                assert_eq!(m.payload_container_type.value, 1);
                Some((m.payload_container.value, 0xc2))
            }
            _ => None,
        };
        if let Some((wire, kind)) = container {
            fivegs_inner(&wire, kind);
            f_nested += 1;
        }
    }
    assert_eq!(f_nested, 9);
    let mut e_nested = 0;
    for (_, wire) in rows(include_str!("fixtures/nas-eps.tsv")) {
        let e::Message::Emm(_, body) = e::Message::decode(&wire).unwrap() else {
            continue;
        };
        let container = match body {
            e::EmmMessage::AttachRequest(m) => Some((m.esm_message_container.value, 0xd0)),
            e::EmmMessage::AttachAccept(m) => Some((m.esm_message_container.value, 0xc1)),
            e::EmmMessage::AttachComplete(m) => Some((m.esm_message_container.value, 0xc2)),
            e::EmmMessage::AttachReject(m) => {
                if m.esm_message_container.is_some() {
                    assert_eq!(m.emm_cause.value, 19);
                }
                m.esm_message_container.map(|c| (c.value, 0xd1))
            }
            e::EmmMessage::ControlPlaneServiceRequest(m) => {
                m.esm_message_container.map(|c| (c.value, 0xeb))
            }
            e::EmmMessage::UplinkNasTransport(m) => {
                assert_eq!(m.nas_message_container.value, [9, 4]); // TS 24.011 CP-ACK
                None
            }
            e::EmmMessage::DownlinkNasTransport(m) => {
                assert_eq!(m.nas_message_container.value, [9, 4]);
                None
            }
            e::EmmMessage::UplinkGenericNasTransport(m) => {
                assert_eq!(m.generic_message_container_type.value, 1); // TS 37.355 LPP
                assert_eq!(m.generic_message_container.value, [0]);
                None
            }
            e::EmmMessage::DownlinkGenericNasTransport(m) => {
                assert_eq!(m.generic_message_container_type.value, 1);
                assert_eq!(m.generic_message_container.value, [0]);
                None
            }
            _ => None,
        };
        if let Some((wire, kind)) = container {
            eps_inner(&wire, kind);
            e_nested += 1;
        }
    }
    assert_eq!(e_nested, 7);
}

/// The name and the text of each line of a fixture of what the messages print.
fn shown(lines: &str) -> impl Iterator<Item = (&str, &str)> {
    lines
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split_once('\t').unwrap())
}

/// Each message of the fixtures prints as its line of nas-5gs-display.tsv or
/// nas-eps-display.tsv: its name, then each of its IEs with its value.
#[test]
fn every_message_of_the_fixtures_prints_its_ies() {
    let messages = rows(include_str!("fixtures/nas-5gs.tsv"));
    let mut lines = shown(include_str!("fixtures/nas-5gs-display.tsv"));
    for (name, wire) in messages {
        let message = f::Message::decode(&wire).unwrap();
        assert_eq!(lines.next(), Some((name, message.to_string().as_str())));
    }
    assert_eq!(lines.next(), None);
    let messages = rows(include_str!("fixtures/nas-eps.tsv"));
    let mut lines = shown(include_str!("fixtures/nas-eps-display.tsv"));
    for (name, wire) in messages {
        let direction = if name.starts_with("DetachRequestUeTerminated") {
            oxirush_nas::Direction::Downlink
        } else {
            oxirush_nas::Direction::Uplink
        };
        let message = e::Message::decode_with(
            &wire,
            oxirush_nas::DecodeOptions::STRICT.with_direction(direction),
        )
        .unwrap();
        assert_eq!(lines.next(), Some((name, message.to_string().as_str())));
    }
    assert_eq!(lines.next(), None);
}
