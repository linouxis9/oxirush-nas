//! Canonical NAS messages cover every supported message type and nested payload.
//! These independently checked wire vectors need no external test tools.
use std::collections::HashSet;

use oxirush_nas::common::{Severity, Validate};
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
        let pdu = f::Nas5gsMessage::from_bytes(&wire).unwrap_or_else(|e| panic!("{name}: {e}"));
        let errors: Vec<_> = pdu
            .validate()
            .into_iter()
            .filter(|finding| matches!(finding.severity, Severity::Error))
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        assert_eq!(pdu.to_bytes().unwrap(), wire, "{name}");
        match pdu {
            f::Nas5gsMessage::Gmm(header, _) => {
                gmm.insert(header.message_type.as_u8());
            }
            f::Nas5gsMessage::Gsm(header, _) => {
                gsm.insert(header.message_type.as_u8());
            }
            _ => panic!("plain fixture expected: {name}"),
        }
    }
    for byte in 0..=255 {
        if !matches!(
            f::Nas5gmmMessageType::try_from(byte).unwrap(),
            f::Nas5gmmMessageType::Unknown(_)
        ) {
            assert!(gmm.contains(&byte), "missing 5GMM type {byte:02x}");
        }
        if !matches!(
            f::Nas5gsmMessageType::try_from(byte).unwrap(),
            f::Nas5gsmMessageType::Unknown(_)
        ) {
            assert!(gsm.contains(&byte), "missing 5GSM type {byte:02x}");
        }
    }
}

#[test]
fn every_supported_eps_message_has_a_canonical_exact_byte_fixture() {
    let mut emm = HashSet::new();
    let mut esm = HashSet::new();
    for (name, wire) in rows(include_str!("fixtures/nas-eps.tsv")) {
        let direction = if name.starts_with("DetachRequestToUe") {
            e::Direction::Downlink
        } else {
            e::Direction::Uplink
        };
        let pdu = e::NasEpsMessage::from_bytes_with_direction(&wire, direction)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let errors: Vec<_> = pdu
            .validate()
            .into_iter()
            .filter(|finding| matches!(finding.severity, Severity::Error))
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        assert_eq!(pdu.to_bytes().unwrap(), wire, "{name}");
        match pdu {
            e::NasEpsMessage::Emm(header, _) => {
                emm.insert(header.message_type.as_u8());
            }
            e::NasEpsMessage::Esm(header, _) => {
                esm.insert(header.message_type.as_u8());
            }
            _ => panic!("plain fixture expected: {name}"),
        }
    }
    for byte in 0..=255 {
        if !matches!(
            e::NasEmmMessageType::try_from(byte).unwrap(),
            e::NasEmmMessageType::Unknown(_)
        ) {
            assert!(emm.contains(&byte), "missing EMM type {byte:02x}");
        }
        if !matches!(
            e::NasEsmMessageType::try_from(byte).unwrap(),
            e::NasEsmMessageType::Unknown(_)
        ) {
            assert!(esm.contains(&byte), "missing ESM type {byte:02x}");
        }
    }
}

#[test]
fn receiver_tolerated_header_spares_are_explicitly_noncanonical() {
    // 24.007 11.4.2: receivers ignore spare bits. They are not retained by
    // these typed headers, so equality is promised only for canonical input.
    let noncanonical = [0x7e, 0xf0, 0x43];
    assert_eq!(
        f::Nas5gsMessage::from_bytes(&noncanonical)
            .unwrap()
            .to_bytes()
            .unwrap(),
        [0x7e, 0, 0x43]
    );
    // EPS deliberately retains received short SERVICE REQUEST header values
    // 12..=15, despite interpreting each as the same security-header class.
    for header in 0xc7..=0xf7 {
        if header & 0x0f == 7 {
            let wire = [header, 0, 0, 0];
            assert_eq!(
                e::NasEpsMessage::from_bytes(&wire)
                    .unwrap()
                    .to_bytes()
                    .unwrap(),
                wire
            );
        }
    }
}

#[test]
fn nas_containers_recursively_decode_to_the_permitted_message_families() {
    fn fivegs_inner(wire: &[u8], message_type: u8) {
        let inner = f::Nas5gsMessage::from_bytes(wire).unwrap();
        assert_eq!(inner.to_bytes().unwrap(), wire);
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
            f::Nas5gsMessage::Gmm(header, _) => {
                assert_eq!(header.message_type.as_u8(), message_type)
            }
            f::Nas5gsMessage::Gsm(header, _) => {
                assert_eq!(header.message_type.as_u8(), message_type)
            }
            _ => panic!("expected plain inner NAS"),
        }
    }
    fn eps_inner(wire: &[u8], message_type: u8) {
        let inner = e::NasEpsMessage::from_bytes(wire).unwrap();
        assert_eq!(inner.to_bytes().unwrap(), wire);
        assert!(
            inner
                .validate()
                .iter()
                .all(|i| i.severity != Severity::Error),
            "nested {}: {:?}",
            hex::encode(wire),
            inner.validate()
        );
        let e::NasEpsMessage::Esm(header, _) = inner else {
            panic!("expected ESM container")
        };
        assert_eq!(header.message_type.as_u8(), message_type);
    }
    let mut f_nested = 0;
    for (_, wire) in rows(include_str!("fixtures/nas-5gs.tsv")) {
        let f::Nas5gsMessage::Gmm(_, body) = f::Nas5gsMessage::from_bytes(&wire).unwrap() else {
            continue;
        };
        let container = match body {
            f::Nas5gmmMessage::RegistrationRequest(m) => {
                m.nas_message_container.map(|c| (c.value, 0x41))
            }
            f::Nas5gmmMessage::DeregistrationRequestFromUe(m) => {
                m.nas_message_container.map(|c| (c.value, 0x45))
            }
            f::Nas5gmmMessage::ServiceRequest(m) => {
                m.nas_message_container.map(|c| (c.value, 0x4c))
            }
            f::Nas5gmmMessage::SecurityModeComplete(m) => {
                m.nas_message_container.map(|c| (c.value, 0x41))
            }
            f::Nas5gmmMessage::ControlPlaneServiceRequest(m) => {
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
            f::Nas5gmmMessage::UlNasTransport(m) => {
                assert_eq!(m.payload_container_type.value, 1);
                Some((m.payload_container.value, 0xc1))
            }
            f::Nas5gmmMessage::DlNasTransport(m) => {
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
        let e::NasEpsMessage::Emm(_, body) = e::NasEpsMessage::from_bytes(&wire).unwrap() else {
            continue;
        };
        let container = match body {
            e::NasEmmMessage::AttachRequest(m) => Some((m.esm_message_container.value, 0xd0)),
            e::NasEmmMessage::AttachAccept(m) => Some((m.esm_message_container.value, 0xc1)),
            e::NasEmmMessage::AttachComplete(m) => Some((m.esm_message_container.value, 0xc2)),
            e::NasEmmMessage::AttachReject(m) => {
                if m.esm_message_container.is_some() {
                    assert_eq!(m.emm_cause.value, 19);
                }
                m.esm_message_container.map(|c| (c.value, 0xd1))
            }
            e::NasEmmMessage::ControlPlaneServiceRequest(m) => {
                m.esm_message_container.map(|c| (c.value, 0xeb))
            }
            e::NasEmmMessage::UplinkNasTransport(m) => {
                assert_eq!(m.nas_message_container.value, [9, 4]); // TS 24.011 CP-ACK
                None
            }
            e::NasEmmMessage::DownlinkNasTransport(m) => {
                assert_eq!(m.nas_message_container.value, [9, 4]);
                None
            }
            e::NasEmmMessage::UplinkGenericNasTransport(m) => {
                assert_eq!(m.generic_message_container_type.value, 1); // TS 37.355 LPP
                assert_eq!(m.generic_message_container.value, [0]);
                None
            }
            e::NasEmmMessage::DownlinkGenericNasTransport(m) => {
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
