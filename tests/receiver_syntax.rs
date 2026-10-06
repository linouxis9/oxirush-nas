use oxirush_nas::common::NasError;
use oxirush_nas::nas_5gs::{
    Nas5gmmMessage, Nas5gsMessage, NasFGmmCapability, NasNon3GppDeviceInformation,
    Non3GppDeviceConnectionInformation, Non3GppDeviceInformationEntry, PduSessionTypeValue,
    decode_nas_5gs_message,
};
use oxirush_nas::nas_eps::decode_nas_eps_message;

#[test]
fn type_six_container_ignores_malformed_inner_optional_ie() {
    use oxirush_nas::nas_5gs::{NasType6IeContainer, Type6IeContainerEntry};
    // TS 24.501 7.7.3.1: malformed inner optional IEs are absent. The
    // location validity IE requires at least 14 value octets (9.11.3.100).
    let container = NasType6IeContainer::new(vec![0x02, 0x00, 0x00]);
    assert!(container.entries().is_empty());
    assert!(!container.is_well_formed());
    for (iei, value) in [
        (0x01, vec![1]),
        (0x02, vec![0; 14]),
        (0x03, vec![1]),
        (0x04, vec![1]),
    ] {
        let mut wire = vec![iei, 0, value.len() as u8];
        wire.extend_from_slice(&value);
        let container = NasType6IeContainer::new(wire);
        assert!(container.entries().is_empty(), "IEI {iei}");
        assert!(!container.is_well_formed());
    }
    let mut wire = vec![0x02, 0, 14];
    wire.extend_from_slice(&[0; 14]);
    wire.extend_from_slice(&[0x03, 0, 0]);
    assert_eq!(NasType6IeContainer::new(wire).entries().len(), 1);
    let location = [0, 12, 1, 1, 0, 1, 1, 2, 3, 4, 0x50, 2, 0xf8, 0x39];
    let mut spare = location.to_vec();
    spare[10] |= 0x0f;
    let mut wire = vec![2, 0, 14];
    wire.extend_from_slice(&spare);
    let received = NasType6IeContainer::new(wire);
    assert_eq!(
        received.entries().len(),
        1,
        "receiver ignores NR CGI spare bits"
    );
    let Type6IeContainerEntry::SNssaiLocationValidityInformation(location_ie) =
        &received.entries()[0]
    else {
        panic!()
    };
    assert_eq!(
        location_ie.entries()[0].nr_cgis[0].nr_cell_id,
        [1, 2, 3, 4, 0x50]
    );
    assert_eq!(location_ie.value, spare, "raw spare bits retained");
    assert!(!received.is_well_formed(), "sender must clear spare bits");
    for (iei, entry, limit) in [
        (1, vec![2, 1, b'a', 1, 1, 7, 0, 2, 0xf8, 0x39, 0, 0, 1], 8),
        (2, location.to_vec(), 16),
        (3, vec![1, 1, 0], 7),
    ] {
        let mut contents = entry.repeat(limit);
        contents.push(0xff);
        let mut wire = vec![iei];
        wire.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        wire.extend_from_slice(&contents);
        let container = NasType6IeContainer::new(wire);
        assert_eq!(
            container.entries().len(),
            usize::from(iei == 1),
            "received limit IEI {iei}"
        );
        assert!(
            !container.is_well_formed(),
            "sender disallows tail IEI {iei}"
        );
    }
    for (declared, actual) in [(300usize, 300usize), (301, 300), (301, 301), (1, 0), (1, 2)] {
        let mut body = vec![1, 1];
        body.extend_from_slice(&(declared as u16).to_be_bytes());
        for _ in 0..actual {
            body.extend_from_slice(&location[6..]);
        }
        let mut contents = (body.len() as u16).to_be_bytes().to_vec();
        contents.extend_from_slice(&body);
        let mut wire = vec![2];
        wire.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        wire.extend_from_slice(&contents);
        wire.extend_from_slice(&[3, 0, 0]);
        let entries = NasType6IeContainer::new(wire).entries();
        assert_eq!(
            entries.len(),
            if declared == 300 && actual == 300 {
                2
            } else {
                1
            },
            "declared={declared}, actual={actual}"
        );
    }
    // A malformed inner IE must not prevent a later, valid IE being read.
    let valid = NasType6IeContainer::new(vec![0x02, 0, 0, 0x03, 0, 0]);
    assert_eq!(
        valid.entries(),
        vec![Type6IeContainerEntry::PartiallyAllowedNssai(
            oxirush_nas::nas_5gs::NasPartialNssai::new(vec![])
        )]
    );
}

#[test]
fn unknown_comprehension_required_ie_is_kept_and_flagged_unless_cut_short() {
    use oxirush_nas::common::{Severity, UnknownIe, Validate, ValidationError};
    // TS 24.501 and TS 24.301 7.5.1: the receiver answers an unknown IE
    // encoded as "comprehension required" (TS 24.007 11.2.5). The decoder
    // keeps a well-framed one, flagged, and `validate()` reports it.
    let flagged = |ies: &[UnknownIe], findings: Vec<ValidationError>| {
        matches!(ies, [ie] if ie.is_comprehension_required())
            && findings.iter().any(|finding| {
                finding.field == "unknown_ies" && finding.severity == Severity::Error
            })
    };
    let cut_short = NasError::InvalidMandatoryIe("unknown_ies");
    for (wire, truncated) in [
        (
            &[0x7e, 0x00, 0x44, 0x16, 0x0f, 0x01, 0xaa][..],
            &[0x7e, 0x00, 0x44, 0x16, 0x0f, 0x02, 0xaa][..],
        ),
        (
            &[0x7e, 0x00, 0x44, 0x16, 0x7f, 0x00, 0x01, 0xaa][..],
            &[0x7e, 0x00, 0x44, 0x16, 0x7f, 0x00][..],
        ),
    ] {
        let message = decode_nas_5gs_message(wire).unwrap();
        assert!(flagged(message.unknown_ies(), message.validate()));
        assert_eq!(message.to_bytes().unwrap(), wire);
        assert_eq!(decode_nas_5gs_message(truncated).unwrap_err(), cut_short);
    }
    for (wire, truncated) in [
        (
            &[0x07, 0x60, 0x02, 0x0f, 0x01, 0xaa][..],
            &[0x07, 0x60, 0x02, 0x0f, 0x02, 0xaa][..],
        ),
        (
            &[0x07, 0x60, 0x02, 0x7e, 0x00, 0x01, 0xaa][..],
            &[0x07, 0x60, 0x02, 0x7e, 0x00][..],
        ),
    ] {
        let message = decode_nas_eps_message(wire).unwrap();
        assert!(flagged(message.unknown_ies(), message.validate()));
        assert_eq!(message.to_bytes().unwrap(), wire);
        assert_eq!(decode_nas_eps_message(truncated).unwrap_err(), cut_short);
    }
    // The flag is read through a security header, and an unknown IE that is
    // not comprehension required is kept without it.
    let protected = [
        0x7e, 0x01, 0, 0, 0, 0, 0, 0x7e, 0x00, 0x44, 0x16, 0x0f, 0x01, 0xaa,
    ];
    let message = decode_nas_5gs_message(&protected).unwrap();
    assert!(flagged(message.unknown_ies(), message.validate()));
    let message = decode_nas_5gs_message(&[0x7e, 0x00, 0x44, 0x16, 0x49, 0x01, 0xaa]).unwrap();
    assert!(!flagged(message.unknown_ies(), message.validate()));
    assert_eq!(message.unknown_ies().len(), 1);
}

#[test]
fn configured_nssai_checks_all_sixteen_receivable_entries() {
    // TS 24.501 9.11.3.37: configured NSSAI has a sixteen-entry receive
    // limit. A truncated ninth S-NSSAI is within that limit, not spare data.
    let mut value = Vec::new();
    for _ in 0..8 {
        value.extend_from_slice(&[0x01, 0x01]);
    }
    value.push(0x04);
    let mut wire = vec![0x7e, 0x00, 0x54, 0x31, value.len() as u8];
    wire.extend_from_slice(&value);
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ConfigurationUpdateCommand(command)) =
        decode_nas_5gs_message(&wire).unwrap()
    else {
        panic!("expected CONFIGURATION UPDATE COMMAND");
    };
    assert!(command.configured_nssai.is_none());
}

#[test]
fn nssai_receive_limit_depends_on_the_message_field() {
    for (iei, limit) in [(0x15, 8), (0x31, 16)] {
        for count in [limit - 1, limit, limit + 1] {
            let mut value: Vec<_> = (1..=count).flat_map(|sst| [0x01, sst]).collect();
            value.push(0x04); // A truncated entry after `count` complete entries.
            let mut wire = vec![0x7e, 0x00, 0x54, iei, value.len() as u8];
            wire.extend_from_slice(&value);
            let Nas5gsMessage::Gmm(_, Nas5gmmMessage::ConfigurationUpdateCommand(command)) =
                decode_nas_5gs_message(&wire).unwrap()
            else {
                panic!("expected CONFIGURATION UPDATE COMMAND");
            };
            let nssai = if iei == 0x15 {
                command.allowed_nssai
            } else {
                command.configured_nssai
            };
            assert_eq!(nssai.is_some(), count >= limit, "IEI {iei:02x}, {count}");
            if let Some(nssai) = nssai {
                let entries = if iei == 0x15 {
                    nssai.parse_allowed()
                } else {
                    nssai.parse_all()
                };
                assert_eq!(entries.len(), usize::from(limit));
            }
        }
    }
    for count in [8, 15, 16, 17] {
        let mut value: Vec<_> = (1..=count).flat_map(|sst| [0x01, sst]).collect();
        value.push(0x04);
        let mut wire = vec![0x7e, 0x00, 0x42, 0x01, 0x01, 0x39, value.len() as u8];
        wire.extend_from_slice(&value);
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(accept)) =
            decode_nas_5gs_message(&wire).unwrap()
        else {
            panic!("expected REGISTRATION ACCEPT");
        };
        assert_eq!(accept.pending_nssai.is_some(), count >= 16, "{count}");
    }
}

#[test]
fn latest_5gmm_capability_accepts_assigned_octet13_bits() {
    for bit in 0..4 {
        let mut value = vec![0; 11];
        value[10] = 1 << bit;
        let capability = NasFGmmCapability::try_from_octets(value).unwrap();
        assert!(capability.validate_strict().is_ok());
    }
}

#[test]
fn latest_non3gpp_device_vlan_id_uses_the_high_twelve_bits() {
    let expected = vec![Non3GppDeviceInformationEntry {
        device_identifier: vec![0xaa],
        connection_information: Some(Non3GppDeviceConnectionInformation::Ethernet {
            mac_address: [1, 2, 3, 4, 5, 6],
            vlan_tag_id: Some(100),
        }),
    }];
    let wire = vec![5, 11, 1, 0xaa, 1, 1, 2, 3, 4, 5, 6, 0x06, 0x40];
    let received = NasNon3GppDeviceInformation::new(wire.clone());
    assert_eq!(received.entries(), expected);
    assert!(received.validate_strict().is_ok());
    let encoded =
        NasNon3GppDeviceInformation::from_entries(PduSessionTypeValue::Ethernet, &expected)
            .unwrap();
    assert_eq!(encoded.value, wire);
    let mut spare = wire;
    *spare.last_mut().unwrap() |= 0x0f;
    let received = NasNon3GppDeviceInformation::new(spare);
    assert_eq!(received.entries(), expected);
    assert!(received.validate_strict().is_err());
    let mut invalid = expected;
    let Some(Non3GppDeviceConnectionInformation::Ethernet { vlan_tag_id, .. }) =
        &mut invalid[0].connection_information
    else {
        unreachable!();
    };
    *vlan_tag_id = Some(4096);
    assert!(
        NasNon3GppDeviceInformation::from_entries(PduSessionTypeValue::Ethernet, &invalid)
            .is_none()
    );
}
