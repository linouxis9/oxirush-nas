#![cfg(feature = "security")]
//! Security roundtrips cover COUNT boundaries, all algorithms and EPS/5GS interworking.
use oxirush_nas::{nas_5gs as f, nas_eps as e};

const MASTER: [u8; 32] = [0x11; 32];
fn rows(messages: &str) -> impl Iterator<Item = (&str, Vec<u8>)> {
    messages
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let mut fields = line.split('\t');
            (
                fields.next().unwrap(),
                hex::decode(fields.next().unwrap()).unwrap(),
            )
        })
}
fn fixture(messages: &str, name: &str) -> Vec<u8> {
    rows(messages).find(|(n, _)| *n == name).unwrap().1
}
fn fctx(
    nia: f::IntegrityAlgorithm,
    nea: f::CipheringAlgorithm,
    count: u32,
) -> f::NasSecurityContext {
    f::NasSecurityContext::restore_from_kamf(&MASTER, nia, nea, (count, count), (count, count))
        .unwrap()
}
fn ectx(
    nia: e::IntegrityAlgorithm,
    nea: e::CipheringAlgorithm,
    count: u32,
) -> e::NasSecurityContext {
    e::NasSecurityContext::restore_from_kasme(&MASTER, nia, nea, count, count).unwrap()
}

#[test]
fn complete_5gs_crypto_matrix_and_nested_eps_attach() {
    let original_eps = fixture(include_str!("fixtures/nas-eps.tsv"), "AttachRequest");
    let mut eps_attach = e::NasEpsMessage::from_bytes(&original_eps).unwrap();
    let e::NasEpsMessage::Emm(_, e::NasEmmMessage::AttachRequest(attach)) = &mut eps_attach else {
        panic!()
    };
    attach.eps_mobile_identity =
        e::NasEpsMobileIdentity::new(hex::decode("f602f83900010211223344").unwrap());
    let plain_eps = eps_attach.to_bytes().unwrap();

    for nia in [
        f::IntegrityAlgorithm::NIA1,
        f::IntegrityAlgorithm::NIA2,
        f::IntegrityAlgorithm::NIA3,
    ] {
        for nea in [
            f::CipheringAlgorithm::NEA0,
            f::CipheringAlgorithm::NEA1,
            f::CipheringAlgorithm::NEA2,
            f::CipheringAlgorithm::NEA3,
        ] {
            for count in [0, 255, 256, 65535, 0x00ff_ffff] {
                for access in [
                    f::security::NasCountAccessType::ThreeGpp,
                    f::security::NasCountAccessType::Non3Gpp,
                ] {
                    for direction in [f::Direction::Uplink, f::Direction::Downlink] {
                        let status = f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::FGmmStatus(
                            f::NasFGmmStatus::new(f::NasFGmmCause::new(3)),
                        ));
                        let command = f::Nas5gsMessage::new_5gmm(
                            f::Nas5gmmMessage::SecurityModeCommand(f::NasSecurityModeCommand::new(
                                f::NasSecurityAlgorithms::from_algorithms(nea, nia),
                                f::NasKeySetIdentifier::new(1),
                                f::NasUeSecurityCapability::new(vec![0xf0, 0x70]),
                            )),
                        );
                        let complete =
                            f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::SecurityModeComplete(
                                f::NasSecurityModeComplete::new(),
                            ));
                        let new = if direction == f::Direction::Downlink {
                            (
                                &command,
                                f::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
                            )
                        } else {
                            (&complete,f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext)
                        };
                        for (message, sht) in [
                            (&status, f::Nas5gsSecurityHeaderType::IntegrityProtected),
                            (
                                &status,
                                f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
                            ),
                            new,
                        ] {
                            let mut tx = fctx(nia, nea, count);
                            let mut rx = fctx(nia, nea, count);
                            let wire = tx
                                .protect_for_access(message, sht, direction, access)
                                .unwrap();
                            assert_eq!(
                                f::Nas5gsMessage::from_bytes(&wire)
                                    .unwrap()
                                    .to_bytes()
                                    .unwrap(),
                                wire
                            );
                            let (decoded, _) =
                                rx.unprotect_for_access(&wire, direction, access).unwrap();
                            assert_eq!(decoded.to_bytes().unwrap(), message.to_bytes().unwrap());
                            assert_eq!(
                                fctx(nia, nea, count)
                                    .protect_for_access(&decoded, sht, direction, access)
                                    .unwrap(),
                                wire
                            );
                            assert_eq!(rx.nas_count(direction, access), count + 1);
                            assert!(rx.unprotect_for_access(&wire, direction, access).is_err());
                            let mut tampered = wire.clone();
                            tampered[2] ^= 1;
                            let mut bad = fctx(nia, nea, count);
                            assert!(
                                bad.unprotect_for_access(&tampered, direction, access)
                                    .is_err()
                            );
                            assert_eq!(bad.nas_count(direction, access), count);
                            if count == 0x00ff_ffff {
                                assert!(
                                    tx.protect_for_access(message, sht, direction, access)
                                        .is_err()
                                );
                            }
                        }
                    }
                }
            }
            // The reverse (N1-to-S1) helper uses the 5G context, per
            // 33.501 8.5.2. Check it separately from the S1-to-N1 container.
            let mapped_wire = fctx(nia, nea, 100).protect_eps_message(&plain_eps).unwrap();
            assert_eq!(
                fctx(nia, nea, 100)
                    .unprotect_eps_message(&mapped_wire)
                    .unwrap(),
                plain_eps
            );
            // 24.501 8.2.6.16: initial registration after S1 mode carries
            // an ATTACH REQUEST protected by the existing EPS context.
            let eia = match nia {
                f::IntegrityAlgorithm::NIA1 => e::IntegrityAlgorithm::EIA1,
                f::IntegrityAlgorithm::NIA2 => e::IntegrityAlgorithm::EIA2,
                f::IntegrityAlgorithm::NIA3 => e::IntegrityAlgorithm::EIA3,
                _ => unreachable!(),
            };
            let eps_wire = ectx(eia, e::CipheringAlgorithm::EEA0, 100)
                .protect(
                    &eps_attach,
                    e::NasEpsSecurityHeaderType::IntegrityProtected,
                    e::Direction::Uplink,
                )
                .unwrap();
            let request = f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::RegistrationRequest(
                f::NasRegistrationRequest::new(
                    f::NasFGsRegistrationType::new(0x11),
                    f::NasFGsMobileIdentity::new(hex::decode("f202f83900010211223344").unwrap()),
                )
                .set_fgmm_capability(f::NasFGmmCapability::new(vec![1]))
                .set_ue_security_capability(f::NasUeSecurityCapability::new(vec![0xf0, 0x70]))
                .set_ue_status(f::NasUeStatus::new(vec![0]))
                .set_additional_guti(f::NasFGsMobileIdentity::new(
                    hex::decode("f202f83901004211223344").unwrap(),
                ))
                .set_eps_nas_message_container(f::NasEpsNasMessageContainer::new(eps_wire.clone())),
            ));
            for sht in [
                f::Nas5gsSecurityHeaderType::IntegrityProtected,
                f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
            ] {
                let wire = fctx(nia, nea, 101)
                    .protect(&request, sht, f::Direction::Uplink)
                    .unwrap();
                let (decoded, _) = fctx(nia, nea, 101)
                    .unprotect(&wire, f::Direction::Uplink)
                    .unwrap();
                assert_eq!(decoded.to_bytes().unwrap(), request.to_bytes().unwrap());
                assert_eq!(
                    fctx(nia, nea, 101)
                        .protect(&decoded, sht, f::Direction::Uplink)
                        .unwrap(),
                    wire
                );
                let f::Nas5gsMessage::Gmm(
                    _,
                    f::Nas5gmmMessage::RegistrationRequest(decoded_request),
                ) = decoded
                else {
                    panic!()
                };
                let nested = decoded_request.eps_nas_message_container.unwrap().value;
                assert_eq!(nested, eps_wire);
                let (eps, _) = ectx(eia, e::CipheringAlgorithm::EEA0, 100)
                    .unprotect(&nested, e::Direction::Uplink)
                    .unwrap();
                assert_eq!(eps.to_bytes().unwrap(), plain_eps);
                assert_eq!(
                    ectx(eia, e::CipheringAlgorithm::EEA0, 100)
                        .protect(
                            &eps,
                            e::NasEpsSecurityHeaderType::IntegrityProtected,
                            e::Direction::Uplink
                        )
                        .unwrap(),
                    nested
                );
                let e::NasEpsMessage::Emm(_, e::NasEmmMessage::AttachRequest(attach)) = eps else {
                    panic!()
                };
                let esm =
                    e::NasEpsMessage::from_bytes(&attach.esm_message_container.value).unwrap();
                assert!(matches!(
                    esm,
                    e::NasEpsMessage::Esm(_, e::NasEsmMessage::PdnConnectivityRequest(_))
                ));
                assert_eq!(esm.to_bytes().unwrap(), attach.esm_message_container.value);
            }
        }
    }
}

#[test]
fn eps_to_5gs_idle_interworking_uses_a_standardized_mapped_key() {
    let tau = fixture(
        include_str!("fixtures/nas-eps.tsv"),
        "TrackingAreaUpdateRequest",
    );
    let eps_tau = e::NasEpsMessage::from_bytes(&tau).unwrap();
    let eps_wire = ectx(
        e::IntegrityAlgorithm::EIA2,
        e::CipheringAlgorithm::EEA0,
        100,
    )
    .protect(
        &eps_tau,
        e::NasEpsSecurityHeaderType::IntegrityProtected,
        e::Direction::Uplink,
    )
    .unwrap();
    let request = f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::RegistrationRequest(
        f::NasRegistrationRequest::new(
            f::NasFGsRegistrationType::new(0x72),
            f::NasFGsMobileIdentity::new(hex::decode("f202f83900010211223344").unwrap()),
        )
        .set_fgmm_capability(f::NasFGmmCapability::new(vec![1]))
        .set_ue_security_capability(f::NasUeSecurityCapability::new(vec![0xf0, 0x70]))
        .set_ue_status(f::NasUeStatus::new(vec![2]))
        .set_eps_nas_message_container(f::NasEpsNasMessageContainer::new(eps_wire.clone())),
    ));
    let wire = request.to_bytes().unwrap();
    assert_eq!(
        f::Nas5gsMessage::from_bytes(&wire)
            .unwrap()
            .to_bytes()
            .unwrap(),
        wire
    );
    assert_eq!(
        ectx(
            e::IntegrityAlgorithm::EIA2,
            e::CipheringAlgorithm::EEA0,
            100
        )
        .unprotect(&eps_wire, e::Direction::Uplink)
        .unwrap()
        .0
        .to_bytes()
        .unwrap(),
        tau
    );

    // TS 33.501 Annex A.15.1: FC75 || 32-bit padded COUNT100 || L0=4.
    // The fixed expected key was computed independently with HMAC-SHA256.
    let expected_kamf =
        hex::decode("01196aca1d4eeffd1a2589f7805c22950eb3c59d05a903b24984c712a079f908").unwrap();
    assert_eq!(
        oxirush_security::nas_eps::derive_mapped_kamf_idle(&MASTER, 100).as_slice(),
        expected_kamf
    );
    let context = || {
        f::NasSecurityContext::from_mapped_kamf_idle(
            &MASTER,
            100,
            f::IntegrityAlgorithm::NIA2,
            f::CipheringAlgorithm::NEA2,
        )
        .unwrap()
    };
    let mut ue = context();
    let mut amf = context();
    let messages = [
        (
            f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::SecurityModeCommand(
                f::NasSecurityModeCommand::new(
                    f::NasSecurityAlgorithms::from_algorithms(
                        f::CipheringAlgorithm::NEA2,
                        f::IntegrityAlgorithm::NIA2,
                    ),
                    f::NasKeySetIdentifier::new(9),
                    f::NasUeSecurityCapability::new(vec![0xf0, 0x70]),
                ),
            )),
            f::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
            f::Direction::Downlink,
        ),
        (
            f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::SecurityModeComplete(
                f::NasSecurityModeComplete::new(),
            )),
            f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext,
            f::Direction::Uplink,
        ),
        (
            f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::RegistrationAccept(
                f::NasRegistrationAccept::new(f::NasFGsRegistrationResult::new(vec![1])),
            )),
            f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
            f::Direction::Downlink,
        ),
    ];
    for (i, (message, sht, direction)) in messages.into_iter().enumerate() {
        let (tx, rx) = if direction == f::Direction::Uplink {
            (&mut ue, &mut amf)
        } else {
            (&mut amf, &mut ue)
        };
        let wire = tx.protect(&message, sht, direction).unwrap();
        let (decoded, _) = rx.unprotect(&wire, direction).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), message.to_bytes().unwrap());
        let mut replay = context();
        if i == 2 {
            replay = f::NasSecurityContext::restore_from_kamf(
                expected_kamf.as_slice().try_into().unwrap(),
                f::IntegrityAlgorithm::NIA2,
                f::CipheringAlgorithm::NEA2,
                (1, 1),
                (0, 0),
            )
            .unwrap();
        }
        assert_eq!(replay.protect(&decoded, sht, direction).unwrap(), wire);
    }
}

#[test]
fn complete_eps_crypto_matrix_with_short_and_partial_messages() {
    let cp = e::NasEpsMessage::from_bytes(&fixture(
        include_str!("fixtures/nas-eps.tsv"),
        "ControlPlaneServiceRequest-optional",
    ))
    .unwrap();
    for nia in [
        e::IntegrityAlgorithm::EIA1,
        e::IntegrityAlgorithm::EIA2,
        e::IntegrityAlgorithm::EIA3,
    ] {
        for nea in [
            e::CipheringAlgorithm::EEA0,
            e::CipheringAlgorithm::EEA1,
            e::CipheringAlgorithm::EEA2,
            e::CipheringAlgorithm::EEA3,
        ] {
            for count in [0, 255, 256, 65535, 0x00ff_ffff] {
                for direction in [e::Direction::Uplink, e::Direction::Downlink] {
                    let status = e::NasEpsMessage::new_emm(e::NasEmmMessage::EmmStatus(
                        e::NasEmmStatus::new(e::NasEmmCause::new(3)),
                    ));
                    let command = e::NasEpsMessage::new_emm(e::NasEmmMessage::SecurityModeCommand(
                        e::NasSecurityModeCommand::new(
                            e::NasSelectedNasSecurityAlgorithms::new(
                                ((nea as u8) << 4) | nia as u8,
                            ),
                            e::NasKeySetIdentifier::new(1),
                            e::NasSpareHalfOctet::new(0),
                            e::NasReplayedUeSecurityCapabilities::new(vec![0xf0, 0x70]),
                        ),
                    ));
                    let complete = e::NasEpsMessage::new_emm(
                        e::NasEmmMessage::SecurityModeComplete(e::NasSecurityModeComplete::new()),
                    );
                    let new = if direction == e::Direction::Downlink {
                        (
                            &command,
                            e::NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext,
                        )
                    } else {
                        (&complete,e::NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext)
                    };
                    let mut cases = vec![
                        (&status, e::NasEpsSecurityHeaderType::IntegrityProtected),
                        (
                            &status,
                            e::NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
                        ),
                        new,
                    ];
                    if direction == e::Direction::Uplink {
                        cases.push((
                            &cp,
                            e::NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered,
                        ));
                    }
                    for (message, sht) in cases {
                        let mut tx = ectx(nia, nea, count);
                        let mut rx = ectx(nia, nea, count);
                        let wire = tx.protect(message, sht, direction).unwrap();
                        assert_eq!(
                            e::NasEpsMessage::from_bytes_with_direction(&wire, direction)
                                .unwrap()
                                .to_bytes()
                                .unwrap(),
                            wire
                        );
                        let (decoded, _) = rx.unprotect(&wire, direction).unwrap();
                        assert_eq!(decoded.to_bytes().unwrap(), message.to_bytes().unwrap());
                        assert_eq!(
                            ectx(nia, nea, count)
                                .protect(&decoded, sht, direction)
                                .unwrap(),
                            wire
                        );
                        assert!(rx.unprotect(&wire, direction).is_err());
                        let mut bad = ectx(nia, nea, count);
                        let mut tampered = wire.clone();
                        tampered[1] ^= 1;
                        assert!(bad.unprotect(&tampered, direction).is_err());
                        assert_eq!((bad.uplink_count(), bad.downlink_count()), (count, count));
                        if count == 0x00ff_ffff {
                            assert!(tx.protect(message, sht, direction).is_err());
                        }
                    }
                }
                let mut tx = ectx(nia, nea, count);
                let short = tx.protect_service_request(1).unwrap();
                let wire = e::NasEpsMessage::ServiceRequest(short.clone())
                    .to_bytes()
                    .unwrap();
                assert_eq!(
                    e::NasEpsMessage::from_bytes(&wire)
                        .unwrap()
                        .to_bytes()
                        .unwrap(),
                    wire
                );
                assert_eq!(
                    e::NasEpsMessage::ServiceRequest(
                        ectx(nia, nea, count).protect_service_request(1).unwrap()
                    )
                    .to_bytes()
                    .unwrap(),
                    wire
                );
                let mut rx = ectx(nia, nea, count);
                rx.unprotect_service_request(&short).unwrap();
                assert!(rx.unprotect_service_request(&short).is_err());
            }
        }
    }
}

#[test]
fn every_message_type_also_roundtrips_under_integrity_and_ciphering() {
    // Chapter 8 message direction, independent of the security codec's
    // validation. Bidirectional status/dummy/data cases use uplink here.
    const F_UP: &[&str] = &[
        "RegistrationRequest",
        "RegistrationComplete",
        "DeregistrationRequestFromUe",
        "DeregistrationAcceptToUe",
        "ConfigurationUpdateComplete",
        "ServiceRequest",
        "AuthenticationResponse",
        "AuthenticationFailure",
        "IdentityResponse",
        "SecurityModeComplete",
        "SecurityModeReject",
        "FGmmStatus",
        "NotificationResponse",
        "UlNasTransport",
        "ControlPlaneServiceRequest",
        "NetworkSliceSpecificAuthenticationComplete",
        "RelayKeyRequest",
        "RelayAuthenticationResponse",
        "PduSessionEstablishmentRequest",
        "PduSessionAuthenticationComplete",
        "PduSessionModificationRequest",
        "PduSessionModificationComplete",
        "PduSessionModificationCommandReject",
        "PduSessionReleaseRequest",
        "PduSessionReleaseComplete",
        "FGsmStatus",
        "ServiceLevelAuthenticationComplete",
        "RemoteUeReport",
    ];
    const E_UP: &[&str] = &[
        "AttachComplete",
        "AttachRequest",
        "AuthenticationFailure",
        "AuthenticationResponse",
        "DetachRequestFromUe",
        "DetachAccept",
        "ExtendedServiceRequest",
        "GutiReallocationComplete",
        "IdentityResponse",
        "SecurityModeComplete",
        "SecurityModeReject",
        "EmmStatus",
        "TrackingAreaUpdateComplete",
        "TrackingAreaUpdateRequest",
        "UplinkNasTransport",
        "UplinkGenericNasTransport",
        "ControlPlaneServiceRequest",
        "ActivateDedicatedEpsBearerContextAccept",
        "ActivateDedicatedEpsBearerContextReject",
        "ActivateDefaultEpsBearerContextAccept",
        "ActivateDefaultEpsBearerContextReject",
        "BearerResourceAllocationRequest",
        "BearerResourceModificationRequest",
        "DeactivateEpsBearerContextAccept",
        "EsmInformationResponse",
        "ModifyEpsBearerContextAccept",
        "ModifyEpsBearerContextReject",
        "PdnConnectivityRequest",
        "PdnDisconnectRequest",
        "RemoteUeReport",
        "EsmDummyMessage",
        "EsmStatus",
        "EsmDataTransport",
    ];
    for (name, inner) in rows(include_str!("fixtures/nas-5gs.tsv")) {
        let kind = name.split('-').next().unwrap();
        let direction = if F_UP.contains(&kind) {
            f::Direction::Uplink
        } else {
            f::Direction::Downlink
        };
        let body = f::Nas5gsMessage::from_bytes(&inner).unwrap();
        // 5GSM security is supplied by its enclosing UL/DL NAS TRANSPORT.
        let nested_sm = matches!(body, f::Nas5gsMessage::Gsm(..));
        let pdu = if nested_sm {
            let payload = f::NasPayloadContainer::new(inner.clone());
            if direction == f::Direction::Uplink {
                f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::UlNasTransport(
                    f::NasUlNasTransport::new(f::NasPayloadContainerType::new(1), payload)
                        .set_pdu_session_id(f::NasPduSessionIdentity2::new(1)),
                ))
            } else {
                f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::DlNasTransport(
                    f::NasDlNasTransport::new(f::NasPayloadContainerType::new(1), payload)
                        .set_pdu_session_id(f::NasPduSessionIdentity2::new(1)),
                ))
            }
        } else {
            body
        };
        let sht = match kind {
            "SecurityModeCommand" => f::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
            "SecurityModeComplete" => {
                f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
            }
            "ServiceRequest" => f::Nas5gsSecurityHeaderType::IntegrityProtected,
            _ => f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
        };
        let wire = fctx(f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2, 17)
            .protect(&pdu, sht, direction)
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        let (decoded, _) = fctx(f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2, 17)
            .unprotect(&wire, direction)
            .unwrap();
        assert_eq!(
            decoded.to_bytes().unwrap(),
            pdu.to_bytes().unwrap(),
            "{name}"
        );
        if nested_sm {
            let payload = match &decoded {
                f::Nas5gsMessage::Gmm(_, f::Nas5gmmMessage::UlNasTransport(message)) => {
                    &message.payload_container.value
                }
                f::Nas5gsMessage::Gmm(_, f::Nas5gmmMessage::DlNasTransport(message)) => {
                    &message.payload_container.value
                }
                _ => panic!("expected SM transport: {name}"),
            };
            assert_eq!(*payload, inner, "{name}");
            assert_eq!(
                f::Nas5gsMessage::from_bytes(payload)
                    .unwrap()
                    .to_bytes()
                    .unwrap(),
                inner,
                "{name}"
            );
        }
        assert_eq!(
            fctx(f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2, 17)
                .protect(&decoded, sht, direction)
                .unwrap(),
            wire,
            "{name}"
        );
    }
    for (name, inner) in rows(include_str!("fixtures/nas-eps.tsv")) {
        let kind = name.split('-').next().unwrap();
        let direction = if E_UP.contains(&kind) {
            e::Direction::Uplink
        } else {
            e::Direction::Downlink
        };
        let pdu = e::NasEpsMessage::from_bytes_with_direction(&inner, direction).unwrap();
        let sht = match kind {
            "SecurityModeCommand" => e::NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext,
            "SecurityModeComplete" => {
                e::NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext
            }
            "AttachRequest" | "TrackingAreaUpdateRequest" => {
                e::NasEpsSecurityHeaderType::IntegrityProtected
            }
            "ControlPlaneServiceRequest" if name.ends_with("optional") => {
                e::NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered
            }
            "ControlPlaneServiceRequest" => e::NasEpsSecurityHeaderType::IntegrityProtected,
            _ => e::NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
        };
        let wire = ectx(e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2, 17)
            .protect(&pdu, sht, direction)
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        let (decoded, _) = ectx(e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2, 17)
            .unprotect(&wire, direction)
            .unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), inner, "{name}");
        assert_eq!(
            ectx(e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2, 17)
                .protect(&decoded, sht, direction)
                .unwrap(),
            wire,
            "{name}"
        );
    }
}

#[test]
fn inter_system_transparent_containers_roundtrip_at_ie_boundary() {
    use bytes::{Bytes, BytesMut};
    use f::{Decode, Encode};
    let n1s1 = f::NasN1ModeToS1ModeNasTransparentContainer::from_sequence_number(0x64);
    let s1n1 = f::NasS1ModeToN1ModeNasTransparentContainer::from_fields(
        0x11223344,
        f::NasSecurityAlgorithms::from_algorithms(
            f::CipheringAlgorithm::NEA2,
            f::IntegrityAlgorithm::NIA2,
        ),
        3,
        f::NasKeySetIdentifier::new(1),
    );
    let intra = f::NasIntraN1ModeNasTransparentContainer::from_fields(
        0x55667788,
        f::NasSecurityAlgorithms::from_algorithms(
            f::CipheringAlgorithm::NEA3,
            f::IntegrityAlgorithm::NIA3,
        ),
        true,
        f::NasKeySetIdentifier::new(2),
        0x65,
    );
    macro_rules! check {
        ($ie:expr,$ty:ty) => {{
            let mut wire = BytesMut::new();
            $ie.encode(&mut wire).unwrap();
            let raw = wire.to_vec();
            let decoded = <$ty>::decode(&mut Bytes::from(raw.clone())).unwrap();
            let mut encoded = BytesMut::new();
            decoded.encode(&mut encoded).unwrap();
            assert_eq!(encoded.to_vec(), raw);
            decoded
        }};
    }
    assert_eq!(
        check!(n1s1, f::NasN1ModeToS1ModeNasTransparentContainer).sequence_number(),
        0x64
    );
    assert_eq!(
        check!(s1n1, f::NasS1ModeToN1ModeNasTransparentContainer).message_authentication_code(),
        Some(0x11223344)
    );
    assert_eq!(
        check!(intra, f::NasIntraN1ModeNasTransparentContainer).sequence_number(),
        Some(0x65)
    );
}

#[test]
fn eps_emm_transport_and_emergency_null_contexts() {
    let data = hex::decode("014500001400000000400100000a0000010a000002").unwrap();
    for nia in [
        e::IntegrityAlgorithm::EIA1,
        e::IntegrityAlgorithm::EIA2,
        e::IntegrityAlgorithm::EIA3,
    ] {
        for nea in [
            e::CipheringAlgorithm::EEA0,
            e::CipheringAlgorithm::EEA1,
            e::CipheringAlgorithm::EEA2,
            e::CipheringAlgorithm::EEA3,
        ] {
            for dir in [e::Direction::Uplink, e::Direction::Downlink] {
                for payload in [None, Some(data.as_slice())] {
                    let wire = ectx(nia, nea, 17)
                        .protect_emm_transport(payload, dir)
                        .unwrap();
                    assert_eq!(
                        e::NasEpsMessage::from_bytes(&wire)
                            .unwrap()
                            .to_bytes()
                            .unwrap(),
                        wire
                    );
                    let (decoded, sht) = ectx(nia, nea, 17).unprotect(&wire, dir).unwrap();
                    assert_eq!(sht, e::NasEpsSecurityHeaderType::EmmTransport);
                    let e::NasEpsMessage::EmmTransport(body) = decoded else {
                        panic!()
                    };
                    assert_eq!(body.data_container.as_deref(), payload);
                    assert_eq!(
                        ectx(nia, nea, 17)
                            .protect_emm_transport(body.data_container.as_deref(), dir)
                            .unwrap(),
                        wire
                    );
                }
            }
        }
    }

    // Null integrity is permitted with null ciphering in the unauthenticated
    // emergency context; it deliberately cannot provide tamper/replay checks.
    let fm = f::Nas5gsMessage::new_5gmm(f::Nas5gmmMessage::FGmmStatus(f::NasFGmmStatus::new(
        f::NasFGmmCause::new(3),
    )));
    let fw = fctx(f::IntegrityAlgorithm::NIA0, f::CipheringAlgorithm::NEA0, 0)
        .protect(
            &fm,
            f::Nas5gsSecurityHeaderType::IntegrityProtected,
            f::Direction::Uplink,
        )
        .unwrap();
    let (fd, _) = fctx(f::IntegrityAlgorithm::NIA0, f::CipheringAlgorithm::NEA0, 0)
        .unprotect(&fw, f::Direction::Uplink)
        .unwrap();
    assert_eq!(fd.to_bytes().unwrap(), fm.to_bytes().unwrap());
    let em = e::NasEpsMessage::new_emm(e::NasEmmMessage::EmmStatus(e::NasEmmStatus::new(
        e::NasEmmCause::new(3),
    )));
    let ew = ectx(e::IntegrityAlgorithm::EIA0, e::CipheringAlgorithm::EEA0, 0)
        .protect(
            &em,
            e::NasEpsSecurityHeaderType::IntegrityProtected,
            e::Direction::Uplink,
        )
        .unwrap();
    let (ed, _) = ectx(e::IntegrityAlgorithm::EIA0, e::CipheringAlgorithm::EEA0, 0)
        .unprotect(&ew, e::Direction::Uplink)
        .unwrap();
    assert_eq!(ed.to_bytes().unwrap(), em.to_bytes().unwrap());
}

/// HMAC-derived NAS keys, AES-CTR plaintext and AES-CMAC were checked independently.
#[test]
fn aes_protected_messages_match_fixed_wire_vectors() {
    let message =
        f::Nas5gsMessage::from_bytes(&fixture(include_str!("fixtures/nas-5gs.tsv"), "FGmmStatus"))
            .unwrap();
    let wire = fctx(f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2, 17)
        .protect(
            &message,
            f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
            f::Direction::Uplink,
        )
        .unwrap();
    assert_eq!(hex::encode(wire), "7e02da1302d81195575472");
    for (name, sht, expected) in [
        (
            "EmmStatus",
            e::NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
            "273d096dfa1179083c",
        ),
        (
            "ControlPlaneServiceRequest-optional",
            e::NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered,
            "5796cc8ee911074d107800192c68d48337e736f7600137b1406aedc39ec3434890e24395a557022000d0",
        ),
    ] {
        let message =
            e::NasEpsMessage::from_bytes(&fixture(include_str!("fixtures/nas-eps.tsv"), name))
                .unwrap();
        let wire = ectx(e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2, 17)
            .protect(&message, sht, e::Direction::Uplink)
            .unwrap();
        assert_eq!(hex::encode(wire), expected, "{name}");
    }
}
