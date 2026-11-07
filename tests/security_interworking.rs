#![cfg(feature = "security")]
//! Security roundtrips cover COUNT boundaries, all algorithms and EPS/5GS interworking.
use oxirush_nas::nas_5gs::NasCount;
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
/// The next NAS COUNT of a context: `None` when the COUNTs are exhausted.
fn next(count: u32) -> Option<NasCount> {
    NasCount::new(count).ok()
}
fn fctx(
    nia: f::IntegrityAlgorithm,
    nea: f::CipheringAlgorithm,
    count: u32,
) -> f::NasSecurityContext {
    let counts = (next(count), next(count));
    f::NasSecurityContext::restore_from_kamf(&f::KAmf::new(&MASTER), nia, nea, counts, counts)
        .unwrap()
}
fn ectx(
    nia: e::IntegrityAlgorithm,
    nea: e::CipheringAlgorithm,
    count: u32,
) -> e::NasSecurityContext {
    let kasme = e::KAsme::new(&MASTER);
    e::NasSecurityContext::restore_from_kasme(&kasme, nia, nea, (next(count), next(count))).unwrap()
}

#[test]
fn complete_5gs_crypto_matrix_and_nested_eps_attach() {
    let original_eps = fixture(include_str!("fixtures/nas-eps.tsv"), "AttachRequest");
    let mut eps_attach = e::NasEpsMessage::decode(&original_eps).unwrap();
    let e::NasEpsMessage::Emm(_, e::NasEmmMessage::AttachRequest(attach)) = &mut eps_attach else {
        panic!()
    };
    attach.eps_mobile_identity =
        e::NasEpsMobileIdentity::new(hex::decode("f602f83900010211223344").unwrap());
    let plain_eps = eps_attach.encode().unwrap();

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
                for access in [f::NasConnection::ThreeGpp, f::NasConnection::Non3Gpp] {
                    for direction in [f::Direction::Uplink, f::Direction::Downlink] {
                        let status = f::Nas5gsMessage::new_5gmm(f::NasFGmmStatus::new(
                            f::NasFGmmCause::new(3),
                        ));
                        let command = f::Nas5gsMessage::new_5gmm(f::NasSecurityModeCommand::new(
                            f::NasSecurityAlgorithms::from_algorithms(nea, nia),
                            f::NasKeySetIdentifier::new(1),
                            f::NasUeSecurityCapability::new(vec![0xf0, 0x70]),
                        ));
                        let complete =
                            f::Nas5gsMessage::new_5gmm(f::NasSecurityModeComplete::new());
                        let new = if direction == f::Direction::Downlink {
                            (
                                &command,
                                f::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                            )
                        } else {
                            (&complete,f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext)
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
                                f::Nas5gsMessage::decode(&wire).unwrap().encode().unwrap(),
                                wire
                            );
                            let decoded = rx
                                .unprotect_for_access(&wire, direction, access)
                                .unwrap()
                                .message;
                            assert_eq!(decoded.encode().unwrap(), message.encode().unwrap());
                            assert_eq!(
                                fctx(nia, nea, count)
                                    .protect_for_access(&decoded, sht, direction, access)
                                    .unwrap(),
                                wire
                            );
                            assert_eq!(rx.nas_count(direction, access), next(count + 1));
                            assert!(rx.unprotect_for_access(&wire, direction, access).is_err());
                            let mut tampered = wire.clone();
                            tampered[2] ^= 1;
                            let mut bad = fctx(nia, nea, count);
                            assert!(
                                bad.unprotect_for_access(&tampered, direction, access)
                                    .is_err()
                            );
                            assert_eq!(bad.nas_count(direction, access), next(count));
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
            let used = NasCount::new(100).unwrap();
            let (mapped_wire, count) = fctx(nia, nea, 100).protect_eps_message(&plain_eps).unwrap();
            assert_eq!(count, used);
            assert_eq!(
                fctx(nia, nea, 100)
                    .unprotect_eps_message(&mapped_wire)
                    .unwrap(),
                (plain_eps.clone(), used)
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
            let request = f::Nas5gsMessage::new_5gmm(
                f::NasRegistrationRequest::new(
                    f::NasFGsRegistrationType::new(0x01),
                    f::NasKeySetIdentifier::new(1),
                    f::NasFGsMobileIdentity::new(hex::decode("f202f83900010211223344").unwrap()),
                )
                .with_fgmm_capability(f::NasFGmmCapability::new(vec![1]))
                .with_ue_security_capability(f::NasUeSecurityCapability::new(vec![0xf0, 0x70]))
                .with_ue_status(f::NasUeStatus::new(vec![0]))
                .with_additional_guti(f::NasFGsMobileIdentity::new(
                    hex::decode("f202f83901004211223344").unwrap(),
                ))
                .with_eps_nas_message_container(f::NasEpsNasMessageContainer::new(
                    eps_wire.clone(),
                )),
            );
            for sht in [
                f::Nas5gsSecurityHeaderType::IntegrityProtected,
                f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
            ] {
                let wire = fctx(nia, nea, 101)
                    .protect(&request, sht, f::Direction::Uplink)
                    .unwrap();
                let decoded = fctx(nia, nea, 101)
                    .unprotect(&wire, f::Direction::Uplink)
                    .unwrap()
                    .message;
                assert_eq!(decoded.encode().unwrap(), request.encode().unwrap());
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
                let eps = ectx(eia, e::CipheringAlgorithm::EEA0, 100)
                    .unprotect(&nested, e::Direction::Uplink)
                    .unwrap()
                    .message;
                assert_eq!(eps.encode().unwrap(), plain_eps);
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
                let esm = e::NasEpsMessage::decode(&attach.esm_message_container.value).unwrap();
                assert!(matches!(
                    esm,
                    e::NasEpsMessage::Esm(_, e::NasEsmMessage::PdnConnectivityRequest(_))
                ));
                assert_eq!(esm.encode().unwrap(), attach.esm_message_container.value);
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
    let eps_tau = e::NasEpsMessage::decode(&tau).unwrap();
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
    let request = f::Nas5gsMessage::new_5gmm(
        f::NasRegistrationRequest::new(
            f::NasFGsRegistrationType::new(0x02),
            f::NasKeySetIdentifier::new(7),
            f::NasFGsMobileIdentity::new(hex::decode("f202f83900010211223344").unwrap()),
        )
        .with_fgmm_capability(f::NasFGmmCapability::new(vec![1]))
        .with_ue_security_capability(f::NasUeSecurityCapability::new(vec![0xf0, 0x70]))
        .with_ue_status(f::NasUeStatus::new(vec![2]))
        .with_eps_nas_message_container(f::NasEpsNasMessageContainer::new(eps_wire.clone())),
    );
    let wire = request.encode().unwrap();
    assert_eq!(
        f::Nas5gsMessage::decode(&wire).unwrap().encode().unwrap(),
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
        .message
        .encode()
        .unwrap(),
        tau
    );

    // TS 33.501 Annex A.15.1: FC75 || 32-bit padded COUNT100 || L0=4.
    // The fixed expected key was computed independently with HMAC-SHA256.
    let expected_kamf =
        hex::decode("01196aca1d4eeffd1a2589f7805c22950eb3c59d05a903b24984c712a079f908").unwrap();
    let master = e::KAsme::new(&MASTER);
    let mapped =
        oxirush_security::nas_5gs::derive_mapped_kamf_idle(&master, NasCount::new(100).unwrap());
    assert_eq!(mapped.as_octets().as_slice(), expected_kamf);
    let context = || {
        f::NasSecurityContext::from_mapped_kamf_idle(
            &master,
            NasCount::new(100).unwrap(),
            f::IntegrityAlgorithm::NIA2,
            f::CipheringAlgorithm::NEA2,
        )
        .unwrap()
    };
    let mut ue = context();
    let mut amf = context();
    let messages = [
        (
            f::Nas5gsMessage::new_5gmm(f::NasSecurityModeCommand::new(
                f::NasSecurityAlgorithms::from_algorithms(
                    f::CipheringAlgorithm::NEA2,
                    f::IntegrityAlgorithm::NIA2,
                ),
                f::NasKeySetIdentifier::new(9),
                f::NasUeSecurityCapability::new(vec![0xf0, 0x70]),
            )),
            f::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
            f::Direction::Downlink,
        ),
        (
            f::Nas5gsMessage::new_5gmm(f::NasSecurityModeComplete::new()),
            f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
            f::Direction::Uplink,
        ),
        (
            f::Nas5gsMessage::new_5gmm(f::NasRegistrationAccept::new(
                f::NasFGsRegistrationResult::new(vec![1]),
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
        let decoded = rx.unprotect(&wire, direction).unwrap().message;
        assert_eq!(decoded.encode().unwrap(), message.encode().unwrap());
        let mut replay = context();
        if i == 2 {
            replay = f::NasSecurityContext::restore_from_kamf(
                &f::KAmf::from_slice(&expected_kamf).unwrap(),
                f::IntegrityAlgorithm::NIA2,
                f::CipheringAlgorithm::NEA2,
                (next(1), next(1)),
                (next(0), next(0)),
            )
            .unwrap();
        }
        assert_eq!(replay.protect(&decoded, sht, direction).unwrap(), wire);
    }
}

#[test]
fn complete_eps_crypto_matrix_with_short_and_partial_messages() {
    let cp = e::NasEpsMessage::decode(&fixture(
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
                    let status =
                        e::NasEpsMessage::new_emm(e::NasEmmStatus::new(e::NasEmmCause::new(3)));
                    let command = e::NasEpsMessage::new_emm(e::NasSecurityModeCommand::new(
                        e::NasSecurityAlgorithms::new(((nea as u8) << 4) | nia as u8),
                        e::NasKeySetIdentifier::new(1),
                        e::NasUeSecurityCapability::new(vec![0xf0, 0x70]),
                    ));
                    let complete = e::NasEpsMessage::new_emm(e::NasSecurityModeComplete::new());
                    let new = if direction == e::Direction::Downlink {
                        (
                            &command,
                            e::NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
                        )
                    } else {
                        (&complete,e::NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext)
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
                            e::NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
                        ));
                    }
                    for (message, sht) in cases {
                        let mut tx = ectx(nia, nea, count);
                        let mut rx = ectx(nia, nea, count);
                        let wire = tx.protect(message, sht, direction).unwrap();
                        assert_eq!(
                            e::NasEpsMessage::decode_with_direction(&wire, direction)
                                .unwrap()
                                .encode()
                                .unwrap(),
                            wire
                        );
                        let decoded = rx.unprotect(&wire, direction).unwrap().message;
                        assert_eq!(decoded.encode().unwrap(), message.encode().unwrap());
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
                        assert_eq!(
                            (
                                bad.nas_count(f::Direction::Uplink),
                                bad.nas_count(f::Direction::Downlink),
                            ),
                            (next(count), next(count))
                        );
                        if count == 0x00ff_ffff {
                            assert!(tx.protect(message, sht, direction).is_err());
                        }
                    }
                }
                let mut tx = ectx(nia, nea, count);
                let short = tx.protect_service_request(1).unwrap();
                let wire = e::NasEpsMessage::ServiceRequest(short.clone())
                    .encode()
                    .unwrap();
                assert_eq!(
                    e::NasEpsMessage::decode(&wire).unwrap().encode().unwrap(),
                    wire
                );
                assert_eq!(
                    e::NasEpsMessage::ServiceRequest(
                        ectx(nia, nea, count).protect_service_request(1).unwrap()
                    )
                    .encode()
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
        "DeregistrationRequestUeOriginating",
        "DeregistrationAcceptUeTerminated",
        "ConfigurationUpdateComplete",
        "ServiceRequest",
        "AuthenticationResponse",
        "AuthenticationFailure",
        "IdentityResponse",
        "SecurityModeComplete",
        "SecurityModeReject",
        "FiveGmmStatus",
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
        "FiveGsmStatus",
        "ServiceLevelAuthenticationComplete",
        "RemoteUeReport",
    ];
    const E_UP: &[&str] = &[
        "AttachComplete",
        "AttachRequest",
        "AuthenticationFailure",
        "AuthenticationResponse",
        "DetachRequestUeOriginating",
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
        let body = f::Nas5gsMessage::decode(&inner).unwrap();
        // 5GSM security is supplied by its enclosing UL/DL NAS TRANSPORT.
        let nested_sm = matches!(body, f::Nas5gsMessage::Gsm(..));
        let pdu = if nested_sm {
            let payload = f::NasPayloadContainer::new(inner.clone());
            if direction == f::Direction::Uplink {
                f::Nas5gsMessage::new_5gmm(
                    f::NasUlNasTransport::new(f::NasPayloadContainerType::new(1), payload)
                        .with_pdu_session_id(f::NasPduSessionIdentity2::new(1)),
                )
            } else {
                f::Nas5gsMessage::new_5gmm(
                    f::NasDlNasTransport::new(f::NasPayloadContainerType::new(1), payload)
                        .with_pdu_session_id(f::NasPduSessionIdentity2::new(1)),
                )
            }
        } else {
            body
        };
        let sht = match kind {
            "SecurityModeCommand" => f::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
            "SecurityModeComplete" => {
                f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
            }
            "ServiceRequest" => f::Nas5gsSecurityHeaderType::IntegrityProtected,
            _ => f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
        };
        // A SERVICE REQUEST under "integrity protected" is an initial NAS
        // message (TS 24.501 §4.4.6): the context puts it, complete, in the
        // NAS message container, ciphered, and the fixture is given
        // without the container that it has.
        let (pdu, initial) = match pdu {
            f::Nas5gsMessage::Gmm(header, f::Nas5gmmMessage::ServiceRequest(mut request)) => {
                request.nas_message_container = None;
                let request = f::Nas5gmmMessage::ServiceRequest(request);
                (f::Nas5gsMessage::Gmm(header, request), true)
            }
            other => (other, false),
        };
        let mut sender = fctx(f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2, 17);
        let wire = match initial {
            true => sender.protect_initial(&pdu),
            false => sender.protect(&pdu, sht, direction),
        }
        .unwrap_or_else(|err| panic!("{name}: {err}"));
        let decoded = fctx(f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2, 17)
            .unprotect(&wire, direction)
            .unwrap()
            .message;
        assert_eq!(decoded.encode().unwrap(), pdu.encode().unwrap(), "{name}");
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
                f::Nas5gsMessage::decode(payload).unwrap().encode().unwrap(),
                inner,
                "{name}"
            );
        }
        let mut again = fctx(f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2, 17);
        let again = match initial {
            true => again.protect_initial(&decoded),
            false => again.protect(&decoded, sht, direction),
        };
        assert_eq!(again.unwrap(), wire, "{name}");
    }
    for (name, inner) in rows(include_str!("fixtures/nas-eps.tsv")) {
        let kind = name.split('-').next().unwrap();
        let direction = if E_UP.contains(&kind) {
            e::Direction::Uplink
        } else {
            e::Direction::Downlink
        };
        let pdu = e::NasEpsMessage::decode_with_direction(&inner, direction).unwrap();
        let sht = match kind {
            "SecurityModeCommand" => {
                e::NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
            }
            "SecurityModeComplete" => {
                e::NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
            }
            "AttachRequest" | "TrackingAreaUpdateRequest" => {
                e::NasEpsSecurityHeaderType::IntegrityProtected
            }
            "ControlPlaneServiceRequest" if name.ends_with("optional") => {
                e::NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
            }
            "ControlPlaneServiceRequest" => e::NasEpsSecurityHeaderType::IntegrityProtected,
            _ => e::NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
        };
        let wire = ectx(e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2, 17)
            .protect(&pdu, sht, direction)
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        let decoded = ectx(e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2, 17)
            .unprotect(&wire, direction)
            .unwrap()
            .message;
        assert_eq!(decoded.encode().unwrap(), inner, "{name}");
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
    )
    .unwrap();
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
            let raw = $ie.encode().unwrap();
            let decoded = <$ty>::decode(&raw).unwrap();
            assert_eq!(decoded.encode().unwrap(), raw);
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

/// The KASME' of a handover from 5GS to EPS and the NH that the MME gives at the
/// handover back (NCC 3), whose values `tests/interworking_keys.py` of
/// oxirush-security derives with Python's HMAC-SHA-256 (TS 33.501 Annex A.14.2,
/// TS 33.401 Annex A.4).
fn handover_keys() -> (e::KAsme, e::Nh) {
    let kasme = "c722847e47f812639563a633db6dead66f91771ee496f91aa9b229a2257a18b8";
    let nh = "ded8ae70ee0547222d73008bc3665f007d627e63f38f372bd48e233e7a155951";
    let kasme = e::KAsme::new(&hex::decode(kasme).unwrap().try_into().unwrap());
    let nh = e::Nh::new(&hex::decode(nh).unwrap().try_into().unwrap());
    (kasme, nh)
}

/// The mapped 5G context of a handover from EPS, as the AMF and the UE derive it
/// (TS 33.501 §8.4.2 steps 3 and 8): KAMF' of KASME and NH (Annex A.15.2), counts 0.
fn mapped(nia: f::IntegrityAlgorithm, nea: f::CipheringAlgorithm) -> f::NasSecurityContext {
    let (kasme, nh) = handover_keys();
    f::NasSecurityContext::from_mapped_kamf_handover(&kasme, &nh, nia, nea).unwrap()
}

fn downlink(context: &f::NasSecurityContext) -> Option<NasCount> {
    context.nas_count(f::Direction::Downlink, f::NasConnection::ThreeGpp)
}

/// TS 24.501 §4.4.2.2 and §9.11.2.9, TS 33.501 §8.4.2 step 3 and §6.9.2.3.3: the
/// AMF puts in the S1 mode to N1 mode NAS transparent container the algorithms of
/// the mapped context, the NCC of the NH of KAMF' and the ngKSI, and a code of
/// KNASint at the COUNT 2^32 - 1, downlink, bearer 1, over every octet of the value
/// from octet 7 on (§4.4.3.3 b)). Its downlink COUNT then advances by one
/// (§4.4.3.1), and so does the UE's once the code verifies.
#[test]
fn the_s1_mode_to_n1_mode_container_has_the_code_of_octets_7_on_at_count_2_32_minus_1() {
    use f::KeySetIdentifier::Mapped;
    let (nia, nea) = (f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2);
    let ngksi = f::NasKeySetIdentifier::from_key_set_identifier(Mapped(2)).unwrap();
    let mut amf = mapped(nia, nea);
    let container = amf.s1_to_n1_container(3, ngksi).unwrap();
    // KNASint of 128-NIA2 is the HMAC-SHA-256 of KAMF' over 69 02 00 01 02 00 01
    // (Annex A.8), b8b97bfcd3c7007b5ffb5be07e1abd65; the code is the AES-CMAC of
    // that key, by OpenSSL 3 (`openssl mac -cipher AES-128-CBC CMAC`), of COUNT
    // ff ff ff ff, BEARER 1 and DIRECTION 1 as 0c 00 00 00 (TS 33.401 Annex
    // B.2.3), then octets 7 to 10: NEA2 and NIA2, NCC 3 with a mapped ngKSI 2, and
    // the two spare octets
    assert_eq!(hex::encode(&container.value), "2979a6ab223a0000");
    assert_eq!(
        (container.ncc(), container.key_set_identifier()),
        (Some(3), Some(ngksi))
    );
    assert_eq!(downlink(&amf), next(1));

    let mut ue = mapped(nia, nea);
    ue.verify_s1_to_n1_container(&container).unwrap();
    assert_eq!(downlink(&ue), next(1));

    // A bit of the code, of the NCC, of the ngKSI or of a spare octet: the code
    // does not verify, and the UE's COUNT stays
    for (octet, bit) in [
        (0, 0x80),
        (3, 0x01),
        (5, 0x10),
        (5, 0x01),
        (6, 0x01),
        (7, 0x80),
    ] {
        let mut changed = container.clone();
        changed.value[octet] ^= bit;
        let mut ue = mapped(nia, nea);
        let refused = ue.verify_s1_to_n1_container(&changed).unwrap_err();
        assert_eq!(
            refused,
            f::NasError::IntegrityCheckFailed,
            "{octet} {bit:#x}"
        );
        assert_eq!(downlink(&ue), next(0));
    }
    // An octet after octet 10 is under the code too, as a UE of every release
    // takes it (§4.4.3.3, note)
    let mut longer = container.clone();
    longer.value.push(0x5a);
    let refused = mapped(nia, nea).verify_s1_to_n1_container(&longer);
    assert_eq!(refused.unwrap_err(), f::NasError::IntegrityCheckFailed);
    let (kasme, nh) = handover_keys();
    let kamf = oxirush_security::nas_5gs::derive_mapped_kamf_handover(&kasme, &nh);
    let knas_int = oxirush_security::nas_5gs::derive_knas_int(
        &kamf,
        oxirush_security::IntegrityAlgorithm::NIA2,
    );
    let code = oxirush_security::nia_mac(
        &knas_int,
        u32::MAX,
        oxirush_security::Bearer::from(f::NasConnection::ThreeGpp),
        oxirush_security::Direction::Downlink,
        &longer.value[4..],
        oxirush_security::IntegrityAlgorithm::NIA2,
    );
    longer.value[..4].copy_from_slice(&code.to_be_bytes());
    mapped(nia, nea).verify_s1_to_n1_container(&longer).unwrap();
}

/// What the container cannot be verified or made with refuses it, and no COUNT
/// is used.
#[test]
fn an_s1_mode_to_n1_mode_container_that_is_refused_uses_no_count() {
    use f::KeySetIdentifier::Mapped;
    let (nia, nea) = (f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2);
    let ngksi = f::NasKeySetIdentifier::from_key_set_identifier(Mapped(2)).unwrap();
    let container = mapped(nia, nea).s1_to_n1_container(3, ngksi).unwrap();

    // The UE verifies with the context of the algorithms that the container
    // selects: a context of others, or a container of a reserved algorithm,
    // is refused before any code
    let mut other = mapped(f::IntegrityAlgorithm::NIA1, f::CipheringAlgorithm::NEA1);
    let refused = other.verify_s1_to_n1_container(&container).unwrap_err();
    assert!(
        matches!(refused, f::NasError::SecurityRefused(_)),
        "{refused}"
    );
    assert_eq!(downlink(&other), next(0));
    let mut reserved = container.clone();
    reserved.value[4] = 0x24;
    let refused = mapped(nia, nea).verify_s1_to_n1_container(&reserved);
    assert!(matches!(refused, Err(f::NasError::SecurityRefused(_))));
    assert!(matches!(
        f::NasSecurityContext::from_mapped_kamf_handover(
            &handover_keys().0,
            &handover_keys().1,
            f::IntegrityAlgorithm::NIA4,
            nea
        ),
        Err(f::NasError::SecurityRefused(_))
    ));
    // A value of fewer than the 8 octets of §9.11.2.9
    let mut short = container.clone();
    short.value.truncate(7);
    let refused = mapped(nia, nea).verify_s1_to_n1_container(&short);
    assert_eq!(refused.unwrap_err(), f::NasError::BufferTooShort);

    // An NCC above 7, and a context whose downlink COUNTs were all used
    let mut amf = mapped(nia, nea);
    assert!(matches!(
        amf.s1_to_n1_container(8, ngksi),
        Err(f::NasError::EncodingError(_))
    ));
    assert_eq!(downlink(&amf), next(0));
    let kamf = f::KAmf::new(&MASTER);
    let exhausted = (next(0), None);
    let mut amf =
        f::NasSecurityContext::restore_from_kamf(&kamf, nia, nea, exhausted, exhausted).unwrap();
    let refused = amf.s1_to_n1_container(3, ngksi).unwrap_err();
    assert_eq!(refused, f::NasError::NasCountExhausted);
    let mut ue =
        f::NasSecurityContext::restore_from_kamf(&kamf, nia, nea, exhausted, exhausted).unwrap();
    let container = fctx(nia, nea, 0).s1_to_n1_container(3, ngksi).unwrap();
    let refused = ue.verify_s1_to_n1_container(&container).unwrap_err();
    assert_eq!(refused, f::NasError::NasCountExhausted);
}

/// TS 24.501 §4.4.2.4 and §9.11.2.7, TS 33.501 §8.3.2 steps 2 and 8: the AMF puts
/// the sequence number of its current downlink NAS COUNT in the N1 mode to S1 mode
/// NAS transparent container, derives KASME' with that COUNT and goes on with the
/// next one. The UE takes the least COUNT above the largest that it received whose
/// 8 low bits are that number (§4.4.3.1), derives KASME' with it, and goes on after
/// it.
#[test]
fn the_n1_mode_to_s1_mode_container_gives_the_downlink_count_by_its_8_low_bits() {
    let (nia, nea) = (f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2);
    let mut amf = fctx(nia, nea, 0x0001fe);
    let mut ue = fctx(nia, nea, 0x0001fe);
    let (container, count) = amf.n1_to_s1_container().unwrap();
    assert_eq!((container.sequence_number(), count.get()), (0xfe, 0x0001fe));
    assert_eq!(downlink(&amf), next(0x0001ff));
    assert_eq!(ue.verify_n1_to_s1_container(&container), Ok(count));
    assert_eq!(downlink(&ue), next(0x0001ff));
    // Both derive the same KASME' with it (Annex A.14.2)
    let kamf = f::KAmf::new(&MASTER);
    let kasme = |count| oxirush_security::nas_5gs::derive_mapped_kasme_handover(&kamf, count);
    assert_eq!(kasme(count), kasme(NasCount::new(0x0001fe).unwrap()));

    // Across the wrap of the sequence number: 01 after a largest COUNT of 01 fe
    let mut ue = fctx(nia, nea, 0x0001ff);
    let wrapped = f::NasN1ModeToS1ModeNasTransparentContainer::from_sequence_number(0x01);
    assert_eq!(
        ue.verify_n1_to_s1_container(&wrapped),
        Ok(NasCount::new(0x000201).unwrap())
    );
    assert_eq!(downlink(&ue), next(0x000202));
    // The number of a COUNT that the UE received is that of a COUNT above it,
    // never the one received
    let mut ue = fctx(nia, nea, 0x0001ff);
    let received = f::NasN1ModeToS1ModeNasTransparentContainer::from_sequence_number(0xfe);
    assert_eq!(
        ue.verify_n1_to_s1_container(&received),
        Ok(NasCount::new(0x0002fe).unwrap())
    );
    // No COUNT above the last: refused, and the COUNT stays
    let mut ue = fctx(nia, nea, 0xffffff);
    let beyond = f::NasN1ModeToS1ModeNasTransparentContainer::from_sequence_number(0x00);
    assert_eq!(
        ue.verify_n1_to_s1_container(&beyond),
        Err(f::NasError::NasCountExhausted)
    );
    assert_eq!(downlink(&ue), next(0xffffff));
    let last = f::NasN1ModeToS1ModeNasTransparentContainer::from_sequence_number(0xff);
    assert_eq!(ue.verify_n1_to_s1_container(&last), Ok(NasCount::MAX));
    assert_eq!(downlink(&ue), None);
    let mut amf = fctx(nia, nea, 0xffffff);
    assert_eq!(amf.n1_to_s1_container().unwrap().1, NasCount::MAX);
    assert_eq!(
        amf.n1_to_s1_container(),
        Err(f::NasError::NasCountExhausted)
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
                        e::NasEpsMessage::decode(&wire).unwrap().encode().unwrap(),
                        wire
                    );
                    let e::Verified {
                        message: decoded,
                        security_header_type: sht,
                        ..
                    } = ectx(nia, nea, 17).unprotect(&wire, dir).unwrap();
                    assert_eq!(
                        sht,
                        e::NasEpsSecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
                    );
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
    let fm = f::Nas5gsMessage::new_5gmm(f::NasFGmmStatus::new(f::NasFGmmCause::new(3)));
    let fw = fctx(f::IntegrityAlgorithm::NIA0, f::CipheringAlgorithm::NEA0, 0)
        .protect(
            &fm,
            f::Nas5gsSecurityHeaderType::IntegrityProtected,
            f::Direction::Uplink,
        )
        .unwrap();
    let fd = fctx(f::IntegrityAlgorithm::NIA0, f::CipheringAlgorithm::NEA0, 0)
        .unprotect(&fw, f::Direction::Uplink)
        .unwrap()
        .message;
    assert_eq!(fd.encode().unwrap(), fm.encode().unwrap());
    let em = e::NasEpsMessage::new_emm(e::NasEmmStatus::new(e::NasEmmCause::new(3)));
    let ew = ectx(e::IntegrityAlgorithm::EIA0, e::CipheringAlgorithm::EEA0, 0)
        .protect(
            &em,
            e::NasEpsSecurityHeaderType::IntegrityProtected,
            e::Direction::Uplink,
        )
        .unwrap();
    let ed = ectx(e::IntegrityAlgorithm::EIA0, e::CipheringAlgorithm::EEA0, 0)
        .unprotect(&ew, e::Direction::Uplink)
        .unwrap()
        .message;
    assert_eq!(ed.encode().unwrap(), em.encode().unwrap());
}

/// HMAC-derived NAS keys, AES-CTR plaintext and AES-CMAC were checked independently.
#[test]
fn aes_protected_messages_match_fixed_wire_vectors() {
    let message = f::Nas5gsMessage::decode(&fixture(
        include_str!("fixtures/nas-5gs.tsv"),
        "FiveGmmStatus",
    ))
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
            e::NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
            "5796cc8ee911074d107800192c68d48337e736f7600137b1406aedc39ec3434890e24395a557022000d0",
        ),
    ] {
        let message =
            e::NasEpsMessage::decode(&fixture(include_str!("fixtures/nas-eps.tsv"), name)).unwrap();
        let wire = ectx(e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2, 17)
            .protect(&message, sht, e::Direction::Uplink)
            .unwrap();
        assert_eq!(hex::encode(wire), expected, "{name}");
    }
}
