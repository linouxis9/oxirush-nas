#![cfg(feature = "security")]
//! Security roundtrips cover COUNT boundaries, all algorithms and EPS/5GS interworking.
use oxirush_nas::NasCount;
use oxirush_nas::identity::Algorithm;
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
fn fctx(nia: Algorithm, nea: Algorithm, count: u32) -> f::SecurityContext {
    let counts = (next(count), next(count));
    f::SecurityContext::restore_from_kamf(&f::KAmf::new(&MASTER), nia, nea, counts, counts).unwrap()
}
fn ectx(nia: Algorithm, nea: Algorithm, count: u32) -> e::SecurityContext {
    let kasme = e::KAsme::new(&MASTER);
    e::SecurityContext::restore_from_kasme(&kasme, nia, nea, (next(count), next(count))).unwrap()
}

#[test]
fn complete_5gs_crypto_matrix_and_nested_eps_attach() {
    let original_eps = fixture(include_str!("fixtures/nas-eps.tsv"), "AttachRequest");
    let mut eps_attach = e::Message::decode(&original_eps).unwrap();
    let e::Message::Emm(_, e::EmmMessage::AttachRequest(attach)) = &mut eps_attach else {
        panic!()
    };
    attach.eps_mobile_identity =
        e::EpsMobileIdentity::new(hex::decode("f602f83900010211223344").unwrap());
    let plain_eps = eps_attach.encode().unwrap();

    for nia in [Algorithm::Snow3g, Algorithm::Aes, Algorithm::Zuc] {
        for nea in [
            Algorithm::Null,
            Algorithm::Snow3g,
            Algorithm::Aes,
            Algorithm::Zuc,
        ] {
            for count in [0, 255, 256, 65535, 0x00ff_ffff] {
                for access in [f::NasConnection::ThreeGpp, f::NasConnection::Non3Gpp] {
                    for direction in [
                        oxirush_nas::Direction::Uplink,
                        oxirush_nas::Direction::Downlink,
                    ] {
                        let status = f::Message::new_5gmm(f::GmmStatus::new(f::GmmCause::new(3)));
                        let command = f::Message::new_5gmm(f::SecurityModeCommand::new(
                            f::SecurityAlgorithms::from_algorithms(nea, nia),
                            f::KeySetIdentifier::new(1),
                            f::UeSecurityCapability::new(vec![0xf0, 0x70]),
                        ));
                        let complete = f::Message::new_5gmm(f::SecurityModeComplete::new());
                        let new = if direction == oxirush_nas::Direction::Downlink {
                            (
                                &command,
                                f::SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                            )
                        } else {
                            (&complete,f::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext)
                        };
                        for (message, sht) in [
                            (&status, f::SecurityHeaderType::IntegrityProtected),
                            (
                                &status,
                                f::SecurityHeaderType::IntegrityProtectedAndCiphered,
                            ),
                            new,
                        ] {
                            let mut tx = fctx(nia, nea, count);
                            let mut rx = fctx(nia, nea, count);
                            let wire = tx.protect(message, sht, direction, access).unwrap();
                            assert_eq!(f::Message::decode(&wire).unwrap().encode().unwrap(), wire);
                            let decoded = rx.unprotect(&wire, direction, access).unwrap().message;
                            assert_eq!(decoded.encode().unwrap(), message.encode().unwrap());
                            assert_eq!(
                                fctx(nia, nea, count)
                                    .protect(&decoded, sht, direction, access)
                                    .unwrap(),
                                wire
                            );
                            assert_eq!(rx.nas_count(direction, access), next(count + 1));
                            assert!(rx.unprotect(&wire, direction, access).is_err());
                            let mut tampered = wire.clone();
                            tampered[2] ^= 1;
                            let mut bad = fctx(nia, nea, count);
                            assert!(bad.unprotect(&tampered, direction, access).is_err());
                            assert_eq!(bad.nas_count(direction, access), next(count));
                            if count == 0x00ff_ffff {
                                assert!(tx.protect(message, sht, direction, access).is_err());
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
                Algorithm::Snow3g => Algorithm::Snow3g,
                Algorithm::Aes => Algorithm::Aes,
                Algorithm::Zuc => Algorithm::Zuc,
                _ => unreachable!(),
            };
            let eps_wire = ectx(eia, Algorithm::Null, 100)
                .protect(
                    &eps_attach,
                    e::SecurityHeaderType::IntegrityProtected,
                    oxirush_nas::Direction::Uplink,
                )
                .unwrap();
            let request = f::Message::new_5gmm(
                f::RegistrationRequest::new(
                    f::RegistrationType::new(0x01),
                    f::KeySetIdentifier::new(1),
                    f::MobileIdentity::new(hex::decode("f202f83900010211223344").unwrap()),
                )
                .with_fgmm_capability(f::GmmCapability::new(vec![1]))
                .with_ue_security_capability(f::UeSecurityCapability::new(vec![0xf0, 0x70]))
                .with_ue_status(f::UeStatus::new(vec![0]))
                .with_additional_guti(f::MobileIdentity::new(
                    hex::decode("f202f83901004211223344").unwrap(),
                ))
                .with_eps_nas_message_container(f::EpsNasMessageContainer::new(eps_wire.clone())),
            );
            for sht in [
                f::SecurityHeaderType::IntegrityProtected,
                f::SecurityHeaderType::IntegrityProtectedAndCiphered,
            ] {
                let wire = fctx(nia, nea, 101)
                    .protect(
                        &request,
                        sht,
                        oxirush_nas::Direction::Uplink,
                        f::NasConnection::ThreeGpp,
                    )
                    .unwrap();
                let decoded = fctx(nia, nea, 101)
                    .unprotect(
                        &wire,
                        oxirush_nas::Direction::Uplink,
                        f::NasConnection::ThreeGpp,
                    )
                    .unwrap()
                    .message;
                assert_eq!(decoded.encode().unwrap(), request.encode().unwrap());
                assert_eq!(
                    fctx(nia, nea, 101)
                        .protect(
                            &decoded,
                            sht,
                            oxirush_nas::Direction::Uplink,
                            f::NasConnection::ThreeGpp
                        )
                        .unwrap(),
                    wire
                );
                let f::Message::Gmm(_, f::GmmMessage::RegistrationRequest(decoded_request)) =
                    decoded
                else {
                    panic!()
                };
                let nested = decoded_request.eps_nas_message_container.unwrap().value;
                assert_eq!(nested, eps_wire);
                let eps = ectx(eia, Algorithm::Null, 100)
                    .unprotect(&nested, oxirush_nas::Direction::Uplink)
                    .unwrap()
                    .message;
                assert_eq!(eps.encode().unwrap(), plain_eps);
                assert_eq!(
                    ectx(eia, Algorithm::Null, 100)
                        .protect(
                            &eps,
                            e::SecurityHeaderType::IntegrityProtected,
                            oxirush_nas::Direction::Uplink
                        )
                        .unwrap(),
                    nested
                );
                let e::Message::Emm(_, e::EmmMessage::AttachRequest(attach)) = eps else {
                    panic!()
                };
                let esm = e::Message::decode(&attach.esm_message_container.value).unwrap();
                assert!(matches!(
                    esm,
                    e::Message::Esm(_, e::EsmMessage::PdnConnectivityRequest(_))
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
    let eps_tau = e::Message::decode(&tau).unwrap();
    let eps_wire = ectx(Algorithm::Aes, Algorithm::Null, 100)
        .protect(
            &eps_tau,
            e::SecurityHeaderType::IntegrityProtected,
            oxirush_nas::Direction::Uplink,
        )
        .unwrap();
    let request = f::Message::new_5gmm(
        f::RegistrationRequest::new(
            f::RegistrationType::new(0x02),
            f::KeySetIdentifier::new(7),
            f::MobileIdentity::new(hex::decode("f202f83900010211223344").unwrap()),
        )
        .with_fgmm_capability(f::GmmCapability::new(vec![1]))
        .with_ue_security_capability(f::UeSecurityCapability::new(vec![0xf0, 0x70]))
        .with_ue_status(f::UeStatus::new(vec![2]))
        .with_eps_nas_message_container(f::EpsNasMessageContainer::new(eps_wire.clone())),
    );
    let wire = request.encode().unwrap();
    assert_eq!(f::Message::decode(&wire).unwrap().encode().unwrap(), wire);
    assert_eq!(
        ectx(Algorithm::Aes, Algorithm::Null, 100)
            .unprotect(&eps_wire, oxirush_nas::Direction::Uplink)
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
        f::SecurityContext::from_mapped_kamf_idle(
            &master,
            NasCount::new(100).unwrap(),
            Algorithm::Aes,
            Algorithm::Aes,
        )
        .unwrap()
    };
    let mut ue = context();
    let mut amf = context();
    let messages = [
        (
            f::Message::new_5gmm(f::SecurityModeCommand::new(
                f::SecurityAlgorithms::from_algorithms(Algorithm::Aes, Algorithm::Aes),
                f::KeySetIdentifier::new(9),
                f::UeSecurityCapability::new(vec![0xf0, 0x70]),
            )),
            f::SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
            oxirush_nas::Direction::Downlink,
        ),
        (
            f::Message::new_5gmm(f::SecurityModeComplete::new()),
            f::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
            oxirush_nas::Direction::Uplink,
        ),
        (
            f::Message::new_5gmm(f::RegistrationAccept::new(f::RegistrationResult::new(
                vec![1],
            ))),
            f::SecurityHeaderType::IntegrityProtectedAndCiphered,
            oxirush_nas::Direction::Downlink,
        ),
    ];
    for (i, (message, sht, direction)) in messages.into_iter().enumerate() {
        let (tx, rx) = if direction == oxirush_nas::Direction::Uplink {
            (&mut ue, &mut amf)
        } else {
            (&mut amf, &mut ue)
        };
        let wire = tx
            .protect(&message, sht, direction, f::NasConnection::ThreeGpp)
            .unwrap();
        let decoded = rx
            .unprotect(&wire, direction, f::NasConnection::ThreeGpp)
            .unwrap()
            .message;
        assert_eq!(decoded.encode().unwrap(), message.encode().unwrap());
        let mut replay = context();
        if i == 2 {
            replay = f::SecurityContext::restore_from_kamf(
                &f::KAmf::from_slice(&expected_kamf).unwrap(),
                Algorithm::Aes,
                Algorithm::Aes,
                (next(1), next(1)),
                (next(0), next(0)),
            )
            .unwrap();
        }
        assert_eq!(
            replay
                .protect(&decoded, sht, direction, f::NasConnection::ThreeGpp)
                .unwrap(),
            wire
        );
    }
}

#[test]
fn complete_eps_crypto_matrix_with_short_and_partial_messages() {
    let cp = e::Message::decode(&fixture(
        include_str!("fixtures/nas-eps.tsv"),
        "ControlPlaneServiceRequest-optional",
    ))
    .unwrap();
    for nia in [Algorithm::Snow3g, Algorithm::Aes, Algorithm::Zuc] {
        for nea in [
            Algorithm::Null,
            Algorithm::Snow3g,
            Algorithm::Aes,
            Algorithm::Zuc,
        ] {
            for count in [0, 255, 256, 65535, 0x00ff_ffff] {
                for direction in [
                    oxirush_nas::Direction::Uplink,
                    oxirush_nas::Direction::Downlink,
                ] {
                    let status = e::Message::new_emm(e::EmmStatus::new(e::EmmCause::new(3)));
                    let command = e::Message::new_emm(e::SecurityModeCommand::new(
                        e::SecurityAlgorithms::new(((nea as u8) << 4) | nia as u8),
                        e::KeySetIdentifier::new(1),
                        e::UeSecurityCapability::new(vec![0xf0, 0x70]),
                    ));
                    let complete = e::Message::new_emm(e::SecurityModeComplete::new());
                    let new = if direction == oxirush_nas::Direction::Downlink {
                        (
                            &command,
                            e::SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext,
                        )
                    } else {
                        (&complete,e::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext)
                    };
                    let mut cases = vec![
                        (&status, e::SecurityHeaderType::IntegrityProtected),
                        (
                            &status,
                            e::SecurityHeaderType::IntegrityProtectedAndCiphered,
                        ),
                        new,
                    ];
                    if direction == oxirush_nas::Direction::Uplink {
                        cases.push((
                            &cp,
                            e::SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
                        ));
                    }
                    for (message, sht) in cases {
                        let mut tx = ectx(nia, nea, count);
                        let mut rx = ectx(nia, nea, count);
                        let wire = tx.protect(message, sht, direction).unwrap();
                        assert_eq!(
                            e::Message::decode_with(
                                &wire,
                                oxirush_nas::DecodeOptions::STRICT.with_direction(direction)
                            )
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
                                bad.nas_count(oxirush_nas::Direction::Uplink),
                                bad.nas_count(oxirush_nas::Direction::Downlink),
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
                let wire = e::Message::ServiceRequest(short.clone()).encode().unwrap();
                assert_eq!(e::Message::decode(&wire).unwrap().encode().unwrap(), wire);
                assert_eq!(
                    e::Message::ServiceRequest(
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
            oxirush_nas::Direction::Uplink
        } else {
            oxirush_nas::Direction::Downlink
        };
        let body = f::Message::decode(&inner).unwrap();
        // 5GSM security is supplied by its enclosing UL/DL NAS TRANSPORT.
        let nested_sm = matches!(body, f::Message::Gsm(..));
        let pdu = if nested_sm {
            let payload = f::PayloadContainer::new(inner.clone());
            if direction == oxirush_nas::Direction::Uplink {
                f::Message::new_5gmm(
                    f::UlNasTransport::new(f::PayloadContainerType::new(1), payload)
                        .with_pdu_session_id(f::PduSessionIdentity2::new(1)),
                )
            } else {
                f::Message::new_5gmm(
                    f::DlNasTransport::new(f::PayloadContainerType::new(1), payload)
                        .with_pdu_session_id(f::PduSessionIdentity2::new(1)),
                )
            }
        } else {
            body
        };
        let sht = match kind {
            "SecurityModeCommand" => {
                f::SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext
            }
            "SecurityModeComplete" => {
                f::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
            }
            "ServiceRequest" => f::SecurityHeaderType::IntegrityProtected,
            _ => f::SecurityHeaderType::IntegrityProtectedAndCiphered,
        };
        // A SERVICE REQUEST under "integrity protected" is an initial NAS
        // message (TS 24.501 §4.4.6): the context puts it, complete, in the
        // NAS message container, ciphered, and the fixture is given
        // without the container that it has.
        let (pdu, initial) = match pdu {
            f::Message::Gmm(header, f::GmmMessage::ServiceRequest(mut request)) => {
                request.nas_message_container = None;
                let request = f::GmmMessage::ServiceRequest(request);
                (f::Message::Gmm(header, request), true)
            }
            other => (other, false),
        };
        let mut sender = fctx(Algorithm::Aes, Algorithm::Aes, 17);
        let wire = match initial {
            true => sender.protect_initial(&pdu, f::NasConnection::ThreeGpp),
            false => sender.protect(&pdu, sht, direction, f::NasConnection::ThreeGpp),
        }
        .unwrap_or_else(|err| panic!("{name}: {err}"));
        let decoded = fctx(Algorithm::Aes, Algorithm::Aes, 17)
            .unprotect(&wire, direction, f::NasConnection::ThreeGpp)
            .unwrap()
            .message;
        assert_eq!(decoded.encode().unwrap(), pdu.encode().unwrap(), "{name}");
        if nested_sm {
            let payload = match &decoded {
                f::Message::Gmm(_, f::GmmMessage::UlNasTransport(message)) => {
                    &message.payload_container.value
                }
                f::Message::Gmm(_, f::GmmMessage::DlNasTransport(message)) => {
                    &message.payload_container.value
                }
                _ => panic!("expected SM transport: {name}"),
            };
            assert_eq!(*payload, inner, "{name}");
            assert_eq!(
                f::Message::decode(payload).unwrap().encode().unwrap(),
                inner,
                "{name}"
            );
        }
        let mut again = fctx(Algorithm::Aes, Algorithm::Aes, 17);
        let again = match initial {
            true => again.protect_initial(&decoded, f::NasConnection::ThreeGpp),
            false => again.protect(&decoded, sht, direction, f::NasConnection::ThreeGpp),
        };
        assert_eq!(again.unwrap(), wire, "{name}");
    }
    for (name, inner) in rows(include_str!("fixtures/nas-eps.tsv")) {
        let kind = name.split('-').next().unwrap();
        let direction = if E_UP.contains(&kind) {
            oxirush_nas::Direction::Uplink
        } else {
            oxirush_nas::Direction::Downlink
        };
        let pdu = e::Message::decode_with(
            &inner,
            oxirush_nas::DecodeOptions::STRICT.with_direction(direction),
        )
        .unwrap();
        let sht = match kind {
            "SecurityModeCommand" => {
                e::SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext
            }
            "SecurityModeComplete" => {
                e::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext
            }
            "AttachRequest" | "TrackingAreaUpdateRequest" => {
                e::SecurityHeaderType::IntegrityProtected
            }
            "ControlPlaneServiceRequest" if name.ends_with("optional") => {
                e::SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage
            }
            "ControlPlaneServiceRequest" => e::SecurityHeaderType::IntegrityProtected,
            _ => e::SecurityHeaderType::IntegrityProtectedAndCiphered,
        };
        let wire = ectx(Algorithm::Aes, Algorithm::Aes, 17)
            .protect(&pdu, sht, direction)
            .unwrap_or_else(|err| panic!("{name}: {err}"));
        let decoded = ectx(Algorithm::Aes, Algorithm::Aes, 17)
            .unprotect(&wire, direction)
            .unwrap()
            .message;
        assert_eq!(decoded.encode().unwrap(), inner, "{name}");
        assert_eq!(
            ectx(Algorithm::Aes, Algorithm::Aes, 17)
                .protect(&decoded, sht, direction)
                .unwrap(),
            wire,
            "{name}"
        );
    }
}

#[test]
fn inter_system_transparent_containers_roundtrip_at_ie_boundary() {
    use oxirush_nas::{Decode, Encode};
    let n1s1 = f::N1ModeToS1ModeNasTransparentContainer::from_sequence_number(0x64);
    let s1n1 = f::S1ModeToN1ModeNasTransparentContainer::from_fields(
        0x11223344,
        f::SecurityAlgorithms::from_algorithms(Algorithm::Aes, Algorithm::Aes),
        3,
        f::KeySetIdentifier::new(1),
    )
    .unwrap();
    let intra = f::IntraN1ModeNasTransparentContainer::from_fields(
        0x55667788,
        f::SecurityAlgorithms::from_algorithms(Algorithm::Zuc, Algorithm::Zuc),
        true,
        f::KeySetIdentifier::new(2),
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
        check!(n1s1, f::N1ModeToS1ModeNasTransparentContainer).sequence_number(),
        0x64
    );
    assert_eq!(
        check!(s1n1, f::S1ModeToN1ModeNasTransparentContainer).message_authentication_code(),
        Some(0x11223344)
    );
    assert_eq!(
        check!(intra, f::IntraN1ModeNasTransparentContainer).sequence_number(),
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
fn mapped(nia: Algorithm, nea: Algorithm) -> f::SecurityContext {
    let (kasme, nh) = handover_keys();
    f::SecurityContext::from_mapped_kamf_handover(&kasme, &nh, nia, nea).unwrap()
}

fn downlink(context: &f::SecurityContext) -> Option<NasCount> {
    context.nas_count(oxirush_nas::Direction::Downlink, f::NasConnection::ThreeGpp)
}

/// TS 24.501 §4.4.2.2 and §9.11.2.9, TS 33.501 §8.4.2 step 3 and §6.9.2.3.3: the
/// AMF puts in the S1 mode to N1 mode NAS transparent container the algorithms of
/// the mapped context, the NCC of the NH of KAMF' and the ngKSI, and a code of
/// KNASint at the COUNT 2^32 - 1, downlink, bearer 1, over every octet of the value
/// from octet 7 on (§4.4.3.3 b)). Its downlink COUNT then advances by one
/// (§4.4.3.1), and so does the UE's once the code verifies.
#[test]
fn the_s1_mode_to_n1_mode_container_has_the_code_of_octets_7_on_at_count_2_32_minus_1() {
    use f::KeySetIdentifierValue::Mapped;
    let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    let ngksi = f::KeySetIdentifier::from_key_set_identifier(Mapped(2)).unwrap();
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
            oxirush_nas::Error::IntegrityCheckFailed,
            "{octet} {bit:#x}"
        );
        assert_eq!(downlink(&ue), next(0));
    }
    // An octet after octet 10 is under the code too, as a UE of every release
    // takes it (§4.4.3.3, note)
    let mut longer = container.clone();
    longer.value.push(0x5a);
    let refused = mapped(nia, nea).verify_s1_to_n1_container(&longer);
    assert_eq!(
        refused.unwrap_err(),
        oxirush_nas::Error::IntegrityCheckFailed
    );
    let (kasme, nh) = handover_keys();
    let kamf = oxirush_security::nas_5gs::derive_mapped_kamf_handover(&kasme, &nh);
    let knas_int = oxirush_security::nas_5gs::derive_knas_int(
        &kamf,
        oxirush_security::identity::Algorithm::Aes,
    );
    let code = oxirush_security::IntegrityContext::new(
        &knas_int,
        oxirush_security::identity::Algorithm::Aes,
    )
    .mac(
        u32::MAX,
        f::NasConnection::ThreeGpp,
        oxirush_security::Direction::Downlink,
        &longer.value[4..],
    );
    longer.value[..4].copy_from_slice(&code.to_be_bytes());
    mapped(nia, nea).verify_s1_to_n1_container(&longer).unwrap();
}

/// What the container cannot be verified or made with refuses it, and no COUNT
/// is used.
#[test]
fn an_s1_mode_to_n1_mode_container_that_is_refused_uses_no_count() {
    use f::KeySetIdentifierValue::Mapped;
    let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    let ngksi = f::KeySetIdentifier::from_key_set_identifier(Mapped(2)).unwrap();
    let container = mapped(nia, nea).s1_to_n1_container(3, ngksi).unwrap();

    // The UE verifies with the context of the algorithms that the container
    // selects: a context of others, or a container of a reserved algorithm,
    // is refused before any code
    let mut other = mapped(Algorithm::Snow3g, Algorithm::Snow3g);
    let refused = other.verify_s1_to_n1_container(&container).unwrap_err();
    assert!(
        matches!(refused, oxirush_nas::Error::SecurityRefused(_)),
        "{refused}"
    );
    assert_eq!(downlink(&other), next(0));
    let mut reserved = container.clone();
    reserved.value[4] = 0x24;
    let refused = mapped(nia, nea).verify_s1_to_n1_container(&reserved);
    assert!(matches!(
        refused,
        Err(oxirush_nas::Error::SecurityRefused(_))
    ));
    // A value of fewer than the 8 octets of §9.11.2.9
    let mut short = container.clone();
    short.value.truncate(7);
    let refused = mapped(nia, nea).verify_s1_to_n1_container(&short);
    assert_eq!(refused.unwrap_err(), oxirush_nas::Error::BufferTooShort);

    // An NCC above 7, and a context whose downlink COUNTs were all used
    let mut amf = mapped(nia, nea);
    assert!(matches!(
        amf.s1_to_n1_container(8, ngksi),
        Err(oxirush_nas::Error::EncodingError(_))
    ));
    assert_eq!(downlink(&amf), next(0));
    let kamf = f::KAmf::new(&MASTER);
    let exhausted = (next(0), None);
    let mut amf =
        f::SecurityContext::restore_from_kamf(&kamf, nia, nea, exhausted, exhausted).unwrap();
    let refused = amf.s1_to_n1_container(3, ngksi).unwrap_err();
    assert_eq!(refused, oxirush_nas::Error::NasCountExhausted);
    let mut ue =
        f::SecurityContext::restore_from_kamf(&kamf, nia, nea, exhausted, exhausted).unwrap();
    let container = fctx(nia, nea, 0).s1_to_n1_container(3, ngksi).unwrap();
    let refused = ue.verify_s1_to_n1_container(&container).unwrap_err();
    assert_eq!(refused, oxirush_nas::Error::NasCountExhausted);
}

/// TS 24.501 §4.4.2.4 and §9.11.2.7, TS 33.501 §8.3.2 steps 2 and 8: the AMF puts
/// the sequence number of its current downlink NAS COUNT in the N1 mode to S1 mode
/// NAS transparent container, derives KASME' with that COUNT and goes on with the
/// next one. The UE takes the least COUNT above the largest that it received whose
/// 8 low bits are that number (§4.4.3.1), derives KASME' with it, and goes on after
/// it.
#[test]
fn the_n1_mode_to_s1_mode_container_gives_the_downlink_count_by_its_8_low_bits() {
    let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
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
    let wrapped = f::N1ModeToS1ModeNasTransparentContainer::from_sequence_number(0x01);
    assert_eq!(
        ue.verify_n1_to_s1_container(&wrapped),
        Ok(NasCount::new(0x000201).unwrap())
    );
    assert_eq!(downlink(&ue), next(0x000202));
    // The number of a COUNT that the UE received is that of a COUNT above it,
    // never the one received
    let mut ue = fctx(nia, nea, 0x0001ff);
    let received = f::N1ModeToS1ModeNasTransparentContainer::from_sequence_number(0xfe);
    assert_eq!(
        ue.verify_n1_to_s1_container(&received),
        Ok(NasCount::new(0x0002fe).unwrap())
    );
    // No COUNT above the last: refused, and the COUNT stays
    let mut ue = fctx(nia, nea, 0xffffff);
    let beyond = f::N1ModeToS1ModeNasTransparentContainer::from_sequence_number(0x00);
    assert_eq!(
        ue.verify_n1_to_s1_container(&beyond),
        Err(oxirush_nas::Error::NasCountExhausted)
    );
    assert_eq!(downlink(&ue), next(0xffffff));
    let last = f::N1ModeToS1ModeNasTransparentContainer::from_sequence_number(0xff);
    assert_eq!(ue.verify_n1_to_s1_container(&last), Ok(NasCount::MAX));
    assert_eq!(downlink(&ue), None);
    let mut amf = fctx(nia, nea, 0xffffff);
    assert_eq!(amf.n1_to_s1_container().unwrap().1, NasCount::MAX);
    assert_eq!(
        amf.n1_to_s1_container(),
        Err(oxirush_nas::Error::NasCountExhausted)
    );
}

#[test]
fn eps_emm_transport_and_emergency_null_contexts() {
    let data = hex::decode("014500001400000000400100000a0000010a000002").unwrap();
    for nia in [Algorithm::Snow3g, Algorithm::Aes, Algorithm::Zuc] {
        for nea in [
            Algorithm::Null,
            Algorithm::Snow3g,
            Algorithm::Aes,
            Algorithm::Zuc,
        ] {
            for dir in [
                oxirush_nas::Direction::Uplink,
                oxirush_nas::Direction::Downlink,
            ] {
                for payload in [None, Some(data.as_slice())] {
                    let wire = ectx(nia, nea, 17)
                        .protect_emm_transport(payload, dir)
                        .unwrap();
                    assert_eq!(e::Message::decode(&wire).unwrap().encode().unwrap(), wire);
                    let e::Verified {
                        message: decoded,
                        security_header_type: sht,
                        ..
                    } = ectx(nia, nea, 17).unprotect(&wire, dir).unwrap();
                    assert_eq!(
                        sht,
                        e::SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
                    );
                    let e::Message::EmmTransport(body) = decoded else {
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
    let fm = f::Message::new_5gmm(f::GmmStatus::new(f::GmmCause::new(3)));
    let fw = fctx(Algorithm::Null, Algorithm::Null, 0)
        .protect(
            &fm,
            f::SecurityHeaderType::IntegrityProtected,
            oxirush_nas::Direction::Uplink,
            f::NasConnection::ThreeGpp,
        )
        .unwrap();
    let fd = fctx(Algorithm::Null, Algorithm::Null, 0)
        .unprotect(
            &fw,
            oxirush_nas::Direction::Uplink,
            f::NasConnection::ThreeGpp,
        )
        .unwrap()
        .message;
    assert_eq!(fd.encode().unwrap(), fm.encode().unwrap());
    let em = e::Message::new_emm(e::EmmStatus::new(e::EmmCause::new(3)));
    let ew = ectx(Algorithm::Null, Algorithm::Null, 0)
        .protect(
            &em,
            e::SecurityHeaderType::IntegrityProtected,
            oxirush_nas::Direction::Uplink,
        )
        .unwrap();
    let ed = ectx(Algorithm::Null, Algorithm::Null, 0)
        .unprotect(&ew, oxirush_nas::Direction::Uplink)
        .unwrap()
        .message;
    assert_eq!(ed.encode().unwrap(), em.encode().unwrap());
}

/// HMAC-derived NAS keys, AES-CTR plaintext and AES-CMAC were checked independently.
#[test]
fn aes_protected_messages_match_fixed_wire_vectors() {
    let message = f::Message::decode(&fixture(
        include_str!("fixtures/nas-5gs.tsv"),
        "FiveGmmStatus",
    ))
    .unwrap();
    let wire = fctx(Algorithm::Aes, Algorithm::Aes, 17)
        .protect(
            &message,
            f::SecurityHeaderType::IntegrityProtectedAndCiphered,
            oxirush_nas::Direction::Uplink,
            f::NasConnection::ThreeGpp,
        )
        .unwrap();
    assert_eq!(hex::encode(wire), "7e02da1302d81195575472");
    for (name, sht, expected) in [
        (
            "EmmStatus",
            e::SecurityHeaderType::IntegrityProtectedAndCiphered,
            "273d096dfa1179083c",
        ),
        (
            "ControlPlaneServiceRequest-optional",
            e::SecurityHeaderType::IntegrityProtectedAndPartiallyCipheredNasMessage,
            "5796cc8ee911074d107800192c68d48337e736f7600137b1406aedc39ec3434890e24395a557022000d0",
        ),
    ] {
        let message =
            e::Message::decode(&fixture(include_str!("fixtures/nas-eps.tsv"), name)).unwrap();
        let wire = ectx(Algorithm::Aes, Algorithm::Aes, 17)
            .protect(&message, sht, oxirush_nas::Direction::Uplink)
            .unwrap();
        assert_eq!(hex::encode(wire), expected, "{name}");
    }
}
