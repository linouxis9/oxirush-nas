// The Rust blocks of the README and of the documentation, each as a function.
// `tests/readme.rs` writes this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what its page shows.
macro_rules! println {
    () => {
        PRINTED.with(|printed| printed.borrow_mut().push('\n'))
    };
    ($($argument:tt)*) => {{
        let line = format!($($argument)*);
        PRINTED.with(|printed| {
            let mut printed = printed.borrow_mut();
            printed.push_str(&line);
            printed.push('\n');
        })
    }};
}

/// What `block` prints.
pub fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

pub const BLOCKS: &[fn()] = &[
    block_1,
    block_2,
    block_3,
    block_4,
    block_5,
    block_6,
    block_7,
    block_8,
    block_9,
    block_10,
    block_11,
    block_12,
    block_13,
    block_14,
    block_15,
    block_16,
    block_17,
    block_18,
    block_19,
    block_20,
    block_21,
    block_22,
    block_23,
    block_24,
];

/// The Rust block 1 of README.md.
fn block_1() {
    use oxirush_nas::nas_5gs::*;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // Decode a REGISTRATION REQUEST
        let bytes = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000")?;
        let msg = Nas5gsMessage::decode(&bytes)?;
        println!("{msg}");

        // Read its IEs through typed accessors
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = &msg {
            let kind = reg.fgs_registration_type.registration_type().ok_or("a reserved type")?;
            let plmn = reg.fgs_mobile_identity.plmn().ok_or("no PLMN")?;
            println!("{kind:?} in MCC {}, MNC {}", plmn.mcc(), plmn.mnc());
        }

        // `validate()` finds nothing wrong, and it encodes back to the same octets
        println!("{} findings, same octets: {}", msg.validate().len(), msg.encode()? == bytes);

        // The answer, a REGISTRATION REJECT with cause #22 and T3346 of ten minutes:
        // `new()` takes the mandatory IEs, and `with_*()` adds the others
        let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
        let t3346 = NasGprsTimer2::from_seconds(600)?;
        let answer = Nas5gsMessage::new_5gmm(NasRegistrationReject::new(cause).with_t3346_value(t3346));
        println!("{answer}: {}", hex::encode(answer.encode()?));
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 2 of README.md.
fn block_2() {
    use oxirush_nas::nas_5gs::*;
    use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
    use oxirush_security::nas_5gs::{ResStar, Supi, derive_kamf, derive_kausf, derive_kseaf};
    use oxirush_security::Rand;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // The subscriber of TS 35.208 test set 1, in the UDM and in the USIM
        let k = K::from_slice(&hex::decode("465b5ce8b199b49faa5f0a2ee238a6bc")?)?;
        let opc = Opc::from_slice(&hex::decode("cd63cb71954a9f4e48a5994e37a02baf")?)?;
        let subscriber = Milenage::new(&k, &opc);
        let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

        // REGISTRATION REQUEST, plain. Its SUCI has the null scheme: the SUPI is in it
        let received = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000")?;
        let registration = Nas5gsMessage::decode(&received)?;
        println!("UE  {registration}");
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(request)) = &registration else {
            unreachable!()
        };
        let Some(Suci::Imsi(suci)) = request.fgs_mobile_identity.as_suci() else { unreachable!() };
        let supi = Supi::from(suci.imsi().ok_or("an MSIN that is concealed")?);
        println!("AMF {supi}");

        // AUTHENTICATION REQUEST: a challenge of MILENAGE, under ngKSI 0
        let rand = Rand::from_slice(&hex::decode("23553cbe9637a89d218ae64dae47bf35")?)?;
        let (sqn, amf) = (Sqn::try_from(0xff9b_b4d0_b607)?, Amf::new(&[0xb9, 0xb9]));
        let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
        let ngksi = NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Native(0))?;
        let challenge = NasAuthenticationRequest::new(ngksi, NasAbba::new(vec![0, 0]))
            .with_authentication_parameter_rand(NasAuthenticationParameterRand::from_rand(
                *rand.as_octets(),
            ))
            .with_authentication_parameter_autn(NasAuthenticationParameterAutn::from_autn(
                *vector.autn().as_octets(),
            ));
        println!("AMF {}", Nas5gsMessage::new_5gmm(challenge));

        // The USIM checks the AUTN and answers with RES*
        let usim = subscriber.check_autn(&rand, vector.autn())?;
        let res_star = *usim.res_star(sn_name)?.as_octets();
        let parameter = NasAuthenticationResponseParameter::from_res_star(res_star);
        let response = NasAuthenticationResponse::new().with_authentication_response_parameter(parameter);
        let sent = Nas5gsMessage::new_5gmm(response).encode()?;

        // The AMF compares RES* with XRES*, then derives KAMF from the SUPI and the ABBA
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::AuthenticationResponse(response)) =
            Nas5gsMessage::decode(&sent)?
        else {
            unreachable!()
        };
        let parameter = response.authentication_response_parameter.ok_or("no RES*")?;
        let res_star = ResStar::new(parameter.res_star().ok_or("no RES* of 16 octets")?);
        println!("UE  RES* accepted: {}", vector.xres_star(sn_name)?.accepts(&res_star));
        let k_ausf = derive_kausf(vector.ck(), vector.ik(), sn_name, vector.autn())?;
        let k_seaf = derive_kseaf(&k_ausf, sn_name)?;
        let k_amf = derive_kamf(&k_seaf, &supi, &[0, 0])?;

        // The UE derives the same KAMF. Each side keeps a context: the NAS keys,
        // the algorithms and the NAS COUNTs
        let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
        let mut amf_context = NasSecurityContext::from_fresh_kamf(&k_amf, nia, nea)?;
        let mut ue_context = NasSecurityContext::from_fresh_kamf(&k_amf, nia, nea)?;

        // SECURITY MODE COMMAND replays the UE security capability. It is integrity
        // protected with the new context, and not ciphered
        let capability = request.ue_security_capability.clone().ok_or("no UE security capability")?;
        let algorithms = NasSecurityAlgorithms::from_algorithms(nea, nia);
        let command = Nas5gsMessage::new_5gmm(NasSecurityModeCommand::new(algorithms, ngksi, capability));
        let header = Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext;
        let sent = amf_context.protect(&command, header, Direction::Downlink)?;
        println!("AMF {}", ue_context.unprotect(&sent, Direction::Downlink)?.message);

        // SECURITY MODE COMPLETE, integrity protected and ciphered, has the whole
        // REGISTRATION REQUEST in its NAS message container
        let container = NasMessageContainer::from_nas_message(&registration)?;
        let complete = NasSecurityModeComplete::new().with_nas_message_container(container);
        let header = Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext;
        let complete = Nas5gsMessage::new_5gmm(complete);
        let sent = ue_context.protect(&complete, header, Direction::Uplink)?;
        let verified = amf_context.unprotect(&sent, Direction::Uplink)?;
        println!("UE  {}, NAS COUNT {}", verified.message, verified.count.get());

        // REGISTRATION ACCEPT: a 5G-GUTI, two tracking areas and a slice, ciphered
        let plmn = Plmn::new("208", "93")?;
        let guti = Guti::new(plmn, 0xca, 0x3fe, 0, 0x1122_3344)?;
        let result = NasFGsRegistrationResult::from_result(RegistrationResult::ThreeGppAccess);
        let accept = NasRegistrationAccept::new(result)
            .with_fg_guti(NasFGsMobileIdentity::from_guti(guti))
            .with_tai_list(NasFGsTrackingAreaIdentityList::from_plmn_tacs(&plmn, &[1, 2])?)
            .with_allowed_nssai(NasNssai::from_snssais(&[NasSNssai::from_sst_sd(1, None)])?);
        let accept = Nas5gsMessage::new_5gmm(accept);
        let header = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
        let sent = amf_context.protect(&accept, header, Direction::Downlink)?;
        println!("AMF {}", ue_context.unprotect(&sent, Direction::Downlink)?.message);
        println!("    {}", hex::encode(&sent));
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 3 of README.md.
fn block_3() {
    use oxirush_nas::nas_eps::*;
    use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
    use oxirush_security::nas_eps::derive_kasme;
    use oxirush_security::{Plmn, Rand};

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        let k = K::from_slice(&hex::decode("465b5ce8b199b49faa5f0a2ee238a6bc")?)?;
        let opc = Opc::from_slice(&hex::decode("cd63cb71954a9f4e48a5994e37a02baf")?)?;
        let subscriber = Milenage::new(&k, &opc);

        // ATTACH REQUEST, plain, with an IMSI
        let attach = NasEpsMessage::decode(&hex::decode("07410108298039000000001002e0e000040201d031")?)?;
        println!("UE  {attach}");
        let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &attach else {
            unreachable!()
        };

        // AUTHENTICATION REQUEST, then the RES of the USIM against XRES
        let rand = Rand::from_slice(&hex::decode("23553cbe9637a89d218ae64dae47bf35")?)?;
        let amf = Amf::new(&[0xb9, 0xb9]);
        let vector = subscriber.authentication_vector(&rand, &Sqn::try_from(32)?, &amf);
        let ksi = NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Native(0))?;
        let challenge = NasAuthenticationRequest::new(
            ksi,
            NasAuthenticationParameterRand::from_rand(*rand.as_octets()),
            NasAuthenticationParameterAutn::from_autn(*vector.autn().as_octets()),
        );
        println!("MME {}", NasEpsMessage::new_emm(challenge));
        let usim = subscriber.check_autn(&rand, vector.autn())?;
        println!("UE  RES accepted: {}", vector.xres().accepts(usim.res()));

        // KASME, from the CK, the IK and the AUTN of the vector and the serving network
        let kasme = derive_kasme(vector.ck(), vector.ik(), Plmn::new("208", "93")?, vector.autn());
        let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
        let mut mme_context = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea)?;
        let mut ue_context = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea)?;

        // SECURITY MODE COMMAND replays the algorithms of the UE network capability
        let capability = NasUeSecurityCapability::from_ue_network_capability(&request.ue_network_capability);
        let algorithms = NasSecurityAlgorithms::from_algorithms(eea, eia);
        let command = NasEpsMessage::new_emm(NasSecurityModeCommand::new(algorithms, ksi, capability));
        let header = NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext;
        let sent = mme_context.protect(&command, header, Direction::Downlink)?;
        println!("MME {}", ue_context.unprotect(&sent, Direction::Downlink)?.message);

        // SECURITY MODE COMPLETE, then the ATTACH ACCEPT with the default bearer
        let complete = NasEpsMessage::new_emm(NasSecurityModeComplete::new());
        let header = NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext;
        let sent = ue_context.protect(&complete, header, Direction::Uplink)?;
        println!("UE  {}", mme_context.unprotect(&sent, Direction::Uplink)?.message);
        let accept = hex::decode("07420121060002f839000100155201c101090908696e7465726e657405010a000001")?;
        let accept = NasEpsMessage::decode(&accept)?;
        let header = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
        let sent = mme_context.protect(&accept, header, Direction::Downlink)?;
        println!("MME {}", ue_context.unprotect(&sent, Direction::Downlink)?.message);
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 4 of README.md.
fn block_4() {
    use oxirush_nas::nas_5gs::*;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
        let mut msg = Nas5gsMessage::decode(&hex::decode("7e0044165f012a")?)?;

        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(reject)) = &mut msg {
            // Read a mandatory IE, an optional IE that is there and one that is not
            assert_eq!(reject.fgmm_cause.cause(), Some(GmmCause::Congestion));
            let t3346 = reject.t3346_value.as_ref().map(NasGprsTimer2::to_seconds);
            assert_eq!(t3346, Some(Some(600)));
            assert!(reject.t3502_value.is_none());

            // Another cause, T3346 taken out and T3502 added
            reject.fgmm_cause = NasFGmmCause::from_cause(GmmCause::IllegalUe);
            reject.clear_t3346_value();
            reject.set_t3502_value(NasGprsTimer2::from_seconds(720)?);
        }

        println!("{msg}");
        assert_eq!(hex::encode(msg.encode()?), "7e00440316012c");
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 5 of README.md.
fn block_5() {
    use oxirush_nas::nas_5gs::*;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // PDU SESSION ESTABLISHMENT REQUEST for PDU session 5, with PTI 1
        let rate = NasIntegrityProtectionMaximumDataRate::new(0xffff);
        let request = Nas5gsMessage::new_5gsm(NasPduSessionEstablishmentRequest::new(rate), 5, 1);

        // UL NAS TRANSPORT has it in its payload container
        let transport = NasUlNasTransport::new(
            NasPayloadContainerType::from_kind(PayloadContainerKind::N1SmInformation),
            NasPayloadContainer::from_n1_sm_message(&request)?,
        )
        .with_pdu_session_id(NasPduSessionIdentity2::from_pdu_session_id(5))
        .with_request_type(NasRequestType::from_request_type(RequestTypeValue::InitialRequest))
        .with_dnn(NasDnn::from_string("internet")?);
        let octets = Nas5gsMessage::new_5gmm(transport).encode()?;
        println!("{}", hex::encode(&octets));

        // The AMF reads what it routes the container by, and the SMF the message
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) =
            Nas5gsMessage::decode(&octets)?
        else {
            unreachable!()
        };
        let kind = transport.payload_container_type.kind();
        assert_eq!(kind, Some(PayloadContainerKind::N1SmInformation));
        assert_eq!(transport.pdu_session_id.map(|id| id.pdu_session_id()), Some(5));
        println!("{}", transport.payload_container.decode_as_n1_sm_message()?);
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 6 of README.md.
fn block_6() {
    use oxirush_nas::nas_5gs::{Nas5gsMessage, Validate};

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION REJECT whose T3346 value is there twice, then an unknown IE
        // that is encoded as "comprehension required"
        let bytes = hex::decode("7e0044165f012a5f012a0400")?;
        let msg = Nas5gsMessage::decode(&bytes)?;

        // What `validate()` finds
        for finding in msg.validate() {
            println!("{finding}");
        }

        // Both are kept as they came, and go out again
        assert_eq!(msg.unknown_ies().len(), 2);
        assert!(msg.unknown_ies().get(1).is_some_and(|ie| ie.is_comprehension_required()));
        assert_eq!(bytes, msg.encode()?);
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 7 of README.md.
fn block_7() {
    use oxirush_nas::nas_5gs::*;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION REQUEST whose 5G-GUTI is one octet short
        let octets = hex::decode("7e004179000af202f839cafe001122332e02a020")?;
        let received = Nas5gsMessage::decode(&octets);
        let error = received.clone().err();
        if let Some(error) = &error {
            println!("{error}");
        }

        // What a network answers: 5GMM STATUS with cause #96
        if let Some(answer) = Nas5gsMessage::answer_to(&octets, &received, Direction::Uplink) {
            println!("{answer}");
            assert_eq!(answer.encode()?, [0x7e, 0x00, 0x64, 0x60]);
        }

        // What the message has, to log it or to treat it all the same
        let (message, faults) = Nas5gsMessage::decode_lenient(&octets)?;
        assert_eq!(faults.first(), error.as_ref());
        println!("{message}");

        // A message that is too short is ignored: no answer
        let short = [0x7e, 0x00];
        let received = Nas5gsMessage::decode(&short);
        assert!(Nas5gsMessage::answer_to(&short, &received, Direction::Uplink).is_none());
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 8 of README.md.
fn block_8() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use oxirush_nas::tree;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
        let reject = Nas5gsMessage::decode(&hex::decode("7e0044165f012a")?)?;
        println!("{}", reject.to_tree());

        // In its view, an IE is changed by its value, one comes in by its octets,
        // and one goes out
        let mut view = reject.to_view();
        println!("{}", view["t3346-value"]);
        view["5gmm-cause"]["value"] = tree!("illegal-ue");
        view["t3502-value"] = tree!({"octets": "2c"});
        view["t3346-value"] = tree!(null);
        let edited = reject.with_view(view)?;
        println!("{}", edited.to_tree());

        // A message written from its tree
        let status = tree!({"message-type": "5gmm-status", "5gmm-cause": "congestion"});
        let status = Nas5gsMessage::from_tree(status)?;
        assert_eq!(status.encode()?, [0x7e, 0x00, 0x64, 0x16]);
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 9 of README.md.
fn block_9() {
    use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
    use oxirush_nas::tree;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
        let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101")?;
        let accept = Nas5gsMessage::decode(&bytes)?;
        let mut tree = accept.to_view();

        // A value by its path, and each entry of a list with `*`
        for path in ["/nas/5g-guti/value/guti/plmn", "/NAS/Allowed NSSAI/value/*/SST"] {
            for value in view::select(&tree, path)? {
                println!("{value}");
            }
        }

        // A value is set at its path, an optional IE added by its value, and an
        // entry put at the end of a list (`-`)
        view::set(&mut tree, "/nas/5g-guti/value/guti/tmsi", tree!("0xdeadbeef"))?;
        view::set(&mut tree, "/nas/t3512-value/value", tree!(3600))?;
        view::insert(&mut tree, "/nas/allowed-nssai/value/-", tree!({"sst": 2}))?;
        let edited = accept.with_view(tree)?;
        println!("{}", hex::encode(edited.encode()?));

        // A name that the message does not have is an error
        if let Err(wrong) = view::select(&accept.to_view(), "/nas/t3512/value") {
            println!("{wrong}");
        }
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 1 of src/lib.rs.
fn block_10() {
    use oxirush_nas::nas_5gs::*;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // Decode a REGISTRATION REQUEST
        let bytes = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000")?;
        let msg = Nas5gsMessage::decode(&bytes)?;
        println!("{msg}");

        // Read its IEs through typed accessors
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = &msg {
            let kind = reg.fgs_registration_type.registration_type();
            assert_eq!(kind, Some(RegistrationType::InitialRegistration));

            let identity = &reg.fgs_mobile_identity;
            assert_eq!(identity.identity_type(), Some(MobileIdentityType::Suci));

            // The PLMN identity names the network: a country code and a network code
            if let Some(plmn) = identity.plmn() {
                println!("MCC={}, MNC={}", plmn.mcc(), plmn.mnc());
            }
        }

        // It passes every check that can be made on a single message, and encodes
        // to the octets that were decoded
        assert!(msg.validate().is_empty());
        assert_eq!(bytes, msg.encode()?);

        // Build the answer, a REGISTRATION REJECT with cause #22 and a T3346 value
        // of ten minutes: `new()` takes the mandatory IEs, `with_*()` adds the others
        let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
        let t3346 = NasGprsTimer2::from_seconds(600)?;
        let reject = NasRegistrationReject::new(cause).with_t3346_value(t3346);
        let answer = Nas5gsMessage::new_5gmm(reject);
        println!("{answer}");

        // Encode it
        assert_eq!(hex::encode(answer.encode()?), "7e0044165f012a");
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 2 of src/lib.rs.
fn block_11() {
    use oxirush_nas::nas_5gs::*;

    // A 5G-GUTI, two tracking areas of one PLMN and two S-NSSAIs
    let plmn = Plmn::new("208", "93").unwrap();
    let guti = Guti::new(plmn, 0xca, 0x3fe, 0, 0x1122_3344).unwrap();
    let tacs = [1, 2];
    let slices = [NasSNssai::from_sst_sd(1, None), NasSNssai::from_sst_sd(1, Some([1, 2, 3]))];

    // REGISTRATION ACCEPT with them
    let result = NasFGsRegistrationResult::from_result(RegistrationResult::ThreeGppAccess);
    let accept = NasRegistrationAccept::new(result)
        .with_fg_guti(NasFGsMobileIdentity::from_guti(guti))
        .with_tai_list(NasFGsTrackingAreaIdentityList::from_plmn_tacs(&plmn, &tacs).unwrap())
        .with_allowed_nssai(NasNssai::from_snssais(&slices).unwrap());
    let accept = Nas5gsMessage::new_5gmm(accept);
    let octets = accept.encode().unwrap();
    println!("{}", hex::encode(&octets));
    println!("{accept}");

    // The other end reads them
    let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationAccept(read)) =
        Nas5gsMessage::decode(&octets).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(read.fg_guti.unwrap().as_guti(), Some(guti));
    assert_eq!(read.tai_list.unwrap().entries()[0].tacs(), tacs);
    let slices = read.allowed_nssai.unwrap().parse_allowed();
    assert_eq!((slices[1].sst, slices[1].sd), (1, Some([1, 2, 3])));
}

/// The Rust block 3 of src/lib.rs.
fn block_12() {
    #[cfg(feature = "security")] {
    use oxirush_nas::nas_5gs::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, KAmf, Nas5gsMessage,
        Nas5gsSecurityHeaderType, NasSecurityContext,
    };

    // The two ends of a link have the same KAMF, the key that the UE and
    // the network share after authentication, and the same algorithms
    let kamf = KAmf::new(&[0x11; 32]);
    let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
    let mut network = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let mut ue = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();

    // The network protects a 5GMM STATUS: MAC, then ciphering
    let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    let header_type = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
    let octets = network.protect(&status, header_type, Direction::Downlink).unwrap();
    assert_eq!(octets.len(), 7 + 4);

    // The UE checks the MAC, deciphers and decodes
    let received = ue.unprotect(&octets, Direction::Downlink).unwrap();
    assert_eq!(received.message, status);
    }
}

/// The Rust block 4 of src/lib.rs.
fn block_13() {
    #[cfg(feature = "serde")] {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use oxirush_nas::tree;

    let reject = Nas5gsMessage::decode(&hex::decode("7e0044165f012a").unwrap()).unwrap();
    let tree = tree!({
        "message-type": "registration-reject",
        "5gmm-cause": "congestion",
        "t3346-value": 600,
    });
    assert_eq!(reject.to_tree(), tree);
    assert_eq!(Nas5gsMessage::from_tree(tree).unwrap(), reject);
    }
}

/// The Rust block 1 of src/nas_eps/mod.rs.
fn block_14() {
    use oxirush_nas::nas_eps::*;

    // Decode an ATTACH REQUEST with an IMSI and a PDN CONNECTIVITY REQUEST
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
    let msg = NasEpsMessage::decode(&bytes).unwrap();
    println!("{msg}");
    assert!(msg.validate().is_empty());

    // Read its IEs, and the ESM message in its container
    if let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &msg {
        let imsi = request.eps_mobile_identity.as_imsi().unwrap();
        assert_eq!(imsi.as_str(), "208930000000001");
        assert!(request.ue_network_capability.supports_eea(2));

        let esm = request.esm_message_container.decode_as_esm_message().unwrap();
        println!("{esm}");
    }

    // It encodes to the octets that were decoded
    assert_eq!(bytes, msg.encode().unwrap());

    // Build an ATTACH REJECT, cause #3, and encode it
    let cause = NasEmmCause::from_cause(EmmCause::IllegalUe);
    let reject = NasAttachReject::new(cause);
    let answer = NasEpsMessage::new_emm(reject);
    assert_eq!(answer.encode().unwrap(), [0x07, 0x44, 0x03]);
}

/// The Rust block 1 of src/nas_5gs/security.rs.
fn block_15() {
    use oxirush_nas::nas_5gs::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, KAmf, Nas5gsMessage,
        Nas5gsSecurityHeaderType, NasCount, NasSecurityContext,
    };

    // REGISTRATION REJECT, cause #3
    let msg = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();

    // The two ends of one link: the same KAMF and the same algorithms
    let kamf = KAmf::new(&[0x11; 32]);
    let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
    let mut tx = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let mut rx = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();

    // Protect outbound: integrity and ciphering
    let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
    let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();

    // Unprotect inbound: MAC check, deciphering and decoding
    let verified = rx.unprotect(&protected, Direction::Downlink).unwrap();
    assert_eq!(verified.message, msg);
    assert_eq!(verified.security_header_type, sht);
    assert_eq!(verified.count, NasCount::ZERO);
}

/// The Rust block 1 of src/nas_eps/security.rs.
fn block_16() {
    use oxirush_nas::nas_eps::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, KAsme, NasCount, NasEpsMessage,
        NasEpsSecurityHeaderType, NasSecurityContext,
    };

    // ATTACH REJECT, cause #3
    let msg = NasEpsMessage::decode(&[0x07, 0x44, 0x03]).unwrap();

    // The two ends of one link: the same KASME and the same algorithms
    let kasme = KAsme::new(&[0x11; 32]);
    let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
    let mut tx = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
    let mut rx = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();

    // Protect outbound: integrity and ciphering
    let sht = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
    let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();

    // Unprotect inbound: MAC check, deciphering and decoding
    let verified = rx.unprotect(&protected, Direction::Downlink).unwrap();
    assert_eq!(verified.message, msg);
    assert_eq!(verified.security_header_type, sht);
    assert_eq!(verified.count, NasCount::ZERO);
}

/// The Rust block 1 of src/view.rs.
fn block_17() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;

    // 5GMM STATUS, cause #22
    let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();

    // Its tree, then its view
    println!("{}", status.to_tree());
    println!("{:#}", status.to_view());
}

/// The Rust block 2 of src/view.rs.
fn block_18() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use oxirush_nas::tree;

    // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
    let bytes = hex::decode("7e0044165f012a").unwrap();
    let reject = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{}", reject.to_view()["t3346-value"]);

    // A T3346 value of two octets, where the specification has one
    let mut view = reject.to_view();
    view["t3346-value"]["octets"] = tree!("2a2b");
    let edited = reject.with_view(view).unwrap();

    // The IE and the octets of the edited message
    println!("{}", edited.to_view()["t3346-value"]);
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044165f022a2b");

    // The 5GMM cause has no length: it is one octet
    let mut view = reject.to_view();
    view["5gmm-cause"]["octets"] = tree!("ffff");
    println!("{}", reject.with_view(view).unwrap_err());
}

/// The Rust block 3 of src/view.rs.
fn block_19() {
    use oxirush_nas::nas_5gs::{Nas5gmmMessageType, Nas5gsMessage};
    use oxirush_nas::tree;

    // A REGISTRATION REJECT by the name of its type and of its IEs
    let reject = Nas5gsMessage::from_tree(tree!({
        "message-type": "registration-reject",
        "5gmm-cause": "congestion",
        "t3346-value": 600,
    }))
    .unwrap();
    assert_eq!(hex::encode(reject.encode().unwrap()), "7e0044165f012a");

    // A 5GSM message writes the fields of its header that its type does not decide
    let complete = Nas5gsMessage::from_tree(tree!({
        "message-type": "pdu-session-release-complete",
        "pdu-session-identity": 5,
        "procedure-transaction-identity": 1,
    }))
    .unwrap();
    assert_eq!(hex::encode(complete.encode().unwrap()), "2e0501d4");

    // A mandatory IE that is left out is an error
    let tree = tree!({"message-type": "registration-reject"});
    println!("{}", Nas5gsMessage::from_tree(tree).unwrap_err());

    // A value that its IE cannot carry says the member and the limit
    let tree = tree!({"message-type": "service-accept", "pdu-session-status": [5, 16]});
    println!("{}", Nas5gsMessage::from_tree(tree).unwrap_err());

    // What a message of a type can have, in the order of the message
    println!("{:?}", Nas5gmmMessageType::AuthenticationFailure.view_names());
}

/// The Rust block 4 of src/view.rs.
fn block_20() {
    use oxirush_nas::nas_eps::NasEpsMessage;
    use oxirush_nas::tree;

    // ATTACH REQUEST with a PDN CONNECTIVITY REQUEST in its ESM message container
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
    let attach = NasEpsMessage::decode(&bytes).unwrap();
    println!("{:#}", attach.to_tree()["esm-message-container"]);

    // In a view, the value of the container is the view of its message
    let mut view = attach.to_view();
    view["esm-message-container"]["value"]["pdn-type"]["value"] = tree!("ipv6");
    let edited = attach.with_view(view).unwrap();

    // The PDN type and the octets of the edited message
    println!("{}", edited.to_tree()["esm-message-container"]["pdn-type"]);
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "07410108298039000000001002e0e000040201d021"
    );
}

/// The Rust block 5 of src/view.rs.
fn block_21() {
    use oxirush_nas::nas_eps::NasEpsMessage;
    use oxirush_nas::tree;

    // PDN CONNECTIVITY REQUEST with the credentials of PAP and a request for
    // the address of a DNS server
    let request = NasEpsMessage::from_tree(tree!({
        "message-type": "pdn-connectivity-request",
        "eps-bearer-identity": 0,
        "procedure-transaction-identity": 1,
        "pdn-type": "ipv4",
        "request-type": "initial",
        "protocol-configuration-options": [
            {"pap": {
                "code": "authenticate-request",
                "identifier": 1,
                "peer-id": "user",
                "password": "secret",
            }},
            "dns-server-ipv4-address-request",
        ],
    }))
    .unwrap();
    assert_eq!(
        hex::encode(request.encode().unwrap()),
        "0201d011271780c0231001010010047573657206736563726574000d00"
    );

    // The network answers in an ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST
    let bytes = hex::decode(
        "5201c101090908696e7465726e657405010a000001271080c023050201000500000d0408080808"
    ).unwrap();
    let answer = NasEpsMessage::decode(&bytes).unwrap();
    println!("{:#}", answer.to_tree()["protocol-configuration-options"]);
}

/// The Rust block 6 of src/view.rs.
fn block_22() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use oxirush_nas::tree;

    // REGISTRATION ACCEPT with an extended emergency number list: 112
    let bytes = hex::decode("7e004201017a0005000211f200").unwrap();
    let accept = Nas5gsMessage::decode(&bytes).unwrap();
    let mut view = accept.to_view();
    println!("{}", view["extended-emergency-number-list"]["value"]);

    // A number of the police is added
    let numbers = &mut view["extended-emergency-number-list"]["value"]["numbers"];
    let police = tree!({"digits": "17", "sub-services": "police"});
    numbers.as_array_mut().unwrap().push(police);
    let edited = accept.with_view(view).unwrap();

    // The list of the edited message
    println!("{}", edited.to_view()["extended-emergency-number-list"]["octets"]);
}

/// The Rust block 7 of src/view.rs.
fn block_23() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use oxirush_nas::tree;

    // 5GMM STATUS under an integrity protected header
    let bytes = hex::decode("7e01e73b901b007e006416").unwrap();
    let protected = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{:#}", protected.to_tree());

    // An edit that leaves the old MAC in the security header is refused
    let mut view = protected.to_view();
    view["5gmm-cause"]["value"] = tree!("illegal-ue");
    println!("{}", protected.with_view(view.clone()).unwrap_err());

    // The view writes the code of the edited message
    view["security-header"]["value"]["message-authentication-code"] = tree!("0x01020304");
    let edited = protected.with_view(view).unwrap();
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e0101020304007e006403");

    // A message that is ciphered has its octets
    let bytes = hex::decode("7e024b708bc300026ff75c").unwrap();
    let ciphered = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{}", ciphered.to_tree()["ciphered-message"]);
}

/// The Rust block 8 of src/view.rs.
fn block_24() {
    use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
    use oxirush_nas::tree;

    // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = Nas5gsMessage::decode(&bytes).unwrap();
    let tree = accept.to_view();

    // Each value with the path that selects it
    for (path, value) in view::paths(&tree) {
        println!("{path} = {value}");
    }

    // A coded value by its name, an identity by its parts, and the octets beside
    let select = |path| view::select(&tree, path).unwrap();
    assert_eq!(select("/nas/message-type/value"), [&tree!("registration-accept")]);
    assert_eq!(select("/nas/5gs-registration-result/value/result"), [&tree!("3gpp-access")]);
    assert_eq!(select("/nas/5g-guti/value/guti/tmsi"), [&tree!(0x1122_3344)]);
    assert_eq!(select("/nas/allowed-nssai/octets"), [&tree!("0101")]);

    // A name in any case, and `*` for each entry of a list
    assert_eq!(select("/NAS/Allowed NSSAI/value/*/SST"), [&tree!(1)]);

    // An optional IE that the message does not have selects nothing
    assert!(select("/nas/t3512-value/value").is_empty());

    // A name that the message does not have is an error
    assert!(view::select(&tree, "/nas/t3512/value").is_err());
}
