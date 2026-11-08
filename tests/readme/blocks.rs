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
    use oxirush_nas::Validate;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // Decode a REGISTRATION REQUEST
        let bytes = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000")?;
        let msg = Message::decode(&bytes)?;
        println!("{msg}");

        // Read its IEs through typed accessors
        if let Message::Gmm(_, GmmMessage::RegistrationRequest(reg)) = &msg {
            let kind = reg.fgs_registration_type.registration_type().ok_or("a reserved type")?;
            let plmn = reg.fgs_mobile_identity.plmn().ok_or("no PLMN")?;
            println!("{kind:?} in MCC {}, MNC {}", plmn.mcc(), plmn.mnc());
        }

        // `validate()` finds nothing wrong, and it encodes back to the same octets
        println!("{} findings, same octets: {}", msg.validate().len(), msg.encode()? == bytes);

        // The answer, a REGISTRATION REJECT with cause #22 and T3346 of ten minutes:
        // `new()` takes the mandatory IEs, and `with_*()` adds the others
        let cause = GmmCause::from_cause(GmmCauseValue::Congestion);
        let t3346 = GprsTimer2::from_seconds(600)?;
        let answer = Message::new_5gmm(RegistrationReject::new(cause).with_t3346_value(t3346));
        println!("{answer}: {}", hex::encode(answer.encode()?));
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 2 of README.md.
fn block_2() {
    use oxirush_nas::identity::Algorithm;
    use oxirush_nas::nas_5gs::*;
    use oxirush_nas::Direction;
    use oxirush_nas::identity::{Guti5g, Plmn, Suci, Supi};
    use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
    use oxirush_security::nas_5gs::{ResStar, derive_kamf, derive_kausf, derive_kseaf};
    use oxirush_security::Rand;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // The subscriber of TS 35.208 test set 1, in the UDM and in the USIM
        let k = K::from_slice(&hex::decode("465b5ce8b199b49faa5f0a2ee238a6bc")?)?;
        let opc = Opc::from_slice(&hex::decode("cd63cb71954a9f4e48a5994e37a02baf")?)?;
        let subscriber = Milenage::new(&k, &opc);
        let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

        // REGISTRATION REQUEST, plain. Its SUCI has the null scheme: the SUPI is in it
        let received = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000")?;
        let registration = Message::decode(&received)?;
        println!("UE  {registration}");
        let Message::Gmm(_, GmmMessage::RegistrationRequest(request)) = &registration else {
            unreachable!()
        };
        let Some(Suci::Imsi(suci)) = request.fgs_mobile_identity.as_suci() else { unreachable!() };
        let supi = Supi::from(suci.imsi().ok_or("an MSIN that is concealed")?);
        println!("AMF {supi}");

        // AUTHENTICATION REQUEST: a challenge of MILENAGE, under ngKSI 0
        let rand = Rand::from_slice(&hex::decode("23553cbe9637a89d218ae64dae47bf35")?)?;
        let (sqn, amf) = (Sqn::try_from(0xff9b_b4d0_b607)?, Amf::new(&[0xb9, 0xb9]));
        let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
        let ngksi = KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Native(0))?;
        let challenge = AuthenticationRequest::new(ngksi, Abba::new(vec![0, 0]))
            .with_authentication_parameter_rand(AuthenticationParameterRand::from_rand(
                *rand.as_octets(),
            ))
            .with_authentication_parameter_autn(AuthenticationParameterAutn::from_autn(
                *vector.autn().as_octets(),
            ));
        println!("AMF {}", Message::new_5gmm(challenge));

        // The USIM checks the AUTN and answers with RES*
        let usim = subscriber.check_autn(&rand, vector.autn())?;
        let res_star = *usim.res_star(sn_name)?.as_octets();
        let parameter = AuthenticationResponseParameter::from_res_star(res_star);
        let response = AuthenticationResponse::new().with_authentication_response_parameter(parameter);
        let sent = Message::new_5gmm(response).encode()?;

        // The AMF compares RES* with XRES*, then derives KAMF from the SUPI and the ABBA
        let Message::Gmm(_, GmmMessage::AuthenticationResponse(response)) =
            Message::decode(&sent)?
        else {
            unreachable!()
        };
        let parameter = response.authentication_response_parameter.ok_or("no RES*")?;
        let res_star = ResStar::new(parameter.res_star().ok_or("no RES* of 16 octets")?);
        println!("UE  RES* accepted: {}", vector.xres_star(sn_name)?.accepts(&res_star));
        let k_ausf = derive_kausf(vector.ck(), vector.ik(), sn_name, vector.autn())?;
        let k_seaf = derive_kseaf(&k_ausf, sn_name)?;
        let k_amf = derive_kamf(&k_seaf, supi.identity(), &[0, 0])?;

        // The UE derives the same KAMF. Each side keeps a context: the NAS keys,
        // the algorithms and the NAS COUNTs of each access, here 3GPP access
        let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
        let mut amf_context = SecurityContext::from_fresh_kamf(&k_amf, nia, nea)?;
        let mut ue_context = SecurityContext::from_fresh_kamf(&k_amf, nia, nea)?;
        let access = NasConnection::ThreeGpp;

        // SECURITY MODE COMMAND replays the UE security capability. It is integrity
        // protected with the new context, and not ciphered
        let capability = request.ue_security_capability.clone().ok_or("no UE security capability")?;
        let algorithms = SecurityAlgorithms::from_algorithms(nea, nia);
        let command = Message::new_5gmm(SecurityModeCommand::new(algorithms, ngksi, capability));
        let header = SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext;
        let sent = amf_context.protect(&command, header, Direction::Downlink, access)?;
        println!("AMF {}", ue_context.unprotect(&sent, Direction::Downlink, access)?.message);

        // SECURITY MODE COMPLETE, integrity protected and ciphered, has the whole
        // REGISTRATION REQUEST in its NAS message container
        let container = MessageContainer::from_nas_message(&registration)?;
        let complete = SecurityModeComplete::new().with_nas_message_container(container);
        let header = SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext;
        let complete = Message::new_5gmm(complete);
        let sent = ue_context.protect(&complete, header, Direction::Uplink, access)?;
        let verified = amf_context.unprotect(&sent, Direction::Uplink, access)?;
        println!("UE  {}, NAS COUNT {}", verified.message, verified.count.get());

        // REGISTRATION ACCEPT: a 5G-GUTI, two tracking areas and a slice, ciphered
        let plmn = Plmn::new("208", "93")?;
        let guti = Guti5g::new(plmn, 0xca, 0x3fe, 0, 0x1122_3344)?;
        let result = RegistrationResult::from_result(RegistrationResultValue::ThreeGppAccess);
        let accept = RegistrationAccept::new(result)
            .with_fg_guti(MobileIdentity::from_guti(guti))
            .with_tai_list(TrackingAreaIdentityList::from_plmn_tacs(&plmn, &[1, 2])?)
            .with_allowed_nssai(Nssai::from_snssais(&[SNssai::from_sst_sd(1, None)])?);
        let accept = Message::new_5gmm(accept);
        let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
        let sent = amf_context.protect(&accept, header, Direction::Downlink, access)?;
        println!("AMF {}", ue_context.unprotect(&sent, Direction::Downlink, access)?.message);
        println!("    {}", hex::encode(&sent));
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 3 of README.md.
fn block_3() {
    use oxirush_nas::identity::Algorithm;
    use oxirush_nas::nas_eps::*;
    use oxirush_nas::Direction;
    use oxirush_nas::identity::Plmn;
    use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
    use oxirush_security::nas_eps::derive_kasme;
    use oxirush_security::Rand;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        let k = K::from_slice(&hex::decode("465b5ce8b199b49faa5f0a2ee238a6bc")?)?;
        let opc = Opc::from_slice(&hex::decode("cd63cb71954a9f4e48a5994e37a02baf")?)?;
        let subscriber = Milenage::new(&k, &opc);

        // ATTACH REQUEST, plain, with an IMSI
        let attach = Message::decode(&hex::decode("07410108298039000000001002e0e000040201d031")?)?;
        println!("UE  {attach}");
        let Message::Emm(_, EmmMessage::AttachRequest(request)) = &attach else {
            unreachable!()
        };

        // AUTHENTICATION REQUEST, then the RES of the USIM against XRES
        let rand = Rand::from_slice(&hex::decode("23553cbe9637a89d218ae64dae47bf35")?)?;
        let amf = Amf::new(&[0xb9, 0xb9]);
        let vector = subscriber.authentication_vector(&rand, &Sqn::try_from(32)?, &amf);
        let ksi = KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Native(0))?;
        let challenge = AuthenticationRequest::new(
            ksi,
            AuthenticationParameterRand::from_rand(*rand.as_octets()),
            AuthenticationParameterAutn::from_autn(*vector.autn().as_octets()),
        );
        println!("MME {}", Message::new_emm(challenge));
        let usim = subscriber.check_autn(&rand, vector.autn())?;
        println!("UE  RES accepted: {}", vector.xres().accepts(usim.res()));

        // KASME, from the CK, the IK and the AUTN of the vector and the serving network
        let kasme = derive_kasme(vector.ck(), vector.ik(), Plmn::new("208", "93")?, vector.autn());
        let (eia, eea) = (Algorithm::Aes, Algorithm::Aes);
        let mut mme_context = SecurityContext::from_fresh_kasme(&kasme, eia, eea)?;
        let mut ue_context = SecurityContext::from_fresh_kasme(&kasme, eia, eea)?;

        // SECURITY MODE COMMAND replays the algorithms of the UE network capability
        let capability = UeSecurityCapability::from_ue_network_capability(&request.ue_network_capability);
        let algorithms = SecurityAlgorithms::from_algorithms(eea, eia);
        let command = Message::new_emm(SecurityModeCommand::new(algorithms, ksi, capability));
        let header = SecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext;
        let sent = mme_context.protect(&command, header, Direction::Downlink)?;
        println!("MME {}", ue_context.unprotect(&sent, Direction::Downlink)?.message);

        // SECURITY MODE COMPLETE, then the ATTACH ACCEPT with the default bearer
        let complete = Message::new_emm(SecurityModeComplete::new());
        let header = SecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext;
        let sent = ue_context.protect(&complete, header, Direction::Uplink)?;
        println!("UE  {}", mme_context.unprotect(&sent, Direction::Uplink)?.message);
        let accept = hex::decode("07420121060002f839000100155201c101090908696e7465726e657405010a000001")?;
        let accept = Message::decode(&accept)?;
        let header = SecurityHeaderType::IntegrityProtectedAndCiphered;
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
        let mut msg = Message::decode(&hex::decode("7e0044165f012a")?)?;

        if let Message::Gmm(_, GmmMessage::RegistrationReject(reject)) = &mut msg {
            // Read a mandatory IE, an optional IE that is there and one that is not
            assert_eq!(reject.fgmm_cause.cause(), Some(GmmCauseValue::Congestion));
            let t3346 = reject.t3346_value.as_ref().map(GprsTimer2::to_seconds);
            assert_eq!(t3346, Some(Some(600)));
            assert!(reject.t3502_value.is_none());

            // Another cause, T3346 taken out and T3502 added
            reject.fgmm_cause = GmmCause::from_cause(GmmCauseValue::IllegalUe);
            reject.clear_t3346_value();
            reject.set_t3502_value(GprsTimer2::from_seconds(720)?);
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
        let rate = IntegrityProtectionMaximumDataRate::new(0xffff);
        let request = Message::new_5gsm(PduSessionEstablishmentRequest::new(rate), 5, 1);

        // UL NAS TRANSPORT has it in its payload container
        let transport = UlNasTransport::new(
            PayloadContainerType::from_kind(PayloadContainerKind::N1SmInformation),
            PayloadContainer::from_n1_sm_message(&request)?,
        )
        .with_pdu_session_id(PduSessionIdentity2::from_pdu_session_id(5))
        .with_request_type(RequestType::from_request_type(RequestTypeValue::InitialRequest))
        .with_dnn(Dnn::from_string("internet")?);
        let octets = Message::new_5gmm(transport).encode()?;
        println!("{}", hex::encode(&octets));

        // The AMF reads what it routes the container by, and the SMF the message
        let Message::Gmm(_, GmmMessage::UlNasTransport(transport)) =
            Message::decode(&octets)?
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
    use oxirush_nas::nas_5gs::Message;
    use oxirush_nas::Validate;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION REJECT whose T3346 value is there twice, then an unknown IE
        // that is encoded as "comprehension required"
        let bytes = hex::decode("7e0044165f012a5f012a0400")?;
        let msg = Message::decode(&bytes)?;

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
    use oxirush_nas::Direction;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION REQUEST whose 5G-GUTI is one octet short
        let octets = hex::decode("7e004179000af202f839cafe001122332e02a020")?;
        let received = Message::decode(&octets);
        let error = received.clone().err();
        if let Some(error) = &error {
            println!("{error}");
        }

        // What a network answers: 5GMM STATUS with cause #96
        if let Some(answer) = Message::answer_to(&octets, &received, Direction::Uplink) {
            println!("{answer}");
            assert_eq!(answer.encode()?, [0x7e, 0x00, 0x64, 0x60]);
        }

        // What the message has, to log it or to treat it all the same
        let (message, faults) = Message::decode_lenient(&octets, oxirush_nas::DecodeOptions::STRICT)?;
        assert_eq!(faults.first(), error.as_ref());
        println!("{message}");

        // A message that is too short is ignored: no answer
        let short = [0x7e, 0x00];
        let received = Message::decode(&short);
        assert!(Message::answer_to(&short, &received, Direction::Uplink).is_none());
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 8 of README.md.
fn block_8() {
    use oxirush_nas::nas_5gs::Message;
    use oxirush_nas::tree;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
        let reject = Message::decode(&hex::decode("7e0044165f012a")?)?;
        println!("{}", reject.to_tree());

        // An IE is changed by its value, one comes in by its octets, and one goes out
        let mut tree = reject.to_tree();
        tree["5gmm-cause"] = tree!("illegal-ue");
        tree["t3502-value"] = tree!({"octets": "2c"});
        tree.as_object_mut().unwrap().shift_remove("t3346-value");
        let edited = reject.with_tree(tree)?;
        println!("{}", edited.to_tree());

        // A message written from its tree
        let status = tree!({"message-type": "5gmm-status", "5gmm-cause": "congestion"});
        let status = Message::from_tree(status)?;
        assert_eq!(status.encode()?, [0x7e, 0x00, 0x64, 0x16]);
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 9 of README.md.
fn block_9() {
    use oxirush_nas::{nas_5gs::Message, paths, tree};

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
        let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101")?;
        let accept = Message::decode(&bytes)?;
        let mut tree = accept.to_tree();

        // A value by its path, and each entry of a list with `*`
        for path in ["/nas/5g-guti/guti/plmn", "/NAS/Allowed NSSAI/*/SST"] {
            for value in paths::select(&tree, path)? {
                println!("{value}");
            }
        }

        // A value is set at its path, an optional IE added by its value, and an
        // entry put at the end of a list (`-`)
        paths::set(&mut tree, "/nas/5g-guti/guti/tmsi", tree!("0xdeadbeef"))?;
        paths::set(&mut tree, "/nas/t3512-value", tree!(3600))?;
        paths::insert(&mut tree, "/nas/allowed-nssai/-", tree!({"sst": 2}))?;
        let edited = accept.with_tree(tree)?;
        println!("{}", hex::encode(edited.encode()?));

        // A name that the message does not have is an error
        if let Err(wrong) = paths::select(&accept.to_tree(), "/nas/t3512") {
            println!("{wrong}");
        }
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 1 of src/lib.rs.
fn block_10() {
    use oxirush_nas::Validate;
    use oxirush_nas::identity::MobileIdentityType5gs;
    use oxirush_nas::nas_5gs::*;

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        // Decode a REGISTRATION REQUEST
        let bytes = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000")?;
        let msg = Message::decode(&bytes)?;
        println!("{msg}");

        // Read its IEs through typed accessors
        if let Message::Gmm(_, GmmMessage::RegistrationRequest(reg)) = &msg {
            let kind = reg.fgs_registration_type.registration_type();
            assert_eq!(kind, Some(RegistrationTypeValue::InitialRegistration));

            let identity = &reg.fgs_mobile_identity;
            assert_eq!(identity.identity_type(), Some(MobileIdentityType5gs::Suci));

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
        let cause = GmmCause::from_cause(GmmCauseValue::Congestion);
        let t3346 = GprsTimer2::from_seconds(600)?;
        let reject = RegistrationReject::new(cause).with_t3346_value(t3346);
        let answer = Message::new_5gmm(reject);
        println!("{answer}");

        // Encode it
        assert_eq!(hex::encode(answer.encode()?), "7e0044165f012a");
        Ok(())
    }

    main().unwrap();
}

/// The Rust block 2 of src/lib.rs.
fn block_11() {
    use oxirush_nas::identity::{Guti5g, Plmn};
    use oxirush_nas::nas_5gs::*;

    // A 5G-GUTI, two tracking areas of one PLMN and two S-NSSAIs
    let plmn = Plmn::new("208", "93").unwrap();
    let guti = Guti5g::new(plmn, 0xca, 0x3fe, 0, 0x1122_3344).unwrap();
    let tacs = [1, 2];
    let slices = [SNssai::from_sst_sd(1, None), SNssai::from_sst_sd(1, Some([1, 2, 3]))];

    // REGISTRATION ACCEPT with them
    let result = RegistrationResult::from_result(RegistrationResultValue::ThreeGppAccess);
    let accept = RegistrationAccept::new(result)
        .with_fg_guti(MobileIdentity::from_guti(guti))
        .with_tai_list(TrackingAreaIdentityList::from_plmn_tacs(&plmn, &tacs).unwrap())
        .with_allowed_nssai(Nssai::from_snssais(&slices).unwrap());
    let accept = Message::new_5gmm(accept);
    let octets = accept.encode().unwrap();
    println!("{}", hex::encode(&octets));
    println!("{accept}");

    // The other end reads them
    let Message::Gmm(_, GmmMessage::RegistrationAccept(read)) =
        Message::decode(&octets).unwrap()
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
    use oxirush_nas::identity::Algorithm;
    use oxirush_nas::nas_5gs::{KAmf, Message, NasConnection, SecurityHeaderType, SecurityContext};
    use oxirush_nas::Direction;

    // The two ends of a link have the same KAMF, the key that the UE and
    // the network share after authentication, and the same algorithms
    let kamf = KAmf::new(&[0x11; 32]);
    let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    let mut network = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();

    // The network protects a 5GMM STATUS: MAC, then ciphering
    let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    let header_type = SecurityHeaderType::IntegrityProtectedAndCiphered;
    let (downlink, access) = (Direction::Downlink, NasConnection::ThreeGpp);
    let octets = network.protect(&status, header_type, downlink, access).unwrap();
    assert_eq!(octets.len(), 7 + 4);

    // The UE checks the MAC, deciphers and decodes
    let received = ue.unprotect(&octets, downlink, access).unwrap();
    assert_eq!(received.message, status);
    }
}

/// The Rust block 4 of src/lib.rs.
fn block_13() {
    #[cfg(feature = "tree")] {
    use oxirush_nas::nas_5gs::Message;
    use oxirush_nas::tree;

    let reject = Message::decode(&hex::decode("7e0044165f012a").unwrap()).unwrap();
    let tree = tree!({
        "message-type": "registration-reject",
        "5gmm-cause": "congestion",
        "t3346-value": 600,
    });
    assert_eq!(reject.to_tree(), tree);
    assert_eq!(Message::from_tree(tree).unwrap(), reject);
    }
}

/// The Rust block 1 of src/nas_eps/mod.rs.
fn block_14() {
    use oxirush_nas::Validate;
    use oxirush_nas::nas_eps::*;

    // Decode an ATTACH REQUEST with an IMSI and a PDN CONNECTIVITY REQUEST
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
    let msg = Message::decode(&bytes).unwrap();
    println!("{msg}");
    assert!(msg.validate().is_empty());

    // Read its IEs, and the ESM message in its container
    if let Message::Emm(_, EmmMessage::AttachRequest(request)) = &msg {
        let imsi = request.eps_mobile_identity.as_imsi().unwrap();
        assert_eq!(imsi.as_str(), "208930000000001");
        assert!(request.ue_network_capability.supports_eea(2));

        let esm = request.esm_message_container.decode_as_esm_message().unwrap();
        println!("{esm}");
    }

    // It encodes to the octets that were decoded
    assert_eq!(bytes, msg.encode().unwrap());

    // Build an ATTACH REJECT, cause #3, and encode it
    let cause = EmmCause::from_cause(EmmCauseValue::IllegalUe);
    let reject = AttachReject::new(cause);
    let answer = Message::new_emm(reject);
    assert_eq!(answer.encode().unwrap(), [0x07, 0x44, 0x03]);
}

/// The Rust block 1 of src/nas_5gs/security.rs.
fn block_15() {
    use oxirush_nas::identity::Algorithm;
    use oxirush_nas::nas_5gs::{KAmf, Message, NasConnection, SecurityHeaderType, SecurityContext};
    use oxirush_nas::{Direction, NasCount};

    // REGISTRATION REJECT, cause #3
    let msg = Message::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();

    // The two ends of one link: the same KAMF and the same algorithms
    let kamf = KAmf::new(&[0x11; 32]);
    let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
    let mut tx = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let mut rx = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();

    // Protect outbound, over 3GPP access: integrity and ciphering
    let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
    let access = NasConnection::ThreeGpp;
    let protected = tx.protect(&msg, sht, Direction::Downlink, access).unwrap();

    // Unprotect inbound: MAC check, deciphering and decoding
    let verified = rx.unprotect(&protected, Direction::Downlink, access).unwrap();
    assert_eq!(verified.message, msg);
    assert_eq!(verified.security_header_type, sht);
    assert_eq!(verified.count, NasCount::ZERO);
}

/// The Rust block 1 of src/nas_eps/security.rs.
fn block_16() {
    use oxirush_nas::identity::Algorithm;
    use oxirush_nas::nas_eps::{KAsme, Message, SecurityHeaderType, SecurityContext};
    use oxirush_nas::{Direction, NasCount};

    // ATTACH REJECT, cause #3
    let msg = Message::decode(&[0x07, 0x44, 0x03]).unwrap();

    // The two ends of one link: the same KASME and the same algorithms
    let kasme = KAsme::new(&[0x11; 32]);
    let (eia, eea) = (Algorithm::Aes, Algorithm::Aes);
    let mut tx = SecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
    let mut rx = SecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();

    // Protect outbound: integrity and ciphering
    let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
    let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();

    // Unprotect inbound: MAC check, deciphering and decoding
    let verified = rx.unprotect(&protected, Direction::Downlink).unwrap();
    assert_eq!(verified.message, msg);
    assert_eq!(verified.security_header_type, sht);
    assert_eq!(verified.count, NasCount::ZERO);
}

/// The Rust block 1 of src/paths.rs.
fn block_17() {
    use oxirush_nas::nas_5gs::Message;

    // 5GMM STATUS, cause #22
    let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    println!("{}", status.to_tree());
}

/// The Rust block 2 of src/paths.rs.
fn block_18() {
    use oxirush_nas::nas_5gs::Message;
    use oxirush_nas::tree;

    // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
    let bytes = hex::decode("7e0044165f012a").unwrap();
    let reject = Message::decode(&bytes).unwrap();

    // A T3346 value of two octets, where the specification has one
    let mut tree = reject.to_tree();
    tree["t3346-value"] = tree!({"octets": "2a2b"});
    let edited = reject.with_tree(tree).unwrap();
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044165f022a2b");

    // The 5GMM cause has no length: it is one octet
    let mut tree = reject.to_tree();
    tree["5gmm-cause"] = tree!({"octets": "ffff"});
    println!("{}", reject.with_tree(tree).unwrap_err());
}

/// The Rust block 3 of src/paths.rs.
fn block_19() {
    use oxirush_nas::nas_5gs::Message;
    use oxirush_nas::tree;

    // A REGISTRATION REJECT by the name of its type and of its IEs
    let reject = Message::from_tree(tree!({
        "message-type": "registration-reject",
        "5gmm-cause": "congestion",
        "t3346-value": 600,
    }))
    .unwrap();
    assert_eq!(hex::encode(reject.encode().unwrap()), "7e0044165f012a");

    // A 5GSM message writes the fields of its header that its type does not decide
    let complete = Message::from_tree(tree!({
        "message-type": "pdu-session-release-complete",
        "pdu-session-identity": 5,
        "procedure-transaction-identity": 1,
    }))
    .unwrap();
    assert_eq!(hex::encode(complete.encode().unwrap()), "2e0501d4");

    // A mandatory IE that is left out is an error
    let tree = tree!({"message-type": "registration-reject"});
    println!("{}", Message::from_tree(tree).unwrap_err());

    // A value that its IE cannot carry says the member and the limit
    let tree = tree!({"message-type": "service-accept", "pdu-session-status": [5, 16]});
    println!("{}", Message::from_tree(tree).unwrap_err());
}

/// The Rust block 4 of src/paths.rs.
fn block_20() {
    use oxirush_nas::nas_eps::Message;
    use oxirush_nas::tree;

    // ATTACH REQUEST with a PDN CONNECTIVITY REQUEST in its ESM message container
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
    let attach = Message::decode(&bytes).unwrap();
    println!("{:#}", attach.to_tree()["esm-message-container"]);

    // The value of the container is the tree of its message
    let mut tree = attach.to_tree();
    tree["esm-message-container"]["pdn-type"] = tree!("ipv6");
    let edited = attach.with_tree(tree).unwrap();
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "07410108298039000000001002e0e000040201d021"
    );
}

/// The Rust block 5 of src/paths.rs.
fn block_21() {
    use oxirush_nas::nas_eps::Message;
    use oxirush_nas::tree;

    // PDN CONNECTIVITY REQUEST with the credentials of PAP and a request for
    // the address of a DNS server
    let request = Message::from_tree(tree!({
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
    let answer = Message::decode(&bytes).unwrap();
    println!("{:#}", answer.to_tree()["protocol-configuration-options"]);
}

/// The Rust block 6 of src/paths.rs.
fn block_22() {
    use oxirush_nas::{nas_5gs::Message, paths, tree};

    // REGISTRATION ACCEPT with an extended emergency number list: 112
    let bytes = hex::decode("7e004201017a0005000211f200").unwrap();
    let accept = Message::decode(&bytes).unwrap();
    let mut tree = accept.to_tree();
    println!("{}", tree["extended-emergency-number-list"]);

    // A number of the police is added at the end of the list
    let police = tree!({"digits": "17", "sub-services": "police"});
    let numbers = "/nas/extended-emergency-number-list/numbers/-";
    paths::insert(&mut tree, numbers, police).unwrap();
    let edited = accept.with_tree(tree).unwrap();
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "7e004201017a000e000211f200017106f0373b3d2e03"
    );
}

/// The Rust block 7 of src/paths.rs.
fn block_23() {
    use oxirush_nas::nas_5gs::Message;
    use oxirush_nas::tree;

    // 5GMM STATUS under an integrity protected header
    let bytes = hex::decode("7e01e73b901b007e006416").unwrap();
    let protected = Message::decode(&bytes).unwrap();
    println!("{:#}", protected.to_tree());

    // An edit that leaves the old MAC in the security header is refused
    let mut tree = protected.to_tree();
    tree["5gmm-cause"] = tree!("illegal-ue");
    println!("{}", protected.with_tree(tree.clone()).unwrap_err());

    // The tree writes the code of the edited message
    tree["security-header"]["message-authentication-code"] = tree!("0x01020304");
    let edited = protected.with_tree(tree).unwrap();
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e0101020304007e006403");

    // A message that is ciphered has its octets
    let bytes = hex::decode("7e024b708bc300026ff75c").unwrap();
    let ciphered = Message::decode(&bytes).unwrap();
    println!("{}", ciphered.to_tree()["ciphered-message"]);
}

/// The Rust block 8 of src/paths.rs.
fn block_24() {
    use oxirush_nas::{nas_5gs::Message, paths, tree};

    // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = Message::decode(&bytes).unwrap();
    let tree = accept.to_tree();

    // Each value with the path that selects it
    for (path, value) in paths::paths(&tree) {
        println!("{path} = {value}");
    }

    // A coded value by its name and an identity by its parts
    let select = |path| paths::select(&tree, path).unwrap();
    assert_eq!(select("/nas/message-type"), [&tree!("registration-accept")]);
    assert_eq!(select("/nas/5gs-registration-result/result"), [&tree!("3gpp-access")]);
    assert_eq!(select("/nas/5g-guti/guti/tmsi"), [&tree!(0x1122_3344)]);

    // A name in any case, and `*` for each entry of a list
    assert_eq!(select("/NAS/Allowed NSSAI/*/SST"), [&tree!(1)]);

    // An optional IE that the message does not have selects nothing
    assert!(select("/nas/t3512-value").is_empty());

    // A name that the message cannot have is an error
    assert!(paths::select(&tree, "/nas/t3512").is_err());
}
