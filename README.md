# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The NAS messages of 5GS and EPS in Rust, per 3GPP TS 24.501 and TS 24.301
(Release 19): decode, build, check and encode them, edit them as JSON, and
protect them.

```rust
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
```

```text
5GMM RegistrationRequest (type=InitialRegistration, FOR, ngKSI=no key, identity=suci-0-208-93-0000-0-0-0000000120, UE-SecCap=EA0 EA2 / IA2)
InitialRegistration in MCC 208, MNC 93
0 findings, same octets: true
5GMM RegistrationReject (cause=#22 (Congestion), T3346=10 min): 7e0044165f012a
```

Each example is followed by its output.

## Installation

```toml
[dependencies]
oxirush-nas = "0.5"
hex = "0.4" # for the examples of this page
# With NAS security and JSON:
# oxirush-nas = { version = "0.5", features = ["security", "serde"] }
# The keys of the registration below:
# oxirush-security = "0.3"
```

| Feature | Adds | Dependencies |
|---------|------|--------------|
| `std` (default) | The standard library | |
| `security` | `NasSecurityContext`, which protects and unprotects messages | `oxirush-security` |
| `serde` | Trees, views and paths, and `Serialize` and `Deserialize` through the trees | `oxirush-utils` with `serde`, `serde_json`, `serde_core`, `spin` |
| `idna` | The NAI of a SUCI is checked as an internationalized name too | `idna`, `unicode-normalization` |

Without its default features the crate is `no_std` and needs an allocator;
`security` and `serde` still work. With `serde`, oxirush-utils 0.1 and
serde_json 1 are public dependencies: a tree is an
`oxirush_utils::tree::Value`.

The minimum supported Rust version is 1.88. Cargo's resolver 3, the
default of edition 2024, keeps each dependency at a version that 1.88
builds. Under resolver 2, `aes` 0.9.3 needs 1.89, and a project keeps 0.9.2:

```sh
cargo update -p aes --precise 0.9.2
```

## Register a UE, from its REGISTRATION REQUEST to the ACCEPT

The AMF's side of a 5G registration: it reads the SUCI, runs 5G AKA, starts
NAS security and accepts the UE. The keys come from
[oxirush-security](https://github.com/linouxis9/oxirush-security), which the
program depends on too. The UE's side is a line or two at each step.

```rust
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
```

```text
UE  5GMM RegistrationRequest (type=InitialRegistration, FOR, ngKSI=no key, identity=suci-0-208-93-0000-0-0-0000000120, UE-SecCap=EA0 EA2 / IA2)
AMF imsi-208930000000120
AMF 5GMM AuthenticationRequest (ngKSI=0, ABBA=0000, RAND=23553cbe9637a89d218ae64dae47bf35, AUTN=55f328b43577b9b94a9ffac354dfafb3)
UE  RES* accepted: true
AMF 5GMM SecurityModeCommand (algorithms=NEA2 NIA2, ngKSI=0, Replayed-UE-SecCap=EA0 EA2 / IA2)
UE  5GMM SecurityModeComplete (NAS-container=5GMM RegistrationRequest (type=InitialRegistration, FOR, ngKSI=no key, identity=suci-0-208-93-0000-0-0-0000000120, UE-SecCap=EA0 EA2 / IA2)), NAS COUNT 0
AMF 5GMM RegistrationAccept (result=ThreeGppAccess, GUTI=5g-guti-20893caff8011223344, TAI-list=[208-93-000001, 208-93-000002], Allowed-NSSAI=[1])
    7e02818e2ede0169e2dfa47cf0a4a5ff3e8b5143585d5033635f8eebad491ccf140fb7eaa8bbe3b0d8e5
```

The same in EPS, shorter: the MME derives KASME from the vector, and the
messages have their EPS types.

```rust
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
```

```text
UE  EMM AttachRequest (type=EpsAttach, KSI=0, identity=imsi-208930000000001, UE-NetCap=EEA0 EEA1 EEA2 / EIA0 EIA1 EIA2, ESM-container=ESM (EBI=0, PTI=1) PdnConnectivityRequest (request=Initial, PDN=Ipv4v6))
MME EMM AuthenticationRequest (KSI=0, RAND=23553cbe9637a89d218ae64dae47bf35, AUTN=aa689c648350b9b9a4a8043ac07aa7e0)
UE  RES accepted: true
MME EMM SecurityModeCommand (algorithms=EEA2 EIA2, KSI=0, Replayed-UE-SecCap=EEA0 EEA1 EEA2 / EIA0 EIA1 EIA2)
UE  EMM SecurityModeComplete
MME EMM AttachAccept (result=EpsOnly, T3412=1 min, TAI-list=[208-93-0001], ESM-container=ESM (EBI=5, PTI=1) ActivateDefaultEpsBearerContextRequest (QoS=QCI 9, APN=internet, PDN-address=IPv4 10.0.0.1))
```

[`nas_5gs::security`](https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/security/index.html)
has an example of each of the other tasks: restore a context after a
restart, change its algorithms with `reselect_algorithms`, and protect an
invalid payload for a negative test with `protect_opaque_payload`.

## Carry the messages in NGAP and S1AP

Between the RAN and the core, a NAS message is the NAS-PDU of an
[NGAP](https://github.com/linouxis9/oxirush-ngap) or
[S1AP](https://github.com/linouxis9/oxirush-s1ap) message: the octets of
`encode()`, which `decode()` reads back.

```rust,ignore
use oxirush_nas::{nas_5gs::Nas5gsMessage, nas_eps::NasEpsMessage};
use oxirush_ngap::{build_ngap, extract_ngap_ies, ngap::NASPDU};
use oxirush_s1ap::build_s1ap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The AMF: a REGISTRATION REJECT, cause #22, in a DOWNLINK NAS TRANSPORT
    let reject = Nas5gsMessage::decode(&hex::decode("7e0044165f012a")?)?;
    let downlink = build_ngap!(InitiatingMessage, DownlinkNASTransport, DownlinkNASTransport,
        AMF_UE_NGAP_ID(1u64),
        RAN_UE_NGAP_ID(7u32),
        NAS_PDU(reject.encode()?),
    )?;
    println!("{}", downlink.to_tree());

    // The gNB gives the UE the NAS-PDU, which decodes as the message
    extract_ngap_ies!(downlink, DownlinkNASTransport,
        req nas: NASPDU = NAS_PDU(nas) => nas,
    );
    println!("{}", Nas5gsMessage::decode(&nas.0)?);

    // The MME: an ATTACH REJECT, cause #3, in a DOWNLINK NAS TRANSPORT of S1AP
    let reject = NasEpsMessage::decode(&[0x07, 0x44, 0x03])?;
    let downlink = build_s1ap!(InitiatingMessage, downlinkNASTransport, DownlinkNASTransport,
        MME_UE_S1AP_ID(1u32),
        eNB_UE_S1AP_ID(7u32),
        NAS_PDU(reject.encode()?),
    )?;
    println!("{}", downlink.to_tree());
    Ok(())
}
```

```text
{"message":"DownlinkNASTransport","ies":[{"AMF-UE-NGAP-ID":1},{"RAN-UE-NGAP-ID":7},{"NAS-PDU":"7e0044165f012a"}]}
5GMM RegistrationReject (cause=#22 (Congestion), T3346=10 min)
{"message":"DownlinkNASTransport","ies":[{"MME-UE-S1AP-ID":1},{"eNB-UE-S1AP-ID":7},{"NAS-PDU":"074403"}]}
```

## Change a decoded message

A message has a public field for each IE. `new()` takes the mandatory IEs.
For each IE, `set_<ie>()` changes it in place and `with_<ie>()` returns the
message with it. An optional IE is an `Option`, and `clear_<ie>()` removes it.

```rust
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
```

```text
5GMM RegistrationReject (cause=#3 (Illegal UE), T3502=12 min)
```

## A 5GSM message in UL NAS TRANSPORT

A 5GSM message travels inside a 5GMM one: UL NAS TRANSPORT carries it in its
payload container, and the AMF routes it by the PDU session identity.

```rust
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
```

```text
7e00670100062e0501c1ffff120581250908696e7465726e6574
5GSM (PSI=5, PTI=1) PduSessionEstablishmentRequest
```

## Validate a message, and answer a faulty one

`validate()` lists what is wrong with one message, built or decoded. A
message keeps the IEs it did not expect, and encodes them again as they came.

```rust
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
```

```text
[Error] unknown_ies: IEI 0x5f was ignored as repeated
[Error] unknown_ies: Unknown IEI 0x04 is encoded as comprehension required
```

`answer_to()` gives the answer that clause 7 of TS 24.501 asks for, to a
message that does not decode or has an unknown IE that must be understood.
`decode_lenient()` gives the message all the same, with its faults.

```rust
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
```

```text
mandatory IE `5gs-mobile-identity` has a value that is syntactically incorrect: `5g-guti` has 10 octets, and must have 11
5GMM Status (cause=#96 (Invalid mandatory information))
5GMM RegistrationRequest (type=InitialRegistration, FOR, ngKSI=no key, identity=5G-GUTI (f202f839cafe00112233), UE-SecCap=EA0 EA2 / IA2)
```

## A message as JSON

With the `serde` feature, a message has two JSON forms. The tree has the
message type and the value of each IE: you print a message with it, and
write one. The view has every IE that the message can have, with its
`value` and its `octets`: you edit a message with it, and `with_view()`
encodes the IEs you changed and keeps the octets of the others. Both carry
the keys of a message, RES and RES\* among them, which `Display` and `Debug`
hide: do not log them. `Serialize` and `Deserialize` go through the tree, in
any format of serde.

```rust
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
```

```text
{"message-type":"registration-reject","5gmm-cause":"congestion","t3346-value":600}
{"value":600,"octets":"2a"}
{"message-type":"registration-reject","5gmm-cause":"illegal-ue","t3502-value":720}
```

The [`view`](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html)
module has the rules of the two forms and the notation of each kind of
value, with examples: a message in a container, the protocol configuration
options, a list, a protected message, and octets sent as they are.

## Read and edit by path

A path starts at `/nas`, then names an IE, in any case.

```rust
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
```

```text
"208-93"
1
7e0042010177000bf202f839010042deadbeef1504010101025e0106
`t3512` is no IE of a message `registration-accept`, at /nas/t3512/value
```

`view::paths` gives each value of a view with the path that selects it.

## Limits

- It runs no procedure, timer or transport. Its only state is a security
  context, which the caller keeps.
- `validate()` checks one message: it does not know which procedure the
  message belongs to.
- `encode()` writes any value that a type can hold, so a test tool can send
  an invalid message.
- 13 5GS and 19 EPS IE types have octets and no value in JSON
  ([which](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html#ie-types-that-have-a-value)).
- Two items follow Release 20 and differ from V19.8.0 on the wire
  ([which](https://docs.rs/oxirush-nas#specification-versions)).

## Performance

On one core of an AMD Ryzen 7 5700G (Linux 7.0, Rust 1.98.1), at c4fdffc on
2026-10-18, and the JSON forms at 3a0d08d, for a message of the 5GS
fixtures (17 octets on average):

| Operation | Time | Allocations |
|-----------|------|-------------|
| `decode` | 109 ns | 1.2 |
| `encode` | 46 ns | 1.0 |
| `validate` | 210 ns | 3.2 |
| `to_view` | 3.2 µs | 65 |
| `with_view` | 13.2 µs | 137 |
| `to_tree` | 15.2 µs | 210 |
| `from_tree` | 29.9 µs | 339 |
| `protect`, `unprotect` (128-NIA2, 128-NEA2) | 230 ns, 323 ns | 2.0, 2.3 |

[`benches/`](benches/README.md) has how to run them and the profilers.

### Against other implementations

The plain messages of the fixtures, decoded and encoded by this crate and
four other implementations, at c4fdffc on the same machine. A ratio is the
time of the other implementation over this crate's. free5GC's library has
no EPS, and packet-dissector only decodes.

| Operation | oxirush-nas | free5GC nas v1.2.3 | Open5GS v2.8.0 | packet-dissector 0.6.1 | pycrate 0.8.1 |
|---|---|---|---|---|---|
| Decode, 5GS, 76 messages | 108.4 ns | 3.8x | 12x | 1.4x | 2,400x |
| Decode, EPS, 95 messages | 98.1 ns | | 10x | 1.2x | 1,900x |
| Encode, 5GS, 61 messages | 33.7 ns | 4.6x | 34x | | 560x |
| Encode, EPS, 82 messages | 36.5 ns | | 39x | | 620x |

[`benches/`](benches/README.md#against-other-implementations) has every
figure, with cycles, instructions, allocations and peak memory, and the
method. `benches/compare/compare.sh 3` runs every row on core 3:

```sh
benches/compare/compare.sh 3
```

## Tests and fuzzing

```sh
cargo test --all-features
cargo test --release --features security --test key_wiping
./fuzz/seed.sh && cargo +nightly fuzz run decode_5gs -- -max_total_time=60 -max_len=512
```

`tests/fixtures` has at least one message of each 5GMM, 5GSM, EMM and ESM
type, and 170 messages that Open5GS, free5GC and PacketRusher sent in a
lab. Each one decodes, validates and encodes back to its octets, also
through its view and its serde form. `key_wiping` searches the memory of its
own process for the keys of a dropped security context, in an optimized
build. Four fuzz targets run in CI. `examples/` has six programs, each for
5GS and for EPS.

Each Rust block of this page is checked with what it prints
([`tests/readme.rs`](tests/readme.rs) says how). The block that uses
oxirush-ngap and oxirush-s1ap runs in the package of [`family/`](family/).
[The documentation](https://docs.rs/oxirush-nas) has what the crate covers,
the rules of the receiver and the sender, the versions of the
specifications, and the tests. In a clone,
`cargo doc --all-features --open` builds it.

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.

## The OxiRush family

- [oxirush-utils](https://github.com/linouxis9/oxirush-utils): the 3GPP identities, and the JSON tree with its paths that the others share.
- [oxirush-aper](https://github.com/linouxis9/oxirush-aper): aligned PER, the runtime of the NGAP and S1AP codecs.
- [oxirush-nas](https://github.com/linouxis9/oxirush-nas): the NAS messages of 5GS and EPS.
- [oxirush-security](https://github.com/linouxis9/oxirush-security): NAS security, AKA and the derivation of keys.
- [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap): NGAP, between a gNB and an AMF.
- [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap): S1AP, between an eNB and an MME.
- [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u): GTP-U tunnels, with a test UPF.
- [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp): SCTP sockets, which carry NGAP and S1AP.

## License

Copyright 2025-2026 Valentin D'Emmanuele. Licensed under the Apache License,
Version 2.0: see [LICENSE](LICENSE).
