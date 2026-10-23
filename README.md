# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The NAS messages of 5GS and EPS in Rust, per 3GPP TS 24.501 and TS 24.301
(Release 19): decode, build, validate and encode them, edit them as JSON,
and protect them.

```rust
use oxirush_nas::nas_5gs::*;

// Decode a REGISTRATION REQUEST
let bytes = hex::decode(
    "7e004179000d0102f8390000000000000010022e08a020000000000000"
).unwrap();
let msg = Nas5gsMessage::decode(&bytes).unwrap();
println!("{msg}");

// Read its IEs through typed accessors
if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = &msg {
    let kind = reg.fgs_registration_type.registration_type();
    assert_eq!(kind, Some(RegistrationType::InitialRegistration));

    let identity = &reg.fgs_mobile_identity;
    assert_eq!(identity.identity_type(), Some(MobileIdentityType::Suci));

    // The PLMN identity names the network: a country code and a network code
    let plmn = identity.plmn().unwrap();
    println!("MCC={}, MNC={}", plmn.mcc(), plmn.mnc());
}

// It passes every check that can be made on a single message, and encodes
// to the octets that were decoded
assert!(msg.validate().is_empty());
assert_eq!(bytes, msg.encode().unwrap());

// Build the answer, a REGISTRATION REJECT with cause #22 and a T3346 value
// of ten minutes: `new()` takes the mandatory IEs, `with_*()` adds the others
let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
let t3346 = NasGprsTimer2::from_seconds(600).unwrap();
let reject = NasRegistrationReject::new(cause).with_t3346_value(t3346);
let answer = Nas5gsMessage::new_5gmm(reject);

// Encode it
let octets = answer.encode().unwrap();
assert_eq!(hex::encode(octets), "7e0044165f012a");
```

```text
5GMM RegistrationRequest (type=InitialRegistration, FOR, ngKSI=no key, identity=suci-0-208-93-0000-0-0-0000000120, UE-SecCap=EA0 EA2 / IA2)
MCC=208, MNC=93
```

The output under a block is what the block prints. The examples use the
`hex` crate for the octets.

> This page describes 0.5.0, which is on `master` and unpublished. crates.io
> has 0.4.0: the [changelog](CHANGELOG.md) says how to migrate.

## Installation

```toml
[dependencies]
oxirush-nas = "0.5"
# With NAS security and JSON:
# oxirush-nas = { version = "0.5", features = ["security", "serde"] }
# The keys of the registration below:
# oxirush-security = "0.3"
```

| Feature | Adds | Dependencies |
|---------|------|--------------|
| `std` (default) | the standard library | |
| `security` | `NasSecurityContext`: `protect` and `unprotect` | `oxirush-security` |
| `serde` | trees, views and paths, and `Serialize` and `Deserialize` through the trees | the feature `serde` of `oxirush-utils`: `serde_json`, `serde_core`; `spin` |
| `idna` | the NAI of a SUCI is also checked as an internationalized name | `idna`, `unicode-normalization` |

With `default-features = false` the crate is `no_std` and needs an
allocator; `security` and `serde` work there too. A tree is a
`tree::Value` of `oxirush-utils` 0.1, built on `serde_json` 1: both are
public dependencies of `serde`.

Until 0.5.0 is on crates.io, a program takes the crate from its repository,
with oxirush-security and oxirush-utils, which are not published either, at
the revisions that it is tested with:

```toml
[dependencies]
oxirush-nas = { git = "https://github.com/linouxis9/oxirush-nas", features = ["security"] }

[patch.crates-io]
oxirush-security = { git = "https://github.com/linouxis9/oxirush-security", rev = "9dc28daf3e8b16d7cb497984cebaec234740c89e" }
oxirush-utils = { git = "https://github.com/linouxis9/oxirush-utils", rev = "2f99edcc40baa5cf7397f94ecfc131dc1143bac5" }
```

In a clone, the same as options of Cargo:

```bash
UNPUBLISHED=(
  --config 'patch.crates-io.oxirush-security.git="https://github.com/linouxis9/oxirush-security"'
  --config 'patch.crates-io.oxirush-security.rev="9dc28daf3e8b16d7cb497984cebaec234740c89e"'
  --config 'patch.crates-io.oxirush-utils.git="https://github.com/linouxis9/oxirush-utils"'
  --config 'patch.crates-io.oxirush-utils.rev="2f99edcc40baa5cf7397f94ecfc131dc1143bac5"'
)
cargo test "${UNPUBLISHED[@]}" --all-features
cargo run "${UNPUBLISHED[@]}" --example decode_message_nas_5gs
```

The minimum supported Rust version is 1.88.

## Register a UE, from its REGISTRATION REQUEST to the ACCEPT

The network side of a 5G registration: the AMF reads the SUCI, authenticates
the UE with 5G AKA, starts NAS security and accepts it. The keys come from
[oxirush-security](https://github.com/linouxis9/oxirush-security), a
dependency of the program beside this crate, and the UE's side is a line or
two each time.

```rust
use oxirush_nas::nas_5gs::*;
use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
use oxirush_security::nas_5gs::{ResStar, Supi, derive_kamf, derive_kausf, derive_kseaf};
use oxirush_security::Rand;

let octets = |s: &str| hex::decode(s).unwrap();

// The subscriber of TS 35.208 test set 1, in the UDM and in the USIM
let k = K::from_slice(&octets("465b5ce8b199b49faa5f0a2ee238a6bc")).unwrap();
let opc = Opc::from_slice(&octets("cd63cb71954a9f4e48a5994e37a02baf")).unwrap();
let subscriber = Milenage::new(&k, &opc);
let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

// REGISTRATION REQUEST, plain. Its SUCI has the null scheme: the SUPI is in it
let received = octets("7e004179000d0102f8390000000000000010022e08a020000000000000");
let registration = Nas5gsMessage::decode(&received).unwrap();
println!("UE  {registration}");
let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(request)) = &registration else {
    unreachable!()
};
let Some(Suci::Imsi(suci)) = request.fgs_mobile_identity.as_suci() else { unreachable!() };
let supi = Supi::from(suci.imsi().unwrap());
println!("AMF {supi}");

// AUTHENTICATION REQUEST: a challenge of MILENAGE, under ngKSI 0
let rand = Rand::from_slice(&octets("23553cbe9637a89d218ae64dae47bf35")).unwrap();
let (sqn, amf) = (Sqn::try_from(0xff9b_b4d0_b607).unwrap(), Amf::new(&[0xb9, 0xb9]));
let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
let ngksi = NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Native(0)).unwrap();
let challenge = NasAuthenticationRequest::new(ngksi, NasAbba::new(vec![0, 0]))
    .with_authentication_parameter_rand(NasAuthenticationParameterRand::from_rand(
        *rand.as_octets(),
    ))
    .with_authentication_parameter_autn(NasAuthenticationParameterAutn::from_autn(
        *vector.autn().as_octets(),
    ));
println!("AMF {}", Nas5gsMessage::new_5gmm(challenge));

// The USIM checks the AUTN and answers with RES*
let usim = subscriber.check_autn(&rand, vector.autn()).unwrap();
let res_star = *usim.res_star(sn_name).unwrap().as_octets();
let parameter = NasAuthenticationResponseParameter::from_res_star(res_star);
let response = NasAuthenticationResponse::new().with_authentication_response_parameter(parameter);
let sent = Nas5gsMessage::new_5gmm(response).encode().unwrap();

// The AMF compares RES* with XRES*, then derives KAMF from the SUPI and the ABBA
let Nas5gsMessage::Gmm(_, Nas5gmmMessage::AuthenticationResponse(response)) =
    Nas5gsMessage::decode(&sent).unwrap()
else {
    unreachable!()
};
let res_star = response.authentication_response_parameter.unwrap();
let res_star = ResStar::from_slice(res_star.res_star()).unwrap();
println!("UE  RES* accepted: {}", vector.xres_star(sn_name).unwrap().accepts(&res_star));
let k_ausf = derive_kausf(vector.ck(), vector.ik(), sn_name, vector.autn()).unwrap();
let k_seaf = derive_kseaf(&k_ausf, sn_name).unwrap();
let k_amf = derive_kamf(&k_seaf, &supi, &[0, 0]).unwrap();

// The UE derives the same KAMF. Each end has a context of the NAS keys, the
// algorithms and the NAS COUNTs
let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
let mut amf_context = NasSecurityContext::from_fresh_kamf(&k_amf, nia, nea).unwrap();
let mut ue_context = NasSecurityContext::from_fresh_kamf(&k_amf, nia, nea).unwrap();

// SECURITY MODE COMMAND replays the UE security capability. It is integrity
// protected with the new context, and not ciphered
let capability = request.ue_security_capability.clone().unwrap();
let algorithms = NasSecurityAlgorithms::from_algorithms(nea, nia);
let command = Nas5gsMessage::new_5gmm(NasSecurityModeCommand::new(algorithms, ngksi, capability));
let header = Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext;
let sent = amf_context.protect(&command, header, Direction::Downlink).unwrap();
println!("AMF {}", ue_context.unprotect(&sent, Direction::Downlink).unwrap().message);

// SECURITY MODE COMPLETE, integrity protected and ciphered, has the whole
// REGISTRATION REQUEST in its NAS message container
let container = NasMessageContainer::from_nas_message(&registration).unwrap();
let complete = NasSecurityModeComplete::new().with_nas_message_container(container);
let header = Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext;
let complete = Nas5gsMessage::new_5gmm(complete);
let sent = ue_context.protect(&complete, header, Direction::Uplink).unwrap();
let verified = amf_context.unprotect(&sent, Direction::Uplink).unwrap();
println!("UE  {}, NAS COUNT {}", verified.message, verified.count.get());

// REGISTRATION ACCEPT: a 5G-GUTI, two tracking areas and a slice, ciphered
let plmn = Plmn::new("208", "93").unwrap();
let guti = Guti::new(plmn, 0xca, 0x3fe, 0, 0x1122_3344).unwrap();
let result = NasFGsRegistrationResult::from_result(RegistrationResult::ThreeGppAccess);
let accept = NasRegistrationAccept::new(result)
    .with_fg_guti(NasFGsMobileIdentity::from_guti(guti))
    .with_tai_list(NasFGsTrackingAreaIdentityList::from_plmn_tacs(&plmn, &[1, 2]).unwrap())
    .with_allowed_nssai(NasNssai::from_snssais(&[NasSNssai::from_sst_sd(1, None)]).unwrap());
let accept = Nas5gsMessage::new_5gmm(accept);
let header = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
let sent = amf_context.protect(&accept, header, Direction::Downlink).unwrap();
println!("AMF {}", ue_context.unprotect(&sent, Direction::Downlink).unwrap().message);
println!("    {}", hex::encode(&sent));
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

The same in EPS, shorter: the MME takes KASME from the vector, and its
messages have their EPS types.

```rust
use oxirush_nas::nas_eps::*;
use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
use oxirush_security::nas_eps::derive_kasme;
use oxirush_security::{Plmn, Rand};

let octets = |s: &str| hex::decode(s).unwrap();
let k = K::from_slice(&octets("465b5ce8b199b49faa5f0a2ee238a6bc")).unwrap();
let opc = Opc::from_slice(&octets("cd63cb71954a9f4e48a5994e37a02baf")).unwrap();
let subscriber = Milenage::new(&k, &opc);

// ATTACH REQUEST, plain, with an IMSI
let attach = NasEpsMessage::decode(&octets("07410108298039000000001002e0e000040201d031")).unwrap();
println!("UE  {attach}");
let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &attach else {
    unreachable!()
};

// AUTHENTICATION REQUEST, then the RES of the USIM against XRES
let rand = Rand::from_slice(&octets("23553cbe9637a89d218ae64dae47bf35")).unwrap();
let amf = Amf::new(&[0xb9, 0xb9]);
let vector = subscriber.authentication_vector(&rand, &Sqn::try_from(32).unwrap(), &amf);
let ksi = NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Native(0)).unwrap();
let challenge = NasAuthenticationRequest::new(
    ksi,
    NasAuthenticationParameterRand::from_rand(*rand.as_octets()),
    NasAuthenticationParameterAutn::from_autn(*vector.autn().as_octets()),
);
println!("MME {}", NasEpsMessage::new_emm(challenge));
let usim = subscriber.check_autn(&rand, vector.autn()).unwrap();
println!("UE  RES accepted: {}", vector.xres().accepts(usim.res()));

// KASME, from the CK, the IK and the AUTN of the vector and the serving network
let kasme = derive_kasme(vector.ck(), vector.ik(), Plmn::new("208", "93").unwrap(), vector.autn());
let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
let mut mme_context = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
let mut ue_context = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();

// SECURITY MODE COMMAND replays the algorithms of the UE network capability
let capability = NasUeSecurityCapability::from_ue_network_capability(&request.ue_network_capability);
let algorithms = NasSecurityAlgorithms::from_algorithms(eea, eia);
let command = NasEpsMessage::new_emm(NasSecurityModeCommand::new(algorithms, ksi, capability));
let header = NasEpsSecurityHeaderType::IntegrityProtectedWithNewEpsSecurityContext;
let sent = mme_context.protect(&command, header, Direction::Downlink).unwrap();
println!("MME {}", ue_context.unprotect(&sent, Direction::Downlink).unwrap().message);

// SECURITY MODE COMPLETE, then the ATTACH ACCEPT with the default bearer
let complete = NasEpsMessage::new_emm(NasSecurityModeComplete::new());
let header = NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewEpsSecurityContext;
let sent = ue_context.protect(&complete, header, Direction::Uplink).unwrap();
println!("UE  {}", mme_context.unprotect(&sent, Direction::Uplink).unwrap().message);
let accept = octets("07420121060002f839000100155201c101090908696e7465726e657405010a000001");
let accept = NasEpsMessage::decode(&accept).unwrap();
let header = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
let sent = mme_context.protect(&accept, header, Direction::Downlink).unwrap();
println!("MME {}", ue_context.unprotect(&sent, Direction::Downlink).unwrap().message);
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
says how to restore a context after a restart, change its algorithms and
protect an invalid payload for a negative test.

## Carry the messages in NGAP and S1AP

A NAS message travels between the RAN and the core as the NAS-PDU of an
[NGAP](https://github.com/linouxis9/oxirush-ngap) or an
[S1AP](https://github.com/linouxis9/oxirush-s1ap) message: its octets, as
`encode()` gives them and `decode()` takes them.

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

A message has a public field for each IE, and `new()` takes the mandatory
ones. Each IE has `set_<ie>()`, which takes `&mut self`, and `with_<ie>()`,
which takes the message and returns it; an optional IE is an `Option`, and
`clear_<ie>()` takes it out.

```rust
use oxirush_nas::nas_5gs::*;

// REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
let bytes = hex::decode("7e0044165f012a").unwrap();
let mut msg = Nas5gsMessage::decode(&bytes).unwrap();

if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(reject)) = &mut msg {
    // Read a mandatory IE, an optional IE that is there and one that is not
    assert_eq!(reject.fgmm_cause.cause(), Some(GmmCause::Congestion));
    let t3346 = reject.t3346_value.as_ref().unwrap();
    assert_eq!(t3346.to_seconds(), Some(600));
    assert!(reject.t3502_value.is_none());

    // Another cause, T3346 taken out and T3502 added
    reject.fgmm_cause = NasFGmmCause::from_cause(GmmCause::IllegalUe);
    reject.clear_t3346_value();
    reject.set_t3502_value(NasGprsTimer2::from_seconds(720).unwrap());
}

assert_eq!(hex::encode(msg.encode().unwrap()), "7e00440316012c");
```

## A 5GSM message in UL NAS TRANSPORT

```rust
use oxirush_nas::nas_5gs::*;

// PDU SESSION ESTABLISHMENT REQUEST for PDU session 5, with PTI 1
let rate = NasIntegrityProtectionMaximumDataRate::new(0xffff);
let request = Nas5gsMessage::new_5gsm(NasPduSessionEstablishmentRequest::new(rate), 5, 1);

// UL NAS TRANSPORT has it in its payload container
let transport = NasUlNasTransport::new(
    NasPayloadContainerType::from_kind(PayloadContainerKind::N1SmInformation),
    NasPayloadContainer::from_n1_sm_message(&request).unwrap(),
)
.with_pdu_session_id(NasPduSessionIdentity2::from_pdu_session_id(5))
.with_request_type(NasRequestType::from_request_type(RequestTypeValue::InitialRequest))
.with_dnn(NasDnn::from_string("internet").unwrap());
let octets = Nas5gsMessage::new_5gmm(transport).encode().unwrap();
println!("{}", hex::encode(&octets));

// The AMF reads what it routes the container by, and the SMF the message
let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) =
    Nas5gsMessage::decode(&octets).unwrap()
else {
    unreachable!()
};
let kind = transport.payload_container_type.kind();
assert_eq!(kind, Some(PayloadContainerKind::N1SmInformation));
assert_eq!(transport.pdu_session_id.unwrap().pdu_session_id(), 5);
assert_eq!(transport.dnn.unwrap().as_string().as_deref(), Some("internet"));
println!("{}", transport.payload_container.decode_as_n1_sm_message().unwrap());
```

```text
7e00670100062e0501c1ffff120581250908696e7465726e6574
5GSM (PSI=5, PTI=1) PduSessionEstablishmentRequest
```

## Validate a message, and answer one that is faulty

`validate()` returns the findings on one message, built or decoded.

```rust
use oxirush_nas::nas_5gs::{Nas5gsMessage, Validate};

// REGISTRATION REJECT whose T3346 value is there twice, then an unknown IE
// that is encoded as "comprehension required"
let bytes = hex::decode("7e0044165f012a5f012a0400").unwrap();
let msg = Nas5gsMessage::decode(&bytes).unwrap();

// What `validate()` finds
for finding in msg.validate() {
    println!("{finding}");
}

// Both are kept as they came, and go out again
assert_eq!(msg.unknown_ies().len(), 2);
assert!(msg.unknown_ies().get(1).unwrap().is_comprehension_required());
assert_eq!(bytes, msg.encode().unwrap());
```

```text
[Error] unknown_ies: IEI 0x5f was ignored as repeated
[Error] unknown_ies: Unknown IEI 0x04 is encoded as comprehension required
```

`answer_to()` gives the answer of clause 7 to what `decode()` returned: an
error, or a message with an unknown IE that is to be understood.
`decode_lenient()` gives the message with its faulty mandatory IE.

```rust
use oxirush_nas::nas_5gs::*;

// REGISTRATION REQUEST whose 5G-GUTI is one octet short
let octets = hex::decode("7e004179000af202f839cafe001122332e02a020").unwrap();
let received = Nas5gsMessage::decode(&octets);
let error = received.clone().unwrap_err();
println!("{error}");

// What a network answers: 5GMM STATUS with cause #96
let answer = Nas5gsMessage::answer_to(&octets, &received, Direction::Uplink).unwrap();
println!("{answer}");
assert_eq!(answer.encode().unwrap(), [0x7e, 0x00, 0x64, 0x60]);

// What the message has, to log it or to treat it all the same
let (message, faults) = Nas5gsMessage::decode_lenient(&octets).unwrap();
assert_eq!(faults, [error]);
println!("{message}");

// A message that is too short is ignored: no answer
let short = [0x7e, 0x00];
let received = Nas5gsMessage::decode(&short);
assert!(Nas5gsMessage::answer_to(&short, &received, Direction::Uplink).is_none());
```

```text
mandatory IE `5gs-mobile-identity` has a value that is syntactically incorrect
5GMM Status (cause=#96 (Invalid mandatory information))
5GMM RegistrationRequest (type=InitialRegistration, FOR, ngKSI=no key, identity=5G-GUTI (f202f839cafe00112233), UE-SecCap=EA0 EA2 / IA2)
```

## A message as JSON

With the `serde` feature a message has two JSON forms. Its tree has the
message type and each IE by its value, and writes a message. Its view has
every IE that the message can have, with its `value` and its `octets`, and
edits a message: `with_view()` encodes the IEs that were edited and keeps
the octets of the others.

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;
use oxirush_nas::tree;

// REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
let reject = Nas5gsMessage::decode(&hex::decode("7e0044165f012a").unwrap()).unwrap();
println!("{}", reject.to_tree());

// In its view, an IE is changed by its value, one comes in by its octets,
// and one goes out
let mut view = reject.to_view();
println!("{}", view["t3346-value"]);
view["5gmm-cause"]["value"] = tree!("illegal-ue");
view["t3502-value"] = tree!({"octets": "2c"});
view["t3346-value"] = tree!(null);
let edited = reject.with_view(view).unwrap();
println!("{}", edited.to_tree());

// A message written from its tree
let status = tree!({"message-type": "5gmm-status", "5gmm-cause": "congestion"});
let status = Nas5gsMessage::from_tree(status).unwrap();
assert_eq!(status.encode().unwrap(), [0x7e, 0x00, 0x64, 0x16]);
```

```json
{"message-type":"registration-reject","5gmm-cause":"congestion","t3346-value":600}
{"value":600,"octets":"2a"}
{"message-type":"registration-reject","5gmm-cause":"illegal-ue","t3502-value":720}
```

The [`view`](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html)
module has the rules of the two forms, the notation of each kind of value,
and examples of the message in a container, the protocol configuration
options, a list, a protected message and octets sent as they are.

## Read and edit by path

`/nas` is the view, and an IE goes by its name in any case.

```rust
use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
use oxirush_nas::tree;

// REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
let accept = Nas5gsMessage::decode(&bytes).unwrap();
let mut tree = accept.to_view();

// A value by its path, and each entry of a list with `*`
let select = |tree, path| view::select(tree, path).unwrap()[0].clone();
println!("{}", select(&tree, "/nas/5g-guti/value/guti/plmn"));
println!("{}", select(&tree, "/NAS/Allowed NSSAI/value/*/SST"));

// A value is set at its path, an optional IE added by its value, and an
// entry put at the end of a list (`-`)
view::set(&mut tree, "/nas/5g-guti/value/guti/tmsi", tree!("0xdeadbeef")).unwrap();
view::set(&mut tree, "/nas/t3512-value/value", tree!(3600)).unwrap();
view::insert(&mut tree, "/nas/allowed-nssai/value/-", tree!({"sst": 2})).unwrap();
let edited = accept.with_view(tree).unwrap();
println!("{}", hex::encode(edited.encode().unwrap()));

// A name that the message does not have is an error
let wrong = view::select(&accept.to_view(), "/nas/t3512/value").unwrap_err();
println!("{wrong}");
```

```text
"208-93"
1
7e0042010177000bf202f839010042deadbeef1504010101025e0106
`t3512` is no IE of a message `registration-accept`, at /nas/t3512/value
```

`view::paths` gives each value of a view with the path that selects it.

## Serialize and deserialize

`Serialize` and `Deserialize` go through the trees, in any format of serde:
a message is written as its tree, and an IE as the tree of a message shows
it.

```rust
use oxirush_nas::nas_5gs::{Nas5gsMessage, NasFGmmCause};

// 5GMM STATUS, cause #22, as a document
let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
let document = serde_json::to_string(&status).unwrap();
println!("{document}");

// The document back to a message, and to its octets
let restored: Nas5gsMessage = serde_json::from_str(&document).unwrap();
assert_eq!(restored.encode().unwrap(), [0x7e, 0x00, 0x64, 0x16]);

// An IE alone
let cause: NasFGmmCause = serde_json::from_value("congestion".into()).unwrap();
assert_eq!(cause.value, 22);
```

```json
{"message-type":"5gmm-status","5gmm-cause":"congestion"}
```

## Limits

- No procedure, timer or transport. The only state is a security context,
  which the caller persists.
- `validate()` does not know the procedure that a message belongs to.
- `encode()` takes every value that a type can hold, so that a test tool can
  send an invalid message.
- 13 5GS and 19 EPS IE types have octets and no value in JSON
  ([which](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html#ie-types-that-have-a-value)).
- Two items follow Release 20 and differ from V19.8.0 on the wire
  ([which](https://docs.rs/oxirush-nas#specification-versions)).

## Performance

On one core of an AMD Ryzen 7 5700G (16 threads, Linux 7.0, Rust 1.98.1),
measured on a quiet machine on 2026-10-18, a message of the 5GS fixtures (17
octets on average), the lowest of five runs:

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

`cargo bench` in `benches/` measures them;
[`benches/src/lib.rs`](benches/src/lib.rs) has the commands of the
profilers.

### Against other implementations

The plain messages of the fixtures that each implementation decodes, and
for encoding those that each writes back to the same octets, on core 2 of
the same machine (Go 1.27, Python 3.14). Times are the lowest of three
runs, and each figure the median of three runs of the script; cycles and
instructions are per message, from `perf stat`, in user mode; peak memory
is that of the whole program; the last column is the time of each against
this crate's. packet-dissector reads a message into fields and writes none.
Open5GS decodes from its packet buffer, made once for each message. Python
counts no allocations.

| Operation | | ns | Cycles | Instructions | Allocations | Octets allocated | Peak memory | Time against oxirush-nas |
|---|---|---|---|---|---|---|---|---|
| decode, 5GS, 76 messages | oxirush-nas | 108.4 | 498 | 1 028 | 1.18 | 225 | 3.7 MiB | |
| | free5GC nas v1.2.3 | 408.9 | 1 835 | 5 782 | 15.95 | 394 | 10.2 MiB | 3.77 |
| | Open5GS v2.8.0 | 1 348.6 | 6 139 | 22 294 | 0 | 0 | 5.5 MiB | 12.4 |
| | packet-dissector 0.6.1 | 147.5 | 674 | 1 361 | 0 | 0 | 3.2 MiB | 1.36 |
| | pycrate 0.8.1 | 257 963 | 1 187 520 | 2 379 701 | | | 51.7 MiB | 2 380 |
| decode, EPS, 95 messages | oxirush-nas | 98.1 | 446 | 855 | 1.06 | 195 | 3.6 MiB | |
| | Open5GS v2.8.0 | 999.9 | 4 509 | 16 398 | 0 | 0 | 6.1 MiB | 10.2 |
| | packet-dissector 0.6.1 | 121.6 | 556 | 1 175 | 0 | 0 | 3.2 MiB | 1.24 |
| | pycrate 0.8.1 | 191 042 | 872 478 | 1 799 598 | | | 49.8 MiB | 1 947 |
| encode, 5GS, 61 messages | oxirush-nas | 33.7 | 145 | 412 | 1.00 | 64 | 3.7 MiB | |
| | free5GC nas v1.2.3 | 156.7 | 692 | 2 034 | 7.28 | 118 | 9.7 MiB | 4.65 |
| | Open5GS v2.8.0 | 1 131.0 | 5 057 | 16 372 | 1.00 | 32 960 | 5.2 MiB | 33.6 |
| | pycrate 0.8.1 | 18 889 | 85 405 | 229 048 | | | 35.2 MiB | 561 |
| encode, EPS, 82 messages | oxirush-nas | 36.5 | 163 | 463 | 1.00 | 64 | 3.7 MiB | |
| | Open5GS v2.8.0 | 1 410.0 | 6 324 | 20 961 | 1.00 | 32 960 | 5.8 MiB | 38.6 |
| | pycrate 0.8.1 | 22 629 | 101 987 | 274 416 | | | 36.0 MiB | 620 |

`benches/compare/compare.sh 3` runs every row on core 3. It fetches each
implementation at the version that it pins, and builds Open5GS's NAS
libraries; perf may need `PERF="sudo -n perf"`.

## Tests and fuzzing

```bash
cargo test "${UNPUBLISHED[@]}" --all-features    # the options of Installation
./fuzz/seed.sh && cargo +nightly fuzz run decode_5gs -- -max_total_time=60 -max_len=512
```

`tests/fixtures` has at least one message of each 5GMM, 5GSM, EMM and ESM
type: each decodes, validates and encodes to its octets, also through its
view and its serde form, and its tree writes a message that means the same.
170 messages that Open5GS, free5GC and PacketRusher sent in a lab decode to
what the dissector of the capture names them. Four fuzz targets run in CI.
`examples/` has six programs, each for 5GS and for EPS.

A pull request comes with a test for what it changes; the Rust blocks of
this page are checked with what they print
([`tests/readme.rs`](tests/readme.rs) says how). The blocks that use other
crates of the family run in the package of [`family/`](family/), which takes
those crates at the revisions that its manifest names. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.

[The documentation](https://docs.rs/oxirush-nas) has what the crate covers,
the receiver and sender rules, the versions of the specifications, the
tests and the examples; `cargo doc "${UNPUBLISHED[@]}" --all-features --open`
in a clone builds it.

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

Inspired by [PacketRusher](https://github.com/HewlettPackard/PacketRusher).
