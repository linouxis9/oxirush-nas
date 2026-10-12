# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A Rust codec for the NAS messages of 5GS and EPS (3GPP TS 24.501 and
TS 24.301, Release 19): it decodes, builds, validates and encodes them
through typed accessors.

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
    println!("MCC={}, MNC={}", plmn.mcc_string(), plmn.mnc_string());
}

// It passes every check that can be made on a single message, and encodes
// to the octets that were decoded
assert!(msg.validate().is_empty());
assert_eq!(bytes, msg.encode().unwrap());

// Build the answer, a REGISTRATION REJECT with cause #22 and a T3346 value
// of ten minutes: `new()` takes the mandatory IEs, `set_*()` adds the others
let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
let t3346 = NasGprsTimer2::from_seconds(600).unwrap();
let reject = NasRegistrationReject::new(cause).set_t3346_value(t3346);
let answer = Nas5gsMessage::new_5gmm(reject);

// Encode it
let octets = answer.encode().unwrap();
assert_eq!(hex::encode(octets), "7e0044165f012a");
```

```text
5GMM RegistrationRequest (type=InitialRegistration, FOR=1, ngKSI=7, identity=SUCI (PLMN=208-93, scheme=0), UE-SecCap=EA0 EA2 / IA2)
MCC=208, MNC=93
```

The output under a block is what the block prints. The examples use the
`hex` crate for the octets.

> This page describes 0.5.0, which is on `master` and unpublished. crates.io
> has 0.4.0: the [changelog](CHANGELOG.md) says how to migrate.

## Install

```toml
[dependencies]
oxirush-nas = "0.5"
```

Until 0.5.0 is published, depend on the repository. Cargo resolves
oxirush-security 0.3.0 for the lockfile with or without the `security`
feature, and it is unpublished too:

```toml
[dependencies]
oxirush-nas = { git = "https://github.com/linouxis9/oxirush-nas", features = ["security"] }

[patch.crates-io]
oxirush-security = { git = "https://github.com/linouxis9/oxirush-security" }
```

[Features](#features) has the three features.

## Messages

A message struct has a public field for each IE. `nas_5gs` and `nas_eps`
have the same interface, and the crate root re-exports `nas_5gs`.

### Change a decoded message

An optional IE is an `Option`, with `set_<ie>_mut()`, `has_<ie>()` and
`clear_<ie>()`.

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
    assert!(!reject.has_t3502_value());

    // Another cause, T3346 taken out and T3502 added
    reject.fgmm_cause = NasFGmmCause::from_cause(GmmCause::IllegalUe);
    reject.clear_t3346_value();
    reject.set_t3502_value_mut(NasGprsTimer2::from_seconds(720).unwrap());
}

assert_eq!(hex::encode(msg.encode().unwrap()), "7e00440316012c");
```

### EPS

```rust
use oxirush_nas::nas_eps::*;

// Decode an ATTACH REQUEST with an IMSI and a PDN CONNECTIVITY REQUEST
let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
let msg = NasEpsMessage::decode(&bytes).unwrap();
println!("{msg}");
assert!(msg.validate().is_empty());

// Read its IEs, and the ESM message in its container
if let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &msg {
    let imsi = request.eps_mobile_identity.as_imsi();
    assert_eq!(imsi.as_deref(), Some("208930000000001"));
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
```

```text
EMM AttachRequest (type=EpsAttach, KSI=Native(0), identity=IMSI 208930000000001, UE-NetCap=EEA0 EEA1 EEA2 / EIA0 EIA1 EIA2, ESM=4B)
ESM (EBI=0, PTI=1) PdnConnectivityRequest (request=Initial, PDN=Ipv4v6)
```

### Validate a message

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
assert!(msg.unknown_ies()[1].is_comprehension_required());
assert_eq!(bytes, msg.encode().unwrap());
```

```text
[Error] unknown_ies: IEI 0x5F was ignored as repeated
[Error] unknown_ies: Unknown IEI 0x04 is encoded as comprehension required
```

### What a constructor refuses

A `from_*`, `with_*` or `set_*` that refuses returns a `ValueError`: the
member, what it was given and the limit.

```rust
use oxirush_nas::nas_5gs::*;

// One error type: `?` takes the refusal of any constructor
fn timers(t3512: u64, zone: i8) -> Result<(NasGprsTimer3, NasTimeZone), ValueError> {
    let t3512 = NasGprsTimer3::from_seconds(t3512)?;
    Ok((t3512, NasTimeZone::from_quarter_hours(zone)?))
}
assert!(timers(3600, 4).is_ok());
println!("{}", timers(3600, 80).unwrap_err());
println!("{}", timers(3601, 4).unwrap_err());

// Digits, the entries of a list and one of them, members that do not go together
let plmn = PlmnId::new("208", "93").unwrap();
println!("{}", PlmnId::new("208", "9").unwrap_err());
println!("{}", NasPlmnList::from_plmns(&[plmn; 16]).unwrap_err());
let causes = [(5, GmmCause::Congestion), (16, GmmCause::Congestion)];
println!("{}", NasPduSessionReactivationResultErrorCause::from_entries(&causes).unwrap_err());
let mut slice = NasSNssai::new(vec![1]).parse().unwrap();
slice.mapped_sd = Some([0, 0, 1]);
println!("{}", slice.to_snssai().unwrap_err());

// The parts of a refusal
let error = NasTimeZone::from_quarter_hours(80).unwrap_err();
assert_eq!(error.member, "time-zone");
assert_eq!(error.fault, ValueFault::Range { given: 80, min: -79, max: 79 });
```

```text
`time-zone` is 80, and is -79 to 79
`seconds` is 3601, and is up to 31 times 2 or 30 seconds, 1 or 10 minutes, or 1 or 10 hours
`mnc` has 1 digit, and has 2 to 3
`plmns` has 16 entries, and has 1 to 15
entry 1: `pdu-session-identity` is 16, and is 1 to 15
`mapped-sd` is written with `mapped-sst`
```

## Security

With the `security` feature. A context has the NAS keys, the algorithms and
the next NAS COUNT of each direction.

```rust
use oxirush_nas::nas_5gs::ie::{CipheringAlgorithm, IntegrityAlgorithm};
use oxirush_nas::nas_5gs::{
    Direction, Nas5gsMessage, Nas5gsSecurityHeaderType, NasSecurityContext,
};

// REGISTRATION REJECT, cause #3
let msg = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();

// The two ends of one link: the same keys and the same algorithms
let (knas_int, knas_enc) = ([0u8; 16], [0u8; 16]);
let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
let mut tx = NasSecurityContext::from_fresh_keys(knas_int, knas_enc, nia, nea).unwrap();
let mut rx = NasSecurityContext::from_fresh_keys(knas_int, knas_enc, nia, nea).unwrap();

// Protect outbound: integrity and ciphering
let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();

// Unprotect inbound: MAC check, deciphering and decoding
let (decoded, header_type) = rx.unprotect(&protected, Direction::Downlink).unwrap();
assert_eq!((decoded, header_type), (msg, sht));
```

The EPS context starts from KASME:

```rust
use oxirush_nas::nas_eps::{
    CipheringAlgorithm, Direction, IntegrityAlgorithm, NasEpsMessage,
    NasEpsSecurityHeaderType, NasSecurityContext,
};

// ATTACH REJECT, cause #3
let msg = NasEpsMessage::decode(&[0x07, 0x44, 0x03]).unwrap();

// The two ends of one link: the same KASME and the same algorithms
let kasme = [0x11; 32];
let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
let mut tx = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
let mut rx = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();

// Protect outbound: integrity and ciphering
let sht = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();

// Unprotect inbound: MAC check, deciphering and decoding
let (decoded, header_type) = rx.unprotect(&protected, Direction::Downlink).unwrap();
assert_eq!((decoded, header_type), (msg, sht));
```

[`nas_5gs::security`](https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/security/index.html)
says how to restore a context after a restart, change its algorithms and
protect an invalid payload for a negative test.

## JSON

With the `serde` feature and the `serde_json` crate, a message is a
`serde_json::Value` in two forms. A tree has the message type and each IE by
its value. A view has every IE that the message can have, with its `value`
and its `octets`.

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;

// 5GMM STATUS, cause #22
let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();

// Its tree, then its view
println!("{}", status.to_tree());
println!("{:#}", status.to_view());
```

```json
{"5gmm-cause":"congestion","message-type":"5gmm-status"}
```

```json
{
  "5gmm-cause": {
    "octets": "16",
    "value": "congestion"
  },
  "extended-protocol-discriminator": {
    "value": 126
  },
  "message-type": {
    "value": "5gmm-status"
  },
  "security-header-type": {
    "value": "plain-nas-message"
  },
  "spare-half-octet": {
    "value": 0
  }
}
```

### Edit a tree

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;
use serde_json::json;

// Decode the REGISTRATION REJECT
let bytes = hex::decode("7e0044165f012a").unwrap();
let reject = Nas5gsMessage::decode(&bytes).unwrap();

// Show it as a tree
let mut tree = reject.to_tree();
println!("{tree:#}");

// Change a value, and encode the message that the tree writes
tree["t3346-value"] = json!(1200);
let edited = Nas5gsMessage::from_tree(tree).unwrap();
assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044165f0134");
```

```json
{
  "5gmm-cause": "congestion",
  "message-type": "registration-reject",
  "t3346-value": 600
}
```

### Read an IE

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;

// REGISTRATION ACCEPT with a 5G-GUTI, the temporary identity that the network
// gives the UE, and an allowed NSSAI, the network slices that it may use
let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
let accept = Nas5gsMessage::decode(&bytes).unwrap();
let view = accept.to_view();

// An IE with its value and its octets
println!("{:#}", view["5g-guti"]);

// A member of a value, and of an entry of a list
assert_eq!(view["5g-guti"]["value"]["guti"]["plmn"], "208-93");
assert_eq!(view["allowed-nssai"]["value"][0]["sst"], 1);

// An optional IE that the message does not have
assert!(view["t3512-value"].is_null());
```

```json
{
  "octets": "f202f83901004211223344",
  "value": {
    "guti": {
      "amf-pointer": 2,
      "amf-region-id": 1,
      "amf-set-id": 1,
      "plmn": "208-93",
      "tmsi": 287454020
    }
  }
}
```

### Change a value

`with_view()` encodes the IEs that were edited and keeps the octets of the
others.

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;
use serde_json::json;

// REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
let accept = Nas5gsMessage::decode(&bytes).unwrap();
println!("{}", accept.to_view()["allowed-nssai"]);

// The slice gets an SD, and the 5G-GUTI another TMSI
let mut view = accept.to_view();
view["allowed-nssai"]["value"][0]["sd"] = json!("010203");
view["5g-guti"]["value"]["guti"]["tmsi"] = json!("0xdeadbeef");
let edited = accept.with_view(view).unwrap();

// The allowed NSSAI and the octets of the edited message
println!("{}", edited.to_view()["allowed-nssai"]);
assert_eq!(
    hex::encode(edited.encode().unwrap()),
    "7e0042010177000bf202f839010042deadbeef15050401010203"
);
```

```json
{"octets":"0101","value":[{"mapped-sd":null,"mapped-sst":null,"sd":null,"sst":1}]}
{"octets":"0401010203","value":[{"mapped-sd":null,"mapped-sst":null,"sd":"010203","sst":1}]}
```

### Add or remove an IE

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;
use serde_json::json;

// REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
let bytes = hex::decode("7e0044165f012a").unwrap();
let reject = Nas5gsMessage::decode(&bytes).unwrap();
println!("{}", reject.to_tree());

// One optional IE comes in, another goes out
let mut view = reject.to_view();
view["t3502-value"] = json!({"value": 720}); // added by its value, or by its octets
view["t3346-value"] = json!(null); // taken out
let edited = reject.with_view(view).unwrap();

// The tree and the octets of the edited message
println!("{}", edited.to_tree());
assert_eq!(hex::encode(edited.encode().unwrap()), "7e00441616012c");
```

```json
{"5gmm-cause":"congestion","message-type":"registration-reject","t3346-value":600}
{"5gmm-cause":"congestion","message-type":"registration-reject","t3502-value":720}
```

Removing a mandatory IE is an error.

### Send octets as they are

The length of the IE follows its octets. In a tree, `{"octets": "2a2b"}`
takes the place of the value.

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;
use serde_json::json;

// REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
let bytes = hex::decode("7e0044165f012a").unwrap();
let reject = Nas5gsMessage::decode(&bytes).unwrap();
println!("{}", reject.to_view()["t3346-value"]);

// A T3346 value of two octets, where the specification has one
let mut view = reject.to_view();
view["t3346-value"]["octets"] = json!("2a2b");
let edited = reject.with_view(view).unwrap();

// The IE and the octets of the edited message
println!("{}", edited.to_view()["t3346-value"]);
assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044165f022a2b");

// The 5GMM cause has no length: it is one octet
let mut view = reject.to_view();
view["5gmm-cause"]["octets"] = json!("ffff");
println!("{}", reject.with_view(view).unwrap_err());
```

```json
{"octets":"2a","value":600}
{"octets":"2a2b","value":600}
```

```text
cannot encode: 5gmm-cause: "ffff" is not 1 octets
```

### Write a message from its name

```rust
use oxirush_nas::nas_5gs::{Nas5gmmMessageType, Nas5gsMessage};
use serde_json::json;

// A REGISTRATION REJECT by the name of its type and of its IEs
let reject = Nas5gsMessage::from_tree(json!({
    "message-type": "registration-reject",
    "5gmm-cause": "congestion",
    "t3346-value": 600,
}))
.unwrap();
assert_eq!(hex::encode(reject.encode().unwrap()), "7e0044165f012a");

// A 5GSM message writes the fields of its header that its type does not decide
let complete = Nas5gsMessage::from_tree(json!({
    "message-type": "pdu-session-release-complete",
    "pdu-session-identity": 5,
    "procedure-transaction-identity": 1,
}))
.unwrap();
assert_eq!(hex::encode(complete.encode().unwrap()), "2e0501d4");

// A mandatory IE that is left out is an error
let tree = json!({"message-type": "registration-reject"});
println!("{}", Nas5gsMessage::from_tree(tree).unwrap_err());

// A value that its IE cannot carry says the member and the limit
let tree = json!({"message-type": "service-accept", "pdu-session-status": [5, 16]});
println!("{}", Nas5gsMessage::from_tree(tree).unwrap_err());

// What a message of a type can have, in the order of the message
println!("{:?}", Nas5gmmMessageType::AuthenticationFailure.view_names());
```

```text
cannot encode: `5gmm-cause` is not written
cannot encode: pdu-session-status: entry 1: `pdu-session-identity` is 16, and is 1 to 15
["extended-protocol-discriminator", "security-header-type", "spare-half-octet", "message-type", "5gmm-cause", "authentication-failure-parameter"]
```

`blank_view()` of a message type is the view to fill.

### The message in a container

```rust
use oxirush_nas::nas_eps::NasEpsMessage;
use serde_json::json;

// ATTACH REQUEST with a PDN CONNECTIVITY REQUEST in its ESM message container
let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
let attach = NasEpsMessage::decode(&bytes).unwrap();
println!("{:#}", attach.to_tree()["esm-message-container"]);

// In a view, the value of the container is the view of its message
let mut view = attach.to_view();
view["esm-message-container"]["value"]["pdn-type"]["value"] = json!("ipv6");
let edited = attach.with_view(view).unwrap();

// The PDN type and the octets of the edited message
println!("{}", edited.to_tree()["esm-message-container"]["pdn-type"]);
assert_eq!(
    hex::encode(edited.encode().unwrap()),
    "07410108298039000000001002e0e000040201d021"
);
```

```json
{
  "eps-bearer-identity": 0,
  "message-type": "pdn-connectivity-request",
  "pdn-type": "ipv4v6",
  "procedure-transaction-identity": 1,
  "request-type": "initial"
}
```

```json
"ipv6"
```

### The protocol configuration options

The value is the list of units. An identifier is a request from the UE and
an answer from the network, so a unit takes its name from the type of the
message. PAP, CHAP, IPCP and LCP packets have the
[names of their protocol](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html#units-of-the-protocol-configuration-options).

```rust
use oxirush_nas::nas_eps::NasEpsMessage;
use serde_json::json;

// PDN CONNECTIVITY REQUEST with the credentials of PAP and a request for
// the address of a DNS server
let request = NasEpsMessage::from_tree(json!({
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
```

```json
[
  {
    "pap": {
      "code": "authenticate-ack",
      "identifier": 1,
      "message": "",
      "password": null,
      "peer-id": null
    }
  },
  {
    "dns-server-ipv4-address": "8.8.8.8"
  }
]
```

### Edit a list

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;
use serde_json::json;

// REGISTRATION ACCEPT with an extended emergency number list: 112
let bytes = hex::decode("7e004201017a0005000211f200").unwrap();
let accept = Nas5gsMessage::decode(&bytes).unwrap();
let mut view = accept.to_view();
println!("{}", view["extended-emergency-number-list"]["value"]);

// A number of the police is added
let numbers = &mut view["extended-emergency-number-list"]["value"]["numbers"];
let police = json!({"digits": "17", "sub-services": "police"});
numbers.as_array_mut().unwrap().push(police);
let edited = accept.with_view(view).unwrap();

// The list of the edited message
println!("{}", edited.to_view()["extended-emergency-number-list"]["octets"]);
```

```json
{"numbers":[{"digits":"112","sub-services":""}],"valid-only-in-plmn":false}
"000211f200017106f0373b3d2e03"
```

### A protected message

A view computes no MAC and ciphers nothing: a
[security context](#security) does.

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;
use serde_json::json;

// 5GMM STATUS under an integrity protected header
let bytes = hex::decode("7e01e73b901b007e006416").unwrap();
let protected = Nas5gsMessage::decode(&bytes).unwrap();
println!("{:#}", protected.to_tree());

// An edit that leaves the old MAC in the security header is refused
let mut view = protected.to_view();
view["5gmm-cause"]["value"] = json!("illegal-ue");
println!("{}", protected.with_view(view.clone()).unwrap_err());

// The view writes the code of the edited message
view["security-header"]["value"]["message-authentication-code"] = json!("0x01020304");
let edited = protected.with_view(view).unwrap();
assert_eq!(hex::encode(edited.encode().unwrap()), "7e0101020304007e006403");

// A message that is ciphered has its octets
let bytes = hex::decode("7e024b708bc300026ff75c").unwrap();
let ciphered = Nas5gsMessage::decode(&bytes).unwrap();
println!("{}", ciphered.to_tree()["ciphered-message"]);
```

```json
{
  "5gmm-cause": "congestion",
  "message-type": "5gmm-status",
  "security-header": {
    "extended-protocol-discriminator": 126,
    "message-authentication-code": 3879440411,
    "security-header-type": "integrity-protected",
    "sequence-number": 0,
    "spare-half-octet": 0
  }
}
```

```text
cannot encode: the message authentication code of `security-header` is that of the message as it was: write the code of the edited message, or edit the plain message
```

```json
{"octets":"026ff75c"}
```

`from_tree()` writes a message under the `security-header` of its tree, with
the MAC that the tree has.

### Select by path

`/nas` is the view, and an IE goes by its name.

```rust
use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
use serde_json::json;

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
assert_eq!(select("/nas/message-type/value"), [&json!("registration-accept")]);
assert_eq!(select("/nas/5gs-registration-result/value/result"), [&json!("3gpp-access")]);
assert_eq!(select("/nas/5g-guti/value/guti/tmsi"), [&json!(0x1122_3344)]);
assert_eq!(select("/nas/allowed-nssai/octets"), [&json!("0101")]);

// A name in any case, and `*` for each entry of a list
assert_eq!(select("/NAS/Allowed NSSAI/value/*/SST"), [&json!(1)]);

// An optional IE that the message does not have selects nothing
assert!(select("/nas/t3512-value/value").is_empty());

// A name that the message does not have is an error
assert!(view::select(&tree, "/nas/t3512/value").is_err());
```

```text
/nas/5g-guti/octets = "f202f83901004211223344"
/nas/5g-guti/value/guti/amf-pointer = 2
/nas/5g-guti/value/guti/amf-region-id = 1
/nas/5g-guti/value/guti/amf-set-id = 1
/nas/5g-guti/value/guti/plmn = "208-93"
/nas/5g-guti/value/guti/tmsi = 287454020
/nas/5gs-registration-result/octets = "01"
/nas/5gs-registration-result/value/disaster-roaming = false
/nas/5gs-registration-result/value/emergency-registered = false
/nas/5gs-registration-result/value/nssaa-performed = false
/nas/5gs-registration-result/value/result = "3gpp-access"
/nas/5gs-registration-result/value/sms-allowed = false
/nas/allowed-nssai/octets = "0101"
/nas/allowed-nssai/value/0/sst = 1
/nas/extended-protocol-discriminator/value = 126
/nas/message-type/value = "registration-accept"
/nas/security-header-type/value = "plain-nas-message"
/nas/spare-half-octet/value = 0
```

The message in a container is under the `value` of the container:
`/nas/esm-message-container/value/pdn-type/value`.

### Edit by path

```rust
use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
use serde_json::json;

// The same REGISTRATION ACCEPT
let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
let accept = Nas5gsMessage::decode(&bytes).unwrap();

// A value is set at its path
let mut tree = accept.to_view();
view::set(&mut tree, "/nas/5g-guti/value/guti/tmsi", json!("0xdeadbeef")).unwrap();
view::set(&mut tree, "/nas/allowed-nssai/value/0/sd", json!("010203")).unwrap();

// An optional IE that the message does not have is added by its value
view::set(&mut tree, "/nas/t3512-value/value", json!(3600)).unwrap();

// The message of the edited view
let edited = accept.with_view(tree).unwrap();
assert_eq!(
    hex::encode(edited.encode().unwrap()),
    "7e0042010177000bf202f839010042deadbeef150504010102035e0106"
);

// A list takes an entry before a position or at its end (`-`), and loses one
let mut tree = accept.to_view();
let slice = json!({"sst": 2, "sd": "0000ff"});
view::insert(&mut tree, "/nas/allowed-nssai/value/-", slice).unwrap();
view::remove(&mut tree, "/nas/allowed-nssai/value/0").unwrap();

let edited = accept.with_view(tree).unwrap();
assert_eq!(edited.to_view()["allowed-nssai"]["octets"], "04020000ff");
```

### The serde form

`Serialize` and `Deserialize` use the field names of the codec and keep the
unknown IEs.

```rust
use oxirush_nas::nas_5gs::Nas5gsMessage;

// 5GMM STATUS, cause #22, as a document
let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
let document = serde_json::to_value(&status).unwrap();
println!("{document}");

// The document back to a message, and to its octets
let restored: Nas5gsMessage = serde_json::from_value(document).unwrap();
assert_eq!(restored.encode().unwrap(), [0x7e, 0x00, 0x64, 0x16]);
```

```json
{"Gmm":[{"extended_protocol_discriminator":126,"message_type":"FGmmStatus","security_header_type":"PlainNasMessage","spare_half_octet":0},{"FGmmStatus":{"fgmm_cause":{"value":22},"optional_ie_order":[],"unknown_ies":[]}}]}
```

The [`view`](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html)
module documents the rules of the two forms, the notation of each kind of
value and the IE types that have octets alone.

## Features

| Feature | Adds | Dependencies |
|---------|------|--------------|
| `std` (default) | the standard library | |
| `security` | `NasSecurityContext`: `protect` and `unprotect` | `oxirush-security`, `zeroize` |
| `serde` | `Serialize` and `Deserialize`; with `std`, trees, views and paths | `serde`, `serde_json` |

With `default-features = false` the crate is `no_std` and needs an allocator:
the codec, `validate()`, the builders and `Display` are the same. `security`
and the `serde` derives are `no_std` too. The JSON forms need `std`, and
with `std` oxirush-security chooses the vector code of SNOW 3G and ZUC from
what the processor has. The minimum Rust version is 1.88.

## Performance

One message of the 5GS fixtures (17 octets on average), on one core of a
desktop processor:

| Operation | Time | Allocations |
|-----------|------|-------------|
| `decode` | 115 ns | 1.2 |
| `encode` | 49 ns | 1.0 |
| `validate` | 234 ns | 3.3 |
| `to_view` | 4.8 µs | 73 |
| `with_view` | 18 µs | 146 |
| `to_tree` | 18 µs | 299 |
| `from_tree` | 38 µs | 380 |
| `protect`, `unprotect` (128-NIA2, 128-NEA2) | 637 ns, 609 ns | 3.4, 2.4 |

`cargo bench` in `benches/` measures them;
[`benches/src/lib.rs`](benches/src/lib.rs) has the commands of the
profilers.

## Tests and fuzzing

`tests/fixtures` has at least one message of each 5GMM, 5GSM, EMM and ESM
type: each decodes, validates and encodes to its octets, also through its
JSON forms. The Rust blocks of this page run as documentation tests, and
`tests/readme.rs` compares what they print with the output shown. Four fuzz
targets run in the continuous integration
([detail](https://docs.rs/oxirush-nas#tests)).

In a clone, `--config` takes oxirush-security from its repository until
0.3.0 is on crates.io:

```bash
SECURITY='patch.crates-io.oxirush-security.git="https://github.com/linouxis9/oxirush-security"'
cargo test --config "$SECURITY" --all-features
cargo run --config "$SECURITY" --example decode_message_nas_5gs
cargo doc --config "$SECURITY" --all-features --no-deps --open
./fuzz/seed.sh && cargo +nightly fuzz run decode_5gs -- -max_total_time=60 -max_len=512
```

`examples/` has [six programs](https://docs.rs/oxirush-nas#examples), each
for 5GS and for EPS.

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

## Documentation

On docs.rs:
[what the crate covers](https://docs.rs/oxirush-nas#what-the-crate-covers),
[receiver and sender rules](https://docs.rs/oxirush-nas#receiving-and-sending),
[specification versions](https://docs.rs/oxirush-nas#specification-versions).
It has 0.4.0 until 0.5.0 is published; `cargo doc` in a clone builds this
version.

## OxiRush crates

[oxirush-security](https://github.com/linouxis9/oxirush-security) (NAS keys
and algorithms) ·
[oxirush-ngap](https://github.com/linouxis9/oxirush-ngap) and
[oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap) (the protocols
that carry NAS) ·
[oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u) (user plane) ·
[oxirush-sctp](https://github.com/linouxis9/oxirush-sctp) (transport)

## Contributing

Open a pull request against `master` with a test for what it changes.
`cargo test --all-features` and `cargo clippy --all-targets --all-features`
pass on every commit. Sign off your commits (`git commit -s`), which agrees
to the [Developer Certificate of Origin](https://developercertificate.org/).
[SECURITY.md](SECURITY.md) says how to report a vulnerability.

## License

Copyright 2025-2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

Inspired by [PacketRusher](https://github.com/HewlettPackard/PacketRusher).
