# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> This page describes the unreleased 0.5.0, the `master` branch. crates.io has
> 0.4.0, whose API differs: the [changelog](CHANGELOG.md) says how to migrate.

A Rust codec for the NAS (non-access stratum) messages of 5GS and EPS (4G):
the signalling between a UE and its core network, per 3GPP TS 24.501 and
TS 24.301. It decodes, builds, validates and encodes the messages of 5GS
mobility and session management (5GMM, 5GSM) and of EPS mobility and session
management (EMM, ESM) through typed accessors, without `unsafe` code. Two
optional features add NAS security, and a JSON form in which a message is
read, written and edited by the names that the specification gives its
information elements (IEs).

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

The output under a block is what the block prints, here and on the rest of
the page. This block needs no feature, and the `hex` crate for the octets.

It is one of the OxiRush crates, with
[oxirush-security](https://github.com/linouxis9/oxirush-security) (the keys
and algorithms of NAS security),
[oxirush-ngap](https://github.com/linouxis9/oxirush-ngap) and
[oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap) (the protocols that
carry NAS messages between a base station and the core),
[oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u) (the user plane)
and [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp) (their
transport).

With the `serde` feature and `serde_json`, the same REGISTRATION REJECT is
also a tree of JSON:

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

[Installation](#installation) ·
[Covered](#what-the-crate-covers) ·
[Not covered](#what-the-crate-does-not-cover) ·
[Typed API](#typed-api) ·
[Security](#security) ·
[JSON cookbook](#json-trees-views-and-paths) ·
[Rules](#rules) ·
[Examples](#examples) ·
[Specifications](#specifications) ·
[Tests](#tests) ·
[Benchmarks](#benchmarks) ·
[API reference](https://docs.rs/oxirush-nas)

## Installation

```toml
[dependencies]
oxirush-nas = "0.5"
# With the optional features:
# oxirush-nas = { version = "0.5", features = ["security", "serde"] }

# For the examples of this page:
hex = "0.4"
serde_json = "1" # with the `serde` feature
```

| Feature | Adds | Through |
|---------|------|---------|
| `security` | 5GS and EPS NAS security contexts: `protect` and `unprotect` | `oxirush-security` without its default features, `zeroize` |
| `serde` | `Serialize` and `Deserialize` for messages, headers and typed IE values, and a message as a `serde_json::Value`: its tree, its view and their paths | `serde`, `serde_json` |

No feature is on by default. The minimum supported Rust version is 1.88. The
examples of this page also use the `hex` crate, and `serde_json` for JSON.

Until 0.5.0 is published, depend on the repository. The `security` feature
needs oxirush-security 0.3.0, which is not published either:

```toml
[dependencies]
oxirush-nas = { git = "https://github.com/linouxis9/oxirush-nas", features = ["security"] }

[patch.crates-io]
oxirush-security = { git = "https://github.com/linouxis9/oxirush-security" }
```

## What the crate covers

| Area | Contents |
|------|----------|
| 5GS messages | All 5GMM and 5GSM messages of TS 24.501, and the UE policy delivery service (Annex D) |
| EPS messages | All EMM and ESM messages of TS 24.301 clause 8, with the short SERVICE REQUEST header, EMM TRANSPORT and security-protected envelopes |
| IEs | 169 5GS and 153 EPS types, each the value of its IE, which a message has in the V, LV, LV-E, TV, TLV and TLV-E formats of TS 24.007 §11.2 |
| Typed accessors | Enums, value structs and `set_*`/`with_*` builders instead of bit manipulation. One implementation for the IEs that both specifications code alike: UE network capability, KSI, NAS security algorithms, GPRS timers, PCO/ePCO units, APN/DNN, PLMN lists, network name, time zone, eDRX and emergency numbers, for example |
| Errors | `NasError` separates the classes of clause 7: too-short messages, unknown protocol discriminators and message types, reserved security header types, invalid mandatory IEs |
| Display | `fmt::Display` for every message, with causes, identities and algorithms decoded |
| Round trip | Decoding then encoding keeps unknown IEs, ignored repetitions, the order of the optional IEs and the spare half octet of a header |
| `security` | Integrity and ciphering with NAS COUNT tracking and replay protection per TS 33.501 and TS 33.401, the EPS short MAC, partial ciphering of CONTROL PLANE SERVICE REQUEST containers and 5GS↔EPS mapped contexts |
| `serde` | Messages, headers and typed IE values as JSON that re-encodes to the octets that were decoded, and each message as a tree and a view: every IE by its name, with its value in the usual notation and its octets |

## What the crate does not cover

| Subject | Limit |
|---------|-------|
| Procedures | It is a codec: no NAS procedure, timer or transport. Its only state is that of a security context. |
| Validity | `validate()` sees one message, not the state of a procedure. Encoding accepts every value a type can represent, so a message that encodes is not thereby valid. |
| Security state | A context does not persist itself: the caller keeps the next COUNT values and restores it from them. |
| Construction | No struct literals for message structs: they are built with `new()` and `set_*()`. |
| JSON | 14 5GS and 21 EPS IE types have octets alone, and 3 and 2 a value that is read only ([which](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html#ie-types-that-have-a-value)). A view has no unknown IEs, and computes no message authentication code. |
| Serde form | The order of the optional IEs in it is decode bookkeeping, not a stable format. |
| Release 19 | Two items follow Release 20 and differ from V19.8.0 on the wire ([Specifications](#specifications)). |
| Evidence | The tests of the crate itself ([Tests](#tests)). The provenance of the 15 legacy 5GS wire values was not recorded. |

## Typed API

The example at the top of this page decodes, reads, validates, encodes and
builds a 5GS message. The crate root re-exports the 5GS API for existing
users; `nas_5gs` and `nas_eps` are the paths for code that handles both
protocols.

### Change a decoded message

The IEs of a message are public fields of its struct, and an optional IE is
an `Option`. Beside the `set_<ie>()` of a builder, an optional IE has
`set_<ie>_mut()`, `get_<ie>()`, `has_<ie>()` and `clear_<ie>()`.

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

`nas_eps` has the same interface.

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

### Validate what was received

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

### Receiving and sending

Decoding follows the receiver rules of TS 24.007 §11 and of the two protocol
specifications: spare bits and octets beyond a value are ignored, an unknown
IE is skipped and kept, a repeated IE or an optional IE that is wrong is
treated as absent and kept, and a mandatory IE that is wrong fails the
message with `NasError::InvalidMandatoryIe`. `validate()` and
`is_well_formed()` check what a sender must produce. Encoding accepts every
value a type can represent, so a test tool can send what is invalid, and no
public function panics on its arguments. The
[front page of the documentation](https://docs.rs/oxirush-nas#receiving-and-sending)
has the rule of each case.

## Security

With the `security` feature. A protected message is under a security header
with a message authentication code (MAC), and may be ciphered. A context has
the NAS keys, the algorithms and the next NAS COUNT of each direction, and
in 5GS of each access: the COUNT numbers the messages of a direction, and
goes into each code so that a message is not accepted twice. The keys come
from KAMF in 5GS and from KASME in EPS, the key that the UE and the network
share after authentication.

`from_fresh_*` starts every COUNT at zero, so it is only for keys that were
just established (TS 33.501 §6.4.5, TS 33.401 §6.5). After a restart,
`restore_from_*` takes the next COUNT values, which the caller persisted.
Under an existing KAMF or KASME, `reselect_algorithms` changes the algorithms
and keeps the COUNTs. A context is not `Clone`: the two below are the two
ends of one link.

A context is made of algorithms that exist: a reserved code, and the null
integrity algorithm with another cipher than the null one, are errors. A
COUNT is a `NasCount` and a 5GS access a `NasConnection`, both of
[oxirush-security](https://github.com/linouxis9/oxirush-security) and
re-exported by the `security` modules; the next COUNT of a direction is
`None` once all its COUNTs were used.

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

The EPS context has the same interface, from a KASME:

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

`protect` and `protect_bytes` validate the inner message. For negative tests,
`protect_opaque_payload` ciphers and integrity-protects any inner octets
under security header types 1 to 4.

## JSON: trees, views and paths

With the `serde` feature a message is a `serde_json::Value` in two forms,
which `Nas5gsMessage` and `NasEpsMessage` have alike. A tree is the compact
form, in which a message is shown and written; a view edits a message and
keeps what it does not touch.

| | Tree | View |
|---|------|------|
| From a message | [`to_tree()`] | [`to_view()`] |
| An IE is | its value, or `{"octets": "…"}` when it has no readable one | its `value` and its `octets` |
| It has | the `message-type` and the IEs that the message has | the fields of the header and every IE that the message can have, `null` for one that it has not |
| Back to a message | [`from_tree()`]: a message written from the tree alone | [`with_view()`]: this message, edited; [`from_view()`]: a message written from the view alone |

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

An IE whose value changed is encoded from it, and the rest of the message
keeps its octets.

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

A mandatory IE stays: taking `5gmm-cause` out is an error.

### Send octets as they are

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

The length of the IE follows its octets. In a tree, `{"octets": "2a2b"}`
takes the place of the value.

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

// What a message of a type can have, in the order of the message
println!("{:?}", Nas5gmmMessageType::AuthenticationFailure.view_names());
```

```text
cannot encode: `5gmm-cause` is not written
["extended-protocol-discriminator", "security-header-type", "spare-half-octet", "message-type", "5gmm-cause", "authentication-failure-parameter"]
```

[`blank_view()`] of a message type is the view to fill: an object for each
entry that a view has to write, and `null` for each optional IE.

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

### A protected message

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

A view computes no code and ciphers nothing: [Security](#security) does.
`from_tree()` writes the message of a tree with a `security-header` under
that header, with the code that the tree has; `from_view()` writes plain
messages.

### Select by path

The [`view`] module reads and edits a view by paths, in which `/nas` stands
for the view and an IE goes by its name.

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

The message in a container is under the `value` of the container, as in
`/nas/esm-message-container/value/pdn-type/value`.

### Edit by path

`view::set`, `view::insert` and `view::remove` write at the same paths, and
`with_view()` gives the message of the edited view.

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

`Serialize` and `Deserialize` give a message with the fields of the codec. A
document re-encodes to the octets that were decoded, unknown IEs included.

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

### Rules

A name is that of the specification in lower case with hyphens, and is read
by its letters and digits whatever is between them. A `value` says what an
IE means, by name where the specification names a code; `octets` are the
value part of the IE in hexadecimal, and are sent as they are written.
Nothing that is written is ignored: a name that the message does not have, a
value that its IE cannot carry and a mandatory IE that is left out are
errors. The documentation of the [`view`] module has every rule, the
notation of each kind of value, and the IE types that have no value or one
that is read only.

## Examples

Each example has a 5GS and an EPS counterpart, `<name>_nas_5gs` and
`<name>_nas_eps`, for the same procedure.

| Example | 5GS | EPS | Feature |
|---------|-----|-----|---------|
| `build_message` | REGISTRATION REJECT | ATTACH REJECT | |
| `build_mobility_request` | mobility registration update REGISTRATION REQUEST | TRACKING AREA UPDATE REQUEST | |
| `decode_message` | REGISTRATION REQUEST with typed accessors | ATTACH REQUEST with typed accessors | |
| `validate_message` | registration, authentication, and security mode messages | attach, authentication, and security mode messages | |
| `security` | protect and unprotect with keys from KAMF | protect and unprotect with keys from KASME | `security` |
| `view_message` | REGISTRATION REQUEST read and edited through its view, by the paths of its IEs | ATTACH REQUEST read and edited through its view, by the paths of its IEs | `serde` |

Until oxirush-security 0.3.0 is on crates.io, a `cargo` command in a clone
of this repository takes it from its repository, with `--config`. Cargo
resolves it even for a command that does not use the `security` feature:

```bash
SECURITY='patch.crates-io.oxirush-security.git="https://github.com/linouxis9/oxirush-security"'
cargo run --config "$SECURITY" --example build_message_nas_5gs
cargo run --config "$SECURITY" --features security --example security_nas_eps
cargo run --config "$SECURITY" --features serde --example view_message_nas_5gs
```

## Specifications

| Specification | Version | For |
|---------------|---------|-----|
| TS 24.501 | V19.8.0 (Release 19) | 5G NAS protocol: message definitions, IE formats, procedures |
| TS 24.301 | V19.8.0 (Release 19) | EPS NAS protocol: EMM and ESM messages and IE tables |
| TS 24.007 | | IE encoding formats (V, LV, TLV, etc.) and receiver rules |
| TS 24.008 | | IEs that TS 24.301 and TS 24.501 delegate: PCO, TFT, QoS, timers, identities |
| TS 23.003 | | identity formats: IMSI, IMEI, GUTI, APN |
| TS 23.038 | | GSM 7-bit default alphabet: network names, emergency number sub-services |
| TS 33.501 | | 5G security architecture: NAS security, key derivation, algorithms |
| TS 33.401 | | EPS security architecture: key derivation, NAS security, algorithms |

Two items follow TS 24.501 V20.1.0 (Release 20) instead, and differ from
V19.8.0 on the wire:

| Item | This crate, as V20.1.0 | V19.8.0 |
|------|------------------------|---------|
| `Non3GppDeviceConnectionInformation::Ethernet::vlan_tag_id`, §9.11.4.41 | The 12-bit VLAN ID: bit 8 of the first octet to bit 5 of the second, with bits 4 to 1 spare. 100 is sent as 0x0640. | A 16-bit VLAN tag ID in the two octets. A peer that follows it sends 100 as 0x0064, which this crate reads as VLAN 6. |
| 5GMM capability octet 13, bits 2 and 3, §9.11.3.1 | NSSAA-EPC (`nssaa_epc`) and AIoTUR (`aiot_ue_reader`). `validate()` accepts them. | Spare: its sender must leave them zero. |

Clauses 8 and 9 and Annex D of TS 24.501 code nothing else differently in
V20.1.0, and clauses 8 and 9 of TS 24.301 are the same in both releases.

## Tests

The tests are kept with the implementation: unit tests, wire vectors, round
trips, documentation tests and examples. The [changelog](CHANGELOG.md) lists
API changes.

| Vectors | What the tests hold |
|---------|---------------------|
| 15 legacy 5GS wire values, with cleartext inner messages | They round-trip. Their provenance was not recorded: regression vectors, not attributed packet-capture evidence. |
| One constructed 5GS REGISTRATION REQUEST that carries a protected EPS ATTACH REQUEST | It round-trips. |
| An embedded EPS corpus: the NAS PDUs of two S1AP-carried attach attempts | They round-trip octet for octet. Their envelopes use EEA0, so the inner messages are decoded too and, with `security`, the HashMME of the SECURITY MODE COMMAND is checked against the ATTACH REQUEST. |
| `tests/fixtures`: 94 5GS and 97 EPS messages, at least one of each 5GMM, 5GSM, EMM and ESM message type of the codec | Each decodes, has no `validate()` error and encodes to its octets, also through its serde form and through its view written alone. Through its tree, each has the same tree, and 167 of the 191 the same octets at this revision. |
| The Rust blocks of this page | They compile and run as documentation tests, with the `serde` and `security` features, and `tests/readme.rs` compares what each prints with the output shown under it. |

```bash
cargo test --config "$SECURITY" --all-features            # everything
cargo test --config "$SECURITY" --all-features capture_   # the EPS corpus
```

Four fuzz targets hold what the tests hold on any octets: `decode_5gs` and
`decode_eps` that a message that decodes encodes, and decodes again to the
same message; `view_5gs` and `view_eps` that its view gives it back, that
its tree writes a message with the same tree, and that its serde form reads
back. The continuous integration runs each for a minute.

```bash
./fuzz/seed.sh                                   # a corpus from tests/fixtures
cargo +nightly fuzz run decode_5gs -- -max_total_time=60 -max_len=512
```

## Benchmarks

The benchmarks and their profilers are a package of their own, `benches/`,
so that criterion and pprof are no dependencies of the crate. They measure
decoding, encoding, validation and the JSON forms on the fixtures and on a
few large or hostile messages. The package takes oxirush-security from its
repository by itself, and the fuzz package does without it: their commands
need no `--config`.

```bash
cd benches
cargo bench --bench codec -- decode/5gs-fixtures       # the time, with criterion
cargo bench --bench allocations                        # the allocations of each operation
cargo bench --bench heap -- decode/5gs-fixtures        # where they are made
cargo bench --bench codec -- --profile-time 10 decode/5gs-fixtures
go tool pprof -top target/criterion/decode/5gs-fixtures/profile/profile.pb
cargo bench --features security --bench codec -- protect   # with oxirush-security
```

`--profile-time` runs the benchmark under [pprof](https://crates.io/crates/pprof)
and writes a CPU profile that `go tool pprof` reads; with `PROFILE=flamegraph`
in the environment it writes `flamegraph.svg` beside it instead.

On one core of a desktop processor, a message of the 5GS fixtures, which
have 17 octets on average:

| Operation | Time | Allocations |
|-----------|------|-------------|
| `decode` | 115 ns | 1.2 |
| `encode` | 49 ns | 1.0 |
| `validate` | 234 ns | 3.3 |
| `to_view` | 4.8 µs | 72 |
| `with_view` | 18 µs | 145 |
| `to_tree` | 18 µs | 299 |
| `from_tree` | 38 µs | 379 |
| `protect`, `unprotect` (128-NIA2, 128-NEA2) | 637 ns, 609 ns | 3.4, 2.4 |

## Contributing

Contributions are welcome. Open a pull request against `master` with a test
for what it changes: `cargo test --all-features` and
`cargo clippy --all-targets --all-features` pass on every commit, with the
`--config` of [Examples](#examples) for now. Sign off
your commits (`git commit -s`): by contributing you agree to the
[Developer Certificate of Origin](https://developercertificate.org/), which
says that you have the right to submit the contribution under the licence of
the project. [SECURITY.md](SECURITY.md) says how to report a vulnerability.

## License

Copyright 2025-2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgements

Inspired by [PacketRusher](https://github.com/HewlettPackard/PacketRusher).

[`to_tree()`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/messages/enum.Nas5gsMessage.html#method.to_tree
[`from_tree()`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/messages/enum.Nas5gsMessage.html#method.from_tree
[`to_view()`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/messages/enum.Nas5gsMessage.html#method.to_view
[`with_view()`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/messages/enum.Nas5gsMessage.html#method.with_view
[`from_view()`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/messages/enum.Nas5gsMessage.html#method.from_view
[`blank_view()`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/message_types/enum.Nas5gmmMessageType.html#method.blank_view
[`NasServiceRequest::from_view()`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_eps/messages/struct.NasServiceRequest.html#method.from_view
[`view`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html
[`view::paths`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/view/fn.paths.html
