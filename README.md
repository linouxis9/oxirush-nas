# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A fast, memory-safe library for encoding and decoding 5G and EPS (4G) NAS messages in Rust, per 3GPP TS 24.501 and TS 24.301.

## Features

- **5GS NAS codec** — all 5GMM and 5GSM messages of TS 24.501, plus the UE policy delivery service (Annex D)
- **EPS NAS codec** — all EMM and ESM messages of TS 24.301 chapter 8, including the short SERVICE REQUEST header, EMM TRANSPORT, and security-protected envelopes
- **Wire-format IE codec** — 169 5GS and 153 EPS information element types with V, LV, LV-E, TV, TLV, and TLV-E formats (TS 24.007 §11.2) through the `Encode`/`Decode` traits
- **Typed IE accessors** — enums, value structs, and `set_*`/`with_*` builders instead of bit manipulation; IEs whose coding TS 24.501 and TS 24.301 share (for example UE network capability, KSI, NAS security algorithms, GPRS timers, PCO/ePCO units, APN/DNN, PLMN lists, network name, time zone, eDRX, and emergency numbers) use one implementation for both protocols
- **Receiver rules** — decoding ignores spare bits and octets beyond the defined value, skips unknown IEs by their format, keeps the first of repeated IEs, treats syntactically incorrect optional and out-of-sequence IEs as absent while preserving their raw wire form, and applies the receive fallbacks of the IE tables
- **Sender checks** — `validate()` reports TS 24.501 and TS 24.301 value and conditional rules, repeated IEs, and out-of-sequence IEs as errors or warnings; `is_well_formed()` checks a single IE
- **Chapter 7 error classes** — `NasError` separates too-short messages, unknown protocol discriminators and message types, reserved security header types, and invalid mandatory IEs
- **Human-readable display** — `fmt::Display` for every message, with causes, identities, and algorithms decoded
- **NAS security contexts** *(optional)* — integrity and ciphering with NAS COUNT tracking and replay protection per TS 33.501 and TS 33.401, including the EPS short MAC, partial ciphering of CONTROL PLANE SERVICE REQUEST containers, and 5GS↔EPS mapped contexts
- **Unchecked protection** *(optional)* — `protect_opaque_payload` ciphers and integrity-protects arbitrary inner octets under security header types 1 to 4, for negative tests; `protect` and `protect_bytes` still validate the inner message
- **Serde support** *(optional)* — messages, headers and typed IE values as JSON that re-encodes to the octets that were decoded, and a readable view of each message: every IE by its name, with its value in the usual notation and its octets
- **Round-trip preservation** — decode then re-encode keeps unknown IEs, ignored repetitions, and the optional IE order

## Protocol modules

| Module | Specification | Layers |
|--------|---------------|--------|
| `oxirush_nas::nas_5gs` | TS 24.501 | `types`, `message_types`, `messages`, `ie`, `display`, `validate`, `security`, `upds` |
| `oxirush_nas::nas_eps` | TS 24.301 | `types`, `message_types`, `messages`, `ie`, `display`, `validate`, `security` |
| `oxirush_nas::common` | Shared | `Encode`/`Decode`, errors, validation findings, NAS format macros, and IE grammars shared by both protocols |

The crate root also re-exports the 5GS API for existing users. The `nas_5gs`
and `nas_eps` modules are the paths for code that handles both protocols.
Construct NAS messages with `new()` and `set_*()` methods. Message structs
retain the decoded optional IE order internally, so external struct literals
are not supported.

### Receiving and sending

Decoding follows the receiver rules of TS 24.007 §11 and the protocol
specifications: spare bits and extra value octets do not stop decoding;
unknown, repeated, syntactically incorrect optional, and out-of-sequence IEs
are skipped semantically and retained in raw form for inspection and
round-trip encoding. A registered syntax error in a mandatory IE returns
`NasError::InvalidMandatoryIe`. An unknown IE encoded as "comprehension
required" is kept as well when it is well framed, so that a tool can inspect
the message: `unknown_ies()` returns it, `UnknownIe::is_comprehension_required`
flags it and `validate()` reports it, and the receiver answers it as §7.5.1
of TS 24.501 or TS 24.301 requires. Typed getters return the value a receiver
must act on, for example `IdentityTypeValue::Imsi` for an undefined identity
type, while `*_strict` and `*_raw` variants expose the exact code.
`validate()` and `is_well_formed()` check what a sender must produce.
Encoding accepts every value a type can represent, so a test tool can emit
invalid values. Builders such as `from_*` return `None` for invalid input;
several legacy 5GS builders panic instead.

For an IMEI sent over NAS, `nas_5gs::NasFGsMobileIdentity` and
`nas_eps::{NasEpsMobileIdentity, NasMobileIdentity}` provide
`from_imei_tac_snr`: pass the 14 TAC and serial-number digits, and the method
adds the transmitted zero spare digit. `from_imei` keeps all 15 supplied
digits.

The [changelog](CHANGELOG.md) lists API changes. Conformance evidence is kept
with the implementation as executable unit, wire-vector, round-trip, doctest,
and example coverage.

### Examples

Each example has a 5GS and an EPS counterpart covering the same procedure:

| Example | 5GS | EPS |
|---------|-----|-----|
| `build_message` | REGISTRATION REJECT | ATTACH REJECT |
| `build_mobility_request` | mobility registration update REGISTRATION REQUEST | TRACKING AREA UPDATE REQUEST |
| `decode_message` | REGISTRATION REQUEST with typed accessors | ATTACH REQUEST with typed accessors |
| `validate_message` | registration, authentication, and security mode messages | attach, authentication, and security mode messages |
| `security` | protect and unprotect with keys from KAMF | protect and unprotect with keys from KASME |
| `view_message` | REGISTRATION REQUEST read and edited through its view, by the paths of its IEs | ATTACH REQUEST read and edited through its view, by the paths of its IEs |

```bash
cargo run -p oxirush-nas --example build_message_nas_5gs
cargo run -p oxirush-nas --example build_message_nas_eps
cargo run -p oxirush-nas --example build_mobility_request_nas_5gs
cargo run -p oxirush-nas --example build_mobility_request_nas_eps
cargo run -p oxirush-nas --example decode_message_nas_5gs
cargo run -p oxirush-nas --example decode_message_nas_eps
cargo run -p oxirush-nas --example validate_message_nas_5gs
cargo run -p oxirush-nas --example validate_message_nas_eps
cargo run -p oxirush-nas --features security --example security_nas_5gs
cargo run -p oxirush-nas --features security --example security_nas_eps
cargo run -p oxirush-nas --features serde --example view_message_nas_5gs
cargo run -p oxirush-nas --features serde --example view_message_nas_eps
```

The 5GS tests round-trip every 5GS PDU currently available in this checkout:
15 legacy embedded wire values, including cleartext inner messages, plus one
separately constructed 5GS REGISTRATION REQUEST carrying a protected EPS ATTACH
REQUEST. The original provenance of the 15 legacy values was not recorded, so
they are treated as regression vectors rather than attributed packet-capture
evidence. The EPS tests additionally include an embedded corpus of the NAS PDUs
from two S1AP-carried attach attempts.
Their envelopes use EEA0, so the tests also decode the inner messages and, with
the `security` feature, check the HashMME of the SECURITY MODE COMMAND against
the ATTACH REQUEST:

```bash
cargo test --all-features capture_
```

## Quick start

```toml
[dependencies]
oxirush-nas = "0.5"
```

### Feature flags

| Feature    | Description                                               |
|------------|-----------------------------------------------------------|
| `security` | 5GS and EPS NAS security contexts (protect/unprotect) via `oxirush-security` |
| `serde`    | JSON serialization with `serde::Serialize`/`Deserialize`, and the view of a message as a `serde_json::Value` |

```toml
oxirush-nas = { version = "0.5", features = ["security", "serde"] }
```

## Usage

### Decode and encode a NAS message

```rust
use oxirush_nas::nas_5gs::{decode_nas_5gs_message, encode_nas_5gs_message, Validate};

// Decode a Registration Request from raw bytes
let bytes = hex::decode(
    "7e004179000d0102f8390000000000000010022e08a020000000000000"
).unwrap();
let msg = decode_nas_5gs_message(&bytes).unwrap();

// Wireshark-style display
println!("{msg}");
// => 5GMM RegistrationRequest (type=InitialRegistration, ..., identity=SUCI (PLMN=208/93, scheme=0), ...)

// Structural validation helpers for common TS 24.501 rules
assert!(msg.validate().is_empty());

// Round-trip encode
assert_eq!(bytes, encode_nas_5gs_message(&msg).unwrap());
```

### Typed IE accessors

```rust
use oxirush_nas::nas_5gs::{decode_nas_5gs_message, Nas5gsMessage, Nas5gmmMessage};
use oxirush_nas::nas_5gs::ie::*;

let bytes = hex::decode(
    "7e004179000d0102f8390000000000000010022e08a020000000000000"
).unwrap();
let msg = decode_nas_5gs_message(&bytes).unwrap();
if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = &msg {
    // Registration type as a typed enum
    assert_eq!(reg.fgs_registration_type.registration_type(),
               Some(RegistrationType::InitialRegistration));

    // Mobile identity variant
    assert_eq!(reg.fgs_mobile_identity.identity_type(),
               Some(MobileIdentityType::Suci));

    // Extract PLMN
    if let Some(plmn) = reg.fgs_mobile_identity.plmn() {
        println!("MCC={}, MNC={}", plmn.mcc_string(), plmn.mnc_string());
    }
}
```

### Build a NAS message from scratch

```rust
use oxirush_nas::nas_5gs::ie::GmmCause;
use oxirush_nas::nas_5gs::messages::NasRegistrationReject;
use oxirush_nas::nas_5gs::*;

// Build a RegistrationReject with cause code
let reject = NasRegistrationReject::new(
    NasFGmmCause::from_cause(GmmCause::IllegalUe),
);
let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationReject(reject));
let wire_bytes = encode_nas_5gs_message(&msg).unwrap();
```

### Decode an EPS NAS message

```rust
use oxirush_nas::nas_eps::{
    decode_nas_eps_message, encode_nas_eps_message, NasEmmMessage, NasEpsMessage, Validate,
};

// ATTACH REQUEST with an IMSI and a PDN CONNECTIVITY REQUEST
let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
let msg = decode_nas_eps_message(&bytes).unwrap();
println!("{msg}");
// => EMM AttachRequest (type=EpsAttach, KSI=Native(0), identity=IMSI 208930000000001, ...)
assert!(msg.validate().is_empty());

if let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &msg {
    assert_eq!(request.eps_mobile_identity.as_imsi().as_deref(), Some("208930000000001"));
    assert!(request.ue_network_capability.supports_eea(2));
    let esm = request.esm_message_container.decode_as_esm_message().unwrap();
    println!("{esm}");
}
assert_eq!(bytes, encode_nas_eps_message(&msg).unwrap());
```

### Build an EPS NAS message

```rust
use oxirush_nas::nas_eps::*;

let reject = NasAttachReject::new(NasEmmCause::from_cause(EmmCause::IllegalUe));
let msg = NasEpsMessage::new_emm(NasEmmMessage::AttachReject(reject));
assert_eq!(encode_nas_eps_message(&msg).unwrap(), [0x07, 0x44, 0x03]);
```

### NAS security envelope (requires `security` feature)

`from_fresh_*` is only for a newly established root key/NAS-key pair. Persist
the next COUNT values and use `restore_from_*` after restart; use
`reselect_algorithms` under an existing KAMF/KASME. A live sending context is
not clonable in production. The two contexts below represent opposite endpoints
in one self-contained example.

```rust
use oxirush_nas::nas_5gs::{
    Direction, Nas5gmmMessage, Nas5gsMessage, Nas5gsSecurityHeaderType, NasFGmmCause,
    NasSecurityContext,
};
use oxirush_nas::nas_5gs::ie::{IntegrityAlgorithm, CipheringAlgorithm};
use oxirush_nas::nas_5gs::ie::GmmCause;
use oxirush_nas::nas_5gs::messages::NasRegistrationReject;

let knas_int = [0u8; 16];
let knas_enc = [0u8; 16];
let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationReject(
    NasRegistrationReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe)),
));

let mut tx = NasSecurityContext::from_fresh_keys(
    knas_int, knas_enc,
    IntegrityAlgorithm::NIA2,
    CipheringAlgorithm::NEA2,
);
let mut rx = NasSecurityContext::from_fresh_keys(
    knas_int, knas_enc,
    IntegrityAlgorithm::NIA2,
    CipheringAlgorithm::NEA2,
);

// Protect outbound (integrity + ciphering)
let protected = tx.protect(
    &msg,
    Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
    Direction::Downlink,
).unwrap();

// Unprotect inbound (MAC verify + decipher + decode)
let (decoded, sht) = rx.unprotect(&protected, Direction::Downlink).unwrap();
assert_eq!(sht, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered);
assert!(matches!(
    decoded,
    Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(_))
));
```

### EPS NAS security envelope (requires `security` feature)

```rust
use oxirush_nas::nas_eps::{
    CipheringAlgorithm, Direction, EmmCause, IntegrityAlgorithm, NasAttachReject,
    NasEmmCause, NasEmmMessage, NasEpsMessage, NasEpsSecurityHeaderType,
    NasSecurityContext,
};

let msg = NasEpsMessage::new_emm(NasEmmMessage::AttachReject(
    NasAttachReject::new(NasEmmCause::from_cause(EmmCause::IllegalUe)),
));
let kasme = [0x11; 32];
let mut tx = NasSecurityContext::from_fresh_kasme(
    &kasme, IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2,
);
let mut rx = NasSecurityContext::from_fresh_kasme(
    &kasme, IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2,
);

let protected = tx.protect(
    &msg,
    NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
    Direction::Downlink,
).unwrap();
let (decoded, sht) = rx.unprotect(&protected, Direction::Downlink).unwrap();
assert_eq!(sht, NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered);
assert_eq!(decoded, msg);
```

### JSON form and view of a message (requires `serde` feature)

Messages, headers and typed IE values implement `Serialize` and
`Deserialize`. The serde form of a message has the fields of the codec: an IE
is its `type_field`, `length` and `value` octets, so a document re-encodes to
the octets that were decoded, unknown IEs included.

`to_view()` is the message as a reader names it: each IE by the name the
specification gives it, with its `value` as the typed accessors decode it and
its `octets` in hexadecimal. `with_view()` returns the message of an edited
view. The `view` module reads and edits a view by paths, in which `/nas`
stands for the view and an IE goes by its name.

```rust
use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
use serde_json::json;

// REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
let accept = Nas5gsMessage::from_bytes(&bytes).unwrap();
let mut tree = accept.to_view();

// Each value with the path that selects it:
// /nas/message-type/value = "registration-accept"
// /nas/5g-guti/value/guti/plmn = "208-93"
// /nas/allowed-nssai/value/0/sst = 1
for (path, value) in view::paths(&tree) {
    println!("{path} = {value}");
}
// A coded value by its name, an identity by its parts
let select = |path| view::select(&tree, path).unwrap();
assert_eq!(select("/nas/message-type/value"), [&json!("registration-accept")]);
assert_eq!(select("/nas/5gs-registration-result/value/result"), [&json!("3gpp-access")]);
assert_eq!(select("/nas/5g-guti/value/guti/tmsi"), [&json!(0x1122_3344)]);
// The octets stay beside the value
assert_eq!(select("/nas/allowed-nssai/octets"), [&json!("0101")]);
// An optional IE that the message does not have selects nothing
assert!(select("/nas/t3512-value/value").is_empty());

// Write a value: the IE is encoded from it
view::set(&mut tree, "/nas/5g-guti/value/guti/tmsi", json!("0xdeadbeef")).unwrap();
view::set(&mut tree, "/nas/allowed-nssai/value/0/sd", json!("010203")).unwrap();
// An optional IE that the message does not have is added by its value
view::set(&mut tree, "/nas/t3512-value/value", json!(3600)).unwrap();
let edited = accept.with_view(tree).unwrap();
assert_eq!(
    hex::encode(edited.to_bytes().unwrap()),
    "7e0042010177000bf202f839010042deadbeef150504010102035e0106"
);
```

A path is a JSON pointer: a name is taken in any case, with hyphens,
underscores or spaces, a list selects by position, and `*` is each entry of a
list. The message in a container is under the `value` of the container, as in
`/nas/nas-message-container/value/5gmm-capability/value/s1-mode`.
`view::remove` takes an optional IE or an entry of a list out, and
`view::insert` adds an entry to a list. A view is also a `serde_json` value,
whose entries can be read and written in place.

A value is in the notation a reader expects:

| What | Notation |
|------|----------|
| coded value (cause, type, mode, result, algorithm) | its name, `"congestion"`, `"initial-registration"`, `"nea2"`; its number where the specification names none |
| PLMN identity | `"208-93"`, `"310-410"` |
| IMSI, IMEI, IMEISV, MSIN, routing indicator | a string of digits |
| TMSI, TAC, LAC, AMF region, set and pointer, SST, QFI, PDU session and bearer identities | a number |
| timer | its seconds, or `"deactivated"` |
| DNN, APN, network name | text |
| IP address | text, `"10.0.0.1"`, `"fe80::1"` |
| flags of a capability or an indication | `true` or `false` by the name of the flag |
| container of a NAS message | the view of that message |
| SD, MAC address, EUI-64, key, interface identifier, raw contents | hexadecimal |

Names are in lower case with hyphens, and `fgs_`, `fgmm_` and `fgsm_` of the
codec read `5gs-`, `5gmm-` and `5gsm-`. The fields of the header (message
type, PDU session identity, PTI) come first, with a `value` alone; a view is
read through a security header. An optional IE that the message does not have
is `null`: a view names every IE that its message can have, and
`view_names()` of a message type gives those names without a message.

`with_view` encodes an IE from a `value` that was changed, gives an IE the
`octets` that were changed, whatever they are, takes out an IE that the view
leaves out or has as `null`, and adds an optional IE that the message does not
have from the `value` or the `octets` that the view gives it. A name is read
in any case, with hyphens, underscores or spaces, and a number also as a
`"0x…"` string. Nothing that the view says is ignored: a name that does not
exist, a member that an IE or a value does not have, a value that its IE
cannot carry, and `octets` and a `value` that were both changed and disagree
are errors. A value says what an IE means, not how it is coded: the encoder
chooses the unit of a timer or the type of a partial tracking area identity
list, and the octets remain the way to choose it. A coded value is written by
its name; a number is for a value without one.

`from_view()` of a message type returns the message that a view describes
alone, without a message to edit: the view has every field of the header,
every mandatory IE and the optional IEs that the message has, and one that it
leaves out is an error. The message in a container is the view that is the
`value` of the container, named by its `message-type`.

The EPS SERVICE REQUEST, which has a short header and no IEs (TS 24.301
§8.2.25), has the fields of that header in its view: its
`security-header-type`, its `ksi-and-sequence-number`, whose value is a `ksi`
and a `sequence-number`, and the two octets of its
`message-authentication-code`. `NasServiceRequest::from_view()` returns the
one that a view describes alone.

Of the 169 5GS IE types, 153 have a value, and 132 of the 153 EPS types. The
value of 33 of the 5GS types and 6 of the EPS types is read only: the lists
and containers that the crate parses but whose builders the view does not
hand what an author writes, such as LADN and CAG information, the service
area list, the SOR transparent container and the mapped EPS bearer contexts.
Their octets are written.

37 types have octets alone: the octet strings (RAND, AUTN, AUTS, RES, ABBA,
nonces, HashMME), the payloads of other protocols (EAP message, SMS, LPP and
user data containers, ATSSS and port management containers), the protocol
configuration options, whose contents depend on the direction of the message,
IEs for which the crate has getters and no constructor, or none (ECS address,
classmark 3, the A/Gb and Iu mode QoS), and the two N1 mode NAS transparent
containers, which no NAS message has as an IE. A payload container has a
value when its type is "N1 SM information", in UL and DL NAS TRANSPORT. In a
5GS SERVICE REQUEST the service type shares the octet of the ngKSI, and both
read under `ngksi`.

## Architecture

```text
src/
├── common/       shared codec traits, errors, macros, validation types, and
│                 IE grammars shared by both protocols (ts24008, ts24301, ts24501)
├── nas_5gs/      TS 24.501 codec
│   ├── types.rs, message_types.rs, messages.rs, ie.rs
│   ├── display.rs, validate.rs, security.rs
│   └── upds.rs   5GS UE policy delivery service
└── nas_eps/      TS 24.301 codec
    ├── types.rs, message_types.rs, messages.rs, ie.rs
    └── display.rs, validate.rs, security.rs
```

Both protocol modules expose the same three layer structure, message type modules,
formatting, and validation. Their `security` modules use the matching
`oxirush_security::nas_5gs` and `oxirush_security::nas_eps` APIs behind the
`security` feature. `upds` is specific to 5GS.

### Three-layer design

- **Layer 1 (`types`)** — raw binary IE structs defined by shared macros. Each struct has a `pub value` field and implements `Encode`/`Decode` for the wire format (V, LV, LV-E, TV, TLV, TLV-E per TS 24.007 &sect;11.2).
- **Layer 2 (`messages`)** — NAS message structs defined by the shared `nas_message!` macro. Mandatory fields in the constructor, optional fields via `set_*()` builder methods. Decode dispatches on IEI bytes.
- **Layer 3 (`ie`)** — typed accessors for protocol-specific fields. Enums such as `RegistrationType` and `PdnType` replace manual bit manipulation.

## 3GPP references

- **TS 24.501 V19.8.0** — 5G NAS protocol (message definitions, IE formats, procedures)
- **TS 24.301 V19.8.0** — EPS NAS protocol (EMM and ESM messages and IE tables)
- **TS 24.007** — IE encoding formats (V, LV, TLV, etc.) and receiver rules
- **TS 24.008** — IEs that TS 24.301 and TS 24.501 delegate (PCO, TFT, QoS, timers, identities)
- **TS 23.003** — identity formats (IMSI, IMEI, GUTI, APN)
- **TS 23.038** — GSM 7-bit default alphabet (network names, emergency number sub-services)
- **TS 33.501** — 5G security architecture (NAS security, key derivation, algorithms)
- **TS 33.401** — EPS security architecture (key derivation, NAS security, algorithms)

### Specification versions

The codec follows Release 19: TS 24.501 V19.8.0 and TS 24.301 V19.8.0. Two
items follow TS 24.501 V20.1.0 (Release 20) instead, and differ from V19.8.0
on the wire:

- `Non3GppDeviceConnectionInformation::Ethernet::vlan_tag_id` is the 12-bit
  VLAN ID of §9.11.4.41: bit 8 of the first octet to bit 5 of the second,
  with bits 4 to 1 spare. V19.8.0 has a 16-bit VLAN tag ID in the two
  octets, so a peer that follows it sends 100 as 0x0064, where this crate
  sends 0x0640 and reads 0x0064 as VLAN 6.
- 5GMM capability octet 13 bits 2 and 3 are NSSAA-EPC (`nssaa_epc`) and
  AIoTUR (`aiot_ue_reader`), §9.11.3.1. V19.8.0 has them spare, so its sender
  must leave them zero; `validate()` here accepts them.

Clauses 8 and 9 and Annex D of TS 24.501 code nothing else differently in
V20.1.0, and clauses 8 and 9 of TS 24.301 are the same in both releases.

## Documentation

Full API reference: **<https://docs.rs/oxirush-nas>**

The crate denies missing documentation for every public item in both protocol
modules, including the 5GS IE and UPDS helper surfaces.

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Sign off your commits (`git commit -s`)
4. Open a Pull Request

### Developer Certificate of Origin (DCO)

By contributing to this project, you agree to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This means that you have the right to submit your contributions and you agree to license them according to the project's license.

All commits should be signed-off with `git commit -s` to indicate your agreement to the DCO.

## License

Copyright 2025 - 2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgements

OxiRush is inspired by [PacketRusher](https://github.com/HewlettPackard/PacketRusher), reimplemented in Rust for improved performance and safety.
