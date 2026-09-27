# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A fast, memory-safe library for encoding and decoding 5G and EPS (4G) NAS messages in Rust, per 3GPP TS 24.501 and TS 24.301.

Part of the [OxiRush](https://github.com/linouxis9/oxirush) project.

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
- **Serde support** *(optional)* — serialization for typed IE values
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
`NasError::InvalidMandatoryIe`. Typed getters return the value a receiver
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

The [changelog](CHANGELOG.md) lists API changes. The repository has separate
[5GS](../docs/5gs-conformance-ledger.md) and
[EPS](../docs/eps-conformance-ledger.md) conformance ledgers with generated
[5GS](../docs/5gs-coverage-matrix.md) and
[EPS](../docs/eps-coverage-matrix.md) IE coverage matrices. They pin the
audited Release-19 sources and map every chapter-8 field and chapter-9 clause
to code and tests.

### Examples

Each example has a 5GS and an EPS counterpart covering the same procedure:

| Example | 5GS | EPS |
|---------|-----|-----|
| `build_message` | REGISTRATION REJECT | ATTACH REJECT |
| `build_mobility_request` | mobility registration update REGISTRATION REQUEST | TRACKING AREA UPDATE REQUEST |
| `decode_message` | REGISTRATION REQUEST with typed accessors | ATTACH REQUEST with typed accessors |
| `validate_message` | registration, authentication, and security mode messages | attach, authentication, and security mode messages |
| `security` | protect and unprotect with keys from KAMF | protect and unprotect with keys from KASME |

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
```

The 5GS tests round-trip every 5GS PDU currently available in this checkout:
15 legacy embedded wire values, including cleartext inner messages, plus one
separately constructed 5GS REGISTRATION REQUEST carrying a protected EPS ATTACH
REQUEST from the locally available EPS capture. The original capture provenance
of the 15 legacy values was not recorded, and no external 5GS pcap is checked
in; see the repository's 5GS conformance ledger for the exact 15+1 corpus
manifest and this evidence limitation. The EPS tests additionally include the
NAS PDUs of two attach attempts taken from the locally available S1AP capture.
Their envelopes use EEA0, so the tests also decode the inner messages and, with
the `security` feature, check the HashMME of the SECURITY MODE COMMAND against
the ATTACH REQUEST:

```bash
cargo test -p oxirush-nas --all-features capture_
```

## Quick start

```toml
[dependencies]
oxirush-nas = "0.4"
```

### Feature flags

| Feature    | Description                                               |
|------------|-----------------------------------------------------------|
| `security` | 5GS and EPS NAS security contexts (protect/unprotect) via `oxirush-security` |
| `serde`    | JSON serialization with `serde::Serialize`/`Deserialize`  |

```toml
oxirush-nas = { version = "0.4", features = ["security", "serde"] }
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

- **TS 24.501** — 5G NAS protocol (message definitions, IE formats, procedures)
- **TS 24.301** — EPS NAS protocol (EMM and ESM messages and IE tables)
- **TS 24.007** — IE encoding formats (V, LV, TLV, etc.) and receiver rules
- **TS 24.008** — IEs that TS 24.301 and TS 24.501 delegate (PCO, TFT, QoS, timers, identities)
- **TS 23.003** — identity formats (IMSI, IMEI, GUTI, APN)
- **TS 23.038** — GSM 7-bit default alphabet (network names, emergency number sub-services)
- **TS 33.501** — 5G security architecture (NAS security, key derivation, algorithms)
- **TS 33.401** — EPS security architecture (key derivation, NAS security, algorithms)

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
