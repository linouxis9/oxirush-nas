# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A fast, memory-safe library for encoding and decoding 5G and EPS (4G) NAS messages in Rust, per 3GPP TS 24.501 and TS 24.301.

Part of the [OxiRush](https://github.com/linouxis9/oxirush) project.

## Features

- **5GS NAS codec** — 5GMM and 5GSM message types from TS 24.501
- **100+ Information Elements** — full TLV/TV/V/LV wire-format codec via `Encode`/`Decode` traits
- **Typed IE accessors** — zero-cost enums and builder helpers over raw bytes (no manual bit manipulation)
- **Human-readable display** — `fmt::Display` for top-level messages, with summaries for common EPS and 5GS procedures
- **Structural validation helpers** — core TS 24.501 checks with error/warning severity levels
- **NAS security contexts** *(optional)* — 5GS integrity and ciphering per TS 33.501 and EPS integrity and ciphering per TS 33.401, with NAS COUNT tracking
- **Serde support** *(optional)* — JSON serialization for typed IE structs
- **Round-trip preservation** — decode then re-encode preserves supported fields, unknown IE payloads, and their optional IE order
- **EPS NAS codec** — EMM and ESM message tables from TS 24.301 Release 19, with the same raw IE, message builder, and `Encode`/`Decode` API

## Protocol modules

| Module | Specification | Layers |
|--------|---------------|--------|
| `oxirush_nas::nas_5gs` | TS 24.501 | `types`, `message_types`, `messages`, `ie`, `display`, `validate`, `security`, `upds` |
| `oxirush_nas::nas_eps` | TS 24.301 | `types`, `message_types`, `messages`, `ie`, `display`, `validate`, `security` |
| `oxirush_nas::common` | Shared | `Encode`/`Decode`, errors, validation findings, and NAS format macros |

The crate root also re-exports the established 5GS API for existing workspace users.
EPS types and functions are available through `oxirush_nas::nas_eps`.
The `nas_5gs` and `nas_eps` modules are the stable paths for code that needs
to distinguish the two NAS protocols.
EPS IE types use semantic names such as `NasEmmCause` and `NasEsmMessageContainer`.
Each IE has one type; its message definition supplies the wire format.
Construct NAS messages with `new()` and `set_*()` methods. Message structs
retain decoded optional IE order internally, so external struct literals are
not supported.
For an IMEI sent over NAS, `nas_5gs::NasFGsMobileIdentity` and
`nas_eps::{NasEpsMobileIdentity, NasMobileIdentity}` provide
`from_imei_tac_snr`: pass the 14 TAC and serial-number digits, and the method
adds the transmitted zero spare digit. `from_imei` retains all 15 supplied
digits for existing interoperability use.

### EPS NAS quick start

```rust
use oxirush_nas::nas_eps::{decode_nas_eps_message, encode_nas_eps_message};

let bytes = [0x07, 0x60, 0x02]; // Plain EPS EMM STATUS, cause 2
let message = decode_nas_eps_message(&bytes).unwrap();
assert_eq!(encode_nas_eps_message(&message).unwrap(), bytes);
```

Without the `security` feature, ciphered EPS security envelopes retain opaque
payload bytes. With it, `nas_eps::NasSecurityContext` derives keys from KASME,
verifies MACs, deciphers EMM and ESM messages, and handles the short SERVICE
REQUEST MAC and partial ciphering of CONTROL PLANE SERVICE REQUEST containers.
Both NAS modules also provide mapped security-context constructors for
5GS↔EPS mobility, using the interworking KDFs in `oxirush-security`.

### Examples

Each example has a 5GS and EPS counterpart:

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

The EPS regression fixtures taken from `s1ap_errors.pcap` are checked with:

```bash
cargo test -p oxirush-nas --all-features capture_nas_pdus_round_trip_byte_for_byte
```

These fixtures round-trip byte for byte. Decoded messages also retain the
order of known and unknown optional IEs when re-encoded.

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
// => 5GMM RegistrationRequest (Initial) SUCI (PLMN=20893, scheme=0) ...

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

### NAS security envelope (requires `security` feature)

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

let mut tx = NasSecurityContext::new(
    knas_int, knas_enc,
    IntegrityAlgorithm::NIA2,
    CipheringAlgorithm::NEA2,
);
let mut rx = tx.clone();

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
let mut tx = NasSecurityContext::from_kasme(
    &[0x11; 32],
    IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2,
);
let mut rx = tx.clone();

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
├── common/       shared codec traits, errors, macros, and validation types
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
- **TS 24.007** — IE encoding formats (V, LV, TLV, etc.)
- **TS 33.501** — 5G security architecture (NAS security, key derivation, algorithms)
- **TS 33.401** — EPS security architecture (key derivation, NAS security, algorithms)

## Documentation

Full API reference: **<https://docs.rs/oxirush-nas>**

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
