# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A fast, memory-safe library for encoding and decoding 5G NAS (Non-Access Stratum) messages in Rust, per 3GPP TS 24.501.

Part of the [OxiRush](https://github.com/linouxis9/oxirush) project — a 5G Core Network testing framework.

## Features

- **Complete 5G NAS codec** — all 5GMM and 5GSM message types from TS 24.501
- **100+ Information Elements** — full TLV/TV/V/LV wire-format codec via `Encode`/`Decode` traits
- **Typed IE accessors** — zero-cost enums and builder helpers over raw bytes (no manual bit manipulation)
- **Human-readable display** — Wireshark-style `fmt::Display` for all messages
- **Structural validation** — per TS 24.501 with error/warning severity levels
- **NAS security envelope** *(optional)* — integrity + ciphering per TS 33.501, with NAS COUNT tracking
- **Serde support** *(optional)* — JSON serialization for typed IE structs
- **Round-trip fidelity** — decode then re-encode produces identical bytes (verified by test suite)

## Quick start

```toml
[dependencies]
oxirush-nas = "0.2"
```

### Feature flags

| Feature    | Description                                               |
|------------|-----------------------------------------------------------|
| `security` | NAS security envelope (protect/unprotect) via `oxirush-security` |
| `serde`    | JSON serialization with `serde::Serialize`/`Deserialize`  |

```toml
oxirush-nas = { version = "0.2", features = ["security", "serde"] }
```

## Usage

### Decode and encode a NAS message

```rust
use oxirush_nas::{decode_nas_5gs_message, encode_nas_5gs_message, Validate};

// Decode a Registration Request from raw bytes
let bytes = hex::decode(
    "7e004179000d0199f9070000000000000010022e08a020000000000000"
).unwrap();
let msg = decode_nas_5gs_message(&bytes).unwrap();

// Wireshark-style display
println!("{msg}");
// => 5GMM RegistrationRequest (Initial) SUCI: 208-93-0000000000 ...

// Structural validation per TS 24.501
assert!(msg.validate().is_empty());

// Round-trip encode
assert_eq!(bytes, encode_nas_5gs_message(&msg).unwrap());
```

### Typed IE accessors

```rust
use oxirush_nas::{decode_nas_5gs_message, Nas5gsMessage, Nas5gmmMessage};
use oxirush_nas::ie::*;

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
use oxirush_nas::*;

// Build a RegistrationReject with cause code
let reject = NasRegistrationReject::new(
    NasFGmmCause::from_cause(GmmCause::IllegalUe),
);
let msg = Nas5gsMessage::Gmm(
    Nas5gmmHeader::new(Nas5gmmMessageType::RegistrationReject),
    Nas5gmmMessage::RegistrationReject(reject),
);
let wire_bytes = encode_nas_5gs_message(&msg).unwrap();
```

### NAS security envelope (requires `security` feature)

```rust
use oxirush_nas::NasSecurityContext;
use oxirush_nas::ie::{IntegrityAlgorithm, CipheringAlgorithm};
use oxirush_nas::message_types::Nas5gsSecurityHeaderType;

let mut ctx = NasSecurityContext::new(
    knas_int, knas_enc,
    IntegrityAlgorithm::NIA2,
    CipheringAlgorithm::NEA2,
);

// Protect outbound (integrity + ciphering)
let protected = ctx.protect(
    &msg,
    Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
    0, // direction: 0=UL, 1=DL
).unwrap();

// Unprotect inbound (MAC verify + decipher + decode)
let (decoded, sht) = ctx.unprotect(&protected, 0).unwrap();
```

## Architecture

```text
                        +-----------+
                        |  lib.rs   |   re-exports everything
                        +-----+-----+
                              |
          +--------+----------+----------+---------+
          |        |          |          |         |
      types.rs  messages.rs  ie.rs  display.rs  validate.rs
      (Layer 1)  (Layer 2)  (Layer 3)
```

| Module       | Description |
|--------------|-------------|
| [`types`]    | Wire-level codec — `Encode`/`Decode` traits, 100+ IE structs (TLV/TV/V/LV formats) |
| [`messages`] | NAS message structs with IEI dispatch, `encode_nas_5gs_message()`/`decode_nas_5gs_message()` |
| [`ie`]       | Typed IE accessors — zero-cost enums, parsers, and builder helpers |
| [`display`]  | `fmt::Display` implementations for Wireshark-style message formatting |
| [`validate`] | Structural validation per TS 24.501 (errors + warnings) |
| [`security`] | NAS security envelope — protect/unprotect with NAS COUNT tracking *(feature-gated)* |

### Three-layer design

- **Layer 1 (`types`)** — raw binary IE structs generated by macros. Each struct has a `pub value` field and implements `Encode`/`Decode` for the wire format (V, LV, LV-E, TV, TLV, TLV-E per TS 24.007 &sect;11.2).
- **Layer 2 (`messages`)** — NAS message structs generated by the `nas_message!` macro. Mandatory fields in the constructor, optional fields via `set_*()` builder methods. Decode dispatches on IEI bytes.
- **Layer 3 (`ie`)** — typed zero-cost wrappers. Enums like `RegistrationType`, `GmmCause`, `CipheringAlgorithm` replace manual bit manipulation. `from_*()` constructors and accessor methods on the raw IE structs.

## 3GPP references

- **TS 24.501** — 5G NAS protocol (message definitions, IE formats, procedures)
- **TS 24.007** — IE encoding formats (V, LV, TLV, etc.)
- **TS 33.501** — 5G security architecture (NAS security, key derivation, algorithms)

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

Copyright 2025-2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgements

OxiRush is inspired by [PacketRusher](https://github.com/HewlettPackard/PacketRusher), reimplemented in Rust for improved performance and safety.
