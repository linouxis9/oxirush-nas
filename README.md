# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> ⚠️ **Note**: This library is currently in active development and not all features may be available.

A fast, memory-safe library for encoding and decoding 5G Non-Access Stratum (NAS) messages, written in Rust.

Part of the future [OxiRush](https://github.com/linouxis9/oxirush) project - a comprehensive next-generation 5G Core Network testing framework.

## Overview

`oxirush-nas` provides a robust implementation for working with 5G NAS protocol messages and IEs, which are used for the communication between the User Equipment (UE) and the 5G Core Network.

## Features

- **Complete Protocol Support**: Full implementation of 5G NAS protocol as defined in 3GPP TS 24.501
- **High Performance**: Optimized for speed and minimal memory usage
- **Type Safety**: Leverages Rust's type system to prevent protocol errors at compile time
- **Typed IE Accessors**: Zero-cost typed wrappers over raw byte-level Information Elements — enums, accessor methods, and builder helpers that eliminate manual bit manipulation
- **Human-Readable Display**: Wireshark-style `fmt::Display` formatting for all NAS messages, useful for debugging and logging
- **Message Validation**: Structural correctness checks per TS 24.501 with error/warning severity levels
- **NAS Security Envelope** *(optional)*: Integrated protect/unprotect API (integrity + ciphering) per TS 33.501 §6.4.3, with NAS COUNT tracking
- **Serde Support** *(optional)*: JSON serialization for all message types

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
oxirush-nas = "0.1"
```

### Feature Flags

| Feature    | Description                                               |
|------------|-----------------------------------------------------------|
| `security` | NAS security envelope (protect/unprotect) via `oxirush-security` |
| `serde`    | JSON serialization with `serde::Serialize`/`Deserialize`  |

```toml
# Enable NAS security + serde
oxirush-nas = { version = "0.1", features = ["security", "serde"] }
```

## Usage Examples

### Basic Message Decoding and Encoding

```rust
use oxirush_nas::{decode_nas_5gs_message, encode_nas_5gs_message, Nas5gsMessage,
                  Nas5gmmMessage, Validate};

// Decode a Registration Request from raw bytes
let nas_bytes = hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000")?;
let msg = decode_nas_5gs_message(&nas_bytes)?;

// Human-readable display (Wireshark-style)
println!("{}", msg);
// => 5GMM RegistrationRequest (Initial) SUCI: ...

// Validate structural correctness per TS 24.501
let errors = msg.validate();
assert!(errors.is_empty(), "Validation errors: {:?}", errors);

// Re-encode and verify roundtrip
let encoded = encode_nas_5gs_message(&msg)?;
assert_eq!(nas_bytes, encoded);
```

### Typed IE Accessors

```rust
use oxirush_nas::{decode_nas_5gs_message, Nas5gsMessage, Nas5gmmMessage};
use oxirush_nas::ie::*;

let msg = decode_nas_5gs_message(&nas_bytes)?;
if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = &msg {
    // Registration type as a typed enum instead of raw u8
    let reg_type = reg.fgs_registration_type.registration_type();
    assert_eq!(reg_type, Some(RegistrationType::Initial));

    // Mobile identity — parse into typed variants (SUCI, GUTI, IMEI, etc.)
    let id_type = reg.fgs_mobile_identity.identity_type();
    assert_eq!(id_type, Some(MobileIdentityType::Suci));

    // Extract PLMN from the identity
    if let Some(plmn) = reg.fgs_mobile_identity.plmn() {
        println!("MCC={}, MNC={}", plmn.mcc_string(), plmn.mnc_string());
    }

    // Security algorithms — typed enums, no magic numbers
    if let Some(sec_cap) = &reg.ue_security_capability {
        println!("UE Security Capability: {:?}", sec_cap.value);
    }
}
```

### NAS Security Envelope (requires `security` feature)

```rust
use oxirush_nas::NasSecurityContext;
use oxirush_nas::ie::{IntegrityAlgorithm, CipheringAlgorithm};
use oxirush_nas::message_types::Nas5gsSecurityHeaderType;

// Create a security context with typed algorithm enums
let mut ctx = NasSecurityContext::new(
    knas_int, knas_enc,
    IntegrityAlgorithm::NIA2,
    CipheringAlgorithm::NEA2,
);

// Protect an outbound message (integrity + ciphering)
let protected = ctx.protect(&msg, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered, 0)?;

// Unprotect an inbound message (MAC verify + decipher + decode)
let (decoded, sht) = ctx.unprotect(&protected, 0)?;
```
## Module Structure

| Module     | Description                                                        |
|------------|--------------------------------------------------------------------|
| `types`    | Raw TLV/TV/V/LV wire codec — `Encode`/`Decode` traits, 100+ IE structs |
| `messages` | NAS message structs with IEI dispatch, `encode`/`decode` functions |
| `ie`       | Typed IE accessors — zero-cost enums and builder helpers           |
| `display`  | `fmt::Display` impls for Wireshark-style message formatting        |
| `validate` | Structural validation per TS 24.501 (errors + warnings)           |
| `security` | NAS security envelope — protect/unprotect with NAS COUNT tracking *(feature-gated)* |

## Documentation

For more detailed documentation, see:

- [oxirush-nas's API Reference](https://docs.rs/oxirush-nas)
- [3GPP TS 24.501 Specification](https://www.3gpp.org/DynaReport/24501.htm)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure your code passes all tests and adheres to the project's coding style.

### Developer Certificate of Origin (DCO)

By contributing to this project, you agree to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This means that you have the right to submit your contributions and you agree to license them according to the project's license.

All commits should be signed-off with `git commit -s` to indicate your agreement to the DCO.

## License

Copyright 2025 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Acknowledgements

OxiRush is inspired by the [PacketRusher](https://github.com/HewlettPackard/PacketRusher) project, reimplemented in Rust for improved performance and safety.