# oxirush-nas

[![Crates.io](https://img.shields.io/crates/v/oxirush-nas.svg)](https://crates.io/crates/oxirush-nas)
[![Documentation](https://docs.rs/oxirush-nas/badge.svg)](https://docs.rs/oxirush-nas)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

> This page describes the unreleased 0.5.0, the `master` branch. crates.io
> and docs.rs have 0.4.0, whose API differs: the [changelog](CHANGELOG.md)
> says how to migrate, and [a clone](#in-a-clone) builds the documentation
> that this page links to.

A Rust codec for NAS (non-access stratum), the signalling between a phone
(the UE) and the core network of 5G (5GS) and of 4G (EPS), per 3GPP
TS 24.501 and TS 24.301.

**What it is.** Octets become typed messages and typed messages become
octets. It has every message of 5GS and of EPS mobility and session
management of Release 19, a typed accessor for what each information
element (IE) means, the checks that a single message allows, and no `unsafe`
code. A message that is decoded encodes to the same octets, unknown IEs
included. Two optional features add NAS security, and a JSON form of each
message by the names of the specification.

**What it is not.** It is not a protocol stack: it has no procedures, no
timers and no transport, and its only state is that of a security context.
A message that encodes is not thereby valid: the encoder takes every value
that a type can represent, so that a test tool can send what is wrong. Its
evidence is its own tests, not a conformance suite.
[The documentation](https://docs.rs/oxirush-nas#what-the-crate-covers) lists
what is covered and what is not.

## Install

```toml
[dependencies]
oxirush-nas = "0.5"
hex = "0.4" # the examples of this page write octets in hexadecimal
```

| Feature | Adds | Takes |
|---------|------|-------|
| `security` | security contexts that protect and unprotect messages | `oxirush-security`, `zeroize` |
| `serde` | a message as JSON, and `Serialize` and `Deserialize` | `serde`, `serde_json` |

No feature is on by default. The minimum supported Rust version is 1.88.

Until 0.5.0 is published, depend on the repository. The `security` feature
needs oxirush-security 0.3.0, which is not published either:

```toml
[dependencies]
oxirush-nas = { git = "https://github.com/linouxis9/oxirush-nas", features = ["security"] }

[patch.crates-io]
oxirush-security = { git = "https://github.com/linouxis9/oxirush-security" }
```

## Decode a message and read an IE

```rust
use oxirush_nas::nas_5gs::*;

// Decode a REGISTRATION REQUEST, and print it on one line
let bytes = hex::decode(
    "7e004179000d0102f8390000000000000010022e08a020000000000000"
).unwrap();
let msg = Nas5gsMessage::decode(&bytes).unwrap();
println!("{msg}");

// The message struct is in the variant of its type
let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(request)) = &msg else {
    panic!("not a REGISTRATION REQUEST");
};

// A mandatory IE is a field, and its accessors say what it means
let kind = request.fgs_registration_type.registration_type();
assert_eq!(kind, Some(RegistrationType::InitialRegistration));

// The PLMN identity names the network: a country code and a network code
let plmn = request.fgs_mobile_identity.plmn().unwrap();
println!("MCC={}, MNC={}", plmn.mcc_string(), plmn.mnc_string());

// An optional IE is an `Option`
assert!(request.ue_security_capability.is_some());
assert!(request.requested_nssai.is_none());

// The message encodes to the octets that were decoded
assert_eq!(msg.encode().unwrap(), bytes);
```

```text
5GMM RegistrationRequest (type=InitialRegistration, FOR=1, ngKSI=7, identity=SUCI (PLMN=208-93, scheme=0), UE-SecCap=EA0 EA2 / IA2)
MCC=208, MNC=93
```

The output under a block is what the block prints, here and in the
documentation. `nas_eps` has the same interface for EPS, from
`NasEpsMessage::decode`: its
[documentation](https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_eps/index.html)
starts with an ATTACH REQUEST.

## Build and encode

```rust
use oxirush_nas::nas_5gs::*;

// REGISTRATION REJECT with cause #22 and a T3346 value of ten minutes:
// `new()` takes the mandatory IEs, `set_*()` adds the optional ones
let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
let t3346 = NasGprsTimer2::from_seconds(600).unwrap();
let reject = NasRegistrationReject::new(cause).set_t3346_value(t3346);

// A message has the header of its protocol
let msg = Nas5gsMessage::new_5gmm(reject);
println!("{msg}");

// It has nothing that a sender must not send
assert!(msg.validate().is_empty());

// Encode it
let octets = msg.encode().unwrap();
assert_eq!(hex::encode(octets), "7e0044165f012a");
```

```text
5GMM RegistrationReject (cause=0x16 (Congestion))
```

## Validate

`validate()` returns what a sender must not send, and what a receiver had to
ignore.

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
assert_eq!(bytes, msg.encode().unwrap());
```

```text
[Error] unknown_ies: IEI 0x5F was ignored as repeated
[Error] unknown_ies: Unknown IEI 0x04 is encoded as comprehension required
```

## Protect and unprotect

With the `security` feature. A protected message is under a security header
with a message authentication code (MAC), and may be ciphered. A security
context has the keys, the algorithms and the counters (NAS COUNT) of one UE.
Its keys come from KAMF in 5GS and from KASME in EPS, the key that the UE
and the network share after authentication.

```rust
use oxirush_nas::nas_5gs::ie::{CipheringAlgorithm, IntegrityAlgorithm};
use oxirush_nas::nas_5gs::{
    Direction, Nas5gsMessage, Nas5gsSecurityHeaderType, NasSecurityContext,
};

// The two ends of a link have the same KAMF and the same algorithms
let kamf = [0x11; 32];
let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
let mut network = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
let mut ue = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();

// The network protects a REGISTRATION REJECT: MAC, then ciphering
let reject = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();
let header_type = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
let protected = network.protect(&reject, header_type, Direction::Downlink).unwrap();

// The UE checks the MAC, deciphers and decodes
let (received, _) = ue.unprotect(&protected, Direction::Downlink).unwrap();
assert_eq!(received, reject);
```

The EPS context has the same interface, from a KASME. The documentation of
[`nas_5gs::security`](https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/security/index.html)
says how a context starts, is restored after a restart and changes its
algorithms.

## JSON

With the `serde` feature and `serde_json`, a message is JSON by the names
that the specification gives its IEs. A tree is the short form, in which a
message is shown and written. A view has each IE with its value and its
octets, and edits a message. A path selects a value of a view.

```rust
use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
use serde_json::json;

// REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
let bytes = hex::decode("7e0044165f012a").unwrap();
let reject = Nas5gsMessage::decode(&bytes).unwrap();

// Its tree
let mut tree = reject.to_tree();
println!("{tree:#}");

// A tree is also how a message is written
tree["t3346-value"] = json!(1200);
let written = Nas5gsMessage::from_tree(tree).unwrap();
assert_eq!(hex::encode(written.encode().unwrap()), "7e0044165f0134");

// Its view: an IE has its value and its octets, and one that the message
// does not have is `null`
let mut view = reject.to_view();
println!("{}", view["t3346-value"]);
assert!(view["t3502-value"].is_null());

// A path selects a value of the view, and sets it
let cause = view::select(&view, "/nas/5gmm-cause/value").unwrap();
assert_eq!(cause, [&json!("congestion")]);
view::set(&mut view, "/nas/5gmm-cause/value", json!("illegal-ue")).unwrap();

// The message of the edited view: what was not edited keeps its octets
let edited = reject.with_view(view).unwrap();
assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044035f012a");
```

```json
{
  "5gmm-cause": "congestion",
  "message-type": "registration-reject",
  "t3346-value": 600
}
```

```json
{"octets":"2a","value":600}
```

Nothing that is written is ignored: a name that the message does not have,
a value that its IE cannot carry and a mandatory IE that is left out are
errors. The documentation of the
[`view`](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html)
module has a cookbook (add or remove an IE, send octets as they are, write
a message from its name, the message in a container, a protected message),
every rule and the notation of each kind of value.

## Benchmarks

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

The benchmarks are a package of their own, `benches/`, so that criterion
and pprof are no dependencies of the crate: `cargo bench` in that directory
runs them, and [`benches/src/lib.rs`](benches/src/lib.rs) says what they
measure and how to profile.

## Reference

| For | Read |
|-----|------|
| Each message, IE type and accessor | [`nas_5gs`](https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/index.html) and [`nas_eps`](https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_eps/index.html) |
| What the crate covers and does not, the rules of a receiver and of a sender, the versions of the specifications, what the tests hold | [the front page of the documentation](https://docs.rs/oxirush-nas) |
| The JSON forms: cookbook, paths, rules, notation of the values, the IE types that have a value, the units of the protocol configuration options | [`view`](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html) |
| Security contexts | [`nas_5gs::security`](https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/security/index.html) and [`nas_eps::security`](https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_eps/security/index.html) |
| Migrating from 0.4.0 | [CHANGELOG.md](CHANGELOG.md) |

The codec follows TS 24.501 and TS 24.301 V19.8.0 (Release 19). Two items
follow Release 20 instead and differ from V19.8.0 on the wire: the VLAN ID
of the non-3GPP device information, and two bits of the 5GMM capability.

## In a clone

`examples/` has six programs, each for 5GS and for EPS (`<name>_nas_5gs`
and `<name>_nas_eps`): `decode_message`, `build_message`,
`build_mobility_request`, `validate_message`, `security` (feature
`security`) and `view_message` (feature `serde`).

Until oxirush-security 0.3.0 is on crates.io, a `cargo` command in a clone
takes it from its repository, with `--config`. Cargo resolves it even for a
command that does not use the `security` feature:

```bash
SECURITY='patch.crates-io.oxirush-security.git="https://github.com/linouxis9/oxirush-security"'
cargo run --config "$SECURITY" --example decode_message_nas_5gs
cargo run --config "$SECURITY" --features security --example security_nas_eps
cargo test --config "$SECURITY" --all-features
cargo doc --config "$SECURITY" --all-features --no-deps --open
```

## The OxiRush family

| Crate | What it is |
|-------|------------|
| [oxirush-security](https://github.com/linouxis9/oxirush-security) | the keys and algorithms of NAS security |
| [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap), [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap) | the protocols that carry NAS messages between a base station and the core |
| [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u) | the user plane |
| [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp) | the transport of NGAP and S1AP |

## Contributing

Contributions are welcome. Open a pull request against `master` with a test
for what it changes: `cargo test --all-features` and
`cargo clippy --all-targets --all-features` pass on every commit, with the
`--config` of [In a clone](#in-a-clone) for now. A Rust block of this page
or of the documentation is checked with what it prints:
[`tests/readme.rs`](tests/readme.rs) says how. Sign off your commits
(`git commit -s`): by contributing you agree to the
[Developer Certificate of Origin](https://developercertificate.org/), which
says that you have the right to submit the contribution under the licence of
the project. [SECURITY.md](SECURITY.md) says how to report a vulnerability.

## License

Copyright 2025-2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgements

Inspired by [PacketRusher](https://github.com/HewlettPackard/PacketRusher).
