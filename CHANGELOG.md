# Changelog

All notable changes to `oxirush-nas` are recorded here.

## Unreleased

### Added

- `innermost()` of a 5GS and of an EPS `Message`: the message inside its
  security envelopes, the plain message of an integrity protected one and
  the ciphertext of a ciphered one.

## 0.6.0 - 2026-11-08

A lighter crate: each item has one path and one name, a message has one
JSON form, its tree, and each thing is written once. It is not source
compatible with 0.5.0; the table below has the changes that a caller makes.

### Changed

- oxirush-utils 0.2 and oxirush-security 0.4. The algorithms of a security
  context and of the IEs are `identity::Algorithm` (`Null`, `Snow3g`, `Aes`,
  `Zuc`), and a SUCI is `identity::Suci`.
- Each item has one path. The submodules of `nas_5gs` and `nas_eps` are
  private and their items are `nas_5gs::X` and `nas_eps::X`; what both
  systems share is at the root (`Error`, `Decode`, `Encode`, `Direction`,
  `Validate`, `DecodeOptions`...); the identities are in `identity` alone.
- A type is named by its specification, without the prefix `Nas` and the
  spelling `FG`: `nas_5gs::RegistrationRequest`, `nas_5gs::MobileIdentity`,
  `GmmCause`, `nas_5gs::Message`, `Error`. An enum of values whose name its IE
  has takes `Value`: `GmmCauseValue`, `RegistrationTypeValue`.
- An enum of codes reads with `TryFrom<u8>` (`Err` with the code) and as a
  receiver with `received()`, and writes with `u8::from`; a message type is
  `From<u8>`, with `Unknown(code)`.
- The feature `serde` is `tree`, and takes `std`; the codec, `validate()` and
  the security contexts stay `no_std`.
- A message has one JSON form, its tree. `with_tree()` writes the message
  that an edited tree says and keeps the octets of every IE that it leaves
  as it was; the module `paths` reads and edits a tree by path, without
  `/value`; `ie_octets()` gives the octets that an IE came with;
  `names()` of a message type lists the members of its tree.
- The names of a tree are printed when the crate is compiled. A name is read
  as itself, written alike, or by its letters and digits; a name spelt as
  the identifier of the source is not (`fgs_mobile_identity`).
- An IE is changed by its setters (`set_x()`); a message keeps its builders.
- A 5GS security context has one method of each kind, which takes the
  `NasConnection` of its access: `protect`, `protect_initial`,
  `protect_opaque_payload`, `unprotect`, `unprotect_raw`.
- A message is decoded with `decode()`, `decode_with(octets, options)` or
  `decode_lenient(octets, options)`, in both systems; the direction that
  tells the two EPS DETACH REQUESTs apart is one of the `DecodeOptions`.
- `Display` of a message is written from its table: its name, then each IE
  that it has, by the name of its tree and as its type shows it, or else as
  its tree on one line (its octets without the feature `tree`). An IE that
  holds a key shows its length alone, the key of an AUN3 device too, whose
  `Debug` now hides it as well.
- `Error` writes its own text; `thiserror` is no dependency, and `hex` one of
  the tests alone. `validate()` takes the rules of each IE type from one table.
- The README blocks are checked by the package of `readme/`.

### Added

- The NAS transparent containers of a handover between 5GS and EPS (TS
  24.501 §4.4.2.2, §4.4.2.4) on the 5GS security context:
  `n1_to_s1_container`, `verify_n1_to_s1_container`, `s1_to_n1_container`
  and `verify_s1_to_n1_container`.
- The names of the units of the protocol configuration options that carry a
  PDU session in a PDN connection (TS 24.008 Table 10.5.154): `pdu-session-id`,
  `5gsm-cause`, `s-nssai`, `qos-rules`, `session-ambr` and
  `qos-flow-descriptions`.
- A replay window: `set_replay_window(size)` lets a security context take a
  message whose NAS COUNT is below the highest that it accepted, once (TS
  24.501 and TS 24.301 §4.4.3.1), up to `MAX_REPLAY_WINDOW` (64).
- `validate()` reports an unknown IE whose octets are not one IE of the
  format of its IEI (TS 24.007 §11.2.4), and holds the MS identity of an
  ATTACH ACCEPT and a TRACKING AREA UPDATE ACCEPT to a TMSI or the IMSI.
- Ten fuzz targets, which CI runs for a minute each at each commit.

### Fixed

- The N3 data flag of the 5GMM capability is `n3_data_not_supported` as
  sent, and `n3_data()` is the capability (TS 24.501 §9.11.3.1).
- Payload container type 8 prints as `ciot`, not `cio-t`.
- A CONTROL PLANE SERVICE REQUEST is read with an ESM message container of
  no octet to two (TS 24.301 §7.5.2).
- `ServiceAreaList::from_entries` refuses a first TAC that would overflow;
  `RemoteUeContextList::from_contexts` writes the HPLMN ID that Table
  9.11.4.29.2 asks for; `ServiceLevelAaContainer::from_parameters` writes the
  length of a parameter as its IEI has it.
- A packet filter of a QoS rule decodes a component after (S)RTP multiplexed
  media identification information; `from_rules` refuses the components
  that Table 9.11.4.13.1 does not allow with an ethertype, and an RTP SDES
  header extension id that is said to be there and is not.
- The SOR transparent container reads its PLMN list, SOR-CMCI rules and
  SOR-SNPN-SI-LS entries with the lengths of TS 24.501 §9.11.3.51.
- 5GMM cause #10 is "Implicitly de-registered".

### Migration from 0.5

| 0.5 | 0.6 |
|-----|-----|
| `oxirush_nas::nas_5gs::ie::X`, `messages::X`, `types::X`, `common::X` | `oxirush_nas::nas_5gs::X`, `oxirush_nas::X` |
| `nas_5gs::Guti`, `STmsi`, `Tai`, `oxirush_nas::Plmn` | `identity::Guti5g`, `STmsi5g`, `Tai5gs`, `identity::Plmn` |
| `NasRegistrationRequest`, `NasFGsMobileIdentity`, `NasFGmmCause` | `RegistrationRequest`, `nas_5gs::MobileIdentity`, `GmmCause` |
| `Nas5gsMessage`, `NasEpsMessage`, `NasError` | `nas_5gs::Message`, `nas_eps::Message`, `Error` |
| `GmmCause` (the enum), `RegistrationType` (the enum) | `GmmCauseValue`, `RegistrationTypeValue` |
| `CipheringAlgorithm::NEA2`, `IntegrityAlgorithm::EIA2` | `identity::Algorithm::Aes` |
| `X::from_u8(c)`, `from_u8_strict(c)`; `x.as_u8()` | `X::try_from(c)`, or `X::received(c)` as a receiver; `u8::from(x)` |
| `features = ["serde"]` | `features = ["tree"]` |
| `to_view()`, `with_view(view)`, `from_view(view)` | `to_tree()`, `with_tree(tree)`, `from_tree(tree)` |
| `view::select(&view, "/nas/5g-guti/value/guti")`, `set`, `insert` | `paths::select(&tree, "/nas/5g-guti/guti")`, `set`, `insert` |
| `view::select(&view, "/nas/5g-guti/octets")` | `message.ie_octets("/nas/5g-guti")` |
| `kind.view_names()` | `kind.names()` |
| `ie.with_x(v)` on an IE | `let mut ie = ..; ie.set_x(v);` |
| `cause.cause_raw()` | `cause.value` |
| `ctx.protect(&m, sht, dir)`, `protect_for_access(.., conn)` | `ctx.protect(&m, sht, dir, NasConnection::ThreeGpp)` |
| `ctx.unprotect(data, dir)`, `unprotect_raw`, `protect_initial(&m)` | the same with the `NasConnection` last |
| `ctx.protect_bytes(octets, sht, dir)` | `ctx.protect(&Message::decode(&octets)?, sht, dir, ..)` |
| `nas_eps::Message::decode_with_direction(octets, dir)` | `decode_with(octets, DecodeOptions::STRICT.with_direction(dir))` |
| `decode_lenient(octets)` | `decode_lenient(octets, DecodeOptions::STRICT)` |
| `5GMM RegistrationReject (cause=#22 (Congestion), T3346=10 min)` | `5GMM RegistrationReject (5gmm-cause: #22 (Congestion), t3346-value: 10 min)`: every IE, by the name of its tree |

## 0.5.0 - 2026-10-24

The receivers closer to TS 24.501 and TS 24.301 V19.8.0: each IE of a
message has `set_<ie>` and `with_<ie>`, and its field is public; a message
is read leniently with `decode_lenient`, answered by `answer_to` (clause 7),
and checked by `validate()` against the rules of a sender and of a receiver;
the views and trees of the messages, with paths; the security contexts of
both systems, with the keys of oxirush-security, the NAS COUNTs and the
initial NAS messages (TS 24.501 §4.4.6); the IEs of TS 24.501 V19 and V20 by
type, with their values. It was not source compatible with 0.4.0.

## 0.4.0 - 2026-09-27

The EPS NAS codec (TS 24.301), and the IEs that 5GS and EPS share in one
type. It was not source compatible with 0.2.0.
