/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#![no_std]
#![deny(unsafe_code)]
#![deny(missing_docs)]

//! # oxirush-nas
//!
//! A codec for the NAS (non-access stratum) messages of 5GS and EPS (4G),
//! the signalling between a UE and its core network, per 3GPP TS 24.501 and
//! TS 24.301: it decodes, builds, validates and encodes them through typed
//! accessors, without `unsafe` code.
//!
//! ```rust
//! use oxirush_nas::nas_5gs::*;
//!
//! // A REGISTRATION REQUEST, as it is in the NAS-PDU of an NGAP message
//! let octets = hex::decode(
//!     "7e004179000d0199f9070000000000000010022e08a020000000000000"
//! ).unwrap();
//! let message = Nas5gsMessage::decode(&octets).unwrap();
//!
//! // On one line, for a log
//! println!("{message}");
//!
//! // The message struct is in the variant of its type
//! let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(request)) = &message else {
//!     panic!("not a REGISTRATION REQUEST");
//! };
//!
//! // A mandatory IE is a field, and its accessors read its value
//! let kind = request.fgs_registration_type.registration_type();
//! assert_eq!(kind, Some(RegistrationType::InitialRegistration));
//! let plmn = request.fgs_mobile_identity.plmn().unwrap();
//! assert_eq!(plmn.to_string(), "999-70");
//!
//! // An optional IE is an `Option`
//! let capability = request.ue_security_capability.as_ref().unwrap();
//! assert_eq!(capability.value, [0xa0, 0x20, 0, 0, 0, 0, 0, 0]);
//!
//! // The message encodes to the octets that it was decoded from
//! assert_eq!(message.encode().unwrap(), octets);
//! ```
//!
//! ```text
//! 5GMM RegistrationRequest (type=InitialRegistration, FOR=1, ngKSI=no key, identity=SUCI (PLMN=999-70, routing-indicator=0000, scheme=0, key=0, MSIN=0000000120), UE-SecCap=EA0 EA2 / IA2)
//! ```
//!
//! The output under a block is what the block prints, here and in the
//! other pages.
//!
//! [`nas_eps::NasEpsMessage`] has the same interface for EPS:
//! `NasEpsMessage::decode(&octets)`, `message.encode()`. The octets of a
//! 5GS message start with `7e` (5GMM) or `2e` (5GSM), and the first octet
//! of an EPS message ends with `7` (EMM) or `2` (ESM): an error of the
//! decoder of the other system says so.
//!
//! The [README](https://github.com/linouxis9/oxirush-nas) has an example of
//! each task. The four protocols:
//!
//! | Protocol | What it does | Module |
//! |----------|--------------|--------|
//! | 5GMM | 5GS mobility management: registration, authentication, security mode | [`nas_5gs`] |
//! | 5GSM | 5GS session management: PDU sessions | [`nas_5gs`] |
//! | EMM | EPS mobility management: attach, tracking area update | [`nas_eps`] |
//! | ESM | EPS session management: PDN connections and bearers | [`nas_eps`] |
//!
//! A message is a header and its information elements (IEs): the mandatory
//! ones in the order of the message, then the optional ones, each after its
//! identifier (IEI). A message struct has a field for each IE, and an IE
//! struct has the octets of its value and typed accessors for what they
//! mean.
//!
//! ## Build and encode a message
//!
//! ```rust
//! use oxirush_nas::nas_5gs::*;
//!
//! // REGISTRATION REJECT with cause #22 and a T3346 value of ten minutes:
//! // `new()` takes the mandatory IEs, `with_*()` adds the optional ones
//! let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
//! let t3346 = NasGprsTimer2::from_seconds(600).unwrap();
//! let reject = NasRegistrationReject::new(cause).with_t3346_value(t3346);
//!
//! // A message has the header of its sublayer
//! let message = Nas5gsMessage::new_5gmm(reject);
//! assert_eq!(hex::encode(message.encode().unwrap()), "7e0044165f012a");
//!
//! // What a sender must not send is a finding of `validate()`
//! assert!(message.validate().is_empty());
//! ```
//!
//! ## Protect and unprotect
//!
//! With the `security` feature, a security context has the NAS keys, the
//! algorithms and the NAS COUNTs of one UE, and puts a message under its
//! security header: integrity protection with a message authentication
//! code (MAC), and ciphering.
//!
//! ```rust
//! # #[cfg(feature = "security")] {
//! use oxirush_nas::nas_5gs::{
//!     CipheringAlgorithm, Direction, IntegrityAlgorithm, KAmf, Nas5gsMessage,
//!     Nas5gsSecurityHeaderType, NasSecurityContext,
//! };
//!
//! // The two ends of a link have the same KAMF, the key that the UE and
//! // the network share after authentication, and the same algorithms
//! let kamf = KAmf::new(&[0x11; 32]);
//! let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
//! let mut network = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
//! let mut ue = NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
//!
//! // The network protects a 5GMM STATUS: MAC, then ciphering
//! let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//! let header_type = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
//! let octets = network.protect(&status, header_type, Direction::Downlink).unwrap();
//! assert_eq!(octets.len(), 7 + 4);
//!
//! // The UE checks the MAC, deciphers and decodes
//! let received = ue.unprotect(&octets, Direction::Downlink).unwrap();
//! assert_eq!(received.message, status);
//! # }
//! ```
//!
//! ## Read and write a message as JSON
//!
//! With the `serde` feature, a message is a tree of JSON by the names of
//! the specification, which is also how one is written:
//!
//! ```rust
//! # #[cfg(feature = "serde")] {
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//! use oxirush_nas::tree;
//!
//! let reject = Nas5gsMessage::decode(&hex::decode("7e0044165f012a").unwrap()).unwrap();
//! let tree = tree!({
//!     "message-type": "registration-reject",
//!     "5gmm-cause": "congestion",
//!     "t3346-value": 600,
//! });
//! assert_eq!(reject.to_tree(), tree);
//! assert_eq!(Nas5gsMessage::from_tree(tree).unwrap(), reject);
//! # }
//! ```
//!
//! [Message views](#message-views) below has the other JSON forms.
//!
//! ## Errors
//!
//! Decoding and encoding return a [`common::NasError`], whose variants are
//! what a receiver answers differently (TS 24.501 and TS 24.301 chapter 7):
//! a message that is too short or of an unknown protocol is ignored, an
//! unknown message type is answered with a STATUS message, and a mandatory
//! IE that is missing or wrong with cause #96, with the field of the IE and
//! what is wrong with it in the error. An optional IE that is wrong does
//! not fail the message: it is kept with the unknown IEs, and `validate()`
//! reports it.
//!
//! ## Architecture
//!
//! Both [`nas_5gs`] and [`nas_eps`] are organized in three layers:
//!
//! | Layer | Module | Description |
//! |-------|--------|-------------|
//! | 1 | `types` | IE structs, defined by shared macros: each has the value of its IE in a `pub value` field and implements [`common::Encode`]/[`common::Decode`] for the value and its length indicator (the formats V, LV and LV-E of TS 24.007 §11.2). The identifier of an optional IE is that of its message, which writes it |
//! | 2 | `messages` | NAS message structs, defined by the shared `nas_message!` macro: mandatory IEs in the constructor, `set_*()` and `with_*()` for each IE, `clear_*()` for an optional one, IEI dispatch and codec functions |
//! | 3 | `ie` | Typed accessors — enums such as `RegistrationType` and `PdnType`, parsers and builder helpers in place of bit manipulation |
//!
//! Additional modules in each protocol: `message_types`, `display`, `validate`,
//! and `security`, which uses the matching `oxirush_security::nas_5gs` and
//! `oxirush_security::nas_eps` APIs behind the `security` feature. `upds`,
//! the UE policy delivery service, is specific to 5GS. The [`common`] module
//! has what the two protocols share: the [`common::Encode`] and
//! [`common::Decode`] traits, [`common::NasError`], the validation types,
//! [`common::Plmn`] and [`common::UnknownIe`]. The crate root has what the
//! two systems share, from [`common`]: the traits, the errors, [`Direction`],
//! the validation types and the unknown IEs. What belongs to one system is
//! in its module alone: [`nas_5gs::Nas5gsMessage`] and
//! [`nas_eps::NasEpsMessage`]. Message structs keep the decoded order of the optional
//! IEs, so they are built with `new()` and `with_*()` and not with struct
//! literals.
//!
//! ## Receiving and sending
//!
//! Decoding follows the receiver rules of TS 24.007 §11 and of the two
//! protocol specifications. `validate()` and `is_well_formed()` check what a
//! sender must produce.
//!
//! | Case | Rule |
//! |------|------|
//! | Spare bits, octets beyond the defined value | Ignored: they do not stop decoding. |
//! | Unknown IE | Skipped by its format, and kept in raw form for inspection and round-trip encoding. |
//! | Repeated IE | The first is taken; the others are kept in raw form. |
//! | Optional IE that is syntactically incorrect or out of sequence | Treated as absent, and kept in raw form. |
//! | Mandatory IE that is missing, cut short, shorter than its message allows or syntactically incorrect | [`common::NasError::InvalidMandatoryIe`], with the field and the fault. |
//! | Unknown IE encoded as "comprehension required" | Kept when it is well framed, so that a tool can inspect the message: `unknown_ies()` returns it, [`common::UnknownIe::is_comprehension_required`] flags it, `validate()` reports it. The answer that §7.5.1 of TS 24.501 or TS 24.301 requires of a receiver is the caller's. |
//! | EPS DETACH REQUEST | One message type for the two directions (TS 24.301 §8.2.11). [`nas_eps::NasEpsMessage::decode`] tells them apart by their contents, which do not decide every case; [`nas_eps::NasEpsMessage::decode_with_direction`] takes the direction. |
//! | Typed getters | The value a receiver must act on, with the receive fallbacks of the IE tables: `IdentityType::Imsi` for an undefined identity type of EPS, for example. `*_strict` and `*_raw` variants give the exact code. |
//! | `validate()` | The value and conditional rules of TS 24.501 and TS 24.301, repeated IEs and out-of-sequence IEs, as errors or warnings. `is_well_formed()` checks a single IE. |
//! | Encoding | Accepts every value a type can represent, so a test tool can emit invalid values. |
//! | Builders | A `from_*`, `with_*` or `set_*` that refuses what it is given returns a [`common::ValueError`]: the member, what it was given and the limit that this breaks. No public function panics on its arguments. |
//! | IMEI over NAS | `from_imei_tac_snr` of `nas_5gs::NasFGsMobileIdentity` and `nas_eps::{NasEpsMobileIdentity, NasMobileIdentity}` takes the 14 TAC and serial-number digits and adds the transmitted zero spare digit. `from_imei` keeps all 15 supplied digits. |
//! | Message structs | Built with `new()` and `with_*()`. They keep the decoded order of the optional IEs, so struct literals are not supported. |
//!
//! ## What the crate covers
//!
//! | Area | Contents |
//! |------|----------|
//! | 5GS messages | All 5GMM and 5GSM messages of TS 24.501, and the UE policy delivery service (Annex D) |
//! | EPS messages | All EMM and ESM messages of TS 24.301 clause 8, with the short SERVICE REQUEST header, EMM TRANSPORT and security-protected envelopes |
//! | IEs | 169 5GS and 153 EPS types, each the value of its IE, which a message has in the V, LV, LV-E, TV, TLV and TLV-E formats of TS 24.007 §11.2 |
//! | Typed accessors | Enums, value structs and `set_*`/`with_*` builders instead of bit manipulation. One implementation for the IEs that both specifications code alike: UE network capability, KSI, NAS security algorithms, GPRS timers, PCO/ePCO units, APN/DNN, PLMN lists, network name, time zone, eDRX and emergency numbers, for example |
//! | Errors | `NasError` separates the classes of clause 7: too-short messages, unknown protocol discriminators and message types, reserved security header types, invalid mandatory IEs |
//! | Display | `fmt::Display` for every message, with causes, identities and algorithms decoded. An identity is printed whole: what goes to a log is the caller's choice |
//! | Round trip | Decoding then encoding keeps unknown IEs, ignored repetitions, the order of the optional IEs and the spare half octet of a header |
//! | `security` | Integrity and ciphering with NAS COUNT tracking and replay protection per TS 33.501 and TS 33.401, the EPS short MAC, partial ciphering of CONTROL PLANE SERVICE REQUEST containers and 5GS↔EPS mapped contexts |
//! | `serde` | Each message as a tree and a view: every IE by its name, with its value in the usual notation and its octets; `Serialize` and `Deserialize` through the trees |
//!
//! ## What the crate does not cover
//!
//! | Subject | Limit |
//! |---------|-------|
//! | Procedures | It is a codec: no NAS procedure, timer or transport. Its only state is that of a security context. |
//! | Validity | `validate()` sees one message, not the state of a procedure. Encoding accepts every value a type can represent, so a message that encodes is not thereby valid. |
//! | Security state | A context does not persist itself: the caller keeps the next COUNT values and restores it from them. |
//! | Construction | No struct literals for message structs: they are built with `new()` and `with_*()`. |
//! | JSON | 13 5GS and 19 EPS IE types have octets alone ([which](https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html#ie-types-that-have-a-value)). A view and a tree compute no message authentication code. |
//! | Serde form | It is the tree: a message read from it means what the message means, with its octets where its values decide them (174 of the 191 fixtures), and the order of its optional IEs is that of the table. |
//! | Release 19 | Two items follow Release 20 and differ from V19.8.0 on the wire ([Specification versions](#specification-versions)). |
//! | Evidence | The tests of the crate itself ([Tests](#tests)), and 170 messages that two open-source cores and one UE simulator sent in a lab, with their source: no commercial UE, RAN or core, and no conformance test suite. The provenance of the 15 legacy 5GS wire values was not recorded. |
//!
//! ## Specification versions
//!
//! | Specification | Version | For |
//! |---------------|---------|-----|
//! | TS 24.501 | V19.8.0 (Release 19) | 5G NAS protocol: message definitions, IE formats, procedures |
//! | TS 24.301 | V19.8.0 (Release 19) | EPS NAS protocol: EMM and ESM messages and IE tables |
//! | TS 24.007 | | IE encoding formats (V, LV, TLV, etc.) and receiver rules |
//! | TS 24.008 | | IEs that TS 24.301 and TS 24.501 delegate: PCO, TFT, QoS, timers, identities |
//! | TS 23.003 | | identity formats: IMSI, IMEI, GUTI, APN |
//! | TS 23.038 | | GSM 7-bit default alphabet: network names, emergency number sub-services |
//! | TS 33.501 | | 5G security architecture: NAS security, key derivation, algorithms |
//! | TS 33.401 | | EPS security architecture: key derivation, NAS security, algorithms |
//!
//! Two items follow TS 24.501 V20.1.0 (Release 20) instead, and differ from
//! V19.8.0 on the wire: the 12-bit VLAN ID of
//! [`nas_5gs::Non3GppDeviceConnectionInformation::Ethernet`] (§9.11.4.41),
//! and bits 2 and 3 of 5GMM capability octet 13,
//! [`nas_5gs::NasFGmmCapability::nssaa_epc`] and
//! [`nas_5gs::NasFGmmCapability::aiot_ue_reader`] (§9.11.3.1).
//!
//! | Item | This crate, as V20.1.0 | V19.8.0 |
//! |------|------------------------|---------|
//! | `Non3GppDeviceConnectionInformation::Ethernet::vlan_tag_id`, §9.11.4.41 | The 12-bit VLAN ID: bit 8 of the first octet to bit 5 of the second, with bits 4 to 1 spare. 100 is sent as 0x0640. | A 16-bit VLAN tag ID in the two octets. A peer that follows it sends 100 as 0x0064, which this crate reads as VLAN 6. |
//! | 5GMM capability octet 13, bits 2 and 3, §9.11.3.1 | NSSAA-EPC (`nssaa_epc`) and AIoTUR (`aiot_ue_reader`). `validate()` accepts them. | Spare: its sender must leave them zero. |
//!
//! Clauses 8 and 9 and Annex D of TS 24.501 code nothing else differently in
//! V20.1.0, and clauses 8 and 9 of TS 24.301 are the same in both releases.
//!
//! ## Tests
//!
//! The tests are kept with the implementation: unit tests, wire vectors, round
//! trips, documentation tests and examples.
//!
//! | Vectors | What the tests hold |
//! |---------|---------------------|
//! | 15 legacy 5GS wire values, with cleartext inner messages | They round-trip. Their provenance was not recorded: regression vectors, not attributed packet-capture evidence. |
//! | `tests/fixtures/captured.tsv`: 170 messages that Open5GS v2.8.0 (as AMF and as MME), free5GC v4.2.3 and PacketRusher sent in a lab run, with the source of each, the name that the dissector of the capture gives it, and for the 114 that were protected their keys and NAS COUNT | Each decodes to the message of that name and encodes to its octets, with no `validate()` finding but for one IMEISV; with `security`, a context of the crate verifies and deciphers each protected one as it was on the wire. The head of the file says how they were captured and what they are not. |
//! | One constructed 5GS REGISTRATION REQUEST that carries a protected EPS ATTACH REQUEST | It round-trips. |
//! | An embedded EPS corpus: the NAS PDUs of two S1AP-carried attach attempts | They round-trip octet for octet. Their envelopes use EEA0, so the inner messages are decoded too and, with `security`, the HashMME of the SECURITY MODE COMMAND is checked against the ATTACH REQUEST. |
//! | `tests/fixtures`: 94 5GS and 97 EPS messages, at least one of each 5GMM, 5GSM, EMM and ESM message type of the codec | Each decodes, has no `validate()` error and encodes to its octets, also through its view written alone. Through its tree, which is its serde form, each is a message that means the same (`means_the_same()`), and 174 of the 191 have the same octets. |
//! | The Rust blocks of the README, of this page and of the pages of [`view`], [`nas_eps`] and the two `security` modules | They compile and run as documentation tests, with the `serde` and `security` features, and `tests/readme.rs` compares what each prints with the output shown under it. |
//!
//! ```bash
//! cargo test --all-features            # everything
//! cargo test --all-features capture_   # the EPS corpus
//! ```
//!
//! Until oxirush-security 0.3.0 and oxirush-utils 0.1.0 are on crates.io,
//! these commands take the `--config` that the README gives.
//!
//! Four fuzz targets hold what the tests hold on any octets: `decode_5gs` and
//! `decode_eps` that a message that decodes encodes, and decodes again to the
//! same message; `view_5gs` and `view_eps` that its view gives it back, that
//! its tree writes a message with the same tree which means the same, IE by
//! IE and after it is decoded again. The continuous integration runs each
//! for a minute.
//!
//! ```bash
//! ./fuzz/seed.sh                 # a corpus from tests/fixtures and fuzz/seeds-*.tsv
//! cargo +nightly fuzz run decode_5gs -- -max_total_time=60 -max_len=512
//! ```
//!
//! ## Examples
//!
//! Each example has a 5GS and an EPS counterpart, `<name>_nas_5gs` and
//! `<name>_nas_eps`, for the same procedure.
//!
//! | Example | 5GS | EPS | Feature |
//! |---------|-----|-----|---------|
//! | `build_message` | REGISTRATION REJECT | ATTACH REJECT | |
//! | `build_mobility_request` | mobility registration update REGISTRATION REQUEST | TRACKING AREA UPDATE REQUEST | |
//! | `decode_message` | REGISTRATION REQUEST with typed accessors | ATTACH REQUEST with typed accessors | |
//! | `validate_message` | registration, authentication, and security mode messages | attach, authentication, and security mode messages | |
//! | `security` | protect and unprotect with keys from KAMF | protect and unprotect with keys from KASME | `security` |
//! | `view_message` | REGISTRATION REQUEST read and edited through its view, by the paths of its IEs | ATTACH REQUEST read and edited through its view, by the paths of its IEs | `serde` |
//!
//! ## Feature flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `std` (default) | The standard library. Without it the crate is `no_std` and needs an allocator: the codec, `validate()`, the builders and `Display` are the same |
//! | `security` | NAS security envelope (protect/unprotect) via `oxirush-security`. It is `no_std` too; with `std`, oxirush-security chooses the vector code of SNOW 3G and ZUC from what the processor has |
//! | `serde` | The tree and the view of a message, and their paths: they keep the names that they printed for the whole program. `Serialize` and `Deserialize` through them: a message is its tree, an IE what the tree of a message shows of it, and a value of an IE its form there. It is `no_std` too. A tree and a view are a `tree::Value`, JSON whose objects keep their members in the order of the message, which converts to and from a `serde_json::Value`: `oxirush-utils` 0.1, and through it `serde_json` 1, are public dependencies of the crate with this feature |
//! | `idna` | The realm and the username of the NAI of a SUCI are also checked as internationalized names: Unicode normalization form C, and a realm that IDNA takes as it is written. Without it they are checked by the grammar of RFC 7542 and the lengths of a domain name. It brings the Unicode tables of `idna` and `unicode-normalization`, and is `no_std` too |
//!
//! ## Message views
//!
//! With the `serde` feature, [`Nas5gsMessage::to_view`] and
//! [`nas_eps::NasEpsMessage::to_view`] give a message as a reader names it:
//! each IE by the name the specification gives it, in lower case with
//! hyphens, with its `value` in the usual notation (the name of a coded
//! value, `"208-93"` for a PLMN identity, digits for an IMSI, a number for
//! a TMSI or a TAC, text for a DNN or an IP address, the view of the
//! message in a container) and its `octets` in hexadecimal. An optional IE
//! that the message does not have is `null`. `with_view` returns the
//! message of an edited view: an IE is encoded from a value that was
//! changed, or takes the octets that were, an optional IE is added or taken
//! out, and what the message cannot keep is an error. The [`view`] module
//! reads and edits a view by paths such as `/nas/5g-guti/value/guti/plmn`.
//!
//! [`Nas5gsMessage::to_tree`] and [`nas_eps::NasEpsMessage::to_tree`] show
//! a message as a tree, which is the compact form of a view: its
//! `message-type` and each IE that it has by its value alone, as in
//! `{"message-type": "5gmm-status", "5gmm-cause": "congestion"}`.
//! `from_tree` writes the message of a tree.
//!
//! ## OxiRush crates
//!
//! [oxirush-security](https://github.com/linouxis9/oxirush-security) (keys
//! and algorithms of NAS security),
//! [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap) and
//! [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap) (the protocols
//! that carry NAS messages between a base station and the core),
//! [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u) (the user
//! plane) and [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp)
//! (their transport).
//!
//! [`view`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/view/index.html
//! [`Nas5gsMessage::to_view`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/messages/enum.Nas5gsMessage.html#method.to_view
//! [`Nas5gsMessage::to_tree`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_5gs/messages/enum.Nas5gsMessage.html#method.to_tree
//! [`nas_eps::NasEpsMessage::to_view`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_eps/messages/enum.NasEpsMessage.html#method.to_view
//! [`nas_eps::NasEpsMessage::to_tree`]: https://docs.rs/oxirush-nas/latest/oxirush_nas/nas_eps/messages/enum.NasEpsMessage.html#method.to_tree

#[macro_use]
extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

/// What the prelude of the standard library has of `alloc`, for the modules
/// of the crate: it is built without `std`.
mod prelude {
    pub(crate) use alloc::borrow::ToOwned;
    pub(crate) use alloc::boxed::Box;
    pub(crate) use alloc::string::{String, ToString};
    pub(crate) use alloc::vec::Vec;
}

pub mod common;
pub mod nas_5gs;
pub mod nas_eps;
#[cfg(feature = "serde")]
pub mod view;

/// The examples of the README, which the documentation tests compile and run.
#[cfg(all(doctest, feature = "serde", feature = "security"))]
#[doc = include_str!("../README.md")]
struct Readme;

// What the two systems share. What belongs to one of them is in its module:
// `nas_5gs::NasSecurityContext` and `nas_eps::NasSecurityContext`.
pub use common::{
    Decode, DecodeOptions, Direction, Encode, IeFault, MAX_IE_VALUE_LENGTH, NasError, Octets, Plmn,
    Result, Severity, UnknownIe, UnknownIes, UnknownIesIter, Validate, ValidationError, ValueError,
    ValueFault,
};
/// The identities of the OxiRush crates: those of both systems, which
/// [`nas_5gs`] and [`nas_eps`] name as their system does.
pub use oxirush_utils::identity;
/// The trees of the OxiRush crates, of the `oxirush-utils` that this crate is
/// built with: the tree and the view of a message, [`tree::Value`], JSON
/// whose objects keep their members in the order of the message, and
/// `tree!`, which writes one in the code as `serde_json::json!` does.
#[cfg(feature = "serde")]
pub use oxirush_utils::tree;

/// Version of oxirush-nas
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nas_5gs::*;
    use base64::prelude::*;

    // The fifteen wire values of the tests from here to
    // `test_deregistration_request` came with the first version of the
    // crate, and where they were captured was not recorded: they are
    // regression vectors, not attributed evidence. The messages of
    // `tests/fixtures/captured.tsv` have their source.

    #[test]
    fn test_registration_request_1() {
        let payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_auth_request() {
        let payload = hex::decode(
            "7e00560002000021ab6f2a1cc5c5938d38cba14dfe26b0012010a820e67b8896800076a638e98eed4747",
        )
        .unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_security_mode_command() {
        let payload = hex::decode("7e005d020002a020e1360102").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_registration_request_2() {
        let payload = BASE64_STANDARD
            .decode("fgBedwAJFREAAAAAAAAAcQAgfgBBCQANAZn5BwAAAAAAAAAQAhABBy4IoCAAAAAAAAA=")
            .unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_registration_accept() {
        let payload = BASE64_STANDARD
            .decode("fgBCAQF3AAvymfkHAgBAwAAC31QHQJn5BwAAARUCAQEhAgEAXgGp")
            .unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_registration_complete() {
        let payload = BASE64_STANDARD.decode("fgBD").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_pdu_session_establishment_request() {
        let payload = BASE64_STANDARD
            .decode("fgBnAQAULgEBwf//kXsACoAACgAADQAAAwASAYEiAQElCQhpbnRlcm5ldA==")
            .unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_configuration_update_command() {
        let payload = BASE64_STANDARD
            .decode("fgBUQw+QAE8AcABlAG4ANQBHAFNGAEdCMGICZHEASQEA")
            .unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_configuration_update_complete() {
        let payload = BASE64_STANDARD.decode("fgBV").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_pdu_session_establishment_accept() {
        let payload = BASE64_STANDARD.decode("fgBoAQBtLgEBwhEACQEABjExAQH/AQYD9CQD9CQpBQEKLQC9IgEBeQAGASBBAQEJewA1gAANBAgICAgADQQICAQEAAMQIAFIYEhgAAAAAAAAAACIiAADECABSGBIYAAAAAAAAAAAiEQlCQhpbnRlcm5ldBIB").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_service_request() {
        let payload = BASE64_STANDARD
            .decode("fgBMEAAHBABAwAAC33EAFX4ATBAABwQAQMAAAt9AAgIAUAICAA==")
            .unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_service_accept() {
        let payload = BASE64_STANDARD.decode("fgBOUAICACYCAAA=").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_pdu_session_release_request() {
        let payload = BASE64_STANDARD.decode("fgBnAQAELgEB0RIB").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_pdu_session_release_command() {
        let payload = BASE64_STANDARD.decode("fgBoAQAFLgEB0yQSAQ==").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_deregistration_request() {
        let payload = BASE64_STANDARD.decode("fgBFCQAL8pn5BwIAQMAAAt8=").unwrap();

        let parsed_message = Nas5gsMessage::decode(&payload).unwrap();
        let encoded_message = parsed_message.encode().unwrap();

        assert_eq!(payload, encoded_message);
    }

    // Test Display formatting
    #[test]
    fn test_display_registration_request() {
        let payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        let msg = Nas5gsMessage::decode(&payload).unwrap();
        let display = format!("{msg}");
        assert!(display.contains("RegistrationRequest"));
        assert!(display.contains("Initial"));
        assert!(display.contains("SUCI"));
    }

    #[test]
    fn test_display_auth_request() {
        let payload = hex::decode(
            "7e00560002000021ab6f2a1cc5c5938d38cba14dfe26b0012010a820e67b8896800076a638e98eed4747",
        )
        .unwrap();
        let msg = Nas5gsMessage::decode(&payload).unwrap();
        let display = format!("{msg}");
        assert!(display.contains("AuthenticationRequest"));
        assert!(display.contains("RAND="));
    }

    #[test]
    fn test_display_security_mode_command() {
        let payload = hex::decode("7e005d020002a020e1360102").unwrap();
        let msg = Nas5gsMessage::decode(&payload).unwrap();
        let display = format!("{msg}");
        assert!(display.contains("SecurityModeCommand"));
        assert!(display.contains("NEA"));
        assert!(display.contains("NIA"));
    }

    // Test validation
    #[test]
    fn test_validate_good_message() {
        let payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        let msg = Nas5gsMessage::decode(&payload).unwrap();
        let errs = msg.validate();
        assert!(errs.is_empty(), "Unexpected errors: {errs:?}");
    }

    // Test container recursive decode
    #[test]
    fn test_container_decode() {
        // SecurityModeComplete with NAS message container containing a RegistrationRequest
        let payload = BASE64_STANDARD
            .decode("fgBedwAJFREAAAAAAAAAcQAgfgBBCQANAZn5BwAAAAAAAAAQAhABBy4IoCAAAAAAAAA=")
            .unwrap();
        let msg = Nas5gsMessage::decode(&payload).unwrap();
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::SecurityModeComplete(smc)) = &msg {
            if let Some(ref container) = smc.nas_message_container {
                let inner = container.decode_as_nas_message().unwrap();
                // The container holds a RegistrationRequest
                if let Nas5gsMessage::Gmm(hdr, _) = &inner {
                    assert_eq!(hdr.message_type, Nas5gmmMessageType::RegistrationRequest);
                } else {
                    panic!("Expected 5GMM message inside container");
                }
            } else {
                panic!("Expected NAS message container in SecurityModeComplete");
            }
        } else {
            panic!("Expected SecurityModeComplete");
        }
    }

    // ── Negative / robustness tests ──────────────────────────────────────

    #[test]
    fn test_empty_buffer() {
        assert!(Nas5gsMessage::decode(&[]).is_err());
    }

    #[test]
    fn test_single_byte() {
        assert!(Nas5gsMessage::decode(&[0x7e]).is_err());
    }

    #[test]
    fn test_two_bytes_5gmm() {
        // EPD + SHT but no message type
        assert!(Nas5gsMessage::decode(&[0x7e, 0x00]).is_err());
    }

    #[test]
    fn test_unknown_epd() {
        assert!(Nas5gsMessage::decode(&[0xFF, 0x00, 0x41]).is_err());
    }

    #[test]
    fn test_truncated_security_header() {
        // Security-protected (SHT=0x01) but not enough bytes for MAC+SN
        assert!(Nas5gsMessage::decode(&[0x7e, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_truncated_unknown_tlv_ie() {
        // RegistrationRequest with unknown TLV IE that claims more data than available.
        // IEI 0x36 is currently unallocated in NasRegistrationRequest.
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x36, 0xFF]); // Unknown IEI 0x36, length=255 but no data
        // Unknown non-comprehension-required IEs are ignored under §7.6.1;
        // with no recoverable boundary, their remaining octets are retained.
        let message = Nas5gsMessage::decode(&payload).unwrap();
        assert_eq!(message.encode().unwrap(), payload);
    }

    #[test]
    fn test_reserved_5gmm_security_header_type_is_rejected() {
        // EPD=5GMM, spare half octet = 0, reserved SHT = 0x05.
        assert!(Nas5gsMessage::decode(&[0x7e, 0x05, 0x41]).is_err());
    }

    #[test]
    fn test_nested_security_protected_message_is_rejected() {
        let inner_plain = Nas5gsMessage::new_5gmm(messages::NasRegistrationComplete::new());
        let nested = Nas5gsMessage::protect(
            inner_plain,
            Nas5gsSecurityHeaderType::IntegrityProtected,
            0,
            0,
        )
        .unwrap();

        assert!(
            Nas5gsMessage::protect(nested, Nas5gsSecurityHeaderType::IntegrityProtected, 0, 1)
                .is_err()
        );
    }

    #[test]
    fn test_unknown_iei_tv1_skip() {
        // RegistrationRequest with unknown TV-1 IEI (0xE0, bit 8=1)
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.push(0xE7); // Unknown TV-1 IEI — preserved (1 byte)
        let msg = Nas5gsMessage::decode(&payload).unwrap();
        // Should still parse as RegistrationRequest
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(ref reg)) = msg {
            assert_eq!(reg.unknown_ies.len(), 1);
            assert_eq!(reg.unknown_ies.get(0).unwrap().iei, 0xE7);
        } else {
            panic!("Expected RegistrationRequest");
        }
        // Round-trip preserves unknown IEs
        let re_encoded = msg.encode().unwrap();
        assert_eq!(payload, re_encoded);
    }

    #[test]
    fn test_unknown_iei_tlve_skip() {
        // RegistrationRequest with unknown TLV-E IEI (0x7D, bits 7-5 = "111")
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x7D, 0x00, 0x02, 0xAA, 0xBB]); // TLV-E: IEI + len(2) + 2 bytes
        let msg = Nas5gsMessage::decode(&payload).unwrap();
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(ref reg)) = msg {
            assert_eq!(reg.unknown_ies.len(), 1);
            assert_eq!(reg.unknown_ies.get(0).unwrap().iei, 0x7D);
            assert_eq!(
                reg.unknown_ies.get(0).unwrap().data,
                [0x00, 0x02, 0xAA, 0xBB]
            );
        } else {
            panic!("Expected RegistrationRequest");
        }
        // Round-trip preserves unknown IEs
        let re_encoded = msg.encode().unwrap();
        assert_eq!(payload, re_encoded);
    }

    #[test]
    fn test_unknown_iei_tlv_skip() {
        // RegistrationRequest with unknown TLV IEI (0x36, bits 7-5 != "111")
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x36, 0x03, 0x01, 0x02, 0x03]); // TLV: IEI + len(3) + 3 bytes
        let msg = Nas5gsMessage::decode(&payload).unwrap();
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(ref reg)) = msg {
            assert_eq!(reg.unknown_ies.len(), 1);
            assert_eq!(reg.unknown_ies.get(0).unwrap().iei, 0x36);
            assert_eq!(
                reg.unknown_ies.get(0).unwrap().data,
                [0x03, 0x01, 0x02, 0x03]
            );
        } else {
            panic!("Expected RegistrationRequest");
        }
        // Round-trip preserves unknown IEs
        let re_encoded = msg.encode().unwrap();
        assert_eq!(payload, re_encoded);
    }

    #[test]
    fn test_registration_reject_accepts_legacy_forbidden_tai_ieis() {
        let mut encoded = Nas5gsMessage::new_5gmm(
            messages::NasRegistrationReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe))
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
        ).encode()
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = Nas5gsMessage::decode(&encoded).unwrap();
        match decoded {
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(message)) => {
                assert!(
                    message
                        .forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming
                        .is_some()
                );
                assert!(message
                    .forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service
                    .is_some());
            }
            _ => panic!("expected RegistrationReject"),
        }
    }

    #[test]
    fn test_deregistration_request_ue_terminated_accepts_legacy_forbidden_tai_ieis() {
        let mut encoded = Nas5gsMessage::new_5gmm(
            messages::NasDeregistrationRequestUeTerminated::new(NasDeRegistrationType::new(0x09))
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
        ).encode()
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = Nas5gsMessage::decode(&encoded).unwrap();
        match decoded {
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::DeregistrationRequestUeTerminated(message)) => {
                assert!(
                    message
                        .forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming
                        .is_some()
                );
                assert!(message
                    .forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service
                    .is_some());
            }
            _ => panic!("expected DeregistrationRequestUeTerminated"),
        }
    }

    #[test]
    fn test_service_reject_accepts_legacy_forbidden_tai_ieis() {
        let mut encoded = Nas5gsMessage::new_5gmm(
            messages::NasServiceReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe))
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
        ).encode()
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = Nas5gsMessage::decode(&encoded).unwrap();
        match decoded {
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::ServiceReject(message)) => {
                assert!(
                    message
                        .forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming
                        .is_some()
                );
                assert!(message
                    .forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service
                    .is_some());
            }
            _ => panic!("expected ServiceReject"),
        }
    }

    #[test]
    fn test_5gsm_header_too_short() {
        // 5GSM EPD but truncated header
        assert!(Nas5gsMessage::decode(&[0x2e, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_encode_decode_identity_request() {
        // Build an IdentityRequest for SUCI
        let msg = Nas5gsMessage::new_5gmm(messages::NasIdentityRequest::new(
            NasFGsIdentityType::from_identity_type(MobileIdentityType::Suci).unwrap(),
        ));
        let encoded = msg.encode().unwrap();
        let decoded = Nas5gsMessage::decode(&encoded).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_registration_reject() {
        let msg = Nas5gsMessage::new_5gmm(messages::NasRegistrationReject::new(
            NasFGmmCause::from_cause(GmmCause::IllegalUe),
        ));
        let encoded = msg.encode().unwrap();
        let decoded = Nas5gsMessage::decode(&encoded).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_auth_failure() {
        let msg = Nas5gsMessage::new_5gmm(
            messages::NasAuthenticationFailure::new(NasFGmmCause::from_cause(
                GmmCause::SynchFailure,
            ))
            .with_authentication_failure_parameter(
                NasAuthenticationFailureParameter::new(vec![0x01; 14]),
            ),
        );
        let encoded = msg.encode().unwrap();
        let decoded = Nas5gsMessage::decode(&encoded).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_deregistration() {
        let msg = Nas5gsMessage::new_5gmm(messages::NasDeregistrationRequestUeOriginating::new(
            NasDeRegistrationType::new(0x09), // switch_off=1, 3GPP access
            NasKeySetIdentifier::new(0),
            NasFGsMobileIdentity::from_guti(
                Guti::new(
                    Plmn::from_digits([2, 0, 8], &[9, 3]).unwrap(),
                    0x02,
                    0x40,
                    0x00,
                    0xDEADBEEF,
                )
                .unwrap(),
            ),
        ));
        let encoded = msg.encode().unwrap();
        let decoded = Nas5gsMessage::decode(&encoded).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_message_protect_rejects_plain_5gsm_inner_message() {
        let inner = Nas5gsMessage::new_5gsm(
            messages::NasPduSessionEstablishmentRequest::new(
                NasIntegrityProtectionMaximumDataRate::from_rates(
                    MaxDataRate::FullRate,
                    MaxDataRate::FullRate,
                ),
            ),
            1,
            1,
        );

        assert!(
            Nas5gsMessage::protect(inner, Nas5gsSecurityHeaderType::IntegrityProtected, 0, 0)
                .is_err()
        );
    }

    #[test]
    fn test_security_protected_plain_5gsm_is_reported_by_validation() {
        let inner = Nas5gsMessage::new_5gsm(
            messages::NasPduSessionEstablishmentRequest::new(
                NasIntegrityProtectionMaximumDataRate::from_rates(
                    MaxDataRate::FullRate,
                    MaxDataRate::FullRate,
                ),
            ),
            1,
            1,
        )
        .encode()
        .unwrap();

        let mut protected = vec![0x7E, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        protected.extend_from_slice(&inner);

        let message = Nas5gsMessage::decode(&protected).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|finding| finding.field == "plain_fgs_nas_message")
        );
        assert_eq!(message.encode().unwrap(), protected);
    }

    #[test]
    fn test_message_protect_rejects_invalid_new_context_sht_for_non_security_mode_command() {
        let inner = Nas5gsMessage::new_5gmm(messages::NasRegistrationComplete::new());

        assert!(
            Nas5gsMessage::protect(
                inner,
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                0,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn test_message_protect_rejects_invalid_ciphered_new_context_sht_for_non_security_mode_complete()
     {
        let inner = Nas5gsMessage::new_5gmm(messages::NasRegistrationComplete::new());

        assert!(
            Nas5gsMessage::protect(
                inner,
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
                0,
                0,
            )
            .is_err()
        );
    }
}
