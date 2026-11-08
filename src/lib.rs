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
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(unsafe_code)]
#![deny(missing_docs)]

//! The NAS messages of 5GS and EPS in Rust, per 3GPP TS 24.501 and TS 24.301
//! (Release 19): decode, build, validate and encode them, edit them as JSON,
//! and protect them.
//!
//! ```rust
//! use oxirush_nas::Validate;
//! use oxirush_nas::identity::MobileIdentityType5gs;
//! use oxirush_nas::nas_5gs::*;
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Decode a REGISTRATION REQUEST
//!     let bytes = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000")?;
//!     let msg = Message::decode(&bytes)?;
//!     println!("{msg}");
//!
//!     // Read its IEs through typed accessors
//!     if let Message::Gmm(_, GmmMessage::RegistrationRequest(reg)) = &msg {
//!         let kind = reg.fgs_registration_type.registration_type();
//!         assert_eq!(kind, Some(RegistrationTypeValue::InitialRegistration));
//!
//!         let identity = &reg.fgs_mobile_identity;
//!         assert_eq!(identity.identity_type(), Some(MobileIdentityType5gs::Suci));
//!
//!         // The PLMN identity names the network: a country code and a network code
//!         if let Some(plmn) = identity.plmn() {
//!             println!("MCC={}, MNC={}", plmn.mcc(), plmn.mnc());
//!         }
//!     }
//!
//!     // It passes every check that can be made on a single message, and encodes
//!     // to the octets that were decoded
//!     assert!(msg.validate().is_empty());
//!     assert_eq!(bytes, msg.encode()?);
//!
//!     // Build the answer, a REGISTRATION REJECT with cause #22 and a T3346 value
//!     // of ten minutes: `new()` takes the mandatory IEs, `with_*()` adds the others
//!     let cause = GmmCause::from_cause(GmmCauseValue::Congestion);
//!     let t3346 = GprsTimer2::from_seconds(600)?;
//!     let reject = RegistrationReject::new(cause).with_t3346_value(t3346);
//!     let answer = Message::new_5gmm(reject);
//!     println!("{answer}");
//!
//!     // Encode it
//!     assert_eq!(hex::encode(answer.encode()?), "7e0044165f012a");
//!     Ok(())
//! }
//! ```
//!
//! ```text
//! 5GMM RegistrationRequest (type=InitialRegistration, FOR, ngKSI=no key, identity=suci-0-208-93-0000-0-0-0000000120, UE-SecCap=EA0 EA2 / IA2)
//! MCC=208, MNC=93
//! 5GMM RegistrationReject (cause=#22 (Congestion), T3346=10 min)
//! ```
//!
//! Each example is followed by its output.
//!
//! [`nas_eps::Message`] has the same interface for EPS:
//! `Message::decode(&octets)`, `message.encode()`. The octets of a
//! 5GS message start with `7e` (5GMM) or `2e` (5GSM), and the first octet
//! of an EPS message ends with `7` (EMM) or `2` (ESM): an error of the
//! decoder of the other system says so.
//!
//! # Tasks
//!
//! The [README](https://github.com/linouxis9/oxirush-nas#readme) has an
//! example of each, with what it prints.
//!
//! | Task | Items |
//! |------|-------|
//! | Register a UE, from its REGISTRATION REQUEST to the ACCEPT | [`nas_5gs::Message`], [`nas_5gs::AuthenticationRequest`], [`nas_5gs::SecurityModeCommand`], [`nas_5gs::SecurityContext`], [`nas_5gs::RegistrationAccept`] |
//! | Attach a UE to EPS | [`nas_eps::Message`], [`nas_eps::AuthenticationRequest`], [`nas_eps::SecurityContext`] |
//! | Change a decoded message | the `set_*`, `with_*` and `clear_*` of a message, as [`nas_5gs::RegistrationReject::with_t3346_value`] |
//! | A 5GSM message in UL NAS TRANSPORT | [`nas_5gs::UlNasTransport`], [`nas_5gs::PayloadContainer`] |
//! | Validate a message, and answer one that is faulty | [`Validate`], [`nas_5gs::Message::answer_to`], [`nas_5gs::Message::decode_lenient`] |
//! | A message as JSON, by path, and with serde | [`paths`], [`Message::to_tree`], [`Message::with_tree`] |
//!
//! The four protocols:
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
//! # Build a message, and read it
//!
//! A REGISTRATION ACCEPT with a 5G-GUTI, a list of tracking areas and the
//! slices that the UE may use, and what its receiver reads of them:
//!
//! ```rust
//! use oxirush_nas::identity::{Guti5g, Plmn};
//! use oxirush_nas::nas_5gs::*;
//!
//! // A 5G-GUTI, two tracking areas of one PLMN and two S-NSSAIs
//! let plmn = Plmn::new("208", "93").unwrap();
//! let guti = Guti5g::new(plmn, 0xca, 0x3fe, 0, 0x1122_3344).unwrap();
//! let tacs = [1, 2];
//! let slices = [SNssai::from_sst_sd(1, None), SNssai::from_sst_sd(1, Some([1, 2, 3]))];
//!
//! // REGISTRATION ACCEPT with them
//! let result = RegistrationResult::from_result(RegistrationResultValue::ThreeGppAccess);
//! let accept = RegistrationAccept::new(result)
//!     .with_fg_guti(MobileIdentity::from_guti(guti))
//!     .with_tai_list(TrackingAreaIdentityList::from_plmn_tacs(&plmn, &tacs).unwrap())
//!     .with_allowed_nssai(Nssai::from_snssais(&slices).unwrap());
//! let accept = Message::new_5gmm(accept);
//! let octets = accept.encode().unwrap();
//! println!("{}", hex::encode(&octets));
//! println!("{accept}");
//!
//! // The other end reads them
//! let Message::Gmm(_, GmmMessage::RegistrationAccept(read)) =
//!     Message::decode(&octets).unwrap()
//! else {
//!     unreachable!()
//! };
//! assert_eq!(read.fg_guti.unwrap().as_guti(), Some(guti));
//! assert_eq!(read.tai_list.unwrap().entries()[0].tacs(), tacs);
//! let slices = read.allowed_nssai.unwrap().parse_allowed();
//! assert_eq!((slices[1].sst, slices[1].sd), (1, Some([1, 2, 3])));
//! ```
//!
//! ```text
//! 7e0042010177000bf202f839caff8011223344540a0102f839000001000002150701010401010203
//! 5GMM RegistrationAccept (result=ThreeGppAccess, GUTI=5g-guti-20893caff8011223344, TAI-list=[208-93-000001, 208-93-000002], Allowed-NSSAI=[1, 1/010203])
//! ```
//!
//! # Protect and unprotect
//!
//! With the `security` feature, a security context has the NAS keys, the
//! algorithms and the NAS COUNTs of one UE, and puts a message under its
//! security header: integrity protection with a message authentication
//! code (MAC), and ciphering.
//!
//! ```rust
//! # #[cfg(feature = "security")] {
//! use oxirush_nas::identity::Algorithm;
//! use oxirush_nas::nas_5gs::{KAmf, Message, NasConnection, SecurityHeaderType, SecurityContext};
//! use oxirush_nas::Direction;
//!
//! // The two ends of a link have the same KAMF, the key that the UE and
//! // the network share after authentication, and the same algorithms
//! let kamf = KAmf::new(&[0x11; 32]);
//! let (nia, nea) = (Algorithm::Aes, Algorithm::Aes);
//! let mut network = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
//! let mut ue = SecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
//!
//! // The network protects a 5GMM STATUS: MAC, then ciphering
//! let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//! let header_type = SecurityHeaderType::IntegrityProtectedAndCiphered;
//! let (downlink, access) = (Direction::Downlink, NasConnection::ThreeGpp);
//! let octets = network.protect(&status, header_type, downlink, access).unwrap();
//! assert_eq!(octets.len(), 7 + 4);
//!
//! // The UE checks the MAC, deciphers and decodes
//! let received = ue.unprotect(&octets, downlink, access).unwrap();
//! assert_eq!(received.message, status);
//! # }
//! ```
//!
//! # Read and write a message as JSON
//!
//! With the `tree` feature, a message is a tree of JSON by the names of
//! the specification, which is also how one is written:
//!
//! ```rust
//! # #[cfg(feature = "tree")] {
//! use oxirush_nas::nas_5gs::Message;
//! use oxirush_nas::tree;
//!
//! let reject = Message::decode(&hex::decode("7e0044165f012a").unwrap()).unwrap();
//! let tree = tree!({
//!     "message-type": "registration-reject",
//!     "5gmm-cause": "congestion",
//!     "t3346-value": 600,
//! });
//! assert_eq!(reject.to_tree(), tree);
//! assert_eq!(Message::from_tree(tree).unwrap(), reject);
//! # }
//! ```
//!
//! [A message as a tree](#a-message-as-a-tree) below says more.
//!
//! # Errors
//!
//! Decoding and encoding return a [`Error`], whose variants are
//! what a receiver answers differently (TS 24.501 and TS 24.301 chapter 7):
//! a message that is too short or of an unknown protocol is ignored, an
//! unknown message type is answered with a STATUS message, and a mandatory
//! IE that is missing or wrong with cause #96, with the field of the IE and
//! what is wrong with it in the error. An optional IE that is wrong does
//! not fail the message: it is kept with the unknown IEs, and `validate()`
//! reports it.
//!
//! # Architecture
//!
//! Each system is one module, [`nas_5gs`] and [`nas_eps`], with its messages,
//! its IEs and their typed values, and with the feature `security` its
//! security context. An IE struct has the value of its IE in a `pub value`
//! field and implements [`Encode`]/[`Decode`] for the value and its length
//! indicator (the formats V, LV and LV-E of TS 24.007 §11.2); the identifier
//! of an optional IE is that of its message, which writes it. A message
//! struct takes its mandatory IEs in its constructor, and has `set_*()` and
//! `with_*()` for each IE and `clear_*()` for an optional one.
//!
//! The crate root has what the two systems share: the traits, the errors,
//! [`Direction`], the validation types and the unknown IEs. [`identity`] has
//! the identities that the OxiRush crates share: the PLMN, the GUTIs, the
//! TAIs, the SUCI.
//!
//! # Receiving and sending
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
//! | Mandatory IE that is missing, cut short, shorter than its message allows or syntactically incorrect | [`Error::InvalidMandatoryIe`], with the field and the fault. |
//! | Unknown IE encoded as "comprehension required" | Kept when it is well framed, so that a tool can inspect the message: `unknown_ies()` returns it, [`UnknownIe::is_comprehension_required`] flags it, `validate()` reports it. The answer that §7.5.1 of TS 24.501 or TS 24.301 requires of a receiver is the caller's. One that is cut short is [`Error::UnknownIeCutShort`]. |
//! | EPS DETACH REQUEST | One message type for the two directions (TS 24.301 §8.2.11). [`nas_eps::Message::decode`] tells them apart by their contents, which do not decide every case; [`nas_eps::Message::decode_with`] takes the direction in its [`DecodeOptions`]. |
//! | Typed getters | The value a receiver must act on, with the receive fallbacks of the IE tables: `IdentityType::Imsi` for an undefined identity type of EPS, for example. `*_strict` and `*_raw` variants give the exact code. |
//! | `validate()` | The value and conditional rules of TS 24.501 and TS 24.301, repeated IEs and out-of-sequence IEs, as errors or warnings. `is_well_formed()` checks a single IE. |
//! | Encoding | Accepts every value a type can represent, so a test tool can emit invalid values. |
//! | Builders | A `from_*`, `with_*` or `set_*` that refuses what it is given returns a [`ValueError`]: the member, what it was given and the limit that this breaks. No public function panics on its arguments. |
//! | IMEI over NAS | `from_imei_tac_snr` of `nas_5gs::MobileIdentity` and `nas_eps::{EpsMobileIdentity, MobileIdentity}` takes the 14 TAC and serial-number digits and adds the transmitted zero spare digit. `from_imei` keeps all 15 supplied digits. |
//! | Message structs | Built with `new()` and `with_*()`. They keep the decoded order of the optional IEs, so struct literals are not supported. |
//!
//! # What the crate covers
//!
//! | Area | Contents |
//! |------|----------|
//! | 5GS messages | All 5GMM and 5GSM messages of TS 24.501, and the UE policy delivery service (Annex D) |
//! | EPS messages | All EMM and ESM messages of TS 24.301 clause 8, with the short SERVICE REQUEST header, EMM TRANSPORT and security-protected envelopes |
//! | IEs | 169 5GS and 153 EPS types, each the value of its IE, which a message has in the V, LV, LV-E, TV, TLV and TLV-E formats of TS 24.007 §11.2 |
//! | Typed accessors | Enums, value structs and `set_*`/`with_*` builders instead of bit manipulation. One implementation for the IEs that both specifications code alike: UE network capability, KSI, NAS security algorithms, GPRS timers, PCO/ePCO units, APN/DNN, PLMN lists, network name, time zone, eDRX and emergency numbers, for example |
//! | Errors | `Error` separates the classes of clause 7: too-short messages, unknown protocol discriminators and message types, reserved security header types, invalid mandatory IEs |
//! | Display | `fmt::Display` for every message and for the IEs that it shows, in these forms: a cause as `#22 (Congestion)`, a timer with its unit, an identity whole as the service based interfaces write it, a key never. `Debug` prints no key either: of RES, RES\*, the ciphering keys of positioning, an MSK and K_NR_ProSe, of the IEs that hold one and of an IE kept unread it shows the length, and of an EAP message its header |
//! | Round trip | Decoding then encoding keeps unknown IEs, ignored repetitions, the order of the optional IEs and the spare half octet of a header |
//! | `security` | Integrity and ciphering with NAS COUNT tracking and replay protection per TS 33.501 and TS 33.401, the EPS short MAC, partial ciphering of CONTROL PLANE SERVICE REQUEST containers and 5GS↔EPS mapped contexts |
//! | `tree` | Each message as a tree: every IE by its name, with its value in the usual notation, or its octets; `Serialize` and `Deserialize` through the tree |
//!
//! # What the crate does not cover
//!
//! | Subject | Limit |
//! |---------|-------|
//! | Procedures | It is a codec: no NAS procedure, timer or transport. Its only state is that of a security context. |
//! | Validity | `validate()` sees one message, not the state of a procedure. Encoding accepts every value a type can represent, so a message that encodes is not thereby valid. |
//! | Security state | A context does not persist itself: the caller keeps the next COUNT values and restores it from them. |
//! | JSON | 13 5GS and 19 EPS IE types have octets alone ([which][ie types with a value]). A tree computes no message authentication code. |
//! | Serde form | It is the tree: a message read from it means what the message means, with its octets where its values decide them (183 of the 202 fixtures), and the order of its optional IEs is that of the table. |
//! | Release 19 | Two items follow Release 20 and differ from V19.8.0 on the wire ([Specification versions](#specification-versions)). |
//! | Evidence | The tests of the crate itself ([Tests](#tests)), and 170 messages that two open-source cores and one UE simulator sent in a lab, with their source: no commercial UE, RAN or core, and no conformance test suite. The provenance of the 15 legacy 5GS wire values was not recorded. |
//!
//! # Specification versions
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
//! [`nas_5gs::GmmCapability::nssaa_epc`] and
//! [`nas_5gs::GmmCapability::aiot_ue_reader`] (§9.11.3.1).
//!
//! | Item | This crate, as V20.1.0 | V19.8.0 |
//! |------|------------------------|---------|
//! | `Non3GppDeviceConnectionInformation::Ethernet::vlan_tag_id`, §9.11.4.41 | The 12-bit VLAN ID: bit 8 of the first octet to bit 5 of the second, with bits 4 to 1 spare. 100 is sent as 0x0640. | A 16-bit VLAN tag ID in the two octets. A peer that follows it sends 100 as 0x0064, which this crate reads as VLAN 6. |
//! | 5GMM capability octet 13, bits 2 and 3, §9.11.3.1 | NSSAA-EPC (`nssaa_epc`) and AIoTUR (`aiot_ue_reader`). `validate()` accepts them. | Spare: its sender must leave them zero. |
//!
//! Clauses 8 and 9 and Annex D of TS 24.501 code nothing else differently in
//! V20.1.0, and clauses 8 and 9 of TS 24.301 are the same in both releases.
//!
//! # Tests
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
//! | `tests/fixtures`: 105 5GS and 97 EPS messages, at least one of each 5GMM, 5GSM, EMM and ESM message type of the codec | Each decodes, has no `validate()` error and encodes to its octets. Through its tree, which is its serde form, each is a message that means the same (`means_the_same()`), and 183 of the 202 have the same octets. |
//! | The Rust blocks of the README, of this page and of the pages of [`paths`], [`nas_eps`] and the two `security` modules | They compile and run as documentation tests, with the `tree` and `security` features, and the package of `readme/` compares what each prints with the output shown under it. |
//!
//! ```sh
//! cargo test --all-features            # everything
//! cargo test --all-features capture_   # the EPS corpus
//! ```
//!
//! Ten fuzz targets hold what the tests hold, five for each system:
//!
//! | Targets | What they hold |
//! |---------|----------------|
//! | `decode_5gs`, `decode_eps` | Of any octets: a message that decodes encodes to those octets, and decodes again to the same message. `decode_lenient` reads what `decode` reads, and a faulty mandatory IE as it came; the answer of `answer_to` encodes, decodes to itself and has no `validate()` error but for the identities that it copies. |
//! | `view_5gs`, `view_eps` | Of any octets: the tree of a message writes a message with the same tree that means the same, IE by IE and after it is decoded again, and the tree edits the message into itself. |
//! | `edit_5gs`, `edit_eps` | A message of the fixtures edited by the paths of its tree: an edit is refused or changes only what it edits, and a message that `validate()` finds nothing wrong with is the one that a receiver reads. |
//! | `build_5gs`, `build_eps` | A message written from a tree whose IEs the fuzzer chooses, with values of the fixtures or of its own, deep in each IE: the same. |
//! | `security_5gs`, `security_eps` | Two security contexts of one link, at any NAS COUNT and with any replay window, and messages protected, delivered, replayed, reordered, changed or cut short: each COUNT, code and refusal is the one that TS 24.501 and TS 24.301 §4.4.3 give, as a model of them written apart and oxirush-security compute it. |
//!
//! The continuous integration runs each for a minute at each commit, an hour
//! each night and four hours on Sunday, when it also minimizes each corpus
//! and keeps the coverage of the crate by it.
//!
//! ```sh
//! ./fuzz/seed.sh                 # a corpus from tests/fixtures and fuzz/seeds-*.tsv
//! cargo +nightly fuzz run decode_5gs -- -max_total_time=60 -max_len=512 -dict=fuzz/nas-5gs.dict
//! cargo +nightly fuzz run security_5gs -- -max_total_time=60 -len_control=0
//! ```
//!
//! # Examples
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
//! | `tree_message` | REGISTRATION REQUEST read and edited through its tree, by the paths of its IEs | ATTACH REQUEST read and edited through its tree, by the paths of its IEs | `tree` |
//!
//! # Feature flags
//!
//! `std` (the default), `security`, `tree` and `idna`: the
//! [README](https://github.com/linouxis9/oxirush-nas#installation) says what
//! each adds and brings.
//!
//! # A message as a tree
//!
//! With the `tree` feature, [`Message::to_tree`] and
//! [`nas_eps::Message::to_tree`] give a message as a reader names it: its
//! `message-type` and each IE that it has by the name the specification
//! gives it, in lower case with hyphens, with its value in the usual
//! notation (the name of a coded value, `"208-93"` for a PLMN identity,
//! digits for an IMSI, a number for a TMSI or a TAC, text for a DNN or an IP
//! address, the tree of the message in a container), or `{"octets": "…"}`
//! where it has no readable value: `{"message-type": "5gmm-status",
//! "5gmm-cause": "congestion"}`. `from_tree` writes the message of a tree,
//! and [`Message::with_tree`] edits a message: an IE that the tree leaves
//! as it was keeps its octets, one that it changes is encoded from its new
//! value or takes its octets, an optional IE is added or taken out, and
//! what the message cannot keep is an error. The [`paths`] module reads and
//! edits a tree by paths such as `/nas/5g-guti/guti/plmn`.
//!
//! # The OxiRush family
//!
//! - [oxirush-utils](https://docs.rs/oxirush-utils): the 3GPP identities, and the JSON tree with its paths that the others share.
//! - [oxirush-aper](https://docs.rs/oxirush-aper): aligned PER, the runtime of the NGAP and S1AP codecs.
//! - [oxirush-nas](https://docs.rs/oxirush-nas): the NAS messages of 5GS and EPS.
//! - [oxirush-security](https://docs.rs/oxirush-security): NAS security, AKA and the derivation of keys.
//! - [oxirush-ngap](https://docs.rs/oxirush-ngap): NGAP, between a gNB and an AMF.
//! - [oxirush-s1ap](https://docs.rs/oxirush-s1ap): S1AP, between an eNB and an MME.
//! - [oxirush-gtp-u](https://docs.rs/oxirush-gtp-u): GTP-U tunnels, with a test UPF.
//! - [oxirush-sctp](https://docs.rs/oxirush-sctp): SCTP sockets, which carry NGAP and S1AP.
//!
//! [`nas_5gs::SecurityContext`]: crate::nas_5gs::SecurityContext
//! [`nas_eps::SecurityContext`]: crate::nas_eps::SecurityContext
//! [`paths`]: crate::paths
//! [`Message::to_tree`]: crate::nas_5gs::Message::to_tree
//! [`Message::with_tree`]: crate::nas_5gs::Message::with_tree
//! [`nas_eps::Message::to_tree`]: crate::nas_eps::Message::to_tree
//! [ie types with a value]: crate::paths#ie-types-that-have-a-value
// What the features `security` and `tree` have is a link where the build
// has them: the links are checked in the build of every feature, which
// docs.rs makes.
#![cfg_attr(
    not(all(feature = "security", feature = "tree")),
    allow(rustdoc::broken_intra_doc_links)
)]

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

mod common;
pub mod nas_5gs;
pub mod nas_eps;
#[cfg(feature = "tree")]
pub mod paths;
#[cfg(all(test, feature = "tree"))]
mod view_tests;
#[cfg(all(test, feature = "tree"))]
mod wireshark_tests;

/// The examples of the README, which the documentation tests compile and run.
#[cfg(all(doctest, feature = "tree", feature = "security"))]
#[doc = include_str!("../README.md")]
struct Readme;

// What the two systems share. What belongs to one of them is in its module:
// `nas_5gs::SecurityContext` and `nas_eps::SecurityContext`.
#[cfg(feature = "security")]
pub use common::MAX_REPLAY_WINDOW;
pub use common::{
    Decode, DecodeOptions, Direction, Encode, Error, IeFault, IeName, MAX_IE_VALUE_LENGTH, Octets,
    Result, Severity, UnknownIe, UnknownIes, UnknownIesIter, Validate, ValidationError, ValueError,
    ValueFault,
};
/// The COUNT of a NAS security context and the errors of NAS security, of the
/// `oxirush-security` that this crate is built with.
#[cfg(feature = "security")]
pub use oxirush_security::{NasCount, SecurityError};
/// The identities of the OxiRush crates: those of both systems, which
/// [`nas_5gs`] and [`nas_eps`] name as their system does.
pub use oxirush_utils::identity;
/// The trees of the OxiRush crates, of the `oxirush-utils` that this crate is
/// built with: the tree of a message, [`tree::Value`], JSON
/// whose objects keep their members in the order of the message, and
/// `tree!`, which writes one in the code as `serde_json::json!` does.
#[cfg(feature = "tree")]
pub use oxirush_utils::tree;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nas_5gs::*;

    // Test container recursive decode
    #[test]
    fn test_container_decode() {
        // SecurityModeComplete with NAS message container containing a RegistrationRequest
        let payload = hex::decode(
            "7e005e7700091511000000000000007100207e004109000d0199f9070000000000000010021001072e08a020000000000000",
        )
        .unwrap();
        let msg = Message::decode(&payload).unwrap();
        if let Message::Gmm(_, GmmMessage::SecurityModeComplete(smc)) = &msg {
            if let Some(ref container) = smc.nas_message_container {
                let inner = container.decode_as_nas_message().unwrap();
                // The container holds a RegistrationRequest
                if let Message::Gmm(hdr, _) = &inner {
                    assert_eq!(hdr.message_type, GmmMessageType::RegistrationRequest);
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
        assert!(Message::decode(&[]).is_err());
    }

    #[test]
    fn test_single_byte() {
        assert!(Message::decode(&[0x7e]).is_err());
    }

    #[test]
    fn test_two_bytes_5gmm() {
        // EPD + SHT but no message type
        assert!(Message::decode(&[0x7e, 0x00]).is_err());
    }

    #[test]
    fn test_unknown_epd() {
        assert!(Message::decode(&[0xFF, 0x00, 0x41]).is_err());
    }

    #[test]
    fn test_truncated_security_header() {
        // Security-protected (SHT=0x01) but not enough bytes for MAC+SN
        assert!(Message::decode(&[0x7e, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_truncated_unknown_tlv_ie() {
        // RegistrationRequest with unknown TLV IE that claims more data than available.
        // IEI 0x36 is currently unallocated in RegistrationRequest.
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x36, 0xFF]); // Unknown IEI 0x36, length=255 but no data
        // Unknown non-comprehension-required IEs are ignored under §7.6.1;
        // with no recoverable boundary, their remaining octets are retained.
        let message = Message::decode(&payload).unwrap();
        assert_eq!(message.encode().unwrap(), payload);
    }

    #[test]
    fn test_reserved_5gmm_security_header_type_is_rejected() {
        // EPD=5GMM, spare half octet = 0, reserved SHT = 0x05.
        assert!(Message::decode(&[0x7e, 0x05, 0x41]).is_err());
    }

    #[test]
    fn test_nested_security_protected_message_is_rejected() {
        let inner_plain = Message::new_5gmm(messages::RegistrationComplete::new());
        let nested =
            Message::protect(inner_plain, SecurityHeaderType::IntegrityProtected, 0, 0).unwrap();

        assert!(Message::protect(nested, SecurityHeaderType::IntegrityProtected, 0, 1).is_err());
    }

    #[test]
    fn test_unknown_iei_tv1_skip() {
        // RegistrationRequest with unknown TV-1 IEI (0xE0, bit 8=1)
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.push(0xE7); // Unknown TV-1 IEI — preserved (1 byte)
        let msg = Message::decode(&payload).unwrap();
        // Should still parse as RegistrationRequest
        if let Message::Gmm(_, GmmMessage::RegistrationRequest(ref reg)) = msg {
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
        let msg = Message::decode(&payload).unwrap();
        if let Message::Gmm(_, GmmMessage::RegistrationRequest(ref reg)) = msg {
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
        let msg = Message::decode(&payload).unwrap();
        if let Message::Gmm(_, GmmMessage::RegistrationRequest(ref reg)) = msg {
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
        let mut encoded = Message::new_5gmm(
            messages::RegistrationReject::new(GmmCause::from_cause(GmmCauseValue::IllegalUe))
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        TrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        TrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
        ).encode()
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = Message::decode(&encoded).unwrap();
        match decoded {
            Message::Gmm(_, GmmMessage::RegistrationReject(message)) => {
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
        let mut encoded = Message::new_5gmm(
            messages::DeregistrationRequestUeTerminated::new(DeRegistrationType::new(0x09))
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        TrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        TrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
        ).encode()
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = Message::decode(&encoded).unwrap();
        match decoded {
            Message::Gmm(_, GmmMessage::DeregistrationRequestUeTerminated(message)) => {
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
        let mut encoded = Message::new_5gmm(
            messages::ServiceReject::new(GmmCause::from_cause(GmmCauseValue::IllegalUe))
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        TrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        TrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
        ).encode()
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = Message::decode(&encoded).unwrap();
        match decoded {
            Message::Gmm(_, GmmMessage::ServiceReject(message)) => {
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
        assert!(Message::decode(&[0x2e, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_encode_decode_identity_request() {
        // Build an IdentityRequest for SUCI
        let msg = Message::new_5gmm(messages::IdentityRequest::new(
            IdentityType::from_identity_type(MobileIdentityType5gs::Suci).unwrap(),
        ));
        let encoded = msg.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_registration_reject() {
        let msg = Message::new_5gmm(messages::RegistrationReject::new(GmmCause::from_cause(
            GmmCauseValue::IllegalUe,
        )));
        let encoded = msg.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_auth_failure() {
        let msg = Message::new_5gmm(
            messages::AuthenticationFailure::new(GmmCause::from_cause(GmmCauseValue::SynchFailure))
                .with_authentication_failure_parameter(AuthenticationFailureParameter::new(
                    vec![0x01; 14],
                )),
        );
        let encoded = msg.encode().unwrap();
        let decoded = Message::decode(&encoded).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_deregistration() {
        let msg = Message::new_5gmm(messages::DeregistrationRequestUeOriginating::new(
            DeRegistrationType::new(0x09), // switch_off=1, 3GPP access
            KeySetIdentifier::new(0),
            MobileIdentity::from_guti(
                Guti5g::new(
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
        let decoded = Message::decode(&encoded).unwrap();
        let re_encoded = decoded.encode().unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_message_protect_rejects_plain_5gsm_inner_message() {
        let inner = Message::new_5gsm(
            messages::PduSessionEstablishmentRequest::new(
                IntegrityProtectionMaximumDataRate::from_rates(
                    MaxDataRate::FullRate,
                    MaxDataRate::FullRate,
                ),
            ),
            1,
            1,
        );

        assert!(Message::protect(inner, SecurityHeaderType::IntegrityProtected, 0, 0).is_err());
    }

    #[test]
    fn test_security_protected_plain_5gsm_is_reported_by_validation() {
        let inner = Message::new_5gsm(
            messages::PduSessionEstablishmentRequest::new(
                IntegrityProtectionMaximumDataRate::from_rates(
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

        let message = Message::decode(&protected).unwrap();
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
        let inner = Message::new_5gmm(messages::RegistrationComplete::new());

        assert!(
            Message::protect(
                inner,
                SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext,
                0,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn test_message_protect_rejects_invalid_ciphered_new_context_sht_for_non_security_mode_complete()
     {
        let inner = Message::new_5gmm(messages::RegistrationComplete::new());

        assert!(
            Message::protect(
                inner,
                SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
                0,
                0,
            )
            .is_err()
        );
    }
}
