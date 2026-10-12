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

#![deny(unsafe_code)]
#![deny(missing_docs)]

//! # oxirush-nas
//!
//! A codec for the NAS (non-access stratum) messages of 5GS and EPS (4G):
//! the signalling that a UE and its core network exchange through the radio
//! access network, per 3GPP TS 24.501 and TS 24.301. It decodes, builds,
//! validates and encodes the messages of four protocols, without `unsafe`
//! code:
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
//! It is one of the OxiRush crates, with
//! [oxirush-security](https://github.com/linouxis9/oxirush-security) (keys
//! and algorithms of NAS security),
//! [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap) and
//! [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap) (the protocols
//! that carry NAS messages between a base station and the core),
//! [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u) (the user
//! plane) and [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp)
//! (their transport).
//!
//! ## Decode a message and read its IEs
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
//! [`nas_eps::NasEpsMessage`] has the same interface for EPS:
//! `NasEpsMessage::decode(&octets)`, `message.encode()`. The octets of a
//! 5GS message start with `7e` (5GMM) or `2e` (5GSM), and the first octet
//! of an EPS message ends with `7` (EMM) or `2` (ESM): an error of the
//! decoder of the other system says so.
//!
//! ## Build and encode a message
//!
//! ```rust
//! use oxirush_nas::nas_5gs::*;
//!
//! // REGISTRATION REJECT with cause #22 and a T3346 value of ten minutes:
//! // `new()` takes the mandatory IEs, `set_*()` adds the optional ones
//! let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
//! let t3346 = NasGprsTimer2::from_seconds(600).unwrap();
//! let reject = NasRegistrationReject::new(cause).set_t3346_value(t3346);
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
//! use oxirush_nas::nas_5gs::ie::{CipheringAlgorithm, IntegrityAlgorithm};
//! use oxirush_nas::nas_5gs::{
//!     Direction, Nas5gsMessage, Nas5gsSecurityHeaderType, NasSecurityContext,
//! };
//!
//! // The two ends of a link have the same KAMF, the key that the UE and
//! // the network share after authentication, and the same algorithms
//! let kamf = [0x11; 32];
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
//! let (received, _) = ue.unprotect(&octets, Direction::Downlink).unwrap();
//! assert_eq!(received, status);
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
//! use serde_json::json;
//!
//! let reject = Nas5gsMessage::decode(&hex::decode("7e0044165f012a").unwrap()).unwrap();
//! let tree = json!({
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
//! | 2 | `messages` | NAS message structs, defined by the shared `nas_message!` macro: mandatory IEs in the constructor, optional IEs through `set_*()` builder methods, IEI dispatch and codec functions |
//! | 3 | `ie` | Typed accessors — enums such as `RegistrationType` and `PdnType`, parsers and builder helpers in place of bit manipulation |
//!
//! Additional modules in each protocol: `message_types`, `display`, `validate`,
//! and `security`, which uses the matching `oxirush_security::nas_5gs` and
//! `oxirush_security::nas_eps` APIs behind the `security` feature. `upds`,
//! the UE policy delivery service, is specific to 5GS. The [`common`] module
//! has what the two protocols share: the [`common::Encode`] and
//! [`common::Decode`] traits, [`common::NasError`], the validation types,
//! [`common::PlmnId`] and [`common::UnknownIe`]. The crate root re-exports the established
//! 5GS API; [`nas_5gs`] and [`nas_eps`] are the paths for code that handles
//! both protocols. Message structs keep the decoded order of the optional
//! IEs, so they are built with `new()` and `set_*()` and not with struct
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
//! | Typed getters | The value a receiver must act on, with the receive fallbacks of the IE tables: `IdentityTypeValue::Imsi` for an undefined identity type, for example. `*_strict` and `*_raw` variants give the exact code. |
//! | `validate()` | The value and conditional rules of TS 24.501 and TS 24.301, repeated IEs and out-of-sequence IEs, as errors or warnings. `is_well_formed()` checks a single IE. |
//! | Encoding | Accepts every value a type can represent, so a test tool can emit invalid values. |
//! | Builders | `from_*` return `None`, or an error, for input that the IE cannot carry: no public function panics on its arguments. |
//! | IMEI over NAS | `from_imei_tac_snr` of `nas_5gs::NasFGsMobileIdentity` and `nas_eps::{NasEpsMobileIdentity, NasMobileIdentity}` takes the 14 TAC and serial-number digits and adds the transmitted zero spare digit. `from_imei` keeps all 15 supplied digits. |
//! | Message structs | Built with `new()` and `set_*()`. They keep the decoded order of the optional IEs, so struct literals are not supported. |
//!
//! ## Specification versions
//!
//! The codec follows TS 24.501 V19.8.0 and TS 24.301 V19.8.0 (Release 19).
//! Two items follow TS 24.501 V20.1.0 (Release 20) instead, which codes them
//! differently: the 12-bit VLAN ID of
//! [`Non3GppDeviceConnectionInformation::Ethernet`] (§9.11.4.41), and bits 2
//! and 3 of 5GMM capability octet 13, [`NasFGmmCapability::nssaa_epc`] and
//! [`NasFGmmCapability::aiot_ue_reader`] (§9.11.3.1).
//!
//! ## Feature flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `security` | NAS security envelope (protect/unprotect) via `oxirush-security` |
//! | `serde` | JSON serialization of messages and typed IE values, and the view of a message |
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

pub mod common;
pub mod nas_5gs;
pub mod nas_eps;
#[cfg(feature = "serde")]
pub mod view;

/// The examples of the README, which the documentation tests compile and run.
#[cfg(all(doctest, feature = "serde", feature = "security"))]
#[doc = include_str!("../README.md")]
struct Readme;

// Keep the established crate-root 5GS API for existing users.
pub use nas_5gs::*;

/// Version of oxirush-nas
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;

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
                let inner = container.decode_plain_inner().unwrap();
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
            assert_eq!(reg.unknown_ies[0].iei, 0xE7);
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
            assert_eq!(reg.unknown_ies[0].iei, 0x7D);
            assert_eq!(reg.unknown_ies[0].data, vec![0x00, 0x02, 0xAA, 0xBB]);
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
            assert_eq!(reg.unknown_ies[0].iei, 0x36);
            assert_eq!(reg.unknown_ies[0].data, vec![0x03, 0x01, 0x02, 0x03]);
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
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
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
                        .forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming
                        .is_some()
                );
                assert!(message
                    .forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service
                    .is_some());
            }
            _ => panic!("expected RegistrationReject"),
        }
    }

    #[test]
    fn test_deregistration_request_to_ue_accepts_legacy_forbidden_tai_ieis() {
        let mut encoded = Nas5gsMessage::new_5gmm(
            messages::NasDeregistrationRequestToUe::new(NasDeRegistrationType::new(0x09))
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
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
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::DeregistrationRequestToUe(message)) => {
                assert!(
                    message
                        .forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming
                        .is_some()
                );
                assert!(message
                    .forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service
                    .is_some());
            }
            _ => panic!("expected DeregistrationRequestToUe"),
        }
    }

    #[test]
    fn test_service_reject_accepts_legacy_forbidden_tai_ieis() {
        let mut encoded = Nas5gsMessage::new_5gmm(
            messages::NasServiceReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe))
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
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
                        .forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming
                        .is_some()
                );
                assert!(message
                    .forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service
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
            NasFGsIdentityType::from_identity_type(MobileIdentityType::Suci),
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
            .set_authentication_failure_parameter(
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
        let msg = Nas5gsMessage::new_5gmm(messages::NasDeregistrationRequestFromUe::new(
            NasDeRegistrationType::new(0x09), // switch_off=1, 3GPP access
            NasFGsMobileIdentity::from_guti(&Guti {
                plmn: PlmnId::from_digits([2, 0, 8], [9, 3, 0x0F]).unwrap(),
                amf_region_id: 0x02,
                amf_set_id: 0x40,
                amf_pointer: 0x00,
                tmsi: 0xDEADBEEF,
            })
            .unwrap(),
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
                .any(|finding| finding.field == "Plain NAS message")
        );
        assert_eq!(message.encode().unwrap(), protected);
    }

    #[test]
    fn test_message_protect_rejects_invalid_new_context_sht_for_non_security_mode_command() {
        let inner = Nas5gsMessage::new_5gmm(messages::NasRegistrationComplete::new());

        assert!(
            Nas5gsMessage::protect(
                inner,
                Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext,
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
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext,
                0,
                0,
            )
            .is_err()
        );
    }
}
