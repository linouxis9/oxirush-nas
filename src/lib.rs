/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

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
//! A fast, memory-safe library for encoding and decoding **5G and EPS NAS**
//! (Non-Access Stratum) messages, per 3GPP TS 24.501 and TS 24.301.
//!
//! ## Quick start
//!
//! ```rust
//! use oxirush_nas::nas_5gs::{decode_nas_5gs_message, encode_nas_5gs_message, Validate};
//!
//! let bytes = hex::decode(
//!     "7e004179000d0199f9070000000000000010022e08a020000000000000"
//! ).unwrap();
//!
//! // Decode
//! let msg = decode_nas_5gs_message(&bytes).unwrap();
//!
//! // Human-readable display
//! println!("{msg}");
//!
//! // Validate common TS 24.501 structural rules
//! assert!(msg.validate().is_empty());
//!
//! // Round-trip encode
//! assert_eq!(bytes, encode_nas_5gs_message(&msg).unwrap());
//! ```
//!
//! The EPS codec has the same interface:
//!
//! ```rust
//! use oxirush_nas::nas_eps::{
//!     decode_nas_eps_message, encode_nas_eps_message, NasEmmMessage, NasEpsMessage, Validate,
//! };
//!
//! // ATTACH REQUEST with an IMSI and a PDN CONNECTIVITY REQUEST
//! let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
//! let msg = decode_nas_eps_message(&bytes).unwrap();
//! println!("{msg}");
//! assert!(msg.validate().is_empty());
//!
//! if let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &msg {
//!     assert_eq!(request.eps_mobile_identity.as_imsi().as_deref(), Some("208930000000001"));
//!     assert!(request.ue_network_capability.supports_eea(2));
//!     let esm = request.esm_message_container.decode_as_esm_message().unwrap();
//!     println!("{esm}");
//! }
//! assert_eq!(bytes, encode_nas_eps_message(&msg).unwrap());
//! ```
//!
//! ## Architecture
//!
//! Both [`nas_5gs`] and [`nas_eps`] are organized in three layers:
//!
//! | Layer | Module | Description |
//! |-------|--------|-------------|
//! | 1 | `types` | Raw wire-format IE structs with [`common::Encode`]/[`common::Decode`] traits |
//! | 2 | `messages` | NAS message structs with IEI dispatch and codec functions |
//! | 3 | `ie` | Typed accessors — enums, parsers, builder helpers |
//!
//! Additional modules in each protocol: `message_types`, `display`, `validate`,
//! and `security`. The [`common`] module contains shared codecs, macros,
//! validation types, and the IE grammars that TS 24.501 and TS 24.301 share.
//! The crate root re-exports the established 5GS API.
//!
//! Decoding follows the receiver rules of TS 24.007 §11 (spare bits and
//! extra octets ignored, unknown IEs skipped, repeated IEs ignored), and
//! typed getters apply the receive fallbacks of the IE tables. `validate()`
//! reports sender rules.
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

pub mod common;
pub mod nas_5gs;
pub mod nas_eps;
#[cfg(feature = "serde")]
pub mod view;

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

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_auth_request() {
        let payload = hex::decode(
            "7e00560002000021ab6f2a1cc5c5938d38cba14dfe26b0012010a820e67b8896800076a638e98eed4747",
        )
        .unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_security_mode_command() {
        let payload = hex::decode("7e005d020002a020e1360102").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_registration_request_2() {
        let payload = BASE64_STANDARD
            .decode("fgBedwAJFREAAAAAAAAAcQAgfgBBCQANAZn5BwAAAAAAAAAQAhABBy4IoCAAAAAAAAA=")
            .unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_registration_accept() {
        let payload = BASE64_STANDARD
            .decode("fgBCAQF3AAvymfkHAgBAwAAC31QHQJn5BwAAARUCAQEhAgEAXgGp")
            .unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_registration_complete() {
        let payload = BASE64_STANDARD.decode("fgBD").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_pdu_session_establishment_request() {
        let payload = BASE64_STANDARD
            .decode("fgBnAQAULgEBwf//kXsACoAACgAADQAAAwASAYEiAQElCQhpbnRlcm5ldA==")
            .unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_configuration_update_command() {
        let payload = BASE64_STANDARD
            .decode("fgBUQw+QAE8AcABlAG4ANQBHAFNGAEdCMGICZHEASQEA")
            .unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_configuration_update_complete() {
        let payload = BASE64_STANDARD.decode("fgBV").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_pdu_session_establishment_accept() {
        let payload = BASE64_STANDARD.decode("fgBoAQBtLgEBwhEACQEABjExAQH/AQYD9CQD9CQpBQEKLQC9IgEBeQAGASBBAQEJewA1gAANBAgICAgADQQICAQEAAMQIAFIYEhgAAAAAAAAAACIiAADECABSGBIYAAAAAAAAAAAiEQlCQhpbnRlcm5ldBIB").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_service_request() {
        let payload = BASE64_STANDARD
            .decode("fgBMEAAHBABAwAAC33EAFX4ATBAABwQAQMAAAt9AAgIAUAICAA==")
            .unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_service_accept() {
        let payload = BASE64_STANDARD.decode("fgBOUAICACYCAAA=").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_pdu_session_release_request() {
        let payload = BASE64_STANDARD.decode("fgBnAQAELgEB0RIB").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_pdu_session_release_command() {
        let payload = BASE64_STANDARD.decode("fgBoAQAFLgEB0yQSAQ==").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_deregistration_request() {
        let payload = BASE64_STANDARD.decode("fgBFCQAL8pn5BwIAQMAAAt8=").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    // Test Display formatting
    #[test]
    fn test_display_registration_request() {
        let payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        let msg = decode_nas_5gs_message(&payload).unwrap();
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
        let msg = decode_nas_5gs_message(&payload).unwrap();
        let display = format!("{msg}");
        assert!(display.contains("AuthenticationRequest"));
        assert!(display.contains("RAND="));
    }

    #[test]
    fn test_display_security_mode_command() {
        let payload = hex::decode("7e005d020002a020e1360102").unwrap();
        let msg = decode_nas_5gs_message(&payload).unwrap();
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
        let msg = decode_nas_5gs_message(&payload).unwrap();
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
        let msg = decode_nas_5gs_message(&payload).unwrap();
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
        assert!(decode_nas_5gs_message(&[]).is_err());
    }

    #[test]
    fn test_single_byte() {
        assert!(decode_nas_5gs_message(&[0x7e]).is_err());
    }

    #[test]
    fn test_two_bytes_5gmm() {
        // EPD + SHT but no message type
        assert!(decode_nas_5gs_message(&[0x7e, 0x00]).is_err());
    }

    #[test]
    fn test_unknown_epd() {
        assert!(decode_nas_5gs_message(&[0xFF, 0x00, 0x41]).is_err());
    }

    #[test]
    fn test_truncated_security_header() {
        // Security-protected (SHT=0x01) but not enough bytes for MAC+SN
        assert!(decode_nas_5gs_message(&[0x7e, 0x01, 0x00]).is_err());
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
        let message = decode_nas_5gs_message(&payload).unwrap();
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), payload);
    }

    #[test]
    fn test_reserved_5gmm_security_header_type_is_rejected() {
        // EPD=5GMM, spare half octet = 0, reserved SHT = 0x05.
        assert!(decode_nas_5gs_message(&[0x7e, 0x05, 0x41]).is_err());
    }

    #[test]
    fn test_nested_security_protected_message_is_rejected() {
        let inner_plain = Nas5gsMessage::from_5gmm(Nas5gmmMessage::RegistrationComplete(
            messages::NasRegistrationComplete::new(),
        ));
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
        let msg = decode_nas_5gs_message(&payload).unwrap();
        // Should still parse as RegistrationRequest
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(ref reg)) = msg {
            assert_eq!(reg.unknown_ies.len(), 1);
            assert_eq!(reg.unknown_ies[0].iei, 0xE7);
        } else {
            panic!("Expected RegistrationRequest");
        }
        // Round-trip preserves unknown IEs
        let re_encoded = encode_nas_5gs_message(&msg).unwrap();
        assert_eq!(payload, re_encoded);
    }

    #[test]
    fn test_unknown_iei_tlve_skip() {
        // RegistrationRequest with unknown TLV-E IEI (0x7D, bits 7-5 = "111")
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x7D, 0x00, 0x02, 0xAA, 0xBB]); // TLV-E: IEI + len(2) + 2 bytes
        let msg = decode_nas_5gs_message(&payload).unwrap();
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(ref reg)) = msg {
            assert_eq!(reg.unknown_ies.len(), 1);
            assert_eq!(reg.unknown_ies[0].iei, 0x7D);
            assert_eq!(reg.unknown_ies[0].data, vec![0x00, 0x02, 0xAA, 0xBB]);
        } else {
            panic!("Expected RegistrationRequest");
        }
        // Round-trip preserves unknown IEs
        let re_encoded = encode_nas_5gs_message(&msg).unwrap();
        assert_eq!(payload, re_encoded);
    }

    #[test]
    fn test_unknown_iei_tlv_skip() {
        // RegistrationRequest with unknown TLV IEI (0x36, bits 7-5 != "111")
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x36, 0x03, 0x01, 0x02, 0x03]); // TLV: IEI + len(3) + 3 bytes
        let msg = decode_nas_5gs_message(&payload).unwrap();
        if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(ref reg)) = msg {
            assert_eq!(reg.unknown_ies.len(), 1);
            assert_eq!(reg.unknown_ies[0].iei, 0x36);
            assert_eq!(reg.unknown_ies[0].data, vec![0x03, 0x01, 0x02, 0x03]);
        } else {
            panic!("Expected RegistrationRequest");
        }
        // Round-trip preserves unknown IEs
        let re_encoded = encode_nas_5gs_message(&msg).unwrap();
        assert_eq!(payload, re_encoded);
    }

    #[test]
    fn test_registration_reject_accepts_legacy_forbidden_tai_ieis() {
        let mut encoded = encode_nas_5gs_message(&Nas5gsMessage::from_5gmm(
            Nas5gmmMessage::RegistrationReject(
                messages::NasRegistrationReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe))
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
            ),
        ))
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = decode_nas_5gs_message(&encoded).unwrap();
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
        let mut encoded = encode_nas_5gs_message(&Nas5gsMessage::from_5gmm(
            Nas5gmmMessage::DeregistrationRequestToUe(
                messages::NasDeregistrationRequestToUe::new(NasDeRegistrationType::new(0x09))
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
            ),
        ))
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = decode_nas_5gs_message(&encoded).unwrap();
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
        let mut encoded = encode_nas_5gs_message(&Nas5gsMessage::from_5gmm(
            Nas5gmmMessage::ServiceReject(
                messages::NasServiceReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe))
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 1]),
                    )
                    .with_forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service(
                        NasFGsTrackingAreaIdentityList::new(vec![0x00, 0x02, 0xf8, 0x39, 0, 0, 2]),
                    ),
            ),
        ))
        .unwrap();
        let first_iei = encoded.iter().position(|&b| b == 0x1D).unwrap();
        let second_iei = encoded.iter().position(|&b| b == 0x1E).unwrap();
        encoded[first_iei] = 0x3B;
        encoded[second_iei] = 0x3C;

        let decoded = decode_nas_5gs_message(&encoded).unwrap();
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
        assert!(decode_nas_5gs_message(&[0x2e, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_encode_decode_identity_request() {
        // Build an IdentityRequest for SUCI
        let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::IdentityRequest(
            messages::NasIdentityRequest::new(NasFGsIdentityType::from_identity_type(
                MobileIdentityType::Suci,
            )),
        ));
        let encoded = encode_nas_5gs_message(&msg).unwrap();
        let decoded = decode_nas_5gs_message(&encoded).unwrap();
        let re_encoded = encode_nas_5gs_message(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_registration_reject() {
        let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::RegistrationReject(
            messages::NasRegistrationReject::new(NasFGmmCause::from_cause(GmmCause::IllegalUe)),
        ));
        let encoded = encode_nas_5gs_message(&msg).unwrap();
        let decoded = decode_nas_5gs_message(&encoded).unwrap();
        let re_encoded = encode_nas_5gs_message(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_auth_failure() {
        let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::AuthenticationFailure(
            messages::NasAuthenticationFailure::new(NasFGmmCause::from_cause(
                GmmCause::SynchFailure,
            ))
            .set_authentication_failure_parameter(
                NasAuthenticationFailureParameter::new(vec![0x01; 14]),
            ),
        ));
        let encoded = encode_nas_5gs_message(&msg).unwrap();
        let decoded = decode_nas_5gs_message(&encoded).unwrap();
        let re_encoded = encode_nas_5gs_message(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_deregistration() {
        let msg = Nas5gsMessage::new_5gmm(Nas5gmmMessage::DeregistrationRequestFromUe(
            messages::NasDeregistrationRequestFromUe::new(
                NasDeRegistrationType::new(0x09), // switch_off=1, 3GPP access
                NasFGsMobileIdentity::from_guti(&Guti {
                    plmn: PlmnId {
                        mcc: [2, 0, 8],
                        mnc: [9, 3, 0x0F],
                    },
                    amf_region_id: 0x02,
                    amf_set_id: 0x40,
                    amf_pointer: 0x00,
                    tmsi: 0xDEADBEEF,
                }),
            ),
        ));
        let encoded = encode_nas_5gs_message(&msg).unwrap();
        let decoded = decode_nas_5gs_message(&encoded).unwrap();
        let re_encoded = encode_nas_5gs_message(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_message_protect_rejects_plain_5gsm_inner_message() {
        let inner = Nas5gsMessage::from_5gsm(
            Nas5gsmMessage::PduSessionEstablishmentRequest(
                messages::NasPduSessionEstablishmentRequest::new(
                    NasIntegrityProtectionMaximumDataRate::from_rates(
                        MaxDataRate::FullRate,
                        MaxDataRate::FullRate,
                    ),
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
        let inner = encode_nas_5gs_message(&Nas5gsMessage::from_5gsm(
            Nas5gsmMessage::PduSessionEstablishmentRequest(
                messages::NasPduSessionEstablishmentRequest::new(
                    NasIntegrityProtectionMaximumDataRate::from_rates(
                        MaxDataRate::FullRate,
                        MaxDataRate::FullRate,
                    ),
                ),
            ),
            1,
            1,
        ))
        .unwrap();

        let mut protected = vec![0x7E, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        protected.extend_from_slice(&inner);

        let message = decode_nas_5gs_message(&protected).unwrap();
        assert!(
            message
                .validate()
                .iter()
                .any(|finding| finding.field == "Plain NAS message")
        );
        assert_eq!(encode_nas_5gs_message(&message).unwrap(), protected);
    }

    #[test]
    fn test_message_protect_rejects_invalid_new_context_sht_for_non_security_mode_command() {
        let inner = Nas5gsMessage::from_5gmm(Nas5gmmMessage::RegistrationComplete(
            messages::NasRegistrationComplete::new(),
        ));

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
        let inner = Nas5gsMessage::from_5gmm(Nas5gmmMessage::RegistrationComplete(
            messages::NasRegistrationComplete::new(),
        ));

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
