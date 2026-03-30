/*
   OxiRush
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
*/

#![deny(unsafe_code)]
// NOTE: missing_docs is enforced in CI for new code via clippy.
// Enabling it crate-wide triggers ~400 warnings from macro-generated items.

//! # oxirush-nas
//!
//! A fast, memory-safe library for encoding and decoding **5G NAS** (Non-Access Stratum)
//! messages, per 3GPP TS 24.501.
//!
//! ## Quick start
//!
//! ```rust
//! use oxirush_nas::{decode_nas_5gs_message, encode_nas_5gs_message, Validate};
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
//! // Validate per TS 24.501
//! assert!(msg.validate().is_empty());
//!
//! // Round-trip encode
//! assert_eq!(bytes, encode_nas_5gs_message(&msg).unwrap());
//! ```
//!
//! ## Architecture
//!
//! The crate is organized in three layers:
//!
//! | Layer | Module | Description |
//! |-------|--------|-------------|
//! | 1 | [`types`] | Raw wire-format IE structs with [`Encode`]/[`Decode`] traits |
//! | 2 | [`messages`] | NAS message structs with IEI dispatch and codec functions |
//! | 3 | [`ie`] | Typed zero-cost accessors — enums, parsers, builder helpers |
//!
//! Additional modules: [`display`] (Wireshark-style formatting), [`validate`]
//! (structural validation), and `security` (NAS security envelope, feature-gated).
//!
//! ## Feature flags
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `security` | NAS security envelope (protect/unprotect) via `oxirush-security` |
//! | `serde` | JSON serialization for typed IE structs |

pub mod display;
pub mod ie;
pub mod message_types;
pub mod messages;
pub mod types;
pub mod validate;

#[cfg(feature = "security")]
pub mod security;

// Re-export key types and functions for easier use
pub use ie::*;
pub use message_types::{Nas5gmmMessageType, Nas5gsSecurityHeaderType, Nas5gsmMessageType};
pub use messages::{
    Nas5gmmMessage, Nas5gsMessage, Nas5gsmMessage, decode_nas_5gs_message, encode_nas_5gs_message,
};
pub use types::{Decode, Encode, NasError, Result, *};
pub use validate::Validate;

#[cfg(feature = "security")]
pub use security::NasSecurityContext;

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
        let display = format!("{}", msg);
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
        let display = format!("{}", msg);
        assert!(display.contains("AuthenticationRequest"));
        assert!(display.contains("RAND="));
    }

    #[test]
    fn test_display_security_mode_command() {
        let payload = hex::decode("7e005d020002a020e1360102").unwrap();
        let msg = decode_nas_5gs_message(&payload).unwrap();
        let display = format!("{}", msg);
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
        assert!(errs.is_empty(), "Unexpected errors: {:?}", errs);
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
                let inner = container.decode_inner().unwrap();
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
        // RegistrationRequest with unknown TLV IE that claims more data than available
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x3F, 0xFF]); // Unknown IEI 0x3F, length=255 but no data
        // Should decode successfully — unknown IE is skipped gracefully (buffer exhausted)
        let msg = decode_nas_5gs_message(&payload);
        assert!(msg.is_ok());
    }

    #[test]
    fn test_unknown_iei_tv1_skip() {
        // RegistrationRequest with unknown TV-1 IEI (0xE0, bit 8=1)
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.push(0xE7); // Unknown TV-1 IEI — should be skipped (1 byte)
        let msg = decode_nas_5gs_message(&payload).unwrap();
        // Should still parse as RegistrationRequest
        assert!(matches!(
            msg,
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(_))
        ));
    }

    #[test]
    fn test_unknown_iei_tlve_skip() {
        // RegistrationRequest with unknown TLV-E IEI (0x7D, bits 7-5 = "111")
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x7D, 0x00, 0x02, 0xAA, 0xBB]); // TLV-E: IEI + len(2) + 2 bytes
        let msg = decode_nas_5gs_message(&payload).unwrap();
        assert!(matches!(
            msg,
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(_))
        ));
    }

    #[test]
    fn test_unknown_iei_tlv_skip() {
        // RegistrationRequest with unknown TLV IEI (0x3F, bits 7-5 != "111")
        let mut payload =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        payload.extend_from_slice(&[0x3F, 0x03, 0x01, 0x02, 0x03]); // TLV: IEI + len(3) + 3 bytes
        let msg = decode_nas_5gs_message(&payload).unwrap();
        assert!(matches!(
            msg,
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(_))
        ));
    }

    #[test]
    fn test_5gsm_header_too_short() {
        // 5GSM EPD but truncated header
        assert!(decode_nas_5gs_message(&[0x2e, 0x01, 0x00]).is_err());
    }

    #[test]
    fn test_encode_decode_identity_request() {
        // Build an IdentityRequest for SUCI
        let msg = Nas5gsMessage::new_5gmm(
            Nas5gmmMessageType::IdentityRequest,
            Nas5gmmMessage::IdentityRequest(messages::NasIdentityRequest::new(
                NasFGsIdentityType::from_identity_type(MobileIdentityType::Suci),
            )),
        );
        let encoded = encode_nas_5gs_message(&msg).unwrap();
        let decoded = decode_nas_5gs_message(&encoded).unwrap();
        let re_encoded = encode_nas_5gs_message(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_registration_reject() {
        let msg = Nas5gsMessage::new_5gmm(
            Nas5gmmMessageType::RegistrationReject,
            Nas5gmmMessage::RegistrationReject(messages::NasRegistrationReject::new(
                NasFGmmCause::from_cause(GmmCause::IllegalUe),
            )),
        );
        let encoded = encode_nas_5gs_message(&msg).unwrap();
        let decoded = decode_nas_5gs_message(&encoded).unwrap();
        let re_encoded = encode_nas_5gs_message(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_auth_failure() {
        let msg = Nas5gsMessage::new_5gmm(
            Nas5gmmMessageType::AuthenticationFailure,
            Nas5gmmMessage::AuthenticationFailure(
                messages::NasAuthenticationFailure::new(NasFGmmCause::from_cause(
                    GmmCause::SynchFailure,
                ))
                .set_authentication_failure_parameter(
                    NasAuthenticationFailureParameter::new(vec![0x01; 14]),
                ),
            ),
        );
        let encoded = encode_nas_5gs_message(&msg).unwrap();
        let decoded = decode_nas_5gs_message(&encoded).unwrap();
        let re_encoded = encode_nas_5gs_message(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn test_encode_decode_deregistration() {
        let msg = Nas5gsMessage::new_5gmm(
            Nas5gmmMessageType::DeregistrationRequestFromUe,
            Nas5gmmMessage::DeregistrationRequestFromUe(
                messages::NasDeregistrationRequestFromUe::new(
                    NasDeRegistrationType::new(0x09), // switch_off=1, 3GPP access
                    NasFGsMobileIdentity::from_guti(&Guti {
                        mcc: [2, 0, 8],
                        mnc: [9, 3, 0x0F],
                        amf_region_id: 0x02,
                        amf_set_id: 0x40,
                        amf_pointer: 0x00,
                        tmsi: 0xDEADBEEF,
                    }),
                ),
            ),
        );
        let encoded = encode_nas_5gs_message(&msg).unwrap();
        let decoded = decode_nas_5gs_message(&encoded).unwrap();
        let re_encoded = encode_nas_5gs_message(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }
}
