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


pub mod types;
pub mod message_types;
pub mod messages;

// Re-export key types and functions for easier use
pub use types::{NasError, Result, Encode, Decode, *};
pub use message_types::{Nas5gmmMessageType, Nas5gsmMessageType, Nas5gsSecurityHeaderType};
pub use messages::{
    Nas5gsMessage, Nas5gmmMessage, Nas5gsmMessage,
    encode_nas_5gs_message, decode_nas_5gs_message,
};

/// Version of oxirush-nas
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;
    
    #[test]
    fn test_registration_request_1() {
        let payload = hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }
        
    #[test]
    fn test_auth_request() {
        let payload = hex::decode("7e00560002000021ab6f2a1cc5c5938d38cba14dfe26b0012010a820e67b8896800076a638e98eed4747").unwrap();

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
        let payload = BASE64_STANDARD.decode("fgBedwAJFREAAAAAAAAAcQAgfgBBCQANAZn5BwAAAAAAAAAQAhABBy4IoCAAAAAAAAA=").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }

    #[test]
    fn test_registration_accept() {
        let payload = BASE64_STANDARD.decode("fgBCAQF3AAvymfkHAgBAwAAC31QHQJn5BwAAARUCAQEhAgEAXgGp").unwrap();

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
        let payload = BASE64_STANDARD.decode("fgBnAQAULgEBwf//kXsACoAACgAADQAAAwASAYEiAQElCQhpbnRlcm5ldA==").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }
        
    #[test]
    fn test_configuration_update_command() {
        let payload = BASE64_STANDARD.decode("fgBUQw+QAE8AcABlAG4ANQBHAFNGAEdCMGICZHEASQEA").unwrap();

        let parsed_message = decode_nas_5gs_message(&payload).unwrap();
        let encoded_message = encode_nas_5gs_message(&parsed_message).unwrap();

        assert_eq!(payload, encoded_message);
    }
        
    #[test]
    fn test_configuration_update_complete() {
        let payload = BASE64_STANDARD.decode("fgBV").unwrap();

        decode_nas_5gs_message(&payload).err().unwrap();
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
        let payload = BASE64_STANDARD.decode("fgBMEAAHBABAwAAC33EAFX4ATBAABwQAQMAAAt9AAgIAUAICAA==").unwrap();

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
}
