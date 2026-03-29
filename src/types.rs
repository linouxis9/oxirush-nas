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

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

/// Error that can occur during NAS message processing
#[derive(Error, Debug)]
pub enum NasError {
    #[error("Invalid message format")]
    InvalidFormat,

    #[error("Buffer too short")]
    BufferTooShort,

    #[error("Unknown message type: {0}")]
    UnknownMessageType(u8),

    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),
}

/// Result type for NAS operations
pub type Result<T> = std::result::Result<T, NasError>;

/// Extended Protocol Discriminator values
pub const EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM: u8 = 0x2e;
pub const EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM: u8 = 0x7e;

/// Trait for encoding NAS messages
pub trait Encode {
    /// Encode self into the provided buffer
    fn encode(&self, buffer: &mut BytesMut) -> Result<()>;
}

/// Trait for decoding NAS messages
pub trait Decode: Sized {
    /// Decode a message from the provided buffer
    fn decode(buffer: &mut Bytes) -> Result<Self>;
}

/// Helper functions for IE encoding/decoding
pub mod helpers {
    use super::*;

    /// Encode an optional Type field
    pub fn encode_optional_type(buffer: &mut BytesMut, type_value: u8) -> Result<()> {
        buffer.put_u8(type_value);
        Ok(())
    }

    /// Convert from network byte order (big-endian) to host byte order
    pub fn be16_to_u16(value: [u8; 2]) -> u16 {
        u16::from_be_bytes(value)
    }

    /// Convert from host byte order to network byte order (big-endian)
    pub fn u16_to_be16(value: u16) -> [u8; 2] {
        value.to_be_bytes()
    }
}

// ── NAS IE format macros ────────────────────────────────────────────────────
//
// Each macro generates: pub struct, new(), Encode impl, Decode impl.
// Formats per 3GPP TS 24.007 §11.2.

/// V format: value only (u8), no type field, no length.
macro_rules! nas_ie_v {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub value: u8 }
        impl $name {
            pub fn new(value: u8) -> Self { Self { value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8(self.value); Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 1 { return Err(NasError::BufferTooShort); }
                Ok(Self { value: buffer.get_u8() })
            }
        }
    };
}

/// V format with u16 value.
macro_rules! nas_ie_v_u16 {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub value: u16 }
        impl $name {
            pub fn new(value: u16) -> Self { Self { value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u16(self.value); Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 2 { return Err(NasError::BufferTooShort); }
                Ok(Self { value: buffer.get_u16() })
            }
        }
    };
}

/// V format with fixed-length Vec<u8> value.
macro_rules! nas_ie_v_fixed {
    ($name:ident, $len:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub value: Vec<u8> }
        impl $name {
            pub fn new(value: Vec<u8>) -> Self { Self { value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_slice(&self.value); Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < $len { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; $len];
                buffer.copy_to_slice(&mut value);
                Ok(Self { value })
            }
        }
    };
}

/// LV format: length (u8) + value, no type field. Mandatory variable-length IEs.
macro_rules! nas_ie_lv {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub length: u8, pub value: Vec<u8> }
        impl $name {
            pub fn new(value: Vec<u8>) -> Self {
                Self { length: value.len() as u8, value }
            }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8(self.length);
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 1 { return Err(NasError::BufferTooShort); }
                let length = buffer.get_u8();
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { length, value })
            }
        }
    };
}

/// LV-E format: length (u16 BE) + value, no type field. Mandatory extended variable-length IEs.
macro_rules! nas_ie_lve {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub length: u16, pub value: Vec<u8> }
        impl $name {
            pub fn new(value: Vec<u8>) -> Self {
                Self { length: value.len() as u16, value }
            }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_slice(&helpers::u16_to_be16(self.length));
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 2 { return Err(NasError::BufferTooShort); }
                let mut lb = [0u8; 2];
                buffer.copy_to_slice(&mut lb);
                let length = helpers::be16_to_u16(lb);
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { length, value })
            }
        }
    };
}

/// TV-1 format: type (4 bits) + value (4 bits) packed in 1 byte. Optional half-byte IEs.
macro_rules! nas_ie_tv1 {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub type_field: u8, pub value: u8 }
        impl $name {
            pub fn new(value: u8) -> Self { Self { type_field: 0, value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8((self.type_field << 4) | (self.value & 0x0F));
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 1 { return Err(NasError::BufferTooShort); }
                let byte = buffer.get_u8();
                Ok(Self { type_field: byte >> 4, value: byte & 0x0F })
            }
        }
    };
}

/// TV format: type (u8) + value (u8). Optional fixed 1-byte value IEs.
macro_rules! nas_ie_tv {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub type_field: u8, pub value: u8 }
        impl $name {
            pub fn new(value: u8) -> Self { Self { type_field: 0, value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8(self.type_field);
                buffer.put_u8(self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 2 { return Err(NasError::BufferTooShort); }
                Ok(Self { type_field: buffer.get_u8(), value: buffer.get_u8() })
            }
        }
    };
}

/// TV format with fixed-length Vec<u8> value. Optional fixed multi-byte value IEs.
macro_rules! nas_ie_tv_fixed {
    ($name:ident, $len:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub type_field: u8, pub value: Vec<u8> }
        impl $name {
            pub fn new(value: Vec<u8>) -> Self { Self { type_field: 0, value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8(self.type_field);
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 1 + $len { return Err(NasError::BufferTooShort); }
                let type_field = buffer.get_u8();
                let mut value = vec![0; $len];
                buffer.copy_to_slice(&mut value);
                Ok(Self { type_field, value })
            }
        }
    };
}

/// TLV format: type (u8) + length (u8) + value. The most common optional IE format.
macro_rules! nas_ie_tlv {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub type_field: u8, pub length: u8, pub value: Vec<u8> }
        impl $name {
            pub fn new(value: Vec<u8>) -> Self {
                Self { type_field: 0, length: value.len() as u8, value }
            }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8(self.type_field);
                buffer.put_u8(self.length);
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 2 { return Err(NasError::BufferTooShort); }
                let type_field = buffer.get_u8();
                let length = buffer.get_u8();
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { type_field, length, value })
            }
        }
    };
}

/// TLV-E format: type (u8) + length (u16 BE) + value. Optional extended variable-length IEs.
macro_rules! nas_ie_tlve {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub type_field: u8, pub length: u16, pub value: Vec<u8> }
        impl $name {
            pub fn new(value: Vec<u8>) -> Self {
                Self { type_field: 0, length: value.len() as u16, value }
            }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8(self.type_field);
                buffer.put_slice(&helpers::u16_to_be16(self.length));
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 3 { return Err(NasError::BufferTooShort); }
                let type_field = buffer.get_u8();
                let mut lb = [0u8; 2];
                buffer.copy_to_slice(&mut lb);
                let length = helpers::be16_to_u16(lb);
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { type_field, length, value })
            }
        }
    };
}

// ── V format (value only) ────────────────────────────────────────────────────

nas_ie_v!(NasDeRegistrationType);            // 9.11.3.20
nas_ie_v!(NasFGmmCause);                     // 9.11.3.2
nas_ie_v!(NasFGsIdentityType);               // 9.11.3.3
nas_ie_v!(NasFGsRegistrationType);           // 9.11.3.7
nas_ie_v!(NasKeySetIdentifier);              // 9.11.3.32
nas_ie_v!(NasPayloadContainerType);          // 9.11.3.40
nas_ie_v!(NasSecurityAlgorithms);            // 9.11.3.34
nas_ie_v_u16!(NasIntegrityProtectionMaximumDataRate);  // 9.11.4.7
nas_ie_v_fixed!(NasMaximumNumberOfSupportedPacketFilters, 3);  // 9.11.4.9

// ── LV format (mandatory variable-length) ────────────────────────────────────

nas_ie_lv!(NasAbba);                         // 9.11.3.10
nas_ie_lv!(NasFGsRegistrationResult);        // 9.11.3.6
nas_ie_lv!(NasSessionAmbr);                  // 9.11.4.14
nas_ie_lv!(NasUeSecurityCapability);         // 9.11.3.54

// ── LV-E format (mandatory extended variable-length) ─────────────────────────

nas_ie_lve!(NasFGsMobileIdentity);           // 9.11.3.4
nas_ie_lve!(NasPayloadContainer);            // 9.11.3.39
nas_ie_lve!(NasQosRules);                    // 9.11.4.13

// ── TV-1 format (half-byte optional) ─────────────────────────────────────────

nas_ie_tv1!(NasAccessType);                  // 9.11.2.1A
nas_ie_tv1!(NasAdditionalConfigurationIndication);  // 9.11.3.75
nas_ie_tv1!(NasAllowedSscMode);              // 9.11.4.5
nas_ie_tv1!(NasAlwaysOnPduSessionIndication); // 9.11.4.3
nas_ie_tv1!(NasAlwaysOnPduSessionRequested); // 9.11.4.4
nas_ie_tv1!(NasConfigurationUpdateIndication); // 9.11.3.18
nas_ie_tv1!(NasControlPlaneOnlyIndication);  // 9.11.3.18B
nas_ie_tv1!(NasImeisvRequest);               // 9.11.3.28
nas_ie_tv1!(NasMaPduSessionInformation);     // 9.11.4.31
nas_ie_tv1!(NasMicoIndication);              // 9.11.3.31
nas_ie_tv1!(NasNFGcIndication);              // 9.11.2.11
nas_ie_tv1!(NasNetworkSlicingIndication);    // 9.11.3.36
nas_ie_tv1!(NasNon3GppNwProvidedPolicies);   // 9.11.3.36A
nas_ie_tv1!(NasNssaiInclusionMode);          // 9.11.3.37A
nas_ie_tv1!(NasPduSessionType);              // 9.11.4.11
nas_ie_tv1!(NasPriorityIndicator);           // 9.11.2.12
nas_ie_tv1!(NasReleaseAssistanceIndication); // 9.11.4.25
nas_ie_tv1!(NasRequestType);                 // 9.11.3.47
nas_ie_tv1!(NasSmsIndication);               // 9.11.3.50A
nas_ie_tv1!(NasSscMode);                     // 9.11.4.16
nas_ie_tv1!(NasUeRadioCapabilityIdDeletionIndication); // 9.11.3.69

// ── TV format (optional fixed 1-byte) ────────────────────────────────────────

nas_ie_tv!(NasEpsNasSecurityAlgorithms);     // 9.11.3.25
nas_ie_tv!(NasGprsTimer);                    // 9.11.2.3
nas_ie_tv!(NasPduSessionIdentity2);          // 9.11.3.41
nas_ie_tv!(NasTimeZone);                     // 9.11.3.52

// ── TV format (fixed-length Vec) ─────────────────────────────────────────────

nas_ie_tv_fixed!(NasAuthenticationParameterRand, 16); // 9.11.3.16
nas_ie_tv_fixed!(NasFGsTrackingAreaIdentity, 7);      // 9.11.3.8
nas_ie_tv_fixed!(NasTimeZoneAndTime, 8);               // 9.11.3.53

// ── TLV format (optional variable-length) ────────────────────────────────────

nas_ie_tlv!(NasAdditionalFGSecurityInformation); // 9.11.3.12
nas_ie_tlv!(NasAdditionalInformation);       // 9.11.2.1
nas_ie_tlv!(NasAdditionalInformationRequested); // 9.11.3.12A
nas_ie_tlv!(NasAllowedPduSessionStatus);     // 9.11.3.13
nas_ie_tlv!(NasAuthenticationFailureParameter); // 9.11.3.14
nas_ie_tlv!(NasAuthenticationParameterAutn); // 9.11.3.15
nas_ie_tlv!(NasAuthenticationResponseParameter); // 9.11.3.17
nas_ie_tlv!(NasDaylightSavingTime);          // 9.11.3.19
nas_ie_tlv!(NasDnn);                         // 9.11.2.1B
nas_ie_tlv!(NasDsTtEthernetPortMacAddress);  // 9.11.4.26
nas_ie_tlv!(NasEmergencyNumberList);         // 9.11.3.23
nas_ie_tlv!(NasEpsBearerContextStatus);      // 9.11.3.23A
nas_ie_tlv!(NasEthernetHeaderCompressionConfiguration); // 9.11.4.28
nas_ie_tlv!(NasExtendedDrxParameters);       // 9.11.3.26A
nas_ie_tlv!(NasExtendedRejectedNssai);       // 9.11.3.75A
nas_ie_tlv!(NasFGmmCapability);              // 9.11.3.1
nas_ie_tlv!(NasFGsAdditionalRequestResult);  // 9.11.3.81
nas_ie_tlv!(NasFGsDrxParameters);            // 9.11.3.2A
nas_ie_tlv!(NasFGsNetworkFeatureSupport);    // 9.11.3.5
nas_ie_tlv!(NasFGsTrackingAreaIdentityList); // 9.11.3.9
nas_ie_tlv!(NasFGsUpdateType);              // 9.11.3.9A
nas_ie_tlv!(NasFGsmCapability);              // 9.11.4.1
nas_ie_tlv!(NasFGsmCongestionReAttemptIndicator); // 9.11.4.21
nas_ie_tlv!(NasFGsmNetworkFeatureSupport);   // 9.11.4.18
nas_ie_tlv!(NasGprsTimer2);                  // 9.11.2.4
nas_ie_tlv!(NasGprsTimer3);                  // 9.11.2.5
nas_ie_tlv!(NasHeaderCompressionConfiguration); // 9.11.4.24
nas_ie_tlv!(NasIpHeaderCompressionConfiguration); // 9.11.4.24A
nas_ie_tlv!(NasListOfPlmnsToBeUsedInDisasterCondition); // 9.11.3.83
nas_ie_tlv!(NasMappedNssai);                 // 9.11.3.31B
nas_ie_tlv!(NasMobileStationClassmark2);     // 9.11.3.31C
nas_ie_tlv!(NasNbN1ModeDrxParameters);       // 9.11.3.73
nas_ie_tlv!(NasNetworkName);                 // 9.11.3.35
nas_ie_tlv!(NasNid);                         // 9.11.3.79
nas_ie_tlv!(NasNssai);                       // 9.11.3.37
nas_ie_tlv!(NasPagingRestriction);           // 9.11.3.77
nas_ie_tlv!(NasPduAddress);                  // 9.11.4.10
nas_ie_tlv!(NasPduSessionPairId);            // 9.11.4.22
nas_ie_tlv!(NasPduSessionReactivationResult); // 9.11.3.42
nas_ie_tlv!(NasPduSessionStatus);            // 9.11.3.44
nas_ie_tlv!(NasPeipsAssistanceInformation);  // 9.11.3.80
nas_ie_tlv!(NasPlmnIdentity);               // 9.11.3.43
nas_ie_tlv!(NasPlmnList);                    // 9.11.3.45
nas_ie_tlv!(NasReAttemptIndicator);          // 9.11.4.17
nas_ie_tlv!(NasRegistrationWaitRange);       // 9.11.3.84
nas_ie_tlv!(NasRejectedNssai);              // 9.11.3.46
nas_ie_tlv!(NasRsn);                         // 9.11.4.23
nas_ie_tlv!(NasS1UeNetworkCapability);       // 9.11.3.48
nas_ie_tlv!(NasS1UeSecurityCapability);      // 9.11.3.48A
nas_ie_tlv!(NasSNssai);                      // 9.11.2.8
nas_ie_tlv!(NasServiceAreaList);             // 9.11.3.49
nas_ie_tlv!(NasServingPlmnRateControl);      // 9.11.4.20
nas_ie_tlv!(NasSmPduDnRequestContainer);     // 9.11.4.15
nas_ie_tlv!(NasSupportedCodecList);          // 9.11.3.51A
nas_ie_tlv!(NasTruncatedFGSTmsiConfiguration); // 9.11.3.70
nas_ie_tlv!(NasUeDsTtResidenceTime);         // 9.11.4.27
nas_ie_tlv!(NasUeRadioCapabilityId);         // 9.11.3.68
nas_ie_tlv!(NasUeRequestType);              // 9.11.3.76
nas_ie_tlv!(NasUeStatus);                    // 9.11.3.56
nas_ie_tlv!(NasUeUsageSetting);              // 9.11.3.55
nas_ie_tlv!(NasUplinkDataStatus);            // 9.11.3.57
nas_ie_tlv!(NasWusAssistanceInformation);    // 9.11.3.71

// ── TLV-E format (optional extended variable-length) ─────────────────────────

nas_ie_tlve!(NasAtsssContainer);             // 9.11.4.22A
nas_ie_tlve!(NasCagInformationList);         // 9.11.3.18A
nas_ie_tlve!(NasCipheringKeyData);           // 9.11.3.18C
nas_ie_tlve!(NasEapMessage);                 // 9.11.2.2
nas_ie_tlve!(NasEpsNasMessageContainer);     // 9.11.3.24
nas_ie_tlve!(NasExtendedCagInformationList); // 9.11.3.86
nas_ie_tlve!(NasExtendedEmergencyNumberList); // 9.11.3.26
nas_ie_tlve!(NasExtendedProtocolConfigurationOptions); // 9.11.4.6
nas_ie_tlve!(NasLadnIndication);             // 9.11.3.29
nas_ie_tlve!(NasLadnInformation);            // 9.11.3.30
nas_ie_tlve!(NasMappedEpsBearerContexts);    // 9.11.4.8
nas_ie_tlve!(NasMessageContainer);           // 9.11.3.33
nas_ie_tlve!(NasNsagInformation);            // 9.11.3.87
nas_ie_tlve!(NasNssrgInformation);           // 9.11.3.82
nas_ie_tlve!(NasOperatorDefinedAccessCategoryDefinitions); // 9.11.3.38
nas_ie_tlve!(NasPduSessionReactivationResultErrorCause); // 9.11.3.42A
nas_ie_tlve!(NasPortManagementInformationContainer); // 9.11.4.29
nas_ie_tlve!(NasQosFlowDescriptions);        // 9.11.4.12
nas_ie_tlve!(NasReceivedMbsContainer);       // 9.11.4.32
nas_ie_tlve!(NasRequestedMbsContainer);      // 9.11.4.33
nas_ie_tlve!(NasServiceLevelAaContainer);    // 9.11.2.10
nas_ie_tlve!(NasSorTransparentContainer);    // 9.11.3.51

// ── Dual-mode (V/TV) — manual impl ──────────────────────────────────────────

/// 9.11.4.2 5GSM cause
/// V when mandatory (type_field=0), TV when optional (type_field!=0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsmCause {
    pub type_field: u8,
    pub value: u8,
}

impl NasFGsmCause {
    pub fn new(value: u8) -> Self {
        Self { type_field: 0, value }
    }

    /// Decode as a mandatory (V) IE: read value byte only, type_field set to 0.
    pub fn decode_value_only(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self { type_field: 0, value })
    }
}

impl Encode for NasFGsmCause {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        if self.type_field != 0 {
            buffer.put_u8(self.type_field);
        }
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasFGsmCause {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let value = buffer.get_u8();
        Ok(Self { type_field, value })
    }
}
