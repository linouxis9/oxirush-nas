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

//! Raw wire-format Information Element types and codec traits.
//!
//! This is **Layer 1** of the crate. Every IE struct here holds raw bytes in a
//! `pub value` field and implements [`Encode`]/[`Decode`] for the wire format
//! defined in 3GPP TS 24.007 &sect;11.2.
//!
//! For typed, semantic access to these bytes (enums, parsers, builders), see the
//! [`ie`](crate::ie) module (Layer 3).
//!
//! # IE format summary
//!
//! | Format | Type field | Length field | Example |
//! |--------|-----------|-------------|---------|
//! | V      | none      | none        | [`NasFGmmCause`] |
//! | LV     | none      | u8          | [`NasAbba`], [`NasUeSecurityCapability`] |
//! | LV-E   | none      | u16         | [`NasFGsMobileIdentity`] |
//! | TV-1   | 4 bits    | none        | [`NasMicoIndication`] |
//! | TV     | u8        | none        | [`NasGprsTimer`] |
//! | TLV    | u8        | u8          | [`NasNssai`], [`NasDnn`] |
//! | TLV-E  | u8        | u16         | [`NasEapMessage`], [`NasMessageContainer`] |

use bytes::{Buf, BufMut, Bytes, BytesMut};
use thiserror::Error;

/// Errors that can occur during NAS message encoding or decoding.
#[derive(Error, Debug, Clone)]
pub enum NasError {
    /// The message structure does not match any known NAS format.
    #[error("Invalid message format")]
    InvalidFormat,

    /// The input buffer is shorter than the minimum required for the IE or message.
    #[error("Buffer too short")]
    BufferTooShort,

    /// The message type byte does not map to a known 5GMM or 5GSM message.
    #[error("Unknown message type: {0}")]
    UnknownMessageType(u8),

    /// An error occurred while encoding a message or IE to bytes.
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// An error occurred while decoding bytes into a message or IE.
    #[error("Decoding error: {0}")]
    DecodingError(String),
}

/// Result type for NAS operations
pub type Result<T> = std::result::Result<T, NasError>;

/// Extended Protocol Discriminator for 5GS Session Management (0x2E).
pub const EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM: u8 = 0x2e;
/// Extended Protocol Discriminator for 5GS Mobility Management (0x7E).
pub const EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM: u8 = 0x7e;

/// Encode a NAS IE or message into a byte buffer.
///
/// All IE structs and message structs implement this trait. The buffer is
/// appended to (not overwritten), so multiple IEs can be encoded sequentially.
pub trait Encode {
    /// Append the wire-format encoding of `self` to `buffer`.
    fn encode(&self, buffer: &mut BytesMut) -> Result<()>;
}

/// Decode a NAS IE or message from a byte buffer.
///
/// The buffer is consumed as bytes are read. After a successful decode, the
/// buffer cursor is advanced past the decoded bytes.
pub trait Decode: Sized {
    /// Read and decode from the front of `buffer`, advancing the cursor.
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

/// Maximum allowed IE value length in bytes.
///
/// Prevents excessive memory allocation from malformed NAS messages.
/// The largest legitimate NAS IE is the EPS NAS Message Container which
/// can theoretically reach ~64KB, but in practice NAS PDUs are limited
/// to the SCTP MTU (~9000 bytes). We use a generous limit here.
pub const MAX_IE_VALUE_LENGTH: usize = 65535;

// ── NAS IE format macros ────────────────────────────────────────────────────
//
// Each macro generates: pub struct, new(), Encode impl, Decode impl.
// Formats per 3GPP TS 24.007 §11.2.

/// V format: value only (u8), no type field, no length.
macro_rules! nas_ie_v {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { pub value: u8 }
        impl $name {
            /// Create a new instance from raw value byte.
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
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
                if (length as usize) > MAX_IE_VALUE_LENGTH { return Err(NasError::DecodingError(format!("IE value length {} exceeds maximum {}", length, MAX_IE_VALUE_LENGTH))); }
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
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
                if (length as usize) > MAX_IE_VALUE_LENGTH { return Err(NasError::DecodingError(format!("IE value length {} exceeds maximum {}", length, MAX_IE_VALUE_LENGTH))); }
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
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
                if (length as usize) > MAX_IE_VALUE_LENGTH { return Err(NasError::DecodingError(format!("IE value length {} exceeds maximum {}", length, MAX_IE_VALUE_LENGTH))); }
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
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
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
                if (length as usize) > MAX_IE_VALUE_LENGTH { return Err(NasError::DecodingError(format!("IE value length {} exceeds maximum {}", length, MAX_IE_VALUE_LENGTH))); }
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { type_field, length, value })
            }
        }
    };
}

// ── V format (value only) ────────────────────────────────────────────────────

nas_ie_v!(
    /// De-Registration Type (TS 24.501 §9.11.3.20). V format (1 byte).
    NasDeRegistrationType
);
nas_ie_v!(
    /// 5GMM Cause (TS 24.501 §9.11.3.2). V format (1 byte).
    NasFGmmCause
);
/// 5GS Identity Type (TS 24.501 &sect;9.11.3.3).
///
/// Only the lower 3 bits are significant. Use [`MobileIdentityType`](crate::ie::MobileIdentityType)
/// for typed access via the `identity_type()` method defined in the [`ie`](crate::ie) module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsIdentityType {
    pub value: u8,
}
impl NasFGsIdentityType {
    pub fn new(value: u8) -> Self {
        Self { value }
    }
}
impl Encode for NasFGsIdentityType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        buffer.put_u8(self.value);
        Ok(())
    }
}
impl Decode for NasFGsIdentityType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        Ok(Self {
            value: buffer.get_u8() & 0x07,
        })
    }
}
nas_ie_v!(
    /// 5GS Registration Type (TS 24.501 §9.11.3.7). V format (1 byte).
    NasFGsRegistrationType
);
nas_ie_v!(
    /// NAS Key Set Identifier (TS 24.501 §9.11.3.32). V format (1 byte).
    NasKeySetIdentifier
);
/// Payload Container Type (TS 24.501 &sect;9.11.3.40).
///
/// Only the lower 4 bits are significant. Use [`PayloadContainerKind`](crate::ie::PayloadContainerKind)
/// for typed access via the `kind()` method defined in the [`ie`](crate::ie) module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPayloadContainerType {
    pub value: u8,
}
impl NasPayloadContainerType {
    pub fn new(value: u8) -> Self {
        Self { value }
    }
}
impl Encode for NasPayloadContainerType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        buffer.put_u8(self.value);
        Ok(())
    }
}
impl Decode for NasPayloadContainerType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        Ok(Self {
            value: buffer.get_u8() & 0x0F,
        })
    }
}
nas_ie_v!(
    /// NAS Security Algorithms (TS 24.501 §9.11.3.34). V format (1 byte).
    NasSecurityAlgorithms
);
nas_ie_v_u16!(
    /// Integrity Protection Maximum Data Rate (TS 24.501 §9.11.4.7). V format (2 bytes).
    NasIntegrityProtectionMaximumDataRate
);
nas_ie_v_fixed!(
    /// Maximum Number of Supported Packet Filters (TS 24.501 §9.11.4.9). V format (3 bytes).
    NasMaximumNumberOfSupportedPacketFilters, 3
);

// ── LV format (mandatory variable-length) ────────────────────────────────────

nas_ie_lv!(
    /// ABBA (TS 24.501 §9.11.3.10). LV format.
    NasAbba
);
nas_ie_lv!(
    /// 5GS Registration Result (TS 24.501 §9.11.3.6). LV format.
    NasFGsRegistrationResult
);
nas_ie_lv!(
    /// Session-AMBR (TS 24.501 §9.11.4.14). LV format.
    NasSessionAmbr
);
nas_ie_lv!(
    /// UE Security Capability (TS 24.501 §9.11.3.54). LV format.
    NasUeSecurityCapability
);

// ── LV-E format (mandatory extended variable-length) ─────────────────────────

nas_ie_lve!(
    /// 5GS Mobile Identity (TS 24.501 §9.11.3.4). LV-E format.
    NasFGsMobileIdentity
);
nas_ie_lve!(
    /// Payload Container (TS 24.501 §9.11.3.39). LV-E format.
    NasPayloadContainer
);
nas_ie_lve!(
    /// QoS Rules (TS 24.501 §9.11.4.13). LV-E format.
    NasQosRules
);

// ── TV-1 format (half-byte optional) ─────────────────────────────────────────

nas_ie_tv1!(
    /// Access Type (TS 24.501 §9.11.2.1A). TV-1 format.
    NasAccessType
);
nas_ie_tv1!(
    /// Additional Configuration Indication (TS 24.501 §9.11.3.75). TV-1 format.
    NasAdditionalConfigurationIndication
);
nas_ie_tv1!(
    /// Allowed SSC Mode (TS 24.501 §9.11.4.5). TV-1 format.
    NasAllowedSscMode
);
nas_ie_tv1!(
    /// Always-on PDU Session Indication (TS 24.501 §9.11.4.3). TV-1 format.
    NasAlwaysOnPduSessionIndication
);
nas_ie_tv1!(
    /// Always-on PDU Session Requested (TS 24.501 §9.11.4.4). TV-1 format.
    NasAlwaysOnPduSessionRequested
);
nas_ie_tv1!(
    /// Configuration Update Indication (TS 24.501 §9.11.3.18). TV-1 format.
    NasConfigurationUpdateIndication
);
nas_ie_tv1!(
    /// Control Plane Only Indication (TS 24.501 §9.11.3.18B). TV-1 format.
    NasControlPlaneOnlyIndication
);
nas_ie_tv1!(
    /// IMEISV Request (TS 24.501 §9.11.3.28). TV-1 format.
    NasImeisvRequest
);
nas_ie_tv1!(
    /// MA PDU Session Information (TS 24.501 §9.11.4.31). TV-1 format.
    NasMaPduSessionInformation
);
nas_ie_tv1!(
    /// MICO Indication (TS 24.501 §9.11.3.31). TV-1 format.
    NasMicoIndication
);
nas_ie_tv1!(
    /// N5GC Indication (TS 24.501 §9.11.2.11). TV-1 format.
    NasNFGcIndication
);
nas_ie_tv1!(
    /// Network Slicing Indication (TS 24.501 §9.11.3.36). TV-1 format.
    NasNetworkSlicingIndication
);
nas_ie_tv1!(
    /// Non-3GPP NW Provided Policies (TS 24.501 §9.11.3.36A). TV-1 format.
    NasNon3GppNwProvidedPolicies
);
nas_ie_tv1!(
    /// NSSAI Inclusion Mode (TS 24.501 §9.11.3.37A). TV-1 format.
    NasNssaiInclusionMode
);
nas_ie_tv1!(
    /// PDU Session Type (TS 24.501 §9.11.4.11). TV-1 format.
    NasPduSessionType
);
nas_ie_tv1!(
    /// Priority Indicator (TS 24.501 §9.11.2.12). TV-1 format.
    NasPriorityIndicator
);
nas_ie_tv1!(
    /// Release Assistance Indication (TS 24.501 §9.11.4.25). TV-1 format.
    NasReleaseAssistanceIndication
);
nas_ie_tv1!(
    /// Request Type (TS 24.501 §9.11.3.47). TV-1 format.
    NasRequestType
);
nas_ie_tv1!(
    /// SMS Indication (TS 24.501 §9.11.3.50A). TV-1 format.
    NasSmsIndication
);
nas_ie_tv1!(
    /// SSC Mode (TS 24.501 §9.11.4.16). TV-1 format.
    NasSscMode
);
nas_ie_tv1!(
    /// UE Radio Capability ID Deletion Indication (TS 24.501 §9.11.3.69). TV-1 format.
    NasUeRadioCapabilityIdDeletionIndication
);

// ── TV format (optional fixed 1-byte) ────────────────────────────────────────

nas_ie_tv!(
    /// EPS NAS Security Algorithms (TS 24.501 §9.11.3.25). TV format (1+1 bytes).
    NasEpsNasSecurityAlgorithms
);
nas_ie_tv!(
    /// GPRS Timer (TS 24.501 §9.11.2.3). TV format (1+1 bytes).
    NasGprsTimer
);
nas_ie_tv!(
    /// PDU Session Identity 2 (TS 24.501 §9.11.3.41). TV format (1+1 bytes).
    NasPduSessionIdentity2
);
nas_ie_tv!(
    /// Time Zone (TS 24.501 §9.11.3.52). TV format (1+1 bytes).
    NasTimeZone
);

// ── TV format (fixed-length Vec) ─────────────────────────────────────────────

nas_ie_tv_fixed!(
    /// Authentication Parameter RAND (TS 24.501 §9.11.3.16). TV format (1+16 bytes).
    NasAuthenticationParameterRand, 16
);
nas_ie_tv_fixed!(
    /// 5GS Tracking Area Identity (TS 24.501 §9.11.3.8). TV format (1+6 bytes: PLMN + TAC).
    NasFGsTrackingAreaIdentity, 6
);
nas_ie_tv_fixed!(
    /// Time Zone and Time (TS 24.501 §9.11.3.53). TV format (1+7 bytes: Y/M/D/H/M/S/TZ).
    NasTimeZoneAndTime, 7
);

// ── TLV format (optional variable-length) ────────────────────────────────────

nas_ie_tlv!(
    /// Additional 5G Security Information (TS 24.501 §9.11.3.12). TLV format.
    NasAdditionalFGSecurityInformation
);
nas_ie_tlv!(
    /// Additional Information (TS 24.501 §9.11.2.1). TLV format.
    NasAdditionalInformation
);
nas_ie_tlv!(
    /// Additional Information Requested (TS 24.501 §9.11.3.12A). TLV format.
    NasAdditionalInformationRequested
);
nas_ie_tlv!(
    /// Allowed PDU Session Status (TS 24.501 §9.11.3.13). TLV format.
    NasAllowedPduSessionStatus
);
nas_ie_tlv!(
    /// Authentication Failure Parameter (TS 24.501 §9.11.3.14). TLV format.
    NasAuthenticationFailureParameter
);
nas_ie_tlv!(
    /// Authentication Parameter AUTN (TS 24.501 §9.11.3.15). TLV format.
    NasAuthenticationParameterAutn
);
nas_ie_tlv!(
    /// Authentication Response Parameter (TS 24.501 §9.11.3.17). TLV format.
    NasAuthenticationResponseParameter
);
nas_ie_tlv!(
    /// Daylight Saving Time (TS 24.501 §9.11.3.19). TLV format.
    NasDaylightSavingTime
);
nas_ie_tlv!(
    /// DNN (TS 24.501 §9.11.2.1B). TLV format.
    NasDnn
);
nas_ie_tlv!(
    /// DS-TT Ethernet Port MAC Address (TS 24.501 §9.11.4.26). TLV format.
    NasDsTtEthernetPortMacAddress
);
nas_ie_tlv!(
    /// Emergency Number List (TS 24.501 §9.11.3.23). TLV format.
    NasEmergencyNumberList
);
nas_ie_tlv!(
    /// EPS Bearer Context Status (TS 24.501 §9.11.3.23A). TLV format.
    NasEpsBearerContextStatus
);
nas_ie_tlv!(
    /// Ethernet Header Compression Configuration (TS 24.501 §9.11.4.28). TLV format.
    NasEthernetHeaderCompressionConfiguration
);
nas_ie_tlv!(
    /// Extended DRX Parameters (TS 24.501 §9.11.3.26A). TLV format.
    NasExtendedDrxParameters
);
nas_ie_tlv!(
    /// Extended Rejected NSSAI (TS 24.501 §9.11.3.75A). TLV format.
    NasExtendedRejectedNssai
);
nas_ie_tlv!(
    /// 5GMM Capability (TS 24.501 §9.11.3.1). TLV format.
    NasFGmmCapability
);
nas_ie_tlv!(
    /// 5GS Additional Request Result (TS 24.501 §9.11.3.81). TLV format.
    NasFGsAdditionalRequestResult
);
nas_ie_tlv!(
    /// 5GS DRX Parameters (TS 24.501 §9.11.3.2A). TLV format.
    NasFGsDrxParameters
);
nas_ie_tlv!(
    /// 5GS Network Feature Support (TS 24.501 §9.11.3.5). TLV format.
    NasFGsNetworkFeatureSupport
);
nas_ie_tlv!(
    /// 5GS Tracking Area Identity List (TS 24.501 §9.11.3.9). TLV format.
    NasFGsTrackingAreaIdentityList
);
nas_ie_tlv!(
    /// 5GS Update Type (TS 24.501 §9.11.3.9A). TLV format.
    NasFGsUpdateType
);
nas_ie_tlv!(
    /// 5GSM Capability (TS 24.501 §9.11.4.1). TLV format.
    NasFGsmCapability
);
nas_ie_tlv!(
    /// 5GSM Congestion Re-attempt Indicator (TS 24.501 §9.11.4.21). TLV format.
    NasFGsmCongestionReAttemptIndicator
);
nas_ie_tlv!(
    /// 5GSM Network Feature Support (TS 24.501 §9.11.4.18). TLV format.
    NasFGsmNetworkFeatureSupport
);
nas_ie_tlv!(
    /// GPRS Timer 2 (TS 24.501 §9.11.2.4). TLV format.
    NasGprsTimer2
);
nas_ie_tlv!(
    /// GPRS Timer 3 (TS 24.501 §9.11.2.5). TLV format.
    NasGprsTimer3
);
nas_ie_tlv!(
    /// Header Compression Configuration (TS 24.501 §9.11.4.24). TLV format.
    NasHeaderCompressionConfiguration
);
nas_ie_tlv!(
    /// IP Header Compression Configuration (TS 24.501 §9.11.4.24A). TLV format.
    NasIpHeaderCompressionConfiguration
);
nas_ie_tlv!(
    /// List of PLMNs to be Used in Disaster Condition (TS 24.501 §9.11.3.83). TLV format.
    NasListOfPlmnsToBeUsedInDisasterCondition
);
nas_ie_tlv!(
    /// Mapped NSSAI (TS 24.501 §9.11.3.31B). TLV format.
    NasMappedNssai
);
nas_ie_tlv!(
    /// Mobile Station Classmark 2 (TS 24.501 §9.11.3.31C). TLV format.
    NasMobileStationClassmark2
);
nas_ie_tlv!(
    /// NB-N1 Mode DRX Parameters (TS 24.501 §9.11.3.73). TLV format.
    NasNbN1ModeDrxParameters
);
nas_ie_tlv!(
    /// Network Name (TS 24.501 §9.11.3.35). TLV format.
    NasNetworkName
);
nas_ie_tlv!(
    /// NID (TS 24.501 §9.11.3.79). TLV format.
    NasNid
);
nas_ie_tlv!(
    /// NSSAI (TS 24.501 §9.11.3.37). TLV format.
    NasNssai
);
nas_ie_tlv!(
    /// Paging Restriction (TS 24.501 §9.11.3.77). TLV format.
    NasPagingRestriction
);
nas_ie_tlv!(
    /// PDU Address (TS 24.501 §9.11.4.10). TLV format.
    NasPduAddress
);
nas_ie_tlv!(
    /// PDU Session Pair ID (TS 24.501 §9.11.4.22). TLV format.
    NasPduSessionPairId
);
nas_ie_tlv!(
    /// PDU Session Reactivation Result (TS 24.501 §9.11.3.42). TLV format.
    NasPduSessionReactivationResult
);
nas_ie_tlv!(
    /// PDU Session Status (TS 24.501 §9.11.3.44). TLV format.
    NasPduSessionStatus
);
nas_ie_tlv!(
    /// PEIPS Assistance Information (TS 24.501 §9.11.3.80). TLV format.
    NasPeipsAssistanceInformation
);
nas_ie_tlv!(
    /// PLMN Identity (TS 24.501 §9.11.3.43). TLV format.
    NasPlmnIdentity
);
nas_ie_tlv!(
    /// PLMN List (TS 24.501 §9.11.3.45). TLV format.
    NasPlmnList
);
nas_ie_tlv!(
    /// Re-attempt Indicator (TS 24.501 §9.11.4.17). TLV format.
    NasReAttemptIndicator
);
nas_ie_tlv!(
    /// Registration Wait Range (TS 24.501 §9.11.3.84). TLV format.
    NasRegistrationWaitRange
);
nas_ie_tlv!(
    /// Rejected NSSAI (TS 24.501 §9.11.3.46). TLV format.
    NasRejectedNssai
);
nas_ie_tlv!(
    /// RSN (TS 24.501 §9.11.4.23). TLV format.
    NasRsn
);
nas_ie_tlv!(
    /// S1 UE Network Capability (TS 24.501 §9.11.3.48). TLV format.
    NasS1UeNetworkCapability
);
nas_ie_tlv!(
    /// S1 UE Security Capability (TS 24.501 §9.11.3.48A). TLV format.
    NasS1UeSecurityCapability
);
nas_ie_tlv!(
    /// S-NSSAI (TS 24.501 §9.11.2.8). TLV format.
    NasSNssai
);
nas_ie_tlv!(
    /// Service Area List (TS 24.501 §9.11.3.49). TLV format.
    NasServiceAreaList
);
nas_ie_tlv!(
    /// Serving PLMN Rate Control (TS 24.501 §9.11.4.20). TLV format.
    NasServingPlmnRateControl
);
nas_ie_tlv!(
    /// SM PDU DN Request Container (TS 24.501 §9.11.4.15). TLV format.
    NasSmPduDnRequestContainer
);
nas_ie_tlv!(
    /// Supported Codec List (TS 24.501 §9.11.3.51A). TLV format.
    NasSupportedCodecList
);
nas_ie_tlv!(
    /// Truncated 5G-S-TMSI Configuration (TS 24.501 §9.11.3.70). TLV format.
    NasTruncatedFGSTmsiConfiguration
);
nas_ie_tlv!(
    /// UE DS-TT Residence Time (TS 24.501 §9.11.4.27). TLV format.
    NasUeDsTtResidenceTime
);
nas_ie_tlv!(
    /// UE Radio Capability ID (TS 24.501 §9.11.3.68). TLV format.
    NasUeRadioCapabilityId
);
nas_ie_tlv!(
    /// UE Request Type (TS 24.501 §9.11.3.76). TLV format.
    NasUeRequestType
);
nas_ie_tlv!(
    /// UE Status (TS 24.501 §9.11.3.56). TLV format.
    NasUeStatus
);
nas_ie_tlv!(
    /// UE Usage Setting (TS 24.501 §9.11.3.55). TLV format.
    NasUeUsageSetting
);
nas_ie_tlv!(
    /// Uplink Data Status (TS 24.501 §9.11.3.57). TLV format.
    NasUplinkDataStatus
);
nas_ie_tlv!(
    /// WUS Assistance Information (TS 24.501 §9.11.3.71). TLV format.
    NasWusAssistanceInformation
);

// ── TLV-E format (optional extended variable-length) ─────────────────────────

nas_ie_tlve!(
    /// ATSSS Container (TS 24.501 §9.11.4.22A). TLV-E format.
    NasAtsssContainer
);
nas_ie_tlve!(
    /// CAG Information List (TS 24.501 §9.11.3.18A). TLV-E format.
    NasCagInformationList
);
nas_ie_tlve!(
    /// Ciphering Key Data (TS 24.501 §9.11.3.18C). TLV-E format.
    NasCipheringKeyData
);
nas_ie_tlve!(
    /// EAP Message (TS 24.501 §9.11.2.2). TLV-E format.
    NasEapMessage
);
nas_ie_tlve!(
    /// EPS NAS Message Container (TS 24.501 §9.11.3.24). TLV-E format.
    NasEpsNasMessageContainer
);
nas_ie_tlve!(
    /// Extended CAG Information List (TS 24.501 §9.11.3.86). TLV-E format.
    NasExtendedCagInformationList
);
nas_ie_tlve!(
    /// Extended Emergency Number List (TS 24.501 §9.11.3.26). TLV-E format.
    NasExtendedEmergencyNumberList
);
nas_ie_tlve!(
    /// Extended Protocol Configuration Options (TS 24.501 §9.11.4.6). TLV-E format.
    NasExtendedProtocolConfigurationOptions
);
nas_ie_tlve!(
    /// LADN Indication (TS 24.501 §9.11.3.29). TLV-E format.
    NasLadnIndication
);
nas_ie_tlve!(
    /// LADN Information (TS 24.501 §9.11.3.30). TLV-E format.
    NasLadnInformation
);
nas_ie_tlve!(
    /// Mapped EPS Bearer Contexts (TS 24.501 §9.11.4.8). TLV-E format.
    NasMappedEpsBearerContexts
);
nas_ie_tlve!(
    /// NAS Message Container (TS 24.501 §9.11.3.33). TLV-E format.
    NasMessageContainer
);
nas_ie_tlve!(
    /// NSAG Information (TS 24.501 §9.11.3.87). TLV-E format.
    NasNsagInformation
);
nas_ie_tlve!(
    /// NSSRG Information (TS 24.501 §9.11.3.82). TLV-E format.
    NasNssrgInformation
);
nas_ie_tlve!(
    /// Operator-defined Access Category Definitions (TS 24.501 §9.11.3.38). TLV-E format.
    NasOperatorDefinedAccessCategoryDefinitions
);
nas_ie_tlve!(
    /// PDU Session Reactivation Result Error Cause (TS 24.501 §9.11.3.42A). TLV-E format.
    NasPduSessionReactivationResultErrorCause
);
nas_ie_tlve!(
    /// Port Management Information Container (TS 24.501 §9.11.4.29). TLV-E format.
    NasPortManagementInformationContainer
);
nas_ie_tlve!(
    /// QoS Flow Descriptions (TS 24.501 §9.11.4.12). TLV-E format.
    NasQosFlowDescriptions
);
nas_ie_tlve!(
    /// Received MBS Container (TS 24.501 §9.11.4.32). TLV-E format.
    NasReceivedMbsContainer
);
nas_ie_tlve!(
    /// Requested MBS Container (TS 24.501 §9.11.4.33). TLV-E format.
    NasRequestedMbsContainer
);
nas_ie_tlve!(
    /// Service-level-AA Container (TS 24.501 §9.11.2.10). TLV-E format.
    NasServiceLevelAaContainer
);
nas_ie_tlve!(
    /// SOR Transparent Container (TS 24.501 §9.11.3.51). TLV-E format.
    NasSorTransparentContainer
);

// ── Dual-mode (V/TV) — manual impl ──────────────────────────────────────────

/// 5GSM Cause (TS 24.501 &sect;9.11.4.2).
///
/// Dual-mode IE: V format when mandatory (`type_field == 0`), TV format when
/// optional (`type_field != 0`). Use the `cause()` method (defined in the
/// [`ie`](crate::ie) module) for typed access via [`GsmCause`](crate::ie::GsmCause).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsmCause {
    pub type_field: u8,
    pub value: u8,
}

impl NasFGsmCause {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0,
            value,
        }
    }

    /// Decode as a mandatory (V) IE: read value byte only, type_field set to 0.
    pub fn decode_value_only(buffer: &mut Bytes) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            type_field: 0,
            value,
        })
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
