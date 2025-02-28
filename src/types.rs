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
use std::convert::TryFrom;

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

/// 9.11.2.1 Additional information
/// O TLV 3-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAdditionalInformation {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasAdditionalInformation {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasAdditionalInformation {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Additional information
        // Format: TLV, Length: 3-n
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAdditionalInformation {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Additional information
        // Format: TLV, Length: 3-n
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.2.10 Service-level-AA container
/// O TLV-E 6-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasServiceLevelAaContainer {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasServiceLevelAaContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasServiceLevelAaContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Service-level-AA container
        // Format: TLV-E, Length: 6-n
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasServiceLevelAaContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Service-level-AA container
        // Format: TLV-E, Length: 6-n
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.2.1A Access type
/// M TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAccessType {
    pub type_field: u8,
    pub value: u8,
}

impl NasAccessType {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasAccessType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Access type
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasAccessType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Access type
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.2.1B DNN
/// O TLV 3-102
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasDnn {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasDnn {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasDnn {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for DNN
        // Format: TLV, Length: 3-102
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasDnn {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for DNN
        // Format: TLV, Length: 3-102
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.2.2 EAP message
/// O TLV-E 7-1503
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasEapMessage {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasEapMessage {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasEapMessage {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for EAP message
        // Format: TLV-E, Length: 7-1503
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasEapMessage {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for EAP message
        // Format: TLV-E, Length: 7-1503
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.2.3 GPRS timer
/// O TV 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasGprsTimer {
    pub type_field: u8,
    pub value: u8,
}

impl NasGprsTimer {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasGprsTimer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for GPRS timer
        // Format: TV, Length: 2
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasGprsTimer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for GPRS timer
        // Format: TV, Length: 2
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let value = buffer.get_u8();
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.2.4 GPRS timer 2
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasGprsTimer2 {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasGprsTimer2 {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasGprsTimer2 {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for GPRS timer 2
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasGprsTimer2 {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for GPRS timer 2
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.2.5 GPRS timer 3
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasGprsTimer3 {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasGprsTimer3 {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasGprsTimer3 {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for GPRS timer 3
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasGprsTimer3 {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for GPRS timer 3
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.2.8 S-NSSAI
/// O TLV 3-10
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasSNssai {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasSNssai {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasSNssai {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for S-NSSAI
        // Format: TLV, Length: 3-10
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasSNssai {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for S-NSSAI
        // Format: TLV, Length: 3-10
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.1 5GMM capability
/// O TLV 3-15
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGmmCapability {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGmmCapability {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGmmCapability {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GMM capability
        // Format: TLV, Length: 3-15
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGmmCapability {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GMM capability
        // Format: TLV, Length: 3-15
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.10 ABBA
/// M LV 3-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAbba {
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasAbba {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasAbba {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for ABBA
        // Format: LV, Length: 3-n
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAbba {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for ABBA
        // Format: LV, Length: 3-n
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 1");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            length,
            value,
        })
    }
}

/// 9.11.3.12 Additional 5G security information
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAdditionalFGSecurityInformation {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasAdditionalFGSecurityInformation {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasAdditionalFGSecurityInformation {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Additional 5G security information
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAdditionalFGSecurityInformation {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Additional 5G security information
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.12A Additional information requested
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAdditionalInformationRequested {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasAdditionalInformationRequested {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasAdditionalInformationRequested {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Additional information requested
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAdditionalInformationRequested {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Additional information requested
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.13 Allowed PDU session status
/// O TLV 4-34
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAllowedPduSessionStatus {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasAllowedPduSessionStatus {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasAllowedPduSessionStatus {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Allowed PDU session status
        // Format: TLV, Length: 4-34
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAllowedPduSessionStatus {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Allowed PDU session status
        // Format: TLV, Length: 4-34
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.14 Authentication failure parameter
/// O TLV 16
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAuthenticationFailureParameter {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasAuthenticationFailureParameter {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasAuthenticationFailureParameter {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Authentication failure parameter
        // Format: TLV, Length: 16
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAuthenticationFailureParameter {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Authentication failure parameter
        // Format: TLV, Length: 16
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.15 Authentication parameter AUTN
/// O TLV 18
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAuthenticationParameterAutn {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasAuthenticationParameterAutn {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasAuthenticationParameterAutn {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Authentication parameter AUTN
        // Format: TLV, Length: 18
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAuthenticationParameterAutn {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Authentication parameter AUTN
        // Format: TLV, Length: 18
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.16 Authentication parameter RAND
/// O TV 17
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAuthenticationParameterRand {
    pub type_field: u8,
    pub value: Vec<u8>,
}

impl NasAuthenticationParameterRand {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasAuthenticationParameterRand {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Authentication parameter RAND
        // Format: TV, Length: 17
        buffer.put_u8(self.type_field);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAuthenticationParameterRand {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Authentication parameter RAND
        // Format: TV, Length: 17
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = 16;
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 1");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.17 Authentication response parameter
/// O TLV 18
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAuthenticationResponseParameter {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasAuthenticationResponseParameter {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasAuthenticationResponseParameter {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Authentication response parameter
        // Format: TLV, Length: 18
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAuthenticationResponseParameter {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Authentication response parameter
        // Format: TLV, Length: 18
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.18 Configuration update indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasConfigurationUpdateIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasConfigurationUpdateIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasConfigurationUpdateIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Configuration update indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasConfigurationUpdateIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Configuration update indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.18A CAG information list
/// O TLV-E 3-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasCagInformationList {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasCagInformationList {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasCagInformationList {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for CAG information list
        // Format: TLV-E, Length: 3-n
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasCagInformationList {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for CAG information list
        // Format: TLV-E, Length: 3-n
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.18C Ciphering key data
/// O TLV-E 34-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasCipheringKeyData {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasCipheringKeyData {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasCipheringKeyData {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Ciphering key data
        // Format: TLV-E, Length: 34-n
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasCipheringKeyData {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Ciphering key data
        // Format: TLV-E, Length: 34-n
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.19 Daylight saving time
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasDaylightSavingTime {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasDaylightSavingTime {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasDaylightSavingTime {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Daylight saving time
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasDaylightSavingTime {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Daylight saving time
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.2 5GMM cause
/// M V 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGmmCause {
    pub value: u8,
}

impl NasFGmmCause {
    pub fn new(value: u8) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasFGmmCause {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GMM cause
        // Format: V, Length: 1
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasFGmmCause {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GMM cause
        // Format: V, Length: 1
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            value,
        })
    }
}

/// 9.11.3.20 De-registration type
/// M V 1/2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasDeRegistrationType {
    pub value: u8,
}

impl NasDeRegistrationType {
    pub fn new(value: u8) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasDeRegistrationType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for De-registration type
        // Format: V, Length: 1/2
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasDeRegistrationType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for De-registration type
        // Format: V, Length: 1/2
        if buffer.remaining() < 0 {
        panic!("wanted  0");
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            value,
        })
    }
}

/// 9.11.3.23 Emergency number list
/// O TLV 5-50
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasEmergencyNumberList {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasEmergencyNumberList {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasEmergencyNumberList {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Emergency number list
        // Format: TLV, Length: 5-50
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasEmergencyNumberList {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Emergency number list
        // Format: TLV, Length: 5-50
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.23A EPS bearer context status
/// O TLV 4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasEpsBearerContextStatus {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasEpsBearerContextStatus {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasEpsBearerContextStatus {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for EPS bearer context status
        // Format: TLV, Length: 4
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasEpsBearerContextStatus {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for EPS bearer context status
        // Format: TLV, Length: 4
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.24 EPS NAS message container
/// O TLV-E 4-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasEpsNasMessageContainer {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasEpsNasMessageContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasEpsNasMessageContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for EPS NAS message container
        // Format: TLV-E, Length: 4-n
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasEpsNasMessageContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for EPS NAS message container
        // Format: TLV-E, Length: 4-n
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.25 EPS NAS security algorithms
/// O TV 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasEpsNasSecurityAlgorithms {
    pub type_field: u8,
    pub value: u8,
}

impl NasEpsNasSecurityAlgorithms {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasEpsNasSecurityAlgorithms {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for EPS NAS security algorithms
        // Format: TV, Length: 2
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasEpsNasSecurityAlgorithms {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for EPS NAS security algorithms
        // Format: TV, Length: 2
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let value = buffer.get_u8();
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.26 Extended emergency number list
/// O TLV-E 7-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasExtendedEmergencyNumberList {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasExtendedEmergencyNumberList {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasExtendedEmergencyNumberList {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Extended emergency number list
        // Format: TLV-E, Length: 7-65538
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasExtendedEmergencyNumberList {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Extended emergency number list
        // Format: TLV-E, Length: 7-65538
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.26A Extended DRX parameters
/// O TLV 3-4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasExtendedDrxParameters {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasExtendedDrxParameters {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasExtendedDrxParameters {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Extended DRX parameters
        // Format: TLV, Length: 3-4
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasExtendedDrxParameters {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Extended DRX parameters
        // Format: TLV, Length: 3-4
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.28 IMEISV request
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasImeisvRequest {
    pub type_field: u8,
    pub value: u8,
}

impl NasImeisvRequest {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasImeisvRequest {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for IMEISV request
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasImeisvRequest {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for IMEISV request
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.29 LADN indication
/// O TLV-E 3-811
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasLadnIndication {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasLadnIndication {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasLadnIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for LADN indication
        // Format: TLV-E, Length: 3-811
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasLadnIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for LADN indication
        // Format: TLV-E, Length: 3-811
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.2A 5GS DRX parameters
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsDrxParameters {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsDrxParameters {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsDrxParameters {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS DRX parameters
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsDrxParameters {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS DRX parameters
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.3 5GS identity type
/// M V 1/2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsIdentityType {
    pub value: u8,
}

impl NasFGsIdentityType {
    pub fn new(value: u8) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasFGsIdentityType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS identity type
        // Format: V, Length: 1/2
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasFGsIdentityType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS identity type
        // Format: V, Length: 1/2
        if buffer.remaining() < 0 {
        panic!("wanted  0");
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            value,
        })
    }
}

/// 9.11.3.30 LADN information
/// O TLV-E 12-1715
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasLadnInformation {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasLadnInformation {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasLadnInformation {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for LADN information
        // Format: TLV-E, Length: 12-1715
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasLadnInformation {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for LADN information
        // Format: TLV-E, Length: 12-1715
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.31 MICO indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasMicoIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasMicoIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasMicoIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for MICO indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasMicoIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for MICO indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.31A MA PDU session information
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasMaPduSessionInformation {
    pub type_field: u8,
    pub value: u8,
}

impl NasMaPduSessionInformation {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasMaPduSessionInformation {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for MA PDU session information
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasMaPduSessionInformation {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for MA PDU session information
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.31B Mapped NSSAI
/// O TLV 3-42
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasMappedNssai {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasMappedNssai {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasMappedNssai {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Mapped NSSAI
        // Format: TLV, Length: 3-42
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasMappedNssai {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Mapped NSSAI
        // Format: TLV, Length: 3-42
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.31C Mobile station classmark 2
/// O TLV 5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasMobileStationClassmark2 {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasMobileStationClassmark2 {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasMobileStationClassmark2 {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Mobile station classmark 2
        // Format: TLV, Length: 5
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasMobileStationClassmark2 {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Mobile station classmark 2
        // Format: TLV, Length: 5
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.32 key set identifier
/// O V 1/2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasKeySetIdentifier {
    pub value: u8,
}

impl NasKeySetIdentifier {
    pub fn new(value: u8) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasKeySetIdentifier {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for key set identifier
        // Format: V, Length: 1/2
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasKeySetIdentifier {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for key set identifier
        // Format: V, Length: 1/2
        if buffer.remaining() < 0 {
        panic!("wanted  0");
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            value,
        })
    }
}

/// 9.11.3.33 message container
/// O TLV-E 4-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasMessageContainer {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasMessageContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasMessageContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for message container
        // Format: TLV-E, Length: 4-n
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasMessageContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for message container
        // Format: TLV-E, Length: 4-n
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.34 security algorithms
/// M V 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasSecurityAlgorithms {
    pub value: u8,
}

impl NasSecurityAlgorithms {
    pub fn new(value: u8) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasSecurityAlgorithms {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for security algorithms
        // Format: V, Length: 1
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasSecurityAlgorithms {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for security algorithms
        // Format: V, Length: 1
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            value,
        })
    }
}

/// 9.11.3.35 Network name
/// O TLV 3-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNetworkName {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasNetworkName {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasNetworkName {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Network name
        // Format: TLV, Length: 3-n
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasNetworkName {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Network name
        // Format: TLV, Length: 3-n
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.36 Network slicing indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNetworkSlicingIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasNetworkSlicingIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasNetworkSlicingIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Network slicing indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasNetworkSlicingIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Network slicing indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.36A Non-3GPP NW provided policies
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNon3GppNwProvidedPolicies {
    pub type_field: u8,
    pub value: u8,
}

impl NasNon3GppNwProvidedPolicies {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasNon3GppNwProvidedPolicies {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Non-3GPP NW provided policies
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasNon3GppNwProvidedPolicies {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Non-3GPP NW provided policies
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.37 NSSAI
/// O TLV 4-74
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNssai {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasNssai {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasNssai {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for NSSAI
        // Format: TLV, Length: 4-74
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasNssai {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for NSSAI
        // Format: TLV, Length: 4-74
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.37A NSSAI inclusion mode
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNssaiInclusionMode {
    pub type_field: u8,
    pub value: u8,
}

impl NasNssaiInclusionMode {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasNssaiInclusionMode {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for NSSAI inclusion mode
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasNssaiInclusionMode {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for NSSAI inclusion mode
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.38 Operator-defined access category definitions
/// O TLV-E 3-8323
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasOperatorDefinedAccessCategoryDefinitions {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasOperatorDefinedAccessCategoryDefinitions {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasOperatorDefinedAccessCategoryDefinitions {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Operator-defined access category definitions
        // Format: TLV-E, Length: 3-8323
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasOperatorDefinedAccessCategoryDefinitions {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Operator-defined access category definitions
        // Format: TLV-E, Length: 3-8323
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.39 Payload container
/// O LV-E 4-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPayloadContainer {
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasPayloadContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasPayloadContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Payload container
        // Format: LV-E, Length: 4-65538
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPayloadContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Payload container
        // Format: LV-E, Length: 4-65538
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            length,
            value,
        })
    }
}

/// 9.11.3.4 5GS mobile identity
/// M LV-E 6-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsMobileIdentity {
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasFGsMobileIdentity {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasFGsMobileIdentity {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS mobile identity
        // Format: LV-E, Length: 6-n
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsMobileIdentity {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS mobile identity
        // Format: LV-E, Length: 6-n
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            length,
            value,
        })
    }
}

/// 9.11.3.40 Payload container type
/// O V 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPayloadContainerType {
    pub value: u8,
}

impl NasPayloadContainerType {
    pub fn new(value: u8) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasPayloadContainerType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Payload container type
        // Format: V, Length: 1
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasPayloadContainerType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Payload container type
        // Format: V, Length: 1
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            value,
        })
    }
}

/// 9.11.3.41 PDU session identity 2
/// C TV 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPduSessionIdentity2 {
    pub type_field: u8,
    pub value: u8,
}

impl NasPduSessionIdentity2 {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasPduSessionIdentity2 {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PDU session identity 2
        // Format: TV, Length: 2
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasPduSessionIdentity2 {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PDU session identity 2
        // Format: TV, Length: 2
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let value = buffer.get_u8();
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.42 PDU session reactivation result
/// O TLV 4-34
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPduSessionReactivationResult {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasPduSessionReactivationResult {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasPduSessionReactivationResult {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PDU session reactivation result
        // Format: TLV, Length: 4-34
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPduSessionReactivationResult {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PDU session reactivation result
        // Format: TLV, Length: 4-34
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.43 PDU session reactivation result error cause
/// O TLV-E 5-515
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPduSessionReactivationResultErrorCause {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasPduSessionReactivationResultErrorCause {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasPduSessionReactivationResultErrorCause {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PDU session reactivation result error cause
        // Format: TLV-E, Length: 5-515
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPduSessionReactivationResultErrorCause {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PDU session reactivation result error cause
        // Format: TLV-E, Length: 5-515
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.44 PDU session status
/// O TLV 4-34
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPduSessionStatus {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasPduSessionStatus {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasPduSessionStatus {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PDU session status
        // Format: TLV, Length: 4-34
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPduSessionStatus {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PDU session status
        // Format: TLV, Length: 4-34
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.45 PLMN list
/// O TLV 5-47
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPlmnList {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasPlmnList {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasPlmnList {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PLMN list
        // Format: TLV, Length: 5-47
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPlmnList {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PLMN list
        // Format: TLV, Length: 5-47
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.46 Rejected NSSAI
/// O TLV 4-42
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasRejectedNssai {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasRejectedNssai {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasRejectedNssai {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Rejected NSSAI
        // Format: TLV, Length: 4-42
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasRejectedNssai {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Rejected NSSAI
        // Format: TLV, Length: 4-42
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.46A Release assistance indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasReleaseAssistanceIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasReleaseAssistanceIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasReleaseAssistanceIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Release assistance indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasReleaseAssistanceIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Release assistance indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.47 Request type
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasRequestType {
    pub type_field: u8,
    pub value: u8,
}

impl NasRequestType {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasRequestType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Request type
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasRequestType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Request type
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.48 S1 UE network capability
/// O TLV 4-15
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasS1UeNetworkCapability {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasS1UeNetworkCapability {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasS1UeNetworkCapability {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for S1 UE network capability
        // Format: TLV, Length: 4-15
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasS1UeNetworkCapability {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for S1 UE network capability
        // Format: TLV, Length: 4-15
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.48A S1 UE security capability
/// O TLV 4-7
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasS1UeSecurityCapability {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasS1UeSecurityCapability {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasS1UeSecurityCapability {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for S1 UE security capability
        // Format: TLV, Length: 4-7
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasS1UeSecurityCapability {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for S1 UE security capability
        // Format: TLV, Length: 4-7
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.49 Service area list
/// O TLV 6-114
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasServiceAreaList {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasServiceAreaList {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasServiceAreaList {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Service area list
        // Format: TLV, Length: 6-114
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasServiceAreaList {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Service area list
        // Format: TLV, Length: 6-114
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.5 5GS network feature support
/// O TLV 3-5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsNetworkFeatureSupport {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsNetworkFeatureSupport {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsNetworkFeatureSupport {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS network feature support
        // Format: TLV, Length: 3-5
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsNetworkFeatureSupport {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS network feature support
        // Format: TLV, Length: 3-5
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.50A SMS indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasSmsIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasSmsIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasSmsIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for SMS indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasSmsIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for SMS indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.51 SOR transparent container
/// O TLV-E 20-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasSorTransparentContainer {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasSorTransparentContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasSorTransparentContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for SOR transparent container
        // Format: TLV-E, Length: 20-n
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasSorTransparentContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for SOR transparent container
        // Format: TLV-E, Length: 20-n
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.51A Supported codec list
/// O TLV 5-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasSupportedCodecList {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasSupportedCodecList {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasSupportedCodecList {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Supported codec list
        // Format: TLV, Length: 5-n
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasSupportedCodecList {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Supported codec list
        // Format: TLV, Length: 5-n
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.52 Time zone
/// O TV 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasTimeZone {
    pub type_field: u8,
    pub value: u8,
}

impl NasTimeZone {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasTimeZone {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Time zone
        // Format: TV, Length: 2
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasTimeZone {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Time zone
        // Format: TV, Length: 2
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let value = buffer.get_u8();
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.53 Time zone and time
/// O TV 8
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasTimeZoneAndTime {
    pub type_field: u8,
    pub value: Vec<u8>,
}

impl NasTimeZoneAndTime {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasTimeZoneAndTime {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Time zone and time
        // Format: TV, Length: 8
        buffer.put_u8(self.type_field);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasTimeZoneAndTime {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Time zone and time
        // Format: TV, Length: 8
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = 7;
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 1");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.54 UE security capability
/// O LV 4-10
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasUeSecurityCapability {
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasUeSecurityCapability {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasUeSecurityCapability {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for UE security capability
        // Format: LV, Length: 4-10
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasUeSecurityCapability {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for UE security capability
        // Format: LV, Length: 4-10
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 1");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            length,
            value,
        })
    }
}

/// 9.11.3.55 UE usage setting
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasUeUsageSetting {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasUeUsageSetting {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasUeUsageSetting {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for UE usage setting
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasUeUsageSetting {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for UE usage setting
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.56 UE status
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasUeStatus {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasUeStatus {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasUeStatus {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for UE status
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasUeStatus {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for UE status
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.57 Uplink data status
/// O TLV 4-34
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasUplinkDataStatus {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasUplinkDataStatus {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasUplinkDataStatus {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Uplink data status
        // Format: TLV, Length: 4-34
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasUplinkDataStatus {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Uplink data status
        // Format: TLV, Length: 4-34
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.6 5GS registration result
/// M LV 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsRegistrationResult {
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsRegistrationResult {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsRegistrationResult {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS registration result
        // Format: LV, Length: 2
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsRegistrationResult {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS registration result
        // Format: LV, Length: 2
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 1");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            length,
            value,
        })
    }
}

/// 9.11.3.68 UE radio capability ID
/// O TLV 3-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasUeRadioCapabilityId {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasUeRadioCapabilityId {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasUeRadioCapabilityId {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for UE radio capability ID
        // Format: TLV, Length: 3-n
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasUeRadioCapabilityId {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for UE radio capability ID
        // Format: TLV, Length: 3-n
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.69 UE radio capability ID deletion indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasUeRadioCapabilityIdDeletionIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasUeRadioCapabilityIdDeletionIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasUeRadioCapabilityIdDeletionIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for UE radio capability ID deletion indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasUeRadioCapabilityIdDeletionIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for UE radio capability ID deletion indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.7 5GS registration type
/// M V 1/2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsRegistrationType {
    pub value: u8,
}

impl NasFGsRegistrationType {
    pub fn new(value: u8) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasFGsRegistrationType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS registration type
        // Format: V, Length: 1/2
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasFGsRegistrationType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS registration type
        // Format: V, Length: 1/2
        if buffer.remaining() < 0 {
        panic!("wanted  0");
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u8();
        Ok(Self {
            value,
        })
    }
}

/// 9.11.3.70 Truncated 5G-S-TMSI configuration
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasTruncatedFGSTmsiConfiguration {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasTruncatedFGSTmsiConfiguration {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasTruncatedFGSTmsiConfiguration {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Truncated 5G-S-TMSI configuration
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasTruncatedFGSTmsiConfiguration {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Truncated 5G-S-TMSI configuration
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.71 WUS assistance information
/// O TLV 3-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasWusAssistanceInformation {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasWusAssistanceInformation {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasWusAssistanceInformation {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for WUS assistance information
        // Format: TLV, Length: 3-n
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasWusAssistanceInformation {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for WUS assistance information
        // Format: TLV, Length: 3-n
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.72 N5GC indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNFGcIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasNFGcIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasNFGcIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for N5GC indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasNFGcIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for N5GC indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.73 NB-N1 mode DRX parameters
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNbN1ModeDrxParameters {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasNbN1ModeDrxParameters {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasNbN1ModeDrxParameters {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for NB-N1 mode DRX parameters
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasNbN1ModeDrxParameters {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for NB-N1 mode DRX parameters
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.74 Additional configuration indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAdditionalConfigurationIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasAdditionalConfigurationIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasAdditionalConfigurationIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Additional configuration indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasAdditionalConfigurationIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Additional configuration indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.75 Extended rejected NSSAI
/// O TLV 5-90
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasExtendedRejectedNssai {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasExtendedRejectedNssai {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasExtendedRejectedNssai {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Extended rejected NSSAI
        // Format: TLV, Length: 5-90
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasExtendedRejectedNssai {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Extended rejected NSSAI
        // Format: TLV, Length: 5-90
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.76 UE request type
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasUeRequestType {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasUeRequestType {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasUeRequestType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for UE request type
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasUeRequestType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for UE request type
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.77 Paging restriction
/// O TLV 3-35
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPagingRestriction {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasPagingRestriction {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasPagingRestriction {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Paging restriction
        // Format: TLV, Length: 3-35
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPagingRestriction {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Paging restriction
        // Format: TLV, Length: 3-35
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.79 NID
/// O TLV 8
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNid {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasNid {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasNid {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for NID
        // Format: TLV, Length: 8
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasNid {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for NID
        // Format: TLV, Length: 8
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.8 5GS tracking area identity
/// O TV 7
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsTrackingAreaIdentity {
    pub type_field: u8,
    pub value: Vec<u8>,
}

impl NasFGsTrackingAreaIdentity {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasFGsTrackingAreaIdentity {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS tracking area identity
        // Format: TV, Length: 7
        buffer.put_u8(self.type_field);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsTrackingAreaIdentity {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS tracking area identity
        // Format: TV, Length: 7
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = 6;
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 1");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.80 PEIPS assistance information
/// O TLV 3-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPeipsAssistanceInformation {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasPeipsAssistanceInformation {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasPeipsAssistanceInformation {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PEIPS assistance information
        // Format: TLV, Length: 3-n
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPeipsAssistanceInformation {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PEIPS assistance information
        // Format: TLV, Length: 3-n
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.81 5GS additional request result
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsAdditionalRequestResult {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsAdditionalRequestResult {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsAdditionalRequestResult {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS additional request result
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsAdditionalRequestResult {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS additional request result
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.82 NSSRG information
/// O TLV-E 7-4099
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNssrgInformation {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasNssrgInformation {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasNssrgInformation {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for NSSRG information
        // Format: TLV-E, Length: 7-4099
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasNssrgInformation {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for NSSRG information
        // Format: TLV-E, Length: 7-4099
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.83 List of PLMNs to be used in disaster condition
/// O TLV 2-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasListOfPlmnsToBeUsedInDisasterCondition {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasListOfPlmnsToBeUsedInDisasterCondition {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasListOfPlmnsToBeUsedInDisasterCondition {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for List of PLMNs to be used in disaster condition
        // Format: TLV, Length: 2-n
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasListOfPlmnsToBeUsedInDisasterCondition {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for List of PLMNs to be used in disaster condition
        // Format: TLV, Length: 2-n
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.84 Registration wait range
/// O TLV 4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasRegistrationWaitRange {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasRegistrationWaitRange {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasRegistrationWaitRange {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Registration wait range
        // Format: TLV, Length: 4
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasRegistrationWaitRange {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Registration wait range
        // Format: TLV, Length: 4
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.85 PLMN identity
/// O TLV 5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPlmnIdentity {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasPlmnIdentity {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasPlmnIdentity {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PLMN identity
        // Format: TLV, Length: 5
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPlmnIdentity {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PLMN identity
        // Format: TLV, Length: 5
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.86 Extended CAG information list
/// O TLV-E 3-n
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasExtendedCagInformationList {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasExtendedCagInformationList {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasExtendedCagInformationList {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Extended CAG information list
        // Format: TLV-E, Length: 3-n
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasExtendedCagInformationList {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Extended CAG information list
        // Format: TLV-E, Length: 3-n
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.87 NSAG information
/// O TLV-E 9-3143
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasNsagInformation {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasNsagInformation {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasNsagInformation {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for NSAG information
        // Format: TLV-E, Length: 9-3143
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasNsagInformation {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for NSAG information
        // Format: TLV-E, Length: 9-3143
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.9 5GS tracking area identity list
/// O TLV 9-114
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsTrackingAreaIdentityList {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsTrackingAreaIdentityList {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsTrackingAreaIdentityList {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS tracking area identity list
        // Format: TLV, Length: 9-114
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsTrackingAreaIdentityList {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS tracking area identity list
        // Format: TLV, Length: 9-114
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.3.91 Priority indicator
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPriorityIndicator {
    pub type_field: u8,
    pub value: u8,
}

impl NasPriorityIndicator {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasPriorityIndicator {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Priority indicator
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasPriorityIndicator {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Priority indicator
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.3.9A 5GS update type
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsUpdateType {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsUpdateType {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsUpdateType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GS update type
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsUpdateType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GS update type
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.1 5GSM capability
/// O TLV 3-15
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsmCapability {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsmCapability {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsmCapability {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GSM capability
        // Format: TLV, Length: 3-15
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsmCapability {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GSM capability
        // Format: TLV, Length: 3-15
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.10 PDU address
/// O TLV 11
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPduAddress {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasPduAddress {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasPduAddress {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PDU address
        // Format: TLV, Length: 11
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPduAddress {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PDU address
        // Format: TLV, Length: 11
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.11 PDU session type
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPduSessionType {
    pub type_field: u8,
    pub value: u8,
}

impl NasPduSessionType {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasPduSessionType {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PDU session type
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasPduSessionType {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PDU session type
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.4.12 QoS flow descriptions
/// O TLV-E 6-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasQosFlowDescriptions {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasQosFlowDescriptions {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasQosFlowDescriptions {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for QoS flow descriptions
        // Format: TLV-E, Length: 6-65538
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasQosFlowDescriptions {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for QoS flow descriptions
        // Format: TLV-E, Length: 6-65538
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.13 QoS rules
/// M LV-E 6-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasQosRules {
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasQosRules {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasQosRules {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for QoS rules
        // Format: LV-E, Length: 6-65538
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasQosRules {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for QoS rules
        // Format: LV-E, Length: 6-65538
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            length,
            value,
        })
    }
}

/// 9.11.4.14 Session-AMBR
/// M LV 7
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasSessionAmbr {
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasSessionAmbr {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasSessionAmbr {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Session-AMBR
        // Format: LV, Length: 7
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasSessionAmbr {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Session-AMBR
        // Format: LV, Length: 7
        if buffer.remaining() < 1 {
        panic!("wanted  1");
            return Err(NasError::BufferTooShort);
        }
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 1");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            length,
            value,
        })
    }
}

/// 9.11.4.15 SM PDU DN request container
/// O TLV 3-255
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasSmPduDnRequestContainer {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasSmPduDnRequestContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasSmPduDnRequestContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for SM PDU DN request container
        // Format: TLV, Length: 3-255
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasSmPduDnRequestContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for SM PDU DN request container
        // Format: TLV, Length: 3-255
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.16 SSC mode
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasSscMode {
    pub type_field: u8,
    pub value: u8,
}

impl NasSscMode {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasSscMode {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for SSC mode
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasSscMode {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for SSC mode
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.4.17 Re-attempt indicator
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasReAttemptIndicator {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasReAttemptIndicator {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasReAttemptIndicator {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Re-attempt indicator
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasReAttemptIndicator {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Re-attempt indicator
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.18 5GSM network feature support
/// O TLV 3-15
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsmNetworkFeatureSupport {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsmNetworkFeatureSupport {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsmNetworkFeatureSupport {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GSM network feature support
        // Format: TLV, Length: 3-15
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsmNetworkFeatureSupport {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GSM network feature support
        // Format: TLV, Length: 3-15
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.2 5GSM cause
/// O TV 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsmCause {
    pub type_field: u8,
    pub value: u8,
}

impl NasFGsmCause {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasFGsmCause {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GSM cause
        // Format: TV, Length: 2
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.value);
        Ok(())
    }
}

impl Decode for NasFGsmCause {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GSM cause
        // Format: TV, Length: 2
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let value = buffer.get_u8();
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.4.20 Serving PLMN rate control
/// O TLV 4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasServingPlmnRateControl {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasServingPlmnRateControl {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasServingPlmnRateControl {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Serving PLMN rate control
        // Format: TLV, Length: 4
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasServingPlmnRateControl {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Serving PLMN rate control
        // Format: TLV, Length: 4
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.21 5GSM congestion re-attempt indicator
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasFGsmCongestionReAttemptIndicator {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasFGsmCongestionReAttemptIndicator {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasFGsmCongestionReAttemptIndicator {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for 5GSM congestion re-attempt indicator
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasFGsmCongestionReAttemptIndicator {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for 5GSM congestion re-attempt indicator
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.22 ATSSS container
/// O TLV-E 3-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAtsssContainer {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasAtsssContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasAtsssContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for ATSSS container
        // Format: TLV-E, Length: 3-65538
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasAtsssContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for ATSSS container
        // Format: TLV-E, Length: 3-65538
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.23 Control plane only indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasControlPlaneOnlyIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasControlPlaneOnlyIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasControlPlaneOnlyIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Control plane only indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasControlPlaneOnlyIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Control plane only indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.4.24 IP header compression configuration
/// O TLV 5-257
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasIpHeaderCompressionConfiguration {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasIpHeaderCompressionConfiguration {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasIpHeaderCompressionConfiguration {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for IP header compression configuration
        // Format: TLV, Length: 5-257
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasIpHeaderCompressionConfiguration {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for IP header compression configuration
        // Format: TLV, Length: 5-257
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.24 Header compression configuration
/// O TLV 5-257
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasHeaderCompressionConfiguration {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasHeaderCompressionConfiguration {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasHeaderCompressionConfiguration {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Header compression configuration
        // Format: TLV, Length: 5-257
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasHeaderCompressionConfiguration {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Header compression configuration
        // Format: TLV, Length: 5-257
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.25 DS-TT Ethernet port MAC address
/// O TLV 8
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasDsTtEthernetPortMacAddress {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasDsTtEthernetPortMacAddress {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasDsTtEthernetPortMacAddress {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for DS-TT Ethernet port MAC address
        // Format: TLV, Length: 8
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasDsTtEthernetPortMacAddress {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for DS-TT Ethernet port MAC address
        // Format: TLV, Length: 8
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.26 UE-DS-TT residence time
/// O TLV 10
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasUeDsTtResidenceTime {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasUeDsTtResidenceTime {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasUeDsTtResidenceTime {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for UE-DS-TT residence time
        // Format: TLV, Length: 10
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasUeDsTtResidenceTime {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for UE-DS-TT residence time
        // Format: TLV, Length: 10
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.27 Port management information container
/// O TLV-E 8-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPortManagementInformationContainer {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasPortManagementInformationContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasPortManagementInformationContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Port management information container
        // Format: TLV-E, Length: 8-65538
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPortManagementInformationContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Port management information container
        // Format: TLV-E, Length: 8-65538
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.28 Ethernet header compression configuration
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasEthernetHeaderCompressionConfiguration {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasEthernetHeaderCompressionConfiguration {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasEthernetHeaderCompressionConfiguration {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Ethernet header compression configuration
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasEthernetHeaderCompressionConfiguration {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Ethernet header compression configuration
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.3 Always-on PDU session indication
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAlwaysOnPduSessionIndication {
    pub type_field: u8,
    pub value: u8,
}

impl NasAlwaysOnPduSessionIndication {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasAlwaysOnPduSessionIndication {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Always-on PDU session indication
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasAlwaysOnPduSessionIndication {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Always-on PDU session indication
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.4.30 Requested MBS container
/// O TLV-E 8-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasRequestedMbsContainer {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasRequestedMbsContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasRequestedMbsContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Requested MBS container
        // Format: TLV-E, Length: 8-65538
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasRequestedMbsContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Requested MBS container
        // Format: TLV-E, Length: 8-65538
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.31 Received MBS container
/// O TLV-E 9-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasReceivedMbsContainer {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasReceivedMbsContainer {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasReceivedMbsContainer {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Received MBS container
        // Format: TLV-E, Length: 9-65538
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasReceivedMbsContainer {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Received MBS container
        // Format: TLV-E, Length: 9-65538
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.32 PDU session pair ID
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasPduSessionPairId {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasPduSessionPairId {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasPduSessionPairId {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for PDU session pair ID
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasPduSessionPairId {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for PDU session pair ID
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.33 RSN
/// O TLV 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasRsn {
    pub type_field: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

impl NasRsn {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u8,
            value,
        }
    }
}

impl Encode for NasRsn {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for RSN
        // Format: TLV, Length: 3
        buffer.put_u8(self.type_field);
        buffer.put_u8(self.length);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasRsn {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for RSN
        // Format: TLV, Length: 3
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let length = buffer.get_u8();
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 2");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.4 Always-on PDU session requested
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAlwaysOnPduSessionRequested {
    pub type_field: u8,
    pub value: u8,
}

impl NasAlwaysOnPduSessionRequested {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasAlwaysOnPduSessionRequested {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Always-on PDU session requested
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasAlwaysOnPduSessionRequested {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Always-on PDU session requested
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.4.5 Allowed SSC mode
/// O TV 1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasAllowedSscMode {
    pub type_field: u8,
    pub value: u8,
}

impl NasAllowedSscMode {
    pub fn new(value: u8) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            value,
        }
    }
}

impl Encode for NasAllowedSscMode {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Allowed SSC mode
        // Format: TV, Length: 1
                buffer.put_u8((self.type_field) | (self.value));
        Ok(())
    }
}

impl Decode for NasAllowedSscMode {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Allowed SSC mode
        // Format: TV, Length: 1
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let byte = buffer.get_u8();
        let type_field = byte >> 4;
        let value = byte & 0x0F;
        Ok(Self {
            type_field,
            value,
        })
    }
}

/// 9.11.4.6 Extended protocol configuration options
/// O TLV-E 4-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasExtendedProtocolConfigurationOptions {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasExtendedProtocolConfigurationOptions {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasExtendedProtocolConfigurationOptions {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Extended protocol configuration options
        // Format: TLV-E, Length: 4-65538
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasExtendedProtocolConfigurationOptions {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Extended protocol configuration options
        // Format: TLV-E, Length: 4-65538
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.7 Integrity protection maximum data rate
/// M V 2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasIntegrityProtectionMaximumDataRate {
    pub value: u16,
}

impl NasIntegrityProtectionMaximumDataRate {
    pub fn new(value: u16) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasIntegrityProtectionMaximumDataRate {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Integrity protection maximum data rate
        // Format: V, Length: 2
        buffer.put_u16(self.value);
        Ok(())
    }
}

impl Decode for NasIntegrityProtectionMaximumDataRate {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Integrity protection maximum data rate
        // Format: V, Length: 2
        if buffer.remaining() < 2 {
        panic!("wanted  2");
            return Err(NasError::BufferTooShort);
        }
        let value = buffer.get_u16();
        Ok(Self {
            value,
        })
    }
}

/// 9.11.4.8 Mapped EPS bearer contexts
/// O TLV-E 7-65538
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasMappedEpsBearerContexts {
    pub type_field: u8,
    pub length: u16,
    pub value: Vec<u8>,
}

impl NasMappedEpsBearerContexts {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            type_field: 0, // Will be set during encoding
            length: value.len() as u16, // probably BE endianness
            value,
        }
    }
}

impl Encode for NasMappedEpsBearerContexts {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Mapped EPS bearer contexts
        // Format: TLV-E, Length: 7-65538
        buffer.put_u8(self.type_field);
        let length_bytes = helpers::u16_to_be16(self.length);
        buffer.put_slice(&length_bytes);
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasMappedEpsBearerContexts {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Mapped EPS bearer contexts
        // Format: TLV-E, Length: 7-65538
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let type_field = buffer.get_u8();
        let mut length_bytes = [0u8; 2];
        buffer.copy_to_slice(&mut length_bytes);
        let length = helpers::be16_to_u16(length_bytes);
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            type_field,
            length,
            value,
        })
    }
}

/// 9.11.4.9 Maximum number of supported packet filters
/// O V 3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NasMaximumNumberOfSupportedPacketFilters {
    pub value: Vec<u8>,
}

impl NasMaximumNumberOfSupportedPacketFilters {
    pub fn new(value: Vec<u8>) -> Self {
        Self {
            value,
        }
    }
}

impl Encode for NasMaximumNumberOfSupportedPacketFilters {
    fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
        // Custom encoding for Maximum number of supported packet filters
        // Format: V, Length: 3
        buffer.put_slice(&self.value);
        Ok(())
    }
}

impl Decode for NasMaximumNumberOfSupportedPacketFilters {
    fn decode(buffer: &mut Bytes) -> Result<Self> {
        // Custom decoding for Maximum number of supported packet filters
        // Format: V, Length: 3
        if buffer.remaining() < 3 {
        panic!("wanted  3");
            return Err(NasError::BufferTooShort);
        }
        let length = 3;
        if buffer.remaining() < length as usize {
        panic!("wanted in vec 3");
            return Err(NasError::BufferTooShort);
        }
        let mut value = vec![0; length as usize];
        buffer.copy_to_slice(&mut value);
        Ok(Self {
            value,
        })
    }
}

