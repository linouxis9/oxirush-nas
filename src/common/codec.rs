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

//! Shared NAS codec traits, errors, and wire helpers.

use bytes::{BufMut, Bytes, BytesMut};
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

    /// The message type byte does not map to a known NAS message.
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
