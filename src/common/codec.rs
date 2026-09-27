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
///
/// The structured variants map to the receiver actions of TS 24.301 and
/// TS 24.501 chapter 7: a message that is too short or has an unknown
/// protocol discriminator is ignored (§7.2, TS 24.007 §11.2.3.1.1), an
/// unknown message type is answered with a STATUS message carrying cause #97
/// (§7.4), and an invalid mandatory IE with cause #96 (§7.5).
#[non_exhaustive]
#[derive(Error, Debug, Clone, PartialEq, Eq)]
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

    /// The PDU is shorter than its header (§7.2).
    #[error("Message too short")]
    MessageTooShort,

    /// The protocol discriminator is not one this codec handles.
    #[error("Unknown protocol discriminator: {0}")]
    UnknownProtocolDiscriminator(u8),

    /// The security header type is reserved (Table 9.3.1).
    #[error("Reserved security header type: {0}")]
    ReservedSecurityHeaderType(u8),

    /// The session management message type is unknown. The header
    /// identities are kept for the STATUS message (§7.4): the EPS bearer
    /// identity or PDU session identity, and the PTI.
    #[error(
        "Unknown session management message type {message_type} (identity {identity}, PTI {pti})"
    )]
    UnknownSessionMessageType {
        /// EPS bearer identity or PDU session identity.
        identity: u8,
        /// Procedure transaction identity.
        pti: u8,
        /// Message type octet.
        message_type: u8,
    },

    /// A mandatory IE is missing or syntactically incorrect (§7.5.1).
    #[error("Invalid mandatory IE: {0}")]
    InvalidMandatoryIe(&'static str),

    /// The NAS MAC does not match. The COUNTs are unchanged. TS 24.301 and
    /// TS 24.501 §4.4.4.3 still let a receiver process some messages, such
    /// as ATTACH REQUEST, from an integrity-only envelope: decode the PDU
    /// without the security context to do so.
    #[error("NAS MAC verification failed")]
    IntegrityCheckFailed,
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
