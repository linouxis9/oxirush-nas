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

//! Shared NAS codec traits, errors, and wire helpers.

use crate::common::names::printed;
use crate::prelude::*;
use core::fmt;
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
    /// The octets end before the value that is read from them does: an IE
    /// or a part of one that is decoded alone is cut short.
    #[error("the octets end before the value does")]
    BufferTooShort,

    /// The message type octet is not that of a message of the sublayer
    /// (§7.4).
    #[error("unknown message type {0:#04x}")]
    UnknownMessageType(u8),

    /// What is to be encoded has no octets: a value that its field cannot
    /// hold, a header that is not that of its message, or a view or a tree
    /// that does not describe a message.
    #[error("cannot encode: {0}")]
    EncodingError(String),

    /// The octets are not those of what is decoded.
    #[error("cannot decode: {0}")]
    DecodingError(String),

    /// The message is shorter than its header (§7.2).
    #[error("the message is too short: it ends inside its header")]
    MessageTooShort,

    /// The first octet of the message does not have a protocol discriminator
    /// that the decoder handles: an extended protocol discriminator of 5GMM
    /// (0x7e) or 5GSM (0x2e) for `nas_5gs`, a protocol discriminator of EMM
    /// (7) or ESM (2) in bits 4 to 1 for `nas_eps`. The octet is kept.
    #[error("{}", unknown_protocol_discriminator(*.0))]
    UnknownProtocolDiscriminator(u8),

    /// The security header type is reserved (Table 9.3.1).
    #[error("reserved security header type {0}")]
    ReservedSecurityHeaderType(u8),

    /// The session management message type is unknown. The header
    /// identities are kept for the STATUS message (§7.4): the EPS bearer
    /// identity or PDU session identity, and the PTI.
    #[error(
        "unknown session management message type {message_type:#04x} (identity {identity}, PTI {pti})"
    )]
    UnknownSessionMessageType {
        /// EPS bearer identity or PDU session identity.
        identity: u8,
        /// Procedure transaction identity.
        pti: u8,
        /// Message type octet.
        message_type: u8,
    },

    /// The PDU session identity of a 5GSM message is reserved (16 to 255,
    /// TS 24.501 §9.4). The header identities and message type are kept: the
    /// network answers a PDU SESSION MODIFICATION REQUEST or PDU SESSION
    /// RELEASE REQUEST with a reject carrying cause #43 and that PTI, and
    /// ignores other messages; the UE ignores the message (§7.3.2).
    #[error(
        "reserved PDU session identity {identity} (PTI {pti}, message type {message_type:#04x})"
    )]
    ReservedPduSessionIdentity {
        /// PDU session identity.
        identity: u8,
        /// Procedure transaction identity.
        pti: u8,
        /// Message type octet.
        message_type: u8,
    },

    /// A mandatory IE is missing or syntactically incorrect (§7.5.1). `ie`
    /// is the field of the message struct, and `fault` what is wrong with
    /// it.
    #[error("mandatory IE `{}` {fault}", printed(.ie))]
    InvalidMandatoryIe {
        /// The field of the message struct that the IE is decoded into.
        ie: &'static str,
        /// What is wrong with the IE.
        fault: IeFault,
    },

    /// An unknown IE that is encoded as "comprehension required" is cut
    /// short: the message ends inside it, and nothing tells where it ends.
    /// It is answered as an invalid mandatory IE is (§7.5.1 and §7.6.1).
    #[error(
        "an unknown IE {iei:#04x}, which is encoded as \"comprehension required\", is cut \
         short: the message ends {octets} octet{} after its start",
        if *.octets == 1 { "" } else { "s" }
    )]
    UnknownIeCutShort {
        /// The IEI of the IE.
        iei: u8,
        /// The octets from the IEI to the end of the message.
        octets: usize,
    },

    /// Every NAS COUNT of the direction was used with the keys of the
    /// security context: it protects and verifies nothing more in that
    /// direction, and the network activates new keys before this happens
    /// (TS 24.501 and TS 24.301 §4.4.3.5).
    #[error("every NAS COUNT of the direction was used with these keys")]
    NasCountExhausted,

    /// The message authentication code is right, and the message under it
    /// is refused for the reason `error`: it does not decode, or it is not
    /// one that its security header type or its direction protects. Its NAS
    /// COUNT is used, as that of every message whose code is right
    /// (TS 24.501 and TS 24.301 §4.4.3.3). `plain` is the message under the
    /// security header, deciphered, which a receiver logs and answers:
    /// `answer_to_refused` reads it.
    #[error("the message is authentic and is refused: {error}")]
    AuthenticMessageRefused {
        /// Why the plain message is refused.
        #[source]
        error: Box<NasError>,
        /// The octets of the plain message.
        plain: Box<[u8]>,
    },

    /// The NAS MAC does not match. The COUNTs are unchanged. TS 24.301 and
    /// TS 24.501 §4.4.4.3 still let a receiver process some messages, such
    /// as ATTACH REQUEST, from an integrity-only envelope: decode the PDU
    /// without the security context to do so.
    #[error("the message authentication code does not match")]
    IntegrityCheckFailed,
}

/// A function that builds the IEs of a message and encodes it has one
/// error: `?` takes what a constructor refuses as what is not encoded.
///
/// ```
/// use oxirush_nas::nas_5gs::*;
///
/// fn reject(t3346: u64) -> Result<Vec<u8>, NasError> {
///     let mut reject = NasRegistrationReject::new(NasFGmmCause::from_cause(GmmCause::Congestion));
///     reject.set_t3346_value(NasGprsTimer2::from_seconds(t3346)?);
///     Nas5gsMessage::new_5gmm(reject).encode()
/// }
/// assert_eq!(reject(600).unwrap(), [0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x2a]);
/// assert_eq!(
///     reject(601).unwrap_err().to_string(),
///     "cannot encode: `seconds` is 601, and is up to 31 times 2 seconds, 1 minute or 6 minutes"
/// );
/// ```
impl From<crate::common::ValueError> for NasError {
    fn from(error: crate::common::ValueError) -> Self {
        Self::EncodingError(error.to_string())
    }
}

/// What is wrong with a mandatory IE that a message cannot be decoded
/// without.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IeFault {
    /// The message ends before the IE.
    Missing,
    /// The message ends inside the IE.
    Truncated,
    /// The IE is shorter than the message table lets it be.
    TooShort,
    /// The value of the IE is syntactically incorrect.
    Syntax,
}

impl fmt::Display for IeFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Missing => "is missing: the message ends before it",
            Self::Truncated => "is cut short: the message ends inside it",
            Self::TooShort => "is shorter than its message allows",
            Self::Syntax => "has a value that is syntactically incorrect",
        })
    }
}

/// The text of [`NasError::UnknownProtocolDiscriminator`]: an octet that
/// starts a message of the other system says which decoder reads it.
fn unknown_protocol_discriminator(octet: u8) -> String {
    let other = match (octet, octet & 0x0f) {
        (0x7e, _) => " of a 5GMM message: decode it with `nas_5gs`",
        (0x2e, _) => " of a 5GSM message: decode it with `nas_5gs`",
        (_, 7) => {
            ", which has the protocol discriminator of an EMM message: decode it with `nas_eps`"
        }
        (_, 2) => {
            ", which has the protocol discriminator of an ESM message: decode it with `nas_eps`"
        }
        _ => "",
    };
    match octet {
        0x7e | 0x2e => format!(
            "unknown protocol discriminator: the first octet is {octet:#04x}, the extended protocol discriminator{other}"
        ),
        _ => format!("unknown protocol discriminator: the first octet is {octet:#04x}{other}"),
    }
}

/// Result type for NAS operations
pub type Result<T> = core::result::Result<T, NasError>;

/// Encode a NAS IE or message.
///
/// A message encodes to its octets, header first. An IE encodes as it is in
/// a message without its IEI: its length indicator, if its format has one,
/// and its value (TS 24.007 §11.2.1.1). The IEI of an optional IE is that of
/// the message table, which the message writes.
pub trait Encode {
    /// Append the octets of `self` to `out`.
    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()>;

    /// The octets of `self`.
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.encode_into(&mut out)?;
        Ok(out)
    }
}

/// Decode a NAS IE or message: what [`Encode`] writes.
pub trait Decode: Sized {
    /// Read `Self` from the front of `input`, which is left at the octets
    /// that follow it.
    fn decode_from(input: &mut &[u8]) -> Result<Self>;

    /// The value that `octets` are, all of them: octets that follow it are
    /// an error.
    fn decode(mut octets: &[u8]) -> Result<Self> {
        let value = Self::decode_from(&mut octets)?;
        match octets.len() {
            0 => Ok(value),
            more => Err(trailing(more)),
        }
    }

    /// Read `Self` from the front of `input` as [`Self::decode_from`] does,
    /// and keep what it refuses of a mandatory IE that has its octets: the
    /// IE comes back as it is, and the refusal is added to `faults`, the
    /// [`NasError::InvalidMandatoryIe`] that `decode_from` returns for it.
    /// A message does this for its mandatory IEs, so that a receiver can
    /// read the rest of a message that it is to reject (TS 24.501 and
    /// TS 24.301 §7.5); a type that has none decodes as `decode_from`.
    fn decode_lenient_from(input: &mut &[u8], faults: &mut Vec<NasError>) -> Result<Self> {
        let _ = faults;
        Self::decode_from(input)
    }
}

/// What a receiver takes beyond the rules of TS 24.501 and TS 24.301, from
/// a peer that does not follow them: [`Nas5gsMessage::decode_with`] and
/// [`NasEpsMessage::decode_with`] read a message by them.
///
/// [`Nas5gsMessage::decode_with`]: crate::nas_5gs::Nas5gsMessage::decode_with
/// [`NasEpsMessage::decode_with`]: crate::nas_eps::NasEpsMessage::decode_with
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeOptions {
    /// Take a known optional IE that comes after one that the message
    /// table places after it, where §7.6.2 has a receiver ignore it, as
    /// other implementations do: `validate()` reports each one as out of the
    /// order of the table, and the message is encoded in the order it came.
    pub out_of_sequence: bool,
}

impl DecodeOptions {
    /// The rules of the specifications, which [`Decode::decode`] follows.
    pub const STRICT: Self = Self {
        out_of_sequence: false,
    };

    /// These options, taking the known optional IEs out of sequence too.
    pub const fn with_out_of_sequence(self) -> Self {
        Self {
            out_of_sequence: true,
        }
    }
}

/// How a decoder reads a message: what it does with a mandatory IE that has
/// its octets and is not one of its type (without a list it refuses the
/// message, and with one it keeps the IE and adds the refusal to the list),
/// and the options of a receiver.
pub(crate) struct Reading<'b> {
    pub(crate) faults: Option<&'b mut Vec<NasError>>,
    pub(crate) options: DecodeOptions,
}

impl<'b> Reading<'b> {
    /// A strict reading, by the specifications.
    pub(crate) fn strict() -> Self {
        Self::with(DecodeOptions::STRICT)
    }

    /// A reading by `options`, without a list of faults.
    pub(crate) fn with(options: DecodeOptions) -> Self {
        Self {
            faults: None,
            options,
        }
    }

    /// A reading that keeps the faults of the mandatory IEs in `faults`.
    pub(crate) fn keeping(faults: &'b mut Vec<NasError>) -> Self {
        Self {
            faults: Some(faults),
            options: DecodeOptions::STRICT,
        }
    }
}

/// The [`Reading`] that a decoder is given.
pub(crate) type Faults<'a, 'b> = &'a mut Reading<'b>;

/// A message, which is read by a [`Reading`].
pub(crate) trait Keeping: Sized {
    /// Read the message from the front of `buffer` by `faults`.
    fn decode_reading(buffer: &mut &[u8], faults: Faults<'_, '_>) -> Result<Self>;
}

/// Decode the message `T` from the front of `buffer` by the reading
/// `faults`: strictly or keeping its faults, with the options of a receiver.
pub(crate) fn decode_keeping<T: Keeping>(buffer: &mut &[u8], faults: Faults<'_, '_>) -> Result<T> {
    T::decode_reading(buffer, faults)
}

/// The error for `count` octets after what was decoded.
pub(crate) fn trailing(count: usize) -> NasError {
    let plural = if count == 1 { "" } else { "s" };
    NasError::DecodingError(format!("{count} octet{plural} after the end"))
}

/// Maximum allowed IE value length in bytes.
///
/// The length indicator of a type 6 IE has two octets (TS 24.007 §11.2.1.1).
pub const MAX_IE_VALUE_LENGTH: usize = 65535;

/// Reading from the front of octets: a slice that shrinks as it is read.
///
/// The methods that return a value take as many octets as it has, and panic
/// when there are fewer, as an index out of a slice does: each is called
/// after `remaining()` was checked, or through [`Reader::take`].
pub(crate) trait Reader<'a> {
    /// How many octets are left.
    fn remaining(&self) -> usize;

    /// Whether any octet is left.
    fn has_remaining(&self) -> bool {
        self.remaining() > 0
    }

    /// The next `count` octets, or [`NasError::BufferTooShort`].
    fn take(&mut self, count: usize) -> Result<&'a [u8]>;

    /// Skip `count` octets.
    fn advance(&mut self, count: usize);

    /// The next `count` octets.
    fn split_to(&mut self, count: usize) -> &'a [u8];

    /// The next octet.
    fn get_u8(&mut self) -> u8;

    /// The next two octets, as a number.
    fn get_u16(&mut self) -> u16;

    /// The next four octets, as a number.
    fn get_u32(&mut self) -> u32;
}

impl<'a> Reader<'a> for &'a [u8] {
    fn remaining(&self) -> usize {
        self.len()
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let (taken, rest) = self
            .split_at_checked(count)
            .ok_or(NasError::BufferTooShort)?;
        *self = rest;
        Ok(taken)
    }

    fn advance(&mut self, count: usize) {
        *self = &self[count..];
    }

    fn split_to(&mut self, count: usize) -> &'a [u8] {
        let (taken, rest) = self.split_at(count);
        *self = rest;
        taken
    }

    fn get_u8(&mut self) -> u8 {
        let octet = self[0];
        *self = &self[1..];
        octet
    }

    fn get_u16(&mut self) -> u16 {
        let octets = self.split_to(2);
        u16::from_be_bytes([octets[0], octets[1]])
    }

    fn get_u32(&mut self) -> u32 {
        let octets = self.split_to(4);
        u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]])
    }
}

/// Writing at the end of octets.
pub(crate) trait Writer {
    /// Add an octet.
    fn put_u8(&mut self, octet: u8);

    /// Add a number of two octets.
    fn put_u16(&mut self, number: u16);

    /// Add a number of four octets.
    fn put_u32(&mut self, number: u32);

    /// Add octets.
    fn put_slice(&mut self, octets: &[u8]);
}

impl Writer for Vec<u8> {
    fn put_u8(&mut self, octet: u8) {
        self.push(octet);
    }

    fn put_u16(&mut self, number: u16) {
        self.extend_from_slice(&number.to_be_bytes());
    }

    fn put_u32(&mut self, number: u32) {
        self.extend_from_slice(&number.to_be_bytes());
    }

    fn put_slice(&mut self, octets: &[u8]) {
        self.extend_from_slice(octets);
    }
}
