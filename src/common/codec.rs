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

use crate::common::Direction;
use crate::common::names::printed;
use crate::prelude::*;
use core::fmt;

/// Errors that can occur during NAS message encoding or decoding.
///
/// The structured variants map to the receiver actions of TS 24.301 and
/// TS 24.501 chapter 7: a message that is too short or has an unknown
/// protocol discriminator is ignored (§7.2, TS 24.007 §11.2.3.1.1), an
/// unknown message type is answered with a STATUS message carrying cause #97
/// (§7.4), and an invalid mandatory IE with cause #96 (§7.5).
///
/// ```
/// use oxirush_nas::Error;
/// use oxirush_nas::nas_5gs::Message;
///
/// // A message too short to have a message type, which a receiver ignores
/// let error = Message::decode(&[0x7e, 0x00]).unwrap_err();
/// assert!(matches!(error, Error::MessageTooShort));
///
/// // A REGISTRATION REQUEST whose 5G-GUTI is one octet short: cause #96
/// let octets = hex::decode("7e004179000af202f839cafe001122332e02a020").unwrap();
/// let error = Message::decode(&octets).unwrap_err();
/// assert!(matches!(error, Error::InvalidMandatoryIe { .. }));
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The octets end before the value that is read from them does: an IE
    /// or a part of one that is decoded alone is cut short.
    BufferTooShort,

    /// The message type octet is not that of a message of the sublayer
    /// (§7.4).
    UnknownMessageType(u8),

    /// What is to be encoded has no octets: a value that its field cannot
    /// hold, a header that is not that of its message, or a tree
    /// that does not describe a message.
    EncodingError(String),

    /// The octets are not those of what is decoded.
    DecodingError(String),

    /// The message is shorter than its header (§7.2).
    MessageTooShort,

    /// The first octet of the message does not have a protocol discriminator
    /// that the decoder handles: an extended protocol discriminator of 5GMM
    /// (0x7e) or 5GSM (0x2e) for `nas_5gs`, a protocol discriminator of EMM
    /// (7) or ESM (2) in bits 4 to 1 for `nas_eps`. The octet is kept.
    UnknownProtocolDiscriminator(u8),

    /// The security header type is reserved (Table 9.3.1).
    ReservedSecurityHeaderType(u8),

    /// The session management message type is unknown. The header
    /// identities are kept for the STATUS message (§7.4): the EPS bearer
    /// identity or PDU session identity, and the PTI.
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
    ReservedPduSessionIdentity {
        /// PDU session identity.
        identity: u8,
        /// Procedure transaction identity.
        pti: u8,
        /// Message type octet.
        message_type: u8,
    },

    /// A mandatory IE is missing or syntactically incorrect (§7.5.1). `ie`
    /// is the IE, `fault` what is wrong with it, and `reason` why a value
    /// that is syntactically incorrect is not one of its type, where the
    /// value says it: the error of oxirush-utils for an identity.
    InvalidMandatoryIe {
        /// The IE, by the name of its table.
        ie: IeName,
        /// What is wrong with the IE.
        fault: IeFault,
        /// Why its value is not one of its type, when it says it. It is
        /// boxed, so that an error stays four words.
        reason: Option<Box<String>>,
    },

    /// An unknown IE that is encoded as "comprehension required" is cut
    /// short: the message ends inside it, and nothing tells where it ends.
    /// It is answered as an invalid mandatory IE is (§7.5.1 and §7.6.1).
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
    NasCountExhausted,

    /// The message authentication code is right, and the message under it
    /// is refused for the reason `error`: it does not decode, or it is not
    /// one that its security header type or its direction protects. Its NAS
    /// COUNT is used, as that of every message whose code is right
    /// (TS 24.501 and TS 24.301 §4.4.3.3). `plain` is the message under the
    /// security header, deciphered, which a receiver logs and answers:
    /// `answer_to_refused` reads it.
    AuthenticMessageRefused {
        /// Why the plain message is refused.
        error: Box<Error>,
        /// The octets of the plain message.
        plain: Box<[u8]>,
    },

    /// A security context is asked for what it does not do: an algorithm
    /// that the specification reserves, NIA0 or EIA0 with another
    /// ciphering algorithm than the null one (TS 33.501 §5.5.2, TS 33.401
    /// §5.1.4.1), or a header type that does not protect a message as it is
    /// asked to.
    SecurityRefused(String),
    /// The NAS MAC does not match. The COUNTs are unchanged. TS 24.301 and
    /// TS 24.501 §4.4.4.3 still let a receiver process some messages, such
    /// as ATTACH REQUEST, from an integrity-only envelope: decode the PDU
    /// without the security context to do so.
    IntegrityCheckFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BufferTooShort => f.write_str("the octets end before the value does"),
            Self::UnknownMessageType(kind) => write!(f, "unknown message type {kind:#04x}"),
            Self::EncodingError(why) => write!(f, "cannot encode: {why}"),
            Self::DecodingError(why) => write!(f, "cannot decode: {why}"),
            Self::MessageTooShort => {
                f.write_str("the message is too short: it ends inside its header")
            }
            Self::UnknownProtocolDiscriminator(octet) => {
                f.write_str(&unknown_protocol_discriminator(*octet))
            }
            Self::ReservedSecurityHeaderType(kind) => {
                write!(f, "reserved security header type {kind}")
            }
            Self::UnknownSessionMessageType {
                identity,
                pti,
                message_type,
            } => write!(
                f,
                "unknown session management message type {message_type:#04x} (identity \
                 {identity}, PTI {pti})"
            ),
            Self::ReservedPduSessionIdentity {
                identity,
                pti,
                message_type,
            } => write!(
                f,
                "reserved PDU session identity {identity} (PTI {pti}, message type \
                 {message_type:#04x})"
            ),
            Self::InvalidMandatoryIe { ie, fault, reason } => {
                write!(f, "mandatory IE `{ie}` {fault}")?;
                match reason {
                    Some(reason) => write!(f, ": {reason}"),
                    None => Ok(()),
                }
            }
            Self::UnknownIeCutShort { iei, octets } => write!(
                f,
                "an unknown IE {iei:#04x}, which is encoded as \"comprehension required\", is \
                 cut short: the message ends {octets} octet{} after its start",
                if *octets == 1 { "" } else { "s" }
            ),
            Self::NasCountExhausted => {
                f.write_str("every NAS COUNT of the direction was used with these keys")
            }
            Self::AuthenticMessageRefused { error, .. } => {
                write!(f, "the message is authentic and is refused: {error}")
            }
            Self::SecurityRefused(why) => f.write_str(why),
            Self::IntegrityCheckFailed => {
                f.write_str("the message authentication code does not match")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::AuthenticMessageRefused { error, .. } => Some(&**error),
            _ => None,
        }
    }
}

/// A function that builds the IEs of a message and encodes it has one
/// error: `?` takes what a constructor refuses as what is not encoded.
///
/// ```
/// use oxirush_nas::nas_5gs::*;
/// use oxirush_nas::Error;
///
/// fn reject(t3346: u64) -> Result<Vec<u8>, Error> {
///     let mut reject = RegistrationReject::new(GmmCause::from_cause(GmmCauseValue::Congestion));
///     reject.set_t3346_value(GprsTimer2::from_seconds(t3346)?);
///     Message::new_5gmm(reject).encode()
/// }
/// assert_eq!(reject(600).unwrap(), [0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x2a]);
/// assert_eq!(
///     reject(601).unwrap_err().to_string(),
///     "cannot encode: `seconds` is 601, and must be up to 31 times 2 seconds, 1 minute or 6 minutes"
/// );
/// ```
impl From<crate::common::ValueError> for Error {
    fn from(error: crate::common::ValueError) -> Self {
        Self::EncodingError(error.to_string())
    }
}

/// An IE of a message, which an error names: `Display` and `Debug` print
/// its name in the table of the message, `5gs-mobile-identity`, and
/// [`IeName::field`] is the field of the message struct that it is decoded
/// into, `fgs_mobile_identity`.
///
/// ```
/// use oxirush_nas::IeName;
///
/// let ie = IeName::of("fgs_mobile_identity");
/// assert_eq!(ie.to_string(), "5gs-mobile-identity");
/// assert_eq!(format!("{ie:?}"), "\"5gs-mobile-identity\"");
/// assert_eq!(ie.field(), "fgs_mobile_identity");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IeName(&'static str);

impl IeName {
    /// The IE of the field `field` of a message struct.
    pub const fn of(field: &'static str) -> Self {
        Self(field)
    }

    /// The field of the message struct that the IE is decoded into.
    pub const fn field(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for IeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&printed(self.0))
    }
}

impl fmt::Debug for IeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", printed(self.0))
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

/// The text of [`Error::UnknownProtocolDiscriminator`]: an octet that
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
pub type Result<T> = core::result::Result<T, Error>;

/// Encode a NAS IE or message.
///
/// A message encodes to its octets, header first. An IE encodes as it is in
/// a message without its IEI: its length indicator, if its format has one,
/// and its value (TS 24.007 §11.2.1.1). The IEI of an optional IE is that of
/// the message table, which the message writes.
///
/// ```
/// use oxirush_nas::{Decode, Encode};
/// use oxirush_nas::nas_5gs::Dnn;
///
/// // A DNN without its IEI: its length indicator, then its labels
/// let dnn = Dnn::from_string("internet").unwrap();
/// let octets = dnn.encode().unwrap();
/// assert_eq!(hex::encode(&octets), "0908696e7465726e6574");
/// assert_eq!(Dnn::decode(&octets).unwrap(), dnn);
/// ```
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
///
/// ```
/// use oxirush_nas::Decode;
/// use oxirush_nas::nas_5gs::Dnn;
///
/// // A DNN at the front of more octets: decode_from leaves them, decode refuses them
/// let octets = hex::decode("0908696e7465726e6574ff").unwrap();
/// let mut input = &octets[..];
/// let dnn = Dnn::decode_from(&mut input).unwrap();
/// assert_eq!(dnn.as_string().as_deref(), Some("internet"));
/// assert_eq!(input, [0xff]);
/// assert!(Dnn::decode(&octets).is_err());
/// ```
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
    /// [`Error::InvalidMandatoryIe`] that `decode_from` returns for it.
    /// A message does this for its mandatory IEs, so that a receiver can
    /// read the rest of a message that it is to reject (TS 24.501 and
    /// TS 24.301 §7.5); a type that has none decodes as `decode_from`.
    fn decode_lenient_from(input: &mut &[u8], faults: &mut Vec<Error>) -> Result<Self> {
        let _ = faults;
        Self::decode_from(input)
    }
}

/// How a message is read beyond what its octets say: who sent it, and what
/// a receiver takes beyond the rules of TS 24.501 and TS 24.301 from a peer
/// that does not follow them. `decode_with` and `decode_lenient` of
/// [`nas_5gs::Message`](crate::nas_5gs::Message) and
/// [`nas_eps::Message`](crate::nas_eps::Message) read a message by them.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecodeOptions {
    /// Take a known optional IE that comes after one that the message
    /// table places after it, where §7.6.2 has a receiver ignore it, as
    /// other implementations do: `validate()` reports each one as out of the
    /// order of the table, and the message is encoded in the order it came.
    pub out_of_sequence: bool,
    /// The direction the message was sent in, where its octets do not say
    /// it: TS 24.301 has one message type for the DETACH REQUEST of the UE
    /// and for that of the network. `None` reads the one that the octets
    /// fit. A 5GS message says its direction by its type, and needs none.
    pub direction: Option<Direction>,
}

impl DecodeOptions {
    /// The rules of the specifications, which [`Decode::decode`] follows.
    pub const STRICT: Self = Self {
        out_of_sequence: false,
        direction: None,
    };

    /// These options, taking the known optional IEs out of sequence too.
    pub const fn with_out_of_sequence(self) -> Self {
        Self {
            out_of_sequence: true,
            ..self
        }
    }

    /// These options, for a message sent in `direction`.
    pub const fn with_direction(self, direction: Direction) -> Self {
        Self {
            direction: Some(direction),
            ..self
        }
    }
}

/// How a decoder reads a message: what it does with a mandatory IE that has
/// its octets and is not one of its type (without a list it refuses the
/// message, and with one it keeps the IE and adds the refusal to the list),
/// and the options of a receiver.
pub(crate) struct Reading<'b> {
    pub(crate) faults: Option<&'b mut Vec<Error>>,
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

    /// A reading by `options` that keeps the faults of the mandatory IEs in
    /// `faults`.
    pub(crate) fn keeping(faults: &'b mut Vec<Error>, options: DecodeOptions) -> Self {
        Self {
            faults: Some(faults),
            options,
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

/// [`Error::BufferTooShort`], for `ok_or_else`: the error is made when
/// it is returned. `ok_or` makes it on every call and drops it, and the drop
/// of a `Error` is a call, as one error keeps another.
pub(crate) fn too_short() -> Error {
    Error::BufferTooShort
}

/// The error for `count` octets after what was decoded.
pub(crate) fn trailing(count: usize) -> Error {
    let plural = if count == 1 { "" } else { "s" };
    Error::DecodingError(format!("{count} octet{plural} after the end"))
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

    /// The next `count` octets, or [`Error::BufferTooShort`].
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
            .ok_or_else(crate::common::too_short)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Each option of a reading is set by its own method, and keeps the others.
    #[test]
    fn the_options_of_a_reading_are_set_one_by_one() {
        let options = DecodeOptions::STRICT.with_direction(Direction::Downlink);
        assert_eq!(
            (options.out_of_sequence, options.direction),
            (false, Some(Direction::Downlink))
        );
        let options = options.with_out_of_sequence();
        assert_eq!(
            (options.out_of_sequence, options.direction),
            (true, Some(Direction::Downlink))
        );
        assert_eq!(DecodeOptions::STRICT, DecodeOptions::default());
    }
}
