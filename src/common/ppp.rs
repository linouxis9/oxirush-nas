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

//! The packets of the configuration protocols, for the view of the protocol
//! configuration options (TS 24.008 §10.5.6.3): the contents of a unit of
//! LCP, PAP, CHAP or IPCP are a packet of RFC 1661 §5 without its protocol
//! field and its padding: a code, an identifier, the length of the packet
//! and its data.
//!
//! A packet has the names of its protocol where they write its octets back,
//! and its octets otherwise: with a code that has no name here, a length
//! that is not that of the contents, or data that is not that of its code.

use crate::common::readable;
use crate::prelude::*;
use core::net::Ipv4Addr;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// The packets of a protocol, by the names of its specification.
pub(crate) trait Protocol: Sized {
    /// The packet that `octets` are; `None` when they are none that this
    /// reads.
    fn read(octets: &[u8]) -> Option<Self>;

    /// The octets of the packet; `None` for what no packet carries.
    fn octets(&self) -> Option<Vec<u8>>;
}

/// A packet of a configuration protocol: with the names of its protocol,
/// or the octets that those names would not write back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Packet<T> {
    Named(T),
    Octets(Vec<u8>),
}

impl<T: Protocol> Packet<T> {
    /// The packet that `octets` are.
    pub(crate) fn of(octets: &[u8]) -> Self {
        match T::read(octets) {
            Some(packet) if packet.octets().as_deref() == Some(octets) => Self::Named(packet),
            _ => Self::Octets(octets.to_vec()),
        }
    }

    /// The octets of the packet; `None` for what no packet carries.
    pub(crate) fn octets(&self) -> Option<Vec<u8>> {
        match self {
            Self::Named(packet) => packet.octets(),
            Self::Octets(octets) => Some(octets.clone()),
        }
    }
}

impl<T: Serialize> Serialize for Packet<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Named(packet) => packet.serialize(serializer),
            Self::Octets(octets) => hexadecimal(octets, serializer),
        }
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Packet<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // An object is a packet by its names, and anything else its octets:
        // each is read as a view reads it.
        let written = serde_json::Value::deserialize(deserializer)?;
        match written.is_object() {
            true => readable::from_value(&written).map(Self::Named),
            false => readable::from_value(&written).map(Self::Octets),
        }
        .map_err(D::Error::custom)
    }
}

/// Octets in hexadecimal, also when there are none: a list of no octets
/// would be shown as an empty list.
fn hexadecimal<S: Serializer>(octets: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(octets))
}

/// [`hexadecimal`] for octets that a packet may not have.
fn hexadecimal_if_any<S: Serializer>(
    octets: &Option<Vec<u8>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match octets {
        Some(octets) => hexadecimal(octets, serializer),
        None => serializer.serialize_none(),
    }
}

/// The code, the identifier and the data of the packet that `octets` are:
/// `None` unless its length is that of the octets.
fn framed(octets: &[u8]) -> Option<(u8, u8, &[u8])> {
    let (&[code, identifier, high, low], data) = octets.split_first_chunk()?;
    let length = usize::from(u16::from_be_bytes([high, low]));
    (length == octets.len()).then_some((code, identifier, data))
}

/// The octets of a packet.
fn frame(code: u8, identifier: u8, data: &[u8]) -> Option<Vec<u8>> {
    let length = u16::try_from(data.len() + 4).ok()?;
    let mut octets = vec![code, identifier];
    octets.extend(length.to_be_bytes());
    octets.extend(data);
    Some(octets)
}

/// The first of `octets` as a length, then that many octets: what a field
/// with its length is, and what follows it.
fn counted(octets: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&length, rest) = octets.split_first()?;
    rest.split_at_checked(usize::from(length))
}

/// `field` after its length in one octet.
fn count(octets: &mut Vec<u8>, field: &[u8]) -> Option<()> {
    octets.push(u8::try_from(field.len()).ok()?);
    octets.extend(field);
    Some(())
}

/// The options of a Configure packet (RFC 1661 §6): the type of each, and
/// its data. `None` when a length is not that of an option within `data`.
fn options(mut data: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let mut options = Vec::new();
    while let Some((&[kind, length], rest)) = data.split_first_chunk() {
        let (contents, rest) = rest.split_at_checked(usize::from(length).checked_sub(2)?)?;
        options.push((kind, contents));
        data = rest;
    }
    data.is_empty().then_some(options)
}

/// An option of the type `kind` with `contents`.
fn option(data: &mut Vec<u8>, kind: u8, contents: &[u8]) -> Option<()> {
    data.push(kind);
    data.push(u8::try_from(contents.len() + 2).ok()?);
    data.extend(contents);
    Some(())
}

/// The codes of the packets that negotiate options, in LCP and in IPCP
/// (RFC 1661 §5.1 to §5.4), by the names that a view prints.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ConfigureCode {
    ConfigureRequest = 1,
    ConfigureAck = 2,
    ConfigureNak = 3,
    ConfigureReject = 4,
}

impl ConfigureCode {
    fn of(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ConfigureRequest),
            2 => Some(Self::ConfigureAck),
            3 => Some(Self::ConfigureNak),
            4 => Some(Self::ConfigureReject),
            _ => None,
        }
    }
}

/// A Configure packet of LCP (RFC 1661).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Lcp {
    code: ConfigureCode,
    identifier: u8,
    options: Vec<LcpOption>,
}

/// A configuration option of LCP (RFC 1661 §6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum LcpOption {
    /// Type 1.
    MaximumReceiveUnit(u16),
    /// Type 3.
    AuthenticationProtocol(Authentication),
    /// Type 5.
    MagicNumber(u32),
    /// Type 7.
    ProtocolFieldCompression,
    /// Type 8.
    AddressAndControlFieldCompression,
    /// An option that has no name here, or whose data is not that of its
    /// name.
    #[serde(rename = "Option")]
    Other {
        r#type: u8,
        #[serde(serialize_with = "hexadecimal")]
        data: Vec<u8>,
    },
}

/// The authentication protocols that the protocol configuration options
/// have units of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Authentication {
    /// C023H (RFC 1334).
    Pap,
    /// C223H with the algorithm 5, MD5 (RFC 1994).
    ChapMd5,
}

impl Protocol for Lcp {
    fn read(octets: &[u8]) -> Option<Self> {
        let (code, identifier, data) = framed(octets)?;
        let named = |(kind, contents): (u8, &[u8])| match (kind, contents) {
            (1, &[high, low]) => LcpOption::MaximumReceiveUnit(u16::from_be_bytes([high, low])),
            (3, [0xc0, 0x23]) => LcpOption::AuthenticationProtocol(Authentication::Pap),
            (3, [0xc2, 0x23, 5]) => LcpOption::AuthenticationProtocol(Authentication::ChapMd5),
            (5, &[a, b, c, d]) => LcpOption::MagicNumber(u32::from_be_bytes([a, b, c, d])),
            (7, []) => LcpOption::ProtocolFieldCompression,
            (8, []) => LcpOption::AddressAndControlFieldCompression,
            _ => LcpOption::Other {
                r#type: kind,
                data: contents.to_vec(),
            },
        };
        Some(Self {
            code: ConfigureCode::of(code)?,
            identifier,
            options: options(data)?.into_iter().map(named).collect(),
        })
    }

    fn octets(&self) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        for written in &self.options {
            match written {
                LcpOption::MaximumReceiveUnit(octets) => {
                    option(&mut data, 1, &octets.to_be_bytes())
                }
                LcpOption::AuthenticationProtocol(Authentication::Pap) => {
                    option(&mut data, 3, &[0xc0, 0x23])
                }
                LcpOption::AuthenticationProtocol(Authentication::ChapMd5) => {
                    option(&mut data, 3, &[0xc2, 0x23, 5])
                }
                LcpOption::MagicNumber(number) => option(&mut data, 5, &number.to_be_bytes()),
                LcpOption::ProtocolFieldCompression => option(&mut data, 7, &[]),
                LcpOption::AddressAndControlFieldCompression => option(&mut data, 8, &[]),
                LcpOption::Other {
                    r#type,
                    data: contents,
                } => option(&mut data, *r#type, contents),
            }?;
        }
        frame(self.code as u8, self.identifier, &data)
    }
}

/// A Configure packet of IPCP (RFC 1332).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Ipcp {
    code: ConfigureCode,
    identifier: u8,
    options: Vec<IpcpOption>,
}

/// A configuration option of IPCP (RFC 1332 §3, RFC 1877 §1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum IpcpOption {
    /// Type 3.
    IpAddress(Ipv4Addr),
    /// Type 129.
    PrimaryDnsServerAddress(Ipv4Addr),
    /// Type 130.
    PrimaryNbnsServerAddress(Ipv4Addr),
    /// Type 131.
    SecondaryDnsServerAddress(Ipv4Addr),
    /// Type 132.
    SecondaryNbnsServerAddress(Ipv4Addr),
    /// An option that has no name here, or whose data is not an address.
    #[serde(rename = "Option")]
    Other {
        r#type: u8,
        #[serde(serialize_with = "hexadecimal")]
        data: Vec<u8>,
    },
}

impl Protocol for Ipcp {
    fn read(octets: &[u8]) -> Option<Self> {
        let (code, identifier, data) = framed(octets)?;
        let named = |(kind, contents): (u8, &[u8])| {
            let address = <[u8; 4]>::try_from(contents).ok().map(Ipv4Addr::from);
            match (kind, address) {
                (3, Some(address)) => IpcpOption::IpAddress(address),
                (129, Some(address)) => IpcpOption::PrimaryDnsServerAddress(address),
                (130, Some(address)) => IpcpOption::PrimaryNbnsServerAddress(address),
                (131, Some(address)) => IpcpOption::SecondaryDnsServerAddress(address),
                (132, Some(address)) => IpcpOption::SecondaryNbnsServerAddress(address),
                _ => IpcpOption::Other {
                    r#type: kind,
                    data: contents.to_vec(),
                },
            }
        };
        Some(Self {
            code: ConfigureCode::of(code)?,
            identifier,
            options: options(data)?.into_iter().map(named).collect(),
        })
    }

    fn octets(&self) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        for written in &self.options {
            let (kind, contents) = match written {
                IpcpOption::IpAddress(address) => (3, address.octets().to_vec()),
                IpcpOption::PrimaryDnsServerAddress(address) => (129, address.octets().to_vec()),
                IpcpOption::PrimaryNbnsServerAddress(address) => (130, address.octets().to_vec()),
                IpcpOption::SecondaryDnsServerAddress(address) => (131, address.octets().to_vec()),
                IpcpOption::SecondaryNbnsServerAddress(address) => (132, address.octets().to_vec()),
                IpcpOption::Other { r#type, data } => (*r#type, data.clone()),
            };
            option(&mut data, kind, &contents)?;
        }
        frame(self.code as u8, self.identifier, &data)
    }
}

/// The codes of PAP (RFC 1334 §2.2), by the names that a view prints.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PapCode {
    AuthenticateRequest = 1,
    AuthenticateAck = 2,
    AuthenticateNak = 3,
}

/// A packet of PAP (RFC 1334 §2.2): a request has the peer-id and the
/// password, and an answer may have a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Pap {
    code: PapCode,
    identifier: u8,
    peer_id: Option<String>,
    password: Option<String>,
    message: Option<String>,
}

/// Octets as the text that they are.
fn text(octets: &[u8]) -> Option<String> {
    String::from_utf8(octets.to_vec()).ok()
}

impl Protocol for Pap {
    fn read(octets: &[u8]) -> Option<Self> {
        let (code, identifier, data) = framed(octets)?;
        let (code, fields) = match code {
            1 => {
                let (peer_id, rest) = counted(data)?;
                let (password, []) = counted(rest)? else {
                    return None;
                };
                let fields = (Some(text(peer_id)?), Some(text(password)?), None);
                (PapCode::AuthenticateRequest, fields)
            }
            2 | 3 => {
                // An answer without the length of its message has none.
                let message = match data {
                    [] => None,
                    data => match counted(data)? {
                        (message, []) => Some(text(message)?),
                        _ => return None,
                    },
                };
                let code = match code {
                    2 => PapCode::AuthenticateAck,
                    _ => PapCode::AuthenticateNak,
                };
                (code, (None, None, message))
            }
            _ => return None,
        };
        let (peer_id, password, message) = fields;
        Some(Self {
            code,
            identifier,
            peer_id,
            password,
            message,
        })
    }

    fn octets(&self) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        match (self.code, &self.peer_id, &self.password, &self.message) {
            (PapCode::AuthenticateRequest, Some(peer_id), Some(password), None) => {
                count(&mut data, peer_id.as_bytes())?;
                count(&mut data, password.as_bytes())?;
            }
            (PapCode::AuthenticateAck | PapCode::AuthenticateNak, None, None, message) => {
                if let Some(message) = message {
                    count(&mut data, message.as_bytes())?;
                }
            }
            // A member that the code does not have, or lacks one that it has.
            _ => return None,
        }
        frame(self.code as u8, self.identifier, &data)
    }
}

/// The codes of CHAP (RFC 1994 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ChapCode {
    Challenge = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

/// A packet of CHAP (RFC 1994 §4): a challenge and a response have a value
/// and a name, a success and a failure a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Chap {
    code: ChapCode,
    identifier: u8,
    #[serde(serialize_with = "hexadecimal_if_any")]
    value: Option<Vec<u8>>,
    name: Option<String>,
    message: Option<String>,
}

impl Protocol for Chap {
    fn read(octets: &[u8]) -> Option<Self> {
        let (code, identifier, data) = framed(octets)?;
        let (code, value, name, message) = match code {
            1 | 2 => {
                let (value, name) = counted(data)?;
                let code = match code {
                    1 => ChapCode::Challenge,
                    _ => ChapCode::Response,
                };
                (code, Some(value.to_vec()), Some(text(name)?), None)
            }
            3 => (ChapCode::Success, None, None, Some(text(data)?)),
            4 => (ChapCode::Failure, None, None, Some(text(data)?)),
            _ => return None,
        };
        Some(Self {
            code,
            identifier,
            value,
            name,
            message,
        })
    }

    fn octets(&self) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        match (self.code, &self.value, &self.name, &self.message) {
            (ChapCode::Challenge | ChapCode::Response, Some(value), Some(name), None) => {
                count(&mut data, value)?;
                data.extend(name.as_bytes());
            }
            (ChapCode::Success | ChapCode::Failure, None, None, Some(message)) => {
                data.extend(message.as_bytes());
            }
            // A member that the code does not have, or lacks one that it has.
            _ => return None,
        }
        frame(self.code as u8, self.identifier, &data)
    }
}
