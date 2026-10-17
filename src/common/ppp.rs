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

/// The packets of a protocol, by the names of its specification.
pub(crate) trait Protocol: Sized {
    /// The packet that `octets` are; `None` when they are none that this
    /// reads.
    fn read(octets: &[u8]) -> Option<Self>;

    /// The octets of the packet, or why no packet has what is written.
    fn octets(&self) -> Result<Vec<u8>, String>;
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
            Some(packet) if packet.octets().as_deref() == Ok(octets) => Self::Named(packet),
            _ => Self::Octets(octets.to_vec()),
        }
    }

    /// The octets of the packet, or why no packet has what is written.
    pub(crate) fn octets(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Named(packet) => packet.octets(),
            Self::Octets(octets) => Ok(octets.clone()),
        }
    }
}

impl<T: crate::common::readable::Readable> crate::common::readable::Readable for Packet<T> {
    fn shown(&self, held: &'static str) -> serde_json::Value {
        match self {
            Self::Named(packet) => packet.shown(held),
            Self::Octets(octets) => crate::common::forms::hexadecimal::shown(octets),
        }
    }

    // An object is a packet by its names, and anything else its octets.
    fn read(value: &serde_json::Value) -> Result<Self, String> {
        match value.is_object() {
            true => T::read(value).map(Self::Named),
            false => Vec::<u8>::read(value).map(Self::Octets),
        }
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        None
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
fn frame(code: u8, identifier: u8, data: &[u8]) -> Result<Vec<u8>, String> {
    let length = u16::try_from(data.len() + 4)
        .map_err(|_| format!("{} octets of data are more than a packet has", data.len()))?;
    let mut octets = vec![code, identifier];
    octets.extend(length.to_be_bytes());
    octets.extend(data);
    Ok(octets)
}

/// The name of a code, as a view prints it.
fn printed<T: readable::Readable>(code: &T) -> String {
    match readable::to_value(code) {
        Ok(serde_json::Value::String(name)) => name,
        _ => String::new(),
    }
}

/// The first of `octets` as a length, then that many octets: what a field
/// with its length is, and what follows it.
fn counted(octets: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&length, rest) = octets.split_first()?;
    rest.split_at_checked(usize::from(length))
}

/// `field`, which is the member `name`, after its length in one octet.
fn count(octets: &mut Vec<u8>, name: &str, field: &[u8]) -> Result<(), String> {
    let length = u8::try_from(field.len())
        .map_err(|_| format!("`{name}` has {} octets, and at most 255", field.len()))?;
    octets.push(length);
    octets.extend(field);
    Ok(())
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
fn option(data: &mut Vec<u8>, kind: u8, contents: &[u8]) -> Result<(), String> {
    let length = u8::try_from(contents.len() + 2).map_err(|_| {
        let octets = contents.len();
        format!("the option of the type {kind} has {octets} octets of data, and at most 253")
    })?;
    data.push(kind);
    data.push(length);
    data.extend(contents);
    Ok(())
}

/// The codes of the packets that negotiate options, in LCP and in IPCP
/// (RFC 1661 §5.1 to §5.4), by the names that a view prints.
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigureCode {
    ConfigureRequest = 1,
    ConfigureAck = 2,
    ConfigureNak = 3,
    ConfigureReject = 4,
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(
    enum ConfigureCode {
        ConfigureRequest,
        ConfigureAck,
        ConfigureNak,
        ConfigureReject,
    }
);

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lcp {
    code: ConfigureCode,
    identifier: u8,
    options: Vec<LcpOption>,
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(struct Lcp { code, identifier, options });

/// A configuration option of LCP (RFC 1661 §6).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    Other { r#type: u8, data: Vec<u8> },
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(enum LcpOption { MaximumReceiveUnit(u16), AuthenticationProtocol(Authentication), MagicNumber(u32), ProtocolFieldCompression, AddressAndControlFieldCompression, Other = "Option" { r#type, data as hexadecimal } });

/// The authentication protocols that the protocol configuration options
/// have units of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Authentication {
    /// C023H (RFC 1334).
    Pap,
    /// C223H with the algorithm 5, MD5 (RFC 1994).
    ChapMd5,
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(
    enum Authentication {
        Pap,
        ChapMd5,
    }
);

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

    fn octets(&self) -> Result<Vec<u8>, String> {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ipcp {
    code: ConfigureCode,
    identifier: u8,
    options: Vec<IpcpOption>,
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(struct Ipcp { code, identifier, options });

/// A configuration option of IPCP (RFC 1332 §3, RFC 1877 §1).
#[derive(Debug, Clone, PartialEq, Eq)]
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
    Other { r#type: u8, data: Vec<u8> },
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(enum IpcpOption { IpAddress(Ipv4Addr), PrimaryDnsServerAddress(Ipv4Addr), PrimaryNbnsServerAddress(Ipv4Addr), SecondaryDnsServerAddress(Ipv4Addr), SecondaryNbnsServerAddress(Ipv4Addr), Other = "Option" { r#type, data as hexadecimal } });

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

    fn octets(&self) -> Result<Vec<u8>, String> {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PapCode {
    AuthenticateRequest = 1,
    AuthenticateAck = 2,
    AuthenticateNak = 3,
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(
    enum PapCode {
        AuthenticateRequest,
        AuthenticateAck,
        AuthenticateNak,
    }
);

/// A packet of PAP (RFC 1334 §2.2): a request has the peer-id and the
/// password, and an answer may have a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pap {
    code: PapCode,
    identifier: u8,
    peer_id: Option<String>,
    password: Option<String>,
    message: Option<String>,
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(struct Pap { code, identifier, peer_id, password, message });

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

    fn octets(&self) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        let code = printed(&self.code);
        match (self.code, &self.peer_id, &self.password, &self.message) {
            (PapCode::AuthenticateRequest, Some(peer_id), Some(password), None) => {
                count(&mut data, "peer-id", peer_id.as_bytes())?;
                count(&mut data, "password", password.as_bytes())?;
            }
            (PapCode::AuthenticateAck | PapCode::AuthenticateNak, None, None, message) => {
                if let Some(message) = message {
                    count(&mut data, "message", message.as_bytes())?;
                }
            }
            // A member that the code does not have, or lacks one that it has.
            (PapCode::AuthenticateRequest, ..) => {
                return Err(format!(
                    "a packet with the code `{code}` has `peer-id` and `password`, and no `message`"
                ));
            }
            _ => {
                return Err(format!(
                    "a packet with the code `{code}` may have a `message`, and has no `peer-id` \
                     and no `password`"
                ));
            }
        }
        frame(self.code as u8, self.identifier, &data)
    }
}

/// The codes of CHAP (RFC 1994 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChapCode {
    Challenge = 1,
    Response = 2,
    Success = 3,
    Failure = 4,
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(
    enum ChapCode {
        Challenge,
        Response,
        Success,
        Failure,
    }
);

/// A packet of CHAP (RFC 1994 §4): a challenge and a response have a value
/// and a name, a success and a failure a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Chap {
    code: ChapCode,
    identifier: u8,
    value: Option<Vec<u8>>,
    name: Option<String>,
    message: Option<String>,
}

#[cfg(all(feature = "serde", feature = "std"))]
crate::common::readable::readable!(struct Chap { code, identifier, value as hexadecimal_if_any, name, message });

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

    fn octets(&self) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        let code = printed(&self.code);
        match (self.code, &self.value, &self.name, &self.message) {
            (ChapCode::Challenge | ChapCode::Response, Some(value), Some(name), None) => {
                count(&mut data, "value", value)?;
                data.extend(name.as_bytes());
            }
            (ChapCode::Success | ChapCode::Failure, None, None, Some(message)) => {
                data.extend(message.as_bytes());
            }
            // A member that the code does not have, or lacks one that it has.
            (ChapCode::Challenge | ChapCode::Response, ..) => {
                return Err(format!(
                    "a packet with the code `{code}` has `value` and `name`, and no `message`"
                ));
            }
            _ => {
                return Err(format!(
                    "a packet with the code `{code}` has `message`, and no `value` and no `name`"
                ));
            }
        }
        frame(self.code as u8, self.identifier, &data)
    }
}
