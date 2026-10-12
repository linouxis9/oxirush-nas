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

//! The view of a message: each of its IEs by the name the specification
//! gives it, with its `value` as the typed accessors decode it and its
//! `octets` in hexadecimal.

use crate::common::ppp::{Chap, Ipcp, Lcp, Packet, Pap};
use crate::common::readable::{self, letters, printed, printed_static, same_name};
use crate::common::ts24008::{Pco, PcoDirection, PcoEntry};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::{Ipv4Addr, Ipv6Addr};

/// An IE type whose octets have a value: what its typed accessors return,
/// in the readable form of [`readable`].
pub(crate) trait Decoded: Serialize + Sized {
    /// The value of the octets; `None` when they have none.
    fn decoded(&self) -> Option<Value>;

    /// This IE with the octets of `value`. The IE that comes back decodes
    /// to `value`: what an IE cannot carry is an error.
    fn with_decoded(&self, value: &Value) -> Result<Self, String>;

    /// The IE without octets yet, as a message that is written alone has it
    /// before its value is written.
    fn unwritten() -> Self;

    /// Whether the IE without octets encodes `value`, and to octets that
    /// have that value.
    fn writes(value: &Value) -> bool {
        Self::unwritten().with_decoded(value).is_ok()
    }
}

/// An IE of a message, as the view shows it.
pub(crate) trait Ie {
    /// The value of the IE; `None` when its octets have none.
    fn value(&self) -> Option<Value>;

    /// The readable serde form of the IE with the octets of `value`, and
    /// the value of those octets.
    fn encoded(&self, value: &Value) -> Result<(Value, Option<Value>), String>;

    /// Whether a message that is written alone takes `value` for this IE:
    /// the IE without octets encodes it.
    fn written_alone(&self, value: &Value) -> bool;
}

impl<T: Decoded> Ie for T {
    fn value(&self) -> Option<Value> {
        self.decoded()
    }

    fn encoded(&self, value: &Value) -> Result<(Value, Option<Value>), String> {
        let new = self.with_decoded(value)?;
        Ok((readable::to_value(&new)?, new.decoded()))
    }

    fn written_alone(&self, value: &Value) -> bool {
        T::writes(value)
    }
}

/// Probe that yields a field as an [`Ie`] with a value when its type
/// implements [`Decoded`] and `None` otherwise (autoref specialization over
/// concrete types).
pub(crate) struct DecodedProbe<'a, T>(pub &'a T);

/// Selected for a field type that implements [`Decoded`].
pub(crate) trait ViaDecoded<'a> {
    fn decoded_ie(&self) -> Option<&'a dyn Ie>;
}

impl<'a, T: Decoded> ViaDecoded<'a> for DecodedProbe<'a, T> {
    fn decoded_ie(&self) -> Option<&'a dyn Ie> {
        Some(self.0)
    }
}

/// Fallback for a field type whose octets have no value.
pub(crate) trait ViaNoDecoded<'a> {
    fn decoded_ie(&self) -> Option<&'a dyn Ie>;
}

impl<'a, T> ViaNoDecoded<'a> for &DecodedProbe<'a, T> {
    fn decoded_ie(&self) -> Option<&'a dyn Ie> {
        None
    }
}

/// An IE that a message has, as its view reads it.
#[derive(Clone, Copy)]
pub(crate) struct Field<'a> {
    /// The name of the field of the message struct.
    pub(crate) name: &'static str,
    /// The name as a view prints it.
    pub(crate) printed: &'static str,
    /// The value of the IE: its octets.
    pub(crate) octets: &'a dyn Shown,
    /// The IE, if its octets have a value.
    pub(crate) ie: Option<&'a dyn Ie>,
    /// Whether the IE is optional.
    pub(crate) optional: bool,
}

/// The `value` field of an IE struct: a number of one or two octets, or
/// octets.
pub(crate) trait Shown {
    /// How many octets a value that is a number has: another size is that
    /// of a string of octets.
    fn size(&self) -> usize;

    /// The octets in hexadecimal.
    fn hex(&self) -> String;
}

impl Shown for u8 {
    fn size(&self) -> usize {
        1
    }

    fn hex(&self) -> String {
        format!("{self:02x}")
    }
}

impl Shown for u16 {
    fn size(&self) -> usize {
        2
    }

    fn hex(&self) -> String {
        format!("{self:04x}")
    }
}

impl Shown for crate::common::Octets {
    fn size(&self) -> usize {
        usize::MAX
    }

    fn hex(&self) -> String {
        hex::encode(self)
    }
}

/// What visits the IEs that a message has.
pub(crate) type Visit<'a> = dyn FnMut(Field<'_>) + 'a;

/// A message enum: its serde form and the IEs of the message struct in it,
/// read through a security header.
pub(crate) trait Viewed: Clone + Serialize + DeserializeOwned {
    /// Visit the IEs that the message struct has.
    fn ies(&self, visit: &mut Visit<'_>);

    /// The readable serde form, without a value, of the optional IE that
    /// the message struct does not have and whose field prints as `name`.
    fn blank(&self, name: &str) -> Option<Value>;

    /// Give `visit` the name, as a view prints it, of each optional IE that
    /// the message struct does not have.
    fn absent(&self, visit: &mut dyn FnMut(&'static str));

    /// The readable serde form of the header of the plain message, read
    /// through a security header: `None` for what has no message struct.
    fn header(&self) -> Option<Value>;

    /// The readable serde form of the header that protects the message,
    /// with that of the octets of a message that is ciphered.
    fn protection(&self) -> Option<(Value, Option<Value>)>;

    /// Give the message struct what the one of `original` keeps of how it
    /// was received: its unknown IEs and the order of its optional IEs.
    fn keep_received(&mut self, original: &Self);

    /// The variants of the enum that hold a plain message.
    const FAMILIES: &'static [&'static str];

    /// This message, which has nothing in it yet, ready for the view
    /// `view`: with the IE that says how another one is read.
    fn prepared(self, _view: &Map<String, Value>) -> Self {
        self
    }

    /// The name that the field `field` of a header reads as for the number
    /// `number`, if the field is one of names and has one for it.
    fn header_name(_field: &str, _number: u64) -> Option<Value> {
        None
    }

    /// The fields of a header that a view may leave out. Such a field keeps
    /// the value that the message has, which is zero in a message that a
    /// view describes alone.
    const SPARE: &'static [&'static str] = &[];
}

/// The names that the view of a message has: the fields of its header `H`,
/// and the IEs of the message structs in the variants `kinds` of `M`. There
/// are none when `M` has no such variant.
pub(crate) fn names<'de, H: Deserialize<'de>, M: Deserialize<'de>>(kinds: &[&str]) -> Vec<String> {
    let mut names = Vec::new();
    for kind in kinds {
        let (Some(header), Some(ies)) = (readable::fields::<H>(""), readable::fields::<M>(kind))
        else {
            continue;
        };
        let ies = (ies.iter()).filter(|ie| !["unknown_ies", "optional_ie_order"].contains(ie));
        for name in header
            .iter()
            .chain(ies)
            .map(|field| printed_static(field).name)
        {
            if !names.iter().any(|known| known == name) {
                names.push(name.to_owned());
            }
        }
    }
    names
}

thread_local! {
    /// Who sent the message whose IEs are being visited, where its type
    /// says so.
    static SENT: std::cell::Cell<Option<PcoDirection>> = const { std::cell::Cell::new(None) };
}

/// The direction of the message whose IEs are visited, until this is
/// dropped: the units of its protocol configuration options are read by it.
pub(crate) struct Sent(Option<PcoDirection>);

impl Sent {
    /// The IEs that are visited from here on are those of a message that
    /// was sent in `direction`, or of one whose type does not say.
    pub(crate) fn by(direction: Option<PcoDirection>) -> Self {
        Self(SENT.with(|sent| sent.replace(direction)))
    }

    /// The direction of the message whose IEs are visited.
    pub(crate) fn direction() -> Option<PcoDirection> {
        SENT.with(|sent| sent.get())
    }
}

impl Drop for Sent {
    fn drop(&mut self) {
        SENT.with(|sent| sent.set(self.0));
    }
}

/// The value of an extended emergency number list (TS 24.301 §9.9.3.37A,
/// TS 24.501 §9.11.3.26): where the list is valid, and its numbers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ExtendedEmergencyNumbers {
    /// Whether the list is valid only in the PLMN that it came from, and
    /// not in the whole country.
    pub(crate) valid_only_in_plmn: bool,
    /// The numbers, in their order.
    pub(crate) numbers: Vec<crate::common::ts24301::ExtendedEmergencyNumber>,
}

/// A unit of the protocol configuration options (TS 24.008 §10.5.6.3): a
/// configuration protocol with its packet, or a container of the additional
/// parameters list by the name that Table 10.5.154 gives its identifier in
/// the direction of the message. A container that has no name here is its
/// identifier and its octets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ConfigurationUnit {
    /// Link control protocol (C021H): its packet.
    Lcp(Packet<Lcp>),
    /// Password authentication protocol (C023H): its packet.
    Pap(Packet<Pap>),
    /// Challenge handshake authentication protocol (C223H): its packet.
    Chap(Packet<Chap>),
    /// Internet protocol control protocol (8021H): its packet.
    Ipcp(Packet<Ipcp>),
    // What the MS asks for or says of itself: no contents.
    PCscfIpv6AddressRequest,
    ImCnSubsystemSignallingFlag,
    DnsServerIpv6AddressRequest,
    MsSupportOfNetworkRequestedBearerControl,
    IpAddressAllocationViaNasSignalling,
    Ipv4AddressAllocationViaDhcpv4,
    PCscfIpv4AddressRequest,
    DnsServerIpv4AddressRequest,
    MsisdnRequest,
    Ipv4LinkMtuRequest,
    MsSupportOfLocalAddressInTft,
    PCscfReselectionSupport,
    NonIpLinkMtuRequest,
    // What the network gives.
    PCscfIpv6Address(Ipv6Addr),
    DnsServerIpv6Address(Ipv6Addr),
    SelectedBearerControlMode(BearerControlMode),
    PCscfIpv4Address(Ipv4Addr),
    DnsServerIpv4Address(Ipv4Addr),
    Ipv4LinkMtu(u16),
    NetworkSupportOfLocalAddressInTft,
    NonIpLinkMtu(u16),
    /// Another protocol or container.
    Container {
        identifier: u16,
        contents: Vec<u8>,
    },
}

/// The selected bearer control mode (TS 24.008 Table 10.5.154).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum BearerControlMode {
    MsOnly,
    MsNw,
}

impl ConfigurationUnit {
    /// The unit that `entry` is in a message sent in `direction`.
    fn of(entry: &PcoEntry, direction: PcoDirection) -> Self {
        use PcoDirection::{Downlink, Uplink};
        let contents = entry.contents.as_slice();
        let ipv6 = || <[u8; 16]>::try_from(contents).ok().map(Ipv6Addr::from);
        let ipv4 = || <[u8; 4]>::try_from(contents).ok().map(Ipv4Addr::from);
        let number = || <[u8; 2]>::try_from(contents).ok().map(u16::from_be_bytes);
        let unit = match (direction, entry.identifier, contents) {
            (_, 0xc021, _) => Some(Self::Lcp(Packet::of(contents))),
            (_, 0xc023, _) => Some(Self::Pap(Packet::of(contents))),
            (_, 0xc223, _) => Some(Self::Chap(Packet::of(contents))),
            (_, 0x8021, _) => Some(Self::Ipcp(Packet::of(contents))),
            (_, 0x0002, []) => Some(Self::ImCnSubsystemSignallingFlag),
            (Uplink, 0x0001, []) => Some(Self::PCscfIpv6AddressRequest),
            (Uplink, 0x0003, []) => Some(Self::DnsServerIpv6AddressRequest),
            (Uplink, 0x0005, []) => Some(Self::MsSupportOfNetworkRequestedBearerControl),
            (Uplink, 0x000a, []) => Some(Self::IpAddressAllocationViaNasSignalling),
            (Uplink, 0x000b, []) => Some(Self::Ipv4AddressAllocationViaDhcpv4),
            (Uplink, 0x000c, []) => Some(Self::PCscfIpv4AddressRequest),
            (Uplink, 0x000d, []) => Some(Self::DnsServerIpv4AddressRequest),
            (Uplink, 0x000e, []) => Some(Self::MsisdnRequest),
            (Uplink, 0x0010, []) => Some(Self::Ipv4LinkMtuRequest),
            (Uplink, 0x0011, []) => Some(Self::MsSupportOfLocalAddressInTft),
            (Uplink, 0x0012, []) => Some(Self::PCscfReselectionSupport),
            (Uplink, 0x0015, []) => Some(Self::NonIpLinkMtuRequest),
            (Downlink, 0x0001, _) => ipv6().map(Self::PCscfIpv6Address),
            (Downlink, 0x0003, _) => ipv6().map(Self::DnsServerIpv6Address),
            (Downlink, 0x0005, [1]) => {
                Some(Self::SelectedBearerControlMode(BearerControlMode::MsOnly))
            }
            (Downlink, 0x0005, [2]) => {
                Some(Self::SelectedBearerControlMode(BearerControlMode::MsNw))
            }
            (Downlink, 0x000c, _) => ipv4().map(Self::PCscfIpv4Address),
            (Downlink, 0x000d, _) => ipv4().map(Self::DnsServerIpv4Address),
            (Downlink, 0x0010, _) => number().map(Self::Ipv4LinkMtu),
            (Downlink, 0x0011, []) => Some(Self::NetworkSupportOfLocalAddressInTft),
            (Downlink, 0x0015, _) => number().map(Self::NonIpLinkMtu),
            _ => None,
        };
        unit.unwrap_or_else(|| Self::Container {
            identifier: entry.identifier,
            contents: contents.to_vec(),
        })
    }

    /// The protocol or container that the unit is in a message sent in
    /// `direction`: `None` for a unit of the other direction, and for a
    /// packet that its protocol does not have.
    fn entry(&self, direction: PcoDirection) -> Option<PcoEntry> {
        use PcoDirection::{Downlink, Uplink};
        let (sent, identifier, contents) = match self {
            Self::Lcp(packet) => (None, 0xc021, packet.octets()?),
            Self::Pap(packet) => (None, 0xc023, packet.octets()?),
            Self::Chap(packet) => (None, 0xc223, packet.octets()?),
            Self::Ipcp(packet) => (None, 0x8021, packet.octets()?),
            Self::ImCnSubsystemSignallingFlag => (None, 0x0002, Vec::new()),
            Self::PCscfIpv6AddressRequest => (Some(Uplink), 0x0001, Vec::new()),
            Self::DnsServerIpv6AddressRequest => (Some(Uplink), 0x0003, Vec::new()),
            Self::MsSupportOfNetworkRequestedBearerControl => (Some(Uplink), 0x0005, Vec::new()),
            Self::IpAddressAllocationViaNasSignalling => (Some(Uplink), 0x000a, Vec::new()),
            Self::Ipv4AddressAllocationViaDhcpv4 => (Some(Uplink), 0x000b, Vec::new()),
            Self::PCscfIpv4AddressRequest => (Some(Uplink), 0x000c, Vec::new()),
            Self::DnsServerIpv4AddressRequest => (Some(Uplink), 0x000d, Vec::new()),
            Self::MsisdnRequest => (Some(Uplink), 0x000e, Vec::new()),
            Self::Ipv4LinkMtuRequest => (Some(Uplink), 0x0010, Vec::new()),
            Self::MsSupportOfLocalAddressInTft => (Some(Uplink), 0x0011, Vec::new()),
            Self::PCscfReselectionSupport => (Some(Uplink), 0x0012, Vec::new()),
            Self::NonIpLinkMtuRequest => (Some(Uplink), 0x0015, Vec::new()),
            Self::PCscfIpv6Address(address) => (Some(Downlink), 0x0001, address.octets().to_vec()),
            Self::DnsServerIpv6Address(address) => {
                (Some(Downlink), 0x0003, address.octets().to_vec())
            }
            Self::SelectedBearerControlMode(mode) => {
                let mode = match mode {
                    BearerControlMode::MsOnly => 1,
                    BearerControlMode::MsNw => 2,
                };
                (Some(Downlink), 0x0005, vec![mode])
            }
            Self::PCscfIpv4Address(address) => (Some(Downlink), 0x000c, address.octets().to_vec()),
            Self::DnsServerIpv4Address(address) => {
                (Some(Downlink), 0x000d, address.octets().to_vec())
            }
            Self::Ipv4LinkMtu(octets) => (Some(Downlink), 0x0010, octets.to_be_bytes().to_vec()),
            Self::NetworkSupportOfLocalAddressInTft => (Some(Downlink), 0x0011, Vec::new()),
            Self::NonIpLinkMtu(octets) => (Some(Downlink), 0x0015, octets.to_be_bytes().to_vec()),
            Self::Container {
                identifier,
                contents,
            } => (None, *identifier, contents.clone()),
        };
        sent.is_none_or(|sent| sent == direction)
            .then_some(PcoEntry {
                identifier,
                contents,
            })
    }

    /// The units of `pco`, of a message sent in `direction`.
    pub(crate) fn units(pco: &Pco, direction: PcoDirection) -> Vec<Self> {
        (pco.entries.iter())
            .map(|entry| Self::of(entry, direction))
            .collect()
    }

    /// The options that have `units`, in a message sent in `direction`.
    pub(crate) fn options(units: &[Self], direction: PcoDirection) -> Option<Pco> {
        let entries = units.iter().map(|unit| unit.entry(direction));
        Some(Pco {
            configuration_protocol: 0,
            entries: entries.collect::<Option<_>>()?,
        })
    }
}

/// [`Decoded`] for the IE types of the protocol configuration options: the
/// units of the options, read by the direction of the message that is
/// visited. Options that are not in a message whose type says who sends
/// it, and octets that the units do not give back, have no value.
macro_rules! configuration_options_ie {
    ($($ie:ty),+ $(,)?) => {$(
        $crate::common::view::decoded_ie!(
            $ie: Vec<$crate::common::view::ConfigurationUnit>,
            |ie| {
                use $crate::common::view::{ConfigurationUnit, Sent};
                let direction = Sent::direction()?;
                let options = ie.pco(direction)?;
                let same = <$ie>::from_pco(&options, direction)?.value == ie.value;
                same.then(|| ConfigurationUnit::units(&options, direction))
            },
            |_, units| {
                use $crate::common::view::{ConfigurationUnit, Sent};
                let direction = Sent::direction()?;
                <$ie>::from_pco(&ConfigurationUnit::options(&units, direction)?, direction)
            }
        );
    )+};
}

/// The messages that containers may carry inside one another and that are
/// still read as messages: a container further in has its octets alone. No
/// message of TS 24.501 or TS 24.301 nests this deep, and the octets of a
/// peer may: a view is built by a function that calls itself for the message
/// of a container.
const NESTED: usize = 8;

thread_local! {
    static INSIDE: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// One more message inside a container, until this is dropped.
pub(crate) struct Inside(());

impl Inside {
    /// What an edit is told of a message that is too far in.
    pub(crate) const REFUSED: &'static str =
        "the message is in more containers than are read as messages: write its octets";

    /// `None` where a container is no longer read as its message.
    pub(crate) fn enter() -> Option<Self> {
        INSIDE.with(|inside| {
            (inside.get() < NESTED).then(|| {
                inside.set(inside.get() + 1);
                Self(())
            })
        })
    }
}

impl Drop for Inside {
    fn drop(&mut self) {
        INSIDE.with(|inside| inside.set(inside.get() - 1));
    }
}

/// The header and the members of the message struct in the readable serde
/// form of a message, `{family: [header, {kind: {..}}]}`, read through
/// `security-protected`.
fn parts(message: &mut Value) -> Option<(&mut Value, &mut Map<String, Value>)> {
    let (family, parts) = message.as_object_mut()?.iter_mut().next()?;
    let [header, body] = parts.as_array_mut()?.as_mut_slice() else {
        return None;
    };
    if family == "security-protected" {
        return self::parts(body);
    }
    Some((
        header,
        body.as_object_mut()?.values_mut().next()?.as_object_mut()?,
    ))
}

/// What the view `view` of a message says that it means: the value of each
/// entry, and the octets of one that has no value, as a tree has them. Two
/// messages that mean the same may differ in octets that a value does not
/// decide.
pub(crate) fn meaning(view: &Value) -> Value {
    let Some(entries) = view.as_object() else {
        return view.clone();
    };
    let meant = |entry: &Value| match (entry.get("value"), entry.get("octets")) {
        (Some(value), _) if is_message(value) => meaning(value),
        (Some(value), _) => value.clone(),
        (None, Some(octets)) => serde_json::json!({ "octets": octets }),
        (None, None) => Value::Null,
    };
    (entries.iter())
        .map(|(name, entry)| (name.clone(), meant(entry)))
        .collect::<Map<String, Value>>()
        .into()
}

/// The view that the tree of the view `view` writes: each entry by its value
/// alone, or by its octets when it has no value.
pub(crate) fn as_a_tree_writes(view: &Value) -> Value {
    let Some(entries) = view.as_object() else {
        return view.clone();
    };
    let written = |entry: &Value| match (entry.get("value"), entry.get("octets")) {
        (Some(value), _) if is_message(value) => {
            serde_json::json!({ "value": as_a_tree_writes(value) })
        }
        (Some(value), _) => serde_json::json!({ "value": value }),
        (None, Some(octets)) => serde_json::json!({ "octets": octets }),
        (None, None) => Value::Null,
    };
    (entries.iter())
        .map(|(name, entry)| (name.clone(), written(entry)))
        .collect::<Map<String, Value>>()
        .into()
}

/// The octets of a message that is ciphered, as its readable serde form has
/// them: in hexadecimal.
pub(crate) fn octets_shown(octets: &[u8]) -> Value {
    match octets.is_empty() {
        true => Value::Array(Vec::new()),
        false => hex::encode(octets).into(),
    }
}

/// The octets of an IE in its readable serde form, in hexadecimal; `size`
/// is that of a value that is a number.
fn octets_of(ie: &Value, size: usize) -> Value {
    match &ie["value"] {
        Value::Number(number) if size <= 2 => {
            format!("{:01$x}", number.as_u64().unwrap_or_default(), 2 * size).into()
        }
        Value::String(octets) => octets.as_str().into(),
        _ => "".into(),
    }
}

/// Write `octets` in hexadecimal as the value of an IE.
fn set_octets(ie: &mut Value, octets: &Value, size: usize) -> Result<(), String> {
    let written = (octets.as_str())
        .and_then(|octets| hex::decode(octets).ok())
        .ok_or_else(|| format!("{octets} is not octets in hexadecimal"))?;
    ie["value"] = match size {
        1 | 2 if written.len() == size => (written.iter())
            .fold(0_u64, |number, octet| number << 8 | u64::from(*octet))
            .into(),
        1 | 2 => return Err(format!("{octets} is not {size} octets")),
        _ => octets.clone(),
    };
    Ok(())
}

/// The entry of a view for the header that protects a message.
const SECURITY_HEADER: &str = "security-header";

/// The entry of a view for a message that is ciphered: its octets.
const CIPHERED: &str = "ciphered-message";

/// The security header and the message that it protects, in the readable
/// serde form `{"security-protected": [header, message]}` of a message.
fn protection(message: &mut Value) -> Option<(&mut Value, &mut Value)> {
    let parts = message.as_object_mut()?.get_mut("security-protected")?;
    let [header, body] = parts.as_array_mut()?.as_mut_slice() else {
        return None;
    };
    Some((header, body))
}

/// The octets of a message that is ciphered, in its readable serde form.
fn ciphered(body: &mut Value) -> Option<&mut Value> {
    body.as_object_mut()?.get_mut("opaque")
}

pub(crate) fn to_view<M: Viewed>(message: &M) -> Value {
    // The view is made of the header and of each IE that the message has:
    // the message is not put in its serde form, which has every octet of
    // every IE as a number, and its unknown IEs.
    let mut view = Map::new();
    let entry = |member: &str, value: Value| Value::from(Map::from_iter([(member.into(), value)]));
    // The header that protects a message is beside the entries of the
    // message, which are those of a plain one; one that is ciphered has
    // its octets alone.
    if let Some((header, ciphered)) = message.protection() {
        view.insert(SECURITY_HEADER.into(), entry("value", header));
        if let Some(octets) = ciphered {
            view.insert(CIPHERED.into(), entry("octets", octets));
        }
    }
    let Some(Value::Object(header)) = message.header() else {
        return view.into();
    };
    for (name, value) in header {
        view.insert(name, entry("value", value));
    }
    message.ies(&mut |field| {
        let mut entry = Map::from_iter([("octets".to_string(), field.octets.hex().into())]);
        entry
            .extend((field.ie.and_then(|ie| ie.value())).map(|value| ("value".to_string(), value)));
        view.insert(field.printed.to_owned(), entry.into());
    });
    // An optional IE that the message does not have.
    message.absent(&mut |name| {
        view.insert(name.to_owned(), Value::Null);
    });
    view.into()
}

/// The `value` and the `octets` that the entry of an IE in a view has.
pub(crate) fn entry(entry: Value) -> Result<[Option<Value>; 2], String> {
    let Value::Object(entry) = entry else {
        return Err(format!("{entry} is not an IE with a `value` or `octets`"));
    };
    let mut members = [None, None];
    for (name, member) in entry {
        let at = (["value", "octets"].iter())
            .position(|known| same_name(known, &name))
            .ok_or_else(|| format!("no member `{name}`, expected `value` or `octets`"))?;
        members[at] = (!member.is_null()).then_some(member);
    }
    if members == [None, None] {
        return Err("an IE is written with a `value` or `octets`".into());
    }
    Ok(members)
}

pub(crate) fn with_view<M: Viewed>(original: &M, view: Value) -> Result<M, String> {
    written(original, view, false)
}

/// The message of the kind `kind` that the view `view` describes alone:
/// `kind` names a message struct in one of the variants `families` of `M`.
pub(crate) fn from_view<M: Viewed>(
    families: &[&str],
    kind: &str,
    view: Value,
) -> Result<M, String> {
    let Value::Object(entries) = &view else {
        return Err(format!("{view} is not a view: an object of IEs by name"));
    };
    for family in families {
        let Some(blank) = readable::blank::<M>(&[family, kind]) else {
            continue;
        };
        // The message struct that `kind` names, and not the first of the enum.
        let tree = readable::to_value(&blank)?;
        let body = tree.as_object().and_then(|tree| tree.values().next());
        let named = (body.and_then(|parts| parts.get(1)?.as_object()?.keys().next()))
            .is_some_and(|name| same_name(name, kind));
        if named {
            return written(&blank.prepared(entries), view, true);
        }
    }
    Err(format!("no message `{kind}`"))
}

/// The view of the message of the kind `kind` that has nothing written yet,
/// as [`from_view`] starts from it: `None` when no variant of `families`
/// has such a message.
pub(crate) fn blank_view<M: Viewed>(families: &[&str], kind: &str) -> Option<Value> {
    families.iter().find_map(|family| {
        let blank = readable::blank::<M>(&[family, kind])?;
        // The message struct that `kind` names, and not the first of the enum.
        let tree = readable::to_value(&blank).ok()?;
        let body = tree.as_object().and_then(|tree| tree.values().next());
        (body.and_then(|parts| parts.get(1)?.as_object()?.keys().next()))
            .is_some_and(|name| same_name(name, kind))
            .then(|| to_view(&blank))
    })
}

/// The name of the `message-type` that the view `view` writes: a name as it
/// is written, or the name that a message of `M` has for a number.
pub(crate) fn message_type<M: Viewed>(view: &Value) -> Option<String> {
    let written = (view.as_object().into_iter().flatten())
        .find(|(name, _)| same_name(name, "message-type"))
        .and_then(|(_, entry)| entry.get("value"))?;
    match written.as_u64() {
        Some(number) => Some(
            M::header_name("message-type", number)?
                .as_str()?
                .to_string(),
        ),
        None => written.as_str().map(str::to_string),
    }
}

/// Whether the `message-type` that the view `view` writes is `kind`, the type
/// of the message that it is to describe alone: the header says what the
/// message is.
pub(crate) fn typed<M: Viewed>(kind: &str, view: &Value) -> Result<(), String> {
    match message_type::<M>(view).filter(|named| !same_name(named, kind)) {
        Some(named) => Err(format!(
            "`message-type` is {named}: the view is that of a message `{}`",
            printed(kind)
        )),
        None => Ok(()),
    }
}

/// The message that the view `view` of a container describes alone: its
/// `message-type` names it.
pub(crate) fn contained<M: Viewed>(view: &Value) -> Result<M, String> {
    let kind = message_type::<M>(view)
        .ok_or("the `message-type` of the view names the message of a container")?;
    from_view(M::FAMILIES, &kind, view.clone())
}

/// What the type of a message decides of its header: the fields that a tree
/// leaves out, each with its value, for the message that its `message-type`
/// names or numbers, or that has none, in the IE `container`, or alone.
pub(crate) type Decided<'a> =
    &'a dyn Fn(Option<&str>, Option<&Value>) -> Result<Vec<(&'static str, Value)>, String>;

/// The name of the `message-type` `kind` that a tree writes, by its name or
/// by the number that a message of `M` has a name for.
pub(crate) fn type_named<M: Viewed>(kind: &Value) -> Result<String, String> {
    match kind.as_u64() {
        Some(number) => M::header_name("message-type", number)
            .and_then(|named| named.as_str().map(str::to_string))
            .ok_or_else(|| format!("no message `{number}`")),
        None => Ok(kind.as_str().unwrap_or_default().to_string()),
    }
}

/// Whether `kind` is a `message-type` as a tree writes one.
fn is_type_written(kind: &Value) -> bool {
    kind.is_string() || kind.is_u64()
}

/// Whether the value of an entry of a view is the view of a message.
fn is_message(value: &Value) -> bool {
    (value.get("message-type")).is_some_and(|kind| kind.get("value").is_some())
}

/// The view `view` as a tree: each entry by its value alone, or by its
/// `octets` when it has no value, a message in a container as its own tree,
/// and without what the type of the message decides and the IEs that the
/// message does not have.
pub(crate) fn to_tree(view: &Value, container: Option<&str>, decided: Decided<'_>) -> Value {
    let Some(entries) = view.as_object() else {
        return view.clone();
    };
    let kind = entries
        .get("message-type")
        .and_then(|kind| kind.get("value"));
    let given = decided(container, kind).unwrap_or_default();
    let mut tree = Map::new();
    for (name, entry) in entries {
        let of_the_type = given.iter().find(|(field, _)| field == name);
        if of_the_type.is_some_and(|(_, value)| entry.get("value") == Some(value)) {
            continue;
        }
        let shown = match (entry.get("value"), entry.get("octets")) {
            (Some(value), _) if is_message(value) => to_tree(value, Some(name), decided),
            (Some(value), _) => value.clone(),
            (None, Some(octets)) => serde_json::json!({ "octets": octets }),
            // An optional IE that the message does not have.
            (None, None) => continue,
        };
        tree.insert(name.clone(), shown);
    }
    tree.into()
}

/// The tree of `message`, whose view is `view`: [`to_tree`], with each IE
/// whose value a message is not written from shown by its octets. A tree is
/// one that a message is written from.
pub(crate) fn tree_of<M: Viewed>(message: &M, view: &Value, decided: Decided<'_>) -> Value {
    let mut tree = to_tree(view, None, decided);
    message.ies(&mut |field| {
        let entry = &view[field.printed];
        if let (Some(ie), Some(value), Some(octets)) =
            (field.ie, entry.get("value"), entry.get("octets"))
            && tree.get(field.printed).is_some()
            && !ie.written_alone(value)
        {
            tree[field.printed] = serde_json::json!({ "octets": octets });
        }
    });
    tree
}

/// The header that protects the message of the tree `tree` and the octets
/// of a message that is ciphered, in their readable serde forms, with the
/// tree of the plain message: what the tree has beside them. A tree of a
/// plain message has no header.
#[allow(clippy::type_complexity)]
pub(crate) fn protection_of(
    tree: Value,
) -> Result<(Option<(Value, Option<Vec<u8>>)>, Value), String> {
    let Value::Object(mut members) = tree else {
        return Ok((None, tree));
    };
    let mut taken = |entry: &str| {
        let name = (members.keys().find(|name| same_name(name, entry))).cloned()?;
        members.remove(&name)
    };
    let (header, ciphered) = (taken(SECURITY_HEADER), taken(CIPHERED));
    let ciphered = match ciphered {
        Some(written) => {
            let octets = (written.as_object().filter(|written| written.len() == 1))
                .and_then(|written| written.get("octets")?.as_str())
                .and_then(|octets| hex::decode(octets).ok());
            Some(octets.ok_or_else(|| {
                format!("`{CIPHERED}` is the message as it is ciphered: it has `octets` alone")
            })?)
        }
        None => None,
    };
    match (header, ciphered) {
        (None, None) => Ok((None, members.into())),
        (None, Some(_)) => Err(format!(
            "`{CIPHERED}` is the message under a `{SECURITY_HEADER}`, which the tree does not have"
        )),
        (Some(_), Some(_)) if !members.is_empty() => Err(format!(
            "a message that is ciphered has its `{SECURITY_HEADER}` and its `{CIPHERED}` alone"
        )),
        (Some(header), ciphered) => Ok((Some((header, ciphered)), members.into())),
    }
}

/// The header of the type `H` that a tree writes as `header`: every field of
/// it.
pub(crate) fn security_header<H: DeserializeOwned>(header: &Value) -> Result<H, String> {
    readable::from_value(header).map_err(|error| format!("{SECURITY_HEADER}: {error}"))
}

/// The view that the tree `tree` writes: [`to_tree`] the other way, with
/// what the type of the message decides where the tree leaves it out.
pub(crate) fn from_tree(
    tree: &Value,
    container: Option<&str>,
    decided: Decided<'_>,
) -> Result<Value, String> {
    let entries = tree
        .as_object()
        .ok_or("a message is written as its `message-type` and its IEs by name")?;
    let kind = (entries.iter()).find(|(name, _)| readable::same_name(name, "message-type"));
    let kind = match kind {
        Some((_, kind)) if is_type_written(kind) => Some(kind),
        Some(_) => return Err("a `message-type` is a name or the number of one".into()),
        None => None,
    };
    let mut view = Map::new();
    for (field, value) in decided(container, kind)? {
        if !entries.keys().any(|name| readable::same_name(name, field)) {
            view.insert(field.into(), serde_json::json!({ "value": value }));
        }
    }
    for (name, written) in entries {
        let octets = written.as_object().filter(|written| written.len() == 1);
        let entry = match octets.and_then(|written| written.get("octets")) {
            Some(octets) => serde_json::json!({ "octets": octets }),
            // The message of a container, by its own tree.
            None if written.get("message-type").is_some_and(is_type_written) => {
                let _inside = Inside::enter().ok_or(Inside::REFUSED)?;
                serde_json::json!({ "value": from_tree(written, Some(name), decided)? })
            }
            None => serde_json::json!({ "value": written }),
        };
        view.insert(name.clone(), entry);
    }
    Ok(view.into())
}

/// The message that `view` describes: `original` as the view edits it, or
/// with `alone` a message that has nothing but what the view writes.
fn written<M: Viewed>(original: &M, view: Value, alone: bool) -> Result<M, String> {
    let Value::Object(view) = view else {
        return Err(format!("{view} is not a view: an object of IEs by name"));
    };
    // The entries by the letters of their names, which are those of a name
    // however it is written.
    let mut entries = BTreeMap::new();
    for (name, entry) in view {
        if let Some((name, _)) = entries.insert(letters(&name), (name, entry)) {
            return Err(format!("`{name}` is named twice"));
        }
    }
    // An optional IE that the message does not have stays out when its
    // entry is null. One that has an entry is added without a value, and
    // then written as any other. The message is edited in its serde form,
    // without its unknown IEs and the order of its optional IEs, which no
    // view writes: the message that is written gets them back.
    let received = original;
    let mut tree = readable::shown(original)?;
    // The header that protects the message is written whole, as a field of
    // a header is, and a message that is ciphered by its octets.
    let protected = protection(&mut tree).is_some().then(|| tree.clone());
    if let Some((header, body)) = protection(&mut tree) {
        let mut taken = |name: &str| entries.remove(&letters(name)).map(|(_, entry)| entry);
        match taken(SECURITY_HEADER).map(entry) {
            Some(Ok([Some(written), None])) => *header = written,
            Some(Err(error)) => return Err(format!("{SECURITY_HEADER}: {error}")),
            _ => {
                return Err(format!(
                    "`{SECURITY_HEADER}` is the header that protects the message: it has a \
                     `value` alone"
                ));
            }
        }
        if let Some(octets) = ciphered(body) {
            match taken(CIPHERED).map(entry) {
                Some(Ok([None, Some(written)])) if written.as_str().is_some_and(is_hex) => {
                    *octets = written;
                }
                _ => {
                    return Err(format!(
                        "`{CIPHERED}` is the message as it is ciphered: it has `octets` alone"
                    ));
                }
            }
        }
    }
    let mut added = Vec::new();
    if let Some((_, members)) = parts(&mut tree) {
        for (name, ie) in members.iter_mut().filter(|(_, ie)| ie.is_null()) {
            let Entry::Occupied(entry) = entries.entry(letters(name)) else {
                continue;
            };
            if entry.get().1.is_null() {
                entry.remove();
            } else {
                *ie = original.blank(name).unwrap_or_default();
                added.push(name.clone());
            }
        }
    }
    let with_added: M;
    let original = match added.is_empty() {
        false => {
            with_added = readable::from_value(&tree)?;
            &with_added
        }
        true => original,
    };
    // An entry that is null is one left out.
    let mut take = |name: &str| {
        let (_, entry) = entries.remove(&letters(name))?;
        Some(entry).filter(|entry| !entry.is_null())
    };
    let before = to_view(original);
    let mut failure = None;
    // The values to encode: the field, the value and whether the octets
    // were written too.
    let mut values = Vec::new();
    if let Some((header, members)) = parts(&mut tree) {
        for (name, value) in header.as_object_mut().into_iter().flatten() {
            match take(name).map(entry) {
                // A field that reads as a name takes the number of one too.
                Some(Ok([Some(written), None])) => {
                    let named = match (&*value, written.as_u64()) {
                        (Value::String(_), Some(number)) => M::header_name(name, number),
                        _ => None,
                    };
                    *value = named.unwrap_or(written);
                }
                Some(Err(error)) => failure = Some(format!("{name}: {error}")),
                None if M::SPARE.contains(&name.as_str()) => {}
                None if alone => failure = Some(format!("`{name}` is not written")),
                _ => failure = Some(format!("`{name}` is the header: it has a `value` alone")),
            }
        }
        original.ies(&mut |visited| {
            let (field, name, optional) = (visited.name, visited.printed, visited.optional);
            let size = visited.octets.size();
            let Some(serialized) = members.get_mut(name) else {
                return;
            };
            // An IE that the view leaves out is taken out of the message.
            let [value, octets] = match take(name).map(entry) {
                Some(Ok(written)) => written,
                Some(Err(error)) => return failure = Some(format!("{name}: {error}")),
                None if optional => return *serialized = Value::Null,
                None if alone => return failure = Some(format!("`{name}` is not written")),
                None => return failure = Some(format!("`{name}` is mandatory: it stays")),
            };
            let was = |member: &str| before.get(name).and_then(|was| was.get(member));
            // What is written of an IE that is added is written, whatever it
            // is, and so is each IE of a message that the view describes
            // alone: octets that happen to be those of an IE without a value
            // are still the ones to send.
            let fresh = alone || added.iter().any(|added| added == name);
            let octets = octets.filter(|octets| fresh || Some(octets) != was("octets"));
            if let Some(Err(error)) =
                (octets.as_ref()).map(|octets| set_octets(serialized, octets, size))
            {
                failure = Some(format!("{name}: {error}"));
            }
            let written = |value: &Value| fresh || Some(value) != was("value");
            if let Some(value) = value.filter(written) {
                values.push((field, value, octets, size));
            }
        });
    }
    if let Some((name, _)) = entries.into_values().next() {
        return Err(format!("`{name}` is no IE of the message"));
    }
    if let Some(failure) = failure {
        return Err(failure);
    }
    let mut message: M = readable::from_value(&tree)?;
    if values.is_empty() {
        return checked(message, protected, received);
    }
    // The IEs of a written value, encoded from it. Octets written too are
    // kept: the value has to be the one they have.
    if let Some((_, members)) = parts(&mut tree) {
        message.ies(&mut |visited| {
            let (field, name, ie) = (visited.name, visited.printed, visited.ie);
            let Some(at) = values.iter().position(|(written, ..)| *written == field) else {
                return;
            };
            let (_, value, octets, size) = values.swap_remove(at);
            let Some(ie) = ie else {
                failure = Some(format!("{name}: this IE has octets and no value to write"));
                return;
            };
            // A value that the octets written have is not encoded again.
            if octets.is_some() && ie.value().as_ref() == Some(&value) {
                return;
            }
            // Octets written too are those of the value: an IE that shares
            // its octet with another has more in its value than in them.
            let same = |encoded: &Value| {
                let of = |octets: &Value| octets.as_str().and_then(|text| hex::decode(text).ok());
                octets
                    .as_ref()
                    .is_none_or(|octets| of(octets) == of(&octets_of(encoded, size)))
            };
            match ie.encoded(&value) {
                Ok((encoded, _)) if same(&encoded) => {
                    members.insert(name.to_owned(), encoded);
                }
                Ok(_) => {
                    failure = Some(format!(
                        "{name}: the octets and the value that are written disagree"
                    ));
                }
                Err(error) => failure = Some(format!("{name}: {error}")),
            }
        });
    }
    if let Some(failure) = failure {
        return Err(failure);
    }
    message = readable::from_value(&tree)?;
    checked(message, protected, received)
}

/// `message`, which a view wrote from the one of the readable serde form
/// `original`, with what `received` keeps of how it was received, unless it
/// keeps the message authentication code of a message that it no longer
/// protects: the code is that of the octets it was computed over.
fn checked<M: Viewed>(mut message: M, original: Option<Value>, received: &M) -> Result<M, String> {
    // A message that no header protected has no code to keep.
    if let Some(mut original) = original {
        let mut written = readable::shown(&message)?;
        if let (Some((header, body)), Some((old_header, old_body))) =
            (protection(&mut written), protection(&mut original))
        {
            let code = |header: &Value| header.get("message-authentication-code").cloned();
            if body != old_body && code(header) == code(old_header) {
                return Err(format!(
                    "the message authentication code of `{SECURITY_HEADER}` is that of the \
                     message as it was: write the code of the edited message, or edit the \
                     plain message"
                ));
            }
        }
    }
    message.keep_received(received);
    Ok(message)
}

/// Whether `text` is octets in hexadecimal.
fn is_hex(text: &str) -> bool {
    hex::decode(text).is_ok()
}

/// The IE that `encode` builds from the readable form `value` of a `D`,
/// if it decodes to that value.
pub(crate) fn built<T: Decoded, D: Serialize + DeserializeOwned>(
    ie: &T,
    value: &Value,
    encode: fn(&T, D) -> Option<T>,
) -> Result<T, String> {
    let typed: D = readable::from_value(value)?;
    let written = readable::to_value(&typed)?;
    let new = encode(ie, typed).ok_or_else(|| format!("no IE of this type is {written}"))?;
    carried(new, &written)
}

/// `ie`, if `written` is the value its octets have.
pub(crate) fn carried<T: Decoded>(ie: T, written: &Value) -> Result<T, String> {
    match ie.decoded() {
        Some(carried) if carried == *written => Ok(ie),
        Some(carried) => Err(format!(
            "{written} cannot be encoded: the IE would be {carried}"
        )),
        None => Err(format!("{written} cannot be encoded")),
    }
}

/// The members of a value that is an object, for the macros below.
pub(crate) fn members(value: &Value) -> Result<&Map<String, Value>, String> {
    (value.as_object()).ok_or_else(|| format!("{value} is not an object of the members of the IE"))
}

/// Octets as the numbers they are, where an IE has a list of identities.
pub(crate) fn numbers(octets: &[u8]) -> Vec<u16> {
    octets.iter().copied().map(u16::from).collect()
}

/// The octets of a list of numbers; `None` for a number above 255.
pub(crate) fn octets(numbers: &[u16]) -> Option<Vec<u8>> {
    numbers
        .iter()
        .map(|number| u8::try_from(*number).ok())
        .collect()
}

/// A value that is a name where the specification has one, else a number:
/// a coded value, or a timer that runs or is `deactivated`.
#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum Code<E, N = u8> {
    Name(E),
    Number(N),
}

impl<E, N> Code<E, N> {
    /// `number`, by the name it has, if any.
    pub(crate) fn of(name: Option<E>, number: N) -> Self {
        name.map_or(Self::Number(number), Self::Name)
    }
}

/// A number, also written `"0x…"`, is read as one and anything else as a
/// name, so that the error for a name that does not exist lists those that
/// do.
impl<'de, E: DeserializeOwned, N: DeserializeOwned> Deserialize<'de> for Code<E, N> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let hexadecimal = |text: &str| text.starts_with("0x") || text.starts_with("0X");
        if value.is_number() || value.as_str().is_some_and(hexadecimal) {
            readable::from_value(&value).map(Self::Number)
        } else {
            readable::from_value(&value).map(Self::Name)
        }
        .map_err(serde::de::Error::custom)
    }
}

/// The value of a GPRS timer: its seconds, or that it is deactivated.
pub(crate) type Timer = Code<Deactivated, u64>;

/// The name of a timer that does not run.
#[derive(Serialize, Deserialize)]
pub(crate) enum Deactivated {
    Deactivated,
}

/// The single-bit flags of an IE type, as `nas_ie_flags!` lists them.
pub(crate) trait Flags {
    /// Every flag by its name.
    fn flags(&self) -> Vec<(&'static str, bool)>;

    /// Set the flag `name`; `false` when the IE has no such flag.
    fn set_flag(&mut self, name: &str, value: bool) -> bool;

    /// Whether the IE has no octet of flags yet.
    fn is_empty(&self) -> bool;
}

/// The octets of the flags and the fields of an IE: a half octet is always
/// there.
pub(crate) trait FlagOctets {
    fn none(&self) -> bool;

    /// One more octet of zeros; `false` for octets that do not grow.
    fn longer(&mut self) -> bool;

    /// How many bits there are.
    fn bits(&self) -> usize;

    /// The bit `bit`, counted from the lowest of the first octet.
    fn bit(&self, bit: usize) -> bool;

    /// Change the bit `bit`.
    fn flip(&mut self, bit: usize);
}

impl FlagOctets for crate::common::Octets {
    fn none(&self) -> bool {
        self.is_empty()
    }

    fn longer(&mut self) -> bool {
        self.push(0);
        true
    }

    fn bits(&self) -> usize {
        8 * self.len()
    }

    fn bit(&self, bit: usize) -> bool {
        self[bit / 8] >> (bit % 8) & 1 == 1
    }

    fn flip(&mut self, bit: usize) {
        self[bit / 8] ^= 1 << (bit % 8);
    }
}

impl FlagOctets for u8 {
    fn none(&self) -> bool {
        false
    }

    fn longer(&mut self) -> bool {
        false
    }

    fn bits(&self) -> usize {
        8
    }

    fn bit(&self, bit: usize) -> bool {
        *self >> bit & 1 == 1
    }

    fn flip(&mut self, bit: usize) {
        *self ^= 1 << bit;
    }
}

/// An IE type that [`fields_ie!`] gives a value: its octets.
pub(crate) trait Fields: Clone {
    fn octets(&mut self) -> &mut dyn FlagOctets;
}

/// What the setter of a member says of the value that it wrote: nothing, and
/// the member is read back to see that the IE has it, or whether the IE has
/// it exactly as it was written.
pub(crate) trait Wrote {
    fn exact(self) -> bool;
}

impl Wrote for () {
    fn exact(self) -> bool {
        false
    }
}

impl Wrote for bool {
    fn exact(self) -> bool {
        self
    }
}

/// Write the coded value of a field of `ie`: by its name with `named`, the
/// setter of the type, or as the number that `raw` reads back. A number is
/// the code itself, whether the specification names it or not: `true` when
/// the IE has it, which then reads as its name if it has one.
pub(crate) fn write_code<T: Fields + Serialize + DeserializeOwned, E>(
    ie: &mut T,
    code: Code<E>,
    named: fn(&mut T, E),
    raw: fn(&T) -> u8,
) -> bool {
    match code {
        Code::Name(name) => {
            named(ie, name);
            false
        }
        Code::Number(number) => {
            set_number(ie, number, raw);
            raw(ie) == number
        }
    }
}

/// Whether a coded value that was written as `code` is the one that an IE
/// now reads as `now`, of the number `raw`: the name that was written, or
/// the number, which is the code whether it has a name or not.
pub(crate) fn wrote<E: Serialize>(code: &Code<E>, now: &Code<E>, raw: u8) -> bool {
    match code {
        Code::Number(number) => *number == raw,
        name => readable::to_value(name).ok() == readable::to_value(now).ok(),
    }
}

/// Write `number` in the bits that `raw` reads the coded value of a field
/// from. A code without a name has no setter: the bits are those that change
/// what `raw` reads, in an IE that is long enough to have them, and they
/// take the first combination that reads as `number`. An IE in which none
/// does is left as it is.
fn set_number<T: Fields + Serialize + DeserializeOwned>(ie: &mut T, number: u8, raw: fn(&T) -> u8) {
    let field = |ie: &mut T| -> Vec<usize> {
        let read = raw(ie);
        let mut bits = Vec::new();
        for bit in 0..ie.octets().bits() {
            ie.octets().flip(bit);
            if raw(ie) != read {
                bits.push(bit);
            }
            ie.octets().flip(bit);
        }
        bits
    };
    let mut written = ie.clone();
    let mut bits = field(&mut written);
    // A field beyond the octets that the IE has: a setter gives it them,
    // and the length that they have.
    for _ in 0..16 {
        if !bits.is_empty() || !written.octets().longer() {
            break;
        }
        bits = field(&mut written);
    }
    if bits.is_empty() || bits.len() > 8 {
        return;
    }
    for combination in 0..1_u16 << bits.len() {
        for (at, bit) in bits.iter().enumerate() {
            if written.octets().bit(*bit) != (combination >> at & 1 == 1) {
                written.octets().flip(*bit);
            }
        }
        if raw(&written) == number {
            *ie = written;
            return;
        }
    }
}

/// Set the flag `name` of `ie` as the member of a value has it. In an IE
/// that is `built` from the value, every flag written has its octet.
pub(crate) fn set_flag<T: Flags>(
    ie: &mut T,
    name: &str,
    value: &Value,
    built: bool,
) -> Result<(), String> {
    let flags = ie.flags();
    let names: Vec<_> = flags.iter().map(|(flag, _)| *flag).collect();
    let Some(flag) = readable::named(&names, name) else {
        let flags: Vec<_> = names.iter().map(|flag| printed(flag)).collect();
        return Err(format!(
            "no member `{name}`, expected one of {}",
            flags.join(", ")
        ));
    };
    let current = flags.contains(&(*flag, true));
    let value = (value.as_bool()).ok_or_else(|| format!("{name}: {value} is not true or false"))?;
    // A flag that is as written is left alone: setting one extends the
    // value up to its octet.
    if (built || current != value)
        && !(ie.set_flag(flag, value) && ie.flags().contains(&(*flag, value)))
    {
        return Err(format!("{name} cannot be {value}"));
    }
    Ok(())
}

/// [`Decoded`] for an IE type: its value is a `$form`, which `$decode`
/// reads and `$encode` builds the IE of. Octets that `$decode` reads and
/// `$encode` does not build have no value: what a view shows can be
/// written.
macro_rules! decoded_ie {
    ($ie:ty: $form:ty, $decode:expr, $encode:expr) => {
        impl $crate::common::view::Decoded for $ie {
            fn unwritten() -> Self {
                <$ie>::blank()
            }

            fn decoded(&self) -> Option<serde_json::Value> {
                let decode: fn(&Self) -> Option<$form> = $decode;
                let encode: fn(&Self, $form) -> Option<Self> = $encode;
                let value = $crate::common::readable::to_value(&decode(self)?).ok()?;
                let typed: $form = $crate::common::readable::from_value(&value).ok()?;
                let again = decode(&encode(self, typed)?)?;
                ($crate::common::readable::to_value(&again).ok()? == value).then_some(value)
            }

            fn with_decoded(&self, value: &serde_json::Value) -> std::result::Result<Self, String> {
                let encode: fn(&Self, $form) -> Option<Self> = $encode;
                $crate::common::view::built(self, value, encode)
            }
        }
    };
}

/// [`Decoded`] for an IE type that is one coded value in a `u8`: `$name`
/// reads the name and `$from` builds the IE of a name. A number that does
/// not encode back from its name stays a number, and a number that is
/// written is the code, whether it has a name or not.
macro_rules! code_ie {
    ($ie:ty, $code:ty, $name:expr, $from:expr) => {
        impl $crate::common::view::Decoded for $ie {
            fn unwritten() -> Self {
                <$ie>::blank()
            }
            fn decoded(&self) -> Option<serde_json::Value> {
                let name: fn(&$ie) -> Option<$code> = $name;
                let from: fn($code) -> $ie = $from;
                let name = name(self).filter(|code| from(*code).value == self.value);
                let code = $crate::common::view::Code::of(name, self.value);
                $crate::common::readable::to_value(&code).ok()
            }

            fn with_decoded(&self, value: &serde_json::Value) -> std::result::Result<Self, String> {
                use $crate::common::view::Code;
                let from: fn($code) -> $ie = $from;
                match $crate::common::readable::from_value::<Code<$code>>(value)? {
                    Code::Name(code) => {
                        let written =
                            $crate::common::readable::to_value(&Code::<$code>::Name(code))?;
                        $crate::common::view::carried(from(code), &written)
                    }
                    Code::Number(number) => {
                        let new = <$ie>::new(number);
                        match new.value == number {
                            true => Ok(new),
                            false => Err(format!("{number} cannot be encoded")),
                        }
                    }
                }
            }
        }
    };
}

/// [`Decoded`] for an IE type whose octets are one named value: `$get`
/// reads the name and `$from` builds the IE of a name. Octets that are not
/// those of their name have no value.
macro_rules! named_ie {
    ($ie:ty, $name:ty, $get:expr, $from:expr) => {
        $crate::common::view::decoded_ie!(
            $ie: $name,
            |ie| {
                let get: fn(&$ie) -> Option<$name> = $get;
                let from: fn($name) -> $ie = $from;
                get(ie).filter(|name| from(*name).value == ie.value)
            },
            |_, name| {
                let from: fn($name) -> $ie = $from;
                Some(from(name))
            }
        );
    };
}

/// [`Decoded`] for an IE type with several typed fields: an object of
/// `"member": getter, setter;`, and of the flags of the type after `flags`.
/// Encoding sets the members that are written and differ from the IE, and
/// every member that is written in an IE without octets. After `exact`, the
/// octets that the members do not give back have no value: those of digits
/// that are no digits.
macro_rules! fields_ie {
    ($ie:ty { $($key:literal: $get:expr, $set:expr;)* } $($flags:ident)?) => {
        impl $crate::common::view::Fields for $ie {
            fn octets(&mut self) -> &mut dyn $crate::common::view::FlagOctets {
                &mut self.value
            }
        }

        impl $crate::common::view::Decoded for $ie {

            fn unwritten() -> Self {
                <$ie>::blank()
            }
            fn decoded(&self) -> Option<serde_json::Value> {
                #[allow(unused_mut)]
                let mut members = serde_json::Map::new();
                $(
                    let get: fn(&Self) -> _ = $get;
                    let member = $crate::common::readable::to_value(&get(self)).ok()?;
                    members.insert($key.into(), member);
                )*
                $crate::common::view::fields_ie!(@flags self, members $(, $flags)?);
                let members: serde_json::Value = members.into();
                $crate::common::view::fields_ie!(@shown self, members $(, $flags)?)
            }

            fn with_decoded(&self, value: &serde_json::Value) -> std::result::Result<Self, String> {
                #[allow(unused_imports)]
                use $crate::common::readable::{from_value, same_name, to_value};
                let mut ie = self.clone();
                // An IE without octets is built from the value: a member
                // that is written has its octet, whatever it is.
                #[allow(unused_variables)]
                let built = $crate::common::view::FlagOctets::none(&self.value);
                for (name, written) in $crate::common::view::members(value)? {
                    $(
                        if same_name(name, $key) {
                            let get: fn(&Self) -> _ = $get;
                            let set: fn(&mut Self, _) -> _ = $set;
                            if built || to_value(&get(&ie))? != *written {
                                let typed = from_value(written).map_err(|e| format!("{name}: {e}"))?;
                                let typed_form = to_value(&typed)?;
                                // A setter that says nothing of what it wrote
                                // is checked by what the IE now reads as.
                                #[allow(clippy::let_unit_value)]
                                let wrote = set(&mut ie, typed);
                                let exact = $crate::common::view::Wrote::exact(wrote);
                                let now = to_value(&get(&ie))?;
                                if !exact && now != typed_form {
                                    return Err(format!(
                                        "{name} cannot be {written}: it would be {now}"
                                    ));
                                }
                            }
                            continue;
                        }
                    )*
                    $crate::common::view::fields_ie!(@member self, ie, name, written $(, $flags)?);
                }
                Ok(ie)
            }
        }
    };
    (@flags $ie:ident, $members:ident) => {};
    (@flags $ie:ident, $members:ident, exact) => {};
    (@flags $ie:ident, $members:ident, flags) => {
        for (flag, value) in $crate::common::view::Flags::flags($ie) {
            $members.insert($crate::common::readable::printed_static(flag).name.to_owned(), value.into());
        }
    };
    (@shown $ie:ident, $members:ident) => {
        Some($members)
    };
    (@shown $ie:ident, $members:ident, flags) => {
        Some($members)
    };
    // What a view shows can be written: octets that the members do not give
    // back, in an IE of the same length, have no value.
    (@shown $ie:ident, $members:ident, exact) => {{
        // An IE without octets reads as the zeros that it is built from.
        if $crate::common::view::FlagOctets::none(&$ie.value) {
            return Some($members);
        }
        let mut blank = $ie.clone();
        let octets = $crate::common::view::Fields::octets(&mut blank);
        for bit in 0..octets.bits() {
            if octets.bit(bit) {
                octets.flip(bit);
            }
        }
        let again = $crate::common::view::Decoded::with_decoded(&blank, &$members).ok()?;
        (again.value == $ie.value).then_some($members)
    }};
    (@member $from:ident, $ie:ident, $name:ident, $written:ident) => {
        return Err(format!("no member `{}`", $name))
    };
    (@member $from:ident, $ie:ident, $name:ident, $written:ident, exact) => {
        return Err(format!("no member `{}`", $name))
    };
    (@member $from:ident, $ie:ident, $name:ident, $written:ident, flags) => {
        // An IE without octets is built from the value.
        let built = $crate::common::view::Flags::is_empty($from);
        $crate::common::view::set_flag(&mut $ie, $name, $written, built)?
    };
}

/// [`Decoded`] for an IE type that `$from` builds from the values of its
/// getters: an object of `member: type` after the getter of that name, or
/// `member: type = getter` for another. A member that is not written keeps
/// the value it has.
macro_rules! built_ie {
    ($ie:ty, $from:expr, { $($key:ident: $ty:ty $(= $get:expr)?),+ $(,)? }) => {
        impl $crate::common::view::Decoded for $ie {

            fn unwritten() -> Self {
                <$ie>::blank()
            }
            fn decoded(&self) -> Option<serde_json::Value> {
                // The members that the getters read, and the IE that `$from`
                // builds of them.
                let read = |ie: &Self| -> Option<(serde_json::Value, Option<Self>)> {
                    let mut members = serde_json::Map::new();
                    $(
                        let $key: $ty = $crate::common::view::built_ie!(@get ie, $key $(, $get)?)?;
                        let member = $crate::common::readable::to_value(&$key).ok()?;
                        let name = $crate::common::readable::printed_static(stringify!($key)).name;
                        members.insert(name.to_owned(), member);
                    )+
                    let from: fn($($ty),+) -> Option<Self> = $from;
                    Some((members.into(), from($($key),+)))
                };
                // Octets that are read and that `$from` does not build have
                // no value: what a view shows can be written.
                let (members, built) = read(self)?;
                (read(&built?)?.0 == members).then_some(members)
            }

            fn with_decoded(&self, value: &serde_json::Value) -> std::result::Result<Self, String> {
                use $crate::common::readable::{from_value, printed_static, same_name, to_value};
                let written = $crate::common::view::members(value)?;
                const NAMES: &[&str] = &[$(stringify!($key)),+];
                if let Some(name) = (written.keys())
                    .find(|name| !NAMES.iter().any(|known| same_name(known, name)))
                {
                    return Err(format!("no member `{name}`"));
                }
                let mut members = serde_json::Map::new();
                $(
                    let $key: $ty = match (written.iter())
                        .find(|(name, _)| same_name(name, stringify!($key)))
                    {
                        Some((name, member)) => {
                            from_value(member).map_err(|error| format!("{name}: {error}"))?
                        }
                        None => $crate::common::view::built_ie!(@get self, $key $(, $get)?)
                            .ok_or(concat!(stringify!($key), " is not written"))?,
                    };
                    let name = printed_static(stringify!($key)).name;
                    members.insert(name.to_owned(), to_value(&$key)?);
                )+
                let from: fn($($ty),+) -> Option<Self> = $from;
                let new = from($($key),+).ok_or_else(|| format!("no IE of this type is {value}"))?;
                $crate::common::view::carried(new, &members.into())
            }
        }
    };
    (@get $ie:ident, $key:ident) => {
        Some($ie.$key())
    };
    (@get $ie:ident, $key:ident, $get:expr) => {{
        let get: fn(&Self) -> Option<_> = $get;
        get($ie)
    }};
}

/// [`Decoded`] for GPRS timer IE types: the seconds that the unit and the
/// count give, encoded with the unit that holds them.
macro_rules! timer_ie {
    ($($ie:ty),+ $(,)?) => {$(
        $crate::common::view::decoded_ie!(
            $ie: $crate::common::view::Timer,
            |ie| {
                use $crate::common::ts24008::GprsTimerValue;
                use $crate::common::view::{Code, Deactivated};
                Some(match Option::<GprsTimerValue>::from(ie.value())? {
                    GprsTimerValue::Deactivated => Code::Name(Deactivated::Deactivated),
                    GprsTimerValue::Seconds(seconds) => Code::Number(seconds),
                })
            },
            |_, timer| match timer {
                $crate::common::view::Code::Name(_) => Some(<$ie>::deactivated()),
                $crate::common::view::Code::Number(seconds) => <$ie>::from_seconds(seconds),
            }
        );
    )+};
}

/// [`Decoded`] for an IE type that is a list `$decode` parses leniently and
/// `$encode` builds: its value is the list when it encodes back to the
/// octets, so that a list cut short has none.
macro_rules! listed_ie {
    ($ie:ty: $entry:ty, $decode:ident, $encode:expr) => {
        $crate::common::view::decoded_ie!(
            $ie: Vec<$entry>,
            |ie| {
                let encode: fn(&[$entry]) -> Option<$ie> = $encode;
                let entries = ie.$decode();
                (encode(&entries)?.value == ie.value).then_some(entries)
            },
            |_, entries| {
                let encode: fn(&[$entry]) -> Option<$ie> = $encode;
                encode(&entries)
            }
        );
    };
}

/// [`Decoded`] for an IE type that carries a plain NAS message, which
/// `$decode` reads and `$encode` carries: its value is the view of the
/// message.
macro_rules! container_ie {
    ($ie:ty: $message:ty, $decode:expr, $encode:expr) => {
        impl $crate::common::view::Decoded for $ie {
            fn unwritten() -> Self {
                <$ie>::blank()
            }
            fn decoded(&self) -> Option<serde_json::Value> {
                let decode: fn(&Self) -> Option<$message> = $decode;
                let _inside = $crate::common::view::Inside::enter()?;
                Some($crate::common::view::to_view(&decode(self)?))
            }

            fn with_decoded(&self, value: &serde_json::Value) -> std::result::Result<Self, String> {
                let decode: fn(&Self) -> Option<$message> = $decode;
                let encode: fn(&$message) -> Option<Self> = $encode;
                let _inside = $crate::common::view::Inside::enter()
                    .ok_or($crate::common::view::Inside::REFUSED)?;
                let message = match decode(self) {
                    Some(message) => $crate::common::view::with_view(&message, value.clone())?,
                    // A container without octets carries what the view names.
                    None if self.value.is_empty() => $crate::common::view::contained(value)?,
                    None => return Err("the octets are not a plain message: write them".into()),
                };
                encode(&message).ok_or_else(|| "the IE cannot carry this message".to_string())
            }

            // The message is written as a tree writes it, from its values,
            // and read back: a value does not say every octet, and the
            // octets that it writes may be those of no message of its type.
            fn writes(value: &serde_json::Value) -> bool {
                use $crate::common::view::{as_a_tree_writes, meaning};
                let written = <$ie>::blank().with_decoded(&as_a_tree_writes(value));
                written.is_ok_and(|written| {
                    (written.decoded()).is_some_and(|read| meaning(&read) == meaning(value))
                })
            }
        }
    };
}

/// The values of the IEs that TS 24.501 and TS 24.301 have alike, for the types of
/// the protocol whose view calls it.
macro_rules! shared_ies {
    () => {
        /// A network name and whether the country initials are to be added to it.
        #[derive(Serialize, Deserialize)]
        struct NetworkName {
            name: String,
            add_ci: bool,
        }

        code_ie!(
            NasRequestType,
            RequestTypeValue,
            |ie| ie.request_type(),
            NasRequestType::from_request_type
        );
        code_ie!(
            NasImeisvRequest,
            ImeisvRequestValue,
            |ie| ie.request_strict(),
            NasImeisvRequest::from_request
        );
        code_ie!(
            NasUeRadioCapabilityIdDeletionIndication,
            RadioCapabilityIdDeletionRequest,
            |ie| ie.deletion_request(),
            NasUeRadioCapabilityIdDeletionIndication::from_deletion_request
        );
        code_ie!(
            NasReleaseAssistanceIndication,
            DownlinkDataExpected,
            |ie| ie.ddx(),
            NasReleaseAssistanceIndication::from_ddx
        );
        named_ie!(
            NasUeRequestType,
            UeRequestType,
            |ie| ie.request_type(),
            NasUeRequestType::from_request_type
        );
        fields_ie!(NasExtendedDrxParameters {
            "paging-time-window": |ie| ie.paging_time_window(), |ie, window: u8| {
                ie.set_paging_time_window(window);
            };
            "edrx-value": |ie| ie.edrx_value(), |ie, value: u8| {
                ie.set_edrx_value(value);
            };
        });
        decoded_ie!(
            NasKeySetIdentifier: KeySetIdentifier,
            |ie| Some(ie.key_set_identifier()),
            |ie, identifier| ie.clone().with_key_set_identifier(identifier).ok()
        );
        built_ie!(NasUnavailabilityInformation, Self::from_fields, {
            due_to_discontinuous_coverage: bool = |ie| ie.due_to_discontinuous_coverage(),
            period_duration: Option<u32> = |ie| Some(ie.period_duration()),
            start_of_period: Option<u32> = |ie| Some(ie.start_of_period()),
        });
        built_ie!(NasUnavailabilityConfiguration, Self::from_fields, {
            end_of_period_report_needed: bool = |ie| ie.end_of_period_report_needed(),
            period_duration: Option<u32> = |ie| Some(ie.period_duration()),
            start_of_period: Option<u32> = |ie| Some(ie.start_of_period()),
        });
        decoded_ie!(
            NasListOfPlmnsToBeUsedInDisasterCondition: Vec<PlmnId>,
            |ie| ie.is_well_formed().then(|| ie.plmns()),
            |_, plmns| NasListOfPlmnsToBeUsedInDisasterCondition::from_plmns(&plmns)
        );
        decoded_ie!(
            NasUeRadioCapabilityId: String,
            |ie| ie.id_string(),
            |_, id| NasUeRadioCapabilityId::from_id_string(&id)
        );
        decoded_ie!(
            NasNetworkName: NetworkName,
            |ie| Some(NetworkName {
                name: ie.name()?,
                add_ci: ie.add_ci(),
            }),
            |_, name| Some(NasNetworkName::from_name(&name.name, name.add_ci))
        );
        decoded_ie!(
            NasEmergencyNumberList: Vec<EmergencyNumber>,
            |ie| ie.numbers(),
            |_, numbers| NasEmergencyNumberList::from_numbers(&numbers)
        );
        decoded_ie!(
            NasServingPlmnRateControl: u16,
            |ie| ie.rate(),
            |_, rate| NasServingPlmnRateControl::from_rate(rate)
        );
        decoded_ie!(
            NasEpsBearerContextStatus: Vec<u16>,
            |ie| Some(numbers(&ie.active_bearers())),
            |_, bearers| NasEpsBearerContextStatus::from_bearers(&octets(&bearers)?)
        );
        fields_ie!(NasReAttemptIndicator {} flags);
        fields_ie!(NasUeStatus {} flags);
        fields_ie!(NasNon3GppNwProvidedPolicies {} flags);
        fields_ie!(NasMobileStationClassmark2 {} flags);
        fields_ie!(NasAccessTechnologyUtilizationControl {} flags);
        decoded_ie!(
            NasExtendedEmergencyNumberList: $crate::common::view::ExtendedEmergencyNumbers,
            |ie| {
                Some($crate::common::view::ExtendedEmergencyNumbers {
                    valid_only_in_plmn: ie.valid_only_in_plmn()?,
                    numbers: ie.numbers()?,
                })
            },
            |_, list| {
                NasExtendedEmergencyNumberList::from_numbers(list.valid_only_in_plmn, &list.numbers)
            }
        );
    };
}

pub(crate) use {
    built_ie, code_ie, configuration_options_ie, container_ie, decoded_ie, fields_ie, listed_ie,
    named_ie, shared_ies, timer_ie,
};

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::common::Direction;
    use crate::nas_5gs::Nas5gsMessage;
    use crate::nas_eps::NasEpsMessage;

    fn pointers(form: &Value, path: String, found: &mut Vec<String>) {
        match form {
            Value::Object(object) => (object.iter())
                .for_each(|(key, value)| pointers(value, format!("{path}/{key}"), found)),
            Value::Array(array) => (array.iter().enumerate())
                .for_each(|(index, value)| pointers(value, format!("{path}/{index}"), found)),
            _ => {}
        }
        found.push(path);
    }

    /// The value of `ie` encodes back to an IE that has it. Whatever takes
    /// the place of a part of it, the encoder answers and what it answers
    /// has a value.
    pub(crate) fn exercise<T: Decoded>(ie: T) {
        let Some(value) = ie.decoded() else {
            panic!("no value of {}", std::any::type_name::<T>());
        };
        exercise_value(ie, value)
    }

    /// [`exercise`] for any octets: they may have no value. One that they
    /// have encodes back, as a name or as the number that has none.
    pub(crate) fn sweep<T: Decoded>(ie: T) {
        if let Some(value) = ie.decoded() {
            exercise_value(ie, value)
        }
    }

    thread_local! {
        static PARTS: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
    }

    /// Whether the values that follow also have each of their parts
    /// replaced: a sweep of every octet does it for a few of them.
    pub(crate) fn replace_parts(on: bool) {
        PARTS.set(on);
    }

    /// An IE without octets that is built from the value it shows has the
    /// octets of that value: none of its members is left out as the zero
    /// that the IE had.
    pub(crate) fn built_from_nothing<T: Decoded>(blank: T) {
        let name = std::any::type_name::<T>();
        let value = blank.decoded().unwrap_or_else(|| panic!("{name}"));
        let built = (blank.with_decoded(&value)).unwrap_or_else(|error| panic!("{name}: {error}"));
        let form = readable::to_value(&built).unwrap();
        let octets = match &form["value"] {
            Value::String(octets) => !octets.is_empty(),
            value => value.is_number(),
        };
        assert!(octets, "{name}: {value} has no octets in {form}");
        assert_eq!(built.decoded(), Some(value), "{name}");
    }

    /// The value that `ie` shows builds an IE that has it from one without
    /// octets: every member is written, a code without a name by its number.
    pub(crate) fn built_from_value<T: Decoded>(blank: T, ie: T) {
        let name = std::any::type_name::<T>();
        let Some(value) = ie.decoded() else {
            return;
        };
        let built =
            (blank.with_decoded(&value)).unwrap_or_else(|error| panic!("{name}: {value}: {error}"));
        assert_eq!(built.decoded().as_ref(), Some(&value), "{name}");
        // A name is shown for the code that it writes: the IE that is built
        // has no bit that `ie` does not have, which may have spare ones.
        let octet = |ie: &T| match &readable::to_value(ie).unwrap()["value"] {
            Value::Number(octet) => octet.as_u64(),
            Value::String(octets) if octets.len() == 2 => u64::from_str_radix(octets, 16).ok(),
            _ => None,
        };
        if let (Some(built), Some(ie)) = (octet(&built), octet(&ie)) {
            assert_eq!(
                built & ie,
                built,
                "{name}: {value} is {built:#x}, was {ie:#x}"
            );
        }
    }

    /// One octet, as the value of an IE type that has one or several.
    pub(crate) trait Octet {
        fn of(octet: u8) -> Self;
    }

    impl Octet for u8 {
        fn of(octet: u8) -> Self {
            octet
        }
    }

    impl Octet for crate::common::Octets {
        fn of(octet: u8) -> Self {
            [octet].into()
        }
    }

    /// How many types of `source`, a view module, and of this one have the
    /// value of `fields_ie!`.
    pub(crate) fn fields_ies(source: &str) -> usize {
        let shared = include_str!("view.rs")
            .matches("\n        fields_ie!(")
            .count();
        source.matches("\nfields_ie!(").count() + shared
    }

    fn exercise_value<T: Decoded>(ie: T, value: Value) {
        let encoded = (ie.with_decoded(&value))
            .unwrap_or_else(|error| panic!("{}: {value}: {error}", std::any::type_name::<T>()));
        assert_eq!(encoded.decoded().as_ref(), Some(&value));
        if !PARTS.get() {
            return;
        }
        let mut found = Vec::new();
        pointers(&value, String::new(), &mut found);
        // A sample of the parts of a value with many, such as a capability.
        let step = found.len().div_ceil(24);
        for pointer in found.into_iter().step_by(step) {
            for part in [
                serde_json::json!(255),
                serde_json::json!(65_536),
                serde_json::json!(1_u64 << 40),
                serde_json::json!(-1),
                serde_json::json!("x"),
                serde_json::json!("0x7fffffffffff"),
                serde_json::json!("999-999"),
                serde_json::json!([]),
                serde_json::json!([300, 300, 300]),
                serde_json::json!({}),
                serde_json::json!(true),
                Value::Null,
            ] {
                let mut edited = value.clone();
                *edited.pointer_mut(&pointer).unwrap() = part;
                if let Ok(encoded) = ie.with_decoded(&edited) {
                    assert!(encoded.decoded().is_some(), "{edited}");
                }
            }
        }
    }

    /// Whatever takes the place of a part of the value `value` of `ie`, the
    /// encoder answers, and what it takes has a value: an author writes
    /// what no parser gives.
    fn written_wrong(ie: &dyn Ie, value: &Value) {
        let mut found = Vec::new();
        pointers(value, String::new(), &mut found);
        // A sample of the parts of a value with many.
        let step = found.len().div_ceil(12);
        for pointer in found.into_iter().step_by(step) {
            for part in [
                serde_json::json!(255),
                serde_json::json!(1_u64 << 40),
                serde_json::json!(-1),
                serde_json::json!("x"),
                serde_json::json!("0x7fffffffffff"),
                serde_json::json!([]),
                serde_json::json!([300, 300, 300]),
                serde_json::json!({}),
                Value::Null,
            ] {
                let mut edited = value.clone();
                *edited.pointer_mut(&pointer).unwrap() = part;
                if let Ok((_, read)) = ie.encoded(&edited) {
                    assert!(read.is_some(), "{edited}");
                }
            }
        }
    }

    /// Encode every value of `message` back: how many IEs it has, how many
    /// have a value, and how many give other octets than they were decoded
    /// from. The message of the encoded values has the same view.
    fn encode_back<M: Viewed + PartialEq + std::fmt::Debug>(message: &M, name: &str) -> [usize; 3] {
        let view = to_view(message);
        assert_eq!(
            &with_view(message, view.clone()).unwrap(),
            message,
            "{name}"
        );
        let mut tree = readable::to_value(message).unwrap();
        let mut counts = [0; 3];
        if let Some((header, members)) = parts(&mut tree) {
            // No field of the header has the name of an IE.
            let header = header.as_object().unwrap().len();
            let ies = members.values().filter(|ie| !ie.is_array()).count();
            assert_eq!(view.as_object().unwrap().len(), header + ies, "{name}");
            message.ies(&mut |visited| {
                let (field, ie) = (visited.name, visited.ie);
                counts[0] += 1;
                let Some((ie, value)) = ie.and_then(|ie| Some((ie, ie.value()?))) else {
                    return;
                };
                counts[1] += 1;
                written_wrong(ie, &value);
                let (encoded, _) =
                    (ie.encoded(&value)).unwrap_or_else(|error| panic!("{name} {field}: {error}"));
                counts[2] += usize::from(members[&printed(field)] != encoded);
                members.insert(printed(field), encoded);
            });
        }
        let encoded: M = readable::from_value(&tree).unwrap();
        let values = |view: Value| -> Vec<Value> {
            let Value::Object(view) = view else { panic!() };
            view.into_iter()
                .map(|(_, mut ie)| ie["value"].take())
                .collect()
        };
        assert_eq!(values(to_view(&encoded)), values(view), "{name}");
        counts
    }

    /// The message that the view of `message` describes alone, which has
    /// the same view.
    fn describe_alone<M: Viewed>(message: &M, name: &str) -> M {
        let tree = readable::to_value(message).unwrap();
        let parts = tree.as_object().unwrap().values().next().unwrap();
        let kind = parts[1].as_object().unwrap().keys().next().unwrap();
        let alone: M = from_view(M::FAMILIES, kind, to_view(message))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(to_view(&alone), to_view(message), "{name}");
        alone
    }

    fn fixtures(file: &str) -> impl Iterator<Item = (&str, Vec<u8>)> {
        file.lines()
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.split_once('\t').unwrap())
            .map(|(name, hex)| (name, hex::decode(hex).unwrap()))
    }

    #[test]
    fn the_values_of_the_fixtures_encode_back() {
        let mut counts = [0; 3];
        for (name, wire) in fixtures(include_str!("../../tests/fixtures/nas-5gs.tsv")) {
            let message = Nas5gsMessage::decode(&wire).unwrap();
            let message = encode_back(&message, name);
            (0..3).for_each(|index| counts[index] += message[index]);
        }
        assert_eq!(
            counts,
            [228, 193, 19],
            "5GS: IEs, with a value, other octets"
        );
        let mut counts = [0; 3];
        for (name, wire) in fixtures(include_str!("../../tests/fixtures/nas-eps.tsv")) {
            let direction = if name.starts_with("DetachRequestToUe") {
                Direction::Downlink
            } else {
                Direction::Uplink
            };
            let message = NasEpsMessage::decode_with_direction(&wire, direction).unwrap();
            let message = encode_back(&message, name);
            (0..3).for_each(|index| counts[index] += message[index]);
        }
        assert_eq!(
            counts,
            [216, 185, 7],
            "EPS: IEs, with a value, other octets"
        );
    }

    #[test]
    fn the_views_of_the_fixtures_describe_them_alone() {
        let mut other = Vec::new();
        for (name, wire) in fixtures(include_str!("../../tests/fixtures/nas-5gs.tsv")) {
            let message = Nas5gsMessage::decode(&wire).unwrap();
            if describe_alone(&message, name).encode().unwrap() != wire {
                other.push(name);
            }
        }
        assert_eq!(other, [""; 0], "5GS: other octets");
        for (name, wire) in fixtures(include_str!("../../tests/fixtures/nas-eps.tsv")) {
            let direction = if name.starts_with("DetachRequestToUe") {
                Direction::Downlink
            } else {
                Direction::Uplink
            };
            let message = NasEpsMessage::decode_with_direction(&wire, direction).unwrap();
            if describe_alone(&message, name).encode().unwrap() != wire {
                other.push(name);
            }
        }
        assert_eq!(other, [""; 0], "EPS: other octets");
    }

    #[test]
    fn a_view_alone_has_the_header_and_every_mandatory_ie() {
        use crate::nas_5gs::Nas5gmmMessageType;
        use serde_json::json;
        let header = json!({
            "extended-protocol-discriminator": {"value": 126},
            "security-header-type": {"value": "plain-nas-message"},
            "message-type": {"value": "5gmm-status"},
        });
        let from = |view: Value| Nas5gmmMessageType::FGmmStatus.from_view(view);
        let error = from(header.clone()).unwrap_err().to_string();
        assert!(error.contains("`5gmm-cause` is not written"), "{error}");
        let mut view = header.clone();
        view["5gmm-cause"] = json!({"octets": "16"});
        assert_eq!(
            from(view.clone()).unwrap().encode().unwrap(),
            [0x7e, 0, 0x64, 0x16]
        );
        view.as_object_mut().unwrap().remove("message-type");
        let error = from(view.clone()).unwrap_err().to_string();
        assert!(error.contains("`message-type` is not written"), "{error}");
        view["message-type"] = json!({"value": "5gmm-status"});
        view["t3512-value"] = json!({"value": 60});
        let error = from(view).unwrap_err().to_string();
        assert!(
            error.contains("`t3512-value` is no IE of the message"),
            "{error}"
        );
    }

    #[test]
    fn an_ie_of_flags_that_a_view_adds_has_the_octet_of_each_flag_written() {
        use crate::nas_5gs::Nas5gmmMessageType;
        use serde_json::json;
        let request = Nas5gmmMessageType::RegistrationRequest
            .from_view(json!({
                "extended-protocol-discriminator": {"value": 126},
                "security-header-type": {"value": "plain-nas-message"},
                "message-type": {"value": "registration-request"},
                "5gs-registration-type": {"octets": "79"},
                "5gs-mobile-identity": {"octets": "0199f907000000000000001002"},
                "5gmm-capability": {"value": {"s1-mode": false, "lpp": false}},
                "ue-status": {"value": {"s1-mode-reg": false, "n1-mode-reg": false}},
            }))
            .unwrap();
        assert_eq!(
            hex::encode(request.encode().unwrap()),
            "7e004179000d0199f9070000000000000010021001002b0100"
        );
    }

    #[test]
    fn a_container_of_a_view_alone_carries_the_message_that_its_view_names() {
        use crate::nas_5gs::{Nas5gmmMessage, Nas5gmmMessageType};
        use serde_json::json;
        let transport = Nas5gmmMessageType::UlNasTransport
            .from_view(json!({
                "extended-protocol-discriminator": {"value": 126},
                "security-header-type": {"value": "plain-nas-message"},
                "message-type": {"value": "ul-nas-transport"},
                "payload-container-type": {"value": "n1-sm-information"},
                "payload-container": {"value": {
                    "extended-protocol-discriminator": {"value": 46},
                    "pdu-session-identity": {"value": 5},
                    "procedure-transaction-identity": {"value": 1},
                    "message-type": {"value": "pdu-session-release-request"},
                    "5gsm-cause": {"value": "regular-deactivation"},
                }},
                "pdu-session-id": {"value": 5},
            }))
            .unwrap();
        let wire = transport.encode().unwrap();
        assert_eq!(
            hex::encode(&wire),
            "7e00670100062e0501d15924120 5".replace(' ', "")
        );
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) = transport else {
            panic!("{transport:?}");
        };
        let inner = transport
            .payload_container
            .decode_as_n1_sm_message()
            .unwrap();
        assert_eq!(
            inner.to_view()["5gsm-cause"]["value"],
            "regular-deactivation"
        );
    }
}
