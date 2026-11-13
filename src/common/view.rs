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

//! The tree of a message: its header, and each of its IEs by the name that
//! the specification gives it, with its value as the typed accessors decode
//! it where that value writes the IE back, or its `octets` in hexadecimal.

use crate::common::readable::{self, letters, same_name};
use crate::common::ts24008::{Pco, PcoDirection, PcoEntry};
use crate::common::{Plmn, ValueError, within};
use crate::nas_5gs::{
    GsmCauseValue, QosFlowDescription, QosFlowDescriptions, QosRule, QosRules, SNssai,
    SNssaiContents, SessionAmbr, SessionAmbrValue,
};
use crate::prelude::*;
use core::any::Any;
use core::net::{Ipv4Addr, Ipv6Addr};
use oxirush_utils::tree::{self, ErrorKind, Map, Value};
use readable::Readable;

/// An IE type whose octets have a value: what its typed accessors return,
/// in the readable form of [`readable`].
pub(crate) trait Decoded: Readable + Clone + PartialEq + 'static {
    /// The value of the octets in `scope`; `None` when they have none. The
    /// value of a container is the tree of its message.
    fn decoded(&self, scope: Scope) -> Option<Value>;

    /// This IE with the octets of `value`, in `scope`. The IE that comes
    /// back decodes to `value`: what an IE cannot carry is an error.
    fn with_decoded(&self, value: &Value, scope: Scope) -> Result<Self, String>;

    /// The IE without octets yet, as a message that is written alone has it
    /// before its value is written.
    fn unwritten() -> Self;

    /// The IE of this type that stands for all those that mean what this
    /// one means: the IE itself, for a type whose value decides its octets.
    /// A type whose value leaves some of them open, as the unit of a timer,
    /// gives the one form that a value is written in. A tree shows the
    /// value of an IE that its value writes back to this form, and the
    /// octets of any other.
    fn meant(&self, _scope: Scope) -> Self {
        self.clone()
    }

    /// The value of the IE where it writes the IE back alone, as
    /// [`Ie::written_back`] says of it; `None` where the IE has its octets.
    fn shown_value(&self, scope: Scope) -> Option<Value> {
        let value = self.decoded(scope)?;
        let written = Self::unwritten().with_decoded(&value, scope).ok()?;
        (written.meant(scope) == self.meant(scope)).then_some(value)
    }

    /// The octets of the IE that `names` names in the message that this IE
    /// carries ([`ie_octets`]); `None` for an IE that carries no message.
    fn octets_inside(&self, _names: &[String], _scope: Scope) -> Option<Found> {
        None
    }

    /// What the tests compare with what Wireshark reads of the IE: its
    /// value, and for a container the reading of its message.
    #[cfg(test)]
    fn reading(&self, scope: Scope) -> Option<Value> {
        self.decoded(scope)
    }
}

/// An IE of a message, as a tree shows it, in the [`Scope`] of the message.
pub(crate) trait Ie {
    /// The value of the IE; `None` when its octets have none.
    fn value(&self, scope: Scope) -> Option<Value>;

    /// The IE with the octets of `value`, of the type of the field of the
    /// message that holds this one ([`Slot::put`]).
    fn encoded_ie(&self, value: &Value, scope: Scope) -> Result<Box<dyn Any>, String>;

    /// The value of the octets of the IE that `value` writes.
    #[cfg(test)]
    fn encoded_value(&self, value: &Value, scope: Scope) -> Result<Option<Value>, String>;

    /// Whether `value` writes this IE back: the IE that it writes alone,
    /// without octets before it, means what this one means.
    fn written_back(&self, value: &Value, scope: Scope) -> bool;

    /// The value of the IE where it writes the IE back; `None` where the IE
    /// has its octets.
    fn shown_value(&self, scope: Scope) -> Option<Value> {
        let value = self.value(scope)?;
        self.written_back(&value, scope).then_some(value)
    }

    /// The IE that stands for all those that mean what this one means,
    /// when it is another than this one.
    fn meant(&self, scope: Scope) -> Option<Box<dyn Any>>;

    /// The octets of the IE that `names` names in the message that this IE
    /// carries; `None` for an IE that carries no message.
    fn octets_inside(&self, names: &[String], scope: Scope) -> Option<Found>;

    /// [`Decoded::reading`].
    #[cfg(test)]
    fn reading(&self, scope: Scope) -> Option<Value>;
}

impl<T: Decoded> Ie for T {
    fn value(&self, scope: Scope) -> Option<Value> {
        self.decoded(scope)
    }

    fn encoded_ie(&self, value: &Value, scope: Scope) -> Result<Box<dyn Any>, String> {
        Ok(Box::new(self.with_decoded(value, scope)?))
    }

    #[cfg(test)]
    fn encoded_value(&self, value: &Value, scope: Scope) -> Result<Option<Value>, String> {
        Ok(self.with_decoded(value, scope)?.decoded(scope))
    }

    fn written_back(&self, value: &Value, scope: Scope) -> bool {
        let written = T::unwritten().with_decoded(value, scope);
        written.is_ok_and(|written| written.meant(scope) == Decoded::meant(self, scope))
    }

    fn shown_value(&self, scope: Scope) -> Option<Value> {
        Decoded::shown_value(self, scope)
    }

    fn meant(&self, scope: Scope) -> Option<Box<dyn Any>> {
        let meant = Decoded::meant(self, scope);
        (meant != *self).then(|| Box::new(meant) as Box<dyn Any>)
    }

    fn octets_inside(&self, names: &[String], scope: Scope) -> Option<Found> {
        Decoded::octets_inside(self, names, scope)
    }

    #[cfg(test)]
    fn reading(&self, scope: Scope) -> Option<Value> {
        Decoded::reading(self, scope)
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

/// Probe that yields how an IE of the type `T` is written from its value,
/// when `T` implements [`Decoded`], and `None` otherwise.
pub(crate) struct WrittenProbe<T>(pub core::marker::PhantomData<T>);

/// How the IE that a value writes is made.
pub(crate) type Writer<T> = fn(&Value) -> Result<T, String>;

/// Selected for an IE type that implements [`Decoded`].
pub(crate) trait ViaWritten<T> {
    fn writer(&self) -> Option<Writer<T>>;
}

impl<T: Decoded> ViaWritten<T> for WrittenProbe<T> {
    fn writer(&self) -> Option<Writer<T>> {
        Some(|value| T::unwritten().with_decoded(value, Scope::NONE))
    }
}

/// Fallback for an IE type whose octets have no value.
pub(crate) trait ViaNoWritten<T> {
    fn writer(&self) -> Option<Writer<T>>;
}

impl<T> ViaNoWritten<T> for &WrittenProbe<T> {
    fn writer(&self) -> Option<Writer<T>> {
        None
    }
}

/// The tree of an IE alone, `ie` where its type has a value, whose value
/// field is `octets`: its value where that writes it back, or else its
/// octets.
pub(crate) fn ie_shown(ie: Option<&dyn Ie>, octets: &dyn Shown) -> Value {
    let shown = ie.and_then(|ie| ie.shown_value(Scope::NONE));
    shown.map_or_else(
        || oxirush_utils::tree!({ "octets": octets.hex() }),
        without_absent,
    )
}

/// The IE of the type `T` that the tree `value` of an IE writes: by its
/// `octets`, or by its value with `writer` where the type has one.
pub(crate) fn ie_written<T: Valued>(value: &Value, writer: Option<Writer<T>>) -> Result<T, String> {
    let octets = value.as_object().filter(|value| value.len() == 1);
    if let Some(octets) = octets.and_then(|value| value.get("octets")) {
        let mut ie = T::blank();
        let octets = octets_value(octets, ie.octets().size())?;
        ie.octets().set(&octets);
        return Ok(ie);
    }
    match writer {
        Some(write) => write(value),
        None => Err("this IE has octets and no value: its tree is its `octets`".into()),
    }
}

/// `Tree` for an IE type, and through it `Serialize` and `Deserialize`:
/// what the tree of a message shows of the IE, its value where that writes
/// it back and its octets otherwise; and the octets of the IE as a message
/// writes them. `$blank` is the IE without a value.
macro_rules! ie_tree {
    ($name:ty, $blank:expr) => {
        impl $crate::common::view::Valued for $name {
            fn blank() -> Self {
                $blank
            }

            fn octets(&mut self) -> &mut dyn $crate::common::view::Shown {
                &mut self.value
            }
        }

        impl oxirush_utils::tree::Tree for $name {
            const NAME: &'static str = stringify!($name);

            fn to_tree(&self) -> oxirush_utils::tree::Value {
                #[allow(unused_imports)]
                use $crate::common::view::{DecodedProbe, ViaDecoded, ViaNoDecoded};
                $crate::common::view::ie_shown((&DecodedProbe(self)).decoded_ie(), &self.value)
            }

            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> core::result::Result<Self, oxirush_utils::tree::Refused> {
                #[allow(unused_imports)]
                use $crate::common::view::{ViaNoWritten, ViaWritten, WrittenProbe};
                let writer = (&WrittenProbe::<Self>(core::marker::PhantomData)).writer();
                $crate::common::view::ie_written(value, writer)
                    .map_err(|why| reading.refuse(oxirush_utils::tree::ErrorKind::Value, why))
            }
        }

        oxirush_utils::impl_serde!($name);
    };
}

pub(crate) use ie_tree;

/// An IE that a message has, as its tree reads it.
#[derive(Clone, Copy)]
pub(crate) struct Field<'a> {
    /// The name of the field of the message struct.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) name: &'static str,
    /// The name as a tree prints it.
    pub(crate) printed: &'static str,
    /// The value of the IE: its octets.
    pub(crate) octets: &'a dyn Shown,
    /// The IE, if its octets have a value.
    pub(crate) ie: Option<&'a dyn Ie>,
    /// Whether the IE is optional.
    pub(crate) optional: bool,
    /// Where the IE is.
    pub(crate) scope: Scope,
}

/// The `value` field of an IE struct: a number of one or two octets, or
/// octets.
pub(crate) trait Shown {
    /// How many octets a value that is a number has: another size is that
    /// of a string of octets.
    fn size(&self) -> usize;

    /// The octets in hexadecimal.
    fn hex(&self) -> String;

    /// Give the value the octets `octets`, which [`octets_value`] read for
    /// its size.
    fn set(&mut self, octets: &[u8]);
}

impl Shown for u8 {
    fn size(&self) -> usize {
        1
    }

    fn hex(&self) -> String {
        format!("{self:02x}")
    }

    fn set(&mut self, octets: &[u8]) {
        *self = octets[0];
    }
}

impl Shown for u16 {
    fn size(&self) -> usize {
        2
    }

    fn hex(&self) -> String {
        format!("{self:04x}")
    }

    fn set(&mut self, octets: &[u8]) {
        *self = u16::from_be_bytes([octets[0], octets[1]]);
    }
}

impl Shown for Vec<u8> {
    fn size(&self) -> usize {
        usize::MAX
    }

    fn hex(&self) -> String {
        oxirush_utils::tree::hex(self)
    }

    fn set(&mut self, octets: &[u8]) {
        *self = octets.to_vec();
    }
}

impl Shown for crate::common::Octets {
    fn size(&self) -> usize {
        usize::MAX
    }

    fn hex(&self) -> String {
        oxirush_utils::tree::hex(self)
    }

    fn set(&mut self, octets: &[u8]) {
        *self = octets.into();
    }
}

/// The octets that `octets`, in hexadecimal, write in the value of an IE
/// whose value is a number of `size` octets, or octets.
pub(crate) fn octets_value(octets: &Value, size: usize) -> Result<Vec<u8>, String> {
    let written = (octets.as_str())
        .and_then(oxirush_utils::tree::unhex)
        .ok_or_else(|| format!("{octets} is not octets in hexadecimal"))?;
    match size {
        1 | 2 if written.len() == size => Ok(written),
        1 => Err(format!("{octets} is not one octet")),
        2 => Err(format!("{octets} is not two octets")),
        _ => Ok(written),
    }
}

/// What visits the IEs that a message has.
pub(crate) type Visit<'a> = dyn FnMut(Field<'_>) + 'a;

/// An IE type, as a message holds it: [`ie_tree`] implements it.
pub(crate) trait Valued: Sized + 'static {
    /// The IE without octets.
    fn blank() -> Self;

    /// The value field of the IE.
    fn octets(&mut self) -> &mut dyn Shown;
}

/// A field of a message struct that a tree writes: a mandatory IE, or an
/// optional one that the message may not have.
pub(crate) trait Slot {
    /// Give the field the IE `ie`, of its type: `false` for one of another.
    fn put(&mut self, ie: Box<dyn Any>) -> bool;

    /// Take an optional IE out of the message.
    fn clear(&mut self);

    /// Give the message an optional IE that it does not have, without
    /// octets.
    fn add(&mut self);

    /// Give the IE the octets `octets`.
    fn set_octets(&mut self, octets: &[u8]);
}

impl<T: Valued> Slot for T {
    fn put(&mut self, ie: Box<dyn Any>) -> bool {
        ie.downcast().map(|ie| *self = *ie).is_ok()
    }

    fn clear(&mut self) {}

    fn add(&mut self) {}

    fn set_octets(&mut self, octets: &[u8]) {
        self.octets().set(octets);
    }
}

impl<T: Valued> Slot for Option<T> {
    fn put(&mut self, ie: Box<dyn Any>) -> bool {
        ie.downcast().map(|ie| *self = Some(*ie)).is_ok()
    }

    fn clear(&mut self) {
        *self = None;
    }

    fn add(&mut self) {
        self.get_or_insert_with(T::blank);
    }

    fn set_octets(&mut self, octets: &[u8]) {
        self.get_or_insert_with(T::blank).octets().set(octets);
    }
}

/// A message enum: its header and the IEs of the message struct in it,
/// read through a security header.
pub(crate) trait Viewed: Clone + PartialEq {
    /// Visit the IEs that the message struct has, in `scope`.
    fn ies(&self, scope: Scope, visit: &mut Visit<'_>);

    /// The message struct, read through a security header: `None` for what
    /// has none.
    fn body(&self) -> Option<&dyn crate::common::MessageBody>;

    /// [`Self::body`], to change it.
    fn body_mut(&mut self) -> Option<&mut dyn crate::common::MessageBody>;

    /// The field of the message struct whose IE prints as `name`, read
    /// through a security header.
    fn slot(&mut self, name: &str) -> Option<&mut dyn Slot> {
        self.body_mut()?.slot(name)
    }

    /// The readable serde form of the header of the plain message, read
    /// through a security header: `None` for what has no message struct.
    fn header(&self) -> Option<Value>;

    /// The message authentication code of the header that protects the
    /// message, and the message that it protects.
    fn protected(&self) -> Option<(u32, &Self)>;

    /// The readable serde form of the header that protects the message,
    /// with that of the octets of a message that is ciphered.
    fn protection(&self) -> Option<(Value, Option<Value>)>;

    /// Give the plain message, read through a security header, the header
    /// of the readable serde form `header`.
    fn set_header(&mut self, header: &Value) -> Result<(), String>;

    /// Give the message the security header of the readable serde form
    /// `header`, and a message that is ciphered the octets of the readable
    /// serde form `ciphered`.
    fn set_protection(&mut self, header: &Value, ciphered: Option<&Value>) -> Result<(), String>;

    /// The message of the variant `family` of the enum that holds the
    /// message struct of the variant `kind`, as a tree that describes it
    /// alone starts from: its header as the readable serde form makes it
    /// blank, and the message with nothing in it yet. `None` where the
    /// family has no such message.
    fn blank_of(family: &str, kind: &str) -> Option<Self>;

    /// The variants of the enum that hold a plain message.
    const FAMILIES: &'static [&'static str];

    /// What the type of a message of the system decides of its header, as a
    /// tree leaves it out, for the message that its `message-type` names in
    /// the IE `container`, or alone: each field with its value.
    fn decided(
        container: Option<&str>,
        kind: Option<&Value>,
    ) -> Result<Vec<(&'static str, Value)>, String>;

    /// This message, which has nothing in it yet, ready for the members
    /// `members` of a tree: with the IE that says how another one is read.
    fn prepared(self, _members: &Map) -> Self {
        self
    }

    /// The name that the field `field` of a header reads as for the number
    /// `number`, if the field is one of names and has one for it.
    fn header_name(_field: &str, _number: u64) -> Option<Value> {
        None
    }

    /// The fields of a header that a tree may leave out. Such a field keeps
    /// the value that the message has, which is zero in a message that a
    /// tree describes alone.
    const SPARE: &'static [&'static str] = &[];

    /// Why the header of this plain message is not one that the message is
    /// sent with: the member, what it is and what it can be.
    fn refused_header(&self) -> Option<String> {
        None
    }

    /// The members of the tree of a message that has no table, as
    /// [`ie_octets`] reads them.
    fn fields(&self) -> Vec<(&'static str, Entry)> {
        Vec::new()
    }
}

/// The names that the tree of a message has: the fields `header` of its
/// header, and the IEs that `ies` gives of the message structs of the
/// variants `kinds`. There are none when there is no such variant.
pub(crate) fn names(
    header: &[&str],
    kinds: &[&str],
    ies: fn(&str) -> Option<&'static [&'static str]>,
) -> Vec<String> {
    let mut names = Vec::new();
    for kind in kinds {
        let Some(ies) = ies(kind) else {
            continue;
        };
        for name in header.iter().chain(ies) {
            if !names.iter().any(|known| known == name) {
                names.push((*name).to_owned());
            }
        }
    }
    names
}

/// Where the IEs that a tree has are: who sent their message, where its
/// type says so, and in how many containers the message is. A tree gives it
/// to each IE that it reads or writes: the units of the protocol
/// configuration options are read by the direction, and a container that is
/// too far in is not read as its message.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Scope {
    sent: Option<PcoDirection>,
    inside: usize,
}

impl Scope {
    /// An IE alone, or a message that is in no container.
    pub(crate) const NONE: Self = Self {
        sent: None,
        inside: 0,
    };

    /// What an edit is told of a message that is too far in.
    pub(crate) const REFUSED: &'static str =
        "the message is in more containers than are read as messages: write its octets";

    /// The IEs of a message in this place that was sent in `direction`, or
    /// of one whose type does not say.
    pub(crate) fn sent_by(self, direction: Option<PcoDirection>) -> Self {
        Self {
            sent: direction,
            ..self
        }
    }

    /// The direction of the message whose IEs are visited.
    pub(crate) fn direction(self) -> Option<PcoDirection> {
        self.sent
    }

    /// The place of the message in a container of this one: `None` where a
    /// container is no longer read as its message.
    pub(crate) fn inside(self) -> Option<Self> {
        (self.inside < NESTED).then_some(Self {
            inside: self.inside + 1,
            ..self
        })
    }
}

/// The value of an extended emergency number list (TS 24.301 §9.9.3.37A,
/// TS 24.501 §9.11.3.26): where the list is valid, and its numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExtendedEmergencyNumbers {
    /// Whether the list is valid only in the PLMN that it came from, and
    /// not in the whole country.
    pub(crate) valid_only_in_plmn: bool,
    /// The numbers, in their order.
    pub(crate) numbers: Vec<crate::common::ts24301::ExtendedEmergencyNumber>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct ExtendedEmergencyNumbers { valid_only_in_plmn, numbers });

/// A unit of the protocol configuration options (TS 24.008 §10.5.6.3): a
/// container of the additional parameters list by the name that Table
/// 10.5.154 gives its identifier in the direction of the message. A
/// container that has no name here, and the packet of a configuration
/// protocol, is its identifier and its octets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigurationUnit {
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
    // The PDU session of a PDN connection (TS 24.501 §6.1.4.1, TS 23.502
    // §4.11.1.5): of the UE, the identity of the session that it allocated
    // and a 5GSM cause; of the network, the parameters of the session that
    // the connection maps to, each the value part of the IE of TS 24.501 of
    // its name, and the PLMN of the S-NSSAI.
    PduSessionId(u8),
    FgsmCause(GsmCauseValue),
    SNssai {
        sst: u8,
        sd: Option<[u8; 3]>,
        mapped_sst: Option<u8>,
        mapped_sd: Option<[u8; 3]>,
        plmn: PlmnText,
    },
    QosRules(Vec<QosRule>),
    SessionAmbr(SessionAmbrValue),
    QosFlowDescriptions(Vec<QosFlowDescription>),
    /// Another protocol or container.
    Container {
        identifier: u16,
        contents: Vec<u8>,
    },
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(enum ConfigurationUnit { PCscfIpv6AddressRequest, ImCnSubsystemSignallingFlag, DnsServerIpv6AddressRequest, MsSupportOfNetworkRequestedBearerControl, IpAddressAllocationViaNasSignalling, Ipv4AddressAllocationViaDhcpv4, PCscfIpv4AddressRequest, DnsServerIpv4AddressRequest, MsisdnRequest, Ipv4LinkMtuRequest, MsSupportOfLocalAddressInTft, PCscfReselectionSupport, NonIpLinkMtuRequest, PCscfIpv6Address(Ipv6Addr), DnsServerIpv6Address(Ipv6Addr), SelectedBearerControlMode(BearerControlMode), PCscfIpv4Address(Ipv4Addr), DnsServerIpv4Address(Ipv4Addr), Ipv4LinkMtu(u16), NetworkSupportOfLocalAddressInTft, NonIpLinkMtu(u16), PduSessionId(u8), FgsmCause(GsmCauseValue), SNssai { sst, sd, mapped_sst, mapped_sd, plmn }, QosRules(Vec<QosRule>), SessionAmbr(SessionAmbrValue), QosFlowDescriptions(Vec<QosFlowDescription>), Container { identifier, contents } });

/// The selected bearer control mode (TS 24.008 Table 10.5.154).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BearerControlMode {
    MsOnly,
    MsNw,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum BearerControlMode {
        MsOnly,
        MsNw,
    }
);

impl ConfigurationUnit {
    /// The unit that `entry` is in a message sent in `direction`.
    fn of(entry: &PcoEntry, direction: PcoDirection) -> Self {
        use PcoDirection::{Downlink, Uplink};
        let contents = entry.contents.as_slice();
        let ipv6 = || <[u8; 16]>::try_from(contents).ok().map(Ipv6Addr::from);
        let ipv4 = || <[u8; 4]>::try_from(contents).ok().map(Ipv4Addr::from);
        let number = || <[u8; 2]>::try_from(contents).ok().map(u16::from_be_bytes);
        let unit = match (direction, entry.identifier, contents) {
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
            // A unit of a PDU session has a name where it writes its contents
            // back: an edit of the options changes no other unit. A session
            // AMBR has it where each rate is in the largest unit that holds
            // it, as the crate writes it.
            (Uplink, 0x001a | 0x0022, _) | (Downlink, 0x001b..=0x001d | 0x001f, _) => {
                Self::of_session(entry.identifier, contents)
                    .filter(|unit| unit.entry(direction).is_ok_and(|was| was == *entry))
            }
            _ => None,
        };
        unit.unwrap_or_else(|| Self::Container {
            identifier: entry.identifier,
            contents: contents.to_vec(),
        })
    }

    /// The unit of a PDU session that the container of `identifier` with
    /// `contents` is, if its contents are the value of one.
    fn of_session(identifier: u16, contents: &[u8]) -> Option<Self> {
        match (identifier, contents) {
            (0x001a, [identity @ 1..=15]) => Some(Self::PduSessionId(*identity)),
            (0x0022, [cause]) => GsmCauseValue::try_from(*cause).ok().map(Self::FgsmCause),
            (0x001b, _) => {
                let (s_nssai, plmn) = contents.split_at(contents.len().checked_sub(3)?);
                let s_nssai = SNssai::new(s_nssai.to_vec()).parse()?;
                Some(Self::SNssai {
                    sst: s_nssai.sst,
                    sd: s_nssai.sd,
                    mapped_sst: s_nssai.mapped_sst,
                    mapped_sd: s_nssai.mapped_sd,
                    plmn: PlmnText(crate::common::plmn_at(plmn)?),
                })
            }
            (0x001c, _) => {
                let rules = QosRules::new(contents.to_vec());
                (rules.validate_strict().is_ok()).then(|| Self::QosRules(rules.rules()))
            }
            (0x001d, _) => (SessionAmbr::new(contents.to_vec()).parse()).map(Self::SessionAmbr),
            (0x001f, _) => (QosFlowDescriptions::new(contents.to_vec()).try_descriptions())
                .map(Self::QosFlowDescriptions),
            _ => None,
        }
    }

    /// The container that the unit is in a message sent in `direction`, or
    /// why it is none: a unit of the other direction.
    fn entry(&self, direction: PcoDirection) -> Result<PcoEntry, String> {
        use PcoDirection::{Downlink, Uplink};
        let value = |octets: Result<Vec<u8>, ValueError>| {
            octets.map_err(|error| format!("`{}`: {}", self.name(), refused(error)))
        };
        let (sent, identifier, contents) = match self {
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
            Self::PduSessionId(identity) => (Some(Uplink), 0x001a, vec![*identity]),
            Self::FgsmCause(cause) => (Some(Uplink), 0x0022, vec![*cause as u8]),
            Self::SNssai {
                sst,
                sd,
                mapped_sst,
                mapped_sd,
                plmn,
            } => {
                let s_nssai = SNssaiContents::new(*sst, *sd, *mapped_sst, *mapped_sd);
                let mut contents = value(s_nssai.to_snssai().map(|ie| ie.value.to_vec()))?;
                contents.extend(plmn.0.to_nas_octets());
                (Some(Downlink), 0x001b, contents)
            }
            Self::QosRules(rules) => {
                let rules = value(QosRules::from_rules(rules).map(|ie| ie.value.to_vec()))?;
                (Some(Downlink), 0x001c, rules)
            }
            Self::SessionAmbr(ambr) => {
                let ambr = SessionAmbr::from_kbps(ambr.dl_kbps, ambr.ul_kbps);
                (
                    Some(Downlink),
                    0x001d,
                    value(ambr.map(|ie| ie.value.to_vec()))?,
                )
            }
            Self::QosFlowDescriptions(descriptions) => {
                let descriptions = QosFlowDescriptions::from_descriptions(descriptions);
                (
                    Some(Downlink),
                    0x001f,
                    value(descriptions.map(|ie| ie.value.to_vec()))?,
                )
            }
            Self::Container {
                identifier,
                contents,
            } => (None, *identifier, contents.clone()),
        };
        match sent {
            Some(sent) if sent != direction => {
                let expected = Self::named(identifier, direction);
                let (name, sent, direction) = (self.name(), towards(sent), towards(direction));
                let other = "is a unit of the direction";
                let this = "and this message is sent in the direction";
                Err(match expected {
                    Some(expected) => format!(
                        "`{name}` {other} {sent}, {this} {direction}: expected `{expected}`, \
                         the unit of the same identifier (0x{identifier:04x})"
                    ),
                    None => format!(
                        "`{name}` {other} {sent}, {this} {direction}, which has no unit of the \
                         same identifier (0x{identifier:04x})"
                    ),
                })
            }
            _ => Ok(PcoEntry {
                identifier,
                contents,
            }),
        }
    }

    /// The name of the unit, as a tree prints it.
    fn name(&self) -> String {
        match readable::to_value(self) {
            Ok(Value::String(name)) => name,
            Ok(Value::Object(unit)) => unit.keys().next().cloned().unwrap_or_default(),
            _ => String::new(),
        }
    }

    /// The name of the unit that `identifier` is in a message sent in
    /// `direction`, if it has one there: that of the unit which [`Self::of`]
    /// reads in contents of the lengths that the units have.
    fn named(identifier: u16, direction: PcoDirection) -> Option<String> {
        ([&[][..], &[1], &[0; 2], &[0; 4], &[0; 16]].into_iter())
            .map(|contents| {
                let entry = PcoEntry {
                    identifier,
                    contents: contents.to_vec(),
                };
                Self::of(&entry, direction)
            })
            .find(|unit| !matches!(unit, Self::Container { .. }))
            .map(|unit| unit.name())
    }

    /// The units of `pco`, of a message sent in `direction`.
    pub(crate) fn units(pco: &Pco, direction: PcoDirection) -> Vec<Self> {
        (pco.entries.iter())
            .map(|entry| Self::of(entry, direction))
            .collect()
    }

    /// The options that have `units` in the message of `scope`, and its
    /// direction; or why they are none.
    pub(crate) fn options(units: &[Self], scope: Scope) -> Result<(Pco, PcoDirection), String> {
        let direction = scope.direction().ok_or(
            "the type of the message does not say who sends it, and the units are named by \
             that: write the `octets`",
        )?;
        let entries = units.iter().map(|unit| unit.entry(direction));
        let options = Pco {
            configuration_protocol: 0,
            entries: entries.collect::<Result<_, _>>()?,
        };
        Ok((options, direction))
    }

    /// Why no IE has `options` in a message sent in `direction`: a
    /// container that cannot have its contents there, or what `error` says
    /// of the octets of a unit or of the units together.
    pub(crate) fn unfit(options: &Pco, direction: PcoDirection, error: ValueError) -> String {
        let wrong = (options.entries.iter()).find(|entry| !entry.is_well_formed(direction));
        match wrong {
            Some(entry) => format!(
                "the container of the identifier 0x{:04x} cannot have the contents `{}` in the \
                 direction {}",
                entry.identifier,
                oxirush_utils::tree::hex(&entry.contents),
                towards(direction)
            ),
            None => refused(error),
        }
    }
}

/// A direction in the words of the specifications.
fn towards(direction: PcoDirection) -> &'static str {
    match direction {
        PcoDirection::Uplink => "UE to network",
        PcoDirection::Downlink => "network to UE",
    }
}

/// [`Decoded`] for the IE types of the protocol configuration options: the
/// units of the options, read by the direction of the message that is
/// visited. Options that are not in a message whose type says who sends
/// it, and octets that the units do not give back, have no value. Units
/// that are written and that the options cannot have are refused with the
/// reason: the direction of a unit, the contents of a container.
macro_rules! configuration_options_ie {
    ($($ie:ty),+ $(,)?) => {$(
        impl $crate::common::view::Decoded for $ie {
            fn unwritten() -> Self {
                <$ie>::blank()
            }

            fn decoded(&self, scope: $crate::common::view::Scope) -> Option<oxirush_utils::tree::Value> {
                use $crate::common::readable::{from_value, to_value};
                use $crate::common::view::ConfigurationUnit;
                let direction = scope.direction()?;
                let options = self.pco(direction)?;
                if <$ie>::from_pco(&options, direction).ok()?.value != self.value {
                    return None;
                }
                // What is shown is what the same units, read back, write.
                let units = ConfigurationUnit::units(&options, direction);
                let value = to_value(&units).ok()?;
                let read: Vec<ConfigurationUnit> = from_value(&value).ok()?;
                (read == units).then_some(value)
            }

            fn with_decoded(
                &self,
                value: &oxirush_utils::tree::Value,
                scope: $crate::common::view::Scope,
            ) -> core::result::Result<Self, String> {
                use $crate::common::readable::{from_value, to_value};
                use $crate::common::view::{ConfigurationUnit, carried};
                let units: Vec<ConfigurationUnit> = from_value(value)?;
                let written = to_value(&units)?;
                let (options, direction) = ConfigurationUnit::options(&units, scope)?;
                let new = <$ie>::from_pco(&options, direction)
                    .map_err(|error| ConfigurationUnit::unfit(&options, direction, error))?;
                carried(new, &written, scope)
            }
        }
    )+};
}

/// The messages that containers may carry inside one another and that are
/// still read as messages: a container further in has its octets alone. No
/// message of TS 24.501 or TS 24.301 nests this deep, and the octets of a
/// peer may: a tree is built by a function that calls itself for the message
/// of a container.
const NESTED: usize = 8;

/// The octets of a message that is ciphered, as its readable serde form has
/// them: in hexadecimal.
pub(crate) fn octets_shown(octets: &[u8]) -> Value {
    match octets.is_empty() {
        true => Value::Array(Vec::new()),
        false => oxirush_utils::tree::hex(octets).into(),
    }
}

/// The member of a tree for the header that protects a message.
const SECURITY_HEADER: &str = "security-header";

/// The member of a tree for a message that is ciphered: its octets.
const CIPHERED: &str = "ciphered-message";

/// The member of a tree for the IEs that the table of the message has no
/// place for: the octets of each, its IEI first, in the order they came in.
/// They are one text, with a space between two IEs: a message can be made
/// of tens of thousands of them, and a list would have a value for each.
const UNKNOWN_IES: &str = "unknown-ies";

/// The text of the member of a tree for the IEs `unknown`.
fn unknown_text(unknown: &crate::common::UnknownIes) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::new();
    for ie in unknown.iter() {
        if !text.is_empty() {
            text.push(' ');
        }
        for octet in [ie.iei].iter().chain(ie.data) {
            text.push(char::from(DIGITS[usize::from(octet >> 4)]));
            text.push(char::from(DIGITS[usize::from(octet & 0x0f)]));
        }
    }
    text
}

/// The IEs that the member `written` of a tree has, each by its octets.
fn unknown_ies(written: &Value) -> Result<crate::common::UnknownIes, String> {
    let refused = || {
        format!(
            "`{UNKNOWN_IES}` is the IEs by their octets in hexadecimal, each with its IEI \
             first, with a space between two of them"
        )
    };
    let text = match Form::of(written)? {
        Form::Value(Value::String(text)) => text,
        _ => return Err(refused()),
    };
    let mut ies = crate::common::UnknownIes::new();
    // The octets of one IE at a time, in one buffer for all of them.
    let mut octets = Vec::new();
    for ie in text.split(' ').filter(|_| !text.is_empty()) {
        octets.clear();
        if ie.is_empty() || ie.len() % 2 != 0 {
            return Err(refused());
        }
        for pair in ie.as_bytes().chunks(2) {
            let digit = |digit: u8| char::from(digit).to_digit(16);
            match (digit(pair[0]), digit(pair[1])) {
                (Some(high), Some(low)) => octets.push((high << 4 | low) as u8),
                _ => return Err(refused()),
            }
        }
        ies.push_raw(&octets);
    }
    Ok(ies)
}

/// What a member of a tree writes of an IE or of a field.
enum Form<'v> {
    /// Its value.
    Value(&'v Value),
    /// Its octets, `{"octets": "…"}`.
    Octets(&'v Value),
}

impl<'v> Form<'v> {
    /// What the member `written` writes: `null` writes nothing.
    fn of(written: &'v Value) -> Result<Self, String> {
        let octets = written.as_object().filter(|written| written.len() == 1);
        match octets.and_then(|written| written.get("octets")) {
            Some(Value::Null) => Err("an IE is written with a `value` or `octets`".into()),
            Some(octets) => Ok(Self::Octets(octets)),
            None if written.is_null() => Err("an IE is written with a `value` or `octets`".into()),
            None => Ok(Self::Value(written)),
        }
    }
}

/// What a tree that is written into a message is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// The tree of a message that it describes alone.
    Alone,
    /// The members of the tree of the message that an edit changes
    /// ([`edits`]): every other member is the one of the message.
    Edit,
}

/// What a tree has of a member of the message written into.
enum Taken {
    /// What it writes.
    Written(Value),
    /// Nothing, or a member that an edit takes out: the member is left out.
    Out,
    /// No member in an edit: the member is kept.
    Kept,
}

/// Whether `kind` is a `message-type` as a tree writes one.
fn is_type_written(kind: &Value) -> bool {
    kind.is_string() || kind.as_u64().is_some()
}

/// The `message-type` that the members `members` of a tree write, as a name
/// or the number of one.
fn written_type(members: &Map) -> Result<Option<&Value>, String> {
    match (members.iter()).find(|(name, _)| same_name(name, "message-type")) {
        Some((_, kind)) if is_type_written(kind) => Ok(Some(kind)),
        Some(_) => Err("a `message-type` is a name or the number of one".into()),
        None => Ok(None),
    }
}

/// What the tree of a message refuses before any of its IEs is written: a
/// `message-type` that names no message of `M`, in the IE `container` or
/// alone, and the same in the messages of its containers, which are not
/// more than [`NESTED`] deep.
fn typed<M: Viewed>(
    members: &Map,
    container: Option<&str>,
    scope: Scope,
) -> Result<Vec<(&'static str, Value)>, String> {
    let given = M::decided(container, written_type(members)?)?;
    for (name, written) in members {
        if let Some(inner) = message_of(written) {
            let inside = scope.inside().ok_or(Scope::REFUSED)?;
            typed::<M>(inner, Some(name), inside)?;
        }
    }
    Ok(given)
}

/// The members of `written` where it is the tree of a message in a
/// container: it has a `message-type`.
fn message_of(written: &Value) -> Option<&Map> {
    let members = written.as_object()?;
    (members.get("message-type"))
        .is_some_and(is_type_written)
        .then_some(members)
}

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

/// The members of the tree `tree` of a plain message of `M` that it writes
/// alone, with what the type of the message decides where the tree leaves
/// it out, and the name of its `message-type`, if it has one.
pub(crate) fn typed_members<M: Viewed>(
    tree: Value,
    scope: Scope,
) -> Result<(Map, Option<String>), String> {
    let Value::Object(mut members) = tree else {
        return Err("a message is written as its `message-type` and its IEs by name".into());
    };
    let given = typed::<M>(&members, None, scope)?;
    let kind = written_type(&members)?.map(type_named::<M>).transpose()?;
    for (field, value) in given {
        if !members.keys().any(|name| same_name(name, field)) {
            members.insert(field.into(), value);
        }
    }
    Ok((members, kind))
}

/// The message of the kind `kind` that the members `members` of a tree
/// write alone: `kind` names a message struct in one of the variants
/// `families` of `M`.
pub(crate) fn alone<M: Viewed>(
    families: &[&str],
    kind: &str,
    members: Map,
    scope: Scope,
) -> Result<M, String> {
    for family in families {
        if let Some(blank) = M::blank_of(family, kind) {
            return written(&blank.prepared(&members), members, Mode::Alone, scope);
        }
    }
    Err(format!("no message `{kind}`"))
}

/// The message that the tree `tree` of a container writes alone: its
/// `message-type` names it.
pub(crate) fn contained<M: Viewed>(tree: &Value, scope: Scope) -> Result<M, String> {
    if message_of(tree).is_none() {
        return Err("the `message-type` of the view names the message of a container".into());
    }
    let (members, kind) = typed_members::<M>(tree.clone(), scope)?;
    let kind = kind.ok_or("the `message-type` of the view names the message of a container")?;
    let message: M = alone(M::FAMILIES, &kind, members, scope)?;
    match message.refused_header() {
        Some(refused) => Err(refused),
        None => Ok(message),
    }
}

/// `message` as the tree `tree` edits it ([`edits`]).
pub(crate) fn edited<M: Viewed>(message: &M, tree: &Value, scope: Scope) -> Result<M, String> {
    let edits = edits::<M>(self::tree(message, scope), tree.clone(), scope)?;
    with_edits(message, edits, scope)
}

/// `value` without the members that it has not: a value has `null` for
/// each, and a tree leaves them out.
pub(crate) fn without_absent(mut value: Value) -> Value {
    fn strip(value: &mut Value) {
        match value {
            Value::Object(members) => {
                members.retain(|_, member| !member.is_null());
                members.values_mut().for_each(strip);
            }
            Value::Array(items) => items.iter_mut().for_each(strip),
            _ => {}
        }
    }
    strip(&mut value);
    value
}

/// The fields of the header `header` of a message of `M` that its type
/// does not decide, in the IE `container` or alone.
fn undecided<M: Viewed>(header: Value, container: Option<&str>) -> Map {
    let Value::Object(mut fields) = without_absent(header) else {
        return Map::new();
    };
    let given = M::decided(container, fields.get("message-type")).unwrap_or_default();
    fields.retain(|name, value| {
        !given
            .iter()
            .any(|(field, given)| field == name && given == value)
    });
    fields
}

/// The tree of `message`: its header without what the type of the message
/// decides, then each IE that it has by its value where that writes it back
/// ([`Ie::shown_value`]) and by its octets otherwise, then the IEs that its
/// table has no place for. A tree is one that a message is written from,
/// and the message that is written means what `message` means ([`meant`]).
pub(crate) fn tree<M: Viewed>(message: &M, scope: Scope) -> Value {
    let mut tree = Map::new();
    if let Some((header, ciphered)) = message.protection() {
        let header = undecided::<M>(header, Some(SECURITY_HEADER));
        tree.insert(SECURITY_HEADER.into(), header.into());
        if let Some(octets) = ciphered {
            let octets = Map::from_iter([("octets".into(), octets)]);
            tree.insert(CIPHERED.into(), octets.into());
        }
    }
    let Some(header) = message.header() else {
        return tree.into();
    };
    tree.extend(undecided::<M>(header, None));
    message.ies(scope, &mut |field| {
        let value = (field.ie)
            .and_then(|ie| ie.shown_value(field.scope))
            .map_or_else(
                || Map::from_iter([("octets".into(), field.octets.hex().into())]).into(),
                without_absent,
            );
        tree.insert(field.printed.to_owned(), value);
    });
    let unknown = message.body().map(|body| body.unknown_ies());
    if let Some(unknown) = unknown.filter(|unknown| !unknown.is_empty()) {
        tree.insert(UNKNOWN_IES.into(), unknown_text(unknown).into());
    }
    tree.into()
}

/// The message that stands for all those that mean what `message` means:
/// each IE in the form that stands for those that mean what it means
/// ([`Decoded::meant`]), the IEs of its table in the order of the table, and
/// after them, in the order they came in, those that the table has no place
/// for. Two messages mean the same when this is the same message for both,
/// and the message that the tree of a message writes means what the message
/// means.
pub(crate) fn meant<M: Viewed>(message: &M, scope: Scope) -> M {
    let mut forms = Vec::new();
    message.ies(scope, &mut |field| {
        if let Some(meant) = field.ie.and_then(|ie| ie.meant(field.scope)) {
            forms.push((field.printed, meant));
        }
    });
    let mut meant = message.clone();
    for (name, ie) in forms {
        if let Some(slot) = meant.slot(name) {
            slot.put(ie);
        }
    }
    if let Some(body) = meant.body_mut() {
        let unknown = body.unknown_ies().clone();
        body.set_unknown(unknown);
    }
    meant
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
        members.shift_remove(&name)
    };
    let (header, ciphered) = (taken(SECURITY_HEADER), taken(CIPHERED));
    let ciphered = match ciphered {
        Some(written) => {
            let octets = (written.as_object().filter(|written| written.len() == 1))
                .and_then(|written| written.get("octets")?.as_str())
                .and_then(oxirush_utils::tree::unhex);
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

/// The header of the type `H` that `header` writes: its fields, and those
/// of `given` that it leaves out, which the system decides.
pub(crate) fn security_header<H: Readable>(
    header: &Value,
    given: &[(&str, Value)],
) -> Result<H, String> {
    let mut header = header.clone();
    if let Value::Object(fields) = &mut header {
        for (field, value) in given {
            if !fields.keys().any(|name| same_name(name, field)) {
                fields.insert((*field).into(), value.clone());
            }
        }
    }
    readable::from_value(&header).map_err(|error| format!("{SECURITY_HEADER}: {error}"))
}

/// The members that the tree `tree` writes as an edit of a message of `M`
/// whose tree is `before`: each member that the tree changes, as the tree
/// writes it, and `None` for each member that the tree leaves out. A member
/// that the tree leaves as it is is not one of them.
pub(crate) fn edits<M: Viewed>(
    before: Value,
    tree: Value,
    scope: Scope,
) -> Result<Vec<(String, Option<Value>)>, String> {
    let (Value::Object(before), Value::Object(members)) = (before, tree) else {
        return Err("a message is written as its IEs by name".into());
    };
    let named = |map: &Map, name: &str| map.keys().any(|key| same_name(key, name));
    let mut edits = Vec::new();
    // What the tree leaves out is taken out.
    for name in before.keys() {
        if !named(&members, name) {
            edits.push((name.clone(), None));
        }
    }
    // What the tree changes is written by it.
    for (name, mut written) in members {
        let known = before.keys().find(|key| same_name(key, &name));
        if known.is_some_and(|known| before[known.as_str()] == written) {
            continue;
        }
        // A security header has the fields that the system decides, which a
        // tree leaves out.
        if let (true, Value::Object(fields)) = (same_name(&name, SECURITY_HEADER), &mut written) {
            for (field, value) in M::decided(Some(SECURITY_HEADER), None)? {
                if !fields.keys().any(|name| same_name(name, field)) {
                    fields.insert(field.into(), value);
                }
            }
        }
        if let Some(inner) = message_of(&written) {
            let inside = scope.inside().ok_or(Scope::REFUSED)?;
            typed::<M>(inner, Some(&name), inside)?;
        }
        match edits
            .iter_mut()
            .find(|(edited, _)| same_name(edited, &name))
        {
            Some(edit) => edit.1 = Some(written),
            None => edits.push((name, Some(written))),
        }
    }
    Ok(edits)
}

/// The message that the members `edits` of the tree of `original` write
/// ([`edits`]).
pub(crate) fn with_edits<M: Viewed>(
    original: &M,
    edits: Vec<(String, Option<Value>)>,
    scope: Scope,
) -> Result<M, String> {
    // An edit that changes nothing leaves the message as it is.
    if edits.is_empty() {
        return Ok(original.clone());
    }
    let entries = Entries::of(edits)?;
    written_entries(original, entries, Mode::Edit, scope)
}

/// What the IE that `names` names in a message has, found by [`ie_octets`]:
/// its octets, `None` for an optional IE that the message does not have, or
/// why it has none.
pub(crate) type Found = Result<Option<Vec<u8>>, (ErrorKind, String)>;

/// A member of the tree of a message, as [`ie_octets`] reads it.
pub(crate) enum Entry {
    /// A field of a header, or a member without octets of its own.
    Field,
    /// Octets of the message that are no IE.
    Octets(Vec<u8>),
    /// The IE at this place among those that the message has.
    Ie(usize),
    /// An optional IE that the message does not have.
    Absent,
}

/// The octets of the IE that `path` names in `message`, as the message has
/// them: `/nas`, then an IE, then for a container an IE of its message.
/// `None` for an optional IE that the message does not have.
pub(crate) fn ie_octets<M: Viewed>(
    message: &M,
    path: &str,
) -> Result<Option<Vec<u8>>, tree::Error> {
    let error = |kind, reason: String| tree::Error::new(kind, path, reason);
    let segments = tree::segments(path)?;
    match segments.split_first() {
        Some((root, names)) if same_name(root, "nas") && !names.is_empty() => {
            octets_at(message, names, Scope::NONE).map_err(|(kind, reason)| error(kind, reason))
        }
        _ => Err(error(
            ErrorKind::Path,
            "the path of an IE is `/nas/<ie>`".into(),
        )),
    }
}

/// [`ie_octets`] in `message`, of the IE that `names` names, in `scope`.
pub(crate) fn octets_at<M: Viewed>(message: &M, names: &[String], scope: Scope) -> Found {
    let mut entries = message.fields();
    if let Some((_, ciphered)) = message.protection() {
        entries.push((SECURITY_HEADER, Entry::Field));
        if let Some(ciphered) = ciphered {
            let octets = ciphered.as_str().and_then(oxirush_utils::tree::unhex);
            entries.push((CIPHERED, octets.map_or(Entry::Field, Entry::Octets)));
        }
    }
    let header = message.header();
    let fields = header.iter().flat_map(Value::as_object).flatten();
    entries.extend(fields.map(|(name, _)| (name.as_str(), Entry::Field)));
    let mut place = 0;
    message.ies(scope, &mut |field| {
        entries.push((field.printed, Entry::Ie(place)));
        place += 1;
    });
    if let Some(body) = message.body() {
        body.absent(&mut |name, _| entries.push((name, Entry::Absent)));
        if !body.unknown_ies().is_empty() {
            entries.push((UNKNOWN_IES, Entry::Field));
        }
    }
    let name = &names[0];
    let all: Vec<&str> = entries.iter().map(|(name, _)| *name).collect();
    let Some(at) = oxirush_utils::tree::named(&all, name) else {
        return Err((
            ErrorKind::NoSuchMember,
            format!("`{name}` is no IE of the message"),
        ));
    };
    let (name, entry) = &entries[at];
    let inside = || (ErrorKind::Refused, format!("`{name}` has no message in it"));
    match (entry, &names[1..]) {
        (Entry::Absent, _) => Ok(None),
        (Entry::Octets(octets), []) => Ok(Some(octets.clone())),
        (Entry::Field, []) => Err((
            ErrorKind::Refused,
            format!("`{name}` is a field of a header, with no octets of its own"),
        )),
        (Entry::Ie(at), rest) => {
            let mut found = None;
            let mut place = 0;
            message.ies(scope, &mut |field| {
                if place == *at {
                    found = match rest {
                        [] => Some(Ok(oxirush_utils::tree::unhex(&field.octets.hex()))),
                        rest => field.ie.and_then(|ie| ie.octets_inside(rest, field.scope)),
                    };
                }
                place += 1;
            });
            found.unwrap_or_else(|| Err(inside()))
        }
        _ => Err(inside()),
    }
}

/// The members of a tree, which are found by their names however these are
/// written: by the letters of a name ([`letters`]). A member that is `None`
/// is one that an edit takes out.
struct Entries {
    /// Each member by its name, in the order of the tree, until it is taken.
    members: Vec<(String, Option<Option<Value>>)>,
    /// The first letter of the name of each member and how many letters it
    /// has: names of the same letters have the same.
    shapes: Vec<(Option<u8>, usize)>,
    /// The first letter of each name, as a bit of its code (0 for a name
    /// without letters), whether its member is still there or not: a name
    /// that starts with another is found without a search.
    starts: u128,
}

/// The letters of `name`, in lower case, as [`letters`] has them.
fn letters_of(name: &str) -> impl Iterator<Item = u8> + '_ {
    (name.bytes().filter(u8::is_ascii_alphanumeric)).map(|octet| octet.to_ascii_lowercase())
}

/// The first letter of `name` and how many letters it has.
fn shape(name: &str) -> (Option<u8>, usize) {
    let mut letters = letters_of(name);
    (letters.next(), letters.count() + 1)
}

impl Entries {
    /// The members `members`; an error names the first member that a later
    /// one names again.
    fn of(members: impl IntoIterator<Item = (String, Option<Value>)>) -> Result<Self, String> {
        let members: Vec<_> = (members.into_iter())
            .map(|(name, member)| (name, Some(member)))
            .collect();
        let shapes: Vec<_> = (members.iter()).map(|(name, _)| shape(name)).collect();
        // The first member that a later one names again, as the later one
        // that comes first has it.
        for (at, (name, _)) in members.iter().enumerate() {
            let twice = (0..at).rev().find(|&before| {
                shapes[before] == shapes[at] && letters_of(&members[before].0).eq(letters_of(name))
            });
            if let Some(before) = twice {
                return Err(format!("`{}` is named twice", members[before].0));
            }
        }
        let starts = (shapes.iter()).fold(0, |starts, (first, _)| starts | start(first.as_ref()));
        Ok(Self {
            members,
            shapes,
            starts,
        })
    }

    /// The place of the member that `name` names.
    fn find(&self, name: &str) -> Option<usize> {
        let shaped = shape(name);
        if self.starts & start(shaped.0.as_ref()) == 0 {
            return None;
        }
        let left = |at: &usize| self.members[*at].1.is_some();
        let places = || (0..self.members.len()).filter(left);
        (places().find(|&at| self.members[at].0 == name)).or_else(|| {
            places().find(|&at| {
                self.shapes[at] == shaped && letters_of(&self.members[at].0).eq(letters_of(name))
            })
        })
    }

    /// The one of the names `absent` that the member at `at` names, if it is
    /// still there.
    fn absent_named<'n>(&self, at: usize, absent: &[&'n str]) -> Option<&'n str> {
        let name = &self.members[at].0;
        self.members[at].1.as_ref()?;
        let (first, count) = self.shapes[at];
        let same = |known: &&&str| {
            letters_of(known).next() == first
                && letters_of(known).count() == count
                && letters_of(known).eq(letters_of(name))
        };
        let found = absent.iter().find(|known| **known == name);
        found.or_else(|| absent.iter().find(same)).copied()
    }

    /// The member that `name` names, taken out.
    fn remove(&mut self, name: &str) -> Option<Option<Value>> {
        self.find(name).and_then(|at| self.members[at].1.take())
    }

    /// The name of the first member left, in the order of the letters.
    fn first(self) -> Option<String> {
        let left = self
            .members
            .into_iter()
            .filter(|(_, member)| member.is_some());
        left.map(|(name, _)| name).min_by_key(|name| letters(name))
    }
}

/// The bit of the first letter `letter` of a name, which is ASCII, in
/// [`Entries`]: bit 0 for a name without letters.
fn start(letter: Option<&u8>) -> u128 {
    1 << letter.map_or(0, |letter| letter & 0x7f)
}

/// The message that `members` write: `original` as an edit changes it, or
/// alone a message that has nothing but what the tree writes.
fn written<M: Viewed>(original: &M, members: Map, mode: Mode, scope: Scope) -> Result<M, String> {
    let entries = Entries::of(members.into_iter().map(|(name, entry)| (name, Some(entry))))?;
    written_entries(original, entries, mode, scope)
}

/// [`written`] of the members `entries`.
fn written_entries<M: Viewed>(
    original: &M,
    mut entries: Entries,
    mode: Mode,
    scope: Scope,
) -> Result<M, String> {
    let (alone, edit) = (mode == Mode::Alone, mode == Mode::Edit);
    // The message is edited in place: each field that the tree writes is
    // checked first, and then written, in the order of the fields of the
    // message, header first.
    let received = original;
    let mut message = original.clone();
    // The header that protects the message is written whole, as a field of
    // a header is, and a message that is ciphered by its octets.
    let mut protection = None;
    if let Some((kept, ciphered)) = original.protection() {
        // What an edit does not write is the message's own.
        let header = match entries.remove(SECURITY_HEADER) {
            None => kept,
            Some(None) => {
                return Err(format!(
                    "{SECURITY_HEADER}: null is not an IE with a `value` or `octets`"
                ));
            }
            Some(Some(written)) => match Form::of(&written) {
                Ok(Form::Value(_)) => written,
                Ok(Form::Octets(_)) => {
                    return Err(format!(
                        "`{SECURITY_HEADER}` is the header that protects the message: it has a \
                         `value` alone"
                    ));
                }
                Err(error) => return Err(format!("{SECURITY_HEADER}: {error}")),
            },
        };
        let octets = match ciphered {
            Some(kept) => {
                let written = match entries.remove(CIPHERED) {
                    None => Some(kept),
                    Some(written) => written
                        .as_ref()
                        .and_then(|written| match Form::of(written) {
                            Ok(Form::Octets(octets)) => Some(octets.clone()),
                            _ => None,
                        }),
                };
                match written.filter(|written| written.as_str().is_some_and(is_hex)) {
                    Some(written) => Some(written),
                    None => {
                        return Err(format!(
                            "`{CIPHERED}` is the message as it is ciphered: it has `octets` alone"
                        ));
                    }
                }
            }
            None => None,
        };
        protection = Some((header, octets));
    }
    // A member that an edit takes out is left out, and one that an edit does
    // not have is kept as the message has it.
    let take = |entries: &mut Entries, name: &str| match entries.remove(name) {
        Some(Some(entry)) => Taken::Written(entry),
        Some(None) => Taken::Out,
        None if edit => Taken::Kept,
        None => Taken::Out,
    };
    // The IEs that the table of the message has no place for, when the tree
    // lists them.
    let unknown = match take(&mut entries, UNKNOWN_IES) {
        Taken::Written(written) => Some(unknown_ies(&written)?),
        _ => None,
    };
    let mut failure = None;
    let mut header = message.header();
    for (name, value) in header.iter_mut().flat_map(Value::as_object_mut).flatten() {
        let written = match take(&mut entries, name) {
            Taken::Kept => continue,
            Taken::Written(written) => Some(written),
            Taken::Out => None,
        };
        match written.as_ref().map(Form::of) {
            // A field that reads as a name takes the number of one too.
            Some(Ok(Form::Value(written))) => {
                let named = match (&*value, written.as_u64()) {
                    (Value::String(_), Some(number)) => M::header_name(name, number),
                    _ => None,
                };
                *value = named.unwrap_or_else(|| written.clone());
            }
            Some(Err(error)) => failure = Some(format!("{name}: {error}")),
            None if M::SPARE.contains(&name.as_str()) => {}
            None if alone => failure = Some(format!("`{name}` is not written")),
            _ => failure = Some(format!("`{name}` is the header: it has a `value` alone")),
        }
    }
    // An optional IE that the message does not have stays out when the
    // tree leaves it out. One that a member left writes is added without a
    // value, and then written as any other.
    let mut absent = Vec::new();
    if let Some(body) = original.body() {
        body.absent(&mut |name, _| absent.push(name));
    }
    let mut added = Vec::new();
    for at in 0..entries.members.len() {
        let Some(name) = entries.absent_named(at, &absent) else {
            continue;
        };
        match &entries.members[at].1 {
            Some(None) => entries.members[at].1 = None,
            Some(Some(_)) => {
                if let Some(slot) = message.slot(name) {
                    slot.add();
                    added.push(name);
                }
            }
            None => {}
        }
    }
    // What the tree writes of each IE: taken out, its octets, or the value
    // to write it from.
    let mut cleared = Vec::new();
    let mut octets_written = Vec::new();
    let mut values = Vec::new();
    // The IEs of the message, which an error lists.
    let mut ie_names = Vec::new();
    message.ies(scope, &mut |visited| {
        let (name, optional) = (visited.printed, visited.optional);
        ie_names.push(name);
        // An IE that the tree leaves out is taken out of the message.
        let written = match take(&mut entries, name) {
            Taken::Kept => return,
            Taken::Written(written) => written,
            Taken::Out if optional => return cleared.push(name),
            Taken::Out if alone => return failure = Some(format!("`{name}` is not written")),
            Taken::Out => return failure = Some(format!("`{name}` is mandatory: it stays")),
        };
        // What is written of an IE that is added is written, whatever it
        // is, and so is each IE of a message that the tree describes
        // alone: octets that happen to be those of an IE without a value
        // are still the ones to send.
        let fresh = alone || added.contains(&name);
        match Form::of(&written) {
            Err(error) => failure = Some(format!("{name}: {error}")),
            Ok(Form::Octets(octets)) => {
                if fresh || *octets != Value::from(visited.octets.hex()) {
                    match octets_value(octets, visited.octets.size()) {
                        Ok(octets) => octets_written.push((name, octets)),
                        Err(error) => failure = Some(format!("{name}: {error}")),
                    }
                }
            }
            Ok(Form::Value(value)) => {
                let value_of = || visited.ie.and_then(|ie| ie.value(visited.scope));
                if fresh || Some(value) != value_of().as_ref() {
                    values.push((name, written));
                }
            }
        }
    });
    if let Some(name) = entries.first() {
        if let Some(body) = original.body() {
            body.absent(&mut |absent, _| ie_names.push(absent));
        }
        return Err(readable::none_of(&name, &ie_names, "IE"));
    }
    if let Some(failure) = failure {
        return Err(failure);
    }
    if let Some((header, octets)) = &protection {
        message.set_protection(header, octets.as_ref())?;
    }
    if let Some(header) = &header {
        message.set_header(header)?;
    }
    for name in cleared {
        if let Some(slot) = message.slot(name) {
            slot.clear();
        }
    }
    for (name, octets) in octets_written {
        if let Some(slot) = message.slot(name) {
            slot.set_octets(&octets);
        }
    }
    if values.is_empty() {
        return checked(message, received, unknown);
    }
    // The IEs of the values, encoded once the octets that are written are
    // the message's: an IE that says how another is read is among them.
    let mut encoded = Vec::new();
    message.ies(scope, &mut |visited| {
        let name = visited.printed;
        let Some(at) = values.iter().position(|(written, _)| *written == name) else {
            return;
        };
        let (_, value) = values.swap_remove(at);
        let Some(ie) = visited.ie else {
            failure = Some(format!("{name}: this IE has octets and no value to write"));
            return;
        };
        match ie.encoded_ie(&value, visited.scope) {
            Ok(ie) => encoded.push((name, ie)),
            Err(error) => failure = Some(format!("{name}: {error}")),
        }
    });
    if let Some(failure) = failure {
        return Err(failure);
    }
    for (name, ie) in encoded {
        if let Some(slot) = message.slot(name) {
            slot.put(ie);
        }
    }
    checked(message, received, unknown)
}

/// `message`, which a tree wrote from `received`, unless it keeps the
/// message authentication code of a message that it no longer protects: the
/// code is that of the octets it was computed over. The IEs `unknown` that
/// the tree lists for those that the table has no place for are those of
/// the message, after the IEs of its table, when they are others than
/// `received` has.
fn checked<M: Viewed>(
    mut message: M,
    received: &M,
    unknown: Option<crate::common::UnknownIes>,
) -> Result<M, String> {
    // A message that no header protected has no code to keep.
    if let (Some((code, body)), Some((old_code, old_body))) =
        (message.protected(), received.protected())
        && body != old_body
        && code == old_code
    {
        return Err(format!(
            "the message authentication code of `{SECURITY_HEADER}` is that of the \
             message as it was: write the code of the edited message, or edit the \
             plain message"
        ));
    }
    let Some(unknown) = unknown else {
        return Ok(message);
    };
    let kept = received.body().map(|body| body.unknown_ies());
    if kept.is_none_or(|kept| *kept != unknown) {
        match message.body_mut() {
            Some(body) => body.set_unknown(unknown),
            None if !unknown.is_empty() => {
                return Err(format!(
                    "`{UNKNOWN_IES}` are IEs of a message that has IEs of its own"
                ));
            }
            None => {}
        }
    }
    Ok(message)
}

/// Whether `text` is octets in hexadecimal.
fn is_hex(text: &str) -> bool {
    oxirush_utils::tree::unhex(text).is_some()
}

/// How the value of an IE type of [`decoded_ie`] is read from its octets
/// and written in them.
pub(crate) struct Coded<T, F> {
    /// The value of the octets, if they have one.
    pub(crate) decode: fn(&T) -> Option<F>,
    /// The IE with the octets of the value, from the IE that it is written
    /// over.
    pub(crate) encode: fn(&T, F) -> Result<T, ValueError>,
}

impl<T: Decoded, F: Readable + Clone + PartialEq> Coded<T, F> {
    /// The value of the octets of `ie`, where encoding it over `ie` gives an
    /// IE that reads as it: octets that `decode` reads and `encode` does not
    /// write have no value.
    pub(crate) fn value(&self, ie: &T) -> Option<F> {
        let value = (self.decode)(ie)?;
        let again = (self.encode)(ie, value.clone()).ok()?;
        (again == *ie || self.reads(&again, &value)).then_some(value)
    }

    /// Whether `ie` has the value `value`: the same value, or one of the same
    /// readable form.
    fn reads(&self, ie: &T, value: &F) -> bool {
        match self.value(ie) {
            Some(read) if read == *value => true,
            Some(read) => readable::to_value(&read).ok() == readable::to_value(value).ok(),
            None => false,
        }
    }

    /// The value of `ie` where it writes the IE back alone, as
    /// [`Ie::written_back`] says of it: the IE that the value writes means
    /// what `ie` means; `by_value` says of an IE whose value says all that
    /// its octets mean without deciding them.
    pub(crate) fn shown(&self, ie: &T, by_value: fn(&T) -> bool, scope: Scope) -> Option<Value> {
        let value = self.value(ie)?;
        let new = (self.encode)(&T::unwritten(), value.clone()).ok()?;
        let back = match by_value(ie) || by_value(&new) {
            false => new == *ie,
            true => self.reads(&new, &value) && new.meant(scope) == ie.meant(scope),
        };
        back.then(|| readable::to_value(&value).ok())?
    }

    /// The IE that stands for those that mean what `ie` means, where
    /// `by_value` says that its value says all that they mean.
    pub(crate) fn meant(&self, ie: &T, by_value: fn(&T) -> bool) -> T {
        let written = || (self.encode)(&T::unwritten(), self.value(ie)?).ok();
        match by_value(ie) {
            true => written().unwrap_or_else(|| ie.clone()),
            false => ie.clone(),
        }
    }

    /// `ie` with the octets of the readable form `value`, if it reads as
    /// that value.
    pub(crate) fn built(&self, ie: &T, value: &Value, scope: Scope) -> Result<T, String> {
        let typed: F = readable::from_value(value)?;
        let new = (self.encode)(ie, typed.clone()).map_err(refused)?;
        match self.reads(&new, &typed) {
            true => Ok(new),
            false => carried(new, &readable::to_value(&typed)?, scope),
        }
    }
}

/// Why the constructor of an IE refuses the value that is written, as an
/// edit is told: the member, what it was given and the limit that it breaks.
pub(crate) fn refused(error: ValueError) -> String {
    error.to_string()
}

/// Why a message does not encode, as an edit is told: what the error says,
/// without the words that the refusal of the edit begins with.
pub(crate) fn unencoded(error: crate::common::Error) -> String {
    match error {
        crate::common::Error::EncodingError(reason) => reason,
        other => other.to_string(),
    }
}

/// Why the value `value` does not write an IE, which it leaves with
/// `octets` octets where the IE has more.
pub(crate) fn too_short(value: &Value, octets: usize) -> String {
    match value.as_object().is_some_and(Map::is_empty) {
        true => format!("{value} writes no member of the IE"),
        false => format!(
            "{value} writes {octets} of the octets of the IE, which has more: a member of \
             each of its octets is written"
        ),
    }
}

/// `ie`, if `written` is the value its octets have; else what they have.
pub(crate) fn carried<T: Decoded>(ie: T, written: &Value, scope: Scope) -> Result<T, String> {
    match ie.decoded(scope) {
        Some(carried) if carried == *written => Ok(ie),
        Some(carried) => Err(format!(
            "{written} cannot be encoded: the IE would be {carried}"
        )),
        None => {
            let octets = readable::to_value(&ie)?;
            let octets = octets.get("value").unwrap_or(&octets);
            Err(format!(
                "{written} cannot be encoded: the IE would have the octets {octets}, which are \
                 read as no value"
            ))
        }
    }
}

/// The members of a value that is an object, for the macros below.
pub(crate) fn members(value: &Value) -> Result<&Map, String> {
    (value.as_object()).ok_or_else(|| format!("{value} is not an object of the members of the IE"))
}

/// Octets as the numbers they are, where an IE has a list of identities.
pub(crate) fn numbers(octets: &[u8]) -> Vec<u16> {
    octets.iter().copied().map(u16::from).collect()
}

/// The octets of a list of numbers, each a `member` that is `min` to `max`.
pub(crate) fn octets(
    member: &'static str,
    numbers: &[u16],
    min: u8,
    max: u8,
) -> Result<Vec<u8>, ValueError> {
    (numbers.iter().enumerate())
        .map(|(entry, number)| {
            within(member, *number, min.into(), max.into())
                .map(|number| number as u8)
                .map_err(|error| error.at(entry))
        })
        .collect()
}

/// A value that is a name where the specification has one, else a number:
/// a coded value, or a timer that runs or is `deactivated`.
#[derive(Clone, PartialEq)]
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

impl<E: readable::Readable, N: readable::Readable> readable::Readable for Code<E, N> {
    fn shown(&self, held: &'static str) -> Value {
        match self {
            Self::Name(name) => name.shown(held),
            Self::Number(number) => number.shown(held),
        }
    }

    /// A number, also written `"0x…"`, is read as one and anything else as
    /// a name, so that the error for a name that does not exist lists those
    /// that do.
    fn read(value: &Value) -> Result<Self, String> {
        let hexadecimal = |text: &str| text.starts_with("0x") || text.starts_with("0X");
        if value.is_number() || value.as_str().is_some_and(hexadecimal) {
            return N::read(value).map(Self::Number);
        }
        // A number in a text, as the specifications write a cause
        let text = value.as_str().unwrap_or_default();
        match text.strip_prefix('#').unwrap_or(text).parse::<u64>() {
            Ok(number) => Err(format!(
                "no name `{text}`: a number is written as one, {number}"
            )),
            Err(_) => E::read(value).map(Self::Name),
        }
    }
}

/// The value of a GPRS timer: its seconds, or that it is deactivated.
pub(crate) type Timer = Code<Deactivated, u64>;

/// A PLMN identity as a tree writes it: `"208-93"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PlmnText(pub(crate) Plmn);

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct PlmnText(Plmn as plmn));

/// The PLMN identities of a list, as a tree writes them.
pub(crate) fn plmn_texts(plmns: Vec<Plmn>) -> Vec<PlmnText> {
    plmns.into_iter().map(PlmnText).collect()
}

/// The PLMN identities that a tree writes.
pub(crate) fn plmns(texts: &[PlmnText]) -> Vec<Plmn> {
    texts.iter().map(|text| text.0).collect()
}

/// A tracking area identity of either system as a tree writes it:
/// `{"plmn": "208-93", "tac": 1}`.
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct TaiForm<T>(pub(crate) T);

impl<T: crate::common::plmn::TaiParts> readable::Readable for TaiForm<T> {
    fn shown(&self, _: &'static str) -> Value {
        crate::common::forms::tai::shown(&self.0)
    }

    fn read(value: &Value) -> Result<Self, String> {
        crate::common::forms::tai::read(value).map(Self)
    }
}

/// The name of a timer that does not run.
#[derive(Clone, PartialEq)]
pub(crate) enum Deactivated {
    Deactivated,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum Deactivated {
        Deactivated,
    }
);

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

    /// Without the last octet, when it is zero and more than `least`
    /// octets are there; `false` when the octets stay as they are.
    fn shorter(&mut self, least: usize) -> bool;

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

    fn shorter(&mut self, least: usize) -> bool {
        let last = self.len() > least && self.last() == Some(&0);
        if last {
            self.truncate(self.len() - 1);
        }
        last
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

    fn shorter(&mut self, _: usize) -> bool {
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
    /// Whether the IE has the value exactly as it was written, or why the
    /// setter refuses it.
    fn exact(self) -> Result<bool, ValueError>;
}

impl Wrote for () {
    fn exact(self) -> Result<bool, ValueError> {
        Ok(false)
    }
}

impl Wrote for bool {
    fn exact(self) -> Result<bool, ValueError> {
        Ok(self)
    }
}

impl<T: Wrote> Wrote for Result<T, ValueError> {
    fn exact(self) -> Result<bool, ValueError> {
        self?.exact()
    }
}

/// Write the coded value of a field of `ie`: by its name with `named`, the
/// setter of the type, or as the number that `raw` reads back. A number is
/// the code itself, whether the specification names it or not: `true` when
/// the IE has it, which then reads as its name if it has one.
pub(crate) fn write_code<T: Fields + Readable, E>(
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

/// Write `number` in the bits that `raw` reads the coded value of a field
/// from. A code without a name has no setter: the bits are those that change
/// what `raw` reads, in an IE that is long enough to have them, and they
/// take the first combination that reads as `number`. An IE in which none
/// does is left as it is.
fn set_number<T: Fields + Readable>(ie: &mut T, number: u8, raw: fn(&T) -> u8) {
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
        return Err(format!(
            "no member `{name}`, expected one of {}",
            names.join(", ")
        ));
    };
    let current = flags.contains(&(*flag, true));
    let value = (value.as_bool()).ok_or_else(|| format!("{name}: {value} is not true or false"))?;
    // A flag that is as written is left alone: setting one extends the
    // value up to its octet.
    if (built || current != value)
        && !(ie.set_flag(flag, value) && ie.flags().contains(&(*flag, value)))
    {
        return Err(format!("{name} cannot be {value}: it would be {}", !value));
    }
    Ok(())
}

/// [`Decoded`] for an IE type: its value is a `$form`, which `$decode`
/// reads and `$encode` builds the IE of. Octets that `$decode` reads and
/// `$encode` does not build have no value: what a tree shows can be
/// written.
macro_rules! decoded_ie {
    ($ie:ty: $form:ty, $decode:expr, $encode:expr) => {
        $crate::common::view::decoded_ie!($ie: $form, $decode, $encode, meant: |_| false);
    };
    // After `meant:`, when the value of an IE says all that its octets mean,
    // though it does not decide them: the IE then stands with all those of
    // its value, in the form that the value is written in.
    ($ie:ty: $form:ty, $decode:expr, $encode:expr, meant: $meant:expr) => {
        impl $ie {
            /// How the value of the IE is read and written.
            const CODED: $crate::common::view::Coded<Self, $form> =
                $crate::common::view::Coded { decode: $decode, encode: $encode };
        }

        impl $crate::common::view::Decoded for $ie {
            fn unwritten() -> Self {
                <$ie>::blank()
            }

            fn meant(&self, _: $crate::common::view::Scope) -> Self {
                Self::CODED.meant(self, $meant)
            }

            fn decoded(&self, _: $crate::common::view::Scope) -> Option<oxirush_utils::tree::Value> {
                $crate::common::readable::to_value(&Self::CODED.value(self)?).ok()
            }

            fn with_decoded(
                &self,
                value: &oxirush_utils::tree::Value,
                scope: $crate::common::view::Scope,
            ) -> core::result::Result<Self, String> {
                Self::CODED.built(self, value, scope)
            }

            fn shown_value(
                &self,
                scope: $crate::common::view::Scope,
            ) -> Option<oxirush_utils::tree::Value> {
                Self::CODED.shown(self, $meant, scope)
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
            fn decoded(
                &self,
                _: $crate::common::view::Scope,
            ) -> Option<oxirush_utils::tree::Value> {
                let name: fn(&$ie) -> Option<$code> = $name;
                let from: fn($code) -> $ie = $from;
                let name = name(self).filter(|code| from(*code).value == self.value);
                let code = $crate::common::view::Code::of(name, self.value);
                $crate::common::readable::to_value(&code).ok()
            }

            fn with_decoded(
                &self,
                value: &oxirush_utils::tree::Value,
                scope: $crate::common::view::Scope,
            ) -> core::result::Result<Self, String> {
                use $crate::common::view::Code;
                let from: fn($code) -> $ie = $from;
                match $crate::common::readable::from_value::<Code<$code>>(value)? {
                    Code::Name(code) => {
                        let written =
                            $crate::common::readable::to_value(&Code::<$code>::Name(code))?;
                        $crate::common::view::carried(from(code), &written, scope)
                    }
                    Code::Number(number) => {
                        let new = <$ie>::new(number);
                        match new.value == number {
                            true => Ok(new),
                            false => Err(format!(
                                "{number} cannot be encoded: the IE would be {}",
                                new.value
                            )),
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
                Ok(from(name))
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
    ($ie:ident { $($key:literal: $get:expr, $set:expr;)* } $($flags:ident)?) => {
        impl $crate::common::view::Fields for $ie {
            fn octets(&mut self) -> &mut dyn $crate::common::view::FlagOctets {
                &mut self.value
            }
        }

        impl $ie {
            /// `onto` with the members of this IE written in it, as a value
            /// that has them writes them: every member where `built`, and
            /// else those that differ. `None` where a member is not written
            /// as it is.
            fn members_onto(&self, mut onto: Self, built: bool) -> Option<Self> {
                $(
                    let get: fn(&Self) -> _ = $get;
                    let set: fn(&mut Self, _) -> _ = $set;
                    let member = get(self);
                    if built || get(&onto) != member {
                        #[allow(clippy::let_unit_value)]
                        let wrote = set(&mut onto, member.clone());
                        let exact = $crate::common::view::Wrote::exact(wrote).ok()?;
                        if !exact && get(&onto) != member {
                            return None;
                        }
                    }
                )*
                $crate::common::view::fields_ie!(@onto self, onto, built $(, $flags)?);
                Some(onto)
            }
        }

        impl $crate::common::view::Decoded for $ie {

            fn unwritten() -> Self {
                <$ie>::blank()
            }

            fn meant(&self, _: $crate::common::view::Scope) -> Self {
                $crate::common::view::fields_ie!(@meant self $(, $flags)?)
            }

            fn decoded(&self, _: $crate::common::view::Scope) -> Option<oxirush_utils::tree::Value> {
                #[allow(unused_mut)]
                let mut members = oxirush_utils::tree::Map::new();
                $(
                    let get: fn(&Self) -> _ = $get;
                    let member = $crate::common::readable::to_value(&get(self)).ok()?;
                    members.insert($key.into(), member);
                )*
                $crate::common::view::fields_ie!(@flags self, members $(, $flags)?);
                let members: oxirush_utils::tree::Value = members.into();
                $crate::common::view::fields_ie!(@shown self, members $(, $flags)?)
            }

            fn with_decoded(
                &self,
                value: &oxirush_utils::tree::Value,
                _: $crate::common::view::Scope,
            ) -> core::result::Result<Self, String> {
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
                                let exact = $crate::common::view::Wrote::exact(wrote)
                                    .map_err($crate::common::view::refused)?;
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
                // An IE that is built has the octets of the members that are
                // written: a value that writes none says nothing of the IE,
                // and one that leaves it with fewer octets than the IE is
                // received with writes too few of them.
                #[allow(unused_imports)]
                use $crate::common::IeRules;
                if built {
                    $crate::common::view::fields_ie!(@shortest ie $(, $flags)?);
                }
                if built
                    && ($crate::common::view::members(value)?.is_empty()
                        || !ie.receiver_length_ok())
                {
                    let bits = $crate::common::view::Fields::octets(&mut ie).bits();
                    return Err($crate::common::view::too_short(value, bits / 8));
                }
                Ok(ie)
            }

            // What `written_back` says of the value of the IE, on the typed
            // members.
            fn shown_value(
                &self,
                scope: $crate::common::view::Scope,
            ) -> Option<oxirush_utils::tree::Value> {
                #[allow(unused_imports)]
                use $crate::common::IeRules;
                use $crate::common::view::Decoded;
                let value = Decoded::decoded(self, scope)?;
                #[allow(unused_mut)]
                let mut ie = self.members_onto(Self::unwritten(), true)?;
                $crate::common::view::fields_ie!(@shortest ie $(, $flags)?);
                let none = value.as_object().is_none_or(oxirush_utils::tree::Map::is_empty);
                (!none && ie.receiver_length_ok() && Decoded::meant(&ie, scope) == Decoded::meant(self, scope))
                    .then_some(value)
            }
        }

        #[cfg(test)]
        pastey::paste! {
            /// The IE is built from its value, with the octets of every
            /// member: from nothing, and from each octet.
            #[test]
            fn [<$ie:snake _is_built_from_its_value>]() {
                use $crate::common::view::tests::{Octet, built_from_nothing, built_from_value};
                built_from_nothing(<$ie>::blank());
                for octet in 0..=255_u8 {
                    // The digits of a time are decimal.
                    let decimal = octet & 0x0f <= 9 && octet >> 4 <= 9;
                    if !decimal && stringify!($ie).contains("Time") {
                        continue;
                    }
                    let mut ie = <$ie>::blank();
                    ie.value = Octet::of(octet);
                    built_from_value(<$ie>::blank(), ie);
                }
            }
        }
    };
    (@meant $ie:ident) => {
        $ie.clone()
    };
    (@meant $ie:ident, exact) => {
        $ie.clone()
    };
    // Octets of flags at the end that are all zero say what their absence
    // says: none of their flags is set.
    (@meant $ie:ident, flags) => {{
        let mut meant = $ie.clone();
        while $crate::common::view::Fields::octets(&mut meant).shorter(0) {}
        meant
    }};
    (@shortest $ie:ident) => {};
    (@shortest $ie:ident, exact) => {};
    // An IE of flags that a value builds is the shortest that carries the
    // flags that are set and that is still an IE of its type: one that the
    // checks of the type take, for its length and as a sender writes it,
    // and that has an octet. Every type of flags has such a check.
    (@shortest $ie:ident, flags) => {
        let mut shorter = $ie.clone();
        while $crate::common::view::Fields::octets(&mut shorter).shorter(1) {
            if shorter.receiver_length_ok() && shorter.sender_ok() {
                $ie = shorter.clone();
            }
        }
    };
    (@flags $ie:ident, $members:ident) => {};
    (@flags $ie:ident, $members:ident, exact) => {};
    (@flags $ie:ident, $members:ident, flags) => {
        for (flag, value) in $crate::common::view::Flags::flags($ie) {
            $members.insert(flag.to_owned(), value.into());
        }
    };
    (@shown $ie:ident, $members:ident) => {
        Some($members)
    };
    (@shown $ie:ident, $members:ident, flags) => {
        Some($members)
    };
    // What a tree shows can be written: octets that the members do not give
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
        let again = $ie.members_onto(blank, false)?;
        (again.value == $ie.value).then_some($members)
    }};
    (@onto $from:ident, $onto:ident, $built:ident) => {};
    (@onto $from:ident, $onto:ident, $built:ident, exact) => {};
    (@onto $from:ident, $onto:ident, $built:ident, flags) => {
        for (flag, on) in $crate::common::view::Flags::flags($from) {
            let current = $crate::common::view::Flags::flags(&$onto).contains(&(flag, true));
            if ($built || current != on)
                && !($crate::common::view::Flags::set_flag(&mut $onto, flag, on)
                    && $crate::common::view::Flags::flags(&$onto).contains(&(flag, on)))
            {
                return None;
            }
        }
    };
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
/// the value it has, or is absent where the IE has none and its type may be,
/// as a tree leaves out a member that a value has not.
macro_rules! built_ie {
    ($ie:ty, $from:expr, { $($key:ident: $ty:ty $(= $get:expr)?),+ $(,)? }) => {
        impl $crate::common::view::Decoded for $ie {

            fn unwritten() -> Self {
                <$ie>::blank()
            }
            fn decoded(&self, _: $crate::common::view::Scope) -> Option<oxirush_utils::tree::Value> {
                // The members that the getters read, and the IE that `$from`
                // builds of them.
                let read = |ie: &Self| -> Option<(oxirush_utils::tree::Value, Option<Self>)> {
                    let mut members = oxirush_utils::tree::Map::new();
                    $(
                        let $key: $ty = $crate::common::view::built_ie!(@get ie, $key $(, $get)?)?;
                        let member = $crate::common::readable::to_value(&$key).ok()?;
                        let name = $crate::common::names::name!(stringify!($key));
                        members.insert(name.to_owned(), member);
                    )+
                    let from: fn(
                        $($ty),+
                    ) -> core::result::Result<Self, $crate::common::ValueError> = $from;
                    Some((members.into(), from($($key),+).ok()))
                };
                // Octets that are read and that `$from` does not build have
                // no value: what a tree shows can be written.
                let (members, built) = read(self)?;
                let built = built?;
                // An IE built as this one reads as it.
                if built == *self {
                    return Some(members);
                }
                (read(&built)?.0 == members).then_some(members)
            }

            fn with_decoded(
                &self,
                value: &oxirush_utils::tree::Value,
                scope: $crate::common::view::Scope,
            ) -> core::result::Result<Self, String> {
                use $crate::common::readable::{from_value, same_name, to_value};
                let written = $crate::common::view::members(value)?;
                const NAMES: &[&str] = &[$($crate::common::names::name!(stringify!($key))),+];
                if let Some(name) = (written.keys())
                    .find(|name| !NAMES.iter().any(|known| same_name(known, name)))
                {
                    return Err(format!("no member `{name}`"));
                }
                let mut members = oxirush_utils::tree::Map::new();
                $(
                    let $key: $ty = match (written.iter())
                        .find(|(name, _)| same_name(name, $crate::common::names::name!(stringify!($key))))
                    {
                        Some((name, member)) => {
                            from_value(member).map_err(|error| format!("{name}: {error}"))?
                        }
                        // The IE's own, or none where it may have none: a
                        // tree leaves out a member that a value has not
                        None => $crate::common::view::built_ie!(@get self, $key $(, $get)?)
                            .or_else(<$ty as $crate::common::readable::Readable>::missing)
                            .ok_or(concat!(stringify!($key), " is not written"))?,
                    };
                    let name = $crate::common::names::name!(stringify!($key));
                    members.insert(name.to_owned(), to_value(&$key)?);
                )+
                let from: fn(
                    $($ty),+
                ) -> core::result::Result<Self, $crate::common::ValueError> = $from;
                let new = from($($key),+).map_err($crate::common::view::refused)?;
                $crate::common::view::carried(new, &members.into(), scope)
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
                $crate::common::view::Code::Name(_) => Ok(<$ie>::deactivated()),
                $crate::common::view::Code::Number(seconds) => <$ie>::from_seconds(seconds),
            },
            // The octet of a timer is its unit and its count, and all that
            // it means is the time that they give.
            meant: |ie| $crate::common::view::Shown::hex(&ie.value).len() == 2
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
                let encode: fn(
                    &[$entry],
                ) -> core::result::Result<$ie, $crate::common::ValueError> = $encode;
                let entries = ie.$decode();
                (encode(&entries).ok()?.value == ie.value).then_some(entries)
            },
            |_, entries| {
                let encode: fn(
                    &[$entry],
                ) -> core::result::Result<$ie, $crate::common::ValueError> = $encode;
                encode(&entries)
            }
        );
    };
}

/// [`Decoded`] for an IE type that carries a plain NAS message, which
/// `$decode` reads and `$encode` carries: its value is the tree of the
/// message.
macro_rules! container_ie {
    ($ie:ty: $message:ty, $decode:expr, $encode:expr) => {
        impl $crate::common::view::Decoded for $ie {
            fn unwritten() -> Self {
                <$ie>::blank()
            }

            fn decoded(
                &self,
                scope: $crate::common::view::Scope,
            ) -> Option<oxirush_utils::tree::Value> {
                let decode: fn(&Self) -> Option<$message> = $decode;
                let inside = scope.inside()?;
                Some($crate::common::view::tree(&decode(self)?, inside))
            }

            fn with_decoded(
                &self,
                value: &oxirush_utils::tree::Value,
                scope: $crate::common::view::Scope,
            ) -> core::result::Result<Self, String> {
                let decode: fn(&Self) -> Option<$message> = $decode;
                let encode: fn(&$message) -> $crate::common::Result<Self> = $encode;
                let inside = scope.inside().ok_or($crate::common::view::Scope::REFUSED)?;
                let message = match decode(self) {
                    Some(message) => $crate::common::view::edited(&message, value, inside)?,
                    // A container without octets carries what the tree names.
                    None if self.value.is_empty() => {
                        $crate::common::view::contained(value, inside)?
                    }
                    None => return Err("the octets are not a plain message: write them".into()),
                };
                encode(&message).map_err($crate::common::view::unencoded)
            }

            // The container of the message that stands for those that mean
            // what the one it carries means.
            fn meant(&self, scope: $crate::common::view::Scope) -> Self {
                let decode: fn(&Self) -> Option<$message> = $decode;
                let encode: fn(&$message) -> $crate::common::Result<Self> = $encode;
                let Some(inside) = scope.inside() else {
                    return self.clone();
                };
                (decode(self).map(|message| $crate::common::view::meant(&message, inside)))
                    .and_then(|message| encode(&message).ok())
                    .unwrap_or_else(|| self.clone())
            }

            fn octets_inside(
                &self,
                names: &[String],
                scope: $crate::common::view::Scope,
            ) -> Option<$crate::common::view::Found> {
                let decode: fn(&Self) -> Option<$message> = $decode;
                let inside = scope.inside()?;
                Some($crate::common::view::octets_at(
                    &decode(self)?,
                    names,
                    inside,
                ))
            }

            #[cfg(test)]
            fn reading(
                &self,
                scope: $crate::common::view::Scope,
            ) -> Option<oxirush_utils::tree::Value> {
                let decode: fn(&Self) -> Option<$message> = $decode;
                Some($crate::wireshark_tests::read(
                    &decode(self)?,
                    scope.inside()?,
                ))
            }
        }
    };
}

/// The values of the IEs that TS 24.501 and TS 24.301 have alike, for the types of
/// the protocol whose module calls it.
macro_rules! shared_ies {
    () => {
        code_ie!(
            RequestType,
            RequestTypeValue,
            |ie| ie.request_type(),
            RequestType::from_request_type
        );
        decoded_ie!(
            KeySetIdentifier: KeySetIdentifierValue,
            |ie| Some(ie.key_set_identifier()),
            |ie, identifier| {
                let mut ie = ie.clone();
                ie.set_key_set_identifier(identifier).map(|()| ie)
            }
        );
        fields_ie!(ReAttemptIndicator {} flags);
    };
}

pub(crate) use {
    built_ie, code_ie, configuration_options_ie, container_ie, decoded_ie, fields_ie, listed_ie,
    named_ie, shared_ies, timer_ie,
};

/// The values of the IE types that one NAS specification defines and the other
/// reuses, one type for both protocols.
mod shared_types {
    use super::*;
    use crate::common::ts24008::*;
    use crate::common::ts24301::*;
    use crate::common::ts24501::*;
    use crate::common::types::*;
    use crate::common::view;

    /// A network name and whether the country initials are to be added to it.
    #[derive(Clone, PartialEq)]
    struct NetworkNameForm {
        name: String,
        add_ci: bool,
    }

    #[cfg(feature = "tree")]
    crate::common::readable::readable!(struct NetworkNameForm { name, add_ci });

    configuration_options_ie!(ExtendedProtocolConfigurationOptions);
    named_ie!(
        DaylightSavingTime,
        DaylightSavingAdjustment,
        |ie| ie.adjustment(),
        DaylightSavingTime::from_adjustment
    );
    named_ie!(
        WusAssistanceInformation,
        UePagingProbability,
        |ie| ie.paging_probability(),
        WusAssistanceInformation::from_paging_probability
    );
    fields_ie!(TimeZoneAndTime {
        "year": |ie| ie.year(), |ie, year: u8| {
            ie.set_year(year);
        };
        "month": |ie| ie.month(), |ie, month: u8| {
            ie.set_month(month);
        };
        "day": |ie| ie.day(), |ie, day: u8| {
            ie.set_day(day);
        };
        "hour": |ie| ie.hour(), |ie, hour: u8| {
            ie.set_hour(hour);
        };
        "minute": |ie| ie.minute(), |ie, minute: u8| {
            ie.set_minute(minute);
        };
        "second": |ie| ie.second(), |ie, second: u8| {
            ie.set_second(second);
        };
        "time-zone-quarter-hours":
            |ie| ie.timezone_quarter_hours(),
            |ie, quarters: i8| ie.set_timezone_quarter_hours(quarters).map(|_| ());
    } exact);
    built_ie!(RegistrationWaitRange, Self::from_range, {
        min_seconds: u64 = |ie| ie.min_seconds(),
        max_seconds: u64 = |ie| ie.max_seconds(),
    });
    decoded_ie!(
        PlmnList: Vec<view::PlmnText>,
        |ie| ie.is_well_formed().then(|| view::plmn_texts(ie.plmns())),
        |_, plmns| PlmnList::from_plmns(&view::plmns(&plmns))
    );
    decoded_ie!(
        PlmnIdentity: view::PlmnText,
        |ie| ie.plmn().map(view::PlmnText),
        |_, plmn| Ok(PlmnIdentity::from_plmn(&plmn.0))
    );
    timer_ie!(GprsTimer);
    timer_ie!(GprsTimer2);
    timer_ie!(GprsTimer3);
    decoded_ie!(
        TimeZone: i8,
        |ie| ie.is_well_formed().then(|| ie.quarter_hours()),
        |_, quarter_hours| TimeZone::from_quarter_hours(quarter_hours)
    );
    decoded_ie!(
        SupportedCodecList: Vec<(u8, Vec<u8>)>,
        |ie| ie.codec_bitmaps(),
        |_, bitmaps| SupportedCodecList::from_codec_bitmaps(&bitmaps)
    );
    code_ie!(
        ImeisvRequest,
        ImeisvRequestValue,
        |ie| ie.request_strict(),
        ImeisvRequest::from_request
    );
    code_ie!(
        UeRadioCapabilityIdDeletionIndication,
        RadioCapabilityIdDeletionRequest,
        |ie| ie.deletion_request(),
        UeRadioCapabilityIdDeletionIndication::from_deletion_request
    );
    code_ie!(
        ReleaseAssistanceIndication,
        DownlinkDataExpected,
        |ie| ie.ddx(),
        ReleaseAssistanceIndication::from_ddx
    );
    named_ie!(
        UeRequestType,
        UeRequestTypeValue,
        |ie| ie.request_type(),
        UeRequestType::from_request_type
    );
    fields_ie!(ExtendedDrxParameters {
        "paging-time-window": |ie| ie.paging_time_window(), |ie, window: u8| {
            ie.set_paging_time_window(window).map(|_| ())
        };
        "edrx-value": |ie| ie.edrx_value(), |ie, value: u8| {
            ie.set_edrx_value(value).map(|_| ())
        };
    });
    built_ie!(UnavailabilityInformation, Self::from_fields, {
        due_to_discontinuous_coverage: bool = |ie| ie.due_to_discontinuous_coverage(),
        period_duration: Option<u32> = |ie| Some(ie.period_duration()),
        start_of_period: Option<u32> = |ie| Some(ie.start_of_period()),
    });
    built_ie!(UnavailabilityConfiguration, Self::from_fields, {
        end_of_period_report_needed: bool = |ie| ie.end_of_period_report_needed(),
        period_duration: Option<u32> = |ie| Some(ie.period_duration()),
        start_of_period: Option<u32> = |ie| Some(ie.start_of_period()),
    });
    decoded_ie!(
        ListOfPlmnsToBeUsedInDisasterCondition: Vec<crate::common::view::PlmnText>,
        |ie| ie.is_well_formed().then(|| crate::common::view::plmn_texts(ie.plmns())),
        |_, plmns| ListOfPlmnsToBeUsedInDisasterCondition::from_plmns(
            &crate::common::view::plmns(&plmns)
        )
    );
    decoded_ie!(
        UeRadioCapabilityId: String,
        |ie| ie.id_string(),
        |_, id| UeRadioCapabilityId::from_id_string(&id)
    );
    decoded_ie!(
        NetworkName: NetworkNameForm,
        |ie| Some(NetworkNameForm {
            name: ie.name()?,
            add_ci: ie.add_ci(),
        }),
        |_, name| Ok(NetworkName::from_name(&name.name, name.add_ci))
    );
    decoded_ie!(
        EmergencyNumberList: Vec<EmergencyNumber>,
        |ie| ie.numbers(),
        |_, numbers| EmergencyNumberList::from_numbers(&numbers)
    );
    decoded_ie!(
        ServingPlmnRateControl: u16,
        |ie| ie.rate(),
        |_, rate| ServingPlmnRateControl::from_rate(rate)
    );
    decoded_ie!(
        EpsBearerContextStatus: Vec<u16>,
        |ie| Some(numbers(&ie.active_bearers())),
        |_, bearers| EpsBearerContextStatus::from_bearers(&octets("eps-bearer-identity", &bearers, 1, 15)?)
    );
    fields_ie!(UeStatus {} flags);
    fields_ie!(Non3GppNwProvidedPolicies {} flags);
    fields_ie!(MobileStationClassmark2 {} flags);
    fields_ie!(AccessTechnologyUtilizationControl {} flags);
    decoded_ie!(
        ExtendedEmergencyNumberList: crate::common::view::ExtendedEmergencyNumbers,
        |ie| {
            Some(crate::common::view::ExtendedEmergencyNumbers {
                valid_only_in_plmn: ie.valid_only_in_plmn()?,
                numbers: ie.numbers()?,
            })
        },
        |_, list| {
            ExtendedEmergencyNumberList::from_numbers(list.valid_only_in_plmn, &list.numbers)
        }
    );
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::common::Direction;
    use crate::nas_5gs;
    use crate::nas_eps;

    /// The part of `value` that the JSON pointer `pointer` names.
    fn pointer_mut<'v>(value: &'v mut Value, pointer: &str) -> Option<&'v mut Value> {
        pointer
            .split('/')
            .skip(1)
            .try_fold(value, |value, part| match value {
                Value::Object(members) => members.get_mut(part),
                Value::Array(items) => items.get_mut(part.parse::<usize>().ok()?),
                _ => None,
            })
    }

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
        let Some(value) = ie.decoded(Scope::NONE) else {
            panic!("no value of {}", core::any::type_name::<T>());
        };
        exercise_value(ie, value)
    }

    /// [`exercise`] for any octets: they may have no value. One that they
    /// have encodes back, as a name or as the number that has none.
    pub(crate) fn sweep<T: Decoded>(ie: T) {
        if let Some(value) = ie.decoded(Scope::NONE) {
            exercise_value(ie, value)
        }
    }

    std::thread_local! {
        static PARTS: core::cell::Cell<bool> = const { core::cell::Cell::new(true) };
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
        let name = core::any::type_name::<T>();
        let value = blank
            .decoded(Scope::NONE)
            .unwrap_or_else(|| panic!("{name}"));
        let built = (blank.with_decoded(&value, Scope::NONE))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let form = readable::to_value(&built).unwrap();
        let octets = match &form["value"] {
            Value::String(octets) => !octets.is_empty(),
            value => value.is_number(),
        };
        assert!(octets, "{name}: {value} has no octets in {form}");
        assert_eq!(built.decoded(Scope::NONE), Some(value), "{name}");
    }

    /// The value that `ie` shows builds an IE that has it from one without
    /// octets: every member is written, a code without a name by its number.
    pub(crate) fn built_from_value<T: Decoded>(blank: T, ie: T) {
        let name = core::any::type_name::<T>();
        let Some(value) = ie.decoded(Scope::NONE) else {
            return;
        };
        let built = (blank.with_decoded(&value, Scope::NONE))
            .unwrap_or_else(|error| panic!("{name}: {value}: {error}"));
        assert_eq!(built.decoded(Scope::NONE).as_ref(), Some(&value), "{name}");
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

    fn exercise_value<T: Decoded>(ie: T, value: Value) {
        let name = core::any::type_name::<T>();
        let encoded = (ie.with_decoded(&value, Scope::NONE))
            .unwrap_or_else(|error| panic!("{name}: {value}: {error}"));
        assert_eq!(encoded.decoded(Scope::NONE).as_ref(), Some(&value));
        // A tree writes the IE from one that has nothing, and leaves out
        // what the value has not
        let tree = without_absent(value.clone());
        let written = (T::unwritten().with_decoded(&tree, Scope::NONE))
            .unwrap_or_else(|error| panic!("{name}, from nothing: {tree}: {error}"));
        assert_eq!(
            written.decoded(Scope::NONE).as_ref(),
            Some(&value),
            "{name}"
        );
        if !PARTS.get() {
            return;
        }
        let mut found = Vec::new();
        pointers(&value, String::new(), &mut found);
        // A sample of the parts of a value with many, such as a capability.
        let step = found.len().div_ceil(24);
        for pointer in found.into_iter().step_by(step) {
            for part in [
                oxirush_utils::tree!(255),
                oxirush_utils::tree!(65_536),
                oxirush_utils::tree!(1_u64 << 40),
                oxirush_utils::tree!(-1),
                oxirush_utils::tree!("x"),
                oxirush_utils::tree!("0x7fffffffffff"),
                oxirush_utils::tree!("999-999"),
                oxirush_utils::tree!([]),
                oxirush_utils::tree!([300, 300, 300]),
                oxirush_utils::tree!({}),
                oxirush_utils::tree!(true),
                Value::Null,
            ] {
                let mut edited = value.clone();
                *pointer_mut(&mut edited, &pointer).unwrap() = part;
                if let Ok(encoded) = ie.with_decoded(&edited, Scope::NONE) {
                    assert!(encoded.decoded(Scope::NONE).is_some(), "{edited}");
                }
            }
        }
    }

    /// Whatever takes the place of a part of the value `value` of `ie`, the
    /// encoder answers, and what it takes has a value: an author writes
    /// what no parser gives.
    fn written_wrong(ie: &dyn Ie, value: &Value, scope: Scope) {
        let mut found = Vec::new();
        pointers(value, String::new(), &mut found);
        // A sample of the parts of a value with many.
        let step = found.len().div_ceil(12);
        for pointer in found.into_iter().step_by(step) {
            for part in [
                oxirush_utils::tree!(255),
                oxirush_utils::tree!(1_u64 << 40),
                oxirush_utils::tree!(-1),
                oxirush_utils::tree!("x"),
                oxirush_utils::tree!("0x7fffffffffff"),
                oxirush_utils::tree!([]),
                oxirush_utils::tree!([300, 300, 300]),
                oxirush_utils::tree!({}),
                Value::Null,
            ] {
                let mut edited = value.clone();
                *pointer_mut(&mut edited, &pointer).unwrap() = part;
                if let Ok(read) = ie.encoded_value(&edited, scope) {
                    assert!(read.is_some(), "{edited}");
                }
            }
        }
    }

    /// The values of the IEs of `message`.
    fn values<M: Viewed>(message: &M) -> Vec<Option<Value>> {
        let mut values = Vec::new();
        message.ies(Scope::NONE, &mut |field| {
            values.push(field.ie.and_then(|ie| ie.value(field.scope)));
        });
        values
    }

    /// Encode every value of `message` back: how many IEs it has, how many
    /// have a value, and how many give other octets than they were decoded
    /// from. Each IE that is encoded has the value it was encoded from.
    fn encode_back<M: Viewed + PartialEq + core::fmt::Debug>(
        message: &M,
        name: &str,
    ) -> [usize; 3] {
        let whole = tree(message, Scope::NONE);
        assert_eq!(
            &edited(message, &whole, Scope::NONE).unwrap(),
            message,
            "{name}"
        );
        let mut counts = [0; 3];
        let mut encoded = Vec::new();
        message.ies(Scope::NONE, &mut |visited| {
            let (field, ie, scope) = (visited.name, visited.ie, visited.scope);
            counts[0] += 1;
            let Some((ie, value)) = ie.and_then(|ie| Some((ie, ie.value(scope)?))) else {
                return;
            };
            counts[1] += 1;
            written_wrong(ie, &value, scope);
            let ie = (ie.encoded_ie(&value, scope))
                .unwrap_or_else(|error| panic!("{name} {field}: {error}"));
            encoded.push((visited.printed, ie));
        });
        for (field, ie) in encoded {
            let mut written = message.clone();
            assert!(written.slot(field).unwrap().put(ie), "{name} {field}");
            counts[2] += usize::from(written != *message);
            assert_eq!(values(&written), values(message), "{name} {field}");
        }
        counts
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
            let message = nas_5gs::Message::decode(&wire).unwrap();
            let message = encode_back(&message, name);
            (0..3).for_each(|index| counts[index] += message[index]);
        }
        assert_eq!(
            counts,
            [279, 241, 22],
            "5GS: IEs, with a value, other octets"
        );
        let mut counts = [0; 3];
        for (name, wire) in fixtures(include_str!("../../tests/fixtures/nas-eps.tsv")) {
            let direction = if name.starts_with("DetachRequestUeTerminated") {
                Direction::Downlink
            } else {
                Direction::Uplink
            };
            let message = nas_eps::Message::decode_with(
                &wire,
                crate::DecodeOptions::STRICT.with_direction(direction),
            )
            .unwrap();
            let message = encode_back(&message, name);
            (0..3).for_each(|index| counts[index] += message[index]);
        }
        assert_eq!(
            counts,
            [198, 185, 3],
            "EPS: IEs, with a value, other octets"
        );
    }

    #[test]
    fn a_tree_alone_has_the_header_and_every_mandatory_ie() {
        use crate::nas_5gs::Message;
        use oxirush_utils::tree;
        let from = |tree: Value| Message::from_tree(tree);
        let error = from(tree!({"message-type": "5gmm-status"})).unwrap_err();
        assert!(
            error.to_string().contains("`5gmm-cause` is not written"),
            "{error}"
        );
        let tree = tree!({"message-type": "5gmm-status", "5gmm-cause": {"octets": "16"}});
        assert_eq!(
            from(tree.clone()).unwrap().encode().unwrap(),
            [0x7e, 0, 0x64, 0x16]
        );
        let mut more = tree;
        more["t3512-value"] = tree!(60);
        let error = from(more).unwrap_err().to_string();
        assert!(
            error.contains("no IE `t3512-value`, expected one of 5gmm-cause"),
            "{error}"
        );
    }

    #[test]
    fn an_ie_of_flags_that_a_tree_adds_has_the_octet_of_each_flag_written() {
        use oxirush_utils::tree;
        let request = crate::nas_5gs::Message::from_tree(tree!({
            "message-type": "registration-request",
            "5gs-registration-type": {"octets": "09"},
            "ngksi": {"octets": "07"},
            "5gs-mobile-identity": {"octets": "0199f907000000000000001002"},
            "5gmm-capability": {"s1-mode": false, "lpp": false},
            "ue-status": {"s1-mode-reg": false, "n1-mode-reg": false},
        }))
        .unwrap();
        assert_eq!(
            hex::encode(request.encode().unwrap()),
            "7e004179000d0199f9070000000000000010021001002b0100"
        );
    }

    #[test]
    fn a_container_of_a_tree_alone_carries_the_message_that_its_tree_names() {
        use crate::nas_5gs::GmmMessage;
        use oxirush_utils::tree;
        let transport = crate::nas_5gs::Message::from_tree(tree!({
            "message-type": "ul-nas-transport",
            "payload-container-type": "n1-sm-information",
            "payload-container": {
                "pdu-session-identity": 5,
                "procedure-transaction-identity": 1,
                "message-type": "pdu-session-release-request",
                "5gsm-cause": "regular-deactivation",
            },
            "pdu-session-id": 5,
        }))
        .unwrap();
        let wire = transport.encode().unwrap();
        assert_eq!(
            oxirush_utils::tree::hex(&wire),
            "7e00670100062e0501d15924120 5".replace(' ', "")
        );
        let nas_5gs::Message::Gmm(_, GmmMessage::UlNasTransport(transport)) = transport else {
            panic!("{transport:?}");
        };
        let inner = transport
            .payload_container
            .decode_as_n1_sm_message()
            .unwrap();
        assert_eq!(
            inner.to_tree()["5gsm-cause"],
            oxirush_utils::tree!("regular-deactivation")
        );
    }
}
