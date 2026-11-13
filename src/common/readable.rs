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

//! The readable form of the typed values, for the view of a message.
//!
//! It is the form that [`Readable`] gives a value, with the names and the
//! notations a reader expects: a name is in lower case with hyphens, a PLMN identity is
//! `"208-93"`, an IP address is its text, a tracking area code is a number
//! and other octets are hexadecimal. Reading takes a name by its letters and
//! its digits, whatever their case and whatever is between them, a number
//! also as a `"0x…"` string, and
//! octets also as a list of numbers. A member or a name that a value does
//! not have is an error.

use crate::prelude::*;
use core::net::{Ipv4Addr, Ipv6Addr};
use oxirush_utils::tree::{Map, Value};

pub(crate) use crate::common::names::printed;

/// The letters and the digits of a name, in lower case: those of any way to
/// write it.
pub(crate) fn letters(name: &str) -> String {
    (name.chars())
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// The octets of [`letters`], written into `letters` in the place of what
/// it had. A character that is not ASCII is no letter or digit, and none of
/// its octets is one either.
pub(crate) fn letters_into(name: &str, letters: &mut Vec<u8>) {
    letters.clear();
    letters.extend(
        (name.bytes())
            .filter(u8::is_ascii_alphanumeric)
            .map(|octet| octet.to_ascii_lowercase()),
    );
}

/// Whether two names are the same: they are written alike, but for their
/// case and their separators, or they have the same letters and digits.
pub(crate) fn same_name(one: &str, other: &str) -> bool {
    oxirush_utils::tree::named(&[one], other).is_some()
}

/// The one of `names` that `name` is: the one written like it, if any.
pub(crate) fn named<'a, T: AsRef<str>>(names: &'a [T], name: &str) -> Option<&'a T> {
    oxirush_utils::tree::named(names, name).map(|at| &names[at])
}

/// The one of `names` that `name` is, or an error that lists them.
pub(crate) fn known(
    name: &str,
    names: &'static [&'static str],
    what: &str,
) -> Result<usize, String> {
    oxirush_utils::tree::named(names, name).ok_or_else(|| none_of(name, names, what))
}

/// The error for `name`, which is none of `names`: it lists them, or of
/// many it gives the nearest, as oxirush-utils says of the names of a type
/// ([`oxirush_utils::tree::nearest`]), or those that start as it does: the
/// name of a timer IE ends in `-value`.
pub(crate) fn none_of(name: &str, names: &[&str], what: &str) -> String {
    if names.is_empty() {
        return format!("no {what} `{name}`: there is none");
    }
    let count = names.len();
    if count <= LISTED {
        return format!("no {what} `{name}`, expected one of {}", names.join(", "));
    }
    let mut near = oxirush_utils::tree::nearest(names, name, 3);
    if near.is_empty() {
        let written = letters(name);
        near = (names.iter())
            .filter(|known| !written.is_empty() && letters(known).starts_with(&written))
            .copied()
            .take(3)
            .collect();
    }
    match near[..] {
        [] => format!(
            "no {what} `{name}`, expected one of {}, and {} more",
            names[..8].join(", "),
            count - 8
        ),
        [one] => format!("no {what} `{name}`; the nearest of its {count} is {one}"),
        [ref near @ .., last] => format!(
            "no {what} `{name}`; the nearest of its {count} are {} and {last}",
            near.join(", ")
        ),
    }
}

/// How many names an error lists whole, as oxirush-utils lists them: of
/// more, it gives the nearest.
const LISTED: usize = 12;

/// A value as a view shows it, and as one that a view writes is read: the
/// readable form. A struct is an object of its members by their names as
/// they print, an enum the name of its variant or an object of that name
/// with what the variant holds, an option `null` or its value, and a list
/// of octets their hexadecimal, or the notation of what they are.
///
/// [`readable!`](crate::common::readable) writes it for a struct or an enum
/// of the crate from the names of its members or variants.
pub(crate) trait Readable: Sized {
    /// The readable form of the value, which the member or the variant
    /// `held` holds: that name says how octets are shown.
    fn shown(&self, held: &'static str) -> Value;

    /// The octet that the value is: a sequence of them is shown as octets.
    fn octet(&self) -> Option<u8> {
        None
    }

    /// The value that `value` writes.
    fn read(value: &Value) -> Result<Self, String>;

    /// The value of a member that is not written, where it may be left out.
    fn missing() -> Option<Self> {
        None
    }

    /// The value with nothing in it: a number is zero, octets and lists are
    /// empty and what is optional is absent. An enum has the variant that
    /// one of `variants` names, however it is written, or else its first.
    fn blank(variants: &[&str], depth: usize) -> Option<Self>;

    /// The names of the members of the struct, or of the struct that the
    /// variant `variant` of the enum holds.
    fn fields(_variant: &str) -> Option<&'static [&'static str]> {
        None
    }
}

/// The readable form of a typed value.
pub(crate) fn to_value<T: Readable>(value: &T) -> Result<Value, String> {
    Ok(value.shown(""))
}

/// The typed value of a readable form.
pub(crate) fn from_value<T: Readable>(value: &Value) -> Result<T, String> {
    T::read(value)
}

/// The fields of the struct `T`, or of the struct in the variant `variant`
/// of the enum `T`.
pub(crate) fn fields<T: Readable>(variant: &str) -> Option<&'static [&'static str]> {
    T::fields(variant)
}

/// A value of `T` with nothing in it: a number is zero, octets and lists are
/// empty and what is optional is absent. An enum has the variant that one of
/// `variants` names, however it is written, or else its first.
pub(crate) fn blank<T: Readable>(variants: &[&str]) -> Option<T> {
    T::blank(variants, 0)
}

/// How deep a blank value is made: a value nested deeper has none.
const BLANK_DEPTH: usize = 64;

/// Whether a blank value can still be made `depth` levels in.
pub(crate) fn blank_at(depth: usize) -> Option<usize> {
    (depth < BLANK_DEPTH).then_some(depth + 1)
}

/// What `value` is, as an error says it is not what is expected.
pub(crate) fn unexpected(value: &Value) -> String {
    match value {
        Value::Null => "unit value".into(),
        Value::Bool(value) => format!("boolean `{value}`"),
        Value::Number(number) => match (number.as_u64(), number.as_i64(), number.as_f64()) {
            (Some(number), _, _) => format!("integer `{number}`"),
            (_, Some(number), _) => format!("integer `{number}`"),
            (_, _, Some(number)) => format!("floating point `{number}`"),
            _ => format!("number `{number}`"),
        },
        Value::String(text) => format!("string {text:?}"),
        Value::Array(_) => "sequence".into(),
        Value::Object(_) => "map".into(),
    }
}

/// The error of a value that is not of the kind `expected`.
pub(crate) fn invalid_type(value: &Value, expected: &str) -> String {
    format!("invalid type: {}, expected {expected}", unexpected(value))
}

/// Octets as the member or the variant `name` shows them.
pub(crate) fn octets_of(name: &'static str, octets: &[u8]) -> Value {
    let is = |names: &[&str]| {
        let letters =
            || (name.bytes().filter(u8::is_ascii_alphanumeric)).map(|c| c.to_ascii_lowercase());
        names.iter().any(|known| letters().eq(known.bytes()))
    };
    let length = octets.len();
    if is(&["mcc", "mnc"]) {
        // The digits of a PLMN identity, without the filler.
        (octets.iter().filter(|digit| **digit <= 9))
            .map(|digit| char::from(b'0' + digit))
            .collect::<String>()
            .into()
    } else if is(&["tac", "tacs", "firsttac"]) && (1..=8).contains(&length) {
        (octets.iter())
            .fold(0_u64, |number, octet| number << 8 | u64::from(*octet))
            .into()
    } else if length == 4
        && is(&[
            "address",
            "addr",
            "mask",
            "ipv4",
            "ipv4address",
            "source",
            "destination",
        ])
    {
        (Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap_or_default()))
            .to_string()
            .into()
    } else if length == 16
        && is(&[
            "address",
            "mask",
            "ipv6",
            "source",
            "destination",
            "smfipv6linklocaladdress",
        ])
    {
        (Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap_or_default()))
            .to_string()
            .into()
    } else if is(&[
        "qfis",
        "payloadtypes",
        "nssrgvalues",
        "connectioncapabilityidentifiers",
    ]) {
        // Identifiers that are a list of numbers and not a string of octets.
        octets.to_vec().into()
    } else {
        oxirush_utils::tree::hex(octets).into()
    }
}

/// A sequence of values that the member or the variant `held` holds: a
/// list, or the octets it is made of.
pub(crate) fn sequence<'a, T: Readable + 'a>(
    held: &'static str,
    items: impl IntoIterator<Item = &'a T>,
) -> Value {
    let mut shown = Vec::new();
    let mut octets = Some(Vec::new());
    for item in items {
        match (&mut octets, item.octet()) {
            (Some(octets), Some(octet)) => octets.push(octet),
            _ => octets = None,
        }
        shown.push(item.shown(held));
    }
    match octets {
        Some(octets) if !octets.is_empty() => octets_of(held, &octets),
        _ => shown.into(),
    }
}

/// Read each of the values of a sequence of `length` of them that `value`
/// writes, in their order: a list of as many, or as many octets in
/// hexadecimal, a number or an IP address. A text or a list that is longer
/// is not read up to the length.
pub(crate) fn each_item(
    value: &Value,
    length: usize,
    mut read: impl FnMut(&Value) -> Result<(), String>,
) -> Result<(), String> {
    match value {
        Value::Array(items) if items.len() == length => items.iter().try_for_each(read),
        Value::Array(_) => Err(format!("{value} is not a list of {length}")),
        value => match octets_from(value, Some(length)) {
            Some(octets) if octets.len() == length => {
                (octets.into_iter()).try_for_each(|octet| read(&Value::from(octet)))
            }
            _ if length == 1 => Err(format!("{value} is not one octet")),
            _ => Err(format!("{value} is not {length} octets")),
        },
    }
}

/// The two values of a pair that `value` writes, as [`each_item`] reads them.
pub(crate) fn pair_items<A: Readable, B: Readable>(value: &Value) -> Result<(A, B), String> {
    let (mut first, mut second) = (None, None);
    let mut at = 0;
    each_item(value, 2, |item| {
        match at {
            0 => first = Some(A::read(item)?),
            _ => second = Some(B::read(item)?),
        }
        at += 1;
        Ok(())
    })?;
    Ok((first.expect("two items"), second.expect("two items")))
}

/// The variant `variant` with what it holds, `contents`.
pub(crate) fn tagged(variant: &'static str, contents: Value) -> Value {
    Map::from_iter([(variant.to_owned(), contents)]).into()
}

/// The members of a struct, by the names that they print as.
pub(crate) struct Members {
    members: Map,
}

impl Members {
    pub(crate) fn new() -> Self {
        Self {
            members: Map::new(),
        }
    }

    /// The member `name` of the struct, with its value.
    pub(crate) fn put<T: Readable>(&mut self, name: &'static str, value: &T) {
        self.members.insert(name.to_owned(), value.shown(name));
    }

    /// The member `name` of the struct, with the value `shown` in its form.
    pub(crate) fn put_shown(&mut self, name: &'static str, shown: Value) {
        self.members.insert(name.to_owned(), shown);
    }

    pub(crate) fn finish(self) -> Value {
        self.members.into()
    }
}

/// The values of the members `fields` of a struct that `value` writes, by
/// their places among the fields: an object of them by name, however each
/// is written, or a list of them in their order. `name` is the name of the
/// struct, as an error says what was expected.
pub(crate) fn members<'v>(
    value: &'v Value,
    name: &str,
    fields: &'static [&'static str],
) -> Result<Vec<Option<&'v Value>>, String> {
    let mut read = vec![None; fields.len()];
    members_into(value, name, fields, &mut read)?;
    Ok(read)
}

/// [`members`] into `read`, a place for each of `fields`.
pub(crate) fn members_into<'v>(
    value: &'v Value,
    name: &str,
    fields: &'static [&'static str],
    read: &mut [Option<&'v Value>],
) -> Result<(), String> {
    match value {
        Value::Object(members) => {
            for (member, value) in members {
                let at = known(member, fields, "member")?;
                if read[at].is_some() {
                    return Err(format!("duplicate field `{}`", fields[at]));
                }
                read[at] = Some(value);
            }
        }
        Value::Array(items) => {
            if items.len() < fields.len() {
                let plural = if fields.len() == 1 { "" } else { "s" };
                return Err(format!(
                    "invalid length {}, expected struct {name} with {} element{plural}",
                    items.len(),
                    fields.len()
                ));
            }
            if items.len() > fields.len() {
                return Err(format!(
                    "invalid length {}, expected fewer elements in array",
                    items.len()
                ));
            }
            for (at, item) in items.iter().enumerate() {
                read[at] = Some(item);
            }
        }
        value => return Err(invalid_type(value, &format!("struct {name}"))),
    }
    Ok(())
}

/// The member `field` of a struct, which `value` writes or leaves out.
pub(crate) fn member<T: Readable>(value: Option<&Value>, field: &str) -> Result<T, String> {
    match value {
        Some(value) => T::read(value),
        None => T::missing().ok_or_else(|| format!("`{field}` is not written")),
    }
}

/// The variant of an enum of the variants `variants` that `value` writes,
/// by its place among them, and what it holds if it is written with it.
pub(crate) fn variant<'v>(
    value: &'v Value,
    variants: &'static [&'static str],
) -> Result<(usize, Option<&'v Value>), String> {
    let (name, contents) = match value {
        Value::String(name) => (name, None),
        Value::Object(members) if members.len() == 1 => {
            let (name, contents) = members.iter().next().expect("one member");
            (name, Some(contents))
        }
        value => {
            return Err(format!(
                "{value} is not a name, or a name with its contents"
            ));
        }
    };
    Ok((known(name, variants, "name")?, contents))
}

/// A variant `name` without contents, which `contents` gives or not.
pub(crate) fn unit_variant(name: &str, contents: Option<&Value>) -> Result<(), String> {
    match contents {
        None | Some(Value::Null) => Ok(()),
        Some(contents) => Err(format!("`{name}` has no contents, and {contents} is given")),
    }
}

/// The place among `variants`, which print as `names`, of the first that
/// one of `wanted` names, or that of the first variant.
pub(crate) fn blank_variant(
    variants: &'static [&'static str],
    names: &'static [&'static str],
    wanted: &[&str],
) -> Option<usize> {
    let named = (wanted
        .iter()
        .filter_map(|wanted| index_of(variants, names, wanted)))
    .min();
    named.or((!variants.is_empty()).then_some(0))
}

/// The number that a `"0x…"` string writes.
fn hexadecimal(text: &str) -> Option<u64> {
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))?;
    u64::from_str_radix(digits, 16).ok()
}

/// The octets that a text or a number writes, `length` of them where the
/// value has a fixed length: hexadecimal, an IP address, or a number.
fn octets_from(value: &Value, length: Option<usize>) -> Option<Vec<u8>> {
    let number = |number: u64| {
        let length = length?;
        let octets = number.to_be_bytes();
        let (zeros, octets) = octets.split_at(octets.len().checked_sub(length)?);
        zeros.iter().all(|zero| *zero == 0).then(|| octets.to_vec())
    };
    match value {
        Value::Number(_) => number(value.as_u64()?),
        Value::String(text) => match (length, hexadecimal(text)) {
            (Some(_), Some(written)) => number(written),
            (Some(4), _) if text.contains('.') => {
                Some(text.parse::<Ipv4Addr>().ok()?.octets().to_vec())
            }
            (Some(16), _) if text.contains(':') => {
                Some(text.parse::<Ipv6Addr>().ok()?.octets().to_vec())
            }
            _ => oxirush_utils::tree::unhex(text.strip_prefix("0x").unwrap_or(text)),
        },
        _ => None,
    }
}

/// The whole number that `value` writes, also as a `"0x…"` string, of a
/// type whose values are `range`, which holds it if `unsigned` or `signed`
/// gives it.
fn whole<T>(
    value: &Value,
    range: &str,
    unsigned: impl Fn(u64) -> Option<T>,
    signed: impl Fn(i64) -> Option<T>,
) -> Result<T, String> {
    let outside =
        |number: &dyn core::fmt::Display| format!("{number} is not a number from {range}");
    if let Some(number) = value.as_str().and_then(hexadecimal) {
        return unsigned(number).ok_or_else(|| outside(&number));
    }
    let expected = || format!("a number from {range}");
    match value {
        Value::Number(number) => match (number.as_u64(), number.as_i64()) {
            (Some(number), _) => unsigned(number).ok_or_else(|| outside(&number)),
            (_, Some(number)) => signed(number).ok_or_else(|| outside(&number)),
            _ => Err(invalid_type(value, &expected())),
        },
        value => Err(invalid_type(value, &expected())),
    }
}

macro_rules! readable_number {
    ($($ty:ident),+) => {$(
        impl Readable for $ty {
            fn shown(&self, _: &'static str) -> Value {
                (*self).into()
            }

            fn read(value: &Value) -> Result<Self, String> {
                whole(
                    value,
                    &format!("{} to {}", $ty::MIN, $ty::MAX),
                    |number| $ty::try_from(number).ok(),
                    |number| $ty::try_from(number).ok(),
                )
            }

            fn blank(_: &[&str], _: usize) -> Option<Self> {
                Some(0)
            }
        }
    )+};
}

readable_number!(u16, u32, u64, i8, i16, i32, i64);

impl Readable for u8 {
    fn shown(&self, _: &'static str) -> Value {
        (*self).into()
    }

    fn octet(&self) -> Option<u8> {
        Some(*self)
    }

    fn read(value: &Value) -> Result<Self, String> {
        whole(
            value,
            "0 to 255",
            |number| u8::try_from(number).ok(),
            |number| u8::try_from(number).ok(),
        )
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        Some(0)
    }
}

impl Readable for usize {
    fn shown(&self, _: &'static str) -> Value {
        (*self as u64).into()
    }

    fn read(value: &Value) -> Result<Self, String> {
        whole(
            value,
            &format!("0 to {}", usize::MAX),
            |number| usize::try_from(number).ok(),
            |number| usize::try_from(number).ok(),
        )
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        Some(0)
    }
}

impl Readable for bool {
    fn shown(&self, _: &'static str) -> Value {
        (*self).into()
    }

    fn read(value: &Value) -> Result<Self, String> {
        value
            .as_bool()
            .ok_or_else(|| invalid_type(value, "a boolean"))
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        Some(false)
    }
}

impl Readable for String {
    fn shown(&self, _: &'static str) -> Value {
        self.as_str().into()
    }

    fn read(value: &Value) -> Result<Self, String> {
        (value.as_str().map(str::to_owned)).ok_or_else(|| invalid_type(value, "a string"))
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        Some(String::new())
    }
}

impl Readable for Ipv4Addr {
    fn shown(&self, _: &'static str) -> Value {
        self.to_string().into()
    }

    fn read(value: &Value) -> Result<Self, String> {
        let text = (value.as_str()).ok_or_else(|| invalid_type(value, "IPv4 address"))?;
        text.parse()
            .map_err(|_| "invalid IPv4 address syntax".into())
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        None
    }
}

impl Readable for Ipv6Addr {
    fn shown(&self, _: &'static str) -> Value {
        self.to_string().into()
    }

    fn read(value: &Value) -> Result<Self, String> {
        let text = (value.as_str()).ok_or_else(|| invalid_type(value, "IPv6 address"))?;
        text.parse()
            .map_err(|_| "invalid IPv6 address syntax".into())
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        None
    }
}

impl Readable for core::net::IpAddr {
    fn shown(&self, _: &'static str) -> Value {
        self.to_string().into()
    }

    fn read(value: &Value) -> Result<Self, String> {
        let text = (value.as_str()).ok_or_else(|| invalid_type(value, "IP address"))?;
        text.parse().map_err(|_| "invalid IP address syntax".into())
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        None
    }
}

impl<T: Readable> Readable for Option<T> {
    fn shown(&self, held: &'static str) -> Value {
        match self {
            Some(value) => value.shown(held),
            None => Value::Null,
        }
    }

    fn read(value: &Value) -> Result<Self, String> {
        match value {
            Value::Null => Ok(None),
            value => T::read(value).map(Some),
        }
    }

    fn missing() -> Option<Self> {
        Some(None)
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        Some(None)
    }
}

impl<T: Readable> Readable for Box<T> {
    fn shown(&self, held: &'static str) -> Value {
        (**self).shown(held)
    }

    fn octet(&self) -> Option<u8> {
        (**self).octet()
    }

    fn read(value: &Value) -> Result<Self, String> {
        T::read(value).map(Box::new)
    }

    fn missing() -> Option<Self> {
        T::missing().map(Box::new)
    }

    fn blank(variants: &[&str], depth: usize) -> Option<Self> {
        T::blank(variants, depth).map(Box::new)
    }

    fn fields(variant: &str) -> Option<&'static [&'static str]> {
        T::fields(variant)
    }
}

impl<T: Readable> Readable for Vec<T> {
    fn shown(&self, held: &'static str) -> Value {
        sequence(held, self)
    }

    fn read(value: &Value) -> Result<Self, String> {
        match (value, octets_from(value, None)) {
            (Value::String(_), Some(octets)) => (octets.into_iter())
                .map(|octet| T::read(&octet.into()))
                .collect(),
            (Value::Array(items), _) => items.iter().map(T::read).collect(),
            (value, _) => Err(invalid_type(value, "a sequence")),
        }
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        Some(Vec::new())
    }
}

impl<T: Readable, const N: usize> Readable for [T; N] {
    fn shown(&self, held: &'static str) -> Value {
        sequence(held, self)
    }

    fn read(value: &Value) -> Result<Self, String> {
        let mut read: [Option<T>; N] = core::array::from_fn(|_| None);
        let mut at = 0;
        each_item(value, N, |item| {
            read[at] = Some(T::read(item)?);
            at += 1;
            Ok(())
        })?;
        Ok(read.map(|item| item.expect("each item is read")))
    }

    fn blank(variants: &[&str], depth: usize) -> Option<Self> {
        let depth = blank_at(depth)?;
        let blank: Option<Vec<T>> = (0..N).map(|_| T::blank(variants, depth)).collect();
        blank?.try_into().ok()
    }
}

impl<A: Readable, B: Readable> Readable for (A, B) {
    fn shown(&self, held: &'static str) -> Value {
        // A pair of octets is the two octets.
        match (self.0.octet(), self.1.octet()) {
            (Some(first), Some(second)) => octets_of(held, &[first, second]),
            _ => Value::Array(vec![self.0.shown(held), self.1.shown(held)]),
        }
    }

    fn read(value: &Value) -> Result<Self, String> {
        pair_items(value)
    }

    fn blank(variants: &[&str], depth: usize) -> Option<Self> {
        let depth = blank_at(depth)?;
        Some((A::blank(variants, depth)?, B::blank(variants, depth)?))
    }
}

impl Readable for crate::common::Octets {
    fn shown(&self, held: &'static str) -> Value {
        sequence(held, self.as_slice())
    }

    fn read(value: &Value) -> Result<Self, String> {
        Vec::<u8>::read(value).map(Self::from)
    }

    fn blank(_: &[&str], _: usize) -> Option<Self> {
        Some(Self::default())
    }
}

/// [`Readable`] for a struct or an enum of the crate, from the names of its
/// members or of its variants and what each holds:
///
/// - `struct Name { member, member as form, member = default, member = skip }`:
///   a member `as` a module `form` of [`forms`](crate::common::forms) is shown
///   and read by it, one `= default` may be left out, and one `= skip` is
///   neither shown nor read.
/// - `struct Name(Type)` for a struct that holds one value, shown as it.
/// - `enum Name { Unit, Newtype(Type), Pair(Type, Type), Struct { member, .. } }`.
macro_rules! readable {
    // A struct of named members.
    (struct $name:ident { $($member:ident $(as $form:ident)? $(= $how:ident)?),* $(,)? }) => {
        impl $crate::common::readable::Readable for $name {
            #[allow(unused_variables)]
            fn shown(&self, held: &'static str) -> oxirush_utils::tree::Value {
                let mut members = $crate::common::readable::Members::new();
                $($crate::common::readable::readable!(@put members, self.$member, $member $(as $form)? $(= $how)?);)*
                members.finish()
            }

            #[allow(unused_variables)]

            fn read(value: &oxirush_utils::tree::Value) -> core::result::Result<Self, alloc::string::String> {
                const FIELDS: &[&str] = &[$($crate::common::names::name!(stringify!($member))),*];
                #[allow(unused_variables, unused_mut)]
                let mut slots = [None; FIELDS.len()];
                $crate::common::readable::members_into(value, stringify!($name), FIELDS, &mut slots)?;
                let mut read = slots.into_iter();
                Ok(Self {
                    $($member: $crate::common::readable::readable!(@read read, $member $(as $form)? $(= $how)?),)*
                })
            }

            #[allow(unused_variables)]

            fn blank(variants: &[&str], depth: usize) -> Option<Self> {
                #[allow(unused_variables)]
                let depth = $crate::common::readable::blank_at(depth)?;
                Some(Self {
                    $($member: $crate::common::readable::readable!(@blank variants, depth $(as $form)? $(= $how)?),)*
                })
            }

            #[allow(unused_variables)]

            fn fields(_: &str) -> Option<&'static [&'static str]> {
                { const FIELDS: &[&str] = &[$($crate::common::names::name!(stringify!($member))),*]; Some(FIELDS) }
            }
        }
    };
    // A struct of one value, which it is shown as.
    (struct $name:ident ($ty:ty $(as $form:ident)? $(,)?)) => {
        impl $crate::common::readable::Readable for $name {
            #[allow(unused_variables)]
            fn shown(&self, held: &'static str) -> oxirush_utils::tree::Value {
                $crate::common::readable::readable!(@show held, [$($form)?] self.0)
            }

            #[allow(unused_variables)]

            fn octet(&self) -> Option<u8> {
                $crate::common::readable::readable!(@octet [$($form)?] self.0)
            }

            #[allow(unused_variables)]

            fn read(value: &oxirush_utils::tree::Value) -> core::result::Result<Self, alloc::string::String> {
                Ok(Self($crate::common::readable::readable!(@value value, $ty $(as $form)?)))
            }

            #[allow(unused_variables)]

            fn blank(variants: &[&str], depth: usize) -> Option<Self> {
                Some(Self($crate::common::readable::readable!(@blank variants, depth $(as $form)?)))
            }

            #[allow(unused_variables)]

            fn fields(variant: &str) -> Option<&'static [&'static str]> {
                $crate::common::readable::readable!(@fields variant, $ty $(as $form)?)
            }
        }
    };
    // An enum.
    (enum $name:ident { $($variants:tt)* }) => {
        $crate::common::readable::readable!(@enum $name (contents, variants, depth, variant, held)
            [] [] [] [] [] $($variants)*);
    };

    // The $variants of an enum, one at a time: what shows each, what reads
    // it by its place, what makes a blank of it, the names of the $variants,
    // and the fields of the struct that a variant holds.
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident, $held:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident = $rename:literal { $($member:ident $(as $form:ident)?),* $(,)? } $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name, $held)
            [$($show)* Self::$variant { $($member),* } => {
                let mut members = $crate::common::readable::Members::new();
                $($crate::common::readable::readable!(@put members, *$member, $member $(as $form)?);)*
                $crate::common::readable::tagged($crate::common::names::name!($rename), members.finish())
            }]
            [$($read)* $rename => {
                const FIELDS: &[&str] = &[$($crate::common::names::name!(stringify!($member))),*];
                let $contents = $contents.unwrap_or(&oxirush_utils::tree::Value::Null);
                #[allow(unused_variables, unused_mut)]
                let mut slots = [None; FIELDS.len()];
                $crate::common::readable::members_into($contents, "", FIELDS, &mut slots)?;
                let mut read = slots.into_iter();
                Ok(Self::$variant {
                    $($member: $crate::common::readable::readable!(@read read, $member $(as $form)?),)*
                })
            }]
            [$($blank)* $rename => {
                #[allow(unused_variables)]
                let $depth = $crate::common::readable::blank_at($depth)?;
                Some(Self::$variant {
                    $($member: $crate::common::readable::readable!(@blank $variants, $depth $(as $form)?),)*
                })
            }]
            [$($names)* ($rename)]
            [$($fields)* $rename => { const FIELDS: &[&str] = &[$($crate::common::names::name!(stringify!($member))),*]; Some(FIELDS) },]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident, $held:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident { $($member:ident $(as $form:ident)?),* $(,)? } $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name, $held)
            [$($show)* Self::$variant { $($member),* } => {
                let mut members = $crate::common::readable::Members::new();
                $($crate::common::readable::readable!(@put members, *$member, $member $(as $form)?);)*
                $crate::common::readable::tagged($crate::common::names::name!(stringify!($variant)), members.finish())
            }]
            [$($read)* stringify!($variant) => {
                const FIELDS: &[&str] = &[$($crate::common::names::name!(stringify!($member))),*];
                let $contents = $contents.unwrap_or(&oxirush_utils::tree::Value::Null);
                #[allow(unused_variables, unused_mut)]
                let mut slots = [None; FIELDS.len()];
                $crate::common::readable::members_into($contents, "", FIELDS, &mut slots)?;
                let mut read = slots.into_iter();
                Ok(Self::$variant {
                    $($member: $crate::common::readable::readable!(@read read, $member $(as $form)?),)*
                })
            }]
            [$($blank)* stringify!($variant) => {
                #[allow(unused_variables)]
                let $depth = $crate::common::readable::blank_at($depth)?;
                Some(Self::$variant {
                    $($member: $crate::common::readable::readable!(@blank $variants, $depth $(as $form)?),)*
                })
            }]
            [$($names)* (stringify!($variant))]
            [$($fields)* stringify!($variant) => { const FIELDS: &[&str] = &[$($crate::common::names::name!(stringify!($member))),*]; Some(FIELDS) },]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident, $held:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident ($ty:ty $(as $form:ident)? $(,)?) $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name, $held)
            [$($show)* Self::$variant(value) => $crate::common::readable::tagged(
                $crate::common::names::name!(stringify!($variant)),
                $crate::common::readable::readable!(
                    @show $crate::common::names::name!(stringify!($variant)),
                    [$($form)?] *value
                ),
            ),]
            [$($read)* stringify!($variant) => {
                let $contents = $contents.unwrap_or(&oxirush_utils::tree::Value::Null);
                Ok(Self::$variant($crate::common::readable::readable!(@value $contents, $ty $(as $form)?)))
            }]
            [$($blank)* stringify!($variant) => {
                let $depth = $crate::common::readable::blank_at($depth)?;
                Some(Self::$variant($crate::common::readable::readable!(@blank $variants, $depth $(as $form)?)))
            }]
            [$($names)* (stringify!($variant))]
            [$($fields)* stringify!($variant) => $crate::common::readable::readable!(@fields $variant_name, $ty $(as $form)?),]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident, $held:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident ($first:ty, $second:ty $(,)?) $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name, $held)
            [$($show)* Self::$variant(first, second) => $crate::common::readable::tagged(
                $crate::common::names::name!(stringify!($variant)),
                $crate::common::readable::pair(
                    $crate::common::names::name!(stringify!($variant)),
                    first,
                    second,
                ),
            ),]
            [$($read)* stringify!($variant) => {
                let $contents = $contents.unwrap_or(&oxirush_utils::tree::Value::Null);
                let (first, second): ($first, $second) =
                    $crate::common::readable::pair_items($contents)?;
                Ok(Self::$variant(first, second))
            }]
            [$($blank)* stringify!($variant) => {
                let $depth = $crate::common::readable::blank_at($depth)?;
                Some(Self::$variant(
                    <$first as $crate::common::readable::Readable>::blank($variants, $depth)?,
                    <$second as $crate::common::readable::Readable>::blank($variants, $depth)?,
                ))
            }]
            [$($names)* (stringify!($variant))]
            [$($fields)*]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident, $held:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name, $held)
            [$($show)* Self::$variant => oxirush_utils::tree::Value::from(
                $crate::common::names::name!(stringify!($variant)),
            ),]
            [$($read)* stringify!($variant) => {
                $crate::common::readable::unit_variant($crate::common::names::name!(stringify!($variant)), $contents)?;
                Ok(Self::$variant)
            }]
            [$($blank)* stringify!($variant) => Some(Self::$variant),]
            [$($names)* (stringify!($variant))]
            [$($fields)*]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident, $held:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$(($names:expr))*] [$($fields:tt)*]) => {
        impl $crate::common::readable::Readable for $name {
            #[allow(unused_variables)]
            fn shown(&self, $held: &'static str) -> oxirush_utils::tree::Value {
                match self {
                    $($show)*
                }
            }

            #[allow(unused_variables)]

            fn read(value: &oxirush_utils::tree::Value) -> core::result::Result<Self, alloc::string::String> {
                const VARIANTS: &[&str] = &[$($names),*];
                const NAMES: &[&str] = &[$($crate::common::names::name!($names)),*];
                let (at, $contents) = $crate::common::readable::variant(value, NAMES)?;
                match VARIANTS[at] {
                    $($read)*
                    _ => unreachable!(),
                }
            }

            #[allow(unused_variables)]
            fn blank($variants: &[&str], $depth: usize) -> Option<Self> {
                const VARIANTS: &[&str] = &[$($names),*];
                const NAMES: &[&str] = &[$($crate::common::names::name!($names)),*];
                let at = $crate::common::readable::blank_variant(VARIANTS, NAMES, $variants)?;
                #[allow(unused_variables)]
                match VARIANTS[at] {
                    $($blank)*
                    _ => None,
                }
            }

            #[allow(unused_variables)]

            fn fields($variant_name: &str) -> Option<&'static [&'static str]> {
                const VARIANTS: &[&str] = &[$($names),*];
                const NAMES: &[&str] = &[$($crate::common::names::name!($names)),*];
                let at = $crate::common::readable::index_of(VARIANTS, NAMES, $variant_name)?;
                #[allow(unused_variables)]
                match VARIANTS[at] {
                    $($fields)*
                    _ => None,
                }
            }
        }
    };

    // A member of a struct: shown, read and made blank, by its form.
    (@put $members:ident, $value:expr, $member:ident) => {
        $members.put($crate::common::names::name!(stringify!($member)), &$value)
    };
    (@put $members:ident, $value:expr, $member:ident as $form:ident) => {
        $members.put_shown($crate::common::names::name!(stringify!($member)), $crate::common::forms::$form::shown(&$value))
    };
    (@put $members:ident, $value:expr, $member:ident = default) => {
        $members.put($crate::common::names::name!(stringify!($member)), &$value)
    };
    (@put $members:ident, $value:expr, $member:ident = skip) => {
        let _ = &$value;
    };
    (@read $read:ident, $member:ident) => {
        $crate::common::readable::member($read.next().flatten(), $crate::common::names::name!(stringify!($member)))?
    };
    (@read $read:ident, $member:ident as $form:ident) => {
        match $read.next().flatten() {
            Some(value) => $crate::common::forms::$form::read(value)?,
            None => $crate::common::forms::$form::missing()
                .ok_or_else(|| format!("`{}` is not written", $crate::common::names::name!(stringify!($member))))?,
        }
    };
    (@read $read:ident, $member:ident = default) => {
        match $read.next().flatten() {
            Some(value) => $crate::common::readable::Readable::read(value)?,
            None => Default::default(),
        }
    };
    (@read $read:ident, $member:ident = skip) => {{
        let _ = $read.next();
        Default::default()
    }};
    (@blank $variants:ident, $depth:ident) => {
        $crate::common::readable::Readable::blank($variants, $depth)?
    };
    (@blank $variants:ident, $depth:ident as $form:ident) => {
        $crate::common::forms::$form::blank()?
    };
    (@blank $variants:ident, $depth:ident = default) => {
        Default::default()
    };
    (@blank $variants:ident, $depth:ident = skip) => {
        Default::default()
    };
    // The value of a struct of one value, or of a variant.
    (@show $held:expr, [] $value:expr) => {
        $crate::common::readable::Readable::shown(&$value, $held)
    };
    (@show $held:expr, [$form:ident] $value:expr) => {
        $crate::common::forms::$form::shown(&$value)
    };
    (@octet [] $value:expr) => {
        $crate::common::readable::Readable::octet(&$value)
    };
    (@octet [$form:ident] $value:expr) => {
        None
    };
    (@value $value:ident, $ty:ty) => {
        <$ty as $crate::common::readable::Readable>::read($value)?
    };
    (@value $value:ident, $ty:ty as $form:ident) => {
        $crate::common::forms::$form::read($value)?
    };
    (@fields $variant:ident, $ty:ty) => {
        <$ty as $crate::common::readable::Readable>::fields($variant)
    };
    (@fields $variant:ident, $ty:ty as $form:ident) => {
        None
    };
}

pub(crate) use readable;

/// `Tree` of oxirush-utils for each of the types named, which are
/// [`Readable`], and through it `Serialize` and `Deserialize`: the serde form
/// of such a type is its readable form, which is what a tree has of it.
macro_rules! serde_by_readable {
    ($($name:ty),+ $(,)?) => {$(
        impl oxirush_utils::tree::Tree for $name {
            const NAME: &'static str = stringify!($name);

            fn to_tree(&self) -> oxirush_utils::tree::Value {
                $crate::common::readable::Readable::shown(self, "")
            }

            fn from_tree(
                value: &oxirush_utils::tree::Value,
                reading: &mut oxirush_utils::tree::Reading,
            ) -> core::result::Result<Self, oxirush_utils::tree::Refused> {
                $crate::common::readable::Readable::read(value)
                    .map_err(|why| reading.refuse(oxirush_utils::tree::ErrorKind::Value, why))
            }
        }

        oxirush_utils::impl_serde!($name);
    )+};
}

pub(crate) use serde_by_readable;

/// The place among `variants`, which print as `names`, of the one that
/// `name` is: the variant itself, or the name it prints as, however it is
/// written.
pub(crate) fn index_of(
    variants: &'static [&'static str],
    names: &'static [&'static str],
    name: &str,
) -> Option<usize> {
    (variants.iter().position(|variant| *variant == name))
        .or_else(|| oxirush_utils::tree::named(names, name))
}

/// Two values that a variant holds: the two octets they are, or a list.
pub(crate) fn pair<A: Readable, B: Readable>(held: &'static str, first: &A, second: &B) -> Value {
    match (first.octet(), second.octet()) {
        (Some(first), Some(second)) => octets_of(held, &[first, second]),
        _ => Value::Array(vec![first.shown(held), second.shown(held)]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::view::{PlmnText, TaiForm};
    use crate::nas_5gs::*;
    use oxirush_utils::tree;

    /// A value of a fixed number of octets is read from that number of
    /// them: a text or a list that is longer was read up to it, with no
    /// error. The lengths are those that the typed values have.
    #[test]
    fn a_value_of_a_fixed_length_is_read_from_that_length() {
        macro_rules! lengths {
            ($($n:literal)+) => {$(
                let text = |octets: usize| tree!("5a".repeat(octets));
                let list = |octets: usize| tree!(vec![0x5a; octets]);
                assert_eq!(from_value::<[u8; $n]>(&text($n)), Ok([0x5a; $n]));
                assert_eq!(from_value::<[u8; $n]>(&list($n)), Ok([0x5a; $n]));
                for wrong in [$n - 1, $n + 1, 2 * $n] {
                    let written = text(wrong);
                    let refused = Err(format!("{written} is not {} octets", $n));
                    assert_eq!(from_value::<[u8; $n]>(&written), refused);
                    assert_eq!(from_value::<Option<[u8; $n]>>(&written), refused.map(Some));
                    let written = list(wrong);
                    let refused = Err(format!("{written} is not a list of {}", $n));
                    assert_eq!(from_value::<[u8; $n]>(&written), refused);
                }
            )+};
        }
        lengths!(2 3 4 5 6 8 16 32);
        // A number is its octets, with the zeros before them, and a number
        // that has more is refused
        assert_eq!(from_value::<[u8; 3]>(&tree!("0x0102")), Ok([0, 1, 2]));
        assert_eq!(from_value::<[u8; 3]>(&tree!(258)), Ok([0, 1, 2]));
        let refused = Err("\"0x01020304\" is not 3 octets".to_string());
        assert_eq!(from_value::<[u8; 3]>(&tree!("0x01020304")), refused);
        // A list of another thing than octets has its number of them too
        let refused = Err("[1,2,3] is not a list of 2".to_string());
        assert_eq!(from_value::<(u8, u16)>(&tree!([1, 2, 3])), refused);
        assert_eq!(from_value::<(u8, u16)>(&tree!([1, 2])), Ok((1, 2)));
    }

    #[test]
    fn names_print_in_lower_case_with_hyphens() {
        for (name, expected) in [
            ("InitialRegistration", "initial-registration"),
            ("fgs_registration_type", "5gs-registration-type"),
            ("fg_s_tmsi", "5g-s-tmsi"),
            ("FiveGmmStatus", "5gmm-status"),
            ("FiveGSServicesNotAllowed", "5gs-services-not-allowed"),
            ("FiveQi", "5qi"),
            ("five_qi", "5qi"),
            ("5qi", "5qi"),
            ("N1ModeNotAllowed", "n1-mode-not-allowed"),
            ("N1SmInformation", "n1-sm-information"),
            ("STmsi", "s-tmsi"),
            ("IPv4v6", "ipv4v6"),
            ("NEA0", "nea0"),
            ("amf_region_id", "amf-region-id"),
            ("5GS registration type", "5gs-registration-type"),
            ("ThreeGppAndNon3Gpp", "3gpp-and-non-3gpp"),
            ("non_3gpp_access", "non-3gpp-access"),
            (
                "PlainFiveGsNasMessageNotSecurityProtected",
                "plain-5gs-nas-message-not-security-protected",
            ),
            (
                "RedirectionToFiveGcnRequired",
                "redirection-to-5gcn-required",
            ),
            (
                "MobileOriginatingCsFallbackOr1xCsFallback",
                "mobile-originating-cs-fallback-or-1x-cs-fallback",
            ),
            ("Ipv4v6", "ipv4v6"),
        ] {
            assert_eq!(printed(name), expected);
        }
        assert!(same_name("Initial_Registration", "initial registration"));
        assert!(same_name("INITIAL-REGISTRATION", "InitialRegistration"));
        assert!(same_name("5gmm_cause", "5GMM cause"));
        assert!(!same_name("fgmm_cause", "5GMM cause"));
        assert!(!same_name("initial-registration", "registration"));
    }

    #[test]
    fn typed_values_read_and_write_in_their_usual_notation() {
        // The members of a GUTI, as the view of a mobile identity has them
        #[derive(Debug, PartialEq)]
        struct Guti {
            plmn: Plmn,
            amf_region_id: u8,
            amf_set_id: u16,
            amf_pointer: u8,
            tmsi: u32,
        }

        #[cfg(feature = "tree")]
        crate::common::readable::readable!(struct Guti { plmn as plmn, amf_region_id, amf_set_id, amf_pointer, tmsi });
        let plmn = crate::common::plmn_at(&[0x02, 0xf8, 0x39]).unwrap();
        let guti = Guti {
            plmn,
            amf_region_id: 1,
            amf_set_id: 1,
            amf_pointer: 2,
            tmsi: 0x1122_3344,
        };
        let readable = tree!({"plmn": "208-93", "amf-region-id": 1, "amf-set-id": 1,
            "amf-pointer": 2, "tmsi": 0x1122_3344});
        assert_eq!(to_value(&guti).unwrap(), readable);
        assert_eq!(from_value::<Guti>(&readable).unwrap(), guti);
        // Names in any case, numbers also in hexadecimal.
        let written = tree!({"PLMN": "208-93", "AMF region ID": "0x01", "amf_set_id": 1,
            "AmfPointer": 2, "tmsi": "0x11223344"});
        assert_eq!(from_value::<Guti>(&written).unwrap(), guti);
        let plmn_text = PlmnText(crate::common::plmn_at(&[0x13, 0x00, 0x14]).unwrap());
        assert_eq!(
            to_value(&plmn_text).unwrap(),
            oxirush_utils::tree!("310-410")
        );

        let tai = TaiForm(tai_of(plmn, [0, 0, 1]).unwrap());
        assert_eq!(to_value(&tai).unwrap(), tree!({"plmn": "208-93", "tac": 1}));
        for tac in [tree!(1), tree!("0x1")] {
            let written = tree!({"plmn": "208-93", "tac": tac});
            assert!(from_value::<TaiForm<Tai5gs>>(&written).unwrap() == tai);
        }
        let snssai = SNssaiContents {
            sst: 1,
            sd: Some([1, 2, 3]),
            mapped_sst: None,
            mapped_sd: None,
        };
        let readable = tree!({"sst": 1, "sd": "010203", "mapped-sst": null, "mapped-sd": null});
        assert_eq!(to_value(&snssai).unwrap(), readable);
        assert_eq!(
            from_value::<SNssaiContents>(&tree!({"sst": 1, "sd": "010203"})).unwrap(),
            snssai
        );

        assert_eq!(
            to_value(&GmmCauseValue::Congestion).unwrap(),
            oxirush_utils::tree!("congestion")
        );
        for name in ["congestion", "Congestion", "CONGESTION"] {
            assert_eq!(
                from_value::<GmmCauseValue>(&tree!(name)).unwrap(),
                GmmCauseValue::Congestion
            );
        }
        let entry = TaiListEntry::OnePlmnNonConsecutive {
            plmn,
            tacs: vec![1, 2],
        };
        let readable = tree!({"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1, 2]}});
        assert_eq!(to_value(&entry).unwrap(), readable);
        assert_eq!(from_value::<TaiListEntry>(&readable).unwrap(), entry);
    }

    #[test]
    fn a_name_or_a_member_that_does_not_exist_is_an_error() {
        let error = from_value::<GmmCauseValue>(&tree!("congestio")).unwrap_err();
        assert!(
            error == "no name `congestio`; the nearest of its 50 is congestion",
            "{error}"
        );
        let error = from_value::<SNssaiContents>(&tree!({"sst": 1, "sdd": "010203"})).unwrap_err();
        assert_eq!(
            error,
            "no member `sdd`, expected one of sst, sd, mapped-sst, mapped-sd"
        );
        for plmn in ["20893", "208-9", "2a8-93", ""] {
            assert!(from_value::<PlmnText>(&tree!(plmn)).is_err(), "{plmn}");
        }
        assert!(from_value::<TaiForm<Tai5gs>>(&tree!({"plmn": "208-93", "tac": 1 << 24})).is_err());
        assert!(from_value::<GmmCauseValue>(&tree!({"congestion": 1})).is_err());
    }

    /// What an error says a value is, of each kind of number and of each other kind.
    #[test]
    fn an_error_says_what_the_value_is() {
        for (value, said) in [
            (tree!(null), "unit value"),
            (tree!(true), "boolean `true`"),
            (tree!(5), "integer `5`"),
            (
                tree!(9_223_372_036_854_775_808_u64),
                "integer `9223372036854775808`",
            ),
            (tree!(-5), "integer `-5`"),
            (tree!(1.5), "floating point `1.5`"),
            (tree!("text"), "string \"text\""),
            (tree!([1]), "sequence"),
            (tree!({"a": 1}), "map"),
        ] {
            assert_eq!(unexpected(&value), said);
        }
        assert_eq!(
            invalid_type(&tree!(true), "a string"),
            "invalid type: boolean `true`, expected a string"
        );
        // A number above the largest `i64` is read as a `usize` where it holds one
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            from_value::<usize>(&tree!(9_223_372_036_854_775_808_u64)),
            Ok(9_223_372_036_854_775_808)
        );
    }

    /// Octets are shown as what the member that holds them is: the digits of a PLMN
    /// identity, a number, an IP address or a list of numbers, and hexadecimal otherwise.
    #[test]
    fn octets_are_shown_as_what_their_member_is() {
        assert_eq!(octets_of("mcc", &[2, 0, 8]), tree!("208"));
        assert_eq!(octets_of("mnc", &[9, 3, 0x0f]), tree!("93"));
        assert_eq!(octets_of("tac", &[0x01, 0x02, 0x03]), tree!(0x010203));
        assert_eq!(octets_of("tac", &[0; 9]), tree!("000000000000000000"));
        assert_eq!(octets_of("address", &[10, 0, 0, 1]), tree!("10.0.0.1"));
        let mut ipv6 = [0; 16];
        ipv6[15] = 1;
        assert_eq!(octets_of("ipv6", &ipv6), tree!("::1"));
        assert_eq!(octets_of("qfis", &[1, 2]), tree!([1, 2]));
        assert_eq!(octets_of("value", &[1, 2]), tree!("0102"));
        // A sequence or a pair of octets, also in a box, is shown as its octets
        assert_eq!(
            to_value(&vec![Box::new(1u8), Box::new(2u8)]),
            Ok(tree!("0102"))
        );
        assert_eq!(to_value(&(1u8, 2u8)), Ok(tree!("0102")));
        assert_eq!(pair("value", &1u8, &2u8), tree!("0102"));
        assert_eq!(pair("value", &1u8, &true), tree!([1, true]));
        // and read from what each kind of member writes
        let read = |value: Value, length: usize| {
            let mut octets = Vec::new();
            each_item(&value, length, |item| {
                octets.push(item.as_u64().unwrap() as u8);
                Ok(())
            })
            .map(|()| octets)
        };
        assert_eq!(read(tree!("::1"), 16), Ok(ipv6.to_vec()));
        assert_eq!(read(tree!("10.0.0.1"), 4), Ok(vec![10, 0, 0, 1]));
        assert_eq!(
            read(tree!("0102"), 1),
            Err("\"0102\" is not one octet".to_string())
        );
        assert_eq!(pair_items::<u8, u8>(&tree!([1, 2])), Ok((1, 2)));
    }

    /// A blank value is made to 64 levels in, of each kind: zero, empty, false or
    /// absent.
    #[test]
    fn a_blank_value_is_made_to_64_levels() {
        assert_eq!(blank_at(0), Some(1));
        assert_eq!(blank_at(2), Some(3));
        assert_eq!(blank_at(63), Some(64));
        assert_eq!(blank_at(64), None);
        assert_eq!(blank::<usize>(&[]), Some(0));
        assert_eq!(blank::<bool>(&[]), Some(false));
        assert_eq!(blank::<String>(&[]), Some(String::new()));
        assert_eq!(blank::<Vec<u8>>(&[]), Some(Vec::new()));
        assert_eq!(blank::<[u8; 2]>(&[]), Some([0, 0]));
        assert_eq!(blank::<(u8, bool)>(&[]), Some((0, false)));
        assert_eq!(<Box<Option<u8>>>::missing(), Some(Box::new(None)));
        assert_eq!(fields::<u8>(""), None);
    }

    /// A struct written as a list has one item for each of its members.
    #[test]
    fn a_struct_written_as_a_list_has_an_item_for_each_member() {
        let fields: &'static [&'static str] = &["first", "second"];
        let written = tree!([1, 2]);
        let read = members(&written, "Pair", fields).unwrap();
        assert_eq!(read, [Some(&tree!(1)), Some(&tree!(2))]);
        assert_eq!(
            members(&tree!([1]), "Pair", fields),
            Err("invalid length 1, expected struct Pair with 2 elements".to_string())
        );
        assert_eq!(
            members(&tree!([1]), "One", &fields[..1]).map(|read| read.len()),
            Ok(1)
        );
        assert_eq!(
            members(&tree!([1, 2, 3]), "Pair", fields),
            Err("invalid length 3, expected fewer elements in array".to_string())
        );
    }
}
