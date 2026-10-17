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
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

pub(crate) use crate::common::names::{printed, printed_static};

/// Whether two names are the same letter for letter, but for their case
/// and for which separator they have.
fn alike(one: &str, other: &str) -> bool {
    let separator = |c: u8| matches!(c, b'-' | b'_' | b' ');
    one.len() == other.len()
        && (one.bytes().zip(other.bytes()))
            .all(|(a, b)| a.eq_ignore_ascii_case(&b) || (separator(a) && separator(b)))
}

/// What two names that are [`alike`] have in common: the name in lower case
/// with one separator. `with` gets it, from where a short name is kept
/// without an allocation.
fn alike_key<T>(name: &str, with: impl FnOnce(&[u8]) -> T) -> T {
    let common = |c: u8| match c {
        b'-' | b'_' | b' ' => b'-',
        other => other.to_ascii_lowercase(),
    };
    let mut short = [0_u8; 64];
    match short.get_mut(..name.len()) {
        Some(key) => {
            (key.iter_mut().zip(name.bytes())).for_each(|(to, c)| *to = common(c));
            with(key)
        }
        None => with(&name.bytes().map(common).collect::<Vec<_>>()),
    }
}

/// Names in their order, to find the one that a name is without going
/// through them: the one that [`named`] finds.
pub(crate) struct Index {
    /// The first name that is [`alike`], by what such names have in common.
    alike: HashMap<Box<[u8]>, usize>,
    /// The first name with the same letters, by the letters, and by a name
    /// as it prints, which is how a view writes it.
    letters: HashMap<String, usize>,
    printed: HashMap<String, usize>,
}

impl Index {
    /// The index of `names`.
    pub(crate) fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        let (mut alike, mut by_letters, mut by_printed) =
            (HashMap::new(), HashMap::new(), HashMap::new());
        for (at, name) in names.into_iter().enumerate() {
            alike_key(name, |key| alike.entry(key.into()).or_insert(at));
            let (printed, letters_of) = (printed(name), letters(name));
            let first = *by_letters.entry(letters_of).or_insert(at);
            // A name that prints as it is has the letters of what it prints.
            if letters(&printed) == letters(name) {
                by_printed.entry(printed).or_insert(first);
            }
        }
        Self {
            alike,
            letters: by_letters,
            printed: by_printed,
        }
    }

    /// The place of the name that `name` is: the first one written like it,
    /// or else the first one with its letters.
    pub(crate) fn find(&self, name: &str) -> Option<usize> {
        alike_key(name, |key| self.alike.get(key).copied()).or_else(|| self.same(name))
    }

    /// The place of the first name with the letters of `name`.
    fn same(&self, name: &str) -> Option<usize> {
        (self.printed.get(name).copied()).or_else(|| self.letters.get(&letters(name)).copied())
    }

    /// The place of the first name that is the same as `name`, written like
    /// it or not.
    pub(crate) fn first(&self, name: &str) -> Option<usize> {
        let alike = alike_key(name, |key| self.alike.get(key).copied());
        match (alike, self.same(name)) {
            (Some(one), Some(other)) => Some(one.min(other)),
            (one, other) => one.or(other),
        }
    }
}

/// The index of the names of the members of a struct or of the variants of
/// an enum of the crate. It is made once and kept for as long as the program runs: there
/// are as many as the crate has structs and enums.
fn index(names: &'static [&'static str]) -> &'static Index {
    type Known = RwLock<HashMap<(usize, usize), &'static Index>>;
    static KNOWN: OnceLock<Known> = OnceLock::new();
    let known = KNOWN.get_or_init(Default::default);
    // The names of a type are one slice of the program.
    let key = (names.as_ptr() as usize, names.len());
    if let Some(found) = known.read().ok().and_then(|known| known.get(&key).copied()) {
        return found;
    }
    let new: &'static Index = Box::leak(Box::new(Index::new(names.iter().copied())));
    match known.write() {
        Ok(mut known) => known.entry(key).or_insert(new),
        Err(_) => new,
    }
}

/// Names in groups, to find the first group that has a name and the place
/// of the name in it: what [`same_name`] finds by going through the groups
/// in their order, without going through them.
pub(crate) struct Groups {
    index: Index,
    /// The group of each name, and its place in the group.
    places: Vec<(usize, usize)>,
}

impl Groups {
    /// The groups of the names that `groups` gives, in their order.
    pub(crate) fn new<I: IntoIterator<Item = String>>(groups: impl IntoIterator<Item = I>) -> Self {
        let (mut names, mut places) = (Vec::new(), Vec::new());
        for (group, of_group) in groups.into_iter().enumerate() {
            for (place, name) in of_group.into_iter().enumerate() {
                names.push(name);
                places.push((group, place));
            }
        }
        Self {
            index: Index::new(names.iter().map(String::as_str)),
            places,
        }
    }

    /// The first group that has a name which is the same as `name`, and the
    /// place in the group of the first such name.
    pub(crate) fn find(&self, name: &str) -> Option<(usize, usize)> {
        let first = self.index.first(name)?;
        self.places.get(first).copied()
    }
}

/// The letters and the digits of a name as it prints: those of any way to
/// write the name.
pub(crate) fn letters(name: &str) -> String {
    // A name as a view writes it is one that was printed already.
    if let Some(known) = crate::common::names::letters_of_printed(name) {
        return known.to_owned();
    }
    let mut printed = printed(name);
    printed.retain(|c| c.is_ascii_alphanumeric());
    printed
}

/// Whether two names are the same: they have the same letters and digits,
/// whatever their case and whatever is between them.
pub(crate) fn same_name(one: &str, other: &str) -> bool {
    alike(one, other) || letters(one) == letters(other)
}

/// The one of `names` that `name` is: the one written like it, if any.
pub(crate) fn named<'a, T: AsRef<str>>(names: &'a [T], name: &str) -> Option<&'a T> {
    (names.iter().find(|known| alike(known.as_ref(), name)))
        .or_else(|| names.iter().find(|known| same_name(known.as_ref(), name)))
}

/// The one of `names` that `name` is, or an error that lists them.
pub(crate) fn known(
    name: &str,
    names: &'static [&'static str],
    what: &str,
) -> Result<usize, String> {
    match index(names).find(name) {
        Some(at) => Ok(at),
        None if names.len() <= LISTED => {
            let names: Vec<_> = names.iter().map(|name| printed(name)).collect();
            Err(format!(
                "no {what} `{name}`, expected one of {}",
                names.join(", ")
            ))
        }
        None => {
            let nearest = nearest(name, names);
            let are = if nearest.len() == 1 { "is" } else { "are" };
            Err(format!(
                "no {what} `{name}`; the nearest of the {} {are} {}",
                names.len(),
                nearest.join(", ")
            ))
        }
    }
}

/// How many names an error lists whole: of more, it gives the nearest.
const LISTED: usize = 8;

/// The three of `names` that are nearest to `name`, by the edits that make
/// the letters of one those of the other, in the order of `names` among
/// those at the same distance.
fn nearest(name: &str, names: &[&str]) -> Vec<String> {
    let written = letters(name).into_bytes();
    let distance = |other: &[u8]| {
        let mut row: Vec<usize> = (0..=other.len()).collect();
        for (i, &a) in written.iter().enumerate() {
            let mut previous = row[0];
            row[0] = i + 1;
            for (j, &b) in other.iter().enumerate() {
                let next = (previous + usize::from(a != b))
                    .min(row[j] + 1)
                    .min(row[j + 1] + 1);
                previous = row[j + 1];
                row[j + 1] = next;
            }
        }
        row[other.len()]
    };
    let mut ranked: Vec<(usize, usize, String)> = (names.iter().enumerate())
        .map(|(at, known)| {
            let shown = printed(known);
            (distance(letters(&shown).as_bytes()), at, shown)
        })
        .collect();
    ranked.sort();
    // Those about as near as the nearest: a name far from what is written
    // says nothing.
    let best = ranked.first().map_or(0, |(distance, _, _)| *distance);
    (ranked.into_iter())
        .take_while(|(distance, _, _)| *distance <= best + 2)
        .take(3)
        .map(|(_, _, shown)| shown)
        .collect()
}

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

std::thread_local! {
    /// Whether the form being made is one to show, without what a message
    /// keeps of how it was received.
    static SHOWN: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// The readable form of a message as a view shows it: without its unknown IEs
/// and the order of its optional IEs, which no view has and which would take
/// an entry of the form each. A message that is to be read back from its form
/// is given by [`to_value`].
pub(crate) fn shown<T: Readable>(value: &T) -> Result<Value, String> {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            SHOWN.with(|shown| shown.set(self.0));
        }
    }
    let _restore = Restore(SHOWN.with(|shown| shown.replace(true)));
    to_value(value)
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
    match (printed_static(name).letters, octets.len()) {
        // The digits of a PLMN identity, without the filler.
        ("mcc" | "mnc", _) => (octets.iter().filter(|digit| **digit <= 9))
            .map(|digit| char::from(b'0' + digit))
            .collect::<String>()
            .into(),
        ("tac" | "tacs" | "firsttac", 1..=8) => octets
            .iter()
            .fold(0_u64, |number, octet| number << 8 | u64::from(*octet))
            .into(),
        ("address" | "addr" | "mask" | "ipv4" | "ipv4address" | "source" | "destination", 4) => {
            Ipv4Addr::from(<[u8; 4]>::try_from(octets).unwrap_or_default())
                .to_string()
                .into()
        }
        (
            "address" | "mask" | "ipv6" | "source" | "destination" | "smfipv6linklocaladdress",
            16,
        ) => Ipv6Addr::from(<[u8; 16]>::try_from(octets).unwrap_or_default())
            .to_string()
            .into(),
        // Identifiers that are a list of numbers and not a string of octets.
        ("qfis" | "payloadtypes" | "nssrgvalues" | "connectioncapabilityidentifiers", _) => {
            octets.to_vec().into()
        }
        _ => hex::encode(octets).into(),
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

/// The values of a sequence of `length` of them that `value` writes: a
/// list of as many, or as many octets in hexadecimal, a number or an IP
/// address. A text or a list that is longer is not read up to the length.
pub(crate) fn items(value: &Value, length: usize) -> Result<Vec<Value>, String> {
    match (value, octets_from(value, Some(length))) {
        (Value::Array(items), _) if items.len() == length => Ok(items.clone()),
        (value @ Value::Array(_), _) => Err(format!("{value} is not a list of {length}")),
        (_, Some(octets)) if octets.len() == length => {
            Ok(octets.into_iter().map(Value::from).collect())
        }
        (value, _) => Err(format!("{value} is not {length} octets")),
    }
}

/// The variant `variant` with what it holds, `contents`.
pub(crate) fn tagged(variant: &'static str, contents: Value) -> Value {
    let name = printed_static(variant).name.to_owned();
    Map::from_iter([(name, contents)]).into()
}

/// The members of a struct, by the names that they print as.
pub(crate) struct Members(Map<String, Value>);

impl Members {
    pub(crate) fn new() -> Self {
        Self(Map::new())
    }

    /// The member `key` of the struct, with its value.
    pub(crate) fn put<T: Readable>(&mut self, key: &'static str, value: &T) {
        let key = unraw(key);
        if matches!(key, "unknown_ies" | "optional_ie_order") && SHOWN.with(|shown| shown.get()) {
            return;
        }
        let name = printed_static(key).name.to_owned();
        self.0.insert(name, value.shown(key));
    }

    /// The member `key` of the struct, with the value `shown` in its form.
    pub(crate) fn put_shown(&mut self, key: &'static str, shown: Value) {
        self.0.insert(printed_static(key).name.to_owned(), shown);
    }

    pub(crate) fn finish(self) -> Value {
        self.0.into()
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
    Ok(read)
}

/// The member `field` of a struct, which `value` writes or leaves out.
pub(crate) fn member<T: Readable>(value: Option<&Value>, field: &str) -> Result<T, String> {
    match value {
        Some(value) => T::read(value),
        None => T::missing().ok_or_else(|| format!("`{}` is not written", printed(field))),
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
        Some(contents) => Err(format!(
            "`{}` has no contents, and {contents} is given",
            printed(name)
        )),
    }
}

/// The place among `variants` of the first that one of `wanted` names, or
/// that of the first variant.
pub(crate) fn blank_variant(variants: &'static [&'static str], wanted: &[&str]) -> Option<usize> {
    let index = index(variants);
    let named = (wanted.iter().filter_map(|wanted| index.first(wanted))).min();
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
            _ => hex::decode(text.strip_prefix("0x").unwrap_or(text)).ok(),
        },
        _ => None,
    }
}

/// The whole number that `value` writes, also as a `"0x…"` string, of the
/// type `ty`, which holds it if `fits` says so.
fn whole<T>(
    value: &Value,
    ty: &str,
    unsigned: impl Fn(u64) -> Option<T>,
    signed: impl Fn(i64) -> Option<T>,
) -> Result<T, String> {
    let outside = |number: &dyn core::fmt::Display| {
        format!("invalid value: integer `{number}`, expected {ty}")
    };
    if let Some(number) = value.as_str().and_then(hexadecimal) {
        return unsigned(number).ok_or_else(|| outside(&number));
    }
    match value {
        Value::Number(number) => match (number.as_u64(), number.as_i64()) {
            (Some(number), _) => unsigned(number).ok_or_else(|| outside(&number)),
            (_, Some(number)) => signed(number).ok_or_else(|| outside(&number)),
            _ => Err(invalid_type(value, ty)),
        },
        value => Err(invalid_type(value, ty)),
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
                    stringify!($ty),
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
            "u8",
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
            "usize",
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
        let read: Vec<T> = (items(value, N)?.iter())
            .map(T::read)
            .collect::<Result<_, _>>()?;
        read.try_into()
            .map_err(|_| format!("{value} is not a list of {N}"))
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
        let items = items(value, 2)?;
        Ok((A::read(&items[0])?, B::read(&items[1])?))
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
            fn shown(&self, _: &'static str) -> serde_json::Value {
                let mut members = $crate::common::readable::Members::new();
                $($crate::common::readable::readable!(@put members, self.$member, $member $(as $form)? $(= $how)?);)*
                members.finish()
            }

            #[allow(unused_variables)]

            fn read(value: &serde_json::Value) -> core::result::Result<Self, alloc::string::String> {
                const FIELDS: &[&str] = &[$($crate::common::readable::unraw(stringify!($member))),*];
                #[allow(unused_variables, unused_mut)]
                let mut read = $crate::common::readable::members(value, stringify!($name), FIELDS)?
                    .into_iter();
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
                { const FIELDS: &[&str] = &[$($crate::common::readable::unraw(stringify!($member))),*]; Some(FIELDS) }
            }
        }
    };
    // A struct of one value, which it is shown as.
    (struct $name:ident ($ty:ty $(as $form:ident)? $(,)?)) => {
        impl $crate::common::readable::Readable for $name {
            #[allow(unused_variables)]
            fn shown(&self, held: &'static str) -> serde_json::Value {
                $crate::common::readable::readable!(@show held, [$($form)?] self.0)
            }

            #[allow(unused_variables)]

            fn octet(&self) -> Option<u8> {
                $crate::common::readable::readable!(@octet [$($form)?] self.0)
            }

            #[allow(unused_variables)]

            fn read(value: &serde_json::Value) -> core::result::Result<Self, alloc::string::String> {
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
        $crate::common::readable::readable!(@enum $name (contents, variants, depth, variant)
            [] [] [] [] [] $($variants)*);
    };

    // The $variants of an enum, one at a time: what shows each, what reads
    // it by its place, what makes a blank of it, the names of the $variants,
    // and the fields of the struct that a variant holds.
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident = $rename:literal { $($member:ident $(as $form:ident)?),* $(,)? } $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name)
            [$($show)* Self::$variant { $($member),* } => {
                let mut members = $crate::common::readable::Members::new();
                $($crate::common::readable::readable!(@put members, *$member, $member $(as $form)?);)*
                $crate::common::readable::tagged($rename, members.finish())
            }]
            [$($read)* $rename => {
                const FIELDS: &[&str] = &[$($crate::common::readable::unraw(stringify!($member))),*];
                let $contents = $contents.unwrap_or(&serde_json::Value::Null);
                #[allow(unused_variables, unused_mut)]
                let mut read = $crate::common::readable::members($contents, "", FIELDS)?.into_iter();
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
            [$($names)* $rename,]
            [$($fields)* $rename => { const FIELDS: &[&str] = &[$($crate::common::readable::unraw(stringify!($member))),*]; Some(FIELDS) },]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident { $($member:ident $(as $form:ident)?),* $(,)? } $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name)
            [$($show)* Self::$variant { $($member),* } => {
                let mut members = $crate::common::readable::Members::new();
                $($crate::common::readable::readable!(@put members, *$member, $member $(as $form)?);)*
                $crate::common::readable::tagged(stringify!($variant), members.finish())
            }]
            [$($read)* stringify!($variant) => {
                const FIELDS: &[&str] = &[$($crate::common::readable::unraw(stringify!($member))),*];
                let $contents = $contents.unwrap_or(&serde_json::Value::Null);
                #[allow(unused_variables, unused_mut)]
                let mut read = $crate::common::readable::members($contents, "", FIELDS)?.into_iter();
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
            [$($names)* stringify!($variant),]
            [$($fields)* stringify!($variant) => { const FIELDS: &[&str] = &[$($crate::common::readable::unraw(stringify!($member))),*]; Some(FIELDS) },]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident ($ty:ty $(as $form:ident)? $(,)?) $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name)
            [$($show)* Self::$variant(value) => $crate::common::readable::tagged(
                stringify!($variant),
                $crate::common::readable::readable!(@show stringify!($variant), [$($form)?] *value),
            ),]
            [$($read)* stringify!($variant) => {
                let $contents = $contents.unwrap_or(&serde_json::Value::Null);
                Ok(Self::$variant($crate::common::readable::readable!(@value $contents, $ty $(as $form)?)))
            }]
            [$($blank)* stringify!($variant) => {
                let $depth = $crate::common::readable::blank_at($depth)?;
                Some(Self::$variant($crate::common::readable::readable!(@blank $variants, $depth $(as $form)?)))
            }]
            [$($names)* stringify!($variant),]
            [$($fields)* stringify!($variant) => $crate::common::readable::readable!(@fields $variant_name, $ty $(as $form)?),]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident ($first:ty, $second:ty $(,)?) $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name)
            [$($show)* Self::$variant(first, second) => $crate::common::readable::tagged(
                stringify!($variant),
                $crate::common::readable::pair(stringify!($variant), first, second),
            ),]
            [$($read)* stringify!($variant) => {
                let $contents = $contents.unwrap_or(&serde_json::Value::Null);
                let items = $crate::common::readable::items($contents, 2)?;
                Ok(Self::$variant(
                    <$first as $crate::common::readable::Readable>::read(&items[0])?,
                    <$second as $crate::common::readable::Readable>::read(&items[1])?,
                ))
            }]
            [$($blank)* stringify!($variant) => {
                let $depth = $crate::common::readable::blank_at($depth)?;
                Some(Self::$variant(
                    <$first as $crate::common::readable::Readable>::blank($variants, $depth)?,
                    <$second as $crate::common::readable::Readable>::blank($variants, $depth)?,
                ))
            }]
            [$($names)* stringify!($variant),]
            [$($fields)*]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]
        $variant:ident $(, $($rest:tt)*)?) => {
        $crate::common::readable::readable!(@enum $name ($contents, $variants, $depth, $variant_name)
            [$($show)* Self::$variant => serde_json::Value::from(
                $crate::common::names::printed_static(stringify!($variant)).name,
            ),]
            [$($read)* stringify!($variant) => {
                $crate::common::readable::unit_variant(stringify!($variant), $contents)?;
                Ok(Self::$variant)
            }]
            [$($blank)* stringify!($variant) => Some(Self::$variant),]
            [$($names)* stringify!($variant),]
            [$($fields)*]
            $($($rest)*)?);
    };
    (@enum $name:ident ($contents:ident, $variants:ident, $depth:ident, $variant_name:ident) [$($show:tt)*] [$($read:tt)*] [$($blank:tt)*] [$($names:tt)*] [$($fields:tt)*]) => {
        impl $crate::common::readable::Readable for $name {
            #[allow(unused_variables)]
            fn shown(&self, _: &'static str) -> serde_json::Value {
                match self {
                    $($show)*
                }
            }

            #[allow(unused_variables)]

            fn read(value: &serde_json::Value) -> core::result::Result<Self, alloc::string::String> {
                const VARIANTS: &[&str] = &[$($names)*];
                let (at, $contents) = $crate::common::readable::variant(value, VARIANTS)?;
                match VARIANTS[at] {
                    $($read)*
                    _ => unreachable!(),
                }
            }

            #[allow(unused_variables)]
            fn blank($variants: &[&str], $depth: usize) -> Option<Self> {
                const VARIANTS: &[&str] = &[$($names)*];
                let at = $crate::common::readable::blank_variant(VARIANTS, $variants)?;
                #[allow(unused_variables)]
                match VARIANTS[at] {
                    $($blank)*
                    _ => None,
                }
            }

            #[allow(unused_variables)]

            fn fields($variant_name: &str) -> Option<&'static [&'static str]> {
                const VARIANTS: &[&str] = &[$($names)*];
                let at = $crate::common::readable::index_of(VARIANTS, $variant_name)?;
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
        $members.put(stringify!($member), &$value)
    };
    (@put $members:ident, $value:expr, $member:ident as $form:ident) => {
        $members.put_shown(stringify!($member), $crate::common::forms::$form::shown(&$value))
    };
    (@put $members:ident, $value:expr, $member:ident = default) => {
        $members.put(stringify!($member), &$value)
    };
    (@put $members:ident, $value:expr, $member:ident = skip) => {
        let _ = &$value;
    };
    (@read $read:ident, $member:ident) => {
        $crate::common::readable::member($read.next().flatten(), stringify!($member))?
    };
    (@read $read:ident, $member:ident as $form:ident) => {
        match $read.next().flatten() {
            Some(value) => $crate::common::forms::$form::read(value)?,
            None => $crate::common::forms::$form::missing()
                .ok_or_else(|| format!(
                    "`{}` is not written",
                    $crate::common::names::printed(stringify!($member))
                ))?,
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

            fn to_tree(&self) -> serde_json::Value {
                $crate::common::readable::Readable::shown(self, "")
            }

            fn from_tree(
                value: &serde_json::Value,
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

/// The name of a member as Rust writes it, without the `r#` of a raw
/// identifier: `r#type` is the member `type`.
pub(crate) const fn unraw(name: &'static str) -> &'static str {
    match name.as_bytes() {
        [b'r', b'#', rest @ ..] => match core::str::from_utf8(rest) {
            Ok(name) => name,
            Err(_) => name,
        },
        _ => name,
    }
}

/// The place among `names` of the one that `name` is, however it is written.
pub(crate) fn index_of(names: &'static [&'static str], name: &str) -> Option<usize> {
    index(names).find(name)
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
    use crate::nas_5gs::ie::*;
    use serde_json::json;

    /// A value of a fixed number of octets is read from that number of
    /// them: a text or a list that is longer was read up to it, with no
    /// error. The lengths are those that the typed values have.
    #[test]
    fn a_value_of_a_fixed_length_is_read_from_that_length() {
        macro_rules! lengths {
            ($($n:literal)+) => {$(
                let text = |octets: usize| json!("5a".repeat(octets));
                let list = |octets: usize| json!(vec![0x5a; octets]);
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
        assert_eq!(from_value::<[u8; 3]>(&json!("0x0102")), Ok([0, 1, 2]));
        assert_eq!(from_value::<[u8; 3]>(&json!(258)), Ok([0, 1, 2]));
        let refused = Err("\"0x01020304\" is not 3 octets".to_string());
        assert_eq!(from_value::<[u8; 3]>(&json!("0x01020304")), refused);
        // A list of another thing than octets has its number of them too
        let refused = Err("[1,2,3] is not a list of 2".to_string());
        assert_eq!(from_value::<(u8, u16)>(&json!([1, 2, 3])), refused);
        assert_eq!(from_value::<(u8, u16)>(&json!([1, 2])), Ok((1, 2)));
    }

    /// The index of names finds the name that going through them finds, for
    /// names and for ways to write them that are alike, that print alike,
    /// and that are neither.
    #[test]
    fn an_index_finds_the_name_that_going_through_the_names_finds() {
        let parts = [
            "F", "g", "Gs", "5", "_", "-", "three", "Gpp", "a", "B", "status",
        ];
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut name = || {
            let mut name = String::new();
            for _ in 0..1 + seed % 4 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                name.push_str(parts[(seed % parts.len() as u64) as usize]);
            }
            name
        };
        for _ in 0..300 {
            let names: Vec<String> = (0..12).map(|_| name()).collect();
            let index = Index::new(names.iter().map(String::as_str));
            let groups = Groups::new([names[..5].to_vec(), names[5..].to_vec()]);
            let written: Vec<String> = (names.iter())
                .flat_map(|name| {
                    [
                        name.clone(),
                        printed(name),
                        name.to_uppercase(),
                        letters(name),
                    ]
                })
                .chain((0..12).map(|_| name()))
                .collect();
            for written in written {
                let found = named(&names, &written);
                let at = found.and_then(|found| names.iter().position(|name| name == found));
                assert_eq!(index.find(&written), at, "{written} in {names:?}");
                // The first group that has the name, and the first such name
                // of the group.
                let same = |name: &&String| same_name(name, &written);
                let place = (names[..5].iter().position(|name| same(&name)))
                    .map(|place| (0, place))
                    .or_else(|| {
                        let place = names[5..].iter().position(|name| same(&name));
                        place.map(|place| (1, place))
                    });
                assert_eq!(groups.find(&written), place, "{written} in {names:?}");
            }
        }
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
        assert!(same_name("fgmm_cause", "5GMM cause"));
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

        #[cfg(all(feature = "serde", feature = "std"))]
        crate::common::readable::readable!(struct Guti { plmn as plmn, amf_region_id, amf_set_id, amf_pointer, tmsi });
        let plmn = crate::common::plmn_at(&[0x02, 0xf8, 0x39]).unwrap();
        let guti = Guti {
            plmn,
            amf_region_id: 1,
            amf_set_id: 1,
            amf_pointer: 2,
            tmsi: 0x1122_3344,
        };
        let readable = json!({"plmn": "208-93", "amf-region-id": 1, "amf-set-id": 1,
            "amf-pointer": 2, "tmsi": 0x1122_3344});
        assert_eq!(to_value(&guti).unwrap(), readable);
        assert_eq!(from_value::<Guti>(&readable).unwrap(), guti);
        // Names in any case, numbers also in hexadecimal.
        let written = json!({"PLMN": "208-93", "AMF region ID": "0x01", "amf_set_id": 1,
            "AmfPointer": 2, "tmsi": "0x11223344"});
        assert_eq!(from_value::<Guti>(&written).unwrap(), guti);
        let plmn_text = PlmnText(crate::common::plmn_at(&[0x13, 0x00, 0x14]).unwrap());
        assert_eq!(to_value(&plmn_text).unwrap(), "310-410");

        let tai = TaiForm(tai_of(plmn, [0, 0, 1]).unwrap());
        assert_eq!(to_value(&tai).unwrap(), json!({"plmn": "208-93", "tac": 1}));
        for tac in [json!(1), json!("0x1")] {
            let written = json!({"plmn": "208-93", "tac": tac});
            assert!(from_value::<TaiForm<Tai>>(&written).unwrap() == tai);
        }
        let snssai = SNssaiContents {
            sst: 1,
            sd: Some([1, 2, 3]),
            mapped_sst: None,
            mapped_sd: None,
        };
        let readable = json!({"sst": 1, "sd": "010203", "mapped-sst": null, "mapped-sd": null});
        assert_eq!(to_value(&snssai).unwrap(), readable);
        assert_eq!(
            from_value::<SNssaiContents>(&json!({"sst": 1, "sd": "010203"})).unwrap(),
            snssai
        );

        assert_eq!(to_value(&GmmCause::Congestion).unwrap(), "congestion");
        for name in ["congestion", "Congestion", "CONGESTION"] {
            assert_eq!(
                from_value::<GmmCause>(&json!(name)).unwrap(),
                GmmCause::Congestion
            );
        }
        let entry = TaiListEntry::OnePlmnNonConsecutive {
            plmn,
            tacs: vec![1, 2],
        };
        let readable = json!({"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1, 2]}});
        assert_eq!(to_value(&entry).unwrap(), readable);
        assert_eq!(from_value::<TaiListEntry>(&readable).unwrap(), entry);
    }

    #[test]
    fn a_name_or_a_member_that_does_not_exist_is_an_error() {
        let error = from_value::<GmmCause>(&json!("congestio")).unwrap_err();
        assert!(
            error == "no name `congestio`; the nearest of the 50 is congestion",
            "{error}"
        );
        let error = from_value::<SNssaiContents>(&json!({"sst": 1, "sdd": "010203"})).unwrap_err();
        assert_eq!(
            error,
            "no member `sdd`, expected one of sst, sd, mapped-sst, mapped-sd"
        );
        for plmn in ["20893", "208-9", "2a8-93", ""] {
            assert!(from_value::<PlmnText>(&json!(plmn)).is_err(), "{plmn}");
        }
        assert!(from_value::<TaiForm<Tai>>(&json!({"plmn": "208-93", "tac": 1 << 24})).is_err());
        assert!(from_value::<GmmCause>(&json!({"congestion": 1})).is_err());
    }
}
