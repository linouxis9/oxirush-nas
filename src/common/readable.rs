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

//! The readable form of the typed values, for the view of a message.
//!
//! It is the serde form of a value with the names and notations a reader
//! expects: a name is in lower case with hyphens, a PLMN identity is
//! `"208-93"`, an IP address is its text, a tracking area code is a number
//! and other octets are hexadecimal. Reading takes a name in any case, with
//! hyphens, underscores or spaces, a number also as a `"0x…"` string, and
//! octets also as a list of numbers. A member or a name that a value does
//! not have is an error.

use serde::de::{self, DeserializeSeed, IntoDeserializer, Visitor};
use serde::ser::{self, Impossible, Serialize};
use serde_json::{Error, Map, Value};
use std::net::{Ipv4Addr, Ipv6Addr};

/// A name as it prints: lower case, its words joined by hyphens, and the
/// `fg` of an identifier of the codec as the `5g` it stands for.
pub(crate) fn printed(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    let lower = |at: usize| chars.get(at).is_some_and(char::is_ascii_lowercase);
    let mut words = String::with_capacity(name.len() + 4);
    for (index, &c) in chars.iter().enumerate() {
        if matches!(c, '_' | ' ' | '-') {
            words.push('-');
            continue;
        }
        // A capital starts a word after a small letter, before a small
        // letter after a digit, and before two after a capital.
        if c.is_ascii_uppercase()
            && index > 0
            && (lower(index - 1)
                || (lower(index + 1)
                    && (chars[index - 1].is_ascii_digit()
                        || (chars[index - 1].is_ascii_uppercase() && lower(index + 2)))))
        {
            words.push('-');
        }
        words.push(c.to_ascii_lowercase());
    }
    let mut printed = String::with_capacity(words.len());
    let mut words = words.split('-').peekable();
    while let Some(word) = words.next() {
        if !printed.is_empty() {
            printed.push('-');
        }
        // The digits that an identifier of Rust spells out or keeps apart.
        let joined = match (word, words.peek().copied()) {
            ("fg" | "fgs" | "fgmm" | "fgsm", _) => {
                printed.extend(["5", &word[1..]]);
                continue;
            }
            ("f" | "five", Some(next @ ("g" | "gs" | "gmm" | "gsm"))) => ["5", next],
            ("three", Some("gpp")) => ["3", "gpp"],
            ("non3", Some("gpp")) => ["non-3", "gpp"],
            _ => {
                printed.push_str(word);
                continue;
            }
        };
        printed.extend(joined);
        words.next();
    }
    printed
}

/// Whether two names are the same letter for letter, but for their case
/// and for which separator they have.
fn alike(one: &str, other: &str) -> bool {
    let separator = |c: u8| matches!(c, b'-' | b'_' | b' ');
    one.len() == other.len()
        && (one.bytes().zip(other.bytes()))
            .all(|(a, b)| a.eq_ignore_ascii_case(&b) || (separator(a) && separator(b)))
}

/// The letters and the digits of a name as it prints: those of any way to
/// write the name.
pub(crate) fn letters(name: &str) -> String {
    printed(name).replace('-', "")
}

/// Whether two names are the same, whatever their case and their separators.
pub(crate) fn same_name(one: &str, other: &str) -> bool {
    alike(one, other) || letters(one) == letters(other)
}

/// The one of `names` that `name` is: the one written like it, if any.
pub(crate) fn named<'a, T: AsRef<str>>(names: &'a [T], name: &str) -> Option<&'a T> {
    (names.iter().find(|known| alike(known.as_ref(), name)))
        .or_else(|| names.iter().find(|known| same_name(known.as_ref(), name)))
}

/// The one of `names` that `name` is, or an error that lists them.
fn known(name: &str, names: &'static [&'static str], what: &str) -> Result<&'static str, Error> {
    match named(names, name) {
        Some(known) => Ok(known),
        None => {
            let names: Vec<_> = names.iter().map(|name| printed(name)).collect();
            Err(de::Error::custom(format!(
                "no {what} `{name}`, expected one of {}",
                names.join(", ")
            )))
        }
    }
}

/// The readable form of a typed value.
pub(crate) fn to_value<T: Serialize + ?Sized>(value: &T) -> Result<Value, String> {
    match value.serialize(Ser("")) {
        Ok((value, _)) => Ok(value),
        Err(error) => Err(error.to_string()),
    }
}

/// The typed value of a readable form.
pub(crate) fn from_value<T: de::DeserializeOwned>(value: &Value) -> Result<T, String> {
    T::deserialize(De(value)).map_err(|error| error.to_string())
}

/// The fields that serde derives for the struct `T`, or for the struct in
/// the variant `variant` of the enum `T`. A deserializer is told them before
/// it gives a value, and this one gives none.
pub(crate) fn fields<'de, T: de::Deserialize<'de>>(
    variant: &str,
) -> Option<&'static [&'static str]> {
    let mut fields = None;
    let _ = T::deserialize(Fields(variant, &mut fields));
    fields
}

struct Fields<'a>(&'a str, &'a mut Option<&'static [&'static str]>);

impl<'de> de::Deserializer<'de> for Fields<'_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Error> {
        Err(de::Error::custom("no value"))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        *self.1 = Some(fields);
        self.deserialize_any(visitor)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_enum(self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes byte_buf option unit
        unit_struct newtype_struct seq tuple tuple_struct map identifier ignored_any
    }
}

impl<'de> de::EnumAccess<'de> for Fields<'_> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<(T::Value, Self), Error> {
        Ok((seed.deserialize(self.0.into_deserializer())?, self))
    }
}

impl<'de> de::VariantAccess<'de> for Fields<'_> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Err(de::Error::custom("no value"))
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(self)
    }

    fn tuple_variant<V: Visitor<'de>>(self, _: usize, visitor: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_any(self, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_any(self, visitor)
    }
}

/// Octets as the member or the variant `name` shows them.
fn octets_of(name: &str, octets: &[u8]) -> Value {
    let name = printed(name).replace('-', "");
    match (name.as_str(), octets.len()) {
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

/// Serializer of the readable form: a value, and whether it is one octet.
/// It keeps the name of the member or variant that holds the value, which
/// says how its octets are shown.
#[derive(Clone, Copy)]
struct Ser(&'static str);

type Out = (Value, bool);

macro_rules! serialize_number {
    ($($method:ident: $ty:ty),+) => {$(
        fn $method(self, number: $ty) -> Result<Out, Error> {
            Ok((number.into(), false))
        }
    )+};
}

impl ser::Serializer for Ser {
    type Ok = Out;
    type Error = Error;
    type SerializeSeq = Seq;
    type SerializeTuple = Seq;
    type SerializeTupleStruct = Seq;
    type SerializeTupleVariant = Tagged<Seq>;
    type SerializeMap = Impossible<Out, Error>;
    type SerializeStruct = Struct;
    type SerializeStructVariant = Tagged<Struct>;

    serialize_number!(serialize_bool: bool, serialize_i8: i8, serialize_i16: i16,
        serialize_i32: i32, serialize_i64: i64, serialize_u16: u16, serialize_u32: u32,
        serialize_u64: u64, serialize_f32: f32, serialize_f64: f64, serialize_str: &str);

    fn serialize_u8(self, octet: u8) -> Result<Out, Error> {
        Ok((octet.into(), true))
    }

    fn serialize_char(self, c: char) -> Result<Out, Error> {
        Ok((c.to_string().into(), false))
    }

    fn serialize_bytes(self, octets: &[u8]) -> Result<Out, Error> {
        Ok((octets_of(self.0, octets), false))
    }

    fn serialize_none(self) -> Result<Out, Error> {
        Ok((Value::Null, false))
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<Out, Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Out, Error> {
        Ok((Value::Null, false))
    }

    fn serialize_unit_struct(self, _: &'static str) -> Result<Out, Error> {
        Ok((Value::Null, false))
    }

    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<Out, Error> {
        Ok((printed(variant).into(), false))
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<Out, Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<Out, Error> {
        Ok(tagged(variant, value.serialize(Ser(variant))?.0))
    }

    fn serialize_seq(self, _: Option<usize>) -> Result<Seq, Error> {
        Ok(Seq::new(self.0))
    }

    fn serialize_tuple(self, _: usize) -> Result<Seq, Error> {
        Ok(Seq::new(self.0))
    }

    fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Seq, Error> {
        Ok(Seq::new(self.0))
    }

    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Tagged<Seq>, Error> {
        Ok(Tagged(variant, Seq::new(variant)))
    }

    fn serialize_map(self, _: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Err(ser::Error::custom("a map has no readable form"))
    }

    fn serialize_struct(self, name: &'static str, _: usize) -> Result<Struct, Error> {
        Ok(Struct(name, Map::new()))
    }

    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        _: usize,
    ) -> Result<Tagged<Struct>, Error> {
        Ok(Tagged(variant, Struct("", Map::new())))
    }
}

/// A variant with contents: an object of its name.
fn tagged(variant: &str, contents: Value) -> Out {
    (Map::from_iter([(printed(variant), contents)]).into(), false)
}

/// A sequence: a list, or the octets it is made of.
struct Seq {
    name: &'static str,
    items: Vec<Value>,
    octets: Option<Vec<u8>>,
}

impl Seq {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            items: Vec::new(),
            octets: Some(Vec::new()),
        }
    }

    fn push<T: Serialize + ?Sized>(&mut self, item: &T) -> Result<(), Error> {
        let (item, octet) = item.serialize(Ser(self.name))?;
        match (&mut self.octets, item.as_u64()) {
            (Some(octets), Some(number)) if octet => octets.push(number as u8),
            _ => self.octets = None,
        }
        self.items.push(item);
        Ok(())
    }

    fn finish(self) -> Out {
        match self.octets {
            Some(octets) if !octets.is_empty() => (octets_of(self.name, &octets), false),
            _ => (self.items.into(), false),
        }
    }
}

macro_rules! serialize_seq {
    ($($form:ident: $method:ident),+) => {$(
        impl ser::$form for Seq {
            type Ok = Out;
            type Error = Error;

            fn $method<T: Serialize + ?Sized>(&mut self, item: &T) -> Result<(), Error> {
                self.push(item)
            }

            fn end(self) -> Result<Out, Error> {
                Ok(self.finish())
            }
        }
    )+};
}
serialize_seq!(SerializeSeq: serialize_element, SerializeTuple: serialize_element,
    SerializeTupleStruct: serialize_field);

/// A struct of the name `.0`: an object of its members.
struct Struct(&'static str, Map<String, Value>);

impl ser::SerializeStruct for Struct {
    type Ok = Out;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.1.insert(printed(key), value.serialize(Ser(key))?.0);
        Ok(())
    }

    fn end(self) -> Result<Out, Error> {
        // A PLMN identity is its digits, "MCC-MNC".
        if self.0 == "PlmnId"
            && let (Some(Value::String(mcc)), Some(Value::String(mnc))) =
                (self.1.get("mcc"), self.1.get("mnc"))
        {
            return Ok((format!("{mcc}-{mnc}").into(), false));
        }
        Ok((self.1.into(), false))
    }
}

/// The contents of the variant `.0`.
struct Tagged<T>(&'static str, T);

impl ser::SerializeTupleVariant for Tagged<Seq> {
    type Ok = Out;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, item: &T) -> Result<(), Error> {
        self.1.push(item)
    }

    fn end(self) -> Result<Out, Error> {
        Ok(tagged(self.0, self.1.finish().0))
    }
}

impl ser::SerializeStructVariant for Tagged<Struct> {
    type Ok = Out;
    type Error = Error;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        ser::SerializeStruct::serialize_field(&mut self.1, key, value)
    }

    fn end(self) -> Result<Out, Error> {
        Ok(tagged(self.0, (self.1).1.into()))
    }
}

/// Deserializer of the readable form.
#[derive(Clone, Copy)]
pub(crate) struct De<'a>(pub &'a Value);

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

/// Octets as the sequence that a typed value reads.
fn sequence(octets: Vec<u8>) -> de::value::SeqDeserializer<std::vec::IntoIter<u8>, Error> {
    octets.into_deserializer()
}

/// The members of a PLMN identity written `"MCC-MNC"`.
fn plmn(text: &str) -> Option<Value> {
    let (mcc, mnc) = text.split_once('-')?;
    let digits = |text: &str| -> Option<Vec<u8>> {
        text.bytes()
            .map(|digit| digit.is_ascii_digit().then(|| digit - b'0'))
            .collect()
    };
    let (mcc, mut mnc) = (digits(mcc)?, digits(mnc)?);
    if mnc.len() == 2 {
        mnc.push(0x0f);
    }
    (mcc.len() == 3 && mnc.len() == 3).then(|| serde_json::json!({"mcc": mcc, "mnc": mnc}))
}

macro_rules! deserialize_number {
    ($($method:ident)+) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
            match self.0.as_str().and_then(hexadecimal) {
                Some(number) => visitor.visit_u64(number),
                None => self.deserialize_any(visitor),
            }
        }
    )+};
}

impl<'de> de::Deserializer<'de> for De<'_> {
    type Error = Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_unit(),
            Value::Bool(value) => visitor.visit_bool(*value),
            Value::Number(number) => match (number.as_u64(), number.as_i64()) {
                (Some(number), _) => visitor.visit_u64(number),
                (_, Some(number)) => visitor.visit_i64(number),
                _ => visitor.visit_f64(number.as_f64().unwrap_or_default()),
            },
            Value::String(text) => visitor.visit_str(text),
            Value::Array(items) => visitor.visit_seq(Items(items.iter())),
            Value::Object(members) => visitor.visit_map(Members {
                members: members.iter(),
                value: None,
                names: None,
            }),
        }
    }

    deserialize_number!(deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64
        deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64);

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match self.0 {
            Value::Null => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        visitor: V,
    ) -> Result<V::Value, Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Error> {
        match (self.0, octets_from(self.0, None)) {
            (Value::String(_), Some(octets)) => visitor.visit_seq(sequence(octets)),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        match (self.0, octets_from(self.0, Some(length))) {
            (Value::Array(_), _) => self.deserialize_any(visitor),
            (_, Some(octets)) => visitor.visit_seq(sequence(octets)),
            (value, None) => Err(de::Error::custom(format!("{value} is not {length} octets"))),
        }
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        length: usize,
        visitor: V,
    ) -> Result<V::Value, Error> {
        self.deserialize_tuple(length, visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        names: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        match self.0 {
            // A PLMN identity is read from its digits alone, so that the
            // encoders, which take one as valid, get no other.
            value if name == "PlmnId" => match value.as_str().and_then(plmn) {
                Some(Value::Object(members)) => visitor.visit_map(Members {
                    members: members.iter(),
                    value: None,
                    names: Some(names),
                }),
                _ => Err(de::Error::custom(format!(
                    "{value} is not a PLMN identity like \"208-93\""
                ))),
            },
            Value::Object(members) => visitor.visit_map(Members {
                members: members.iter(),
                value: None,
                names: Some(names),
            }),
            _ => self.deserialize_any(visitor),
        }
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _: &'static str,
        names: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        let (name, contents) = match self.0 {
            Value::String(name) => (name, None),
            Value::Object(members) if members.len() == 1 => {
                let (name, contents) = members.iter().next().unwrap_or((&EMPTY, &Value::Null));
                (name, Some(contents))
            }
            value => {
                return Err(de::Error::custom(format!(
                    "{value} is not a name, or a name with its contents"
                )));
            }
        };
        visitor.visit_enum(Variant(known(name, names, "name")?, contents))
    }

    serde::forward_to_deserialize_any! {
        bool f32 f64 char str string bytes byte_buf unit unit_struct map identifier ignored_any
    }
}

static EMPTY: String = String::new();

struct Items<'a>(std::slice::Iter<'a, Value>);

impl<'de> de::SeqAccess<'de> for Items<'_> {
    type Error = Error;

    fn next_element_seed<T: DeserializeSeed<'de>>(
        &mut self,
        seed: T,
    ) -> Result<Option<T::Value>, Error> {
        self.0
            .next()
            .map(|item| seed.deserialize(De(item)))
            .transpose()
    }
}

/// The members of an object, by the names `names` when the value is a
/// struct: a member that it does not have is an error.
struct Members<'a> {
    members: serde_json::map::Iter<'a>,
    value: Option<&'a Value>,
    names: Option<&'static [&'static str]>,
}

impl<'de> de::MapAccess<'de> for Members<'_> {
    type Error = Error;

    fn next_key_seed<K: DeserializeSeed<'de>>(
        &mut self,
        seed: K,
    ) -> Result<Option<K::Value>, Error> {
        let Some((name, value)) = self.members.next() else {
            return Ok(None);
        };
        self.value = Some(value);
        match self.names {
            Some(names) => seed.deserialize(de::value::BorrowedStrDeserializer::new(known(
                name, names, "member",
            )?)),
            None => seed.deserialize(name.as_str().into_deserializer()),
        }
        .map(Some)
    }

    fn next_value_seed<T: DeserializeSeed<'de>>(&mut self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(De(self.value.take().unwrap_or(&Value::Null)))
    }
}

/// The variant `.0` of an enum, and its contents.
struct Variant<'a>(&'static str, Option<&'a Value>);

impl<'de, 'a> de::EnumAccess<'de> for Variant<'a> {
    type Error = Error;
    type Variant = Self;

    fn variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<(T::Value, Self), Error> {
        let name = seed.deserialize(de::value::BorrowedStrDeserializer::new(self.0))?;
        Ok((name, self))
    }
}

impl<'de> de::VariantAccess<'de> for Variant<'_> {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        match self.1 {
            None | Some(Value::Null) => Ok(()),
            Some(contents) => Err(de::Error::custom(format!(
                "`{}` has no contents, and {contents} is given",
                printed(self.0)
            ))),
        }
    }

    fn newtype_variant_seed<T: DeserializeSeed<'de>>(self, seed: T) -> Result<T::Value, Error> {
        seed.deserialize(De(self.1.unwrap_or(&Value::Null)))
    }

    fn tuple_variant<V: Visitor<'de>>(self, length: usize, visitor: V) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_tuple(De(self.1.unwrap_or(&Value::Null)), length, visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        names: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error> {
        de::Deserializer::deserialize_struct(De(self.1.unwrap_or(&Value::Null)), "", names, visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nas_5gs::ie::*;
    use serde_json::json;

    #[test]
    fn names_print_in_lower_case_with_hyphens() {
        for (name, expected) in [
            ("InitialRegistration", "initial-registration"),
            ("fgs_registration_type", "5gs-registration-type"),
            ("fg_s_tmsi", "5g-s-tmsi"),
            ("FGmmStatus", "5gmm-status"),
            ("FiveGSServicesNotAllowed", "5gs-services-not-allowed"),
            ("N1ModeNotAllowed", "n1-mode-not-allowed"),
            ("N1SmInformation", "n1-sm-information"),
            ("STmsi", "s-tmsi"),
            ("IPv4v6", "ipv4v6"),
            ("NEA0", "nea0"),
            ("amf_region_id", "amf-region-id"),
            ("5GS registration type", "5gs-registration-type"),
            ("ThreeGppAndNon3Gpp", "3gpp-and-non-3gpp"),
            ("non_3gpp_access", "non-3gpp-access"),
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
        let plmn = PlmnId::from_tbcd(&[0x02, 0xf8, 0x39]).unwrap();
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
        assert_eq!(
            to_value(&PlmnId::from_tbcd(&[0x13, 0x00, 0x14]).unwrap()).unwrap(),
            "310-410"
        );

        let tai = TrackingAreaIdentity {
            plmn,
            tac: [0, 0, 1],
        };
        assert_eq!(to_value(&tai).unwrap(), json!({"plmn": "208-93", "tac": 1}));
        for tac in [json!(1), json!("0x1"), json!("000001"), json!([0, 0, 1])] {
            let written = json!({"plmn": "208-93", "tac": tac});
            assert_eq!(from_value::<TrackingAreaIdentity>(&written).unwrap(), tai);
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
            tacs: vec![[0, 0, 1], [0, 0, 2]],
        };
        let readable = json!({"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1, 2]}});
        assert_eq!(to_value(&entry).unwrap(), readable);
        assert_eq!(from_value::<TaiListEntry>(&readable).unwrap(), entry);
    }

    #[test]
    fn a_name_or_a_member_that_does_not_exist_is_an_error() {
        let error = from_value::<GmmCause>(&json!("congestio")).unwrap_err();
        assert!(
            error.starts_with("no name `congestio`, expected one of illegal-ue, "),
            "{error}"
        );
        let error = from_value::<SNssaiContents>(&json!({"sst": 1, "sdd": "010203"})).unwrap_err();
        assert_eq!(
            error,
            "no member `sdd`, expected one of sst, sd, mapped-sst, mapped-sd"
        );
        for plmn in ["20893", "208-9", "2a8-93", ""] {
            assert!(from_value::<PlmnId>(&json!(plmn)).is_err(), "{plmn}");
        }
        assert!(
            from_value::<TrackingAreaIdentity>(&json!({"plmn": "208-93", "tac": 1 << 24})).is_err()
        );
        assert!(from_value::<GmmCause>(&json!({"congestion": 1})).is_err());
    }
}
