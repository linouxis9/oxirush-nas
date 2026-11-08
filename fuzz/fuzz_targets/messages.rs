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

//! What the targets that edit and build messages share: the messages of the
//! fixtures, which they start from, the values that their trees have, and
//! the checks of a message that the crate wrote.
//!
//! A target picks a message of the fixtures by a number of its input, so
//! that it starts from each message type of the codec and from the messages
//! of a lab with no corpus at all, and spends its time on what it changes.

#![allow(dead_code)]

use libfuzzer_sys::arbitrary::{self, Arbitrary};

use oxirush_nas::tree::Value;
use oxirush_nas::{Error, Severity, Validate};
use oxirush_nas::{nas_5gs, nas_eps};
use std::collections::BTreeMap;
use std::fmt::{Debug, Display};
use std::sync::LazyLock;

/// A message of one system, with what the targets call of it.
pub trait Message: Clone + PartialEq + Debug + Display + Validate + Sized + 'static {
    /// The messages of the fixtures and of the seeds of the system, as
    /// `name<TAB>octets` lines.
    const FIXTURES: [&'static str; 2];
    /// The system of the rows of `captured.tsv` that are of this system.
    const SYSTEM: &'static str;

    fn decode(octets: &[u8]) -> Result<Self, Error>;
    fn encode(&self) -> Result<Vec<u8>, Error>;
    fn with_tree(&self, tree: Value) -> Result<Self, Error>;
    /// The names of the members that the tree of the message can have.
    fn names(&self) -> Vec<String>;
    fn to_tree(&self) -> Value;
    fn from_tree(tree: Value) -> Result<Self, Error>;
    fn means_the_same(&self, other: &Self) -> bool;
    /// Whether the message is a plain one under a header that says it is
    /// ciphered: the message that a security context deciphered, which has
    /// no octets before one ciphers it, and which `from_tree` writes.
    fn deciphered(&self) -> bool;
    /// The messages and values of the fixtures, read once.
    fn pool() -> &'static Pool<Self>;
}

impl Message for nas_5gs::Message {
    const FIXTURES: [&'static str; 2] = [
        include_str!("../../tests/fixtures/nas-5gs.tsv"),
        include_str!("../seeds-5gs.tsv"),
    ];
    const SYSTEM: &'static str = "5gs";

    fn decode(octets: &[u8]) -> Result<Self, Error> {
        Self::decode(octets)
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.encode()
    }
    fn with_tree(&self, tree: Value) -> Result<Self, Error> {
        self.with_tree(tree)
    }
    fn names(&self) -> Vec<String> {
        match self {
            Self::Gmm(_, message) => message.message_type().names(),
            Self::Gsm(_, message) => message.message_type().names(),
            Self::SecurityProtected(_, inner) => inner.names(),
            _ => Vec::new(),
        }
    }
    fn to_tree(&self) -> Value {
        self.to_tree()
    }
    fn from_tree(tree: Value) -> Result<Self, Error> {
        Self::from_tree(tree)
    }
    fn means_the_same(&self, other: &Self) -> bool {
        self.means_the_same(other)
    }
    fn deciphered(&self) -> bool {
        use nas_5gs::SecurityHeaderType::*;
        let Self::SecurityProtected(header, inner) = self else {
            return false;
        };
        let ciphered = matches!(
            header.security_header_type,
            IntegrityProtectedAndCiphered
                | IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        );
        ciphered && !matches!(**inner, Self::Opaque(_))
    }
    fn pool() -> &'static Pool<Self> {
        static POOL: LazyLock<Pool<nas_5gs::Message>> = LazyLock::new(Pool::read);
        &POOL
    }
}

impl Message for nas_eps::Message {
    const FIXTURES: [&'static str; 2] = [
        include_str!("../../tests/fixtures/nas-eps.tsv"),
        include_str!("../seeds-eps.tsv"),
    ];
    const SYSTEM: &'static str = "eps";

    fn decode(octets: &[u8]) -> Result<Self, Error> {
        Self::decode(octets)
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        self.encode()
    }
    fn with_tree(&self, tree: Value) -> Result<Self, Error> {
        self.with_tree(tree)
    }
    fn names(&self) -> Vec<String> {
        match self {
            Self::Emm(_, message) => message.message_type().names(),
            Self::Esm(_, message) => message.message_type().names(),
            Self::SecurityProtected(_, inner) => inner.names(),
            _ => Vec::new(),
        }
    }
    fn to_tree(&self) -> Value {
        self.to_tree()
    }
    fn from_tree(tree: Value) -> Result<Self, Error> {
        Self::from_tree(tree)
    }
    fn means_the_same(&self, other: &Self) -> bool {
        self.means_the_same(other)
    }
    fn deciphered(&self) -> bool {
        use nas_eps::SecurityHeaderType::*;
        let Self::SecurityProtected(header, inner) = self else {
            return false;
        };
        let ciphered = matches!(
            header.security_header_type,
            IntegrityProtectedAndCiphered | IntegrityProtectedAndCipheredWithNewEpsSecurityContext
        );
        ciphered && !matches!(**inner, Self::Opaque(_))
    }
    fn pool() -> &'static Pool<Self> {
        static POOL: LazyLock<Pool<nas_eps::Message>> = LazyLock::new(Pool::read);
        &POOL
    }
}

/// The lab messages: their plain octets and those on the wire, which are
/// under a security header where they were protected.
const CAPTURED: &str = include_str!("../../tests/fixtures/captured.tsv");

/// The messages of the fixtures of a system, and the values of their trees.
pub struct Pool<M> {
    /// Each message of the fixtures, of the seeds and of the lab.
    pub messages: Vec<M>,
    /// For the name of each IE and of each field, the values that it has
    /// in the trees of the messages, each once.
    pub values: BTreeMap<String, Vec<Value>>,
    /// Each text of a value of the trees: the names of coded values above
    /// all, which a value is written with.
    pub names: Vec<String>,
}

impl<M: Message> Pool<M> {
    fn read() -> Self {
        let rows = M::FIXTURES.iter().flat_map(|text| text.lines());
        let fixtures = rows
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| line.split('\t').nth(1));
        let captured = (CAPTURED.lines())
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.split('\t').collect::<Vec<_>>())
            .filter(|columns| columns.first() == Some(&M::SYSTEM))
            .flat_map(|columns| columns.into_iter().skip(8));
        let messages: Vec<M> = fixtures
            .chain(captured)
            .filter_map(|octets| M::decode(&unhex(octets)).ok())
            .collect();
        let mut values = BTreeMap::<String, Vec<Value>>::new();
        let mut names = Vec::new();
        for message in &messages {
            let tree = message.to_tree();
            for (name, value) in tree.as_object().into_iter().flat_map(|tree| tree.iter()) {
                let seen = values.entry(name.clone()).or_default();
                if !seen.contains(value) {
                    seen.push(value.clone());
                }
                texts(value, &mut names);
            }
        }
        names.sort();
        names.dedup();
        Self {
            messages,
            values,
            names,
        }
    }

    /// The message of the fixtures that `number` picks.
    pub fn message(&self, number: u16) -> &M {
        &self.messages[usize::from(number) % self.messages.len()]
    }

    /// A value that the IE or the field `name` has in a tree of the
    /// fixtures, which `number` picks.
    pub fn value(&self, name: &str, number: u16) -> Option<&Value> {
        let seen = self.values.get(name)?;
        seen.get(usize::from(number) % seen.len().max(1))
    }
}

/// Each text in `value`.
fn texts(value: &Value, names: &mut Vec<String>) {
    match value {
        Value::String(text) => names.push(text.clone()),
        Value::Array(entries) => entries.iter().for_each(|entry| texts(entry, names)),
        Value::Object(members) => members.values().for_each(|member| texts(member, names)),
        _ => {}
    }
}

/// The octets of a hexadecimal text.
pub fn unhex(text: &str) -> Vec<u8> {
    let digit = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
    text.as_bytes()
        .chunks(2)
        .map(|pair| digit(pair[0]) << 4 | pair.get(1).map_or(0, |low| digit(*low)))
        .collect()
}

/// Octets in hexadecimal, as a tree writes them.
pub fn hex(octets: &[u8]) -> String {
    octets.iter().map(|octet| format!("{octet:02x}")).collect()
}

/// A value that the fuzzer writes in the place of another.
#[derive(Arbitrary, Debug)]
pub enum Leaf {
    Unsigned(u64),
    Signed(i64),
    Small(u8),
    Text(String),
    Hex(Vec<u8>),
    Bool(bool),
    Null,
    /// A text of a value of the fixtures: the name of a coded value
    Name(u16),
}

impl Leaf {
    pub fn value<M: Message>(&self) -> Value {
        match self {
            Leaf::Unsigned(number) => Value::from(*number),
            Leaf::Signed(number) => Value::from(*number),
            Leaf::Small(number) => Value::from(*number),
            Leaf::Text(text) => Value::from(text.as_str()),
            Leaf::Hex(octets) => Value::from(hex(octets)),
            Leaf::Bool(flag) => Value::from(*flag),
            Leaf::Null => Value::Null,
            Leaf::Name(number) => {
                let names = &M::pool().names;
                match names.get(usize::from(*number) % names.len().max(1)) {
                    Some(name) => Value::from(name.as_str()),
                    None => Value::Null,
                }
            }
        }
    }
}

/// Replace the leaf of `value` that `walk` goes to, a member or an entry by
/// its place at each step, with `leaf`.
pub fn change(value: &mut Value, walk: &[u16], leaf: Value) {
    let Some((&step, rest)) = walk.split_first() else {
        *value = leaf;
        return;
    };
    match value {
        Value::Array(entries) if !entries.is_empty() => {
            let at = usize::from(step) % entries.len();
            change(&mut entries[at], rest, leaf);
        }
        Value::Object(members) if !members.is_empty() => {
            let at = usize::from(step) % members.len();
            if let Some(member) = members.values_mut().nth(at) {
                change(member, rest, leaf);
            }
        }
        _ => *value = leaf,
    }
}

/// Whether `message` has an error that `validate()` finds.
pub fn faulty<M: Message>(message: &M) -> bool {
    let findings = message.validate();
    findings
        .iter()
        .any(|finding| finding.severity == Severity::Error)
}

/// What holds of a message that the crate wrote, from a tree.
///
/// It encodes, unless it is a plain message under a header that says it is
/// ciphered, which has no octets yet (`from_tree` says so), and a receiver reads the same octets back, with no
/// difference to what the decoder keeps. A message that `validate()` finds
/// nothing wrong with is the message that the receiver reads: a difference
/// is a rule of a sender that `validate()` does not check, or one that the
/// decoder reads otherwise. Its tree writes a message with the same tree
/// that means the same, and edits it into itself.
pub fn written<M: Message>(message: &M) {
    let octets = match message.encode() {
        Ok(octets) => octets,
        Err(_) if message.deciphered() => return,
        Err(error) => {
            panic!("a message that the crate wrote does not encode: {error}: {message:?}")
        }
    };
    let sound = !faulty(message);
    match M::decode(&octets) {
        Ok(read) => {
            assert_eq!(read.encode().as_ref(), Ok(&octets), "{read:?}");
            if sound {
                assert_eq!(
                    &read,
                    message,
                    "validate() finds nothing wrong, and the receiver reads another message in {}",
                    hex(&octets)
                );
            }
        }
        Err(error) => assert!(
            !sound,
            "validate() finds nothing wrong, and the receiver refuses {}: {error}: {message:?}",
            hex(&octets)
        ),
    }

    let tree = message.to_tree();
    match M::from_tree(tree.clone()) {
        Ok(again) => {
            assert_eq!(again.to_tree(), tree, "{message:?}");
            assert!(
                again.means_the_same(message),
                "the tree {tree} of {message:?} writes {again:?}"
            );
        }
        Err(error) => panic!("the tree of a message is refused: {error}: {tree}"),
    }
    match message.with_tree(tree) {
        Ok(same) => assert_eq!(&same, message),
        Err(error) => panic!("the tree of a message does not edit it: {error}: {message:?}"),
    }
}
