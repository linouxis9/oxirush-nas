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

//! A message written from a tree, as `from_tree` writes one, whose IEs the
//! fuzzer chooses by their names and their values.
//!
//! The tree starts as that of a message of the fixtures, and each IE that
//! its message type can have may be taken out, given a value that an IE of
//! that name has in a tree of the fixtures, with one of its leaves changed
//! or not, a leaf of its own, or octets. So the fuzzer writes the IEs of
//! every message type with the values of their types, deep in the IE, and
//! not only octets that a decoder refuses at the header. A tree that the
//! message type or a value refuses is an error, never a panic, and a
//! message that `from_tree` writes is one that the crate wrote
//! ([`written`]).

use crate::messages::{Leaf, Message, change, hex, written};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use oxirush_nas::tree::Value;

/// A message of the fixtures and what is done to the IEs of its tree.
#[derive(Arbitrary, Debug)]
pub struct Build {
    base: u16,
    ies: Vec<(u16, Choice)>,
}

/// What an IE of the tree becomes.
#[derive(Arbitrary, Debug)]
enum Choice {
    /// Taken out
    Absent,
    /// A value that an IE of the name has in a tree of the fixtures, with
    /// one of its leaves changed or not
    Seen {
        value: u16,
        walk: Vec<u16>,
        to: Option<Leaf>,
    },
    /// A value of its own
    Leaf(Leaf),
    /// Octets, which the tree writes as they are
    Octets(Vec<u8>),
}

pub fn build<M: Message>(input: Build) {
    let pool = M::pool();
    let message = pool.message(input.base);
    // What the message type can have, but for the type itself, which
    // decides them
    let names: Vec<String> = (message.names().into_iter())
        .filter(|name| name != "message-type")
        .collect();
    let mut tree = message.to_tree();
    let Some(members) = tree.as_object_mut() else {
        return;
    };
    if names.is_empty() {
        return;
    }
    for (name, choice) in input.ies.iter().take(16) {
        let name = &names[usize::from(*name) % names.len()];
        let value = match choice {
            Choice::Absent => {
                members.shift_remove(name);
                continue;
            }
            Choice::Seen { value, walk, to } => {
                let Some(mut value) = pool.value(name, *value).cloned() else {
                    continue;
                };
                if let Some(to) = to {
                    change(&mut value, walk, to.value::<M>());
                }
                value
            }
            Choice::Leaf(leaf) => leaf.value::<M>(),
            Choice::Octets(octets) => {
                let mut entry = oxirush_nas::tree::Map::new();
                entry.insert("octets".into(), Value::from(hex(octets)));
                Value::Object(entry)
            }
        };
        members.insert(name.clone(), value);
    }
    if let Ok(written_message) = M::from_tree(tree) {
        written(&written_message);
    }
}
