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

//! A path that the fuzzer writes, on the tree of a message of the fixtures:
//! `paths::select`, `set`, `insert` and `remove`, and `paths::paths` of
//! the tree. The path starts as one that the tree has, cut anywhere, and goes
//! on with the fuzzer's text: escapes, `*`, positions past the end, `octets`
//! under a field, members of a payload container, entries by `id`.
//!
//! No path and no value makes a function panic. Each path that `paths`
//! lists selects its value; a path selects or is refused; an edit is done
//! whole or not at all, and a value that is set is the one that the path
//! selects. A tree that an edit changed writes a message or is refused, and a
//! message that it writes is one that the crate wrote ([`written`]).

use crate::messages::{Message, written};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use oxirush_nas::paths;
use oxirush_nas::tree::Value;

/// A message of the fixtures, a function, a path and a value.
#[derive(Arbitrary, Debug)]
pub struct Call {
    base: u16,
    function: u8,
    /// A path that the tree has, cut after `cut` characters
    pick: u16,
    cut: u8,
    /// What the path goes on with
    extra: String,
    /// The value: JSON, or else a string of its text
    value: Vec<u8>,
}

/// Whether a member of `tree` is named `*`, at any depth: a path names no
/// such member.
fn has_a_star(tree: &Value) -> bool {
    match tree {
        Value::Object(members) => members
            .iter()
            .any(|(name, member)| name == "*" || has_a_star(member)),
        Value::Array(entries) => entries.iter().any(has_a_star),
        _ => false,
    }
}

pub fn call<M: Message>(input: Call) {
    let message = M::pool().message(input.base);
    let tree = message.to_tree();

    // Each path that is listed selects its value.
    let known = paths::paths(&tree);
    let plain = !has_a_star(&tree);
    for (listed, held) in &known {
        if plain {
            let selected = paths::select(&tree, listed)
                .unwrap_or_else(|error| panic!("{listed} is listed and refused: {error}"));
            assert!(selected.contains(&held), "{listed}");
        }
    }

    // A path of the tree, cut short, with what the fuzzer adds to it
    let start = match known.get(usize::from(input.pick) % known.len().max(1)) {
        Some((path, _)) => path.as_str(),
        None => "/nas",
    };
    let start: String = start.chars().take(usize::from(input.cut)).collect();
    let path = format!("{start}{}", input.extra);
    let value = serde_json::from_slice::<Value>(&input.value)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&input.value).into_owned()));

    // Any path selects, or is refused.
    if let Ok(selected) = paths::select(&tree, &path) {
        assert!(selected.len() <= 65_536, "{path}");
    }

    // An edit is done whole, or not at all.
    let mut edited = tree.clone();
    let done = match input.function % 3 {
        0 => match paths::set(&mut edited, &path, value.clone()) {
            // What was set is what is selected, where the value is one.
            Ok(()) if !value.is_null() && plain => {
                let selected = paths::select(&edited, &path)
                    .unwrap_or_else(|error| panic!("{path} is set and refused: {error}"));
                assert!(
                    !selected.is_empty() && selected.iter().all(|held| **held == value),
                    "{path}: {selected:?}"
                );
                true
            }
            Ok(()) => true,
            Err(_) => false,
        },
        1 => paths::insert(&mut edited, &path, value).is_ok(),
        _ => paths::remove(&mut edited, &path).is_ok(),
    };
    if !done {
        assert_eq!(edited, tree, "{path}");
        return;
    }

    // What the edit left writes a message, or is refused.
    let _ = paths::paths(&edited);
    if let Ok(written_from) = M::from_tree(edited.clone()) {
        written(&written_from);
    }
    if let Ok(edited_message) = message.with_tree(edited) {
        written(&edited_message);
    }
}
