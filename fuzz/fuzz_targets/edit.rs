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

//! A message of the fixtures, edited through its view by the paths that
//! `view::paths` lists, as a user edits one: `view::set`, `view::remove`
//! and `view::insert`, then `with_view`.
//!
//! An edit that the view or the message refuses is an error, never a panic.
//! The message that `with_view` writes is one that the crate wrote
//! ([`written`]), and only what was edited changes: each IE that no edit
//! touched has the octets that it had, and each field of the header its
//! value, unless an edit was of the header, whose fields decide what the
//! IEs are.

use crate::messages::{Leaf, Message, change, hex, written};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use oxirush_nas::tree::Value;
use oxirush_nas::view;

/// A message of the fixtures and what is done to its view.
#[derive(Arbitrary, Debug)]
pub struct Edits {
    base: u16,
    edits: Vec<Edit>,
}

/// One edit of a view. A path is one of those of `view::paths`, which the
/// number picks.
#[derive(Arbitrary, Debug)]
enum Edit {
    /// A value at the path
    Set { path: u16, to: Leaf },
    /// The value of another path of the view
    Copy { path: u16, from: u16 },
    /// A value that the IE of the path has in a tree of the fixtures, with
    /// one of its leaves changed or not
    Seen {
        path: u16,
        value: u16,
        walk: Vec<u16>,
        to: Option<Leaf>,
    },
    /// The member or the entry of a list that the path is in, or its IE
    Remove { path: u16 },
    /// A copy of the entry of a list that the path is in, before it
    Insert { path: u16 },
    /// An IE that the message can have, or a field of its header, by its
    /// octets
    Octets { name: u16, octets: Vec<u8> },
}

/// The name of the IE or of the field of the header that a path of a view
/// is under: the segment after `/nas`.
fn top(path: &str) -> String {
    path.split('/').nth(2).unwrap_or_default().to_owned()
}

/// The path of the entry of a list that `path` is in, the deepest one.
fn entry_of(path: &str) -> Option<String> {
    let segments: Vec<&str> = path.split('/').collect();
    let last = segments
        .iter()
        .rposition(|segment| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit()))?;
    Some(segments[..=last].join("/"))
}

pub fn edit<M: Message>(input: Edits) {
    let pool = M::pool();
    let message = pool.message(input.base);
    let before = message.to_view();
    let names: Vec<String> = (before.as_object().into_iter())
        .flat_map(|view| view.keys().cloned())
        .collect();
    // The paths of the message as it was: one that an edit took out
    // selects nothing for the next
    let paths = view::paths(&before);
    if paths.is_empty() || names.is_empty() {
        return;
    }
    let mut view = before.clone();
    let mut edited = Vec::new();
    for edit in input.edits.iter().take(8) {
        let pick = |number: u16| paths[usize::from(number) % paths.len()].clone();
        let (key, done) = match edit {
            Edit::Set { path, to } => {
                let (path, _) = pick(*path);
                (top(&path), view::set(&mut view, &path, to.value::<M>()))
            }
            Edit::Copy { path, from } => {
                let ((path, _), (_, value)) = (pick(*path), pick(*from));
                (top(&path), view::set(&mut view, &path, value))
            }
            Edit::Seen {
                path,
                value,
                walk,
                to,
            } => {
                let key = top(&pick(*path).0);
                let Some(mut value) = pool.value(&key, *value).cloned() else {
                    continue;
                };
                if let Some(to) = to {
                    change(&mut value, walk, to.value::<M>());
                }
                let path = format!("/nas/{key}/value");
                (key, view::set(&mut view, &path, value))
            }
            Edit::Remove { path } => {
                let (path, _) = pick(*path);
                let key = top(&path);
                let parent = &path[..path.rfind('/').unwrap_or(0)];
                let removed = view::remove(&mut view, parent)
                    .or_else(|_| view::remove(&mut view, &format!("/nas/{key}")));
                (key, removed)
            }
            Edit::Insert { path } => {
                let (path, _) = pick(*path);
                let Some(entry) = entry_of(&path) else {
                    continue;
                };
                let Some(copy) = view::select(&view, &entry)
                    .ok()
                    .and_then(|selected| selected.first().map(|value| (*value).clone()))
                else {
                    continue;
                };
                (top(&path), view::insert(&mut view, &entry, copy))
            }
            Edit::Octets { name, octets } => {
                let key = names[usize::from(*name) % names.len()].clone();
                let path = format!("/nas/{key}/octets");
                (key, view::set(&mut view, &path, Value::from(hex(octets))))
            }
        };
        if done.is_ok() {
            edited.push(key);
        }
    }

    let Ok(changed) = message.with_view(view) else {
        return;
    };
    written(&changed);

    // An IE has its octets in a view, a field of the header a value alone
    let after = changed.to_view();
    let octets =
        |view: &Value, key: &str| view.get(key).and_then(|entry| entry.get("octets")).cloned();
    let is_ie = |key: &String| octets(&before, key).is_some() || octets(&after, key).is_some();
    if !edited.iter().all(is_ie) {
        return;
    }
    let keys = (before.as_object().into_iter().chain(after.as_object()))
        .flat_map(|view| view.keys())
        .filter(|key| !edited.contains(key));
    for key in keys {
        let (was, is) = match octets(&before, key) {
            Some(was) => (Some(was), octets(&after, key)),
            None => (before.get(key).cloned(), after.get(key).cloned()),
        };
        assert_eq!(
            was, is,
            "`{key}` changed with an edit of {edited:?} of {message:?} to {changed:?}"
        );
    }
}
