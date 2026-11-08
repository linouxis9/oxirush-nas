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

//! A message of the fixtures, edited through its tree by the paths that
//! `paths::paths` lists, as a user edits one: `paths::set`, `paths::remove`
//! and `paths::insert`, then `with_tree`.
//!
//! An edit that the tree or the message refuses is an error, never a panic.
//! The message that `with_tree` writes is one that the crate wrote
//! ([`written`]), and only what was edited changes: each IE that no edit
//! touched has the octets that it had, and each field of the header is as it
//! was, unless an edit was of the header, whose fields decide what the IEs
//! are. The octets of an IE read as an edited IE may say: a payload
//! container as its type.

use crate::messages::{Leaf, Message, change, hex, written};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use oxirush_nas::paths;

/// A message of the fixtures and what is done to its tree.
#[derive(Arbitrary, Debug)]
pub struct Edits {
    base: u16,
    edits: Vec<Edit>,
}

/// One edit of a tree. A path is one of those of `paths::paths`, which the
/// number picks.
#[derive(Arbitrary, Debug)]
enum Edit {
    /// A value at the path
    Set { path: u16, to: Leaf },
    /// The value of another path of the tree
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

/// The name of the IE or of the field of the header that a path of a tree
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
    let before = message.to_tree();
    let names = message.names();
    // The paths of the message as it was: one that an edit took out
    // selects nothing for the next
    let all = paths::paths(&before);
    if all.is_empty() || names.is_empty() {
        return;
    }
    let mut tree = before.clone();
    let mut edited = Vec::new();
    for edit in input.edits.iter().take(8) {
        let pick = |number: u16| all[usize::from(number) % all.len()].clone();
        let (key, done) = match edit {
            Edit::Set { path, to } => {
                let (path, _) = pick(*path);
                (top(&path), paths::set(&mut tree, &path, to.value::<M>()))
            }
            Edit::Copy { path, from } => {
                let ((path, _), (_, value)) = (pick(*path), pick(*from));
                (top(&path), paths::set(&mut tree, &path, value))
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
                let path = format!("/nas/{key}");
                (key, paths::set(&mut tree, &path, value))
            }
            Edit::Remove { path } => {
                let (path, _) = pick(*path);
                let key = top(&path);
                let parent = &path[..path.rfind('/').unwrap_or(0)];
                let removed = paths::remove(&mut tree, parent)
                    .or_else(|_| paths::remove(&mut tree, &format!("/nas/{key}")));
                (key, removed)
            }
            Edit::Insert { path } => {
                let (path, _) = pick(*path);
                let Some(entry) = entry_of(&path) else {
                    continue;
                };
                let Some(copy) = paths::select(&tree, &entry)
                    .ok()
                    .and_then(|selected| selected.first().map(|value| (*value).clone()))
                else {
                    continue;
                };
                (top(&path), paths::insert(&mut tree, &entry, copy))
            }
            Edit::Octets { name, octets } => {
                let key = names[usize::from(*name) % names.len()].clone();
                let path = format!("/nas/{key}");
                let octets = oxirush_nas::tree!({ "octets": hex(octets) });
                (key, paths::set(&mut tree, &path, octets))
            }
        };
        if done.is_ok() {
            edited.push(key);
        }
    }

    let Ok(changed) = message.with_tree(tree) else {
        return;
    };
    written(&changed);

    // An edit of the header may change what the IEs are; else each IE that
    // no edit touched has its octets, however they read now, and each other
    // member of the tree is as it was
    let after = changed.to_tree();
    let header = ["message-type", "security-header-type", "spare-half-octet"];
    if edited.iter().any(|key| header.contains(&key.as_str())) {
        return;
    }
    let keys = (before.as_object().into_iter().chain(after.as_object()))
        .flat_map(|tree| tree.keys())
        .filter(|key| !edited.contains(key));
    for key in keys {
        let path = format!("/nas/{key}");
        match (message.ie_octets(&path), changed.ie_octets(&path)) {
            (Ok(octets), Ok(again)) => assert_eq!(
                octets, again,
                "the octets of `{key}` changed with an edit of {edited:?} of {message:?} to \
                 {changed:?}"
            ),
            _ => assert_eq!(
                before.get(key),
                after.get(key),
                "`{key}` changed with an edit of {edited:?} of {message:?} to {changed:?}"
            ),
        }
    }
}
