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

//! The values of the view of a message by their paths.
//!
//! [`paths`] gives each value of a view with the path that selects it,
//! [`select`] the values at a path, and [`set`], [`remove`] and [`insert`]
//! edit a view at a path. `/nas` stands for the view, and the segment
//! after it is the name of an IE or of a field of the header:
//!
//! ```text
//! /nas/message-type/value = "registration-accept"
//! /nas/5g-guti/octets = "f202f839cafe0011223344"
//! /nas/5g-guti/value/guti/plmn = "208-93"
//! /nas/allowed-nssai/value/0/sst = 1
//! ```
//!
//! A path is a JSON pointer. A name is taken however it is written, as a
//! view takes it, a list selects by position, and `*` is each entry of a
//! list or each member of a value. The message in a container is under the
//! `value` of the container, with the names of its own IEs. An IE that the
//! message does not have selects nothing, and a name that a view or a
//! value does not have is an error.
//!
//! ```
//! use oxirush_nas::{Nas5gsMessage, view};
//! use serde_json::json;
//!
//! // 5GMM STATUS, cause #22 "congestion".
//! let status = Nas5gsMessage::from_bytes(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//! let mut tree = status.to_view();
//! assert_eq!(view::select(&tree, "/nas/5gmm-cause/value")?, [&json!("congestion")]);
//!
//! view::set(&mut tree, "/nas/5gmm-cause/value", json!("illegal-ue"))?;
//! let edited = status.with_view(tree).unwrap();
//! assert_eq!(edited.to_bytes().unwrap(), [0x7e, 0x00, 0x64, 0x03]);
//! # Ok::<(), String>(())
//! ```

use crate::common::readable::{named, same_name};
use serde_json::{Map, Value};

/// The first segment of a path.
const ROOT: &str = "nas";
/// The most occurrences that a path selects.
const OCCURRENCES: usize = 4096;

/// The segments of a path after its root: those of a JSON pointer.
fn segments(path: &str) -> Result<Vec<String>, String> {
    if path.len() > 4096 || !path.starts_with('/') {
        return Err("IE path must start with / and be at most 4096 bytes".into());
    }
    let mut parts = path[1..]
        .split('/')
        .map(|part| {
            let mut decoded = String::new();
            let mut chars = part.chars();
            while let Some(c) = chars.next() {
                decoded.push(if c == '~' {
                    match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err("invalid JSON-pointer escape".into()),
                    }
                } else {
                    c
                });
            }
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if parts.len() > 64 {
        return Err("IE path nesting exceeds 64".into());
    }
    if parts.remove(0) != ROOT {
        return Err(format!(
            "{path} is not a path of a view: it starts with /{ROOT}"
        ));
    }
    Ok(parts)
}

/// The name that `members` has for `name`, however it is written.
fn key<'a>(members: &'a Map<String, Value>, name: &str) -> Option<&'a String> {
    let names: Vec<_> = members.keys().collect();
    named(&names, name).copied()
}

/// The values at `path` in `view`, in the order of the view. An IE that the
/// message does not have selects nothing; a name that the view or a value
/// does not have is an error.
pub fn select<'a>(view: &'a Value, path: &str) -> Result<Vec<&'a Value>, String> {
    let mut selected = vec![view];
    for part in segments(path)? {
        let mut next = Vec::new();
        for value in selected {
            match value {
                Value::Null => {}
                Value::Array(entries) if part == "*" => next.extend(entries),
                Value::Object(members) if part == "*" => next.extend(members.values()),
                Value::Object(members) => match key(members, &part) {
                    Some(name) => next.push(&members[name]),
                    None => {
                        return Err(format!(
                            "unknown or unavailable decoded field {part:?} at {path}"
                        ));
                    }
                },
                Value::Array(entries) => {
                    let index = part
                        .parse::<usize>()
                        .map_err(|_| format!("array index must be numeric at {path}"))?;
                    next.extend(entries.get(index));
                }
                _ if part == "*" => {
                    return Err(format!("wildcard cannot traverse a scalar at {path}"));
                }
                _ => return Err(format!("decoded path traverses a scalar at {path}")),
            }
            if next.len() > OCCURRENCES {
                return Err(format!("IE selection exceeds {OCCURRENCES} occurrences"));
            }
        }
        selected = next;
    }
    Ok(selected)
}

/// Each value of `view` with the path that selects it, in the order of the
/// view. A list of plain values is one value, and an IE that the message
/// does not have has no path.
pub fn paths(view: &Value) -> Vec<(String, Value)> {
    let mut found = Vec::new();
    walk(view, &mut format!("/{ROOT}"), &mut found);
    found
}

fn walk(value: &Value, path: &mut String, found: &mut Vec<(String, Value)>) {
    let step = |segment: &str, child: &Value, path: &mut String, found: &mut _| {
        let length = path.len();
        path.push('/');
        path.push_str(&segment.replace('~', "~0").replace('/', "~1"));
        walk(child, path, found);
        path.truncate(length);
    };
    match value {
        Value::Object(members) if !members.is_empty() => {
            for (name, member) in members.iter().filter(|(_, member)| !member.is_null()) {
                step(name, member, path, found);
            }
        }
        Value::Array(entries) if entries.iter().any(|e| e.is_object() || e.is_array()) => {
            for (index, entry) in entries.iter().enumerate() {
                step(&index.to_string(), entry, path, found);
            }
        }
        plain => found.push((path.clone(), plain.clone())),
    }
}

/// What an edit does at its path.
enum Edit {
    Set(Value),
    Remove,
    Insert(Value),
}

/// Give the IE, the member or the list entry at `path` the value `value`.
/// An optional IE that the message does not have is added by its `value`
/// or its `octets`, and `null` takes an optional IE or member out.
///
/// A path that selects nothing is an error, and the view is then as it
/// was.
pub fn set(view: &mut Value, path: &str, value: Value) -> Result<(), String> {
    edit(view, path, Edit::Set(value))
}

/// Take the IE, the member or the list entries at `path` out of `view`. An
/// optional IE that is taken out is `null`, as one that the message does
/// not have. A path that selects nothing is an error.
pub fn remove(view: &mut Value, path: &str) -> Result<(), String> {
    edit(view, path, Edit::Remove)
}

/// Add `value` to a list of `view`: before each entry that `path` selects,
/// or at the end for a path that ends with `-`.
pub fn insert(view: &mut Value, path: &str, value: Value) -> Result<(), String> {
    edit(view, path, Edit::Insert(value))
}

fn edit(view: &mut Value, path: &str, operation: Edit) -> Result<(), String> {
    let parts = segments(path)?;
    let (last, ie) = parts.split_last().ok_or("empty edit path")?;
    let of_an_ie = ["value", "octets"].iter().any(|name| same_name(name, last));
    let removes = matches!(&operation, Edit::Remove | Edit::Set(Value::Null));
    if removes && of_an_ie {
        return Err("an IE is removed, not its value or its octets".into());
    }
    let nothing = || format!("IE edit selected no field: {path}");
    let mut edited = view.clone();
    // An IE that the message does not have becomes an entry when its value
    // or its octets are set, and is no IE to take out.
    if of_an_ie && let Some(absent @ Value::Null) = at(&mut edited, ie) {
        *absent = Map::new().into();
    }
    if removes && matches!(at(&mut edited, &parts), Some(Value::Null)) {
        return Err(nothing());
    }
    // The view keeps the name of an IE that is taken out.
    let operation = match operation {
        Edit::Remove if ie.is_empty() => Edit::Set(Value::Null),
        operation => operation,
    };
    if apply(&mut edited, &parts, &operation)? == 0 {
        return Err(nothing());
    }
    *view = edited;
    Ok(())
}

/// The one value at `parts` under `value`, if the names and the positions
/// of `parts` lead to one.
fn at<'a>(value: &'a mut Value, parts: &[String]) -> Option<&'a mut Value> {
    let Some((part, rest)) = parts.split_first() else {
        return Some(value);
    };
    let child = match value {
        Value::Object(members) => {
            let name = key(members, part)?.clone();
            members.get_mut(&name)?
        }
        Value::Array(entries) => entries.get_mut(part.parse::<usize>().ok()?)?,
        _ => return None,
    };
    at(child, rest)
}

/// Apply `operation` at `parts` under `value`; the number of places that it
/// changed.
fn apply(value: &mut Value, parts: &[String], operation: &Edit) -> Result<usize, String> {
    let (part, rest) = parts.split_first().ok_or("empty edit path")?;
    if let Some(members) = value.as_object_mut() {
        if part == "*" {
            return Err("array selection used on an object".into());
        }
        let name = key(members, part).cloned();
        if rest.is_empty() {
            return match (operation, name) {
                // Null removes a member: one that is not there is not selected.
                (Edit::Set(Value::Null), None) => Ok(0),
                (Edit::Set(value), name) => {
                    members.insert(name.unwrap_or_else(|| part.clone()), value.clone());
                    Ok(1)
                }
                (Edit::Remove, name) => Ok(usize::from(
                    name.is_some_and(|name| members.remove(&name).is_some()),
                )),
                (Edit::Insert(_), _) => Err("insert adds to a list".into()),
            };
        }
        let child = name.and_then(|name| members.get_mut(&name));
        return child.map_or(Ok(0), |child| apply(child, rest, operation));
    }
    let Some(entries) = value.as_array_mut() else {
        return Ok(0);
    };
    if let (Edit::Insert(value), "-", []) = (operation, part.as_str(), rest) {
        entries.push(value.clone());
        return Ok(1);
    }
    let indexes: Vec<_> = match part.as_str() {
        "*" => (0..entries.len()).collect(),
        part => vec![
            part.parse::<usize>()
                .map_err(|_| "array index must be numeric")?,
        ],
    };
    if indexes.len() > OCCURRENCES {
        return Err(format!(
            "IE edit selects more than {OCCURRENCES} occurrences"
        ));
    }
    let mut changed = 0;
    for index in indexes.into_iter().rev() {
        if index >= entries.len() {
            continue;
        }
        if rest.is_empty() {
            match operation {
                Edit::Set(value) => entries[index] = value.clone(),
                Edit::Remove => {
                    entries.remove(index);
                }
                Edit::Insert(value) => entries.insert(index, value.clone()),
            }
            changed += 1;
        } else {
            changed += apply(&mut entries[index], rest, operation)?;
        }
    }
    Ok(changed)
}
