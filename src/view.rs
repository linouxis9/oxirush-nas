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

//! A message as JSON: its tree, its view, and the paths of their values.
//!
//! With the `serde` feature a message is a `serde_json::Value` in two forms,
//! which [`Nas5gsMessage`](crate::nas_5gs::Nas5gsMessage) and
//! [`NasEpsMessage`](crate::nas_eps::NasEpsMessage) have alike. A tree is
//! the compact form, in which a message is shown and written; a view edits
//! a message and keeps what it does not touch.
//!
//! | | Tree | View |
//! |---|------|------|
//! | From a message | [`to_tree()`] | [`to_view()`] |
//! | An IE is | its value, or `{"octets": "…"}` when it has no readable one | its `value` and its `octets` |
//! | It has | the `message-type` and the IEs that the message has | the fields of the header and every IE that the message can have, `null` for one that it has not |
//! | Back to a message | [`from_tree()`]: a message written from the tree alone | [`with_view()`]: this message, edited; [`from_view()`]: a message written from the view alone |
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//!
//! // 5GMM STATUS, cause #22
//! let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//!
//! // Its tree, then its view
//! println!("{}", status.to_tree());
//! println!("{:#}", status.to_view());
//! ```
//!
//! ```json
//! {"5gmm-cause":"congestion","message-type":"5gmm-status"}
//! ```
//!
//! ```json
//! {
//!   "5gmm-cause": {
//!     "octets": "16",
//!     "value": "congestion"
//!   },
//!   "extended-protocol-discriminator": {
//!     "value": 126
//!   },
//!   "message-type": {
//!     "value": "5gmm-status"
//!   },
//!   "security-header-type": {
//!     "value": "plain-nas-message"
//!   },
//!   "spare-half-octet": {
//!     "value": 0
//!   }
//! }
//! ```
//!
//! The [README](https://github.com/linouxis9/oxirush-nas#json) has an
//! example of each task: read an IE, change a value, add or remove an IE,
//! send octets as they are, write a message from its name, the message in
//! a container, the protocol configuration options, a protected message,
//! select and edit by path, the serde form.
//!
//! This page has the [paths](#paths) that the functions of this module
//! take, the [rules](#rules) of the two forms, the [notation](#values) of
//! each kind of value, the
//! [IE types that have a value](#ie-types-that-have-a-value) and the
//! [units](#units-of-the-protocol-configuration-options) of the protocol
//! configuration options.
//!
//! # Paths
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
//! A path is a JSON pointer. A name is its letters and its digits, whatever
//! their case and whatever is between them, as a view takes it: `/nas/5GMM
//! cause/value` and `/NAS/5gmm_cause/Value` are one path. A list selects by
//! position, a number as decimal writes it, and `*` is each entry of a list
//! or each member of a value. The message in a container is under the
//! `value` of the container, with the names of its own IEs.
//!
//! What is not there selects nothing: an optional IE that the message does
//! not have, which a view has as `null`, anything under it, and an optional
//! member that a value has as `null`. [`paths`] lists none of them. A name
//! that a view or a value does not have is an error, so a name that is
//! written wrong is not taken for an IE that is absent.
//!
//! ```
//! use oxirush_nas::{Nas5gsMessage, view};
//! use serde_json::json;
//!
//! // 5GMM STATUS, cause #22 "congestion".
//! let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//! let mut tree = status.to_view();
//! assert_eq!(view::select(&tree, "/nas/5gmm-cause/value")?, [&json!("congestion")]);
//!
//! view::set(&mut tree, "/nas/5gmm-cause/value", json!("illegal-ue"))?;
//! let edited = status.with_view(tree).unwrap();
//! assert_eq!(edited.encode().unwrap(), [0x7e, 0x00, 0x64, 0x03]);
//! # Ok::<(), String>(())
//! ```
//!
//! # Rules
//!
//! These are the rules of the two JSON forms of a message, its view and its
//! tree, which [`to_view()`](crate::nas_5gs::Nas5gsMessage::to_view),
//! [`with_view()`](crate::nas_5gs::Nas5gsMessage::with_view),
//! [`from_view()`](crate::nas_5gs::Nas5gsMessage::from_view),
//! [`to_tree()`](crate::nas_5gs::Nas5gsMessage::to_tree) and
//! [`from_tree()`](crate::nas_5gs::Nas5gsMessage::from_tree) read and write;
//! [`NasEpsMessage`](crate::nas_eps::NasEpsMessage) has the same methods.
//!
//! | Subject | Rule |
//! |---------|------|
//! | Names | The name that the specification gives an IE, in lower case with hyphens; `fg` of the codec reads `5g`, as in `5gs-registration-result`. A name is read by its letters and its digits, whatever their case and whatever is between them: `5GMM cause` and `5gmm_cause` are `5gmm-cause`. |
//! | `value` | What the IE means, in the notation of [Values](#values). A code is its name or its number. A number is also read as a `"0x…"` string, except in `message-type` and `security-header-type`, where a string is a name. |
//! | `octets` | The value part of the IE in hexadecimal. Octets that are written are sent whatever they are, and the length of the IE follows them. |
//! | Header | Each field is an entry with a `value` alone. A tree leaves out what its `message-type` decides: the protocol discriminator, and in a 5GMM message a plain security header type and a spare half octet of zero. A view that is written alone may leave out the `spare-half-octet`, which is then zero. |
//! | An IE that is not there | `null` in a view, left out of a tree. It selects nothing, and [`paths`] does not list it. |
//! | Unknown IEs | In neither form. `with_view()` keeps them; a message written alone has none. |
//! | Order | `serde_json` sorts the members of an object by name; with its `preserve_order` feature they are in the order of the message, header first. `view_names()` has that order either way. |
//! | Errors | Nothing that is written is ignored. These are errors: a name that the message or a value does not have; a value that its IE cannot carry; a `value` and `octets` that were both changed and disagree; a mandatory IE that is taken out or not written; octets of a length that the message does not give the IE; a `message-type` that the IEs are not those of; an edit under a `security-header` that keeps its code. |
//! | Not checked | The rules of a sender: `validate()` has them. |
//! | Octets after `with_view()` | Only what was edited changes, and a view that changes nothing gives the message back. |
//! | Octets after a tree | The message means the same and may have other octets: where a value does not decide its coding (the unit of a timer or of a bit rate, the length of a capability, the type of a partial tracking area identity list), where an IE had more octets than its value, and without the unknown IEs. The `octets` of an IE are the way to choose them. |
//! | EPS SERVICE REQUEST | A short header, no IEs and no `message-type` (TS 24.301 §8.2.25). Its view has the fields of that header: `protocol-discriminator`, `security-header-type`, `ksi-and-sequence-number`, whose value is a `ksi` and a `sequence-number`, and the two `octets` of `message-authentication-code`. [`NasServiceRequest::from_view()`](crate::nas_eps::NasServiceRequest::from_view) writes one alone. |
//!
//! # Values
//!
//! | What | Notation |
//! |------|----------|
//! | coded value (cause, type, mode, result, algorithm) | its name, `"congestion"`, `"initial-registration"`, `"nea2"`; its number where the specification names none, and for a reserved code that a receiver takes as another |
//! | PLMN identity | `"208-93"`, `"310-410"` |
//! | IMSI, IMEI, IMEISV, MSIN, routing indicator | a string of digits |
//! | TMSI, TAC, LAC, AMF region, set and pointer, SST, QFI, PDU session and bearer identities | a number |
//! | timer | its seconds, or `"deactivated"` |
//! | DNN, APN, network name | text |
//! | IP address | text, `"10.0.0.1"`, `"fe80::1"` |
//! | flags of a capability or an indication | `true` or `false` by the name of the flag |
//! | container of a NAS message | the view of that message, or its tree in a tree |
//! | protocol configuration options | the list of their [units](#units-of-the-protocol-configuration-options) |
//! | SD, MAC address, EUI-64, key, interface identifier, raw contents | hexadecimal |
//!
//! # IE types that have a value
//!
//! | | 5GS | EPS |
//! |---|-----|-----|
//! | IE types | 169 | 153 |
//! | with a `value` | 156 | 134 |
//! | with `octets` alone | 13 | 19 |
//!
//! A value is read and written: octets that the crate reads and would not
//! write back to the same value have no value, and are shown by their
//! `octets`.
//!
//! The 32 types with octets alone:
//!
//! | Kind | Types |
//! |------|-------|
//! | Octet strings | RAND, AUTN, AUTS, RES, ABBA, nonces, HashMME |
//! | Payloads of other protocols and of upper layers | EAP message, SMS, LPP and user data containers, ATSSS and port management containers, additional information |
//! | Getters and no constructor in the crate, or neither | ECS address, classmark 3, the A/Gb and Iu mode QoS, LCS client identity, UE coarse location information |
//! | Typed accessors and constructors that a view does not use | non-3GPP device information, whose constructor takes the type of the PDU session; negotiated LLC SAPI |
//! | No content | spare half octet |
//! | No NAS message has them as an IE | the two N1 mode NAS transparent containers |
//!
//! # Units of the protocol configuration options
//!
//! The value of the protocol configuration options and of the extended
//! protocol configuration options is the list of their units, in their
//! order (TS 24.008 §10.5.6.3). An identifier means one thing in a message
//! of the UE and another in a message of the network, so a unit is read by
//! the type of its message. A name of the other direction is refused, with
//! the unit that this direction has for the same identifier. A unit that
//! has a name is written by it, and not as a `container`.
//!
//! | Identifier | In a message of the UE | In a message of the network |
//! |------------|------------------------|-----------------------------|
//! | C021H, C023H, C223H, 8021H | `{"lcp": …}`, `{"pap": …}`, `{"chap": …}`, `{"ipcp": …}`: the [packet](#packets-of-the-configuration-protocols) of the configuration protocol | the same |
//! | 0001H | `"p-cscf-ipv6-address-request"` | `{"p-cscf-ipv6-address": "2001:db8::1"}` |
//! | 0002H | `"im-cn-subsystem-signalling-flag"` | the same |
//! | 0003H | `"dns-server-ipv6-address-request"` | `{"dns-server-ipv6-address": "2001:db8::53"}` |
//! | 0005H | `"ms-support-of-network-requested-bearer-control"` | `{"selected-bearer-control-mode": "ms-only"}`, or `"ms-nw"` |
//! | 000AH | `"ip-address-allocation-via-nas-signalling"` | |
//! | 000BH | `"ipv4-address-allocation-via-dhcpv4"` | |
//! | 000CH | `"p-cscf-ipv4-address-request"` | `{"p-cscf-ipv4-address": "10.0.0.2"}` |
//! | 000DH | `"dns-server-ipv4-address-request"` | `{"dns-server-ipv4-address": "8.8.8.8"}` |
//! | 000EH | `"msisdn-request"` | |
//! | 0010H | `"ipv4-link-mtu-request"` | `{"ipv4-link-mtu": 1400}` |
//! | 0011H | `"ms-support-of-local-address-in-tft"` | `"network-support-of-local-address-in-tft"` |
//! | 0012H | `"p-cscf-reselection-support"` | |
//! | 0015H | `"non-ip-link-mtu-request"` | `{"non-ip-link-mtu": 1358}` |
//! | any other | `{"container": {"identifier": 65280, "contents": "01"}}`: the number of the identifier and the contents in hexadecimal | the same |
//!
//! Where a cell is empty, the identifier has no name in that direction. It
//! is a `container` if the specification has it there, as the MSISDN that
//! the network gives under 000EH, and the options have their octets alone
//! if it does not.
//!
//! The options have a value where the units give their octets back: not
//! with a spare bit of the first octet set, not with a configuration
//! protocol other than PPP, and not with a unit that the specification
//! lets a receiver ignore (an address of another length). Those have their
//! `octets`, which are written as they are.
//!
//! ## Packets of the configuration protocols
//!
//! The contents of a unit of LCP, PAP, CHAP or IPCP are a packet of that
//! protocol (RFC 1661 §5): its `code`, its `identifier`, and its options or
//! its fields. The length of a packet, of an option and of a field is that
//! of what is written.
//!
//! | Protocol | `code` | Other members |
//! |----------|--------|---------------|
//! | `lcp` (RFC 1661) | `"configure-request"`, `"configure-ack"`, `"configure-nak"`, `"configure-reject"` | `options`, a list of `{"maximum-receive-unit": 1500}`, `{"authentication-protocol": "pap"}` or `"chap-md5"`, `{"magic-number": 305419896}`, `"protocol-field-compression"`, `"address-and-control-field-compression"` |
//! | `ipcp` (RFC 1332, RFC 1877) | the same four | `options`, a list of `{"ip-address": "10.0.0.1"}`, `{"primary-dns-server-address": "8.8.8.8"}`, `{"secondary-dns-server-address": "8.8.4.4"}`, `{"primary-nbns-server-address": …}`, `{"secondary-nbns-server-address": …}` |
//! | `pap` (RFC 1334) | `"authenticate-request"`; `"authenticate-ack"`, `"authenticate-nak"` | a request has the texts `peer-id` and `password`; an answer has the text `message`, or none |
//! | `chap` (RFC 1994) | `"challenge"`, `"response"`; `"success"`, `"failure"` | the first two have `value` in hexadecimal and the text `name`; the last two have the text `message` |
//!
//! A member that the code of a packet does not have is `null`, and may be
//! left out of what is written. An option that has no name here, or whose
//! data is not that of its name, is its type and its data:
//! `{"option": {"type": 2, "data": "002d"}}`.
//!
//! A packet has these names where they write its octets back. One with
//! another code (a Terminate-Request of LCP), with a length that is not
//! that of its unit, or with a peer-id, a password, a name or a message
//! that is no text, is its octets in hexadecimal: `{"ipcp": "05000004"}`.
//! A packet that has names is written by them, and so is an option.
//!
//! [`to_tree()`]: crate::nas_5gs::Nas5gsMessage::to_tree
//! [`from_tree()`]: crate::nas_5gs::Nas5gsMessage::from_tree
//! [`to_view()`]: crate::nas_5gs::Nas5gsMessage::to_view
//! [`with_view()`]: crate::nas_5gs::Nas5gsMessage::with_view
//! [`from_view()`]: crate::nas_5gs::Nas5gsMessage::from_view

use crate::common::readable::{named, same_name};
use crate::prelude::*;
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
    if !same_name(&parts.remove(0), ROOT) {
        return Err(format!(
            "{path} is not a path of a view: it starts with /{ROOT}"
        ));
    }
    Ok(parts)
}

/// The position that a segment is: a number as decimal writes it, without a
/// sign and without a zero before it.
fn position(part: &str) -> Option<usize> {
    let plain = !part.is_empty()
        && part.bytes().all(|digit| digit.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'));
    part.parse().ok().filter(|_| plain)
}

/// The name that `members` has for `name`, however it is written.
fn key<'a>(members: &'a Map<String, Value>, name: &str) -> Option<&'a String> {
    let names: Vec<_> = members.keys().collect();
    named(&names, name).copied()
}

/// The values at `path` in `view`, in the order of the view. An IE that the
/// message does not have and an optional member that a value does not have
/// select nothing, whether the path ends at them or goes on; a name that the
/// view or a value does not have is an error.
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
                    let index = position(&part)
                        .ok_or_else(|| format!("array index must be numeric at {path}"))?;
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
    selected.retain(|value| !value.is_null());
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
/// was. So is the name of an IE that the message cannot have, in a view
/// whose `message-type` names the message; in a view that does not say what
/// it is of, `with_view` or `from_view` refuses the name.
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
    if let Some(name) = parts.first() {
        known(view, name)?;
    }
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

/// Whether `view` can have the entry `name`: it has it, it does not say what
/// message it is of, or a message of the type that it names has that IE.
fn known(view: &Value, name: &str) -> Result<(), String> {
    use crate::common::view::names;
    use crate::{nas_5gs, nas_eps};
    let Some(members) = view.as_object() else {
        return Ok(());
    };
    let kind = key(members, "message-type")
        .and_then(|entry| members[entry].get("value")?.as_str())
        .filter(|_| key(members, name).is_none());
    let Some(kind) = kind else {
        return Ok(());
    };
    // The protocols have types of the same name, with other IEs.
    let of_the_type = [
        names::<nas_5gs::messages::Nas5gmmHeader, nas_5gs::Nas5gmmMessage>(&[kind]),
        names::<nas_5gs::messages::Nas5gsmHeader, nas_5gs::Nas5gsmMessage>(&[kind]),
        names::<nas_eps::messages::NasEmmHeader, nas_eps::NasEmmMessage>(&[kind]),
        names::<nas_eps::messages::NasEsmHeader, nas_eps::NasEsmMessage>(&[kind]),
    ]
    .concat();
    if of_the_type.is_empty() || named(&of_the_type, name).is_some() {
        return Ok(());
    }
    Err(format!("`{name}` is no IE of a message `{kind}`"))
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
        Value::Array(entries) => entries.get_mut(position(part)?)?,
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
        part => vec![position(part).ok_or("array index must be numeric")?],
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
