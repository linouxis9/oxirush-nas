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
//! {"message-type":"5gmm-status","5gmm-cause":"congestion"}
//! ```
//!
//! ```json
//! {
//!   "extended-protocol-discriminator": {
//!     "value": 126
//!   },
//!   "security-header-type": {
//!     "value": "plain-nas-message"
//!   },
//!   "spare-half-octet": {
//!     "value": 0
//!   },
//!   "message-type": {
//!     "value": "5gmm-status"
//!   },
//!   "5gmm-cause": {
//!     "value": "congestion",
//!     "octets": "16"
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
//! use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
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
//! # Ok::<(), oxirush_nas::view::Error>(())
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
//! | Unknown IEs | `unknown-ies` is the IEs that the table of the message has no place for, as one text: each by its octets in hexadecimal, its IEI first, with a space between two of them, in the order they came in: an IEI that the table does not have, and what a receiver ignores of one that it has (a repetition, an IE out of sequence, one whose value is not one of its type). A message that is written has them after its other IEs; `with_view()` keeps their places when the entry is as it was. |
//! | Order | The order of the message: the header first, then the IEs in the order of the message table, and in a value its members in the order of the clause. A view or a tree that is written may have them in any order. |
//! | Errors | Nothing that is written is ignored. These are errors: a name that the message or a value does not have; a value that its IE cannot carry, with the member and the limit that it breaks as the constructor of the IE says them (``pdu-session-status: entry 1: `pdu-session-identity` is 16, and is 1 to 15``); a `value` and `octets` that were both changed and disagree; a mandatory IE that is taken out or not written; octets of a length that the message does not give the IE; a `message-type` that the IEs are not those of; an edit under a `security-header` that keeps its code. |
//! | Not checked | The rules of a sender: `validate()` has them. |
//! | Octets after `with_view()` | Only what was edited changes, and a view that changes nothing gives the message back. |
//! | Octets after a tree | The message means the same ([`means_the_same()`]) and may have other octets, in three cases: its optional IEs are in the order of the message table, with the unknown IEs after them; and a value that says all that its octets mean without deciding them is written in one form (the unit of a timer of one octet and of the rates of a session AMBR, octets of zeros at the end of the flags of a capability, the partial lists of an EPS tracking area identity list). An IE whose value does not write it back is shown by its `octets`, which are the way to choose them. |
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
//! [`means_the_same()`]: crate::nas_5gs::Nas5gsMessage::means_the_same
//! [`from_tree()`]: crate::nas_5gs::Nas5gsMessage::from_tree
//! [`to_view()`]: crate::nas_5gs::Nas5gsMessage::to_view
//! [`with_view()`]: crate::nas_5gs::Nas5gsMessage::with_view
//! [`from_view()`]: crate::nas_5gs::Nas5gsMessage::from_view

use crate::prelude::*;
use oxirush_utils::tree::{self, Absent, Edit, Family, Next, Place, Removal, Root, Step};
use serde_json::Value;

pub use oxirush_utils::tree::{Error, ErrorKind};

/// The first segment of a path.
const ROOT: &str = "nas";

/// What a path knows of a place of a view.
#[derive(Clone, Default)]
enum Shape {
    /// The view of a message, with the `message-type` that it writes.
    View(Option<String>),
    /// The entry of an IE or of a field of the header: its `value` and its
    /// `octets`.
    Entry,
    /// A value, which the plain rules walk: the message in a container is a
    /// value too.
    #[default]
    Value,
}

/// The views of the NAS messages of both systems, as the paths of oxirush-utils
/// walk them: `/nas` stands for the view, and the segment after it names an IE
/// or a field of the header.
struct Views;

impl Family for Views {
    type Shape = Shape;

    fn root(&self) -> Root<'_> {
        Root {
            name: ROOT,
            stands_for: &[],
            required: true,
        }
    }

    fn start(&self, tree: &Value, _rooted: bool) -> Shape {
        let members = tree.as_object();
        let kind = members.and_then(|members| {
            let entry = tree::member(members, "message-type")?.1;
            Some(entry.get("value")?.as_str()?.to_owned())
        });
        Shape::View(kind)
    }

    fn step<'v>(
        &self,
        place: &Place<'v, Shape>,
        segment: &str,
        next: &mut Next<'v, Shape>,
    ) -> Result<Step<Shape>, Error> {
        let member = ["value", "octets"]
            .into_iter()
            .find(|member| tree::same_name(member, segment));
        let (Shape::Entry, Some(member), true) = (place.shape(), member, next.is_last()) else {
            return Ok(Step::Plain);
        };
        match next.edit() {
            Some(Edit::Remove) => Err(Error::new(
                ErrorKind::Refused,
                "",
                "an IE is removed, not its value or its octets",
            )),
            // An IE that the message does not have becomes an entry when its
            // value or its octets are written.
            Some(Edit::Set) if place.value().is_none_or(Value::is_null) => {
                next.absent(member, Shape::Value);
                Ok(Step::Taken)
            }
            _ => Ok(Step::Plain),
        }
    }

    fn member(&self, shape: &Shape, _name: &str, _value: Option<&Value>) -> Shape {
        match shape {
            Shape::View(_) => Shape::Entry,
            _ => Shape::Value,
        }
    }

    fn absent(&self, shape: &Shape, name: &str) -> Absent<Shape> {
        let Shape::View(Some(kind)) = shape else {
            return Absent::Unknown;
        };
        match can_have(kind, name) {
            true => Absent::Optional(Shape::Entry),
            false => Absent::Refused(Error::new(
                ErrorKind::NoSuchMember,
                "",
                format!("`{name}` is no IE of a message `{kind}`"),
            )),
        }
    }

    // A view keeps the name of an IE that is taken out.
    fn removal(&self, shape: &Shape) -> Removal {
        match shape {
            Shape::Entry => Removal::Null,
            _ => Removal::Take,
        }
    }
}

/// Whether a message of the type `kind` can have the entry `name`: one of the
/// messages of that name has it, or no message has that name.
fn can_have(kind: &str, name: &str) -> bool {
    use crate::common::view::names;
    use crate::{nas_5gs, nas_eps};
    // The protocols have types of the same name, with other IEs.
    let of_the_type = [
        names::<nas_5gs::messages::Nas5gmmHeader, nas_5gs::Nas5gmmMessage>(&[kind]),
        names::<nas_5gs::messages::Nas5gsmHeader, nas_5gs::Nas5gsmMessage>(&[kind]),
        names::<nas_eps::messages::NasEmmHeader, nas_eps::NasEmmMessage>(&[kind]),
        names::<nas_eps::messages::NasEsmHeader, nas_eps::NasEsmMessage>(&[kind]),
    ]
    .concat();
    of_the_type.is_empty() || tree::named(&of_the_type, name).is_some()
}

/// The values at `path` in `view`, in the order of the view. An IE that the
/// message does not have and an optional member that a value does not have
/// select nothing, whether the path ends at them or goes on; a name that the
/// view or a value does not have is an error.
///
/// # Errors
///
/// The errors of [`tree::select_in`]: a path that is none, more than 4096
/// values, a name that the value at its place does not have, a segment that
/// is no position in a list, a path that goes on into a number or a string,
/// and the name of an IE that the message of the view cannot have.
pub fn select<'a>(view: &'a Value, path: &str) -> Result<Vec<&'a Value>, Error> {
    tree::select_in(&Views, view, path)
}

/// Each value of `view` with the path that selects it, in the order of the
/// view. A list of plain values is one value, and an IE that the message
/// does not have has no path.
pub fn paths(view: &Value) -> Vec<(String, Value)> {
    tree::paths_in(&Views, view)
}

/// Give the IE, the member or the list entry at `path` the value `value`.
/// An optional IE that the message does not have is added by its `value`
/// or its `octets`, and `null` takes an optional IE, a member or an entry
/// out, as [`remove`] does.
///
/// # Errors
///
/// Those of [`select`], and a path that selects nothing: the view is then as
/// it was. In a view that does not say what it is of, `with_view` or
/// `from_view` refuses the name of an IE that its message cannot have.
pub fn set(view: &mut Value, path: &str, value: Value) -> Result<(), Error> {
    tree::set_in(&Views, view, path, value)
}

/// Take the IE, the member or the list entries at `path` out of `view`. An
/// optional IE that is taken out is `null`, as one that the message does
/// not have.
///
/// # Errors
///
/// Those of [`set`], and the `value` or the `octets` of an IE: an IE is
/// taken out whole.
pub fn remove(view: &mut Value, path: &str) -> Result<(), Error> {
    tree::remove_in(&Views, view, path)
}

/// Add `value` to a list of `view`: before each entry that `path` selects,
/// or at the end for a path that ends with `-`.
///
/// # Errors
///
/// Those of [`set`], and a path that ends at a member: an entry is added to
/// a list.
pub fn insert(view: &mut Value, path: &str, value: Value) -> Result<(), Error> {
    tree::insert_in(&Views, view, path, value)
}
