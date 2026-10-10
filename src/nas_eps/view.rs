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

//! The view of an EPS message and the values of its IEs.

use crate::common::readable::{from_value, same_name};
use crate::common::view::{self, Viewed, Visit};
use crate::common::{NasError, Result};
use crate::nas_eps::messages::{NasEmmHeader, NasEsmHeader, NasServiceRequest};
use crate::nas_eps::{
    NasEmmMessage, NasEmmMessageType, NasEpsMessage, NasEsmMessage, NasEsmMessageType,
};

impl Viewed for NasEpsMessage {
    fn ies(&self, visit: &mut Visit<'_>) {
        match self {
            Self::Emm(_, message) => message.body().ies(visit),
            Self::Esm(_, message) => message.body().ies(visit),
            Self::SecurityProtected(_, inner) => inner.ies(visit),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => {}
        }
    }

    fn blank(&self, name: &str) -> Option<serde_json::Value> {
        match self {
            Self::Emm(_, message) => message.body().blank(name),
            Self::Esm(_, message) => message.body().blank(name),
            Self::SecurityProtected(_, inner) => inner.blank(name),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => None,
        }
    }

    const FAMILIES: &'static [&'static str] = &["Emm", "Esm"];

    fn header_name(field: &str, number: u64) -> Option<serde_json::Value> {
        let number = u8::try_from(number).ok()?;
        match field {
            "security-header-type" => {
                let named = crate::nas_eps::NasEpsSecurityHeaderType::try_from(number).ok()?;
                crate::common::readable::to_value(&named).ok()
            }
            // The types of EMM and of ESM have no number in common.
            "message-type" => match NasEmmMessageType::try_from(number) {
                Ok(named) => crate::common::readable::to_value(&named).ok(),
                Err(_) => {
                    let named = NasEsmMessageType::try_from(number).ok()?;
                    crate::common::readable::to_value(&named).ok()
                }
            },
            _ => None,
        }
    }
}

impl NasEpsMessage {
    /// The view of the message: each of its IEs by the name TS 24.301 gives
    /// it, with its `value` and its `octets`.
    ///
    /// `octets` is the value part of the IE in hexadecimal. `value` is what
    /// the typed accessors of the IE decode from it, in the notation a
    /// reader expects: a coded value is its name (`"eps-attach"`) or, where
    /// the specification names none, its number; a PLMN identity is
    /// `"208-93"`; an IMSI or an IMEI is its digits; a TMSI or a TAC is a
    /// number and an APN is text; an IP address is its text; a container of
    /// a NAS message is the view of that message. What has no other
    /// notation stays hexadecimal. An IE that the crate does not decode,
    /// and octets that do not decode, have `octets` alone.
    ///
    /// Names are in lower case with hyphens; the fields of the header come
    /// first, with a `value` alone, and an optional IE that the message
    /// does not have is `null`. The unknown IEs of a message are not in
    /// it.
    ///
    /// A view is read through a security header: its entries are those of
    /// the plain message, and `security-header` beside them has the value
    /// of the header that protects it, with its `security-header-type`, its
    /// `message-authentication-code` and its `sequence-number`. A message
    /// that is ciphered has that header and its octets as
    /// `ciphered-message`. A SERVICE
    /// REQUEST has the fields of its short header (§8.2.25): its
    /// `security-header-type`, its `ksi-and-sequence-number`, whose value
    /// is a `ksi` and a `sequence-number`, and the octets of its
    /// `message-authentication-code`. EMM TRANSPORT, which has no IEs, has
    /// an empty view.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::NasEpsMessage;
    /// use serde_json::json;
    ///
    /// // ATTACH REJECT with EMM cause #3.
    /// let reject = NasEpsMessage::from_bytes(&[0x07, 0x44, 0x03]).unwrap();
    /// let mut view = reject.to_view();
    /// assert_eq!(view["message-type"]["value"], "attach-reject");
    /// assert_eq!(view["emm-cause"], json!({"value": "illegal-ue", "octets": "03"}));
    ///
    /// view["emm-cause"]["value"] = json!("congestion");
    /// let edited = reject.with_view(view).unwrap();
    /// assert_eq!(edited.to_bytes().unwrap(), [0x07, 0x44, 0x16]);
    /// ```
    pub fn to_view(&self) -> serde_json::Value {
        match self {
            Self::ServiceRequest(request) => request.view(),
            message => view::to_view(message),
        }
    }

    /// The message that an edited view of this one describes.
    ///
    /// An IE whose `value` was changed is encoded from it, and an IE whose
    /// `octets` were changed has those octets, whatever they are: its
    /// length follows. An IE that the view leaves out or has as `null` is
    /// taken out of the message, and an optional IE that the message does
    /// not have is added with the `value` or the `octets` that the view
    /// gives it. The message is otherwise this one, with its unknown IEs.
    ///
    /// A name is its letters and its digits, whatever their case and
    /// whatever is between them, and a number is also read as a `"0x…"`
    /// string. Nothing that the view says is
    /// ignored: a name that does not exist, a member that an IE or a value
    /// does not have, a value that its IE cannot carry or that the crate
    /// does not encode, and `octets` and a `value` that were both changed
    /// and disagree are errors.
    ///
    /// A value says what an IE means, not how it is coded. The encoder
    /// chooses what the value does not show, such as the unit of a timer
    /// or the type of a partial tracking area identity list; the octets
    /// are the way to choose it. A coded value is written by its name or
    /// by its number, which are two ways to write one code.
    ///
    /// The message authentication code of a security header is that of the
    /// octets it was computed over: an edit of the message under the header
    /// that keeps the code is an error, and the code that the view writes
    /// in `security-header` is taken as it is.
    ///
    /// The message that comes back is one that [`Self::to_bytes`] encodes,
    /// as this one is: an edit that makes a message that has no octets, such
    /// as octets of a length that the message does not give the IE, is an
    /// error here. What the message says is not checked against the rules of
    /// a sender, which `validate()` has.
    pub fn with_view(&self, view: serde_json::Value) -> Result<Self> {
        let edited = match self {
            Self::ServiceRequest(request) => {
                let request = request.written(view, false);
                request.map(Self::ServiceRequest)
            }
            message => view::with_view(message, view),
        }
        .map_err(NasError::EncodingError)?;
        // A message that the view leaves as it is comes back as it is.
        if edited != *self {
            edited.to_bytes()?;
        }
        Ok(edited)
    }

    /// The message that a view describes alone, which its `message-type`
    /// names: an EMM or an ESM message, as [`NasEmmMessageType::from_view`]
    /// and [`NasEsmMessageType::from_view`] make it of a type that is known.
    /// A view without a `message-type` that has a `ksi-and-sequence-number`
    /// is that of a SERVICE REQUEST, as [`NasServiceRequest::from_view`]
    /// reads it.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::NasEpsMessage;
    /// use serde_json::json;
    ///
    /// let reject = NasEpsMessage::from_view(json!({
    ///     "protocol-discriminator": {"value": 7},
    ///     "security-header-type": {"value": "plain-nas-message"},
    ///     "message-type": {"value": "attach-reject"},
    ///     "emm-cause": {"value": "congestion"},
    /// }))
    /// .unwrap();
    /// assert_eq!(reject.to_bytes().unwrap(), [0x07, 0x44, 0x16]);
    /// ```
    pub fn from_view(view: serde_json::Value) -> Result<Self> {
        let Some(named) = view::message_type::<Self>(&view) else {
            let short = (view.as_object().into_iter().flatten())
                .any(|(name, _)| same_name(name, "ksi-and-sequence-number"));
            return match short {
                true => NasServiceRequest::from_view(view),
                false => Err(NasError::EncodingError(
                    "the `message-type` of the view names the message".into(),
                )),
            };
        };
        let is = |kind: &dyn std::fmt::Debug| same_name(&format!("{kind:?}"), &named);
        let mut emm = (0..=u8::MAX).filter_map(|octet| NasEmmMessageType::try_from(octet).ok());
        let mut esm = (0..=u8::MAX).filter_map(|octet| NasEsmMessageType::try_from(octet).ok());
        if let Some(kind) = emm.find(|kind| is(kind)) {
            return kind.from_view(view);
        }
        match esm.find(|kind| is(kind)) {
            Some(kind) => kind.from_view(view),
            None => Err(NasError::EncodingError(format!("no message `{named}`"))),
        }
    }
}

/// The names of the fields of the short header of a SERVICE REQUEST.
const SERVICE_REQUEST: [&str; 4] = [
    "protocol-discriminator",
    "security-header-type",
    "ksi-and-sequence-number",
    "message-authentication-code",
];

impl NasServiceRequest {
    /// The SERVICE REQUEST that a view describes alone: every field of its
    /// short header, as [`NasEpsMessage::to_view`] has them. The
    /// `ksi-and-sequence-number` has its `value` or its `octets`, and the
    /// `message-authentication-code` its two `octets`.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::NasServiceRequest;
    /// use serde_json::json;
    ///
    /// let request = NasServiceRequest::from_view(json!({
    ///     "protocol-discriminator": {"value": 7},
    ///     "security-header-type": {"value": "service-request"},
    ///     "ksi-and-sequence-number": {"value": {"ksi": 1, "sequence-number": 5}},
    ///     "message-authentication-code": {"octets": "abcd"},
    /// }))
    /// .unwrap();
    /// assert_eq!(request.to_bytes().unwrap(), [0xc7, 0x25, 0xab, 0xcd]);
    /// ```
    pub fn from_view(view: serde_json::Value) -> Result<NasEpsMessage> {
        let request = Self::new(0, 0).written(view, true);
        (request.map(NasEpsMessage::ServiceRequest)).map_err(NasError::EncodingError)
    }

    fn view(&self) -> serde_json::Value {
        let octet = self.ksi_and_sequence_number;
        let header_type = match self.security_header_type {
            12 => serde_json::json!("service-request"),
            other => other.into(),
        };
        serde_json::json!({
            "protocol-discriminator": {"value": 7},
            "security-header-type": {"value": header_type},
            "ksi-and-sequence-number": {
                "value": {"ksi": octet >> 5, "sequence-number": octet & 0x1f},
                "octets": format!("{octet:02x}"),
            },
            "message-authentication-code": {
                "octets": format!("{:04x}", self.message_authentication_code),
            },
        })
    }

    /// This request as `view` edits it, or with `alone` the one that has
    /// nothing but what the view writes.
    fn written(&self, view: serde_json::Value, alone: bool) -> std::result::Result<Self, String> {
        let serde_json::Value::Object(view) = view else {
            return Err(format!("{view} is not a view: an object of IEs by name"));
        };
        let before = self.view();
        let mut request = self.clone();
        let mut left: Vec<_> = SERVICE_REQUEST.to_vec();
        for (name, written) in view {
            let Some(at) = left.iter().position(|field| same_name(field, &name)) else {
                return Err(format!("`{name}` is no IE of the message"));
            };
            // An entry that is null is one left out.
            if written.is_null() {
                continue;
            }
            let field = left.swap_remove(at);
            let [value, octets] =
                view::entry(written).map_err(|error| format!("{name}: {error}"))?;
            // What the view has as the message does is not written again.
            let changed = |member: &str, written: Option<serde_json::Value>| {
                written.filter(|written| alone || before[field].get(member) != Some(written))
            };
            let (value, octets) = (changed("value", value), changed("octets", octets));
            let refused = |reason: String| format!("{name}: {reason}");
            let bytes = |octets: &serde_json::Value| {
                let bytes = octets.as_str().and_then(|octets| hex::decode(octets).ok());
                bytes.ok_or_else(|| refused(format!("{octets} is not octets in hexadecimal")))
            };
            match (field, value, octets) {
                ("protocol-discriminator", Some(value), None) => {
                    if from_value::<u8>(&value) != Ok(7) {
                        return Err(refused(format!(
                            "{value} is not 7, the discriminator of EMM"
                        )));
                    }
                }
                ("security-header-type", Some(value), None) => {
                    let named = value
                        .as_str()
                        .is_some_and(|name| same_name(name, "service-request"));
                    request.security_header_type = match named {
                        true => 12,
                        false => from_value(&value).map_err(refused)?,
                    };
                    if !(12..=15).contains(&request.security_header_type) {
                        return Err(refused(format!(
                            "{value} is not service-request, or 12 to 15"
                        )));
                    }
                }
                ("ksi-and-sequence-number", value, octets) => {
                    let of_octets = match octets.as_ref().map(bytes).transpose()?.as_deref() {
                        Some([octet]) => Some(*octet),
                        Some(_) => return Err(refused("its octets are one octet".into())),
                        None => None,
                    };
                    let of_value = match &value {
                        Some(value) => {
                            let mut parts = [0_u8; 2];
                            for (part, written) in view::members(value).map_err(refused)? {
                                let known = ["ksi", "sequence-number"];
                                let at = known.iter().position(|known| same_name(known, part));
                                let at =
                                    at.ok_or_else(|| refused(format!("no member `{part}`")))?;
                                parts[at] = from_value(written).map_err(refused)?;
                            }
                            if parts[0] > 7 || parts[1] > 31 {
                                return Err(refused(
                                    "a ksi is 0 to 7 and a sequence-number 0 to 31".into(),
                                ));
                            }
                            Some(parts[0] << 5 | parts[1])
                        }
                        None => None,
                    };
                    request.ksi_and_sequence_number = match (of_value, of_octets) {
                        (Some(value), Some(octets)) if value != octets => {
                            return Err(refused(
                                "the octets and the value that are written disagree".into(),
                            ));
                        }
                        (Some(octet), _) | (None, Some(octet)) => octet,
                        (None, None) => request.ksi_and_sequence_number,
                    };
                }
                ("message-authentication-code", None, Some(octets)) => {
                    let Ok(mac) = <[u8; 2]>::try_from(bytes(&octets)?) else {
                        return Err(refused("its octets are two octets".into()));
                    };
                    request.message_authentication_code = u16::from_be_bytes(mac);
                }
                (_, None, None) => {}
                ("message-authentication-code", ..) => {
                    return Err(refused("it has its `octets` alone".into()));
                }
                _ => return Err(refused("it is the header: it has a `value` alone".into())),
            }
        }
        match left.first().filter(|_| alone) {
            Some(field) => Err(format!("`{field}` is not written")),
            None => Ok(request),
        }
    }
}

/// What the type of an EPS message decides of its header, as a tree leaves
/// it out: the protocol discriminator of its sublayer, and for EMM a plain
/// security header type. A message without a `message-type` is a SERVICE
/// REQUEST, whose security header type is its own.
pub(crate) fn decided(
    _container: Option<&str>,
    kind: Option<&str>,
) -> std::result::Result<Vec<(&'static str, serde_json::Value)>, String> {
    use serde_json::json;
    let Some(kind) = kind else {
        return Ok(vec![
            ("protocol-discriminator", json!(7)),
            ("security-header-type", json!("service-request")),
        ]);
    };
    let is = |known: &dyn std::fmt::Debug| same_name(&format!("{known:?}"), kind);
    let mut emm = (0..=u8::MAX).filter_map(|octet| NasEmmMessageType::try_from(octet).ok());
    let mut esm = (0..=u8::MAX).filter_map(|octet| NasEsmMessageType::try_from(octet).ok());
    if emm.any(|known| is(&known)) {
        return Ok(vec![
            ("protocol-discriminator", json!(7)),
            ("security-header-type", json!("plain-nas-message")),
        ]);
    }
    match esm.any(|known| is(&known)) {
        true => Ok(vec![("protocol-discriminator", json!(2))]),
        false => Err(format!("no message `{kind}`")),
    }
}

impl NasEpsMessage {
    /// This message as a tree: its `message-type` and its IEs by name, each
    /// with its value as [`Self::to_view`] reads it, or with its `octets`
    /// when it has no readable value.
    ///
    /// A tree is a view written shortly. What the type of the message
    /// decides is left out (the protocol discriminator, and a plain security
    /// header type), and so are the optional IEs that the message does not
    /// have. The message in a container is its own tree, and the header that
    /// protects a message is its `security-header`. A SERVICE REQUEST has no
    /// `message-type`.
    ///
    /// A tree says what a message means, and a message is written from it:
    /// an IE whose value the crate reads and does not encode is shown by its
    /// octets. Where a value does not decide how it is coded, as the unit of
    /// a timer or the length of a capability, the message that is written
    /// from the tree means the same and may have other octets:
    /// [`Self::to_view`] has the octets of each IE beside its value.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::NasEpsMessage;
    /// use serde_json::json;
    ///
    /// // ATTACH REJECT with cause #22.
    /// let reject = NasEpsMessage::from_bytes(&[0x07, 0x44, 0x16]).unwrap();
    /// let tree = json!({"message-type": "attach-reject", "emm-cause": "congestion"});
    /// assert_eq!(reject.to_tree(), tree);
    /// assert_eq!(NasEpsMessage::from_tree(tree).unwrap(), reject);
    /// ```
    pub fn to_tree(&self) -> serde_json::Value {
        let view = self.to_view();
        let built = |tree: &serde_json::Value| {
            let written = Self::from_tree(tree.clone()).and_then(|message| message.to_bytes());
            written.map(|_| ()).map_err(|error| match error {
                NasError::EncodingError(reason) => reason,
                other => other.to_string(),
            })
        };
        view::written_from(view::to_tree(&view, None, &decided), &view, &built)
    }

    /// The message that a tree writes, as [`Self::to_tree`] shows one: its
    /// `message-type` names it, and each other member is an IE or a field of
    /// its header with its value, or `{"octets": "…"}` for the octets of an
    /// IE as they are sent. What the type of the message decides of its
    /// header is given where the tree leaves it out, and nothing else is:
    /// the tree is read as [`Self::from_view`] reads a view, so that a
    /// mandatory IE that it leaves out is an error.
    pub fn from_tree(tree: serde_json::Value) -> Result<Self> {
        let view = view::from_tree(&tree, None, &decided).map_err(NasError::EncodingError)?;
        Self::from_view(view)
    }
}

impl NasEmmMessageType {
    /// The message of this type that a view describes alone.
    ///
    /// The view has every field of the header with its `value`, every
    /// mandatory IE and the optional IEs that the message has, each with
    /// its `value` or its `octets`. It is read as
    /// [`NasEpsMessage::with_view`] reads one: nothing that it says is
    /// ignored, and a field of the header or a mandatory IE that it leaves
    /// out is an error. A member that a `value` leaves out is zero. The
    /// message in a container is the view that is the `value` of the
    /// container, named by its `message-type`. A DETACH REQUEST is the one
    /// from the UE if the view is one of it, else the one to the UE.
    ///
    /// The message is what the view writes, and [`NasEpsMessage::to_bytes`]
    /// says whether it has octets: an IE that is written by its `octets`
    /// has them whatever their length, which encoding checks against the
    /// lengths that the message gives the IE.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::NasEmmMessageType;
    /// use serde_json::json;
    ///
    /// let reject = NasEmmMessageType::AttachReject
    ///     .from_view(json!({
    ///         "protocol-discriminator": {"value": 7},
    ///         "security-header-type": {"value": "plain-nas-message"},
    ///         "message-type": {"value": "attach-reject"},
    ///         "emm-cause": {"value": "congestion"},
    ///     }))
    ///     .unwrap();
    /// assert_eq!(reject.to_bytes().unwrap(), [0x07, 0x44, 0x16]);
    /// ```
    pub fn from_view(self, view: serde_json::Value) -> Result<NasEpsMessage> {
        let from = |kind: &str| view::from_view(&["Emm"], kind, view.clone());
        if let Err(error) = view::typed::<NasEpsMessage>(&format!("{self:?}"), &view) {
            return Err(NasError::EncodingError(error));
        }
        match self {
            // A view of neither message is refused as each of the two.
            Self::DetachRequest => from("DetachRequestFromUe").or_else(|from_ue| {
                let to_ue = from("DetachRequestToUe");
                to_ue.map_err(|to_ue| format!("from the UE: {from_ue}; to the UE: {to_ue}"))
            }),
            _ => from(&format!("{self:?}")),
        }
        .map_err(NasError::EncodingError)
    }

    /// The names of the entries that the view of a message of this type
    /// has: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none. DETACH REQUEST has the names of its two
    /// messages, the one from the UE and the one to it.
    pub fn view_names(self) -> Vec<String> {
        match self {
            Self::DetachRequest => view::names::<NasEmmHeader, NasEmmMessage>(&[
                "DetachRequestFromUe",
                "DetachRequestToUe",
            ]),
            _ => view::names::<NasEmmHeader, NasEmmMessage>(&[&format!("{self:?}")]),
        }
    }

    /// The view of a message of this type that has nothing written yet,
    /// which [`Self::from_view`] fills: the fields of its header, each
    /// mandatory IE with the `octets` of one without content, and `null`
    /// for each optional IE. It says which entries a view has to write, and
    /// is not a message to send: a field is zero and an IE is empty. `None`
    /// for a type that the crate has no message of. DETACH REQUEST has the
    /// view of the message from the UE.
    pub fn blank_view(self) -> Option<serde_json::Value> {
        let kind = match self {
            Self::DetachRequest => "DetachRequestFromUe".to_string(),
            _ => format!("{self:?}"),
        };
        let mut blank = view::blank_view::<NasEpsMessage>(&["Emm"], &kind)?;
        // The message from the UE is not named as its type is: the view
        // says the type that it is of.
        if matches!(self, Self::DetachRequest) {
            let named = crate::common::readable::to_value(&self).ok()?;
            blank["message-type"]["value"] = named;
        }
        Some(blank)
    }
}

impl NasEsmMessageType {
    /// The message of this type that a view describes alone, as
    /// [`NasEmmMessageType::from_view`] has it.
    pub fn from_view(self, view: serde_json::Value) -> Result<NasEpsMessage> {
        let kind = format!("{self:?}");
        view::typed::<NasEpsMessage>(&kind, &view)
            .and_then(|()| view::from_view(&["Esm"], &kind, view))
            .map_err(NasError::EncodingError)
    }

    /// The names of the entries that the view of a message of this type
    /// has: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn view_names(self) -> Vec<String> {
        view::names::<NasEsmHeader, NasEsmMessage>(&[&format!("{self:?}")])
    }

    /// The view of a message of this type that has nothing written yet, as
    /// [`NasEmmMessageType::blank_view`] has it.
    pub fn blank_view(self) -> Option<serde_json::Value> {
        view::blank_view::<NasEpsMessage>(&["Esm"], &format!("{self:?}"))
    }
}

// ── Values ─────────────────────────────────────────────────────────────────
//
// Each is what the typed accessors of the IE return, and is encoded back
// by the matching constructor or setters.

use crate::common::ts24301::KeySetIdentifier;
use crate::common::view::{
    Code, built_ie, code_ie, container_ie, decoded_ie, fields_ie, named_ie, numbers, octets,
    shared_ies, timer_ie, write_code,
};
use crate::nas_eps::ie::*;
use crate::nas_eps::types::*;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// The IEs that TS 24.501 and TS 24.301 have alike.
shared_ies!();

// A container of a plain NAS message: the view of the message.
container_ie!(
    NasEsmMessageContainer: NasEpsMessage,
    |ie| ie.decode_as_esm_message().ok(),
    |message| NasEsmMessageContainer::from_esm_message(message).ok()
);
container_ie!(
    NasReplayedNasMessageContainer: NasEpsMessage,
    |ie| ie.decode_as_emm_message().ok(),
    |message| NasReplayedNasMessageContainer::from_emm_message(message).ok()
);

// One coded value.
code_ie!(
    NasEmmCause,
    EmmCause,
    |ie| EmmCause::from_u8_strict(ie.cause_raw()),
    NasEmmCause::from_cause
);
code_ie!(
    NasEsmCause,
    EsmCause,
    |ie| EsmCause::from_u8_strict(ie.cause_raw()),
    NasEsmCause::from_cause
);
code_ie!(
    NasEpsAttachType,
    AttachType,
    |ie| ie.attach_type_strict(),
    NasEpsAttachType::from_attach_type
);
code_ie!(
    NasEpsAttachResult,
    AttachResult,
    |ie| ie.attach_result(),
    NasEpsAttachResult::from_attach_result
);
code_ie!(
    NasEpsUpdateResult,
    UpdateResult,
    |ie| ie.update_result(),
    NasEpsUpdateResult::from_update_result
);
code_ie!(
    NasServiceType,
    ServiceType,
    |ie| ie.service_type_strict(),
    NasServiceType::from_service_type
);
code_ie!(
    NasIdentityType,
    IdentityTypeValue,
    |ie| ie.identity_type_strict(),
    NasIdentityType::from_identity_type
);
code_ie!(
    NasPdnType,
    PdnType,
    |ie| ie.pdn_type_strict(),
    NasPdnType::from_pdn_type
);
code_ie!(
    NasAdditionalUpdateResult,
    AdditionalUpdateResult,
    |ie| ie.result(),
    NasAdditionalUpdateResult::from_result
);
code_ie!(
    NasSmsServicesStatus,
    SmsServicesStatus,
    |ie| ie.status(),
    NasSmsServicesStatus::from_status
);
code_ie!(
    NasGenericMessageContainerType,
    GenericMessageContainerType,
    |ie| ie.container_type(),
    NasGenericMessageContainerType::from_container_type
);
code_ie!(
    NasRadioPriority,
    RadioPriorityLevel,
    |ie| RadioPriorityLevel::from_u8_strict(ie.priority_level_raw()),
    NasRadioPriority::from_priority_level
);
named_ie!(
    NasNetworkDaylightSavingTime,
    DaylightSavingAdjustment,
    |ie| ie.adjustment(),
    NasNetworkDaylightSavingTime::from_adjustment
);
named_ie!(
    NasRequestedWusAssistanceInformation,
    UePagingProbability,
    |ie| ie.paging_probability(),
    NasRequestedWusAssistanceInformation::from_paging_probability
);
named_ie!(
    NasNegotiatedWusAssistanceInformation,
    UePagingProbability,
    |ie| ie.paging_probability(),
    NasNegotiatedWusAssistanceInformation::from_paging_probability
);
named_ie!(
    NasDrxParameterInNbS1Mode,
    NbS1DrxValue,
    |ie| ie.drx_value(),
    NasDrxParameterInNbS1Mode::from_drx_value
);
named_ie!(
    NasNegotiatedDrxParameterInNbS1Mode,
    NbS1DrxValue,
    |ie| ie.drx_value(),
    NasNegotiatedDrxParameterInNbS1Mode::from_drx_value
);
named_ie!(
    NasEpsAdditionalRequestResult,
    PagingRestrictionDecision,
    |ie| ie.paging_restriction_decision(),
    NasEpsAdditionalRequestResult::from_paging_restriction_decision
);
named_ie!(
    NasNotificationIndicator,
    NotificationIndicatorValue,
    |ie| ie.indicator(),
    NasNotificationIndicator::from_indicator
);

// The fields of an octet.
fields_ie!(NasEpsUpdateType {
    "update-type":
        |ie| Code::of(ie.update_type_strict(), ie.update_type_raw()),
        |ie, code: Code<UpdateType>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_update_type(name);
            },
            |ie| ie.update_type_raw(),
        );
    "active": |ie| ie.is_active(), |ie, active: bool| {
        ie.set_active(active);
    };
});
fields_ie!(NasControlPlaneServiceType {
    "service-type":
        |ie| Code::of(ie.service_type_strict(), ie.service_type_raw()),
        |ie, code: Code<ControlPlaneServiceType>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_service_type(name);
            },
            |ie| ie.service_type_raw(),
        );
    "active": |ie| ie.is_active(), |ie, active: bool| {
        ie.set_active(active);
    };
});
// The same code names a type of detach in each direction, so both read.
fields_ie!(NasDetachType {
    "ue-detach-kind":
        |ie| Code::of(UeDetachKind::from_u8_strict(ie.value), ie.detach_type_raw()),
        |ie, code: Code<UeDetachKind>| write_code(
            ie,
            code,
            |ie, name| {
                ie.value = NasDetachType::from_ue_detach_kind(name, ie.is_switch_off()).value;
            },
            |ie| ie.detach_type_raw(),
        );
    "network-detach-kind":
        |ie| Code::of(NetworkDetachKind::from_u8_strict(ie.value), ie.detach_type_raw()),
        |ie, code: Code<NetworkDetachKind>| write_code(
            ie,
            code,
            |ie, name| {
                ie.value = NasDetachType::from_network_detach_kind(name).value | (ie.value & 0x08);
            },
            |ie| ie.detach_type_raw(),
        );
    "switch-off": |ie| ie.is_switch_off(), |ie, on: bool| {
        ie.value = (ie.value & !0x08) | (u8::from(on) << 3);
    };
});
fields_ie!(NasSelectedNasSecurityAlgorithms {
    "ciphering":
        |ie| Code::of(ie.ciphering(), ie.ciphering_raw()),
        |ie, code: Code<CipheringAlgorithm>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_ciphering(name);
            },
            |ie| ie.ciphering_raw(),
        );
    "integrity":
        |ie| Code::of(ie.integrity(), ie.integrity_raw()),
        |ie, code: Code<IntegrityAlgorithm>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_integrity(name);
            },
            |ie| ie.integrity_raw(),
        );
});
fields_ie!(NasUniversalTimeAndLocalTimeZone {
    "year": |ie| ie.year(), |ie, year: u8| {
        ie.set_year(year);
    };
    "month": |ie| ie.month(), |ie, month: u8| {
        ie.set_month(month);
    };
    "day": |ie| ie.day(), |ie, day: u8| {
        ie.set_day(day);
    };
    "hour": |ie| ie.hour(), |ie, hour: u8| {
        ie.set_hour(hour);
    };
    "minute": |ie| ie.minute(), |ie, minute: u8| {
        ie.set_minute(minute);
    };
    "second": |ie| ie.second(), |ie, second: u8| {
        ie.set_second(second);
    };
    "time-zone-quarter-hours": |ie| ie.timezone_quarter_hours(), |ie, quarters: i8| {
        ie.set_timezone_quarter_hours(quarters);
    };
} exact);
decoded_ie!(
    NasNonCurrentNativeNasKeySetIdentifier: KeySetIdentifier,
    |ie| Some(ie.key_set_identifier()),
    |ie, identifier| {
        let bits = identifier.as_u8().ok()?;
        Some(ie.clone().with_ksi(bits).with_tsc(bits & 0x08 != 0))
    }
);

// The flags of an indication, by the names of its accessors.
built_ie!(
    NasAdditionalUpdateType,
    |sms_only, signalling_active, ciot| Some(Self::from_fields(sms_only, signalling_active, ciot)),
    {
        sms_only: bool,
        signalling_active: bool,
        preferred_ciot_behavior: PreferredCiotBehavior = |ie| ie.preferred_ciot_behavior(),
    }
);
built_ie!(NasConnectivityType, |lipa| Some(Self::from_lipa(lipa)), { is_lipa: bool });
built_ie!(
    NasControlPlaneOnlyIndication,
    |only: bool| only.then(Self::control_plane_only),
    { is_control_plane_only: bool }
);
built_ie!(NasCsfbResponse, |accepted| Some(Self::from_accepted(accepted)), {
    accepted: bool = |ie| ie.accepted()
});
built_ie!(
    NasEsmInformationTransferFlag,
    |required| Some(Self::from_required(required)),
    { is_required: bool }
);
built_ie!(
    NasExtendedEmmCause,
    |eutran, optimization, nb_iot, satellite| {
        Some(Self::from_flags(eutran, optimization, nb_iot, satellite))
    },
    {
        eutran_not_allowed: bool,
        eps_optimization_not_supported: bool,
        nb_iot_not_allowed: bool,
        satellite_eutran_not_allowed: bool,
    }
);
built_ie!(NasLcsIndicator, |mt_lr: bool| mt_lr.then(Self::mt_lr), { is_mt_lr: bool });
built_ie!(NasOldGutiType, |mapped| Some(Self::from_mapped(mapped)), { is_mapped: bool });
built_ie!(NasPagingIdentity, |tmsi| Some(Self::from_tmsi(tmsi)), { is_tmsi: bool });
built_ie!(NasTmsiStatus, |valid| Some(Self::from_valid_tmsi(valid)), { has_valid_tmsi: bool });
built_ie!(
    NasUeCoarseLocationInformationRequest,
    |requested| Some(Self::from_requested(requested)),
    { requested: bool }
);
built_ie!(
    NasUeRadioCapabilityIdAvailability,
    |available| Some(Self::from_available(available)),
    { is_available: bool = |ie| ie.is_available() }
);
built_ie!(
    NasUeRadioCapabilityIdRequest,
    |requested| Some(Self::from_requested(requested)),
    { is_requested: bool = |ie| ie.is_requested() }
);
built_ie!(
    NasUeRadioCapabilityInformationUpdateNeeded,
    |needed| Some(Self::from_update_needed(needed)),
    { update_needed: bool }
);
built_ie!(
    NasVoiceDomainPreferenceAndUeUsageSetting,
    |preference, data_centric| Some(Self::from_fields(preference, data_centric)),
    {
        voice_domain_preference: VoiceDomainPreference = |ie| ie.voice_domain_preference(),
        data_centric: bool = |ie| ie.data_centric(),
    }
);
built_ie!(NasTransactionIdentifier, Self::from_ti, {
    ti_flag: bool = |ie| ie.ti_flag(),
    ti_value: u8 = |ie| ie.ti_value(),
});
built_ie!(NasDrxParameter, Self::from_fields, {
    split_pg_cycle_code: u8 = |ie| ie.split_pg_cycle_code(),
    s1_drx_value: S1DrxValue = |ie| ie.s1_drx_value(),
    split_on_ccch: bool = |ie| ie.split_on_ccch(),
    non_drx_timer: u8 = |ie| ie.non_drx_timer(),
});
built_ie!(NasDisasterRoamingWaitRange, Self::from_range, {
    min_seconds: u64 = |ie| ie.min_seconds(),
    max_seconds: u64 = |ie| ie.max_seconds(),
});
built_ie!(NasDisasterReturnWaitRange, Self::from_range, {
    min_seconds: u64 = |ie| ie.min_seconds(),
    max_seconds: u64 = |ie| ie.max_seconds(),
});
// The unit of the extended T3412 value says whether the IE counts at all,
// so it reads with the count and not as seconds.
built_ie!(
    NasT3412ExtendedValue,
    |unit, count| Some(Self::from_unit_value(unit, count)),
    {
        unit: GprsTimer3Unit = |ie| ie.unit(),
        timer_value: u8 = |ie| ie.timer_value(),
    }
);

/// The algorithms an octet of a capability has the bits of, by number.
fn supported<T>(ie: &T, supports: fn(&T, u8) -> bool, algorithms: u8) -> Vec<u16> {
    (0..algorithms)
        .filter(|algorithm| supports(ie, *algorithm))
        .map(u16::from)
        .collect()
}

fields_ie!(NasUeNetworkCapability {
    "eea": |ie| supported(ie, Self::supports_eea, 8), |ie, algorithms: Vec<u16>| {
        (0..8).for_each(|algorithm| ie.set_eea(algorithm, algorithms.contains(&algorithm.into())));
    };
    "eia": |ie| supported(ie, Self::supports_eia, 8), |ie, algorithms: Vec<u16>| {
        (0..8).for_each(|algorithm| ie.set_eia(algorithm, algorithms.contains(&algorithm.into())));
    };
} flags);
fields_ie!(NasReplayedUeSecurityCapabilities {
    "eea": |ie| supported(ie, Self::supports_eea, 8), |ie, algorithms: Vec<u16>| {
        (0..8).for_each(|algorithm| ie.set_eea(algorithm, algorithms.contains(&algorithm.into())));
    };
    "eia": |ie| supported(ie, Self::supports_eia, 8), |ie, algorithms: Vec<u16>| {
        (0..8).for_each(|algorithm| ie.set_eia(algorithm, algorithms.contains(&algorithm.into())));
    };
} flags);
fields_ie!(NasUeAdditionalSecurityCapability {
    "ea": |ie| supported(ie, Self::supports_ea, 16), |ie, algorithms: Vec<u16>| {
        (0..16).for_each(|algorithm| ie.set_ea(algorithm, algorithms.contains(&algorithm.into())));
    };
    "ia": |ie| supported(ie, Self::supports_ia, 16), |ie, algorithms: Vec<u16>| {
        (0..16).for_each(|algorithm| ie.set_ia(algorithm, algorithms.contains(&algorithm.into())));
    };
});

/// The identity of an EPS mobile identity, by its type of identity.
#[derive(Serialize, Deserialize)]
enum EpsMobileIdentity {
    Imsi(String),
    Imei(String),
    Guti(Guti),
}

decoded_ie!(
    NasEpsMobileIdentity: EpsMobileIdentity,
    |ie| Some(match ie.identity_type()? {
        MobileIdentityType::Imsi => EpsMobileIdentity::Imsi(ie.as_imsi()?),
        MobileIdentityType::Imei => EpsMobileIdentity::Imei(ie.as_imei()?),
        MobileIdentityType::Guti => EpsMobileIdentity::Guti(ie.as_guti()?),
    }),
    |_, identity| match identity {
        EpsMobileIdentity::Imsi(imsi) => NasEpsMobileIdentity::from_imsi(&imsi),
        EpsMobileIdentity::Imei(imei) => NasEpsMobileIdentity::try_from_imei(&imei),
        EpsMobileIdentity::Guti(guti) => Some(NasEpsMobileIdentity::from_guti(guti)),
    }
);

/// The identity of a mobile identity of TS 24.008, by its type of identity.
#[derive(Serialize, Deserialize)]
enum MobileIdentity {
    NoIdentity,
    Imsi(String),
    Imei(String),
    Imeisv(String),
    Tmsi(u32),
}

decoded_ie!(
    NasMobileIdentity: MobileIdentity,
    |ie| {
        if ie.is_no_identity() {
            return Some(MobileIdentity::NoIdentity);
        }
        (ie.as_imsi().map(MobileIdentity::Imsi))
            .or_else(|| ie.as_imei().map(MobileIdentity::Imei))
            .or_else(|| ie.as_imeisv().map(MobileIdentity::Imeisv))
            .or_else(|| ie.as_tmsi().map(MobileIdentity::Tmsi))
    },
    |_, identity| match identity {
        MobileIdentity::NoIdentity => Some(NasMobileIdentity::from_no_identity()),
        MobileIdentity::Imsi(imsi) => NasMobileIdentity::from_imsi(&imsi),
        MobileIdentity::Imei(imei) => NasMobileIdentity::from_imei(&imei),
        MobileIdentity::Imeisv(imeisv) => NasMobileIdentity::from_imeisv(&imeisv),
        MobileIdentity::Tmsi(tmsi) => Some(NasMobileIdentity::from_tmsi(tmsi)),
    }
);

// Tracking areas and PLMNs.
macro_rules! tai_list_view {
    ($($ie:ty),+) => {$(
        decoded_ie!($ie: TaiList, |ie| ie.tai_list(), |_, list| <$ie>::from_tai_list(&list));
    )+};
}
tai_list_view!(
    NasTaiList,
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService
);
decoded_ie!(
    NasLastVisitedRegisteredTai: Tai,
    |ie| ie.tai(),
    |_, tai| Some(NasLastVisitedRegisteredTai::from_tai(tai))
);
decoded_ie!(
    NasLocationAreaIdentification: Lai,
    |ie| ie.lai(),
    |_, lai| Some(NasLocationAreaIdentification::from_lai(lai))
);
decoded_ie!(
    NasEquivalentPlmns: Vec<PlmnId>,
    |ie| ie.is_well_formed().then(|| ie.plmns()),
    |_, plmns| NasEquivalentPlmns::from_plmns(&plmns)
);
decoded_ie!(
    NasUeDeterminedPlmnWithDisasterCondition: PlmnId,
    |ie| ie.plmn(),
    |_, plmn| Some(NasUeDeterminedPlmnWithDisasterCondition::from_plmn(&plmn))
);

// Timers, names and numbers.
timer_ie!(
    NasT3412Value,
    NasT3402Value,
    NasT3423Value,
    NasT3442Value,
    NasT3346Value,
    NasT3324Value,
    NasT3448Value,
    NasGprsTimer2,
    NasBackOffTimerValue,
    NasT3396Value,
    NasT3447Value,
    NasLowerBoundTimerValue,
    NasMaximumTimeOffset
);
decoded_ie!(
    NasAccessPointName: String,
    |ie| ie.as_string(),
    |_, name| NasAccessPointName::from_string(&name)
);

decoded_ie!(
    NasLocalTimeZone: i8,
    |ie| ie.is_well_formed().then(|| ie.quarter_hours()),
    |_, quarter_hours| NasLocalTimeZone::from_quarter_hours(quarter_hours)
);
decoded_ie!(NasDcnId: u16, |ie| ie.dcn_id(), |_, identity| Some(NasDcnId::from_dcn_id(identity)));
decoded_ie!(
    NasTmsiBasedNriContainer: u16,
    |ie| ie.nri(),
    |_, nri| NasTmsiBasedNriContainer::from_nri(nri)
);
decoded_ie!(
    NasOldPTmsiSignature: u32,
    |ie| ie.p_tmsi_signature(),
    |_, signature| NasOldPTmsiSignature::from_p_tmsi_signature(signature)
);
decoded_ie!(
    NasLinkedEpsBearerIdentity: u8,
    |ie| Some(ie.bearer_identity()),
    |_, identity| NasLinkedEpsBearerIdentity::from_bearer_identity(identity)
);
decoded_ie!(
    NasRequestedImsiOffset: u16,
    |ie| ie.imsi_offset(),
    |_, offset| Some(NasRequestedImsiOffset::from_imsi_offset(offset))
);
decoded_ie!(
    NasNegotiatedImsiOffset: u16,
    |ie| ie.imsi_offset(),
    |_, offset| Some(NasNegotiatedImsiOffset::from_imsi_offset(offset))
);
decoded_ie!(NasSsCode: u8, |ie| Some(ie.code()), |_, code| Some(NasSsCode::from_code(code)));
decoded_ie!(
    NasGprsCipheringKeySequenceNumber: u8,
    |ie| ie.key_sequence_number_strict(),
    |_, number| NasGprsCipheringKeySequenceNumber::from_key_sequence_number(number)
);
decoded_ie!(
    NasPacketFlowIdentifier: PacketFlowId,
    |ie| ie.pfi(),
    |_, pfi| NasPacketFlowIdentifier::from_pfi(pfi)
);
decoded_ie!(
    NasProseKeyManagementFunctionAddress: IpAddr,
    |ie| ie.address(),
    |_, address| Some(NasProseKeyManagementFunctionAddress::from_address(address))
);
decoded_ie!(
    NasSupportedCodecs: Vec<(u8, Vec<u8>)>,
    |ie| ie.codec_bitmaps(),
    |_, bitmaps| NasSupportedCodecs::from_codec_bitmaps(&bitmaps)
);

// Bearers: the identities a status has the bits of, and what a bearer has.
decoded_ie!(
    NasHeaderCompressionConfigurationStatus: Vec<u16>,
    |ie| ie.is_well_formed().then(|| numbers(&ie.not_used_ebis())),
    |_, bearers| NasHeaderCompressionConfigurationStatus::from_not_used_ebis(&octets(&bearers)?)
);
decoded_ie!(
    NasPdnAddress: PdnAddress,
    |ie| ie.pdn_address(),
    |_, address| Some(NasPdnAddress::from_pdn_address(address))
);
decoded_ie!(
    NasApnAmbr: ApnAmbrValue,
    |ie| ie.parse(),
    |_, ambr| NasApnAmbr::from_kbps(ambr.dl_kbps, ambr.ul_kbps)
);
decoded_ie!(
    NasExtendedApnAmbr: ExtendedApnAmbr,
    |ie| ie.ambr(),
    |_, ambr| Some(NasExtendedApnAmbr::from_ambr(ambr))
);
macro_rules! eps_qos_view {
    ($($ie:ty),+) => {$(
        decoded_ie!($ie: EpsQos, |ie| ie.qos(), |_, qos| <$ie>::from_qos(qos));
    )+};
}
eps_qos_view!(NasEpsQos, NasNewEpsQos, NasRequiredTrafficFlowQos);
decoded_ie!(
    NasExtendedEpsQos: ExtendedEpsQos,
    |ie| ie.qos(),
    |_, qos| Some(NasExtendedEpsQos::from_qos(qos))
);
decoded_ie!(NasTft: Tft, |ie| ie.tft(), |_, tft| NasTft::from_tft(&tft));
decoded_ie!(
    NasTrafficFlowAggregate: Tft,
    |ie| ie.tft(),
    |_, tft| NasTrafficFlowAggregate::from_tft(&tft)
);

// Capabilities: every flag by its name, and the algorithms by number.
fields_ie!(NasN1UeNetworkCapability {
    "pnb-ciot":
        |ie| Code::of(ie.pnb_ciot(), ie.pnb_ciot_raw()),
        |ie, code: Code<PreferredCiotBehavior>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_pnb_ciot(name);
            },
            |ie| ie.pnb_ciot_raw(),
        );
} flags);
fields_ie!(NasEpsNetworkFeatureSupport {
    "cs-lcs":
        |ie| Code::of(ie.cs_lcs(), ie.cs_lcs_raw()),
        |ie, code: Code<CsLcsSupport>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_cs_lcs(name);
            },
            |ie| ie.cs_lcs_raw(),
        );
} flags);
fields_ie!(NasMsNetworkCapability {} flags);
fields_ie!(NasAdditionalInformationRequested {} flags);
fields_ie!(NasDeviceProperties {} flags);
fields_ie!(NasWlanOffloadIndication {} flags);
fields_ie!(NasNetworkPolicy {} flags);
fields_ie!(NasMsNetworkFeatureSupport {} flags);

// The parts of an IE that its constructor takes.
built_ie!(
    NasHeaderCompressionConfiguration,
    |profiles, max_cid, setup: Option<IpHdrCompAdditionalSetupType>, container: Option<Vec<u8>>| {
        match (setup, container) {
            (None, None) => Self::from_profiles(profiles, max_cid),
            (Some(setup), container) => Self::from_profiles_with_additional_setup(
                profiles,
                max_cid,
                setup,
                &container.unwrap_or_default(),
            ),
            (None, Some(_)) => None,
        }
    },
    {
        profiles: IpHdrCompProfiles = |ie| ie.is_well_formed().then(|| ie.profiles()),
        max_cid: u16,
        additional_setup_type: Option<IpHdrCompAdditionalSetupType> =
            |ie| Some(ie.additional_setup_type_value()),
        additional_setup_container: Option<Vec<u8>> =
            |ie| Some(ie.additional_setup_container().map(<[u8]>::to_vec)),
    }
);
built_ie!(
    NasPagingRestriction,
    |restriction_type, ebis: Vec<u16>| Self::from_restriction(restriction_type, &octets(&ebis)?),
    {
        restriction_type: EpsPagingRestrictionType =
            |ie| ie.restriction_type().filter(|_| ie.is_well_formed()),
        unrestricted_ebis: Vec<u16> =
            |ie| Some(numbers(&ie.unrestricted_ebis().unwrap_or_default())),
    }
);
built_ie!(
    NasSAndFSatelliteOperationParameters,
    |wait_time, uplink_delivery_time, monitoring_list: SAndFMonitoringList| {
        Self::from_fields(wait_time, uplink_delivery_time, &monitoring_list)
    },
    {
        wait_time: Option<u16> = |ie| ie.is_well_formed().then(|| ie.wait_time()),
        uplink_delivery_time: Option<u32> = |ie| Some(ie.uplink_delivery_time()),
        monitoring_list: SAndFMonitoringList = |ie| ie.monitoring_list(),
    }
);

// Read only. The crate parses these; their builders take the parsed entries
// and have not been driven with values that a parser does not produce, so
// the view does not hand them what an author writes.
decoded_ie!(NasCli: CallingPartyNumber, |ie| ie.number());
decoded_ie!(NasNbifomContainer: Vec<NbifomParameter>, |ie| ie.parameters());
decoded_ie!(NasCipheringKeyData: Vec<CipheringDataSet>, |ie| ie
    .is_well_formed()
    .then(|| ie.data_sets()));
decoded_ie!(NasRemoteUeContextConnected: Vec<EpsRemoteUeContext>, |ie| ie.contexts());
decoded_ie!(NasRemoteUeContextDisconnected: Vec<EpsRemoteUeContext>, |ie| ie.contexts());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::view::tests::{
        Octet, built_from_nothing, built_from_value, exercise, fields_ies, replace_parts, sweep,
    };

    #[test]
    fn an_ie_of_fields_is_built_from_its_value_with_the_octets_of_every_member() {
        macro_rules! each {
            ($($ie:ty),+ $(,)?) => {{
                $(
                    // Zeros have their octets too.
                    built_from_nothing(<$ie>::new(Default::default()));
                    for octet in 0..=255_u8 {
                        // The digits of a time are decimal.
                        let decimal = octet & 0x0f <= 9 && octet >> 4 <= 9;
                        if !decimal && stringify!($ie).contains("Time") {
                            continue;
                        }
                        let blank = <$ie>::new(Default::default());
                        built_from_value(blank, <$ie>::new(Octet::of(octet)));
                    }
                )+
                [$(stringify!($ie)),+].len()
            }};
        }
        let built = each!(
            NasEpsUpdateType,
            NasControlPlaneServiceType,
            NasDetachType,
            NasSelectedNasSecurityAlgorithms,
            NasUniversalTimeAndLocalTimeZone,
            NasUeNetworkCapability,
            NasReplayedUeSecurityCapabilities,
            NasUeAdditionalSecurityCapability,
            NasN1UeNetworkCapability,
            NasEpsNetworkFeatureSupport,
            NasMsNetworkCapability,
            NasAdditionalInformationRequested,
            NasDeviceProperties,
            NasWlanOffloadIndication,
            NasNetworkPolicy,
            NasMsNetworkFeatureSupport,
            NasExtendedDrxParameters,
            NasReAttemptIndicator,
            NasUeStatus,
            NasNon3GppNwProvidedPolicies,
            NasMobileStationClassmark2,
            NasAccessTechnologyUtilizationControl,
        );
        // Every type that `fields_ie!` gives a value is in the list.
        assert_eq!(built, fields_ies(include_str!("view.rs")));
    }

    #[test]
    fn values_encode_back_and_take_nothing_unchecked() {
        // Every octet has a value that encodes back, or none; the parts of
        // the values of a few are replaced too.
        for value in 0..=255_u8 {
            replace_parts([1, 0x16, 0x79, 0xff].contains(&value));
            let half = value & 0x0f;
            sweep(NasHeaderCompressionConfiguration::new(vec![value; 3]));
            sweep(NasHeaderCompressionConfiguration::new(vec![
                value & 0x7f,
                0,
                value,
                value & 7,
                value,
            ]));
            sweep(NasPagingRestriction::new(vec![half]));
            sweep(NasPagingRestriction::new(vec![3, value & 0xfe, value]));
            sweep(NasSAndFSatelliteOperationParameters::new(vec![
                value & 0x0b,
                0,
                value,
                0,
                1,
                value,
                1,
                value,
            ]));
            sweep(NasEmmCause::new(value));
            sweep(NasEsmCause::new(value));
            sweep(NasEpsAttachType::new(half));
            sweep(NasEpsAttachResult::new(half));
            sweep(NasEpsUpdateResult::new(half));
            sweep(NasEpsUpdateType::new(half));
            sweep(NasServiceType::new(half));
            sweep(NasControlPlaneServiceType::new(half));
            sweep(NasIdentityType::new(half));
            sweep(NasRequestType::new(half));
            sweep(NasPdnType::new(half));
            sweep(NasDetachType::new(half));
            sweep(NasKeySetIdentifier::new(half));
            sweep(NasNonCurrentNativeNasKeySetIdentifier::new(half));
            sweep(NasSelectedNasSecurityAlgorithms::new(value));
            sweep(NasT3412Value::new(value));
            sweep(NasT3402Value::new(value));
            sweep(NasGprsTimer2::new(vec![value]));
            sweep(NasT3396Value::new(vec![value]));
            sweep(NasT3412ExtendedValue::new(vec![value]));
            sweep(NasUeNetworkCapability::new(vec![value; 2]));
            sweep(NasUeNetworkCapability::new(vec![value; 13]));
            sweep(NasReplayedUeSecurityCapabilities::new(vec![value; 2]));
            sweep(NasReplayedUeSecurityCapabilities::new(vec![value; 5]));
            sweep(NasUeAdditionalSecurityCapability::new(vec![value; 4]));
            sweep(NasN1UeNetworkCapability::new(vec![value]));
            sweep(NasEpsNetworkFeatureSupport::new(vec![value; 2]));
            sweep(NasMsNetworkCapability::new(vec![value; 3]));
            sweep(NasEpsBearerContextStatus::new(vec![value & 0xfe, value]));
            sweep(NasHeaderCompressionConfigurationStatus::new(vec![
                value & 0xe0,
                value,
            ]));
            sweep(NasAdditionalUpdateType::new(half));
            sweep(NasConnectivityType::new(half));
            sweep(NasControlPlaneOnlyIndication::new(half));
            sweep(NasCsfbResponse::new(half));
            sweep(NasEsmInformationTransferFlag::new(half));
            sweep(NasExtendedEmmCause::new(half));
            sweep(NasLcsIndicator::new(value));
            sweep(NasOldGutiType::new(half));
            sweep(NasPagingIdentity::new(half));
            sweep(NasTmsiStatus::new(half));
            sweep(NasUeCoarseLocationInformationRequest::new(half));
            sweep(NasUeRadioCapabilityIdAvailability::new(vec![value]));
            sweep(NasUeRadioCapabilityIdRequest::new(vec![value]));
            sweep(NasUeRadioCapabilityInformationUpdateNeeded::new(half));
            sweep(NasVoiceDomainPreferenceAndUeUsageSetting::new(vec![value]));
            sweep(NasTransactionIdentifier::new(vec![value]));
            sweep(NasDrxParameter::new(vec![value, value]));
            sweep(NasDisasterRoamingWaitRange::new(vec![value, value]));
            sweep(NasExtendedDrxParameters::new(vec![value]));
            sweep(NasUniversalTimeAndLocalTimeZone::new(vec![value & 0x11; 7]));
            sweep(NasDcnId::new(vec![value, value]));
            sweep(NasTmsiBasedNriContainer::new(vec![value, value & 0xc0]));
            sweep(NasOldPTmsiSignature::new(vec![value; 3]));
            sweep(NasLinkedEpsBearerIdentity::new(half));
            sweep(NasRequestedImsiOffset::new(vec![value, value]));
            sweep(NasSsCode::new(value));
            sweep(NasPacketFlowIdentifier::new(vec![value & 0x7f]));
            sweep(NasDrxParameterInNbS1Mode::new(vec![value]));
            sweep(NasEpsAdditionalRequestResult::new(vec![value]));
            sweep(NasNotificationIndicator::new(vec![value]));
            sweep(NasRequestedWusAssistanceInformation::new(vec![value]));
            sweep(NasImeisvRequest::new(half));
            sweep(NasRadioPriority::new(half));
            sweep(NasGprsCipheringKeySequenceNumber::new(half));
            sweep(NasUnavailabilityInformation::new(vec![
                value & 0x1f,
                0,
                0,
                value,
            ]));
            sweep(NasUnavailabilityConfiguration::new(vec![
                value & 0x1f,
                0,
                0,
                value,
            ]));
        }
        replace_parts(true);
        let plmn = [0x02, 0xf8, 0x39];
        let octets = |parts: &[&[u8]]| parts.concat();
        exercise(NasEpsMobileIdentity::from_imsi("208930000000001").unwrap());
        exercise(NasEpsMobileIdentity::try_from_imei("356938035643809").unwrap());
        exercise(NasEpsMobileIdentity::new(octets(&[
            &[0xf6],
            &plmn,
            &[0x80, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44],
        ])));
        exercise(NasMobileIdentity::from_imsi("208930000000001").unwrap());
        exercise(NasMobileIdentity::from_imei("356938035643809").unwrap());
        exercise(NasMobileIdentity::from_imeisv("3569380356438091").unwrap());
        exercise(NasMobileIdentity::from_tmsi(0x1122_3344));
        exercise(NasMobileIdentity::from_no_identity());
        for list in [
            octets(&[&[0x01], &plmn, &[0, 1, 0, 2]]),
            octets(&[&[0x21], &plmn, &[0, 1]]),
            octets(&[&[0x41], &plmn, &[0, 1], &plmn, &[0, 2]]),
        ] {
            exercise(NasTaiList::new(list));
        }
        exercise(NasLastVisitedRegisteredTai::new(octets(&[&plmn, &[0, 1]])));
        exercise(NasLocationAreaIdentification::new(octets(&[
            &plmn,
            &[0, 1],
        ])));
        exercise(NasEquivalentPlmns::new(octets(&[
            &plmn,
            &[0x02, 0x18, 0x39],
        ])));
        exercise(NasUeDeterminedPlmnWithDisasterCondition::new(plmn.to_vec()));
        exercise(NasAccessPointName::new(b"\x08internet".to_vec()));
        exercise(NasPdnAddress::new(vec![1, 10, 0, 0, 1]));
        exercise(NasPdnAddress::new(vec![
            3, 1, 2, 3, 4, 5, 6, 7, 8, 10, 0, 0, 1,
        ]));
        exercise(NasApnAmbr::new(vec![0x5e, 0x5e]));
        exercise(NasExtendedApnAmbr::new(vec![3, 0, 100, 3, 0, 50]));
        exercise(NasEpsQos::new(vec![9]));
        exercise(NasEpsQos::new(vec![1, 0x40, 0x40, 0x40, 0x40]));
        exercise(NasExtendedEpsQos::new(vec![3, 0, 1, 0, 1, 3, 0, 1, 0, 1]));
        // Create new TFT: one uplink packet filter matching protocol 17.
        exercise(NasTft::new(vec![0x21, 0x21, 0, 2, 0x30, 17]));
        exercise(NasNetworkName::from_name("Open5GS", false));
        exercise(NasLocalTimeZone::new(0x40));
        exercise(NasEmergencyNumberList::new(vec![3, 0x1f, 0x11, 0xf2]));
        exercise(NasProseKeyManagementFunctionAddress::new(vec![
            1, 10, 0, 0, 1,
        ]));
        exercise(NasSupportedCodecs::new(vec![4, 2, 0x60, 0]));
        // A container of a PDN CONNECTIVITY REQUEST.
        exercise(NasEsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x31]));
    }
}
