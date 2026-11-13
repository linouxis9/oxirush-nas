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

//! The view of an EPS message and the values of its IEs.

use crate::common::readable::{from_value, same_name};
use crate::common::view::{self, Viewed, Visit};
use crate::common::{Error, Result};
use crate::nas_eps::{EmmMessageType, EsmMessage, EsmMessageType, Message};
use crate::nas_eps::{EmmTransport, ServiceRequest};
use crate::prelude::*;

/// Who sends an ESM message, where its type says so (TS 24.301 §8.3): the
/// units of its protocol configuration options are read by it.
fn sent(message: &EsmMessage) -> Option<PcoDirection> {
    use EsmMessage as M;
    match message {
        M::ActivateDedicatedEpsBearerContextAccept(_)
        | M::ActivateDedicatedEpsBearerContextReject(_)
        | M::ActivateDefaultEpsBearerContextAccept(_)
        | M::ActivateDefaultEpsBearerContextReject(_)
        | M::BearerResourceAllocationRequest(_)
        | M::BearerResourceModificationRequest(_)
        | M::DeactivateEpsBearerContextAccept(_)
        | M::EsmInformationResponse(_)
        | M::ModifyEpsBearerContextAccept(_)
        | M::ModifyEpsBearerContextReject(_)
        | M::PdnConnectivityRequest(_)
        | M::PdnDisconnectRequest(_)
        | M::RemoteUeReport(_) => Some(PcoDirection::Uplink),
        M::ActivateDedicatedEpsBearerContextRequest(_)
        | M::ActivateDefaultEpsBearerContextRequest(_)
        | M::BearerResourceAllocationReject(_)
        | M::BearerResourceModificationReject(_)
        | M::DeactivateEpsBearerContextRequest(_)
        | M::EsmInformationRequest(_)
        | M::ModifyEpsBearerContextRequest(_)
        | M::Notification(_)
        | M::PdnConnectivityReject(_)
        | M::PdnDisconnectReject(_)
        | M::RemoteUeReportResponse(_) => Some(PcoDirection::Downlink),
        // Sent by either.
        M::EsmDummyMessage(_) | M::EsmStatus(_) | M::EsmDataTransport(_) => None,
    }
}

impl Viewed for Message {
    fn ies(&self, scope: view::Scope, visit: &mut Visit<'_>) {
        let scope = scope.sent_by(match self {
            Self::Esm(_, message) => sent(message),
            _ => None,
        });
        match self {
            Self::Emm(_, message) => message.body().ies(scope, visit),
            Self::Esm(_, message) => message.body().ies(scope, visit),
            Self::SecurityProtected(_, inner) => inner.ies(scope, visit),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => {}
        }
    }

    fn absent(&self, visit: &mut dyn FnMut(&'static str, usize)) {
        match self {
            Self::Emm(_, message) => message.body().absent(visit),
            Self::Esm(_, message) => message.body().absent(visit),
            Self::SecurityProtected(_, inner) => inner.absent(visit),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => {}
        }
    }

    fn header(&self) -> Option<oxirush_utils::tree::Value> {
        match self {
            Self::Emm(header, _) => crate::common::readable::to_value(header).ok(),
            Self::Esm(header, _) => crate::common::readable::to_value(header).ok(),
            Self::SecurityProtected(_, inner) => inner.header(),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => None,
        }
    }

    fn protection(
        &self,
    ) -> Option<(
        oxirush_utils::tree::Value,
        Option<oxirush_utils::tree::Value>,
    )> {
        let Self::SecurityProtected(header, inner) = self else {
            return None;
        };
        let ciphered = match &**inner {
            Self::Opaque(octets) => Some(view::octets_shown(octets)),
            _ => None,
        };
        Some((crate::common::readable::to_value(header).ok()?, ciphered))
    }

    fn keep_received(&mut self, original: &Self) {
        let (body, received) = match (self, original) {
            (Self::Emm(_, message), Self::Emm(_, original)) => {
                (message.body_mut(), original.body().received())
            }
            (Self::Esm(_, message), Self::Esm(_, original)) => {
                (message.body_mut(), original.body().received())
            }
            (Self::SecurityProtected(_, inner), Self::SecurityProtected(_, original)) => {
                return inner.keep_received(original);
            }
            _ => return,
        };
        body.set_received(received.0, received.1);
    }

    fn unknown(&self) -> crate::common::UnknownIes {
        match self {
            Self::Emm(_, message) => message.body().received().0.clone(),
            Self::Esm(_, message) => message.body().received().0.clone(),
            Self::SecurityProtected(_, inner) => inner.unknown(),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => {
                crate::common::UnknownIes::new()
            }
        }
    }

    fn set_unknown(&mut self, unknown: &crate::common::UnknownIes) -> bool {
        match self {
            Self::Emm(_, message) => message
                .body_mut()
                .set_received(unknown, &crate::common::IeOrder::new()),
            Self::Esm(_, message) => message
                .body_mut()
                .set_received(unknown, &crate::common::IeOrder::new()),
            Self::SecurityProtected(_, inner) => return inner.set_unknown(unknown),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => return false,
        }
        true
    }

    fn blank(&self, name: &str) -> Option<oxirush_utils::tree::Value> {
        match self {
            Self::Emm(_, message) => message.body().blank(name),
            Self::Esm(_, message) => message.body().blank(name),
            Self::SecurityProtected(_, inner) => inner.blank(name),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => None,
        }
    }

    #[cfg(test)]
    fn variant_name(&self) -> Option<&'static str> {
        match self {
            Self::Emm(_, message) => Some(message.variant_name()),
            Self::Esm(_, message) => Some(message.variant_name()),
            Self::SecurityProtected(_, inner) => inner.variant_name(),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => None,
        }
    }

    fn blank_of(family: &str, kind: &str) -> Option<Self> {
        use crate::common::readable::blank;
        match family {
            "Emm" => Some(Self::Emm(
                blank(&[family, kind])?,
                EmmMessage::blank_named(kind)?,
            )),
            "Esm" => Some(Self::Esm(
                blank(&[family, kind])?,
                EsmMessage::blank_named(kind)?,
            )),
            _ => None,
        }
    }

    fn protected(&self) -> Option<(u32, &Self)> {
        match self {
            Self::SecurityProtected(header, inner) => {
                Some((header.message_authentication_code, &**inner))
            }
            _ => None,
        }
    }

    fn slot(&mut self, name: &str) -> Option<&mut dyn view::Slot> {
        match self {
            Self::Emm(_, message) => message.body_mut().slot(name),
            Self::Esm(_, message) => message.body_mut().slot(name),
            Self::SecurityProtected(_, inner) => inner.slot(name),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => None,
        }
    }

    fn set_header(
        &mut self,
        header: &oxirush_utils::tree::Value,
    ) -> core::result::Result<(), String> {
        use crate::common::readable::from_value;
        match self {
            Self::Emm(written, _) => *written = from_value(header)?,
            Self::Esm(written, _) => *written = from_value(header)?,
            Self::SecurityProtected(_, inner) => return inner.set_header(header),
            Self::ServiceRequest(_) | Self::EmmTransport(_) | Self::Opaque(_) => {}
        }
        Ok(())
    }

    fn set_protection(
        &mut self,
        header: &oxirush_utils::tree::Value,
        ciphered: Option<&oxirush_utils::tree::Value>,
    ) -> core::result::Result<(), String> {
        use crate::common::readable::from_value;
        if let Self::SecurityProtected(written, inner) = self {
            *written = from_value(header)?;
            if let (Self::Opaque(octets), Some(ciphered)) = (&mut **inner, ciphered) {
                *octets = from_value(ciphered)?;
            }
        }
        Ok(())
    }

    const FAMILIES: &'static [&'static str] = &["Emm", "Esm"];

    fn decided(
        container: Option<&str>,
        kind: Option<&oxirush_utils::tree::Value>,
    ) -> core::result::Result<Vec<(&'static str, oxirush_utils::tree::Value)>, String> {
        decided(container, kind)
    }

    fn refused_header(&self) -> Option<String> {
        use crate::nas_eps::SecurityHeaderType::PlainNasMessageNotSecurityProtected;
        let discriminator = |written: u8, sublayer: &str, is: u8| {
            (written != is).then(|| {
                format!(
                    "`protocol-discriminator` is {written}, and that of {sublayer} message is {is}"
                )
            })
        };
        match self {
            Self::Emm(header, _) => discriminator(header.protocol_discriminator, "an EMM", 7)
                .or_else(|| {
                    let written = crate::common::readable::to_value(&header.security_header_type);
                    let written = written.ok()?;
                    (header.security_header_type != PlainNasMessageNotSecurityProtected).then(
                        || {
                            format!(
                                "`security-header-type` is {written}, and that of a plain message \
                             is \"plain-nas-message-not-security-protected\": the header that protects a message is \
                             its `security-header`"
                            )
                        },
                    )
                }),
            Self::Esm(header, _) => discriminator(header.protocol_discriminator, "an ESM", 2)
                .or_else(|| {
                    let bearer = header.eps_bearer_identity;
                    (bearer > 15)
                        .then(|| format!("`eps-bearer-identity` is {bearer}, and must be 0 to 15"))
                }),
            _ => None,
        }
    }

    fn header_name(field: &str, number: u64) -> Option<oxirush_utils::tree::Value> {
        let number = u8::try_from(number).ok()?;
        match field {
            "security-header-type" => {
                let named = crate::nas_eps::SecurityHeaderType::try_from(number).ok()?;
                crate::common::readable::to_value(&named).ok()
            }
            // The types of EMM and of ESM have no number in common, and a
            // number that is of neither has no name.
            "message-type" => match EmmMessageType::from(number) {
                EmmMessageType::Unknown(_) => {
                    let named = EsmMessageType::from(number);
                    crate::common::readable::to_value(&named).ok()
                }
                named => crate::common::readable::to_value(&named).ok(),
            }
            .filter(oxirush_utils::tree::Value::is_string),
            _ => None,
        }
    }
}

impl Message {
    /// The view of the message: each field of the header and each IE that the message
    /// can have, with its `value` and its `octets`, `null` for one that the message has
    /// not. A tree is made of it.
    pub(crate) fn to_view(&self) -> oxirush_utils::tree::Value {
        match self {
            Self::ServiceRequest(request) => request.view(),
            Self::EmmTransport(transport) => transport.view(),
            message => view::to_view(message, view::Scope::NONE),
        }
    }

    /// The message that an edited view of this one describes: an IE whose `value`
    /// changed is encoded from it, one whose `octets` changed has them, and the others
    /// keep their octets.
    pub(crate) fn with_view(&self, view: oxirush_utils::tree::Value) -> Result<Self> {
        let edited = match self {
            Self::ServiceRequest(request) => {
                let request = request.written(view, false);
                request.map(Self::ServiceRequest)
            }
            Self::EmmTransport(_) => EmmTransport::written(view).map(Self::EmmTransport),
            message => view::with_view(message, view, view::Scope::NONE),
        }
        .map_err(Error::EncodingError)?;
        // A message that the view leaves as it is comes back as it is.
        if edited != *self {
            edited.encode()?;
        }
        Ok(edited)
    }

    /// The message that a view describes alone, which its `message-type` names.
    pub(crate) fn from_view(view: oxirush_utils::tree::Value) -> Result<Self> {
        let Some(named) = view::message_type::<Self>(&view) else {
            let has = |entry: &str| {
                (view.as_object().into_iter().flatten()).any(|(name, _)| same_name(name, entry))
            };
            return match (has("ksi-and-sequence-number"), has("security-header")) {
                (true, _) => ServiceRequest::from_view(view),
                // An EMM TRANSPORT is a security header and a container.
                (_, true) => (EmmTransport::written(view).map(Self::EmmTransport))
                    .map_err(Error::EncodingError)
                    .and_then(sendable),
                _ => Err(Error::EncodingError(
                    "the `message-type` of the view names the message".into(),
                )),
            };
        };
        match message_type_place(&named) {
            Some((0, place)) => match emm_types().nth(place) {
                Some(kind) => kind.message_from_view(view),
                None => Err(Error::EncodingError(format!("no message `{named}`"))),
            },
            Some((_, place)) => match esm_types().nth(place) {
                Some(kind) => kind.message_from_view(view),
                None => Err(Error::EncodingError(format!("no message `{named}`"))),
            },
            None => Err(Error::EncodingError(no_message(&named))),
        }
    }
}

/// The message types of EMM, in the order of their numbers.
fn emm_types() -> impl Iterator<Item = EmmMessageType> {
    EmmMessageType::ALL.iter().copied()
}

/// The message types of ESM, in the order of their numbers.
fn esm_types() -> impl Iterator<Item = EsmMessageType> {
    EsmMessageType::ALL.iter().copied()
}

/// The family of the message type that `kind` names, EMM (0) or ESM (1), and
/// its place among the types of the family.
fn message_type_place(kind: &str) -> Option<(usize, usize)> {
    let families = [EmmMessageType::NAMES, EsmMessageType::NAMES];
    (families.iter().enumerate())
        .find_map(|(family, names)| Some((family, oxirush_utils::tree::named(names, kind)?)))
}

impl EmmTransport {
    /// The entry of a view for a data container that is not ciphered.
    const DATA_CONTAINER: &'static str = "data-container";

    /// The view of an EMM TRANSPORT: its `security-header`, and its
    /// container, as the `octets` of a `ciphered-message` or, once it was
    /// deciphered, of a `data-container`.
    fn view(&self) -> oxirush_utils::tree::Value {
        let entry = |member: &str, value: oxirush_utils::tree::Value| {
            oxirush_utils::tree::Value::from(oxirush_utils::tree::Map::from_iter([(
                member.to_string(),
                value,
            )]))
        };
        let mut view = oxirush_utils::tree::Map::new();
        let header = crate::common::readable::to_value(&self.security_header);
        view.insert(
            "security-header".into(),
            entry("value", header.unwrap_or_default()),
        );
        if let Some(octets) = &self.protected_payload {
            let octets = oxirush_utils::tree::hex(octets).into();
            view.insert("ciphered-message".into(), entry("octets", octets));
        }
        if let Some(octets) = &self.data_container {
            let octets = oxirush_utils::tree::hex(octets).into();
            view.insert(Self::DATA_CONTAINER.into(), entry("octets", octets));
        }
        view.into()
    }

    /// The EMM TRANSPORT that the view `view` describes: every entry that
    /// it has is written.
    fn written(view: oxirush_utils::tree::Value) -> core::result::Result<Self, String> {
        let oxirush_utils::tree::Value::Object(view) = view else {
            return Err(format!("{view} is not a view: an object of IEs by name"));
        };
        let (mut header, mut ciphered, mut data) = (None, None, None);
        for (name, written) in view {
            // An entry that is null is one left out.
            if written.is_null() {
                continue;
            }
            let entry = view::entry(written).map_err(|error| format!("{name}: {error}"))?;
            let octets = |octets: &oxirush_utils::tree::Value| {
                let octets = octets.as_str().and_then(oxirush_utils::tree::unhex);
                octets.ok_or_else(|| format!("{name}: its octets are hexadecimal"))
            };
            match entry {
                [Some(value), None] if same_name(&name, "security-header") => {
                    header = Some(view::security_header(&value, &[])?);
                }
                [None, Some(written)] if same_name(&name, "ciphered-message") => {
                    ciphered = Some(octets(&written)?);
                }
                [None, Some(written)] if same_name(&name, Self::DATA_CONTAINER) => {
                    data = Some(octets(&written)?);
                }
                _ => {
                    return Err(format!(
                        "`{name}` is no entry of an EMM TRANSPORT: it has a `security-header` \
                         with a `value`, and the `octets` of a `ciphered-message` or of a \
                         `{}`",
                        Self::DATA_CONTAINER
                    ));
                }
            }
        }
        let header: crate::nas_eps::SecurityHeader =
            header.ok_or("`security-header` is not written")?;
        if header.security_header_type
            != crate::nas_eps::SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        {
            return Err(
                "security-header: a message under another header than `emm-transport` is \
                 written as a tree, or edited with `with_view`"
                    .into(),
            );
        }
        if ciphered.is_some() && data.is_some() {
            return Err(format!(
                "an EMM TRANSPORT has a `ciphered-message` or a `{}`, not both",
                Self::DATA_CONTAINER
            ));
        }
        Ok(Self {
            security_header: header,
            data_container: data,
            protected_payload: ciphered,
        })
    }

    /// The EMM TRANSPORT of a tree: its header, the octets of a container
    /// that is ciphered, and what else the tree has.
    fn of_tree(
        header: crate::nas_eps::SecurityHeader,
        ciphered: Option<Vec<u8>>,
        rest: &oxirush_utils::tree::Value,
    ) -> core::result::Result<Self, String> {
        let entry = |member: &str, value: oxirush_utils::tree::Value| {
            oxirush_utils::tree::Value::from(oxirush_utils::tree::Map::from_iter([(
                member.to_string(),
                value,
            )]))
        };
        let mut view = oxirush_utils::tree::Map::new();
        let header = crate::common::readable::to_value(&header)?;
        view.insert("security-header".into(), entry("value", header));
        if let Some(octets) = ciphered {
            let octets = oxirush_utils::tree::hex(&octets).into();
            view.insert("ciphered-message".into(), entry("octets", octets));
        }
        // A member of a tree that is `{"octets": ..}` is the entry of a view.
        for (name, written) in rest.as_object().into_iter().flatten() {
            view.insert(name.clone(), written.clone());
        }
        Self::written(view.into())
    }
}

/// The names of the fields of the short header of a SERVICE REQUEST.
const SERVICE_REQUEST: [&str; 4] = [
    "protocol-discriminator",
    "security-header-type",
    "ksi-and-sequence-number",
    "message-authentication-code",
];

impl ServiceRequest {
    /// The message that a view describes alone, which its `message-type` names.
    pub(crate) fn from_view(view: oxirush_utils::tree::Value) -> Result<Message> {
        let request = Self::new(0, 0).written(view, true);
        (request.map(Message::ServiceRequest))
            .map_err(Error::EncodingError)
            .and_then(sendable)
    }

    fn view(&self) -> oxirush_utils::tree::Value {
        let octet = self.ksi_and_sequence_number;
        let header_type = match self.security_header_type {
            12 => oxirush_utils::tree!("security-header-for-the-service-request-message"),
            other => other.into(),
        };
        oxirush_utils::tree!({
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
    fn written(
        &self,
        view: oxirush_utils::tree::Value,
        alone: bool,
    ) -> core::result::Result<Self, String> {
        let oxirush_utils::tree::Value::Object(view) = view else {
            return Err(format!("{view} is not a view: an object of IEs by name"));
        };
        let before = self.view();
        let mut request = self.clone();
        let mut left: Vec<_> = SERVICE_REQUEST.to_vec();
        for (name, written) in view {
            let Some(at) = left.iter().position(|field| same_name(field, &name)) else {
                return Err(crate::common::readable::none_of(
                    &name,
                    &SERVICE_REQUEST,
                    "IE",
                ));
            };
            // An entry that is null is one left out.
            if written.is_null() {
                continue;
            }
            let field = left.swap_remove(at);
            let [value, octets] =
                view::entry(written).map_err(|error| format!("{name}: {error}"))?;
            // What the view has as the message does is not written again.
            let changed = |member: &str, written: Option<oxirush_utils::tree::Value>| {
                written.filter(|written| alone || before[field].get(member) != Some(written))
            };
            let (value, octets) = (changed("value", value), changed("octets", octets));
            let refused = |reason: String| format!("{name}: {reason}");
            let bytes = |octets: &oxirush_utils::tree::Value| {
                let bytes = octets.as_str().and_then(oxirush_utils::tree::unhex);
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
                    let named = value.as_str().is_some_and(|name| {
                        same_name(name, "security-header-for-the-service-request-message")
                    });
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
    container: Option<&str>,
    kind: Option<&oxirush_utils::tree::Value>,
) -> core::result::Result<Vec<(&'static str, oxirush_utils::tree::Value)>, String> {
    use oxirush_utils::tree;
    // An EPS security header has no field that the system decides.
    if container.is_some_and(|ie| same_name(ie, "security-header")) {
        return Ok(vec![]);
    }
    let Some(kind) = kind else {
        return Ok(vec![
            ("protocol-discriminator", tree!(7)),
            (
                "security-header-type",
                tree!("security-header-for-the-service-request-message"),
            ),
        ]);
    };
    let kind = &view::type_named::<Message>(kind)?;
    match message_type_place(kind).map(|(family, _)| family) {
        Some(0) => Ok(vec![
            ("protocol-discriminator", tree!(7)),
            (
                "security-header-type",
                tree!("plain-nas-message-not-security-protected"),
            ),
        ]),
        Some(_) => Ok(vec![("protocol-discriminator", tree!(2))]),
        None => Err(no_message(kind)),
    }
}

/// Whether `kind` names an EPS message.
pub(crate) fn is_message(kind: &str) -> bool {
    message_type_place(kind).is_some()
}

/// The error for `kind`, which names no EPS message: the 5GS message that
/// it names, or the nearest names.
fn no_message(kind: &str) -> String {
    if crate::nas_5gs::view::is_message(kind) {
        return format!("no EPS message `{kind}`: it is a 5GS message, which `nas_5gs` reads");
    }
    let kinds: Vec<&str> = (EmmMessageType::NAMES.iter().chain(EsmMessageType::NAMES))
        .copied()
        .collect();
    crate::common::readable::none_of(kind, &kinds, "message")
}

impl Message {
    /// Whether this message means what `other` means: each IE of one has
    /// the octets of the same IE of the other, or octets that its value
    /// reads the same where the value says all that they mean, as the unit
    /// of a timer does not; and both have the same IEs that their table has
    /// no place for, in the same order. The order of their optional IEs may
    /// differ. [`Self::to_tree`] lists what a value leaves open.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::Message;
    ///
    /// // ATTACH REJECT with a T3346 value of twelve minutes, counted in minutes
    /// // and in units of six minutes
    /// let decode = |octets: &str| Message::decode(&hex::decode(octets).unwrap()).unwrap();
    /// let (minutes, decihours) = (decode("0744165f012c"), decode("0744165f0142"));
    /// assert!(minutes != decihours && minutes.means_the_same(&decihours));
    /// assert!(!minutes.means_the_same(&decode("0744165f012b")));
    /// ```
    pub fn means_the_same(&self, other: &Self) -> bool {
        match (
            view::meant(self, view::Scope::NONE),
            view::meant(other, view::Scope::NONE),
        ) {
            (Ok(this), Ok(other)) => this == other,
            _ => self == other,
        }
    }

    /// This message as a tree: its `message-type` and its IEs by name, each
    /// with its value, or as `{"octets": "…"}` when it has no readable value.
    ///
    /// What the type of the message
    /// decides is left out (the protocol discriminator, and a plain security
    /// header type), and so are the optional IEs that the message does not
    /// have. The message in a container is its own tree, and the header that
    /// protects a message is its `security-header`. A SERVICE REQUEST has no
    /// `message-type`.
    ///
    /// A tree says what a message means, and a message is written from it:
    /// [`Self::from_tree`] of the tree of a message gives a message that
    /// means what this one means ([`Self::means_the_same`]). An IE whose
    /// value does not write it back is shown by its octets: one that has
    /// more in its octets than its value says, as a spare bit that is set
    /// or a part that the crate does not read. The message that is written
    /// has the octets of this one, except where a value says all that the
    /// octets mean and does not decide them:
    ///
    /// - A GPRS timer of one octet is its seconds, or deactivated: the
    ///   unit that counts them, and the count of a timer that is
    ///   deactivated, are those that the encoder chooses.
    /// - A tracking area identity list that a sender may send is its
    ///   tracking areas: the partial lists that they are in, and their
    ///   types, are those that the encoder chooses.
    /// - An IE of flags, as a capability, is the flags that are set: octets
    ///   of zeros at its end say what their absence says, and the IE that
    ///   is written has the fewest octets that its clause gives it.
    /// - The optional IEs are in the order of the message table, each under
    ///   the first IEI of its place. The IEs that the table has no place
    ///   for are in `unknown-ies`, one text of the octets of each with a
    ///   space between two of them, and come after them
    ///   in the order they came in: an IEI that the table does not have,
    ///   and what a receiver ignores of one that it has, a repetition, an
    ///   IE out of sequence or one whose value is not one of its type.
    ///
    /// [`Self::with_tree`] keeps the octets of every IE that an edit does not
    /// change.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::Message;
    /// use oxirush_nas::tree;
    ///
    /// // ATTACH REJECT with cause #22.
    /// let reject = Message::decode(&[0x07, 0x44, 0x16]).unwrap();
    /// let tree = tree!({"message-type": "attach-reject", "emm-cause": "congestion"});
    /// assert_eq!(reject.to_tree(), tree);
    /// assert_eq!(Message::from_tree(tree).unwrap(), reject);
    /// ```
    pub fn to_tree(&self) -> oxirush_utils::tree::Value {
        match self {
            // A message that has no table: the fields of its view.
            Self::ServiceRequest(_) | Self::EmmTransport(_) => {
                view::to_tree(&self.to_view(), None, &decided)
            }
            message => view::tree(message, None, &decided, view::Scope::NONE),
        }
    }

    /// The message that a tree writes, as [`Self::to_tree`] shows one: its
    /// `message-type` names it, and each other member is an IE or a field of
    /// its header with its value, or `{"octets": "…"}` for the octets of an
    /// IE as they are sent. What the type of the message decides of its
    /// header is given where the tree leaves it out, and nothing else is: a
    /// mandatory IE that it leaves out is an error.
    ///
    /// The `message-type` is the name of the type or its number. A field of
    /// the header that the type does not decide is written, as the
    /// `eps-bearer-identity` and the `procedure-transaction-identity` of an
    /// ESM message.
    ///
    /// A tree with a `security-header` writes a message under that header:
    /// every field of the header is written, the code among them, and what
    /// else the tree has is the plain message, or `ciphered-message` alone
    /// with the `octets` of one that is ciphered.
    ///
    /// The message that comes back is one that [`Self::encode`] encodes. Two
    /// are not: a plain message under a header that says it is ciphered, and
    /// an EMM TRANSPORT with a `data-container`, which are what a security
    /// context deciphered and have no octets before one ciphers them.
    pub fn from_tree(tree: oxirush_utils::tree::Value) -> Result<Self> {
        let (protection, tree) = view::protection_of(tree).map_err(Error::EncodingError)?;
        let Some((header, ciphered)) = protection else {
            let view = view::from_tree(&tree, None, &decided, view::Scope::NONE)
                .map_err(Error::EncodingError)?;
            return Self::from_view(view);
        };
        let header: crate::nas_eps::SecurityHeader =
            view::security_header(&header, &[]).map_err(Error::EncodingError)?;
        // An EMM TRANSPORT is its header and a container.
        if header.security_header_type
            == crate::nas_eps::SecurityHeaderType::SecurityHeaderForTheEmmTransportMessage
        {
            let transport = EmmTransport::of_tree(header, ciphered, &tree);
            return (transport.map(Self::EmmTransport))
                .map_err(Error::EncodingError)
                .and_then(sendable);
        }
        let message = match ciphered {
            Some(octets) => Self::Opaque(octets),
            None => Self::from_tree(tree)?,
        };
        sendable(Self::SecurityProtected(header, Box::new(message)))
    }

    /// The values at `path` in the [tree](Self::to_tree) of the message, as
    /// [`paths::select`](crate::paths::select) gives them, and the octets of
    /// an IE that `octets` after its name selects as the message has them: the
    /// value part of the IE, without its IEI and its length, in hexadecimal.
    /// A tree has the value of an IE, and its octets where the value does not
    /// write them back; the message has the octets of each IE, also in a
    /// container: `/nas/nas-message-container/5gmm-capability/octets`.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::Message;
    /// use oxirush_nas::tree;
    ///
    /// // ATTACH REJECT with EMM cause #3
    /// let reject = Message::decode(&[0x07, 0x44, 0x03]).unwrap();
    /// assert_eq!(reject.select("/nas/emm-cause")?, [tree!("illegal-ue")]);
    /// assert_eq!(reject.select("/nas/emm-cause/octets")?, [tree!("03")]);
    /// # Ok::<(), tree::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Those of [`paths::select`](crate::paths::select), and `octets` after
    /// a field of a header, which has no octets of its own.
    pub fn select(
        &self,
        path: &str,
    ) -> core::result::Result<Vec<oxirush_utils::tree::Value>, oxirush_utils::tree::Error> {
        crate::paths::of_message(&self.to_tree(), path, |ie| {
            view::ie_octets(&self.to_view(), ie)
        })
    }

    /// The message that an edited tree of this one writes: this message, with
    /// what the tree changes.
    ///
    /// An IE that the tree leaves as [`Self::to_tree`] shows it keeps its octets.
    /// An IE whose value the tree changes is encoded from it, and one written as
    /// `{"octets": "…"}` has those octets, whatever they are: its length follows.
    /// An IE that the tree leaves out is taken out of the message, and an optional
    /// IE that the message does not have is added from what the tree writes. The
    /// message is otherwise this one, with its unknown IEs.
    ///
    /// Nothing that the tree says is ignored: a name that does not exist, a member
    /// that an IE or a value does not have, and a value that its IE cannot carry
    /// are errors. The message authentication code of a security header is that of
    /// the octets it was computed over: an edit of the message under the header that
    /// keeps the code is an error, and the code that the tree writes in
    /// `security-header` is taken as it is. The message that comes back is one that
    /// [`Self::encode`] encodes; what it says is not checked against the rules of a
    /// sender, which `validate()` has.
    ///
    /// ```
    /// use oxirush_nas::nas_eps::Message;
    /// use oxirush_nas::tree;
    ///
    /// // ATTACH REJECT with EMM cause #3
    /// let reject = Message::decode(&[0x07, 0x44, 0x03]).unwrap();
    /// let mut tree = reject.to_tree();
    /// tree["emm-cause"] = tree!("congestion");
    /// let edited = reject.with_tree(tree).unwrap();
    /// assert_eq!(edited.encode().unwrap(), [0x07, 0x44, 0x16]);
    /// ```
    pub fn with_tree(&self, tree: oxirush_utils::tree::Value) -> Result<Self> {
        let view = match self {
            // A message that has no table: the fields of its view.
            Self::ServiceRequest(_) | Self::EmmTransport(_) => self.to_view(),
            message => view::edited(message),
        };
        let edited = view::edited_view(view, self.to_tree(), tree, &decided, view::Scope::NONE)
            .map_err(Error::EncodingError)?;
        self.with_view(edited)
    }
}

/// The message `message` that a view or a tree wrote, if it is one that is
/// sent: what the header of a plain message cannot have is refused by the
/// name of its member, and whatever else has no octets as encoding refuses
/// it. A message that is not ciphered under a header that says it is, and an
/// EMM TRANSPORT whose container is not, have no octets before a security
/// context ciphers them, and are what they are.
fn sendable(message: Message) -> Result<Message> {
    use crate::nas_eps::SecurityHeaderType::{
        IntegrityProtectedAndCiphered, IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
        IntegrityProtectedAndPartiallyCipheredNasMessage,
    };
    let to_cipher = match &message {
        Message::SecurityProtected(header, inner) => {
            matches!(
                header.security_header_type,
                IntegrityProtectedAndCiphered
                    | IntegrityProtectedAndCipheredWithNewEpsSecurityContext
                    | IntegrityProtectedAndPartiallyCipheredNasMessage
            ) && !matches!(**inner, Message::Opaque(_))
        }
        Message::EmmTransport(transport) => transport.data_container.is_some(),
        _ => false,
    };
    match message.refused_header() {
        Some(refused) => Err(Error::EncodingError(refused)),
        None if to_cipher => Ok(message),
        None => message.encode().map(|_| message),
    }
}

impl EmmMessageType {
    /// The message that a view describes alone, which its `message-type` names.
    pub(crate) fn message_from_view(self, view: oxirush_utils::tree::Value) -> Result<Message> {
        let from = |kind: &str| view::from_view(&["Emm"], kind, view.clone(), view::Scope::NONE);
        if let Err(error) = view::typed::<Message>(&format!("{self:?}"), &view) {
            return Err(Error::EncodingError(error));
        }
        match self {
            // A view of neither message is refused as each of the two.
            Self::DetachRequest => from("DetachRequestUeOriginating").or_else(|from_ue| {
                let to_ue = from("DetachRequestUeTerminated");
                to_ue.map_err(|to_ue| format!("from the UE: {from_ue}; to the UE: {to_ue}"))
            }),
            _ => from(&format!("{self:?}")),
        }
        .map_err(Error::EncodingError)
        .and_then(sendable)
    }

    /// The names of the members that the tree of a message of this type can
    /// have: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn names(self) -> Vec<String> {
        use crate::nas_eps::{EmmHeader, EmmMessage};
        match self {
            Self::DetachRequest => view::names::<EmmHeader>(
                &["DetachRequestUeOriginating", "DetachRequestUeTerminated"],
                EmmMessage::fields_named,
            ),
            _ => view::names::<EmmHeader>(&[&format!("{self:?}")], EmmMessage::fields_named),
        }
    }
}

impl EsmMessageType {
    /// The message that a view describes alone, which its `message-type` names.
    pub(crate) fn message_from_view(self, view: oxirush_utils::tree::Value) -> Result<Message> {
        let kind = format!("{self:?}");
        view::typed::<Message>(&kind, &view)
            .and_then(|()| view::from_view(&["Esm"], &kind, view, view::Scope::NONE))
            .map_err(Error::EncodingError)
            .and_then(sendable)
    }

    /// The names of the members that the tree of a message of this type can
    /// have: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn names(self) -> Vec<String> {
        view::names::<crate::nas_eps::EsmHeader>(&[&format!("{self:?}")], EsmMessage::fields_named)
    }
}

// ── Values ─────────────────────────────────────────────────────────────────
//
// Each is what the typed accessors of the IE return, and is encoded back
// by the matching constructor or setters.

use crate::common::ts24008::PcoDirection;
use crate::common::ts24301::KeySetIdentifierValue;
use crate::common::view::{
    Code, built_ie, code_ie, configuration_options_ie, container_ie, decoded_ie, fields_ie,
    named_ie, numbers, octets, shared_ies, timer_ie, write_code,
};
use crate::nas_eps::*;
use core::net::IpAddr;

// The IEs that TS 24.501 and TS 24.301 have alike.
shared_ies!();

/// The EPS bearer identities that an IE has the bits of: 1 to 15.
fn ebis(bearers: &[u16]) -> core::result::Result<Vec<u8>, ValueError> {
    octets("eps-bearer-identity", bearers, 1, 15)
}

// The units of the protocol configuration options, by the direction of the
// message.
configuration_options_ie!(ProtocolConfigurationOptions);

// A container of a plain NAS message: the view of the message.
container_ie!(
    EsmMessageContainer: Message,
    |ie| ie.decode_as_esm_message().ok(),
    |message| EsmMessageContainer::from_esm_message(message)
);
container_ie!(
    ReplayedNasMessageContainer: Message,
    |ie| ie.decode_as_emm_message().ok(),
    |message| ReplayedNasMessageContainer::from_emm_message(message)
);

// One coded value.
code_ie!(
    EmmCause,
    EmmCauseValue,
    |ie| EmmCauseValue::try_from(ie.value).ok(),
    EmmCause::from_cause
);
code_ie!(
    EsmCause,
    EsmCauseValue,
    |ie| EsmCauseValue::try_from(ie.value).ok(),
    EsmCause::from_cause
);
code_ie!(
    EpsAttachType,
    AttachType,
    |ie| ie.attach_type_strict(),
    EpsAttachType::from_attach_type
);
code_ie!(
    EpsAttachResult,
    AttachResult,
    |ie| ie.attach_result(),
    EpsAttachResult::from_attach_result
);
code_ie!(
    EpsUpdateResult,
    UpdateResult,
    |ie| ie.update_result(),
    EpsUpdateResult::from_update_result
);
code_ie!(
    ServiceType,
    ServiceTypeValue,
    |ie| ie.service_type_strict(),
    ServiceType::from_service_type
);
/// The identity that an IDENTITY REQUEST asks for (TS 24.008 Table
/// 10.5.142), by its name.
#[derive(Clone, Copy)]
enum IdentityTypeName {
    Imsi,
    Imei,
    Imeisv,
    Tmsi,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum IdentityTypeName {
        Imsi,
        Imei,
        Imeisv,
        Tmsi,
    }
);

code_ie!(
    IdentityType2,
    IdentityTypeName,
    |ie| match ie.identity_type_strict()? {
        IdentityType::Imsi => Some(IdentityTypeName::Imsi),
        IdentityType::Imei => Some(IdentityTypeName::Imei),
        IdentityType::Imeisv => Some(IdentityTypeName::Imeisv),
        IdentityType::Tmsi => Some(IdentityTypeName::Tmsi),
        _ => None,
    },
    |name| IdentityType2::new(match name {
        IdentityTypeName::Imsi => IdentityType::Imsi,
        IdentityTypeName::Imei => IdentityType::Imei,
        IdentityTypeName::Imeisv => IdentityType::Imeisv,
        IdentityTypeName::Tmsi => IdentityType::Tmsi,
    } as u8)
);
code_ie!(
    PdnType,
    PdnTypeValue,
    |ie| ie.pdn_type_strict(),
    PdnType::from_pdn_type
);
code_ie!(
    AdditionalUpdateResult,
    AdditionalUpdateResultValue,
    |ie| ie.result(),
    AdditionalUpdateResult::from_result
);
code_ie!(
    SmsServicesStatus,
    SmsServicesStatusValue,
    |ie| ie.status(),
    SmsServicesStatus::from_status
);
code_ie!(
    GenericMessageContainerType,
    GenericMessageContainerTypeValue,
    |ie| ie.container_type(),
    GenericMessageContainerType::from_container_type
);
code_ie!(
    RadioPriority,
    RadioPriorityLevel,
    |ie| RadioPriorityLevel::try_from(ie.priority_level_raw() & 0x07).ok(),
    RadioPriority::from_priority_level
);
named_ie!(
    NbS1DrxParameter,
    NbS1DrxValue,
    |ie| ie.drx_value(),
    NbS1DrxParameter::from_drx_value
);
named_ie!(
    EpsAdditionalRequestResult,
    PagingRestrictionDecision,
    |ie| ie.paging_restriction_decision(),
    EpsAdditionalRequestResult::from_paging_restriction_decision
);
named_ie!(
    NotificationIndicator,
    NotificationIndicatorValue,
    |ie| ie.indicator(),
    NotificationIndicator::from_indicator
);

// The fields of an octet.
fields_ie!(EpsUpdateType {
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
fields_ie!(ControlPlaneServiceType {
    "service-type":
        |ie| Code::of(ie.service_type_strict(), ie.service_type_raw()),
        |ie, code: Code<ControlPlaneServiceTypeValue>| write_code(
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
fields_ie!(DetachType {
    "ue-detach-kind":
        |ie| Code::of(UeDetachKind::try_from(ie.value & 0x07).ok(), ie.detach_type_raw()),
        |ie, code: Code<UeDetachKind>| write_code(
            ie,
            code,
            |ie, name| {
                ie.value = DetachType::from_ue_detach_kind(name, ie.is_switch_off()).value;
            },
            |ie| ie.detach_type_raw(),
        );
    "network-detach-kind":
        |ie| Code::of(NetworkDetachKind::try_from(ie.value & 0x07).ok(), ie.detach_type_raw()),
        |ie, code: Code<NetworkDetachKind>| write_code(
            ie,
            code,
            |ie, name| {
                ie.value = DetachType::from_network_detach_kind(name).value | (ie.value & 0x08);
            },
            |ie| ie.detach_type_raw(),
        );
    "switch-off": |ie| ie.is_switch_off(), |ie, on: bool| {
        ie.value = (ie.value & !0x08) | (u8::from(on) << 3);
    };
});
fields_ie!(SecurityAlgorithms {
    "ciphering":
        |ie| Code::of(CipheringAlgorithm::try_from(ie.ciphering_raw()).ok(), ie.ciphering_raw()),
        |ie, code: Code<CipheringAlgorithm>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_ciphering_raw(name as u8);
            },
            |ie| ie.ciphering_raw(),
        );
    "integrity":
        |ie| Code::of(IntegrityAlgorithm::try_from(ie.integrity_raw()).ok(), ie.integrity_raw()),
        |ie, code: Code<IntegrityAlgorithm>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_integrity_raw(name as u8);
            },
            |ie| ie.integrity_raw(),
        );
});

// The flags of an indication, by the names of its accessors.
built_ie!(
    AdditionalUpdateType,
    |sms_only, signalling_active, ciot| Ok(Self::from_fields(sms_only, signalling_active, ciot)),
    {
        sms_only: bool,
        signalling_active: bool,
        preferred_ciot_behavior: PreferredCiotBehavior = |ie| ie.preferred_ciot_behavior(),
    }
);
built_ie!(ConnectivityType, |lipa| Ok(Self::from_lipa(lipa)), { is_lipa: bool });
built_ie!(ControlPlaneOnlyIndication, Self::from_cpoi, { cpoi: bool });
built_ie!(CsfbResponse, |accepted| Ok(Self::from_accepted(accepted)), {
    accepted: bool = |ie| ie.accepted()
});
built_ie!(
    EsmInformationTransferFlag,
    |required| Ok(Self::from_required(required)),
    { is_required: bool }
);
built_ie!(
    ExtendedEmmCause,
    |eutran, optimization, nb_iot, satellite| {
        Ok(Self::from_flags(eutran, optimization, nb_iot, satellite))
    },
    {
        eutran_not_allowed: bool,
        eps_optimization_not_supported: bool,
        nb_iot_not_allowed: bool,
        satellite_eutran_not_allowed: bool,
    }
);
built_ie!(
    LcsIndicator,
    |mt_lr: bool| {
        let rule = "is true in an IE that is sent: a message without the IE says false";
        mt_lr.then(Self::mt_lr).ok_or(ValueError::combination("is-mt-lr", rule))
    },
    { is_mt_lr: bool }
);
built_ie!(GutiType, |mapped| Ok(Self::from_mapped(mapped)), { is_mapped: bool });
named_ie!(
    PagingIdentity,
    PagingIdentityValue,
    |ie| Some(ie.paging_identity()),
    PagingIdentity::from_paging_identity
);
built_ie!(TmsiStatus, |valid| Ok(Self::from_valid_tmsi(valid)), { has_valid_tmsi: bool });
built_ie!(
    UeInformationRequest,
    |requested| Ok(Self::from_requested(requested)),
    { requested: bool }
);
built_ie!(
    UeRadioCapabilityIdAvailability,
    |available| Ok(Self::from_available(available)),
    { is_available: bool = |ie| ie.is_available() }
);
built_ie!(
    UeRadioCapabilityIdRequest,
    |requested| Ok(Self::from_requested(requested)),
    { is_requested: bool = |ie| ie.is_requested() }
);
built_ie!(
    UeRadioCapabilityInformationUpdateNeeded,
    |needed| Ok(Self::from_update_needed(needed)),
    { update_needed: bool }
);
built_ie!(
    VoiceDomainPreferenceAndUeUsageSetting,
    |preference, data_centric| Ok(Self::from_fields(preference, data_centric)),
    {
        voice_domain_preference: VoiceDomainPreference = |ie| ie.voice_domain_preference(),
        data_centric: bool = |ie| ie.data_centric(),
    }
);
built_ie!(TransactionIdentifier, Self::from_ti, {
    ti_flag: bool = |ie| ie.ti_flag(),
    ti_value: u8 = |ie| ie.ti_value(),
});
built_ie!(DrxParameter, Self::from_fields, {
    split_pg_cycle_code: u8 = |ie| ie.split_pg_cycle_code(),
    s1_drx_value: S1DrxValue = |ie| ie.s1_drx_value(),
    split_on_ccch: bool = |ie| ie.split_on_ccch(),
    non_drx_timer: u8 = |ie| ie.non_drx_timer(),
});
// The unit of the extended T3412 value says whether the IE counts at all,
// so it reads with the count and not as seconds.
built_ie!(
    T3412ExtendedValue,
    Self::from_unit_value,
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

fields_ie!(UeNetworkCapability {
    "eea": |ie| supported(ie, Self::supports_eea, 8), |ie, algorithms: Vec<u16>| {
        (0..8).try_for_each(|algorithm| {
            ie.set_eea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "eia": |ie| supported(ie, Self::supports_eia, 8), |ie, algorithms: Vec<u16>| {
        (0..7).try_for_each(|algorithm| {
            ie.set_eia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "uea": |ie| supported(ie, Self::supports_uea, 8), |ie, algorithms: Vec<u16>| {
        (0..8).try_for_each(|algorithm| {
            ie.set_uea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "uia": |ie| supported(ie, Self::supports_uia, 8), |ie, algorithms: Vec<u16>| {
        (1..8).try_for_each(|algorithm| {
            ie.set_uia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
} flags);
fields_ie!(UeSecurityCapability {
    "eea": |ie| supported(ie, Self::supports_eea, 8), |ie, algorithms: Vec<u16>| {
        (0..8).try_for_each(|algorithm| {
            ie.set_eea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "eia": |ie| supported(ie, Self::supports_eia, 8), |ie, algorithms: Vec<u16>| {
        (0..7).try_for_each(|algorithm| {
            ie.set_eia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "uea": |ie| supported(ie, Self::supports_uea, 8), |ie, algorithms: Vec<u16>| {
        (0..8).try_for_each(|algorithm| {
            ie.set_uea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "uia": |ie| supported(ie, Self::supports_uia, 8), |ie, algorithms: Vec<u16>| {
        (1..8).try_for_each(|algorithm| {
            ie.set_uia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "gea": |ie| supported(ie, Self::supports_gea, 8), |ie, algorithms: Vec<u16>| {
        (1..8).try_for_each(|algorithm| {
            ie.set_gea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
} flags);
fields_ie!(UeAdditionalSecurityCapability {
    "ea": |ie| supported(ie, Self::supports_ea, 16), |ie, algorithms: Vec<u16>| {
        (0..16).try_for_each(|algorithm| {
            ie.set_ea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "ia": |ie| supported(ie, Self::supports_ia, 16), |ie, algorithms: Vec<u16>| {
        (0..16).try_for_each(|algorithm| {
            ie.set_ia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
});

/// The identity of an EPS mobile identity, by its type of identity.
enum EpsMobileIdentityForm {
    Imsi(String),
    Imei(String),
    Guti(GutiForm),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum EpsMobileIdentityForm {
        Imsi(String),
        Imei(String),
        Guti(GutiForm),
    }
);

/// A GUTI by its parts, as a view writes it.
struct GutiForm {
    plmn: crate::common::Plmn,
    mme_group_id: u16,
    mme_code: u8,
    m_tmsi: u32,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct GutiForm { plmn as plmn, mme_group_id, mme_code, m_tmsi });

decoded_ie!(
    EpsMobileIdentity: EpsMobileIdentityForm,
    |ie| Some(match ie.identity_type()? {
        MobileIdentityTypeEps::Imsi => EpsMobileIdentityForm::Imsi(ie.as_imsi()?.to_string()),
        MobileIdentityTypeEps::Imei => EpsMobileIdentityForm::Imei(ie.as_imei()?.to_string()),
        MobileIdentityTypeEps::Guti => {
            let guti = ie.as_guti()?;
            EpsMobileIdentityForm::Guti(GutiForm {
                plmn: guti.plmn(),
                mme_group_id: guti.mme_group_id(),
                mme_code: guti.mme_code(),
                m_tmsi: guti.m_tmsi(),
            })
        }
        _ => return None,
    }),
    |_, identity| match identity {
        EpsMobileIdentityForm::Imsi(imsi) => EpsMobileIdentity::from_imsi(&imsi),
        EpsMobileIdentityForm::Imei(imei) => EpsMobileIdentity::from_imei(&imei),
        EpsMobileIdentityForm::Guti(guti) => Ok(EpsMobileIdentity::from_guti(GutiEps::new(
            guti.plmn,
            guti.mme_group_id,
            guti.mme_code,
            guti.m_tmsi,
        ))),
    }
);

/// The identity of a mobile identity of TS 24.008, by its type of identity.
enum MobileIdentityForm {
    NoIdentity,
    Imsi(String),
    Imei(String),
    Imeisv(String),
    Tmsi(u32),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum MobileIdentityForm {
        NoIdentity,
        Imsi(String),
        Imei(String),
        Imeisv(String),
        Tmsi(u32),
    }
);

decoded_ie!(
    MobileIdentity: MobileIdentityForm,
    |ie| {
        if ie.is_no_identity() {
            return Some(MobileIdentityForm::NoIdentity);
        }
        (ie.as_imsi().map(|imsi| MobileIdentityForm::Imsi(imsi.to_string())))
            .or_else(|| ie.as_imei().map(|imei| MobileIdentityForm::Imei(imei.to_string())))
            .or_else(|| (ie.as_imeisv()).map(|imeisv| MobileIdentityForm::Imeisv(imeisv.to_string())))
            .or_else(|| ie.as_tmsi().map(MobileIdentityForm::Tmsi))
    },
    |_, identity| match identity {
        MobileIdentityForm::NoIdentity => Ok(MobileIdentity::from_no_identity()),
        MobileIdentityForm::Imsi(imsi) => MobileIdentity::from_imsi(&imsi),
        MobileIdentityForm::Imei(imei) => MobileIdentity::from_imei(&imei),
        MobileIdentityForm::Imeisv(imeisv) => MobileIdentity::from_imeisv(&imeisv),
        MobileIdentityForm::Tmsi(tmsi) => Ok(MobileIdentity::from_tmsi(tmsi)),
    }
);

// Tracking areas and PLMNs.
decoded_ie!(
    TrackingAreaIdentityList: Vec<TaiListEntry>,
    |ie| ie.receiver_syntax_is_valid().then(|| ie.entries()),
    |_, entries| TrackingAreaIdentityList::from_entries(&entries)
);
decoded_ie!(
    TrackingAreaIdentity: view::TaiForm<TaiEps>,
    |ie| ie.tai().map(view::TaiForm),
    |_, tai| Ok(TrackingAreaIdentity::from_tai(tai.0))
);
decoded_ie!(
    LocationAreaIdentification: Lai,
    |ie| ie.lai(),
    |_, lai| Ok(LocationAreaIdentification::from_lai(lai))
);

// Timers, names and numbers.
timer_ie!(T3412Value);
decoded_ie!(
    AccessPointName: String,
    |ie| ie.as_string(),
    |_, name| AccessPointName::from_string(&name)
);

decoded_ie!(DcnId: u16, |ie| ie.dcn_id(), |_, identity| Ok(DcnId::from_dcn_id(identity)));
decoded_ie!(
    NetworkResourceIdentifierContainer: u16,
    |ie| ie.nri(),
    |_, nri| NetworkResourceIdentifierContainer::from_nri(nri)
);
decoded_ie!(
    PTmsiSignature: u32,
    |ie| ie.p_tmsi_signature(),
    |_, signature| PTmsiSignature::from_p_tmsi_signature(signature)
);
decoded_ie!(
    LinkedEpsBearerIdentity: u8,
    |ie| Some(ie.bearer_identity()),
    |_, identity| LinkedEpsBearerIdentity::from_bearer_identity(identity)
);
decoded_ie!(
    ImsiOffset: u16,
    |ie| ie.imsi_offset(),
    |_, offset| Ok(ImsiOffset::from_imsi_offset(offset))
);
decoded_ie!(SsCode: u8, |ie| Some(ie.code()), |_, code| Ok(SsCode::from_code(code)));
decoded_ie!(
    CipheringKeySequenceNumber: u8,
    |ie| ie.key_sequence_number_strict(),
    |_, number| match number {
        7 => {
            let expected = "0 to 6: 7 says that no key is available, and is written as `octets`";
            Err(ValueError::value("key-sequence", number, expected))
        }
        number => CipheringKeySequenceNumber::from_key_sequence_number(number),
    }
);
decoded_ie!(
    PacketFlowIdentifier: PacketFlowId,
    |ie| ie.pfi(),
    |_, pfi| PacketFlowIdentifier::from_pfi(pfi)
);
decoded_ie!(
    PkmfAddress: IpAddr,
    |ie| ie.address(),
    |_, address| Ok(PkmfAddress::from_address(address))
);

// Bearers: the identities a status has the bits of, and what a bearer has.
decoded_ie!(
    HeaderCompressionConfigurationStatus: Vec<u16>,
    |ie| ie.is_well_formed().then(|| numbers(&ie.not_used_ebis())),
    |_, bearers| HeaderCompressionConfigurationStatus::from_not_used_ebis(&ebis(&bearers)?)
);
decoded_ie!(
    PdnAddress: PdnAddressValue,
    |ie| ie.pdn_address(),
    |_, address| Ok(PdnAddress::from_pdn_address(address))
);
decoded_ie!(
    ApnAggregateMaximumBitRate: ApnAmbrValue,
    |ie| ie.parse(),
    |_, ambr| ApnAggregateMaximumBitRate::from_kbps(ambr.dl_kbps, ambr.ul_kbps)
);
decoded_ie!(
    ExtendedApnAggregateMaximumBitRate: ExtendedApnAmbr,
    |ie| ie.ambr(),
    |_, ambr| Ok(ExtendedApnAggregateMaximumBitRate::from_ambr(ambr))
);
macro_rules! eps_qos_view {
    ($($ie:ty),+) => {$(
        decoded_ie!($ie: EpsQos, |ie| ie.qos(), |_, qos| <$ie>::from_qos(qos));
    )+};
}
eps_qos_view!(EpsQualityOfService);
decoded_ie!(
    ExtendedQualityOfService: ExtendedEpsQos,
    |ie| ie.qos(),
    |_, qos| Ok(ExtendedQualityOfService::from_qos(qos))
);
decoded_ie!(TrafficFlowTemplate: Tft, |ie| ie.tft(), |_, tft| TrafficFlowTemplate::from_tft(&tft));
decoded_ie!(
    TrafficFlowAggregateDescription: Tft,
    |ie| ie.tft(),
    |_, tft| TrafficFlowAggregateDescription::from_tft(&tft)
);

// Capabilities: every flag by its name, and the algorithms by number.
fields_ie!(N1UeNetworkCapability {
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
fields_ie!(EpsNetworkFeatureSupport {
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
fields_ie!(MsNetworkCapability {} flags);
fields_ie!(AdditionalInformationRequested {} flags);
fields_ie!(DeviceProperties {} flags);
fields_ie!(WlanOffloadAcceptability {} flags);
fields_ie!(NetworkPolicy {} flags);
fields_ie!(MsNetworkFeatureSupport {} flags);

// The parts of an IE that its constructor takes.
built_ie!(
    HeaderCompressionConfiguration,
    |profiles, max_cid, setup: Option<IpHdrCompAdditionalSetupType>, container: Option<Vec<u8>>| {
        match (setup, container) {
            (None, None) => Self::from_profiles(profiles, max_cid),
            (Some(setup), container) => Self::from_profiles_with_additional_setup(
                profiles,
                max_cid,
                setup,
                &container.unwrap_or_default(),
            ),
            (None, Some(_)) => {
                let rule = "is written with `additional-setup-type`";
                Err(ValueError::combination("additional-setup-container", rule))
            }
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
    PagingRestriction,
    |restriction_type, bearers: Vec<u16>| Self::from_restriction(restriction_type, &ebis(&bearers)?),
    {
        restriction_type: PagingRestrictionType =
            |ie| ie.restriction_type().filter(|_| ie.is_well_formed()),
        unrestricted_ebis: Vec<u16> =
            |ie| Some(numbers(&ie.unrestricted_ebis().unwrap_or_default())),
    }
);
built_ie!(
    SAndFSatelliteOperationParameters,
    |wait_time, uplink_delivery_time, monitoring_list: SAndFMonitoringList| {
        Self::from_fields(wait_time, uplink_delivery_time, &monitoring_list)
    },
    {
        wait_time: Option<u16> = |ie| ie.is_well_formed().then(|| ie.wait_time()),
        uplink_delivery_time: Option<u32> = |ie| Some(ie.uplink_delivery_time()),
        monitoring_list: SAndFMonitoringList = |ie| ie.monitoring_list(),
    }
);

/// The value of a CLI: the calling party number, with the names of its
/// codes. Octet 3a has the two indicators, or neither is there.
struct CallingNumber {
    type_of_number: CallingPartyTypeOfNumber,
    numbering_plan: CallingPartyNumberingPlan,
    presentation: Option<CallingPartyPresentation>,
    screening: Option<CallingPartyScreening>,
    digits: String,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct CallingNumber { type_of_number, numbering_plan, presentation, screening, digits });

decoded_ie!(
    Cli: CallingNumber,
    |ie| {
        let number = ie.number()?;
        let indicators = match number.presentation_screening {
            Some(_) => Some(number.presentation_screening_values()?),
            None => None,
        };
        Some(CallingNumber {
            type_of_number: number.type_of_number_value()?,
            numbering_plan: number.numbering_plan_value()?,
            presentation: indicators.map(|(presentation, _)| presentation),
            screening: indicators.map(|(_, screening)| screening),
            digits: number.digits,
        })
    },
    |_, number| {
        let presentation_screening = match (number.presentation, number.screening) {
            (Some(presentation), Some(screening)) => Some((presentation as u8, screening as u8)),
            (None, None) => None,
            (Some(_), None) => {
                let rule = "is written with `screening`: octet 3a has both or neither";
                return Err(ValueError::combination("presentation", rule));
            }
            (None, Some(_)) => {
                let rule = "is written with `presentation`: octet 3a has both or neither";
                return Err(ValueError::combination("screening", rule));
            }
        };
        Cli::from_number(&CallingPartyNumber {
            type_of_number: number.type_of_number as u8,
            numbering_plan: number.numbering_plan as u8,
            presentation_screening,
            digits: number.digits,
        })
    }
);

// Lists and containers that their constructors build from the entries that
// are parsed. What an author writes is built and read back: a value that
// the IE does not then have is refused.
decoded_ie!(
    NbifomContainer: Vec<NbifomParameter>,
    |ie| ie.parameters(),
    |_, parameters| NbifomContainer::from_parameters(&parameters)
);
decoded_ie!(
    CipheringKeyData: Vec<CipheringDataSet>,
    |ie| ie.is_well_formed().then(|| ie.data_sets()),
    |_, sets| CipheringKeyData::from_data_sets(&sets)
);
decoded_ie!(
    RemoteUeContextList: Vec<RemoteUeContext>,
    |ie| ie.contexts(),
    |_, contexts| RemoteUeContextList::from_contexts(&contexts)
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::view::tests::{exercise, replace_parts, sweep};

    #[test]
    fn values_encode_back_and_take_nothing_unchecked() {
        // Every octet has a value that encodes back, or none; the parts of
        // the values of a few are replaced too.
        for value in 0..=255_u8 {
            replace_parts([1, 0x16, 0x79, 0xff].contains(&value));
            let half = value & 0x0f;
            sweep(HeaderCompressionConfiguration::new(vec![value; 3]));
            sweep(HeaderCompressionConfiguration::new(vec![
                value & 0x7f,
                0,
                value,
                value & 7,
                value,
            ]));
            sweep(PagingRestriction::new(vec![half]));
            sweep(PagingRestriction::new(vec![3, value & 0xfe, value]));
            // The flags alone, and with what they indicate
            sweep(SAndFSatelliteOperationParameters::new(vec![value & 0x0c]));
            sweep(SAndFSatelliteOperationParameters::new(vec![
                value & 0x0b,
                0,
                value,
                0,
                1,
                value,
                1,
                value,
            ]));
            sweep(EmmCause::new(value));
            sweep(EsmCause::new(value));
            sweep(EpsAttachType::new(half));
            sweep(EpsAttachResult::new(half));
            sweep(EpsUpdateResult::new(half));
            sweep(EpsUpdateType::new(half));
            sweep(ServiceType::new(half));
            sweep(ControlPlaneServiceType::new(half));
            sweep(IdentityType2::new(half));
            sweep(RequestType::new(half));
            sweep(PdnType::new(half));
            sweep(DetachType::new(half));
            sweep(KeySetIdentifier::new(half));
            sweep(SecurityAlgorithms::new(value));
            sweep(T3412Value::new(value));
            sweep(GprsTimer::new(value));
            sweep(GprsTimer2::new(vec![value]));
            sweep(GprsTimer3::new(vec![value]));
            sweep(T3412ExtendedValue::new(vec![value]));
            sweep(UeNetworkCapability::new(vec![value; 2]));
            sweep(UeNetworkCapability::new(vec![value; 13]));
            sweep(UeSecurityCapability::new(vec![value; 2]));
            sweep(UeSecurityCapability::new(vec![value; 5]));
            sweep(UeAdditionalSecurityCapability::new(vec![value; 4]));
            sweep(N1UeNetworkCapability::new(vec![value]));
            sweep(EpsNetworkFeatureSupport::new(vec![value; 2]));
            sweep(MsNetworkCapability::new(vec![value; 3]));
            sweep(EpsBearerContextStatus::new(vec![value & 0xfe, value]));
            sweep(HeaderCompressionConfigurationStatus::new(vec![
                value & 0xe0,
                value,
            ]));
            sweep(AdditionalUpdateType::new(half));
            sweep(ConnectivityType::new(half));
            sweep(ControlPlaneOnlyIndication::new(half));
            sweep(CsfbResponse::new(half));
            sweep(EsmInformationTransferFlag::new(half));
            sweep(ExtendedEmmCause::new(half));
            sweep(LcsIndicator::new(value));
            sweep(GutiType::new(half));
            sweep(PagingIdentity::new(half));
            sweep(TmsiStatus::new(half));
            sweep(UeInformationRequest::new(half));
            sweep(UeRadioCapabilityIdAvailability::new(vec![value]));
            sweep(UeRadioCapabilityIdRequest::new(vec![value]));
            sweep(UeRadioCapabilityInformationUpdateNeeded::new(half));
            sweep(VoiceDomainPreferenceAndUeUsageSetting::new(vec![value]));
            sweep(TransactionIdentifier::new(vec![value]));
            sweep(DrxParameter::new(vec![value, value]));
            sweep(RegistrationWaitRange::new(vec![value, value]));
            sweep(ExtendedDrxParameters::new(vec![value]));
            sweep(TimeZoneAndTime::new(vec![value & 0x11; 7]));
            sweep(DcnId::new(vec![value, value]));
            sweep(NetworkResourceIdentifierContainer::new(vec![
                value,
                value & 0xc0,
            ]));
            sweep(PTmsiSignature::new(vec![value; 3]));
            sweep(LinkedEpsBearerIdentity::new(half));
            sweep(ImsiOffset::new(vec![value, value]));
            sweep(SsCode::new(value));
            sweep(PacketFlowIdentifier::new(vec![value & 0x7f]));
            sweep(NbS1DrxParameter::new(vec![value]));
            sweep(EpsAdditionalRequestResult::new(vec![value]));
            sweep(NotificationIndicator::new(vec![value]));
            sweep(WusAssistanceInformation::new(vec![value]));
            sweep(ImeisvRequest::new(half));
            sweep(RadioPriority::new(half));
            sweep(CipheringKeySequenceNumber::new(half));
            sweep(UnavailabilityInformation::new(vec![
                value & 0x1f,
                0,
                0,
                value,
            ]));
            sweep(UnavailabilityConfiguration::new(vec![
                value & 0x1f,
                0,
                0,
                value,
            ]));
        }
        replace_parts(true);
        let plmn = [0x02, 0xf8, 0x39];
        let octets = |parts: &[&[u8]]| parts.concat();
        exercise(EpsMobileIdentity::from_imsi("208930000000001").unwrap());
        exercise(EpsMobileIdentity::from_imei("356938035643809").unwrap());
        exercise(EpsMobileIdentity::new(octets(&[
            &[0xf6],
            &plmn,
            &[0x80, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44],
        ])));
        exercise(MobileIdentity::from_imsi("208930000000001").unwrap());
        exercise(MobileIdentity::from_imei("356938035643809").unwrap());
        exercise(MobileIdentity::from_imeisv("3569380356438091").unwrap());
        exercise(MobileIdentity::from_tmsi(0x1122_3344));
        exercise(MobileIdentity::from_no_identity());
        for list in [
            octets(&[&[0x01], &plmn, &[0, 1, 0, 2]]),
            octets(&[&[0x21], &plmn, &[0, 1]]),
            octets(&[&[0x41], &plmn, &[0, 1], &plmn, &[0, 2]]),
        ] {
            exercise(TrackingAreaIdentityList::new(list));
        }
        exercise(TrackingAreaIdentity::new(octets(&[&plmn, &[0, 1]])));
        exercise(LocationAreaIdentification::new(octets(&[&plmn, &[0, 1]])));
        exercise(PlmnList::new(octets(&[&plmn, &[0x02, 0x18, 0x39]])));
        exercise(PlmnIdentity::new(plmn));
        exercise(AccessPointName::new(b"\x08internet".to_vec()));
        exercise(PdnAddress::new(vec![1, 10, 0, 0, 1]));
        exercise(PdnAddress::new(vec![
            3, 1, 2, 3, 4, 5, 6, 7, 8, 10, 0, 0, 1,
        ]));
        exercise(ApnAggregateMaximumBitRate::new(vec![0x5e, 0x5e]));
        exercise(ExtendedApnAggregateMaximumBitRate::new(vec![
            3, 0, 100, 3, 0, 50,
        ]));
        exercise(EpsQualityOfService::new(vec![9]));
        exercise(EpsQualityOfService::new(vec![1, 0x40, 0x40, 0x40, 0x40]));
        exercise(ExtendedQualityOfService::new(vec![
            3, 0, 1, 0, 1, 3, 0, 1, 0, 1,
        ]));
        // Create new TFT: one uplink packet filter matching protocol 17.
        exercise(TrafficFlowTemplate::new(vec![0x21, 0x21, 0, 2, 0x30, 17]));
        exercise(NetworkName::from_name("Open5GS", false));
        exercise(TimeZone::new(0x40));
        exercise(EmergencyNumberList::new(vec![3, 0x1f, 0x11, 0xf2]));
        exercise(PkmfAddress::new(vec![1, 10, 0, 0, 1]));
        exercise(SupportedCodecList::new(vec![4, 2, 0x60, 0]));
        // A container of a PDN CONNECTIVITY REQUEST.
        exercise(EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x31]));
    }
}

/// The serde form of a message is its tree: [`Message::to_tree`], and
/// [`Message::from_tree`] the other way.
impl oxirush_utils::tree::Tree for Message {
    const NAME: &'static str = "Message";

    fn to_tree(&self) -> oxirush_utils::tree::Value {
        Message::to_tree(self)
    }

    fn from_tree(
        value: &oxirush_utils::tree::Value,
        reading: &mut oxirush_utils::tree::Reading,
    ) -> core::result::Result<Self, oxirush_utils::tree::Refused> {
        (Message::from_tree(value.clone())).map_err(|error| {
            let why = view::unencoded(error);
            reading.refuse(oxirush_utils::tree::ErrorKind::Value, why)
        })
    }
}

oxirush_utils::impl_serde!(Message);
