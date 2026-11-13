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

//! The view of a 5GS message and the values of its IEs.

use crate::common::readable;
use crate::common::view::{self, Ie, Viewed, Visit};
use crate::common::{Error, MessageBody, Result};
use crate::nas_5gs::{GmmMessage, GmmMessageType, GsmMessage, GsmMessageType, Message};
use crate::prelude::*;
use oxirush_utils::identity::ProtectionScheme;

/// Visit the IEs of `body` in `scope`, with `ie` in the place of the field
/// `field`.
fn with_ie(
    body: &dyn MessageBody,
    field: &str,
    ie: &dyn Ie,
    scope: view::Scope,
    visit: &mut Visit<'_>,
) {
    body.ies(scope, &mut |visited| {
        let ie = if visited.name == field {
            Some(ie)
        } else {
            visited.ie
        };
        visit(view::Field { ie, ..visited })
    });
}

/// Who sends a 5GSM message, where its type says so (TS 24.501 §8.3): the
/// units of its protocol configuration options are read by it.
fn sent(message: &GsmMessage) -> Option<PcoDirection> {
    use GsmMessage as M;
    match message {
        M::PduSessionEstablishmentRequest(_)
        | M::PduSessionAuthenticationComplete(_)
        | M::PduSessionModificationRequest(_)
        | M::PduSessionModificationComplete(_)
        | M::PduSessionModificationCommandReject(_)
        | M::PduSessionReleaseRequest(_)
        | M::PduSessionReleaseComplete(_)
        | M::ServiceLevelAuthenticationComplete(_)
        | M::RemoteUeReport(_) => Some(PcoDirection::Uplink),
        M::PduSessionEstablishmentAccept(_)
        | M::PduSessionEstablishmentReject(_)
        | M::PduSessionAuthenticationCommand(_)
        | M::PduSessionAuthenticationResult(_)
        | M::PduSessionModificationReject(_)
        | M::PduSessionModificationCommand(_)
        | M::PduSessionReleaseReject(_)
        | M::PduSessionReleaseCommand(_)
        | M::ServiceLevelAuthenticationCommand(_)
        | M::RemoteUeReportResponse(_) => Some(PcoDirection::Downlink),
        // A 5GSM STATUS is sent by either.
        M::FiveGsmStatus(_) => None,
    }
}

impl Viewed for Message {
    fn ies(&self, scope: view::Scope, visit: &mut Visit<'_>) {
        let scope = scope.sent_by(match self {
            Self::Gsm(_, message) => sent(message),
            _ => None,
        });
        match self {
            // The payload container type says what the container carries.
            Self::Gmm(_, GmmMessage::UlNasTransport(transport))
                if transport.payload_container_type.is_n1_sm() =>
            {
                let container = N1SmContainer(&transport.payload_container);
                with_ie(&**transport, "payload_container", &container, scope, visit);
            }
            Self::Gmm(_, GmmMessage::DlNasTransport(transport))
                if transport.payload_container_type.is_n1_sm() =>
            {
                let container = N1SmContainer(&transport.payload_container);
                with_ie(&**transport, "payload_container", &container, scope, visit);
            }
            Self::Gmm(_, message) => message.body().ies(scope, visit),
            Self::Gsm(_, message) => message.body().ies(scope, visit),
            Self::SecurityProtected(_, inner) => inner.ies(scope, visit),
            Self::Opaque(_) => {}
        }
    }

    fn body(&self) -> Option<&dyn MessageBody> {
        match self {
            Self::Gmm(_, message) => Some(message.body()),
            Self::Gsm(_, message) => Some(message.body()),
            Self::SecurityProtected(_, inner) => inner.body(),
            Self::Opaque(_) => None,
        }
    }

    fn body_mut(&mut self) -> Option<&mut dyn MessageBody> {
        match self {
            Self::Gmm(_, message) => Some(message.body_mut()),
            Self::Gsm(_, message) => Some(message.body_mut()),
            Self::SecurityProtected(_, inner) => inner.body_mut(),
            Self::Opaque(_) => None,
        }
    }

    fn header(&self) -> Option<oxirush_utils::tree::Value> {
        match self {
            Self::Gmm(header, _) => readable::to_value(header).ok(),
            Self::Gsm(header, _) => readable::to_value(header).ok(),
            Self::SecurityProtected(_, inner) => inner.header(),
            Self::Opaque(_) => None,
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
        Some((readable::to_value(header).ok()?, ciphered))
    }

    fn blank_of(family: &str, kind: &str) -> Option<Self> {
        use crate::common::readable::blank;
        match family {
            "Gmm" => Some(Self::Gmm(
                blank(&[family, kind])?,
                GmmMessage::blank_named(kind)?,
            )),
            "Gsm" => Some(Self::Gsm(
                blank(&[family, kind])?,
                GsmMessage::blank_named(kind)?,
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

    fn set_header(
        &mut self,
        header: &oxirush_utils::tree::Value,
    ) -> core::result::Result<(), String> {
        match self {
            Self::Gmm(written, _) => *written = readable::from_value(header)?,
            Self::Gsm(written, _) => *written = readable::from_value(header)?,
            Self::SecurityProtected(_, inner) => return inner.set_header(header),
            Self::Opaque(_) => {}
        }
        Ok(())
    }

    fn set_protection(
        &mut self,
        header: &oxirush_utils::tree::Value,
        ciphered: Option<&oxirush_utils::tree::Value>,
    ) -> core::result::Result<(), String> {
        if let Self::SecurityProtected(written, inner) = self {
            *written = readable::from_value(header)?;
            if let (Self::Opaque(octets), Some(ciphered)) = (&mut **inner, ciphered) {
                *octets = readable::from_value(ciphered)?;
            }
        }
        Ok(())
    }

    const FAMILIES: &'static [&'static str] = &["Gmm", "Gsm"];

    fn decided(
        container: Option<&str>,
        kind: Option<&oxirush_utils::tree::Value>,
    ) -> core::result::Result<Vec<(&'static str, oxirush_utils::tree::Value)>, String> {
        decided(container, kind)
    }

    const SPARE: &'static [&'static str] = &["spare-half-octet"];

    fn refused_header(&self) -> Option<String> {
        use crate::nas_5gs::SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected;
        let discriminator = |written: u8, sublayer: &str, is: u8| {
            (written != is).then(|| {
                format!(
                    "`extended-protocol-discriminator` is {written}, and that of a {sublayer} \
                     message is {is}"
                )
            })
        };
        match self {
            Self::Gmm(header, _) => {
                discriminator(header.extended_protocol_discriminator, "5GMM", 126)
                    .or_else(|| {
                        let written = readable::to_value(&header.security_header_type).ok()?;
                        (header.security_header_type != PlainFiveGsNasMessageNotSecurityProtected)
                            .then(|| {
                                format!(
                                    "`security-header-type` is {written}, and that of a plain \
                                 message is \"plain-5gs-nas-message-not-security-protected\": the header that protects a \
                                 message is its `security-header`"
                                )
                            })
                    })
                    .or_else(|| {
                        let spare = header.spare_half_octet;
                        (spare > 15)
                            .then(|| format!("`spare-half-octet` is {spare}, and must be 0 to 15"))
                    })
            }
            Self::Gsm(header, _) => {
                discriminator(header.extended_protocol_discriminator, "5GSM", 46)
            }
            _ => None,
        }
    }

    fn header_name(field: &str, number: u64) -> Option<oxirush_utils::tree::Value> {
        let number = u8::try_from(number).ok()?;
        match field {
            "security-header-type" => {
                let named = crate::nas_5gs::SecurityHeaderType::try_from(number).ok()?;
                readable::to_value(&named).ok()
            }
            // The types of 5GMM and of 5GSM have no number in common, and a
            // number that is of neither has no name.
            "message-type" => match GmmMessageType::from(number) {
                GmmMessageType::Unknown(_) => {
                    readable::to_value(&GsmMessageType::from(number)).ok()
                }
                named => readable::to_value(&named).ok(),
            }
            .filter(oxirush_utils::tree::Value::is_string),
            _ => None,
        }
    }

    fn prepared(mut self, members: &oxirush_utils::tree::Map) -> Self {
        // The payload container is read as its type says.
        let kind = match &mut self {
            Self::Gmm(_, GmmMessage::UlNasTransport(transport)) => {
                &mut transport.payload_container_type
            }
            Self::Gmm(_, GmmMessage::DlNasTransport(transport)) => {
                &mut transport.payload_container_type
            }
            _ => return self,
        };
        let written = (members.iter())
            .find(|(name, _)| readable::same_name(name, "payload-container-type"))
            .map(|(_, written)| written);
        if let Some(Ok(written)) =
            written.map(|value| view::Decoded::with_decoded(kind, value, view::Scope::NONE))
        {
            *kind = written;
        }
        self
    }
}

impl Message {
    /// The plain message that a tree writes alone, which its `message-type`
    /// names.
    fn plain(tree: oxirush_utils::tree::Value) -> Result<Self> {
        let (members, named) =
            view::typed_members::<Self>(tree, view::Scope::NONE).map_err(Error::EncodingError)?;
        let named = named.ok_or_else(|| {
            Error::EncodingError("the `message-type` of the view names the message".into())
        })?;
        let (family, kind) = match message_type_place(&named) {
            Some((0, place)) => (
                "Gmm",
                gmm_types().nth(place).map(|kind| format!("{kind:?}")),
            ),
            Some((_, place)) => (
                "Gsm",
                gsm_types().nth(place).map(|kind| format!("{kind:?}")),
            ),
            None => return Err(Error::EncodingError(no_message(&named))),
        };
        let kind = kind.ok_or_else(|| Error::EncodingError(format!("no message `{named}`")))?;
        view::alone(&[family], &kind, members, view::Scope::NONE)
            .map_err(Error::EncodingError)
            .and_then(sendable)
    }
}

/// The message `message` that a view or a tree wrote, if it is one that is
/// sent: what the header of a plain message cannot have is refused by the
/// name of its member, and whatever else has no octets as encoding refuses
/// it. A message that is not ciphered under a header that says it is has no
/// octets before a security context ciphers it, and is what it is.
fn sendable(message: Message) -> Result<Message> {
    use crate::nas_5gs::SecurityHeaderType::{
        IntegrityProtectedAndCiphered, IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
    };
    let to_cipher = matches!(
        &message,
        Message::SecurityProtected(header, inner) if matches!(
            header.security_header_type,
            IntegrityProtectedAndCiphered | IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        ) && !matches!(**inner, Message::Opaque(_))
    );
    match message.refused_header() {
        Some(refused) => Err(Error::EncodingError(refused)),
        None if to_cipher => Ok(message),
        None => message.encode().map(|_| message),
    }
}

/// The message types of 5GMM, in the order of their numbers.
fn gmm_types() -> impl Iterator<Item = GmmMessageType> {
    GmmMessageType::ALL.iter().copied()
}

/// The message types of 5GSM, in the order of their numbers.
fn gsm_types() -> impl Iterator<Item = GsmMessageType> {
    GsmMessageType::ALL.iter().copied()
}

/// The family of the message type that `kind` names, 5GMM (0) or 5GSM (1), and
/// its place among the types of the family.
fn message_type_place(kind: &str) -> Option<(usize, usize)> {
    let families = [GmmMessageType::NAMES, GsmMessageType::NAMES];
    (families.iter().enumerate())
        .find_map(|(family, names)| Some((family, oxirush_utils::tree::named(names, kind)?)))
}

/// What the type of a 5GS message decides of its header, as a tree leaves it
/// out: the extended protocol discriminator of its sublayer, and for 5GMM a
/// plain security header type. The message of an EPS NAS message container
/// is an EPS one, and so is that of a container of the EPS message: no 5GS
/// message has an IE of their names.
fn decided(
    container: Option<&str>,
    kind: Option<&oxirush_utils::tree::Value>,
) -> core::result::Result<Vec<(&'static str, oxirush_utils::tree::Value)>, String> {
    use oxirush_utils::tree;
    const EPS: [&str; 3] = [
        "eps-nas-message-container",
        "esm-message-container",
        "replayed-nas-message-container",
    ];
    if container.is_some_and(|ie| EPS.iter().any(|eps| readable::same_name(ie, eps))) {
        return crate::nas_eps::view::decided(None, kind);
    }
    // A security protected 5GS NAS message is one of 5GMM (§9.1.1).
    if container.is_some_and(|ie| readable::same_name(ie, "security-header")) {
        return Ok(vec![
            ("extended-protocol-discriminator", tree!(126)),
            ("spare-half-octet", tree!(0)),
        ]);
    }
    let kind = kind.ok_or("the `message-type` of a message names it")?;
    let kind = &view::type_named::<Message>(kind)?;
    match message_type_place(kind).map(|(family, _)| family) {
        Some(0) => Ok(vec![
            ("extended-protocol-discriminator", tree!(126)),
            (
                "security-header-type",
                tree!("plain-5gs-nas-message-not-security-protected"),
            ),
            ("spare-half-octet", tree!(0)),
        ]),
        Some(_) => Ok(vec![("extended-protocol-discriminator", tree!(46))]),
        None => Err(no_message(kind)),
    }
}

/// Whether `kind` names a 5GS message.
pub(crate) fn is_message(kind: &str) -> bool {
    message_type_place(kind).is_some()
}

/// The error for `kind`, which names no 5GS message: the EPS message that
/// it names, or the nearest names.
fn no_message(kind: &str) -> String {
    if crate::nas_eps::view::is_message(kind) {
        return format!("no 5GS message `{kind}`: it is an EPS message, which `nas_eps` reads");
    }
    let kinds: Vec<&str> = (GmmMessageType::NAMES.iter().chain(GsmMessageType::NAMES))
        .copied()
        .collect();
    readable::none_of(kind, &kinds, "message")
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
    /// use oxirush_nas::nas_5gs::Message;
    ///
    /// // REGISTRATION REJECT with a T3346 value of twelve minutes, counted in minutes
    /// // and in units of six minutes
    /// let decode = |octets: &str| Message::decode(&hex::decode(octets).unwrap()).unwrap();
    /// let (minutes, decihours) = (decode("7e0044165f012c"), decode("7e0044165f0142"));
    /// assert!(minutes != decihours && minutes.means_the_same(&decihours));
    /// assert!(!minutes.means_the_same(&decode("7e0044165f012b")));
    /// ```
    pub fn means_the_same(&self, other: &Self) -> bool {
        view::meant(self, view::Scope::NONE) == view::meant(other, view::Scope::NONE)
    }

    /// This message as a tree: its `message-type` and its IEs by name, each
    /// with its value, or as `{"octets": "…"}` when it has no readable value.
    ///
    /// What the type of the message
    /// decides is left out (the extended protocol discriminator, and for a
    /// 5GMM message a plain security header type and a spare half octet of
    /// zero, in its `security-header` too), and so are the optional IEs that
    /// the message does not have.
    /// The message in a container is its own tree, and the header that
    /// protects a message is its `security-header`.
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
    /// - A session AMBR with units of its table is its two rates: the unit
    ///   that counts each is the largest that counts it exactly.
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
    /// use oxirush_nas::nas_5gs::Message;
    /// use oxirush_nas::tree;
    ///
    /// // 5GMM STATUS with cause #22.
    /// let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let tree = tree!({"message-type": "5gmm-status", "5gmm-cause": "congestion"});
    /// assert_eq!(status.to_tree(), tree);
    /// assert_eq!(Message::from_tree(tree).unwrap(), status);
    /// ```
    pub fn to_tree(&self) -> oxirush_utils::tree::Value {
        view::tree(self, view::Scope::NONE)
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
    /// `pdu-session-identity` and the `procedure-transaction-identity` of a
    /// 5GSM message.
    ///
    /// A tree with a `security-header` writes a message under that header:
    /// every field of the header is written, the code among them, but the
    /// extended protocol discriminator, which is that of 5GMM, and a spare
    /// half octet of zero, which the tree may leave out as `to_tree` does;
    /// what else the tree has is the plain message, or `ciphered-message`
    /// alone with the `octets` of one that is ciphered.
    ///
    /// The message that comes back is one that [`Self::encode`] encodes. One
    /// is not: a plain message under a header that says it is ciphered,
    /// which is the message that a security context deciphered and has no
    /// octets before one ciphers it.
    pub fn from_tree(tree: oxirush_utils::tree::Value) -> Result<Self> {
        let (protection, tree) = view::protection_of(tree).map_err(Error::EncodingError)?;
        let Some((header, ciphered)) = protection else {
            return Self::plain(tree);
        };
        let given = decided(Some("security-header"), None).map_err(Error::EncodingError)?;
        let header: crate::nas_5gs::SecurityHeader =
            view::security_header(&header, &given).map_err(Error::EncodingError)?;
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
    /// use oxirush_nas::nas_5gs::Message;
    /// use oxirush_nas::tree;
    ///
    /// // REGISTRATION ACCEPT with a 5G-GUTI
    /// let octets = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    /// let accept = Message::decode(&octets).unwrap();
    /// let tmsi = accept.select("/nas/5g-guti/guti/tmsi")?;
    /// assert_eq!(tmsi, [tree!(0x1122_3344)]);
    ///
    /// // The tree has the value of the 5G-GUTI, and the message its octets
    /// let guti = accept.select("/nas/5g-guti/octets")?;
    /// assert_eq!(guti, [tree!("f202f83901004211223344")]);
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
        crate::paths::of_message(&self.to_tree(), path, |ie| view::ie_octets(self, ie))
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
    /// use oxirush_nas::nas_5gs::Message;
    /// use oxirush_nas::tree;
    ///
    /// // 5GMM STATUS with cause #22
    /// let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let mut tree = status.to_tree();
    /// tree["5gmm-cause"] = tree!("illegal-ue");
    /// let edited = status.with_tree(tree).unwrap();
    /// assert_eq!(edited.encode().unwrap(), [0x7e, 0x00, 0x64, 0x03]);
    /// ```
    pub fn with_tree(&self, tree: oxirush_utils::tree::Value) -> Result<Self> {
        let edits = view::edits::<Self>(self.to_tree(), tree, view::Scope::NONE)
            .map_err(Error::EncodingError)?;
        let edited =
            view::with_edits(self, edits, view::Scope::NONE).map_err(Error::EncodingError)?;
        // A message that the tree leaves as it is comes back as it is.
        if edited != *self {
            edited.encode()?;
        }
        Ok(edited)
    }
}

impl GmmMessageType {
    /// The names of the members that the tree of a message of this type can
    /// have: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn names(self) -> Vec<String> {
        view::names::<crate::nas_5gs::GmmHeader>(&[&format!("{self:?}")], GmmMessage::fields_named)
    }
}

impl GsmMessageType {
    /// The names of the members that the tree of a message of this type can
    /// have: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn names(self) -> Vec<String> {
        view::names::<crate::nas_5gs::GsmHeader>(&[&format!("{self:?}")], GsmMessage::fields_named)
    }
}

// ── Values ─────────────────────────────────────────────────────────────────
//
// Each is what the typed accessors of the IE return, and is encoded back
// by the matching constructor or setters.

use crate::common::ts24008::PcoDirection;
use crate::common::ts24301::KeySetIdentifierValue;
use crate::common::view::{
    Code, built_ie, code_ie, container_ie, decoded_ie, fields_ie, listed_ie, named_ie, numbers,
    octets, shared_ies, timer_ie, write_code,
};
use crate::common::{decode_labels, encode_labels, within};
use crate::nas_5gs::*;
use core::net::{Ipv4Addr, Ipv6Addr};

// The IEs that TS 24.501 and TS 24.301 have alike.
shared_ies!();

/// A payload container of the type "N1 SM information": a 5GSM message.
struct N1SmContainer<'a>(&'a PayloadContainer);

impl N1SmContainer<'_> {
    fn message(&self) -> Option<Message> {
        let message = self.0.decode_as_n1_sm_message().ok()?;
        matches!(message, Message::Gsm(..)).then_some(message)
    }

    /// The container that the tree `value` of its message writes in
    /// `scope`, and that message.
    fn written(
        &self,
        value: &oxirush_utils::tree::Value,
        scope: view::Scope,
    ) -> core::result::Result<(PayloadContainer, Message), String> {
        let inside = scope.inside().ok_or(view::Scope::REFUSED)?;
        let message = match self.message() {
            Some(message) => view::edited(&message, value, inside)?,
            // A container without octets carries what the tree names.
            None if self.0.value.is_empty() => view::contained(value, inside)?,
            None => return Err("the octets are not a 5GSM message: write them".into()),
        };
        let container = PayloadContainer::from_n1_sm_message(&message).map_err(view::unencoded)?;
        Ok((container, message))
    }

    /// The container of the message that stands for those that mean what
    /// the one it carries means.
    fn meant_container(&self, scope: view::Scope) -> Option<PayloadContainer> {
        let meant = view::meant(&self.message()?, scope.inside()?);
        PayloadContainer::from_n1_sm_message(&meant).ok()
    }
}

impl Ie for N1SmContainer<'_> {
    fn value(&self, scope: view::Scope) -> Option<oxirush_utils::tree::Value> {
        Some(view::tree(&self.message()?, scope.inside()?))
    }

    fn encoded_ie(
        &self,
        value: &oxirush_utils::tree::Value,
        scope: view::Scope,
    ) -> core::result::Result<Box<dyn core::any::Any>, String> {
        Ok(Box::new(self.written(value, scope)?.0))
    }

    #[cfg(test)]
    fn encoded_value(
        &self,
        value: &oxirush_utils::tree::Value,
        scope: view::Scope,
    ) -> core::result::Result<Option<oxirush_utils::tree::Value>, String> {
        let (_, message) = self.written(value, scope)?;
        let inside = scope.inside().ok_or(view::Scope::REFUSED)?;
        Ok(Some(view::tree(&message, inside)))
    }

    fn written_back(&self, value: &oxirush_utils::tree::Value, scope: view::Scope) -> bool {
        // The container that the tree of the message writes alone carries a
        // message that means what this one means.
        let written = N1SmContainer(&PayloadContainer::blank()).written(value, scope);
        let meant = written
            .ok()
            .and_then(|(written, _)| N1SmContainer(&written).meant_container(scope));
        meant.is_some() && meant == self.meant_container(scope)
    }

    fn meant(&self, scope: view::Scope) -> Option<Box<dyn core::any::Any>> {
        let meant = self.meant_container(scope)?;
        (meant != *self.0).then(|| Box::new(meant) as Box<dyn core::any::Any>)
    }

    fn octets_inside(&self, names: &[String], scope: view::Scope) -> Option<view::Found> {
        Some(view::octets_at(&self.message()?, names, scope.inside()?))
    }

    #[cfg(test)]
    fn reading(&self, scope: view::Scope) -> Option<oxirush_utils::tree::Value> {
        Some(crate::wireshark_tests::read(
            &self.message()?,
            scope.inside()?,
        ))
    }
}

// The units of the protocol configuration options, by the direction of the
// message.

// A container of a plain NAS message: the view of the message.
container_ie!(
    MessageContainer: Message,
    |ie| (ie.decode_as_nas_message().ok())
        .filter(|message| matches!(message, Message::Gmm(..))),
    |message| MessageContainer::from_nas_message(message)
);
container_ie!(
    EpsNasMessageContainer: crate::nas_eps::Message,
    |ie| ie.decode_as_eps_message().ok(),
    |message| EpsNasMessageContainer::from_eps_message(message)
);

// One coded value.
code_ie!(
    ServiceType,
    ServiceTypeValue,
    |ie| ie.service_type_strict(),
    ServiceType::from_service_type
);
code_ie!(
    GmmCause,
    GmmCauseValue,
    |ie| ie.cause(),
    GmmCause::from_cause
);
code_ie!(
    GsmCause,
    GsmCauseValue,
    |ie| ie.cause(),
    GsmCause::from_cause
);
// A type that no identity is asked for by is written as the code that it is
// read as, so that the refusal says what the IE would be.
/// The identity that an IDENTITY REQUEST asks for (TS 24.501 §9.11.3.3), by
/// its name.
#[derive(Clone, Copy)]
enum IdentityTypeName {
    NoIdentity,
    Suci,
    Guti,
    Imei,
    STmsi,
    Imeisv,
    MacAddress,
    Eui64,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum IdentityTypeName {
        NoIdentity,
        Suci,
        Guti,
        Imei,
        STmsi,
        Imeisv,
        MacAddress,
        Eui64,
    }
);

impl IdentityTypeName {
    const ALL: [(Self, MobileIdentityType5gs); 8] = [
        (Self::NoIdentity, MobileIdentityType5gs::NoIdentity),
        (Self::Suci, MobileIdentityType5gs::Suci),
        (Self::Guti, MobileIdentityType5gs::Guti),
        (Self::Imei, MobileIdentityType5gs::Imei),
        (Self::STmsi, MobileIdentityType5gs::STmsi),
        (Self::Imeisv, MobileIdentityType5gs::Imeisv),
        (Self::MacAddress, MobileIdentityType5gs::MacAddress),
        (Self::Eui64, MobileIdentityType5gs::Eui64),
    ];
}

code_ie!(
    IdentityType,
    IdentityTypeName,
    |ie| {
        let identity = ie.identity_type_strict()?;
        let found = IdentityTypeName::ALL
            .iter()
            .find(|(_, kind)| *kind == identity);
        found.map(|(name, _)| *name)
    },
    |name| {
        let found = IdentityTypeName::ALL
            .iter()
            .find(|(known, _)| *known as u8 == name as u8);
        let identity = found.map_or(MobileIdentityType5gs::Suci, |(_, kind)| *kind);
        IdentityType::from_identity_type(identity)
            .unwrap_or(IdentityType::new(MobileIdentityType5gs::Suci as u8))
    }
);
code_ie!(
    PduSessionType,
    PduSessionTypeValue,
    |ie| ie.session_type(),
    PduSessionType::from_session_type
);
code_ie!(SscMode, SscModeValue, |ie| ie.mode(), SscMode::from_mode);
code_ie!(
    AccessType,
    AccessTypeValue,
    |ie| ie.access_type(),
    AccessType::from_access_type
);
code_ie!(
    PayloadContainerType,
    PayloadContainerKind,
    |ie| ie.kind(),
    PayloadContainerType::from_kind
);
code_ie!(
    NssaiInclusionMode,
    NssaiInclusionModeValue,
    |ie| Some(ie.mode()),
    NssaiInclusionMode::from_mode
);
code_ie!(
    MaPduSessionInformation,
    MaPduSessionInfoValue,
    |ie| ie.info(),
    MaPduSessionInformation::from_info
);
// An identity that is assigned with the number of one that is not is written
// as that number, so that the refusal says what the IE would be.
code_ie!(
    ProseRelayTransactionIdentity,
    ProseRelayTransactionIdentityValue,
    |ie| ie.identity(),
    |identity| ProseRelayTransactionIdentity::new(match identity {
        ProseRelayTransactionIdentityValue::Unassigned => 0,
        ProseRelayTransactionIdentityValue::Assigned(number) => number,
        ProseRelayTransactionIdentityValue::Reserved => 0xff,
    })
);
named_ie!(
    DrxParameters,
    DrxValue,
    |ie| ie.drx_value(),
    DrxParameters::from_drx_value
);
named_ie!(
    NbN1ModeDrxParameters,
    NbN1DrxValue,
    |ie| ie.drx_value(),
    NbN1ModeDrxParameters::from_drx_value
);
named_ie!(Rsn, RsnValue, |ie| ie.rsn(), Rsn::from_rsn);
named_ie!(
    AdditionalRequestResult,
    PagingRestrictionDecision,
    |ie| ie.paging_restriction_decision(),
    AdditionalRequestResult::from_paging_restriction_decision
);
named_ie!(
    EthernetHeaderCompressionConfiguration,
    EthHdrCompCidLen,
    |ie| ie.cid_length(),
    EthernetHeaderCompressionConfiguration::from_cid_length
);

// The fields of an octet.
fields_ie!(RegistrationType {
"registration-type":
    |ie| Code::of(RegistrationTypeValue::try_from(ie.value & 0x07).ok(), ie.value & 0x07),
    |ie, code: Code<RegistrationTypeValue>| write_code(
        ie,
        code,
        |ie, name| {
            ie.set_registration_type(name);
        },
        |ie| ie.value & 0x07,
    );
"follow-on-request": |ie| ie.follow_on_request(), |ie, on: bool| ie.set_follow_on_request(on);
});
fields_ie!(DeRegistrationType {
"switch-off": |ie| ie.switch_off(), |ie, on: bool| ie.set_switch_off(on);
"re-registration-required":
    |ie| ie.re_registration_required(),
    |ie, on: bool| ie.set_re_registration_required(on);
"access-type":
    |ie| Code::of(ie.deregistration_access_type(), ie.access_type_raw()),
    |ie, code: Code<DeregistrationAccessType>| write_code(
        ie,
        code,
        |ie, name| {
            ie.set_deregistration_access_type(name);
        },
        |ie| ie.access_type_raw(),
    );
});
fields_ie!(UpdateType {
    "sms-requested": |ie| ie.sms_requested(), |ie, on: bool| ie.set_sms_requested(on);
    "ng-ran-rcu": |ie| ie.ng_ran_rcu(), |ie, on: bool| ie.set_ng_ran_rcu(on);
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
    "eps-pnb-ciot":
        |ie| Code::of(ie.eps_pnb_ciot(), ie.eps_pnb_ciot_raw()),
        |ie, code: Code<PreferredCiotBehavior>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_eps_pnb_ciot(name);
            },
            |ie| ie.eps_pnb_ciot_raw(),
        );
});
fields_ie!(RegistrationResult {
    "result":
        |ie| Code::of(
            RegistrationResultValue::try_from(ie.result_value_raw() & 0x07).ok(),
            ie.result_value_raw(),
        ),
        |ie, code: Code<RegistrationResultValue>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_result_value(name);
            },
            |ie| ie.result_value_raw(),
        );
    "sms-allowed": |ie| ie.sms_allowed(), |ie, on: bool| ie.set_sms_allowed(on);
    "nssaa-performed": |ie| ie.nssaa_performed(), |ie, on: bool| ie.set_nssaa_performed(on);
    "emergency-registered":
        |ie| ie.emergency_registered(),
        |ie, on: bool| ie.set_emergency_registered(on);
    "disaster-roaming": |ie| ie.disaster_roaming(), |ie, on: bool| ie.set_disaster_roaming(on);
});
fields_ie!(ControlPlaneServiceType {
"service-type":
    |ie| Code::of(
        ControlPlaneServiceTypeValue::try_from(ie.service_type_raw() & 0x07).ok(),
        ie.service_type_raw(),
    ),
    |ie, code: Code<ControlPlaneServiceTypeValue>| write_code(
        ie,
        code,
        |ie, name| {
            ie.set_service_type(name);
        },
        |ie| ie.service_type_raw(),
    );
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
fields_ie!(EpsNasSecurityAlgorithms {
    "ciphering":
        |ie| Code::of(crate::common::ts24301::CipheringAlgorithm::try_from(ie.ciphering_raw()).ok(), ie.ciphering_raw()),
        |ie, code: Code<crate::common::ts24301::CipheringAlgorithm>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_ciphering_raw(name as u8);
            },
            |ie| ie.ciphering_raw(),
        );
    "integrity":
        |ie| Code::of(crate::common::ts24301::IntegrityAlgorithm::try_from(ie.integrity_raw()).ok(), ie.integrity_raw()),
        |ie, code: Code<crate::common::ts24301::IntegrityAlgorithm>| write_code(
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
    Additional5gSecurityInformation,
    |rinmr, hdp| Ok(Self::from_flags(rinmr, hdp)),
    { rinmr: bool, hdp: bool }
);
built_ie!(
    AdditionalConfigurationIndication,
    |scmr| Ok(Self::from_scmr(scmr)),
    { scmr: bool }
);
built_ie!(
    AdditionalInformationRequested,
    |requested| Ok(Self::from_cipher_key_data_requested(requested)),
    { cipher_key_data_requested: bool }
);
built_ie!(
    AllowedSscMode,
    |ssc1, ssc2, ssc3| Ok(Self::from_modes(ssc1, ssc2, ssc3)),
    { ssc1: bool, ssc2: bool, ssc3: bool }
);
built_ie!(AlwaysOnPduSessionIndication, |apsi| Ok(Self::from_apsi(apsi)), { apsi: bool });
built_ie!(AlwaysOnPduSessionRequested, |apsr| Ok(Self::from_apsr(apsr)), { apsr: bool });
built_ie!(Aun3Indication, |aun3reg| Ok(Self::from_aun3reg(aun3reg)), { aun3reg: bool });
built_ie!(
    ConfigurationUpdateIndication,
    |ack, red| Ok(Self::from_flags(ack, red)),
    { ack: bool, red: bool }
);
built_ie!(ControlPlaneOnlyIndication, Self::from_cpoi, { cpoi: bool });
built_ie!(
    ExtendedGmmCause,
    |not_allowed| Ok(Self::from_satellite_nr_not_allowed(not_allowed)),
    { satellite_nr_not_allowed: bool }
);
built_ie!(
    GsmCongestionReAttemptIndicator,
    |abo, catbo| Ok(Self::from_flags(abo, catbo)),
    { abo: bool, catbo: bool }
);
built_ie!(
    GsmNetworkFeatureSupport,
    |ept_s1, naps| Ok(Self::from_flags(ept_s1, naps)),
    { ept_s1: bool, naps: bool }
);
built_ie!(
    FeatureAuthorizationIndication,
    |hpase, mbsrai| Ok(Self::from_flags(hpase, mbsrai)),
    { hpase: bool, mbsrai: FeatureAuthMbsraiValue = |ie| ie.mbsrai() }
);
built_ie!(LpWusStatus, |disabled| Ok(Self::from_disabled(disabled)), {
    lp_wus_disabled: bool
});
built_ie!(
    MicoIndication,
    |raai, sprti| Ok(Self::from_flags(raai, sprti)),
    { raai: bool, sprti: bool }
);
built_ie!(N5gcIndication, |n5gc| Ok(Self::from_n5gc(n5gc)), { n5gc: bool });
built_ie!(
    NetworkSlicingIndication,
    |nssci, dcni| Ok(Self::from_flags(nssci, dcni)),
    { nssci: bool, dcni: bool }
);
built_ie!(
    Non3GppAccessPathSwitchingIndication,
    |naps| Ok(Self::from_naps(naps)),
    { naps: bool }
);
built_ie!(
    Non3GppPathSwitchingInformation,
    |nsonr| Ok(Self::from_nsonr(nsonr)),
    { nsonr: bool }
);
built_ie!(PayloadContainerInformation, |pru| Ok(Self::from_pru(pru)), { pru: bool });
built_ie!(
    PriorityIndicator,
    |mpsi, mcsi| Ok(Self::from_flags(mpsi, mcsi)),
    { mpsi: bool, mcsi: bool }
);
built_ie!(
    RanTimingSynchronization,
    |request| Ok(Self::from_recreation_request(request)),
    { recreation_request: bool }
);
built_ie!(SmsIndication, |sai| Ok(Self::from_sai(sai)), { sai: bool });
built_ie!(
    UeUsageSetting,
    |data_centric| Ok(Self::from_data_centric(data_centric)),
    { data_centric: bool }
);
built_ie!(Truncated5gSTmsiConfiguration, Self::try_from_lengths, {
    truncated_amf_set_id_length: u8 = |ie| ie.truncated_amf_set_id_length(),
    truncated_amf_pointer_length: u8 = |ie| ie.truncated_amf_pointer_length(),
});
built_ie!(
    Aun3DeviceSecurityKey,
    |askt, key: Vec<u8>| Self::from_typed(askt, &key),
    {
        askt: Aun3DeviceSecurityKeyType = |ie| ie.askt(),
        key: Vec<u8> = |ie| ie.key().map(<[u8]>::to_vec),
    }
);

// The parts of an IE that its constructor takes.
built_ie!(
    IpHeaderCompressionConfiguration,
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
    |restriction_type, psis: Vec<u16>| Self::from_restriction(
        restriction_type,
        &octets("psi", &psis, 1, 15)?
    ),
    {
        restriction_type: PagingRestrictionType =
            |ie| ie.restriction_type().filter(|_| ie.is_well_formed()),
        unrestricted_psis: Vec<u16> =
            |ie| Some(numbers(&ie.unrestricted_psis().unwrap_or_default())),
    }
);
built_ie!(
    TnanInformation,
    |tngf_id: Option<Vec<u8>>, ssid: Option<String>| {
        let mut ie = Self::new(Vec::new());
        ie.set_tngf_id(tngf_id.as_deref())?
            .set_ssid(ssid.as_ref().map(String::as_bytes))?;
        Ok(ie)
    },
    {
        tngf_id: Option<Vec<u8>> = |ie| match ie.tngf_id_indicator() {
            true => Some(Some(ie.tngf_id()?.to_vec())),
            false => Some(None),
        },
        ssid: Option<String> = |ie| match ie.ssid_indicator() {
            true => String::from_utf8(ie.ssid()?.to_vec()).ok().map(Some),
            false => Some(None),
        },
    }
);

/// What an LP-WUS PS assistance information is, by its type.
#[derive(Clone, PartialEq)]
enum LpWuspsAssistance {
    PagingSubgroupId(u8),
    UePagingProbabilityInformation(u8),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum LpWuspsAssistance {
        PagingSubgroupId(u8),
        UePagingProbabilityInformation(u8),
    }
);

decoded_ie!(
    LpWuspsAssistanceInformation: LpWuspsAssistance,
    |ie| (ie.paging_subgroup_id().map(LpWuspsAssistance::PagingSubgroupId)).or_else(|| {
        let information = ie.ue_paging_probability_information();
        information.map(LpWuspsAssistance::UePagingProbabilityInformation)
    }),
    |_, assistance| match assistance {
        LpWuspsAssistance::PagingSubgroupId(id) => Self::from_paging_subgroup_id(id),
        LpWuspsAssistance::UePagingProbabilityInformation(information) => {
            Self::from_ue_paging_probability_information(information)
        }
    }
);
// The correctionField of IEEE Std 1588: a number of 2^-16 ns.
decoded_ie!(
    UeDsTtResidenceTime: i64,
    |ie| {
        let field = ie.correction_field().filter(|_| ie.is_well_formed())?;
        Some(i64::from_le_bytes(field.wire_bytes()))
    },
    |_, field| {
        let field = DsTtCorrectionField::from_wire_bytes(field.to_le_bytes());
        Ok(Self::from_correction_field(field))
    }
);

/// The identity of a 5GS mobile identity, by its type of identity.
#[derive(Clone, PartialEq)]
enum MobileIdentityForm {
    NoIdentity,
    Suci(SuciForm),
    Guti(GutiForm),
    Imei(String),
    STmsi(STmsiForm),
    Imeisv(String),
    MacAddress { address: [u8; 6], mauri: bool },
    Eui64([u8; 8]),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(enum MobileIdentityForm { NoIdentity, Suci(SuciForm), Guti(GutiForm), Imei(String), STmsi(STmsiForm), Imeisv(String), MacAddress { address, mauri }, Eui64([u8; 8]) });

/// A 5G-GUTI by its parts, as a view writes it.
#[derive(Clone, PartialEq)]
struct GutiForm {
    plmn: Plmn,
    amf_region_id: u8,
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct GutiForm { plmn as plmn, amf_region_id, amf_set_id, amf_pointer, tmsi });

/// A 5G-S-TMSI by its parts, as a view writes it.
#[derive(Clone, PartialEq)]
struct STmsiForm {
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct STmsiForm { amf_set_id, amf_pointer, tmsi });

/// The protection scheme of a SUCI by its name (TS 33.501 Annex C.1), or the
/// identifier of a scheme of the operator.
#[derive(PartialEq, Clone, Copy)]
enum SchemeName {
    Null,
    ProfileA,
    ProfileB,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(
    enum SchemeName {
        Null,
        ProfileA,
        ProfileB,
    }
);

/// A SUCI with its digits: the MSIN of the null scheme, else the output of
/// the protection scheme; or the text of a NAI.
#[derive(Clone, PartialEq)]
enum SuciForm {
    Imsi {
        plmn: Plmn,
        routing_indicator: String,
        protection_scheme: view::Code<SchemeName>,
        home_network_public_key_id: u8,
        msin: Option<String>,
        scheme_output: Option<Vec<u8>>,
    },
    Nai(String),
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(enum SuciForm { Imsi { plmn as plmn, routing_indicator, protection_scheme, home_network_public_key_id, msin, scheme_output }, Nai(String) });

impl SuciForm {
    fn of(suci: Suci) -> Self {
        match suci {
            Suci::Nai(suci) => Self::Nai(suci.to_string()),
            Suci::Imsi(suci) => {
                let scheme = suci.protection_scheme();
                let name = match scheme.identifier() {
                    0 => Some(SchemeName::Null),
                    1 => Some(SchemeName::ProfileA),
                    2 => Some(SchemeName::ProfileB),
                    _ => None,
                };
                Self::Imsi {
                    plmn: suci.plmn(),
                    routing_indicator: suci.routing_indicator().to_string(),
                    protection_scheme: view::Code::of(name, scheme.identifier()),
                    home_network_public_key_id: suci.home_network_public_key_identifier(),
                    msin: suci.msin().map(String::from),
                    scheme_output: suci.concealed_output().map(<[u8]>::to_vec),
                }
            }
        }
    }

    fn suci(self) -> core::result::Result<Suci, ValueError> {
        Ok(match self {
            Self::Nai(nai) => Suci::Nai(NaiSuci::parse(&nai)?),
            Self::Imsi {
                plmn,
                routing_indicator,
                protection_scheme,
                home_network_public_key_id,
                msin,
                scheme_output,
            } => {
                let routing_indicator = RoutingIndicator::new(&routing_indicator)?;
                let scheme = ProtectionScheme::new(match protection_scheme {
                    view::Code::Name(SchemeName::Null) => 0,
                    view::Code::Name(SchemeName::ProfileA) => 1,
                    view::Code::Name(SchemeName::ProfileB) => 2,
                    view::Code::Number(identifier) => identifier,
                })?;
                Suci::Imsi(match (msin, scheme_output) {
                    (Some(msin), None) if scheme.is_null() => {
                        let key = home_network_public_key_id;
                        if key != 0 {
                            let member = "home-network-public-key-id";
                            return Err(ValueError::value(member, key, "0 with the null scheme"));
                        }
                        ImsiSuci::null(plmn, routing_indicator, &msin)?
                    }
                    (None, Some(output)) => ImsiSuci::concealed(
                        plmn,
                        routing_indicator,
                        scheme,
                        home_network_public_key_id,
                        output,
                    )?,
                    _ => {
                        let rule = "is written with the null scheme and without `scheme-output`, \
                                    and `scheme-output` with another scheme and without `msin`";
                        return Err(ValueError::combination("msin", rule));
                    }
                })
            }
        })
    }
}

decoded_ie!(
    MobileIdentity: MobileIdentityForm,
    |ie| Some(match ie.identity_type()? {
        MobileIdentityType5gs::NoIdentity => MobileIdentityForm::NoIdentity,
        MobileIdentityType5gs::Suci => MobileIdentityForm::Suci(SuciForm::of(ie.as_suci()?)),
        MobileIdentityType5gs::Guti => {
            let guti = ie.as_guti()?;
            MobileIdentityForm::Guti(GutiForm {
                plmn: guti.plmn(),
                amf_region_id: guti.amf_region_id(),
                amf_set_id: guti.amf_set_id(),
                amf_pointer: guti.amf_pointer(),
                tmsi: guti.tmsi(),
            })
        }
        MobileIdentityType5gs::Imei => MobileIdentityForm::Imei(ie.as_imei()?.to_string()),
        MobileIdentityType5gs::STmsi => {
            let s_tmsi = ie.as_s_tmsi()?;
            MobileIdentityForm::STmsi(STmsiForm {
                amf_set_id: s_tmsi.amf_set_id(),
                amf_pointer: s_tmsi.amf_pointer(),
                tmsi: s_tmsi.tmsi(),
            })
        }
        MobileIdentityType5gs::Imeisv => MobileIdentityForm::Imeisv(ie.as_imeisv()?.to_string()),
        MobileIdentityType5gs::MacAddress => MobileIdentityForm::MacAddress {
            address: ie.as_mac_address()?,
            mauri: ie.mauri()?,
        },
        MobileIdentityType5gs::Eui64 => MobileIdentityForm::Eui64(ie.as_eui64()?),
        _ => return None,
    }),
    |_, identity| match identity {
        MobileIdentityForm::NoIdentity => Ok(MobileIdentity::from_no_identity()),
        MobileIdentityForm::Suci(suci) => MobileIdentity::from_suci(&suci.suci()?),
        MobileIdentityForm::Guti(guti) => {
            let GutiForm {
                plmn,
                amf_region_id,
                amf_set_id,
                amf_pointer,
                tmsi,
            } = guti;
            let guti = Guti5g::new(plmn, amf_region_id, amf_set_id, amf_pointer, tmsi)?;
            Ok(MobileIdentity::from_guti(guti))
        }
        MobileIdentityForm::Imei(imei) => MobileIdentity::from_imei(&imei),
        MobileIdentityForm::STmsi(s_tmsi) => {
            let s_tmsi = STmsi5g::new(s_tmsi.amf_set_id, s_tmsi.amf_pointer, s_tmsi.tmsi)?;
            Ok(MobileIdentity::from_s_tmsi(s_tmsi))
        }
        MobileIdentityForm::Imeisv(imeisv) => MobileIdentity::from_imeisv(&imeisv),
        MobileIdentityForm::MacAddress { address, mauri } => {
            Ok(MobileIdentity::from_mac_address_with_mauri(address, mauri))
        }
        MobileIdentityForm::Eui64(eui64) => Ok(MobileIdentity::from_eui64(eui64)),
    }
);
decoded_ie!(
    DsTtEthernetPortMacAddress: [u8; 6],
    |ie| ie.mac_address(),
    |_, address| Ok(DsTtEthernetPortMacAddress::from_mac_address(address))
);

/// The algorithms a UE security capability has the bits of, by number.
#[derive(Clone, PartialEq)]
struct SecurityCapability {
    ea: Vec<u16>,
    ia: Vec<u16>,
    eea: Option<Vec<u16>>,
    eia: Option<Vec<u16>>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct SecurityCapability { ea, ia, eea, eia });

/// The algorithms an octet of a capability has the bits of, by number.
fn supported<T>(ie: &T, supports: fn(&T, u8) -> bool) -> Vec<u16> {
    (0..8)
        .filter(|algorithm| supports(ie, *algorithm))
        .map(u16::from)
        .collect()
}

/// The octet of a capability with the bits of the `algorithms` of `member`,
/// 0 in bit 8.
fn algorithm_bits(
    member: &'static str,
    algorithms: &[u16],
) -> core::result::Result<u8, ValueError> {
    (algorithms.iter().enumerate()).try_fold(0, |bits, (entry, algorithm)| {
        let algorithm = within(member, *algorithm, 0, 7).map_err(|error| error.at(entry))?;
        Ok(bits | 0x80u8 >> algorithm)
    })
}

decoded_ie!(
    UeSecurityCapability: SecurityCapability,
    |ie| {
        let eps = ie.has_eps_algorithms();
        Some(SecurityCapability {
            ea: supported(ie, Self::supports_ea),
            ia: supported(ie, Self::supports_ia),
            eea: eps.then(|| supported(ie, Self::supports_eea)),
            eia: eps.then(|| supported(ie, Self::supports_eia)),
        })
    },
    |_, capability| {
        let ea = algorithm_bits("ea", &capability.ea)?;
        let ia = algorithm_bits("ia", &capability.ia)?;
        Ok(match (capability.eea, capability.eia) {
            (None, None) => UeSecurityCapability::from_capabilities(ea, ia),
            (eea, eia) => UeSecurityCapability::from_capabilities_extended(
                ea,
                ia,
                algorithm_bits("eea", &eea.unwrap_or_default())?,
                algorithm_bits("eia", &eia.unwrap_or_default())?,
            ),
        })
    }
);

/// The S-NSSAIs of `contents`, each of the entry that it is.
fn snssais<'a>(
    contents: impl Iterator<Item = &'a SNssaiContents>,
) -> core::result::Result<Vec<SNssai>, ValueError> {
    (contents.enumerate())
        .map(|(entry, contents)| contents.to_snssai().map_err(|error| error.at(entry)))
        .collect()
}

// Slices, tracking areas and PLMNs.
decoded_ie!(SNssai: SNssaiContents, |ie| ie.parse(), |_, contents| contents.to_snssai());
decoded_ie!(
    Nssai: Vec<SNssaiContents>,
    |ie| ie.try_parse_all(),
    |_, contents| Nssai::from_snssais(&snssais(contents.iter())?)
);
decoded_ie!(
    MappedNssai: Vec<SNssaiContents>,
    |ie| ie.try_parse_all(),
    |_, contents| MappedNssai::from_snssais(&snssais(contents.iter())?)
);

/// A rejected S-NSSAI and the cause of its rejection.
#[derive(Clone, PartialEq)]
struct RejectedSNssai {
    cause: RejectedNssaiCause,
    s_nssai: SNssaiContents,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct RejectedSNssai { cause, s_nssai });

decoded_ie!(
    RejectedNssai: Vec<RejectedSNssai>,
    |ie| ie.receiver_syntax_is_valid().then(|| {
        (ie.entries().into_iter())
            .map(|(cause, s_nssai)| RejectedSNssai { cause, s_nssai })
            .collect()
    }),
    |_, rejected| {
        let snssais = snssais(rejected.iter().map(|one| &one.s_nssai))?;
        let entries: Vec<_> = rejected.iter().map(|one| one.cause).zip(&snssais).collect();
        RejectedNssai::from_entries(&entries)
    }
);
decoded_ie!(
    TrackingAreaIdentity: view::TaiForm<Tai5gs>,
    |ie| ie.tai().map(view::TaiForm),
    |_, tai| TrackingAreaIdentity::from_plmn_tac(&tai.0.plmn(), tai.0.tac())
);
decoded_ie!(
    TrackingAreaIdentityList: Vec<TaiListEntry>,
    |ie| ie.receiver_syntax_is_valid().then(|| ie.entries()),
    |_, entries| TrackingAreaIdentityList::from_entries(&entries)
);
decoded_ie!(
    LadnIndication: Vec<String>,
    |ie| ie.dnn_values().iter().map(|dnn| decode_labels(dnn)).collect(),
    |_, dnns| {
        let dnns: core::result::Result<Vec<_>, _> = (dnns.iter().enumerate())
            .map(|(entry, dnn)| encode_labels("dnn", dnn, 100).map_err(|error| error.at(entry)))
            .collect();
        LadnIndication::from_dnn_values(&dnns?)
    }
);

// Timers, names and numbers.
timer_ie!(T3512Value);
decoded_ie!(Dnn: String, |ie| ie.as_string(), |_, name| Dnn::from_string(&name));
decoded_ie!(Nid: String, |ie| Some(ie.nid_value()), |_, nid| Nid::from_nid_value(&nid));
decoded_ie!(
    SmPduDnRequestContainer: String,
    |ie| ie.as_utf8_str().map(str::to_string),
    |_, text| Ok(SmPduDnRequestContainer::from_str(&text))
);

decoded_ie!(
    PduSessionIdentity2: u8,
    |ie| Some(ie.pdu_session_id()),
    |_, identity| Ok(PduSessionIdentity2::from_pdu_session_id(identity))
);
decoded_ie!(
    PduSessionPairId: u8,
    |ie| ie.pair_id(),
    |_, identity| Ok(PduSessionPairId::from_pair_id(identity))
);
decoded_ie!(
    MaximumNumberOfSupportedPacketFilters: u16,
    |ie| ie.is_well_formed().then(|| ie.max_filters()),
    |_, filters| MaximumNumberOfSupportedPacketFilters::from_max_filters(filters)
);
decoded_ie!(
    N1ModeToS1ModeNasTransparentContainer: u8,
    |ie| Some(ie.sequence_number()),
    |_, number| Ok(N1ModeToS1ModeNasTransparentContainer::from_sequence_number(number))
);

/// The fields of an intra N1 mode NAS transparent container (TS 24.501
/// §9.11.2.6). The algorithms and the ngKSI are coded as in a SECURITY MODE
/// COMMAND, whose names they have.
#[derive(Clone, PartialEq)]
struct IntraN1ModeFields {
    message_authentication_code: u32,
    selected_nas_security_algorithms: SecurityAlgorithms,
    k_amf_change_flag: bool,
    ngksi: KeySetIdentifier,
    sequence_number: u8,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct IntraN1ModeFields { message_authentication_code, selected_nas_security_algorithms as tree, k_amf_change_flag, ngksi as tree, sequence_number });

decoded_ie!(
    IntraN1ModeNasTransparentContainer: IntraN1ModeFields,
    |ie| {
        (ie.value.len() == 7).then_some(())?;
        Some(IntraN1ModeFields {
            message_authentication_code: ie.message_authentication_code()?,
            selected_nas_security_algorithms: ie.security_algorithms()?,
            k_amf_change_flag: ie.k_amf_change_flag()?,
            ngksi: ie.key_set_identifier()?,
            sequence_number: ie.sequence_number()?,
        })
    },
    |_, fields| Ok(IntraN1ModeNasTransparentContainer::from_fields(
        fields.message_authentication_code,
        fields.selected_nas_security_algorithms,
        fields.k_amf_change_flag,
        fields.ngksi,
        fields.sequence_number,
    ))
);

/// The fields of an S1 mode to N1 mode NAS transparent container (TS 24.501
/// §9.11.2.9), named as those of [`IntraN1ModeFields`]. Its octets 9 and 10
/// are spare.
#[derive(Clone, PartialEq)]
struct S1ModeToN1ModeFields {
    message_authentication_code: u32,
    selected_nas_security_algorithms: SecurityAlgorithms,
    ncc: u8,
    ngksi: KeySetIdentifier,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct S1ModeToN1ModeFields { message_authentication_code, selected_nas_security_algorithms as tree, ncc, ngksi as tree });

decoded_ie!(
    S1ModeToN1ModeNasTransparentContainer: S1ModeToN1ModeFields,
    |ie| {
        (ie.value.len() == 8).then_some(())?;
        Some(S1ModeToN1ModeFields {
            message_authentication_code: ie.message_authentication_code()?,
            selected_nas_security_algorithms: ie.security_algorithms()?,
            ncc: ie.ncc()?,
            ngksi: ie.key_set_identifier()?,
        })
    },
    |_, fields| S1ModeToN1ModeNasTransparentContainer::from_fields(
        fields.message_authentication_code,
        fields.selected_nas_security_algorithms,
        fields.ncc,
        fields.ngksi,
    )
);
decoded_ie!(
    TimeDuration: u32,
    |ie| ie.seconds(),
    |_, seconds| TimeDuration::from_seconds(seconds)
);
decoded_ie!(
    EcnMarkingForL4sIndication: Vec<u16>,
    |ie| Some(numbers(ie.qri_values())),
    |_, qris| EcnMarkingForL4sIndication::try_from_qri_values(&octets("qri", &qris, 1, 255)?)
);

/// The PDU session identities that a status has the bits of: 1 to 15.
fn psis(sessions: &[u16]) -> core::result::Result<Vec<u8>, ValueError> {
    octets("pdu-session-identity", sessions, 1, 15)
}

// Sessions: the identities a status has the bits of, and what a session has.
decoded_ie!(
    PduSessionStatus: Vec<u16>,
    |ie| Some(numbers(&ie.active_sessions())),
    |_, sessions| PduSessionStatus::from_sessions(&psis(&sessions)?)
);
decoded_ie!(
    UplinkDataStatus: Vec<u16>,
    |ie| Some(numbers(&ie.sessions_with_data())),
    |_, sessions| UplinkDataStatus::from_sessions(&psis(&sessions)?)
);
decoded_ie!(
    AllowedPduSessionStatus: Vec<u16>,
    |ie| Some(numbers(&ie.allowed_sessions())),
    |_, sessions| AllowedPduSessionStatus::from_sessions(&psis(&sessions)?)
);
decoded_ie!(
    PduSessionReactivationResult: Vec<u16>,
    |ie| Some(numbers(&ie.failed_sessions())),
    |_, sessions| PduSessionReactivationResult::from_failed_sessions(&psis(&sessions)?)
);
decoded_ie!(
    SessionAmbr: SessionAmbrValue,
    |ie| ie.parse(),
    |_, ambr| SessionAmbr::from_kbps(ambr.dl_kbps, ambr.ul_kbps),
    // The two rates are all that a session AMBR with units of the table
    // means: the unit that counts each of them says no more.
    meant: |ie| ie.is_well_formed()
);

/// The addresses of a PDU address, by the PDU session type that has them.
#[derive(Clone, PartialEq)]
struct PduAddressForm {
    ipv4: Option<Ipv4Addr>,
    ipv6_interface_id: Option<[u8; 8]>,
    smf_ipv6_link_local_address: Option<Ipv6Addr>,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct PduAddressForm { ipv4, ipv6_interface_id, smf_ipv6_link_local_address });

decoded_ie!(
    PduAddress: PduAddressForm,
    |ie| ie.receiver_syntax_is_valid().then(|| PduAddressForm {
        ipv4: ie.ipv4().map(Ipv4Addr::from),
        ipv6_interface_id: ie.ipv6_interface_id(),
        smf_ipv6_link_local_address: ie.smf_ipv6_link_local_address().map(Ipv6Addr::from),
    }),
    |_, address| {
        let ipv4 = address.ipv4.map(|ipv4| ipv4.octets());
        let smf = address.smf_ipv6_link_local_address.map(|smf| smf.octets());
        Ok(match (ipv4, address.ipv6_interface_id, smf) {
            (Some(ipv4), None, None) => PduAddress::from_ipv4(ipv4),
            (None, Some(id), None) => PduAddress::from_ipv6_iid(id),
            (Some(ipv4), Some(id), None) => PduAddress::from_ipv4v6(id, ipv4),
            (Some(ipv4), None, Some(smf)) => {
                PduAddress::from_ipv4_with_smf_ipv6_link_local_address(ipv4, smf)
            }
            (None, Some(id), Some(smf)) => {
                PduAddress::from_ipv6_iid_with_smf_ipv6_link_local_address(id, smf)
            }
            (Some(ipv4), Some(id), Some(smf)) => {
                PduAddress::from_ipv4v6_with_smf_ipv6_link_local_address(id, ipv4, smf)
            }
            (None, None, _) => {
                let rule = "or `ipv6-interface-id` is written: a PDU address has one of them or \
                            both";
                return Err(ValueError::combination("ipv4", rule));
            }
        })
    }
);

/// The maximum data rates of user plane integrity protection.
#[derive(Clone, PartialEq)]
struct MaximumDataRates {
    ul: MaxDataRate,
    dl: MaxDataRate,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct MaximumDataRates { ul, dl });

decoded_ie!(
    IntegrityProtectionMaximumDataRate: MaximumDataRates,
    |ie| Some(MaximumDataRates {
        ul: MaxDataRate::try_from(ie.ul_raw()).ok()?,
        dl: MaxDataRate::try_from(ie.dl_raw()).ok()?,
    }),
    |_, rates| Ok(IntegrityProtectionMaximumDataRate::from_rates(rates.ul, rates.dl))
);
decoded_ie!(
    QosRules: Vec<QosRule>,
    |ie| ie.validate_strict().is_ok().then(|| ie.rules()),
    |_, rules| QosRules::from_rules(&rules)
);
decoded_ie!(
    QosFlowDescriptions: Vec<QosFlowDescription>,
    |ie| ie.try_descriptions(),
    |_, descriptions| QosFlowDescriptions::from_descriptions(&descriptions)
);

// Capabilities: every flag by its name, and the algorithms by number.
fields_ie!(GmmCapability {} flags);
crate::common::nas_ie_flags!(@named NetworkFeatureSupport {
    ims_vops_3gpp ims_vops_n3gpp iwk_n26 mpsi emcn3 mcsi cp_ciot n3_data iphc_cp_ciot up_ciot
    lcs_5g ats_ind ehc_cp_ciot ncr piv rpr pr un_per naps lcs_upp supl rslp mlcsup ef5l
});
fields_ie!(NetworkFeatureSupport {
    "emc":
        |ie| Code::of(ie.emc_value(), ie.emc()),
        |ie, code: Code<EmergencyServiceSupport>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_emc_value(name);
            },
            |ie| ie.emc(),
        );
    "emf":
        |ie| Code::of(ie.emf_value(), ie.emf()),
        |ie, code: Code<EmergencyFallbackSupport>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_emf_value(name);
            },
            |ie| ie.emf(),
        );
    "restrict-ec":
        |ie| Code::of(ie.restrict_ec_value(), ie.restrict_ec()),
        |ie, code: Code<RestrictionOnEnhancedCoverage>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_restrict_ec_value(name);
            },
            |ie| ie.restrict_ec(),
        );
} flags);
crate::common::nas_ie_flags!(@named GsmCapability {
    tpmic ept_s1 mh6_pdu rqos mpquic_ip mpquic_udp mptcp rtpmmii sdnaepc apmqf e8pcpdei mpquic_e
});
fields_ie!(GsmCapability {
    "atsss-st":
        |ie| Code::of(ie.atsss_st_value(), ie.atsss_st()),
        |ie, code: Code<AtsssSteeringFunctionality>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_atsss_st_value(name);
            },
            |ie| ie.atsss_st(),
        );
    "atsss-ll":
        |ie| Code::of(ie.atsss_ll_value(), ie.atsss_ll()),
        |ie, code: Code<AtsssLowLayerFunctionality>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_atsss_ll_value(name);
            },
            |ie| ie.atsss_ll(),
        );
} flags);
fields_ie!(S1UeNetworkCapability {
    "eea": |ie| supported(ie, Self::supports_eea), |ie, algorithms: Vec<u16>| {
        (0..8).try_for_each(|algorithm| {
            ie.set_eea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "eia": |ie| supported(ie, Self::supports_eia), |ie, algorithms: Vec<u16>| {
        (0..7).try_for_each(|algorithm| {
            ie.set_eia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "uea": |ie| supported(ie, Self::supports_uea), |ie, algorithms: Vec<u16>| {
        (0..8).try_for_each(|algorithm| {
            ie.set_uea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "uia": |ie| supported(ie, Self::supports_uia), |ie, algorithms: Vec<u16>| {
        (1..8).try_for_each(|algorithm| {
            ie.set_uia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
} flags);
fields_ie!(S1UeSecurityCapability {
    "eea": |ie| supported(ie, Self::supports_eea), |ie, algorithms: Vec<u16>| {
        (0..8).try_for_each(|algorithm| {
            ie.set_eea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "eia": |ie| supported(ie, Self::supports_eia), |ie, algorithms: Vec<u16>| {
        (0..7).try_for_each(|algorithm| {
            ie.set_eia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "uea": |ie| supported(ie, Self::supports_uea), |ie, algorithms: Vec<u16>| {
        (0..8).try_for_each(|algorithm| {
            ie.set_uea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "uia": |ie| supported(ie, Self::supports_uia), |ie, algorithms: Vec<u16>| {
        (1..8).try_for_each(|algorithm| {
            ie.set_uia(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
    "gea": |ie| supported(ie, Self::supports_gea), |ie, algorithms: Vec<u16>| {
        (1..8).try_for_each(|algorithm| {
            ie.set_gea(algorithm, algorithms.contains(&algorithm.into())).map(|_| ())
        })
    };
} flags);

// Lists and containers that their constructors build from the entries that
// are parsed. What an author writes is built and read back: a value that
// the IE does not then have is refused.
decoded_ie!(
    NsagInformation: Vec<NsagInfoEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NsagInformation::from_entries(&entries)
);
decoded_ie!(
    NssrgInformation: Vec<NssrgInfoEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NssrgInformation::from_entries(&entries)
);
decoded_ie!(
    LadnInformation: Vec<LadnInfoEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| LadnInformation::from_entries(&entries)
);
decoded_ie!(
    CagInformationList: Vec<CagInformationEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| CagInformationList::from_entries(&entries)
);
decoded_ie!(
    ExtendedCagInformationList: Vec<CagInformationEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| ExtendedCagInformationList::from_entries(&entries)
);
decoded_ie!(
    ServiceAreaList: Vec<ServiceAreaListEntry>,
    |ie| ie.receiver_syntax_is_valid().then(|| ie.entries()),
    |_, entries| ServiceAreaList::from_entries(&entries)
);
decoded_ie!(
    ExtendedRejectedNssai: Vec<ExtendedRejectedNssaiPartialList>,
    |ie| ie.is_well_formed().then(|| ie.partial_lists()),
    |_, lists| ExtendedRejectedNssai::from_partial_lists(&lists)
);
decoded_ie!(
    OperatorDefinedAccessCategoryDefinitions: Vec<OperatorAccessCategoryDefinition>,
    |ie| ie.try_definitions(),
    |_, definitions| OperatorDefinedAccessCategoryDefinitions::from_definitions(&definitions)
);
decoded_ie!(
    PduSessionReactivationResultErrorCause: Vec<(u8, GmmCauseValue)>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| PduSessionReactivationResultErrorCause::from_entries(&entries)
);
decoded_ie!(
    MappedEpsBearerContexts: Vec<MappedEpsBearerContext>,
    |ie| ie.contexts(),
    |_, contexts| MappedEpsBearerContexts::from_contexts(&contexts)
);
decoded_ie!(
    ReceivedMbsContainer: Vec<ReceivedMbsSession>,
    |ie| ie.try_sessions(),
    |_, sessions| ReceivedMbsContainer::try_from_sessions(&sessions)
);
decoded_ie!(
    RequestedMbsContainer: Vec<RequestedMbsSession>,
    |ie| ie.try_sessions(),
    |_, sessions| RequestedMbsContainer::try_from_sessions(&sessions)
);
decoded_ie!(
    SorTransparentContainer: SorTransparentContainerContents,
    |ie| ie.parse(),
    |_, contents| match contents {
        SorTransparentContainerContents::Acknowledgement {
            mssi,
            mssnpnsi,
            msssnpnsils,
            sor_mac_iue,
        } => Ok(SorTransparentContainer::from_ack(
            mssi,
            mssnpnsi,
            msssnpnsils,
            sor_mac_iue,
        )),
        SorTransparentContainerContents::Information {
            list_indication,
            list_type,
            acknowledgement_requested,
            additional_parameters,
            sor_mac_iausf,
            counter_sor,
            body,
        } => SorTransparentContainer::from_information(
            list_indication,
            list_type,
            acknowledgement_requested,
            additional_parameters,
            sor_mac_iausf,
            counter_sor,
            &body,
        ),
    }
);
decoded_ie!(
    UeParametersUpdateTransparentContainer: UeParametersUpdateTransparentContainerContents,
    |ie| ie.parse(),
    |_, contents| UeParametersUpdateTransparentContainer::from_parsed(&contents)
);
decoded_ie!(
    CiotSmallDataContainer: CiotSmallDataContainerContents,
    |ie| ie.parse(),
    |_, contents| CiotSmallDataContainer::from_parsed(&contents)
);
decoded_ie!(
    N3Qai: Vec<N3QaiEntry>,
    |ie| ie.try_entries(),
    |_, entries| N3Qai::from_entries(&entries)
);
decoded_ie!(
    ProtocolDescription: Vec<ProtocolDescriptionEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| ProtocolDescription::from_entries(&entries)
);
decoded_ie!(
    Type6IeContainer: Vec<Type6IeContainerEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| Type6IeContainer::from_entries(&entries)
);
decoded_ie!(
    SNssaiLocationValidityInformation: Vec<SNssaiLocationValidityEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| SNssaiLocationValidityInformation::from_entries(&entries)
);
decoded_ie!(
    RelayKeyRequestParameters: RelayKeyRequestParametersValue,
    |ie| ie.parse(),
    |_, parameters| RelayKeyRequestParameters::from_parsed(&parameters)
);
decoded_ie!(
    RelayKeyResponseParameters: RelayKeyResponseParametersValue,
    |ie| ie.parse(),
    |_, parameters| RelayKeyResponseParameters::from_parsed(&parameters)
);
decoded_ie!(
    ServiceLevelAaContainer: Vec<ServiceLevelAaParameter>,
    |ie| ie.try_parameters().ok(),
    |_, parameters| ServiceLevelAaContainer::from_parameters(&parameters)
);
decoded_ie!(
    N3iwfIdentifier: N3iwfAddress,
    |ie| ie.address(),
    |_, address| Ok(N3iwfIdentifier::from_address(&address))
);
// Lists that had octets alone and that their constructors build.
listed_ie!(
    PeipsAssistanceInformation: PeipsAssistanceInformationEntry,
    entries,
    Self::from_entries
);
listed_ie!(SnpnList: SnpnListEntry, entries, |entries| {
    Ok(Self::from_entries(entries))
});
listed_ie!(AlternativeNssai: AlternativeNssaiEntry, entries, |entries| {
    Self::from_entries(entries)
});
listed_ie!(OnDemandNssai: OnDemandNssaiEntry, entries, |entries| {
    Self::from_entries(entries)
});
listed_ie!(PartialNssai: PartialNssaiEntry, entries, |entries| {
    Self::from_entries(entries)
});
listed_ie!(ExtendedLadnInformation: ExtendedLadnInformationEntry, entries, Self::from_entries);
listed_ie!(Non3GppDelayBudget: Non3GppDelayBudgetEntry, entries, Self::from_entries);
decoded_ie!(
    RemoteUeContextList: Vec<RemoteUeContext>,
    |ie| {
        // The contexts are the value when they encode back to its octets.
        let contexts = ie.contexts()?;
        let encoded = RemoteUeContextList::from_contexts(&contexts).ok()?;
        (encoded.value == ie.value).then_some(contexts)
    },
    |_, contexts| RemoteUeContextList::from_contexts(&contexts)
);
listed_ie!(
    SNssaiTimeValidityInformation: SNssaiTimeValidityEntry,
    entries,
    Self::from_entries
);
listed_ie!(UrspRuleEnforcementReports: UrspRuleEnforcementReport, reports, Self::from_reports);
listed_ie!(CipheringKeyData: CipheringDataSet, data_sets, Self::from_data_sets);

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
            sweep(IpHeaderCompressionConfiguration::new(vec![value; 3]));
            sweep(IpHeaderCompressionConfiguration::new(vec![
                value & 0x7f,
                0,
                value,
                value & 7,
                value,
            ]));
            sweep(PagingRestriction::new(vec![value & 0x0f]));
            sweep(PagingRestriction::new(vec![3, value & 0xfe, value]));
            sweep(TnanInformation::new(vec![value & 3, 1, value, 1, 0x41]));
            sweep(LpWuspsAssistanceInformation::new(vec![value]));
            sweep(UeDsTtResidenceTime::new(vec![value; 8]));
            sweep(GmmCause::new(value));
            sweep(GsmCause::new(value));
            sweep(IdentityType::new(value));
            sweep(PduSessionType::new(value));
            sweep(SscMode::new(value));
            sweep(RequestType::new(value));
            sweep(AccessType::new(value));
            sweep(PayloadContainerType::new(value));
            sweep(NssaiInclusionMode::new(value));
            sweep(ProseRelayTransactionIdentity::new(value));
            sweep(RegistrationType::new(value));
            sweep(DeRegistrationType::new(value));
            sweep(ControlPlaneServiceType::new(value));
            sweep(SecurityAlgorithms::new(value));
            sweep(EpsNasSecurityAlgorithms::new(value));
            sweep(KeySetIdentifier::new(value));
            sweep(GprsTimer::new(value));
            sweep(GprsTimer2::new(vec![value]));
            sweep(GprsTimer3::new(vec![value]));
            sweep(UpdateType::new(vec![value]));
            sweep(RegistrationResult::new(vec![value]));
            sweep(GmmCapability::new(vec![value]));
            sweep(GmmCapability::new(vec![value; 13]));
            sweep(GsmCapability::new(vec![value]));
            sweep(GsmCapability::new(vec![value; 3]));
            sweep(NetworkFeatureSupport::new(vec![value]));
            sweep(NetworkFeatureSupport::new(vec![value; 4]));
            sweep(S1UeNetworkCapability::new(vec![value; 2]));
            sweep(S1UeNetworkCapability::new(vec![value; 9]));
            sweep(S1UeSecurityCapability::new(vec![value; 5]));
            sweep(UeSecurityCapability::new(vec![value; 2]));
            sweep(UeSecurityCapability::new(vec![value; 4]));
            sweep(PduSessionStatus::new(vec![value; 2]));
            sweep(UplinkDataStatus::new(vec![value; 2]));
            sweep(AllowedPduSessionStatus::new(vec![value; 2]));
            sweep(PduSessionReactivationResult::new(vec![value; 2]));
            sweep(EpsBearerContextStatus::new(vec![value & 0xfe, value]));
            sweep(UeStatus::new(vec![value]));
            sweep(ReAttemptIndicator::new(vec![value]));
            sweep(ExtendedDrxParameters::new(vec![value]));
            sweep(TimeZoneAndTime::new(vec![value & 0x11; 7]));
            sweep(Additional5gSecurityInformation::new(vec![value]));
            sweep(AdditionalConfigurationIndication::new(value & 0x0f));
            sweep(AdditionalInformationRequested::new(vec![value]));
            sweep(AllowedSscMode::new(value & 0x0f));
            sweep(AlwaysOnPduSessionIndication::new(value & 0x0f));
            sweep(AlwaysOnPduSessionRequested::new(value & 0x0f));
            sweep(Aun3Indication::new(vec![value]));
            sweep(ConfigurationUpdateIndication::new(value & 0x0f));
            sweep(ControlPlaneOnlyIndication::new(value & 0x0f));
            sweep(ExtendedGmmCause::new(vec![value]));
            sweep(GsmCongestionReAttemptIndicator::new(vec![value]));
            sweep(GsmNetworkFeatureSupport::new(vec![value]));
            sweep(FeatureAuthorizationIndication::new(vec![value]));
            sweep(LpWusStatus::new(value & 0x0f));
            sweep(MicoIndication::new(value & 0x0f));
            sweep(N5gcIndication::new(value & 0x0f));
            sweep(NetworkSlicingIndication::new(value & 0x0f));
            sweep(Non3GppAccessPathSwitchingIndication::new(vec![value]));
            sweep(Non3GppPathSwitchingInformation::new(vec![value]));
            sweep(PayloadContainerInformation::new(value & 0x0f));
            sweep(PriorityIndicator::new(value & 0x0f));
            sweep(RanTimingSynchronization::new(vec![value]));
            sweep(SmsIndication::new(value & 0x0f));
            sweep(UeUsageSetting::new(vec![value]));
            sweep(Truncated5gSTmsiConfiguration::new(vec![value]));
            sweep(RegistrationWaitRange::new(vec![value, value]));
            sweep(Aun3DeviceSecurityKey::new(vec![value & 1, 2, 0xaa, 0xbb]));
            sweep(PduSessionIdentity2::new(value));
            sweep(PduSessionPairId::new(vec![value]));
            sweep(MaximumNumberOfSupportedPacketFilters::new(vec![
                value,
                value & 0xe0,
            ]));
            sweep(N1ModeToS1ModeNasTransparentContainer::new(value));
            sweep(IntraN1ModeNasTransparentContainer::new(vec![
                1, 2, 3, 4, value, value, value,
            ]));
            sweep(S1ModeToN1ModeNasTransparentContainer::new(vec![
                1, 2, 3, 4, value, value, 0, 0,
            ]));
            sweep(TimeDuration::new(vec![value, value]));
            sweep(EcnMarkingForL4sIndication::new(vec![value & 0x3f]));
            sweep(WusAssistanceInformation::new(vec![value]));
            sweep(EthernetHeaderCompressionConfiguration::new(vec![value]));
            sweep(ImeisvRequest::new(value & 0x0f));
            sweep(DrxParameters::new(vec![value]));
            sweep(Rsn::new(vec![value]));
            sweep(IntegrityProtectionMaximumDataRate::new(
                u16::from(value) * 0x0101,
            ));
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
        for identity in [
            octets(&[&[0x01], &plmn, &[0, 0, 0, 0, 0, 0, 0, 0, 0x10]]),
            octets(&[&[0x01], &plmn, &[0xf0, 0xff, 1, 2], &[0xaa; 41]]),
            octets(&[&[0xf2], &plmn, &[1, 0, 0x42, 0x11, 0x22, 0x33, 0x44]]),
            vec![0xf4, 0, 0x42, 0x11, 0x22, 0x33, 0x44],
            vec![0x4b, 0x09, 0x51, 0x24, 0x30, 0x32, 0x57, 0x81],
            vec![0x45, 0x09, 0x51, 0x24, 0x30, 0x32, 0x57, 0x81, 0xf1],
            vec![0x0e, 1, 2, 3, 4, 5, 6],
            vec![0x07, 1, 2, 3, 4, 5, 6, 7, 8],
            vec![0x00],
        ] {
            exercise(MobileIdentity::new(identity));
        }
        let nai = "type1.rid678.schid0.useriduser17@example.com";
        exercise(MobileIdentity::from_suci_nai(nai).unwrap());
        exercise(DsTtEthernetPortMacAddress::new(vec![1, 2, 3, 4, 5, 6]));
        exercise(TrackingAreaIdentity::new(octets(&[&plmn, &[0, 0, 1]])));
        for list in [
            octets(&[&[0x01], &plmn, &[0, 0, 1, 0, 0, 2]]),
            octets(&[&[0x21], &plmn, &[0, 0, 1]]),
            octets(&[&[0x41], &plmn, &[0, 0, 1], &plmn, &[0, 0, 2]]),
        ] {
            exercise(TrackingAreaIdentityList::new(list));
        }
        exercise(PlmnList::new(octets(&[&plmn, &[0x02, 0x18, 0x39]])));
        exercise(ListOfPlmnsToBeUsedInDisasterCondition::new(plmn.to_vec()));
        exercise(PlmnIdentity::new(plmn));
        exercise(SNssai::new(vec![1, 1, 2, 3]));
        exercise(Nssai::new(vec![4, 1, 1, 2, 3, 1, 2]));
        exercise(MappedNssai::new(vec![1, 1, 4, 1, 1, 2, 3]));
        exercise(RejectedNssai::new(vec![0x10, 1, 0x41, 2, 1, 2, 3]));
        exercise(LadnIndication::new(b"\x09\x08internet\x04\x03ims".to_vec()));
        exercise(Dnn::new(b"\x08internet".to_vec()));
        exercise(Nid::from_nid_value("000007ed9d5a").unwrap());
        exercise(SmPduDnRequestContainer::from_str("user@example.com"));
        exercise(SessionAmbr::new(vec![6, 0, 100, 6, 0, 50]));
        exercise(PduAddress::new(vec![1, 10, 0, 0, 1]));
        exercise(PduAddress::new(vec![2, 1, 2, 3, 4, 5, 6, 7, 8]));
        exercise(PduAddress::new(vec![
            3, 1, 2, 3, 4, 5, 6, 7, 8, 10, 0, 0, 1,
        ]));
        exercise(PduAddress::new(octets(&[&[9, 10, 0, 0, 1], &[0xfe; 16]])));
        // One QoS rule: create, default, precedence 255, QFI 1, match-all filter.
        exercise(QosRules::new(vec![1, 0, 6, 0x31, 0x31, 1, 1, 255, 1]));
        // One QoS flow description: create QFI 1 with a 5QI of 9.
        exercise(QosFlowDescriptions::new(vec![1, 0x20, 0x41, 1, 1, 9]));
        exercise(NetworkName::from_name("Open5GS", true));
        exercise(TimeZone::new(0x40));
        exercise(EmergencyNumberList::new(vec![3, 0x1f, 0x11, 0xf2]));
        exercise(ServingPlmnRateControl::new(vec![0, 10]));
        exercise(SupportedCodecList::new(vec![4, 2, 0x60, 0]));
        // A container of a 5GMM STATUS with cause #22, and lists.
        exercise(MessageContainer::new(vec![0x7e, 0x00, 0x64, 0x16]));
        exercise(ServiceAreaList::new(octets(&[&[0x00], &plmn, &[0, 0, 1]])));
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
