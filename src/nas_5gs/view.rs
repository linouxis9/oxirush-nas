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
use crate::common::{MessageBody, NasError, Result};
use crate::nas_5gs::messages::{Nas5gmmHeader, Nas5gsmHeader};
use crate::nas_5gs::{
    Nas5gmmMessage, Nas5gmmMessageType, Nas5gsMessage, Nas5gsmMessage, Nas5gsmMessageType,
};
use crate::prelude::*;

/// Visit the IEs of `body`, with `ie` in the place of the field `field`.
fn with_ie(body: &dyn MessageBody, field: &str, ie: &dyn Ie, visit: &mut Visit<'_>) {
    body.ies(&mut |visited| {
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
fn sent(message: &Nas5gsmMessage) -> Option<PcoDirection> {
    use Nas5gsmMessage as M;
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

impl Viewed for Nas5gsMessage {
    fn ies(&self, visit: &mut Visit<'_>) {
        let _sent = view::Sent::by(match self {
            Self::Gsm(_, message) => sent(message),
            _ => None,
        });
        match self {
            // The payload container type says what the container carries.
            Self::Gmm(_, Nas5gmmMessage::UlNasTransport(transport))
                if transport.payload_container_type.is_n1_sm() =>
            {
                let container = N1SmContainer(&transport.payload_container);
                with_ie(&**transport, "payload_container", &container, visit);
            }
            Self::Gmm(_, Nas5gmmMessage::DlNasTransport(transport))
                if transport.payload_container_type.is_n1_sm() =>
            {
                let container = N1SmContainer(&transport.payload_container);
                with_ie(&**transport, "payload_container", &container, visit);
            }
            Self::Gmm(_, message) => message.body().ies(visit),
            Self::Gsm(_, message) => message.body().ies(visit),
            Self::SecurityProtected(_, inner) => inner.ies(visit),
            Self::Opaque(_) => {}
        }
    }

    fn absent(&self, visit: &mut dyn FnMut(&'static str, usize)) {
        match self {
            Self::Gmm(_, message) => message.body().absent(visit),
            Self::Gsm(_, message) => message.body().absent(visit),
            Self::SecurityProtected(_, inner) => inner.absent(visit),
            Self::Opaque(_) => {}
        }
    }

    fn header(&self) -> Option<serde_json::Value> {
        match self {
            Self::Gmm(header, _) => readable::to_value(header).ok(),
            Self::Gsm(header, _) => readable::to_value(header).ok(),
            Self::SecurityProtected(_, inner) => inner.header(),
            Self::Opaque(_) => None,
        }
    }

    fn protection(&self) -> Option<(serde_json::Value, Option<serde_json::Value>)> {
        let Self::SecurityProtected(header, inner) = self else {
            return None;
        };
        let ciphered = match &**inner {
            Self::Opaque(octets) => Some(view::octets_shown(octets)),
            _ => None,
        };
        Some((readable::to_value(header).ok()?, ciphered))
    }

    fn keep_received(&mut self, original: &Self) {
        let (body, received) = match (self, original) {
            (Self::Gmm(_, message), Self::Gmm(_, original)) => {
                (message.body_mut(), original.body().received())
            }
            (Self::Gsm(_, message), Self::Gsm(_, original)) => {
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
            Self::Gmm(_, message) => message.body().received().0.clone(),
            Self::Gsm(_, message) => message.body().received().0.clone(),
            Self::SecurityProtected(_, inner) => inner.unknown(),
            Self::Opaque(_) => crate::common::UnknownIes::new(),
        }
    }

    fn set_unknown(&mut self, unknown: &crate::common::UnknownIes) -> bool {
        match self {
            Self::Gmm(_, message) => message
                .body_mut()
                .set_received(unknown, &crate::common::IeOrder::new()),
            Self::Gsm(_, message) => message
                .body_mut()
                .set_received(unknown, &crate::common::IeOrder::new()),
            Self::SecurityProtected(_, inner) => return inner.set_unknown(unknown),
            Self::Opaque(_) => return false,
        }
        true
    }

    fn blank(&self, name: &str) -> Option<serde_json::Value> {
        match self {
            Self::Gmm(_, message) => message.body().blank(name),
            Self::Gsm(_, message) => message.body().blank(name),
            Self::SecurityProtected(_, inner) => inner.blank(name),
            Self::Opaque(_) => None,
        }
    }

    const FAMILIES: &'static [&'static str] = &["Gmm", "Gsm"];

    const SPARE: &'static [&'static str] = &["spare-half-octet"];

    fn refused_header(&self) -> Option<String> {
        use crate::nas_5gs::Nas5gsSecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected;
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
                            .then(|| format!("`spare-half-octet` is {spare}, and is 0 to 15"))
                    })
            }
            Self::Gsm(header, _) => {
                discriminator(header.extended_protocol_discriminator, "5GSM", 46)
            }
            _ => None,
        }
    }

    fn header_name(field: &str, number: u64) -> Option<serde_json::Value> {
        let number = u8::try_from(number).ok()?;
        match field {
            "security-header-type" => {
                let named = crate::nas_5gs::Nas5gsSecurityHeaderType::try_from(number).ok()?;
                readable::to_value(&named).ok()
            }
            // The types of 5GMM and of 5GSM have no number in common, and a
            // number that is of neither has no name.
            "message-type" => match Nas5gmmMessageType::try_from(number).ok()? {
                Nas5gmmMessageType::Unknown(_) => {
                    readable::to_value(&Nas5gsmMessageType::try_from(number).ok()?).ok()
                }
                named => readable::to_value(&named).ok(),
            }
            .filter(serde_json::Value::is_string),
            _ => None,
        }
    }

    fn prepared(mut self, view: &serde_json::Map<String, serde_json::Value>) -> Self {
        // The payload container is read as its type says.
        let kind = match &mut self {
            Self::Gmm(_, Nas5gmmMessage::UlNasTransport(transport)) => {
                &mut transport.payload_container_type
            }
            Self::Gmm(_, Nas5gmmMessage::DlNasTransport(transport)) => {
                &mut transport.payload_container_type
            }
            _ => return self,
        };
        let written = (view.iter())
            .find(|(name, _)| readable::same_name(name, "payload-container-type"))
            .and_then(|(_, entry)| entry.get("value"));
        if let Some(Ok(written)) = written.map(|value| view::Decoded::with_decoded(kind, value)) {
            *kind = written;
        }
        self
    }
}

impl Nas5gsMessage {
    /// The view of the message: each of its IEs by the name TS 24.501 gives
    /// it, with its `value` and its `octets`.
    ///
    /// `octets` is the value part of the IE in hexadecimal. `value` is what
    /// the typed accessors of the IE decode from it, in the notation a
    /// reader expects: a coded value is its name (`"initial-registration"`)
    /// or, where the specification names none, its number; a PLMN identity
    /// is `"208-93"`; an IMSI, an IMEI or an MSIN is its digits; a TMSI, a
    /// TAC or an SST is a number and a DNN is text; an IP address is its
    /// text; a container of a NAS message is the view of that message.
    /// What has no other notation stays hexadecimal: an SD, a key, a MAC
    /// address. An IE that the crate does not decode, and octets that do
    /// not decode, have `octets` alone. So do octets whose value the crate
    /// could not take back, such as a time whose digits are no decimal
    /// digits: a value that a view shows is one that it takes.
    ///
    /// Names are in lower case with hyphens, and `fg` in a field of the
    /// codec reads `5g`: `fgs_registration_result` is
    /// `5gs-registration-result`. A field of the header has a `value`
    /// alone, and an optional IE that the message does not have is `null`.
    /// The unknown IEs of a message are not in it. The entries are in the
    /// order of the message: the fields of the header first, then the IEs
    /// in the order of the message table.
    ///
    /// Two IEs that share an octet are two entries, as `5gs-registration-type`
    /// and `ngksi` of a REGISTRATION REQUEST, each with the octet of its half
    /// in bits 4 to 1; the spare half octet beside an IE is in the octets of
    /// that IE. In UL and DL NAS TRANSPORT the `payload-container` has a
    /// value when its type is "N1 SM information": the view of the 5GSM
    /// message in it.
    ///
    /// A view is read through a security header: its entries are those of
    /// the plain message, and `security-header` beside them has the value
    /// of the header that protects it, with its `security-header-type`, its
    /// `spare-half-octet`, its `message-authentication-code` and its
    /// `sequence-number`. A message that is ciphered has that header and its
    /// octets as `ciphered-message`.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Nas5gsMessage;
    /// use serde_json::json;
    ///
    /// // 5GMM STATUS with cause #22.
    /// let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let mut view = status.to_view();
    /// assert_eq!(view["message-type"]["value"], "5gmm-status");
    /// assert_eq!(view["5gmm-cause"], json!({"value": "congestion", "octets": "16"}));
    ///
    /// view["5gmm-cause"]["value"] = json!("illegal-ue");
    /// let edited = status.with_view(view).unwrap();
    /// assert_eq!(edited.encode().unwrap(), [0x7e, 0x00, 0x64, 0x03]);
    /// ```
    pub fn to_view(&self) -> serde_json::Value {
        view::to_view(self)
    }

    /// The message that an edited view of this one describes.
    ///
    /// An IE whose `value` was changed is encoded from it, and an IE whose
    /// `octets` were changed has those octets, whatever they are: its
    /// length follows. An IE that the view leaves out or has as `null` is
    /// taken out of the message, and an optional IE that the message does
    /// not have is added with the `value` or the `octets` that the view
    /// gives it. An IE that is built from a value has the octets of every
    /// member that is written, a zero or a `false` as any other. The
    /// message is otherwise this one, with its unknown IEs.
    ///
    /// A name is its letters and its digits, whatever their case and
    /// whatever is between them, and a number is also read as a `"0x…"`
    /// string, except in the `message-type` and the `security-header-type`
    /// of a header, where a string is a name. Nothing that the view says is
    /// ignored: a name that does not exist, a member that an IE or a value
    /// does not have, a value that its IE cannot carry, and `octets` and a
    /// `value` that were both changed and disagree are errors.
    ///
    /// A value says what an IE means, not how it is coded. The encoder
    /// chooses what the value does not show, such as the unit of a timer
    /// or the type of a partial tracking area identity list; the octets
    /// are the way to choose it. A coded value is written by its name or
    /// by its number, which are two ways to write one code, in an IE and
    /// in the header: `"congestion"` and `22` are one cause, and a
    /// `message-type` of `0x64` is `"5gmm-status"`.
    ///
    /// The message authentication code of a security header is that of the
    /// octets it was computed over: an edit of the message under the header
    /// that keeps the code is an error, and the code that the view writes
    /// in `security-header` is taken as it is.
    ///
    /// The message that comes back is one that [`Self::encode`] encodes,
    /// as this one is: an edit that makes a message that has no octets, such
    /// as octets of a length that the message does not give the IE, is an
    /// error here. What the message says is not checked against the rules of
    /// a sender, which `validate()` has.
    pub fn with_view(&self, view: serde_json::Value) -> Result<Self> {
        let edited = view::with_view(self, view).map_err(NasError::EncodingError)?;
        // A message that the view leaves as it is comes back as it is.
        if edited != *self {
            edited.encode()?;
        }
        Ok(edited)
    }

    /// The message that a view describes alone, which its `message-type`
    /// names: a 5GMM or a 5GSM message, as [`Nas5gmmMessageType::from_view`]
    /// and [`Nas5gsmMessageType::from_view`] make it of a type that is known.
    ///
    /// The message is a plain one. The `security-header` that the view of a
    /// protected message has is no entry of it: [`Self::with_view`] edits a
    /// message under its header.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Nas5gsMessage;
    /// use serde_json::json;
    ///
    /// let status = Nas5gsMessage::from_view(json!({
    ///     "extended-protocol-discriminator": {"value": 126},
    ///     "security-header-type": {"value": "plain-5gs-nas-message-not-security-protected"},
    ///     "message-type": {"value": "5gmm-status"},
    ///     "5gmm-cause": {"value": "congestion"},
    /// }))
    /// .unwrap();
    /// assert_eq!(status.encode().unwrap(), [0x7e, 0x00, 0x64, 0x16]);
    /// ```
    pub fn from_view(view: serde_json::Value) -> Result<Self> {
        let named = view::message_type::<Self>(&view).ok_or_else(|| {
            NasError::EncodingError("the `message-type` of the view names the message".into())
        })?;
        match message_types().find(&named) {
            Some((0, place)) => match gmm_types().nth(place) {
                Some(kind) => kind.from_view(view),
                None => Err(NasError::EncodingError(format!("no message `{named}`"))),
            },
            Some((_, place)) => match gsm_types().nth(place) {
                Some(kind) => kind.from_view(view),
                None => Err(NasError::EncodingError(format!("no message `{named}`"))),
            },
            None => Err(NasError::EncodingError(format!("no message `{named}`"))),
        }
    }
}

/// The message `message` that a view or a tree wrote, if it is one that is
/// sent: what the header of a plain message cannot have is refused by the
/// name of its member, and whatever else has no octets as encoding refuses
/// it. A message that is not ciphered under a header that says it is has no
/// octets before a security context ciphers it, and is what it is.
fn sendable(message: Nas5gsMessage) -> Result<Nas5gsMessage> {
    use crate::nas_5gs::Nas5gsSecurityHeaderType::{
        IntegrityProtectedAndCiphered, IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
    };
    let to_cipher = matches!(
        &message,
        Nas5gsMessage::SecurityProtected(header, inner) if matches!(
            header.security_header_type,
            IntegrityProtectedAndCiphered | IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        ) && !matches!(**inner, Nas5gsMessage::Opaque(_))
    );
    match message.refused_header() {
        Some(refused) => Err(NasError::EncodingError(refused)),
        None if to_cipher => Ok(message),
        None => message.encode().map(|_| message),
    }
}

/// The message types of 5GMM, in the order of their numbers.
fn gmm_types() -> impl Iterator<Item = Nas5gmmMessageType> {
    (0..=u8::MAX).filter_map(|octet| Nas5gmmMessageType::try_from(octet).ok())
}

/// The message types of 5GSM, in the order of their numbers.
fn gsm_types() -> impl Iterator<Item = Nas5gsmMessageType> {
    (0..=u8::MAX).filter_map(|octet| Nas5gsmMessageType::try_from(octet).ok())
}

/// The message types of 5GMM, then those of 5GSM, by their names.
fn message_types() -> &'static readable::Groups {
    static TYPES: std::sync::OnceLock<readable::Groups> = std::sync::OnceLock::new();
    TYPES.get_or_init(|| {
        readable::Groups::new([
            gmm_types()
                .map(|known| format!("{known:?}"))
                .collect::<Vec<_>>(),
            gsm_types().map(|known| format!("{known:?}")).collect(),
        ])
    })
}

/// What the type of a 5GS message decides of its header, as a tree leaves it
/// out: the extended protocol discriminator of its sublayer, and for 5GMM a
/// plain security header type. The message of an EPS NAS message container
/// is an EPS one.
fn decided(
    container: Option<&str>,
    kind: Option<&serde_json::Value>,
) -> core::result::Result<Vec<(&'static str, serde_json::Value)>, String> {
    use serde_json::json;
    if container.is_some_and(|ie| readable::same_name(ie, "eps-nas-message-container")) {
        return crate::nas_eps::view::decided(None, kind);
    }
    let kind = kind.ok_or("the `message-type` of a message names it")?;
    let kind = &view::type_named::<Nas5gsMessage>(kind)?;
    match message_types().find(kind).map(|(family, _)| family) {
        Some(0) => Ok(vec![
            ("extended-protocol-discriminator", json!(126)),
            (
                "security-header-type",
                json!("plain-5gs-nas-message-not-security-protected"),
            ),
            ("spare-half-octet", json!(0)),
        ]),
        Some(_) => Ok(vec![("extended-protocol-discriminator", json!(46))]),
        None => Err(format!("no message `{kind}`")),
    }
}

impl Nas5gsMessage {
    /// Whether this message means what `other` means: each IE of one has
    /// the octets of the same IE of the other, or octets that its value
    /// reads the same where the value says all that they mean, as the unit
    /// of a timer does not; and both have the same IEs that their table has
    /// no place for, in the same order. The order of their optional IEs may
    /// differ. [`Self::to_tree`] lists what a value leaves open.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Nas5gsMessage;
    ///
    /// // REGISTRATION REJECT with a T3346 value of twelve minutes, counted in minutes
    /// // and in units of six minutes
    /// let decode = |octets: &str| Nas5gsMessage::decode(&hex::decode(octets).unwrap()).unwrap();
    /// let (minutes, decihours) = (decode("7e0044165f012c"), decode("7e0044165f0142"));
    /// assert!(minutes != decihours && minutes.means_the_same(&decihours));
    /// assert!(!minutes.means_the_same(&decode("7e0044165f012b")));
    /// ```
    pub fn means_the_same(&self, other: &Self) -> bool {
        match (view::meant(self), view::meant(other)) {
            (Ok(this), Ok(other)) => this == other,
            _ => self == other,
        }
    }

    /// This message as a tree: its `message-type` and its IEs by name, each
    /// with its value as [`Self::to_view`] reads it, or with its `octets`
    /// when it has no readable value.
    ///
    /// A tree is the compact form of a view. What the type of the message
    /// decides is left out (the extended protocol discriminator, and for a
    /// 5GMM message a plain security header type and a spare half octet of
    /// zero), and so are the optional IEs that the message does not have.
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
    /// [`Self::to_view`] has the octets of each IE beside its value, and
    /// [`Self::with_view`] keeps every octet that an edit does not change.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Nas5gsMessage;
    /// use serde_json::json;
    ///
    /// // 5GMM STATUS with cause #22.
    /// let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let tree = json!({"message-type": "5gmm-status", "5gmm-cause": "congestion"});
    /// assert_eq!(status.to_tree(), tree);
    /// assert_eq!(Nas5gsMessage::from_tree(tree).unwrap(), status);
    /// ```
    pub fn to_tree(&self) -> serde_json::Value {
        view::tree_of(self, &self.to_view(), &decided)
    }

    /// The message that a tree writes, as [`Self::to_tree`] shows one: its
    /// `message-type` names it, and each other member is an IE or a field of
    /// its header with its value, or `{"octets": "…"}` for the octets of an
    /// IE as they are sent. What the type of the message decides of its
    /// header is given where the tree leaves it out, and nothing else is:
    /// the tree is read as [`Self::from_view`] reads a view, so that a
    /// mandatory IE that it leaves out is an error.
    ///
    /// The `message-type` is the name of the type or its number. A field of
    /// the header that the type does not decide is written, as the
    /// `pdu-session-identity` and the `procedure-transaction-identity` of a
    /// 5GSM message.
    ///
    /// A tree with a `security-header` writes a message under that header:
    /// every field of the header is written, the code among them, and what
    /// else the tree has is the plain message, or `ciphered-message` alone
    /// with the `octets` of one that is ciphered.
    ///
    /// The message that comes back is one that [`Self::encode`] encodes. One
    /// is not: a plain message under a header that says it is ciphered,
    /// which is the message that a security context deciphered and has no
    /// octets before one ciphers it.
    pub fn from_tree(tree: serde_json::Value) -> Result<Self> {
        let (protection, tree) = view::protection_of(tree).map_err(NasError::EncodingError)?;
        let Some((header, ciphered)) = protection else {
            let view = view::from_tree(&tree, None, &decided).map_err(NasError::EncodingError)?;
            return Self::from_view(view);
        };
        let header: crate::nas_5gs::Nas5gsSecurityHeader =
            view::security_header(&header).map_err(NasError::EncodingError)?;
        let message = match ciphered {
            Some(octets) => Self::Opaque(octets),
            None => Self::from_tree(tree)?,
        };
        sendable(Self::SecurityProtected(header, Box::new(message)))
    }
}

impl Nas5gmmMessageType {
    /// The message of this type that a view describes alone.
    ///
    /// The view has every field of the header with its `value`, every
    /// mandatory IE and the optional IEs that the message has, each with
    /// its `value` or its `octets`. It is read as
    /// [`Nas5gsMessage::with_view`] reads one: nothing that it says is
    /// ignored, and a field of the header or a mandatory IE that it leaves
    /// out is an error, except the `spare-half-octet` of the header, which
    /// is then zero. A member that a `value` leaves out is zero. The
    /// message in a container is the view that is the `value` of the
    /// container, named by its `message-type`. The `message-type` of the
    /// view is this type, by its name or by its number, and another one is
    /// an error; its `security-header-type` is a name or the number of one.
    ///
    /// The message is what the view writes, and is one that
    /// [`Nas5gsMessage::encode`] encodes, as that of
    /// [`Nas5gsMessage::with_view`] is: a field of the header that the
    /// message is not sent with is an error, by the name of the field, and
    /// so is an IE that has no octets. An IE that is written by its `octets`
    /// has them whatever they are, where the encoding of the message has a
    /// place for them. A `value` writes its IE or is an error: one without
    /// any member, as `{}`, writes nothing of an IE.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Nas5gmmMessageType;
    /// use serde_json::json;
    ///
    /// let status = Nas5gmmMessageType::FiveGmmStatus
    ///     .from_view(json!({
    ///         "extended-protocol-discriminator": {"value": 126},
    ///         "security-header-type": {"value": "plain-5gs-nas-message-not-security-protected"},
    ///         "message-type": {"value": "5gmm-status"},
    ///         "5gmm-cause": {"value": "congestion"},
    ///     }))
    ///     .unwrap();
    /// assert_eq!(status.encode().unwrap(), [0x7e, 0x00, 0x64, 0x16]);
    /// ```
    pub fn from_view(self, view: serde_json::Value) -> Result<Nas5gsMessage> {
        let kind = format!("{self:?}");
        view::typed::<Nas5gsMessage>(&kind, &view)
            .and_then(|()| view::from_view(&["Gmm"], &kind, view))
            .map_err(NasError::EncodingError)
            .and_then(sendable)
    }

    /// The names of the entries that the view of a message of this type
    /// has: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn view_names(self) -> Vec<String> {
        view::names::<Nas5gmmHeader, Nas5gmmMessage>(&[&format!("{self:?}")])
    }

    /// The view of a message of this type that has nothing written yet,
    /// which [`Self::from_view`] fills: the fields of its header, each
    /// mandatory IE with the `octets` of one without content, and `null`
    /// for each optional IE. It says which entries a view has to write, and
    /// is not a message to send: a field is zero and an IE is empty. `None`
    /// for a type that the crate has no message of.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Nas5gmmMessageType;
    ///
    /// let blank = Nas5gmmMessageType::FiveGmmStatus.blank_view().unwrap();
    /// assert_eq!(blank["message-type"]["value"], "5gmm-status");
    /// assert_eq!(blank["5gmm-cause"]["octets"], "00");
    /// let accept = Nas5gmmMessageType::RegistrationAccept.blank_view().unwrap();
    /// assert!(accept["5gs-registration-result"].is_object());
    /// assert!(accept["5g-guti"].is_null());
    /// ```
    pub fn blank_view(self) -> Option<serde_json::Value> {
        view::blank_view::<Nas5gsMessage>(&["Gmm"], &format!("{self:?}"))
    }
}

impl Nas5gsmMessageType {
    /// The message of this type that a view describes alone, as
    /// [`Nas5gmmMessageType::from_view`] has it.
    pub fn from_view(self, view: serde_json::Value) -> Result<Nas5gsMessage> {
        let kind = format!("{self:?}");
        view::typed::<Nas5gsMessage>(&kind, &view)
            .and_then(|()| view::from_view(&["Gsm"], &kind, view))
            .map_err(NasError::EncodingError)
            .and_then(sendable)
    }

    /// The names of the entries that the view of a message of this type
    /// has: the fields of its header, then its IEs in the order of the
    /// message, with those that are optional. A type that the crate has no
    /// message of has none.
    pub fn view_names(self) -> Vec<String> {
        view::names::<Nas5gsmHeader, Nas5gsmMessage>(&[&format!("{self:?}")])
    }

    /// The view of a message of this type that has nothing written yet, as
    /// [`Nas5gmmMessageType::blank_view`] has it.
    pub fn blank_view(self) -> Option<serde_json::Value> {
        view::blank_view::<Nas5gsMessage>(&["Gsm"], &format!("{self:?}"))
    }
}

// ── Values ─────────────────────────────────────────────────────────────────
//
// Each is what the typed accessors of the IE return, and is encoded back
// by the matching constructor or setters.

use crate::common::ts24008::PcoDirection;
use crate::common::ts24301::KeySetIdentifier;
use crate::common::view::{
    Code, built_ie, code_ie, container_ie, decoded_ie, fields_ie, listed_ie, named_ie, numbers,
    octets, shared_ies, timer_ie, write_code,
};
use crate::common::{decode_labels, encode_labels, within};
use crate::nas_5gs::ie::*;
use crate::nas_5gs::types::*;
use core::net::{Ipv4Addr, Ipv6Addr};
use serde::{Deserialize, Serialize};

// The IEs that TS 24.501 and TS 24.301 have alike.
shared_ies!();

/// A payload container of the type "N1 SM information": a 5GSM message.
struct N1SmContainer<'a>(&'a NasPayloadContainer);

impl N1SmContainer<'_> {
    fn message(&self) -> Option<Nas5gsMessage> {
        let message = self.0.decode_as_n1_sm_message().ok()?;
        matches!(message, Nas5gsMessage::Gsm(..)).then_some(message)
    }

    /// The container of the message that stands for those that mean what
    /// the one it carries means.
    fn meant_container(&self) -> Option<NasPayloadContainer> {
        let _inside = view::Inside::enter()?;
        let meant = view::meant(&self.message()?).ok()?;
        NasPayloadContainer::from_n1_sm_message(&meant).ok()
    }
}

impl Ie for N1SmContainer<'_> {
    fn value(&self) -> Option<serde_json::Value> {
        let _inside = view::Inside::enter()?;
        Some(view::to_view(&self.message()?))
    }

    fn encoded(
        &self,
        value: &serde_json::Value,
    ) -> core::result::Result<(serde_json::Value, Option<serde_json::Value>), String> {
        let _inside = view::Inside::enter().ok_or(view::Inside::REFUSED)?;
        let message = match self.message() {
            Some(message) => view::with_view(&message, value.clone())?,
            // A container without octets carries what the view names.
            None if self.0.value.is_empty() => view::contained(value)?,
            None => return Err("the octets are not a 5GSM message: write them".into()),
        };
        let container =
            NasPayloadContainer::from_n1_sm_message(&message).map_err(view::unencoded)?;
        Ok((
            readable::to_value(&container)?,
            Some(view::to_view(&message)),
        ))
    }

    fn written_back(&self, value: &serde_json::Value) -> bool {
        // `value` is the view that the tree of the message writes: the
        // container that it writes alone carries a message that means what
        // this one means.
        let written = N1SmContainer(&NasPayloadContainer::blank()).encoded(value);
        let written = written
            .ok()
            .and_then(|(written, _)| readable::from_value::<NasPayloadContainer>(&written).ok());
        let meant = written.and_then(|written| N1SmContainer(&written).meant_container());
        meant.is_some() && meant == self.meant_container()
    }

    fn meant(&self) -> Option<serde_json::Value> {
        let meant = self.meant_container()?;
        (meant != *self.0).then(|| readable::to_value(&meant).ok())?
    }

    fn tree(&self, name: &str, decided: view::Decided<'_>) -> Option<serde_json::Value> {
        let _inside = view::Inside::enter()?;
        let message = self.message()?;
        Some(view::tree_in(
            &message,
            &view::to_view(&message),
            Some(name),
            decided,
        ))
    }
}

// The units of the protocol configuration options, by the direction of the
// message.

// A container of a plain NAS message: the view of the message.
container_ie!(
    NasMessageContainer: Nas5gsMessage,
    |ie| (ie.decode_plain_inner().ok())
        .filter(|message| matches!(message, Nas5gsMessage::Gmm(..))),
    |message| NasMessageContainer::from_plain_message(message)
);
container_ie!(
    NasEpsNasMessageContainer: crate::nas_eps::NasEpsMessage,
    |ie| ie.decode_as_eps_message().ok(),
    |message| NasEpsNasMessageContainer::from_eps_message(message)
);

// One coded value.
code_ie!(
    NasServiceType,
    ServiceType,
    |ie| ie.service_type_strict(),
    NasServiceType::from_service_type
);
code_ie!(
    NasFGmmCause,
    GmmCause,
    |ie| ie.cause(),
    NasFGmmCause::from_cause
);
code_ie!(
    NasFGsmCause,
    GsmCause,
    |ie| ie.cause(),
    NasFGsmCause::from_cause
);
// A type that no identity is asked for by is written as the code that it is
// read as, so that the refusal says what the IE would be.
/// The identity that an IDENTITY REQUEST asks for (TS 24.501 §9.11.3.3), by
/// its name.
#[derive(Clone, Copy, Serialize, Deserialize)]
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

impl IdentityTypeName {
    const ALL: [(Self, MobileIdentityType); 8] = [
        (Self::NoIdentity, MobileIdentityType::NoIdentity),
        (Self::Suci, MobileIdentityType::Suci),
        (Self::Guti, MobileIdentityType::Guti),
        (Self::Imei, MobileIdentityType::Imei),
        (Self::STmsi, MobileIdentityType::STmsi),
        (Self::Imeisv, MobileIdentityType::Imeisv),
        (Self::MacAddress, MobileIdentityType::MacAddress),
        (Self::Eui64, MobileIdentityType::Eui64),
    ];
}

code_ie!(
    NasFGsIdentityType,
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
        let identity = found.map_or(MobileIdentityType::Suci, |(_, kind)| *kind);
        NasFGsIdentityType::from_identity_type(identity)
            .unwrap_or(NasFGsIdentityType::new(MobileIdentityType::Suci as u8))
    }
);
code_ie!(
    NasPduSessionType,
    PduSessionTypeValue,
    |ie| ie.session_type(),
    NasPduSessionType::from_session_type
);
code_ie!(
    NasSscMode,
    SscModeValue,
    |ie| ie.mode(),
    NasSscMode::from_mode
);
code_ie!(
    NasAccessType,
    AccessTypeValue,
    |ie| ie.access_type(),
    NasAccessType::from_access_type
);
code_ie!(
    NasPayloadContainerType,
    PayloadContainerKind,
    |ie| ie.kind(),
    NasPayloadContainerType::from_kind
);
code_ie!(
    NasNssaiInclusionMode,
    NssaiInclusionModeValue,
    |ie| Some(ie.mode()),
    NasNssaiInclusionMode::from_mode
);
code_ie!(
    NasMaPduSessionInformation,
    MaPduSessionInfoValue,
    |ie| ie.info(),
    NasMaPduSessionInformation::from_info
);
// An identity that is assigned with the number of one that is not is written
// as that number, so that the refusal says what the IE would be.
code_ie!(
    NasProseRelayTransactionIdentity,
    ProseRelayTransactionIdentityValue,
    |ie| ie.identity(),
    |identity| NasProseRelayTransactionIdentity::new(match identity {
        ProseRelayTransactionIdentityValue::Unassigned => 0,
        ProseRelayTransactionIdentityValue::Assigned(number) => number,
        ProseRelayTransactionIdentityValue::Reserved => 0xff,
    })
);
named_ie!(
    NasFGsDrxParameters,
    DrxValue,
    |ie| ie.drx_value(),
    NasFGsDrxParameters::from_drx_value
);
named_ie!(
    NasNbN1ModeDrxParameters,
    NbN1DrxValue,
    |ie| ie.drx_value(),
    NasNbN1ModeDrxParameters::from_drx_value
);
named_ie!(NasRsn, RsnValue, |ie| ie.rsn(), NasRsn::from_rsn);
named_ie!(
    NasFGsAdditionalRequestResult,
    PagingRestrictionDecision,
    |ie| ie.prd(),
    NasFGsAdditionalRequestResult::from_prd
);
named_ie!(
    NasEthernetHeaderCompressionConfiguration,
    EthHdrCompCidLen,
    |ie| ie.cid_length(),
    NasEthernetHeaderCompressionConfiguration::from_cid_length
);

// The fields of an octet.
fields_ie!(NasFGsRegistrationType {
"registration-type":
    |ie| Code::of(RegistrationType::from_u8_strict(ie.value & 0x07), ie.value & 0x07),
    |ie, code: Code<RegistrationType>| write_code(
        ie,
        code,
        |ie, name| {
            ie.set_registration_type(name);
        },
        |ie| ie.value & 0x07,
    );
"follow-on-request": |ie| ie.follow_on_request(), |ie, on: bool| ie.set_follow_on_request(on);
});
fields_ie!(NasDeRegistrationType {
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
fields_ie!(NasFGsUpdateType {
    "sms-requested": |ie| ie.sms_requested(), |ie, on: bool| ie.set_sms_requested(on);
    "ng-ran-rcu": |ie| ie.ng_ran_rcu(), |ie, on: bool| ie.set_ng_ran_rcu(on);
    "pnb-ciot": |ie| ie.pnb_ciot(), |ie, value: u8| ie.set_pnb_ciot(value).map(|_| ());
    "eps-pnb-ciot":
        |ie| ie.eps_pnb_ciot(),
        |ie, value: u8| ie.set_eps_pnb_ciot(value).map(|_| ());
});
fields_ie!(NasFGsRegistrationResult {
    "result":
        |ie| Code::of(
            RegistrationResult::from_u8_strict(ie.result_value_raw()),
            ie.result_value_raw(),
        ),
        |ie, code: Code<RegistrationResult>| write_code(
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
fields_ie!(NasControlPlaneServiceType {
"service-type":
    |ie| Code::of(
        ControlPlaneServiceTypeValue::from_u8_strict(ie.service_type_raw()),
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
fields_ie!(NasSecurityAlgorithms {
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
fields_ie!(NasEpsNasSecurityAlgorithms {
    "ciphering":
        |ie| Code::of(ie.ciphering(), ie.ciphering_raw()),
        |ie, code: Code<crate::common::ts24301::CipheringAlgorithm>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_ciphering(name);
            },
            |ie| ie.ciphering_raw(),
        );
    "integrity":
        |ie| Code::of(ie.integrity(), ie.integrity_raw()),
        |ie, code: Code<crate::common::ts24301::IntegrityAlgorithm>| write_code(
            ie,
            code,
            |ie, name| {
                ie.set_integrity(name);
            },
            |ie| ie.integrity_raw(),
        );
});

// The flags of an indication, by the names of its accessors.
built_ie!(
    NasAdditional5gSecurityInformation,
    |rinmr, hdp| Ok(Self::from_flags(rinmr, hdp)),
    { rinmr: bool, hdp: bool }
);
built_ie!(
    NasAdditionalConfigurationIndication,
    |scmr| Ok(Self::from_scmr(scmr)),
    { scmr: bool }
);
built_ie!(
    NasAdditionalInformationRequested,
    |requested| Ok(Self::from_cipher_key_data_requested(requested)),
    { cipher_key_data_requested: bool }
);
built_ie!(
    NasAllowedSscMode,
    |ssc1, ssc2, ssc3| Ok(Self::from_modes(ssc1, ssc2, ssc3)),
    { ssc1: bool, ssc2: bool, ssc3: bool }
);
built_ie!(NasAlwaysOnPduSessionIndication, |apsi| Ok(Self::from_apsi(apsi)), { apsi: bool });
built_ie!(NasAlwaysOnPduSessionRequested, |apsr| Ok(Self::from_apsr(apsr)), { apsr: bool });
built_ie!(NasAun3Indication, |aun3reg| Ok(Self::from_aun3reg(aun3reg)), { aun3reg: bool });
built_ie!(
    NasConfigurationUpdateIndication,
    |ack, red| Ok(Self::from_flags(ack, red)),
    { ack: bool, red: bool }
);
built_ie!(NasControlPlaneOnlyIndication, Self::from_cpoi, { cpoi: bool });
built_ie!(
    NasExtendedFGmmCause,
    |not_allowed| Ok(Self::from_satellite_nr_not_allowed(not_allowed)),
    { satellite_nr_not_allowed: bool }
);
built_ie!(
    NasFGsmCongestionReAttemptIndicator,
    |abo, catbo| Ok(Self::from_flags(abo, catbo)),
    { abo: bool, catbo: bool }
);
built_ie!(
    NasFGsmNetworkFeatureSupport,
    |ept_s1, naps| Ok(Self::from_flags(ept_s1, naps)),
    { ept_s1: bool, naps: bool }
);
built_ie!(
    NasFeatureAuthorizationIndication,
    |hpase, mbsrai| Ok(Self::from_flags(hpase, mbsrai)),
    { hpase: bool, mbsrai: FeatureAuthMbsraiValue = |ie| ie.mbsrai() }
);
built_ie!(NasLpWusStatus, |disabled| Ok(Self::from_disabled(disabled)), {
    lp_wus_disabled: bool
});
built_ie!(
    NasMicoIndication,
    |raai, sprti| Ok(Self::from_flags(raai, sprti)),
    { raai: bool, sprti: bool }
);
built_ie!(NasN5gcIndication, |n5gc| Ok(Self::from_n5gc(n5gc)), { n5gc: bool });
built_ie!(
    NasNetworkSlicingIndication,
    |nssci, dcni| Ok(Self::from_flags(nssci, dcni)),
    { nssci: bool, dcni: bool }
);
built_ie!(
    NasNon3GppAccessPathSwitchingIndication,
    |naps| Ok(Self::from_naps(naps)),
    { naps: bool }
);
built_ie!(
    NasNon3GppPathSwitchingInformation,
    |nsonr| Ok(Self::from_nsonr(nsonr)),
    { nsonr: bool }
);
built_ie!(NasPayloadContainerInformation, |pru| Ok(Self::from_pru(pru)), { pru: bool });
built_ie!(
    NasPriorityIndicator,
    |mpsi, mcsi| Ok(Self::from_flags(mpsi, mcsi)),
    { mpsi: bool, mcsi: bool }
);
built_ie!(
    NasRanTimingSynchronization,
    |request| Ok(Self::from_recreation_request(request)),
    { recreation_request: bool }
);
built_ie!(NasSmsIndication, |sai| Ok(Self::from_sai(sai)), { sai: bool });
built_ie!(
    NasUeUsageSetting,
    |data_centric| Ok(Self::from_data_centric(data_centric)),
    { data_centric: bool }
);
built_ie!(NasTruncatedFGSTmsiConfiguration, Self::try_from_lengths, {
    truncated_amf_set_id_length: u8 = |ie| ie.truncated_amf_set_id_length(),
    truncated_amf_pointer_length: u8 = |ie| ie.truncated_amf_pointer_length(),
});
built_ie!(
    NasAun3DeviceSecurityKey,
    |askt, key: Vec<u8>| Self::from_typed(askt, &key),
    {
        askt: Aun3DeviceSecurityKeyType = |ie| ie.askt(),
        key: Vec<u8> = |ie| ie.key().map(<[u8]>::to_vec),
    }
);

// The parts of an IE that its constructor takes.
built_ie!(
    NasIpHeaderCompressionConfiguration,
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
    NasPagingRestriction,
    |restriction_type, psis: Vec<u16>| Self::from_restriction_type_with_unrestricted_psis(
        restriction_type,
        &octets("psi", &psis, 1, 15)?
    ),
    {
        restriction_type: PagingRestrictionType =
            |ie| ie.restriction_type().filter(|_| ie.is_well_formed()),
        unrestricted_psi_list: Vec<u16> = |ie| Some(numbers(&ie.unrestricted_psi_list())),
    }
);
built_ie!(
    NasTnanInformation,
    |tngf_id: Option<Vec<u8>>, ssid: Option<String>| {
        Self::new(Vec::new())
            .with_tngf_id(tngf_id.as_deref())?
            .with_ssid(ssid.as_ref().map(String::as_bytes))
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
#[derive(Serialize, Deserialize)]
enum LpWuspsAssistance {
    PagingSubgroupId(u8),
    UePagingProbabilityInformation(u8),
}

decoded_ie!(
    NasLpWuspsAssistanceInformation: LpWuspsAssistance,
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
    NasUeDsTtResidenceTime: i64,
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
#[derive(Serialize, Deserialize)]
enum MobileIdentity {
    NoIdentity,
    Suci(SuciForm),
    Guti(GutiForm),
    Imei(String),
    STmsi(STmsiForm),
    Imeisv(String),
    MacAddress { address: [u8; 6], mauri: bool },
    Eui64([u8; 8]),
}

/// A 5G-GUTI by its parts, as a view writes it.
#[derive(Serialize, Deserialize)]
struct GutiForm {
    #[serde(with = "crate::common::plmn_text")]
    plmn: Plmn,
    amf_region_id: u8,
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
}

/// A 5G-S-TMSI by its parts, as a view writes it.
#[derive(Serialize, Deserialize)]
struct STmsiForm {
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
}

/// The protection scheme of a SUCI by its name (TS 33.501 Annex C.1), or the
/// identifier of a scheme of the operator.
#[derive(Clone, Copy, Serialize, Deserialize)]
enum SchemeName {
    Null,
    ProfileA,
    ProfileB,
}

/// A SUCI with its digits: the MSIN of the null scheme, else the output of
/// the protection scheme; or the text of a NAI.
#[derive(Serialize, Deserialize)]
enum SuciForm {
    Imsi {
        #[serde(with = "crate::common::plmn_text")]
        plmn: Plmn,
        routing_indicator: String,
        protection_scheme: view::Code<SchemeName>,
        home_network_public_key_id: u8,
        msin: Option<String>,
        scheme_output: Option<Vec<u8>>,
    },
    Nai(String),
}

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
    NasFGsMobileIdentity: MobileIdentity,
    |ie| Some(match ie.identity_type()? {
        MobileIdentityType::NoIdentity => MobileIdentity::NoIdentity,
        MobileIdentityType::Suci => MobileIdentity::Suci(SuciForm::of(ie.as_suci()?)),
        MobileIdentityType::Guti => {
            let guti = ie.as_guti()?;
            MobileIdentity::Guti(GutiForm {
                plmn: guti.plmn(),
                amf_region_id: guti.amf_region_id(),
                amf_set_id: guti.amf_set_id(),
                amf_pointer: guti.amf_pointer(),
                tmsi: guti.tmsi(),
            })
        }
        MobileIdentityType::Imei => MobileIdentity::Imei(ie.as_imei()?.to_string()),
        MobileIdentityType::STmsi => {
            let s_tmsi = ie.as_s_tmsi()?;
            MobileIdentity::STmsi(STmsiForm {
                amf_set_id: s_tmsi.amf_set_id(),
                amf_pointer: s_tmsi.amf_pointer(),
                tmsi: s_tmsi.tmsi(),
            })
        }
        MobileIdentityType::Imeisv => MobileIdentity::Imeisv(ie.as_imeisv()?.to_string()),
        MobileIdentityType::MacAddress => MobileIdentity::MacAddress {
            address: ie.as_mac_address()?,
            mauri: ie.mauri()?,
        },
        MobileIdentityType::Eui64 => MobileIdentity::Eui64(ie.as_eui64()?),
        _ => return None,
    }),
    |_, identity| match identity {
        MobileIdentity::NoIdentity => Ok(NasFGsMobileIdentity::from_no_identity()),
        MobileIdentity::Suci(suci) => NasFGsMobileIdentity::from_suci(&suci.suci()?),
        MobileIdentity::Guti(guti) => {
            let GutiForm {
                plmn,
                amf_region_id,
                amf_set_id,
                amf_pointer,
                tmsi,
            } = guti;
            let guti = Guti::new(plmn, amf_region_id, amf_set_id, amf_pointer, tmsi)?;
            Ok(NasFGsMobileIdentity::from_guti(guti))
        }
        MobileIdentity::Imei(imei) => NasFGsMobileIdentity::from_imei(&imei),
        MobileIdentity::STmsi(s_tmsi) => {
            let s_tmsi = STmsi::new(s_tmsi.amf_set_id, s_tmsi.amf_pointer, s_tmsi.tmsi)?;
            Ok(NasFGsMobileIdentity::from_s_tmsi(s_tmsi))
        }
        MobileIdentity::Imeisv(imeisv) => NasFGsMobileIdentity::from_imeisv(&imeisv),
        MobileIdentity::MacAddress { address, mauri } => {
            Ok(NasFGsMobileIdentity::from_mac_address_with_mauri(address, mauri))
        }
        MobileIdentity::Eui64(eui64) => Ok(NasFGsMobileIdentity::from_eui64(eui64)),
    }
);
decoded_ie!(
    NasDsTtEthernetPortMacAddress: [u8; 6],
    |ie| ie.mac_address(),
    |_, address| Ok(NasDsTtEthernetPortMacAddress::from_mac_address(address))
);

/// The algorithms a UE security capability has the bits of, by number.
#[derive(Serialize, Deserialize)]
struct SecurityCapability {
    ea: Vec<u16>,
    ia: Vec<u16>,
    eea: Option<Vec<u16>>,
    eia: Option<Vec<u16>>,
}

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
    NasUeSecurityCapability: SecurityCapability,
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
            (None, None) => NasUeSecurityCapability::from_capabilities(ea, ia),
            (eea, eia) => NasUeSecurityCapability::from_capabilities_extended(
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
) -> core::result::Result<Vec<NasSNssai>, ValueError> {
    (contents.enumerate())
        .map(|(entry, contents)| contents.to_snssai().map_err(|error| error.at(entry)))
        .collect()
}

// Slices, tracking areas and PLMNs.
decoded_ie!(NasSNssai: SNssaiContents, |ie| ie.parse(), |_, contents| contents.to_snssai());
decoded_ie!(
    NasNssai: Vec<SNssaiContents>,
    |ie| ie.try_parse_all(),
    |_, contents| NasNssai::from_snssais(&snssais(contents.iter())?)
);
decoded_ie!(
    NasMappedNssai: Vec<SNssaiContents>,
    |ie| ie.try_parse_all(),
    |_, contents| NasMappedNssai::from_snssais(&snssais(contents.iter())?)
);

/// A rejected S-NSSAI and the cause of its rejection.
#[derive(Serialize, Deserialize)]
struct RejectedSNssai {
    cause: RejectedNssaiCause,
    s_nssai: SNssaiContents,
}

decoded_ie!(
    NasRejectedNssai: Vec<RejectedSNssai>,
    |ie| ie.receiver_syntax_is_valid().then(|| {
        (ie.entries().into_iter())
            .map(|(cause, s_nssai)| RejectedSNssai { cause, s_nssai })
            .collect()
    }),
    |_, rejected| {
        let snssais = snssais(rejected.iter().map(|one| &one.s_nssai))?;
        let entries: Vec<_> = rejected.iter().map(|one| one.cause).zip(&snssais).collect();
        NasRejectedNssai::from_entries(&entries)
    }
);
decoded_ie!(
    NasFGsTrackingAreaIdentity: view::TaiForm<Tai>,
    |ie| ie.parse().map(view::TaiForm),
    |_, tai| NasFGsTrackingAreaIdentity::from_plmn_tac(&tai.0.plmn(), tac_octets(&tai.0))
);
decoded_ie!(
    NasFGsTrackingAreaIdentityList: Vec<TaiListEntry>,
    |ie| ie.receiver_syntax_is_valid().then(|| ie.parse()),
    |_, entries| NasFGsTrackingAreaIdentityList::from_entries(&entries)
);
decoded_ie!(
    NasLadnIndication: Vec<String>,
    |ie| ie.dnn_values().iter().map(|dnn| decode_labels(dnn)).collect(),
    |_, dnns| {
        let dnns: core::result::Result<Vec<_>, _> = (dnns.iter().enumerate())
            .map(|(entry, dnn)| encode_labels("dnn", dnn, 100).map_err(|error| error.at(entry)))
            .collect();
        NasLadnIndication::from_dnn_values(&dnns?)
    }
);

// Timers, names and numbers.
timer_ie!(NasT3512Value);
decoded_ie!(NasDnn: String, |ie| ie.as_string(), |_, name| NasDnn::from_string(&name));
decoded_ie!(NasNid: String, |ie| Some(ie.nid_value()), |_, nid| NasNid::from_nid_value(&nid));
decoded_ie!(
    NasSmPduDnRequestContainer: String,
    |ie| ie.as_utf8_str().map(str::to_string),
    |_, text| Ok(NasSmPduDnRequestContainer::from_str(&text))
);

decoded_ie!(
    NasPduSessionIdentity2: u8,
    |ie| Some(ie.pdu_session_id()),
    |_, identity| Ok(NasPduSessionIdentity2::from_pdu_session_id(identity))
);
decoded_ie!(
    NasPduSessionPairId: u8,
    |ie| ie.pair_id(),
    |_, identity| Ok(NasPduSessionPairId::from_pair_id(identity))
);
decoded_ie!(
    NasMaximumNumberOfSupportedPacketFilters: u16,
    |ie| ie.is_well_formed().then(|| ie.max_filters()),
    |_, filters| NasMaximumNumberOfSupportedPacketFilters::from_max_filters(filters)
);
decoded_ie!(
    NasN1ModeToS1ModeNasTransparentContainer: u8,
    |ie| Some(ie.sequence_number()),
    |_, number| Ok(NasN1ModeToS1ModeNasTransparentContainer::from_sequence_number(number))
);
decoded_ie!(
    NasTimeDuration: u32,
    |ie| ie.seconds(),
    |_, seconds| NasTimeDuration::from_seconds(seconds)
);
decoded_ie!(
    NasEcnMarkingL4sIndication: Vec<u16>,
    |ie| Some(numbers(ie.qri_values())),
    |_, qris| NasEcnMarkingL4sIndication::try_from_qri_values(&octets("qri", &qris, 1, 255)?)
);

/// The PDU session identities that a status has the bits of: 1 to 15.
fn psis(sessions: &[u16]) -> core::result::Result<Vec<u8>, ValueError> {
    octets("pdu-session-identity", sessions, 1, 15)
}

// Sessions: the identities a status has the bits of, and what a session has.
decoded_ie!(
    NasPduSessionStatus: Vec<u16>,
    |ie| Some(numbers(&ie.active_sessions())),
    |_, sessions| NasPduSessionStatus::from_sessions(&psis(&sessions)?)
);
decoded_ie!(
    NasUplinkDataStatus: Vec<u16>,
    |ie| Some(numbers(&ie.sessions_with_data())),
    |_, sessions| NasUplinkDataStatus::from_sessions(&psis(&sessions)?)
);
decoded_ie!(
    NasAllowedPduSessionStatus: Vec<u16>,
    |ie| Some(numbers(&ie.allowed_sessions())),
    |_, sessions| NasAllowedPduSessionStatus::from_sessions(&psis(&sessions)?)
);
decoded_ie!(
    NasPduSessionReactivationResult: Vec<u16>,
    |ie| Some(numbers(&ie.failed_sessions())),
    |_, sessions| NasPduSessionReactivationResult::from_failed_sessions(&psis(&sessions)?)
);
decoded_ie!(
    NasSessionAmbr: SessionAmbrValue,
    |ie| ie.parse(),
    |_, ambr| NasSessionAmbr::from_kbps(ambr.dl_kbps, ambr.ul_kbps),
    // The two rates are all that a session AMBR with units of the table
    // means: the unit that counts each of them says no more.
    meant: |ie| ie.is_well_formed()
);

/// The addresses of a PDU address, by the PDU session type that has them.
#[derive(Serialize, Deserialize)]
struct PduAddress {
    ipv4: Option<Ipv4Addr>,
    ipv6_interface_id: Option<[u8; 8]>,
    smf_ipv6_link_local_address: Option<Ipv6Addr>,
}

decoded_ie!(
    NasPduAddress: PduAddress,
    |ie| ie.receiver_syntax_is_valid().then(|| PduAddress {
        ipv4: ie.ipv4().map(Ipv4Addr::from),
        ipv6_interface_id: ie.ipv6_interface_id().and_then(|id| id.try_into().ok()),
        smf_ipv6_link_local_address: ie.smf_ipv6_link_local_address().map(Ipv6Addr::from),
    }),
    |_, address| {
        let ipv4 = address.ipv4.map(|ipv4| ipv4.octets());
        let smf = address.smf_ipv6_link_local_address.map(|smf| smf.octets());
        Ok(match (ipv4, address.ipv6_interface_id, smf) {
            (Some(ipv4), None, None) => NasPduAddress::from_ipv4(ipv4),
            (None, Some(id), None) => NasPduAddress::from_ipv6_iid(id),
            (Some(ipv4), Some(id), None) => NasPduAddress::from_ipv4v6(id, ipv4),
            (Some(ipv4), None, Some(smf)) => {
                NasPduAddress::from_ipv4_with_smf_ipv6_link_local_address(ipv4, smf)
            }
            (None, Some(id), Some(smf)) => {
                NasPduAddress::from_ipv6_iid_with_smf_ipv6_link_local_address(id, smf)
            }
            (Some(ipv4), Some(id), Some(smf)) => {
                NasPduAddress::from_ipv4v6_with_smf_ipv6_link_local_address(id, ipv4, smf)
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
#[derive(Serialize, Deserialize)]
struct MaximumDataRates {
    ul: MaxDataRate,
    dl: MaxDataRate,
}

decoded_ie!(
    NasIntegrityProtectionMaximumDataRate: MaximumDataRates,
    |ie| Some(MaximumDataRates {
        ul: MaxDataRate::from_u8_strict(ie.ul_raw())?,
        dl: MaxDataRate::from_u8_strict(ie.dl_raw())?,
    }),
    |_, rates| Ok(NasIntegrityProtectionMaximumDataRate::from_rates(rates.ul, rates.dl))
);
decoded_ie!(
    NasQosRules: Vec<QosRule>,
    |ie| ie.validate_strict().is_ok().then(|| ie.rules()),
    |_, rules| NasQosRules::from_rules(&rules)
);
decoded_ie!(
    NasQosFlowDescriptions: Vec<QosFlowDescription>,
    |ie| ie.try_descriptions(),
    |_, descriptions| NasQosFlowDescriptions::from_descriptions(&descriptions)
);

// Capabilities: every flag by its name, and the algorithms by number.
fields_ie!(NasFGmmCapability {} flags);
crate::common::nas_ie_flags!(@named NasFGsNetworkFeatureSupport {
    ims_vops_3gpp ims_vops_n3gpp iwk_n26 mpsi emcn3 mcsi cp_ciot n3_data iphc_cp_ciot up_ciot
    lcs_5g ats_ind ehc_cp_ciot ncr piv rpr pr un_per naps lcs_upp supl rslp mlcsup ef5l
});
fields_ie!(NasFGsNetworkFeatureSupport {
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
crate::common::nas_ie_flags!(@named NasFGsmCapability {
    tpmic ept_s1 mh6_pdu rqos mpquic_ip mpquic_udp mptcp rtpmmii sdnaepc apmqf e8pcpdei mpquic_e
});
fields_ie!(NasFGsmCapability {
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
fields_ie!(NasS1UeNetworkCapability {
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
fields_ie!(NasS1UeSecurityCapability {
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
    NasNsagInformation: Vec<NsagInfoEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasNsagInformation::from_entries(&entries)
);
decoded_ie!(
    NasNssrgInformation: Vec<NssrgInfoEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasNssrgInformation::from_entries(&entries)
);
decoded_ie!(
    NasLadnInformation: Vec<LadnInfoEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasLadnInformation::from_entries(&entries)
);
decoded_ie!(
    NasCagInformationList: Vec<CagInformationEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasCagInformationList::from_entries(&entries)
);
decoded_ie!(
    NasExtendedCagInformationList: Vec<CagInformationEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasExtendedCagInformationList::from_entries(&entries)
);
decoded_ie!(
    NasServiceAreaList: Vec<ServiceAreaListEntry>,
    |ie| ie.receiver_syntax_is_valid().then(|| ie.entries()),
    |_, entries| NasServiceAreaList::from_entries(&entries)
);
decoded_ie!(
    NasExtendedRejectedNssai: Vec<ExtendedRejectedNssaiPartialList>,
    |ie| ie.is_well_formed().then(|| ie.partial_lists()),
    |_, lists| NasExtendedRejectedNssai::from_partial_lists(&lists)
);
decoded_ie!(
    NasOperatorDefinedAccessCategoryDefinitions: Vec<OperatorAccessCategoryDefinition>,
    |ie| ie.try_definitions(),
    |_, definitions| NasOperatorDefinedAccessCategoryDefinitions::from_definitions(&definitions)
);
decoded_ie!(
    NasPduSessionReactivationResultErrorCause: Vec<(u8, GmmCause)>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasPduSessionReactivationResultErrorCause::from_entries(&entries)
);
decoded_ie!(
    NasMappedEpsBearerContexts: Vec<MappedEpsBearerContext>,
    |ie| ie.try_contexts(),
    |_, contexts| NasMappedEpsBearerContexts::from_contexts(&contexts)
);
decoded_ie!(
    NasReceivedMbsContainer: Vec<ReceivedMbsSession>,
    |ie| ie.try_sessions(),
    |_, sessions| NasReceivedMbsContainer::try_from_sessions(&sessions)
);
decoded_ie!(
    NasRequestedMbsContainer: Vec<RequestedMbsSession>,
    |ie| ie.try_sessions(),
    |_, sessions| NasRequestedMbsContainer::try_from_sessions(&sessions)
);
decoded_ie!(
    NasSorTransparentContainer: SorTransparentContainerContents,
    |ie| ie.parse(),
    |_, contents| match contents {
        SorTransparentContainerContents::Acknowledgement {
            mssi,
            mssnpnsi,
            msssnpnsils,
            sor_mac_iue,
        } => Ok(NasSorTransparentContainer::from_ack(
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
        } => NasSorTransparentContainer::from_information(
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
    NasUeParametersUpdateTransparentContainer: UeParametersUpdateTransparentContainerContents,
    |ie| ie.parse(),
    |_, contents| NasUeParametersUpdateTransparentContainer::from_parsed(&contents)
);
decoded_ie!(
    NasCiotSmallDataContainer: CiotSmallDataContainerContents,
    |ie| ie.parse(),
    |_, contents| NasCiotSmallDataContainer::from_parsed(&contents)
);
decoded_ie!(
    NasN3Qai: Vec<N3QaiEntry>,
    |ie| ie.try_entries(),
    |_, entries| NasN3Qai::from_entries(&entries)
);
decoded_ie!(
    NasProtocolDescription: Vec<ProtocolDescriptionEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasProtocolDescription::from_entries(&entries)
);
decoded_ie!(
    NasType6IeContainer: Vec<Type6IeContainerEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasType6IeContainer::from_entries(&entries)
);
decoded_ie!(
    NasSNssaiLocationValidityInformation: Vec<SNssaiLocationValidityEntry>,
    |ie| ie.is_well_formed().then(|| ie.entries()),
    |_, entries| NasSNssaiLocationValidityInformation::from_entries(&entries)
);
decoded_ie!(
    NasRelayKeyRequestParameters: RelayKeyRequestParameters,
    |ie| ie.parse(),
    |_, parameters| NasRelayKeyRequestParameters::from_parsed(&parameters)
);
decoded_ie!(
    NasRelayKeyResponseParameters: RelayKeyResponseParameters,
    |ie| ie.parse(),
    |_, parameters| NasRelayKeyResponseParameters::from_parsed(&parameters)
);
decoded_ie!(
    NasServiceLevelAaContainer: Vec<ServiceLevelAaParameter>,
    |ie| ie.try_parameters().ok(),
    |_, parameters| NasServiceLevelAaContainer::from_parameters(&parameters)
);
decoded_ie!(
    NasN3iwfIdentifier: N3iwfAddress,
    |ie| ie.address(),
    |_, address| Ok(NasN3iwfIdentifier::from_address(&address))
);
// Lists that had octets alone and that their constructors build.
listed_ie!(
    NasPeipsAssistanceInformation: PeipsAssistanceInformationEntry,
    entries,
    Self::from_entries
);
listed_ie!(NasSnpnList: SnpnListEntry, entries, |entries| {
    Ok(Self::from_entries(entries))
});
listed_ie!(NasAlternativeNssai: AlternativeNssaiEntry, entries, |entries| {
    Self::from_entries(entries)
});
listed_ie!(NasOnDemandNssai: OnDemandNssaiEntry, entries, |entries| {
    Self::from_entries(entries)
});
listed_ie!(NasPartialNssai: PartialNssaiEntry, entries, |entries| {
    Self::from_entries(entries)
});
listed_ie!(NasExtendedLadnInformation: ExtendedLadnInformationEntry, entries, Self::from_entries);
listed_ie!(NasNon3GppDelayBudget: Non3GppDelayBudgetEntry, entries, Self::from_entries);
listed_ie!(NasRemoteUeContextList: RemoteUeContext, contexts, Self::from_contexts);
listed_ie!(
    NasSNssaiTimeValidityInformation: SNssaiTimeValidityEntry,
    entries,
    Self::from_entries
);
listed_ie!(NasUrspRuleEnforcementReports: UrspRuleEnforcementReport, reports, Self::from_reports);
listed_ie!(NasCipheringKeyData: CipheringDataSet, data_sets, Self::from_data_sets);

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
                    built_from_nothing(<$ie>::blank());
                    for octet in 0..=255_u8 {
                        // The digits of a time are decimal.
                        let decimal = octet & 0x0f <= 9 && octet >> 4 <= 9;
                        if !decimal && stringify!($ie).contains("Time") {
                            continue;
                        }
                        let mut ie = <$ie>::blank();
                        ie.value = Octet::of(octet);
                        built_from_value(<$ie>::blank(), ie);
                    }
                )+
                [$(stringify!($ie)),+].len()
            }};
        }
        let built = each!(
            NasFGsRegistrationType,
            NasDeRegistrationType,
            NasFGsUpdateType,
            NasFGsRegistrationResult,
            NasControlPlaneServiceType,
            NasSecurityAlgorithms,
            NasEpsNasSecurityAlgorithms,
            NasTimeZoneAndTime,
            NasFGmmCapability,
            NasFGsNetworkFeatureSupport,
            NasFGsmCapability,
            NasS1UeNetworkCapability,
            NasS1UeSecurityCapability,
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
            sweep(NasIpHeaderCompressionConfiguration::new(vec![value; 3]));
            sweep(NasIpHeaderCompressionConfiguration::new(vec![
                value & 0x7f,
                0,
                value,
                value & 7,
                value,
            ]));
            sweep(NasPagingRestriction::new(vec![value & 0x0f]));
            sweep(NasPagingRestriction::new(vec![3, value & 0xfe, value]));
            sweep(NasTnanInformation::new(vec![value & 3, 1, value, 1, 0x41]));
            sweep(NasLpWuspsAssistanceInformation::new(vec![value]));
            sweep(NasUeDsTtResidenceTime::new(vec![value; 8]));
            sweep(NasFGmmCause::new(value));
            sweep(NasFGsmCause::new(value));
            sweep(NasFGsIdentityType::new(value));
            sweep(NasPduSessionType::new(value));
            sweep(NasSscMode::new(value));
            sweep(NasRequestType::new(value));
            sweep(NasAccessType::new(value));
            sweep(NasPayloadContainerType::new(value));
            sweep(NasNssaiInclusionMode::new(value));
            sweep(NasProseRelayTransactionIdentity::new(value));
            sweep(NasFGsRegistrationType::new(value));
            sweep(NasDeRegistrationType::new(value));
            sweep(NasControlPlaneServiceType::new(value));
            sweep(NasSecurityAlgorithms::new(value));
            sweep(NasEpsNasSecurityAlgorithms::new(value));
            sweep(NasKeySetIdentifier::new(value));
            sweep(NasGprsTimer::new(value));
            sweep(NasGprsTimer2::new(vec![value]));
            sweep(NasGprsTimer3::new(vec![value]));
            sweep(NasFGsUpdateType::new(vec![value]));
            sweep(NasFGsRegistrationResult::new(vec![value]));
            sweep(NasFGmmCapability::new(vec![value]));
            sweep(NasFGmmCapability::new(vec![value; 13]));
            sweep(NasFGsmCapability::new(vec![value]));
            sweep(NasFGsmCapability::new(vec![value; 3]));
            sweep(NasFGsNetworkFeatureSupport::new(vec![value]));
            sweep(NasFGsNetworkFeatureSupport::new(vec![value; 4]));
            sweep(NasS1UeNetworkCapability::new(vec![value; 2]));
            sweep(NasS1UeNetworkCapability::new(vec![value; 9]));
            sweep(NasS1UeSecurityCapability::new(vec![value; 5]));
            sweep(NasUeSecurityCapability::new(vec![value; 2]));
            sweep(NasUeSecurityCapability::new(vec![value; 4]));
            sweep(NasPduSessionStatus::new(vec![value; 2]));
            sweep(NasUplinkDataStatus::new(vec![value; 2]));
            sweep(NasAllowedPduSessionStatus::new(vec![value; 2]));
            sweep(NasPduSessionReactivationResult::new(vec![value; 2]));
            sweep(NasEpsBearerContextStatus::new(vec![value & 0xfe, value]));
            sweep(NasUeStatus::new(vec![value]));
            sweep(NasReAttemptIndicator::new(vec![value]));
            sweep(NasExtendedDrxParameters::new(vec![value]));
            sweep(NasTimeZoneAndTime::new(vec![value & 0x11; 7]));
            sweep(NasAdditional5gSecurityInformation::new(vec![value]));
            sweep(NasAdditionalConfigurationIndication::new(value & 0x0f));
            sweep(NasAdditionalInformationRequested::new(vec![value]));
            sweep(NasAllowedSscMode::new(value & 0x0f));
            sweep(NasAlwaysOnPduSessionIndication::new(value & 0x0f));
            sweep(NasAlwaysOnPduSessionRequested::new(value & 0x0f));
            sweep(NasAun3Indication::new(vec![value]));
            sweep(NasConfigurationUpdateIndication::new(value & 0x0f));
            sweep(NasControlPlaneOnlyIndication::new(value & 0x0f));
            sweep(NasExtendedFGmmCause::new(vec![value]));
            sweep(NasFGsmCongestionReAttemptIndicator::new(vec![value]));
            sweep(NasFGsmNetworkFeatureSupport::new(vec![value]));
            sweep(NasFeatureAuthorizationIndication::new(vec![value]));
            sweep(NasLpWusStatus::new(value & 0x0f));
            sweep(NasMicoIndication::new(value & 0x0f));
            sweep(NasN5gcIndication::new(value & 0x0f));
            sweep(NasNetworkSlicingIndication::new(value & 0x0f));
            sweep(NasNon3GppAccessPathSwitchingIndication::new(vec![value]));
            sweep(NasNon3GppPathSwitchingInformation::new(vec![value]));
            sweep(NasPayloadContainerInformation::new(value & 0x0f));
            sweep(NasPriorityIndicator::new(value & 0x0f));
            sweep(NasRanTimingSynchronization::new(vec![value]));
            sweep(NasSmsIndication::new(value & 0x0f));
            sweep(NasUeUsageSetting::new(vec![value]));
            sweep(NasTruncatedFGSTmsiConfiguration::new(vec![value]));
            sweep(NasRegistrationWaitRange::new(vec![value, value]));
            sweep(NasAun3DeviceSecurityKey::new(vec![
                value & 1,
                2,
                0xaa,
                0xbb,
            ]));
            sweep(NasPduSessionIdentity2::new(value));
            sweep(NasPduSessionPairId::new(vec![value]));
            sweep(NasMaximumNumberOfSupportedPacketFilters::new(vec![
                value,
                value & 0xe0,
            ]));
            sweep(NasN1ModeToS1ModeNasTransparentContainer::new(value));
            sweep(NasTimeDuration::new(vec![value, value]));
            sweep(NasEcnMarkingL4sIndication::new(vec![value & 0x3f]));
            sweep(NasWusAssistanceInformation::new(vec![value]));
            sweep(NasEthernetHeaderCompressionConfiguration::new(vec![value]));
            sweep(NasImeisvRequest::new(value & 0x0f));
            sweep(NasFGsDrxParameters::new(vec![value]));
            sweep(NasRsn::new(vec![value]));
            sweep(NasIntegrityProtectionMaximumDataRate::new(
                u16::from(value) * 0x0101,
            ));
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
        for identity in [
            octets(&[&[0x01], &plmn, &[0, 0, 0, 0, 0, 0, 0, 0, 0x10]]),
            octets(&[&[0x01], &plmn, &[0xf0, 0xff, 1, 2, 0xaa, 0xbb, 0xcc]]),
            octets(&[&[0xf2], &plmn, &[1, 0, 0x42, 0x11, 0x22, 0x33, 0x44]]),
            vec![0xf4, 0, 0x42, 0x11, 0x22, 0x33, 0x44],
            vec![0x4b, 0x09, 0x51, 0x24, 0x30, 0x32, 0x57, 0x81],
            vec![0x45, 0x09, 0x51, 0x24, 0x30, 0x32, 0x57, 0x81, 0xf1],
            vec![0x0e, 1, 2, 3, 4, 5, 6],
            vec![0x07, 1, 2, 3, 4, 5, 6, 7, 8],
            vec![0x00],
        ] {
            exercise(NasFGsMobileIdentity::new(identity));
        }
        let nai = "type1.rid678.schid0.useriduser17@example.com";
        exercise(NasFGsMobileIdentity::from_suci_nai(nai).unwrap());
        exercise(NasDsTtEthernetPortMacAddress::new(vec![1, 2, 3, 4, 5, 6]));
        exercise(NasFGsTrackingAreaIdentity::new(octets(&[
            &plmn,
            &[0, 0, 1],
        ])));
        for list in [
            octets(&[&[0x01], &plmn, &[0, 0, 1, 0, 0, 2]]),
            octets(&[&[0x21], &plmn, &[0, 0, 1]]),
            octets(&[&[0x41], &plmn, &[0, 0, 1], &plmn, &[0, 0, 2]]),
        ] {
            exercise(NasFGsTrackingAreaIdentityList::new(list));
        }
        exercise(NasPlmnList::new(octets(&[&plmn, &[0x02, 0x18, 0x39]])));
        exercise(NasListOfPlmnsToBeUsedInDisasterCondition::new(
            plmn.to_vec(),
        ));
        exercise(NasPlmnIdentity::new(plmn));
        exercise(NasSNssai::new(vec![1, 1, 2, 3]));
        exercise(NasNssai::new(vec![4, 1, 1, 2, 3, 1, 2]));
        exercise(NasMappedNssai::new(vec![1, 1, 4, 1, 1, 2, 3]));
        exercise(NasRejectedNssai::new(vec![0x10, 1, 0x41, 2, 1, 2, 3]));
        exercise(NasLadnIndication::new(
            b"\x09\x08internet\x04\x03ims".to_vec(),
        ));
        exercise(NasDnn::new(b"\x08internet".to_vec()));
        exercise(NasNid::from_nid_value("000007ed9d5a").unwrap());
        exercise(NasSmPduDnRequestContainer::from_str("user@example.com"));
        exercise(NasSessionAmbr::new(vec![6, 0, 100, 6, 0, 50]));
        exercise(NasPduAddress::new(vec![1, 10, 0, 0, 1]));
        exercise(NasPduAddress::new(vec![2, 1, 2, 3, 4, 5, 6, 7, 8]));
        exercise(NasPduAddress::new(vec![
            3, 1, 2, 3, 4, 5, 6, 7, 8, 10, 0, 0, 1,
        ]));
        exercise(NasPduAddress::new(octets(&[
            &[9, 10, 0, 0, 1],
            &[0xfe; 16],
        ])));
        // One QoS rule: create, default, precedence 255, QFI 1, match-all filter.
        exercise(NasQosRules::new(vec![1, 0, 6, 0x31, 0x31, 1, 1, 255, 1]));
        // One QoS flow description: create QFI 1 with a 5QI of 9.
        exercise(NasQosFlowDescriptions::new(vec![1, 0x20, 0x41, 1, 1, 9]));
        exercise(NasNetworkName::from_name("Open5GS", true));
        exercise(NasTimeZone::new(0x40));
        exercise(NasEmergencyNumberList::new(vec![3, 0x1f, 0x11, 0xf2]));
        exercise(NasServingPlmnRateControl::new(vec![0, 10]));
        exercise(NasSupportedCodecList::new(vec![4, 2, 0x60, 0]));
        // A container of a 5GMM STATUS with cause #22, and lists.
        exercise(NasMessageContainer::new(vec![0x7e, 0x00, 0x64, 0x16]));
        exercise(NasServiceAreaList::new(octets(&[
            &[0x00],
            &plmn,
            &[0, 0, 1],
        ])));
    }
}
