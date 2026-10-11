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

//! Shared NAS message struct and codec macros.

use crate::common::{
    IeFault, IgnoredIeReason, NasError, OptionalIeOrder, Reader, Result, Severity, UnknownIe,
    ValidationError, generic_ie_length,
};

// ── Codec of the optional part ─────────────────────────────────────────────────
//
// What does not depend on the type of a field is compiled once here;
// `nas_message!` expands to the calls and to one closure over the fields.

/// IEIs of the optional IEs of a message, one group per IE in table order.
pub(crate) type IeiTable = &'static [&'static [u8]];

/// The place in a table of each IEI: `NO_IE` for one that the table does
/// not have.
pub(crate) type IeiIndex = [u8; 256];

const NO_IE: u8 = u8::MAX;

/// The index of the table `table`.
pub(crate) const fn iei_index(table: IeiTable) -> IeiIndex {
    assert!(table.len() <= 128, "a message has at most 128 optional IEs");
    let mut index = [NO_IE; 256];
    let mut at = 0;
    while at < table.len() {
        let group = table[at];
        let mut alias = 0;
        while alias < group.len() {
            index[group[alias] as usize] = at as u8;
            alias += 1;
        }
        at += 1;
    }
    index
}

fn table_index(table: IeiTable, iei: u8) -> Option<usize> {
    table.iter().position(|group| group.contains(&iei))
}

/// Decode a mandatory IE. One that is missing, cut short or syntactically
/// incorrect is reported as such (TS 24.301 and TS 24.501 §7.5.1).
pub(crate) fn decode_mandatory_ie<T>(
    buffer: &mut &[u8],
    field: &'static str,
    min_length: usize,
    decode: impl FnOnce(&mut &[u8]) -> Result<T>,
    receivable: impl FnOnce(&T) -> bool,
) -> Result<T> {
    let before = buffer.len();
    let fault = match decode(buffer) {
        Ok(_) if before - buffer.len() < min_length => IeFault::TooShort,
        Ok(value) if receivable(&value) => return Ok(value),
        Ok(_) => IeFault::Syntax,
        Err(NasError::BufferTooShort) if before == 0 => IeFault::Missing,
        Err(NasError::BufferTooShort) => IeFault::Truncated,
        Err(_) => IeFault::Syntax,
    };
    Err(NasError::InvalidMandatoryIe { ie: field, fault })
}

/// The IEs that were kept so far, as the order that a decoded message keeps:
/// each by the first IEI of its place in the table, in the order of the
/// table, which is the order they came in.
fn kept_so_far(table: IeiTable, kept: u128, order: &mut Vec<OptionalIeOrder>) {
    for (at, group) in table.iter().enumerate() {
        if kept >> at & 1 == 1 {
            order.push(OptionalIeOrder::Known(group[0]));
        }
    }
}

/// What decodes the IE of an IEI of the table of a message, from a copy of
/// the buffer that is still at the IEI, and keeps it in its field if it may.
pub(crate) type DecodeKnown<'a> = dyn FnMut(u8, &mut &[u8], bool) -> Result<bool> + 'a;

/// Decode the optional part of a message into the fields `known` assigns,
/// `unknown_ies` and `order`.
///
/// `known` decodes the IE at a place of the table from a copy of the
/// buffer. Its flag says whether the IE is the first of its kind and in
/// sequence: only then may it keep the value, and it returns whether it did.
///
/// `order` stays empty for a message whose optional IEs are all kept, in the
/// order of the table and with the first IEI of their place: encoding the
/// fields in the order of the table gives the octets back, and nothing has
/// to be remembered. The order is written from the first IE that is unknown,
/// ignored, or under another IEI of its place.
pub(crate) fn decode_optional_ies(
    buffer: &mut &[u8],
    table: IeiTable,
    index: &IeiIndex,
    tlve_start: u8,
    unknown_ies: &mut Vec<UnknownIe>,
    order: &mut Vec<OptionalIeOrder>,
    known: &mut DecodeKnown<'_>,
) -> Result<()> {
    // The places of the table that had an IE, and those whose IE was kept.
    let (mut seen, mut kept) = (0_u128, 0_u128);
    let mut furthest: Option<u8> = None;
    let mut in_table_order = true;
    while let Some(&peek) = buffer.first() {
        let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };
        let at = index[usize::from(iei)];
        if in_table_order && (at == NO_IE || seen >> at & 1 == 1) {
            in_table_order = false;
            kept_so_far(table, kept, order);
        }
        if at == NO_IE {
            // Unknown IEI: skip it by the TS 24.007 §11.2.4 format rule and
            // keep its octets for re-encoding. One encoded as "comprehension
            // required" is kept too, flagged by
            // `UnknownIe::is_comprehension_required`: the receiver, not the
            // decoder, answers it (TS 24.301/24.501 §7.5.1).
            let length = match generic_ie_length(buffer, tlve_start) {
                Ok(length) => length,
                // A malformed unknown non-comprehension-required IE is
                // ignored (§7.6.1). Its boundary is unknowable, so the rest
                // of the PDU is retained as that IE.
                Err(_) if !(peek <= 0x0f || matches!(peek, 0x7e | 0x7f)) => buffer.len(),
                // A comprehension-required one that is cut short has no
                // boundary to keep it by: invalid mandatory information.
                Err(_) => {
                    return Err(NasError::InvalidMandatoryIe {
                        ie: "unknown_ies",
                        fault: IeFault::Truncated,
                    });
                }
            };
            let raw = buffer.split_to(length);
            order.push(OptionalIeOrder::Unknown(unknown_ies.len()));
            unknown_ies.push(UnknownIe {
                iei: raw[0],
                data: raw[1..].into(),
            });
            continue;
        }
        // Only the first occurrence is handled (§7.6.3), and an
        // out-of-sequence IE is ignored (§7.6.2).
        let repeated = seen >> at & 1 == 1;
        seen |= 1 << at;
        let out_of_sequence = furthest.is_some_and(|furthest| at < furthest);
        furthest = Some(furthest.map_or(at, |furthest| furthest.max(at)));
        // An ignored IE is still decoded, on the copy, to find where its
        // known format ends. A truncated one is syntactically incorrect and
        // therefore absent (§7.7.1): it takes the rest of the PDU.
        let mut probe = *buffer;
        let decoded = known(iei, &mut probe, !repeated && !out_of_sequence);
        let length = match decoded {
            Ok(_) => buffer.len() - probe.len(),
            Err(_) => buffer.len(),
        };
        if matches!(decoded, Ok(true)) {
            buffer.advance(length);
            kept |= 1 << at;
            // Another IEI of the place is one to give back.
            if in_table_order && iei != table[usize::from(at)][0] {
                in_table_order = false;
                kept_so_far(table, kept & !(1 << at), order);
            }
            if !in_table_order {
                order.push(OptionalIeOrder::Known(iei));
            }
            continue;
        }
        if in_table_order {
            in_table_order = false;
            kept_so_far(table, kept, order);
        }
        // The raw octets are retained for diagnostics and relay.
        let reason = if repeated {
            IgnoredIeReason::Repeated
        } else if out_of_sequence {
            IgnoredIeReason::OutOfSequence
        } else {
            IgnoredIeReason::Malformed
        };
        let raw = buffer.split_to(length);
        order.push(OptionalIeOrder::Ignored(unknown_ies.len(), reason));
        unknown_ies.push(UnknownIe {
            iei: raw[0],
            data: raw[1..].into(),
        });
    }
    Ok(())
}

/// Encode the optional part of a message that keeps an order: replay the
/// decoded IE order, and insert IEs set after decoding at their position in
/// the message table (§8.1). `present` says which table IEs are set; `known`
/// encodes the one of an IEI. A message without an order and without unknown
/// IEs is encoded in the order of its table, by its own code.
pub(crate) fn encode_optional_ies(
    buffer: &mut Vec<u8>,
    table: IeiTable,
    index: &IeiIndex,
    present: u128,
    unknown_ies: &[UnknownIe],
    decoded: &[OptionalIeOrder],
    known: &dyn Fn(&mut Vec<u8>, u8) -> Result<()>,
) -> Result<()> {
    // The places of the table that the decoded order has an IE of.
    let mut ordered = 0_u128;
    for entry in decoded {
        if let OptionalIeOrder::Known(iei) = entry
            && index[usize::from(*iei)] != NO_IE
        {
            ordered |= 1 << index[usize::from(*iei)];
        }
    }
    // The IEs that were set after decoding, each before the first decoded IE
    // of a later place.
    let mut added = present & !ordered;
    let mut emit_added_before = |buffer: &mut Vec<u8>, place: usize| -> Result<()> {
        while added != 0 {
            let at = added.trailing_zeros() as usize;
            if at >= place.min(table.len()) {
                break;
            }
            added &= added - 1;
            known(buffer, table[at][0])?;
        }
        Ok(())
    };
    // Decoding numbers the unknown IEs in the order they came in, so the
    // ones that were replayed are the first `replayed` of them. An order
    // that was not decoded may say otherwise, and then each is noted.
    let mut replayed = 0;
    let mut noted: Option<Vec<bool>> = None;
    for entry in decoded {
        match *entry {
            OptionalIeOrder::Known(iei) => {
                let at = index[usize::from(iei)];
                if at != NO_IE {
                    emit_added_before(buffer, usize::from(at))?;
                }
                known(buffer, iei)?;
            }
            OptionalIeOrder::Unknown(at) | OptionalIeOrder::Ignored(at, _) => {
                if let Some(ie) = unknown_ies.get(at) {
                    buffer.push(ie.iei);
                    buffer.extend_from_slice(&ie.data);
                    match &mut noted {
                        Some(noted) => noted[at] = true,
                        None if at == replayed => replayed += 1,
                        None => {
                            let mut each = vec![false; unknown_ies.len()];
                            each[..replayed].fill(true);
                            each[at] = true;
                            noted = Some(each);
                        }
                    }
                }
            }
        }
    }
    emit_added_before(buffer, table.len())?;
    // Unknown IEs added after decoding follow the replayed ones.
    for (at, ie) in unknown_ies.iter().enumerate() {
        let replayed = match &noted {
            Some(noted) => noted[at],
            None => at < replayed,
        };
        if !replayed {
            buffer.push(ie.iei);
            buffer.extend_from_slice(&ie.data);
        }
    }
    Ok(())
}

/// Findings on optional IEs that were ignored during decoding. Every ignored
/// known occurrence is a sender error; the raw bookkeeping distinguishes
/// repeated, malformed, and out-of-sequence receiver behavior (§7.5.1).
pub(crate) fn optional_ie_order_findings(
    table: IeiTable,
    order: &[OptionalIeOrder],
    unknown_ies: &[UnknownIe],
) -> Vec<ValidationError> {
    let mut findings = Vec::new();
    let mut error = |field, message| {
        findings.push(ValidationError {
            severity: Severity::Error,
            field,
            message,
        })
    };
    let mut furthest = 0;
    for entry in order {
        match *entry {
            OptionalIeOrder::Known(iei) => {
                let index = table_index(table, iei).unwrap_or(0);
                if index < furthest {
                    error(
                        "optional_ies",
                        format!("IEI 0x{iei:02X} is out of the message table order"),
                    );
                }
                furthest = furthest.max(index);
            }
            OptionalIeOrder::Unknown(index) => {
                let Some(ie) = unknown_ies.get(index) else {
                    continue;
                };
                let iei = if ie.iei >= 0x80 {
                    ie.iei & 0xf0
                } else {
                    ie.iei
                };
                if table_index(table, iei).is_some() {
                    error(
                        "unknown_ies",
                        format!(
                            "IEI 0x{:02X} was ignored as malformed, repeated, or out of sequence",
                            ie.iei
                        ),
                    );
                }
            }
            OptionalIeOrder::Ignored(index, reason) => {
                let Some(ie) = unknown_ies.get(index) else {
                    continue;
                };
                let description = match reason {
                    IgnoredIeReason::Repeated => "repeated",
                    IgnoredIeReason::Malformed => "malformed",
                    IgnoredIeReason::OutOfSequence => "out of sequence",
                };
                error(
                    "unknown_ies",
                    format!("IEI 0x{:02X} was ignored as {description}", ie.iei),
                );
            }
        }
    }
    findings
}

/// The sender check finding of an IE whose value or structure is invalid.
pub(crate) fn invalid_ie(field: &'static str) -> ValidationError {
    ValidationError {
        severity: Severity::Error,
        field,
        message: "IE has invalid value or structure".into(),
    }
}

/// Report a field whose encoding, as written by `encode`, is outside the
/// whole-IE length range of the message table. `encoded` is a buffer that
/// the fields of a message are encoded in one after the other.
pub(crate) fn check_table_length(
    findings: &mut Vec<ValidationError>,
    field: &'static str,
    range: std::ops::RangeInclusive<usize>,
    encoded: &mut Vec<u8>,
    encode: &dyn Fn(&mut Vec<u8>) -> Result<()>,
) {
    encoded.clear();
    if !(encode(encoded).is_ok() && range.contains(&encoded.len())) {
        findings.push(ValidationError {
            severity: Severity::Error,
            field,
            message: format!(
                "message-table length is outside {}..={}",
                range.start(),
                range.end()
            ),
        });
    }
}

/// What the message enums use of every message struct, so that each enum
/// lists its variants once. `nas_message!` implements it.
pub(crate) trait MessageBody: crate::common::Encode + crate::common::Validate {
    /// Unknown IEs and ignored known IEs, as decoded.
    fn unknown_ies(&self) -> &[UnknownIe];
    /// Findings on optional IEs that were ignored during decoding.
    fn ie_order_findings(&self) -> Vec<ValidationError>;
    /// Order findings followed by the sender check findings.
    fn ie_findings(&self) -> Vec<ValidationError>;
    /// Visit the IEs that the message has, for its view.
    #[cfg(feature = "serde")]
    fn ies(&self, visit: &mut crate::common::view::Visit<'_>);
    /// The readable serde form, without a value, of the optional IE that
    /// the message does not have and whose field prints as `name`.
    #[cfg(feature = "serde")]
    fn blank(&self, name: &str) -> Option<serde_json::Value>;
}

// ── Macros ─────────────────────────────────────────────────────────────────────

/// Implement `Default` for a `nas_message!`-defined struct only when it has
/// no mandatory fields (so `new()` takes no arguments).
macro_rules! nas_message_impl_default {
    ($name:ident) => {
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
    ($name:ident, $first:ident $(, $rest:ident)*) => {};
}

/// Define a NAS message struct with mandatory and optional fields.
///
/// Defines: struct definition, `new()` constructor, builder/accessor methods
/// for optional fields, and `Encode`/`Decode` trait implementations.
///
/// Optional field annotations:
/// - (none)       The IEI of the table, then the IE as its type encodes it:
///   a value, or a length indicator and a value (types 3, 4 and 6)
/// - `[tv1]`      Type 1: the IEI in bits 8 to 5 of one octet and the value
///   in its bits 4 to 1. The IEI is written as the octet with a value of
///   zero (`0xB0` for the IEI `B-`)
/// - ``{wire_len MIN, MAX}`` whole-IE length from the message table, with
///   the IEI. A receiver enforces only `MIN`; sender validation enforces the
///   full range.
///
/// Mandatory field annotations:
/// - (none)              The IE as its type encodes it
/// - `[low_half_first]`  The half octet in bits 4 to 1 of an octet that the
///   next field shares
/// - `[high_half_last]`  The half octet in bits 8 to 5 of that octet
/// - ``{wire_len MIN, MAX}`` Whole-field length from the message table.
macro_rules! nas_message {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            mandatory {
                $($mfield:ident : $mtype:ty $([$mattr:ident])?
                    $({wire_len $mmin:expr, $mmax:expr})? ),* $(,)?
            }
            optional {
                $($( $iei:literal )|+ => $ofield:ident : $otype:ty $([$oattr:ident])?
                    $({wire_len $omin:expr, $omax:expr})? ),* $(,)?
            }
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            $(
                #[doc = concat!("Mandatory IE `", stringify!($mfield), "`.")]
                pub $mfield: $mtype,
            )*
            $(
                #[doc = concat!("Optional IE `", stringify!($ofield), "`.")]
                pub $ofield: Option<$otype>,
            )*
            /// IEs not recognized by this version of the codec, and ignored
            /// repetitions of known IEs (TS 24.301 and TS 24.501 §7.6.3).
            /// Preserved during decode and re-emitted during encode.
            #[cfg_attr(feature = "serde", serde(default))]
            pub unknown_ies: Vec<UnknownIe>,
            #[cfg_attr(feature = "serde", serde(default))]
            optional_ie_order: Vec<crate::common::OptionalIeOrder>,
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                true
                    $(&& self.$mfield == other.$mfield)*
                    $(&& self.$ofield == other.$ofield)*
                    && self.unknown_ies == other.unknown_ies
            }
        }

        impl $name {
            /// Build the message from its mandatory IEs, in table order.
            pub fn new( $($mfield: $mtype),* ) -> Self {
                Self {
                    $( $mfield, )*
                    $( $ofield: None, )*
                    unknown_ies: Vec::new(),
                    optional_ie_order: Vec::new(),
                }
            }

            pastey::paste! {
                $(
                    #[doc = concat!("Replace `", stringify!($mfield), "` and return `self`.")]
                    pub fn [< with_ $mfield _value >](mut self, value: $mtype) -> Self {
                        self.[< set_ $mfield _value >](value);
                        self
                    }

                    #[doc = concat!("Replace `", stringify!($mfield), "`.")]
                    pub fn [< set_ $mfield _value >](&mut self, value: $mtype) -> &mut Self {
                        self.$mfield = value;
                        self
                    }

                    #[doc = concat!("`", stringify!($mfield), "`.")]
                    pub fn [< get_ $mfield >](&self) -> &$mtype {
                        &self.$mfield
                    }

                    #[doc = concat!("Mutable `", stringify!($mfield), "`.")]
                    pub fn [< get_ $mfield _mut >](&mut self) -> &mut $mtype {
                        &mut self.$mfield
                    }
                )*

                $(
                    #[doc = concat!("Include `", stringify!($ofield), "` and return `self`.")]
                    pub fn [< set_ $ofield >](mut self, value: $otype) -> Self {
                        self.[< set_ $ofield _mut >](value);
                        self
                    }

                    #[doc = concat!("Include `", stringify!($ofield), "` and return `self`.")]
                    pub fn [< with_ $ofield >](mut self, value: $otype) -> Self {
                        self.[< set_ $ofield _mut >](value);
                        self
                    }

                    #[doc = concat!("Include `", stringify!($ofield), "`.")]
                    pub fn [< set_ $ofield _mut >](&mut self, value: $otype) -> &mut Self {
                        self.$ofield = Some(value);
                        self
                    }

                    #[doc = concat!("`", stringify!($ofield), "`, if present.")]
                    pub fn [< get_ $ofield >](&self) -> Option<&$otype> {
                        self.$ofield.as_ref()
                    }

                    #[doc = concat!("Mutable `", stringify!($ofield), "`, if present.")]
                    pub fn [< get_ $ofield _mut >](&mut self) -> Option<&mut $otype> {
                        self.$ofield.as_mut()
                    }

                    #[doc = concat!("Whether `", stringify!($ofield), "` is present.")]
                    pub fn [< has_ $ofield >](&self) -> bool {
                        self.$ofield.is_some()
                    }

                    #[doc = concat!("Remove and return `", stringify!($ofield), "`.")]
                    pub fn [< clear_ $ofield >](&mut self) -> Option<$otype> {
                        self.$ofield.take()
                    }
                )*
            }
        }

        nas_message_impl_default!($name $(, $mfield)*);

        impl $name {
            const OPTIONAL_IEIS: crate::common::IeiTable = &[$(&[$($iei),+]),*];
            const OPTIONAL_IEI_INDEX: &'static crate::common::IeiIndex =
                &crate::common::iei_index(Self::OPTIONAL_IEIS);

            /// Findings on optional IEs that were ignored during decoding.
            pub(crate) fn ie_order_findings(&self) -> Vec<crate::common::ValidationError> {
                crate::common::optional_ie_order_findings(
                    Self::OPTIONAL_IEIS,
                    &self.optional_ie_order,
                    &self.unknown_ies,
                )
            }

            /// Order findings followed by the sender check findings.
            pub(crate) fn ie_findings(&self) -> Vec<crate::common::ValidationError> {
                let mut findings = self.ie_order_findings();
                findings.extend(self.sender_check_findings());
                findings
            }

            /// Sender check findings of the fields whose IE type has a
            /// `SenderCheck` implementation.
            pub(crate) fn sender_check_findings(&self) -> Vec<crate::common::ValidationError> {
                #[allow(unused_imports)]
                use crate::common::{
                    IeLengthCheckProbe, SenderCheckProbe, ViaIeLengthCheck, ViaNoIeLengthCheck,
                    ViaNoSenderCheck, ViaSenderCheck, invalid_ie,
                };
                #[allow(unused_mut)]
                let mut findings = Vec::new();
                // The fields that the table gives a length are encoded in
                // one buffer, one after the other.
                #[allow(unused_mut, unused_variables)]
                let mut encoded = Vec::<u8>::new();
                $(
                    if (&SenderCheckProbe(&self.$mfield)).sender_check_result() == Some(false)
                        || (&IeLengthCheckProbe(&self.$mfield)).sender_length_result() == Some(false)
                    {
                        findings.push(invalid_ie(stringify!($mfield)));
                    }
                )*
                $(
                    if let Some(value) = &self.$ofield
                        && ((&SenderCheckProbe(value)).sender_check_result() == Some(false)
                            || (&IeLengthCheckProbe(value)).sender_length_result() == Some(false))
                    {
                        findings.push(invalid_ie(stringify!($ofield)));
                    }
                )*
                $(
                    nas_message!(@sender_mlength findings, encoded, self, $mfield
                        $(, $mattr)? $({wire_len $mmin, $mmax})?);
                )*
                $(
                    nas_message!(@sender_olength findings, encoded, self, $ofield,
                        ($($iei)|+) $(, $oattr)? $({wire_len $omin, $omax})?);
                )*
                findings
            }
        }

        impl crate::common::MessageBody for $name {
            fn unknown_ies(&self) -> &[UnknownIe] {
                &self.unknown_ies
            }
            fn ie_order_findings(&self) -> Vec<crate::common::ValidationError> {
                Self::ie_order_findings(self)
            }
            fn ie_findings(&self) -> Vec<crate::common::ValidationError> {
                Self::ie_findings(self)
            }
            #[cfg(feature = "serde")]
            #[allow(unused_variables)]
            fn ies(&self, visit: &mut crate::common::view::Visit<'_>) {
                #[allow(unused_imports)]
                use crate::common::view::{DecodedProbe, ViaDecoded, ViaNoDecoded};
                $(
                    visit(
                        stringify!($mfield),
                        std::mem::size_of_val(&self.$mfield.value),
                        (&DecodedProbe(&self.$mfield)).decoded_ie(),
                        false,
                    );
                )*
                $(
                    if let Some(ie) = &self.$ofield {
                        visit(
                            stringify!($ofield),
                            std::mem::size_of_val(&ie.value),
                            (&DecodedProbe(ie)).decoded_ie(),
                            true,
                        );
                    }
                )*
            }
            #[cfg(feature = "serde")]
            #[allow(unused_variables)]
            fn blank(&self, name: &str) -> Option<serde_json::Value> {
                #[allow(unused_imports)]
                use crate::common::readable::{printed, to_value};
                $(
                    if self.$ofield.is_none() && printed(stringify!($ofield)) == name {
                        return to_value(&<$otype>::blank()).ok();
                    }
                )*
                None
            }
        }

        impl Encode for $name {
            fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
                $( nas_message!(@encode_mand buffer, self, $mfield $(, $mattr)?); )*
                #[allow(unused_variables)]
                let known = |buffer: &mut Vec<u8>, iei: u8| -> Result<()> {
                    match iei {
                        $( $($iei)|+ => {
                            if let Some(value) = &self.$ofield {
                                nas_message!(@encode_opt buffer, value, iei $(, $oattr)?);
                            }
                        } )*
                        _ => {}
                    }
                    Ok(())
                };
                // The optional IEs that the message has, by their place in
                // the table.
                #[allow(unused_mut, unused_variables, unused_assignments)]
                let present = {
                    let (mut present, mut place) = (0_u128, 0_u32);
                    $(
                        present |= u128::from(self.$ofield.is_some()) << place;
                        place += 1;
                    )*
                    present
                };
                crate::common::encode_optional_ies(
                    buffer,
                    Self::OPTIONAL_IEIS,
                    Self::OPTIONAL_IEI_INDEX,
                    present,
                    &self.unknown_ies,
                    &self.optional_ie_order,
                    &known,
                )
            }
        }

        impl Decode for $name {
            fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
                #[allow(unused_imports)]
                use crate::common::{
                    IeLengthCheckProbe, Reader, ReceiverSyntaxCheckProbe, ViaIeLengthCheck,
                    ViaNoIeLengthCheck, ViaNoReceiverSyntaxCheck, ViaReceiverSyntaxCheck,
                };
                $(
                    let $mfield = crate::common::decode_mandatory_ie(
                        buffer,
                        stringify!($mfield),
                        nas_message!(@min $($mmin)?),
                        |buffer| Ok(nas_message!(@decode_mand buffer, $mtype $(, $mattr)?)),
                        |value: &$mtype| nas_message!(@receivable value, $mfield),
                    )?;
                )*
                let mut message = Self::new( $($mfield),* );
                // A value the receiver does not accept is treated as not
                // present, and its IE is kept with the unknown IEs.
                #[allow(unused_variables)]
                let mut known = |iei: u8, probe: &mut &[u8], first: bool| -> Result<bool> {
                    let before = probe.len();
                    match iei {
                        $( $($iei)|+ => {
                            let value: $otype = nas_message!(@decode_opt probe, $otype $(, $oattr)?);
                            let kept = first
                                && nas_message!(@receivable &value, $ofield)
                                $(&& before - probe.len() >= $omin)?;
                            if kept {
                                message.$ofield = Some(value);
                            }
                            Ok(kept)
                        } )*
                        _ => Ok(false),
                    }
                };
                crate::common::decode_optional_ies(
                    buffer,
                    Self::OPTIONAL_IEIS,
                    Self::OPTIONAL_IEI_INDEX,
                    UNKNOWN_TLVE_START,
                    &mut message.unknown_ies,
                    &mut message.optional_ie_order,
                    &mut known,
                )?;
                Ok(message)
            }
        }
    };

    (@canonical_iei $first:literal $(| $rest:literal)*) => {
        $first
    };

    // Minimum whole-IE length a receiver enforces: that of `wire_len`, if any.
    (@min) => { 0 };
    (@min $min:expr) => { $min };

    (@sender_mlength $findings:ident, $encoded:ident, $self:ident, $field:ident
        $(, $attr:ident)? {wire_len $min:expr, $max:expr}) => {
        crate::common::check_table_length(
            &mut $findings,
            stringify!($field),
            $min..=$max,
            &mut $encoded,
            &|buffer| {
                nas_message!(@encode_mand buffer, $self, $field $(, $attr)?);
                Ok(())
            },
        );
    };
    (@sender_mlength $findings:ident, $encoded:ident, $self:ident, $field:ident
        $(, $attr:ident)?) => {};

    (@sender_olength $findings:ident, $encoded:ident, $self:ident, $field:ident,
        ($($iei:literal)|+) $(, $attr:ident)? {wire_len $min:expr, $max:expr}) => {
        if let Some(value) = &$self.$field {
            crate::common::check_table_length(
                &mut $findings,
                stringify!($field),
                $min..=$max,
                &mut $encoded,
                &|buffer| {
                    let iei = nas_message!(@canonical_iei $($iei)|+);
                    nas_message!(@encode_opt buffer, value, iei $(, $attr)?);
                    Ok(())
                },
            );
        }
    };
    (@sender_olength $findings:ident, $encoded:ident, $self:ident, $field:ident,
        ($($iei:literal)|+) $(, $attr:ident)?) => {};

    // Whether a receiver accepts the decoded value of `$field`: its type's
    // syntax and minimum-length checks, for the types that have them.
    (@receivable $value:expr, $field:ident) => {
        (&ReceiverSyntaxCheckProbe($value)).receiver_syntax_result(stringify!($field))
            != Some(false)
            && (&IeLengthCheckProbe($value)).receiver_length_result() != Some(false)
    };

    // ── Internal encode rules ──────────────────────────────────────────────

    // An optional IE of type 3, 4 or 6: its IEI, then the IE as its type
    // encodes it.
    (@encode_opt $buf:ident, $value:ident, $iei:expr) => {
        $buf.push($iei);
        $value.encode_into($buf)?;
    };

    // An optional IE of type 1: the IEI in bits 8 to 5 and the value in
    // bits 4 to 1 of one octet.
    (@encode_opt $buf:ident, $value:ident, $iei:expr, tv1) => {
        if $value.value > 0x0f {
            return Err(NasError::EncodingError(
                "a half octet has four bits".into(),
            ));
        }
        $buf.push($iei | $value.value);
    };

    // Mandatory half octets share one octet; the first field writes it and
    // the second adds its bits. TS 24.301 and TS 24.501 chapter 8 list the
    // half octet of bits 4 to 1 first.
    (@encode_mand $buf:ident, $self:ident, $field:ident, low_half_first) => {
        if $self.$field.value > 0x0f {
            return Err(NasError::EncodingError(
                "a half octet has four bits".into(),
            ));
        }
        $buf.push($self.$field.value);
    };
    (@encode_mand $buf:ident, $self:ident, $field:ident, high_half_last) => {
        if $self.$field.value > 0x0f {
            return Err(NasError::EncodingError(
                "a half octet has four bits".into(),
            ));
        }
        if let Some(octet) = $buf.last_mut() {
            *octet |= $self.$field.value << 4;
        }
    };
    (@encode_mand $buf:ident, $self:ident, $field:ident) => {
        $self.$field.encode_into($buf)?;
    };

    // ── Internal decode rules ──────────────────────────────────────────────

    // The first field of an octet of two half octets reads it and leaves it
    // to the second.
    (@decode_mand $buf:ident, $ty:ty, low_half_first) => {
        <$ty>::new($buf.first().ok_or(NasError::BufferTooShort)? & 0x0F)
    };
    (@decode_mand $buf:ident, $ty:ty, high_half_last) => {
        <$ty>::new($buf.take(1)?[0] >> 4)
    };
    (@decode_mand $buf:ident, $ty:ty) => {
        <$ty>::decode_from($buf)?
    };

    // An optional IE is decoded where its IEI was read, which is still there.
    (@decode_opt $buf:ident, $ty:ty) => {{
        $buf.advance(1);
        <$ty>::decode_from($buf)?
    }};
    (@decode_opt $buf:ident, $ty:ty, tv1) => {
        <$ty>::new($buf.get_u8() & 0x0F)
    };
}

/// Define a NAS message with no known fields while preserving unknown IEs.
macro_rules! nas_message_empty {
    ($(#[$meta:meta])* $name:ident) => {
        nas_message! {
            $(#[$meta])*
            pub struct $name {
                mandatory {}
                optional {}
            }
        }
    };
}

pub(crate) use {nas_message, nas_message_empty, nas_message_impl_default};

macro_rules! nas_message_optional_alias {
    ($name:ident, $alias:ident, $field:ident, $ty:ty) => {
        impl $name {
            pastey::paste! {
                #[doc = concat!("Alias of `set_", stringify!($field), "`.")]
                pub fn [< set_ $alias >](mut self, value: $ty) -> Self {
                    self.[< set_ $alias _mut >](value);
                    self
                }

                #[doc = concat!("Alias of `with_", stringify!($field), "`.")]
                pub fn [< with_ $alias >](mut self, value: $ty) -> Self {
                    self.[< set_ $alias _mut >](value);
                    self
                }

                #[doc = concat!("Alias of `set_", stringify!($field), "_mut`.")]
                pub fn [< set_ $alias _mut >](&mut self, value: $ty) -> &mut Self {
                    self.$field = Some(value);
                    self
                }

                #[doc = concat!("Alias of `get_", stringify!($field), "`.")]
                pub fn [< get_ $alias >](&self) -> Option<&$ty> {
                    self.$field.as_ref()
                }

                #[doc = concat!("Alias of `get_", stringify!($field), "_mut`.")]
                pub fn [< get_ $alias _mut >](&mut self) -> Option<&mut $ty> {
                    self.$field.as_mut()
                }

                #[doc = concat!("Alias of `has_", stringify!($field), "`.")]
                pub fn [< has_ $alias >](&self) -> bool {
                    self.$field.is_some()
                }

                #[doc = concat!("Alias of `clear_", stringify!($field), "`.")]
                pub fn [< clear_ $alias >](&mut self) -> Option<$ty> {
                    self.$field.take()
                }
            }
        }
    };
}

pub(crate) use nas_message_optional_alias;
