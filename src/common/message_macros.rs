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

//! Shared NAS message struct and codec macros.

use crate::common::{
    IgnoredIeReason, NasError, OptionalIeOrder, Result, Severity, UnknownIe, ValidationError,
    generic_ie_length,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

// ── Codec of the optional part ─────────────────────────────────────────────────
//
// What does not depend on the type of a field is compiled once here;
// `nas_message!` expands to the calls and to one closure over the fields.

/// IEIs of the optional IEs of a message, one group per IE in table order.
pub(crate) type IeiTable = &'static [&'static [u8]];

fn table_index(table: IeiTable, iei: u8) -> Option<usize> {
    table.iter().position(|group| group.contains(&iei))
}

/// Decode a mandatory IE. One that is missing, cut short or syntactically
/// incorrect is reported as such (TS 24.301 and TS 24.501 §7.5.1).
pub(crate) fn decode_mandatory_ie<T>(
    buffer: &mut Bytes,
    field: &'static str,
    min_length: usize,
    decode: impl FnOnce(&mut Bytes) -> Result<T>,
    receivable: impl FnOnce(&T) -> bool,
) -> Result<T> {
    let before = buffer.remaining();
    match decode(buffer) {
        Ok(value) if receivable(&value) && before - buffer.remaining() >= min_length => Ok(value),
        _ => Err(NasError::InvalidMandatoryIe(field)),
    }
}

/// Decode the optional part of a message into the fields `known` assigns,
/// `unknown_ies` and `order`.
///
/// `known` decodes the IE of a table IEI from a copy of the buffer. Its flag
/// says whether the IE is the first of its kind and in sequence: only then
/// may it keep the value, and it returns whether it did.
pub(crate) fn decode_optional_ies(
    buffer: &mut Bytes,
    table: IeiTable,
    tlve_start: u8,
    unknown_ies: &mut Vec<UnknownIe>,
    order: &mut Vec<OptionalIeOrder>,
    known: &mut dyn FnMut(u8, &mut Bytes, bool) -> Result<bool>,
) -> Result<()> {
    let mut seen = vec![false; table.len()];
    let mut furthest: Option<usize> = None;
    while buffer.has_remaining() {
        let peek = buffer[0];
        let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };
        let Some(index) = table_index(table, iei) else {
            // Unknown IEI: skip it by the TS 24.007 §11.2.4 format rule and
            // keep its octets for re-encoding. One encoded as "comprehension
            // required" is kept too, flagged by
            // `UnknownIe::is_comprehension_required`: the receiver, not the
            // decoder, answers it (TS 24.301/24.501 §7.5.1).
            let length = match generic_ie_length(&buffer[..], tlve_start) {
                Ok(length) => length,
                // A malformed unknown non-comprehension-required IE is
                // ignored (§7.6.1). Its boundary is unknowable, so the rest
                // of the PDU is retained as that IE.
                Err(_) if !(peek <= 0x0f || matches!(peek, 0x7e | 0x7f)) => buffer.remaining(),
                // A comprehension-required one that is cut short has no
                // boundary to keep it by: invalid mandatory information.
                Err(_) => return Err(NasError::InvalidMandatoryIe("unknown_ies")),
            };
            let raw = buffer.split_to(length);
            order.push(OptionalIeOrder::Unknown(unknown_ies.len()));
            unknown_ies.push(UnknownIe {
                iei: raw[0],
                data: raw[1..].to_vec(),
            });
            continue;
        };
        // Only the first occurrence is handled (§7.6.3), and an
        // out-of-sequence IE is ignored (§7.6.2).
        let repeated = std::mem::replace(&mut seen[index], true);
        let out_of_sequence = furthest.is_some_and(|furthest| index < furthest);
        furthest = Some(furthest.map_or(index, |furthest| furthest.max(index)));
        // An ignored IE is still decoded, on the copy, to find where its
        // known format ends. A truncated one is syntactically incorrect and
        // therefore absent (§7.7.1): it takes the rest of the PDU.
        let mut probe = buffer.clone();
        let kept = known(iei, &mut probe, !repeated && !out_of_sequence);
        let length = match kept {
            Ok(_) => buffer.remaining() - probe.remaining(),
            Err(_) => buffer.remaining(),
        };
        if matches!(kept, Ok(true)) {
            buffer.advance(length);
            order.push(OptionalIeOrder::Known(iei));
            continue;
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
            data: raw[1..].to_vec(),
        });
    }
    Ok(())
}

/// Encode the optional part of a message: replay the decoded IE order, and
/// insert IEs set after decoding at their position in the message table
/// (§8.1). `present` says which table IEs are set; `known` encodes one.
pub(crate) fn encode_optional_ies(
    buffer: &mut BytesMut,
    table: IeiTable,
    present: &[bool],
    unknown_ies: &[UnknownIe],
    decoded: &[OptionalIeOrder],
    known: &dyn Fn(&mut BytesMut, u8) -> Result<()>,
) -> Result<()> {
    let mut plan = decoded.to_vec();
    for (own, group) in table.iter().enumerate() {
        if present[own]
            && !plan
                .iter()
                .any(|order| matches!(order, OptionalIeOrder::Known(iei) if group.contains(iei)))
        {
            let at = plan
                .iter()
                .position(|order| {
                    matches!(order, OptionalIeOrder::Known(other)
                        if table_index(table, *other) > Some(own))
                })
                .unwrap_or(plan.len());
            plan.insert(at, OptionalIeOrder::Known(group[0]));
        }
    }
    let mut replayed = vec![false; unknown_ies.len()];
    for entry in &plan {
        match *entry {
            OptionalIeOrder::Known(iei) => known(buffer, iei)?,
            OptionalIeOrder::Unknown(index) | OptionalIeOrder::Ignored(index, _) => {
                if let Some(ie) = unknown_ies.get(index) {
                    buffer.put_u8(ie.iei);
                    buffer.put_slice(&ie.data);
                    replayed[index] = true;
                }
            }
        }
    }
    // Unknown IEs added after decoding follow the replayed ones.
    for (ie, replayed) in unknown_ies.iter().zip(replayed) {
        if !replayed {
            buffer.put_u8(ie.iei);
            buffer.put_slice(&ie.data);
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
/// whole-IE length range of the message table.
pub(crate) fn check_table_length(
    findings: &mut Vec<ValidationError>,
    field: &'static str,
    range: std::ops::RangeInclusive<usize>,
    encode: &dyn Fn(&mut BytesMut) -> Result<()>,
) {
    let mut encoded = BytesMut::new();
    if !(encode(&mut encoded).is_ok() && range.contains(&encoded.len())) {
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
/// - (none)       Standard TLV/TLV-E: encode sets `type_field`, decode calls `Type::decode()`
/// - `[tv1]`      Standard TV-1: encode sets `type_field = IEI >> 4`, decode calls `Type::decode()`
///   IEI is the decode-side match value (e.g. `0xB0` for type_field `0x0B`)
/// - `[opt_type]` V/LV/LV-E used as optional: encode writes IEI byte separately, decode skips IEI
/// - `[v_as_tv1]` V-type used as TV-1: encode packs `IEI | (value & 0x0F)`, decode extracts low nibble
/// - ``{wire_len MIN, MAX}`` whole-IE length from the message table. A receiver
///   enforces only `MIN`; sender validation enforces the full range.
///
/// Mandatory field annotations:
/// - (none)              Standard: `Type::decode(buffer)?`
/// - `[decode_value_only]` Uses `Type::decode_value_only(buffer)?`
/// - `[tlv_as_lv]`         Reuses a TLV type as an untagged mandatory LV field
/// - `[tlve_as_lve]`       Reuses a TLV-E type as an untagged mandatory LV-E field
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

            paste::paste! {
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
                    nas_message!(@sender_mlength findings, self, $mfield
                        $(, $mattr)? $({wire_len $mmin, $mmax})?);
                )*
                $(
                    nas_message!(@sender_olength findings, self, $ofield, $otype,
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
        }

        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                $( nas_message!(@encode_mand buffer, self, $mfield $(, $mattr)?); )*
                #[allow(unused_variables)]
                let known = |buffer: &mut BytesMut, iei: u8| -> Result<()> {
                    match iei {
                        $( $($iei)|+ => { nas_message!(@encode_opt buffer, self, iei, $ofield, $otype $(, $oattr)?); } )*
                        _ => {}
                    }
                    Ok(())
                };
                crate::common::encode_optional_ies(
                    buffer,
                    Self::OPTIONAL_IEIS,
                    &[$(self.$ofield.is_some()),*],
                    &self.unknown_ies,
                    &self.optional_ie_order,
                    &known,
                )
            }
        }

        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                #[allow(unused_imports)]
                use crate::common::{
                    IeLengthCheckProbe, ReceiverSyntaxCheckProbe, ViaIeLengthCheck,
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
                let mut known = |iei: u8, probe: &mut Bytes, first: bool| -> Result<bool> {
                    let before = probe.remaining();
                    match iei {
                        $( $($iei)|+ => {
                            let value: $otype = nas_message!(@decode_opt probe, $ofield, $otype $(, $oattr)?);
                            let kept = first
                                && nas_message!(@receivable &value, $ofield)
                                $(&& before - probe.remaining() >= $omin)?;
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

    (@sender_mlength $findings:ident, $self:ident, $field:ident
        $(, $attr:ident)? {wire_len $min:expr, $max:expr}) => {
        crate::common::check_table_length(
            &mut $findings,
            stringify!($field),
            $min..=$max,
            &|buffer| {
                nas_message!(@encode_mand buffer, $self, $field $(, $attr)?);
                Ok(())
            },
        );
    };
    (@sender_mlength $findings:ident, $self:ident, $field:ident $(, $attr:ident)?) => {};

    (@sender_olength $findings:ident, $self:ident, $field:ident, $ty:ty,
        ($($iei:literal)|+) $(, $attr:ident)? {wire_len $min:expr, $max:expr}) => {
        if $self.$field.is_some() {
            crate::common::check_table_length(
                &mut $findings,
                stringify!($field),
                $min..=$max,
                &|buffer| {
                    let iei = nas_message!(@canonical_iei $($iei)|+);
                    nas_message!(@encode_opt buffer, $self, iei, $field, $ty $(, $attr)?);
                    Ok(())
                },
            );
        }
    };
    (@sender_olength $findings:ident, $self:ident, $field:ident, $ty:ty,
        ($($iei:literal)|+) $(, $attr:ident)?) => {};

    // Whether a receiver accepts the decoded value of `$field`: its type's
    // syntax and minimum-length checks, for the types that have them.
    (@receivable $value:expr, $field:ident) => {
        (&ReceiverSyntaxCheckProbe($value)).receiver_syntax_result(stringify!($field))
            != Some(false)
            && (&IeLengthCheckProbe($value)).receiver_length_result() != Some(false)
    };

    // ── Internal encode rules ──────────────────────────────────────────────

    // Standard TLV/TLV-E: clone, set type_field, encode
    (@encode_opt $buf:ident, $self:ident, $iei:expr, $field:ident, $ty:ty) => {
        if let Some(ref value) = $self.$field {
            let mut ie = value.clone();
            ie.type_field = $iei;
            ie.encode($buf)?;
        }
    };

    // TV-1 standard: type_field is IEI >> 4
    (@encode_opt $buf:ident, $self:ident, $iei:expr, $field:ident, $ty:ty, tv1) => {
        if let Some(ref value) = $self.$field {
            let mut ie = value.clone();
            ie.type_field = ($iei >> 4) as u8;
            ie.encode($buf)?;
        }
    };

    // opt_type: write IEI byte separately, then encode IE
    (@encode_opt $buf:ident, $self:ident, $iei:expr, $field:ident, $ty:ty, opt_type) => {
        if let Some(ref value) = $self.$field {
            helpers::encode_optional_type($buf, $iei)?;
            value.encode($buf)?;
        }
    };

    // v_as_tv1: pack IEI high nibble + value low nibble in one byte
    (@encode_opt $buf:ident, $self:ident, $iei:expr, $field:ident, $ty:ty, v_as_tv1) => {
        if let Some(ref value) = $self.$field {
            if value.value > 0x0f {
                return Err(NasError::EncodingError("NAS half octet exceeds four bits".into()));
            }
            $buf.put_u8($iei | (value.value & 0x0F));
        }
    };

    // ── Internal decode rules ──────────────────────────────────────────────

    // Mandatory EPS half octets share one byte; the first field peeks and the
    // second consumes it. TS 24.301 chapter 8 lists the low nibble first.
    (@encode_mand $buf:ident, $self:ident, $field:ident, low_half_first) => {
        if $self.$field.value > 0x0f {
            return Err(NasError::EncodingError("NAS half octet exceeds four bits".into()));
        }
        $buf.put_u8($self.$field.value & 0x0F);
    };
    (@encode_mand $buf:ident, $self:ident, $field:ident, high_half_last) => {
        if $self.$field.value > 0x0f {
            return Err(NasError::EncodingError("NAS half octet exceeds four bits".into()));
        }
        if let Some(byte) = $buf.last_mut() {
            *byte |= ($self.$field.value & 0x0F) << 4;
        }
    };
    (@encode_mand $buf:ident, $self:ident, $field:ident, decode_value_only) => {
        $self.$field.encode($buf)?;
    };
    (@encode_mand $buf:ident, $self:ident, $field:ident, tlv_as_lv) => {
        let mut tagged = BytesMut::new();
        $self.$field.encode(&mut tagged)?;
        $buf.put_slice(&tagged[1..]);
    };
    (@encode_mand $buf:ident, $self:ident, $field:ident, tlve_as_lve) => {
        let mut tagged = BytesMut::new();
        $self.$field.encode(&mut tagged)?;
        $buf.put_slice(&tagged[1..]);
    };
    (@encode_mand $buf:ident, $self:ident, $field:ident) => {
        $self.$field.encode($buf)?;
    };

    (@decode_mand $buf:ident, $ty:ty, low_half_first) => {{
        if $buf.remaining() < 1 { return Err(NasError::BufferTooShort); }
        <$ty>::new($buf[0] & 0x0F)
    }};
    (@decode_mand $buf:ident, $ty:ty, high_half_last) => {{
        if $buf.remaining() < 1 { return Err(NasError::BufferTooShort); }
        <$ty>::new($buf.get_u8() >> 4)
    }};

    // Standard mandatory decode
    (@decode_mand $buf:ident, $ty:ty) => {
        <$ty>::decode($buf)?
    };

    // Mandatory with decode_value_only
    (@decode_mand $buf:ident, $ty:ty, decode_value_only) => {
        <$ty>::decode_value_only($buf)?
    };
    (@decode_mand $buf:ident, $ty:ty, tlv_as_lv) => {{
        if $buf.remaining() < 1 { return Err(NasError::BufferTooShort); }
        let length = $buf.get_u8() as usize;
        if $buf.remaining() < length { return Err(NasError::BufferTooShort); }
        let mut value = vec![0; length];
        $buf.copy_to_slice(&mut value);
        <$ty>::new(value)
    }};
    (@decode_mand $buf:ident, $ty:ty, tlve_as_lve) => {{
        if $buf.remaining() < 2 { return Err(NasError::BufferTooShort); }
        let length = $buf.get_u16() as usize;
        if length > crate::common::MAX_IE_VALUE_LENGTH {
            return Err(NasError::DecodingError("NAS IE value exceeds maximum length".into()));
        }
        if $buf.remaining() < length { return Err(NasError::BufferTooShort); }
        let mut value = vec![0; length];
        $buf.copy_to_slice(&mut value);
        <$ty>::new(value)
    }};

    // Standard optional decode (TLV/TLV-E and TV-1): IE's own decode reads the IEI
    (@decode_opt $buf:ident, $field:ident, $ty:ty) => {
        <$ty>::decode($buf)?
    };

    // TV-1 standard decode: same as standard (the IE reads the whole byte)
    (@decode_opt $buf:ident, $field:ident, $ty:ty, tv1) => {
        <$ty>::decode($buf)?
    };

    // opt_type: skip IEI byte, then decode as V/LV/LV-E
    (@decode_opt $buf:ident, $field:ident, $ty:ty, opt_type) => {{
        $buf.advance(1);
        <$ty>::decode($buf)?
    }};

    // v_as_tv1: read byte, extract value from low nibble
    (@decode_opt $buf:ident, $field:ident, $ty:ty, v_as_tv1) => {{
        let byte = $buf.get_u8();
        <$ty>::new(byte & 0x0F)
    }};
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
            paste::paste! {
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
