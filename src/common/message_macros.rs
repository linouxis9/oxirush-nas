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
            pub unknown_ies: Vec<UnknownIe>,
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
            /// Findings on optional IEs that were ignored during decoding.
            /// Every ignored known occurrence is a sender error; the raw
            /// bookkeeping distinguishes repeated, malformed, and
            /// out-of-sequence receiver behavior (§7.5.1).
            #[allow(dead_code)]
            pub(crate) fn ie_order_findings(&self) -> Vec<crate::common::ValidationError> {
                use crate::common::{OptionalIeOrder, Severity, ValidationError};
                const TABLE_ORDER: &[&[u8]] = &[$(&[$($iei),+]),*];
                #[allow(unused_variables)]
                let table_index = |iei: u8| TABLE_ORDER.iter().position(|group| group.contains(&iei));
                #[allow(unused_mut)]
                let mut findings = Vec::new();
                #[allow(unused_mut, unused_variables)]
                let mut furthest = 0;
                for order in &self.optional_ie_order {
                    match *order {
                        OptionalIeOrder::Known(iei) => {
                            let index = table_index(iei).unwrap_or(0);
                            if index < furthest {
                                findings.push(ValidationError {
                                    severity: Severity::Error,
                                    field: "optional_ies",
                                    message: format!("IEI 0x{iei:02X} is out of the message table order"),
                                });
                            }
                            furthest = furthest.max(index);
                        }
                        OptionalIeOrder::Unknown(index) => {
                            let Some(ie) = self.unknown_ies.get(index) else { continue };
                            let iei = if ie.iei >= 0x80 { ie.iei & 0xf0 } else { ie.iei };
                            if table_index(iei).is_some() {
                                findings.push(ValidationError {
                                    severity: Severity::Error,
                                    field: "unknown_ies",
                                    message: format!(
                                        "IEI 0x{:02X} was ignored as malformed, repeated, or out of sequence",
                                        ie.iei
                                    ),
                                });
                            }
                        }
                        OptionalIeOrder::Ignored(index, reason) => {
                            let Some(ie) = self.unknown_ies.get(index) else { continue };
                            let (severity, description) = match reason {
                                crate::common::IgnoredIeReason::Repeated => {
                                    (Severity::Error, "repeated")
                                }
                                crate::common::IgnoredIeReason::Malformed => {
                                    (Severity::Error, "malformed")
                                }
                                crate::common::IgnoredIeReason::OutOfSequence => {
                                    (Severity::Error, "out of sequence")
                                }
                            };
                            findings.push(ValidationError {
                                severity,
                                field: "unknown_ies",
                                message: format!(
                                    "IEI 0x{:02X} was ignored as {description}",
                                    ie.iei
                                ),
                            });
                        }
                    }
                }
                findings
            }

            /// Order findings followed by the sender check findings.
            #[allow(dead_code)]
            pub(crate) fn ie_findings(&self) -> Vec<crate::common::ValidationError> {
                let mut findings = self.ie_order_findings();
                findings.extend(self.sender_check_findings());
                findings
            }

            /// Sender check findings of the fields whose IE type has a
            /// `SenderCheck` implementation.
            #[allow(dead_code)]
            pub(crate) fn sender_check_findings(&self) -> Vec<crate::common::ValidationError> {
                #[allow(unused_imports)]
                use crate::common::{
                    IeLengthCheckProbe, SenderCheckProbe, Severity, ValidationError,
                    ViaIeLengthCheck, ViaNoIeLengthCheck, ViaNoSenderCheck, ViaSenderCheck,
                };
                #[allow(unused_mut)]
                let mut findings = Vec::new();
                $(
                    if (&SenderCheckProbe(&self.$mfield)).sender_check_result() == Some(false)
                        || (&IeLengthCheckProbe(&self.$mfield)).sender_length_result() == Some(false)
                    {
                        findings.push(ValidationError {
                            severity: Severity::Error,
                            field: stringify!($mfield),
                            message: "IE has invalid value or structure".into(),
                        });
                    }
                )*
                $(
                    if let Some(value) = &self.$ofield
                        && ((&SenderCheckProbe(value)).sender_check_result() == Some(false)
                            || (&IeLengthCheckProbe(value)).sender_length_result() == Some(false))
                    {
                        findings.push(ValidationError {
                            severity: Severity::Error,
                            field: stringify!($ofield),
                            message: "IE has invalid value or structure".into(),
                        });
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

        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                $( nas_message!(@encode_mand buffer, self, $mfield $(, $mattr)?); )*
                // Replay the decoded IE order, and insert IEs set after decoding
                // at their position in the message table (§8.1).
                const TABLE_ORDER: &[&[u8]] = &[$(&[$($iei),+]),*];
                #[allow(unused_variables)]
                let table_index = |iei: u8| TABLE_ORDER.iter().position(|group| group.contains(&iei));
                #[allow(unused_mut)]
                let mut plan = self.optional_ie_order.clone();
                $(
                    if self.$ofield.is_some() && !plan.iter().any(|order| matches!(order,
                        crate::common::OptionalIeOrder::Known(iei) if matches!(*iei, $($iei)|+)
                    )) {
                        let iei = nas_message!(@canonical_iei $($iei)|+);
                        let own = table_index(iei);
                        let at = plan
                            .iter()
                            .position(|order| matches!(order,
                                crate::common::OptionalIeOrder::Known(other) if table_index(*other) > own))
                            .unwrap_or(plan.len());
                        plan.insert(at, crate::common::OptionalIeOrder::Known(iei));
                    }
                )*
                for order in &plan {
                    match *order {
                        crate::common::OptionalIeOrder::Known(iei) => match iei {
                            $( $($iei)|+ => { nas_message!(@encode_opt buffer, self, iei, $ofield, $otype $(, $oattr)?); } )*
                            _ => {}
                        },
                        crate::common::OptionalIeOrder::Unknown(index) => {
                            if let Some(ie) = self.unknown_ies.get(index) {
                                buffer.put_u8(ie.iei);
                                buffer.put_slice(&ie.data);
                            }
                        }
                        crate::common::OptionalIeOrder::Ignored(index, _) => {
                            if let Some(ie) = self.unknown_ies.get(index) {
                                buffer.put_u8(ie.iei);
                                buffer.put_slice(&ie.data);
                            }
                        }
                    }
                }
                // Unknown IEs added after decoding follow the replayed ones.
                let mut replayed = vec![false; self.unknown_ies.len()];
                for order in &self.optional_ie_order {
                    if let crate::common::OptionalIeOrder::Unknown(index)
                    | crate::common::OptionalIeOrder::Ignored(index, _) = *order
                        && let Some(slot) = replayed.get_mut(index)
                    {
                        *slot = true;
                    }
                }
                for (ie, replayed) in self.unknown_ies.iter().zip(replayed) {
                    if !replayed {
                        buffer.put_u8(ie.iei);
                        buffer.put_slice(&ie.data);
                    }
                }
                Ok(())
            }
        }

        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                const TABLE_ORDER: &[&[u8]] = &[$(&[$($iei),+]),*];
                #[allow(unused_variables)]
                let table_index = |iei: u8| TABLE_ORDER.iter().position(|group| group.contains(&iei));
                $(
                    // TS 24.301 and TS 24.501 §7.5.1: a missing or syntactically
                    // incorrect mandatory IE is reported as such.
                    let before = buffer.remaining();
                    #[allow(unused_mut)]
                    let mut decode_field = || -> Result<$mtype> {
                        Ok(nas_message!(@decode_mand buffer, $mtype $(, $mattr)?))
                    };
                    let $mfield = decode_field()
                        .map_err(|_| NasError::InvalidMandatoryIe(stringify!($mfield)))?;
                    #[allow(unused_variables)]
                    let wire_length = before - buffer.remaining();
                    {
                        #[allow(unused_imports)]
                        use crate::common::{
                            IeLengthCheckProbe, ReceiverSyntaxCheckProbe, ViaIeLengthCheck,
                            ViaNoIeLengthCheck, ViaNoReceiverSyntaxCheck, ViaReceiverSyntaxCheck,
                        };
                        if (&ReceiverSyntaxCheckProbe(&$mfield)).receiver_syntax_result()
                            == Some(false)
                            || (&IeLengthCheckProbe(&$mfield)).receiver_length_result()
                                == Some(false)
                            $(|| wire_length < $mmin)?
                        {
                            return Err(NasError::InvalidMandatoryIe(stringify!($mfield)));
                        }
                    }
                )*
                let mut message = Self::new( $($mfield),* );
                #[allow(unused_mut, unused_variables)]
                let mut furthest_optional_index: Option<usize> = None;
                #[allow(unused_mut, unused_variables)]
                let mut seen_optional_indices = vec![false; TABLE_ORDER.len()];
                while buffer.has_remaining() {
                    if buffer.remaining() < 1 { break; }
                    let peek = buffer[0];
                    let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };
                    match iei {
                        $( $($iei)|+ => {
                            let start = buffer.clone();
                            let index = table_index(iei).unwrap_or(0);
                            let repeated = seen_optional_indices[index];
                            seen_optional_indices[index] = true;
                            let out_of_sequence = furthest_optional_index
                                .is_some_and(|furthest| index < furthest);
                            furthest_optional_index = Some(
                                furthest_optional_index.map_or(index, |furthest| furthest.max(index))
                            );
                            let ignored_reason;
                            if !repeated && !out_of_sequence {
                                let mut probe_bytes = buffer.clone();
                                let probe = &mut probe_bytes;
                                let mut parse_optional = || -> Result<Option<$otype>> {
                                    Ok(nas_message!(@decode_opt probe, $ofield, $otype $(, $oattr)?))
                                };
                                let parsed = parse_optional();
                                match parsed {
                                    Ok(Some(value)) => {
                                        let length = buffer.remaining() - probe_bytes.remaining();
                                        #[allow(unused_imports)]
                                        use crate::common::{
                                            IeLengthCheckProbe, ReceiverSyntaxCheckProbe,
                                            ViaIeLengthCheck, ViaNoIeLengthCheck,
                                            ViaNoReceiverSyntaxCheck, ViaReceiverSyntaxCheck,
                                        };
                                        if (&ReceiverSyntaxCheckProbe(&value)).receiver_syntax_result()
                                            == Some(false)
                                            || (&IeLengthCheckProbe(&value)).receiver_length_result()
                                                == Some(false)
                                            $(|| length < $omin)?
                                        {
                                            buffer.advance(length);
                                            ignored_reason = crate::common::IgnoredIeReason::Malformed;
                                        } else {
                                            buffer.advance(length);
                                            message.$ofield = Some(value);
                                            message.optional_ie_order.push(crate::common::OptionalIeOrder::Known(iei));
                                            continue;
                                        }
                                    }
                                    Ok(None) => {
                                        let length = buffer.remaining() - probe_bytes.remaining();
                                        buffer.advance(length);
                                        ignored_reason = crate::common::IgnoredIeReason::Malformed;
                                    }
                                    // A truncated optional IE is syntactically incorrect
                                    // and therefore absent for receiver semantics
                                    // (TS 24.301/24.501 §7.7.1). Its remaining raw
                                    // octets are retained for diagnostics and relay.
                                    Err(_) => {
                                        buffer.advance(buffer.remaining());
                                        ignored_reason = crate::common::IgnoredIeReason::Malformed;
                                    }
                                }
                            } else {
                                ignored_reason = if repeated {
                                    crate::common::IgnoredIeReason::Repeated
                                } else {
                                    crate::common::IgnoredIeReason::OutOfSequence
                                };
                                // Only the first occurrence is handled (§7.6.3), and a
                                // non-comprehension-required out-of-sequence IE is
                                // ignored (§7.6.2). Decode on a clone solely to find its
                                // exact known format, without assigning its value.
                                let mut probe_bytes = buffer.clone();
                                let probe = &mut probe_bytes;
                                let mut parse_repetition = || -> Result<()> {
                                    let _ = nas_message!(@decode_opt probe, $ofield, $otype $(, $oattr)?);
                                    Ok(())
                                };
                                let parsed = parse_repetition();
                                let length = match parsed {
                                    Ok(()) => buffer.remaining() - probe_bytes.remaining(),
                                    Err(_) => buffer.remaining(),
                                };
                                buffer.advance(length);
                            }
                            let raw = &start[..start.len() - buffer.remaining()];
                            message.optional_ie_order.push(crate::common::OptionalIeOrder::Ignored(
                                message.unknown_ies.len(),
                                ignored_reason,
                            ));
                            message.unknown_ies.push(UnknownIe { iei: raw[0], data: raw[1..].to_vec() });
                        } )*
                        _ => {
                            // Unknown IEI: skip it by the TS 24.007 §11.2.4 format
                            // rule and keep its octets for re-encoding.
                            let length = match crate::common::generic_ie_length(
                                &buffer,
                                UNKNOWN_TLVE_START,
                            ) {
                                Ok(length) => length,
                                Err(_) if !(peek <= 0x0f || matches!(peek, 0x7e | 0x7f)) => {
                                    // A malformed unknown non-comprehension-required IE is
                                    // ignored (§7.6.1). Its boundary is unknowable, so the
                                    // rest of the PDU is retained as that IE.
                                    buffer.remaining()
                                }
                                // An unknown IE encoded as "comprehension required" is
                                // invalid mandatory information (§7.5.1), also when it
                                // is cut short.
                                Err(_) => return Err(NasError::InvalidMandatoryIe("unknown_ies")),
                            };
                            let raw = buffer.split_to(length);
                            message.optional_ie_order.push(crate::common::OptionalIeOrder::Unknown(message.unknown_ies.len()));
                            message.unknown_ies.push(UnknownIe { iei: raw[0], data: raw[1..].to_vec() });
                        }
                    }
                }
                Ok(message)
            }
        }
    };

    (@canonical_iei $first:literal $(| $rest:literal)*) => {
        $first
    };

    (@sender_mlength $findings:ident, $self:ident, $field:ident
        $(, $attr:ident)? {wire_len $min:expr, $max:expr}) => {
        if !(|| -> crate::common::Result<usize> {
            let mut encoded_storage = bytes::BytesMut::new();
            let encoded = &mut encoded_storage;
            nas_message!(@encode_mand encoded, $self, $field $(, $attr)?);
            Ok(encoded_storage.len())
        })()
        .is_ok_and(|length| ($min..=$max).contains(&length))
        {
            $findings.push(crate::common::ValidationError {
                severity: crate::common::Severity::Error,
                field: stringify!($field),
                message: format!("message-table length is outside {}..={}", $min, $max),
            });
        }
    };
    (@sender_mlength $findings:ident, $self:ident, $field:ident $(, $attr:ident)?) => {};

    (@sender_olength $findings:ident, $self:ident, $field:ident, $ty:ty,
        ($($iei:literal)|+) $(, $attr:ident)? {wire_len $min:expr, $max:expr}) => {
        if $self.$field.is_some()
            && !(|| -> crate::common::Result<usize> {
                let mut encoded_storage = bytes::BytesMut::new();
                let encoded = &mut encoded_storage;
                let iei = nas_message!(@canonical_iei $($iei)|+);
                nas_message!(@encode_opt encoded, $self, iei, $field, $ty $(, $attr)?);
                Ok(encoded_storage.len())
            })()
            .is_ok_and(|length| ($min..=$max).contains(&length))
        {
            $findings.push(crate::common::ValidationError {
                severity: crate::common::Severity::Error,
                field: stringify!($field),
                message: format!("message-table length is outside {}..={}", $min, $max),
            });
        }
    };
    (@sender_olength $findings:ident, $self:ident, $field:ident, $ty:ty,
        ($($iei:literal)|+) $(, $attr:ident)?) => {};

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

    // Optional decode rules return `None` for an IE the receiver treats as
    // not present, which is then kept with the unknown IEs.

    // Standard optional decode (TLV/TLV-E and TV-1): IE's own decode reads the IEI
    (@decode_opt $buf:ident, $field:ident, $ty:ty) => {
        Some(<$ty>::decode($buf)?)
    };

    // TV-1 standard decode: same as standard (the IE reads the whole byte)
    (@decode_opt $buf:ident, $field:ident, $ty:ty, tv1) => {
        Some(<$ty>::decode($buf)?)
    };

    // opt_type: skip IEI byte, then decode as V/LV/LV-E
    (@decode_opt $buf:ident, $field:ident, $ty:ty, opt_type) => {{
        $buf.advance(1);
        Some(<$ty>::decode($buf)?)
    }};

    // v_as_tv1: read byte, extract value from low nibble
    (@decode_opt $buf:ident, $field:ident, $ty:ty, v_as_tv1) => {{
        let byte = $buf.get_u8();
        Some(<$ty>::new(byte & 0x0F))
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
