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
/// - `[v_as_tlv]` One-byte V used as TLV: encode writes IEI and length 1, decode checks length 1
/// - `[v_as_tv1]` V-type used as TV-1: encode packs `IEI | (value & 0x0F)`, decode extracts low nibble
///
/// Mandatory field annotations:
/// - (none)              Standard: `Type::decode(buffer)?`
/// - `[decode_value_only]` Uses `Type::decode_value_only(buffer)?`
/// - `[tlv_as_lv]`         Reuses a TLV type as an untagged mandatory LV field
/// - `[tlve_as_lve]`       Reuses a TLV-E type as an untagged mandatory LV-E field
macro_rules! nas_message {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            mandatory { $($mfield:ident : $mtype:ty $([$mattr:ident])? ),* $(,)? }
            optional { $($( $iei:literal )|+ => $ofield:ident : $otype:ty $([$oattr:ident])? ),* $(,)? }
        }
    ) => {
        $(#[$meta])*
        #[allow(missing_docs)]
        #[derive(Debug, Clone)]
        pub struct $name {
            $( pub $mfield: $mtype, )*
            $( pub $ofield: Option<$otype>, )*
            /// IEs not recognized by this version of the codec.
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
                    pub fn [< with_ $mfield _value >](mut self, value: $mtype) -> Self {
                        self.[< set_ $mfield _value >](value);
                        self
                    }

                    pub fn [< set_ $mfield _value >](&mut self, value: $mtype) -> &mut Self {
                        self.$mfield = value;
                        self
                    }

                    pub fn [< get_ $mfield >](&self) -> &$mtype {
                        &self.$mfield
                    }

                    pub fn [< get_ $mfield _mut >](&mut self) -> &mut $mtype {
                        &mut self.$mfield
                    }
                )*

                $(
                    pub fn [< set_ $ofield >](mut self, value: $otype) -> Self {
                        self.[< set_ $ofield _mut >](value);
                        self
                    }

                    pub fn [< with_ $ofield >](mut self, value: $otype) -> Self {
                        self.[< set_ $ofield _mut >](value);
                        self
                    }

                    pub fn [< set_ $ofield _mut >](&mut self, value: $otype) -> &mut Self {
                        self.$ofield = Some(value);
                        self
                    }

                    pub fn [< get_ $ofield >](&self) -> Option<&$otype> {
                        self.$ofield.as_ref()
                    }

                    pub fn [< get_ $ofield _mut >](&mut self) -> Option<&mut $otype> {
                        self.$ofield.as_mut()
                    }

                    pub fn [< has_ $ofield >](&self) -> bool {
                        self.$ofield.is_some()
                    }

                    pub fn [< clear_ $ofield >](&mut self) -> Option<$otype> {
                        self.$ofield.take()
                    }
                )*
            }
        }

        nas_message_impl_default!($name $(, $mfield)*);

        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                $( nas_message!(@encode_mand buffer, self, $mfield $(, $mattr)?); )*
                for order in &self.optional_ie_order {
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
                    }
                }
                $(
                    if !self.optional_ie_order.iter().any(|order| matches!(order,
                        crate::common::OptionalIeOrder::Known(iei) if matches!(*iei, $($iei)|+)
                    )) {
                        nas_message!(@encode_opt buffer, self, nas_message!(@canonical_iei $($iei)|+), $ofield, $otype $(, $oattr)?);
                    }
                )*
                for (index, ie) in self.unknown_ies.iter().enumerate() {
                    if !self.optional_ie_order.contains(&crate::common::OptionalIeOrder::Unknown(index)) {
                        buffer.put_u8(ie.iei);
                        buffer.put_slice(&ie.data);
                    }
                }
                Ok(())
            }
        }

        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                $( let $mfield = nas_message!(@decode_mand buffer, $mtype $(, $mattr)?); )*
                let mut message = Self::new( $($mfield),* );
                while buffer.has_remaining() {
                    if buffer.remaining() < 1 { break; }
                    let peek = buffer[0];
                    let iei = if peek >= 0x80 { peek & 0xF0 } else { peek };
                    match iei {
                        $( $($iei)|+ => {
                            nas_message!(@decode_opt buffer, message, $ofield, $otype $(, $oattr)?);
                            message.optional_ie_order.push(crate::common::OptionalIeOrder::Known(iei));
                        } )*
                        _ => {
                            let unknown_index = message.unknown_ies.len();
                            // Unknown IEI — collect per TS 24.007 §11.2.4.
                            if peek >= 0x80 {
                                // Bit 8 = 1: TV type 1 — entire IE is one octet
                                buffer.advance(1);
                                message.unknown_ies.push(UnknownIe { iei: peek, data: Vec::new() });
                            } else if (UNKNOWN_TLVE_START..=0x7f).contains(&peek) {
                                // The TLV-E range starts at 0x70 in 5GS and 0x78 in EPS.
                                // TLV-E type 6 — next 2 octets are length (u16 BE)
                                buffer.advance(1);
                                if buffer.remaining() < 2 {
                                    return Err(NasError::BufferTooShort);
                                }
                                let mut lb = [0u8; 2];
                                buffer.copy_to_slice(&mut lb);
                                let skip_len = helpers::be16_to_u16(lb) as usize;
                                if buffer.remaining() < skip_len {
                                    return Err(NasError::BufferTooShort);
                                }
                                let mut data = Vec::with_capacity(2 + skip_len);
                                data.extend_from_slice(&lb);
                                let mut val = vec![0u8; skip_len];
                                buffer.copy_to_slice(&mut val);
                                data.extend_from_slice(&val);
                                message.unknown_ies.push(UnknownIe { iei: peek, data });
                            } else {
                                // Bit 8 = 0, bits 7-5 != "111":
                                // TLV type 4 — next octet is length (u8)
                                buffer.advance(1);
                                if buffer.remaining() < 1 {
                                    return Err(NasError::BufferTooShort);
                                }
                                let len_byte = buffer.get_u8();
                                let skip_len = len_byte as usize;
                                if buffer.remaining() < skip_len {
                                    return Err(NasError::BufferTooShort);
                                }
                                let mut data = Vec::with_capacity(1 + skip_len);
                                data.push(len_byte);
                                let mut val = vec![0u8; skip_len];
                                buffer.copy_to_slice(&mut val);
                                data.extend_from_slice(&val);
                                message.unknown_ies.push(UnknownIe { iei: peek, data });
                            }
                            message.optional_ie_order.push(crate::common::OptionalIeOrder::Unknown(unknown_index));
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

    // One-byte value whose optional message-table form includes a TLV length.
    (@encode_opt $buf:ident, $self:ident, $iei:expr, $field:ident, $ty:ty, v_as_tlv) => {
        if let Some(ref value) = $self.$field {
            helpers::encode_optional_type($buf, $iei)?;
            $buf.put_u8(1);
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
    (@decode_opt $buf:ident, $msg:ident, $field:ident, $ty:ty) => {
        if $msg.$field.is_some() {
            return Err(NasError::DecodingError(format!("Duplicate NAS optional IE {}", stringify!($field))));
        }
        $msg.$field = Some(<$ty>::decode($buf)?);
    };

    // TV-1 standard decode: same as standard (the IE reads the whole byte)
    (@decode_opt $buf:ident, $msg:ident, $field:ident, $ty:ty, tv1) => {
        if $msg.$field.is_some() {
            return Err(NasError::DecodingError(format!("Duplicate NAS optional IE {}", stringify!($field))));
        }
        $msg.$field = Some(<$ty>::decode($buf)?);
    };

    // opt_type: skip IEI byte, then decode as V/LV/LV-E
    (@decode_opt $buf:ident, $msg:ident, $field:ident, $ty:ty, opt_type) => {
        if $msg.$field.is_some() {
            return Err(NasError::DecodingError(format!("Duplicate NAS optional IE {}", stringify!($field))));
        }
        $buf.advance(1);
        $msg.$field = Some(<$ty>::decode($buf)?);
    };

    // One-byte value carried by a TLV field in this message table.
    (@decode_opt $buf:ident, $msg:ident, $field:ident, $ty:ty, v_as_tlv) => {
        if $msg.$field.is_some() {
            return Err(NasError::DecodingError(format!("Duplicate NAS optional IE {}", stringify!($field))));
        }
        if $buf.remaining() < 2 {
            return Err(NasError::BufferTooShort);
        }
        $buf.advance(1);
        if $buf.get_u8() != 1 {
            return Err(NasError::DecodingError(format!("Invalid NAS optional IE length for {}", stringify!($field))));
        }
        $msg.$field = Some(<$ty>::decode($buf)?);
    };

    // v_as_tv1: read byte, extract value from low nibble
    (@decode_opt $buf:ident, $msg:ident, $field:ident, $ty:ty, v_as_tv1) => {
        if $msg.$field.is_some() {
            return Err(NasError::DecodingError(format!("Duplicate NAS optional IE {}", stringify!($field))));
        }
        let byte = $buf.get_u8();
        $msg.$field = Some(<$ty>::new(byte & 0x0F));
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
            paste::paste! {
                pub fn [< set_ $alias >](mut self, value: $ty) -> Self {
                    self.[< set_ $alias _mut >](value);
                    self
                }

                pub fn [< with_ $alias >](mut self, value: $ty) -> Self {
                    self.[< set_ $alias _mut >](value);
                    self
                }

                pub fn [< set_ $alias _mut >](&mut self, value: $ty) -> &mut Self {
                    self.$field = Some(value);
                    self
                }

                pub fn [< get_ $alias >](&self) -> Option<&$ty> {
                    self.$field.as_ref()
                }

                pub fn [< get_ $alias _mut >](&mut self) -> Option<&mut $ty> {
                    self.$field.as_mut()
                }

                pub fn [< has_ $alias >](&self) -> bool {
                    self.$field.is_some()
                }

                pub fn [< clear_ $alias >](&mut self) -> Option<$ty> {
                    self.$field.take()
                }
            }
        }
    };
}

pub(crate) use nas_message_optional_alias;
