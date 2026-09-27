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

//! Shared NAS information element format and value-access macros.

// ── NAS IE format macros ────────────────────────────────────────────────────
//
// Each macro defines: pub struct, new(), Encode impl, Decode impl.
// Formats per 3GPP TS 24.007 §11.2.

/// V format: value only (u8), no type field, no length.
macro_rules! nas_ie_v {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Value octet.
            pub value: u8,
        }
        impl $name {
            /// Create a new instance from raw value byte.
            pub fn new(value: u8) -> Self { Self { value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8(self.value); Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 1 { return Err(NasError::BufferTooShort); }
                Ok(Self { value: buffer.get_u8() })
            }
        }
    };
}

/// V format with u16 value.
macro_rules! nas_ie_v_u16 {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Value octets.
            pub value: u16,
        }
        impl $name {
            /// Build the IE from its value.
            pub fn new(value: u16) -> Self { Self { value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u16(self.value); Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 2 { return Err(NasError::BufferTooShort); }
                Ok(Self { value: buffer.get_u16() })
            }
        }
    };
}

/// V format with a fixed multi-octet value.
macro_rules! nas_ie_v_fixed {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Value octets.
            pub value: Vec<u8>,
        }
        impl $name {
            /// Build the IE from its value.
            pub fn new(value: Vec<u8>) -> Self { Self { value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                if self.value.len() != $len {
                    return Err(NasError::EncodingError(format!(
                        "{} requires {} bytes, got {}", stringify!($name), $len, self.value.len()
                    )));
                }
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < $len { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; $len];
                buffer.copy_to_slice(&mut value);
                Ok(Self { value })
            }
        }
    };
}

/// LV format: length (u8) + value, no type field. Mandatory variable-length IEs.
macro_rules! nas_ie_lv {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Length octet as decoded; builders keep it equal to the value length.
            pub length: u8,
            /// Value octets.
            pub value: Vec<u8>,
        }
        impl $name {
            /// Build the IE from its value.
            pub fn new(value: Vec<u8>) -> Self {
                Self { length: value.len() as u8, value }
            }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                if self.value.len() > u8::MAX as usize || self.length as usize != self.value.len() {
                    return Err(NasError::EncodingError(format!("{} has invalid LV length", stringify!($name))));
                }
                buffer.put_u8(self.length);
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 1 { return Err(NasError::BufferTooShort); }
                let length = buffer.get_u8();
                if (length as usize) > MAX_IE_VALUE_LENGTH { return Err(NasError::DecodingError(format!("IE value length {} exceeds maximum {}", length, MAX_IE_VALUE_LENGTH))); }
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { length, value })
            }
        }
    };
}

/// LV-E format: length (u16 BE) + value, no type field. Mandatory extended variable-length IEs.
macro_rules! nas_ie_lve {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Length octets as decoded; builders keep them equal to the value length.
            pub length: u16,
            /// Value octets.
            pub value: Vec<u8>,
        }
        impl $name {
            /// Build the IE from its value.
            pub fn new(value: Vec<u8>) -> Self {
                Self { length: value.len() as u16, value }
            }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                if self.value.len() > u16::MAX as usize || self.length as usize != self.value.len() {
                    return Err(NasError::EncodingError(format!("{} has invalid LV-E length", stringify!($name))));
                }
                buffer.put_slice(&helpers::u16_to_be16(self.length));
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 2 { return Err(NasError::BufferTooShort); }
                let mut lb = [0u8; 2];
                buffer.copy_to_slice(&mut lb);
                let length = helpers::be16_to_u16(lb);
                if (length as usize) > MAX_IE_VALUE_LENGTH { return Err(NasError::DecodingError(format!("IE value length {} exceeds maximum {}", length, MAX_IE_VALUE_LENGTH))); }
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { length, value })
            }
        }
    };
}

/// TV-1 format: type (4 bits) + value (4 bits) packed in 1 byte. Optional half-byte IEs.
macro_rules! nas_ie_tv1 {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Type field (IEI) as decoded; a message encodes the IEI of its table.
            pub type_field: u8,
            /// Value octet.
            pub value: u8,
        }
        impl $name {
            /// Build the IE from its value; the type field is 0 until a message sets it.
            pub fn new(value: u8) -> Self { Self { type_field: 0, value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                if self.type_field > 0x0f || self.value > 0x0f {
                    return Err(NasError::EncodingError("NAS TV1 IE exceeds four-bit field".into()));
                }
                buffer.put_u8((self.type_field << 4) | (self.value & 0x0F));
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 1 { return Err(NasError::BufferTooShort); }
                let byte = buffer.get_u8();
                Ok(Self { type_field: byte >> 4, value: byte & 0x0F })
            }
        }
    };
}

/// TV format: type (u8) + value (u8). Optional fixed 1-byte value IEs.
macro_rules! nas_ie_tv {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Type field (IEI) as decoded; a message encodes the IEI of its table.
            pub type_field: u8,
            /// Value octet.
            pub value: u8,
        }
        impl $name {
            /// Build the IE from its value; the type field is 0 until a message sets it.
            pub fn new(value: u8) -> Self { Self { type_field: 0, value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                buffer.put_u8(self.type_field);
                buffer.put_u8(self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 2 { return Err(NasError::BufferTooShort); }
                Ok(Self { type_field: buffer.get_u8(), value: buffer.get_u8() })
            }
        }
    };
}

/// TV format with fixed-length Vec<u8> value. Optional fixed multi-byte value IEs.
macro_rules! nas_ie_tv_fixed {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Type field (IEI) as decoded; a message encodes the IEI of its table.
            pub type_field: u8,
            /// Value octets.
            pub value: Vec<u8>,
        }
        impl $name {
            /// Build the IE from its value; the type field is 0 until a message sets it.
            pub fn new(value: Vec<u8>) -> Self { Self { type_field: 0, value } }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                if self.value.len() != $len {
                    return Err(NasError::EncodingError(format!("{} requires {} bytes", stringify!($name), $len)));
                }
                buffer.put_u8(self.type_field);
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 1 + $len { return Err(NasError::BufferTooShort); }
                let type_field = buffer.get_u8();
                let mut value = vec![0; $len];
                buffer.copy_to_slice(&mut value);
                Ok(Self { type_field, value })
            }
        }
    };
}

/// TLV format: type (u8) + length (u8) + value. The most common optional IE format.
macro_rules! nas_ie_tlv {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Type field (IEI) as decoded; a message encodes the IEI of its table.
            pub type_field: u8,
            /// Length octet as decoded; builders keep it equal to the value length.
            pub length: u8,
            /// Value octets.
            pub value: Vec<u8>,
        }
        impl $name {
            /// Build the IE from its value; the type field is 0 until a message sets it.
            pub fn new(value: Vec<u8>) -> Self {
                Self { type_field: 0, length: value.len() as u8, value }
            }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                if self.value.len() > u8::MAX as usize || self.length as usize != self.value.len() {
                    return Err(NasError::EncodingError(format!("{} has invalid TLV length", stringify!($name))));
                }
                buffer.put_u8(self.type_field);
                buffer.put_u8(self.length);
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 2 { return Err(NasError::BufferTooShort); }
                let type_field = buffer.get_u8();
                let length = buffer.get_u8();
                if (length as usize) > MAX_IE_VALUE_LENGTH { return Err(NasError::DecodingError(format!("IE value length {} exceeds maximum {}", length, MAX_IE_VALUE_LENGTH))); }
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { type_field, length, value })
            }
        }
    };
}

/// TLV-E format: type (u8) + length (u16 BE) + value. Optional extended variable-length IEs.
macro_rules! nas_ie_tlve {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            /// Type field (IEI) as decoded; a message encodes the IEI of its table.
            pub type_field: u8,
            /// Length octets as decoded; builders keep them equal to the value length.
            pub length: u16,
            /// Value octets.
            pub value: Vec<u8>,
        }
        impl $name {
            /// Build the IE from its value; the type field is 0 until a message sets it.
            pub fn new(value: Vec<u8>) -> Self {
                Self { type_field: 0, length: value.len() as u16, value }
            }
        }
        impl Encode for $name {
            fn encode(&self, buffer: &mut BytesMut) -> Result<()> {
                if self.value.len() > u16::MAX as usize || self.length as usize != self.value.len() {
                    return Err(NasError::EncodingError(format!("{} has invalid TLV-E length", stringify!($name))));
                }
                buffer.put_u8(self.type_field);
                buffer.put_slice(&helpers::u16_to_be16(self.length));
                buffer.put_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode(buffer: &mut Bytes) -> Result<Self> {
                if buffer.remaining() < 3 { return Err(NasError::BufferTooShort); }
                let type_field = buffer.get_u8();
                let mut lb = [0u8; 2];
                buffer.copy_to_slice(&mut lb);
                let length = helpers::be16_to_u16(lb);
                if (length as usize) > MAX_IE_VALUE_LENGTH { return Err(NasError::DecodingError(format!("IE value length {} exceeds maximum {}", length, MAX_IE_VALUE_LENGTH))); }
                if buffer.remaining() < length as usize { return Err(NasError::BufferTooShort); }
                let mut value = vec![0; length as usize];
                buffer.copy_to_slice(&mut value);
                Ok(Self { type_field, length, value })
            }
        }
    };
}

/// Add raw value access to an existing length-prefixed NAS IE type.
macro_rules! nas_opaque_ie {
    ($name:ident, $spec:literal, $section:literal) => {
        impl $name {
            #[doc = concat!("Value octets (TS ", $spec, " §", $section, ").")]
            pub fn data(&self) -> &[u8] {
                &self.value
            }

            /// Build from value octets.
            pub fn from_data(data: Vec<u8>) -> Self {
                Self::new(data)
            }

            /// Replace value octets and their declared length.
            pub fn set_data(&mut self, data: Vec<u8>) -> &mut Self {
                self.length = data.len() as _;
                self.value = data;
                self
            }

            /// Builder form of [`Self::set_data`].
            pub fn with_data(mut self, data: Vec<u8>) -> Self {
                self.set_data(data);
                self
            }
        }
    };
}

/// Add single-bit flag accessors to an IE.
///
/// Each entry gives the flag name, the value octet index (0 is the first
/// octet after any length field), and the bit as numbered in the
/// specifications (1 is the least significant bit). Getters return `false`
/// when the octet is absent, so optional trailing octets read as "not
/// supported". Setters extend the value with zero octets as needed and keep
/// the declared length in sync. The `half_octet` form applies to IEs whose
/// value is a single `u8`, such as type 1 IEs.
#[allow(unused_macros)]
macro_rules! nas_ie_flags {
    ($name:ident { $( $(#[$doc:meta])* $flag:ident: $octet:literal, $bit:literal; )* }) => {
        impl $name {
            paste::paste! { $(
                $(#[$doc])*
                pub fn $flag(&self) -> bool {
                    self.value
                        .get($octet)
                        .is_some_and(|octet| octet & (1 << ($bit - 1)) != 0)
                }

                #[doc = concat!("Set [`Self::", stringify!($flag), "`], extending the value with zero octets as needed.")]
                pub fn [<set_ $flag>](&mut self, value: bool) {
                    if self.value.len() <= $octet {
                        self.value.resize($octet + 1, 0);
                    }
                    if value {
                        self.value[$octet] |= 1 << ($bit - 1);
                    } else {
                        self.value[$octet] &= !(1 << ($bit - 1));
                    }
                    self.length = self.value.len() as _;
                }

                #[doc = concat!("Builder form of [`Self::set_", stringify!($flag), "`].")]
                pub fn [<with_ $flag>](mut self, value: bool) -> Self {
                    self.[<set_ $flag>](value);
                    self
                }
            )* }
        }
    };
    ($name:ident half_octet { $( $(#[$doc:meta])* $flag:ident: $bit:literal; )* }) => {
        impl $name {
            paste::paste! { $(
                $(#[$doc])*
                pub fn $flag(&self) -> bool {
                    self.value & (1 << ($bit - 1)) != 0
                }

                #[doc = concat!("Set [`Self::", stringify!($flag), "`].")]
                pub fn [<set_ $flag>](&mut self, value: bool) {
                    if value {
                        self.value |= 1 << ($bit - 1);
                    } else {
                        self.value &= !(1 << ($bit - 1));
                    }
                }

                #[doc = concat!("Builder form of [`Self::set_", stringify!($flag), "`].")]
                pub fn [<with_ $flag>](mut self, value: bool) -> Self {
                    self.[<set_ $flag>](value);
                    self
                }
            )* }
        }
    };
}

pub(crate) use {
    nas_ie_flags, nas_ie_lv, nas_ie_lve, nas_ie_tlv, nas_ie_tlve, nas_ie_tv, nas_ie_tv_fixed,
    nas_ie_tv1, nas_ie_v, nas_ie_v_fixed, nas_ie_v_u16, nas_opaque_ie,
};
