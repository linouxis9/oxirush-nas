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

//! Shared NAS information element format macros.

// ── NAS IE format macros ────────────────────────────────────────────────────
//
// Each macro defines: pub struct, new(), Encode impl, Decode impl.
// Formats per 3GPP TS 24.007 §11.2.

/// V format: value only (u8), no type field, no length.
macro_rules! nas_ie_v {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub value: u8 }
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub value: u16 }
        impl $name {
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub value: Vec<u8> }
        impl $name {
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub length: u8, pub value: Vec<u8> }
        impl $name {
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub length: u16, pub value: Vec<u8> }
        impl $name {
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub type_field: u8, pub value: u8 }
        impl $name {
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub type_field: u8, pub value: u8 }
        impl $name {
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub type_field: u8, pub value: Vec<u8> }
        impl $name {
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub type_field: u8, pub length: u8, pub value: Vec<u8> }
        impl $name {
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
        #[allow(missing_docs)]
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name { pub type_field: u8, pub length: u16, pub value: Vec<u8> }
        impl $name {
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

pub(crate) use {
    nas_ie_lv, nas_ie_lve, nas_ie_tlv, nas_ie_tlve, nas_ie_tv, nas_ie_tv_fixed, nas_ie_tv1,
    nas_ie_v, nas_ie_v_fixed, nas_ie_v_u16,
};
