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

//! Shared NAS information element format and value-access macros.

// ── NAS IE format macros ────────────────────────────────────────────────────
//
// Each macro defines a struct of the value of an IE, with `new()`, `Encode`
// and `Decode`. An IE type is its value: it encodes as the IE is in a
// message without its IEI, which is that of the message table and which the
// message writes (TS 24.007 §11.2.1.1).

/// The struct of an IE type whose value is a `$value`, with `new()`.
macro_rules! nas_ie_struct {
    ($(#[$meta:meta])* $name:ident, $doc:literal, octets) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            #[doc = $doc]
            pub value: crate::common::Octets,
        }
        impl $name {
            /// Build the IE from its value.
            pub fn new(value: impl Into<crate::common::Octets>) -> Self {
                Self { value: value.into() }
            }

            /// The IE without a value yet.
            #[allow(dead_code)]
            pub(crate) fn blank() -> Self {
                Self { value: Default::default() }
            }
        }
        #[cfg(all(feature = "serde", feature = "std"))]
        crate::common::readable::readable!(struct $name { value });
        #[cfg(feature = "serde")]
        crate::common::view::ie_tree!($name, <$name>::blank());
    };
    // A value of one or two octets: the IE is `Copy`, as its value is.
    ($(#[$meta:meta])* $name:ident, $doc:literal, $value:ty) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            #[doc = $doc]
            pub value: $value,
        }
        impl $name {
            /// Build the IE from its value.
            pub fn new(value: $value) -> Self {
                Self { value }
            }

            /// The IE without a value yet.
            #[allow(dead_code)]
            pub(crate) fn blank() -> Self {
                Self { value: Default::default() }
            }
        }
        #[cfg(all(feature = "serde", feature = "std"))]
        crate::common::readable::readable!(struct $name { value });
        #[cfg(feature = "serde")]
        crate::common::view::ie_tree!($name, <$name>::blank());
    };
}

/// An IE whose value is one octet: a type 3 IE of one octet, or the value
/// of a type 1 IE in the bits of its octet.
macro_rules! nas_ie_v {
    ($(#[$meta:meta])* $name:ident) => {
        crate::common::nas_ie_struct!($(#[$meta])* $name, "Value octet.", u8);
        impl Encode for $name {
            fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
                buffer.push(self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
                Ok(Self { value: buffer.take(1)?[0] })
            }
        }
    };
}

/// An IE whose value is two octets, read as a number.
macro_rules! nas_ie_v_u16 {
    ($(#[$meta:meta])* $name:ident) => {
        crate::common::nas_ie_struct!($(#[$meta])* $name, "Value octets.", u16);
        impl Encode for $name {
            fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
                buffer.extend_from_slice(&self.value.to_be_bytes());
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
                let octets = buffer.take(2)?;
                Ok(Self { value: u16::from_be_bytes([octets[0], octets[1]]) })
            }
        }
    };
}

/// An IE whose value is `$len` octets (type 3).
macro_rules! nas_ie_v_fixed {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        crate::common::nas_ie_struct!($(#[$meta])* $name, "Value octets.", octets);
        impl Encode for $name {
            fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
                if self.value.len() != $len {
                    return Err(NasError::EncodingError(format!(
                        "{} has {} octets, and {} are written",
                        stringify!($name), $len, self.value.len()
                    )));
                }
                buffer.extend_from_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
                Ok(Self { value: buffer.take($len)?.into() })
            }
        }
    };
}

/// An IE whose value follows a length indicator of one octet (type 4).
macro_rules! nas_ie_lv {
    ($(#[$meta:meta])* $name:ident) => {
        crate::common::nas_ie_struct!($(#[$meta])* $name, "Value octets.", octets);
        impl Encode for $name {
            fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
                let Ok(length) = u8::try_from(self.value.len()) else {
                    return Err(NasError::EncodingError(format!(
                        "{} has a length indicator of one octet, and {} octets are written",
                        stringify!($name), self.value.len()
                    )));
                };
                buffer.push(length);
                buffer.extend_from_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
                let length = usize::from(buffer.take(1)?[0]);
                Ok(Self { value: buffer.take(length)?.into() })
            }
        }
    };
}

/// An IE whose value follows a length indicator of two octets (type 6).
macro_rules! nas_ie_lve {
    ($(#[$meta:meta])* $name:ident) => {
        crate::common::nas_ie_struct!($(#[$meta])* $name, "Value octets.", octets);
        impl Encode for $name {
            fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
                let Ok(length) = u16::try_from(self.value.len()) else {
                    return Err(NasError::EncodingError(format!(
                        "{} has a length indicator of two octets, and {} octets are written",
                        stringify!($name), self.value.len()
                    )));
                };
                buffer.extend_from_slice(&length.to_be_bytes());
                buffer.extend_from_slice(&self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
                let length = buffer.take(2)?;
                let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
                Ok(Self { value: buffer.take(length)?.into() })
            }
        }
    };
}

/// An IE whose value is a half octet (type 1): bits 4 to 1 of an octet that
/// has its IEI or another half octet in bits 8 to 5. A message puts the half
/// octet beside its IEI, or beside the half octet that shares its octet. An
/// IE that has a mandatory octet to itself is that octet, with the spare
/// half octet in bits 8 to 5 of its value: this is what the type encodes
/// and decodes alone.
macro_rules! nas_ie_tv1 {
    ($(#[$meta:meta])* $name:ident) => {
        crate::common::nas_ie_struct!($(#[$meta])* $name, "Value half octet.", u8);
        impl Encode for $name {
            fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
                buffer.push(self.value);
                Ok(())
            }
        }
        impl Decode for $name {
            fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
                Ok(Self { value: buffer.take(1)?[0] })
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
/// supported". Setters extend the value with zero octets as needed. The
/// `half_octet` form applies to IEs whose value is a single `u8`, such as
/// type 1 IEs.
#[allow(unused_macros)]
macro_rules! nas_ie_flags {
    ($name:ident { $( $(#[$doc:meta])* $flag:ident: $octet:literal, $bit:literal; )* }) => {
        crate::common::nas_ie_flags!(@named $name { $($flag)* });
        impl $name {
            pastey::paste! { $(
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
                }

                #[doc = concat!("Builder form of [`Self::set_", stringify!($flag), "`].")]
                pub fn [<with_ $flag>](mut self, value: bool) -> Self {
                    self.[<set_ $flag>](value);
                    self
                }
            )* }
        }
    };
    // The flags by name, for the value of the IE in a view.
    (@named $name:ident { $($flag:ident)* }) => {
        #[cfg(all(feature = "serde", feature = "std"))]
        impl crate::common::view::Flags for $name {
            fn flags(&self) -> Vec<(&'static str, bool)> {
                vec![$((stringify!($flag), self.$flag())),*]
            }

            fn set_flag(&mut self, name: &str, value: bool) -> bool {
                pastey::paste! {
                    match name {
                        $(stringify!($flag) => self.[<set_ $flag>](value),)*
                        _ => return false,
                    }
                }
                true
            }

            fn is_empty(&self) -> bool {
                crate::common::view::FlagOctets::none(&self.value)
            }
        }
    };
    ($name:ident half_octet { $( $(#[$doc:meta])* $flag:ident: $bit:literal; )* }) => {
        crate::common::nas_ie_flags!(@named $name { $($flag)* });
        impl $name {
            pastey::paste! { $(
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
    nas_ie_flags, nas_ie_lv, nas_ie_lve, nas_ie_struct, nas_ie_tv1, nas_ie_v, nas_ie_v_fixed,
    nas_ie_v_u16,
};
