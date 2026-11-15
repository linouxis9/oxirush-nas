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

//! The enums of the codes that the IEs carry, each written once as its table.

/// An enum of the codes of an IE, from its table: each variant with its code,
/// and with `=> "text"` its description in the words of the specification.
///
/// It writes the enum, `TryFrom<u8>` (the code back, as the error, where no
/// value has it), `From<Enum> for u8`, `description()` when the variants have
/// a text, the names of its JSON forms, and with `received { .. }` the value
/// that a receiver reads from a code that the sender rules do not give: a
/// pattern of codes, then the value, and `_ => Value` for every other code,
/// which makes `received` return the value itself rather than an `Option`.
macro_rules! nas_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($(#[$vmeta:meta])* $variant:ident = $value:literal $(=> $text:literal)?),+ $(,)?
        }
        $(received { $($received:tt)* })?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        $vis enum $name {
            $($(#[$vmeta])* $variant = $value,)+
        }

        impl TryFrom<u8> for $name {
            type Error = u8;

            fn try_from(code: u8) -> core::result::Result<Self, u8> {
                match code {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(code),
                }
            }
        }

        impl From<$name> for u8 {
            fn from(value: $name) -> u8 {
                value as u8
            }
        }

        $crate::common::enums::nas_enum!(@text $name $($variant $(=> $text)?),+);
        $($crate::common::enums::nas_enum!(@received $name [] $($received)*);)?

        #[cfg(feature = "tree")]
        $crate::common::readable::readable!(enum $name { $($variant),+ });
        #[cfg(feature = "tree")]
        $crate::common::readable::serde_by_readable!($name);
    };

    // The description of each variant, where every one has a text.
    (@text $name:ident $($variant:ident => $text:literal),+) => {
        impl $name {
            /// The description of the value, in the words of its table.
            pub fn description(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }
    };
    (@text $name:ident $($variant:ident),+) => {};

    // The rules of a receiver: gathered one by one, until `_` or the end.
    (@received $name:ident [$(($code:pat) $to:ident)*] _ => $fallback:ident $(,)?) => {
        impl $name {
            /// The value that a receiver reads from `code`: that of the code,
            /// or the one that its table has a receiver read instead.
            pub fn received(code: u8) -> Self {
                match code {
                    $($code => Self::$to,)*
                    _ => Self::try_from(code).unwrap_or(Self::$fallback),
                }
            }
        }
    };
    (@received $name:ident [$($rules:tt)*] $code:pat => $to:ident $(, $($rest:tt)*)?) => {
        $crate::common::enums::nas_enum!(@received $name [$($rules)* ($code) $to] $($($rest)*)?);
    };
    (@received $name:ident [$(($code:pat) $to:ident)*]) => {
        impl $name {
            /// The value that a receiver reads from `code`: that of the code,
            /// the one that its table has a receiver read instead, or `None`.
            pub fn received(code: u8) -> Option<Self> {
                match code {
                    $($code => Some(Self::$to),)*
                    _ => Self::try_from(code).ok(),
                }
            }
        }
    };
}

pub(crate) use nas_enum;

/// The readable form of a table of values that `named_values!` of
/// oxirush-utils writes: a value by its name in a tree, and one that the
/// table does not name by its number. A name is read however it is written,
/// and the error for one that does not exist lists those that do.
macro_rules! values_readable {
    ($($name:ty),+ $(,)?) => {$(
        #[cfg(feature = "tree")]
        impl $crate::common::readable::Readable for $name {
            const TAKES: &'static oxirush_utils::tree::Takes =
                &oxirush_utils::tree::Takes::Named(<$name>::NAMED);

            fn shown(&self, _: &'static str) -> oxirush_utils::tree::Value {
                match self.tree_name() {
                    Some(name) => name.into(),
                    None => self.value().into(),
                }
            }

            fn read(
                value: &oxirush_utils::tree::Value,
            ) -> core::result::Result<Self, alloc::string::String> {
                let (at, contents) = $crate::common::readable::variant(value, <$name>::NAMED)?;
                $crate::common::readable::unit_variant(<$name>::NAMED[at], contents)?;
                Ok(Self::from_value(<$name>::NAMES[at].0))
            }
        }

        #[cfg(feature = "tree")]
        $crate::common::readable::serde_by_readable!($name);
    )+};
}

pub(crate) use values_readable;
