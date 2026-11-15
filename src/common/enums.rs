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
