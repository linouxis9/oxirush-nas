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

//! The fields of an IE that its table describes: where the bits of each
//! field are in the octets of its value, as the figure of its clause has
//! them, and the tree of those octets, which one function writes and reads
//! for every such IE from its rows.
//!
//! A tree shows the value of the octets where its fields give every bit of
//! them back: no spare bit is set, and the IE has a length of its table.
//! That is known from the rows, without writing the value back.

/// A field of the value of an IE: its bits, from bit `low` (1 is the least
/// significant) of octet `octet` (0 is the first of the value), `width` of
/// them, and for a field split over two octets the low part in `next`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Row {
    /// The name of the field as the tree prints it.
    #[cfg(feature = "tree")]
    pub(crate) member: &'static str,
    pub(crate) octet: usize,
    pub(crate) low: u8,
    pub(crate) width: u8,
    pub(crate) next: Option<(usize, u8, u8)>,
    /// How the tree shows and reads the field.
    #[cfg(feature = "tree")]
    pub(crate) form: Form,
}

/// How a tree shows a field: a flag, or a value of a table.
#[cfg(feature = "tree")]
#[derive(Debug, Clone, Copy)]
pub(crate) enum Form {
    Flag,
    /// Its name, or the number of a value that the table does not name:
    /// `show` writes the tree of the number, `read` the number of a tree.
    Named {
        show: fn(u16) -> oxirush_utils::tree::Value,
        read: fn(&oxirush_utils::tree::Value) -> Result<u16, alloc::string::String>,
        takes: &'static oxirush_utils::tree::Takes,
    },
}

impl Row {
    /// The largest number that the field holds.
    #[cfg(feature = "tree")]
    pub(crate) const fn max(&self) -> u16 {
        let bits = match self.next {
            Some((_, _, width)) => self.width + width,
            None => self.width,
        };
        ((1u32 << bits) - 1) as u16
    }

    /// The bits of octet `octet` that the field has.
    pub(crate) const fn mask(&self, octet: usize) -> u8 {
        let mut mask = 0;
        if octet == self.octet {
            mask |= ones(self.low, self.width);
        }
        if let Some((next, low, width)) = self.next {
            if octet == next {
                mask |= ones(low, width);
            }
        }
        mask
    }

    /// The value of the field in `octets`: 0 for an octet that they do not
    /// have.
    #[cfg(feature = "tree")]
    pub(crate) fn get(&self, octets: &[u8]) -> u16 {
        let part = |octet: usize, low: u8, width: u8| {
            u16::from(octets.get(octet).copied().unwrap_or(0) >> (low - 1)) & ((1 << width) - 1)
        };
        match self.next {
            Some((next, low, width)) => {
                part(self.octet, self.low, self.width) << width | part(next, low, width)
            }
            None => part(self.octet, self.low, self.width),
        }
    }

    /// Write `value`, which fits the field, in `octets`, which have the
    /// octets of the field.
    #[cfg(feature = "tree")]
    pub(crate) fn put(&self, octets: &mut [u8], value: u16) {
        let mut part = |octet: usize, low: u8, width: u8, value: u16| {
            let mask = ones(low, width);
            octets[octet] = octets[octet] & !mask | ((value as u8) << (low - 1)) & mask;
        };
        match self.next {
            Some((next, low, width)) => {
                part(self.octet, self.low, self.width, value >> width);
                part(next, low, width, value & ((1 << width) - 1));
            }
            None => part(self.octet, self.low, self.width, value),
        }
    }

    /// How many octets the value needs to have the field.
    #[cfg(feature = "tree")]
    pub(crate) const fn octets(&self) -> usize {
        match self.next {
            Some((next, _, _)) if next > self.octet => next + 1,
            _ => self.octet + 1,
        }
    }
}

/// `width` ones from bit `low`.
const fn ones(low: u8, width: u8) -> u8 {
    (((1u16 << width) - 1) << (low - 1)) as u8
}

/// The table of an IE: its fields, and the lengths of its value.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Table {
    pub(crate) rows: &'static [Row],
    /// The least and the most octets of the value of a sender.
    pub(crate) least: usize,
    pub(crate) most: usize,
    /// The least octets of a value that a receiver takes, which a tree shows.
    #[cfg(feature = "tree")]
    pub(crate) receives: usize,
    /// Whether the octets of the value at its end that are absent or zero
    /// say the same, as they do of flags that a later release adds: none of
    /// their fields is set.
    #[cfg(feature = "tree")]
    pub(crate) trailing: bool,
}

impl Table {
    /// The bits of octet `octet` that a field has.
    pub(crate) fn mask(&self, octet: usize) -> u8 {
        self.rows.iter().fold(0, |mask, row| mask | row.mask(octet))
    }

    /// Whether the fields give every bit of `octets` back: no bit that no
    /// field has is set, and the value has a length of the table, or one
    /// whose octets past it are zero where they say nothing.
    #[cfg(feature = "tree")]
    pub(crate) fn exact(&self, octets: &[u8]) -> bool {
        let length = octets.len() >= self.receives && (self.trailing || octets.len() <= self.most);
        length && (octets.iter().enumerate()).all(|(at, octet)| octet & !self.mask(at) == 0)
    }

    /// Whether a sender of the release writes `octets`: no spare bit is
    /// set, and the value has a length of the table.
    pub(crate) fn spare_bits_are_zero(&self, octets: &[u8]) -> bool {
        (self.least..=self.most).contains(&octets.len())
            && (octets.iter().enumerate()).all(|(at, octet)| octet & !self.mask(at) == 0)
    }
}

#[cfg(feature = "tree")]
mod tree {
    use super::{Form, Row, Table};
    use crate::common::Octets;
    use crate::common::readable;
    use crate::prelude::*;
    use oxirush_utils::tree::{Map, Takes, Value};

    impl Row {
        /// The tree of the field in `octets`.
        pub(crate) fn tree(&self, octets: &[u8]) -> Value {
            let value = self.get(octets);
            match self.form {
                Form::Flag => Value::Bool(value != 0),
                Form::Named { show, .. } => show(value),
            }
        }

        /// The number of the field that `value` writes.
        pub(crate) fn read(&self, value: &Value) -> Result<u16, String> {
            let number = match self.form {
                Form::Flag => {
                    return (value.as_bool())
                        .map(u16::from)
                        .ok_or_else(|| format!("{value} is not true or false"));
                }
                Form::Named { read, .. } => read(value)?,
            };
            match number <= self.max() {
                true => Ok(number),
                false => Err(format!(
                    "{number} is more than {}, the most that its bits hold",
                    self.max()
                )),
            }
        }

        /// What the tree of the field takes.
        pub(crate) const fn takes(&self) -> &'static Takes {
            match self.form {
                Form::Flag => &Takes::Flag,
                Form::Named { takes, .. } => takes,
            }
        }
    }

    impl Table {
        /// The tree of `octets`: each field by its name, in the order of the
        /// table.
        pub(crate) fn tree(&self, octets: &[u8]) -> Value {
            let mut members = Map::new();
            for row in self.rows {
                members.push(row.member.into(), row.tree(octets));
            }
            members.into()
        }

        /// The tree of `octets` where it gives them back, else `None`.
        pub(crate) fn shown(&self, octets: &[u8]) -> Option<Value> {
            self.exact(octets).then(|| self.tree(octets))
        }

        /// Write the members of `value` in `octets`, which keep every bit
        /// that no member writes. Octets that have none yet are built from
        /// the value: the shortest of a sender that carries the members that
        /// are written, and every member written has its octet.
        pub(crate) fn write(&self, octets: &mut Octets, value: &Value) -> Result<(), String> {
            let members = (value.as_object())
                .ok_or_else(|| format!("{value} is not an object of the members of the IE"))?;
            let built = octets.is_empty();
            for (name, written) in members {
                let Some(row) =
                    (self.rows.iter()).find(|row| readable::same_name(row.member, name))
                else {
                    let names: Vec<&str> = self.rows.iter().map(|row| row.member).collect();
                    return Err(readable::none_of(name, &names, "member"));
                };
                let number = row
                    .read(written)
                    .map_err(|error| format!("{name}: {error}"))?;
                if built || row.get(octets) != number {
                    if octets.len() < row.octets() {
                        octets.resize(row.octets(), 0);
                    }
                    row.put(octets, number);
                }
            }
            if built {
                while self.trailing && octets.len() > self.least && octets.last() == Some(&0) {
                    octets.truncate(octets.len() - 1);
                }
                if members.is_empty() || octets.len() < self.least.max(1) {
                    return Err(crate::common::message_tree::too_short(value, octets.len()));
                }
            }
            Ok(())
        }

        /// What the tree of the value takes: its members.
        pub(crate) const fn takes<const N: usize>(&self) -> [(&'static str, &'static Takes); N] {
            let mut members = [("", &Takes::Flag); N];
            let mut at = 0;
            while at < N {
                members[at] = (self.rows[at].member, self.rows[at].takes());
                at += 1;
            }
            members
        }
    }
}

/// A row of `FIELDS` of an IE type, which `bits!` of oxirush-utils writes
/// once for each field of the table of the type, in the order of its
/// figure: a flag of one bit, or a value of the table `Kind`. The tree
/// names the field as the code does.
macro_rules! field_row {
    ($field:ident, $name:literal, $octet:literal, $low:literal, 1, [], []) => {
        $crate::common::field_table::Row {
            #[cfg(feature = "tree")]
            member: $crate::common::names::name!(stringify!($field)),
            octet: $octet,
            low: $low,
            width: 1,
            next: None,
            #[cfg(feature = "tree")]
            form: $crate::common::field_table::Form::Flag,
        }
    };
    ($field:ident, $name:literal, $octet:literal, $low:literal, $width:tt, [], [$kind:ident]) => {
        $crate::common::field_table::Row {
            #[cfg(feature = "tree")]
            member: $crate::common::names::name!(stringify!($field)),
            octet: $octet,
            low: $low,
            width: $width,
            next: None,
            #[cfg(feature = "tree")]
            form: $crate::common::field_table::Form::Named {
                show: |raw| match <$kind>::from_value(raw as u8).tree_name() {
                    Some(name) => name.into(),
                    None => raw.into(),
                },
                read: |value| {
                    use $crate::common::message_tree::Code;
                    Ok(
                        match $crate::common::readable::from_value::<Code<$kind>>(value)? {
                            Code::Name(name) => name.value().into(),
                            Code::Number(number) => number.into(),
                        },
                    )
                },
                takes: &oxirush_utils::tree::Takes::OneOf(&[
                    <$kind as $crate::common::readable::Readable>::TAKES,
                    &oxirush_utils::tree::Takes::Number((1 << $width) - 1),
                ]),
            },
        }
    };
}

/// The table of an IE type whose fields `bits!` of oxirush-utils lays out
/// over its `value`, an octet (`octet`) or octets (`octets`): the least and
/// the most octets of its value from a sender, the least that a receiver
/// takes, and after them `trailing` for octets of flags whose absent and zero
/// octets at the end say the same. The tree of the IE comes from the table.
macro_rules! table_ie {
    ($ie:ty, $storage:ident, $least:literal ..= $most:literal, receives $receives:literal $(, $option:ident)?) => {
        impl $ie {
            /// The table of the fields of the IE.
            pub(crate) const TABLE: $crate::common::field_table::Table = $crate::common::field_table::Table {
                rows: <$ie>::FIELDS,
                least: $least,
                most: $most,
                #[cfg(feature = "tree")]
                receives: $receives,
                #[cfg(feature = "tree")]
                trailing: $crate::common::field_table::table_ie!(@trailing $($option)?),
            };

            /// The octets of the value.
            #[allow(dead_code)]
            pub(crate) fn table_octets(&self) -> &[u8] {
                $crate::common::field_table::table_ie!(@octets $storage self.value)
            }
        }

        #[cfg(feature = "tree")]
        impl $crate::common::message_tree::Decoded for $ie {
            const VALUE_TAKES: &'static oxirush_utils::tree::Takes =
                $crate::common::field_table::table_ie!(@takes $ie $(, $option)?);

            fn unwritten() -> Self {
                <$ie>::blank()
            }

            fn meant(&self, _: $crate::common::message_tree::Scope) -> Self {
                $crate::common::field_table::table_ie!(@meant self $(, $option)?)
            }

            fn decoded(&self, _: $crate::common::message_tree::Scope) -> Option<oxirush_utils::tree::Value> {
                Some(Self::TABLE.tree(self.table_octets()))
            }

            fn with_decoded(
                &self,
                value: &oxirush_utils::tree::Value,
                _: $crate::common::message_tree::Scope,
            ) -> core::result::Result<Self, alloc::string::String> {
                let mut octets = $crate::common::Octets::from(self.table_octets());
                Self::TABLE.write(&mut octets, value)?;
                let mut ie = self.clone();
                ie.value = $crate::common::field_table::table_ie!(@stored $storage octets);
                Ok(ie)
            }

            fn shown_value(&self, scope: $crate::common::message_tree::Scope) -> Option<oxirush_utils::tree::Value> {
                let shown = Self::TABLE.shown(self.table_octets());
                // The table decides that the value writes the IE back; a
                // build with debug assertions writes it back to see.
                #[cfg(debug_assertions)]
                if let Some(value) = &shown {
                    let written = Self::unwritten().with_decoded(value, scope);
                    debug_assert!(
                        written.is_ok_and(|written| written.meant(scope) == self.meant(scope)),
                        "{} {:?}: {value} does not write it back",
                        stringify!($ie),
                        self.table_octets(),
                    );
                }
                #[cfg(not(debug_assertions))]
                let _ = scope;
                shown
            }
        }
    };
    (@trailing trailing) => { true };
    (@trailing $($option:ident)?) => { false };
    (@octets octet $value:expr) => { core::slice::from_ref(&$value) };
    (@octets octets $value:expr) => { &$value };
    (@stored octet $octets:ident) => {
        match $octets[..] {
            [octet] => octet,
            _ => return Err(alloc::string::String::from("the IE has one octet")),
        }
    };
    (@stored octets $octets:ident) => { $octets };
    (@meant $ie:ident, trailing) => {{
        let mut meant = $ie.clone();
        while meant.value.last() == Some(&0) {
            meant.value.truncate(meant.value.len() - 1);
        }
        meant
    }};
    (@meant $ie:ident $(, $option:ident)?) => { $ie.clone() };
    (@takes $ie:ty $(, $option:ident)?) => {
        &oxirush_utils::tree::Takes::Members(None, &<$ie>::TABLE.takes::<{ <$ie>::FIELDS.len() }>())
    };
}

pub(crate) use {field_row, table_ie};
