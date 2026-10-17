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

//! The forms of a member of a struct that its type alone does not give, as
//! [`readable!`](crate::common::readable::readable) names them: each module
//! has `shown`, `read`, `missing` and `blank` for the type of the member,
//! which a form may not need all of.
#![allow(dead_code)]

/// A PLMN identity as its text, `208-93`.
pub(crate) mod plmn {
    use crate::common::Plmn;
    use crate::common::readable::invalid_type;
    use crate::prelude::*;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown(plmn: &Plmn) -> Value {
        plmn.to_string().into()
    }

    pub(crate) fn read(value: &Value) -> Result<Plmn, String> {
        let text = (value.as_str()).ok_or_else(|| invalid_type(value, "a string"))?;
        text.parse()
            .map_err(|_| format!("\"{text}\" is not a PLMN identity like \"208-93\""))
    }

    pub(crate) fn missing() -> Option<Plmn> {
        None
    }

    pub(crate) fn blank() -> Option<Plmn> {
        None
    }
}

/// An optional PLMN identity, as its text or `null`.
pub(crate) mod plmn_option {
    use crate::common::Plmn;
    use crate::prelude::*;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown(plmn: &Option<Plmn>) -> Value {
        plmn.as_ref().map_or(Value::Null, super::plmn::shown)
    }

    pub(crate) fn read(value: &Value) -> Result<Option<Plmn>, String> {
        match value {
            Value::Null => Ok(None),
            value => super::plmn::read(value).map(Some),
        }
    }

    pub(crate) fn missing() -> Option<Option<Plmn>> {
        Some(None)
    }

    pub(crate) fn blank() -> Option<Option<Plmn>> {
        Some(None)
    }
}

/// A list of PLMN identities, each as its text.
pub(crate) mod plmn_list {
    use crate::common::Plmn;
    use crate::common::readable::invalid_type;
    use crate::prelude::*;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown(plmns: &[Plmn]) -> Value {
        plmns
            .iter()
            .map(super::plmn::shown)
            .collect::<Vec<_>>()
            .into()
    }

    pub(crate) fn read(value: &Value) -> Result<Vec<Plmn>, String> {
        let items = (value.as_array()).ok_or_else(|| invalid_type(value, "a sequence"))?;
        items.iter().map(super::plmn::read).collect()
    }

    pub(crate) fn missing() -> Option<Vec<Plmn>> {
        None
    }

    pub(crate) fn blank() -> Option<Vec<Plmn>> {
        Some(Vec::new())
    }
}

/// A tracking area identity of either system, `{"plmn": "208-93", "tac": 1}`.
pub(crate) mod tai {
    use crate::common::TaiParts;
    use crate::common::readable::{Members, member, members};
    use crate::prelude::*;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown<T: TaiParts>(tai: &T) -> Value {
        let (plmn, tac) = tai.parts();
        let mut shown = Members::new();
        shown.put_shown("plmn", super::plmn::shown(&plmn));
        shown.put("tac", &tac);
        shown.finish()
    }

    pub(crate) fn read<T: TaiParts>(value: &Value) -> Result<T, String> {
        let read = members(value, "TrackingAreaIdentity", &["plmn", "tac"])?;
        let plmn = match read[0] {
            Some(plmn) => super::plmn::read(plmn)?,
            None => return Err("`plmn` is not written".into()),
        };
        let tac: u32 = member(read[1], "tac")?;
        T::of(plmn, tac)
    }

    pub(crate) fn missing<T>() -> Option<T> {
        None
    }

    pub(crate) fn blank<T>() -> Option<T> {
        None
    }
}

/// A list of tracking area identities.
pub(crate) mod tai_list {
    use crate::common::TaiParts;
    use crate::common::readable::invalid_type;
    use crate::prelude::*;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown<T: TaiParts>(tais: &[T]) -> Value {
        tais.iter()
            .map(super::tai::shown)
            .collect::<Vec<_>>()
            .into()
    }

    pub(crate) fn read<T: TaiParts>(value: &Value) -> Result<Vec<T>, String> {
        let items = (value.as_array()).ok_or_else(|| invalid_type(value, "a sequence"))?;
        items.iter().map(super::tai::read).collect()
    }

    pub(crate) fn missing<T>() -> Option<Vec<T>> {
        None
    }

    pub(crate) fn blank<T>() -> Option<Vec<T>> {
        Some(Vec::new())
    }
}

/// Octets in hexadecimal, also when there are none: a list of no octets
/// would be shown as an empty list.
pub(crate) mod hexadecimal {
    use crate::common::readable::Readable;
    use crate::prelude::*;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown(octets: &[u8]) -> Value {
        hex::encode(octets).into()
    }

    pub(crate) fn read(value: &Value) -> Result<Vec<u8>, String> {
        Vec::<u8>::read(value)
    }

    pub(crate) fn missing() -> Option<Vec<u8>> {
        None
    }

    pub(crate) fn blank() -> Option<Vec<u8>> {
        Some(Vec::new())
    }
}

/// [`hexadecimal`] for octets that may be absent.
pub(crate) mod hexadecimal_if_any {
    use crate::common::readable::Readable;
    use crate::prelude::*;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown(octets: &Option<Vec<u8>>) -> Value {
        match octets {
            Some(octets) => super::hexadecimal::shown(octets),
            None => Value::Null,
        }
    }

    pub(crate) fn read(value: &Value) -> Result<Option<Vec<u8>>, String> {
        Option::<Vec<u8>>::read(value)
    }

    pub(crate) fn missing() -> Option<Option<Vec<u8>>> {
        Some(None)
    }

    pub(crate) fn blank() -> Option<Option<Vec<u8>>> {
        Some(None)
    }
}

/// An IE that a value holds, as the tree of a message shows it: its value
/// where that writes it back, or its octets.
pub(crate) mod tree {
    use crate::prelude::*;
    use oxirush_utils::tree::Tree;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown<T: Tree>(ie: &T) -> Value {
        ie.to_tree()
    }

    pub(crate) fn read<T: Tree>(value: &Value) -> Result<T, String> {
        oxirush_utils::tree::from_value(value).map_err(|error| error.to_string())
    }

    pub(crate) fn missing<T>() -> Option<T> {
        None
    }

    pub(crate) fn blank<T>() -> Option<T> {
        None
    }
}

/// [`tree`] for an IE that may be absent, `null` then.
pub(crate) mod tree_option {
    use crate::prelude::*;
    use oxirush_utils::tree::Tree;
    use oxirush_utils::tree::Value;

    pub(crate) fn shown<T: Tree>(ie: &Option<T>) -> Value {
        ie.as_ref().map_or(Value::Null, Tree::to_tree)
    }

    pub(crate) fn read<T: Tree>(value: &Value) -> Result<Option<T>, String> {
        match value {
            Value::Null => Ok(None),
            value => super::tree::read(value).map(Some),
        }
    }

    pub(crate) fn missing<T>() -> Option<Option<T>> {
        Some(None)
    }

    pub(crate) fn blank<T>() -> Option<Option<T>> {
        Some(None)
    }
}

/// A form of the octets of the value of an IE of the type `$ie` that a
/// value holds: shown as the tree of a message shows that IE, `null` when
/// there are none.
macro_rules! ie_octets {
    ($($form:ident: $ie:ty),+ $(,)?) => {$(
        pub(crate) mod $form {
            use crate::prelude::*;
            use oxirush_utils::tree::Tree;
            use oxirush_utils::tree::Value;

            pub(crate) fn shown(octets: &[u8]) -> Value {
                match octets.is_empty() {
                    true => Value::Null,
                    false => <$ie>::new(octets.to_vec()).to_tree(),
                }
            }

            pub(crate) fn read(value: &Value) -> Result<Vec<u8>, String> {
                match value {
                    Value::Null => Ok(Vec::new()),
                    value => {
                        let ie: $ie = super::tree::read(value)?;
                        Ok(ie.value.to_vec())
                    }
                }
            }

            pub(crate) fn missing() -> Option<Vec<u8>> {
                Some(Vec::new())
            }

            pub(crate) fn blank() -> Option<Vec<u8>> {
                Some(Vec::new())
            }
        }
    )+};
}

ie_octets!(
    dnn_octets: crate::nas_5gs::NasDnn,
    s_nssai_octets: crate::nas_5gs::NasSNssai,
    tai_list_5gs_octets: crate::nas_5gs::NasFGsTrackingAreaIdentityList,
    tai_list_eps_octets: crate::nas_eps::NasTrackingAreaIdentityList,
);
