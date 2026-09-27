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

//! Shared wire format, message macros, and validation interfaces for 5GS and EPS NAS.

mod codec;
mod identity;
mod ie_macros;
mod labels;
mod message_macros;
mod plmn;
#[cfg(feature = "security")]
mod security;
mod unknown_ie;
mod validate;

pub use codec::{Decode, Encode, MAX_IE_VALUE_LENGTH, NasError, Result, helpers};
pub(crate) use identity::imei_with_spare;
pub(crate) use ie_macros::{
    nas_ie_lv, nas_ie_lve, nas_ie_tlv, nas_ie_tlve, nas_ie_tv, nas_ie_tv_fixed, nas_ie_tv1,
    nas_ie_v, nas_ie_v_fixed, nas_ie_v_u16,
};
pub(crate) use labels::{decode_labels, encode_labels};
pub(crate) use message_macros::{
    nas_message, nas_message_empty, nas_message_impl_default, nas_message_optional_alias,
};
pub use plmn::PlmnId;
#[cfg(feature = "security")]
pub use security::Direction;
#[cfg(feature = "security")]
pub(crate) use security::{estimate_count, estimate_count_bits};
pub(crate) use unknown_ie::OptionalIeOrder;
pub use unknown_ie::UnknownIe;
pub use validate::{Severity, Validate, ValidationError};
