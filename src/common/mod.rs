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
mod direction;
pub(crate) mod gsm7;
mod identity;
mod ie_macros;
mod labels;
mod message_macros;
mod plmn;
#[cfg(feature = "security")]
mod security;
pub(crate) mod ts24008;
pub(crate) mod ts24301;
pub(crate) mod ts24501;
mod unknown_ie;
mod validate;

pub use codec::{Decode, Encode, MAX_IE_VALUE_LENGTH, NasError, Result, helpers};
pub use direction::Direction;
pub(crate) use identity::{decode_identity_digits, encode_identity_digits, imei_with_spare};
#[allow(unused_imports)]
pub(crate) use ie_macros::nas_ie_flags;
pub(crate) use ie_macros::{
    nas_ie_lv, nas_ie_lve, nas_ie_tlv, nas_ie_tlve, nas_ie_tv, nas_ie_tv_fixed, nas_ie_tv1,
    nas_ie_v, nas_ie_v_fixed, nas_ie_v_u16, nas_opaque_ie,
};
pub(crate) use labels::{
    decode_labels, decode_labels_with_maximum, encode_labels, labels_are_framed,
};
pub(crate) use message_macros::{
    IeiTable, check_table_length, decode_mandatory_ie, decode_optional_ies, encode_optional_ies,
    invalid_ie, nas_message, nas_message_empty, nas_message_impl_default,
    nas_message_optional_alias, optional_ie_order_findings,
};
pub use plmn::PlmnId;
pub(crate) use plmn::plmn_sequence_ie;
#[cfg(feature = "security")]
pub use security::estimate_nas_count;
#[cfg(feature = "security")]
pub(crate) use security::{estimate_count, estimate_count_bits};
pub use unknown_ie::UnknownIe;
pub(crate) use unknown_ie::{IgnoredIeReason, OptionalIeOrder, generic_ie_length};
pub(crate) use validate::{
    IeLengthCheck, IeLengthCheckProbe, ReceiverSyntaxCheck, ReceiverSyntaxCheckProbe, SenderCheck,
    SenderCheckProbe, ViaIeLengthCheck, ViaNoIeLengthCheck, ViaNoReceiverSyntaxCheck,
    ViaNoSenderCheck, ViaReceiverSyntaxCheck, ViaSenderCheck, with_optional_ie_checks,
};
pub use validate::{Severity, Validate, ValidationError};
