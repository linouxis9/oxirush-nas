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

//! Shared wire format, message macros, and validation interfaces for 5GS and EPS NAS.

mod codec;
mod direction;
#[cfg(feature = "serde")]
pub(crate) mod forms;
pub(crate) mod gsm7;
mod identity;
mod ie_macros;
mod labels;
mod message_macros;
pub(crate) mod names;
mod octets;
mod plmn;
#[cfg(feature = "serde")]
mod ppp;
#[cfg(feature = "serde")]
pub(crate) mod readable;
#[cfg(feature = "security")]
mod security;
pub(crate) mod ts24008;
pub(crate) mod ts24301;
pub(crate) mod ts24501;
pub(crate) mod types;
mod unknown_ie;
mod validate;
mod value;
#[cfg(feature = "serde")]
pub(crate) mod view;

pub use codec::{Decode, DecodeOptions, Encode, IeFault, MAX_IE_VALUE_LENGTH, NasError, Result};
pub(crate) use codec::{
    Faults, Keeping, Reader, Reading, Writer, decode_keeping, too_short, trailing,
};
pub use direction::Direction;
pub(crate) use identity::{of_type, receiver_identity};
#[allow(unused_imports)]
pub(crate) use ie_macros::nas_ie_flags;
pub(crate) use ie_macros::{
    nas_ie_lv, nas_ie_lve, nas_ie_struct, nas_ie_tv1, nas_ie_v, nas_ie_v_fixed, nas_ie_v_u16,
};
pub(crate) use labels::{
    decode_labels, decode_labels_with_maximum, encode_labels, labels_are_framed,
};
pub(crate) use message_macros::{
    IeiIndex, IeiTable, MessageBody, check_table_length, decode_mandatory_ie, decode_optional_ies,
    encode_optional_ies, iei_index, invalid_ie, nas_message, nas_message_empty,
    nas_message_impl_default, optional_ie_order_findings,
};
pub use octets::Octets;
pub use plmn::Plmn;
pub(crate) use plmn::{TaiParts, plmn_at, plmn_sequence_ie};
#[cfg(feature = "security")]
pub(crate) use security::{Core, Keys, NextCount, System, wiped};
pub(crate) use unknown_ie::{
    IeOrder, IgnoredIeReason, NO_UNKNOWN_IES, OptionalIeOrder, Placed, generic_ie_length,
};
pub use unknown_ie::{UnknownIe, UnknownIes, UnknownIesIter};
pub(crate) use validate::{
    Bounded, IeLengthCheck, IeLengthCheckProbe, ReceiverSyntaxCheck, ReceiverSyntaxCheckProbe,
    SenderCheck, SenderCheckProbe, ViaIeLengthCheck, ViaNoIeLengthCheck, ViaNoReceiverSyntaxCheck,
    ViaNoSenderCheck, ViaReceiverSyntaxCheck, ViaSenderCheck, ie_length_checked, sender_checked,
    with_optional_ie_checks,
};
pub use validate::{Severity, Validate, ValidationError};
pub use value::{ValueError, ValueFault};
pub(crate) use value::{counted, sized, within, within_usize};
