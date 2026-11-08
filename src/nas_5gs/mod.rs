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

//! 5GS NAS codec per 3GPP TS 24.501.
//!
//! The messages, their IEs and the values of those, with the same interface
//! as [`crate::nas_eps`]. What both systems share is at the
//! [root of the crate](crate).

pub(crate) mod ie;
pub(crate) mod message_types;
pub(crate) mod messages;
pub(crate) mod types;
pub(crate) mod upds;
pub(crate) mod validate;
#[cfg(feature = "tree")]
pub(crate) mod view;

#[cfg(feature = "security")]
pub(crate) mod security;

pub use ie::*;
pub use message_types::*;
pub use messages::*;
pub use types::*;
pub use upds::*;

#[cfg(feature = "security")]
pub use oxirush_security::nas_5gs::{KAmf, KNasEnc, KNasInt, NasConnection};
#[cfg(feature = "security")]
pub use security::{SecurityContext, Verified};
