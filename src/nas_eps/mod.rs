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

//! EPS NAS codec per 3GPP TS 24.301.
//!
//! Raw IEs, message types, messages, formatting, and validation follow the
//! same layer layout as [`crate::nas_5gs`]. Definitions follow the chapter 8
//! and 9 tables of TS 24.301. Shared codecs and macros are in [`crate::common`].

pub mod display;
pub mod ie;
pub mod message_types;
pub mod messages;
#[cfg(feature = "security")]
pub mod security;
pub mod types;
pub mod validate;
#[cfg(feature = "serde")]
pub(crate) mod view;

pub use crate::common::Direction;
pub use ie::*;
pub use message_types::*;
pub use messages::*;
#[cfg(feature = "security")]
pub use security::NasSecurityContext;
pub use types::*;
pub use validate::Validate;
