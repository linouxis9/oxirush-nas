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

//! EPS NAS codec per 3GPP TS 24.301.
//!
//! Raw IEs, message types, messages, formatting, and validation follow the
//! same layer layout as [`crate::nas_5gs`]. Definitions follow the chapter 8
//! and 9 tables of TS 24.301. Shared codecs and macros are in [`crate::common`].
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::nas_eps::*;
//!
//! // Decode an ATTACH REQUEST with an IMSI and a PDN CONNECTIVITY REQUEST
//! let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
//! let msg = NasEpsMessage::decode(&bytes).unwrap();
//! println!("{msg}");
//! assert!(msg.validate().is_empty());
//!
//! // Read its IEs, and the ESM message in its container
//! if let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &msg {
//!     let imsi = request.eps_mobile_identity.as_imsi().unwrap();
//!     assert_eq!(imsi.as_str(), "208930000000001");
//!     assert!(request.ue_network_capability.supports_eea(2));
//!
//!     let esm = request.esm_message_container.decode_as_esm_message().unwrap();
//!     println!("{esm}");
//! }
//!
//! // It encodes to the octets that were decoded
//! assert_eq!(bytes, msg.encode().unwrap());
//!
//! // Build an ATTACH REJECT, cause #3, and encode it
//! let cause = NasEmmCause::from_cause(EmmCause::IllegalUe);
//! let reject = NasAttachReject::new(cause);
//! let answer = NasEpsMessage::new_emm(reject);
//! assert_eq!(answer.encode().unwrap(), [0x07, 0x44, 0x03]);
//! ```
//!
//! ```text
//! EMM AttachRequest (type=EpsAttach, KSI=0, identity=imsi-208930000000001, UE-NetCap=EEA0 EEA1 EEA2 / EIA0 EIA1 EIA2, ESM-container=ESM (EBI=0, PTI=1) PdnConnectivityRequest (request=Initial, PDN=Ipv4v6))
//! ESM (EBI=0, PTI=1) PdnConnectivityRequest (request=Initial, PDN=Ipv4v6)
//! ```

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
pub use crate::common::{Severity, ValidationError};
pub use ie::*;
pub use message_types::*;
pub use messages::*;
#[cfg(feature = "security")]
pub use oxirush_security::nas_eps::{KAsme, KNasEnc, KNasInt, Nh};
#[cfg(feature = "security")]
pub use oxirush_security::{NasCount, SecurityError};
#[cfg(feature = "security")]
pub use security::{NasSecurityContext, Verified};
pub use types::*;
pub use validate::Validate;
