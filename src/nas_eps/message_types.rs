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

//! The security header type of an EPS message (TS 24.301 table 9.3.1). The
//! message types are those of the tables of the messages.

use crate::common::{NasError, Result};
use core::convert::TryFrom;

/// EPS Mobility Management protocol discriminator.
pub const EPS_EMM_PROTOCOL_DISCRIMINATOR: u8 = 0x07;
/// EPS Session Management protocol discriminator.
pub const EPS_ESM_PROTOCOL_DISCRIMINATOR: u8 = 0x02;

/// EPS NAS security header type from TS 24.301 table 9.3.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NasEpsSecurityHeaderType {
    /// Plain EMM NAS message.
    PlainNasMessageNotSecurityProtected = 0,
    /// Integrity protected.
    IntegrityProtected = 1,
    /// Integrity protected and ciphered.
    IntegrityProtectedAndCiphered = 2,
    /// Integrity protected SECURITY MODE COMMAND with a new context.
    IntegrityProtectedWithNewEpsSecurityContext = 3,
    /// Ciphered SECURITY MODE COMPLETE with a new context.
    IntegrityProtectedAndCipheredWithNewEpsSecurityContext = 4,
    /// Partially ciphered CONTROL PLANE SERVICE REQUEST.
    IntegrityProtectedAndPartiallyCipheredNasMessage = 5,
    /// EMM TRANSPORT special security header.
    SecurityHeaderForTheEmmTransportMessage = 11,
    /// Short SERVICE REQUEST; received values 12 through 15 map here.
    SecurityHeaderForTheServiceRequestMessage = 12,
}

#[cfg(feature = "serde")]
crate::common::readable::readable!(
    enum NasEpsSecurityHeaderType {
        PlainNasMessageNotSecurityProtected,
        IntegrityProtected,
        IntegrityProtectedAndCiphered,
        IntegrityProtectedWithNewEpsSecurityContext,
        IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
        IntegrityProtectedAndPartiallyCipheredNasMessage,
        SecurityHeaderForTheEmmTransportMessage,
        SecurityHeaderForTheServiceRequestMessage,
    }
);
#[cfg(feature = "serde")]
crate::common::readable::serde_by_readable!(NasEpsSecurityHeaderType);

impl TryFrom<u8> for NasEpsSecurityHeaderType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::PlainNasMessageNotSecurityProtected,
            1 => Self::IntegrityProtected,
            2 => Self::IntegrityProtectedAndCiphered,
            3 => Self::IntegrityProtectedWithNewEpsSecurityContext,
            4 => Self::IntegrityProtectedAndCipheredWithNewEpsSecurityContext,
            5 => Self::IntegrityProtectedAndPartiallyCipheredNasMessage,
            11 => Self::SecurityHeaderForTheEmmTransportMessage,
            12..=15 => Self::SecurityHeaderForTheServiceRequestMessage,
            other => return Err(NasError::ReservedSecurityHeaderType(other)),
        })
    }
}

// BEGIN TS24301 MESSAGE_TYPES
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

// END TS24301 MESSAGE_TYPES
