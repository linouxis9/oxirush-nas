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

//! The security header type of a 5GS message (TS 24.501 table 9.3.1). The
//! message types are those of the tables of the messages.

use crate::nas_5gs::*;
use core::convert::TryFrom;

/// NAS Security Header Type per TS 24.501 &sect;9.3.1.
///
/// Indicates the level of security protection applied to the NAS message.
/// Used in the security header to select the protect/unprotect mode.
///
/// ```
/// use oxirush_nas::nas_5gs::Nas5gsSecurityHeaderType;
///
/// // The second octet of a 5GMM message: 2 is integrity protected and ciphered
/// let header = Nas5gsSecurityHeaderType::try_from(0x02).unwrap();
/// assert_eq!(header, Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered);
/// assert_eq!(header as u8, 2);
/// assert!(Nas5gsSecurityHeaderType::try_from(0x05).is_err());
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Nas5gsSecurityHeaderType {
    /// No security protection.
    PlainFiveGsNasMessageNotSecurityProtected = 0x00,
    /// Integrity protected only (MAC, no ciphering).
    IntegrityProtected = 0x01,
    /// Integrity protected and ciphered.
    IntegrityProtectedAndCiphered = 0x02,
    /// Integrity protected with new NAS security context (used for SecurityModeCommand).
    IntegrityProtectedWithNewFiveGNasSecurityContext = 0x03,
    /// Integrity protected and ciphered with new NAS security context.
    IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext = 0x04,
}

#[cfg(feature = "serde")]
crate::common::readable::readable!(
    enum Nas5gsSecurityHeaderType {
        PlainFiveGsNasMessageNotSecurityProtected,
        IntegrityProtected,
        IntegrityProtectedAndCiphered,
        IntegrityProtectedWithNewFiveGNasSecurityContext,
        IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
    }
);
#[cfg(feature = "serde")]
crate::common::readable::serde_by_readable!(Nas5gsSecurityHeaderType);

impl TryFrom<u8> for Nas5gsSecurityHeaderType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Nas5gsSecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected),
            0x01 => Ok(Nas5gsSecurityHeaderType::IntegrityProtected),
            0x02 => Ok(Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered),
            0x03 => Ok(Nas5gsSecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext),
            0x04 => Ok(
                Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
            ),
            _ => Err(NasError::ReservedSecurityHeaderType(value)),
        }
    }
}
