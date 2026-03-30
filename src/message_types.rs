/*
   OxiRush
   Copyright 2025 Valentin D'Emmanuele

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

//! NAS message type and security header type enums.
//!
//! These enums map the raw message-type byte (from the NAS header) to a named
//! variant. All implement `TryFrom<u8>` for decoding from the wire.

use crate::types::*;
use std::convert::TryFrom;

/// 5G Mobility Management (5GMM) message types per TS 24.501 Table 8.2.1.
///
/// The discriminant value is the message type octet on the wire.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nas5gmmMessageType {
    RegistrationRequest,
    RegistrationAccept,
    RegistrationComplete,
    RegistrationReject,
    DeregistrationRequestFromUe,
    DeregistrationAcceptFromUe,
    DeregistrationRequestToUe,
    DeregistrationAcceptToUe,
    ServiceRequest,
    ServiceReject,
    ServiceAccept,
    ConfigurationUpdateCommand,
    ConfigurationUpdateComplete,
    AuthenticationRequest,
    AuthenticationResponse,
    AuthenticationReject,
    AuthenticationFailure,
    AuthenticationResult,
    IdentityRequest,
    IdentityResponse,
    SecurityModeCommand,
    SecurityModeComplete,
    SecurityModeReject,
    FGmmStatus,
    Notification,
    NotificationResponse,
    UlNasTransport,
    DlNasTransport,
    Unknown(u8),
}

impl Nas5gmmMessageType {
    /// Wire-format value of this message type.
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::RegistrationRequest => 65,
            Self::RegistrationAccept => 66,
            Self::RegistrationComplete => 67,
            Self::RegistrationReject => 68,
            Self::DeregistrationRequestFromUe => 69,
            Self::DeregistrationAcceptFromUe => 70,
            Self::DeregistrationRequestToUe => 71,
            Self::DeregistrationAcceptToUe => 72,
            Self::ServiceRequest => 76,
            Self::ServiceReject => 77,
            Self::ServiceAccept => 78,
            Self::ConfigurationUpdateCommand => 84,
            Self::ConfigurationUpdateComplete => 85,
            Self::AuthenticationRequest => 86,
            Self::AuthenticationResponse => 87,
            Self::AuthenticationReject => 88,
            Self::AuthenticationFailure => 89,
            Self::AuthenticationResult => 90,
            Self::IdentityRequest => 91,
            Self::IdentityResponse => 92,
            Self::SecurityModeCommand => 93,
            Self::SecurityModeComplete => 94,
            Self::SecurityModeReject => 95,
            Self::FGmmStatus => 100,
            Self::Notification => 101,
            Self::NotificationResponse => 102,
            Self::UlNasTransport => 103,
            Self::DlNasTransport => 104,
            Self::Unknown(v) => *v,
        }
    }
}

impl TryFrom<u8> for Nas5gmmMessageType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            65 => Ok(Nas5gmmMessageType::RegistrationRequest),
            66 => Ok(Nas5gmmMessageType::RegistrationAccept),
            67 => Ok(Nas5gmmMessageType::RegistrationComplete),
            68 => Ok(Nas5gmmMessageType::RegistrationReject),
            69 => Ok(Nas5gmmMessageType::DeregistrationRequestFromUe),
            70 => Ok(Nas5gmmMessageType::DeregistrationAcceptFromUe),
            71 => Ok(Nas5gmmMessageType::DeregistrationRequestToUe),
            72 => Ok(Nas5gmmMessageType::DeregistrationAcceptToUe),
            76 => Ok(Nas5gmmMessageType::ServiceRequest),
            77 => Ok(Nas5gmmMessageType::ServiceReject),
            78 => Ok(Nas5gmmMessageType::ServiceAccept),
            84 => Ok(Nas5gmmMessageType::ConfigurationUpdateCommand),
            85 => Ok(Nas5gmmMessageType::ConfigurationUpdateComplete),
            86 => Ok(Nas5gmmMessageType::AuthenticationRequest),
            87 => Ok(Nas5gmmMessageType::AuthenticationResponse),
            88 => Ok(Nas5gmmMessageType::AuthenticationReject),
            89 => Ok(Nas5gmmMessageType::AuthenticationFailure),
            90 => Ok(Nas5gmmMessageType::AuthenticationResult),
            91 => Ok(Nas5gmmMessageType::IdentityRequest),
            92 => Ok(Nas5gmmMessageType::IdentityResponse),
            93 => Ok(Nas5gmmMessageType::SecurityModeCommand),
            94 => Ok(Nas5gmmMessageType::SecurityModeComplete),
            95 => Ok(Nas5gmmMessageType::SecurityModeReject),
            100 => Ok(Nas5gmmMessageType::FGmmStatus),
            101 => Ok(Nas5gmmMessageType::Notification),
            102 => Ok(Nas5gmmMessageType::NotificationResponse),
            103 => Ok(Nas5gmmMessageType::UlNasTransport),
            104 => Ok(Nas5gmmMessageType::DlNasTransport),
            _ => Ok(Nas5gmmMessageType::Unknown(value)),
        }
    }
}

/// 5G Session Management (5GSM) message types per TS 24.501 Table 8.3.1.
///
/// The discriminant value is the message type octet on the wire.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Nas5gsmMessageType {
    PduSessionEstablishmentRequest,
    PduSessionEstablishmentAccept,
    PduSessionEstablishmentReject,
    PduSessionAuthenticationCommand,
    PduSessionAuthenticationComplete,
    PduSessionAuthenticationResult,
    PduSessionModificationRequest,
    PduSessionModificationReject,
    PduSessionModificationCommand,
    PduSessionModificationComplete,
    PduSessionModificationCommandReject,
    PduSessionReleaseRequest,
    PduSessionReleaseReject,
    PduSessionReleaseCommand,
    PduSessionReleaseComplete,
    FGsmStatus,
    Unknown(u8),
}

impl Nas5gsmMessageType {
    /// Wire-format value of this message type.
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::PduSessionEstablishmentRequest => 193,
            Self::PduSessionEstablishmentAccept => 194,
            Self::PduSessionEstablishmentReject => 195,
            Self::PduSessionAuthenticationCommand => 197,
            Self::PduSessionAuthenticationComplete => 198,
            Self::PduSessionAuthenticationResult => 199,
            Self::PduSessionModificationRequest => 201,
            Self::PduSessionModificationReject => 202,
            Self::PduSessionModificationCommand => 203,
            Self::PduSessionModificationComplete => 204,
            Self::PduSessionModificationCommandReject => 205,
            Self::PduSessionReleaseRequest => 209,
            Self::PduSessionReleaseReject => 210,
            Self::PduSessionReleaseCommand => 211,
            Self::PduSessionReleaseComplete => 212,
            Self::FGsmStatus => 214,
            Self::Unknown(v) => *v,
        }
    }
}

impl TryFrom<u8> for Nas5gsmMessageType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            193 => Ok(Nas5gsmMessageType::PduSessionEstablishmentRequest),
            194 => Ok(Nas5gsmMessageType::PduSessionEstablishmentAccept),
            195 => Ok(Nas5gsmMessageType::PduSessionEstablishmentReject),
            197 => Ok(Nas5gsmMessageType::PduSessionAuthenticationCommand),
            198 => Ok(Nas5gsmMessageType::PduSessionAuthenticationComplete),
            199 => Ok(Nas5gsmMessageType::PduSessionAuthenticationResult),
            201 => Ok(Nas5gsmMessageType::PduSessionModificationRequest),
            202 => Ok(Nas5gsmMessageType::PduSessionModificationReject),
            203 => Ok(Nas5gsmMessageType::PduSessionModificationCommand),
            204 => Ok(Nas5gsmMessageType::PduSessionModificationComplete),
            205 => Ok(Nas5gsmMessageType::PduSessionModificationCommandReject),
            209 => Ok(Nas5gsmMessageType::PduSessionReleaseRequest),
            210 => Ok(Nas5gsmMessageType::PduSessionReleaseReject),
            211 => Ok(Nas5gsmMessageType::PduSessionReleaseCommand),
            212 => Ok(Nas5gsmMessageType::PduSessionReleaseComplete),
            214 => Ok(Nas5gsmMessageType::FGsmStatus),
            _ => Ok(Nas5gsmMessageType::Unknown(value)),
        }
    }
}

/// NAS Security Header Type per TS 24.501 &sect;9.3.1.
///
/// Indicates the level of security protection applied to the NAS message.
/// Used in the security header to select the protect/unprotect mode.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Nas5gsSecurityHeaderType {
    /// No security protection.
    PlainNasMessage = 0x00,
    /// Integrity protected only (MAC, no ciphering).
    IntegrityProtected = 0x01,
    /// Integrity protected and ciphered.
    IntegrityProtectedAndCiphered = 0x02,
    /// Integrity protected with new NAS security context (used for SecurityModeCommand).
    IntegrityProtectedWithNewContext = 0x03,
    /// Integrity protected and ciphered with new NAS security context.
    IntegrityProtectedAndCipheredWithNewContext = 0x04,
}

impl TryFrom<u8> for Nas5gsSecurityHeaderType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Nas5gsSecurityHeaderType::PlainNasMessage),
            0x01 => Ok(Nas5gsSecurityHeaderType::IntegrityProtected),
            0x02 => Ok(Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered),
            0x03 => Ok(Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext),
            0x04 => Ok(Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext),
            _ => Err(NasError::DecodingError(format!(
                "Unknown Security Header Type: {}",
                value
            ))),
        }
    }
}
