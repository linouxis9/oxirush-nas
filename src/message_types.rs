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

use crate::types::*;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::convert::TryFrom;

/// 5GMM Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Nas5gmmMessageType {
    RegistrationRequest = 65,
    RegistrationAccept = 66,
    RegistrationComplete = 67,
    RegistrationReject = 68,
    DeregistrationRequestFromUe = 69,
    DeregistrationAcceptFromUe = 70,
    DeregistrationRequestToUe = 71,
    DeregistrationAcceptToUe = 72,
    ServiceRequest = 76,
    ServiceReject = 77,
    ServiceAccept = 78,
    ConfigurationUpdateCommand = 84,
    ConfigurationUpdateComplete = 85,
    AuthenticationRequest = 86,
    AuthenticationResponse = 87,
    AuthenticationReject = 88,
    AuthenticationFailure = 89,
    AuthenticationResult = 90,
    IdentityRequest = 91,
    IdentityResponse = 92,
    SecurityModeCommand = 93,
    SecurityModeComplete = 94,
    SecurityModeReject = 95,
    FGmmStatus = 100,
    Notification = 101,
    NotificationResponse = 102,
    UlNasTransport = 103,
    DlNasTransport = 104,
    // Add other 5GMM message types as needed
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
            _ => Err(NasError::UnknownMessageType(value)),
        }
    }
}

/// 5GSM Message Types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Nas5gsmMessageType {
    PduSessionEstablishmentRequest = 193,
    PduSessionEstablishmentAccept = 194,
    PduSessionEstablishmentReject = 195,
    PduSessionAuthenticationCommand = 197,
    PduSessionAuthenticationComplete = 198,
    PduSessionAuthenticationResult = 199,
    PduSessionModificationRequest = 201,
    PduSessionModificationReject = 202,
    PduSessionModificationCommand = 203,
    PduSessionModificationComplete = 204,
    PduSessionModificationCommandReject = 205,
    PduSessionReleaseRequest = 209,
    PduSessionReleaseReject = 210,
    PduSessionReleaseCommand = 211,
    PduSessionReleaseComplete = 212,
    FGsmStatus = 214,
    // might be missing 5GSM message types
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
            _ => Err(NasError::UnknownMessageType(value)),
        }
    }
}

/// 5G NAS Security Header Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Nas5gsSecurityHeaderType {
    PlainNasMessage = 0x00,
    IntegrityProtected = 0x01,
    IntegrityProtectedAndCiphered = 0x02,
    IntegrityProtectedWithNewContext = 0x03,
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
            _ => Err(NasError::DecodingError(format!("Unknown Security Header Type: {}", value))),
        }
    }
}

