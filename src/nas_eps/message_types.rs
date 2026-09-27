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

//! EPS EMM and ESM message type and security header codes.
//!
//! Message type enums map the raw type byte in an EPS NAS header to a named
//! variant, following TS 24.301 table 9.8. They implement `TryFrom<u8>` for
//! decoding. Security header types follow TS 24.301 table 9.3.1.

use crate::common::{NasError, Result};
use std::convert::TryFrom;

/// EPS Mobility Management protocol discriminator.
pub const EPS_EMM_PROTOCOL_DISCRIMINATOR: u8 = 0x07;
/// EPS Session Management protocol discriminator.
pub const EPS_ESM_PROTOCOL_DISCRIMINATOR: u8 = 0x02;

/// Direction used to disambiguate the two EPS DETACH REQUEST wire forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasEpsDecodeDirection {
    Uplink,
    Downlink,
}

/// EPS NAS security header type from TS 24.301 table 9.3.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NasEpsSecurityHeaderType {
    /// Plain EMM NAS message.
    PlainNasMessage = 0,
    /// Integrity protected.
    IntegrityProtected = 1,
    /// Integrity protected and ciphered.
    IntegrityProtectedAndCiphered = 2,
    /// Integrity protected SECURITY MODE COMMAND with a new context.
    IntegrityProtectedWithNewContext = 3,
    /// Ciphered SECURITY MODE COMPLETE with a new context.
    IntegrityProtectedAndCipheredWithNewContext = 4,
    /// Partially ciphered CONTROL PLANE SERVICE REQUEST.
    IntegrityProtectedAndPartiallyCiphered = 5,
    /// EMM TRANSPORT special security header.
    EmmTransport = 11,
    /// Short SERVICE REQUEST; received values 12 through 15 map here.
    ServiceRequest = 12,
}

impl TryFrom<u8> for NasEpsSecurityHeaderType {
    type Error = NasError;

    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::PlainNasMessage,
            1 => Self::IntegrityProtected,
            2 => Self::IntegrityProtectedAndCiphered,
            3 => Self::IntegrityProtectedWithNewContext,
            4 => Self::IntegrityProtectedAndCipheredWithNewContext,
            5 => Self::IntegrityProtectedAndPartiallyCiphered,
            11 => Self::EmmTransport,
            12..=15 => Self::ServiceRequest,
            other => {
                return Err(NasError::DecodingError(format!(
                    "Unknown EPS security header type {other}"
                )));
            }
        })
    }
}

// BEGIN TS24301 MESSAGE_TYPES
// TS 24.301 V19.6.0 chapter 8/9 table definitions.

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasEmmMessageType {
    AttachAccept,
    AttachComplete,
    AttachReject,
    AttachRequest,
    AuthenticationFailure,
    AuthenticationReject,
    AuthenticationRequest,
    AuthenticationResponse,
    CsServiceNotification,
    DetachAccept,
    DetachRequest,
    DownlinkNasTransport,
    EmmInformation,
    EmmStatus,
    ExtendedServiceRequest,
    GutiReallocationCommand,
    GutiReallocationComplete,
    IdentityRequest,
    IdentityResponse,
    SecurityModeCommand,
    SecurityModeComplete,
    SecurityModeReject,
    ServiceReject,
    TrackingAreaUpdateAccept,
    TrackingAreaUpdateComplete,
    TrackingAreaUpdateReject,
    TrackingAreaUpdateRequest,
    UplinkNasTransport,
    DownlinkGenericNasTransport,
    UplinkGenericNasTransport,
    ControlPlaneServiceRequest,
    ServiceAccept,
    Unknown(u8),
}
impl NasEmmMessageType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::AttachAccept => 0x42,
            Self::AttachComplete => 0x43,
            Self::AttachReject => 0x44,
            Self::AttachRequest => 0x41,
            Self::AuthenticationFailure => 0x5C,
            Self::AuthenticationReject => 0x54,
            Self::AuthenticationRequest => 0x52,
            Self::AuthenticationResponse => 0x53,
            Self::CsServiceNotification => 0x64,
            Self::DetachAccept => 0x46,
            Self::DetachRequest => 0x45,
            Self::DownlinkNasTransport => 0x62,
            Self::EmmInformation => 0x61,
            Self::EmmStatus => 0x60,
            Self::ExtendedServiceRequest => 0x4C,
            Self::GutiReallocationCommand => 0x50,
            Self::GutiReallocationComplete => 0x51,
            Self::IdentityRequest => 0x55,
            Self::IdentityResponse => 0x56,
            Self::SecurityModeCommand => 0x5D,
            Self::SecurityModeComplete => 0x5E,
            Self::SecurityModeReject => 0x5F,
            Self::ServiceReject => 0x4E,
            Self::TrackingAreaUpdateAccept => 0x49,
            Self::TrackingAreaUpdateComplete => 0x4A,
            Self::TrackingAreaUpdateReject => 0x4B,
            Self::TrackingAreaUpdateRequest => 0x48,
            Self::UplinkNasTransport => 0x63,
            Self::DownlinkGenericNasTransport => 0x68,
            Self::UplinkGenericNasTransport => 0x69,
            Self::ControlPlaneServiceRequest => 0x4D,
            Self::ServiceAccept => 0x4F,
            Self::Unknown(value) => value,
        }
    }
}
impl TryFrom<u8> for NasEmmMessageType {
    type Error = NasError;
    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0x42 => Self::AttachAccept,
            0x43 => Self::AttachComplete,
            0x44 => Self::AttachReject,
            0x41 => Self::AttachRequest,
            0x5C => Self::AuthenticationFailure,
            0x54 => Self::AuthenticationReject,
            0x52 => Self::AuthenticationRequest,
            0x53 => Self::AuthenticationResponse,
            0x64 => Self::CsServiceNotification,
            0x46 => Self::DetachAccept,
            0x45 => Self::DetachRequest,
            0x62 => Self::DownlinkNasTransport,
            0x61 => Self::EmmInformation,
            0x60 => Self::EmmStatus,
            0x4C => Self::ExtendedServiceRequest,
            0x50 => Self::GutiReallocationCommand,
            0x51 => Self::GutiReallocationComplete,
            0x55 => Self::IdentityRequest,
            0x56 => Self::IdentityResponse,
            0x5D => Self::SecurityModeCommand,
            0x5E => Self::SecurityModeComplete,
            0x5F => Self::SecurityModeReject,
            0x4E => Self::ServiceReject,
            0x49 => Self::TrackingAreaUpdateAccept,
            0x4A => Self::TrackingAreaUpdateComplete,
            0x4B => Self::TrackingAreaUpdateReject,
            0x48 => Self::TrackingAreaUpdateRequest,
            0x63 => Self::UplinkNasTransport,
            0x68 => Self::DownlinkGenericNasTransport,
            0x69 => Self::UplinkGenericNasTransport,
            0x4D => Self::ControlPlaneServiceRequest,
            0x4F => Self::ServiceAccept,
            other => Self::Unknown(other),
        })
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasEsmMessageType {
    ActivateDedicatedEpsBearerContextAccept,
    ActivateDedicatedEpsBearerContextReject,
    ActivateDedicatedEpsBearerContextRequest,
    ActivateDefaultEpsBearerContextAccept,
    ActivateDefaultEpsBearerContextReject,
    ActivateDefaultEpsBearerContextRequest,
    BearerResourceAllocationReject,
    BearerResourceAllocationRequest,
    BearerResourceModificationReject,
    BearerResourceModificationRequest,
    DeactivateEpsBearerContextAccept,
    DeactivateEpsBearerContextRequest,
    EsmDummyMessage,
    EsmInformationRequest,
    EsmInformationResponse,
    EsmStatus,
    ModifyEpsBearerContextAccept,
    ModifyEpsBearerContextReject,
    ModifyEpsBearerContextRequest,
    Notification,
    PdnConnectivityReject,
    PdnConnectivityRequest,
    PdnDisconnectReject,
    PdnDisconnectRequest,
    RemoteUeReport,
    RemoteUeReportResponse,
    EsmDataTransport,
    Unknown(u8),
}
impl NasEsmMessageType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::ActivateDedicatedEpsBearerContextAccept => 0xC6,
            Self::ActivateDedicatedEpsBearerContextReject => 0xC7,
            Self::ActivateDedicatedEpsBearerContextRequest => 0xC5,
            Self::ActivateDefaultEpsBearerContextAccept => 0xC2,
            Self::ActivateDefaultEpsBearerContextReject => 0xC3,
            Self::ActivateDefaultEpsBearerContextRequest => 0xC1,
            Self::BearerResourceAllocationReject => 0xD5,
            Self::BearerResourceAllocationRequest => 0xD4,
            Self::BearerResourceModificationReject => 0xD7,
            Self::BearerResourceModificationRequest => 0xD6,
            Self::DeactivateEpsBearerContextAccept => 0xCE,
            Self::DeactivateEpsBearerContextRequest => 0xCD,
            Self::EsmDummyMessage => 0xDC,
            Self::EsmInformationRequest => 0xD9,
            Self::EsmInformationResponse => 0xDA,
            Self::EsmStatus => 0xE8,
            Self::ModifyEpsBearerContextAccept => 0xCA,
            Self::ModifyEpsBearerContextReject => 0xCB,
            Self::ModifyEpsBearerContextRequest => 0xC9,
            Self::Notification => 0xDB,
            Self::PdnConnectivityReject => 0xD1,
            Self::PdnConnectivityRequest => 0xD0,
            Self::PdnDisconnectReject => 0xD3,
            Self::PdnDisconnectRequest => 0xD2,
            Self::RemoteUeReport => 0xE9,
            Self::RemoteUeReportResponse => 0xEA,
            Self::EsmDataTransport => 0xEB,
            Self::Unknown(value) => value,
        }
    }
}
impl TryFrom<u8> for NasEsmMessageType {
    type Error = NasError;
    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0xC6 => Self::ActivateDedicatedEpsBearerContextAccept,
            0xC7 => Self::ActivateDedicatedEpsBearerContextReject,
            0xC5 => Self::ActivateDedicatedEpsBearerContextRequest,
            0xC2 => Self::ActivateDefaultEpsBearerContextAccept,
            0xC3 => Self::ActivateDefaultEpsBearerContextReject,
            0xC1 => Self::ActivateDefaultEpsBearerContextRequest,
            0xD5 => Self::BearerResourceAllocationReject,
            0xD4 => Self::BearerResourceAllocationRequest,
            0xD7 => Self::BearerResourceModificationReject,
            0xD6 => Self::BearerResourceModificationRequest,
            0xCE => Self::DeactivateEpsBearerContextAccept,
            0xCD => Self::DeactivateEpsBearerContextRequest,
            0xDC => Self::EsmDummyMessage,
            0xD9 => Self::EsmInformationRequest,
            0xDA => Self::EsmInformationResponse,
            0xE8 => Self::EsmStatus,
            0xCA => Self::ModifyEpsBearerContextAccept,
            0xCB => Self::ModifyEpsBearerContextReject,
            0xC9 => Self::ModifyEpsBearerContextRequest,
            0xDB => Self::Notification,
            0xD1 => Self::PdnConnectivityReject,
            0xD0 => Self::PdnConnectivityRequest,
            0xD3 => Self::PdnDisconnectReject,
            0xD2 => Self::PdnDisconnectRequest,
            0xE9 => Self::RemoteUeReport,
            0xEA => Self::RemoteUeReportResponse,
            0xEB => Self::EsmDataTransport,
            other => Self::Unknown(other),
        })
    }
}

// END TS24301 MESSAGE_TYPES
