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
            other => return Err(NasError::ReservedSecurityHeaderType(other)),
        })
    }
}

// BEGIN TS24301 MESSAGE_TYPES
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

/// EMM message types (TS 24.301 Table 9.8.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasEmmMessageType {
    /// Attach Request (0x41).
    AttachRequest,
    /// Attach Accept (0x42).
    AttachAccept,
    /// Attach Complete (0x43).
    AttachComplete,
    /// Attach Reject (0x44).
    AttachReject,
    /// Detach Request (0x45).
    DetachRequest,
    /// Detach Accept (0x46).
    DetachAccept,
    /// Tracking Area Update Request (0x48).
    TrackingAreaUpdateRequest,
    /// Tracking Area Update Accept (0x49).
    TrackingAreaUpdateAccept,
    /// Tracking Area Update Complete (0x4A).
    TrackingAreaUpdateComplete,
    /// Tracking Area Update Reject (0x4B).
    TrackingAreaUpdateReject,
    /// Extended Service Request (0x4C).
    ExtendedServiceRequest,
    /// Control Plane Service Request (0x4D).
    ControlPlaneServiceRequest,
    /// Service Reject (0x4E).
    ServiceReject,
    /// Service Accept (0x4F).
    ServiceAccept,
    /// GUTI Reallocation Command (0x50).
    GutiReallocationCommand,
    /// GUTI Reallocation Complete (0x51).
    GutiReallocationComplete,
    /// Authentication Request (0x52).
    AuthenticationRequest,
    /// Authentication Response (0x53).
    AuthenticationResponse,
    /// Authentication Reject (0x54).
    AuthenticationReject,
    /// Identity Request (0x55).
    IdentityRequest,
    /// Identity Response (0x56).
    IdentityResponse,
    /// Authentication Failure (0x5C).
    AuthenticationFailure,
    /// Security Mode Command (0x5D).
    SecurityModeCommand,
    /// Security Mode Complete (0x5E).
    SecurityModeComplete,
    /// Security Mode Reject (0x5F).
    SecurityModeReject,
    /// EMM Status (0x60).
    EmmStatus,
    /// EMM Information (0x61).
    EmmInformation,
    /// Downlink NAS Transport (0x62).
    DownlinkNasTransport,
    /// Uplink NAS Transport (0x63).
    UplinkNasTransport,
    /// CS Service Notification (0x64).
    CsServiceNotification,
    /// Downlink Generic NAS Transport (0x68).
    DownlinkGenericNasTransport,
    /// Uplink Generic NAS Transport (0x69).
    UplinkGenericNasTransport,
    /// A message type this codec does not know.
    Unknown(u8),
}
impl NasEmmMessageType {
    /// Message type octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::AttachRequest => 0x41,
            Self::AttachAccept => 0x42,
            Self::AttachComplete => 0x43,
            Self::AttachReject => 0x44,
            Self::DetachRequest => 0x45,
            Self::DetachAccept => 0x46,
            Self::TrackingAreaUpdateRequest => 0x48,
            Self::TrackingAreaUpdateAccept => 0x49,
            Self::TrackingAreaUpdateComplete => 0x4A,
            Self::TrackingAreaUpdateReject => 0x4B,
            Self::ExtendedServiceRequest => 0x4C,
            Self::ControlPlaneServiceRequest => 0x4D,
            Self::ServiceReject => 0x4E,
            Self::ServiceAccept => 0x4F,
            Self::GutiReallocationCommand => 0x50,
            Self::GutiReallocationComplete => 0x51,
            Self::AuthenticationRequest => 0x52,
            Self::AuthenticationResponse => 0x53,
            Self::AuthenticationReject => 0x54,
            Self::IdentityRequest => 0x55,
            Self::IdentityResponse => 0x56,
            Self::AuthenticationFailure => 0x5C,
            Self::SecurityModeCommand => 0x5D,
            Self::SecurityModeComplete => 0x5E,
            Self::SecurityModeReject => 0x5F,
            Self::EmmStatus => 0x60,
            Self::EmmInformation => 0x61,
            Self::DownlinkNasTransport => 0x62,
            Self::UplinkNasTransport => 0x63,
            Self::CsServiceNotification => 0x64,
            Self::DownlinkGenericNasTransport => 0x68,
            Self::UplinkGenericNasTransport => 0x69,
            Self::Unknown(value) => value,
        }
    }
}
impl TryFrom<u8> for NasEmmMessageType {
    type Error = NasError;
    fn try_from(value: u8) -> Result<Self> {
        Ok(match value {
            0x41 => Self::AttachRequest,
            0x42 => Self::AttachAccept,
            0x43 => Self::AttachComplete,
            0x44 => Self::AttachReject,
            0x45 => Self::DetachRequest,
            0x46 => Self::DetachAccept,
            0x48 => Self::TrackingAreaUpdateRequest,
            0x49 => Self::TrackingAreaUpdateAccept,
            0x4A => Self::TrackingAreaUpdateComplete,
            0x4B => Self::TrackingAreaUpdateReject,
            0x4C => Self::ExtendedServiceRequest,
            0x4D => Self::ControlPlaneServiceRequest,
            0x4E => Self::ServiceReject,
            0x4F => Self::ServiceAccept,
            0x50 => Self::GutiReallocationCommand,
            0x51 => Self::GutiReallocationComplete,
            0x52 => Self::AuthenticationRequest,
            0x53 => Self::AuthenticationResponse,
            0x54 => Self::AuthenticationReject,
            0x55 => Self::IdentityRequest,
            0x56 => Self::IdentityResponse,
            0x5C => Self::AuthenticationFailure,
            0x5D => Self::SecurityModeCommand,
            0x5E => Self::SecurityModeComplete,
            0x5F => Self::SecurityModeReject,
            0x60 => Self::EmmStatus,
            0x61 => Self::EmmInformation,
            0x62 => Self::DownlinkNasTransport,
            0x63 => Self::UplinkNasTransport,
            0x64 => Self::CsServiceNotification,
            0x68 => Self::DownlinkGenericNasTransport,
            0x69 => Self::UplinkGenericNasTransport,
            other => Self::Unknown(other),
        })
    }
}

/// ESM message types (TS 24.301 Table 9.8.2).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NasEsmMessageType {
    /// Activate Default EPS Bearer Context Request (0xC1).
    ActivateDefaultEpsBearerContextRequest,
    /// Activate Default EPS Bearer Context Accept (0xC2).
    ActivateDefaultEpsBearerContextAccept,
    /// Activate Default EPS Bearer Context Reject (0xC3).
    ActivateDefaultEpsBearerContextReject,
    /// Activate Dedicated EPS Bearer Context Request (0xC5).
    ActivateDedicatedEpsBearerContextRequest,
    /// Activate Dedicated EPS Bearer Context Accept (0xC6).
    ActivateDedicatedEpsBearerContextAccept,
    /// Activate Dedicated EPS Bearer Context Reject (0xC7).
    ActivateDedicatedEpsBearerContextReject,
    /// Modify EPS Bearer Context Request (0xC9).
    ModifyEpsBearerContextRequest,
    /// Modify EPS Bearer Context Accept (0xCA).
    ModifyEpsBearerContextAccept,
    /// Modify EPS Bearer Context Reject (0xCB).
    ModifyEpsBearerContextReject,
    /// Deactivate EPS Bearer Context Request (0xCD).
    DeactivateEpsBearerContextRequest,
    /// Deactivate EPS Bearer Context Accept (0xCE).
    DeactivateEpsBearerContextAccept,
    /// PDN Connectivity Request (0xD0).
    PdnConnectivityRequest,
    /// PDN Connectivity Reject (0xD1).
    PdnConnectivityReject,
    /// PDN Disconnect Request (0xD2).
    PdnDisconnectRequest,
    /// PDN Disconnect Reject (0xD3).
    PdnDisconnectReject,
    /// Bearer Resource Allocation Request (0xD4).
    BearerResourceAllocationRequest,
    /// Bearer Resource Allocation Reject (0xD5).
    BearerResourceAllocationReject,
    /// Bearer Resource Modification Request (0xD6).
    BearerResourceModificationRequest,
    /// Bearer Resource Modification Reject (0xD7).
    BearerResourceModificationReject,
    /// ESM Information Request (0xD9).
    EsmInformationRequest,
    /// ESM Information Response (0xDA).
    EsmInformationResponse,
    /// Notification (0xDB).
    Notification,
    /// ESM Dummy Message (0xDC).
    EsmDummyMessage,
    /// ESM Status (0xE8).
    EsmStatus,
    /// Remote UE Report (0xE9).
    RemoteUeReport,
    /// Remote UE Report Response (0xEA).
    RemoteUeReportResponse,
    /// ESM Data Transport (0xEB).
    EsmDataTransport,
    /// A message type this codec does not know.
    Unknown(u8),
}
impl NasEsmMessageType {
    /// Message type octet.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::ActivateDefaultEpsBearerContextRequest => 0xC1,
            Self::ActivateDefaultEpsBearerContextAccept => 0xC2,
            Self::ActivateDefaultEpsBearerContextReject => 0xC3,
            Self::ActivateDedicatedEpsBearerContextRequest => 0xC5,
            Self::ActivateDedicatedEpsBearerContextAccept => 0xC6,
            Self::ActivateDedicatedEpsBearerContextReject => 0xC7,
            Self::ModifyEpsBearerContextRequest => 0xC9,
            Self::ModifyEpsBearerContextAccept => 0xCA,
            Self::ModifyEpsBearerContextReject => 0xCB,
            Self::DeactivateEpsBearerContextRequest => 0xCD,
            Self::DeactivateEpsBearerContextAccept => 0xCE,
            Self::PdnConnectivityRequest => 0xD0,
            Self::PdnConnectivityReject => 0xD1,
            Self::PdnDisconnectRequest => 0xD2,
            Self::PdnDisconnectReject => 0xD3,
            Self::BearerResourceAllocationRequest => 0xD4,
            Self::BearerResourceAllocationReject => 0xD5,
            Self::BearerResourceModificationRequest => 0xD6,
            Self::BearerResourceModificationReject => 0xD7,
            Self::EsmInformationRequest => 0xD9,
            Self::EsmInformationResponse => 0xDA,
            Self::Notification => 0xDB,
            Self::EsmDummyMessage => 0xDC,
            Self::EsmStatus => 0xE8,
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
            0xC1 => Self::ActivateDefaultEpsBearerContextRequest,
            0xC2 => Self::ActivateDefaultEpsBearerContextAccept,
            0xC3 => Self::ActivateDefaultEpsBearerContextReject,
            0xC5 => Self::ActivateDedicatedEpsBearerContextRequest,
            0xC6 => Self::ActivateDedicatedEpsBearerContextAccept,
            0xC7 => Self::ActivateDedicatedEpsBearerContextReject,
            0xC9 => Self::ModifyEpsBearerContextRequest,
            0xCA => Self::ModifyEpsBearerContextAccept,
            0xCB => Self::ModifyEpsBearerContextReject,
            0xCD => Self::DeactivateEpsBearerContextRequest,
            0xCE => Self::DeactivateEpsBearerContextAccept,
            0xD0 => Self::PdnConnectivityRequest,
            0xD1 => Self::PdnConnectivityReject,
            0xD2 => Self::PdnDisconnectRequest,
            0xD3 => Self::PdnDisconnectReject,
            0xD4 => Self::BearerResourceAllocationRequest,
            0xD5 => Self::BearerResourceAllocationReject,
            0xD6 => Self::BearerResourceModificationRequest,
            0xD7 => Self::BearerResourceModificationReject,
            0xD9 => Self::EsmInformationRequest,
            0xDA => Self::EsmInformationResponse,
            0xDB => Self::Notification,
            0xDC => Self::EsmDummyMessage,
            0xE8 => Self::EsmStatus,
            0xE9 => Self::RemoteUeReport,
            0xEA => Self::RemoteUeReportResponse,
            0xEB => Self::EsmDataTransport,
            other => Self::Unknown(other),
        })
    }
}

// END TS24301 MESSAGE_TYPES
