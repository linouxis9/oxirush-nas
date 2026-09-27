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

//! Typed accessors for EPS NAS information elements.
//!
//! This module provides enums and methods over the raw IE structs in
//! [`crate::nas_eps::types`]. The raw `.value` fields remain public; typed
//! accessors parse bit fields and cause codes according to TS 24.301.
//! Methods are implemented on the IE types from [`crate::nas_eps::types`].
//!
//! # Architecture
//!
//! ```text
//! Layer 3 — This module: typed enums and IE accessors
//! Layer 2 — messages.rs: NAS message structs with IEI dispatch
//! Layer 1 — types.rs: raw TLV/TV/V/LV wire codec
//! ```

pub use crate::common::PlmnId;
use crate::nas_eps::types::*;

// BEGIN TS24301 IE
// TS 24.301 V19.6.0 chapter 8/9 table definitions.

/// EmmCause values from TS 24.301 Table 9.9.3.9.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EmmCause {
    /// IMSI unknown in HSS (0x02).
    ImsiUnknownInHss,
    /// Illegal UE (0x03).
    IllegalUe,
    /// IMEI not accepted (0x05).
    ImeiNotAccepted,
    /// Illegal ME (0x06).
    IllegalMe,
    /// EPS services not allowed (0x07).
    EpsServicesNotAllowed,
    /// EPS services and non-EPS services not allowed (0x08).
    EpsServicesAndNonEpsServicesNotAllowed,
    /// UE identity cannot be derived by the network (0x09).
    UeIdentityCannotBeDerivedByTheNetwork,
    /// Implicitly detached (0x0A).
    ImplicitlyDetached,
    /// PLMN not allowed (0x0B).
    PlmnNotAllowed,
    /// Tracking Area not allowed (0x0C).
    TrackingAreaNotAllowed,
    /// Roaming not allowed in this tracking area (0x0D).
    RoamingNotAllowedInThisTrackingArea,
    /// EPS services not allowed in this PLMN (0x0E).
    EpsServicesNotAllowedInThisPlmn,
    /// No Suitable Cells In tracking area (0x0F).
    NoSuitableCellsInTrackingArea,
    /// MSC temporarily not reachable (0x10).
    MscTemporarilyNotReachable,
    /// Network failure (0x11).
    NetworkFailure,
    /// CS domain not available (0x12).
    CsDomainNotAvailable,
    /// ESM failure (0x13).
    EsmFailure,
    /// MAC failure (0x14).
    MacFailure,
    /// Synch failure (0x15).
    SynchFailure,
    /// Congestion (0x16).
    Congestion,
    /// UE security capabilities mismatch (0x17).
    UeSecurityCapabilitiesMismatch,
    /// Security mode rejected, unspecified (0x18).
    SecurityModeRejectedUnspecified,
    /// Not authorized for this CSG (0x19).
    NotAuthorizedForThisCsg,
    /// Non-EPS authentication unacceptable (0x1A).
    NonEpsAuthenticationUnacceptable,
    /// Redirection to 5GCN required (0x1F).
    RedirectionTo5gcnRequired,
    /// Requested service option not authorized in this PLMN (0x23).
    RequestedServiceOptionNotAuthorizedInThisPlmn,
    /// IAB-node operation not authorized (0x24).
    IabNodeOperationNotAuthorized,
    /// CS service temporarily not available (0x27).
    CsServiceTemporarilyNotAvailable,
    /// No EPS bearer context activated (0x28).
    NoEpsBearerContextActivated,
    /// Severe network failure (0x2A).
    SevereNetworkFailure,
    /// PLMN not allowed to operate at the present UE location (0x4E).
    PlmnNotAllowedToOperateAtThePresentUeLocation,
    /// Disaster roaming for the determined PLMN with disaster condition not allowed (0x50).
    DisasterRoamingForTheDeterminedPlmnWithDisasterConditionNotAllowed,
    /// Procedure cannot be completed due to unavailable feeder link while MME is operating in S&F mode (0x53).
    ProcedureCannotBeCompletedDueToUnavailableFeederLinkWhileMmeIsOperatingInSAndFMode,
    /// Semantically incorrect message (0x5F).
    SemanticallyIncorrectMessage,
    /// Invalid mandatory information (0x60).
    InvalidMandatoryInformation,
    /// Message type non-existent or not implemented (0x61).
    MessageTypeNonExistentOrNotImplemented,
    /// Message type not compatible with the protocol state (0x62).
    MessageTypeNotCompatibleWithTheProtocolState,
    /// Information element non-existent or not implemented (0x63).
    InformationElementNonExistentOrNotImplemented,
    /// Conditional IE error (0x64).
    ConditionalIeError,
    /// Message not compatible with the protocol state (0x65).
    MessageNotCompatibleWithTheProtocolState,
    /// Protocol error, unspecified (0x6F).
    ProtocolErrorUnspecified,
    /// A cause code outside the listed values.
    Unknown(u8),
}
impl EmmCause {
    /// Decode a cause while preserving unknown codes.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x02 => Self::ImsiUnknownInHss,
            0x03 => Self::IllegalUe,
            0x05 => Self::ImeiNotAccepted,
            0x06 => Self::IllegalMe,
            0x07 => Self::EpsServicesNotAllowed,
            0x08 => Self::EpsServicesAndNonEpsServicesNotAllowed,
            0x09 => Self::UeIdentityCannotBeDerivedByTheNetwork,
            0x0A => Self::ImplicitlyDetached,
            0x0B => Self::PlmnNotAllowed,
            0x0C => Self::TrackingAreaNotAllowed,
            0x0D => Self::RoamingNotAllowedInThisTrackingArea,
            0x0E => Self::EpsServicesNotAllowedInThisPlmn,
            0x0F => Self::NoSuitableCellsInTrackingArea,
            0x10 => Self::MscTemporarilyNotReachable,
            0x11 => Self::NetworkFailure,
            0x12 => Self::CsDomainNotAvailable,
            0x13 => Self::EsmFailure,
            0x14 => Self::MacFailure,
            0x15 => Self::SynchFailure,
            0x16 => Self::Congestion,
            0x17 => Self::UeSecurityCapabilitiesMismatch,
            0x18 => Self::SecurityModeRejectedUnspecified,
            0x19 => Self::NotAuthorizedForThisCsg,
            0x1A => Self::NonEpsAuthenticationUnacceptable,
            0x1F => Self::RedirectionTo5gcnRequired,
            0x23 => Self::RequestedServiceOptionNotAuthorizedInThisPlmn,
            0x24 => Self::IabNodeOperationNotAuthorized,
            0x27 => Self::CsServiceTemporarilyNotAvailable,
            0x28 => Self::NoEpsBearerContextActivated,
            0x2A => Self::SevereNetworkFailure,
            0x4E => Self::PlmnNotAllowedToOperateAtThePresentUeLocation,
            0x50 => Self::DisasterRoamingForTheDeterminedPlmnWithDisasterConditionNotAllowed,
            0x53 => Self::ProcedureCannotBeCompletedDueToUnavailableFeederLinkWhileMmeIsOperatingInSAndFMode,
            0x5F => Self::SemanticallyIncorrectMessage,
            0x60 => Self::InvalidMandatoryInformation,
            0x61 => Self::MessageTypeNonExistentOrNotImplemented,
            0x62 => Self::MessageTypeNotCompatibleWithTheProtocolState,
            0x63 => Self::InformationElementNonExistentOrNotImplemented,
            0x64 => Self::ConditionalIeError,
            0x65 => Self::MessageNotCompatibleWithTheProtocolState,
            0x6F => Self::ProtocolErrorUnspecified,
            other => Self::Unknown(other),
        }
    }
    /// Return the wire value.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::ImsiUnknownInHss => 0x02,
            Self::IllegalUe => 0x03,
            Self::ImeiNotAccepted => 0x05,
            Self::IllegalMe => 0x06,
            Self::EpsServicesNotAllowed => 0x07,
            Self::EpsServicesAndNonEpsServicesNotAllowed => 0x08,
            Self::UeIdentityCannotBeDerivedByTheNetwork => 0x09,
            Self::ImplicitlyDetached => 0x0A,
            Self::PlmnNotAllowed => 0x0B,
            Self::TrackingAreaNotAllowed => 0x0C,
            Self::RoamingNotAllowedInThisTrackingArea => 0x0D,
            Self::EpsServicesNotAllowedInThisPlmn => 0x0E,
            Self::NoSuitableCellsInTrackingArea => 0x0F,
            Self::MscTemporarilyNotReachable => 0x10,
            Self::NetworkFailure => 0x11,
            Self::CsDomainNotAvailable => 0x12,
            Self::EsmFailure => 0x13,
            Self::MacFailure => 0x14,
            Self::SynchFailure => 0x15,
            Self::Congestion => 0x16,
            Self::UeSecurityCapabilitiesMismatch => 0x17,
            Self::SecurityModeRejectedUnspecified => 0x18,
            Self::NotAuthorizedForThisCsg => 0x19,
            Self::NonEpsAuthenticationUnacceptable => 0x1A,
            Self::RedirectionTo5gcnRequired => 0x1F,
            Self::RequestedServiceOptionNotAuthorizedInThisPlmn => 0x23,
            Self::IabNodeOperationNotAuthorized => 0x24,
            Self::CsServiceTemporarilyNotAvailable => 0x27,
            Self::NoEpsBearerContextActivated => 0x28,
            Self::SevereNetworkFailure => 0x2A,
            Self::PlmnNotAllowedToOperateAtThePresentUeLocation => 0x4E,
            Self::DisasterRoamingForTheDeterminedPlmnWithDisasterConditionNotAllowed => 0x50,
            Self::ProcedureCannotBeCompletedDueToUnavailableFeederLinkWhileMmeIsOperatingInSAndFMode => 0x53,
            Self::SemanticallyIncorrectMessage => 0x5F,
            Self::InvalidMandatoryInformation => 0x60,
            Self::MessageTypeNonExistentOrNotImplemented => 0x61,
            Self::MessageTypeNotCompatibleWithTheProtocolState => 0x62,
            Self::InformationElementNonExistentOrNotImplemented => 0x63,
            Self::ConditionalIeError => 0x64,
            Self::MessageNotCompatibleWithTheProtocolState => 0x65,
            Self::ProtocolErrorUnspecified => 0x6F,
            Self::Unknown(value) => value,
        }
    }
}

impl NasEmmCause {
    /// Build the raw IE from a typed cause.
    pub fn from_cause(cause: EmmCause) -> Self {
        Self::new(cause.as_u8())
    }
    /// Decode the cause value.
    pub fn cause(&self) -> EmmCause {
        EmmCause::from_u8(self.value)
    }
}

/// EsmCause values from TS 24.301 Table 9.9.4.4.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EsmCause {
    /// Operator Determined Barring (0x08).
    OperatorDeterminedBarring,
    /// Insufficient resources (0x1A).
    InsufficientResources,
    /// Missing or unknown APN (0x1B).
    MissingOrUnknownApn,
    /// Unknown PDN type (0x1C).
    UnknownPdnType,
    /// User authentication or authorization failed (0x1D).
    UserAuthenticationOrAuthorizationFailed,
    /// Request rejected by Serving GW or PDN GW (0x1E).
    RequestRejectedByServingGwOrPdnGw,
    /// Request rejected, unspecified (0x1F).
    RequestRejectedUnspecified,
    /// Service option not supported (0x20).
    ServiceOptionNotSupported,
    /// Requested service option not subscribed (0x21).
    RequestedServiceOptionNotSubscribed,
    /// Service option temporarily out of order (0x22).
    ServiceOptionTemporarilyOutOfOrder,
    /// PTI already in use (0x23).
    PtiAlreadyInUse,
    /// Regular deactivation (0x24).
    RegularDeactivation,
    /// EPS QoS not accepted (0x25).
    EpsQosNotAccepted,
    /// Network failure (0x26).
    NetworkFailure,
    /// Reactivation requested (0x27).
    ReactivationRequested,
    /// Semantic error in the TFT operation (0x29).
    SemanticErrorInTheTftOperation,
    /// Syntactical error in the TFT operation (0x2A).
    SyntacticalErrorInTheTftOperation,
    /// Invalid EPS bearer identity (0x2B).
    InvalidEpsBearerIdentity,
    /// Semantic errors in packet filter(s) (0x2C).
    SemanticErrorsInPacketFilterS,
    /// Syntactical errors in packet filter(s) (0x2D).
    SyntacticalErrorsInPacketFilterS,
    /// PTI mismatch (0x2F).
    PtiMismatch,
    /// Last PDN disconnection not allowed (0x31).
    LastPdnDisconnectionNotAllowed,
    /// PDN type IPv4 only allowed (0x32).
    PdnTypeIpv4OnlyAllowed,
    /// PDN type IPv6 only allowed (0x33).
    PdnTypeIpv6OnlyAllowed,
    /// Single address bearers only allowed (0x34).
    SingleAddressBearersOnlyAllowed,
    /// ESM information not received (0x35).
    EsmInformationNotReceived,
    /// PDN connection does not exist (0x36).
    PdnConnectionDoesNotExist,
    /// Multiple PDN connections for a given APN not allowed (0x37).
    MultiplePdnConnectionsForAGivenApnNotAllowed,
    /// Collision with network initiated request (0x38).
    CollisionWithNetworkInitiatedRequest,
    /// PDN type IPv4v6 only allowed (0x39).
    PdnTypeIpv4v6OnlyAllowed,
    /// PDN type non IP only allowed (0x3A).
    PdnTypeNonIpOnlyAllowed,
    /// Unsupported QCI value (0x3B).
    UnsupportedQciValue,
    /// Bearer handling not supported (0x3C).
    BearerHandlingNotSupported,
    /// PDN type Ethernet only allowed (0x3D).
    PdnTypeEthernetOnlyAllowed,
    /// Maximum number of EPS bearers reached (0x41).
    MaximumNumberOfEpsBearersReached,
    /// Requested APN not supported in current RAT and PLMN combination (0x42).
    RequestedApnNotSupportedInCurrentRatAndPlmnCombination,
    /// Invalid PTI value (0x51).
    InvalidPtiValue,
    /// Semantically incorrect message (0x5F).
    SemanticallyIncorrectMessage,
    /// Invalid mandatory information (0x60).
    InvalidMandatoryInformation,
    /// Message type non-existent or not implemented (0x61).
    MessageTypeNonExistentOrNotImplemented,
    /// Message type not compatible with the protocol state (0x62).
    MessageTypeNotCompatibleWithTheProtocolState,
    /// Information element non-existent or not implemented (0x63).
    InformationElementNonExistentOrNotImplemented,
    /// Conditional IE error (0x64).
    ConditionalIeError,
    /// Message not compatible with the protocol state (0x65).
    MessageNotCompatibleWithTheProtocolState,
    /// Protocol error, unspecified (0x6F).
    ProtocolErrorUnspecified,
    /// APN restriction value incompatible with active EPS bearer context (0x70).
    ApnRestrictionValueIncompatibleWithActiveEpsBearerContext,
    /// Multiple accesses to a PDN connection not allowed (0x71).
    MultipleAccessesToAPdnConnectionNotAllowed,
    /// A cause code outside the listed values.
    Unknown(u8),
}
impl EsmCause {
    /// Decode a cause while preserving unknown codes.
    pub fn from_u8(value: u8) -> Self {
        match value {
            0x08 => Self::OperatorDeterminedBarring,
            0x1A => Self::InsufficientResources,
            0x1B => Self::MissingOrUnknownApn,
            0x1C => Self::UnknownPdnType,
            0x1D => Self::UserAuthenticationOrAuthorizationFailed,
            0x1E => Self::RequestRejectedByServingGwOrPdnGw,
            0x1F => Self::RequestRejectedUnspecified,
            0x20 => Self::ServiceOptionNotSupported,
            0x21 => Self::RequestedServiceOptionNotSubscribed,
            0x22 => Self::ServiceOptionTemporarilyOutOfOrder,
            0x23 => Self::PtiAlreadyInUse,
            0x24 => Self::RegularDeactivation,
            0x25 => Self::EpsQosNotAccepted,
            0x26 => Self::NetworkFailure,
            0x27 => Self::ReactivationRequested,
            0x29 => Self::SemanticErrorInTheTftOperation,
            0x2A => Self::SyntacticalErrorInTheTftOperation,
            0x2B => Self::InvalidEpsBearerIdentity,
            0x2C => Self::SemanticErrorsInPacketFilterS,
            0x2D => Self::SyntacticalErrorsInPacketFilterS,
            0x2F => Self::PtiMismatch,
            0x31 => Self::LastPdnDisconnectionNotAllowed,
            0x32 => Self::PdnTypeIpv4OnlyAllowed,
            0x33 => Self::PdnTypeIpv6OnlyAllowed,
            0x34 => Self::SingleAddressBearersOnlyAllowed,
            0x35 => Self::EsmInformationNotReceived,
            0x36 => Self::PdnConnectionDoesNotExist,
            0x37 => Self::MultiplePdnConnectionsForAGivenApnNotAllowed,
            0x38 => Self::CollisionWithNetworkInitiatedRequest,
            0x39 => Self::PdnTypeIpv4v6OnlyAllowed,
            0x3A => Self::PdnTypeNonIpOnlyAllowed,
            0x3B => Self::UnsupportedQciValue,
            0x3C => Self::BearerHandlingNotSupported,
            0x3D => Self::PdnTypeEthernetOnlyAllowed,
            0x41 => Self::MaximumNumberOfEpsBearersReached,
            0x42 => Self::RequestedApnNotSupportedInCurrentRatAndPlmnCombination,
            0x51 => Self::InvalidPtiValue,
            0x5F => Self::SemanticallyIncorrectMessage,
            0x60 => Self::InvalidMandatoryInformation,
            0x61 => Self::MessageTypeNonExistentOrNotImplemented,
            0x62 => Self::MessageTypeNotCompatibleWithTheProtocolState,
            0x63 => Self::InformationElementNonExistentOrNotImplemented,
            0x64 => Self::ConditionalIeError,
            0x65 => Self::MessageNotCompatibleWithTheProtocolState,
            0x6F => Self::ProtocolErrorUnspecified,
            0x70 => Self::ApnRestrictionValueIncompatibleWithActiveEpsBearerContext,
            0x71 => Self::MultipleAccessesToAPdnConnectionNotAllowed,
            other => Self::Unknown(other),
        }
    }
    /// Return the wire value.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::OperatorDeterminedBarring => 0x08,
            Self::InsufficientResources => 0x1A,
            Self::MissingOrUnknownApn => 0x1B,
            Self::UnknownPdnType => 0x1C,
            Self::UserAuthenticationOrAuthorizationFailed => 0x1D,
            Self::RequestRejectedByServingGwOrPdnGw => 0x1E,
            Self::RequestRejectedUnspecified => 0x1F,
            Self::ServiceOptionNotSupported => 0x20,
            Self::RequestedServiceOptionNotSubscribed => 0x21,
            Self::ServiceOptionTemporarilyOutOfOrder => 0x22,
            Self::PtiAlreadyInUse => 0x23,
            Self::RegularDeactivation => 0x24,
            Self::EpsQosNotAccepted => 0x25,
            Self::NetworkFailure => 0x26,
            Self::ReactivationRequested => 0x27,
            Self::SemanticErrorInTheTftOperation => 0x29,
            Self::SyntacticalErrorInTheTftOperation => 0x2A,
            Self::InvalidEpsBearerIdentity => 0x2B,
            Self::SemanticErrorsInPacketFilterS => 0x2C,
            Self::SyntacticalErrorsInPacketFilterS => 0x2D,
            Self::PtiMismatch => 0x2F,
            Self::LastPdnDisconnectionNotAllowed => 0x31,
            Self::PdnTypeIpv4OnlyAllowed => 0x32,
            Self::PdnTypeIpv6OnlyAllowed => 0x33,
            Self::SingleAddressBearersOnlyAllowed => 0x34,
            Self::EsmInformationNotReceived => 0x35,
            Self::PdnConnectionDoesNotExist => 0x36,
            Self::MultiplePdnConnectionsForAGivenApnNotAllowed => 0x37,
            Self::CollisionWithNetworkInitiatedRequest => 0x38,
            Self::PdnTypeIpv4v6OnlyAllowed => 0x39,
            Self::PdnTypeNonIpOnlyAllowed => 0x3A,
            Self::UnsupportedQciValue => 0x3B,
            Self::BearerHandlingNotSupported => 0x3C,
            Self::PdnTypeEthernetOnlyAllowed => 0x3D,
            Self::MaximumNumberOfEpsBearersReached => 0x41,
            Self::RequestedApnNotSupportedInCurrentRatAndPlmnCombination => 0x42,
            Self::InvalidPtiValue => 0x51,
            Self::SemanticallyIncorrectMessage => 0x5F,
            Self::InvalidMandatoryInformation => 0x60,
            Self::MessageTypeNonExistentOrNotImplemented => 0x61,
            Self::MessageTypeNotCompatibleWithTheProtocolState => 0x62,
            Self::InformationElementNonExistentOrNotImplemented => 0x63,
            Self::ConditionalIeError => 0x64,
            Self::MessageNotCompatibleWithTheProtocolState => 0x65,
            Self::ProtocolErrorUnspecified => 0x6F,
            Self::ApnRestrictionValueIncompatibleWithActiveEpsBearerContext => 0x70,
            Self::MultipleAccessesToAPdnConnectionNotAllowed => 0x71,
            Self::Unknown(value) => value,
        }
    }
}

impl NasEsmCause {
    /// Build the raw IE from a typed cause.
    pub fn from_cause(cause: EsmCause) -> Self {
        Self::new(cause.as_u8())
    }
    /// Decode the cause value.
    pub fn cause(&self) -> EsmCause {
        EsmCause::from_u8(self.value)
    }
}

// END TS24301 IE

macro_rules! esm_message_container_ie {
    ($name:ident) => {
        impl $name {
            /// Decode the contained plain ESM PDU.
            pub fn decode_as_esm_message(
                &self,
            ) -> crate::common::Result<crate::nas_eps::messages::NasEpsMessage> {
                use crate::nas_eps::messages::{NasEpsMessage, decode_nas_eps_message};
                let message = decode_nas_eps_message(&self.value)?;
                if matches!(message, NasEpsMessage::Esm(..)) {
                    Ok(message)
                } else {
                    Err(crate::common::NasError::DecodingError(
                        "EPS message container does not contain an ESM PDU".into(),
                    ))
                }
            }

            /// Build a container from a plain ESM PDU.
            pub fn from_esm_message(
                message: &crate::nas_eps::messages::NasEpsMessage,
            ) -> crate::common::Result<Self> {
                use crate::nas_eps::messages::{NasEpsMessage, encode_nas_eps_message};
                if !matches!(message, NasEpsMessage::Esm(..)) {
                    return Err(crate::common::NasError::EncodingError(
                        "EPS message container requires a plain ESM PDU".into(),
                    ));
                }
                Ok(Self::new(encode_nas_eps_message(message)?))
            }
        }
    };
}

esm_message_container_ie!(NasEsmMessageContainer);

impl NasPagingRestriction {
    /// Check the paging type, spare bits, and bearer bitmap layout (§9.9.3.66).
    pub fn is_well_formed(&self) -> bool {
        match self.value.as_slice() {
            [kind] => kind & 0xf0 == 0 && matches!(kind & 0x0f, 1 | 2),
            [kind, low, _high] => kind & 0xf0 == 0 && matches!(kind & 0x0f, 3 | 4) && low & 1 == 0,
            _ => false,
        }
    }
}

impl NasEpsAdditionalRequestResult {
    /// Check the paging restriction decision and spare bits (§9.9.3.67).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [decision] if *decision <= 2)
    }
}

impl NasUnavailabilityInformation {
    /// Check the presence flags and their three-octet fields (§9.9.3.69).
    pub fn is_well_formed(&self) -> bool {
        self.value.first().is_some_and(|header| {
            header & 0xe6 == 0
                && self.value.len()
                    == 1 + 3 * ((header & 0x08 != 0) as usize + (header & 0x10 != 0) as usize)
        })
    }
}

impl NasUnavailabilityConfiguration {
    /// Check the presence flags and their three-octet fields (§9.9.3.70).
    pub fn is_well_formed(&self) -> bool {
        self.value.first().is_some_and(|header| {
            header & 0xf8 == 0
                && self.value.len()
                    == 1 + 3 * ((header & 0x02 != 0) as usize + (header & 0x04 != 0) as usize)
        })
    }
}

impl NasSupportedCodecs {
    /// Decode the successive system IDs and codec bitmaps (TS 24.008 §10.5.4.32).
    pub fn codec_bitmaps(&self) -> Option<Vec<(u8, Vec<u8>)>> {
        let mut rest = self.value.as_slice();
        let mut bitmaps = Vec::new();
        while !rest.is_empty() {
            if rest.len() < 3 {
                return None;
            }
            let bitmap_len = rest[1] as usize;
            if bitmap_len == 0 || rest.len() < 2 + bitmap_len {
                return None;
            }
            bitmaps.push((rest[0], rest[2..2 + bitmap_len].to_vec()));
            rest = &rest[2 + bitmap_len..];
        }
        (!bitmaps.is_empty()).then_some(bitmaps)
    }
}

impl NasDrxParameter {
    /// Check the paging cycle and S1-mode DRX value (TS 24.008 §10.5.5.6).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [cycle, value]
            if *cycle <= 98 && matches!(value >> 4, 0 | 6 | 7 | 8 | 9))
    }
}

impl NasNetworkDaylightSavingTime {
    /// Check the daylight-saving-time code (TS 24.008 §10.5.3.12).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [value] if *value <= 2)
    }
}

impl NasEmergencyNumberList {
    /// Check the length of each category and emergency number record (TS 24.008 §10.5.3.13).
    pub fn is_well_formed(&self) -> bool {
        let mut rest = self.value.as_slice();
        if rest.is_empty() {
            return false;
        }
        while !rest.is_empty() {
            let record_len = rest[0] as usize;
            if record_len < 2 || rest.len() < 1 + record_len || rest[1] & 0xe0 != 0 {
                return false;
            }
            rest = &rest[1 + record_len..];
        }
        true
    }
}

impl NasExtendedEmergencyNumberList {
    /// Check validity and each number/subservice length (TS 24.301 §9.9.3.37A).
    pub fn is_well_formed(&self) -> bool {
        let Some((&validity, mut rest)) = self.value.split_first() else {
            return false;
        };
        if validity & 0xfe != 0 || rest.is_empty() {
            return false;
        }
        while !rest.is_empty() {
            let number_len = rest[0] as usize;
            if number_len == 0 || rest.len() < 2 + number_len {
                return false;
            }
            rest = &rest[1 + number_len..];
            let subservice_len = rest[0] as usize;
            if rest.len() < 1 + subservice_len {
                return false;
            }
            rest = &rest[1 + subservice_len..];
        }
        true
    }
}

impl NasVoiceDomainPreferenceAndUeUsageSetting {
    /// Check the spare bits of the voice preference octet (TS 24.008 §10.5.5.28).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [value] if value & 0xf8 == 0)
    }
}

impl NasN1UeNetworkCapability {
    /// Check the spare bit of the capability octet (TS 24.301 §9.9.3.57).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [value] if value & 0x80 == 0)
    }
}

impl NasTmsiBasedNriContainer {
    /// Check the six spare bits after the NRI (TS 24.008 §10.5.5.31).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [_, low] if low & 0x3f == 0)
    }
}

fn network_name_header_is_well_formed(value: &[u8]) -> bool {
    value
        .first()
        .is_some_and(|header| header & 0x80 != 0 && header & 0x70 <= 0x10)
}

impl NasFullNameForNetwork {
    /// Check the extension bit and alphabet code (TS 24.008 §10.5.3.5a).
    pub fn is_well_formed(&self) -> bool {
        network_name_header_is_well_formed(&self.value)
    }
}

impl NasShortNameForNetwork {
    /// Check the extension bit and alphabet code (TS 24.008 §10.5.3.5a).
    pub fn is_well_formed(&self) -> bool {
        network_name_header_is_well_formed(&self.value)
    }
}

impl NasEquivalentPlmns {
    /// Decode the complete list of 3-octet PLMN identities.
    pub fn plmns(&self) -> Option<Vec<PlmnId>> {
        if self.value.is_empty() || self.value.len() > 45 || !self.value.len().is_multiple_of(3) {
            return None;
        }
        self.value.chunks_exact(3).map(PlmnId::from_tbcd).collect()
    }

    /// Build a list of one to fifteen PLMN identities.
    pub fn from_plmns(plmns: &[PlmnId]) -> Option<Self> {
        if !(1..=15).contains(&plmns.len()) {
            return None;
        }
        let mut value = Vec::with_capacity(plmns.len() * 3);
        for plmn in plmns {
            let bytes = plmn.to_tbcd();
            (PlmnId::from_tbcd(&bytes) == Some(*plmn)).then_some(())?;
            value.extend_from_slice(&bytes);
        }
        Some(Self::new(value))
    }
}

impl NasListOfPlmnsToBeUsedInDisasterCondition {
    /// Decode the complete list of PLMN IDs (TS 24.301 §9.9.3.76).
    pub fn plmns(&self) -> Option<Vec<PlmnId>> {
        if !self.value.len().is_multiple_of(3) {
            return None;
        }
        self.value.chunks_exact(3).map(PlmnId::from_tbcd).collect()
    }

    /// Build a list of up to eighty-five PLMN IDs.
    pub fn from_plmns(plmns: &[PlmnId]) -> Option<Self> {
        if plmns.len() > 85 {
            return None;
        }
        let mut value = Vec::with_capacity(plmns.len() * 3);
        for plmn in plmns {
            let bytes = plmn.to_tbcd();
            (PlmnId::from_tbcd(&bytes) == Some(*plmn)).then_some(())?;
            value.extend_from_slice(&bytes);
        }
        Some(Self::new(value))
    }
}

impl NasMobileStationClassmark2 {
    /// Check the classmark-2 length and spare bit (TS 24.008 §10.5.1.6).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [first, _, _] if first & 0x80 == 0)
    }
}

impl NasNbifomContainer {
    /// Check all parameter-unit boundaries (TS 24.161 §6.1.1).
    pub fn is_well_formed(&self) -> bool {
        let mut remaining = self.value.as_slice();
        while !remaining.is_empty() {
            if remaining.len() < 2 {
                return false;
            }
            let unit_len = 2 + usize::from(remaining[1]);
            if remaining.len() < unit_len {
                return false;
            }
            remaining = &remaining[unit_len..];
        }
        true
    }
}

impl NasCipheringKeyData {
    /// Check ciphering data set boundaries and spare bits (TS 24.301 §9.9.3.56).
    pub fn is_well_formed(&self) -> bool {
        let mut remaining = self.value.as_slice();
        let mut count = 0;
        while !remaining.is_empty() {
            count += 1;
            if count > 16 || remaining.len() < 31 {
                return false;
            }
            let c0_length = remaining[18];
            if c0_length & 0xe0 != 0 || c0_length & 0x1f > 16 {
                return false;
            }
            let sib_start = 19 + usize::from(c0_length & 0x1f);
            let tai_length_at = sib_start + 4 + 5 + 2;
            let Some(&tai_length) = remaining.get(tai_length_at) else {
                return false;
            };
            if remaining[sib_start + 3] & 0x1f != 0 {
                return false;
            }
            let end = tai_length_at + 1 + usize::from(tai_length);
            if remaining.len() < end {
                return false;
            }
            if tai_length != 0 && TaiList::from_bytes(&remaining[tai_length_at + 1..end]).is_none()
            {
                return false;
            }
            remaining = &remaining[end..];
        }
        count > 0
    }
}

impl NasSAndFSatelliteOperationParameters {
    /// Check flag, duration, and satellite-list lengths from TS 24.301 §9.9.3.73.
    pub fn is_well_formed(&self) -> bool {
        let Some(&flags) = self.value.first() else {
            return false;
        };
        let list_mode = (flags >> 2) & 3;
        if flags & 0xf0 != 0 || list_mode == 3 {
            return false;
        }
        let mut offset =
            1 + if flags & 1 != 0 { 2 } else { 0 } + if flags & 2 != 0 { 3 } else { 0 };
        if self.value.len() < offset {
            return false;
        }
        if list_mode == 2 {
            let Some(&count) = self.value.get(offset) else {
                return false;
            };
            offset += 1 + usize::from(count);
        }
        self.value.len() == offset
    }
}

macro_rules! remote_ue_context_list_ie {
    ($name:ident) => {
        impl $name {
            /// Split the declared remote UE contexts without changing their bytes.
            pub fn contexts(&self) -> Option<Vec<&[u8]>> {
                let count = usize::from(*self.value.first()?);
                let mut offset = 1;
                let mut contexts = Vec::with_capacity(count);
                for _ in 0..count {
                    let length = usize::from(*self.value.get(offset)?);
                    if length < 2 || self.value.len() < offset + 1 + length {
                        return None;
                    }
                    contexts.push(&self.value[offset + 1..offset + 1 + length]);
                    offset += 1 + length;
                }
                (offset == self.value.len()).then_some(contexts)
            }
        }
    };
}

remote_ue_context_list_ie!(NasRemoteUeContextConnected);
remote_ue_context_list_ie!(NasRemoteUeContextDisconnected);

impl NasProseKeyManagementFunctionAddress {
    /// Read the PKMF IPv4 or IPv6 address from TS 24.301 §9.9.4.21.
    pub fn address(&self) -> Option<std::net::IpAddr> {
        match self.value.as_slice() {
            [1, bytes @ ..] if bytes.len() == 4 => Some(std::net::IpAddr::V4(
                std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?),
            )),
            [2, bytes @ ..] if bytes.len() == 16 => Some(std::net::IpAddr::V6(
                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?),
            )),
            _ => None,
        }
    }

    /// Build a PKMF address IE from an IP address.
    pub fn from_address(address: std::net::IpAddr) -> Self {
        let mut value = Vec::new();
        match address {
            std::net::IpAddr::V4(ipv4) => {
                value.push(1);
                value.extend_from_slice(&ipv4.octets());
            }
            std::net::IpAddr::V6(ipv6) => {
                value.push(2);
                value.extend_from_slice(&ipv6.octets());
            }
        }
        Self::new(value)
    }
}

// ── APN (TS 24.301 §9.9.4.1) ─────────────────────────────────────────────

impl NasAccessPointName {
    /// Decode length-prefixed labels to a dot-separated APN.
    pub fn as_string(&self) -> Option<String> {
        crate::common::decode_labels(&self.value)
    }

    /// Encode a dot-separated APN of at most 100 wire octets.
    pub fn from_string(apn: &str) -> Option<Self> {
        Some(Self::new(crate::common::encode_labels(apn, 100)?))
    }
}

// ── NAS security algorithms (TS 33.401 §8) ────────────────────────────────

/// EPS NAS ciphering algorithm identifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CipheringAlgorithm {
    /// Null ciphering.
    EEA0 = 0,
    /// SNOW 3G ciphering.
    EEA1 = 1,
    /// AES CTR ciphering.
    EEA2 = 2,
    /// ZUC ciphering.
    EEA3 = 3,
    /// Reserved for future ciphering use.
    EEA4 = 4,
    /// Reserved for future ciphering use.
    EEA5 = 5,
    /// Reserved for future ciphering use.
    EEA6 = 6,
    /// Reserved for future ciphering use.
    EEA7 = 7,
}

impl CipheringAlgorithm {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::EEA0),
            1 => Some(Self::EEA1),
            2 => Some(Self::EEA2),
            3 => Some(Self::EEA3),
            4 => Some(Self::EEA4),
            5 => Some(Self::EEA5),
            6 => Some(Self::EEA6),
            7 => Some(Self::EEA7),
            _ => None,
        }
    }
}

/// EPS NAS integrity algorithm identifier.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum IntegrityAlgorithm {
    /// Null integrity, used for unauthenticated emergency calls.
    EIA0 = 0,
    /// SNOW 3G integrity.
    EIA1 = 1,
    /// AES CMAC integrity.
    EIA2 = 2,
    /// ZUC integrity.
    EIA3 = 3,
    /// Reserved for future integrity use.
    EIA4 = 4,
    /// Reserved for future integrity use.
    EIA5 = 5,
    /// Reserved for future integrity use.
    EIA6 = 6,
    /// Reserved for future integrity use.
    EIA7 = 7,
}

impl IntegrityAlgorithm {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::EIA0),
            1 => Some(Self::EIA1),
            2 => Some(Self::EIA2),
            3 => Some(Self::EIA3),
            4 => Some(Self::EIA4),
            5 => Some(Self::EIA5),
            6 => Some(Self::EIA6),
            7 => Some(Self::EIA7),
            _ => None,
        }
    }
}

impl NasSelectedNasSecurityAlgorithms {
    /// Read the EPS ciphering algorithm in the high nibble.
    pub fn ciphering(&self) -> Option<CipheringAlgorithm> {
        CipheringAlgorithm::from_u8(self.value >> 4)
    }

    /// Read the EPS integrity algorithm in the low nibble.
    pub fn integrity(&self) -> Option<IntegrityAlgorithm> {
        IntegrityAlgorithm::from_u8(self.value & 0x0F)
    }

    /// Build the selected algorithms IE.
    pub fn from_algorithms(ciphering: CipheringAlgorithm, integrity: IntegrityAlgorithm) -> Self {
        Self::new((ciphering as u8) << 4 | integrity as u8)
    }
}

/// EPS attach type from TS 24.301 table 9.9.3.11.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttachType {
    EpsAttach = 1,
    CombinedEpsImsiAttach = 2,
    EpsRlosAttach = 3,
    EpsEmergencyAttach = 6,
    DisasterRoamingAttach = 7,
}

impl AttachType {
    /// Parse a received value, applying the spec's fallback for unused values.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x07 {
            2 => Self::CombinedEpsImsiAttach,
            3 => Self::EpsRlosAttach,
            6 => Self::EpsEmergencyAttach,
            7 => Self::DisasterRoamingAttach,
            _ => Self::EpsAttach,
        }
    }
}

impl NasEpsAttachType {
    /// Build the raw IE from a typed attach type.
    pub fn from_attach_type(value: AttachType) -> Self {
        Self::new(value as u8)
    }

    /// Read the EPS attach type from the lower three bits.
    pub fn attach_type(&self) -> AttachType {
        AttachType::from_u8(self.value)
    }

    /// Set the attach type while preserving the remaining bits.
    pub fn set_attach_type(&mut self, value: AttachType) {
        self.value = (self.value & !0x07) | value as u8;
    }

    /// Builder form of [`Self::set_attach_type`].
    pub fn with_attach_type(mut self, value: AttachType) -> Self {
        self.set_attach_type(value);
        self
    }
}

/// Extended SERVICE REQUEST service type (TS 24.301 table 9.9.3.27.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ServiceType {
    MobileOriginatingCsFallback = 0,
    MobileTerminatingCsFallback = 1,
    MobileOriginatingEmergencyCsFallback = 2,
    PacketServices = 8,
}

impl ServiceType {
    /// Interpret received unused values as specified by the network fallback rules.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0f {
            0 | 3 | 4 => Some(Self::MobileOriginatingCsFallback),
            1 => Some(Self::MobileTerminatingCsFallback),
            2 => Some(Self::MobileOriginatingEmergencyCsFallback),
            8..=11 => Some(Self::PacketServices),
            _ => None,
        }
    }
}

impl NasServiceType {
    pub fn from_service_type(value: ServiceType) -> Self {
        Self::new(value as u8)
    }

    pub fn service_type(&self) -> Option<ServiceType> {
        ServiceType::from_u8(self.value)
    }

    pub fn set_service_type(&mut self, value: ServiceType) {
        self.value = value as u8;
    }

    pub fn with_service_type(mut self, value: ServiceType) -> Self {
        self.set_service_type(value);
        self
    }
}

/// CONTROL PLANE SERVICE REQUEST service type (table 9.9.3.47.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ControlPlaneServiceType {
    MobileOriginating = 0,
    MobileTerminating = 1,
}

impl ControlPlaneServiceType {
    /// Values 2 through 7 use the mobile-originating receive fallback.
    pub fn from_u8(value: u8) -> Self {
        match value & 0x07 {
            1 => Self::MobileTerminating,
            _ => Self::MobileOriginating,
        }
    }
}

impl NasControlPlaneServiceType {
    pub fn from_service_type(value: ControlPlaneServiceType, active: bool) -> Self {
        Self::new(value as u8 | ((active as u8) << 3))
    }

    pub fn service_type(&self) -> ControlPlaneServiceType {
        ControlPlaneServiceType::from_u8(self.value)
    }

    pub fn is_active(&self) -> bool {
        self.value & 0x08 != 0
    }

    pub fn set_service_type(&mut self, value: ControlPlaneServiceType) {
        self.value = (self.value & 0x08) | value as u8;
    }

    pub fn with_service_type(mut self, value: ControlPlaneServiceType) -> Self {
        self.set_service_type(value);
        self
    }

    pub fn with_active(mut self, active: bool) -> Self {
        self.value = (self.value & 0x07) | ((active as u8) << 3);
        self
    }
}

/// EPS PDN type from TS 24.301 table 9.9.4.10.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PdnType {
    Ipv4 = 1,
    Ipv6 = 2,
    Ipv4v6 = 3,
    NonIp = 5,
    Ethernet = 6,
}

impl PdnType {
    /// Parse a received value; code 4 is interpreted as IPv6 by the network.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::Ipv4),
            2 | 4 => Some(Self::Ipv6),
            3 => Some(Self::Ipv4v6),
            5 => Some(Self::NonIp),
            6 => Some(Self::Ethernet),
            _ => None,
        }
    }
}

impl NasPdnType {
    /// Build the raw IE from a typed PDN type.
    pub fn from_pdn_type(value: PdnType) -> Self {
        Self::new(value as u8)
    }

    /// Read the PDN type from the lower three bits.
    pub fn pdn_type(&self) -> Option<PdnType> {
        PdnType::from_u8(self.value)
    }

    /// Set the PDN type while preserving the remaining bits.
    pub fn set_pdn_type(&mut self, value: PdnType) {
        self.value = (self.value & !0x07) | value as u8;
    }

    /// Builder form of [`Self::set_pdn_type`].
    pub fn with_pdn_type(mut self, value: PdnType) -> Self {
        self.set_pdn_type(value);
        self
    }
}

// ── Attach and tracking area update values ─────────────────────────────────

/// EPS attach result from TS 24.301 table 9.9.3.10.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttachResult {
    EpsOnly = 1,
    CombinedEpsImsi = 2,
}

impl AttachResult {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::EpsOnly),
            2 => Some(Self::CombinedEpsImsi),
            _ => None,
        }
    }
}

impl NasEpsAttachResult {
    pub fn from_attach_result(value: AttachResult) -> Self {
        Self::new(value as u8)
    }

    pub fn attach_result(&self) -> Option<AttachResult> {
        AttachResult::from_u8(self.value)
    }

    pub fn set_attach_result(&mut self, value: AttachResult) {
        self.value = (self.value & !0x07) | value as u8;
    }

    pub fn with_attach_result(mut self, value: AttachResult) -> Self {
        self.set_attach_result(value);
        self
    }
}

/// EPS update type from TS 24.301 table 9.9.3.14.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpdateType {
    TaUpdating = 0,
    CombinedTaLaUpdating = 1,
    CombinedTaLaUpdatingWithImsiAttach = 2,
    PeriodicUpdating = 3,
    DisasterRoamingUpdate = 6,
}

impl UpdateType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            0 | 4 | 5 => Some(Self::TaUpdating),
            1 => Some(Self::CombinedTaLaUpdating),
            2 => Some(Self::CombinedTaLaUpdatingWithImsiAttach),
            3 => Some(Self::PeriodicUpdating),
            6 => Some(Self::DisasterRoamingUpdate),
            _ => None,
        }
    }
}

impl NasEpsUpdateType {
    pub fn from_update_type(value: UpdateType) -> Self {
        Self::new(value as u8)
    }

    pub fn update_type(&self) -> Option<UpdateType> {
        UpdateType::from_u8(self.value)
    }

    pub fn set_update_type(&mut self, value: UpdateType) {
        self.value = (self.value & !0x07) | value as u8;
    }

    pub fn with_update_type(mut self, value: UpdateType) -> Self {
        self.set_update_type(value);
        self
    }

    pub fn is_active(&self) -> bool {
        self.value & 0x08 != 0
    }

    pub fn with_active(mut self, active: bool) -> Self {
        self.value = (self.value & !0x08) | ((active as u8) << 3);
        self
    }
}

/// EPS update result from TS 24.301 table 9.9.3.13.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpdateResult {
    TaUpdated = 0,
    CombinedTaLaUpdated = 1,
    TaUpdatedWithIsr = 4,
    CombinedTaLaUpdatedWithIsr = 5,
}

impl UpdateResult {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            0 => Some(Self::TaUpdated),
            1 => Some(Self::CombinedTaLaUpdated),
            4 => Some(Self::TaUpdatedWithIsr),
            5 => Some(Self::CombinedTaLaUpdatedWithIsr),
            _ => None,
        }
    }
}

impl NasEpsUpdateResult {
    pub fn from_update_result(value: UpdateResult) -> Self {
        Self::new(value as u8)
    }

    pub fn update_result(&self) -> Option<UpdateResult> {
        UpdateResult::from_u8(self.value)
    }

    pub fn set_update_result(&mut self, value: UpdateResult) {
        self.value = (self.value & !0x07) | value as u8;
    }

    pub fn with_update_result(mut self, value: UpdateResult) -> Self {
        self.set_update_result(value);
        self
    }
}

// ── Identity and security context ──────────────────────────────────────────

/// Identity type from TS 24.301 table 9.9.3.12.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MobileIdentityType {
    Imsi = 1,
    Imei = 3,
    Guti = 6,
}

impl MobileIdentityType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::Imsi),
            3 => Some(Self::Imei),
            6 => Some(Self::Guti),
            _ => None,
        }
    }
}

/// Parsed EPS GUTI from TS 24.301 figure 9.9.3.12.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Guti {
    pub plmn: PlmnId,
    pub mme_group_id: u16,
    pub mme_code: u8,
    pub m_tmsi: u32,
}

impl Guti {
    /// Parse the 11-octet GUTI value, including the identity type octet.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 11 || bytes[0] != 0xf6 {
            return None;
        }
        Some(Self {
            plmn: PlmnId::from_tbcd(&bytes[1..4])?,
            mme_group_id: u16::from_be_bytes([bytes[4], bytes[5]]),
            mme_code: bytes[6],
            m_tmsi: u32::from_be_bytes(bytes[7..11].try_into().ok()?),
        })
    }

    /// Encode the GUTI value, including the identity type octet.
    pub fn to_bytes(self) -> [u8; 11] {
        let mut bytes = [0u8; 11];
        bytes[0] = 0xf6;
        bytes[1..4].copy_from_slice(&self.plmn.to_tbcd());
        bytes[4..6].copy_from_slice(&self.mme_group_id.to_be_bytes());
        bytes[6] = self.mme_code;
        bytes[7..11].copy_from_slice(&self.m_tmsi.to_be_bytes());
        bytes
    }
}

fn decode_mobile_identity_digits_raw(value: &[u8], kind: u8, max_digits: usize) -> Option<String> {
    if value.len() < 2 || value[0] & 0x07 != kind {
        return None;
    }
    let first = value[0] >> 4;
    if first > 9 {
        return None;
    }
    let mut digits = String::from(char::from(b'0' + first));
    for (index, byte) in value[1..].iter().enumerate() {
        let low = byte & 0x0f;
        let high = byte >> 4;
        if low > 9 {
            return None;
        }
        digits.push(char::from(b'0' + low));
        if high == 0x0f && index + 2 == value.len() {
            continue;
        }
        if high > 9 {
            return None;
        }
        digits.push(char::from(b'0' + high));
    }
    if (digits.len() % 2 == 1) != (value[0] & 0x08 != 0) {
        return None;
    }
    (digits.len() >= 2 && digits.len() <= max_digits).then_some(digits)
}

fn decode_mobile_identity_digits(value: &[u8], kind: MobileIdentityType) -> Option<String> {
    decode_mobile_identity_digits_raw(value, kind as u8, 15)
}

fn encode_mobile_identity_digits_raw(digits: &str, kind: u8, max_digits: usize) -> Option<Vec<u8>> {
    if digits.len() < 2
        || digits.len() > max_digits
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let raw = digits.as_bytes();
    let mut value = vec![(raw[0] - b'0') << 4 | (digits.len() as u8 & 1) << 3 | kind];
    for pair in raw[1..].chunks(2) {
        let high = pair.get(1).map_or(0x0f, |digit| digit - b'0');
        value.push((high << 4) | (pair[0] - b'0'));
    }
    Some(value)
}

fn encode_mobile_identity_digits(digits: &str, kind: MobileIdentityType) -> Option<Vec<u8>> {
    encode_mobile_identity_digits_raw(digits, kind as u8, 15)
}

impl NasMobileIdentity {
    /// Build an IDENTITY RESPONSE mobile identity containing an IMSI.
    pub fn from_imsi(imsi: &str) -> Option<Self> {
        Some(Self::new(encode_mobile_identity_digits_raw(imsi, 1, 15)?))
    }

    /// Build an IDENTITY RESPONSE mobile identity containing an IMEI.
    pub fn from_imei(imei: &str) -> Option<Self> {
        if imei.len() != 15 {
            return None;
        }
        Some(Self::new(encode_mobile_identity_digits_raw(imei, 2, 15)?))
    }

    /// Build a transmitted IMEI from its 14 TAC and serial-number digits.
    /// The fifteenth wire digit is the zero spare required by TS 23.003 §6.2.1.
    pub fn from_imei_tac_snr(tac_snr: &str) -> Option<Self> {
        Self::from_imei(&crate::common::imei_with_spare(tac_snr)?)
    }

    /// Build an IDENTITY RESPONSE mobile identity containing an IMEISV.
    pub fn from_imeisv(imeisv: &str) -> Option<Self> {
        if imeisv.len() != 16 {
            return None;
        }
        Some(Self::new(encode_mobile_identity_digits_raw(imeisv, 3, 16)?))
    }

    /// Build a TMSI mobile identity; its first value octet is 0xF4.
    pub fn from_tmsi(tmsi: u32) -> Self {
        let mut value = vec![0xf4];
        value.extend_from_slice(&tmsi.to_be_bytes());
        Self::new(value)
    }

    /// Decode the IMSI supplied in an IDENTITY RESPONSE.
    pub fn as_imsi(&self) -> Option<String> {
        decode_mobile_identity_digits_raw(&self.value, 1, 15)
    }

    /// Decode the IMEI supplied in an IDENTITY RESPONSE.
    pub fn as_imei(&self) -> Option<String> {
        let digits = decode_mobile_identity_digits_raw(&self.value, 2, 15)?;
        (digits.len() == 15).then_some(digits)
    }

    /// Decode the IMEISV supplied in an IDENTITY RESPONSE.
    pub fn as_imeisv(&self) -> Option<String> {
        let digits = decode_mobile_identity_digits_raw(&self.value, 3, 16)?;
        (digits.len() == 16).then_some(digits)
    }

    /// Decode a four-octet TMSI from an IDENTITY RESPONSE.
    pub fn as_tmsi(&self) -> Option<u32> {
        (self.value.len() == 5 && self.value[0] == 0xf4)
            .then(|| u32::from_be_bytes(self.value[1..5].try_into().expect("four TMSI octets")))
    }

    /// Whether the UE reported no available identity.
    pub fn is_no_identity(&self) -> bool {
        self.value.as_slice() == [0]
    }
}

impl NasImeisv {
    /// Build an IMEISV IE for SECURITY MODE COMPLETE.
    pub fn from_imeisv(imeisv: &str) -> Option<Self> {
        Some(Self::new(NasMobileIdentity::from_imeisv(imeisv)?.value))
    }

    /// Decode the classic 16-digit IMEISV mobile identity.
    pub fn as_imeisv(&self) -> Option<String> {
        NasMobileIdentity::new(self.value.clone()).as_imeisv()
    }
}

impl NasEpsMobileIdentity {
    /// Build an EPS mobile identity containing an IMSI.
    pub fn from_imsi(imsi: &str) -> Option<Self> {
        Some(Self::new(encode_mobile_identity_digits(
            imsi,
            MobileIdentityType::Imsi,
        )?))
    }

    /// Build an EPS mobile identity containing an IMEI.
    pub fn from_imei(imei: &str) -> Self {
        Self::try_from_imei(imei).expect("IMEI must be exactly 15 decimal digits")
    }

    /// Fallible IMEI mobile identity builder.
    pub fn try_from_imei(imei: &str) -> Option<Self> {
        if imei.len() != 15 {
            return None;
        }
        Some(Self::new(encode_mobile_identity_digits(
            imei,
            MobileIdentityType::Imei,
        )?))
    }

    /// Build a transmitted IMEI from its 14 TAC and serial-number digits.
    /// The fifteenth wire digit is the zero spare required by TS 23.003 §6.2.1.
    pub fn from_imei_tac_snr(tac_snr: &str) -> Option<Self> {
        Self::try_from_imei(&crate::common::imei_with_spare(tac_snr)?)
    }

    /// Build an EPS mobile identity containing a GUTI.
    pub fn from_guti(guti: Guti) -> Self {
        Self::new(guti.to_bytes().to_vec())
    }

    /// Decode an IMSI identity.
    pub fn as_imsi(&self) -> Option<String> {
        decode_mobile_identity_digits(&self.value, MobileIdentityType::Imsi)
    }

    /// Decode an IMEI identity.
    pub fn as_imei(&self) -> Option<String> {
        let digits = decode_mobile_identity_digits(&self.value, MobileIdentityType::Imei)?;
        (digits.len() == 15).then_some(digits)
    }

    /// Decode a GUTI identity.
    pub fn as_guti(&self) -> Option<Guti> {
        Guti::from_bytes(&self.value)
    }

    pub fn identity_type(&self) -> Option<MobileIdentityType> {
        self.value
            .first()
            .and_then(|value| MobileIdentityType::from_u8(*value))
    }

    pub fn is_odd_digits(&self) -> Option<bool> {
        self.value.first().map(|value| value & 0x08 != 0)
    }
}

macro_rules! eps_guti_ie {
    ($name:ident) => {
        impl $name {
            /// Build the raw IE from a typed EPS GUTI.
            pub fn from_guti(guti: Guti) -> Self {
                Self::new(guti.to_bytes().to_vec())
            }

            /// Decode the raw IE as an EPS GUTI.
            pub fn as_guti(&self) -> Option<Guti> {
                Guti::from_bytes(&self.value)
            }
        }
    };
}

eps_guti_ie!(NasGuti);
eps_guti_ie!(NasOldGuti);
eps_guti_ie!(NasAdditionalGuti);

/// NAS key set identifier from TS 24.301 table 9.9.3.21.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum KeySetIdentifier {
    Native(u8),
    Mapped(u8),
    NoKey,
}

impl KeySetIdentifier {
    pub fn from_u8(value: u8) -> Self {
        let id = value & 0x07;
        if id == 7 {
            Self::NoKey
        } else if value & 0x08 != 0 {
            Self::Mapped(id)
        } else {
            Self::Native(id)
        }
    }

    pub fn as_u8(self) -> Result<u8> {
        match self {
            Self::Native(id) if id <= 6 => Ok(id),
            Self::Mapped(id) if id <= 6 => Ok(0x08 | id),
            Self::NoKey => Ok(7),
            _ => Err(NasError::EncodingError(
                "EPS NAS key set identifier must be 0..=6".into(),
            )),
        }
    }
}

impl NasKeySetIdentifier {
    pub fn from_key_set_identifier(value: KeySetIdentifier) -> Result<Self> {
        Ok(Self::new(value.as_u8()?))
    }

    pub fn key_set_identifier(&self) -> KeySetIdentifier {
        KeySetIdentifier::from_u8(self.value)
    }
}

impl NasKeySetIdentifierAsme {
    pub fn from_key_set_identifier(value: KeySetIdentifier) -> Result<Self> {
        Ok(Self::new(value.as_u8()?))
    }

    pub fn key_set_identifier(&self) -> KeySetIdentifier {
        KeySetIdentifier::from_u8(self.value)
    }
}

// ── Detach type ──────────────────────────────────────────────────────────────

/// UE-originated detach kind from TS 24.301 table 9.9.3.7.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UeDetachKind {
    Eps = 1,
    Imsi = 2,
    CombinedEpsImsi = 3,
}

impl UeDetachKind {
    pub fn from_u8(value: u8) -> Self {
        match value & 0x07 {
            1 => Self::Eps,
            2 => Self::Imsi,
            _ => Self::CombinedEpsImsi,
        }
    }
}

/// Network-originated detach kind from TS 24.301 table 9.9.3.7.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NetworkDetachKind {
    ReattachRequired = 1,
    ReattachNotRequired = 2,
    Imsi = 3,
}

impl NetworkDetachKind {
    pub fn from_u8(value: u8) -> Self {
        match value & 0x07 {
            1 => Self::ReattachRequired,
            3 => Self::Imsi,
            _ => Self::ReattachNotRequired,
        }
    }
}

impl NasDetachType {
    pub fn from_ue_detach_kind(value: UeDetachKind, switch_off: bool) -> Self {
        Self::new(value as u8 | ((switch_off as u8) << 3))
    }

    pub fn ue_detach_kind(&self) -> UeDetachKind {
        UeDetachKind::from_u8(self.value)
    }

    pub fn network_detach_kind(&self) -> NetworkDetachKind {
        NetworkDetachKind::from_u8(self.value)
    }

    pub fn is_switch_off(&self) -> bool {
        self.value & 0x08 != 0
    }
}

/// Tracking area identity: PLMN and two-octet TAC (TS 24.301 §9.9.3.32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tai {
    pub plmn: PlmnId,
    pub tac: u16,
}

impl Tai {
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        if value.len() != 5 {
            return None;
        }
        Some(Self {
            plmn: PlmnId::from_tbcd(&value[..3])?,
            tac: u16::from_be_bytes([value[3], value[4]]),
        })
    }

    pub fn to_bytes(self) -> [u8; 5] {
        let mut value = [0u8; 5];
        value[..3].copy_from_slice(&self.plmn.to_tbcd());
        value[3..].copy_from_slice(&self.tac.to_be_bytes());
        value
    }
}

impl NasLastVisitedRegisteredTai {
    pub fn from_tai(tai: Tai) -> Self {
        Self::new(tai.to_bytes().to_vec())
    }

    pub fn tai(&self) -> Option<Tai> {
        Tai::from_bytes(&self.value)
    }
}

/// TAI list entries, including all three partial-list formats of §9.9.3.33.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaiList(pub Vec<Tai>);

impl TaiList {
    /// Parse every partial list and expand consecutive TAC ranges.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let mut result = Vec::new();
        let mut offset = 0;
        while offset < value.len() {
            let header = value[offset];
            if header & 0x80 != 0 {
                return None;
            }
            let kind = (header >> 5) & 0x03;
            let count = usize::from((header & 0x1f).min(15)) + 1;
            offset += 1;
            match kind {
                0 | 1 => {
                    let size = if kind == 0 { 3 + 2 * count } else { 5 };
                    let part = value.get(offset..offset + size)?;
                    let plmn = PlmnId::from_tbcd(&part[..3])?;
                    if kind == 0 {
                        for tac_bytes in part[3..].chunks_exact(2) {
                            result.push(Tai {
                                plmn,
                                tac: u16::from_be_bytes([tac_bytes[0], tac_bytes[1]]),
                            });
                        }
                    } else {
                        let first = u16::from_be_bytes([part[3], part[4]]);
                        if usize::from(first) + count > 65_536 {
                            return None;
                        }
                        for step in 0..count {
                            result.push(Tai {
                                plmn,
                                tac: first + step as u16,
                            });
                        }
                    }
                    offset += size;
                }
                2 => {
                    let size = 5 * count;
                    let part = value.get(offset..offset + size)?;
                    for tai in part.chunks_exact(5) {
                        result.push(Tai::from_bytes(tai)?);
                    }
                    offset += size;
                }
                _ => return None,
            }
            if result.len() >= 16 {
                result.truncate(16);
                break;
            }
        }
        (!result.is_empty()).then_some(Self(result))
    }

    /// Encode TAIs in type-10 partial lists of up to 16 entries each.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        if self.0.is_empty() || self.0.len() > 16 {
            return None;
        }
        let mut value = Vec::with_capacity(1 + 5 * self.0.len());
        value.push(0x40 | (self.0.len() as u8 - 1));
        for tai in &self.0 {
            value.extend_from_slice(&tai.to_bytes());
        }
        Some(value)
    }
}

macro_rules! tai_list_ie {
    ($name:ident) => {
        impl $name {
            /// Build the IE from typed TAIs.
            pub fn from_tai_list(list: &TaiList) -> Option<Self> {
                Some(Self::new(list.to_bytes()?))
            }
            /// Decode all TAIs in the IE.
            pub fn tai_list(&self) -> Option<TaiList> {
                TaiList::from_bytes(&self.value)
            }
        }
    };
}
tai_list_ie!(NasTaiList);

/// PDN address variants from TS 24.301 table 9.9.4.9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PdnAddress {
    Ipv4([u8; 4]),
    Ipv6InterfaceId([u8; 8]),
    Ipv4v6 {
        ipv6_interface_id: [u8; 8],
        ipv4: [u8; 4],
    },
    NonIp,
    Ethernet,
}

impl PdnAddress {
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let (&kind, data) = value.split_first()?;
        if kind & 0xf8 != 0 {
            return None;
        }
        match (kind, data) {
            (1, [a, b, c, d]) => Some(Self::Ipv4([*a, *b, *c, *d])),
            (2, [a, b, c, d, e, f, g, h]) => {
                Some(Self::Ipv6InterfaceId([*a, *b, *c, *d, *e, *f, *g, *h]))
            }
            (3, [a, b, c, d, e, f, g, h, i, j, k, l]) => Some(Self::Ipv4v6 {
                ipv6_interface_id: [*a, *b, *c, *d, *e, *f, *g, *h],
                ipv4: [*i, *j, *k, *l],
            }),
            (5, [0, 0, 0, 0]) => Some(Self::NonIp),
            (6, [0, 0, 0, 0]) => Some(Self::Ethernet),
            _ => None,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::Ipv4(addr) => [vec![1], addr.to_vec()].concat(),
            Self::Ipv6InterfaceId(id) => [vec![2], id.to_vec()].concat(),
            Self::Ipv4v6 {
                ipv6_interface_id,
                ipv4,
            } => [vec![3], ipv6_interface_id.to_vec(), ipv4.to_vec()].concat(),
            Self::NonIp => vec![5, 0, 0, 0, 0],
            Self::Ethernet => vec![6, 0, 0, 0, 0],
        }
    }
}

impl NasPdnAddress {
    pub fn from_pdn_address(address: PdnAddress) -> Self {
        Self::new(address.to_bytes())
    }

    pub fn pdn_address(&self) -> Option<PdnAddress> {
        PdnAddress::from_bytes(&self.value)
    }
}

/// APN aggregate maximum bit rates (§9.9.4.2), in coded octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApnAmbr {
    pub downlink: u8,
    pub uplink: u8,
    pub extension: Option<[u8; 2]>,
    pub extension2: Option<[u8; 2]>,
}

impl ApnAmbr {
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        if value.len() >= 2 && (value[0] == 0 || value[1] == 0) {
            return None;
        }
        match value {
            [downlink, uplink] => Some(Self {
                downlink: *downlink,
                uplink: *uplink,
                extension: None,
                extension2: None,
            }),
            [downlink, uplink, dl1, ul1] => Some(Self {
                downlink: *downlink,
                uplink: *uplink,
                extension: Some([*dl1, *ul1]),
                extension2: None,
            }),
            [downlink, uplink, dl1, ul1, dl2, ul2] => Some(Self {
                downlink: *downlink,
                uplink: *uplink,
                extension: Some([*dl1, *ul1]),
                extension2: Some([*dl2, *ul2]),
            }),
            _ => None,
        }
    }

    pub fn to_bytes(self) -> Option<Vec<u8>> {
        if self.downlink == 0
            || self.uplink == 0
            || self.extension2.is_some() && self.extension.is_none()
        {
            return None;
        }
        let mut value = vec![self.downlink, self.uplink];
        if let Some(extension) = self.extension {
            value.extend_from_slice(&extension);
        }
        if let Some(extension2) = self.extension2 {
            value.extend_from_slice(&extension2);
        }
        Some(value)
    }
}

impl NasApnAmbr {
    pub fn from_ambr(ambr: ApnAmbr) -> Option<Self> {
        Some(Self::new(ambr.to_bytes()?))
    }

    pub fn ambr(&self) -> Option<ApnAmbr> {
        ApnAmbr::from_bytes(&self.value)
    }
}

/// EPS QoS coded octets, with optional four-octet bit-rate groups (§9.9.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EpsQos {
    pub qci: u8,
    /// UL-MBR, DL-MBR, UL-GBR, DL-GBR in wire order.
    pub bit_rates: Option<[u8; 4]>,
    pub extension: Option<[u8; 4]>,
    pub extension2: Option<[u8; 4]>,
}

impl EpsQos {
    /// Whether the QCI is assigned or operator-specific for a network-to-UE IE.
    ///
    /// TS 24.301 §9.9.4.3 reserves the gaps between the assigned values.
    pub fn qci_is_network_valid(&self) -> bool {
        matches!(self.qci, 1..=10 | 65..=67 | 69..=76 | 79..=80 | 82..=85 | 128..=254)
    }

    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        if !matches!(value.len(), 1 | 5 | 9 | 13) {
            return None;
        }
        let group = |start| -> Option<[u8; 4]> { value.get(start..start + 4)?.try_into().ok() };
        Some(Self {
            qci: value[0],
            bit_rates: if value.len() >= 5 { group(1) } else { None },
            extension: if value.len() >= 9 { group(5) } else { None },
            extension2: if value.len() >= 13 { group(9) } else { None },
        })
    }

    pub fn to_bytes(self) -> Option<Vec<u8>> {
        if self.extension.is_some() && self.bit_rates.is_none()
            || self.extension2.is_some() && self.extension.is_none()
        {
            return None;
        }
        let mut value = vec![self.qci];
        if let Some(group) = self.bit_rates {
            value.extend_from_slice(&group);
        }
        if let Some(group) = self.extension {
            value.extend_from_slice(&group);
        }
        if let Some(group) = self.extension2 {
            value.extend_from_slice(&group);
        }
        Some(value)
    }
}

impl NasEpsQos {
    pub fn from_qos(qos: EpsQos) -> Option<Self> {
        Some(Self::new(qos.to_bytes()?))
    }

    pub fn qos(&self) -> Option<EpsQos> {
        EpsQos::from_bytes(&self.value)
    }
}

impl NasNewEpsQos {
    /// Decode the EPS QoS fields (TS 24.301 §9.9.4.3).
    pub fn qos(&self) -> Option<EpsQos> {
        EpsQos::from_bytes(&self.value)
    }
}

impl NasRequiredTrafficFlowQos {
    /// Decode the EPS QoS fields (TS 24.301 §9.9.4.3).
    pub fn qos(&self) -> Option<EpsQos> {
        EpsQos::from_bytes(&self.value)
    }
}

impl NasEpsBearerContextStatus {
    /// Set the activity bitmap for EBIs 1 through 15 (§9.9.2.1).
    pub fn from_active_ebis(ebis: &[u8]) -> Option<Self> {
        let mut bits = 0u16;
        for &ebi in ebis {
            if !(1..=15).contains(&ebi) {
                return None;
            }
            bits |= 1 << ebi;
        }
        Some(Self::new(bits.to_le_bytes().to_vec()))
    }

    /// Return active EBIs; EBI zero is spare and must be clear.
    pub fn active_ebis(&self) -> Option<Vec<u8>> {
        if self.value.len() != 2 || self.value[0] & 1 != 0 {
            return None;
        }
        let bits = u16::from_le_bytes([self.value[0], self.value[1]]);
        Some((1..=15).filter(|ebi| bits & (1 << ebi) != 0).collect())
    }
}

macro_rules! ue_network_capability_ie {
    ($name:ident) => {
        impl $name {
            /// Query an EEA support bit in octet 1 (§9.9.3.34).
            pub fn supports_eea(&self, algorithm: CipheringAlgorithm) -> Option<bool> {
                Some(self.value.first()? & (0x80 >> algorithm as u8) != 0)
            }
            /// Query an EIA support bit in octet 2 (§9.9.3.34).
            pub fn supports_eia(&self, algorithm: IntegrityAlgorithm) -> Option<bool> {
                Some(self.value.get(1)? & (0x80 >> algorithm as u8) != 0)
            }
            /// Set an EEA support bit, extending the mandatory two octets.
            pub fn set_eea(&mut self, algorithm: CipheringAlgorithm, supported: bool) {
                if self.value.len() < 2 {
                    self.value.resize(2, 0);
                }
                let mask = 0x80 >> algorithm as u8;
                self.value[0] = (self.value[0] & !mask) | (if supported { mask } else { 0 });
                self.length = self.value.len() as _;
            }
            /// Set an EIA support bit, extending the mandatory two octets.
            pub fn set_eia(&mut self, algorithm: IntegrityAlgorithm, supported: bool) {
                if self.value.len() < 2 {
                    self.value.resize(2, 0);
                }
                let mask = 0x80 >> algorithm as u8;
                self.value[1] = (self.value[1] & !mask) | (if supported { mask } else { 0 });
                self.length = self.value.len() as _;
            }
        }
    };
}
ue_network_capability_ie!(NasUeNetworkCapability);
ue_network_capability_ie!(NasReplayedUeSecurityCapabilities);

/// Direction used to interpret protocol configuration option lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PcoDirection {
    Uplink,
    Downlink,
}

/// One protocol configuration option from TS 24.008 §10.5.6.3.1.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PcoEntry {
    pub identifier: u16,
    pub contents: Vec<u8>,
}

/// Protocol configuration options with the configuration protocol selector.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Pco {
    pub configuration_protocol: u8,
    pub entries: Vec<PcoEntry>,
}

fn pco_two_octet_length(identifier: u16, direction: PcoDirection) -> bool {
    match direction {
        PcoDirection::Uplink => matches!(identifier, 0x0041 | 0x0051 | 0x0056),
        PcoDirection::Downlink => matches!(
            identifier,
            0x0023 | 0x0024 | 0x0030 | 0x0031 | 0x0032 | 0x0041 | 0x0051 | 0x0056
        ),
    }
}

impl Pco {
    /// Parse a PCO value. Some container IDs use a two-octet length only in one direction.
    pub fn from_bytes(value: &[u8], direction: PcoDirection) -> Option<Self> {
        let (&first, mut remaining) = value.split_first()?;
        if first & 0xf8 != 0x80 {
            return None;
        }
        let mut entries = Vec::new();
        while !remaining.is_empty() {
            if remaining.len() < 3 {
                return None;
            }
            let identifier = u16::from_be_bytes([remaining[0], remaining[1]]);
            remaining = &remaining[2..];
            let length = if pco_two_octet_length(identifier, direction) {
                if remaining.len() < 2 {
                    return None;
                }
                let length = u16::from_be_bytes([remaining[0], remaining[1]]) as usize;
                remaining = &remaining[2..];
                length
            } else {
                let length = remaining[0] as usize;
                remaining = &remaining[1..];
                length
            };
            if remaining.len() < length {
                return None;
            }
            entries.push(PcoEntry {
                identifier,
                contents: remaining[..length].to_vec(),
            });
            remaining = &remaining[length..];
        }
        Some(Self {
            configuration_protocol: first & 0x07,
            entries,
        })
    }

    /// Encode a PCO value, checking each container's direction-specific length.
    pub fn to_bytes(&self, direction: PcoDirection) -> Option<Vec<u8>> {
        if self.configuration_protocol != 0 {
            return None;
        }
        let mut value = vec![0x80 | self.configuration_protocol];
        for entry in &self.entries {
            value.extend_from_slice(&entry.identifier.to_be_bytes());
            if pco_two_octet_length(entry.identifier, direction) {
                value.extend_from_slice(&u16::try_from(entry.contents.len()).ok()?.to_be_bytes());
            } else {
                value.push(u8::try_from(entry.contents.len()).ok()?);
            }
            value.extend_from_slice(&entry.contents);
        }
        Some(value)
    }
}

impl NasProtocolConfigurationOptions {
    /// Parse this PCO for the specified sender direction.
    pub fn pco(&self, direction: PcoDirection) -> Option<Pco> {
        Pco::from_bytes(&self.value, direction)
    }

    /// Build the raw PCO IE from typed containers.
    pub fn from_pco(pco: &Pco, direction: PcoDirection) -> Option<Self> {
        let value = pco.to_bytes(direction)?;
        (value.len() <= 251).then(|| Self::new(value))
    }
}

impl NasExtendedProtocolConfigurationOptions {
    /// Parse an extended PCO using the same internal container layout.
    pub fn pco(&self, direction: PcoDirection) -> Option<Pco> {
        Pco::from_bytes(&self.value, direction)
    }

    /// Build an extended PCO IE from typed containers.
    pub fn from_pco(pco: &Pco, direction: PcoDirection) -> Option<Self> {
        let value = pco.to_bytes(direction)?;
        (value.len() <= u16::MAX as usize).then(|| Self::new(value))
    }
}

/// Traffic flow template operation from TS 24.008 §10.5.6.12.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum TftOperation {
    Ignore = 0,
    Create = 1,
    Delete = 2,
    AddFilters = 3,
    ReplaceFilters = 4,
    DeleteFilters = 5,
    NoOperation = 6,
}

impl TftOperation {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Ignore),
            1 => Some(Self::Create),
            2 => Some(Self::Delete),
            3 => Some(Self::AddFilters),
            4 => Some(Self::ReplaceFilters),
            5 => Some(Self::DeleteFilters),
            6 => Some(Self::NoOperation),
            _ => None,
        }
    }
}

/// One TFT packet filter. Delete-filter operations carry only `identifier`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TftPacketFilter {
    pub identifier: u8,
    pub direction: u8,
    pub precedence: Option<u8>,
    pub contents: Vec<u8>,
}

/// A TFT parameter encoded after the packet filters when the E bit is set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TftParameter {
    pub identifier: u8,
    pub contents: Vec<u8>,
}

/// Traffic flow template with packet filters and optional parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tft {
    pub operation: TftOperation,
    pub packet_filters: Vec<TftPacketFilter>,
    pub parameters: Vec<TftParameter>,
}

fn valid_tft_filter_contents(contents: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut ether_type = None;
    let mut remaining = contents;
    while let Some((&kind, rest)) = remaining.split_first() {
        let size = match kind {
            0x10 | 0x11 => 8,
            0x20 => 32,
            0x21 | 0x23 => 17,
            0x30 | 0x85 | 0x86 => 1,
            0x40 | 0x50 | 0x70 | 0x83 | 0x84 | 0x87 => 2,
            0x41 | 0x51 | 0x60 => 4,
            0x80 => 3,
            0x81 | 0x82 => 6,
            _ => return false,
        };
        if seen[kind as usize] || rest.len() < size {
            return false;
        }
        let value = &rest[..size];
        if matches!(kind, 0x80 | 0x83 | 0x84 | 0x85 | 0x86) && value[0] & 0xf0 != 0 {
            return false;
        }
        if kind == 0x87 {
            ether_type = Some(u16::from_be_bytes([value[0], value[1]]));
        }
        seen[kind as usize] = true;
        remaining = &rest[size..];
    }
    if seen[0x10] && (seen[0x20] || seen[0x21])
        || seen[0x20] && seen[0x21]
        || seen[0x11] && seen[0x23]
        || seen[0x40] && seen[0x41]
        || seen[0x50] && seen[0x51]
    {
        return false;
    }
    if let Some(value) = ether_type
        && !matches!(value, 0x0800 | 0x86dd)
        && (seen[0x10]
            || seen[0x11]
            || seen[0x20]
            || seen[0x21]
            || seen[0x23]
            || seen[0x30]
            || seen[0x40]
            || seen[0x41]
            || seen[0x50]
            || seen[0x51]
            || seen[0x60]
            || seen[0x70]
            || seen[0x80])
    {
        return false;
    }
    !contents.is_empty()
}

fn valid_tft_parameters(parameters: &[TftParameter]) -> bool {
    let mut needs_flow_id = false;
    for parameter in parameters {
        match parameter.identifier {
            1 => {
                if needs_flow_id {
                    return false;
                }
                needs_flow_id = true;
            }
            2 => {
                if parameter.contents.len() != 4 {
                    return false;
                }
                needs_flow_id = false;
            }
            3 => {
                if parameter.contents.is_empty()
                    || parameter.contents.iter().any(|value| value & 0xf0 != 0)
                {
                    return false;
                }
            }
            _ => {}
        }
    }
    !needs_flow_id
}

impl Tft {
    /// Parse a TFT value and check its packet filter component syntax.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        Self::from_bytes_mode(value, false)
    }

    fn from_bytes_mode(value: &[u8], traffic_flow_aggregate: bool) -> Option<Self> {
        let (&first, mut remaining) = value.split_first()?;
        let operation = TftOperation::from_u8(first >> 5)?;
        let parameter_present = first & 0x10 != 0;
        let count = usize::from(first & 0x0f);
        match operation {
            TftOperation::Ignore if parameter_present || count != 0 => return None,
            TftOperation::Delete if count != 0 || parameter_present => return None,
            TftOperation::NoOperation if !parameter_present || count != 0 => return None,
            TftOperation::Create
            | TftOperation::AddFilters
            | TftOperation::ReplaceFilters
            | TftOperation::DeleteFilters
                if count == 0 =>
            {
                return None;
            }
            _ => {}
        }
        if operation == TftOperation::Ignore {
            return remaining.is_empty().then_some(Self {
                operation,
                packet_filters: Vec::new(),
                parameters: Vec::new(),
            });
        }
        let mut packet_filters = Vec::with_capacity(count);
        let mut seen_filters = [false; 16];
        for _ in 0..count {
            let (&header, rest) = remaining.split_first()?;
            remaining = rest;
            let identifier = (header & 0x0f) as usize;
            let new_aggregate_filter = traffic_flow_aggregate
                && matches!(operation, TftOperation::Create | TftOperation::AddFilters);
            if new_aggregate_filter && identifier != 0
                || !new_aggregate_filter && seen_filters[identifier]
            {
                return None;
            }
            seen_filters[identifier] = true;
            if operation == TftOperation::DeleteFilters {
                if header & 0xf0 != 0 {
                    return None;
                }
                packet_filters.push(TftPacketFilter {
                    identifier: header,
                    direction: 0,
                    precedence: None,
                    contents: Vec::new(),
                });
            } else {
                if header & 0xc0 != 0 || remaining.len() < 2 {
                    return None;
                }
                let precedence = remaining[0];
                let length = remaining[1] as usize;
                remaining = &remaining[2..];
                if length == 0
                    || remaining.len() < length
                    || !valid_tft_filter_contents(&remaining[..length])
                {
                    return None;
                }
                packet_filters.push(TftPacketFilter {
                    identifier: header & 0x0f,
                    direction: (header >> 4) & 0x03,
                    precedence: Some(precedence),
                    contents: remaining[..length].to_vec(),
                });
                remaining = &remaining[length..];
            }
        }
        let mut parameters = Vec::new();
        if parameter_present {
            if remaining.is_empty() {
                return None;
            }
            while !remaining.is_empty() {
                if remaining.len() < 2 {
                    return None;
                }
                let identifier = remaining[0];
                let length = remaining[1] as usize;
                remaining = &remaining[2..];
                if remaining.len() < length {
                    return None;
                }
                parameters.push(TftParameter {
                    identifier,
                    contents: remaining[..length].to_vec(),
                });
                remaining = &remaining[length..];
            }
        } else if !remaining.is_empty() {
            return None;
        }
        if !valid_tft_parameters(&parameters) {
            return None;
        }
        Some(Self {
            operation,
            packet_filters,
            parameters,
        })
    }

    /// Encode a TFT value after checking operation, count, and record lengths.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        self.to_bytes_mode(false)
    }

    fn to_bytes_mode(&self, traffic_flow_aggregate: bool) -> Option<Vec<u8>> {
        let count = self.packet_filters.len();
        if count > 15 {
            return None;
        }
        match self.operation {
            TftOperation::Ignore if count != 0 || !self.parameters.is_empty() => return None,
            TftOperation::Delete if count != 0 || !self.parameters.is_empty() => return None,
            TftOperation::NoOperation if count != 0 || self.parameters.is_empty() => return None,
            TftOperation::Create
            | TftOperation::AddFilters
            | TftOperation::ReplaceFilters
            | TftOperation::DeleteFilters
                if count == 0 =>
            {
                return None;
            }
            _ => {}
        }
        let mut value = vec![
            (self.operation as u8) << 5
                | if !self.parameters.is_empty() { 0x10 } else { 0 }
                | count as u8,
        ];
        let mut seen_filters = [false; 16];
        for filter in &self.packet_filters {
            if filter.identifier > 15 {
                return None;
            }
            let new_aggregate_filter = traffic_flow_aggregate
                && matches!(
                    self.operation,
                    TftOperation::Create | TftOperation::AddFilters
                );
            if new_aggregate_filter && filter.identifier != 0
                || !new_aggregate_filter && seen_filters[filter.identifier as usize]
            {
                return None;
            }
            seen_filters[filter.identifier as usize] = true;
            if self.operation == TftOperation::DeleteFilters {
                if filter.precedence.is_some()
                    || filter.direction != 0
                    || !filter.contents.is_empty()
                {
                    return None;
                }
                value.push(filter.identifier);
            } else {
                if filter.direction > 3 || !valid_tft_filter_contents(&filter.contents) {
                    return None;
                }
                value.push((filter.direction << 4) | filter.identifier);
                value.push(filter.precedence?);
                value.push(u8::try_from(filter.contents.len()).ok()?);
                value.extend_from_slice(&filter.contents);
            }
        }
        if !valid_tft_parameters(&self.parameters) {
            return None;
        }
        for parameter in &self.parameters {
            value.push(parameter.identifier);
            value.push(u8::try_from(parameter.contents.len()).ok()?);
            value.extend_from_slice(&parameter.contents);
        }
        Some(value)
    }
}

macro_rules! tft_ie {
    ($name:ident) => {
        impl $name {
            /// Parse this IE as a TFT.
            pub fn tft(&self) -> Option<Tft> {
                Tft::from_bytes(&self.value)
            }
            /// Build a raw IE from a typed TFT.
            pub fn from_tft(tft: &Tft) -> Option<Self> {
                let value = tft.to_bytes()?;
                (value.len() <= u8::MAX as usize).then(|| Self::new(value))
            }
        }
    };
}
tft_ie!(NasTft);

impl NasTrafficFlowAggregate {
    /// Parse a UE traffic flow aggregate, including repeated unassigned filter IDs.
    pub fn tft(&self) -> Option<Tft> {
        Tft::from_bytes_mode(&self.value, true)
    }

    /// Build a UE traffic flow aggregate from packet filters and parameters.
    pub fn from_tft(tft: &Tft) -> Option<Self> {
        let value = tft.to_bytes_mode(true)?;
        (value.len() <= u8::MAX as usize).then(|| Self::new(value))
    }
}

/// GPRS timer unit from TS 24.008 §10.5.7.3 and §10.5.7.4.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum GprsTimerUnit {
    TwoSeconds = 0,
    OneMinute = 1,
    SixMinutes = 2,
    Deactivated = 7,
}

impl GprsTimerUnit {
    pub fn from_u8(value: u8) -> Self {
        match value & 7 {
            0 => Self::TwoSeconds,
            2 => Self::SixMinutes,
            7 => Self::Deactivated,
            _ => Self::OneMinute,
        }
    }

    pub fn seconds_multiplier(self) -> u64 {
        match self {
            Self::TwoSeconds => 2,
            Self::OneMinute => 60,
            Self::SixMinutes => 360,
            Self::Deactivated => 0,
        }
    }
}

/// GPRS timer 3 unit from TS 24.008 §10.5.7.4a.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum GprsTimer3Unit {
    TenMinutes = 0,
    OneHour = 1,
    TenHours = 2,
    TwoSeconds = 3,
    ThirtySeconds = 4,
    OneMinute = 5,
    ThreeHundredTwentyHours = 6,
    Deactivated = 7,
}

impl GprsTimer3Unit {
    pub fn from_u8(value: u8) -> Self {
        match value & 7 {
            0 => Self::TenMinutes,
            1 => Self::OneHour,
            2 => Self::TenHours,
            3 => Self::TwoSeconds,
            4 => Self::ThirtySeconds,
            5 => Self::OneMinute,
            6 => Self::ThreeHundredTwentyHours,
            _ => Self::Deactivated,
        }
    }

    pub fn seconds_multiplier(self) -> u64 {
        match self {
            Self::TenMinutes => 600,
            Self::OneHour => 3_600,
            Self::TenHours => 36_000,
            Self::TwoSeconds => 2,
            Self::ThirtySeconds => 30,
            Self::OneMinute => 60,
            Self::ThreeHundredTwentyHours => 1_152_000,
            Self::Deactivated => 0,
        }
    }
}

macro_rules! gprs_timer_ie {
    ($name:ident, $unit:ident, $zero_deactivated:expr) => {
        impl $name {
            /// Timer unit encoded in the high three bits.
            pub fn unit(&self) -> $unit {
                $unit::from_u8(self.value >> 5)
            }
            /// Timer value encoded in the low five bits.
            pub fn timer_value(&self) -> u8 {
                self.value & 0x1f
            }
            /// Effective duration in seconds, or `None` when deactivated.
            pub fn to_seconds(&self) -> Option<u64> {
                let unit = self.unit();
                (unit.seconds_multiplier() != 0 && (!$zero_deactivated || self.timer_value() != 0))
                    .then(|| unit.seconds_multiplier() * self.timer_value() as u64)
            }
            /// Build the timer from a unit and five-bit value.
            pub fn from_unit_value(unit: $unit, value: u8) -> Self {
                Self::new((unit as u8) << 5 | (value & 0x1f))
            }
        }
    };
}

gprs_timer_ie!(NasT3412Value, GprsTimerUnit, true);
gprs_timer_ie!(NasT3402Value, GprsTimerUnit, false);
gprs_timer_ie!(NasT3423Value, GprsTimerUnit, false);
gprs_timer_ie!(NasT3442Value, GprsTimerUnit, false);

macro_rules! gprs_timer_vector_ie {
    ($name:ident, $unit:ident, $reject_320_hours:expr) => {
        impl $name {
            /// Timer unit and value if this IE contains one timer octet.
            pub fn timer(&self) -> Option<($unit, u8)> {
                (self.value.len() == 1)
                    .then(|| ($unit::from_u8(self.value[0] >> 5), self.value[0] & 0x1f))
            }
            /// Effective duration in seconds, or `None` when deactivated or malformed.
            pub fn to_seconds(&self) -> Option<u64> {
                let (unit, value) = self.timer()?;
                (unit.seconds_multiplier() != 0 && (!$reject_320_hours || unit as u8 != 6))
                    .then(|| unit.seconds_multiplier() * value as u64)
            }
            /// Build a one-octet timer IE.
            pub fn from_unit_value(unit: $unit, value: u8) -> Self {
                Self::new(vec![(unit as u8) << 5 | (value & 0x1f)])
            }
        }
    };
}

gprs_timer_vector_ie!(NasT3346Value, GprsTimerUnit, false);
gprs_timer_vector_ie!(NasT3324Value, GprsTimerUnit, false);
gprs_timer_vector_ie!(NasT3448Value, GprsTimerUnit, false);
gprs_timer_vector_ie!(NasBackOffTimerValue, GprsTimer3Unit, true);
gprs_timer_vector_ie!(NasT3396Value, GprsTimer3Unit, true);
gprs_timer_vector_ie!(NasT3447Value, GprsTimer3Unit, true);
gprs_timer_vector_ie!(NasLowerBoundTimerValue, GprsTimer3Unit, true);

impl NasT3412ExtendedValue {
    /// Decode the one-octet extended T3412 timer.
    pub fn timer(&self) -> Option<(GprsTimer3Unit, u8)> {
        (self.value.len() == 1).then(|| {
            (
                GprsTimer3Unit::from_u8(self.value[0] >> 5),
                self.value[0] & 0x1f,
            )
        })
    }

    /// Interpret the timer using the integrity protection of its containing message.
    /// Unit 110 is one hour without integrity protection, and 320 hours with it.
    pub fn to_seconds_with_integrity(&self, integrity_protected: bool) -> Option<u64> {
        let (unit, value) = self.timer()?;
        if unit == GprsTimer3Unit::Deactivated || value == 0 {
            return None;
        }
        let multiplier = if unit == GprsTimer3Unit::ThreeHundredTwentyHours && !integrity_protected
        {
            3_600
        } else {
            unit.seconds_multiplier()
        };
        Some(multiplier * value as u64)
    }

    /// Build an extended T3412 IE from a unit and five-bit value.
    pub fn from_unit_value(unit: GprsTimer3Unit, value: u8) -> Self {
        Self::new(vec![(unit as u8) << 5 | (value & 0x1f)])
    }
}

/// Identity requested by an EPS IDENTITY REQUEST (TS 24.008 §10.5.5.9).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IdentityTypeValue {
    Imsi = 1,
    Imei = 2,
    Imeisv = 3,
    Tmsi = 4,
}

impl NasIdentityType {
    /// The specified identity, or `None` for an extension value.
    pub fn identity_type(&self) -> Option<IdentityTypeValue> {
        match self.value & 7 {
            1 => Some(IdentityTypeValue::Imsi),
            2 => Some(IdentityTypeValue::Imei),
            3 => Some(IdentityTypeValue::Imeisv),
            4 => Some(IdentityTypeValue::Tmsi),
            _ => None,
        }
    }

    /// Raw three-bit identity type, preserving unknown codes.
    pub fn identity_type_raw(&self) -> u8 {
        self.value & 7
    }

    /// Construct a sender value with the spare bit cleared.
    pub fn from_identity_type(identity_type: IdentityTypeValue) -> Self {
        Self::new(identity_type as u8)
    }
}

impl NasImeisvRequest {
    /// Whether the network requests IMEISV (TS 24.008 §10.5.5.10).
    pub fn is_requested(&self) -> bool {
        self.value & 7 == 1
    }

    /// Construct a request with spare bits clear.
    pub fn from_requested(requested: bool) -> Self {
        Self::new(u8::from(requested))
    }
}

/// EPS PDN connectivity request type (TS 24.008 §10.5.6.17).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RequestTypeValue {
    Initial = 1,
    Handover = 2,
    Rlos = 3,
    Emergency = 4,
    EmergencyHandover = 6,
}

impl NasRequestType {
    /// Decode a defined request type, leaving reserved values untyped.
    pub fn request_type(&self) -> Option<RequestTypeValue> {
        match self.value & 7 {
            1 => Some(RequestTypeValue::Initial),
            2 => Some(RequestTypeValue::Handover),
            3 => Some(RequestTypeValue::Rlos),
            4 => Some(RequestTypeValue::Emergency),
            6 => Some(RequestTypeValue::EmergencyHandover),
            _ => None,
        }
    }

    /// Construct a sender value with the spare bit cleared.
    pub fn from_request_type(request_type: RequestTypeValue) -> Self {
        Self::new(request_type as u8)
    }
}

impl NasEsmInformationTransferFlag {
    /// Whether the APN or PCO must be transferred under NAS security (§9.9.4.5).
    pub fn is_required(&self) -> bool {
        self.value & 1 != 0
    }

    /// Construct the EIT value with spare bits clear.
    pub fn from_required(required: bool) -> Self {
        Self::new(u8::from(required))
    }
}

impl NasEpsNetworkFeatureSupport {
    /// IMS voice over PS session support (octet 3, bit 1; §9.9.3.12A).
    pub fn ims_voice_over_ps(&self) -> Option<bool> {
        Some(self.value.first()? & 0x01 != 0)
    }

    /// Emergency bearer service support (octet 3, bit 2).
    pub fn emergency_bearer_services(&self) -> Option<bool> {
        Some(self.value.first()? & 0x02 != 0)
    }

    /// Control plane CIoT EPS optimization support (octet 3, bit 8).
    pub fn control_plane_ciot(&self) -> Option<bool> {
        Some(self.value.first()? & 0x80 != 0)
    }

    /// User plane CIoT EPS optimization support (octet 4, bit 1).
    pub fn user_plane_ciot(&self) -> bool {
        self.value.get(1).is_some_and(|octet| octet & 0x01 != 0)
    }

    /// Extended PCO support (octet 4, bit 4).
    pub fn extended_pco(&self) -> bool {
        self.value.get(1).is_some_and(|octet| octet & 0x08 != 0)
    }

    /// NAS signalling connection release support (octet 5, bit 1).
    pub fn nas_signalling_connection_release(&self) -> bool {
        self.value.get(2).is_some_and(|octet| octet & 0x01 != 0)
    }
}

impl NasExtendedDrxParameters {
    /// Paging Time Window code in bits 5–8 (TS 24.008 §10.5.5.32).
    pub fn paging_time_window(&self) -> u8 {
        self.value.first().map_or(0, |octet| octet >> 4)
    }

    /// Set the Paging Time Window while preserving the eDRX code.
    pub fn set_paging_time_window(&mut self, ptw: u8) {
        if self.value.is_empty() {
            self.value.push(0);
        }
        self.value[0] = (self.value[0] & 0x0f) | ((ptw & 0x0f) << 4);
        self.length = self.value.len() as _;
    }

    /// Builder form of [`Self::set_paging_time_window`].
    pub fn with_paging_time_window(mut self, ptw: u8) -> Self {
        self.set_paging_time_window(ptw);
        self
    }

    /// eDRX cycle code in bits 1–4.
    pub fn edrx_value(&self) -> u8 {
        self.value.first().map_or(0, |octet| octet & 0x0f)
    }

    /// Set the eDRX cycle while preserving the Paging Time Window.
    pub fn set_edrx_value(&mut self, value: u8) {
        if self.value.is_empty() {
            self.value.push(0);
        }
        self.value[0] = (self.value[0] & 0xf0) | (value & 0x0f);
        self.length = self.value.len() as _;
    }

    /// Builder form of [`Self::set_edrx_value`].
    pub fn with_edrx_value(mut self, value: u8) -> Self {
        self.set_edrx_value(value);
        self
    }
}

impl NasReAttemptIndicator {
    /// Whether retry in an equivalent PLMN is forbidden (§9.9.4.13A, bit 2).
    pub fn eplmnc_not_allowed(&self) -> bool {
        self.value.first().is_some_and(|octet| octet & 0x02 != 0)
    }

    /// Whether retry in A/Gb, Iu, or N1 mode is forbidden (bit 1).
    pub fn ratc_not_allowed(&self) -> bool {
        self.value.first().is_some_and(|octet| octet & 0x01 != 0)
    }

    /// Build from the two restriction flags with spare bits clear.
    pub fn from_flags(eplmnc_not_allowed: bool, ratc_not_allowed: bool) -> Self {
        Self::new(vec![
            (u8::from(eplmnc_not_allowed) << 1) | u8::from(ratc_not_allowed),
        ])
    }
}

impl NasServingPlmnRateControl {
    /// Maximum uplink user-data transports per six minutes (§9.9.4.28).
    /// `0xffff` denotes no restriction; values below 10 are invalid.
    pub fn rate(&self) -> Option<u16> {
        let rate = self.rate_raw();
        (rate >= 10).then_some(rate)
    }

    /// Raw rate value, including reserved values; returns zero if incomplete.
    pub fn rate_raw(&self) -> u16 {
        match self.value.as_slice() {
            [high, low] => u16::from_be_bytes([*high, *low]),
            _ => 0,
        }
    }

    /// Build a valid rate; `0xffff` means unrestricted.
    pub fn from_rate(rate: u16) -> Option<Self> {
        (rate >= 10).then(|| Self::new(rate.to_be_bytes().to_vec()))
    }

    /// Whether the rate imposes no restriction.
    pub fn is_unrestricted(&self) -> bool {
        self.rate() == Some(u16::MAX)
    }
}

/// Downlink data expected indication (TS 24.301 §9.9.4.25).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DownlinkDataExpected {
    /// No information available.
    NoInfo = 0,
    /// No further uplink or downlink data expected.
    NoFurtherData = 1,
    /// One downlink data transmission, then no further data expected.
    SingleDlThenNone = 2,
}

impl DownlinkDataExpected {
    /// Decode the two-bit value, rejecting the reserved value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x03 {
            0 => Some(Self::NoInfo),
            1 => Some(Self::NoFurtherData),
            2 => Some(Self::SingleDlThenNone),
            _ => None,
        }
    }
}

impl NasReleaseAssistanceIndication {
    /// Typed downlink data expected value (bits 1–2).
    pub fn ddx(&self) -> Option<DownlinkDataExpected> {
        DownlinkDataExpected::from_u8(self.value & 0x03)
    }

    /// Raw downlink data expected value.
    pub fn ddx_raw(&self) -> u8 {
        self.value & 0x03
    }

    /// Build with spare bits clear.
    pub fn from_ddx(ddx: DownlinkDataExpected) -> Self {
        Self::new(ddx as u8)
    }
}

impl NasUeStatus {
    /// N1 mode registration status (bit 2).
    pub fn n1_mode_reg(&self) -> bool {
        self.value.first().is_some_and(|octet| octet & 0x02 != 0)
    }

    /// S1 mode registration status (bit 1).
    pub fn s1_mode_reg(&self) -> bool {
        self.value.first().is_some_and(|octet| octet & 0x01 != 0)
    }

    /// Build with spare bits clear.
    pub fn from_status(n1_reg: bool, s1_reg: bool) -> Self {
        Self::new(vec![(u8::from(n1_reg) << 1) | u8::from(s1_reg)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_assistance_and_ue_status_match_5gs_helpers() {
        let release =
            NasReleaseAssistanceIndication::from_ddx(DownlinkDataExpected::SingleDlThenNone);
        assert_eq!(release.ddx(), Some(DownlinkDataExpected::SingleDlThenNone));
        assert_eq!(release.ddx_raw(), 2);
        assert_eq!(NasReleaseAssistanceIndication::new(3).ddx(), None);

        let status = NasUeStatus::from_status(true, false);
        assert!(status.n1_mode_reg());
        assert!(!status.s1_mode_reg());
        assert_eq!(status.value, [0x02]);
    }

    #[test]
    fn requested_identity_security_and_feature_bits() {
        assert_eq!(
            NasIdentityType::from_identity_type(IdentityTypeValue::Imeisv).identity_type(),
            Some(IdentityTypeValue::Imeisv)
        );
        assert_eq!(NasIdentityType::new(0xf7).identity_type_raw(), 7);
        assert_eq!(NasIdentityType::new(7).identity_type(), None);
        assert!(NasImeisvRequest::from_requested(true).is_requested());
        assert!(!NasImeisvRequest::new(2).is_requested());
        assert_eq!(
            NasRequestType::from_request_type(RequestTypeValue::EmergencyHandover).request_type(),
            Some(RequestTypeValue::EmergencyHandover)
        );
        assert_eq!(NasRequestType::new(5).request_type(), None);
        assert!(NasEsmInformationTransferFlag::from_required(true).is_required());

        let feature = NasEpsNetworkFeatureSupport::new(vec![0x83, 0x09, 0x01]);
        assert_eq!(feature.ims_voice_over_ps(), Some(true));
        assert_eq!(feature.emergency_bearer_services(), Some(true));
        assert_eq!(feature.control_plane_ciot(), Some(true));
        assert!(feature.user_plane_ciot());
        assert!(feature.extended_pco());
        assert!(feature.nas_signalling_connection_release());
        assert!(!NasEpsNetworkFeatureSupport::new(vec![0]).extended_pco());

        let mut replayed = NasReplayedUeSecurityCapabilities::new(vec![0, 0]);
        replayed.set_eea(CipheringAlgorithm::EEA2, true);
        replayed.set_eia(IntegrityAlgorithm::EIA1, true);
        assert_eq!(replayed.supports_eea(CipheringAlgorithm::EEA2), Some(true));
        assert_eq!(replayed.supports_eia(IntegrityAlgorithm::EIA1), Some(true));
    }

    #[test]
    fn extended_drx_retry_and_eps_rate_helpers() {
        let drx = NasExtendedDrxParameters::new(vec![])
            .with_paging_time_window(0xa)
            .with_edrx_value(3);
        assert_eq!(drx.value, [0xa3]);
        assert_eq!(drx.length, 1);
        assert_eq!((drx.paging_time_window(), drx.edrx_value()), (10, 3));

        let retry = NasReAttemptIndicator::from_flags(true, false);
        assert_eq!(retry.value, [0x02]);
        assert!(retry.eplmnc_not_allowed());
        assert!(!retry.ratc_not_allowed());

        assert!(NasServingPlmnRateControl::from_rate(9).is_none());
        let limited = NasServingPlmnRateControl::from_rate(10).unwrap();
        assert_eq!(limited.value, [0, 10]);
        assert_eq!(limited.rate(), Some(10));
        assert!(!limited.is_unrestricted());
        let unlimited = NasServingPlmnRateControl::from_rate(u16::MAX).unwrap();
        assert!(unlimited.is_unrestricted());
        assert_eq!(NasServingPlmnRateControl::new(vec![0, 9]).rate(), None);
    }

    #[test]
    fn paging_and_unavailability_flags_match_payload_lengths() {
        assert!(NasPagingRestriction::new(vec![1]).is_well_formed());
        assert!(NasPagingRestriction::new(vec![3, 0x02, 0xff]).is_well_formed());
        assert!(!NasPagingRestriction::new(vec![3]).is_well_formed());
        assert!(!NasPagingRestriction::new(vec![3, 0x01, 0xff]).is_well_formed());
        assert!(NasEpsAdditionalRequestResult::new(vec![2]).is_well_formed());
        assert!(!NasEpsAdditionalRequestResult::new(vec![3]).is_well_formed());

        for flags in [0, 0x08, 0x10, 0x18] {
            let mut value = vec![flags];
            value.resize(
                1 + 3 * ((flags & 0x08 != 0) as usize + (flags & 0x10 != 0) as usize),
                0,
            );
            assert!(NasUnavailabilityInformation::new(value.clone()).is_well_formed());
            value.push(0);
            assert!(!NasUnavailabilityInformation::new(value).is_well_formed());
        }
        for flags in [0, 0x02, 0x04, 0x06] {
            let mut value = vec![flags];
            value.resize(
                1 + 3 * ((flags & 0x02 != 0) as usize + (flags & 0x04 != 0) as usize),
                0,
            );
            assert!(NasUnavailabilityConfiguration::new(value.clone()).is_well_formed());
            value.pop();
            assert!(!NasUnavailabilityConfiguration::new(value).is_well_formed());
        }
    }

    #[test]
    fn delegated_codec_drx_and_daylight_fields_follow_24_008() {
        let codecs = NasSupportedCodecs::new(vec![0, 1, 0xff, 4, 2, 0x12, 0x34]);
        assert_eq!(
            codecs.codec_bitmaps(),
            Some(vec![(0, vec![0xff]), (4, vec![0x12, 0x34])])
        );
        assert!(
            NasSupportedCodecs::new(vec![0, 2, 0xff])
                .codec_bitmaps()
                .is_none()
        );
        assert!(NasDrxParameter::new(vec![98, 0x90]).is_well_formed());
        assert!(!NasDrxParameter::new(vec![99, 0x90]).is_well_formed());
        assert!(!NasDrxParameter::new(vec![98, 0x50]).is_well_formed());
        assert!(NasNetworkDaylightSavingTime::new(vec![2]).is_well_formed());
        assert!(!NasNetworkDaylightSavingTime::new(vec![0xff]).is_well_formed());
    }

    #[test]
    fn emergency_and_spare_bit_fields_follow_delegated_rules() {
        assert!(NasEmergencyNumberList::new(vec![2, 0, 0x11]).is_well_formed());
        assert!(!NasEmergencyNumberList::new(vec![5, 0, 0x11]).is_well_formed());
        assert!(NasExtendedEmergencyNumberList::new(vec![0, 1, 0x11, 0]).is_well_formed());
        assert!(!NasExtendedEmergencyNumberList::new(vec![0, 5, 0x11, 0]).is_well_formed());
        assert!(NasVoiceDomainPreferenceAndUeUsageSetting::new(vec![7]).is_well_formed());
        assert!(!NasVoiceDomainPreferenceAndUeUsageSetting::new(vec![0xf8]).is_well_formed());
        assert!(NasN1UeNetworkCapability::new(vec![0x7f]).is_well_formed());
        assert!(!NasN1UeNetworkCapability::new(vec![0x80]).is_well_formed());
        assert!(NasTmsiBasedNriContainer::new(vec![0x12, 0xc0]).is_well_formed());
        assert!(!NasTmsiBasedNriContainer::new(vec![0x12, 1]).is_well_formed());
        assert!(NasFullNameForNetwork::new(vec![0x80]).is_well_formed());
        assert!(!NasShortNameForNetwork::new(vec![0xa0]).is_well_formed());
    }

    #[test]
    fn service_type_helpers_keep_receiver_fallbacks_separate_from_builders() {
        assert_eq!(
            ServiceType::from_u8(3),
            Some(ServiceType::MobileOriginatingCsFallback)
        );
        assert_eq!(ServiceType::from_u8(9), Some(ServiceType::PacketServices));
        assert_eq!(ServiceType::from_u8(7), None);
        assert_eq!(
            NasServiceType::from_service_type(ServiceType::PacketServices).value,
            8
        );

        let cp = NasControlPlaneServiceType::from_service_type(
            ControlPlaneServiceType::MobileTerminating,
            true,
        );
        assert_eq!(cp.value, 9);
        assert_eq!(
            cp.service_type(),
            ControlPlaneServiceType::MobileTerminating
        );
        assert!(cp.is_active());
        assert_eq!(
            ControlPlaneServiceType::from_u8(7),
            ControlPlaneServiceType::MobileOriginating
        );
    }

    #[test]
    fn typed_network_and_relay_ie_accessors_preserve_valid_payloads() {
        let plmn = PlmnId::from_tbcd(&[0x02, 0xf8, 0x39]).unwrap();
        let list = NasEquivalentPlmns::from_plmns(&[plmn]).unwrap();
        assert_eq!(list.plmns(), Some(vec![plmn]));
        let disaster_list = NasListOfPlmnsToBeUsedInDisasterCondition::from_plmns(&[plmn]).unwrap();
        assert_eq!(disaster_list.plmns(), Some(vec![plmn]));
        assert!(
            NasListOfPlmnsToBeUsedInDisasterCondition::new(vec![0x02, 0xf8])
                .plmns()
                .is_none()
        );
        assert!(
            NasListOfPlmnsToBeUsedInDisasterCondition::new(vec![0xff, 0xff, 0xff])
                .plmns()
                .is_none()
        );
        assert_eq!(
            NasListOfPlmnsToBeUsedInDisasterCondition::new(vec![]).plmns(),
            Some(vec![])
        );
        assert!(NasMobileStationClassmark2::new(vec![0, 0, 0]).is_well_formed());
        assert!(!NasMobileStationClassmark2::new(vec![0x80, 0, 0]).is_well_formed());
        assert!(NasNbifomContainer::new(vec![1, 1, 0]).is_well_formed());
        assert!(!NasNbifomContainer::new(vec![1]).is_well_formed());
        assert!(!NasNbifomContainer::new(vec![1, 10]).is_well_formed());
        let mut ciphering_set = vec![0; 32];
        ciphering_set[18] = 1;
        assert!(NasCipheringKeyData::new(ciphering_set.clone()).is_well_formed());
        ciphering_set[18] = 31;
        assert!(!NasCipheringKeyData::new(ciphering_set.clone()).is_well_formed());
        ciphering_set[18] = 1;
        ciphering_set[23] = 1;
        assert!(!NasCipheringKeyData::new(ciphering_set).is_well_formed());
        assert!(
            NasEquivalentPlmns::new(vec![0x02, 0xf8, 0x39, 0])
                .plmns()
                .is_none()
        );

        assert!(NasSAndFSatelliteOperationParameters::new(vec![0x01, 0, 1]).is_well_formed());
        assert!(NasSAndFSatelliteOperationParameters::new(vec![0x08, 2, 7, 8]).is_well_formed());
        assert!(!NasSAndFSatelliteOperationParameters::new(vec![0x01]).is_well_formed());

        let contexts = NasRemoteUeContextConnected::new(vec![1, 2, 0, 0]);
        assert_eq!(contexts.contexts(), Some(vec![&[0, 0][..]]));
        assert!(
            NasRemoteUeContextDisconnected::new(vec![1, 0])
                .contexts()
                .is_none()
        );

        let address = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let ie = NasProseKeyManagementFunctionAddress::from_address(address);
        assert_eq!(ie.address(), Some(address));
    }

    #[test]
    fn mobile_identities_and_guti_follow_eps_wire_layout() {
        let imsi = NasEpsMobileIdentity::from_imsi("208930000000001").unwrap();
        assert_eq!(hex::encode(&imsi.value), "2980390000000010");
        assert_eq!(imsi.as_imsi().as_deref(), Some("208930000000001"));
        let even = NasEpsMobileIdentity::from_imsi("208930").unwrap();
        assert_eq!(even.as_imsi().as_deref(), Some("208930"));
        assert!(NasEpsMobileIdentity::from_imsi("1").is_none());
        assert!(NasEpsMobileIdentity::try_from_imei("12").is_none());
        assert!(
            NasEpsMobileIdentity::new(vec![0x29, 0x0a])
                .as_imsi()
                .is_none()
        );
        let imei = NasEpsMobileIdentity::from_imei("123456789012345");
        assert_eq!(imei.as_imei().as_deref(), Some("123456789012345"));
        let guti = Guti {
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0f],
            },
            mme_group_id: 0x1234,
            mme_code: 0x56,
            m_tmsi: 0x789a_bcde,
        };
        assert_eq!(hex::encode(guti.to_bytes()), "f602f839123456789abcde");
        assert_eq!(NasEpsMobileIdentity::from_guti(guti).as_guti(), Some(guti));
    }

    #[test]
    fn tai_lists_parse_all_three_partial_list_types() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        };
        let a = Tai { plmn, tac: 0x1234 };
        let b = Tai { plmn, tac: 0x1235 };
        assert_eq!(Tai::from_bytes(&a.to_bytes()), Some(a));
        let generic = TaiList(vec![a, b]);
        assert_eq!(
            generic.to_bytes().unwrap(),
            [
                0x41, 0x02, 0xf8, 0x39, 0x12, 0x34, 0x02, 0xf8, 0x39, 0x12, 0x35
            ]
        );
        assert_eq!(
            TaiList::from_bytes(&generic.to_bytes().unwrap()),
            Some(generic.clone())
        );
        assert_eq!(
            TaiList::from_bytes(&[0x01, 0x02, 0xf8, 0x39, 0x12, 0x34, 0x12, 0x35]),
            Some(generic.clone())
        );
        assert_eq!(
            TaiList::from_bytes(&[0x21, 0x02, 0xf8, 0x39, 0x12, 0x34]),
            Some(generic)
        );
        assert!(TaiList::from_bytes(&[0x61, 0x02, 0xf8, 0x39, 0x12, 0x34]).is_none());
        assert!(TaiList::from_bytes(&[0x81, 0x02, 0xf8, 0x39, 0x12, 0x34]).is_none());
    }

    #[test]
    fn pdn_qos_ambr_bearer_and_capability_accessors() {
        let pdn = PdnAddress::Ipv4v6 {
            ipv6_interface_id: [1; 8],
            ipv4: [192, 0, 2, 1],
        };
        assert_eq!(
            NasPdnAddress::from_pdn_address(pdn).pdn_address(),
            Some(pdn)
        );
        assert!(PdnAddress::from_bytes(&[3, 0, 0, 0, 0]).is_none());
        let ambr = ApnAmbr {
            downlink: 1,
            uplink: 2,
            extension: Some([3, 4]),
            extension2: Some([5, 6]),
        };
        assert_eq!(NasApnAmbr::from_ambr(ambr).unwrap().ambr(), Some(ambr));
        assert!(ApnAmbr::from_bytes(&[1, 2, 3]).is_none());
        let qos = EpsQos {
            qci: 9,
            bit_rates: Some([1, 2, 3, 4]),
            extension: None,
            extension2: None,
        };
        assert_eq!(NasEpsQos::from_qos(qos).unwrap().qos(), Some(qos));
        assert!(qos.qci_is_network_valid());
        assert!(!EpsQos { qci: 11, ..qos }.qci_is_network_valid());
        assert!(EpsQos { qci: 65, ..qos }.qci_is_network_valid());
        assert!(EpsQos::from_bytes(&[9, 1, 2]).is_none());
        let status = NasEpsBearerContextStatus::from_active_ebis(&[5, 15]).unwrap();
        assert_eq!(status.value, [0x20, 0x80]);
        assert_eq!(status.active_ebis(), Some(vec![5, 15]));
        assert!(
            NasEpsBearerContextStatus::new(vec![1, 0])
                .active_ebis()
                .is_none()
        );
        let mut capability = NasUeNetworkCapability::new(vec![0, 0]);
        capability.set_eea(CipheringAlgorithm::EEA2, true);
        capability.set_eia(IntegrityAlgorithm::EIA2, true);
        assert_eq!(capability.value, [0x20, 0x20]);
        assert_eq!(
            capability.supports_eea(CipheringAlgorithm::EEA2),
            Some(true)
        );
        assert_eq!(
            capability.supports_eia(IntegrityAlgorithm::EIA1),
            Some(false)
        );
    }

    #[test]
    fn typed_eps_ie_accessors_follow_spec_fallbacks() {
        assert_eq!(
            NasEpsAttachType::new(0).attach_type(),
            AttachType::EpsAttach
        );
        assert_eq!(NasPdnType::new(4).pdn_type(), Some(PdnType::Ipv6));
        assert_eq!(NasPdnType::from_pdn_type(PdnType::Ethernet).value, 6);
    }

    #[test]
    fn apn_labels_match_the_5gs_dnn_wire_form() {
        let apn = NasAccessPointName::from_string("internet.example").unwrap();
        let dnn = crate::nas_5gs::types::NasDnn::new(apn.value.clone());
        assert_eq!(apn.as_string().as_deref(), Some("internet.example"));
        assert_eq!(dnn.as_string(), apn.as_string());
        assert_eq!(
            NasAccessPointName::from_string("internet.example")
                .unwrap()
                .value,
            apn.value
        );
        assert!(NasAccessPointName::from_string("invalid..apn").is_none());
    }

    #[test]
    fn eps_cause_tables_preserve_unknown_values() {
        assert_eq!(NasEmmCause::new(3).cause(), EmmCause::IllegalUe);
        assert_eq!(
            NasEsmCause::new(0x1B).cause(),
            EsmCause::MissingOrUnknownApn
        );
        assert_eq!(NasEmmCause::new(0xFE).cause(), EmmCause::Unknown(0xFE));
        assert_eq!(NasEsmCause::from_cause(EsmCause::Unknown(0xFE)).value, 0xFE);
    }

    #[test]
    fn eps_bit_fields_follow_chapter_9_tables() {
        assert_eq!(
            NasEpsUpdateType::new(4).update_type(),
            Some(UpdateType::TaUpdating)
        );
        assert!(NasEpsUpdateType::new(0).with_active(true).is_active());
        assert_eq!(
            NasEpsUpdateResult::new(5).update_result(),
            Some(UpdateResult::CombinedTaLaUpdatedWithIsr)
        );
        assert_eq!(
            NasEpsMobileIdentity::new(vec![0xF6]).identity_type(),
            Some(MobileIdentityType::Guti)
        );
        assert_eq!(
            NasKeySetIdentifier::new(0x0A).key_set_identifier(),
            KeySetIdentifier::Mapped(2)
        );
        assert!(NasKeySetIdentifier::from_key_set_identifier(KeySetIdentifier::Native(7)).is_err());
        assert!(NasDetachType::from_ue_detach_kind(UeDetachKind::Eps, true).is_switch_off());
    }

    #[test]
    fn pco_lengths_depend_on_message_direction() {
        let pco = Pco {
            configuration_protocol: 0,
            entries: vec![
                PcoEntry {
                    identifier: 0x0023,
                    contents: vec![0xaa, 0xbb],
                },
                PcoEntry {
                    identifier: 0x0041,
                    contents: vec![0xcc],
                },
            ],
        };
        let downlink = pco.to_bytes(PcoDirection::Downlink).unwrap();
        assert_eq!(
            downlink,
            [0x80, 0, 0x23, 0, 2, 0xaa, 0xbb, 0, 0x41, 0, 1, 0xcc]
        );
        assert_eq!(
            Pco::from_bytes(&downlink, PcoDirection::Downlink),
            Some(pco.clone())
        );
        assert_eq!(
            NasExtendedProtocolConfigurationOptions::from_pco(&pco, PcoDirection::Downlink)
                .unwrap()
                .pco(PcoDirection::Downlink),
            Some(pco)
        );
        assert!(Pco::from_bytes(&downlink, PcoDirection::Uplink).is_none());
        assert!(
            NasProtocolConfigurationOptions::from_pco(
                &Pco {
                    configuration_protocol: 0,
                    entries: vec![PcoEntry {
                        identifier: 0x0041,
                        contents: vec![0; 250]
                    }]
                },
                PcoDirection::Uplink
            )
            .is_none()
        );
    }

    #[test]
    fn received_pco_selector_fallback_cannot_be_built_for_sending() {
        let pco = Pco::from_bytes(&[0x81], PcoDirection::Uplink).unwrap();
        assert_eq!(pco.configuration_protocol, 1);
        assert!(pco.to_bytes(PcoDirection::Uplink).is_none());
        assert!(NasProtocolConfigurationOptions::from_pco(&pco, PcoDirection::Uplink).is_none());
    }

    #[test]
    fn eps_timers_distinguish_zero_from_deactivated_and_t3412_integrity() {
        assert_eq!(
            NasT3412Value::from_unit_value(GprsTimerUnit::OneMinute, 0).to_seconds(),
            None
        );
        assert_eq!(
            NasT3402Value::from_unit_value(GprsTimerUnit::OneMinute, 0).to_seconds(),
            Some(0)
        );
        assert_eq!(
            NasT3412Value::from_unit_value(GprsTimerUnit::Deactivated, 1).to_seconds(),
            None
        );
        let extended =
            NasT3412ExtendedValue::from_unit_value(GprsTimer3Unit::ThreeHundredTwentyHours, 1);
        assert_eq!(extended.to_seconds_with_integrity(false), Some(3_600));
        assert_eq!(extended.to_seconds_with_integrity(true), Some(1_152_000));
        assert_eq!(
            NasBackOffTimerValue::from_unit_value(GprsTimer3Unit::ThreeHundredTwentyHours, 1)
                .to_seconds(),
            None
        );
        assert_eq!(
            NasT3412ExtendedValue::from_unit_value(GprsTimer3Unit::OneMinute, 0)
                .to_seconds_with_integrity(true),
            None
        );
    }

    #[test]
    fn tai_list_receiver_keeps_first_sixteen_entries() {
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        };
        let tai = Tai { plmn, tac: 1 };
        let mut value = TaiList(vec![tai; 16]).to_bytes().unwrap();
        value.extend_from_slice(&[0x40]);
        value.extend_from_slice(&tai.to_bytes());
        assert_eq!(TaiList::from_bytes(&value).unwrap().0.len(), 16);
    }

    #[test]
    fn tft_packet_filters_and_parameters_round_trip() {
        let tft = Tft {
            operation: TftOperation::Create,
            packet_filters: vec![TftPacketFilter {
                identifier: 2,
                direction: 3,
                precedence: Some(10),
                contents: vec![0x30, 0x11],
            }],
            parameters: vec![TftParameter {
                identifier: 2,
                contents: vec![0, 0, 0, 1],
            }],
        };
        let wire = tft.to_bytes().unwrap();
        assert_eq!(wire, [0x31, 0x32, 10, 2, 0x30, 0x11, 2, 4, 0, 0, 0, 1]);
        assert_eq!(Tft::from_bytes(&wire), Some(tft.clone()));
        assert_eq!(NasTft::from_tft(&tft).unwrap().tft(), Some(tft));
        assert!(Tft::from_bytes(&[0xc0]).is_none());
        assert!(Tft::from_bytes(&[0x20]).is_none());
        assert!(Tft::from_bytes(&[0xd0]).is_none());
        assert!(Tft::from_bytes(&[0x31, 0x32, 10, 2, 0x10]).is_none());
        assert!(Tft::from_bytes(&[0x21, 0x10, 1, 1, 0x10]).is_none());
        assert!(Tft::from_bytes(&[0x22, 0x32, 1, 2, 0x30, 0x11, 0x32, 2, 2, 0x30, 0x11]).is_none());
        assert!(Tft::from_bytes(&[0x31, 0x32, 1, 2, 0x30, 0x11, 2, 1, 0]).is_none());
        assert!(Tft::from_bytes(&[0x31, 0x32, 1, 2, 0x30, 0x11, 3, 1, 0xf1]).is_none());
        let aggregate = [0x22, 0x30, 1, 2, 0x30, 0x11, 0x30, 2, 2, 0x30, 0x11];
        assert!(Tft::from_bytes(&aggregate).is_none());
        let aggregate_ie = NasTrafficFlowAggregate::new(aggregate.to_vec());
        let parsed = aggregate_ie.tft().unwrap();
        assert_eq!(
            NasTrafficFlowAggregate::from_tft(&parsed).unwrap().value,
            aggregate
        );
        assert!(Tft::from_bytes(&[0x00, 0xff]).is_none());
        assert!(Tft::from_bytes(&[0x10, 0xff]).is_none());
        let ignore = Tft::from_bytes(&[0x00]).unwrap();
        assert_eq!(ignore.operation, TftOperation::Ignore);
        assert_eq!(ignore.to_bytes(), Some(vec![0x00]));
        assert!(Tft::from_bytes(&[0x10]).is_none());
        assert_eq!(
            NasTrafficFlowAggregate::from_tft(&ignore).unwrap().value,
            [0x00]
        );
    }

    #[test]
    fn identity_response_mobile_identity_uses_classic_type_codes() {
        let imsi = NasMobileIdentity::from_imsi("208930000000001").unwrap();
        assert_eq!(imsi.as_imsi().as_deref(), Some("208930000000001"));
        let imei = NasMobileIdentity::from_imei("490154203237518").unwrap();
        assert_eq!(imei.value[0] & 7, 2);
        assert_eq!(imei.as_imei().as_deref(), Some("490154203237518"));
        assert_eq!(
            NasMobileIdentity::from_imei_tac_snr("49015420323751")
                .unwrap()
                .as_imei()
                .as_deref(),
            Some("490154203237510")
        );
        assert_eq!(
            NasEpsMobileIdentity::from_imei_tac_snr("49015420323751")
                .unwrap()
                .as_imei()
                .as_deref(),
            Some("490154203237510")
        );
        let imeisv = NasMobileIdentity::from_imeisv("4901542032375183").unwrap();
        assert_eq!(imeisv.value.len(), 9);
        assert_eq!(imeisv.as_imeisv().as_deref(), Some("4901542032375183"));
        assert_eq!(
            NasImeisv::from_imeisv("4901542032375183")
                .unwrap()
                .as_imeisv()
                .as_deref(),
            Some("4901542032375183")
        );
        let tmsi = NasMobileIdentity::from_tmsi(0x1234_5678);
        assert_eq!(tmsi.value, [0xf4, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(tmsi.as_tmsi(), Some(0x1234_5678));
        assert!(NasMobileIdentity::new(vec![0]).is_no_identity());
    }
}
