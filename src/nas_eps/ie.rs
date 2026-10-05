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
use crate::common::nas_opaque_ie;
use crate::nas_eps::types::*;

// BEGIN TS24301 IE
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

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
        Self::from_u8_strict(value).unwrap_or(Self::Unknown(value))
    }
    /// Decode only the listed cause values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value {
            0x02 => Some(Self::ImsiUnknownInHss),
            0x03 => Some(Self::IllegalUe),
            0x05 => Some(Self::ImeiNotAccepted),
            0x06 => Some(Self::IllegalMe),
            0x07 => Some(Self::EpsServicesNotAllowed),
            0x08 => Some(Self::EpsServicesAndNonEpsServicesNotAllowed),
            0x09 => Some(Self::UeIdentityCannotBeDerivedByTheNetwork),
            0x0A => Some(Self::ImplicitlyDetached),
            0x0B => Some(Self::PlmnNotAllowed),
            0x0C => Some(Self::TrackingAreaNotAllowed),
            0x0D => Some(Self::RoamingNotAllowedInThisTrackingArea),
            0x0E => Some(Self::EpsServicesNotAllowedInThisPlmn),
            0x0F => Some(Self::NoSuitableCellsInTrackingArea),
            0x10 => Some(Self::MscTemporarilyNotReachable),
            0x11 => Some(Self::NetworkFailure),
            0x12 => Some(Self::CsDomainNotAvailable),
            0x13 => Some(Self::EsmFailure),
            0x14 => Some(Self::MacFailure),
            0x15 => Some(Self::SynchFailure),
            0x16 => Some(Self::Congestion),
            0x17 => Some(Self::UeSecurityCapabilitiesMismatch),
            0x18 => Some(Self::SecurityModeRejectedUnspecified),
            0x19 => Some(Self::NotAuthorizedForThisCsg),
            0x1A => Some(Self::NonEpsAuthenticationUnacceptable),
            0x1F => Some(Self::RedirectionTo5gcnRequired),
            0x23 => Some(Self::RequestedServiceOptionNotAuthorizedInThisPlmn),
            0x24 => Some(Self::IabNodeOperationNotAuthorized),
            0x27 => Some(Self::CsServiceTemporarilyNotAvailable),
            0x28 => Some(Self::NoEpsBearerContextActivated),
            0x2A => Some(Self::SevereNetworkFailure),
            0x4E => Some(Self::PlmnNotAllowedToOperateAtThePresentUeLocation),
            0x50 => Some(Self::DisasterRoamingForTheDeterminedPlmnWithDisasterConditionNotAllowed),
            0x53 => Some(Self::ProcedureCannotBeCompletedDueToUnavailableFeederLinkWhileMmeIsOperatingInSAndFMode),
            0x5F => Some(Self::SemanticallyIncorrectMessage),
            0x60 => Some(Self::InvalidMandatoryInformation),
            0x61 => Some(Self::MessageTypeNonExistentOrNotImplemented),
            0x62 => Some(Self::MessageTypeNotCompatibleWithTheProtocolState),
            0x63 => Some(Self::InformationElementNonExistentOrNotImplemented),
            0x64 => Some(Self::ConditionalIeError),
            0x65 => Some(Self::MessageNotCompatibleWithTheProtocolState),
            0x6F => Some(Self::ProtocolErrorUnspecified),
            _ => None,
        }
    }
    /// Decode a cause received by the UE or the network, applying the rule for values that
    /// are not listed: they are treated as `ProtocolErrorUnspecified`.
    pub fn from_u8_received(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::ProtocolErrorUnspecified)
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
    /// Cause text from the specification table.
    pub fn description(self) -> &'static str {
        match self {
            Self::ImsiUnknownInHss => "IMSI unknown in HSS",
            Self::IllegalUe => "Illegal UE",
            Self::ImeiNotAccepted => "IMEI not accepted",
            Self::IllegalMe => "Illegal ME",
            Self::EpsServicesNotAllowed => "EPS services not allowed",
            Self::EpsServicesAndNonEpsServicesNotAllowed => "EPS services and non-EPS services not allowed",
            Self::UeIdentityCannotBeDerivedByTheNetwork => "UE identity cannot be derived by the network",
            Self::ImplicitlyDetached => "Implicitly detached",
            Self::PlmnNotAllowed => "PLMN not allowed",
            Self::TrackingAreaNotAllowed => "Tracking Area not allowed",
            Self::RoamingNotAllowedInThisTrackingArea => "Roaming not allowed in this tracking area",
            Self::EpsServicesNotAllowedInThisPlmn => "EPS services not allowed in this PLMN",
            Self::NoSuitableCellsInTrackingArea => "No Suitable Cells In tracking area",
            Self::MscTemporarilyNotReachable => "MSC temporarily not reachable",
            Self::NetworkFailure => "Network failure",
            Self::CsDomainNotAvailable => "CS domain not available",
            Self::EsmFailure => "ESM failure",
            Self::MacFailure => "MAC failure",
            Self::SynchFailure => "Synch failure",
            Self::Congestion => "Congestion",
            Self::UeSecurityCapabilitiesMismatch => "UE security capabilities mismatch",
            Self::SecurityModeRejectedUnspecified => "Security mode rejected, unspecified",
            Self::NotAuthorizedForThisCsg => "Not authorized for this CSG",
            Self::NonEpsAuthenticationUnacceptable => "Non-EPS authentication unacceptable",
            Self::RedirectionTo5gcnRequired => "Redirection to 5GCN required",
            Self::RequestedServiceOptionNotAuthorizedInThisPlmn => "Requested service option not authorized in this PLMN",
            Self::IabNodeOperationNotAuthorized => "IAB-node operation not authorized",
            Self::CsServiceTemporarilyNotAvailable => "CS service temporarily not available",
            Self::NoEpsBearerContextActivated => "No EPS bearer context activated",
            Self::SevereNetworkFailure => "Severe network failure",
            Self::PlmnNotAllowedToOperateAtThePresentUeLocation => "PLMN not allowed to operate at the present UE location",
            Self::DisasterRoamingForTheDeterminedPlmnWithDisasterConditionNotAllowed => "Disaster roaming for the determined PLMN with disaster condition not allowed",
            Self::ProcedureCannotBeCompletedDueToUnavailableFeederLinkWhileMmeIsOperatingInSAndFMode => "Procedure cannot be completed due to unavailable feeder link while MME is operating in S&F mode",
            Self::SemanticallyIncorrectMessage => "Semantically incorrect message",
            Self::InvalidMandatoryInformation => "Invalid mandatory information",
            Self::MessageTypeNonExistentOrNotImplemented => "Message type non-existent or not implemented",
            Self::MessageTypeNotCompatibleWithTheProtocolState => "Message type not compatible with the protocol state",
            Self::InformationElementNonExistentOrNotImplemented => "Information element non-existent or not implemented",
            Self::ConditionalIeError => "Conditional IE error",
            Self::MessageNotCompatibleWithTheProtocolState => "Message not compatible with the protocol state",
            Self::ProtocolErrorUnspecified => "Protocol error, unspecified",
            Self::Unknown(_) => "Unknown EMM cause",
        }
    }
}

impl NasEmmCause {
    /// Build the raw IE from a typed cause.
    pub fn from_cause(cause: EmmCause) -> Self {
        Self::new(cause.as_u8())
    }
    /// Decode the cause value, preserving unknown codes.
    pub fn cause(&self) -> EmmCause {
        EmmCause::from_u8(self.value)
    }
    /// Raw cause value.
    pub fn cause_raw(&self) -> u8 {
        self.value
    }
    /// Decode the cause received by the UE or the network (see [`EmmCause::from_u8_received`]).
    pub fn cause_received(&self) -> EmmCause {
        EmmCause::from_u8_received(self.value)
    }
    /// Set the cause value.
    pub fn set_cause(&mut self, cause: EmmCause) -> &mut Self {
        self.value = cause.as_u8();
        self
    }
    /// Builder form of [`Self::set_cause`].
    pub fn with_cause(mut self, cause: EmmCause) -> Self {
        self.set_cause(cause);
        self
    }
    /// Cause text, with the hexadecimal value for unknown codes.
    pub fn description(&self) -> String {
        match self.cause() {
            EmmCause::Unknown(value) => format!("Unknown EMM cause 0x{value:02X}"),
            cause => cause.description().to_string(),
        }
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
    SemanticErrorsInPacketFilters,
    /// Syntactical errors in packet filter(s) (0x2D).
    SyntacticalErrorsInPacketFilters,
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
        Self::from_u8_strict(value).unwrap_or(Self::Unknown(value))
    }
    /// Decode only the listed cause values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value {
            0x08 => Some(Self::OperatorDeterminedBarring),
            0x1A => Some(Self::InsufficientResources),
            0x1B => Some(Self::MissingOrUnknownApn),
            0x1C => Some(Self::UnknownPdnType),
            0x1D => Some(Self::UserAuthenticationOrAuthorizationFailed),
            0x1E => Some(Self::RequestRejectedByServingGwOrPdnGw),
            0x1F => Some(Self::RequestRejectedUnspecified),
            0x20 => Some(Self::ServiceOptionNotSupported),
            0x21 => Some(Self::RequestedServiceOptionNotSubscribed),
            0x22 => Some(Self::ServiceOptionTemporarilyOutOfOrder),
            0x23 => Some(Self::PtiAlreadyInUse),
            0x24 => Some(Self::RegularDeactivation),
            0x25 => Some(Self::EpsQosNotAccepted),
            0x26 => Some(Self::NetworkFailure),
            0x27 => Some(Self::ReactivationRequested),
            0x29 => Some(Self::SemanticErrorInTheTftOperation),
            0x2A => Some(Self::SyntacticalErrorInTheTftOperation),
            0x2B => Some(Self::InvalidEpsBearerIdentity),
            0x2C => Some(Self::SemanticErrorsInPacketFilters),
            0x2D => Some(Self::SyntacticalErrorsInPacketFilters),
            0x2F => Some(Self::PtiMismatch),
            0x31 => Some(Self::LastPdnDisconnectionNotAllowed),
            0x32 => Some(Self::PdnTypeIpv4OnlyAllowed),
            0x33 => Some(Self::PdnTypeIpv6OnlyAllowed),
            0x34 => Some(Self::SingleAddressBearersOnlyAllowed),
            0x35 => Some(Self::EsmInformationNotReceived),
            0x36 => Some(Self::PdnConnectionDoesNotExist),
            0x37 => Some(Self::MultiplePdnConnectionsForAGivenApnNotAllowed),
            0x38 => Some(Self::CollisionWithNetworkInitiatedRequest),
            0x39 => Some(Self::PdnTypeIpv4v6OnlyAllowed),
            0x3A => Some(Self::PdnTypeNonIpOnlyAllowed),
            0x3B => Some(Self::UnsupportedQciValue),
            0x3C => Some(Self::BearerHandlingNotSupported),
            0x3D => Some(Self::PdnTypeEthernetOnlyAllowed),
            0x41 => Some(Self::MaximumNumberOfEpsBearersReached),
            0x42 => Some(Self::RequestedApnNotSupportedInCurrentRatAndPlmnCombination),
            0x51 => Some(Self::InvalidPtiValue),
            0x5F => Some(Self::SemanticallyIncorrectMessage),
            0x60 => Some(Self::InvalidMandatoryInformation),
            0x61 => Some(Self::MessageTypeNonExistentOrNotImplemented),
            0x62 => Some(Self::MessageTypeNotCompatibleWithTheProtocolState),
            0x63 => Some(Self::InformationElementNonExistentOrNotImplemented),
            0x64 => Some(Self::ConditionalIeError),
            0x65 => Some(Self::MessageNotCompatibleWithTheProtocolState),
            0x6F => Some(Self::ProtocolErrorUnspecified),
            0x70 => Some(Self::ApnRestrictionValueIncompatibleWithActiveEpsBearerContext),
            0x71 => Some(Self::MultipleAccessesToAPdnConnectionNotAllowed),
            _ => None,
        }
    }
    /// Decode a cause received by the UE, applying the rule for values that
    /// are not listed: they are treated as `ServiceOptionTemporarilyOutOfOrder`.
    pub fn from_u8_for_ue(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::ServiceOptionTemporarilyOutOfOrder)
    }
    /// Decode a cause received by the network, applying the rule for values that
    /// are not listed: they are treated as `ProtocolErrorUnspecified`.
    pub fn from_u8_for_network(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::ProtocolErrorUnspecified)
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
            Self::SemanticErrorsInPacketFilters => 0x2C,
            Self::SyntacticalErrorsInPacketFilters => 0x2D,
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
    /// Cause text from the specification table.
    pub fn description(self) -> &'static str {
        match self {
            Self::OperatorDeterminedBarring => "Operator Determined Barring",
            Self::InsufficientResources => "Insufficient resources",
            Self::MissingOrUnknownApn => "Missing or unknown APN",
            Self::UnknownPdnType => "Unknown PDN type",
            Self::UserAuthenticationOrAuthorizationFailed => {
                "User authentication or authorization failed"
            }
            Self::RequestRejectedByServingGwOrPdnGw => "Request rejected by Serving GW or PDN GW",
            Self::RequestRejectedUnspecified => "Request rejected, unspecified",
            Self::ServiceOptionNotSupported => "Service option not supported",
            Self::RequestedServiceOptionNotSubscribed => "Requested service option not subscribed",
            Self::ServiceOptionTemporarilyOutOfOrder => "Service option temporarily out of order",
            Self::PtiAlreadyInUse => "PTI already in use",
            Self::RegularDeactivation => "Regular deactivation",
            Self::EpsQosNotAccepted => "EPS QoS not accepted",
            Self::NetworkFailure => "Network failure",
            Self::ReactivationRequested => "Reactivation requested",
            Self::SemanticErrorInTheTftOperation => "Semantic error in the TFT operation",
            Self::SyntacticalErrorInTheTftOperation => "Syntactical error in the TFT operation",
            Self::InvalidEpsBearerIdentity => "Invalid EPS bearer identity",
            Self::SemanticErrorsInPacketFilters => "Semantic errors in packet filter(s)",
            Self::SyntacticalErrorsInPacketFilters => "Syntactical errors in packet filter(s)",
            Self::PtiMismatch => "PTI mismatch",
            Self::LastPdnDisconnectionNotAllowed => "Last PDN disconnection not allowed",
            Self::PdnTypeIpv4OnlyAllowed => "PDN type IPv4 only allowed",
            Self::PdnTypeIpv6OnlyAllowed => "PDN type IPv6 only allowed",
            Self::SingleAddressBearersOnlyAllowed => "Single address bearers only allowed",
            Self::EsmInformationNotReceived => "ESM information not received",
            Self::PdnConnectionDoesNotExist => "PDN connection does not exist",
            Self::MultiplePdnConnectionsForAGivenApnNotAllowed => {
                "Multiple PDN connections for a given APN not allowed"
            }
            Self::CollisionWithNetworkInitiatedRequest => {
                "Collision with network initiated request"
            }
            Self::PdnTypeIpv4v6OnlyAllowed => "PDN type IPv4v6 only allowed",
            Self::PdnTypeNonIpOnlyAllowed => "PDN type non IP only allowed",
            Self::UnsupportedQciValue => "Unsupported QCI value",
            Self::BearerHandlingNotSupported => "Bearer handling not supported",
            Self::PdnTypeEthernetOnlyAllowed => "PDN type Ethernet only allowed",
            Self::MaximumNumberOfEpsBearersReached => "Maximum number of EPS bearers reached",
            Self::RequestedApnNotSupportedInCurrentRatAndPlmnCombination => {
                "Requested APN not supported in current RAT and PLMN combination"
            }
            Self::InvalidPtiValue => "Invalid PTI value",
            Self::SemanticallyIncorrectMessage => "Semantically incorrect message",
            Self::InvalidMandatoryInformation => "Invalid mandatory information",
            Self::MessageTypeNonExistentOrNotImplemented => {
                "Message type non-existent or not implemented"
            }
            Self::MessageTypeNotCompatibleWithTheProtocolState => {
                "Message type not compatible with the protocol state"
            }
            Self::InformationElementNonExistentOrNotImplemented => {
                "Information element non-existent or not implemented"
            }
            Self::ConditionalIeError => "Conditional IE error",
            Self::MessageNotCompatibleWithTheProtocolState => {
                "Message not compatible with the protocol state"
            }
            Self::ProtocolErrorUnspecified => "Protocol error, unspecified",
            Self::ApnRestrictionValueIncompatibleWithActiveEpsBearerContext => {
                "APN restriction value incompatible with active EPS bearer context"
            }
            Self::MultipleAccessesToAPdnConnectionNotAllowed => {
                "Multiple accesses to a PDN connection not allowed"
            }
            Self::Unknown(_) => "Unknown ESM cause",
        }
    }
}

impl NasEsmCause {
    /// Build the raw IE from a typed cause.
    pub fn from_cause(cause: EsmCause) -> Self {
        Self::new(cause.as_u8())
    }
    /// Decode the cause value, preserving unknown codes.
    pub fn cause(&self) -> EsmCause {
        EsmCause::from_u8(self.value)
    }
    /// Raw cause value.
    pub fn cause_raw(&self) -> u8 {
        self.value
    }
    /// Decode the cause received by the UE (see [`EsmCause::from_u8_for_ue`]).
    pub fn cause_for_ue(&self) -> EsmCause {
        EsmCause::from_u8_for_ue(self.value)
    }
    /// Decode the cause received by the network (see [`EsmCause::from_u8_for_network`]).
    pub fn cause_for_network(&self) -> EsmCause {
        EsmCause::from_u8_for_network(self.value)
    }
    /// Set the cause value.
    pub fn set_cause(&mut self, cause: EsmCause) -> &mut Self {
        self.value = cause.as_u8();
        self
    }
    /// Builder form of [`Self::set_cause`].
    pub fn with_cause(mut self, cause: EsmCause) -> Self {
        self.set_cause(cause);
        self
    }
    /// Cause text, with the hexadecimal value for unknown codes.
    pub fn description(&self) -> String {
        match self.cause() {
            EsmCause::Unknown(value) => format!("Unknown ESM cause 0x{value:02X}"),
            cause => cause.description().to_string(),
        }
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

/// EPS paging restriction type (TS 24.301 Table 9.9.3.66.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum EpsPagingRestrictionType {
    /// All paging is restricted.
    AllRestricted = 1,
    /// All paging is restricted except for voice service.
    AllRestrictedExceptVoice = 2,
    /// All paging is restricted except for specified PDN connections.
    AllRestrictedExceptSpecifiedPdnConnections = 3,
    /// All paging is restricted except for voice service and specified PDN
    /// connections.
    AllRestrictedExceptVoiceAndSpecifiedPdnConnections = 4,
}

impl EpsPagingRestrictionType {
    /// Decode bits 4-1; reserved values return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0f {
            1 => Some(Self::AllRestricted),
            2 => Some(Self::AllRestrictedExceptVoice),
            3 => Some(Self::AllRestrictedExceptSpecifiedPdnConnections),
            4 => Some(Self::AllRestrictedExceptVoiceAndSpecifiedPdnConnections),
            _ => None,
        }
    }

    fn has_bearer_bitmap(self) -> bool {
        matches!(
            self,
            Self::AllRestrictedExceptSpecifiedPdnConnections
                | Self::AllRestrictedExceptVoiceAndSpecifiedPdnConnections
        )
    }
}

impl NasPagingRestriction {
    /// Typed restriction type; reserved values return `None`.
    pub fn restriction_type(&self) -> Option<EpsPagingRestrictionType> {
        EpsPagingRestrictionType::from_u8(*self.value.first()?)
    }

    /// Raw restriction type (bits 4-1).
    pub fn restriction_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x0f)
    }

    /// EBIs 1 to 15 whose bit is 1: for a default bearer, paging is not
    /// restricted for its PDN connection. `None` for types without a bitmap.
    pub fn unrestricted_ebis(&self) -> Option<Vec<u8>> {
        if !self.restriction_type()?.has_bearer_bitmap() {
            return None;
        }
        let bitmap = self.value.get(1..3)?;
        Some(
            (1..=15u8)
                .filter(|&ebi| bitmap[usize::from(ebi / 8)] >> (ebi % 8) & 1 != 0)
                .collect(),
        )
    }

    /// Build a restriction; the EBIs apply only to the types with a bearer
    /// bitmap and must be 1 to 15.
    pub fn from_restriction(
        restriction_type: EpsPagingRestrictionType,
        unrestricted_ebis: &[u8],
    ) -> Option<Self> {
        let mut value = vec![restriction_type as u8];
        if restriction_type.has_bearer_bitmap() {
            value.extend([0, 0]);
            for &ebi in unrestricted_ebis {
                if !(1..=15).contains(&ebi) {
                    return None;
                }
                value[1 + usize::from(ebi / 8)] |= 1 << (ebi % 8);
            }
        } else if !unrestricted_ebis.is_empty() {
            return None;
        }
        Some(Self::new(value))
    }

    /// Check the paging type, spare bits, and bearer bitmap layout (§9.9.3.66).
    pub fn is_well_formed(&self) -> bool {
        match self.value.as_slice() {
            [kind] => kind & 0xf0 == 0 && matches!(kind & 0x0f, 1 | 2),
            [kind, low, _high] => kind & 0xf0 == 0 && matches!(kind & 0x0f, 3 | 4) && low & 1 == 0,
            _ => false,
        }
    }
}

/// Paging restriction decision (TS 24.301 Table 9.9.3.67.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PagingRestrictionDecision {
    /// No additional information.
    NoAdditionalInformation = 0,
    /// Paging restriction is accepted.
    Accepted = 1,
    /// Paging restriction is rejected.
    Rejected = 2,
}

impl NasEpsAdditionalRequestResult {
    /// Paging restriction decision (bits 2-1); the reserved value is `None`.
    pub fn paging_restriction_decision(&self) -> Option<PagingRestrictionDecision> {
        match self.value.first()? & 0x03 {
            0 => Some(PagingRestrictionDecision::NoAdditionalInformation),
            1 => Some(PagingRestrictionDecision::Accepted),
            2 => Some(PagingRestrictionDecision::Rejected),
            _ => None,
        }
    }

    /// Build with the spare bits clear.
    pub fn from_paging_restriction_decision(decision: PagingRestrictionDecision) -> Self {
        Self::new(vec![decision as u8])
    }

    /// Check the paging restriction decision and spare bits (§9.9.3.67).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [decision] if *decision <= 2)
    }
}

/// DRX value for S1 mode, the DRX cycle parameter T (TS 24.008 Table
/// 10.5.139).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum S1DrxValue {
    /// DRX value not specified by the MS.
    NotSpecified = 0,
    /// T = 32.
    T32 = 6,
    /// T = 64.
    T64 = 7,
    /// T = 128.
    T128 = 8,
    /// T = 256.
    T256 = 9,
}

impl S1DrxValue {
    /// Decode bits 4-1 of the argument; other values are read as "not
    /// specified".
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::NotSpecified)
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x0f {
            0 => Some(Self::NotSpecified),
            6 => Some(Self::T32),
            7 => Some(Self::T64),
            8 => Some(Self::T128),
            9 => Some(Self::T256),
            _ => None,
        }
    }
}

/// SPLIT PG CYCLE values for codes 65 to 98 (TS 24.008 Table 10.5.139).
const SPLIT_PG_CYCLES: [u16; 34] = [
    71, 72, 74, 75, 77, 79, 80, 83, 86, 88, 90, 92, 96, 101, 103, 107, 112, 116, 118, 128, 141,
    144, 150, 160, 171, 176, 192, 214, 224, 235, 256, 288, 320, 352,
];

impl NasDrxParameter {
    /// SPLIT PG CYCLE CODE (value octet 1).
    pub fn split_pg_cycle_code(&self) -> Option<u8> {
        self.value.first().copied()
    }

    /// SPLIT PG CYCLE: code 0 is 704 (no DRX), and reserved codes are read
    /// as 1.
    pub fn split_pg_cycle(&self) -> Option<u16> {
        Some(match self.split_pg_cycle_code()? {
            0 => 704,
            code @ 1..=64 => u16::from(code),
            code @ 65..=98 => SPLIT_PG_CYCLES[usize::from(code - 65)],
            _ => 1,
        })
    }

    /// DRX value for S1 mode (value octet 2, bits 8-5), with the receive
    /// fallback.
    pub fn s1_drx_value(&self) -> Option<S1DrxValue> {
        self.value
            .get(1)
            .map(|octet| S1DrxValue::from_u8(octet >> 4))
    }

    /// Raw CN specific DRX cycle length coefficient and S1 DRX value.
    pub fn s1_drx_value_raw(&self) -> Option<u8> {
        self.value.get(1).map(|octet| octet >> 4)
    }

    /// SPLIT on CCCH (value octet 2, bit 4).
    pub fn split_on_ccch(&self) -> Option<bool> {
        self.value.get(1).map(|octet| octet & 0x08 != 0)
    }

    /// Non-DRX timer code (value octet 2, bits 3-1): 0 means no non-DRX
    /// mode, and code n means at most 2^(n-1) seconds.
    pub fn non_drx_timer(&self) -> Option<u8> {
        self.value.get(1).map(|octet| octet & 0x07)
    }

    /// Build from the fields.
    pub fn from_fields(
        split_pg_cycle_code: u8,
        s1_drx_value: S1DrxValue,
        split_on_ccch: bool,
        non_drx_timer: u8,
    ) -> Option<Self> {
        (non_drx_timer <= 7).then(|| {
            Self::new(vec![
                split_pg_cycle_code,
                (s1_drx_value as u8) << 4 | u8::from(split_on_ccch) << 3 | non_drx_timer,
            ])
        })
    }

    /// Check the paging cycle and S1-mode DRX value (TS 24.008 §10.5.5.6).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [cycle, value]
            if *cycle <= 98 && matches!(value >> 4, 0 | 6 | 7 | 8 | 9))
    }
}

/// Voice domain preference for E-UTRAN (TS 24.008 Table 10.5.166A).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum VoiceDomainPreference {
    /// CS voice only.
    CsVoiceOnly = 0,
    /// IMS PS voice only.
    ImsPsVoiceOnly = 1,
    /// CS voice preferred, IMS PS voice as secondary.
    CsVoicePreferred = 2,
    /// IMS PS voice preferred, CS voice as secondary.
    ImsPsVoicePreferred = 3,
}

impl NasVoiceDomainPreferenceAndUeUsageSetting {
    /// Voice domain preference for E-UTRAN (bits 2-1).
    pub fn voice_domain_preference(&self) -> Option<VoiceDomainPreference> {
        Some(match self.value.first()? & 0x03 {
            0 => VoiceDomainPreference::CsVoiceOnly,
            1 => VoiceDomainPreference::ImsPsVoiceOnly,
            2 => VoiceDomainPreference::CsVoicePreferred,
            _ => VoiceDomainPreference::ImsPsVoicePreferred,
        })
    }

    /// UE's usage setting (bit 3): `true` for data centric, `false` for
    /// voice centric.
    pub fn data_centric(&self) -> Option<bool> {
        self.value.first().map(|octet| octet & 0x04 != 0)
    }

    /// Build with the spare bits clear.
    pub fn from_fields(preference: VoiceDomainPreference, data_centric: bool) -> Self {
        Self::new(vec![u8::from(data_centric) << 2 | preference as u8])
    }

    /// Check the spare bits of the voice preference octet (TS 24.008 §10.5.5.28).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [value] if value & 0xf8 == 0)
    }
}

crate::common::nas_ie_flags!(NasN1UeNetworkCapability {
    /// Control plane CIoT 5GS optimization (octet 3, bit 1).
    cp_ciot: 0, 1;
    /// N3 data bit as sent (octet 3, bit 2): `true` means N3 data transfer
    /// is not supported.
    n3_data: 0, 2;
    /// IP header compression for control plane CIoT 5GS optimization (octet 3, bit 3).
    hc_cp_ciot: 0, 3;
    /// User plane CIoT 5GS optimization (octet 3, bit 4).
    up_ciot: 0, 4;
    /// Ethernet header compression for control plane CIoT 5GS optimization (octet 3, bit 7).
    ehc_cp_ciot: 0, 7;
});

impl Default for NasN1UeNetworkCapability {
    /// One octet with no capability indicated.
    fn default() -> Self {
        Self::new(vec![0])
    }
}

impl NasN1UeNetworkCapability {
    /// Whether N3 data transfer is supported (N3 data bit clear).
    pub fn n3_data_transfer_supported(&self) -> bool {
        !self.value.is_empty() && !self.n3_data()
    }

    /// Preferred 5GS CIoT network behaviour (octet 3, bits 6-5); reserved is `None`.
    pub fn pnb_ciot(&self) -> Option<PreferredCiotBehavior> {
        PreferredCiotBehavior::from_u8(self.pnb_ciot_raw())
    }

    /// Raw 5GS-PNB-CIoT field.
    pub fn pnb_ciot_raw(&self) -> u8 {
        self.value.first().map_or(0, |octet| (octet >> 4) & 0x03)
    }

    /// Set the preferred 5GS CIoT network behaviour.
    pub fn set_pnb_ciot(&mut self, value: PreferredCiotBehavior) {
        if self.value.is_empty() {
            self.value.push(0);
        }
        self.value[0] = (self.value[0] & !0x30) | ((value as u8) << 4);
        self.length = self.value.len() as _;
    }

    /// Builder form of [`Self::set_pnb_ciot`].
    pub fn with_pnb_ciot(mut self, value: PreferredCiotBehavior) -> Self {
        self.set_pnb_ciot(value);
        self
    }

    /// Sender check: 1 to 13 octets with octet 3 bit 8 clear and later octets spare.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.split_first(), Some((first, rest))
            if first & 0x80 == 0 && rest.len() <= 12 && rest.iter().all(|&octet| octet == 0))
    }
}

impl NasTmsiBasedNriContainer {
    /// The 10-bit NRI container value: TMSI bits 23 to 14 (TS 24.008
    /// §10.5.5.31). Spare bits and extra octets are ignored.
    pub fn nri(&self) -> Option<u16> {
        match self.value.as_slice() {
            [high, low, ..] => Some(u16::from(*high) << 2 | u16::from(low >> 6)),
            _ => None,
        }
    }

    /// Build from a 10-bit NRI container value.
    pub fn from_nri(nri: u16) -> Option<Self> {
        (nri <= 0x03ff).then(|| Self::new(vec![(nri >> 2) as u8, ((nri & 0x03) << 6) as u8]))
    }

    /// Check the six spare bits after the NRI (TS 24.008 §10.5.5.31).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [_, low] if low & 0x3f == 0)
    }
}

pub use crate::common::ts24008::MsRevisionLevel;
crate::common::ts24008::mobile_station_classmark_2_ie!(NasMobileStationClassmark2);

/// NBIFOM parameter identifiers (TS 24.161 Table 6.1.1-1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum NbifomParameterId {
    /// NBIFOM mode.
    Mode = 0x01,
    /// NBIFOM default access.
    DefaultAccess = 0x02,
    /// NBIFOM status.
    Status = 0x03,
    /// NBIFOM routing rules.
    RoutingRules = 0x04,
    /// NBIFOM IP flow mapping (MS to network).
    IpFlowMapping = 0x05,
    /// NBIFOM RAN rules handling (network to MS).
    RanRulesHandling = 0x06,
    /// NBIFOM access stratum status (MS to network).
    AccessStratumStatus = 0x07,
    /// NBIFOM access usability indication (MS to network).
    AccessUsabilityIndication = 0x08,
}

/// Direction of an NBIFOM parameter container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NbifomDirection {
    /// UE to network.
    UeToNetwork,
    /// Network to UE.
    NetworkToUe,
}

/// One unit of the NBIFOM parameter list (TS 24.161 §6.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NbifomParameter {
    /// Parameter identifier.
    pub identifier: u8,
    /// Parameter contents.
    pub contents: Vec<u8>,
}

/// NBIFOM status parameter (TS 24.161 Table 6.1.3-1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum NbifomStatus {
    /// Accepted.
    Accepted = 0x00,
    /// Insufficient resources (#26).
    InsufficientResources = 0x1a,
    /// Service option temporarily out of order (#34).
    ServiceOptionTemporarilyOutOfOrder = 0x22,
    /// Requested service option not subscribed (0x25; the clause text says #33).
    RequestedServiceOptionNotSubscribed = 0x25,
    /// Request rejected, unspecified (0x3F; the clause text says #31).
    RequestRejectedUnspecified = 0x3f,
    /// Incorrect indication in the routing rule operation (#57).
    IncorrectIndicationInRoutingRuleOperation = 0x39,
    /// Unknown information in IP flow filter(s) (#58).
    UnknownInformationInIpFlowFilters = 0x3a,
    /// Protocol error, unspecified (#111).
    ProtocolErrorUnspecified = 0x6f,
    /// Unknown routing access information (#130).
    UnknownRoutingAccessInformation = 0x82,
}

impl NbifomStatus {
    /// Decode a status; other values are interpreted as "protocol error,
    /// unspecified".
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::ProtocolErrorUnspecified)
    }

    /// Decode only the listed status values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Accepted),
            0x1a => Some(Self::InsufficientResources),
            0x22 => Some(Self::ServiceOptionTemporarilyOutOfOrder),
            0x25 => Some(Self::RequestedServiceOptionNotSubscribed),
            0x3f => Some(Self::RequestRejectedUnspecified),
            0x39 => Some(Self::IncorrectIndicationInRoutingRuleOperation),
            0x3a => Some(Self::UnknownInformationInIpFlowFilters),
            0x6f => Some(Self::ProtocolErrorUnspecified),
            0x82 => Some(Self::UnknownRoutingAccessInformation),
            _ => None,
        }
    }
}

fn nbifom_routing_rule_is_well_formed(rule: &[u8]) -> bool {
    if rule.len() < 7 {
        return false;
    }
    let access_and_operation = rule[1];
    if !matches!(access_and_operation & 0xC0, 0x40 | 0x80)
        || access_and_operation & 0x38 != 0
        || !matches!(access_and_operation & 0x07, 1..=3)
        || rule[4] & 0xC0 != 0
        || rule[5] != 0
        || rule[6] != 0
    {
        return false;
    }
    let first = rule[3];
    let second = rule[4];
    if first & 0x03 != 0 && first & 0x0C != 0
        || second & 0x02 != 0 && second & 0x01 == 0
        || second & 0x08 != 0 && second & 0x04 == 0
    {
        return false;
    }
    let first_sizes = [1usize, 4, 1, 1, 16, 16, 4, 4];
    let second_sizes = [4usize, 4, 4, 4, 1, 4];
    let mut length = 7usize;
    for (index, size) in first_sizes.into_iter().enumerate() {
        if first & (0x80 >> index) != 0 {
            length += size;
        }
    }
    let mut n_offset = None;
    for (index, size) in second_sizes.into_iter().enumerate() {
        if second & (1 << index) != 0 {
            if index == 5 {
                n_offset = Some(length);
            }
            length += size;
        }
    }
    rule.len() == length
        && n_offset.is_none_or(|offset| rule.get(offset).is_some_and(|octet| octet & 0xF0 == 0))
}

fn nbifom_routing_rules_are_well_formed(mut contents: &[u8]) -> bool {
    if contents.is_empty() {
        return false;
    }
    while let Some((&length, rest)) = contents.split_first() {
        let Some(rule) = rest.get(..usize::from(length)) else {
            return false;
        };
        if !nbifom_routing_rule_is_well_formed(rule) {
            return false;
        }
        contents = &rest[rule.len()..];
    }
    true
}

fn nbifom_parameter_is_well_formed(
    parameter: &NbifomParameter,
    direction: NbifomDirection,
) -> bool {
    let contents = parameter.contents.as_slice();
    let allowed = match direction {
        NbifomDirection::UeToNetwork => matches!(parameter.identifier, 1 | 2 | 3 | 4 | 5 | 7 | 8),
        NbifomDirection::NetworkToUe => matches!(parameter.identifier, 1 | 2 | 3 | 4 | 6),
    };
    allowed
        && match parameter.identifier {
            1 | 2 | 6 => matches!(contents, [1 | 2]),
            3 => matches!(contents, [value] if NbifomStatus::from_u8_strict(*value).is_some()),
            4 | 5 => nbifom_routing_rules_are_well_formed(contents),
            7 => matches!(contents, [1..=3]),
            8 => matches!(contents, [value] if value & 0xF0 == 0
                && value & 0x03 != 0x03
                && value & 0x0C != 0x0C),
            _ => false,
        }
}

impl NasNbifomContainer {
    /// Parameter units in wire order; `None` if a unit overruns the value.
    pub fn parameters(&self) -> Option<Vec<NbifomParameter>> {
        let mut parameters = Vec::new();
        let mut remaining = self.value.as_slice();
        while let Some((&identifier, rest)) = remaining.split_first() {
            let (&length, rest) = rest.split_first()?;
            let contents = rest.get(..usize::from(length))?;
            parameters.push(NbifomParameter {
                identifier,
                contents: contents.to_vec(),
            });
            remaining = &rest[contents.len()..];
        }
        Some(parameters)
    }

    /// Contents of the first unit with `identifier`. Units are unordered
    /// and unsupported identifiers are ignored (TS 24.161 §6.1.1).
    pub fn parameter(&self, identifier: NbifomParameterId) -> Option<Vec<u8>> {
        self.parameters()?
            .into_iter()
            .find(|parameter| parameter.identifier == identifier as u8)
            .map(|parameter| parameter.contents)
    }

    /// NBIFOM status of the first status unit, with the receive fallback.
    pub fn status(&self) -> Option<NbifomStatus> {
        let contents = self.parameter(NbifomParameterId::Status)?;
        contents
            .first()
            .map(|&status| NbifomStatus::from_u8(status))
    }

    /// Build from parameter units; `None` if a unit or the value exceeds
    /// 255 octets.
    pub fn from_parameters(parameters: &[NbifomParameter]) -> Option<Self> {
        let mut value = Vec::new();
        for parameter in parameters {
            value.push(parameter.identifier);
            value.push(u8::try_from(parameter.contents.len()).ok()?);
            value.extend_from_slice(&parameter.contents);
        }
        (value.len() <= 255).then(|| Self::new(value))
    }

    /// Sender check for a particular NBIFOM message direction.
    pub fn is_well_formed_for(&self, direction: NbifomDirection) -> bool {
        self.parameters().is_some_and(|parameters| {
            !parameters.is_empty()
                && parameters
                    .iter()
                    .all(|parameter| nbifom_parameter_is_well_formed(parameter, direction))
        })
    }

    /// Direction-agnostic sender check for standalone IE construction.
    /// Message validation uses [`Self::is_well_formed_for`].
    pub fn is_well_formed(&self) -> bool {
        self.parameters().is_some_and(|parameters| {
            !parameters.is_empty()
                && parameters.iter().all(|parameter| {
                    nbifom_parameter_is_well_formed(parameter, NbifomDirection::UeToNetwork)
                        || nbifom_parameter_is_well_formed(parameter, NbifomDirection::NetworkToUe)
                })
        })
    }
}

/// One ciphering data set of the ciphering key data IE (TS 24.301 §9.9.3.56).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CipheringDataSet {
    /// Ciphering set identifier.
    pub set_id: u16,
    /// Ciphering key.
    pub ciphering_key: [u8; 16],
    /// c0 counter value, 0 to 16 octets.
    pub c0: Vec<u8>,
    /// E-UTRA posSIB types bitmap (octets k+1 to k+4).
    pub pos_sib_types: [u8; 4],
    /// Validity start time: octets 2 to 6 of the TS 24.008 time zone and time IE.
    pub validity_start_time: [u8; 5],
    /// Validity duration in minutes.
    pub validity_duration: u16,
    /// TAI list value octets; empty means the whole serving PLMN.
    pub tai_list: Vec<u8>,
}

impl CipheringDataSet {
    /// Tracking areas covered by the set, or `None` for the whole serving PLMN.
    pub fn tai_list_value(&self) -> Option<TaiList> {
        TaiList::from_bytes(&self.tai_list)
    }
}

impl NasCipheringKeyData {
    /// The raw ciphering key data octets.
    pub fn data(&self) -> &[u8] {
        &self.value
    }

    /// Decode the ciphering data sets. The receiver keeps the first 16 sets
    /// and ignores the remaining octets (Table 9.9.3.56.1); decoding stops at
    /// the first incomplete set. Spare bits of the c0 length octet are ignored.
    pub fn data_sets(&self) -> Vec<CipheringDataSet> {
        let mut rest = self.value.as_slice();
        let mut sets = Vec::new();
        while sets.len() < 16 && rest.len() >= 31 {
            let c0_length = usize::from(rest[18] & 0x1f);
            if c0_length > 16 {
                break;
            }
            let fixed = 19 + c0_length;
            let Some(&tai_length) = rest.get(fixed + 11) else {
                break;
            };
            let end = fixed + 12 + usize::from(tai_length);
            if rest.len() < end {
                break;
            }
            sets.push(CipheringDataSet {
                set_id: u16::from_be_bytes([rest[0], rest[1]]),
                ciphering_key: rest[2..18].try_into().expect("16 key octets"),
                c0: rest[19..fixed].to_vec(),
                pos_sib_types: rest[fixed..fixed + 4].try_into().expect("4 bitmap octets"),
                validity_start_time: rest[fixed + 4..fixed + 9]
                    .try_into()
                    .expect("5 time octets"),
                validity_duration: u16::from_be_bytes([rest[fixed + 9], rest[fixed + 10]]),
                tai_list: rest[fixed + 12..end].to_vec(),
            });
            rest = &rest[end..];
        }
        sets
    }

    /// Encode 1 to 16 ciphering data sets; `None` for an invalid count, a c0
    /// longer than 16 octets, or a TAI list longer than 255 octets.
    pub fn from_data_sets(sets: &[CipheringDataSet]) -> Option<Self> {
        if !(1..=16).contains(&sets.len()) {
            return None;
        }
        let mut value = Vec::new();
        for set in sets {
            if set.c0.len() > 16 {
                return None;
            }
            value.extend_from_slice(&set.set_id.to_be_bytes());
            value.extend_from_slice(&set.ciphering_key);
            value.push(set.c0.len() as u8);
            value.extend_from_slice(&set.c0);
            value.extend_from_slice(&set.pos_sib_types);
            value.extend_from_slice(&set.validity_start_time);
            value.extend_from_slice(&set.validity_duration.to_be_bytes());
            value.push(u8::try_from(set.tai_list.len()).ok()?);
            value.extend_from_slice(&set.tai_list);
        }
        (value.len() <= u16::MAX as usize).then(|| Self::new(value))
    }

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
            if tai_length != 0
                && TaiList::from_bytes_strict(&remaining[tai_length_at + 1..end]).is_none()
            {
                return false;
            }
            remaining = &remaining[end..];
        }
        count > 0
    }
}

/// Handling of the S&F monitoring list (SFMLI, TS 24.301 Table 9.9.3.73.1).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SAndFMonitoringList {
    /// No list; also the reading of the unused value 11.
    NotPresent,
    /// No list, and the UE deletes any list received before.
    Delete,
    /// Satellite IDs.
    Present(Vec<u8>),
}

impl NasSAndFSatelliteOperationParameters {
    /// S&F wait time duration in seconds, when indicated.
    pub fn wait_time(&self) -> Option<u16> {
        let flags = *self.value.first()?;
        if flags & 0x01 == 0 {
            return None;
        }
        let [high, low] = *self.value.get(1..)?.first_chunk::<2>()?;
        Some(u16::from_be_bytes([high, low]))
    }

    /// Estimated S&F uplink delivery time duration in seconds, when indicated.
    pub fn uplink_delivery_time(&self) -> Option<u32> {
        let flags = *self.value.first()?;
        if flags & 0x02 == 0 {
            return None;
        }
        let offset = 1 + if flags & 0x01 != 0 { 2 } else { 0 };
        crate::common::ts24301::read_time_duration(self.value.get(offset..)?)
    }

    /// S&F monitoring list handling; `None` if the list overruns the value.
    pub fn monitoring_list(&self) -> Option<SAndFMonitoringList> {
        let flags = *self.value.first()?;
        Some(match (flags >> 2) & 0x03 {
            1 => SAndFMonitoringList::Delete,
            2 => {
                let offset = 1
                    + if flags & 0x01 != 0 { 2 } else { 0 }
                    + if flags & 0x02 != 0 { 3 } else { 0 };
                let (&count, ids) = self.value.get(offset..)?.split_first()?;
                SAndFMonitoringList::Present(ids.get(..usize::from(count))?.to_vec())
            }
            _ => SAndFMonitoringList::NotPresent,
        })
    }

    /// Build from the fields; the uplink delivery time is at most 0xFFFFFF
    /// seconds and the list holds at most 255 satellite IDs.
    pub fn from_fields(
        wait_time: Option<u16>,
        uplink_delivery_time: Option<u32>,
        monitoring_list: &SAndFMonitoringList,
    ) -> Option<Self> {
        let list_mode = match monitoring_list {
            SAndFMonitoringList::NotPresent => 0,
            SAndFMonitoringList::Delete => 1,
            SAndFMonitoringList::Present(_) => 2,
        };
        let mut value = vec![
            u8::from(wait_time.is_some())
                | u8::from(uplink_delivery_time.is_some()) << 1
                | list_mode << 2,
        ];
        if let Some(wait_time) = wait_time {
            value.extend_from_slice(&wait_time.to_be_bytes());
        }
        if let Some(seconds) = uplink_delivery_time {
            if seconds > 0x00ff_ffff {
                return None;
            }
            value.extend_from_slice(&seconds.to_be_bytes()[1..]);
        }
        if let SAndFMonitoringList::Present(ids) = monitoring_list {
            value.push(u8::try_from(ids.len()).ok()?);
            value.extend_from_slice(ids);
        }
        (value.len() <= 255).then(|| Self::new(value))
    }

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

pub use crate::common::ts24501::PortRange;

/// Type of a remote UE user identity (TS 24.301 Table 9.9.4.20.2).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RemoteUeIdentityType {
    /// Encrypted IMSI, a 128-bit string.
    EncryptedImsi = 1,
    /// IMSI.
    Imsi = 2,
    /// MSISDN.
    Msisdn = 3,
    /// IMEI.
    Imei = 4,
    /// IMEISV.
    Imeisv = 5,
}

/// One user identity of a remote UE context: octet 4 onwards of the
/// identity, which carries digit 1, the odd/even indication, and the type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RemoteUeUserIdentity {
    /// Identity octets, starting with the type octet.
    pub octets: Vec<u8>,
}

impl RemoteUeUserIdentity {
    /// Raw type of identity (bits 3-1 of the first octet).
    pub fn identity_type_raw(&self) -> Option<u8> {
        self.octets.first().map(|octet| octet & 0x07)
    }

    /// Typed identity type; reserved codes return `None`.
    pub fn identity_type(&self) -> Option<RemoteUeIdentityType> {
        match self.identity_type_raw()? {
            1 => Some(RemoteUeIdentityType::EncryptedImsi),
            2 => Some(RemoteUeIdentityType::Imsi),
            3 => Some(RemoteUeIdentityType::Msisdn),
            4 => Some(RemoteUeIdentityType::Imei),
            5 => Some(RemoteUeIdentityType::Imeisv),
            _ => None,
        }
    }

    /// BCD digits of an IMSI, MSISDN, IMEI, or IMEISV.
    pub fn digits(&self) -> Option<String> {
        let kind = self.identity_type_raw()?;
        let max_digits = match self.identity_type()? {
            RemoteUeIdentityType::EncryptedImsi => return None,
            RemoteUeIdentityType::Imeisv => 16,
            _ => 15,
        };
        crate::common::decode_identity_digits(&self.octets, kind, max_digits)
    }

    /// The 128-bit encrypted IMSI, from the 16 octets after the type octet.
    pub fn encrypted_imsi(&self) -> Option<[u8; 16]> {
        if self.identity_type()? != RemoteUeIdentityType::EncryptedImsi {
            return None;
        }
        self.octets.get(1..17)?.try_into().ok()
    }

    /// Whether this identity uses a defined type and canonical sender coding.
    pub fn is_well_formed(&self) -> bool {
        match self.identity_type() {
            Some(RemoteUeIdentityType::EncryptedImsi) => {
                self.octets.len() == 17
                    && self.octets.first() == Some(&(RemoteUeIdentityType::EncryptedImsi as u8))
            }
            Some(identity_type) => self.digits().is_some_and(|digits| {
                let type_specific = match identity_type {
                    RemoteUeIdentityType::Imsi | RemoteUeIdentityType::Msisdn => true,
                    RemoteUeIdentityType::Imei => digits.len() == 15 && digits.ends_with('0'),
                    RemoteUeIdentityType::Imeisv => digits.len() == 16 && !digits.ends_with("99"),
                    RemoteUeIdentityType::EncryptedImsi => unreachable!(),
                };
                type_specific && Self::from_digits(identity_type, &digits).as_ref() == Some(self)
            }),
            None => false,
        }
    }

    /// Build a BCD identity; `None` for the encrypted IMSI or invalid digits.
    pub fn from_digits(identity_type: RemoteUeIdentityType, digits: &str) -> Option<Self> {
        let max_digits = match identity_type {
            RemoteUeIdentityType::EncryptedImsi => return None,
            RemoteUeIdentityType::Imei if digits.len() != 15 || !digits.ends_with('0') => {
                return None;
            }
            RemoteUeIdentityType::Imeisv if digits.len() != 16 || digits.ends_with("99") => {
                return None;
            }
            RemoteUeIdentityType::Imeisv => 16,
            _ => 15,
        };
        let octets =
            crate::common::encode_identity_digits(digits, identity_type as u8, max_digits)?;
        Some(Self { octets })
    }

    /// Build an encrypted IMSI identity with bits 8 to 5 of the type octet clear.
    pub fn from_encrypted_imsi(encrypted_imsi: [u8; 16]) -> Self {
        let mut octets = vec![RemoteUeIdentityType::EncryptedImsi as u8];
        octets.extend_from_slice(&encrypted_imsi);
        Self { octets }
    }
}

/// Address information of a remote UE context (TS 24.301 Table 9.9.4.20.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RemoteUeAddress {
    /// No IP information.
    NoIpInfo,
    /// IPv4 address and NAT port, with optional UDP and TCP port ranges.
    Ipv4 {
        /// IPv4 address.
        address: [u8; 4],
        /// Port number assigned in the NAT function.
        port: u16,
        /// UDP port range.
        udp_port_range: Option<PortRange>,
        /// TCP port range.
        tcp_port_range: Option<PortRange>,
    },
    /// /64 IPv6 prefix.
    Ipv6Prefix([u8; 8]),
    /// A reserved address type and the octets after octet j.
    Unknown {
        /// Address type (bits 3-1 of octet j).
        address_type: u8,
        /// Remaining octets of the context.
        octets: Vec<u8>,
    },
}

/// One remote UE context of the remote UE context list IE.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EpsRemoteUeContext {
    /// User identities in wire order.
    pub user_identities: Vec<RemoteUeUserIdentity>,
    /// Address information.
    pub address: RemoteUeAddress,
}

fn read_port_range(octets: &[u8]) -> Option<(PortRange, &[u8])> {
    let (range, rest) = octets.split_first_chunk::<4>()?;
    let low = u16::from_be_bytes([range[0], range[1]]);
    let high = u16::from_be_bytes([range[2], range[3]]);
    Some((PortRange { low, high }, rest))
}

impl EpsRemoteUeContext {
    /// Parse the octets after the context length. Spare bits are ignored;
    /// the port-range indicators apply only to IPv4, and octets after the
    /// address information are ignored.
    pub fn from_bytes(octets: &[u8]) -> Option<Self> {
        let (&count, mut rest) = octets.split_first()?;
        let mut user_identities = Vec::with_capacity(usize::from(count));
        for _ in 0..count {
            let (&length, after) = rest.split_first()?;
            if length == 0 {
                return None;
            }
            let identity = after.get(..usize::from(length))?;
            user_identities.push(RemoteUeUserIdentity {
                octets: identity.to_vec(),
            });
            rest = &after[identity.len()..];
        }
        let (&flags, rest) = rest.split_first()?;
        let address = match flags & 0x07 {
            0 => RemoteUeAddress::NoIpInfo,
            1 => {
                let (info, mut rest) = rest.split_first_chunk::<6>()?;
                let mut udp_port_range = None;
                let mut tcp_port_range = None;
                if flags & 0x10 != 0 {
                    let (range, after) = read_port_range(rest)?;
                    udp_port_range = Some(range);
                    rest = after;
                }
                if flags & 0x08 != 0 {
                    tcp_port_range = Some(read_port_range(rest)?.0);
                }
                RemoteUeAddress::Ipv4 {
                    address: [info[0], info[1], info[2], info[3]],
                    port: u16::from_be_bytes([info[4], info[5]]),
                    udp_port_range,
                    tcp_port_range,
                }
            }
            2 => RemoteUeAddress::Ipv6Prefix(*rest.first_chunk::<8>()?),
            address_type => RemoteUeAddress::Unknown {
                address_type,
                octets: rest.to_vec(),
            },
        };
        Some(Self {
            user_identities,
            address,
        })
    }

    /// Whether every identity and the address use canonical sender coding.
    pub fn is_well_formed(&self) -> bool {
        self.user_identities
            .iter()
            .all(RemoteUeUserIdentity::is_well_formed)
            && match &self.address {
                RemoteUeAddress::Ipv4 {
                    port,
                    udp_port_range,
                    tcp_port_range,
                    ..
                } => [udp_port_range, tcp_port_range]
                    .into_iter()
                    .flatten()
                    .all(|range| range.low <= *port && *port <= range.high),
                RemoteUeAddress::Unknown { .. } => false,
                _ => true,
            }
    }

    /// Encode the octets after the context length; `None` if a count or
    /// length does not fit its octet.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let mut octets = vec![u8::try_from(self.user_identities.len()).ok()?];
        for identity in &self.user_identities {
            if identity.octets.is_empty() {
                return None;
            }
            octets.push(u8::try_from(identity.octets.len()).ok()?);
            octets.extend_from_slice(&identity.octets);
        }
        match &self.address {
            RemoteUeAddress::NoIpInfo => octets.push(0),
            RemoteUeAddress::Ipv4 {
                address,
                port,
                udp_port_range,
                tcp_port_range,
            } => {
                octets.push(
                    0x01 | u8::from(udp_port_range.is_some()) << 4
                        | u8::from(tcp_port_range.is_some()) << 3,
                );
                octets.extend_from_slice(address);
                octets.extend_from_slice(&port.to_be_bytes());
                for range in [udp_port_range, tcp_port_range].into_iter().flatten() {
                    octets.extend_from_slice(&range.low.to_be_bytes());
                    octets.extend_from_slice(&range.high.to_be_bytes());
                }
            }
            RemoteUeAddress::Ipv6Prefix(prefix) => {
                octets.push(0x02);
                octets.extend_from_slice(prefix);
            }
            RemoteUeAddress::Unknown {
                address_type,
                octets: rest,
            } => {
                octets.push(address_type & 0x07);
                octets.extend_from_slice(rest);
            }
        }
        Some(octets)
    }
}

/// Remote UE context list (TS 24.301 §9.9.4.20).
macro_rules! remote_ue_context_list_ie {
    ($name:ident) => {
        impl $name {
            /// Split the declared remote UE contexts without changing their bytes.
            pub fn context_octets(&self) -> Option<Vec<&[u8]>> {
                let count = usize::from(*self.value.first()?);
                let mut remaining = &self.value[1..];
                let mut contexts = Vec::with_capacity(count);
                for _ in 0..count {
                    let (&length, rest) = remaining.split_first()?;
                    let context = rest.get(..usize::from(length))?;
                    contexts.push(context);
                    remaining = &rest[context.len()..];
                }
                Some(contexts)
            }

            /// Typed remote UE contexts; octets after the declared contexts
            /// are ignored.
            pub fn contexts(&self) -> Option<Vec<EpsRemoteUeContext>> {
                self.context_octets()?
                    .into_iter()
                    .map(EpsRemoteUeContext::from_bytes)
                    .collect()
            }

            /// Build from typed contexts; `None` if the list is empty or a
            /// length does not fit.
            pub fn from_contexts(contexts: &[EpsRemoteUeContext]) -> Option<Self> {
                if contexts.is_empty() || contexts.iter().any(|context| !context.is_well_formed()) {
                    return None;
                }
                let mut value = vec![u8::try_from(contexts.len()).ok()?];
                for context in contexts {
                    let octets = context.to_bytes()?;
                    value.push(u8::try_from(octets.len()).ok()?);
                    value.extend_from_slice(&octets);
                }
                (value.len() <= usize::from(u16::MAX)).then(|| Self::new(value))
            }

            /// Sender check: at least one context (the §9.9.4.20 minimum of
            /// 5 octets), the declared contexts fill the value exactly, and
            /// each re-encodes to the same octets.
            pub fn is_well_formed(&self) -> bool {
                let (Some(octets), Some(contexts)) = (self.context_octets(), self.contexts())
                else {
                    return false;
                };
                let used: usize = octets.iter().map(|context| 1 + context.len()).sum();
                !octets.is_empty()
                    && used + 1 == self.value.len()
                    && octets.iter().zip(&contexts).all(|(octets, context)| {
                        context.is_well_formed() && context.to_bytes().as_deref() == Some(*octets)
                    })
            }
        }
    };
}

remote_ue_context_list_ie!(NasRemoteUeContextConnected);
remote_ue_context_list_ie!(NasRemoteUeContextDisconnected);

/// PKMF address type (TS 24.301 Table 9.9.4.21.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PkmfAddressType {
    /// IPv4 address.
    Ipv4 = 1,
    /// IPv6 address.
    Ipv6 = 2,
}

impl NasProseKeyManagementFunctionAddress {
    /// Raw address type (octet 3, bits 3-1).
    pub fn address_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x07)
    }

    /// Typed address type; reserved codes return `None`.
    pub fn address_type(&self) -> Option<PkmfAddressType> {
        match self.address_type_raw()? {
            1 => Some(PkmfAddressType::Ipv4),
            2 => Some(PkmfAddressType::Ipv6),
            _ => None,
        }
    }

    /// Read the PKMF IPv4 or IPv6 address from TS 24.301 §9.9.4.21. Spare
    /// bits and octets after the address are ignored.
    pub fn address(&self) -> Option<std::net::IpAddr> {
        let address = self.value.get(1..)?;
        match self.address_type()? {
            PkmfAddressType::Ipv4 => Some(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(address.get(..4)?).ok()?,
            ))),
            PkmfAddressType::Ipv6 => Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(address.get(..16)?).ok()?,
            ))),
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

    /// Sender check: spare bits clear and exactly one address.
    pub fn is_well_formed(&self) -> bool {
        self.address()
            .is_some_and(|address| Self::from_address(address).value == self.value)
    }
}

// ── APN (TS 24.301 §9.9.4.1) ─────────────────────────────────────────────

crate::common::ts24008::access_point_name_ie!(NasAccessPointName);
crate::common::ts24008::plmn_list_ie!(NasEquivalentPlmns);
pub use crate::common::ts24008::{
    DaylightSavingAdjustment, EmergencyNumber, NetworkNameCodingScheme,
};
crate::common::ts24008::network_name_ie!(NasNetworkName);
crate::common::ts24008::time_zone_ie!(NasLocalTimeZone);
crate::common::ts24008::time_zone_and_time_ie!(NasUniversalTimeAndLocalTimeZone);
crate::common::ts24008::daylight_saving_time_ie!(NasNetworkDaylightSavingTime);
crate::common::ts24008::emergency_number_list_ie!(NasEmergencyNumberList);
pub use crate::common::ts24301::ExtendedEmergencyNumber;
crate::common::ts24301::extended_emergency_number_list_ie!(NasExtendedEmergencyNumberList);
pub use crate::common::ts24008::EutraMode;
crate::common::ts24008::extended_drx_parameters_ie!(NasExtendedDrxParameters);
crate::common::ts24008::supported_codec_list_ie!(NasSupportedCodecs);
pub use crate::common::ts24301::{UePagingProbability, UeRequestType};
crate::common::ts24301::wus_assistance_information_ie!(NasRequestedWusAssistanceInformation);
crate::common::ts24301::wus_assistance_information_ie!(NasNegotiatedWusAssistanceInformation);
crate::common::ts24301::ue_request_type_ie!(NasUeRequestType);
crate::common::ts24301::unavailability_information_ie!(NasUnavailabilityInformation);
crate::common::ts24301::unavailability_configuration_ie!(NasUnavailabilityConfiguration);
crate::common::ts24301::access_technology_utilization_control_ie!(
    NasAccessTechnologyUtilizationControl
);
pub use crate::common::ts24501::RadioCapabilityIdDeletionRequest;
crate::common::ts24501::ue_radio_capability_id_ie!(NasUeRadioCapabilityId);
crate::common::ts24501::ue_radio_capability_id_deletion_indication_ie!(
    NasUeRadioCapabilityIdDeletionIndication
);
crate::common::ts24501::plmn_identity_ie!(NasUeDeterminedPlmnWithDisasterCondition);
crate::common::ts24501::registration_wait_range_ie!(NasDisasterRoamingWaitRange);
crate::common::ts24501::registration_wait_range_ie!(NasDisasterReturnWaitRange);
crate::common::ts24501::disaster_plmn_list_ie!(NasListOfPlmnsToBeUsedInDisasterCondition);

// ── NAS security algorithms (TS 24.301 §9.9.3.23) ─────────────────────────

pub use crate::common::ts24301::{CipheringAlgorithm, IntegrityAlgorithm};

crate::common::ts24301::nas_security_algorithms_ie!(
    NasSelectedNasSecurityAlgorithms,
    CipheringAlgorithm,
    IntegrityAlgorithm,
    0x07
);

/// EPS attach type from TS 24.301 table 9.9.3.11.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AttachType {
    /// EPS attach.
    EpsAttach = 1,
    /// Combined EPS/IMSI attach.
    CombinedEpsImsiAttach = 2,
    /// EPS RLOS attach; a network without RLOS support reads it as EPS attach.
    EpsRlosAttach = 3,
    /// EPS emergency attach.
    EpsEmergencyAttach = 6,
    /// EPS attach for access to disaster roaming services.
    DisasterRoamingAttach = 7,
}

impl AttachType {
    /// Parse a received value; unused values are read as EPS attach by the
    /// network.
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::EpsAttach)
    }

    /// Parse only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::EpsAttach),
            2 => Some(Self::CombinedEpsImsiAttach),
            3 => Some(Self::EpsRlosAttach),
            6 => Some(Self::EpsEmergencyAttach),
            7 => Some(Self::DisasterRoamingAttach),
            _ => None,
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

    /// Read only a defined attach type.
    pub fn attach_type_strict(&self) -> Option<AttachType> {
        AttachType::from_u8_strict(self.value)
    }

    /// Raw attach type (bits 3-1).
    pub fn attach_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the attach type and clear the spare bit.
    pub fn set_attach_type(&mut self, value: AttachType) -> &mut Self {
        self.value = value as u8;
        self
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
    /// Mobile originating CS fallback or 1xCS fallback.
    MobileOriginatingCsFallback = 0,
    /// Mobile terminating CS fallback or 1xCS fallback.
    MobileTerminatingCsFallback = 1,
    /// Mobile originating CS fallback emergency call or 1xCS fallback
    /// emergency call.
    MobileOriginatingEmergencyCsFallback = 2,
    /// Packet services via S1.
    PacketServices = 8,
}

impl ServiceType {
    /// Interpret received unused values as specified by the network fallback rules.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0f {
            3 | 4 => Some(Self::MobileOriginatingCsFallback),
            9..=11 => Some(Self::PacketServices),
            other => Self::from_u8_strict(other),
        }
    }

    /// Parse only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x0f {
            0 => Some(Self::MobileOriginatingCsFallback),
            1 => Some(Self::MobileTerminatingCsFallback),
            2 => Some(Self::MobileOriginatingEmergencyCsFallback),
            8 => Some(Self::PacketServices),
            _ => None,
        }
    }
}

impl NasServiceType {
    /// Build from a typed service type.
    pub fn from_service_type(value: ServiceType) -> Self {
        Self::new(value as u8)
    }

    /// Service type with the network receive fallbacks.
    pub fn service_type(&self) -> Option<ServiceType> {
        ServiceType::from_u8(self.value)
    }

    /// Service type, only for a defined value.
    pub fn service_type_strict(&self) -> Option<ServiceType> {
        ServiceType::from_u8_strict(self.value)
    }

    /// Raw service type (bits 4-1).
    pub fn service_type_raw(&self) -> u8 {
        self.value & 0x0f
    }

    /// Set the service type.
    pub fn set_service_type(&mut self, value: ServiceType) -> &mut Self {
        self.value = value as u8;
        self
    }

    /// Builder form of [`Self::set_service_type`].
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
    /// Mobile originating request.
    MobileOriginating = 0,
    /// Mobile terminating request.
    MobileTerminating = 1,
}

impl ControlPlaneServiceType {
    /// Values 2 through 7 use the mobile-originating receive fallback.
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::MobileOriginating)
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            0 => Some(Self::MobileOriginating),
            1 => Some(Self::MobileTerminating),
            _ => None,
        }
    }
}

impl NasControlPlaneServiceType {
    /// Build from a service type and the "active" flag.
    pub fn from_service_type(value: ControlPlaneServiceType, active: bool) -> Self {
        Self::new(value as u8 | ((active as u8) << 3))
    }

    /// Service type with the mobile-originating receive fallback.
    pub fn service_type(&self) -> ControlPlaneServiceType {
        ControlPlaneServiceType::from_u8(self.value)
    }

    /// Service type, only for a defined value.
    pub fn service_type_strict(&self) -> Option<ControlPlaneServiceType> {
        ControlPlaneServiceType::from_u8_strict(self.value)
    }

    /// Raw service type (bits 3-1).
    pub fn service_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// "Active" flag (bit 4): radio bearer establishment requested.
    pub fn is_active(&self) -> bool {
        self.value & 0x08 != 0
    }

    /// Set the service type, keeping the "active" flag.
    pub fn set_service_type(&mut self, value: ControlPlaneServiceType) -> &mut Self {
        self.value = (self.value & 0x08) | value as u8;
        self
    }

    /// Builder form of [`Self::set_service_type`].
    pub fn with_service_type(mut self, value: ControlPlaneServiceType) -> Self {
        self.set_service_type(value);
        self
    }

    /// Set the "active" flag.
    pub fn set_active(&mut self, active: bool) -> &mut Self {
        self.value = (self.value & 0x07) | ((active as u8) << 3);
        self
    }

    /// Builder form of [`Self::set_active`].
    pub fn with_active(mut self, active: bool) -> Self {
        self.set_active(active);
        self
    }
}

/// EPS PDN type from TS 24.301 table 9.9.4.10.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PdnType {
    /// IPv4.
    Ipv4 = 1,
    /// IPv6.
    Ipv6 = 2,
    /// IPv4v6.
    Ipv4v6 = 3,
    /// Non-IP.
    NonIp = 5,
    /// Ethernet.
    Ethernet = 6,
}

impl PdnType {
    /// Parse a received value; code 4 is interpreted as IPv6 by the network.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            4 => Some(Self::Ipv6),
            other => Self::from_u8_strict(other),
        }
    }

    /// Parse only the defined codes.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::Ipv4),
            2 => Some(Self::Ipv6),
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

    /// Read only a defined PDN type code.
    pub fn pdn_type_strict(&self) -> Option<PdnType> {
        PdnType::from_u8_strict(self.value)
    }

    /// Raw PDN type (bits 3-1).
    pub fn pdn_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the PDN type and clear the spare bit.
    pub fn set_pdn_type(&mut self, value: PdnType) -> &mut Self {
        self.value = value as u8;
        self
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
    /// EPS only.
    EpsOnly = 1,
    /// Combined EPS/IMSI attach.
    CombinedEpsImsi = 2,
}

impl AttachResult {
    /// Decode bits 3-1; reserved values return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::EpsOnly),
            2 => Some(Self::CombinedEpsImsi),
            _ => None,
        }
    }
}

impl NasEpsAttachResult {
    /// Build from a typed attach result.
    pub fn from_attach_result(value: AttachResult) -> Self {
        Self::new(value as u8)
    }

    /// Typed attach result; reserved values return `None`.
    pub fn attach_result(&self) -> Option<AttachResult> {
        AttachResult::from_u8(self.value)
    }

    /// Raw attach result (bits 3-1).
    pub fn attach_result_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the attach result and clear the spare bit.
    pub fn set_attach_result(&mut self, value: AttachResult) -> &mut Self {
        self.value = value as u8;
        self
    }

    /// Builder form of [`Self::set_attach_result`].
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
    /// TA updating.
    TaUpdating = 0,
    /// Combined TA/LA updating.
    CombinedTaLaUpdating = 1,
    /// Combined TA/LA updating with IMSI attach.
    CombinedTaLaUpdatingWithImsiAttach = 2,
    /// Periodic updating.
    PeriodicUpdating = 3,
    /// Disaster roaming update.
    DisasterRoamingUpdate = 6,
}

impl UpdateType {
    /// Decode bits 3-1; the unused values 4 and 5 are read as TA updating
    /// by the network, and the reserved value 7 returns `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            4 | 5 => Some(Self::TaUpdating),
            other => Self::from_u8_strict(other),
        }
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            0 => Some(Self::TaUpdating),
            1 => Some(Self::CombinedTaLaUpdating),
            2 => Some(Self::CombinedTaLaUpdatingWithImsiAttach),
            3 => Some(Self::PeriodicUpdating),
            6 => Some(Self::DisasterRoamingUpdate),
            _ => None,
        }
    }
}

impl NasEpsUpdateType {
    /// Build from a typed update type with the "active" flag clear.
    pub fn from_update_type(value: UpdateType) -> Self {
        Self::new(value as u8)
    }

    /// Update type with the network receive fallback.
    pub fn update_type(&self) -> Option<UpdateType> {
        UpdateType::from_u8(self.value)
    }

    /// Update type, only for a defined value.
    pub fn update_type_strict(&self) -> Option<UpdateType> {
        UpdateType::from_u8_strict(self.value)
    }

    /// Raw update type (bits 3-1).
    pub fn update_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the update type, keeping the "active" flag.
    pub fn set_update_type(&mut self, value: UpdateType) -> &mut Self {
        self.value = (self.value & 0x08) | value as u8;
        self
    }

    /// Builder form of [`Self::set_update_type`].
    pub fn with_update_type(mut self, value: UpdateType) -> Self {
        self.set_update_type(value);
        self
    }

    /// "Active" flag (bit 4): bearer establishment requested.
    pub fn is_active(&self) -> bool {
        self.value & 0x08 != 0
    }

    /// Set the "active" flag.
    pub fn set_active(&mut self, active: bool) -> &mut Self {
        self.value = (self.value & 0x07) | ((active as u8) << 3);
        self
    }

    /// Builder form of [`Self::set_active`].
    pub fn with_active(mut self, active: bool) -> Self {
        self.set_active(active);
        self
    }
}

/// EPS update result from TS 24.301 table 9.9.3.13.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UpdateResult {
    /// TA updated.
    TaUpdated = 0,
    /// Combined TA/LA updated.
    CombinedTaLaUpdated = 1,
    /// TA updated and ISR activated.
    TaUpdatedWithIsr = 4,
    /// Combined TA/LA updated and ISR activated.
    CombinedTaLaUpdatedWithIsr = 5,
}

impl UpdateResult {
    /// Decode bits 3-1; reserved values return `None`.
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
    /// Build from a typed update result.
    pub fn from_update_result(value: UpdateResult) -> Self {
        Self::new(value as u8)
    }

    /// Typed update result; reserved values return `None`.
    pub fn update_result(&self) -> Option<UpdateResult> {
        UpdateResult::from_u8(self.value)
    }

    /// Raw update result (bits 3-1).
    pub fn update_result_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Set the update result and clear the spare bit.
    pub fn set_update_result(&mut self, value: UpdateResult) -> &mut Self {
        self.value = value as u8;
        self
    }

    /// Builder form of [`Self::set_update_result`].
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
    /// IMSI.
    Imsi = 1,
    /// IMEI.
    Imei = 3,
    /// GUTI.
    Guti = 6,
}

impl MobileIdentityType {
    /// Decode bits 3-1; reserved values return `None`.
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
    /// PLMN identity.
    pub plmn: PlmnId,
    /// MME group ID.
    pub mme_group_id: u16,
    /// MME code.
    pub mme_code: u8,
    /// M-TMSI.
    pub m_tmsi: u32,
}

impl Guti {
    /// Parse a GUTI value, including the identity type octet. Only the type
    /// bits of that octet are checked, and octets after the eleventh are
    /// ignored (TS 24.007 §11.4.2).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let bytes = bytes.get(..11)?;
        if bytes[0] & 0x07 != 0x06 {
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

fn decode_receiver_identity_digits(value: &[u8], kind: u8, max_digits: usize) -> Option<String> {
    let max_octets = 1 + max_digits.saturating_sub(1).div_ceil(2);
    (2..=value.len().min(max_octets))
        .rev()
        .find_map(|end| crate::common::decode_identity_digits(&value[..end], kind, max_digits))
}

fn decode_mobile_identity_digits(value: &[u8], kind: MobileIdentityType) -> Option<String> {
    decode_receiver_identity_digits(value, kind as u8, 15)
}

fn encode_mobile_identity_digits(digits: &str, kind: MobileIdentityType) -> Option<Vec<u8>> {
    crate::common::encode_identity_digits(digits, kind as u8, 15)
}

impl NasMobileIdentity {
    /// Build an IDENTITY RESPONSE mobile identity containing an IMSI.
    pub fn from_imsi(imsi: &str) -> Option<Self> {
        Some(Self::new(crate::common::encode_identity_digits(
            imsi, 1, 15,
        )?))
    }

    /// Build an IDENTITY RESPONSE mobile identity containing an IMEI.
    pub fn from_imei(imei: &str) -> Option<Self> {
        if imei.len() != 15 {
            return None;
        }
        Some(Self::new(crate::common::encode_identity_digits(
            imei, 2, 15,
        )?))
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
        Some(Self::new(crate::common::encode_identity_digits(
            imeisv, 3, 16,
        )?))
    }

    /// Build a TMSI mobile identity; its first value octet is 0xF4.
    pub fn from_tmsi(tmsi: u32) -> Self {
        let mut value = vec![0xf4];
        value.extend_from_slice(&tmsi.to_be_bytes());
        Self::new(value)
    }

    /// Build the "No Identity" value an EMM IDENTITY RESPONSE uses: three
    /// zero octets (TS 24.008 Table 10.5.4).
    pub fn from_no_identity() -> Self {
        Self::new(vec![0; 3])
    }

    /// Raw type of identity (bits 3-1 of the first octet).
    pub fn identity_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x07)
    }

    /// Decode the IMSI supplied in an IDENTITY RESPONSE.
    pub fn as_imsi(&self) -> Option<String> {
        decode_receiver_identity_digits(&self.value, 1, 15)
    }

    /// Decode the IMEI supplied in an IDENTITY RESPONSE.
    pub fn as_imei(&self) -> Option<String> {
        let digits = decode_receiver_identity_digits(&self.value, 2, 15)?;
        (digits.len() == 15).then_some(digits)
    }

    /// Decode the IMEISV supplied in an IDENTITY RESPONSE.
    pub fn as_imeisv(&self) -> Option<String> {
        let digits = decode_receiver_identity_digits(&self.value, 3, 16)?;
        (digits.len() == 16).then_some(digits)
    }

    /// Decode a four-octet TMSI from an IDENTITY RESPONSE. Only the type
    /// bits are checked, and octets after the TMSI are ignored.
    pub fn as_tmsi(&self) -> Option<u32> {
        if self.value.first().copied()? & 0x07 != 0x04 {
            return None;
        }
        Some(u32::from_be_bytes(self.value.get(1..5)?.try_into().ok()?))
    }

    /// Whether the UE reported no available identity (type of identity 000).
    pub fn is_no_identity(&self) -> bool {
        self.identity_type_raw() == Some(0)
    }

    /// Sender check: an IMSI, an IMEI with a zero spare digit (TS 23.003
    /// §6.2.1), an IMEISV, a 0xF4-coded TMSI of four octets, or the
    /// three-octet "No Identity" value.
    pub fn is_well_formed(&self) -> bool {
        crate::common::decode_identity_digits(&self.value, 1, 15).is_some()
            || crate::common::decode_identity_digits(&self.value, 2, 15)
                .is_some_and(|imei| imei.len() == 15 && imei.ends_with('0'))
            || crate::common::decode_identity_digits(&self.value, 3, 16)
                .is_some_and(|imeisv| imeisv.len() == 16)
            || matches!(self.value.as_slice(), [0xf4, _, _, _, _] | [0, 0, 0])
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

    /// PLMN identity of a GUTI.
    pub fn plmn(&self) -> Option<PlmnId> {
        self.as_guti().map(|guti| guti.plmn)
    }

    /// Typed type of identity; reserved values return `None`.
    pub fn identity_type(&self) -> Option<MobileIdentityType> {
        self.value
            .first()
            .and_then(|value| MobileIdentityType::from_u8(*value))
    }

    /// Raw type of identity (bits 3-1 of the first octet).
    pub fn identity_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x07)
    }

    /// Odd/even indication (bit 4 of the first octet).
    pub fn is_odd_digits(&self) -> Option<bool> {
        self.value.first().map(|value| value & 0x08 != 0)
    }

    /// Sender check: an IMSI, an IMEI with a zero spare digit (TS 23.003
    /// §6.2.1), or an eleven-octet GUTI whose first octet is 0xF6.
    pub fn is_well_formed(&self) -> bool {
        crate::common::decode_identity_digits(&self.value, MobileIdentityType::Imsi as u8, 15)
            .is_some()
            || crate::common::decode_identity_digits(
                &self.value,
                MobileIdentityType::Imei as u8,
                15,
            )
            .is_some_and(|imei| imei.len() == 15 && imei.ends_with('0'))
            || (self.value.len() == 11 && self.value[0] == 0xf6 && self.as_guti().is_some())
    }
}

pub use crate::common::ts24301::KeySetIdentifier;
/// Key set identifier value that means no key is available (§9.9.3.21).
pub use crate::common::ts24301::NAS_KSI_NO_KEY_AVAILABLE;

crate::common::ts24301::key_set_identifier_ie!(NasKeySetIdentifier, builders);
crate::common::ts24301::key_set_identifier_ie!(NasNonCurrentNativeNasKeySetIdentifier);

impl Default for NasKeySetIdentifier {
    /// No key available, native context.
    fn default() -> Self {
        Self::new(NAS_KSI_NO_KEY_AVAILABLE)
    }
}

// ── Detach type ──────────────────────────────────────────────────────────────

/// UE-originated detach kind from TS 24.301 table 9.9.3.7.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum UeDetachKind {
    /// EPS detach.
    Eps = 1,
    /// IMSI detach.
    Imsi = 2,
    /// Combined EPS/IMSI detach.
    CombinedEpsImsi = 3,
}

impl UeDetachKind {
    /// Decode bits 3-1; other values are interpreted as combined EPS/IMSI
    /// detach by the network.
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::CombinedEpsImsi)
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::Eps),
            2 => Some(Self::Imsi),
            3 => Some(Self::CombinedEpsImsi),
            _ => None,
        }
    }
}

/// Network-originated detach kind from TS 24.301 table 9.9.3.7.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NetworkDetachKind {
    /// Re-attach required.
    ReattachRequired = 1,
    /// Re-attach not required.
    ReattachNotRequired = 2,
    /// IMSI detach.
    Imsi = 3,
}

impl NetworkDetachKind {
    /// Decode bits 3-1; other values are interpreted as "re-attach not
    /// required" by the UE.
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::ReattachNotRequired)
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::ReattachRequired),
            2 => Some(Self::ReattachNotRequired),
            3 => Some(Self::Imsi),
            _ => None,
        }
    }
}

impl NasDetachType {
    /// Build a UE-originating detach type.
    pub fn from_ue_detach_kind(value: UeDetachKind, switch_off: bool) -> Self {
        Self::new(value as u8 | ((switch_off as u8) << 3))
    }

    /// Build a network-originating detach type; bit 4 is spare.
    pub fn from_network_detach_kind(value: NetworkDetachKind) -> Self {
        Self::new(value as u8)
    }

    /// Type of detach sent by the UE, with the network receive fallback.
    pub fn ue_detach_kind(&self) -> UeDetachKind {
        UeDetachKind::from_u8(self.value)
    }

    /// Type of detach sent by the network, with the UE receive fallback.
    pub fn network_detach_kind(&self) -> NetworkDetachKind {
        NetworkDetachKind::from_u8(self.value)
    }

    /// Raw type of detach (bits 3-1).
    pub fn detach_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Switch off (bit 4); meaningful only from the UE, since the bit is
    /// spare from the network.
    pub fn is_switch_off(&self) -> bool {
        self.value & 0x08 != 0
    }
}

/// Tracking area identity: PLMN and two-octet TAC (TS 24.301 §9.9.3.32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tai {
    /// PLMN identity.
    pub plmn: PlmnId,
    /// Tracking area code.
    pub tac: u16,
}

impl Tai {
    /// Parse a five-octet TAI.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        if value.len() != 5 {
            return None;
        }
        Some(Self {
            plmn: PlmnId::from_tbcd(&value[..3])?,
            tac: u16::from_be_bytes([value[3], value[4]]),
        })
    }

    /// Encode the five TAI octets.
    pub fn to_bytes(self) -> [u8; 5] {
        let mut value = [0u8; 5];
        value[..3].copy_from_slice(&self.plmn.to_tbcd());
        value[3..].copy_from_slice(&self.tac.to_be_bytes());
        value
    }
}

impl NasLastVisitedRegisteredTai {
    /// Build from a typed TAI.
    pub fn from_tai(tai: Tai) -> Self {
        Self::new(tai.to_bytes().to_vec())
    }

    /// Typed TAI; `None` if the value is not a TAI.
    pub fn tai(&self) -> Option<Tai> {
        Tai::from_bytes(&self.value)
    }
}

/// TAI list entries, including all three partial-list formats of §9.9.3.33.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TaiList(pub Vec<Tai>);

impl TaiList {
    /// Parse every partial list and expand consecutive TAC ranges. The
    /// spare bit is ignored, a count above 16 is read as 16, and after 16
    /// TAIs the rest of the value is ignored (Table 9.9.3.33.1).
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        Self::parse(value, false)
    }

    /// Parse only a value a sender may produce: spare bits clear, counts of
    /// at most 16, at most 16 TAIs, and no trailing octets.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
        Self::parse(value, true)
    }

    fn parse(value: &[u8], strict: bool) -> Option<Self> {
        let mut result = Vec::new();
        let mut offset = 0;
        while offset < value.len() {
            if result.len() >= 16 {
                if strict {
                    return None;
                }
                break;
            }
            let header = value[offset];
            if strict && (header & 0x80 != 0 || header & 0x1f > 15) {
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
                        for tac_bytes in part[3..].as_chunks::<2>().0 {
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
                    for tai in part.as_chunks::<5>().0 {
                        result.push(Tai::from_bytes(tai)?);
                    }
                    offset += size;
                }
                _ => return None,
            }
        }
        if result.len() > 16 {
            if strict {
                return None;
            }
            result.truncate(16);
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

            /// Decode the TAIs under the receiver rules.
            pub fn tai_list(&self) -> Option<TaiList> {
                TaiList::from_bytes(&self.value)
            }

            /// Sender check (see [`TaiList::from_bytes_strict`]).
            pub fn is_well_formed(&self) -> bool {
                TaiList::from_bytes_strict(&self.value).is_some()
            }
        }
    };
}
tai_list_ie!(NasTaiList);
tai_list_ie!(NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming);
tai_list_ie!(NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService);

/// PDN address variants from TS 24.301 table 9.9.4.9.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PdnAddress {
    /// IPv4 address; 0.0.0.0 when the address is obtained by DHCPv4.
    Ipv4([u8; 4]),
    /// IPv6 interface identifier.
    Ipv6InterfaceId([u8; 8]),
    /// IPv6 interface identifier and IPv4 address.
    Ipv4v6 {
        /// IPv6 interface identifier.
        ipv6_interface_id: [u8; 8],
        /// IPv4 address.
        ipv4: [u8; 4],
    },
    /// Non-IP; the four address octets are spare.
    NonIp,
    /// Ethernet; the four address octets are spare.
    Ethernet,
}

impl PdnAddress {
    /// Parse a received value: spare bits, spare address octets, and
    /// octets beyond the address are ignored (TS 24.007 §11.1.4, §11.4.2).
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let (&kind, data) = value.split_first()?;
        let octets = |length: usize| data.get(..length);
        match kind & 0x07 {
            1 => Some(Self::Ipv4(octets(4)?.try_into().ok()?)),
            2 => Some(Self::Ipv6InterfaceId(octets(8)?.try_into().ok()?)),
            3 => Some(Self::Ipv4v6 {
                ipv6_interface_id: octets(8)?.try_into().ok()?,
                ipv4: data.get(8..12)?.try_into().ok()?,
            }),
            5 => octets(4).map(|_| Self::NonIp),
            6 => octets(4).map(|_| Self::Ethernet),
            _ => None,
        }
    }

    /// Parse only an exactly sized value with spare bits and octets clear.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
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

    /// Encode the PDN type octet and address information.
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
    /// Build from a typed address.
    pub fn from_pdn_address(address: PdnAddress) -> Self {
        Self::new(address.to_bytes())
    }

    /// Typed address under the receiver rules of [`PdnAddress::from_bytes`].
    pub fn pdn_address(&self) -> Option<PdnAddress> {
        PdnAddress::from_bytes(&self.value)
    }

    /// Raw PDN type (octet 3, bits 3-1).
    pub fn pdn_type_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x07)
    }

    /// IPv4 address of an IPv4 or IPv4v6 PDN address.
    pub fn ipv4(&self) -> Option<[u8; 4]> {
        match self.pdn_address()? {
            PdnAddress::Ipv4(ipv4) | PdnAddress::Ipv4v6 { ipv4, .. } => Some(ipv4),
            _ => None,
        }
    }

    /// IPv6 interface identifier of an IPv6 or IPv4v6 PDN address.
    pub fn ipv6_interface_id(&self) -> Option<[u8; 8]> {
        match self.pdn_address()? {
            PdnAddress::Ipv6InterfaceId(id)
            | PdnAddress::Ipv4v6 {
                ipv6_interface_id: id,
                ..
            } => Some(id),
            _ => None,
        }
    }

    /// Whether the IPv4 address is 0.0.0.0, meaning it is obtained by DHCPv4.
    pub fn uses_dhcpv4(&self) -> bool {
        self.ipv4() == Some([0; 4])
    }

    /// Sender check: an exactly sized value with spare bits and octets clear.
    pub fn is_well_formed(&self) -> bool {
        PdnAddress::from_bytes_strict(&self.value).is_some()
    }
}

/// APN aggregate maximum bit rates (§9.9.4.2), in coded octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApnAmbr {
    /// APN-AMBR for downlink (octet 3).
    pub downlink: u8,
    /// APN-AMBR for uplink (octet 4).
    pub uplink: u8,
    /// Downlink and uplink extended octets 5 and 6.
    pub extension: Option<[u8; 2]>,
    /// Downlink and uplink extended-2 octets 7 and 8.
    pub extension2: Option<[u8; 2]>,
}

/// Decoded APN-AMBR bit rates in kbps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ApnAmbrValue {
    /// Downlink APN-AMBR in kbps.
    pub dl_kbps: u64,
    /// Uplink APN-AMBR in kbps.
    pub ul_kbps: u64,
}

fn apn_ambr_kbps(base: u8, extended: Option<u8>, extended2: Option<u8>) -> Option<u64> {
    use crate::common::ts24301::{eps_bit_rate_kbps, eps_extended_bit_rate_kbps};
    let low = match extended.and_then(eps_extended_bit_rate_kbps) {
        Some(kbps) => kbps,
        None => eps_bit_rate_kbps(base)?,
    };
    // Extended-2 value 11111111 is interpreted as 00000000.
    Some(match extended2 {
        Some(high @ 1..=0xfe) => u64::from(high) * 256_000 + low,
        _ => low,
    })
}

/// Octets 3, 5, and 7 of one APN-AMBR direction. Above 8640 kbps octet 3
/// is 11111110, so an extended-2 rate adds 8640 kbps (octet 5 unused) or an
/// octet 5 rate to its multiple of 256 Mbps (Table 9.9.4.2.1).
fn apn_ambr_octets(kbps: u64) -> Option<(u8, u8, u8)> {
    use crate::common::ts24301::{eps_bit_rate_octets, eps_extended_bit_rate_octet};
    if let Some((base, extended)) = eps_bit_rate_octets(kbps) {
        return Some((base, extended, 0));
    }
    (1..=0xfe_u8).find_map(|high| {
        let low = kbps.checked_sub(u64::from(high) * 256_000)?;
        let extended = if low == 8_640 {
            0
        } else {
            eps_extended_bit_rate_octet(low)?
        };
        Some((0xfe, extended, high))
    })
}

impl ApnAmbr {
    /// Parse the coded octets as a receiver: pairs beyond the defined three
    /// and an unpaired trailing octet are ignored; a reserved 0 base octet
    /// makes the value invalid unless the extended octet replaces it.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let [downlink, uplink] = *value.get(..2)? else {
            return None;
        };
        let pair =
            |start: usize| -> Option<[u8; 2]> { value.get(start..start + 2)?.try_into().ok() };
        let extension = pair(2);
        let reserved =
            |base: u8, index: usize| base == 0 && extension.is_none_or(|octets| octets[index] == 0);
        if reserved(downlink, 0) || reserved(uplink, 1) {
            return None;
        }
        Some(Self {
            downlink,
            uplink,
            extension,
            extension2: extension.and(pair(4)),
        })
    }

    /// Parse the coded octets as a sender must encode them: 2, 4, or 6 octets.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
        matches!(value.len(), 2 | 4 | 6).then(|| Self::from_bytes(value))?
    }

    /// Encode the coded octets.
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

    /// Downlink APN-AMBR in kbps (Table 9.9.4.2.1).
    pub fn downlink_kbps(self) -> Option<u64> {
        apn_ambr_kbps(
            self.downlink,
            self.extension.map(|octets| octets[0]),
            self.extension2.map(|octets| octets[0]),
        )
    }

    /// Uplink APN-AMBR in kbps (Table 9.9.4.2.1).
    pub fn uplink_kbps(self) -> Option<u64> {
        apn_ambr_kbps(
            self.uplink,
            self.extension.map(|octets| octets[1]),
            self.extension2.map(|octets| octets[1]),
        )
    }

    /// Shortest exact encoding of rates up to 65280 Mbps.
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> Option<Self> {
        let (dl, dl_extended, dl_extended2) = apn_ambr_octets(dl_kbps)?;
        let (ul, ul_extended, ul_extended2) = apn_ambr_octets(ul_kbps)?;
        let extended2 = dl_extended2 != 0 || ul_extended2 != 0;
        let extended = extended2 || dl_extended != 0 || ul_extended != 0;
        Some(Self {
            downlink: dl,
            uplink: ul,
            extension: extended.then_some([dl_extended, ul_extended]),
            extension2: extended2.then_some([dl_extended2, ul_extended2]),
        })
    }
}

impl NasApnAmbr {
    /// Build from coded octets.
    pub fn from_ambr(ambr: ApnAmbr) -> Option<Self> {
        Some(Self::new(ambr.to_bytes()?))
    }

    /// Coded octets as a receiver reads them.
    pub fn ambr(&self) -> Option<ApnAmbr> {
        ApnAmbr::from_bytes(&self.value)
    }

    /// Downlink and uplink rates in kbps.
    pub fn parse(&self) -> Option<ApnAmbrValue> {
        let ambr = self.ambr()?;
        Some(ApnAmbrValue {
            dl_kbps: ambr.downlink_kbps()?,
            ul_kbps: ambr.uplink_kbps()?,
        })
    }

    /// Downlink rate in kbps.
    pub fn downlink_kbps(&self) -> Option<u64> {
        self.ambr()?.downlink_kbps()
    }

    /// Uplink rate in kbps.
    pub fn uplink_kbps(&self) -> Option<u64> {
        self.ambr()?.uplink_kbps()
    }

    /// Shortest exact encoding of rates up to 65280 Mbps.
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> Option<Self> {
        Self::from_ambr(ApnAmbr::from_kbps(dl_kbps, ul_kbps)?)
    }

    /// Rates combined with the extended APN-AMBR IE: an extended rate
    /// replaces this IE's rate only when it exceeds 65280 Mbps (§9.9.4.29).
    pub fn effective_kbps(&self, extended: Option<&NasExtendedApnAmbr>) -> Option<ApnAmbrValue> {
        let mut value = self.parse()?;
        if let Some(extended) = extended.and_then(NasExtendedApnAmbr::ambr) {
            let limit = 65_280_000;
            if let Some(dl) = extended.downlink_kbps().filter(|&kbps| kbps > limit) {
                value.dl_kbps = dl;
            }
            if let Some(ul) = extended.uplink_kbps().filter(|&kbps| kbps > limit) {
                value.ul_kbps = ul;
            }
        }
        Some(value)
    }

    /// Sender check (§9.9.4.2): 2, 4, or 6 octets; octet 3 or 4 is 11111110
    /// when its extended or extended-2 octet is used, and those octets hold
    /// defined values.
    pub fn is_well_formed(&self) -> bool {
        let Some(ambr) = ApnAmbr::from_bytes_strict(&self.value) else {
            return false;
        };
        let [extension, extension2] =
            [ambr.extension, ambr.extension2].map(Option::unwrap_or_default);
        [ambr.downlink, ambr.uplink]
            .into_iter()
            .enumerate()
            .all(|(index, base)| {
                base != 0
                    && extension[index] <= 0xfa
                    && extension2[index] <= 0xfe
                    && (extension[index] == 0 && extension2[index] == 0 || base == 0xfe)
            })
    }
}

/// Extended APN aggregate maximum bit rate (§9.9.4.29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedApnAmbr {
    /// Unit of the downlink value (octet 3).
    pub dl_unit: u8,
    /// Downlink value (octets 4-5).
    pub dl_value: u16,
    /// Unit of the uplink value (octet 6).
    pub ul_unit: u8,
    /// Uplink value (octets 7-8).
    pub ul_value: u16,
}

impl ExtendedApnAmbr {
    /// Parse the first six value octets; extra octets are ignored.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let value = value.get(..6)?;
        Some(Self {
            dl_unit: value[0],
            dl_value: u16::from_be_bytes([value[1], value[2]]),
            ul_unit: value[3],
            ul_value: u16::from_be_bytes([value[4], value[5]]),
        })
    }

    /// Encode the six value octets.
    pub fn to_bytes(self) -> [u8; 6] {
        let [dl_high, dl_low] = self.dl_value.to_be_bytes();
        let [ul_high, ul_low] = self.ul_value.to_be_bytes();
        [self.dl_unit, dl_high, dl_low, self.ul_unit, ul_high, ul_low]
    }

    /// Downlink rate in kbps; unused units 0 to 2 are read as 4 Mbps.
    pub fn downlink_kbps(self) -> Option<u64> {
        u64::from(self.dl_value).checked_mul(crate::common::ts24301::extended_apn_ambr_unit_kbps(
            self.dl_unit,
        ))
    }

    /// Uplink rate in kbps; unused units 0 to 2 are read as 4 Mbps.
    pub fn uplink_kbps(self) -> Option<u64> {
        u64::from(self.ul_value).checked_mul(crate::common::ts24301::extended_apn_ambr_unit_kbps(
            self.ul_unit,
        ))
    }

    /// Smallest exact encoding using units 4 Mbps (3) to 256 Pbps (0x15).
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> Option<Self> {
        use crate::common::ts24301::{eps_extended_unit_value, extended_apn_ambr_unit_kbps};
        let (dl_unit, dl_value) =
            eps_extended_unit_value(dl_kbps, 3..=0x15, extended_apn_ambr_unit_kbps)?;
        let (ul_unit, ul_value) =
            eps_extended_unit_value(ul_kbps, 3..=0x15, extended_apn_ambr_unit_kbps)?;
        Some(Self {
            dl_unit,
            dl_value,
            ul_unit,
            ul_value,
        })
    }
}

impl NasExtendedApnAmbr {
    /// Typed value.
    pub fn ambr(&self) -> Option<ExtendedApnAmbr> {
        ExtendedApnAmbr::from_bytes(&self.value)
    }

    /// Build from a typed value.
    pub fn from_ambr(ambr: ExtendedApnAmbr) -> Self {
        Self::new(ambr.to_bytes().to_vec())
    }

    /// Downlink rate in kbps.
    pub fn downlink_kbps(&self) -> Option<u64> {
        self.ambr()?.downlink_kbps()
    }

    /// Uplink rate in kbps.
    pub fn uplink_kbps(&self) -> Option<u64> {
        self.ambr()?.uplink_kbps()
    }

    /// Smallest exact encoding of both rates.
    pub fn from_kbps(dl_kbps: u64, ul_kbps: u64) -> Option<Self> {
        Some(Self::from_ambr(ExtendedApnAmbr::from_kbps(
            dl_kbps, ul_kbps,
        )?))
    }

    /// Sender check: six octets using defined units (3 or above).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.ambr(), Some(ambr) if self.value.len() == 6 && ambr.dl_unit >= 3 && ambr.ul_unit >= 3)
    }
}

/// An EPS QoS bit rate (Table 9.9.4.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EpsBitRate {
    /// A bit rate in kbps.
    Kbps(u64),
    /// Base octet 0: the subscribed rate from the UE, reserved from the network.
    SubscribedOrReserved,
}

/// EPS QoS coded octets, with optional four-octet bit-rate groups (§9.9.4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EpsQos {
    /// QoS class identifier (octet 3).
    pub qci: u8,
    /// UL-MBR, DL-MBR, UL-GBR, DL-GBR in wire order.
    pub bit_rates: Option<[u8; 4]>,
    /// Extended bit rates in the same order.
    pub extension: Option<[u8; 4]>,
    /// Extended-2 bit rates in the same order.
    pub extension2: Option<[u8; 4]>,
}

impl EpsQos {
    /// Whether the QCI is assigned or operator-specific for a network-to-UE IE.
    ///
    /// TS 24.301 §9.9.4.3 reserves the gaps between the assigned values.
    pub fn qci_is_network_valid(&self) -> bool {
        matches!(self.qci, 1..=10 | 65..=67 | 69..=76 | 79..=80 | 82..=85 | 128..=254)
    }

    /// Whether the QCI is a standardized GBR QCI (TS 23.203 Table 6.1.7).
    pub fn is_gbr(&self) -> bool {
        matches!(self.qci, 1..=4 | 65..=67 | 71..=76 | 82..=85)
    }

    /// Parse as a receiver: groups beyond the third and a trailing partial
    /// group are ignored.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let (&qci, rest) = value.split_first()?;
        let group = |index: usize| -> Option<[u8; 4]> {
            rest.get(index * 4..index * 4 + 4)?.try_into().ok()
        };
        let bit_rates = group(0);
        let extension = bit_rates.and(group(1));
        Some(Self {
            qci,
            bit_rates,
            extension,
            extension2: extension.and(group(2)),
        })
    }

    /// Parse the octet lengths a sender may use: 1, 5, 9, or 13.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
        matches!(value.len(), 1 | 5 | 9 | 13).then(|| Self::from_bytes(value))?
    }

    /// Encode the coded octets.
    pub fn to_bytes(self) -> Option<Vec<u8>> {
        if self.extension.is_some() && self.bit_rates.is_none()
            || self.extension2.is_some() && self.extension.is_none()
        {
            return None;
        }
        let mut value = vec![self.qci];
        for group in [self.bit_rates, self.extension, self.extension2]
            .into_iter()
            .flatten()
        {
            value.extend_from_slice(&group);
        }
        Some(value)
    }

    fn bit_rate(&self, index: usize) -> Option<EpsBitRate> {
        use crate::common::ts24301::{
            eps_bit_rate_kbps, eps_extended_bit_rate_kbps, eps_qos_extended2_bit_rate_kbps,
        };
        let base = self.bit_rates?[index];
        if let Some(kbps) = self
            .extension2
            .and_then(|group| eps_qos_extended2_bit_rate_kbps(group[index]))
        {
            return Some(EpsBitRate::Kbps(kbps));
        }
        if let Some(kbps) = self
            .extension
            .and_then(|group| eps_extended_bit_rate_kbps(group[index]))
        {
            return Some(EpsBitRate::Kbps(kbps));
        }
        Some(eps_bit_rate_kbps(base).map_or(EpsBitRate::SubscribedOrReserved, EpsBitRate::Kbps))
    }

    /// Maximum bit rate for uplink, if the bit rate group is present.
    pub fn mbr_ul(&self) -> Option<EpsBitRate> {
        self.bit_rate(0)
    }

    /// Maximum bit rate for downlink, if the bit rate group is present.
    pub fn mbr_dl(&self) -> Option<EpsBitRate> {
        self.bit_rate(1)
    }

    /// Guaranteed bit rate for uplink, if the bit rate group is present.
    pub fn gbr_ul(&self) -> Option<EpsBitRate> {
        self.bit_rate(2)
    }

    /// Guaranteed bit rate for downlink, if the bit rate group is present.
    pub fn gbr_dl(&self) -> Option<EpsBitRate> {
        self.bit_rate(3)
    }

    /// Shortest exact encoding of a QCI and four rates up to 10 Gbps, in the
    /// order UL-MBR, DL-MBR, UL-GBR, DL-GBR.
    pub fn from_kbps(qci: u8, rates: [u64; 4]) -> Option<Self> {
        use crate::common::ts24301::{eps_bit_rate_octets, eps_qos_extended2_bit_rate_octet};
        let mut base = [0; 4];
        let mut extended = [0; 4];
        let mut extended2 = [0; 4];
        for (index, &kbps) in rates.iter().enumerate() {
            if let Some((low, high)) = eps_bit_rate_octets(kbps) {
                (base[index], extended[index]) = (low, high);
            } else {
                extended2[index] = eps_qos_extended2_bit_rate_octet(kbps)?;
                (base[index], extended[index]) = (0xfe, 0xfa);
            }
        }
        let has_extended2 = extended2.iter().any(|&octet| octet != 0);
        let has_extended = has_extended2 || extended.iter().any(|&octet| octet != 0);
        Some(Self {
            qci,
            bit_rates: Some(base),
            extension: has_extended.then_some(extended),
            extension2: has_extended2.then_some(extended2),
        })
    }
}

macro_rules! eps_qos_ie {
    ($name:ident) => {
        impl $name {
            /// Build from coded octets.
            pub fn from_qos(qos: EpsQos) -> Option<Self> {
                Some(Self::new(qos.to_bytes()?))
            }

            /// Coded octets as a receiver reads them.
            pub fn qos(&self) -> Option<EpsQos> {
                EpsQos::from_bytes(&self.value)
            }

            /// Sender check (§9.9.4.3): 1, 5, 9, or 13 octets; a bit rate
            /// octet is 11111110 when its extended octet is used, an extended
            /// octet is 11111010 when its extended-2 octet is used, and those
            /// octets hold defined values.
            pub fn is_well_formed(&self) -> bool {
                let Some(qos) = EpsQos::from_bytes_strict(&self.value) else {
                    return false;
                };
                let [base, extension, extension2] =
                    [qos.bit_rates, qos.extension, qos.extension2].map(Option::unwrap_or_default);
                (0..4).all(|index| {
                    extension[index] <= 0xfa
                        && extension2[index] <= 0xf6
                        && (extension[index] == 0 || base[index] == 0xfe)
                        && (extension2[index] == 0 || extension[index] == 0xfa)
                })
            }

            /// Whether both maximum bit rates are 0 kbps, which a sender shall
            /// not request and a receiver treats as a syntactical error
            /// (§9.9.4.3).
            pub fn has_zero_maximum_bit_rates(&self) -> bool {
                self.qos().is_some_and(|qos| {
                    qos.mbr_ul() == Some(EpsBitRate::Kbps(0))
                        && qos.mbr_dl() == Some(EpsBitRate::Kbps(0))
                })
            }
        }
    };
}

eps_qos_ie!(NasEpsQos);
eps_qos_ie!(NasNewEpsQos);
eps_qos_ie!(NasRequiredTrafficFlowQos);

/// Quality of service of TS 24.008 §10.5.6.5, carried as Negotiated QoS and
/// New QoS (TS 24.301 §9.9.4.12). Value octet `n` is IE octet `n + 3`.
macro_rules! gprs_qos_ie {
    ($name:ident) => {
        impl $name {
            fn octet(&self, ie_octet: usize) -> Option<u8> {
                self.value.get(ie_octet - 3).copied()
            }

            /// Delay class with the receiver rule: 5 and 6 are read as class 4
            /// (best effort); 0 (subscribed or reserved) and 7 (reserved) are `None`.
            pub fn delay_class(&self) -> Option<u8> {
                match (self.octet(3)? >> 3) & 0x07 {
                    class @ 1..=4 => Some(class),
                    5 | 6 => Some(4),
                    _ => None,
                }
            }

            /// Reliability class with the receiver rule: 1 is read as 2, and
            /// 6 as 3; 0 and 7 are `None`.
            pub fn reliability_class(&self) -> Option<u8> {
                match self.octet(3)? & 0x07 {
                    1 => Some(2),
                    class @ 2..=5 => Some(class),
                    6 => Some(3),
                    _ => None,
                }
            }

            /// Peak throughput class with the receiver rule: undefined codes
            /// are read as 1 (up to 1000 octet/s); 0 and 15 are `None`.
            pub fn peak_throughput(&self) -> Option<u8> {
                match self.octet(4)? >> 4 {
                    class @ 1..=9 => Some(class),
                    10..=14 => Some(1),
                    _ => None,
                }
            }

            /// Precedence class with the receiver rule: 4 to 6 are read as 2
            /// (normal priority); 0 and 7 are `None`.
            pub fn precedence_class(&self) -> Option<u8> {
                match self.octet(4)? & 0x07 {
                    class @ 1..=3 => Some(class),
                    4..=6 => Some(2),
                    _ => None,
                }
            }

            /// Mean throughput class with the receiver rule: undefined codes
            /// are read as 31 (best effort); 0 and 30 are `None`.
            pub fn mean_throughput(&self) -> Option<u8> {
                match self.octet(5)? & 0x1f {
                    class @ (1..=18 | 31) => Some(class),
                    19..=29 => Some(31),
                    _ => None,
                }
            }

            /// Traffic class (octet 6, bits 8-6).
            pub fn traffic_class_raw(&self) -> Option<u8> {
                self.octet(6).map(|octet| octet >> 5)
            }

            /// Delivery order (octet 6, bits 5-4).
            pub fn delivery_order_raw(&self) -> Option<u8> {
                self.octet(6).map(|octet| (octet >> 3) & 0x03)
            }

            /// Delivery of erroneous SDUs (octet 6, bits 3-1).
            pub fn delivery_of_erroneous_sdu_raw(&self) -> Option<u8> {
                self.octet(6).map(|octet| octet & 0x07)
            }

            /// Maximum SDU size code (octet 7).
            pub fn maximum_sdu_size_raw(&self) -> Option<u8> {
                self.octet(7)
            }

            /// Residual BER (octet 10, bits 8-5).
            pub fn residual_ber_raw(&self) -> Option<u8> {
                self.octet(10).map(|octet| octet >> 4)
            }

            /// SDU error ratio (octet 10, bits 4-1).
            pub fn sdu_error_ratio_raw(&self) -> Option<u8> {
                self.octet(10).map(|octet| octet & 0x0f)
            }

            /// Transfer delay code (octet 11, bits 8-3).
            pub fn transfer_delay_raw(&self) -> Option<u8> {
                self.octet(11).map(|octet| octet >> 2)
            }

            /// Traffic handling priority (octet 11, bits 2-1).
            pub fn traffic_handling_priority_raw(&self) -> Option<u8> {
                self.octet(11).map(|octet| octet & 0x03)
            }

            /// Signalling indication (octet 14, bit 5).
            pub fn signalling_indication(&self) -> Option<bool> {
                self.octet(14).map(|octet| octet & 0x10 != 0)
            }

            /// Source statistics descriptor (octet 14, bits 4-1).
            pub fn source_statistics_descriptor_raw(&self) -> Option<u8> {
                self.octet(14).map(|octet| octet & 0x0f)
            }

            fn bit_rate_kbps(
                &self,
                base: usize,
                extended: usize,
                extended2: usize,
            ) -> Option<EpsBitRate> {
                use crate::common::ts24301::{
                    eps_bit_rate_kbps, eps_extended_bit_rate_kbps, eps_qos_extended2_bit_rate_kbps,
                };
                let octet = self.octet(base)?;
                if let Some(kbps) = self
                    .octet(extended2)
                    .and_then(eps_qos_extended2_bit_rate_kbps)
                {
                    return Some(EpsBitRate::Kbps(kbps));
                }
                if let Some(kbps) = self.octet(extended).and_then(eps_extended_bit_rate_kbps) {
                    return Some(EpsBitRate::Kbps(kbps));
                }
                Some(
                    eps_bit_rate_kbps(octet)
                        .map_or(EpsBitRate::SubscribedOrReserved, EpsBitRate::Kbps),
                )
            }

            /// Maximum bit rate for uplink (octets 8, 17, 21).
            pub fn mbr_ul(&self) -> Option<EpsBitRate> {
                self.bit_rate_kbps(8, 17, 21)
            }

            /// Maximum bit rate for downlink (octets 9, 15, 19).
            pub fn mbr_dl(&self) -> Option<EpsBitRate> {
                self.bit_rate_kbps(9, 15, 19)
            }

            /// Guaranteed bit rate for uplink (octets 12, 18, 22).
            pub fn gbr_ul(&self) -> Option<EpsBitRate> {
                self.bit_rate_kbps(12, 18, 22)
            }

            /// Guaranteed bit rate for downlink (octets 13, 16, 20).
            pub fn gbr_dl(&self) -> Option<EpsBitRate> {
                self.bit_rate_kbps(13, 16, 20)
            }

            /// Receiver framing accepted by TS 24.008 §10.5.6.5.
            ///
            /// The three- and eleven-octet legacy values omit octets 6-22 or
            /// 14-22 respectively. Modern values add each extension pair as a
            /// unit. Field-code fallbacks are exposed by the typed getters and
            /// are deliberately not sender validation.
            pub fn receiver_syntax_is_valid(&self) -> bool {
                matches!(self.value.len(), 3 | 11 | 12 | 14 | 16 | 18 | 20)
            }

            /// Sender check: 12 to 20 value octets in the specified pairs,
            /// with every network-assigned field using a defined code.  The
            /// extension dependency rules are from TS 24.008 table 10.5.156.
            pub fn is_well_formed(&self) -> bool {
                if !matches!(self.value.len(), 12 | 14 | 16 | 18 | 20) {
                    return false;
                }

                let value = &self.value;
                let mandatory_fields_are_defined = value[0] & 0xc0 == 0
                    && matches!((value[0] >> 3) & 0x07, 1..=4)
                    && matches!(value[0] & 0x07, 2..=5)
                    && matches!(value[1] >> 4, 1..=9)
                    && value[1] & 0x08 == 0
                    && matches!(value[1] & 0x07, 1..=3)
                    && value[2] & 0xe0 == 0
                    && matches!(value[2] & 0x1f, 1..=18 | 31)
                    && matches!(value[3] >> 5, 1..=4)
                    && matches!((value[3] >> 3) & 0x03, 1..=2)
                    && matches!(value[3] & 0x07, 1..=3)
                    && matches!(value[4], 1..=0x99)
                    && value[5] != 0
                    && value[6] != 0
                    && matches!(value[7] >> 4, 1..=9)
                    && matches!(value[7] & 0x0f, 1..=7)
                    && matches!(value[8] >> 2, 1..=62)
                    && matches!(value[8] & 0x03, 1..=3)
                    && value[9] != 0
                    && value[10] != 0
                    && value[11] & !0x10 == 0;
                if !mandatory_fields_are_defined {
                    return false;
                }

                let extension_is_defined = |index: usize, base: usize| {
                    value[index] <= 0xfa && (value[index] == 0 || value[base] == 0xfe)
                };
                let extension2_is_defined = |index: usize, extension: usize| {
                    value[index] <= 0xf6 && (value[index] == 0 || value[extension] == 0xfa)
                };

                (value.len() < 14 || (extension_is_defined(12, 6) && extension_is_defined(13, 10)))
                    && (value.len() < 16
                        || (extension_is_defined(14, 5) && extension_is_defined(15, 9)))
                    && (value.len() < 18
                        || (extension2_is_defined(16, 12) && extension2_is_defined(17, 13)))
                    && (value.len() < 20
                        || (extension2_is_defined(18, 14) && extension2_is_defined(19, 15)))
            }
        }
    };
}

gprs_qos_ie!(NasNegotiatedQos);
gprs_qos_ie!(NasNewQos);

/// Extended quality of service (§9.9.4.30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedEpsQos {
    /// Unit of the maximum bit rates (octet 3).
    pub mbr_unit: u8,
    /// Maximum bit rate for uplink (octets 4-5).
    pub mbr_ul: u16,
    /// Maximum bit rate for downlink (octets 6-7).
    pub mbr_dl: u16,
    /// Unit of the guaranteed bit rates (octet 8).
    pub gbr_unit: u8,
    /// Guaranteed bit rate for uplink (octets 9-10).
    pub gbr_ul: u16,
    /// Guaranteed bit rate for downlink (octets 11-12).
    pub gbr_dl: u16,
}

impl ExtendedEpsQos {
    /// Parse the first ten value octets; extra octets are ignored.
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        let value = value.get(..10)?;
        let word = |index: usize| u16::from_be_bytes([value[index], value[index + 1]]);
        Some(Self {
            mbr_unit: value[0],
            mbr_ul: word(1),
            mbr_dl: word(3),
            gbr_unit: value[5],
            gbr_ul: word(6),
            gbr_dl: word(8),
        })
    }

    /// Encode the ten value octets.
    pub fn to_bytes(self) -> [u8; 10] {
        let mut value = [0; 10];
        value[0] = self.mbr_unit;
        value[1..3].copy_from_slice(&self.mbr_ul.to_be_bytes());
        value[3..5].copy_from_slice(&self.mbr_dl.to_be_bytes());
        value[5] = self.gbr_unit;
        value[6..8].copy_from_slice(&self.gbr_ul.to_be_bytes());
        value[8..10].copy_from_slice(&self.gbr_dl.to_be_bytes());
        value
    }

    fn rate(unit: u8, value: u16) -> Option<u64> {
        // A receiver ignores rates of 10 Gbps or less, including the zero filler.
        u64::from(value)
            .checked_mul(crate::common::ts24301::extended_qos_unit_kbps(unit))
            .filter(|&kbps| kbps > 10_000_000)
    }

    /// Maximum bit rate for uplink above 10 Gbps, in kbps.
    pub fn mbr_ul_kbps(self) -> Option<u64> {
        Self::rate(self.mbr_unit, self.mbr_ul)
    }

    /// Maximum bit rate for downlink above 10 Gbps, in kbps.
    pub fn mbr_dl_kbps(self) -> Option<u64> {
        Self::rate(self.mbr_unit, self.mbr_dl)
    }

    /// Guaranteed bit rate for uplink above 10 Gbps, in kbps.
    pub fn gbr_ul_kbps(self) -> Option<u64> {
        Self::rate(self.gbr_unit, self.gbr_ul)
    }

    /// Guaranteed bit rate for downlink above 10 Gbps, in kbps.
    pub fn gbr_dl_kbps(self) -> Option<u64> {
        Self::rate(self.gbr_unit, self.gbr_dl)
    }

    /// Encode rates in kbps; a rate of 10 Gbps or less is sent as 0 because
    /// the EPS QoS IE carries it. Each pair shares the smallest common unit.
    pub fn from_kbps(mbr_ul: u64, mbr_dl: u64, gbr_ul: u64, gbr_dl: u64) -> Option<Self> {
        use crate::common::ts24301::extended_qos_unit_kbps;
        let pair = |uplink: u64, downlink: u64| -> Option<(u8, u16, u16)> {
            let keep = |kbps: u64| if kbps > 10_000_000 { kbps } else { 0 };
            let (uplink, downlink) = (keep(uplink), keep(downlink));
            (1..=0x15u8).find_map(|unit| {
                let step = extended_qos_unit_kbps(unit);
                let fits =
                    |kbps: u64| kbps.is_multiple_of(step) && kbps / step <= u64::from(u16::MAX);
                (fits(uplink) && fits(downlink))
                    .then(|| (unit, (uplink / step) as u16, (downlink / step) as u16))
            })
        };
        let (mbr_unit, mbr_ul, mbr_dl) = pair(mbr_ul, mbr_dl)?;
        let (gbr_unit, gbr_ul, gbr_dl) = pair(gbr_ul, gbr_dl)?;
        Some(Self {
            mbr_unit,
            mbr_ul,
            mbr_dl,
            gbr_unit,
            gbr_ul,
            gbr_dl,
        })
    }
}

impl NasExtendedEpsQos {
    /// Typed value.
    pub fn qos(&self) -> Option<ExtendedEpsQos> {
        ExtendedEpsQos::from_bytes(&self.value)
    }

    /// Build from a typed value.
    pub fn from_qos(qos: ExtendedEpsQos) -> Self {
        Self::new(qos.to_bytes().to_vec())
    }

    /// Sender check: ten octets using defined units (1 or above).
    pub fn is_well_formed(&self) -> bool {
        matches!(self.qos(), Some(qos) if self.value.len() == 10 && qos.mbr_unit >= 1 && qos.gbr_unit >= 1)
    }
}

crate::common::ts24301::ue_network_capability_ie!(NasUeNetworkCapability);
crate::common::ts24301::ue_security_capability_ie!(
    NasReplayedUeSecurityCapabilities,
    NasUeNetworkCapability
);

/// Traffic flow template operation from TS 24.008 §10.5.6.12.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum TftOperation {
    /// Ignore this IE (traffic flow aggregate only).
    Ignore = 0,
    /// Create new TFT.
    Create = 1,
    /// Delete existing TFT.
    Delete = 2,
    /// Add packet filters to existing TFT.
    AddFilters = 3,
    /// Replace packet filters in existing TFT.
    ReplaceFilters = 4,
    /// Delete packet filters from existing TFT.
    DeleteFilters = 5,
    /// No TFT operation.
    NoOperation = 6,
}

impl TftOperation {
    /// Decode bits 8-6 of octet 3; the reserved code 7 returns `None`.
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

/// Class of a TFT decoding error, as distinguished by TS 24.301
/// §6.4.2.4 and §6.4.3.4.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TftError {
    /// The TFT operation, the filter count, or the list coding is invalid
    /// (ESM cause #42).
    SyntacticalTftOperation,
    /// A packet filter is incorrectly coded (ESM cause #45).
    SyntacticalPacketFilter,
    /// The parameters list has consecutive Authorization Tokens without a
    /// Flow Identifier between them (TS 24.008 Table 10.5.162, ESM cause
    /// #41).
    SemanticTftOperation,
}

impl TftError {
    /// ESM cause the UE sends when rejecting the request.
    pub fn esm_cause(self) -> EsmCause {
        match self {
            Self::SyntacticalTftOperation => EsmCause::SyntacticalErrorInTheTftOperation,
            Self::SyntacticalPacketFilter => EsmCause::SyntacticalErrorsInPacketFilters,
            Self::SemanticTftOperation => EsmCause::SemanticErrorInTheTftOperation,
        }
    }
}

/// Direction of a TFT packet filter (octet 4 bits 6-5).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum TftPacketFilterDirection {
    /// Pre Rel-7 TFT filter.
    PreRel7 = 0,
    /// Downlink only.
    Downlink = 1,
    /// Uplink only.
    Uplink = 2,
    /// Bidirectional.
    Bidirectional = 3,
}

/// One packet filter component (TS 24.008 Table 10.5.162).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TftPacketFilterComponent {
    /// IPv4 remote address and mask (0x10).
    Ipv4RemoteAddress {
        /// IPv4 address.
        address: [u8; 4],
        /// Address mask.
        mask: [u8; 4],
    },
    /// IPv4 local address and mask (0x11).
    Ipv4LocalAddress {
        /// IPv4 address.
        address: [u8; 4],
        /// Address mask.
        mask: [u8; 4],
    },
    /// IPv6 remote address and mask (0x20).
    Ipv6RemoteAddress {
        /// IPv6 address.
        address: [u8; 16],
        /// Address mask.
        mask: [u8; 16],
    },
    /// IPv6 remote address and prefix length (0x21).
    Ipv6RemoteAddressPrefix {
        /// IPv6 address.
        address: [u8; 16],
        /// Prefix length.
        prefix_length: u8,
    },
    /// IPv6 local address and prefix length (0x23).
    Ipv6LocalAddressPrefix {
        /// IPv6 address.
        address: [u8; 16],
        /// Prefix length.
        prefix_length: u8,
    },
    /// IPv4 protocol identifier or IPv6 next header (0x30).
    ProtocolIdentifierNextHeader(u8),
    /// Single local port (0x40).
    SingleLocalPort(u16),
    /// Local port range (0x41).
    LocalPortRange {
        /// Low limit.
        low: u16,
        /// High limit.
        high: u16,
    },
    /// Single remote port (0x50).
    SingleRemotePort(u16),
    /// Remote port range (0x51).
    RemotePortRange {
        /// Low limit.
        low: u16,
        /// High limit.
        high: u16,
    },
    /// IPsec security parameter index (0x60).
    SecurityParameterIndex(u32),
    /// Type of service or traffic class, and mask (0x70).
    TypeOfServiceTrafficClass {
        /// Type of service or traffic class.
        value: u8,
        /// Mask.
        mask: u8,
    },
    /// 20-bit IPv6 flow label (0x80).
    FlowLabel(u32),
    /// Destination MAC address (0x81).
    DestinationMacAddress([u8; 6]),
    /// Source MAC address (0x82).
    SourceMacAddress([u8; 6]),
    /// 12-bit 802.1Q C-TAG VID (0x83).
    CTagVid(u16),
    /// 12-bit 802.1Q S-TAG VID (0x84).
    STagVid(u16),
    /// 802.1Q C-TAG PCP and DEI (0x85).
    CTagPcpDei {
        /// Priority code point.
        pcp: u8,
        /// Drop eligible indicator.
        dei: bool,
    },
    /// 802.1Q S-TAG PCP and DEI (0x86).
    STagPcpDei {
        /// Priority code point.
        pcp: u8,
        /// Drop eligible indicator.
        dei: bool,
    },
    /// Ethertype (0x87).
    Ethertype(u16),
}

/// Value length of a component type, or `None` for a reserved type.
fn tft_component_size(kind: u8) -> Option<usize> {
    Some(match kind {
        0x10 | 0x11 => 8,
        0x20 => 32,
        0x21 | 0x23 => 17,
        0x30 | 0x85 | 0x86 => 1,
        0x40 | 0x50 | 0x70 | 0x83 | 0x84 | 0x87 => 2,
        0x41 | 0x51 | 0x60 => 4,
        0x80 => 3,
        0x81 | 0x82 => 6,
        _ => return None,
    })
}

impl TftPacketFilterComponent {
    /// Decode one component value of type `kind`. Spare bits of the flow
    /// label, VID, and PCP/DEI components are ignored.
    fn decode(kind: u8, value: &[u8]) -> Option<Self> {
        let array = |range: std::ops::Range<usize>| value.get(range);
        let word = |index: usize| u16::from_be_bytes([value[index], value[index + 1]]);
        if value.len() != tft_component_size(kind)? {
            return None;
        }
        Some(match kind {
            0x10 => Self::Ipv4RemoteAddress {
                address: array(0..4)?.try_into().ok()?,
                mask: array(4..8)?.try_into().ok()?,
            },
            0x11 => Self::Ipv4LocalAddress {
                address: array(0..4)?.try_into().ok()?,
                mask: array(4..8)?.try_into().ok()?,
            },
            0x20 => Self::Ipv6RemoteAddress {
                address: array(0..16)?.try_into().ok()?,
                mask: array(16..32)?.try_into().ok()?,
            },
            0x21 => Self::Ipv6RemoteAddressPrefix {
                address: array(0..16)?.try_into().ok()?,
                prefix_length: value[16],
            },
            0x23 => Self::Ipv6LocalAddressPrefix {
                address: array(0..16)?.try_into().ok()?,
                prefix_length: value[16],
            },
            0x30 => Self::ProtocolIdentifierNextHeader(value[0]),
            0x40 => Self::SingleLocalPort(word(0)),
            0x41 => Self::LocalPortRange {
                low: word(0),
                high: word(2),
            },
            0x50 => Self::SingleRemotePort(word(0)),
            0x51 => Self::RemotePortRange {
                low: word(0),
                high: word(2),
            },
            0x60 => Self::SecurityParameterIndex(u32::from_be_bytes(array(0..4)?.try_into().ok()?)),
            0x70 => Self::TypeOfServiceTrafficClass {
                value: value[0],
                mask: value[1],
            },
            0x80 => Self::FlowLabel(u32::from_be_bytes([0, value[0] & 0x0f, value[1], value[2]])),
            0x81 => Self::DestinationMacAddress(array(0..6)?.try_into().ok()?),
            0x82 => Self::SourceMacAddress(array(0..6)?.try_into().ok()?),
            0x83 => Self::CTagVid(word(0) & 0x0fff),
            0x84 => Self::STagVid(word(0) & 0x0fff),
            0x85 => Self::CTagPcpDei {
                pcp: (value[0] >> 1) & 0x07,
                dei: value[0] & 1 != 0,
            },
            0x86 => Self::STagPcpDei {
                pcp: (value[0] >> 1) & 0x07,
                dei: value[0] & 1 != 0,
            },
            0x87 => Self::Ethertype(word(0)),
            _ => return None,
        })
    }

    /// Component type identifier.
    pub fn type_identifier(&self) -> u8 {
        match self {
            Self::Ipv4RemoteAddress { .. } => 0x10,
            Self::Ipv4LocalAddress { .. } => 0x11,
            Self::Ipv6RemoteAddress { .. } => 0x20,
            Self::Ipv6RemoteAddressPrefix { .. } => 0x21,
            Self::Ipv6LocalAddressPrefix { .. } => 0x23,
            Self::ProtocolIdentifierNextHeader(_) => 0x30,
            Self::SingleLocalPort(_) => 0x40,
            Self::LocalPortRange { .. } => 0x41,
            Self::SingleRemotePort(_) => 0x50,
            Self::RemotePortRange { .. } => 0x51,
            Self::SecurityParameterIndex(_) => 0x60,
            Self::TypeOfServiceTrafficClass { .. } => 0x70,
            Self::FlowLabel(_) => 0x80,
            Self::DestinationMacAddress(_) => 0x81,
            Self::SourceMacAddress(_) => 0x82,
            Self::CTagVid(_) => 0x83,
            Self::STagVid(_) => 0x84,
            Self::CTagPcpDei { .. } => 0x85,
            Self::STagPcpDei { .. } => 0x86,
            Self::Ethertype(_) => 0x87,
        }
    }

    /// Encode the type identifier and value; `None` if a field exceeds its
    /// width (flow label 20 bits, VID 12 bits, PCP 3 bits).
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        let mut octets = vec![self.type_identifier()];
        match *self {
            Self::Ipv4RemoteAddress { address, mask }
            | Self::Ipv4LocalAddress { address, mask } => {
                octets.extend_from_slice(&address);
                octets.extend_from_slice(&mask);
            }
            Self::Ipv6RemoteAddress { address, mask } => {
                octets.extend_from_slice(&address);
                octets.extend_from_slice(&mask);
            }
            Self::Ipv6RemoteAddressPrefix {
                address,
                prefix_length,
            }
            | Self::Ipv6LocalAddressPrefix {
                address,
                prefix_length,
            } => {
                octets.extend_from_slice(&address);
                octets.push(prefix_length);
            }
            Self::ProtocolIdentifierNextHeader(value) => octets.push(value),
            Self::SingleLocalPort(port) | Self::SingleRemotePort(port) | Self::Ethertype(port) => {
                octets.extend_from_slice(&port.to_be_bytes())
            }
            Self::LocalPortRange { low, high } | Self::RemotePortRange { low, high } => {
                octets.extend_from_slice(&low.to_be_bytes());
                octets.extend_from_slice(&high.to_be_bytes());
            }
            Self::SecurityParameterIndex(spi) => octets.extend_from_slice(&spi.to_be_bytes()),
            Self::TypeOfServiceTrafficClass { value, mask } => {
                octets.extend_from_slice(&[value, mask])
            }
            Self::FlowLabel(label) => {
                if label > 0x000f_ffff {
                    return None;
                }
                octets.extend_from_slice(&label.to_be_bytes()[1..]);
            }
            Self::DestinationMacAddress(mac) | Self::SourceMacAddress(mac) => {
                octets.extend_from_slice(&mac)
            }
            Self::CTagVid(vid) | Self::STagVid(vid) => {
                if vid > 0x0fff {
                    return None;
                }
                octets.extend_from_slice(&vid.to_be_bytes());
            }
            Self::CTagPcpDei { pcp, dei } | Self::STagPcpDei { pcp, dei } => {
                if pcp > 7 {
                    return None;
                }
                octets.push(pcp << 1 | u8::from(dei));
            }
        }
        Some(octets)
    }
}

/// Check the packet filter contents rules of TS 24.008 Table 10.5.162:
/// at least one component, no reserved or repeated component type, the
/// exclusive pairs, and no IP component with a non-IP Ethertype.
fn valid_tft_filter_contents(contents: &[u8]) -> bool {
    let mut seen = [false; 256];
    let mut ether_type = None;
    let mut remaining = contents;
    while let Some((&kind, rest)) = remaining.split_first() {
        let Some(size) = tft_component_size(kind) else {
            return false;
        };
        if seen[usize::from(kind)] || rest.len() < size {
            return false;
        }
        if kind == 0x87 {
            ether_type = Some(u16::from_be_bytes([rest[0], rest[1]]));
        }
        seen[usize::from(kind)] = true;
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
    // The "IP packet filter components" listed in Table 10.5.162.
    const IP_COMPONENTS: [usize; 13] = [
        0x10, 0x11, 0x20, 0x21, 0x23, 0x30, 0x40, 0x41, 0x50, 0x51, 0x60, 0x70, 0x80,
    ];
    if ether_type.is_some_and(|value| !matches!(value, 0x0800 | 0x86dd))
        && IP_COMPONENTS.iter().any(|&kind| seen[kind])
    {
        return false;
    }
    !contents.is_empty()
}

/// Whether valid contents also keep their component spare bits clear.
fn canonical_tft_filter_contents(contents: &[u8]) -> bool {
    let filter = TftPacketFilter {
        identifier: 0,
        direction: 0,
        precedence: None,
        contents: contents.to_vec(),
    };
    filter.components().is_some_and(|components| {
        components
            .iter()
            .map(TftPacketFilterComponent::to_bytes)
            .collect::<Option<Vec<_>>>()
            .is_some_and(|octets| octets.concat() == contents)
    })
}

/// One TFT packet filter. Delete-filter operations carry only `identifier`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TftPacketFilter {
    /// Packet filter identifier (bits 4-1).
    pub identifier: u8,
    /// Raw direction (bits 6-5).
    pub direction: u8,
    /// Evaluation precedence; absent for deleted filters.
    pub precedence: Option<u8>,
    /// Packet filter contents: component type identifiers and values.
    pub contents: Vec<u8>,
}

impl TftPacketFilter {
    /// Typed direction.
    pub fn direction_value(&self) -> TftPacketFilterDirection {
        match self.direction & 0x03 {
            0 => TftPacketFilterDirection::PreRel7,
            1 => TftPacketFilterDirection::Downlink,
            2 => TftPacketFilterDirection::Uplink,
            _ => TftPacketFilterDirection::Bidirectional,
        }
    }

    /// Typed components; `None` if the contents are not valid.
    pub fn components(&self) -> Option<Vec<TftPacketFilterComponent>> {
        if !valid_tft_filter_contents(&self.contents) {
            return None;
        }
        let mut components = Vec::new();
        let mut remaining = self.contents.as_slice();
        while let Some((&kind, rest)) = remaining.split_first() {
            let size = tft_component_size(kind)?;
            components.push(TftPacketFilterComponent::decode(kind, rest.get(..size)?)?);
            remaining = &rest[size..];
        }
        Some(components)
    }

    /// Build a packet filter from typed components; `None` if the
    /// identifier exceeds 15 or the components break Table 10.5.162.
    pub fn from_components(
        identifier: u8,
        direction: TftPacketFilterDirection,
        precedence: u8,
        components: &[TftPacketFilterComponent],
    ) -> Option<Self> {
        let mut contents = Vec::new();
        for component in components {
            contents.extend(component.to_bytes()?);
        }
        (identifier <= 15 && contents.len() <= 255 && valid_tft_filter_contents(&contents))
            .then_some(Self {
                identifier,
                direction: direction as u8,
                precedence: Some(precedence),
                contents,
            })
    }
}

/// A TFT parameter encoded after the packet filters when the E bit is set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TftParameter {
    /// Parameter identifier.
    pub identifier: u8,
    /// Parameter contents.
    pub contents: Vec<u8>,
}

/// Typed TFT parameter (TS 24.008 Table 10.5.162).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TftParameterValue<'a> {
    /// Authorization token (0x01).
    AuthorizationToken(&'a [u8]),
    /// Flow identifier (0x02): media component number and IP flow number.
    FlowIdentifier {
        /// Media component number.
        media_component: u16,
        /// IP flow number.
        ip_flow: u16,
    },
    /// Packet filter identifiers (0x03), with the spare bits removed.
    PacketFilterIdentifiers(Vec<u8>),
    /// A parameter the receiver discards.
    Unsupported,
}

impl TftParameter {
    /// Typed value; a malformed or unknown parameter is `Unsupported`.
    pub fn value(&self) -> TftParameterValue<'_> {
        match (self.identifier, self.contents.as_slice()) {
            (1, token) => TftParameterValue::AuthorizationToken(token),
            (2, [a, b, c, d]) => TftParameterValue::FlowIdentifier {
                media_component: u16::from_be_bytes([*a, *b]),
                ip_flow: u16::from_be_bytes([*c, *d]),
            },
            (3, ids) if !ids.is_empty() => {
                TftParameterValue::PacketFilterIdentifiers(ids.iter().map(|id| id & 0x0f).collect())
            }
            _ => TftParameterValue::Unsupported,
        }
    }
}

/// Traffic flow template with packet filters and optional parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tft {
    /// TFT operation.
    pub operation: TftOperation,
    /// Packet filters in wire order.
    pub packet_filters: Vec<TftPacketFilter>,
    /// Parameters in wire order.
    pub parameters: Vec<TftParameter>,
}

/// Sender rules for the parameters list: an authorization token is
/// followed by at least one flow identifier, a flow identifier has four
/// octets, and packet filter identifiers use only bits 4-1.
/// Error class of a TFT parameters list, if any (TS 24.008 Table 10.5.162).
fn tft_parameters_error(parameters: &[TftParameter]) -> Option<TftError> {
    let mut needs_flow_id = false;
    for parameter in parameters {
        match parameter.identifier {
            1 => {
                if needs_flow_id {
                    return Some(TftError::SemanticTftOperation);
                }
                needs_flow_id = true;
            }
            2 => {
                if parameter.contents.len() != 4 {
                    return Some(TftError::SyntacticalTftOperation);
                }
                needs_flow_id = false;
            }
            3 if parameter.contents.is_empty()
                || parameter.contents.iter().any(|value| value & 0xf0 != 0) =>
            {
                return Some(TftError::SyntacticalTftOperation);
            }
            _ => {}
        }
    }
    needs_flow_id.then_some(TftError::SyntacticalTftOperation)
}

impl Tft {
    /// Parse a TFT value under the receiver rules and classify errors as
    /// TS 24.301 §6.4.2.4 and §6.4.3.4 do. Spare bits are ignored, "Ignore
    /// this IE" ignores the rest of the value, "Delete packet filters" may
    /// repeat an identifier, and unknown parameters are kept for the
    /// caller to discard.
    pub fn parse(value: &[u8]) -> std::result::Result<Self, TftError> {
        Self::parse_mode(value, false)
    }

    /// Parse a TFT value; see [`Self::parse`].
    pub fn from_bytes(value: &[u8]) -> Option<Self> {
        Self::parse(value).ok()
    }

    /// Parse only a value that the sender rules would produce unchanged.
    pub fn from_bytes_strict(value: &[u8]) -> Option<Self> {
        Self::from_bytes(value).filter(|tft| tft.to_bytes().as_deref() == Some(value))
    }

    fn parse_mode(
        value: &[u8],
        traffic_flow_aggregate: bool,
    ) -> std::result::Result<Self, TftError> {
        use TftError::{SyntacticalPacketFilter, SyntacticalTftOperation};
        let (&first, mut remaining) = value.split_first().ok_or(SyntacticalTftOperation)?;
        let operation = TftOperation::from_u8(first >> 5).ok_or(SyntacticalTftOperation)?;
        let parameter_present = first & 0x10 != 0;
        let count = usize::from(first & 0x0f);
        match operation {
            TftOperation::Ignore if parameter_present || count != 0 => {
                return Err(SyntacticalTftOperation);
            }
            // TS 24.008 Table 10.5.162: the contents are ignored.
            TftOperation::Ignore => {
                return Ok(Self {
                    operation,
                    packet_filters: Vec::new(),
                    parameters: Vec::new(),
                });
            }
            TftOperation::Delete | TftOperation::NoOperation if count != 0 => {
                return Err(SyntacticalTftOperation);
            }
            TftOperation::Create
            | TftOperation::AddFilters
            | TftOperation::ReplaceFilters
            | TftOperation::DeleteFilters
                if count == 0 =>
            {
                return Err(SyntacticalTftOperation);
            }
            _ => {}
        }
        // Identical identifiers are an error only when filters are created
        // or replaced (§6.4.3.4 d) 1); the UE sends identifier 0 for every
        // new traffic flow aggregate filter.
        let check_duplicates = match operation {
            TftOperation::Create | TftOperation::AddFilters => !traffic_flow_aggregate,
            TftOperation::ReplaceFilters => true,
            _ => false,
        };
        let mut packet_filters = Vec::with_capacity(count);
        let mut seen_filters = [false; 16];
        for _ in 0..count {
            let (&header, rest) = remaining.split_first().ok_or(SyntacticalTftOperation)?;
            remaining = rest;
            let identifier = header & 0x0f;
            if check_duplicates
                && std::mem::replace(&mut seen_filters[usize::from(identifier)], true)
            {
                return Err(SyntacticalPacketFilter);
            }
            if operation == TftOperation::DeleteFilters {
                packet_filters.push(TftPacketFilter {
                    identifier,
                    direction: 0,
                    precedence: None,
                    contents: Vec::new(),
                });
                continue;
            }
            let (&[precedence, length], rest) = remaining
                .split_first_chunk::<2>()
                .ok_or(SyntacticalTftOperation)?;
            let contents = rest
                .get(..usize::from(length))
                .ok_or(SyntacticalTftOperation)?;
            if !valid_tft_filter_contents(contents) {
                return Err(SyntacticalPacketFilter);
            }
            packet_filters.push(TftPacketFilter {
                identifier,
                direction: (header >> 4) & 0x03,
                precedence: Some(precedence),
                contents: contents.to_vec(),
            });
            remaining = &rest[contents.len()..];
        }
        let mut parameters = Vec::new();
        if parameter_present {
            if remaining.is_empty() {
                return Err(SyntacticalTftOperation);
            }
            while let Some((&identifier, rest)) = remaining.split_first() {
                let (&length, rest) = rest.split_first().ok_or(SyntacticalTftOperation)?;
                let contents = rest
                    .get(..usize::from(length))
                    .ok_or(SyntacticalTftOperation)?;
                parameters.push(TftParameter {
                    identifier,
                    contents: contents.to_vec(),
                });
                remaining = &rest[contents.len()..];
            }
        } else if !remaining.is_empty() {
            return Err(SyntacticalTftOperation);
        }
        let known: Vec<_> = parameters
            .iter()
            .filter(|parameter| (1..=3).contains(&parameter.identifier))
            .map(|parameter| TftParameter {
                identifier: parameter.identifier,
                contents: match parameter.identifier {
                    3 => parameter.contents.iter().map(|id| id & 0x0f).collect(),
                    _ => parameter.contents.clone(),
                },
            })
            .collect();
        if let Some(error) = tft_parameters_error(&known) {
            return Err(error);
        }
        Ok(Self {
            operation,
            packet_filters,
            parameters,
        })
    }

    /// Encode a TFT value under the sender rules: operation, filter count,
    /// unique identifiers, record lengths, and parameters list.
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
                if filter.direction > 3 || !canonical_tft_filter_contents(&filter.contents) {
                    return None;
                }
                value.push((filter.direction << 4) | filter.identifier);
                value.push(filter.precedence?);
                value.push(u8::try_from(filter.contents.len()).ok()?);
                value.extend_from_slice(&filter.contents);
            }
        }
        if tft_parameters_error(&self.parameters).is_some() {
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
            /// Parse this IE as a TFT under the receiver rules.
            pub fn tft(&self) -> Option<Tft> {
                Tft::from_bytes(&self.value)
            }

            /// Parse this IE, classifying any error by ESM cause.
            pub fn parse_tft(&self) -> std::result::Result<Tft, TftError> {
                Tft::parse(&self.value)
            }

            /// Build a raw IE from a typed TFT.
            pub fn from_tft(tft: &Tft) -> Option<Self> {
                let value = tft.to_bytes()?;
                (value.len() <= u8::MAX as usize).then(|| Self::new(value))
            }

            /// Sender check: the value re-encodes unchanged and does not use
            /// "Ignore this IE", which only a UE uses, in a traffic flow
            /// aggregate (TS 24.008 §10.5.6.12).
            pub fn is_well_formed(&self) -> bool {
                Tft::from_bytes_strict(&self.value)
                    .is_some_and(|tft| tft.operation != TftOperation::Ignore)
            }
        }
    };
}
tft_ie!(NasTft);

impl NasTrafficFlowAggregate {
    /// Parse a traffic flow aggregate under the receiver rules; new
    /// filters may repeat the identifier 0.
    pub fn tft(&self) -> Option<Tft> {
        self.parse_tft().ok()
    }

    /// Parse this IE, classifying any error by ESM cause.
    pub fn parse_tft(&self) -> std::result::Result<Tft, TftError> {
        Tft::parse_mode(&self.value, true)
    }

    /// Build a UE traffic flow aggregate from packet filters and parameters.
    pub fn from_tft(tft: &Tft) -> Option<Self> {
        let value = tft.to_bytes_mode(true)?;
        (value.len() <= u8::MAX as usize).then(|| Self::new(value))
    }

    /// The value a UE sends when the IE serves no purpose: "Ignore this IE".
    pub fn ignore() -> Self {
        Self::new(vec![0x00])
    }

    /// Sender check: the value re-encodes unchanged, and new filters use
    /// identifier 0 (§9.9.4.15).
    pub fn is_well_formed(&self) -> bool {
        self.tft()
            .and_then(|tft| tft.to_bytes_mode(true))
            .is_some_and(|value| value == self.value)
    }
}

pub use crate::common::ts24008::{GprsTimer3Unit, GprsTimerUnit};

pub use crate::common::ts24008::GprsTimerValue;
use crate::common::ts24008::{gprs_timer_2_ie, gprs_timer_3_ie, gprs_timer_ie};

gprs_timer_ie!(NasT3412Value, true);
gprs_timer_ie!(NasT3402Value, false);
gprs_timer_ie!(NasT3423Value, false);
gprs_timer_ie!(NasT3442Value, false);

gprs_timer_2_ie!(NasT3346Value);
gprs_timer_2_ie!(NasT3324Value);
gprs_timer_2_ie!(NasT3448Value);
// T3402 value in ATTACH REJECT (Table 8.2.3.1).
gprs_timer_2_ie!(NasGprsTimer2);

gprs_timer_3_ie!(NasBackOffTimerValue);
gprs_timer_3_ie!(NasT3396Value);
gprs_timer_3_ie!(NasT3447Value);
gprs_timer_3_ie!(NasLowerBoundTimerValue);
gprs_timer_3_ie!(NasMaximumTimeOffset);

/// Receiver interpretation of the T3412 extended value (TS 24.008 Table
/// 10.5.163a NOTE 1 and NOTE 2, TS 24.301 §5.3.5).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum T3412ExtendedValue {
    /// Unit 111: the IE is treated as not included; use the T3412 value IE.
    NotIncluded,
    /// Timer value 0: T3412 is deactivated.
    Deactivated,
    /// T3412 runs for this many seconds.
    Seconds(u64),
}

impl NasT3412ExtendedValue {
    /// Unit and value of the first value octet; extra octets are ignored.
    pub fn timer(&self) -> Option<(GprsTimer3Unit, u8)> {
        let octet = *self.value.first()?;
        Some((GprsTimer3Unit::from_u8(octet >> 5), octet & 0x1f))
    }

    /// Timer unit.
    pub fn unit(&self) -> Option<GprsTimer3Unit> {
        self.timer().map(|(unit, _)| unit)
    }

    /// Timer value in bits 5-1.
    pub fn timer_value(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x1f)
    }

    /// Value as interpreted by the UE: unit 110 means 320 hours when the
    /// carrying message is integrity protected and 1 hour otherwise.
    pub fn value_for_ue(&self, integrity_protected: bool) -> Option<T3412ExtendedValue> {
        let (unit, value) = self.timer()?;
        Some(match unit {
            GprsTimer3Unit::Deactivated => T3412ExtendedValue::NotIncluded,
            _ if value == 0 => T3412ExtendedValue::Deactivated,
            GprsTimer3Unit::ThreeHundredTwentyHours if !integrity_protected => {
                T3412ExtendedValue::Seconds(3_600 * u64::from(value))
            }
            unit => T3412ExtendedValue::Seconds(unit.seconds_multiplier() * u64::from(value)),
        })
    }

    /// Value as interpreted by the network, for which unit 110 is 320 hours.
    pub fn value_for_network(&self) -> Option<T3412ExtendedValue> {
        self.value_for_ue(true)
    }

    /// Duration in seconds for the UE, or `None` when deactivated, treated
    /// as not included, or missing.
    pub fn to_seconds_with_integrity(&self, integrity_protected: bool) -> Option<u64> {
        match self.value_for_ue(integrity_protected)? {
            T3412ExtendedValue::Seconds(seconds) => Some(seconds),
            _ => None,
        }
    }

    /// Build from a unit and five-bit value.
    pub fn from_unit_value(unit: GprsTimer3Unit, value: u8) -> Self {
        Self::new(vec![(unit as u8) << 5 | (value & 0x1f)])
    }

    /// Sender check: exactly one value octet, not using the deactivated unit
    /// (TS 24.008 Table 10.5.163a, NOTE 2).
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 1 && self.unit() != Some(GprsTimer3Unit::Deactivated)
    }
}

/// Identity requested by an EPS IDENTITY REQUEST (TS 24.008 §10.5.5.9).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IdentityTypeValue {
    /// IMSI.
    Imsi = 1,
    /// IMEI.
    Imei = 2,
    /// IMEISV.
    Imeisv = 3,
    /// TMSI.
    Tmsi = 4,
}

impl IdentityTypeValue {
    /// Decode bits 3-1; other values are interpreted as IMSI (TS 24.008
    /// Table 10.5.142).
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::Imsi)
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::Imsi),
            2 => Some(Self::Imei),
            3 => Some(Self::Imeisv),
            4 => Some(Self::Tmsi),
            _ => None,
        }
    }
}

impl NasIdentityType {
    /// The requested identity, reading undefined values as IMSI.
    pub fn identity_type(&self) -> IdentityTypeValue {
        IdentityTypeValue::from_u8(self.value)
    }

    /// The requested identity, only for a defined value.
    pub fn identity_type_strict(&self) -> Option<IdentityTypeValue> {
        IdentityTypeValue::from_u8_strict(self.value)
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

pub use crate::common::ts24008::ImeisvRequestValue;
crate::common::ts24008::imeisv_request_ie!(NasImeisvRequest);

/// EPS PDN connectivity request type (TS 24.008 §10.5.6.17).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RequestTypeValue {
    /// Initial request.
    Initial = 1,
    /// Handover.
    Handover = 2,
    /// Request for access to RLOS; a network in S1 mode without RLOS
    /// support treats it as an initial request (Table 10.5.173, NOTE 3).
    Rlos = 3,
    /// Emergency.
    Emergency = 4,
    /// Handover of emergency bearer services.
    EmergencyHandover = 6,
}

impl RequestTypeValue {
    /// Decode bits 3-1; reserved codes have no receive fallback.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::Initial),
            2 => Some(Self::Handover),
            3 => Some(Self::Rlos),
            4 => Some(Self::Emergency),
            6 => Some(Self::EmergencyHandover),
            _ => None,
        }
    }
}

impl NasRequestType {
    /// Decode a defined request type, leaving reserved values untyped.
    pub fn request_type(&self) -> Option<RequestTypeValue> {
        RequestTypeValue::from_u8(self.value)
    }

    /// Raw request type (bits 3-1).
    pub fn request_type_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Whether the request is for emergency bearer services.
    pub fn is_emergency(&self) -> bool {
        matches!(
            self.request_type(),
            Some(RequestTypeValue::Emergency | RequestTypeValue::EmergencyHandover)
        )
    }

    /// Construct a sender value with the spare bit cleared.
    pub fn from_request_type(request_type: RequestTypeValue) -> Self {
        Self::new(request_type as u8)
    }

    /// Set the request type and clear the spare bit.
    pub fn set_request_type(&mut self, request_type: RequestTypeValue) -> &mut Self {
        self.value = request_type as u8;
        self
    }

    /// Builder form of [`Self::set_request_type`].
    pub fn with_request_type(mut self, request_type: RequestTypeValue) -> Self {
        self.set_request_type(request_type);
        self
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

/// CS location services indicator (TS 24.301 §9.9.3.12A, octet 3 bits 5-4).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CsLcsSupport {
    /// No information about support of location services via CS domain.
    NoInformation = 0,
    /// Location services via CS domain supported.
    Supported = 1,
    /// Location services via CS domain not supported.
    NotSupported = 2,
}

impl CsLcsSupport {
    /// Decode the two-bit field; the reserved value 11 has no fallback.
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::from_u8_strict(value)
    }

    /// Decode only the defined codes.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x03 {
            0 => Some(Self::NoInformation),
            1 => Some(Self::Supported),
            2 => Some(Self::NotSupported),
            _ => None,
        }
    }
}

crate::common::nas_ie_flags!(NasEpsNetworkFeatureSupport {
    /// IMS voice over PS session in S1 mode (octet 3, bit 1).
    ims_vops: 0, 1;
    /// Emergency bearer services in S1 mode (octet 3, bit 2).
    emc_bs: 0, 2;
    /// Location services via EPC (octet 3, bit 3).
    epc_lcs: 0, 3;
    /// Extended service request for packet services (octet 3, bit 6).
    esr_ps: 0, 6;
    /// EMM-REGISTERED without PDN connection (octet 3, bit 7).
    erw_opdn: 0, 7;
    /// Control plane CIoT EPS optimization (octet 3, bit 8).
    cp_ciot: 0, 8;
    /// User plane CIoT EPS optimization (octet 4, bit 1).
    up_ciot: 1, 1;
    /// S1-U data transfer bit as sent (octet 4, bit 2); see
    /// [`Self::s1u_data_supported`] for the receiver interpretation.
    s1u_data: 1, 2;
    /// Header compression for control plane CIoT EPS optimization (octet 4, bit 3).
    hc_cp_ciot: 1, 3;
    /// Extended protocol configuration options (octet 4, bit 4).
    epco: 1, 4;
    /// Restriction on enhanced coverage (octet 4, bit 5).
    restrict_ec: 1, 5;
    /// Restriction on the use of dual connectivity with NR (octet 4, bit 6).
    restrict_dcnr: 1, 6;
    /// Interworking without N26 (octet 4, bit 7).
    iwk_n26: 1, 7;
    /// Signalling for a maximum of 15 EPS bearer contexts (octet 4, bit 8).
    fifteen_bearers: 1, 8;
    /// NAS signalling connection release (octet 5, bit 1).
    ncr: 2, 1;
    /// Paging indication for voice services (octet 5, bit 2).
    piv: 2, 2;
    /// Reject paging request (octet 5, bit 3).
    rpr: 2, 3;
    /// Paging restriction (octet 5, bit 4).
    pr: 2, 4;
    /// Paging timing collision control (octet 5, bit 5).
    ptcc: 2, 5;
    /// Enhanced discontinuous coverage (octet 5, bit 6).
    edc: 2, 6;
    /// Overhead reduction bit as sent (octet 5, bit 7); see
    /// [`Self::ohr_cp_ciot_supported`] for the receiver interpretation.
    ohr_cp_ciot: 2, 7;
});

impl Default for NasEpsNetworkFeatureSupport {
    /// One octet with no feature indicated.
    fn default() -> Self {
        Self::new(vec![0])
    }
}

impl NasEpsNetworkFeatureSupport {
    /// Location services via CS domain (octet 3, bits 5-4); reserved is `None`.
    pub fn cs_lcs(&self) -> Option<CsLcsSupport> {
        CsLcsSupport::from_u8(self.cs_lcs_raw())
    }

    /// Raw CS-LCS field.
    pub fn cs_lcs_raw(&self) -> u8 {
        self.value.first().map_or(0, |octet| (octet >> 3) & 0x03)
    }

    /// Set the CS-LCS field.
    pub fn set_cs_lcs(&mut self, value: CsLcsSupport) {
        if self.value.is_empty() {
            self.value.push(0);
        }
        self.value[0] = (self.value[0] & !0x18) | ((value as u8) << 3);
        self.length = self.value.len() as _;
    }

    /// Builder form of [`Self::set_cs_lcs`].
    pub fn with_cs_lcs(mut self, value: CsLcsSupport) -> Self {
        self.set_cs_lcs(value);
        self
    }

    /// S1-U data transfer as interpreted by the UE: supported when control
    /// plane CIoT EPS optimization is not indicated.
    pub fn s1u_data_supported(&self) -> bool {
        !self.cp_ciot() || self.s1u_data()
    }

    /// Overhead reduction as interpreted by the UE: ignored when control
    /// plane CIoT EPS optimization is not indicated.
    pub fn ohr_cp_ciot_supported(&self) -> bool {
        self.cp_ciot() && self.ohr_cp_ciot()
    }

    /// Whether octet 5 bit 8 is clear.
    pub fn spare_bits_are_zero(&self) -> bool {
        self.value.get(2).is_none_or(|octet| octet & 0x80 == 0)
    }

    /// Sender check: 1 to 3 octets, no reserved CS-LCS value, spare bit clear.
    pub fn is_well_formed(&self) -> bool {
        (1..=3).contains(&self.value.len()) && self.cs_lcs().is_some() && self.spare_bits_are_zero()
    }
}

crate::common::nas_ie_flags!(NasReAttemptIndicator {
    /// Whether retry in A/Gb, Iu, or N1 mode is forbidden (§9.9.4.13A, bit 1).
    ratc_not_allowed: 0, 1;
    /// Whether retry in an equivalent PLMN is forbidden (bit 2).
    eplmnc_not_allowed: 0, 2;
});

impl NasReAttemptIndicator {
    /// Build from the two restriction flags with spare bits clear.
    pub fn from_flags(eplmnc_not_allowed: bool, ratc_not_allowed: bool) -> Self {
        Self::new(vec![
            (u8::from(eplmnc_not_allowed) << 1) | u8::from(ratc_not_allowed),
        ])
    }

    /// Sender check: one octet with the spare bits clear.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [octet] if octet & 0xfc == 0)
    }
}

crate::common::ts24501::ue_status_ie!(NasUeStatus);
pub use crate::common::ts24008::{Pco, PcoDirection, PcoEntry};
crate::common::ts24008::protocol_configuration_options_ie!(NasProtocolConfigurationOptions);
crate::common::ts24008::extended_protocol_configuration_options_ie!(
    NasExtendedProtocolConfigurationOptions
);
crate::common::ts24301::eps_bearer_context_status_ie!(NasEpsBearerContextStatus);
crate::common::ts24301::serving_plmn_rate_control_ie!(NasServingPlmnRateControl);
pub use crate::common::ts24301::DownlinkDataExpected;
crate::common::ts24301::release_assistance_indication_ie!(NasReleaseAssistanceIndication);
pub use crate::common::ts24301::{IpHdrCompAdditionalSetupType, IpHdrCompProfiles};
crate::common::ts24301::header_compression_configuration_ie!(NasHeaderCompressionConfiguration);

impl NasHeaderCompressionConfigurationStatus {
    /// Whether the header compression configuration of EBI 1 to 15 is used
    /// (bit clear, §9.9.4.27); `None` for other EBIs or a missing octet.
    pub fn is_configuration_used(&self, ebi: u8) -> Option<bool> {
        if !(1..=15).contains(&ebi) {
            return None;
        }
        let octet = self.value.get(usize::from(ebi / 8))?;
        Some(octet >> (ebi % 8) & 1 == 0)
    }

    /// EBIs whose configuration is not used. The spare EBI(0) bit and octets
    /// after the second are ignored.
    pub fn not_used_ebis(&self) -> Vec<u8> {
        (1..=15)
            .filter(|&ebi| self.is_configuration_used(ebi) == Some(false))
            .collect()
    }

    /// Build from the EBIs whose configuration is not used; `None` for an
    /// EBI outside 1 to 15.
    pub fn from_not_used_ebis(ebis: &[u8]) -> Option<Self> {
        let mut value = [0u8; 2];
        for &ebi in ebis {
            if !(1..=15).contains(&ebi) {
                return None;
            }
            value[usize::from(ebi / 8)] |= 1 << (ebi % 8);
        }
        Some(Self::new(value.to_vec()))
    }

    /// Sender check: two octets with the spare EBI(0) bit clear.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 2 && self.value[0] & 0x01 == 0
    }
}

/// Additional result for combined attach or tracking-area update (§9.9.3.0A).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum AdditionalUpdateResult {
    /// No additional information.
    NoAdditionalInformation = 0,
    /// CS fallback is not preferred.
    CsFallbackNotPreferred = 1,
    /// SMS only.
    SmsOnly = 2,
}

impl AdditionalUpdateResult {
    /// Decode bits 1–2, excluding the reserved value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x03 {
            0 => Some(Self::NoAdditionalInformation),
            1 => Some(Self::CsFallbackNotPreferred),
            2 => Some(Self::SmsOnly),
            _ => None,
        }
    }
}

impl NasAdditionalUpdateResult {
    /// Typed additional update result (bits 1–2).
    pub fn result(&self) -> Option<AdditionalUpdateResult> {
        AdditionalUpdateResult::from_u8(self.value)
    }

    /// Raw result bits, including the reserved value.
    pub fn result_raw(&self) -> u8 {
        self.value & 0x03
    }

    /// Build with spare bits clear.
    pub fn from_result(result: AdditionalUpdateResult) -> Self {
        Self::new(result as u8)
    }
}

impl NasTmsiStatus {
    /// Whether the UE has a valid TMSI (TS 24.008 §10.5.5.4, bit 1).
    pub fn has_valid_tmsi(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Build with spare bits clear.
    pub fn from_valid_tmsi(valid: bool) -> Self {
        Self::new(u8::from(valid))
    }
}

/// Radio priority level (TS 24.008 §10.5.7.2).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RadioPriorityLevel {
    /// Highest priority.
    One = 1,
    /// Second priority.
    Two = 2,
    /// Third priority.
    Three = 3,
    /// Lowest priority.
    Four = 4,
}

impl RadioPriorityLevel {
    /// Decode a received value: reserved values are read as level four
    /// (TS 24.008 §10.5.7.2).
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::Four)
    }

    /// Decode only the defined levels 1 to 4.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            3 => Some(Self::Three),
            4 => Some(Self::Four),
            _ => None,
        }
    }
}

impl NasRadioPriority {
    /// Effective priority level, including the specified receive fallback.
    pub fn priority_level(&self) -> RadioPriorityLevel {
        RadioPriorityLevel::from_u8(self.value)
    }

    /// Raw three-bit priority value.
    pub fn priority_level_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Build with spare bit clear.
    pub fn from_priority_level(level: RadioPriorityLevel) -> Self {
        Self::new(level as u8)
    }

    /// Set the priority level and clear the spare bit.
    pub fn set_priority_level(&mut self, level: RadioPriorityLevel) -> &mut Self {
        self.value = level as u8;
        self
    }

    /// Builder form of [`Self::set_priority_level`].
    pub fn with_priority_level(mut self, level: RadioPriorityLevel) -> Self {
        self.set_priority_level(level);
        self
    }
}

// Raw value accessors use the shared macro on the wire types in types.rs.
macro_rules! fixed_data_ie {
    ($name:ident, $section:literal) => {
        impl $name {
            #[doc = concat!("Value octets (TS 24.301 §", $section, ").")]
            pub fn data(&self) -> &[u8] {
                &self.value
            }

            /// Build from value octets.
            pub fn from_data(data: Vec<u8>) -> Self {
                Self::new(data)
            }

            /// Replace value octets.
            pub fn set_data(&mut self, data: Vec<u8>) -> &mut Self {
                self.value = data;
                self
            }

            /// Builder form of [`Self::set_data`].
            pub fn with_data(mut self, data: Vec<u8>) -> Self {
                self.set_data(data);
                self
            }
        }
    };
}

nas_opaque_ie!(NasAccessTechnologyUtilizationControl, "24.301", "9.9.3.3A");
nas_opaque_ie!(NasAdditionalInformation, "24.301", "9.9.2.0");
nas_opaque_ie!(NasAuthenticationFailureParameter, "24.301", "9.9.3.1");
nas_opaque_ie!(
    NasAuthenticationParameterAutnEpsChallenge,
    "24.301",
    "9.9.3.2"
);
nas_opaque_ie!(NasAuthenticationResponseParameter, "24.301", "9.9.3.4");
nas_opaque_ie!(NasCli, "24.301", "9.9.3.38");

/// Type-of-number values for the CLI calling-party number.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CallingPartyTypeOfNumber {
    /// Unknown.
    Unknown = 0,
    /// International number.
    International = 1,
    /// National number.
    National = 2,
    /// Network-specific number.
    NetworkSpecific = 3,
    /// Dedicated-access short code.
    DedicatedAccessShortCode = 4,
}

impl CallingPartyTypeOfNumber {
    /// Decode a defined TS 24.008 Table 10.5.118 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::International),
            2 => Some(Self::National),
            3 => Some(Self::NetworkSpecific),
            4 => Some(Self::DedicatedAccessShortCode),
            _ => None,
        }
    }
}

/// Numbering-plan values for the CLI calling-party number.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CallingPartyNumberingPlan {
    /// Unknown.
    Unknown = 0,
    /// ISDN/telephony numbering plan (E.164).
    Isdn = 1,
    /// Data numbering plan (X.121).
    Data = 3,
    /// Telex numbering plan (F.69).
    Telex = 4,
    /// National numbering plan.
    National = 8,
    /// Private numbering plan.
    Private = 9,
}

impl CallingPartyNumberingPlan {
    /// Decode a defined TS 24.008 Table 10.5.118 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Unknown),
            1 => Some(Self::Isdn),
            3 => Some(Self::Data),
            4 => Some(Self::Telex),
            8 => Some(Self::National),
            9 => Some(Self::Private),
            _ => None,
        }
    }
}

/// Presentation indicator in CLI octet 3a.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CallingPartyPresentation {
    /// Presentation allowed.
    Allowed = 0,
    /// Presentation restricted.
    Restricted = 1,
    /// Number unavailable due to interworking.
    Unavailable = 2,
}

impl CallingPartyPresentation {
    /// Decode a defined TS 24.008 Table 10.5.120 value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Allowed),
            1 => Some(Self::Restricted),
            2 => Some(Self::Unavailable),
            _ => None,
        }
    }
}

/// Screening indicator in CLI octet 3a.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CallingPartyScreening {
    /// User-provided, not screened.
    UserProvidedNotScreened = 0,
    /// User-provided, verified and passed.
    UserProvidedVerifiedPassed = 1,
    /// User-provided, verified and failed.
    UserProvidedVerifiedFailed = 2,
    /// Network-provided.
    NetworkProvided = 3,
}

impl CallingPartyScreening {
    /// Decode the two-bit screening value; all values are defined.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::UserProvidedNotScreened),
            1 => Some(Self::UserProvidedVerifiedPassed),
            2 => Some(Self::UserProvidedVerifiedFailed),
            3 => Some(Self::NetworkProvided),
            _ => None,
        }
    }
}

/// Calling party BCD number carried by the CLI IE (TS 24.301 §9.9.3.38,
/// TS 24.008 §10.5.4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CallingPartyNumber {
    /// Type of number (octet 3, bits 7-5).
    pub type_of_number: u8,
    /// Numbering plan identification (octet 3, bits 4-1).
    pub numbering_plan: u8,
    /// Presentation and screening indicators of octet 3a; when absent, the
    /// receiver assumes "presentation allowed" and "user provided, not
    /// screened".
    pub presentation_screening: Option<(u8, u8)>,
    /// Number digits: `0`-`9`, `*`, `#`, `a`, `b`, and `c`.
    pub digits: String,
}

impl CallingPartyNumber {
    /// Typed type-of-number value.
    pub fn type_of_number_value(&self) -> Option<CallingPartyTypeOfNumber> {
        CallingPartyTypeOfNumber::from_u8(self.type_of_number)
    }

    /// Typed numbering-plan value.
    pub fn numbering_plan_value(&self) -> Option<CallingPartyNumberingPlan> {
        CallingPartyNumberingPlan::from_u8(self.numbering_plan)
    }

    /// Typed presentation and screening values.
    pub fn presentation_screening_values(
        &self,
    ) -> Option<(CallingPartyPresentation, CallingPartyScreening)> {
        let (presentation, screening) = self.presentation_screening?;
        Some((
            CallingPartyPresentation::from_u8(presentation)?,
            CallingPartyScreening::from_u8(screening)?,
        ))
    }
}

impl NasCli {
    /// Typed calling party number; spare bits are ignored.
    pub fn number(&self) -> Option<CallingPartyNumber> {
        let (&first, rest) = self.value.split_first()?;
        let (presentation_screening, digits) = match rest.split_first() {
            Some((&octet, digits)) if first & 0x80 == 0 => {
                (Some(((octet >> 5) & 0x03, octet & 0x03)), digits)
            }
            _ => (None, rest),
        };
        Some(CallingPartyNumber {
            type_of_number: (first >> 4) & 0x07,
            numbering_plan: first & 0x0f,
            presentation_screening,
            digits: crate::common::ts24008::decode_number_digits(digits),
        })
    }

    /// Receiver-side structural check for the extension chain, defined code
    /// points, and canonical BCD endmark placement; spare bits are ignored.
    pub fn receiver_syntax_is_valid(&self) -> bool {
        let Some((&first, rest)) = self.value.split_first() else {
            return false;
        };
        if CallingPartyTypeOfNumber::from_u8((first >> 4) & 0x07).is_none()
            || CallingPartyNumberingPlan::from_u8(first & 0x0f).is_none()
        {
            return false;
        }
        let digits = if first & 0x80 == 0 {
            let Some((&second, digits)) = rest.split_first() else {
                return false;
            };
            // Bits 5 to 3 of octet 3a are spare and ignored on receipt.
            if second & 0x80 == 0
                || CallingPartyPresentation::from_u8((second >> 5) & 0x03).is_none()
            {
                return false;
            }
            digits
        } else {
            rest
        };
        digits.is_empty() || crate::common::ts24008::number_digits_are_well_formed(digits)
    }

    /// Strict network-sender check, including spare bits and TON digit
    /// restrictions.
    pub fn is_well_formed(&self) -> bool {
        if !self.receiver_syntax_is_valid()
            || self.value.len() > 12
            || self.value[0] & 0x80 == 0 && self.value[1] & 0x1c != 0
        {
            return false;
        }
        let Some(number) = self.number() else {
            return false;
        };
        !matches!(
            number.type_of_number_value(),
            Some(CallingPartyTypeOfNumber::International | CallingPartyTypeOfNumber::National)
        ) || number.digits.bytes().all(|digit| digit.is_ascii_digit())
    }

    /// Build from a typed number; `None` for a field out of range, invalid
    /// digits, or more than 12 value octets.
    pub fn from_number(number: &CallingPartyNumber) -> Option<Self> {
        if number.type_of_number_value().is_none() || number.numbering_plan_value().is_none() {
            return None;
        }
        if matches!(
            number.type_of_number_value(),
            Some(CallingPartyTypeOfNumber::International | CallingPartyTypeOfNumber::National)
        ) && !number.digits.bytes().all(|digit| digit.is_ascii_digit())
        {
            return None;
        }
        let mut value = vec![number.type_of_number << 4 | number.numbering_plan];
        if let Some((presentation, screening)) = number.presentation_screening {
            if CallingPartyPresentation::from_u8(presentation).is_none()
                || CallingPartyScreening::from_u8(screening).is_none()
            {
                return None;
            }
            value.push(0x80 | presentation << 5 | screening);
        } else {
            value[0] |= 0x80;
        }
        if !number.digits.is_empty() {
            value.extend(crate::common::ts24008::encode_number_digits(
                &number.digits,
            )?);
        }
        (value.len() <= 12).then(|| Self::new(value))
    }
}
nas_opaque_ie!(NasDcnId, "24.301", "9.9.3.48");

impl NasDcnId {
    /// The 16-bit DCN-ID (TS 24.008 §10.5.5.35); extra octets are ignored.
    pub fn dcn_id(&self) -> Option<u16> {
        let [high, low] = *self.value.first_chunk::<2>()?;
        Some(u16::from_be_bytes([high, low]))
    }

    /// Build from a DCN-ID.
    pub fn from_dcn_id(dcn_id: u16) -> Self {
        Self::new(dcn_id.to_be_bytes().to_vec())
    }
}

/// NB-S1 mode DRX value, the DRX cycle parameter T (TS 24.301 Table
/// 9.9.3.63.1). T = 1024 is 0110 here but 0111 in the 5GS NB-N1 IE.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum NbS1DrxValue {
    /// DRX value not specified; use the cell specific value.
    NotSpecified = 0,
    /// T = 32.
    T32 = 1,
    /// T = 64.
    T64 = 2,
    /// T = 128.
    T128 = 3,
    /// T = 256.
    T256 = 4,
    /// T = 512.
    T512 = 5,
    /// T = 1024.
    T1024 = 6,
}

impl NbS1DrxValue {
    /// Decode bits 4-1; other values are read as "not specified".
    pub fn from_u8(value: u8) -> Self {
        Self::from_u8_strict(value).unwrap_or(Self::NotSpecified)
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x0f {
            0 => Some(Self::NotSpecified),
            1 => Some(Self::T32),
            2 => Some(Self::T64),
            3 => Some(Self::T128),
            4 => Some(Self::T256),
            5 => Some(Self::T512),
            6 => Some(Self::T1024),
            _ => None,
        }
    }
}

/// NB-S1 DRX parameter (TS 24.301 §9.9.3.63).
macro_rules! nb_s1_drx_parameter_ie {
    ($name:ident) => {
        impl $name {
            /// DRX value with the receive fallback; spare bits are ignored.
            pub fn drx_value(&self) -> Option<NbS1DrxValue> {
                self.value.first().map(|&octet| NbS1DrxValue::from_u8(octet))
            }

            /// Raw DRX value (bits 4-1).
            pub fn drx_value_raw(&self) -> Option<u8> {
                self.value.first().map(|octet| octet & 0x0f)
            }

            /// Build from a DRX value with the spare bits clear.
            pub fn from_drx_value(value: NbS1DrxValue) -> Self {
                Self::new(vec![value as u8])
            }

            /// Sender check: one octet with a defined value.
            pub fn is_well_formed(&self) -> bool {
                matches!(self.value.as_slice(), [octet] if *octet <= 6)
            }
        }
    };
}

nb_s1_drx_parameter_ie!(NasDrxParameterInNbS1Mode);
nb_s1_drx_parameter_ie!(NasNegotiatedDrxParameterInNbS1Mode);

/// IMSI offset (TS 24.301 §9.9.3.64).
macro_rules! imsi_offset_ie {
    ($name:ident) => {
        impl $name {
            /// The 16-bit IMSI offset; extra octets are ignored.
            pub fn imsi_offset(&self) -> Option<u16> {
                let [high, low] = *self.value.first_chunk::<2>()?;
                Some(u16::from_be_bytes([high, low]))
            }

            /// Build from an IMSI offset.
            pub fn from_imsi_offset(offset: u16) -> Self {
                Self::new(offset.to_be_bytes().to_vec())
            }
        }
    };
}

imsi_offset_ie!(NasRequestedImsiOffset);
imsi_offset_ie!(NasNegotiatedImsiOffset);
nas_opaque_ie!(NasDisasterReturnWaitRange, "24.301", "9.9.3.75");
nas_opaque_ie!(NasDisasterRoamingWaitRange, "24.301", "9.9.3.75");
nas_opaque_ie!(NasDrxParameterInNbS1Mode, "24.301", "9.9.3.63");
nas_opaque_ie!(NasExtendedApnAmbr, "24.301", "9.9.4.29");
nas_opaque_ie!(NasExtendedEpsQos, "24.301", "9.9.4.30");
nas_opaque_ie!(
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService,
    "24.301",
    "9.9.3.33"
);
nas_opaque_ie!(
    NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming,
    "24.301",
    "9.9.3.33"
);
nas_opaque_ie!(NasGenericMessageContainer, "24.301", "9.9.3.43");
nas_opaque_ie!(NasHashMme, "24.301", "9.9.3.50");
nas_opaque_ie!(NasHeaderCompressionConfiguration, "24.301", "9.9.4.22");
nas_opaque_ie!(
    NasHeaderCompressionConfigurationStatus,
    "24.301",
    "9.9.4.27"
);
nas_opaque_ie!(NasLcsClientIdentity, "24.301", "9.9.3.41");
nas_opaque_ie!(NasMessageContainer, "24.301", "9.9.3.22");
nas_opaque_ie!(NasMobileStationClassmark3, "24.301", "9.9.2.5");
nas_opaque_ie!(NasMsNetworkCapability, "24.301", "9.9.3.20");
nas_opaque_ie!(NasNegotiatedDrxParameterInNbS1Mode, "24.301", "9.9.3.63");
nas_opaque_ie!(NasNegotiatedImsiOffset, "24.301", "9.9.3.64");
nas_opaque_ie!(NasNegotiatedQos, "24.301", "9.9.4.12");
nas_opaque_ie!(NasNegotiatedWusAssistanceInformation, "24.301", "9.9.3.62");
nas_opaque_ie!(NasNewQos, "24.301", "9.9.4.12");
nas_opaque_ie!(NasNotificationIndicator, "24.301", "9.9.4.7A");

/// Notification indicator value (TS 24.301 Table 9.9.4.7A.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum NotificationIndicatorValue {
    /// SRVCC handover cancelled, IMS session re-establishment required.
    SrvccHandoverCancelledImsSessionReestablishmentRequired = 1,
}

impl NasNotificationIndicator {
    /// Typed indicator; unused and reserved values return `None`.
    pub fn indicator(&self) -> Option<NotificationIndicatorValue> {
        match self.value.first()? {
            1 => Some(
                NotificationIndicatorValue::SrvccHandoverCancelledImsSessionReestablishmentRequired,
            ),
            _ => None,
        }
    }

    /// Raw indicator octet.
    pub fn indicator_raw(&self) -> Option<u8> {
        self.value.first().copied()
    }

    /// Whether the UE ignores the value: 0x02 to 0x7F are unused.
    pub fn is_ignorable(&self) -> bool {
        self.indicator_raw()
            .is_some_and(|value| (0x02..=0x7f).contains(&value))
    }

    /// Build from a typed indicator.
    pub fn from_indicator(indicator: NotificationIndicatorValue) -> Self {
        Self::new(vec![indicator as u8])
    }
}
nas_opaque_ie!(NasPacketFlowIdentifier, "24.301", "9.9.4.8");

/// Packet flow identifier value (TS 24.008 Table 10.5.161).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PacketFlowId {
    /// Best effort (0).
    BestEffort,
    /// Signalling (1).
    Signalling,
    /// SMS (2).
    Sms,
    /// TOM8 (3).
    Tom8,
    /// Dynamically assigned value 8 to 127.
    Dynamic(u8),
}

impl PacketFlowId {
    /// Decode bits 7-1; the reserved values 4 to 7 return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x7f {
            0 => Some(Self::BestEffort),
            1 => Some(Self::Signalling),
            2 => Some(Self::Sms),
            3 => Some(Self::Tom8),
            4..=7 => None,
            dynamic => Some(Self::Dynamic(dynamic)),
        }
    }

    /// Wire value; `None` for a dynamic value outside 8 to 127.
    pub fn as_u8(self) -> Option<u8> {
        match self {
            Self::BestEffort => Some(0),
            Self::Signalling => Some(1),
            Self::Sms => Some(2),
            Self::Tom8 => Some(3),
            Self::Dynamic(value) => (8..=127).contains(&value).then_some(value),
        }
    }
}

impl NasPacketFlowIdentifier {
    /// Typed PFI; the spare bit is ignored and reserved values return `None`.
    pub fn pfi(&self) -> Option<PacketFlowId> {
        PacketFlowId::from_u8(*self.value.first()?)
    }

    /// Raw PFI (bits 7-1).
    pub fn pfi_raw(&self) -> Option<u8> {
        self.value.first().map(|octet| octet & 0x7f)
    }

    /// Build from a typed PFI; `None` for an invalid dynamic value.
    pub fn from_pfi(pfi: PacketFlowId) -> Option<Self> {
        Some(Self::new(vec![pfi.as_u8()?]))
    }

    /// Sender check: one octet, spare bit clear, and not a reserved value.
    pub fn is_well_formed(&self) -> bool {
        matches!(self.value.as_slice(), [octet] if octet & 0x80 == 0) && self.pfi().is_some()
    }
}
nas_opaque_ie!(NasProtocolConfigurationOptions, "24.301", "9.9.4.11");
nas_opaque_ie!(NasReplayedNasMessageContainer, "24.301", "9.9.3.51");
nas_opaque_ie!(NasRequestedImsiOffset, "24.301", "9.9.3.64");
nas_opaque_ie!(NasRequestedWusAssistanceInformation, "24.301", "9.9.3.62");
nas_opaque_ie!(NasTransactionIdentifier, "24.301", "9.9.4.17");

impl NasTransactionIdentifier {
    /// TI flag (octet 3, bit 8): set when the message is sent to the side
    /// that originated the TI (TS 24.007 §11.2.3.1.3).
    pub fn ti_flag(&self) -> Option<bool> {
        self.value.first().map(|octet| octet & 0x80 != 0)
    }

    /// TI value: TIE when the extension octet is present, otherwise TIO.
    /// `None` for TIO 7 without an extension, or a reserved TIE of 0 to 6.
    pub fn ti_value(&self) -> Option<u8> {
        match self.value.as_slice() {
            [_, extension, ..] => Some(extension & 0x7f).filter(|&tie| tie >= 7),
            [octet] => Some((octet >> 4) & 0x07).filter(|&tio| tio != 7),
            [] => None,
        }
    }

    /// Build a TI; values 7 to 127 use the extension octet.
    pub fn from_ti(flag: bool, value: u8) -> Option<Self> {
        let flag = u8::from(flag) << 7;
        match value {
            0..=6 => Some(Self::new(vec![flag | value << 4])),
            7..=127 => Some(Self::new(vec![flag | 0x70, 0x80 | value])),
            _ => None,
        }
    }

    /// Sender check: spare bits clear, and the extension octet used only
    /// for TI values of 7 or greater.
    pub fn is_well_formed(&self) -> bool {
        match (self.ti_flag(), self.ti_value()) {
            (Some(flag), Some(value)) => {
                Self::from_ti(flag, value).is_some_and(|ti| ti.value == self.value)
            }
            _ => false,
        }
    }
}
nas_opaque_ie!(NasUeAdditionalSecurityCapability, "24.301", "9.9.3.53");
nas_opaque_ie!(NasUeCoarseLocationInformation, "24.301", "9.9.3.72");
nas_opaque_ie!(
    NasUeDeterminedPlmnWithDisasterCondition,
    "24.301",
    "9.9.3.77"
);
nas_opaque_ie!(NasUeRadioCapabilityId, "24.301", "9.9.3.60");
nas_opaque_ie!(NasUeRadioCapabilityIdAvailability, "24.301", "9.9.3.58");

impl NasUeRadioCapabilityIdAvailability {
    /// Whether a UE radio capability ID is available; values other than 1
    /// are read as "not available" (Table 9.9.3.58.1).
    pub fn is_available(&self) -> Option<bool> {
        self.value.first().map(|octet| octet & 0x07 == 1)
    }

    /// Build with the spare bits clear.
    pub fn from_available(available: bool) -> Self {
        Self::new(vec![u8::from(available)])
    }
}
nas_opaque_ie!(NasUeRadioCapabilityIdRequest, "24.301", "9.9.3.59");

impl NasUeRadioCapabilityIdRequest {
    /// Whether the UE radio capability ID is requested (URCIDR, bit 1).
    pub fn is_requested(&self) -> Option<bool> {
        self.value.first().map(|octet| octet & 0x01 != 0)
    }

    /// Build with the spare bits clear.
    pub fn from_requested(requested: bool) -> Self {
        Self::new(vec![u8::from(requested)])
    }
}
nas_opaque_ie!(NasUserDataContainer, "24.301", "9.9.4.24");

fixed_data_ie!(NasLocationAreaIdentification, "9.9.2.2");

/// Location area identification (TS 24.008 §10.5.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Lai {
    /// PLMN identity.
    pub plmn: PlmnId,
    /// Location area code.
    pub lac: u16,
}

impl NasLocationAreaIdentification {
    /// Typed LAI; `None` for a PLMN that does not decode, which the
    /// network treats as a deleted LAI.
    pub fn lai(&self) -> Option<Lai> {
        let value = self.value.get(..5)?;
        Some(Lai {
            plmn: PlmnId::from_tbcd(&value[..3])?,
            lac: u16::from_be_bytes([value[3], value[4]]),
        })
    }

    /// Build from a typed LAI.
    pub fn from_lai(lai: Lai) -> Self {
        let mut value = lai.plmn.to_tbcd().to_vec();
        value.extend_from_slice(&lai.lac.to_be_bytes());
        Self::new(value)
    }
}
fixed_data_ie!(NasNonceMme, "9.9.3.25");
fixed_data_ie!(NasNonceUe, "9.9.3.25");
fixed_data_ie!(NasOldPTmsiSignature, "9.9.3.26");
fixed_data_ie!(NasReplayedNonceUe, "9.9.3.25");

// ── Nonces, signatures, and hashes (TS 24.301 §9.9.3.25, §9.9.3.26, §9.9.3.50) ──

macro_rules! nonce_ie {
    ($name:ident) => {
        impl $name {
            /// The 32-bit nonce; `None` unless four octets are present.
            pub fn nonce(&self) -> Option<u32> {
                Some(u32::from_be_bytes(self.value.as_slice().try_into().ok()?))
            }

            /// Build from a 32-bit nonce.
            pub fn from_nonce(nonce: u32) -> Self {
                Self::new(nonce.to_be_bytes().to_vec())
            }

            /// Replace the nonce.
            pub fn set_nonce(&mut self, nonce: u32) {
                self.value = nonce.to_be_bytes().to_vec();
            }

            /// Builder form of [`Self::set_nonce`].
            pub fn with_nonce(mut self, nonce: u32) -> Self {
                self.set_nonce(nonce);
                self
            }
        }
    };
}

nonce_ie!(NasNonceMme);
nonce_ie!(NasNonceUe);
nonce_ie!(NasReplayedNonceUe);

impl NasOldPTmsiSignature {
    /// The 24-bit P-TMSI signature (TS 24.008 §10.5.5.8).
    pub fn p_tmsi_signature(&self) -> Option<u32> {
        match self.value.as_slice() {
            [high, middle, low] => Some(u32::from_be_bytes([0, *high, *middle, *low])),
            _ => None,
        }
    }

    /// Build from a 24-bit signature; `None` when it exceeds 24 bits.
    pub fn from_p_tmsi_signature(signature: u32) -> Option<Self> {
        (signature <= 0x00ff_ffff).then(|| Self::new(signature.to_be_bytes()[1..].to_vec()))
    }
}

impl NasHashMme {
    /// The 64-bit HashMME (TS 24.301 §9.9.3.50); octets beyond eight are ignored.
    pub fn hash_mme(&self) -> Option<[u8; 8]> {
        self.value.get(..8)?.try_into().ok()
    }

    /// Build from a 64-bit HashMME.
    pub fn from_hash_mme(hash: [u8; 8]) -> Self {
        Self::new(hash.to_vec())
    }

    /// Sender check: exactly eight octets.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 8
    }
}

// ── UE additional security capability (TS 24.301 §9.9.3.53) ─────────────────

impl NasUeAdditionalSecurityCapability {
    /// 5G-EA0 to 5G-EA15 as a bitmap with 5G-EA0 in the most significant bit.
    pub fn ea_bits(&self) -> Option<u16> {
        Some(u16::from_be_bytes(self.value.get(..2)?.try_into().ok()?))
    }

    /// 5G-IA0 to 5G-IA15 as a bitmap with 5G-IA0 in the most significant bit.
    pub fn ia_bits(&self) -> Option<u16> {
        Some(u16::from_be_bytes(self.value.get(2..4)?.try_into().ok()?))
    }

    /// Whether 5G-EA`algo` (0 to 15) is supported.
    pub fn supports_ea(&self, algo: u8) -> bool {
        algo <= 15
            && self
                .ea_bits()
                .is_some_and(|bits| bits & (0x8000 >> algo) != 0)
    }

    /// Whether 5G-IA`algo` (0 to 15) is supported.
    pub fn supports_ia(&self, algo: u8) -> bool {
        algo <= 15
            && self
                .ia_bits()
                .is_some_and(|bits| bits & (0x8000 >> algo) != 0)
    }

    /// Build from the encryption and integrity bitmaps.
    pub fn from_capabilities(ea_bits: u16, ia_bits: u16) -> Self {
        let mut value = ea_bits.to_be_bytes().to_vec();
        value.extend_from_slice(&ia_bits.to_be_bytes());
        Self::new(value)
    }

    /// Set 5G-EA`algo` (0 to 15), extending the value to four octets.
    pub fn set_ea(&mut self, algo: u8, supported: bool) {
        if algo <= 15 {
            self.set_bit(usize::from(algo), supported);
        }
    }

    /// Set 5G-IA`algo` (0 to 15), extending the value to four octets.
    pub fn set_ia(&mut self, algo: u8, supported: bool) {
        if algo <= 15 {
            self.set_bit(16 + usize::from(algo), supported);
        }
    }

    fn set_bit(&mut self, index: usize, supported: bool) {
        if self.value.len() < 4 {
            self.value.resize(4, 0);
        }
        let mask = 0x80 >> (index % 8);
        if supported {
            self.value[index / 8] |= mask;
        } else {
            self.value[index / 8] &= !mask;
        }
        self.length = self.value.len() as _;
    }

    /// Sender check: exactly four octets.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() == 4
    }
}

// ── MS network capability (TS 24.008 §10.5.5.12) ────────────────────────────

crate::common::nas_ie_flags!(NasMsNetworkCapability {
    /// GEA/1 bit as sent (octet 3, bit 8); the MS sets it to 0.
    gea1: 0, 8;
    /// Mobile terminated SMS via CS domain (octet 3, bit 7).
    sm_dedicated: 0, 7;
    /// Mobile terminated SMS via PS domain (octet 3, bit 6).
    sm_gprs: 0, 6;
    /// UCS2 treatment (octet 3, bit 5): `true` means no preference.
    ucs2: 0, 5;
    /// SoLSA capability (octet 3, bit 2).
    solsa: 0, 2;
    /// R99 or later protocol support (octet 3, bit 1).
    revision_level_indicator: 0, 1;
    /// BSS packet flow procedures (octet 4, bit 8).
    pfc: 1, 8;
    /// LCS value added location request notification (octet 4, bit 1).
    lcs_va: 1, 1;
    /// PS inter-RAT handover from GERAN to UTRAN Iu mode (octet 5, bit 8).
    ps_ho_utran: 2, 8;
    /// PS inter-RAT handover from GERAN to E-UTRAN S1 mode (octet 5, bit 7).
    ps_ho_eutran: 2, 7;
    /// EMM combined procedures (octet 5, bit 6).
    emm_combined: 2, 6;
    /// ISR support (octet 5, bit 5).
    isr: 2, 5;
    /// SRVCC to GERAN/UTRAN (octet 5, bit 4).
    srvcc: 2, 4;
    /// EPC capability (octet 5, bit 3).
    epc: 2, 3;
    /// Notification procedure (octet 5, bit 2).
    nf: 2, 2;
    /// GERAN network sharing (octet 5, bit 1).
    geran_network_sharing: 2, 1;
    /// User plane integrity protection (octet 6, bit 8).
    up_integrity_protection: 3, 8;
    /// ePCO IE indicator (octet 6, bit 3).
    epco: 3, 3;
    /// Restriction on use of enhanced coverage (octet 6, bit 2).
    restrict_ec: 3, 2;
    /// Dual connectivity of E-UTRA with NR (octet 6, bit 1).
    dcnr: 3, 1;
});

impl NasMsNetworkCapability {
    /// SS screening indicator (octet 3, bits 4-3).
    pub fn ss_screening_indicator(&self) -> Option<u8> {
        self.value.first().map(|octet| (octet >> 2) & 0x03)
    }

    /// Whether GEA/`algo` (2 to 7) is available (octet 4, bits 7-2).
    pub fn supports_gea(&self, algo: u8) -> bool {
        (2..=7).contains(&algo)
            && self
                .value
                .get(1)
                .is_some_and(|octet| octet & (0x80 >> (algo - 1)) != 0)
    }

    /// Whether GIA/`algo` (4 to 7) is available (octet 6, bits 7-4).
    pub fn supports_gia(&self, algo: u8) -> bool {
        (4..=7).contains(&algo)
            && self
                .value
                .get(3)
                .is_some_and(|octet| octet & (0x80 >> (algo - 3)) != 0)
    }

    /// Sender check: 2 to 8 octets with GEA/1 clear and trailing spare octets zero.
    pub fn is_well_formed(&self) -> bool {
        (2..=8).contains(&self.value.len())
            && !self.gea1()
            && self
                .value
                .get(4..)
                .is_none_or(|spare| spare.iter().all(|&octet| octet == 0))
    }
}

impl NasMobileStationClassmark3 {
    /// Sender check: at most 32 octets. The CSN.1 content is not decoded.
    pub fn is_well_formed(&self) -> bool {
        self.value.len() <= 32
    }
}

// ── Replayed NAS message container (TS 24.301 §9.9.3.51) ────────────────────

impl NasReplayedNasMessageContainer {
    /// Decode the replayed ATTACH REQUEST or TRACKING AREA UPDATE REQUEST,
    /// which is carried without a NAS security header.
    pub fn decode_as_emm_message(
        &self,
    ) -> crate::common::Result<crate::nas_eps::messages::NasEpsMessage> {
        use crate::nas_eps::messages::{NasEmmMessage, NasEpsMessage, decode_nas_eps_message};
        let message = decode_nas_eps_message(&self.value)?;
        if matches!(
            message,
            NasEpsMessage::Emm(
                _,
                NasEmmMessage::AttachRequest(_) | NasEmmMessage::TrackingAreaUpdateRequest(_)
            )
        ) {
            Ok(message)
        } else {
            Err(NasError::DecodingError(
                "replayed NAS message container requires a plain ATTACH or TAU REQUEST".into(),
            ))
        }
    }

    /// Build the container from a plain ATTACH REQUEST or TRACKING AREA UPDATE REQUEST.
    pub fn from_emm_message(
        message: &crate::nas_eps::messages::NasEpsMessage,
    ) -> crate::common::Result<Self> {
        use crate::nas_eps::messages::{NasEmmMessage, NasEpsMessage, encode_nas_eps_message};
        if !matches!(
            message,
            NasEpsMessage::Emm(
                _,
                NasEmmMessage::AttachRequest(_) | NasEmmMessage::TrackingAreaUpdateRequest(_)
            )
        ) {
            return Err(NasError::EncodingError(
                "replayed NAS message container requires a plain ATTACH or TAU REQUEST".into(),
            ));
        }
        Ok(Self::new(encode_nas_eps_message(message)?))
    }
}

crate::common::nas_ie_flags!(NasAdditionalInformationRequested half_octet {
    /// Ciphering keys for ciphered broadcast assistance data requested (§9.9.3.55, bit 1).
    cipher_key_data_requested: 1;
});

impl NasAdditionalInformationRequested {
    /// Build with spare bits clear.
    pub fn from_cipher_key_data_requested(requested: bool) -> Self {
        Self::new(u8::from(requested))
    }

    /// Whether bits 8 to 2 are clear.
    pub fn spare_bits_are_zero(&self) -> bool {
        self.value & 0xfe == 0
    }
}

/// Preferred CIoT network behavior (TS 24.301 §9.9.3.0B).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PreferredCiotBehavior {
    /// No preference signalled.
    NoPreference = 0,
    /// Control plane optimization is preferred.
    ControlPlane = 1,
    /// User plane optimization is preferred.
    UserPlane = 2,
}

impl PreferredCiotBehavior {
    /// Decode bits 3–4, excluding the reserved value.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x03 {
            0 => Some(Self::NoPreference),
            1 => Some(Self::ControlPlane),
            2 => Some(Self::UserPlane),
            _ => None,
        }
    }
}

impl NasAdditionalUpdateType {
    /// Whether the UE asks for SMS-only service (bit 1).
    pub fn sms_only(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Whether the NAS signalling connection should remain active (bit 2).
    pub fn signalling_active(&self) -> bool {
        self.value & 0x02 != 0
    }

    /// Preferred CIoT behavior (bits 3–4).
    pub fn preferred_ciot_behavior(&self) -> Option<PreferredCiotBehavior> {
        PreferredCiotBehavior::from_u8(self.value >> 2)
    }

    /// Build all three fields in one half octet.
    pub fn from_fields(
        sms_only: bool,
        signalling_active: bool,
        ciot: PreferredCiotBehavior,
    ) -> Self {
        Self::new(u8::from(sms_only) | (u8::from(signalling_active) << 1) | ((ciot as u8) << 2))
    }
}

crate::common::ts24008::authentication_parameter_rand_ie!(
    NasAuthenticationParameterRandEpsChallenge
);
crate::common::ts24008::authentication_parameter_autn_ie!(
    NasAuthenticationParameterAutnEpsChallenge
);
crate::common::ts24008::authentication_failure_parameter_ie!(NasAuthenticationFailureParameter);
crate::common::ts24301::authentication_response_parameter_ie!(NasAuthenticationResponseParameter);

impl NasControlPlaneOnlyIndication {
    /// Whether this PDN connection is restricted to control plane CIoT (§9.9.4.23).
    pub fn is_control_plane_only(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Build the only defined sending value.
    pub fn control_plane_only() -> Self {
        Self::new(1)
    }
}

impl NasCsfbResponse {
    /// Whether the UE accepted CS fallback paging (§9.9.3.5).
    /// Reserved three-bit values return `None`.
    pub fn accepted(&self) -> Option<bool> {
        match self.value & 0x07 {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }

    /// Raw three-bit response value for exact wire preservation.
    pub fn accepted_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Build a response with spare bits clear.
    pub fn from_accepted(accepted: bool) -> Self {
        Self::new(u8::from(accepted))
    }
}

impl NasConnectivityType {
    /// Whether the PDN connection is LIPA (TS 24.008 §10.5.6.19).
    /// Other received values indicate that no connection type was supplied.
    pub fn is_lipa(&self) -> bool {
        self.value & 0x0f == 1
    }

    /// Build the LIPA or unspecified connection type.
    pub fn from_lipa(lipa: bool) -> Self {
        Self::new(u8::from(lipa))
    }

    /// Raw connectivity type (bits 4-1).
    pub fn connectivity_type_raw(&self) -> u8 {
        self.value & 0x0f
    }
}

crate::common::nas_ie_flags!(NasDeviceProperties half_octet {
    /// MS configured for NAS signalling low priority (TS 24.008 §10.5.7.8, bit 1).
    low_priority: 1;
});

impl NasDeviceProperties {
    /// Build with spare bits clear.
    pub fn from_low_priority(low_priority: bool) -> Self {
        Self::new(u8::from(low_priority))
    }
}

crate::common::nas_ie_flags!(NasWlanOffloadIndication half_octet {
    /// Whether WLAN offload is acceptable in S1 mode (TS 24.008 §10.5.6.20).
    s1_offload_acceptable: 1;
    /// Whether WLAN offload is acceptable in Iu mode.
    iu_offload_acceptable: 2;
});

impl NasWlanOffloadIndication {
    /// Build from the two access-mode flags with spare bits clear.
    pub fn from_acceptability(s1: bool, iu: bool) -> Self {
        Self::new(u8::from(s1) | (u8::from(iu) << 1))
    }
}

impl NasLinkedEpsBearerIdentity {
    /// Raw linked EPS bearer identity in bits 1–4 (§9.9.4.6).
    pub fn bearer_identity(&self) -> u8 {
        self.value & 0x0f
    }

    /// EPS bearer identity 1 to 15, or `None` for the reserved value 0.
    pub fn ebi(&self) -> Option<u8> {
        Some(self.bearer_identity()).filter(|&ebi| ebi != 0)
    }

    /// Build a linked bearer identity from 1 through 15.
    pub fn from_bearer_identity(identity: u8) -> Option<Self> {
        (1..=15).contains(&identity).then(|| Self::new(identity))
    }

    /// Set an identity from 1 through 15; `None` leaves the IE unchanged.
    pub fn set_bearer_identity(&mut self, identity: u8) -> Option<&mut Self> {
        *self = Self::from_bearer_identity(identity)?;
        Some(self)
    }
}

impl NasExtendedEmmCause {
    /// Whether E-UTRAN access is barred (bit 1, §9.9.3.26A).
    pub fn eutran_not_allowed(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Whether the requested EPS optimization is unsupported (bit 2).
    pub fn eps_optimization_not_supported(&self) -> bool {
        self.value & 0x02 != 0
    }

    /// Whether NB-IoT access is barred (bit 3).
    pub fn nb_iot_not_allowed(&self) -> bool {
        self.value & 0x04 != 0
    }

    /// Whether satellite E-UTRAN access is barred (bit 4).
    pub fn satellite_eutran_not_allowed(&self) -> bool {
        self.value & 0x08 != 0
    }

    /// Build all four specified flags.
    pub fn from_flags(eutran: bool, eps_optimization: bool, nb_iot: bool, satellite: bool) -> Self {
        Self::new(
            u8::from(eutran)
                | (u8::from(eps_optimization) << 1)
                | (u8::from(nb_iot) << 2)
                | (u8::from(satellite) << 3),
        )
    }
}

/// Defined generic message container types (§9.9.3.42).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum GenericMessageContainerType {
    /// LTE Positioning Protocol message.
    Lpp = 1,
    /// Location services message.
    Lcs = 2,
}

impl GenericMessageContainerType {
    /// Decode a defined container type; unused and reserved values have no fallback.
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::from_u8_strict(value)
    }

    /// Decode only the defined container types.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Lpp),
            2 => Some(Self::Lcs),
            _ => None,
        }
    }
}

impl NasGenericMessageContainerType {
    /// Typed container type; reserved and unused values return `None`.
    pub fn container_type(&self) -> Option<GenericMessageContainerType> {
        GenericMessageContainerType::from_u8(self.value)
    }

    /// Raw container type.
    pub fn container_type_raw(&self) -> u8 {
        self.value
    }

    /// Whether the value is reserved (0 or 128 to 255) rather than unused.
    pub fn is_reserved(&self) -> bool {
        self.value == 0 || self.value >= 128
    }

    /// Build a defined container type.
    pub fn from_container_type(kind: GenericMessageContainerType) -> Self {
        Self::new(kind as u8)
    }

    /// Replace the container type.
    pub fn set_container_type(&mut self, kind: GenericMessageContainerType) {
        self.value = kind as u8;
    }

    /// Builder form of [`Self::set_container_type`].
    pub fn with_container_type(mut self, kind: GenericMessageContainerType) -> Self {
        self.set_container_type(kind);
        self
    }
}

impl NasLcsIndicator {
    /// Whether the message originated from a mobile-terminated location request (§9.9.3.40).
    pub fn is_mt_lr(&self) -> bool {
        self.value == 1
    }

    /// Build the mobile-terminated location request indication.
    pub fn mt_lr() -> Self {
        Self::new(1)
    }
}

crate::common::nas_ie_flags!(NasNetworkPolicy half_octet {
    /// Unsecured redirection to GERAN or UTRAN not allowed (§9.9.3.52, bit 1).
    unsecured_redirection_forbidden: 1;
});

impl NasNetworkPolicy {
    /// Build with spare bits clear.
    pub fn from_unsecured_redirection_forbidden(forbidden: bool) -> Self {
        Self::new(u8::from(forbidden))
    }
}

impl NasOldGutiType {
    /// Whether the GUTI is mapped rather than native (§9.9.3.45).
    pub fn is_mapped(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Build with spare bits clear.
    pub fn from_mapped(mapped: bool) -> Self {
        Self::new(u8::from(mapped))
    }
}

impl NasPagingIdentity {
    /// Whether non-EPS paging uses the TMSI rather than IMSI (§9.9.3.25A).
    pub fn is_tmsi(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Build with spare bits clear.
    pub fn from_tmsi(tmsi: bool) -> Self {
        Self::new(u8::from(tmsi))
    }
}

/// Defined SMS service status values (§9.9.3.4B).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum SmsServicesStatus {
    /// SMS services are unavailable.
    Unavailable = 0,
    /// SMS services are unavailable in this PLMN.
    UnavailableInPlmn = 1,
    /// Network failure.
    NetworkFailure = 2,
    /// Congestion.
    Congestion = 3,
}

impl SmsServicesStatus {
    /// Decode bits 3-1; the unused values 4 to 7 return `None`, and the UE
    /// treats them as an abnormal case.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            0 => Some(Self::Unavailable),
            1 => Some(Self::UnavailableInPlmn),
            2 => Some(Self::NetworkFailure),
            3 => Some(Self::Congestion),
            _ => None,
        }
    }
}

impl NasSmsServicesStatus {
    /// Typed status; values 4–7 are abnormal on reception.
    pub fn status(&self) -> Option<SmsServicesStatus> {
        SmsServicesStatus::from_u8(self.value)
    }

    /// Raw status (bits 3-1).
    pub fn status_raw(&self) -> u8 {
        self.value & 0x07
    }

    /// Build a defined status with spare bit clear.
    pub fn from_status(status: SmsServicesStatus) -> Self {
        Self::new(status as u8)
    }
}

impl NasSpareHalfOctet {
    /// Whether all four spare bits are clear (§9.9.2.9).
    pub fn is_zero(&self) -> bool {
        self.value & 0x0f == 0
    }

    /// Build the specified zero spare value.
    pub fn zero() -> Self {
        Self::new(0)
    }
}

impl NasUeCoarseLocationInformationRequest {
    /// Whether coarse location information is requested (§9.9.3.71).
    pub fn requested(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Build with spare bits clear.
    pub fn from_requested(requested: bool) -> Self {
        Self::new(u8::from(requested))
    }
}

impl NasUeRadioCapabilityInformationUpdateNeeded {
    /// Whether the MME must delete stored radio capability information (§9.9.3.35).
    pub fn update_needed(&self) -> bool {
        self.value & 0x01 != 0
    }

    /// Build with spare bits clear.
    pub fn from_update_needed(needed: bool) -> Self {
        Self::new(u8::from(needed))
    }
}

impl Default for NasGprsCipheringKeySequenceNumber {
    /// No key available.
    fn default() -> Self {
        Self::from_no_key()
    }
}

impl NasGprsCipheringKeySequenceNumber {
    /// Key sequence number in bits 1–3 (TS 24.008 §10.5.1.2).
    /// Value 7 means no key is available in UE-to-network messages.
    pub fn key_sequence_number(&self) -> u8 {
        self.value & 0x07
    }

    /// Key sequence number 0 to 6, or `None` when no key is available.
    pub fn key_sequence_number_strict(&self) -> Option<u8> {
        let value = self.key_sequence_number();
        (value != 7).then_some(value)
    }

    /// Whether no key is available (value 111).
    pub fn no_key_available(&self) -> bool {
        self.key_sequence_number() == 7
    }

    /// Build a three-bit key sequence number with the spare bit clear.
    pub fn from_key_sequence_number(sequence: u8) -> Option<Self> {
        (sequence <= 7).then(|| Self::new(sequence))
    }

    /// Build the "no key is available" value.
    pub fn from_no_key() -> Self {
        Self::new(7)
    }

    /// Set the key sequence number; `None` when it exceeds three bits.
    pub fn set_key_sequence_number(&mut self, sequence: u8) -> Option<()> {
        (sequence <= 7).then(|| self.value = sequence)
    }

    /// Builder form of [`Self::set_key_sequence_number`].
    pub fn with_key_sequence_number(mut self, sequence: u8) -> Option<Self> {
        self.set_key_sequence_number(sequence)?;
        Some(self)
    }
}

crate::common::nas_ie_flags!(NasMsNetworkFeatureSupport half_octet {
    /// Extended periodic timers supported (TS 24.008 §10.5.1.15, bit 1).
    extended_periodic_timers_supported: 1;
});

impl NasMsNetworkFeatureSupport {
    /// Build with spare bits clear.
    pub fn from_extended_periodic_timers_supported(supported: bool) -> Self {
        Self::new(u8::from(supported))
    }
}

/// LLC SAPI (TS 24.008 Table 10.5.165).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum LlcSapi {
    /// LLC SAPI not assigned.
    NotAssigned = 0,
    /// SAPI 3.
    Sapi3 = 3,
    /// SAPI 5.
    Sapi5 = 5,
    /// SAPI 9.
    Sapi9 = 9,
    /// SAPI 11.
    Sapi11 = 11,
}

impl LlcSapi {
    /// Decode bits 4-1; reserved codes return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0f {
            0 => Some(Self::NotAssigned),
            3 => Some(Self::Sapi3),
            5 => Some(Self::Sapi5),
            9 => Some(Self::Sapi9),
            11 => Some(Self::Sapi11),
            _ => None,
        }
    }
}

impl NasNegotiatedLlcSapi {
    /// LLC SAPI in bits 1–4 (TS 24.008 §10.5.6.9).
    pub fn sapi(&self) -> Option<u8> {
        self.llc_sapi().map(|sapi| sapi as u8)
    }

    /// Typed LLC SAPI; reserved codes return `None`.
    pub fn llc_sapi(&self) -> Option<LlcSapi> {
        LlcSapi::from_u8(self.value)
    }

    /// Raw LLC SAPI (bits 4-1).
    pub fn sapi_raw(&self) -> u8 {
        self.value & 0x0f
    }

    /// Build an assigned LLC SAPI, or zero for an unassigned SAPI.
    pub fn from_sapi(sapi: u8) -> Option<Self> {
        LlcSapi::from_u8(sapi)
            .filter(|_| sapi <= 0x0f)
            .map(Self::from_llc_sapi)
    }

    /// Build from a typed LLC SAPI with the spare bits clear.
    pub fn from_llc_sapi(sapi: LlcSapi) -> Self {
        Self::new(sapi as u8)
    }
}

crate::common::ts24008::non_3gpp_nw_provided_policies_ie!(NasNon3GppNwProvidedPolicies);

impl NasNonCurrentNativeNasKeySetIdentifier {
    /// Build from a valid non-current native key set identifier.
    pub fn from_key_set_identifier(value: KeySetIdentifier) -> Result<Self> {
        match value {
            KeySetIdentifier::Native(id) if id <= 6 => Ok(Self::new(id)),
            _ => Err(NasError::EncodingError(
                "non-current native NAS key set identifier requires a valid native key".into(),
            )),
        }
    }

    /// Sender check: a native key set identifier 0 to 6 (§8.2.29.2).
    pub fn is_well_formed(&self) -> bool {
        self.value <= 6
    }
}

impl NasSsCode {
    /// Supplementary service code (TS 24.301 §9.9.3.39).
    pub fn code(&self) -> u8 {
        self.value
    }

    /// Build from the TS 29.002 service code byte.
    pub fn from_code(code: u8) -> Self {
        Self::new(code)
    }
}

// Raw value access for IEs whose counterpart in the other protocol has it.
crate::common::nas_opaque_ie!(NasUnavailabilityInformation, "24.301", "9.9.3.69");
crate::common::nas_opaque_ie!(NasUnavailabilityConfiguration, "24.301", "9.9.3.70");
crate::common::nas_opaque_ie!(NasUeRequestType, "24.301", "9.9.3.65");
crate::common::nas_opaque_ie!(NasSupportedCodecs, "24.301", "9.9.2.10");
crate::common::nas_opaque_ie!(
    NasListOfPlmnsToBeUsedInDisasterCondition,
    "24.301",
    "9.9.3.76"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_scalar_eps_ie_wire_values() {
        let tai = Tai {
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0f],
            },
            tac: 0x1234,
        };
        let last_tai = NasLastVisitedRegisteredTai::from_tai(tai);
        assert_eq!(last_tai.value, [0x02, 0xf8, 0x39, 0x12, 0x34]);
        assert_eq!(last_tai.tai(), Some(tai));

        let update = NasUeRadioCapabilityInformationUpdateNeeded::from_update_needed(true);
        assert_eq!(update.value, 0x01);
        assert!(update.update_needed());

        let ss = NasSsCode::from_code(0x2b);
        assert_eq!(ss.code(), 0x2b);

        let lcs = NasLcsIndicator::mt_lr();
        assert_eq!(lcs.value, 0x01);
        assert!(lcs.is_mt_lr());

        let old_guti = NasOldGutiType::from_mapped(true);
        assert_eq!(old_guti.value, 0x01);
        assert!(old_guti.is_mapped());

        let coarse = NasUeCoarseLocationInformationRequest::from_requested(true);
        assert_eq!(coarse.value, 0x01);
        assert!(coarse.requested());
    }

    #[test]
    fn ciphering_key_data_sets_round_trip_and_keep_first_sixteen() {
        let set = CipheringDataSet {
            set_id: 0x0102,
            ciphering_key: [0x11; 16],
            c0: vec![0xaa, 0xbb],
            pos_sib_types: [0xfe, 0x00, 0x00, 0x80],
            validity_start_time: [0x62, 0x90, 0x62, 0x21, 0x00],
            validity_duration: 1440,
            tai_list: vec![0x00, 0x02, 0xf8, 0x39, 0x00, 0x01],
        };
        let ie = NasCipheringKeyData::from_data_sets(std::slice::from_ref(&set)).unwrap();
        assert!(ie.is_well_formed());
        assert_eq!(ie.data_sets(), std::slice::from_ref(&set));
        assert_eq!(ie.data_sets()[0].tai_list_value().unwrap().0.len(), 1);

        // Spare bits of the c0 length octet are ignored on receipt.
        let mut spare = ie.value.clone();
        spare[18] |= 0x80;
        assert_eq!(
            NasCipheringKeyData::new(spare.clone()).data_sets(),
            std::slice::from_ref(&set)
        );
        assert!(!NasCipheringKeyData::new(spare).is_well_formed());

        // Seventeen sets: the receiver keeps the first sixteen.
        let seventeen: Vec<u8> = std::iter::repeat_n(ie.value.clone(), 17)
            .flatten()
            .collect();
        let received = NasCipheringKeyData::new(seventeen);
        assert_eq!(received.data_sets().len(), 16);
        assert!(!received.is_well_formed());
        assert!(NasCipheringKeyData::from_data_sets(&[]).is_none());
    }

    #[test]
    fn gprs_timers_distinguish_zero_deactivated_and_undefined_units() {
        // T3402 zero means "act as on expiry"; T3412 zero is deactivated (§5.3.5).
        assert_eq!(NasT3402Value::new(0x20).value(), GprsTimerValue::Seconds(0));
        assert_eq!(
            NasT3412Value::new(0x20).value(),
            GprsTimerValue::Deactivated
        );
        assert_eq!(
            NasT3412Value::new(0xe5).value(),
            GprsTimerValue::Deactivated
        );
        // Units 011-110 of GPRS timer are read as minutes.
        assert_eq!(NasT3423Value::new(0x62).to_seconds(), Some(120));
        assert_eq!(NasT3423Value::new(0x62).unit_raw(), 3);
        assert_eq!(NasT3402Value::from_seconds(12 * 60).unwrap().value, 0x2c);
        assert_eq!(NasT3402Value::from_seconds(62).unwrap().value, 0x1f);
        assert!(NasT3402Value::from_seconds(63).is_none());
        assert_eq!(NasT3442Value::deactivated().value, 0xe0);

        // GPRS timer 2 and 3: extra value octets are ignored on receipt.
        assert_eq!(NasT3346Value::new(vec![0x21, 0x99]).to_seconds(), Some(60));
        assert!(!NasT3346Value::new(vec![0x21, 0x99]).is_well_formed());
        assert_eq!(
            NasT3324Value::new(vec![0x00]).value(),
            Some(GprsTimerValue::Seconds(0))
        );
        assert_eq!(
            NasLowerBoundTimerValue::new(vec![0x21, 0]).to_seconds(),
            Some(3_600)
        );
        // T3396 deactivated and the undefined 320-hour unit are distinct.
        assert_eq!(
            NasT3396Value::new(vec![0xe0]).value(),
            Some(GprsTimerValue::Deactivated)
        );
        assert_eq!(NasT3396Value::new(vec![0xc1]).value(), None);
        assert!(!NasT3396Value::new(vec![0xc1]).is_well_formed());
        assert_eq!(
            NasMaximumTimeOffset::from_seconds(90).unwrap().value,
            [0x83]
        );
        assert_eq!(
            NasBackOffTimerValue::from_unit_value(GprsTimer3Unit::Deactivated, 9).value,
            [0xe0]
        );

        // T3412 extended value: unit 111 means "not included", value 0 deactivates,
        // and unit 110 depends on integrity protection for the UE.
        let extended = |octet| NasT3412ExtendedValue::new(vec![octet]);
        assert_eq!(
            extended(0xe3).value_for_ue(true),
            Some(T3412ExtendedValue::NotIncluded)
        );
        assert_eq!(
            extended(0x40).value_for_ue(true),
            Some(T3412ExtendedValue::Deactivated)
        );
        assert_eq!(
            extended(0xc2).value_for_ue(false),
            Some(T3412ExtendedValue::Seconds(7_200))
        );
        assert_eq!(
            extended(0xc2).value_for_network(),
            Some(T3412ExtendedValue::Seconds(2_304_000))
        );
        assert_eq!(
            extended(0xc2).to_seconds_with_integrity(true),
            Some(2_304_000)
        );
    }

    #[test]
    fn apn_ambr_and_eps_qos_decode_bit_rate_tables() {
        // Table 9.9.4.2.1 boundaries.
        let ambr = |value: Vec<u8>| NasApnAmbr::new(value).parse().unwrap();
        assert_eq!(
            ambr(vec![0x3f, 0x40]),
            ApnAmbrValue {
                dl_kbps: 63,
                ul_kbps: 64
            }
        );
        assert_eq!(
            ambr(vec![0x7f, 0xfe]),
            ApnAmbrValue {
                dl_kbps: 568,
                ul_kbps: 8_640
            }
        );
        assert_eq!(ambr(vec![0xff, 0xfe, 0x00, 0x4a]).ul_kbps, 16_000);
        assert_eq!(ambr(vec![0xfe, 0xfe, 0xfa, 0xff]).ul_kbps, 256_000);
        // Extended-2: 1 * 256 Mbps + 8640 kbps is the 264.64 Mbps lower bound;
        // 11111111 is read as 00000000.
        assert_eq!(ambr(vec![0xfe, 0xfe, 0, 0, 0x01, 0xff]).dl_kbps, 264_640);
        assert_eq!(ambr(vec![0xfe, 0xfe, 0, 0, 0x01, 0xff]).ul_kbps, 8_640);
        // Receivers ignore octets after the three pairs.
        assert_eq!(ambr(vec![0x01, 0x01, 0, 0, 0, 0, 9]).dl_kbps, 1);
        assert!(NasApnAmbr::new(vec![0, 1]).parse().is_none());
        let built = NasApnAmbr::from_kbps(300_000, 8_640).unwrap();
        assert_eq!(built.value, [0xfe, 0xfe, 0x66, 0x00, 0x01, 0x00]);
        assert_eq!(
            built.parse(),
            Some(ApnAmbrValue {
                dl_kbps: 300_000,
                ul_kbps: 8_640
            })
        );
        assert!(NasApnAmbr::from_kbps(65_280_001, 0).is_none());

        // Table 9.9.4.3.1: a 10 Gbps rate needs octets 12-15.
        let qos = EpsQos::from_kbps(1, [10_000_000, 1_024, 0, 520_000]).unwrap();
        assert_eq!(qos.to_bytes().unwrap().len(), 13);
        assert_eq!(qos.mbr_ul(), Some(EpsBitRate::Kbps(10_000_000)));
        assert_eq!(qos.mbr_dl(), Some(EpsBitRate::Kbps(1_024)));
        assert!(EpsQos::from_kbps(1, [1_000, 0, 0, 0]).is_none());
        assert_eq!(qos.gbr_ul(), Some(EpsBitRate::Kbps(0)));
        assert_eq!(qos.gbr_dl(), Some(EpsBitRate::Kbps(520_000)));
        assert!(qos.is_gbr());
        assert!(EpsQos::from_kbps(1, [10_100_000, 0, 0, 0]).is_none());
        let subscribed = EpsQos::from_bytes(&[5, 0, 0, 0, 0]).unwrap();
        assert_eq!(subscribed.mbr_ul(), Some(EpsBitRate::SubscribedOrReserved));
        // The UE maps undefined extended-2 codes onto 10 Gbps.
        let undefined =
            EpsQos::from_bytes(&[1, 0xfe, 0xfe, 0xfe, 0xfe, 0xfa, 0, 0, 0, 0xf7, 0, 0, 0]).unwrap();
        assert_eq!(undefined.mbr_ul(), Some(EpsBitRate::Kbps(10_000_000)));
        assert!(NasNewEpsQos::from_qos(qos).unwrap().is_well_formed());
        assert!(!NasEpsQos::new(vec![1, 0, 0]).is_well_formed());
    }

    #[test]
    fn apn_ambr_and_eps_qos_follow_the_sender_rules() {
        // Above 8640 kbps octet 3 is 11111110, so an
        // extended-2 rate adds 8640 kbps or an octet 5 rate (§9.9.4.2).
        let built = |dl, ul| NasApnAmbr::from_kbps(dl, ul).map(|ie| ie.value);
        assert_eq!(
            built(512_000, 65_024_000),
            Some(vec![0xfe, 0xfe, 0xfa, 0xfa, 0x01, 0xfd])
        );
        assert_eq!(
            built(65_280_000, 65_280_000),
            Some(vec![0xfe, 0xfe, 0xfa, 0xfa, 0xfe, 0xfe])
        );
        assert_eq!(
            built(264_640, 1),
            Some(vec![0xfe, 0x01, 0x00, 0x00, 0x01, 0x00])
        );
        assert_eq!(built(260_000, 1), None);
        for value in [
            &[0xfe, 0xfe, 0xfa, 0xfa, 0xfe, 0xfe][..],
            &[0xfe, 0x01, 0x10, 0x00],
        ] {
            assert!(NasApnAmbr::new(value.to_vec()).is_well_formed());
        }
        for value in [
            &[0x01, 0x01, 0x10, 0x10][..],
            &[0xff, 0xff, 0x00, 0x00, 0x02, 0x02],
            &[0xfe, 0xfe, 0xfb, 0x00],
            &[0xfe, 0xfe, 0xfa, 0xfa, 0xff, 0x00],
        ] {
            assert!(
                !NasApnAmbr::new(value.to_vec()).is_well_formed(),
                "{value:02x?}"
            );
        }
        // An extended octet overrides a reserved base octet.
        assert_eq!(
            NasApnAmbr::new(vec![0x00, 0x01, 0x10, 0x00]).parse(),
            Some(ApnAmbrValue {
                dl_kbps: 10_200,
                ul_kbps: 1
            })
        );
        assert!(!NasApnAmbr::new(vec![0x00, 0x01, 0x10, 0x00]).is_well_formed());

        // §9.9.4.3: octet 8 needs octet 4 = 11111110, octet 12 needs octet 8
        // = 11111010.
        assert!(!NasEpsQos::new(vec![1, 1, 1, 1, 1, 0x10, 0x10, 0x10, 0x10]).is_well_formed());
        assert!(
            !NasEpsQos::new(vec![1, 0xfe, 0xfe, 0xfe, 0xfe, 0x10, 0, 0, 0, 1, 0, 0, 0])
                .is_well_formed()
        );
        assert!(
            NasEpsQos::new(vec![1, 0xfe, 0xfe, 0xfe, 0xfe, 0xfa, 0, 0, 0, 1, 0, 0, 0])
                .is_well_formed()
        );
        // 0 kbps for both maximum bit rates.
        assert!(NasEpsQos::new(vec![1, 0xff, 0xff, 0x01, 0x01]).has_zero_maximum_bit_rates());
        assert!(!NasEpsQos::new(vec![1, 0xff, 0x01, 0x01, 0x01]).has_zero_maximum_bit_rates());
        assert!(!NasEpsQos::new(vec![9]).has_zero_maximum_bit_rates());
        use crate::common::Validate;
        let request = crate::nas_eps::decode_nas_eps_message(&[
            0x02, 0x05, 0xd4, 0x05, 0x01, 0x00, 0x05, 0x01, 0xff, 0xff, 0x01, 0x01,
        ])
        .unwrap();
        assert!(
            request
                .validate()
                .iter()
                .any(|error| error.field == "required_traffic_flow_qos")
        );
    }

    #[test]
    fn extended_rates_ignore_values_the_base_ies_carry() {
        let extended = ExtendedEpsQos::from_kbps(20_000_000, 5_000_000, 0, 0).unwrap();
        assert_eq!(
            (extended.mbr_unit, extended.mbr_ul, extended.mbr_dl),
            (2, 20_000, 0)
        );
        assert_eq!(extended.mbr_ul_kbps(), Some(20_000_000));
        assert_eq!(extended.mbr_dl_kbps(), None);
        let ie = NasExtendedEpsQos::from_qos(extended);
        assert!(ie.is_well_formed());
        assert_eq!(ie.qos(), Some(extended));

        let ambr = NasExtendedApnAmbr::from_kbps(100_000_000, 4_000).unwrap();
        assert_eq!(ambr.value, [3, 0x61, 0xa8, 3, 0x00, 0x01]);
        assert_eq!(ambr.downlink_kbps(), Some(100_000_000));
        // The unused units 0-2 are read as 4 Mbps.
        assert_eq!(
            NasExtendedApnAmbr::new(vec![0, 0, 1, 3, 0, 1]).downlink_kbps(),
            Some(4_000)
        );
        assert!(!NasExtendedApnAmbr::new(vec![0, 0, 1, 3, 0, 1]).is_well_formed());
        let base = NasApnAmbr::from_kbps(8_640, 8_640).unwrap();
        let effective = base.effective_kbps(Some(&ambr)).unwrap();
        assert_eq!(
            effective,
            ApnAmbrValue {
                dl_kbps: 100_000_000,
                ul_kbps: 8_640
            }
        );
    }

    #[test]
    fn bearer_ies_ignore_spare_bits_and_extra_octets_on_receipt() {
        // PDN address: spare bits 8-4, spare non-IP octets, and a trailing
        // octet are ignored; the strict form rejects each of them.
        let received = NasPdnAddress::new(vec![0xf9, 10, 0, 0, 1, 0xff]);
        assert_eq!(
            received.pdn_address(),
            Some(PdnAddress::Ipv4([10, 0, 0, 1]))
        );
        assert!(!received.is_well_formed());
        let dual = NasPdnAddress::from_pdn_address(PdnAddress::Ipv4v6 {
            ipv6_interface_id: [1; 8],
            ipv4: [0; 4],
        });
        assert!(dual.is_well_formed() && dual.uses_dhcpv4());
        assert_eq!(dual.ipv6_interface_id(), Some([1; 8]));
        assert_eq!(
            PdnAddress::from_bytes(&[0x05, 1, 2, 3, 4]),
            Some(PdnAddress::NonIp)
        );
        assert_eq!(PdnAddress::from_bytes_strict(&[0x05, 1, 2, 3, 4]), None);
        assert_eq!(
            PdnAddress::from_bytes(&[0x03, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
            None
        );

        // PDN type 4 is read as IPv6 by the network only in the tolerant form.
        let mut pdn_type = NasPdnType::new(0x0c);
        assert_eq!(pdn_type.pdn_type(), Some(PdnType::Ipv6));
        assert_eq!(
            (pdn_type.pdn_type_strict(), pdn_type.pdn_type_raw()),
            (None, 4)
        );
        pdn_type.set_pdn_type(PdnType::Ipv4v6);
        assert_eq!(pdn_type.value, 3);

        let request = NasRequestType::new(0x0e).with_request_type(RequestTypeValue::Emergency);
        assert!(request.is_emergency() && request.value == 4);
        assert_eq!(NasRequestType::new(0x0d).request_type_raw(), 5);
        assert_eq!(NasRequestType::new(5).request_type(), None);

        let mut lbi = NasLinkedEpsBearerIdentity::new(0);
        assert_eq!(lbi.ebi(), None);
        assert!(lbi.set_bearer_identity(16).is_none());
        assert_eq!(lbi.set_bearer_identity(5).unwrap().ebi(), Some(5));

        assert_eq!(
            NasNegotiatedLlcSapi::new(0x93).llc_sapi(),
            Some(LlcSapi::Sapi3)
        );
        assert_eq!(NasNegotiatedLlcSapi::new(0x04).sapi(), None);
        assert!(NasNegotiatedLlcSapi::from_sapi(0x13).is_none());

        let radio = NasRadioPriority::new(0x0f);
        assert_eq!(radio.priority_level(), RadioPriorityLevel::Four);
        assert_eq!(RadioPriorityLevel::from_u8_strict(radio.value), None);
        assert_eq!(radio.with_priority_level(RadioPriorityLevel::One).value, 1);

        assert!(NasConnectivityType::new(0x01).is_lipa());
        assert!(!NasConnectivityType::new(0x02).is_lipa());

        let wlan = NasWlanOffloadIndication::new(0x0c).with_iu_offload_acceptable(true);
        assert!(wlan.iu_offload_acceptable() && !wlan.s1_offload_acceptable());

        let mut reattempt = NasReAttemptIndicator::new(vec![]);
        reattempt.set_eplmnc_not_allowed(true);
        assert_eq!(
            (reattempt.length, reattempt.value.as_slice()),
            (1, [0x02].as_slice())
        );
        assert!(reattempt.is_well_formed());
        let received = NasReAttemptIndicator::new(vec![0xfd, 0xff]);
        assert!(received.ratc_not_allowed() && !received.eplmnc_not_allowed());
        assert!(!received.is_well_formed());
    }

    #[test]
    fn identifier_ies_follow_24007_and_24008_codings() {
        // TS 24.007 §11.2.3.1.3: TIO 0-6 in one octet, TIE 7-127 in the
        // extension, and the TIO is ignored when the extension is present.
        let short = NasTransactionIdentifier::from_ti(true, 3).unwrap();
        assert_eq!(short.value, [0xb0]);
        assert_eq!((short.ti_flag(), short.ti_value()), (Some(true), Some(3)));
        let long = NasTransactionIdentifier::from_ti(false, 100).unwrap();
        assert_eq!(long.value, [0x70, 0xe4]);
        assert!(long.is_well_formed());
        assert_eq!(
            NasTransactionIdentifier::new(vec![0x20, 0x88]).ti_value(),
            Some(8)
        );
        assert_eq!(
            NasTransactionIdentifier::new(vec![0x70, 0x86]).ti_value(),
            None
        );
        assert_eq!(NasTransactionIdentifier::new(vec![0x70]).ti_value(), None);
        assert!(!NasTransactionIdentifier::new(vec![0x31]).is_well_formed());
        assert!(!NasTransactionIdentifier::new(vec![0x10, 0x88]).is_well_formed());

        let pfi = NasPacketFlowIdentifier::from_pfi(PacketFlowId::Dynamic(8)).unwrap();
        assert!(pfi.is_well_formed());
        assert_eq!(
            NasPacketFlowIdentifier::new(vec![0x82]).pfi(),
            Some(PacketFlowId::Sms)
        );
        assert_eq!(NasPacketFlowIdentifier::new(vec![0x05]).pfi(), None);
        assert!(NasPacketFlowIdentifier::from_pfi(PacketFlowId::Dynamic(4)).is_none());

        let notification = NasNotificationIndicator::new(vec![0x02]);
        assert!(notification.indicator().is_none() && notification.is_ignorable());
        assert!(!NasNotificationIndicator::new(vec![0x80]).is_ignorable());

        let pkmf = NasProseKeyManagementFunctionAddress::new(vec![0xf9, 192, 0, 2, 1, 0]);
        assert_eq!(pkmf.address(), Some("192.0.2.1".parse().unwrap()));
        assert_eq!(pkmf.address_type(), Some(PkmfAddressType::Ipv4));
        assert!(!pkmf.is_well_formed());
        assert!(
            NasProseKeyManagementFunctionAddress::new(vec![2, 0, 0])
                .address()
                .is_none()
        );

        let apn = NasAccessPointName::new(vec![3, b'a', b'_', b'b', 1, b'c']);
        assert_eq!(apn.as_string(), None);
        assert_eq!(apn.labels(), Some(vec![b"a_b".as_slice(), b"c"]));
        assert!(!apn.is_well_formed());
        assert!(NasAccessPointName::new(vec![4, b'a']).labels().is_none());
    }

    #[test]
    fn emm_value_ies_apply_receive_fallbacks() {
        // Unused attach type 0 is read as EPS attach by the network.
        let attach = NasEpsAttachType::new(0x08);
        assert_eq!(attach.attach_type(), AttachType::EpsAttach);
        assert_eq!(
            (attach.attach_type_strict(), attach.attach_type_raw()),
            (None, 0)
        );
        assert_eq!(
            attach
                .with_attach_type(AttachType::EpsEmergencyAttach)
                .value,
            6
        );

        let mut update = NasEpsUpdateType::new(0x0c);
        assert_eq!(update.update_type(), Some(UpdateType::TaUpdating));
        assert_eq!(update.update_type_strict(), None);
        update
            .set_update_type(UpdateType::PeriodicUpdating)
            .set_active(false);
        assert_eq!(update.value, 3);
        assert_eq!(NasEpsUpdateType::new(7).update_type(), None);

        let service = NasServiceType::new(0x0a);
        assert_eq!(service.service_type(), Some(ServiceType::PacketServices));
        assert_eq!(
            (service.service_type_strict(), service.service_type_raw()),
            (None, 10)
        );
        assert_eq!(NasServiceType::new(0x05).service_type(), None);

        assert_eq!(
            NasEpsUpdateResult::new(0x0c).update_result(),
            Some(UpdateResult::TaUpdatedWithIsr)
        );
        assert_eq!(NasEpsAttachResult::new(3).attach_result(), None);

        // Table 9.9.3.7.1: fallbacks differ by direction, and bit 4 is
        // spare from the network.
        let detach = NasDetachType::new(0x0d);
        assert_eq!(detach.ue_detach_kind(), UeDetachKind::CombinedEpsImsi);
        assert_eq!(
            detach.network_detach_kind(),
            NetworkDetachKind::ReattachNotRequired
        );
        assert_eq!(UeDetachKind::from_u8_strict(detach.value), None);
        assert!(detach.is_switch_off());
        let network = NasDetachType::from_network_detach_kind(NetworkDetachKind::Imsi);
        assert_eq!((network.value, network.detach_type_raw()), (3, 3));
    }

    #[test]
    fn mobile_identities_check_type_bits_on_receipt() {
        // TS 24.008 Table 10.5.4: an EMM IDENTITY RESPONSE sends "No
        // Identity" as three zero octets.
        let none = NasMobileIdentity::from_no_identity();
        assert!(none.is_no_identity() && none.is_well_formed());
        assert!(NasMobileIdentity::new(vec![0]).is_no_identity());

        let tmsi = NasMobileIdentity::new(vec![0xf4, 1, 2, 3, 4, 0xff]);
        assert_eq!(tmsi.as_tmsi(), Some(0x0102_0304));
        // A receiver reads the type of identity only: bits 8 to 5 are coded
        // "1111" but a TMSI without them is still a TMSI, as in 5GS.
        let unfilled = NasMobileIdentity::new(vec![0x04, 1, 2, 3, 4]);
        assert_eq!(unfilled.as_tmsi(), Some(0x0102_0304));
        assert!(!unfilled.is_well_formed());
        assert_eq!(
            NasMobileIdentity::new(vec![0xf1, 1, 2, 3, 4]).as_tmsi(),
            None
        );
        assert!(!tmsi.is_well_formed());
        assert!(NasMobileIdentity::from_tmsi(7).is_well_formed());

        let guti = Guti {
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0f],
            },
            mme_group_id: 0x8001,
            mme_code: 1,
            m_tmsi: 0xc000_0001,
        };
        let mut received = guti.to_bytes().to_vec();
        received.push(0);
        let identity = NasEpsMobileIdentity::new(received);
        assert_eq!(identity.as_guti(), Some(guti));
        assert_eq!(identity.plmn(), Some(guti.plmn));
        assert!(!identity.is_well_formed());

        let mut unfilled = guti.to_bytes().to_vec();
        unfilled[0] = 0x06;
        let identity = NasEpsMobileIdentity::new(unfilled);
        assert_eq!(identity.as_guti(), Some(guti));
        assert_eq!(identity.plmn(), Some(guti.plmn));
        assert!(!identity.is_well_formed());
        let mut imsi = guti.to_bytes().to_vec();
        imsi[0] = 0xf1;
        assert_eq!(NasEpsMobileIdentity::new(imsi).as_guti(), None);
        assert!(NasEpsMobileIdentity::from_guti(guti).is_well_formed());
        assert_eq!(identity.identity_type_raw(), Some(6));
    }

    #[test]
    fn location_and_calling_party_ies_decode() {
        let lai = Lai {
            plmn: PlmnId {
                mcc: [2, 0, 8],
                mnc: [9, 3, 0x0f],
            },
            lac: 0x1234,
        };
        let ie = NasLocationAreaIdentification::from_lai(lai);
        assert_eq!(ie.value, [0x02, 0xf8, 0x39, 0x12, 0x34]);
        assert_eq!(ie.lai(), Some(lai));

        // International number +33 1 23 with octet 3a (restricted, network provided).
        let number = CallingPartyNumber {
            type_of_number: 1,
            numbering_plan: 1,
            presentation_screening: Some((1, 3)),
            digits: "33123".into(),
        };
        let cli = NasCli::from_number(&number).unwrap();
        assert_eq!(cli.value, [0x11, 0xa3, 0x33, 0x21, 0xf3]);
        assert_eq!(cli.number(), Some(number));
        assert_eq!(
            NasCli::new(vec![0x91, 0x21])
                .number()
                .unwrap()
                .presentation_screening,
            None
        );
        // Bits 5 to 3 of octet 3a are spare (Wireshark: "Spare bit(s)"): the
        // CLI of a received CS SERVICE NOTIFICATION keeps them.
        let message =
            crate::nas_eps::decode_nas_eps_message(&hex::decode("076401600401bc214365").unwrap())
                .unwrap();
        let crate::nas_eps::NasEpsMessage::Emm(
            _,
            crate::nas_eps::NasEmmMessage::CsServiceNotification(notification),
        ) = message
        else {
            panic!("expected CS SERVICE NOTIFICATION");
        };
        let cli = notification.cli.unwrap();
        assert_eq!(cli.number().unwrap().digits, "1234");
        assert!(!cli.is_well_formed());

        let nri = NasTmsiBasedNriContainer::from_nri(0x3ff).unwrap();
        assert_eq!(
            (nri.value.as_slice(), nri.nri()),
            ([0xff, 0xc0].as_slice(), Some(0x3ff))
        );
        assert_eq!(
            NasTmsiBasedNriContainer::new(vec![0x01, 0x7f]).nri(),
            Some(0x05)
        );
        assert_eq!(NasSmsServicesStatus::new(0x0d).status(), None);
        assert_eq!(NasSmsServicesStatus::new(0x0d).status_raw(), 5);
    }

    #[test]
    fn paging_and_drx_ies_apply_receive_rules() {
        // DRX parameter: SPLIT PG CYCLE CODE 70 is 79; reserved 99 reads as 1;
        // S1 DRX 1010 reads as "not specified".
        let drx = NasDrxParameter::new(vec![70, 0xab]);
        assert_eq!(drx.split_pg_cycle(), Some(79));
        assert_eq!(NasDrxParameter::new(vec![99, 0]).split_pg_cycle(), Some(1));
        assert_eq!(NasDrxParameter::new(vec![0, 0]).split_pg_cycle(), Some(704));
        assert_eq!(drx.s1_drx_value(), Some(S1DrxValue::NotSpecified));
        assert_eq!(
            (drx.split_on_ccch(), drx.non_drx_timer()),
            (Some(true), Some(3))
        );
        let built = NasDrxParameter::from_fields(10, S1DrxValue::T128, false, 0).unwrap();
        assert_eq!(built.value, [10, 0x80]);
        assert!(built.is_well_formed() && !drx.is_well_formed());

        let nb = NasDrxParameterInNbS1Mode::new(vec![0xf7]);
        assert_eq!(nb.drx_value(), Some(NbS1DrxValue::NotSpecified));
        assert_eq!(nb.drx_value_raw(), Some(7));
        assert!(!nb.is_well_formed());
        assert!(
            NasNegotiatedDrxParameterInNbS1Mode::from_drx_value(NbS1DrxValue::T1024)
                .is_well_formed()
        );
        assert_eq!(
            NasRequestedImsiOffset::from_imsi_offset(0x1234).imsi_offset(),
            Some(0x1234)
        );
        assert_eq!(NasDcnId::from_dcn_id(7).dcn_id(), Some(7));

        let restriction = NasPagingRestriction::from_restriction(
            EpsPagingRestrictionType::AllRestrictedExceptSpecifiedPdnConnections,
            &[5, 9],
        )
        .unwrap();
        assert_eq!(restriction.value, [3, 0x20, 0x02]);
        assert_eq!(restriction.unrestricted_ebis(), Some(vec![5, 9]));
        assert!(restriction.is_well_formed());
        assert!(
            NasPagingRestriction::from_restriction(EpsPagingRestrictionType::AllRestricted, &[5])
                .is_none()
        );
        assert_eq!(
            NasEpsAdditionalRequestResult::new(vec![0xfe]).paging_restriction_decision(),
            Some(PagingRestrictionDecision::Rejected)
        );

        let availability = NasUeRadioCapabilityIdAvailability::new(vec![0x05]);
        assert_eq!(availability.is_available(), Some(false));
        assert_eq!(
            NasUeRadioCapabilityIdRequest::from_requested(true).is_requested(),
            Some(true)
        );

        let voice = NasVoiceDomainPreferenceAndUeUsageSetting::from_fields(
            VoiceDomainPreference::ImsPsVoicePreferred,
            true,
        );
        assert_eq!(voice.value, [0x07]);
        assert_eq!(
            voice.voice_domain_preference(),
            Some(VoiceDomainPreference::ImsPsVoicePreferred)
        );

        let list = SAndFMonitoringList::Present(vec![3, 4]);
        let parameters =
            NasSAndFSatelliteOperationParameters::from_fields(Some(600), Some(70_000), &list)
                .unwrap();
        assert!(parameters.is_well_formed());
        assert_eq!(parameters.wait_time(), Some(600));
        assert_eq!(parameters.uplink_delivery_time(), Some(70_000));
        assert_eq!(parameters.monitoring_list(), Some(list));
        // SFMLI 11 is unused and read as "not present".
        assert_eq!(
            NasSAndFSatelliteOperationParameters::new(vec![0x0c]).monitoring_list(),
            Some(SAndFMonitoringList::NotPresent)
        );
    }

    #[test]
    fn cause_values_apply_receive_rules() {
        // Table 9.9.3.9.1: unlisted EMM causes are treated as #111.
        let emm = NasEmmCause::new(0x04);
        assert_eq!(emm.cause(), EmmCause::Unknown(0x04));
        assert_eq!(emm.cause_received(), EmmCause::ProtocolErrorUnspecified);
        assert_eq!(emm.description(), "Unknown EMM cause 0x04");
        assert_eq!(EmmCause::from_u8_strict(0x04), None);
        let emm = NasEmmCause::new(0).with_cause(EmmCause::IllegalUe);
        assert_eq!(
            (emm.cause_raw(), emm.cause().description()),
            (3, "Illegal UE")
        );

        // Table 9.9.4.4.1: the UE uses #34 and the network #111, including
        // for the unused value 0x2E (NOTE 2).
        let esm = NasEsmCause::new(0x2e);
        assert_eq!(
            esm.cause_for_ue(),
            EsmCause::ServiceOptionTemporarilyOutOfOrder
        );
        assert_eq!(esm.cause_for_network(), EsmCause::ProtocolErrorUnspecified);
        assert_eq!(
            NasEsmCause::new(0x1a).cause_for_ue(),
            EsmCause::InsufficientResources
        );
    }

    #[test]
    fn negotiated_qos_applies_24008_receive_rules() {
        // Delay 6, reliability 1; peak 12, precedence 5; mean 20; interactive;
        // MBR UL 64 kbps; MBR DL 8640 kbps with extended-2 0x01; GBR UL 0 kbps;
        // GBR DL 0 kbps with extended 0x4b.
        let mut value = vec![
            0x31, 0xc5, 0x14, 0x63, 0x96, 0x40, 0xfe, 0x74, 0x4b, 0xff, 0xfe, 0x13,
        ];
        value.extend([0x4b, 0x4b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);
        let qos = NasNegotiatedQos::new(value);
        // Receivers apply the documented fallback rules, but a network sender
        // must not emit these reserved and unused assignments.
        assert!(!qos.is_well_formed());
        assert_eq!(
            (qos.delay_class(), qos.reliability_class()),
            (Some(4), Some(2))
        );
        assert_eq!(
            (qos.peak_throughput(), qos.precedence_class()),
            (Some(1), Some(2))
        );
        assert_eq!(qos.mean_throughput(), Some(31));
        assert_eq!(qos.traffic_class_raw(), Some(3));
        assert_eq!(qos.transfer_delay_raw(), Some(0x12));
        assert_eq!(qos.signalling_indication(), Some(true));
        assert_eq!(qos.source_statistics_descriptor_raw(), Some(3));
        assert_eq!(qos.mbr_ul(), Some(EpsBitRate::Kbps(64)));
        assert_eq!(qos.mbr_dl(), Some(EpsBitRate::Kbps(260_000)));
        assert_eq!(qos.gbr_ul(), Some(EpsBitRate::Kbps(0)));
        assert_eq!(qos.gbr_dl(), Some(EpsBitRate::Kbps(17_000)));

        // Reserved codes, spare bits, and an odd extension length.
        let reserved = NasNewQos::new(vec![0xff, 0xff, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            (reserved.delay_class(), reserved.reliability_class()),
            (None, None)
        );
        assert_eq!(
            (reserved.peak_throughput(), reserved.precedence_class()),
            (None, None)
        );
        assert_eq!(reserved.mean_throughput(), None);
        assert_eq!(reserved.mbr_ul(), Some(EpsBitRate::SubscribedOrReserved));
        assert!(!reserved.is_well_formed());
        assert_eq!(NasNewQos::new(vec![0x23]).mbr_ul(), None);

        // TS 24.008 table 10.5.156 network-assigned values, including all
        // three bitrate tiers.  Each non-zero extension requires the sentinel
        // in the preceding tier.
        let valid = NasNegotiatedQos::new(vec![
            0x0b, 0x11, 0x01, 0x29, 0x96, 0xfe, 0xfe, 0x11, 0x05, 0xfe, 0xfe, 0x10, 0xfa, 0xfa,
            0xfa, 0xfa, 0x01, 0x01, 0x01, 0x01,
        ]);
        assert!(valid.is_well_formed());

        let all_zero = NasNewQos::new(vec![0; 12]);
        assert!(!all_zero.is_well_formed());
        let mut invalid_extension = valid.clone();
        invalid_extension.value[12] = 0xfb;
        assert!(!invalid_extension.is_well_formed());
        let mut missing_base_sentinel = valid;
        missing_base_sentinel.value[6] = 0xfd;
        assert!(!missing_base_sentinel.is_well_formed());
    }

    #[test]
    fn key_set_identifiers_expose_ksi_tsc_and_no_key() {
        let ksi = NasKeySetIdentifier::default();
        assert!(ksi.no_key_available());
        let mapped = ksi.with_ksi(3).with_tsc(true);
        assert_eq!((mapped.ksi(), mapped.tsc(), mapped.value), (3, true, 0x0b));
        assert_eq!(mapped.key_set_identifier(), KeySetIdentifier::Mapped(3));
        let non_current = NasNonCurrentNativeNasKeySetIdentifier::new(0x0a);
        assert!(non_current.tsc() && !non_current.is_well_formed());

        let cksn = NasGprsCipheringKeySequenceNumber::default();
        assert!(cksn.no_key_available());
        assert_eq!(cksn.key_sequence_number_strict(), None);
        let cksn = cksn.with_key_sequence_number(4).unwrap();
        assert_eq!(cksn.key_sequence_number_strict(), Some(4));
        assert!(NasGprsCipheringKeySequenceNumber::from_key_sequence_number(8).is_none());
    }

    #[test]
    fn selected_algorithms_ignore_spare_bits_on_receipt() {
        // TS 24.007 §11.1.4: spare bits 8 and 4 are accepted as 0 or 1.
        let received = NasSelectedNasSecurityAlgorithms::new(0xaa);
        assert_eq!(received.ciphering(), Some(CipheringAlgorithm::EEA2));
        assert_eq!(received.integrity(), Some(IntegrityAlgorithm::EIA2));
        assert!(!received.is_well_formed());
        let built = NasSelectedNasSecurityAlgorithms::from_algorithms(
            CipheringAlgorithm::EEA0,
            IntegrityAlgorithm::EIA2,
        )
        .with_ciphering(CipheringAlgorithm::EEA3);
        assert_eq!(built.value, 0x32);
        assert!(built.is_well_formed());
    }

    #[test]
    fn n1_and_ms_network_capabilities_decode_their_bits() {
        let n1 = NasN1UeNetworkCapability::default()
            .with_cp_ciot(true)
            .with_pnb_ciot(PreferredCiotBehavior::UserPlane);
        assert_eq!(n1.value, [0x21]);
        assert!(n1.n3_data_transfer_supported());
        assert_eq!(n1.pnb_ciot(), Some(PreferredCiotBehavior::UserPlane));
        // Longer TLV 3-15 values are valid; only octet 3 is defined.
        assert!(NasN1UeNetworkCapability::new(vec![0x7f, 0x00]).is_well_formed());
        assert!(!NasN1UeNetworkCapability::new(vec![0x80]).is_well_formed());
        assert!(!NasN1UeNetworkCapability::new(vec![0x02]).n3_data_transfer_supported());

        // UCS2, SS 01, R99 / GEA2-GEA3 / EMM combined, ISR, EPC.
        let ms = NasMsNetworkCapability::new(vec![0x15, 0x60, 0x34, 0x00]);
        assert!(ms.ucs2() && ms.revision_level_indicator() && !ms.gea1());
        assert_eq!(ms.ss_screening_indicator(), Some(1));
        assert!(ms.supports_gea(2) && ms.supports_gea(3) && !ms.supports_gea(4));
        assert!(ms.emm_combined() && ms.isr() && ms.epc() && !ms.srvcc());
        assert!(ms.is_well_formed());
        assert!(!NasMsNetworkCapability::new(vec![0x80, 0x00]).is_well_formed());
        let dcnr = NasMsNetworkCapability::new(vec![0x10, 0x00]).with_dcnr(true);
        assert_eq!(
            (dcnr.value.as_slice(), dcnr.length),
            (&[0x10, 0, 0, 0x01][..], 4)
        );
    }

    #[test]
    fn additional_security_capability_nonces_and_hashes() {
        let mut additional = NasUeAdditionalSecurityCapability::from_capabilities(0xe000, 0x6000);
        assert!(additional.supports_ea(2) && !additional.supports_ea(3));
        assert!(additional.supports_ia(1) && !additional.supports_ia(0));
        additional.set_ea(15, true);
        assert_eq!(additional.value, [0xe0, 0x01, 0x60, 0x00]);
        assert!(additional.is_well_formed());

        assert_eq!(NasNonceUe::from_nonce(0x0102_0304).value, [1, 2, 3, 4]);
        assert_eq!(
            NasReplayedNonceUe::new(vec![1, 2, 3, 4]).nonce(),
            Some(0x0102_0304)
        );
        assert_eq!(NasNonceMme::new(vec![1, 2, 3]).nonce(), None);
        let signature = NasOldPTmsiSignature::from_p_tmsi_signature(0x00ab_cdef).unwrap();
        assert_eq!(signature.p_tmsi_signature(), Some(0x00ab_cdef));
        assert!(NasOldPTmsiSignature::from_p_tmsi_signature(0x0100_0000).is_none());

        // HashMME of capture packet 37.
        let hash = NasHashMme::from_hash_mme([0xb1, 0xe1, 0x11, 0x5a, 0x6c, 0x47, 0xa7, 0x50]);
        assert_eq!(hash.hash_mme().unwrap()[0], 0xb1);
        assert!(hash.is_well_formed());
    }

    #[test]
    fn replayed_nas_message_container_carries_plain_attach_or_tau_request() {
        let attach = crate::nas_eps::messages::decode_nas_eps_message(
            &hex::decode("07410108991007000020160605e0e000000000250243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1").unwrap(),
        )
        .unwrap();
        let container = NasReplayedNasMessageContainer::from_emm_message(&attach).unwrap();
        assert_eq!(container.decode_as_emm_message().unwrap(), attach);
        let protected = NasReplayedNasMessageContainer::new(
            hex::decode("17830224400307410108991007000020160605e0e000000000250243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1").unwrap(),
        );
        assert!(protected.decode_as_emm_message().is_err());
    }

    #[test]
    fn small_flag_ies_have_setters_and_generic_container_type_ranges() {
        assert_eq!(NasDeviceProperties::new(0).with_low_priority(true).value, 1);
        assert!(NasNetworkPolicy::new(0x0f).unsecured_redirection_forbidden());
        assert!(
            NasMsNetworkFeatureSupport::new(0)
                .with_extended_periodic_timers_supported(true)
                .extended_periodic_timers_supported()
        );
        let requested = NasAdditionalInformationRequested::from_cipher_key_data_requested(true);
        assert!(requested.cipher_key_data_requested() && requested.spare_bits_are_zero());
        let container = NasGenericMessageContainerType::new(0x80);
        assert!(container.is_reserved() && container.container_type().is_none());
        let lcs = container.with_container_type(GenericMessageContainerType::Lcs);
        assert_eq!((lcs.container_type_raw(), lcs.is_reserved()), (2, false));
    }

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
    fn additional_result_tmsi_priority_and_musim_request_helpers() {
        let result = NasAdditionalUpdateResult::from_result(AdditionalUpdateResult::SmsOnly);
        assert_eq!(result.result(), Some(AdditionalUpdateResult::SmsOnly));
        assert_eq!(NasAdditionalUpdateResult::new(3).result(), None);

        let tmsi = NasTmsiStatus::from_valid_tmsi(true);
        assert!(tmsi.has_valid_tmsi());
        assert_eq!(tmsi.value, 1);

        let priority = NasRadioPriority::from_priority_level(RadioPriorityLevel::Two);
        assert_eq!(priority.priority_level(), RadioPriorityLevel::Two);
        assert_eq!(
            NasRadioPriority::new(0).priority_level(),
            RadioPriorityLevel::Four
        );

        let request = NasUeRequestType::from_request_type(UeRequestType::RejectionOfPaging);
        assert_eq!(
            request.request_type(),
            Some(UeRequestType::RejectionOfPaging)
        );
        assert_eq!(request.request_type_raw(), Some(2));
        assert_eq!(NasUeRequestType::new(vec![3]).request_type(), None);
    }

    #[test]
    fn byte_container_helpers_keep_declared_lengths_in_sync() {
        let mut container = NasUserDataContainer::from_data(vec![1, 2]);
        container.set_data(vec![3, 4, 5]);
        assert_eq!(container.data(), [3, 4, 5]);
        assert_eq!(container.length, 3);
        let next = NasMessageContainer::from_data(vec![0x07]).with_data(vec![0x07, 0x60]);
        assert_eq!(next.length, 2);
        assert_eq!(next.data(), [0x07, 0x60]);

        let epco = NasExtendedProtocolConfigurationOptions::from_epco_data(vec![0x80])
            .with_epco_data(vec![0x80, 0x00]);
        assert_eq!(epco.length, 2);
        assert_eq!(epco.epco_data(), [0x80, 0x00]);
    }

    #[test]
    fn update_type_and_authentication_rand_helpers() {
        let update =
            NasAdditionalUpdateType::from_fields(true, true, PreferredCiotBehavior::ControlPlane);
        assert_eq!(update.value, 0x07);
        assert!(update.sms_only());
        assert!(update.signalling_active());
        assert_eq!(
            update.preferred_ciot_behavior(),
            Some(PreferredCiotBehavior::ControlPlane)
        );
        assert_eq!(
            NasAdditionalUpdateType::new(0x0c).preferred_ciot_behavior(),
            None
        );

        let rand = [0xa5; 16];
        assert_eq!(
            NasAuthenticationParameterRandEpsChallenge::from_rand(rand).rand_array(),
            Some(rand)
        );
        assert_eq!(
            NasAuthenticationParameterRandEpsChallenge::new(vec![0; 15]).rand_array(),
            None
        );
        assert!(NasControlPlaneOnlyIndication::control_plane_only().is_control_plane_only());
        assert_eq!(NasCsfbResponse::from_accepted(true).accepted(), Some(true));
        assert_eq!(NasCsfbResponse::new(3).accepted(), None);
        assert_eq!(NasCsfbResponse::new(3).accepted_raw(), 3);
    }

    #[test]
    fn scalar_ie_accessors_preserve_reserved_wire_values() {
        use crate::common::{Decode, Encode};
        use bytes::{Bytes, BytesMut};

        let cause = NasExtendedEmmCause::from_flags(true, false, true, false);
        assert_eq!(cause.value, 0x05);
        assert!(cause.eutran_not_allowed());
        assert!(!cause.eps_optimization_not_supported());
        assert!(cause.nb_iot_not_allowed());
        assert!(!cause.satellite_eutran_not_allowed());

        let mut raw = Bytes::from_static(&[0xe5]);
        let status = NasSmsServicesStatus::decode(&mut raw).unwrap();
        assert_eq!(status.status(), None);
        let mut out = BytesMut::new();
        status.encode(&mut out).unwrap();
        assert_eq!(&out[..], &[0xe5]);
        assert_eq!(
            NasSmsServicesStatus::from_status(SmsServicesStatus::Congestion).value,
            3
        );

        assert_eq!(
            NasGenericMessageContainerType::new(0x80).container_type(),
            None
        );
        assert_eq!(
            NasGenericMessageContainerType::from_container_type(GenericMessageContainerType::Lpp)
                .value,
            1
        );
        assert_eq!(
            NasUeRadioCapabilityIdDeletionIndication::new(7).deletion_request(),
            Some(RadioCapabilityIdDeletionRequest::NotRequested)
        );
        assert_eq!(
            NasUeRadioCapabilityIdDeletionIndication::new(7).deletion_request_raw(),
            7
        );
        assert_eq!(RadioCapabilityIdDeletionRequest::from_u8_strict(7), None);
        assert!(
            NasNonCurrentNativeNasKeySetIdentifier::from_key_set_identifier(
                KeySetIdentifier::Mapped(1)
            )
            .is_err()
        );
        assert!(
            NasNonCurrentNativeNasKeySetIdentifier::from_key_set_identifier(
                KeySetIdentifier::NoKey
            )
            .is_err()
        );
        assert_eq!(NasNegotiatedLlcSapi::from_sapi(3).unwrap().sapi(), Some(3));
        assert!(NasNegotiatedLlcSapi::from_sapi(4).is_none());
        assert_eq!(
            NasLocalTimeZone::from_quarter_hours(-14)
                .unwrap()
                .quarter_hours(),
            -14
        );
        assert!(NasLocalTimeZone::from_quarter_hours(80).is_none());
        assert!(NasLocalTimeZone::from_quarter_hours(-128).is_none());
    }

    #[test]
    fn requested_identity_security_and_feature_bits() {
        assert_eq!(
            NasIdentityType::from_identity_type(IdentityTypeValue::Imeisv).identity_type(),
            IdentityTypeValue::Imeisv
        );
        assert_eq!(NasIdentityType::new(0xf7).identity_type_raw(), 7);
        // TS 24.008 Table 10.5.142: other values are interpreted as IMSI.
        assert_eq!(
            NasIdentityType::new(7).identity_type(),
            IdentityTypeValue::Imsi
        );
        assert_eq!(NasIdentityType::new(7).identity_type_strict(), None);
        assert!(NasImeisvRequest::from_requested(true).is_requested());
        assert!(!NasImeisvRequest::new(2).is_requested());
        assert_eq!(
            NasRequestType::from_request_type(RequestTypeValue::EmergencyHandover).request_type(),
            Some(RequestTypeValue::EmergencyHandover)
        );
        assert_eq!(NasRequestType::new(5).request_type(), None);
        assert!(NasEsmInformationTransferFlag::from_required(true).is_required());

        let feature = NasEpsNetworkFeatureSupport::new(vec![0x83, 0x09, 0x01]);
        assert!(feature.ims_vops() && feature.emc_bs() && feature.cp_ciot());
        assert!(feature.up_ciot() && feature.epco() && feature.ncr());
        assert!(!NasEpsNetworkFeatureSupport::new(vec![0]).epco());
        // CS-LCS, S1-U data and OHR-CP CIoT receiver rules (Table 9.9.3.12A.1).
        let lcs = NasEpsNetworkFeatureSupport::new(vec![0x10, 0x00, 0x40]);
        assert_eq!(lcs.cs_lcs(), Some(CsLcsSupport::NotSupported));
        assert!(lcs.s1u_data_supported() && !lcs.ohr_cp_ciot_supported());
        assert!(lcs.is_well_formed());
        let reserved = NasEpsNetworkFeatureSupport::new(vec![0x18, 0x00, 0x80]);
        assert_eq!((reserved.cs_lcs(), reserved.cs_lcs_raw()), (None, 3));
        assert!(!reserved.is_well_formed());
        let built = NasEpsNetworkFeatureSupport::default()
            .with_cs_lcs(CsLcsSupport::Supported)
            .with_iwk_n26(true)
            .with_ptcc(true);
        assert_eq!(built.value, [0x08, 0x40, 0x10]);
        assert_eq!(built.length, 3);

        let mut replayed = NasReplayedUeSecurityCapabilities::new(vec![0, 0]);
        replayed.set_eea(CipheringAlgorithm::EEA2 as u8, true);
        replayed.set_eia(IntegrityAlgorithm::EIA1 as u8, true);
        assert!(replayed.supports_eea(CipheringAlgorithm::EEA2 as u8));
        assert!(replayed.supports_eia(IntegrityAlgorithm::EIA1 as u8));
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
        assert!(NasNetworkName::new(vec![0x80]).is_well_formed());
        assert!(!NasNetworkName::new(vec![0xa0]).is_well_formed());
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
        assert_eq!(ControlPlaneServiceType::from_u8_strict(7), None);
        assert_eq!(
            NasControlPlaneServiceType::new(0x0f).service_type_strict(),
            None
        );
    }

    #[test]
    fn typed_network_and_relay_ie_accessors_preserve_valid_payloads() {
        let plmn = PlmnId::from_tbcd(&[0x02, 0xf8, 0x39]).unwrap();
        let list = NasEquivalentPlmns::from_plmns(&[plmn]).unwrap();
        assert_eq!(list.plmns(), [plmn]);
        let disaster_list = NasListOfPlmnsToBeUsedInDisasterCondition::from_plmns(&[plmn]).unwrap();
        assert_eq!(disaster_list.plmns(), [plmn]);
        // Receivers ignore a truncated entry and skip an undecodable one;
        // the sender check rejects both.
        let truncated =
            NasListOfPlmnsToBeUsedInDisasterCondition::new(vec![0x02, 0xf8, 0x39, 0x02]);
        assert_eq!(truncated.plmns(), [plmn]);
        assert!(!truncated.is_well_formed());
        let undecodable = NasEquivalentPlmns::new(vec![0xff, 0xff, 0xff, 0x02, 0xf8, 0x39]);
        assert_eq!(undecodable.plmns(), [plmn]);
        assert!(!undecodable.is_well_formed());
        assert!(NasEquivalentPlmns::from_plmns(&[plmn; 16]).is_none());
        let sixteen = NasEquivalentPlmns::new([0x02, 0xf8, 0x39].repeat(16));
        assert_eq!(sixteen.plmns().len(), 15);
        assert!(NasListOfPlmnsToBeUsedInDisasterCondition::new(vec![]).is_well_formed());
        assert!(NasMobileStationClassmark2::new(vec![0, 0, 0]).is_well_formed());
        assert!(!NasMobileStationClassmark2::new(vec![0x80, 0, 0]).is_well_formed());
        assert!(NasNbifomContainer::new(vec![1, 1, 1]).is_well_formed());
        assert!(!NasNbifomContainer::new(vec![]).is_well_formed());
        let nbifom = NasNbifomContainer::from_parameters(&[
            NbifomParameter {
                identifier: 0x09,
                contents: vec![0xff],
            },
            NbifomParameter {
                identifier: NbifomParameterId::Status as u8,
                contents: vec![0x07],
            },
        ])
        .unwrap();
        // An unassigned status is read as "protocol error, unspecified".
        assert_eq!(
            nbifom.status(),
            Some(NbifomStatus::ProtocolErrorUnspecified)
        );
        assert_eq!(nbifom.parameter(NbifomParameterId::Mode), None);
        assert!(!NasNbifomContainer::new(vec![1]).is_well_formed());
        assert!(!NasNbifomContainer::new(vec![1, 10]).is_well_formed());
        assert!(!NasNbifomContainer::new(vec![2, 1, 0]).is_well_formed());
        let default_access = NasNbifomContainer::new(vec![2, 1, 1]);
        assert!(default_access.is_well_formed_for(NbifomDirection::UeToNetwork));
        assert!(default_access.is_well_formed_for(NbifomDirection::NetworkToUe));
        let ip_flow_mapping = NasNbifomContainer::new(vec![5, 8, 7, 1, 0x41, 0, 0, 0, 0, 0]);
        assert!(ip_flow_mapping.is_well_formed_for(NbifomDirection::UeToNetwork));
        assert!(!ip_flow_mapping.is_well_formed_for(NbifomDirection::NetworkToUe));
        let wrong_h_length =
            NasNbifomContainer::new(vec![4, 12, 11, 1, 0x41, 0, 0x80, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!wrong_h_length.is_well_formed_for(NbifomDirection::UeToNetwork));
        let mixed_ipv4_ipv6 = NasNbifomContainer::new(
            [vec![4, 28, 27, 1, 0x41, 0, 0x05, 0, 0, 0], vec![0; 20]].concat(),
        );
        assert!(!mixed_ipv4_ipv6.is_well_formed_for(NbifomDirection::UeToNetwork));
        let mut ciphering_set = vec![0; 32];
        ciphering_set[18] = 1;
        assert!(NasCipheringKeyData::new(ciphering_set.clone()).is_well_formed());
        ciphering_set[18] = 31;
        assert!(!NasCipheringKeyData::new(ciphering_set.clone()).is_well_formed());
        ciphering_set[18] = 1;
        ciphering_set[23] = 1;
        assert!(!NasCipheringKeyData::new(ciphering_set).is_well_formed());
        assert!(!NasEquivalentPlmns::new(vec![0x02, 0xf8, 0x39, 0]).is_well_formed());

        assert!(NasSAndFSatelliteOperationParameters::new(vec![0x01, 0, 1]).is_well_formed());
        assert!(NasSAndFSatelliteOperationParameters::new(vec![0x08, 2, 7, 8]).is_well_formed());
        assert!(!NasSAndFSatelliteOperationParameters::new(vec![0x01]).is_well_formed());

        let contexts = NasRemoteUeContextConnected::new(vec![1, 2, 0, 0]);
        assert_eq!(contexts.context_octets(), Some(vec![&[0, 0][..]]));
        let context = &contexts.contexts().unwrap()[0];
        assert_eq!(context.address, RemoteUeAddress::NoIpInfo);
        assert!(contexts.is_well_formed());
        let empty_identity = NasRemoteUeContextConnected::new(vec![1, 3, 1, 0, 0]);
        assert!(empty_identity.contexts().is_none());
        assert!(!empty_identity.is_well_formed());
        // §9.9.4.20 sets the minimum IE length to 5 octets: one context.
        assert_eq!(
            NasRemoteUeContextConnected::new(vec![0]).contexts(),
            Some(vec![])
        );
        assert!(!NasRemoteUeContextConnected::new(vec![0]).is_well_formed());
        assert!(NasRemoteUeContextConnected::from_contexts(&[]).is_none());
        let reserved_identity = NasRemoteUeContextConnected::new(vec![1, 4, 1, 1, 0, 0]);
        assert!(reserved_identity.contexts().is_some());
        assert!(!reserved_identity.is_well_formed());
        let reserved_address = NasRemoteUeContextConnected::new(vec![1, 2, 0, 3]);
        assert!(reserved_address.contexts().is_some());
        assert!(!reserved_address.is_well_formed());
        let mut short_encrypted_imsi = vec![0x01];
        short_encrypted_imsi.extend([0; 15]);
        assert!(
            !RemoteUeUserIdentity {
                octets: short_encrypted_imsi
            }
            .is_well_formed()
        );
        assert!(
            NasRemoteUeContextDisconnected::new(vec![1, 0])
                .contexts()
                .is_none()
        );

        // IMSI 208930000000001 and an IPv4 address with a UDP port range.
        let context = EpsRemoteUeContext {
            user_identities: vec![
                RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imsi, "208930000000001")
                    .unwrap(),
                RemoteUeUserIdentity::from_encrypted_imsi([0xab; 16]),
            ],
            address: RemoteUeAddress::Ipv4 {
                address: [10, 0, 0, 2],
                port: 1500,
                udp_port_range: Some(PortRange {
                    low: 1000,
                    high: 2000,
                }),
                tcp_port_range: None,
            },
        };
        let list =
            NasRemoteUeContextConnected::from_contexts(std::slice::from_ref(&context)).unwrap();
        assert!(list.is_well_formed());
        let decoded = &list.contexts().unwrap()[0];
        assert_eq!(decoded, &context);
        assert_eq!(
            decoded.user_identities[0].digits().as_deref(),
            Some("208930000000001")
        );
        assert_eq!(
            decoded.user_identities[1].encrypted_imsi(),
            Some([0xab; 16])
        );
        assert_eq!(decoded.user_identities[1].digits(), None);
        // Spare bits of octet j are ignored, and port-range indicators set
        // for an IPv6 prefix are not followed.
        let ipv6 = EpsRemoteUeContext::from_bytes(&[0, 0xfa, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(
            ipv6.address,
            RemoteUeAddress::Ipv6Prefix([1, 2, 3, 4, 5, 6, 7, 8])
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
        assert!(ApnAmbr::from_bytes_strict(&[1, 2, 3]).is_none());
        assert_eq!(ApnAmbr::from_bytes(&[1, 2, 3]).unwrap().extension, None);
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
        assert!(EpsQos::from_bytes_strict(&[9, 1, 2]).is_none());
        assert_eq!(EpsQos::from_bytes(&[9, 1, 2]).unwrap().bit_rates, None);
        let mut status = NasEpsBearerContextStatus::from_bearers(&[1, 5, 15]).unwrap();
        assert_eq!(status.value, [0x22, 0x80]);
        assert_eq!(status.active_bearers(), [1, 5, 15]);
        status.set_active(1, false).unwrap();
        assert!(status.is_well_formed() && !status.is_active(1));
        assert!(NasEpsBearerContextStatus::from_bearers(&[0]).is_none());
        // TS 24.007 §11.1.4 and §11.4.2: the spare EBI(0) bit and extra
        // octets are ignored on receipt.
        let received = NasEpsBearerContextStatus::new(vec![0x21, 0x00, 0xff]);
        assert_eq!(received.active_bearers(), [5]);
        assert!(!received.is_well_formed());
        let mut short = NasEpsBearerContextStatus::new(vec![]);
        short.set_active(9, true).unwrap();
        assert_eq!(
            (short.length, short.value.as_slice()),
            (2, [0x00, 0x02].as_slice())
        );
        let hc = NasHeaderCompressionConfigurationStatus::from_not_used_ebis(&[6, 8]).unwrap();
        assert_eq!(hc.value, [0x40, 0x01]);
        assert_eq!(hc.is_configuration_used(5), Some(true));
        assert_eq!(hc.not_used_ebis(), [6, 8]);
        assert_eq!(hc.is_configuration_used(0), None);
        let mut capability = NasUeNetworkCapability::new(vec![0, 0]);
        capability.set_eea(CipheringAlgorithm::EEA2 as u8, true);
        capability.set_eia(IntegrityAlgorithm::EIA2 as u8, true);
        assert_eq!(capability.value, [0x20, 0x20]);
        assert!(capability.supports_eea(CipheringAlgorithm::EEA2 as u8));
        assert!(!capability.supports_eia(IntegrityAlgorithm::EIA1 as u8));
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
    fn pco_ignores_invalid_units_without_losing_valid_units() {
        // TS 24.008 §10.5.6.3: uplink address requests are empty, IPv4
        // Link MTU is exactly two octets in downlink, and NBIFOM mode is 0/1.
        let uplink = [
            0x80, 0x00, 0x0c, 0x01, 0xff, // invalid P-CSCF IPv4 request
            0x00, 0x0d, 0x00, // valid DNS IPv4 request
            0x00, 0x14, 0x01, 0x02, // invalid NBIFOM mode
        ];
        let parsed = Pco::from_bytes(&uplink, PcoDirection::Uplink).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].identifier, 0x000c);
        assert_eq!(parsed.entries[1].identifier, 0x000d);

        let downlink = [
            0x80, 0x00, 0x10, 0x01, 0x05, // invalid IPv4 Link MTU
            0x00, 0x0c, 0x04, 192, 0, 2, 1, // valid P-CSCF IPv4 address
        ];
        let parsed = Pco::from_bytes(&downlink, PcoDirection::Downlink).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].identifier, 0x000c);

        let invalid_sender = Pco {
            configuration_protocol: 0,
            entries: vec![PcoEntry {
                identifier: 0x0010,
                contents: vec![0x05],
            }],
        };
        assert!(invalid_sender.to_bytes(PcoDirection::Downlink).is_none());
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
    fn tai_list_ignores_spare_bits_and_reads_large_counts_as_sixteen() {
        // Table 9.9.3.33.1: bit 8 of octet 1 is spare.
        let spare = NasTaiList::new(vec![0x80, 0x02, 0xf8, 0x39, 0x12, 0x34]);
        assert_eq!(spare.tai_list().unwrap().0.len(), 1);
        assert!(!spare.is_well_formed());
        // Count 11111 is unused and read as 16 by the UE.
        let mut value = vec![0x1f, 0x02, 0xf8, 0x39];
        value.extend((0..16u16).flat_map(u16::to_be_bytes));
        let list = NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming::new(value);
        assert_eq!(list.tai_list().unwrap().0.len(), 16);
        assert!(!list.is_well_formed());
        assert!(TaiList::from_bytes_strict(&[0x00, 0x02, 0xf8, 0x39, 0, 1, 0xff]).is_none());
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
    fn tft_receiver_rules_and_error_classes() {
        // Spare bits 8-7 of the filter header, bits 8-5 of a deleted
        // filter identifier, and the flow label spare nibble are ignored.
        let received = [0x21, 0xf2, 7, 4, 0x80, 0xf1, 0x23, 0x45];
        let tft = Tft::parse(&received).unwrap();
        let filter = &tft.packet_filters[0];
        assert_eq!(
            (filter.identifier, filter.direction_value()),
            (2, TftPacketFilterDirection::Bidirectional)
        );
        assert_eq!(
            filter.components(),
            Some(vec![TftPacketFilterComponent::FlowLabel(0x12345)])
        );
        assert!(!NasTft::new(received.to_vec()).is_well_formed());
        assert_eq!(
            Tft::parse(&[0xa2, 0xf1, 0x01])
                .unwrap()
                .packet_filters
                .len(),
            2
        );
        // "Delete existing TFT" with a parameters list is accepted on receipt.
        let delete = Tft::parse(&[0x50, 0x02, 0x04, 0, 1, 0, 2]).unwrap();
        assert_eq!(
            delete.parameters[0].value(),
            TftParameterValue::FlowIdentifier {
                media_component: 1,
                ip_flow: 2
            }
        );
        assert_eq!(delete.to_bytes(), None);

        // §6.4.3.4: operation and count errors are #42, filter errors #45.
        assert_eq!(Tft::parse(&[0xe0]), Err(TftError::SyntacticalTftOperation));
        assert_eq!(
            Tft::parse(&[0x40, 0x01]),
            Err(TftError::SyntacticalTftOperation)
        );
        assert_eq!(
            Tft::parse(&[0x22, 0x21, 1, 2, 0x30, 6]),
            Err(TftError::SyntacticalTftOperation)
        );
        let reserved = Tft::parse(&[0x21, 0x21, 1, 2, 0x31, 6]).unwrap_err();
        assert_eq!(
            reserved.esm_cause(),
            EsmCause::SyntacticalErrorsInPacketFilters
        );
        // A non-IP Ethertype with an IP component, and IPv4 with IPv6 remote.
        let ether = [0x21, 0x21, 1, 5, 0x87, 0x88, 0xa8, 0x30, 6];
        assert_eq!(Tft::parse(&ether), Err(TftError::SyntacticalPacketFilter));
        let mut both = vec![0x21, 0x21, 1, 26, 0x10];
        both.extend([0; 8]);
        both.extend([0x21]);
        both.extend([0; 17]);
        assert_eq!(Tft::parse(&both), Err(TftError::SyntacticalPacketFilter));
        // Consecutive Authorization Tokens are a semantical
        // TFT error (TS 24.008 Table 10.5.162), ESM cause #41.
        let tokens = [
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0, 0, 1, 0xff, 0xff, 0xff, 0xff, 0x01, 0x01, 0xaa,
            0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ];
        let error = Tft::parse(&tokens).unwrap_err();
        assert_eq!(error, TftError::SemanticTftOperation);
        assert_eq!(error.esm_cause(), EsmCause::SemanticErrorInTheTftOperation);
        // A token without a following Flow Identifier stays syntactical.
        assert_eq!(
            Tft::parse(&tokens[..16]),
            Err(TftError::SyntacticalTftOperation)
        );

        // A received traffic flow aggregate may use assigned identifiers;
        // only the UE sender rule requires identifier 0 for new filters.
        let aggregate = NasTrafficFlowAggregate::new(vec![0x21, 0x25, 1, 2, 0x30, 17]);
        assert!(aggregate.tft().is_some() && !aggregate.is_well_formed());
        assert!(NasTrafficFlowAggregate::ignore().is_well_formed());
        // The network's TFT never uses "Ignore this IE".
        assert!(NasTft::new(vec![0x00]).tft().is_some());
        assert!(!NasTft::new(vec![0x00]).is_well_formed());

        let filter = TftPacketFilter::from_components(
            1,
            TftPacketFilterDirection::Uplink,
            3,
            &[
                TftPacketFilterComponent::Ipv4RemoteAddress {
                    address: [192, 0, 2, 0],
                    mask: [255, 255, 255, 0],
                },
                TftPacketFilterComponent::RemotePortRange {
                    low: 5060,
                    high: 5061,
                },
                TftPacketFilterComponent::CTagPcpDei { pcp: 5, dei: true },
            ],
        )
        .unwrap();
        assert_eq!(
            &filter.contents[9..],
            [0x51, 0x13, 0xc4, 0x13, 0xc5, 0x85, 0x0b]
        );
        let tft = Tft {
            operation: TftOperation::Create,
            packet_filters: vec![filter],
            parameters: vec![],
        };
        assert!(NasTft::from_tft(&tft).unwrap().is_well_formed());
        assert!(
            TftPacketFilterComponent::FlowLabel(0x10_0000)
                .to_bytes()
                .is_none()
        );
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
        // "No TFT operation" without parameters is a sender error only.
        assert!(Tft::from_bytes(&[0xc0]).is_some());
        assert!(Tft::from_bytes_strict(&[0xc0]).is_none());
        assert!(Tft::from_bytes(&[0x20]).is_none());
        assert!(Tft::from_bytes(&[0xd0]).is_none());
        assert!(Tft::from_bytes(&[0x31, 0x32, 10, 2, 0x10]).is_none());
        assert!(Tft::from_bytes(&[0x21, 0x10, 1, 1, 0x10]).is_none());
        assert!(Tft::from_bytes(&[0x22, 0x32, 1, 2, 0x30, 0x11, 0x32, 2, 2, 0x30, 0x11]).is_none());
        assert!(Tft::from_bytes(&[0x31, 0x32, 1, 2, 0x30, 0x11, 2, 1, 0]).is_none());
        // Packet filter identifier parameters use bits 4-1 only.
        let spare = [0x31, 0x32, 1, 2, 0x30, 0x11, 3, 1, 0xf1];
        assert!(Tft::from_bytes(&spare).is_some() && Tft::from_bytes_strict(&spare).is_none());
        let aggregate = [0x22, 0x30, 1, 2, 0x30, 0x11, 0x30, 2, 2, 0x30, 0x11];
        assert!(Tft::from_bytes(&aggregate).is_none());
        let aggregate_ie = NasTrafficFlowAggregate::new(aggregate.to_vec());
        let parsed = aggregate_ie.tft().unwrap();
        assert_eq!(
            NasTrafficFlowAggregate::from_tft(&parsed).unwrap().value,
            aggregate
        );
        // TS 24.008 Table 10.5.162: the contents after "Ignore this IE" are ignored.
        assert_eq!(
            Tft::from_bytes(&[0x00, 0xff]).unwrap().operation,
            TftOperation::Ignore
        );
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
        let tmsi = NasMobileIdentity::from_tmsi(0x1234_5678);
        assert_eq!(tmsi.value, [0xf4, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(tmsi.as_tmsi(), Some(0x1234_5678));
        assert!(NasMobileIdentity::new(vec![0]).is_no_identity());
    }
}
