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

//! The IE types that one NAS specification defines and the other reuses:
//! one type for both protocols, which `nas_5gs` and `nas_eps` re-export.

use crate::common::Plmn;
use crate::common::ts24008::*;
use crate::common::ts24301::*;
use crate::common::ts24501::*;
use crate::common::{
    Decode, Encode, NasError, Reader, Result, nas_ie_lv, nas_ie_lve, nas_ie_tv1, nas_ie_v,
    nas_ie_v_fixed,
};
use crate::prelude::*;

// ── Defined in TS 24.008, which TS 24.501 and TS 24.301 refer to ──

nas_ie_lv!(
    /// Authentication failure parameter (TS 24.008 §10.5.3.2.2;
    /// TS 24.501 §9.11.3.14, TS 24.301 §9.9.3.1).
    /// LV format.
    NasAuthenticationFailureParameter
);
nas_ie_lv!(
    /// Authentication parameter AUTN (TS 24.008 §10.5.3.1.1;
    /// TS 24.501 §9.11.3.15, TS 24.301 §9.9.3.2).
    /// LV format.
    NasAuthenticationParameterAutn
);
nas_ie_v_fixed!(
    /// Authentication parameter RAND (TS 24.008 §10.5.3.1;
    /// TS 24.501 §9.11.3.16, TS 24.301 §9.9.3.3).
    /// V format (16 bytes).
    NasAuthenticationParameterRand, 16
);
nas_ie_lv!(
    /// Daylight saving time (TS 24.008 §10.5.3.12; TS 24.501 §9.11.3.19, TS 24.301 §9.9.3.6).
    /// LV format.
    NasDaylightSavingTime
);
nas_ie_lv!(
    /// Emergency number list (TS 24.008 §10.5.3.13; TS 24.501 §9.11.3.23, TS 24.301 §9.9.3.37).
    /// LV format.
    NasEmergencyNumberList
);
nas_ie_lv!(
    /// Extended DRX parameters (TS 24.008 §10.5.5.32; TS 24.501 §9.11.3.26A, TS 24.301 §9.9.3.46).
    /// LV format.
    NasExtendedDrxParameters
);
nas_ie_lve!(
    /// Extended protocol configuration options (TS 24.008 §10.5.6.3A;
    /// TS 24.501 §9.11.4.6, TS 24.301 §9.9.4.26).
    /// LV-E format.
    NasExtendedProtocolConfigurationOptions
);
nas_ie_v!(
    /// GPRS timer (TS 24.008 §10.5.7.3; TS 24.501 §9.11.2.3, TS 24.301 §9.9.3.16).
    /// V format (1 byte).
    NasGprsTimer
);
nas_ie_lv!(
    /// GPRS timer 2 (TS 24.008 §10.5.7.4; TS 24.501 §9.11.2.4, TS 24.301 §9.9.3.16A). LV format.
    NasGprsTimer2
);
nas_ie_lv!(
    /// GPRS timer 3 (TS 24.008 §10.5.7.4a; TS 24.501 §9.11.2.5, TS 24.301 §9.9.3.16B). LV format.
    NasGprsTimer3
);
nas_ie_tv1!(
    /// IMEISV request (TS 24.008 §10.5.5.10; TS 24.501 §9.11.3.28, TS 24.301 §9.9.3.18).
    /// Half octet.
    NasImeisvRequest
);
nas_ie_lv!(
    /// Mobile station classmark 2 (TS 24.008 §10.5.1.6; TS 24.501 §9.11.3.31C, TS 24.301 §9.9.2.4).
    /// LV format.
    NasMobileStationClassmark2
);
nas_ie_lv!(
    /// Network name (TS 24.008 §10.5.3.5a; TS 24.501 §9.11.3.35, TS 24.301 §9.9.3.24). LV format.
    NasNetworkName
);
nas_ie_tv1!(
    /// Non-3GPP NW provided policies (TS 24.008 §10.5.5.37;
    /// TS 24.501 §9.11.3.36A, TS 24.301 §9.9.3.49).
    /// Half octet.
    NasNon3GppNwProvidedPolicies
);
nas_ie_lv!(
    /// PLMN list (TS 24.008 §10.5.1.13; TS 24.501 §9.11.3.45, TS 24.301 §9.9.2.8). LV format.
    NasPlmnList
);
nas_ie_lv!(
    /// Supported codec list (TS 24.008 §10.5.4.32; TS 24.501 §9.11.3.51A, TS 24.301 §9.9.2.10).
    /// LV format.
    NasSupportedCodecList
);
nas_ie_v!(
    /// Time zone (TS 24.008 §10.5.3.8; TS 24.501 §9.11.3.52, TS 24.301 §9.9.3.29).
    /// V format (1 byte).
    NasTimeZone
);
nas_ie_v_fixed!(
    /// Time zone and time (TS 24.008 §10.5.3.9; TS 24.501 §9.11.3.53, TS 24.301 §9.9.3.30).
    /// V format (7 bytes: Y/M/D/H/M/S/TZ).
    NasTimeZoneAndTime, 7
);
crate::common::ts24008::gprs_timer_ie!(NasGprsTimer, false);
crate::common::ts24008::gprs_timer_2_ie!(NasGprsTimer2);
crate::common::ts24008::gprs_timer_3_ie!(NasGprsTimer3);
crate::common::ts24008::plmn_list_ie!(NasPlmnList);
crate::common::ts24008::network_name_ie!(NasNetworkName);
crate::common::ts24008::time_zone_ie!(NasTimeZone);
crate::common::ts24008::time_zone_and_time_ie!(NasTimeZoneAndTime);
crate::common::ts24008::daylight_saving_time_ie!(NasDaylightSavingTime);
crate::common::ts24008::emergency_number_list_ie!(NasEmergencyNumberList);
crate::common::ts24008::extended_drx_parameters_ie!(NasExtendedDrxParameters);
crate::common::ts24008::supported_codec_list_ie!(NasSupportedCodecList);
crate::common::nas_opaque_ie!(NasSupportedCodecList, "24.008", "10.5.4.32");
crate::common::ts24008::extended_protocol_configuration_options_ie!(
    NasExtendedProtocolConfigurationOptions
);
crate::common::ts24008::imeisv_request_ie!(NasImeisvRequest);
crate::common::ts24008::non_3gpp_nw_provided_policies_ie!(NasNon3GppNwProvidedPolicies);
crate::common::ts24008::authentication_parameter_rand_ie!(NasAuthenticationParameterRand);
crate::common::ts24008::authentication_parameter_autn_ie!(NasAuthenticationParameterAutn);
crate::common::ts24008::authentication_failure_parameter_ie!(NasAuthenticationFailureParameter);
crate::common::ts24008::mobile_station_classmark_2_ie!(NasMobileStationClassmark2);
crate::common::nas_opaque_ie!(NasAuthenticationFailureParameter, "24.008", "10.5.3.2.2");
crate::common::nas_opaque_ie!(NasAuthenticationParameterAutn, "24.008", "10.5.3.1.1");

// ── Defined in TS 24.301, which TS 24.501 refers to ──

nas_ie_lv!(
    /// Access technology utilization control (TS 24.301 §9.9.3.3A; TS 24.501 §9.11.3.110).
    /// LV format.
    NasAccessTechnologyUtilizationControl
);
nas_ie_lv!(
    /// Authentication response parameter (TS 24.301 §9.9.3.4; TS 24.501 §9.11.3.17). LV format.
    NasAuthenticationResponseParameter
);
nas_ie_lv!(
    /// EPS bearer context status (TS 24.301 §9.9.2.1; TS 24.501 §9.11.3.23A). LV format.
    NasEpsBearerContextStatus
);
nas_ie_lve!(
    /// Extended emergency number list (TS 24.301 §9.9.3.37A; TS 24.501 §9.11.3.26). LV-E format.
    NasExtendedEmergencyNumberList
);
nas_ie_tv1!(
    /// Release assistance indication (TS 24.301 §9.9.4.25; TS 24.501 §9.11.3.46A). Half octet.
    NasReleaseAssistanceIndication
);
nas_ie_lv!(
    /// Serving PLMN rate control (TS 24.301 §9.9.4.28; TS 24.501 §9.11.4.20). LV format.
    NasServingPlmnRateControl
);
nas_ie_lv!(
    /// UE request type (TS 24.301 §9.9.3.65; TS 24.501 §9.11.3.76). LV format.
    NasUeRequestType
);
nas_ie_lv!(
    /// Unavailability configuration (TS 24.301 §9.9.3.70; TS 24.501 §9.11.2.21). LV format.
    NasUnavailabilityConfiguration
);
nas_ie_lv!(
    /// Unavailability information (TS 24.301 §9.9.3.69; TS 24.501 §9.11.2.20). LV format.
    NasUnavailabilityInformation
);
nas_ie_lv!(
    /// WUS assistance information (TS 24.301 §9.9.3.62; TS 24.501 §9.11.3.71). LV format.
    NasWusAssistanceInformation
);
crate::common::ts24301::extended_emergency_number_list_ie!(NasExtendedEmergencyNumberList);
crate::common::ts24301::wus_assistance_information_ie!(NasWusAssistanceInformation);
crate::common::nas_opaque_ie!(NasWusAssistanceInformation, "24.301", "9.9.3.62");
crate::common::ts24301::ue_request_type_ie!(NasUeRequestType);
crate::common::nas_opaque_ie!(NasUeRequestType, "24.301", "9.9.3.65");
crate::common::ts24301::unavailability_information_ie!(NasUnavailabilityInformation);
crate::common::nas_opaque_ie!(NasUnavailabilityInformation, "24.301", "9.9.3.69");
crate::common::ts24301::unavailability_configuration_ie!(NasUnavailabilityConfiguration);
crate::common::nas_opaque_ie!(NasUnavailabilityConfiguration, "24.301", "9.9.3.70");
crate::common::ts24301::access_technology_utilization_control_ie!(
    NasAccessTechnologyUtilizationControl
);
crate::common::nas_opaque_ie!(NasAccessTechnologyUtilizationControl, "24.301", "9.9.3.3A");
crate::common::ts24301::eps_bearer_context_status_ie!(NasEpsBearerContextStatus);
crate::common::ts24301::serving_plmn_rate_control_ie!(NasServingPlmnRateControl);
crate::common::ts24301::release_assistance_indication_ie!(NasReleaseAssistanceIndication);
crate::common::ts24301::authentication_response_parameter_ie!(NasAuthenticationResponseParameter);
crate::common::nas_opaque_ie!(NasAuthenticationResponseParameter, "24.301", "9.9.3.4");

// ── Defined in TS 24.501, which TS 24.301 refers to ──

nas_ie_lv!(
    /// List of PLMNs to be used in disaster condition (TS 24.501 §9.11.3.83; TS 24.301 §9.9.3.76).
    /// LV format.
    NasListOfPlmnsToBeUsedInDisasterCondition
);
nas_ie_lv!(
    /// PLMN identity (TS 24.501 §9.11.3.85; TS 24.301 §9.9.3.77). LV format.
    NasPlmnIdentity
);
nas_ie_lv!(
    /// Registration wait range (TS 24.501 §9.11.3.84; TS 24.301 §9.9.3.75). LV format.
    NasRegistrationWaitRange
);
nas_ie_lv!(
    /// UE radio capability ID (TS 24.501 §9.11.3.68; TS 24.301 §9.9.3.60). LV format.
    NasUeRadioCapabilityId
);
nas_ie_tv1!(
    /// UE radio capability ID deletion indication (TS 24.501 §9.11.3.69; TS 24.301 §9.9.3.61).
    /// Half octet.
    NasUeRadioCapabilityIdDeletionIndication
);
nas_ie_lv!(
    /// UE status (TS 24.501 §9.11.3.56; TS 24.301 §9.9.3.54). LV format.
    NasUeStatus
);
crate::common::ts24501::ue_radio_capability_id_ie!(NasUeRadioCapabilityId);
crate::common::nas_opaque_ie!(NasUeRadioCapabilityId, "24.501", "9.11.3.68");
crate::common::ts24501::ue_radio_capability_id_deletion_indication_ie!(
    NasUeRadioCapabilityIdDeletionIndication
);
crate::common::ts24501::plmn_identity_ie!(NasPlmnIdentity);
crate::common::ts24501::registration_wait_range_ie!(NasRegistrationWaitRange);
crate::common::ts24501::disaster_plmn_list_ie!(NasListOfPlmnsToBeUsedInDisasterCondition);
crate::common::nas_opaque_ie!(
    NasListOfPlmnsToBeUsedInDisasterCondition,
    "24.501",
    "9.11.3.83"
);
crate::common::ts24501::ue_status_ie!(NasUeStatus);
crate::common::nas_opaque_ie!(NasRegistrationWaitRange, "24.501", "9.11.3.84");
crate::common::nas_opaque_ie!(NasPlmnIdentity, "24.501", "9.11.3.85");

// ── Methods beyond the grammars ──

impl NasGprsTimer3 {
    /// T3512 value as the UE interprets it: unit 110 means 320 hours when
    /// the carrying message is integrity protected and 1 hour otherwise
    /// (TS 24.008 Table 10.5.163a NOTE 1), and a zero value deactivates the
    /// timer (TS 24.501 §5.3.7). `None` when the value octet is missing.
    pub fn t3512_value_for_ue(&self, integrity_protected: bool) -> Option<GprsTimerValue> {
        let (unit, value) = self.timer()?;
        Some(match unit {
            GprsTimer3Unit::Deactivated => GprsTimerValue::Deactivated,
            _ if value == 0 => GprsTimerValue::Deactivated,
            GprsTimer3Unit::ThreeHundredTwentyHours if !integrity_protected => {
                GprsTimerValue::Seconds(3_600 * u64::from(value))
            }
            unit => GprsTimerValue::Seconds(unit.seconds_multiplier() * u64::from(value)),
        })
    }
}

impl NasRegistrationWaitRange {
    /// Minimum registration wait time as a GPRS timer.
    pub fn min_timer(&self) -> Option<NasGprsTimer> {
        self.value.first().copied().map(NasGprsTimer::new)
    }

    /// Maximum registration wait time as a GPRS timer.
    pub fn max_timer(&self) -> Option<NasGprsTimer> {
        self.value.get(1).copied().map(NasGprsTimer::new)
    }

    /// Build from minimum and maximum GPRS timers.
    pub fn from_timers(min_timer: NasGprsTimer, max_timer: NasGprsTimer) -> Self {
        Self::new(vec![min_timer.value, max_timer.value])
    }
}

impl Default for NasTimeZoneAndTime {
    /// Default: all-zero 7-byte payload (year=0, month=0, ... tz=0).
    fn default() -> Self {
        Self::new(vec![0u8; 7])
    }
}

impl Default for NasExtendedDrxParameters {
    fn default() -> Self {
        Self::new(vec![0])
    }
}

impl Default for NasNetworkName {
    /// Default: extension bit set, GSM 7-bit coding, no Add CI, no spare bits, empty name.
    fn default() -> Self {
        Self::new(vec![0x80])
    }
}

// ── Checks ──

// The sender rules of the types: `is_well_formed()`, or the values a sender
// may set.
crate::common::sender_checked!(
    NasAccessTechnologyUtilizationControl,
    NasDaylightSavingTime,
    NasEmergencyNumberList,
    NasEpsBearerContextStatus,
    NasExtendedDrxParameters,
    NasExtendedEmergencyNumberList,
    NasGprsTimer2,
    NasGprsTimer3,
    NasImeisvRequest => 0 | 1,
    NasListOfPlmnsToBeUsedInDisasterCondition,
    NasMobileStationClassmark2,
    NasNetworkName,
    NasNon3GppNwProvidedPolicies => 0 | 1,
    NasPlmnIdentity,
    NasPlmnList,
    NasRegistrationWaitRange,
    NasReleaseAssistanceIndication => 0..=2,
    NasServingPlmnRateControl,
    NasSupportedCodecList,
    NasTimeZone,
    NasTimeZoneAndTime,
    NasUeRequestType,
    NasUeStatus,
    NasUnavailabilityConfiguration,
    NasUnavailabilityInformation,
    NasWusAssistanceInformation,
);

// The value lengths of the clauses that define the types: a receiver needs
// the minimum, a sender stays within both.
crate::common::ie_length_checked!(
    NasAccessTechnologyUtilizationControl => 0, 3,
    NasAuthenticationFailureParameter => 14, 14,
    NasAuthenticationParameterAutn => 16, 16,
    NasAuthenticationResponseParameter => 4, 16,
    NasDaylightSavingTime => 1, 1,
    NasEmergencyNumberList => 3, 48,
    NasEpsBearerContextStatus => 2, 2,
    NasExtendedDrxParameters => 1, 2,
    NasExtendedEmergencyNumberList => 4, 65535,
    NasExtendedProtocolConfigurationOptions => 1, 65535,
    NasGprsTimer2 => 1, 1,
    NasGprsTimer3 => 1, 1,
    NasListOfPlmnsToBeUsedInDisasterCondition => 0, usize::MAX,
    NasMobileStationClassmark2 => 3, 3,
    NasNetworkName => 1, usize::MAX,
    NasPlmnIdentity => 3, 3,
    NasPlmnList => 3, 45,
    NasRegistrationWaitRange => 2, 2,
    NasServingPlmnRateControl => 2, 2,
    NasSupportedCodecList => 3, usize::MAX,
    NasUeRadioCapabilityId => 1, usize::MAX,
    NasUeRequestType => 1, 1,
    NasUeStatus => 1, 1,
    NasUnavailabilityConfiguration => 1, 7,
    NasUnavailabilityInformation => 1, 7,
    NasWusAssistanceInformation => 1, 1,
);

impl crate::common::ReceiverSyntaxCheck for NasAuthenticationFailureParameter {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 14
    }
}

impl crate::common::ReceiverSyntaxCheck for NasAuthenticationParameterAutn {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 16
    }
}

impl crate::common::ReceiverSyntaxCheck for NasAuthenticationResponseParameter {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 4
    }
}

// TS 24.007 §11.4.2: extra value octets are receiver-tolerated, but an
// empty timer value is a syntactically incorrect optional IE.
impl crate::common::ReceiverSyntaxCheck for NasGprsTimer2 {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl crate::common::ReceiverSyntaxCheck for NasGprsTimer3 {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}
