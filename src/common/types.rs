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

use crate::common::{
    Decode, Encode, Error, Reader, Result, nas_ie_lv, nas_ie_lve, nas_ie_v, nas_ie_v_fixed,
};
use crate::prelude::*;

// ── Defined in TS 24.008, which TS 24.501 and TS 24.301 refer to ──

nas_ie_lv!(
    /// Authentication failure parameter (TS 24.008 §10.5.3.2.2;
    /// TS 24.501 §9.11.3.14, TS 24.301 §9.9.3.1).
    /// LV format.
    AuthenticationFailureParameter
);
nas_ie_lv!(
    /// Authentication parameter AUTN (TS 24.008 §10.5.3.1.1;
    /// TS 24.501 §9.11.3.15, TS 24.301 §9.9.3.2).
    /// LV format.
    AuthenticationParameterAutn
);
nas_ie_v_fixed!(
    /// Authentication parameter RAND (TS 24.008 §10.5.3.1;
    /// TS 24.501 §9.11.3.16, TS 24.301 §9.9.3.3).
    /// V format (16 bytes).
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::AuthenticationParameterRand;
    ///
    /// // The RAND of a challenge, which a `Rand` of oxirush-security takes
    /// let rand = AuthenticationParameterRand::from_rand([0x23; 16]);
    /// assert_eq!(rand.rand(), Some(&[0x23; 16]));
    /// assert_eq!(rand.to_string(), "23".repeat(16));
    /// ```
    AuthenticationParameterRand, 16
);
nas_ie_lv!(
    /// Daylight saving time (TS 24.008 §10.5.3.12; TS 24.501 §9.11.3.19, TS 24.301 §9.9.3.6).
    /// LV format.
    DaylightSavingTime
);
nas_ie_lv!(
    /// Emergency number list (TS 24.008 §10.5.3.13; TS 24.501 §9.11.3.23, TS 24.301 §9.9.3.37).
    /// LV format.
    EmergencyNumberList
);
nas_ie_lv!(
    /// Extended DRX parameters (TS 24.008 §10.5.5.32; TS 24.501 §9.11.3.26A, TS 24.301 §9.9.3.46).
    /// LV format.
    ExtendedDrxParameters
);
nas_ie_lve!(
    /// Extended protocol configuration options (TS 24.008 §10.5.6.3A;
    /// TS 24.501 §9.11.4.6, TS 24.301 §9.9.4.26).
    /// LV-E format.
    ExtendedProtocolConfigurationOptions
);
nas_ie_v!(
    /// GPRS timer (TS 24.008 §10.5.7.3; TS 24.501 §9.11.2.3, TS 24.301 §9.9.3.16).
    /// V format (1 byte).
    GprsTimer
);
nas_ie_lv!(
    /// GPRS timer 2 (TS 24.008 §10.5.7.4; TS 24.501 §9.11.2.4, TS 24.301 §9.9.3.16A). LV format.
    GprsTimer2
);
nas_ie_lv!(
    /// GPRS timer 3 (TS 24.008 §10.5.7.4a; TS 24.501 §9.11.2.5, TS 24.301 §9.9.3.16B). LV format.
    GprsTimer3
);
nas_ie_v!(
    /// IMEISV request (TS 24.008 §10.5.5.10; TS 24.501 §9.11.3.28, TS 24.301 §9.9.3.18).
    /// Half octet.
    ImeisvRequest
);
nas_ie_lv!(
    /// Mobile station classmark 2 (TS 24.008 §10.5.1.6; TS 24.501 §9.11.3.31C, TS 24.301 §9.9.2.4).
    /// LV format.
    MobileStationClassmark2
);
nas_ie_lv!(
    /// Network name (TS 24.008 §10.5.3.5a; TS 24.501 §9.11.3.35, TS 24.301 §9.9.3.24). LV format.
    NetworkName
);
nas_ie_v!(
    /// Non-3GPP NW provided policies (TS 24.008 §10.5.5.37;
    /// TS 24.501 §9.11.3.36A, TS 24.301 §9.9.3.49).
    /// Half octet.
    Non3GppNwProvidedPolicies
);
nas_ie_lv!(
    /// PLMN list (TS 24.008 §10.5.1.13; TS 24.501 §9.11.3.45, TS 24.301 §9.9.2.8). LV format.
    PlmnList
);
nas_ie_lv!(
    /// Supported codec list (TS 24.008 §10.5.4.32; TS 24.501 §9.11.3.51A, TS 24.301 §9.9.2.10).
    /// LV format.
    SupportedCodecList
);
nas_ie_v!(
    /// Time zone (TS 24.008 §10.5.3.8; TS 24.501 §9.11.3.52, TS 24.301 §9.9.3.29).
    /// V format (1 byte).
    TimeZone
);
nas_ie_v_fixed!(
    /// Time zone and time (TS 24.008 §10.5.3.9; TS 24.501 §9.11.3.53, TS 24.301 §9.9.3.30).
    /// V format (7 bytes: Y/M/D/H/M/S/TZ).
    TimeZoneAndTime, 7
);
crate::common::ts24008::gprs_timer_ie!(GprsTimer, false);

crate::common::ts24008::time_zone_and_time_ie!(TimeZoneAndTime);

// ── Defined in TS 24.301, which TS 24.501 refers to ──

nas_ie_lv!(
    /// Access technology utilization control (TS 24.301 §9.9.3.3A; TS 24.501 §9.11.3.110).
    /// LV format.
    AccessTechnologyUtilizationControl
);
nas_ie_lv!(
    /// Authentication response parameter (TS 24.301 §9.9.3.4; TS 24.501 §9.11.3.17). LV format.
    ///
    /// RES of EPS, or RES\* of 5GS. Both are keys of the challenge: `Debug`
    /// and the `Display` of a message print their length alone.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::AuthenticationResponseParameter;
    ///
    /// // RES* has 16 octets, and RES 4 to 16
    /// let parameter = AuthenticationResponseParameter::from_res_star([0xab; 16]);
    /// assert_eq!(parameter.res_star(), Some(&[0xab; 16]));
    /// let res = AuthenticationResponseParameter::from_res(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
    /// assert_eq!(res.res(), [1, 2, 3, 4, 5, 6, 7, 8]);
    /// assert!(AuthenticationResponseParameter::from_res(&[1, 2, 3]).is_err());
    ///
    /// // `{:?}` shows how long it is, and not what it is
    /// assert_eq!(
    ///     format!("{parameter:?}"),
    ///     "AuthenticationResponseParameter { value: hidden (16 octets) }"
    /// );
    /// ```
    AuthenticationResponseParameter, own_debug
);
/// RES and RES\*, by their length.
impl core::fmt::Debug for AuthenticationResponseParameter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        crate::common::display::hidden_octets(f, "AuthenticationResponseParameter", &self.value)
    }
}

/// A key by its length alone: `hidden (16 octets)`.
impl core::fmt::Display for AuthenticationResponseParameter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&crate::common::display::Hidden(self.value.len()), f)
    }
}
nas_ie_lv!(
    /// EPS bearer context status (TS 24.301 §9.9.2.1; TS 24.501 §9.11.3.23A). LV format.
    EpsBearerContextStatus
);
nas_ie_lve!(
    /// Extended emergency number list (TS 24.301 §9.9.3.37A; TS 24.501 §9.11.3.26). LV-E format.
    ExtendedEmergencyNumberList
);
nas_ie_v!(
    /// Release assistance indication (TS 24.301 §9.9.4.25; TS 24.501 §9.11.3.46A). Half octet.
    ReleaseAssistanceIndication
);
nas_ie_lv!(
    /// Serving PLMN rate control (TS 24.301 §9.9.4.28; TS 24.501 §9.11.4.20). LV format.
    ServingPlmnRateControl
);
nas_ie_lv!(
    /// UE request type (TS 24.301 §9.9.3.65; TS 24.501 §9.11.3.76). LV format.
    UeRequestType
);
nas_ie_lv!(
    /// Unavailability configuration (TS 24.301 §9.9.3.70; TS 24.501 §9.11.2.21). LV format.
    UnavailabilityConfiguration
);
nas_ie_lv!(
    /// Unavailability information (TS 24.301 §9.9.3.69; TS 24.501 §9.11.2.20). LV format.
    UnavailabilityInformation
);
nas_ie_lv!(
    /// WUS assistance information (TS 24.301 §9.9.3.62; TS 24.501 §9.11.3.71). LV format.
    WusAssistanceInformation
);

// ── Defined in TS 24.501, which TS 24.301 refers to ──

nas_ie_lv!(
    /// List of PLMNs to be used in disaster condition (TS 24.501 §9.11.3.83; TS 24.301 §9.9.3.76).
    /// LV format.
    ListOfPlmnsToBeUsedInDisasterCondition
);
nas_ie_lv!(
    /// PLMN identity (TS 24.501 §9.11.3.85; TS 24.301 §9.9.3.77). LV format.
    PlmnIdentity
);
nas_ie_lv!(
    /// Registration wait range (TS 24.501 §9.11.3.84; TS 24.301 §9.9.3.75). LV format.
    RegistrationWaitRange
);
nas_ie_lv!(
    /// UE radio capability ID (TS 24.501 §9.11.3.68; TS 24.301 §9.9.3.60). LV format.
    UeRadioCapabilityId
);
nas_ie_v!(
    /// UE radio capability ID deletion indication (TS 24.501 §9.11.3.69; TS 24.301 §9.9.3.61).
    /// Half octet.
    UeRadioCapabilityIdDeletionIndication
);
nas_ie_lv!(
    /// UE status (TS 24.501 §9.11.3.56; TS 24.301 §9.9.3.54). LV format.
    UeStatus
);

// ── Methods beyond the grammars ──

impl RegistrationWaitRange {
    /// Minimum registration wait time as a GPRS timer.
    pub fn min_timer(&self) -> Option<GprsTimer> {
        self.value.first().copied().map(GprsTimer::new)
    }

    /// Maximum registration wait time as a GPRS timer.
    pub fn max_timer(&self) -> Option<GprsTimer> {
        self.value.get(1).copied().map(GprsTimer::new)
    }

    /// Build from minimum and maximum GPRS timers.
    pub fn from_timers(min_timer: GprsTimer, max_timer: GprsTimer) -> Self {
        Self::new(vec![min_timer.value, max_timer.value])
    }
}

impl Default for TimeZoneAndTime {
    /// Default: all-zero 7-byte payload (year=0, month=0, ... tz=0).
    fn default() -> Self {
        Self::new(vec![0u8; 7])
    }
}

impl Default for ExtendedDrxParameters {
    fn default() -> Self {
        Self::new(vec![0])
    }
}

impl Default for NetworkName {
    /// Default: extension bit set, GSM 7-bit coding, no Add CI, no spare bits, empty name.
    fn default() -> Self {
        Self::new(vec![0x80])
    }
}

// ── Checks ──

// The rules of the IE types that `validate()` checks: the value lengths of
// their clauses, the values that a sender sets, and a receiver's grammar.
crate::common::ie_rules! {
    AccessTechnologyUtilizationControl: lengths(0, 3), sender;
    AuthenticationFailureParameter: lengths(14, 14), display;
    AuthenticationParameterAutn: lengths(16, 16), display;
    AuthenticationParameterRand: display;
    AuthenticationResponseParameter: lengths(4, 16), display;
    DaylightSavingTime: lengths(1, 1), sender;
    EmergencyNumberList: lengths(3, 48), sender;
    EpsBearerContextStatus: lengths(2, 2), sender, display;
    ExtendedDrxParameters: lengths(1, 2), sender;
    ExtendedEmergencyNumberList: lengths(4, 65535), sender;
    ExtendedProtocolConfigurationOptions: lengths(1, 65535);
    GprsTimer: display;
    GprsTimer2: lengths(1, 1), sender, display;
    GprsTimer3: lengths(1, 1), sender, display;
    ImeisvRequest: sender(0 | 1);
    ListOfPlmnsToBeUsedInDisasterCondition: lengths(0, usize::MAX), sender;
    MobileStationClassmark2: lengths(3, 3), sender;
    NetworkName: lengths(1, usize::MAX), sender, display;
    Non3GppNwProvidedPolicies: sender(0 | 1);
    PlmnIdentity: lengths(3, 3), sender;
    PlmnList: lengths(3, 45), sender;
    RegistrationWaitRange: lengths(2, 2), sender;
    ReleaseAssistanceIndication: sender(0..=2);
    ServingPlmnRateControl: lengths(2, 2), sender;
    SupportedCodecList: lengths(3, usize::MAX), sender;
    TimeZone: sender, display;
    TimeZoneAndTime: sender;
    UeRadioCapabilityId: lengths(1, usize::MAX);
    UeRadioCapabilityIdDeletionIndication;
    UeRequestType: lengths(1, 1), sender;
    UeStatus: lengths(1, 1), sender;
    UnavailabilityConfiguration: lengths(1, 7), sender;
    UnavailabilityInformation: lengths(1, 7), sender;
    WusAssistanceInformation: lengths(1, 1), sender;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::IeRules;

    /// A receiver takes authentication parameters of their length at least, and timers
    /// that have a value.
    #[test]
    fn a_receiver_takes_parameters_of_their_length() {
        let ok = |check: &dyn IeRules| check.receiver_length_ok();
        for (length, taken) in [(14, true), (13, false)] {
            assert_eq!(
                ok(&AuthenticationFailureParameter::new(vec![0; length])),
                taken
            );
        }
        for (length, taken) in [(16, true), (15, false)] {
            assert_eq!(
                ok(&AuthenticationParameterAutn::new(vec![0; length])),
                taken
            );
        }
        for (length, taken) in [(4, true), (3, false)] {
            assert_eq!(
                ok(&AuthenticationResponseParameter::new(vec![0; length])),
                taken
            );
        }
        for (length, taken) in [(1, true), (0, false)] {
            assert_eq!(ok(&GprsTimer2::new(vec![0x21; length])), taken);
            assert_eq!(ok(&GprsTimer3::new(vec![0x21; length])), taken);
        }
    }
}
