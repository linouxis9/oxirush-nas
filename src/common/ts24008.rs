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

//! Value grammars defined in TS 24.008 and delegated to by both NAS protocols.
//!
//! TS 24.301 and TS 24.501 refer several IEs to the same TS 24.008 clause.
//! The macros here add one implementation of each grammar to the EPS type
//! and its 5GS counterpart. Typed getters follow the receiver rules of
//! TS 24.007 §11.1.4 and §11.4.2; `is_well_formed()` checks sender rules.

// ── Authentication parameters (§10.5.3.1, §10.5.3.1.1, §10.5.3.2.2) ─────────

/// Authentication parameter RAND (TS 24.008 §10.5.3.1): a 128-bit value.
macro_rules! authentication_parameter_rand_ie {
    ($name:ident) => {
        impl $name {
            /// The RAND octets.
            pub fn rand(&self) -> &[u8] {
                &self.value
            }

            /// The 16-octet RAND, or `None` if fewer octets are present.
            pub fn rand_array(&self) -> Option<[u8; 16]> {
                self.value.get(..16)?.try_into().ok()
            }

            /// Build from a 16-octet RAND.
            pub fn from_rand(rand: [u8; 16]) -> Self {
                Self::new(rand.to_vec())
            }
        }
    };
}

/// Authentication parameter AUTN (TS 24.008 §10.5.3.1.1):
/// SQN ⊕ AK (6 octets) ‖ AMF (2 octets) ‖ MAC (8 octets).
macro_rules! authentication_parameter_autn_ie {
    ($name:ident) => {
        impl $name {
            /// The AUTN octets.
            pub fn autn(&self) -> &[u8] {
                &self.value
            }

            /// The 16-octet AUTN; octets beyond 16 are ignored.
            pub fn autn_array(&self) -> Option<[u8; 16]> {
                self.value.get(..16)?.try_into().ok()
            }

            /// SQN ⊕ AK (AUTN octets 1 to 6).
            pub fn sqn_xor_ak(&self) -> Option<&[u8]> {
                self.value.get(..6)
            }

            /// Authentication management field (AUTN octets 7 and 8).
            pub fn amf_field(&self) -> Option<[u8; 2]> {
                self.value.get(6..8)?.try_into().ok()
            }

            /// AMF separation bit (bit 8 of AUTN octet 7, TS 33.401 §6.1.1),
            /// set for authentication vectors computed for E-UTRAN and 5GS.
            pub fn amf_separation_bit(&self) -> Option<bool> {
                self.value.get(6).map(|octet| octet & 0x80 != 0)
            }

            /// MAC (AUTN octets 9 to 16).
            pub fn mac_a(&self) -> Option<&[u8]> {
                self.value.get(8..16)
            }

            /// Build from a 16-octet AUTN.
            pub fn from_autn(autn: [u8; 16]) -> Self {
                Self::new(autn.to_vec())
            }
        }
    };
}

/// Authentication failure parameter (TS 24.008 §10.5.3.2.2):
/// AUTS = SQN_MS ⊕ AK (6 octets) ‖ MAC-S (8 octets).
macro_rules! authentication_failure_parameter_ie {
    ($name:ident) => {
        impl $name {
            /// The AUTS octets.
            pub fn auts(&self) -> &[u8] {
                &self.value
            }

            /// The 14-octet AUTS; octets beyond 14 are ignored.
            pub fn auts_array(&self) -> Option<[u8; 14]> {
                self.value.get(..14)?.try_into().ok()
            }

            /// SQN_MS ⊕ AK (AUTS octets 1 to 6).
            pub fn sqn_xor_aks(&self) -> Option<&[u8]> {
                self.value.get(..6)
            }

            /// MAC-S (AUTS octets 7 to 14).
            pub fn mac_s(&self) -> Option<&[u8]> {
                self.value.get(6..14)
            }

            /// Build from a 14-octet AUTS.
            pub fn from_auts(auts: [u8; 14]) -> Self {
                Self::new(auts.to_vec())
            }
        }
    };
}

// ── GPRS timers (§10.5.7.3, §10.5.7.4, §10.5.7.4a) ──────────────────────────

/// Unit of a GPRS timer or GPRS timer 2 value (TS 24.008 §10.5.7.3).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum GprsTimerUnit {
    /// Value is incremented in multiples of 2 seconds.
    TwoSeconds = 0,
    /// Value is incremented in multiples of 1 minute.
    OneMinute = 1,
    /// Value is incremented in multiples of decihours.
    SixMinutes = 2,
    /// Timer is deactivated.
    Deactivated = 7,
}

impl GprsTimerUnit {
    /// Decode bits 8-6 with the receiver rule: other values are interpreted
    /// as multiples of 1 minute. Always returns `Some`.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(Self::from_u8_strict(v).unwrap_or(Self::OneMinute))
    }

    /// Decode only the defined unit codes.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x07 {
            0 => Some(Self::TwoSeconds),
            1 => Some(Self::OneMinute),
            2 => Some(Self::SixMinutes),
            7 => Some(Self::Deactivated),
            _ => None,
        }
    }

    /// Seconds per timer value step; zero when deactivated.
    pub fn seconds_multiplier(self) -> u64 {
        match self {
            Self::TwoSeconds => 2,
            Self::OneMinute => 60,
            Self::SixMinutes => 360,
            Self::Deactivated => 0,
        }
    }
}

/// Unit of a GPRS timer 3 value (TS 24.008 §10.5.7.4a).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum GprsTimer3Unit {
    /// Value is incremented in multiples of 10 minutes.
    TenMinutes = 0,
    /// Value is incremented in multiples of 1 hour.
    OneHour = 1,
    /// Value is incremented in multiples of 10 hours.
    TenHours = 2,
    /// Value is incremented in multiples of 2 seconds.
    TwoSeconds = 3,
    /// Value is incremented in multiples of 30 seconds.
    ThirtySeconds = 4,
    /// Value is incremented in multiples of 1 minute.
    OneMinute = 5,
    /// Value is incremented in multiples of 320 hours; only defined for the
    /// T3312 extended, T3412 extended, and T3512 values.
    ThreeHundredTwentyHours = 6,
    /// Timer is deactivated.
    Deactivated = 7,
}

impl GprsTimer3Unit {
    /// Decode bits 8-6; every code is defined.
    pub fn from_u8(v: u8) -> Self {
        match v & 0x07 {
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

    /// Decode bits 8-6; provided for naming symmetry with other value enums.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        Some(Self::from_u8(v))
    }

    /// Seconds per timer value step; zero when deactivated.
    pub fn seconds_multiplier(self) -> u64 {
        match self {
            Self::TwoSeconds => 2,
            Self::ThirtySeconds => 30,
            Self::OneMinute => 60,
            Self::TenMinutes => 600,
            Self::OneHour => 3_600,
            Self::TenHours => 36_000,
            Self::ThreeHundredTwentyHours => 1_152_000,
            Self::Deactivated => 0,
        }
    }
}

/// Encode a duration as the smallest exact GPRS timer octet; `None` when
/// the duration cannot be represented.
pub(crate) fn gprs_timer_octet_from_seconds(seconds: u64) -> Option<u8> {
    [
        GprsTimerUnit::TwoSeconds,
        GprsTimerUnit::OneMinute,
        GprsTimerUnit::SixMinutes,
    ]
    .into_iter()
    .find_map(|unit| {
        let step = unit.seconds_multiplier();
        (seconds.is_multiple_of(step) && seconds / step <= 31)
            .then(|| (unit as u8) << 5 | (seconds / step) as u8)
    })
}

/// Encode a duration as the smallest exact GPRS timer 3 octet, excluding
/// the 320-hour unit; `None` when the duration cannot be represented.
pub(crate) fn gprs_timer3_octet_from_seconds(seconds: u64) -> Option<u8> {
    [
        GprsTimer3Unit::TwoSeconds,
        GprsTimer3Unit::ThirtySeconds,
        GprsTimer3Unit::OneMinute,
        GprsTimer3Unit::TenMinutes,
        GprsTimer3Unit::OneHour,
        GprsTimer3Unit::TenHours,
    ]
    .into_iter()
    .find_map(|unit| {
        let step = unit.seconds_multiplier();
        (seconds.is_multiple_of(step) && seconds / step <= 31)
            .then(|| (unit as u8) << 5 | (seconds / step) as u8)
    })
}

/// Decoded value of a GPRS timer IE.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum GprsTimerValue {
    /// The timer is deactivated.
    Deactivated,
    /// The timer runs for this many seconds, possibly zero.
    Seconds(u64),
}

/// One-octet GPRS timer IEs (TS 24.008 §10.5.7.3) carried as V or TV.
/// `$zero_deactivated` applies TS 24.301 §5.3.5 to T3412.
macro_rules! gprs_timer_ie {
    ($name:ident, $zero_deactivated:expr) => {
        impl $name {
            /// Timer unit with the receiver rule applied (bits 8-6).
            pub fn unit(&self) -> Option<crate::common::ts24008::GprsTimerUnit> {
                crate::common::ts24008::GprsTimerUnit::from_u8(self.value >> 5)
            }

            /// Raw timer unit code.
            pub fn unit_raw(&self) -> u8 {
                self.value >> 5
            }

            /// Timer value in bits 5-1.
            pub fn timer_value(&self) -> u8 {
                self.value & 0x1f
            }

            /// Whether the timer is deactivated.
            pub fn is_deactivated(&self) -> bool {
                self.unit() == Some(crate::common::ts24008::GprsTimerUnit::Deactivated)
                    || ($zero_deactivated && self.timer_value() == 0)
            }

            /// Decoded timer value.
            pub fn value(&self) -> crate::common::ts24008::GprsTimerValue {
                if self.is_deactivated() {
                    return crate::common::ts24008::GprsTimerValue::Deactivated;
                }
                let unit = self
                    .unit()
                    .unwrap_or(crate::common::ts24008::GprsTimerUnit::OneMinute);
                crate::common::ts24008::GprsTimerValue::Seconds(
                    unit.seconds_multiplier() * u64::from(self.timer_value()),
                )
            }

            /// Duration in seconds, or `None` when deactivated.
            pub fn to_seconds(&self) -> Option<u64> {
                match self.value() {
                    crate::common::ts24008::GprsTimerValue::Seconds(seconds) => Some(seconds),
                    crate::common::ts24008::GprsTimerValue::Deactivated => None,
                }
            }

            /// Build from a unit and five-bit value; a deactivated timer has value 0.
            pub fn from_unit_value(unit: crate::common::ts24008::GprsTimerUnit, value: u8) -> Self {
                let value = if unit == crate::common::ts24008::GprsTimerUnit::Deactivated {
                    0
                } else {
                    value & 0x1f
                };
                Self::new((unit as u8) << 5 | value)
            }

            /// Build the smallest exact encoding of a duration.
            pub fn from_seconds(seconds: u64) -> Option<Self> {
                Some(Self::new(
                    crate::common::ts24008::gprs_timer_octet_from_seconds(seconds)?,
                ))
            }

            /// Build a deactivated timer.
            pub fn deactivated() -> Self {
                Self::from_unit_value(crate::common::ts24008::GprsTimerUnit::Deactivated, 0)
            }
        }
    };
}

/// GPRS timer 2 IEs (TS 24.008 §10.5.7.4), whose value is one GPRS timer octet.
macro_rules! gprs_timer_2_ie {
    ($name:ident) => {
        impl $name {
            /// Unit and value of the first value octet; extra octets are ignored.
            pub fn timer(&self) -> Option<(crate::common::ts24008::GprsTimerUnit, u8)> {
                let octet = *self.value.first()?;
                Some((
                    crate::common::ts24008::GprsTimerUnit::from_u8(octet >> 5)?,
                    octet & 0x1f,
                ))
            }

            /// Timer unit with the receiver rule applied.
            pub fn unit(&self) -> Option<crate::common::ts24008::GprsTimerUnit> {
                self.timer().map(|(unit, _)| unit)
            }

            /// Raw timer unit code.
            pub fn unit_raw(&self) -> Option<u8> {
                self.value.first().map(|octet| octet >> 5)
            }

            /// Timer value in bits 5-1.
            pub fn timer_value(&self) -> Option<u8> {
                self.value.first().map(|octet| octet & 0x1f)
            }

            /// Whether the timer is deactivated.
            pub fn is_deactivated(&self) -> bool {
                self.unit() == Some(crate::common::ts24008::GprsTimerUnit::Deactivated)
            }

            /// Decoded timer value; `None` when the value octet is missing.
            pub fn value(&self) -> Option<crate::common::ts24008::GprsTimerValue> {
                let (unit, value) = self.timer()?;
                Some(
                    if unit == crate::common::ts24008::GprsTimerUnit::Deactivated {
                        crate::common::ts24008::GprsTimerValue::Deactivated
                    } else {
                        crate::common::ts24008::GprsTimerValue::Seconds(
                            unit.seconds_multiplier() * u64::from(value),
                        )
                    },
                )
            }

            /// Duration in seconds, or `None` when deactivated or missing.
            pub fn to_seconds(&self) -> Option<u64> {
                match self.value()? {
                    crate::common::ts24008::GprsTimerValue::Seconds(seconds) => Some(seconds),
                    crate::common::ts24008::GprsTimerValue::Deactivated => None,
                }
            }

            /// Build from a unit and five-bit value; a deactivated timer has value 0.
            pub fn from_unit_value(unit: crate::common::ts24008::GprsTimerUnit, value: u8) -> Self {
                let value = if unit == crate::common::ts24008::GprsTimerUnit::Deactivated {
                    0
                } else {
                    value & 0x1f
                };
                Self::new(vec![(unit as u8) << 5 | value])
            }

            /// Build the smallest exact encoding of a duration.
            pub fn from_seconds(seconds: u64) -> Option<Self> {
                Some(Self::new(vec![
                    crate::common::ts24008::gprs_timer_octet_from_seconds(seconds)?,
                ]))
            }

            /// Build a deactivated timer.
            pub fn deactivated() -> Self {
                Self::from_unit_value(crate::common::ts24008::GprsTimerUnit::Deactivated, 0)
            }

            /// Sender check: exactly one value octet.
            pub fn is_well_formed(&self) -> bool {
                self.value.len() == 1
            }
        }
    };
}

/// GPRS timer 3 IEs (TS 24.008 §10.5.7.4a). The 320-hour unit is read as
/// undefined; the EPS T3412 extended value and the 5GS T3512 value provide
/// their own accessors for it.
macro_rules! gprs_timer_3_ie {
    ($name:ident) => {
        impl $name {
            /// Unit and value of the first value octet; extra octets are ignored.
            pub fn timer(&self) -> Option<(crate::common::ts24008::GprsTimer3Unit, u8)> {
                let octet = *self.value.first()?;
                Some((
                    crate::common::ts24008::GprsTimer3Unit::from_u8(octet >> 5),
                    octet & 0x1f,
                ))
            }

            /// Timer unit.
            pub fn unit(&self) -> Option<crate::common::ts24008::GprsTimer3Unit> {
                self.timer().map(|(unit, _)| unit)
            }

            /// Raw timer unit code.
            pub fn unit_raw(&self) -> Option<u8> {
                self.value.first().map(|octet| octet >> 5)
            }

            /// Timer value in bits 5-1.
            pub fn timer_value(&self) -> Option<u8> {
                self.value.first().map(|octet| octet & 0x1f)
            }

            /// Whether the timer is deactivated.
            pub fn is_deactivated(&self) -> bool {
                self.unit() == Some(crate::common::ts24008::GprsTimer3Unit::Deactivated)
            }

            /// Decoded timer value; `None` when the value octet is missing or
            /// uses the 320-hour unit, which TS 24.008 Table 10.5.163a NOTE 1
            /// does not define for this timer.
            pub fn value(&self) -> Option<crate::common::ts24008::GprsTimerValue> {
                let (unit, value) = self.timer()?;
                match unit {
                    crate::common::ts24008::GprsTimer3Unit::Deactivated => {
                        Some(crate::common::ts24008::GprsTimerValue::Deactivated)
                    }
                    crate::common::ts24008::GprsTimer3Unit::ThreeHundredTwentyHours => None,
                    unit => Some(crate::common::ts24008::GprsTimerValue::Seconds(
                        unit.seconds_multiplier() * u64::from(value),
                    )),
                }
            }

            /// Duration in seconds, or `None` when deactivated, missing, or
            /// using the undefined 320-hour unit.
            pub fn to_seconds(&self) -> Option<u64> {
                match self.value()? {
                    crate::common::ts24008::GprsTimerValue::Seconds(seconds) => Some(seconds),
                    crate::common::ts24008::GprsTimerValue::Deactivated => None,
                }
            }

            /// Build from a unit and five-bit value; a deactivated timer has value 0.
            pub fn from_unit_value(
                unit: crate::common::ts24008::GprsTimer3Unit,
                value: u8,
            ) -> Self {
                let value = if unit == crate::common::ts24008::GprsTimer3Unit::Deactivated {
                    0
                } else {
                    value & 0x1f
                };
                Self::new(vec![(unit as u8) << 5 | value])
            }

            /// Build the smallest exact encoding of a duration.
            pub fn from_seconds(seconds: u64) -> Option<Self> {
                Some(Self::new(vec![
                    crate::common::ts24008::gprs_timer3_octet_from_seconds(seconds)?,
                ]))
            }

            /// Build a deactivated timer.
            pub fn deactivated() -> Self {
                Self::from_unit_value(crate::common::ts24008::GprsTimer3Unit::Deactivated, 0)
            }

            /// Sender check: exactly one value octet without the 320-hour unit.
            pub fn is_well_formed(&self) -> bool {
                self.value.len() == 1
                    && self.unit()
                        != Some(crate::common::ts24008::GprsTimer3Unit::ThreeHundredTwentyHours)
            }
        }
    };
}

// ── IMEISV request (§10.5.5.10) ──────────────────────────────────────────────

/// IMEISV request value (TS 24.008 §10.5.5.10, Table 10.5.143).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ImeisvRequestValue {
    /// IMEISV not requested.
    NotRequested = 0x00,
    /// IMEISV requested.
    Requested = 0x01,
}

impl ImeisvRequestValue {
    /// Decode bits 1-3 with the receiver rule: values other than 001 are
    /// interpreted as "IMEISV not requested". Always returns `Some`.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(if v & 0x07 == 1 {
            Self::Requested
        } else {
            Self::NotRequested
        })
    }

    /// Decode only the two defined values.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x07 {
            0 => Some(Self::NotRequested),
            1 => Some(Self::Requested),
            _ => None,
        }
    }
}

/// IMEISV request (TS 24.008 §10.5.5.10), a type 1 IE.
macro_rules! imeisv_request_ie {
    ($name:ident) => {
        impl $name {
            /// Request value with the receiver rule applied.
            pub fn request(&self) -> Option<crate::common::ts24008::ImeisvRequestValue> {
                crate::common::ts24008::ImeisvRequestValue::from_u8(self.value)
            }

            /// Request value restricted to the defined codes.
            pub fn request_strict(&self) -> Option<crate::common::ts24008::ImeisvRequestValue> {
                crate::common::ts24008::ImeisvRequestValue::from_u8_strict(self.value)
            }

            /// Raw request value (bits 1-3).
            pub fn request_raw(&self) -> u8 {
                self.value & 0x07
            }

            /// Whether the IMEISV is requested.
            pub fn is_requested(&self) -> bool {
                self.request_raw() == 1
            }

            /// Set the request value, clearing the spare bit.
            pub fn set_request(
                &mut self,
                request: crate::common::ts24008::ImeisvRequestValue,
            ) -> &mut Self {
                self.value = request as u8;
                self
            }

            /// Builder form of [`Self::set_request`].
            pub fn with_request(
                mut self,
                request: crate::common::ts24008::ImeisvRequestValue,
            ) -> Self {
                self.set_request(request);
                self
            }

            /// Build from a request value.
            pub fn from_request(request: crate::common::ts24008::ImeisvRequestValue) -> Self {
                Self::new(request as u8)
            }

            /// Build from a flag.
            pub fn from_requested(requested: bool) -> Self {
                Self::new(u8::from(requested))
            }
        }
    };
}

// ── Non-3GPP NW provided policies (§10.5.5.37) ───────────────────────────────

/// Non-3GPP NW provided policies (TS 24.008 §10.5.5.37), a type 1 IE.
macro_rules! non_3gpp_nw_provided_policies_ie {
    ($name:ident) => {
        crate::common::nas_ie_flags!($name half_octet {
            /// N3EN: use of non-3GPP emergency numbers permitted (bit 1).
            n3en: 1;
        });

        impl $name {
            /// Build from the N3EN indicator with spare bits clear.
            pub fn from_n3en(n3en: bool) -> Self {
                Self::new(u8::from(n3en))
            }
        }
    };
}

// ── Mobile station classmark 2 (§10.5.1.6) ───────────────────────────────────

/// Revision level of a mobile station classmark (TS 24.008 §10.5.1.6).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MsRevisionLevel {
    /// Reserved for GSM phase 1.
    GsmPhase1 = 0,
    /// GSM phase 2 mobile station.
    GsmPhase2 = 1,
    /// R99 or later mobile station.
    R99OrLater = 2,
}

impl MsRevisionLevel {
    /// Decode bits 7-6 of octet 3. The reserved value 11 is interpreted as
    /// the highest supported level (R99 or later). Always returns `Some`.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v & 0x03 {
            0 => Self::GsmPhase1,
            1 => Self::GsmPhase2,
            _ => Self::R99OrLater,
        })
    }

    /// Decode only the defined codes.
    pub fn from_u8_strict(v: u8) -> Option<Self> {
        match v & 0x03 {
            0 => Some(Self::GsmPhase1),
            1 => Some(Self::GsmPhase2),
            2 => Some(Self::R99OrLater),
            _ => None,
        }
    }
}

/// Mobile station classmark 2 (TS 24.008 §10.5.1.6): three value octets.
macro_rules! mobile_station_classmark_2_ie {
    ($name:ident) => {
        crate::common::nas_ie_flags!($name {
            /// ES IND: controlled early classmark sending (octet 3, bit 5).
            es_ind: 0, 5;
            /// PS capability (octet 4, bit 7).
            ps_capability: 1, 7;
            /// SM capability: mobile terminated point-to-point SMS (octet 4, bit 4).
            sm_capability: 1, 4;
            /// VBS notification reception (octet 4, bit 3).
            vbs: 1, 3;
            /// VGCS notification reception (octet 4, bit 2).
            vgcs: 1, 2;
            /// Frequency capability (octet 4, bit 1).
            fc: 1, 1;
            /// Classmark 3 options are supported (octet 5, bit 8).
            cm3: 2, 8;
            /// LCS value added location request notification (octet 5, bit 6).
            lcsva_cap: 2, 6;
            /// UCS2 treatment (octet 5, bit 5); an absent octet reads as 0.
            ucs2: 2, 5;
            /// SoLSA (octet 5, bit 4).
            solsa: 2, 4;
            /// CM service prompt (octet 5, bit 3).
            cmsp: 2, 3;
            /// A5/3 available (octet 5, bit 2).
            a53: 2, 2;
            /// A5/2 bit as sent (octet 5, bit 1); the network accepts any value.
            a52: 2, 1;
        });

        impl $name {
            /// The raw classmark octets.
            pub fn data(&self) -> &[u8] {
                &self.value
            }

            /// Build from raw classmark octets.
            pub fn from_data(data: Vec<u8>) -> Self {
                Self::new(data)
            }

            /// Revision level (octet 3, bits 7-6) with the receiver rule applied.
            pub fn revision_level(&self) -> Option<crate::common::ts24008::MsRevisionLevel> {
                crate::common::ts24008::MsRevisionLevel::from_u8(self.value.first()? >> 5)
            }

            /// Raw revision level (octet 3, bits 7-6).
            pub fn revision_level_raw(&self) -> Option<u8> {
                self.value.first().map(|octet| (octet >> 5) & 0x03)
            }

            /// Whether A5/1 is available (octet 3, bit 4 is 0 when available).
            pub fn a51_available(&self) -> Option<bool> {
                self.value.first().map(|octet| octet & 0x08 == 0)
            }

            /// RF power capability (octet 3, bits 3-1).
            pub fn rf_power_capability(&self) -> Option<u8> {
                self.value.first().map(|octet| octet & 0x07)
            }

            /// SS screening indicator (octet 4, bits 6-5).
            pub fn ss_screening_indicator(&self) -> Option<u8> {
                self.value.get(1).map(|octet| (octet >> 4) & 0x03)
            }

            /// Sender check: three octets with the spare bits clear.
            pub fn is_well_formed(&self) -> bool {
                matches!(self.value.as_slice(), [octet3, octet4, octet5]
                    if octet3 & 0x80 == 0 && octet4 & 0x80 == 0 && octet5 & 0x40 == 0)
            }
        }
    };
}

// ── Protocol configuration options (§10.5.6.3, §10.5.6.3A) ──────────────────

/// Sender direction, which selects the length coding of some container IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PcoDirection {
    /// MS to network.
    Uplink,
    /// Network to MS.
    Downlink,
}

/// One protocol or container unit of TS 24.008 §10.5.6.3.1.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PcoEntry {
    /// Protocol ID or container ID.
    pub identifier: u16,
    /// Unit contents.
    pub contents: Vec<u8>,
}

fn pco_empty_indicator(identifier: u16, direction: PcoDirection) -> bool {
    match direction {
        PcoDirection::Uplink => matches!(
            identifier,
            0x0001 | 0x0002 | 0x0003 | 0x0005 | 0x0007
                ..=0x0013
                    | 0x0015
                    | 0x0016
                    | 0x0018
                    | 0x0019
                    | 0x0020
                    | 0x0021
                    | 0x0023
                    | 0x0024
                    | 0x0027
                    | 0x0031
                    | 0x0032
                    | 0x0036
                    | 0x0047
                    | 0x004a
                    | 0x0050
                    | 0x0057
        ),
        PcoDirection::Downlink => matches!(
            identifier,
            0x0002 | 0x000f | 0x0011 | 0x0013
                | 0x0017
                | 0x0018
                | 0x003a
                | 0x003e..=0x0040
                | 0x0048..=0x004a
                | 0x0057
        ),
    }
}

fn pco_reserved_container(identifier: u16, direction: PcoDirection) -> bool {
    match direction {
        PcoDirection::Uplink => matches!(
            identifier,
            0x0006
                | 0x001b..=0x001f
                | 0x0025..=0x0026
                | 0x0028..=0x002b
                | 0x0035
                | 0x0037..=0x0038
                | 0x003b..=0x0040
                | 0x0048..=0x0049
        ),
        PcoDirection::Downlink => matches!(
            identifier,
            0x0006 | 0x000a
                ..=0x000b | 0x0012 | 0x001a | 0x0022 | 0x0039 | 0x0047 | 0x0050 | 0x0052 | 0x0058
        ),
    }
}

impl PcoEntry {
    /// Sender check for the container-specific rules defined directly by
    /// TS 24.008 §10.5.6.3. Unsupported and delegated protocol identifiers
    /// remain opaque and usable.
    pub fn is_well_formed(&self, direction: PcoDirection) -> bool {
        let length = self.contents.len();
        if pco_empty_indicator(self.identifier, direction) {
            return length == 0;
        }
        match (direction, self.identifier) {
            // NBIFOM mode: exactly one octet, UE- or network-initiated.
            (_, 0x0014) => matches!(self.contents.as_slice(), [0 | 1]),
            // 3GPP PS data off UE status.
            (PcoDirection::Uplink, 0x0017) => matches!(self.contents.as_slice(), [1 | 2]),
            // PDU session identity and 5GSM cause value.
            (PcoDirection::Uplink, 0x001a) => {
                matches!(self.contents.as_slice(), [identity] if (1..=15).contains(identity))
            }
            (PcoDirection::Uplink, 0x0022) => length == 1,
            // DNS security support carries exactly one TLS or DTLS selector.
            (PcoDirection::Uplink, 0x0039) => matches!(self.contents.as_slice(), [1 | 2]),
            // EAS rediscovery support is empty or one three-bit capability.
            (PcoDirection::Uplink, 0x003a) => {
                matches!(self.contents.as_slice(), [] | [0x00..=0x07])
            }

            // Network-provided fixed-size address and MTU containers.
            (PcoDirection::Downlink, 0x0001 | 0x0003 | 0x0007) => length == 16,
            (PcoDirection::Downlink, 0x0008) => length == 17,
            (PcoDirection::Downlink, 0x0009 | 0x000c | 0x000d) => length == 4,
            (PcoDirection::Downlink, 0x0010 | 0x0015 | 0x001e | 0x0020 | 0x0021) => length == 2,
            (PcoDirection::Downlink, 0x0004) => length == 1,
            (PcoDirection::Downlink, 0x0005) => matches!(self.contents.as_slice(), [1 | 2]),
            (PcoDirection::Downlink, 0x0027) => length > 0,
            // PVS IPv4 starts with the address and may append DNN/S-NSSAI.
            (PcoDirection::Downlink, 0x0036) => length >= 4,
            (PcoDirection::Downlink, 0x003b) => length == 8,
            (PcoDirection::Downlink, 0x003c) => length == 32,

            // A reserved additional-parameter identifier is not valid in a
            // sender PCO. Other identifiers can still name a configuration
            // protocol whose support is implementation-dependent.
            _ if pco_reserved_container(self.identifier, direction) => false,
            // Unknown, operator-specific, and containers delegated to another
            // clause/protocol are kept opaque.
            _ => true,
        }
    }

    fn is_receiver_usable(&self, direction: PcoDirection) -> bool {
        // Empty requests/indicators retain their identifier semantics when
        // the receiver ignores forbidden contents. For 003AH, excess octets
        // and spare capability bits are likewise ignored.
        pco_empty_indicator(self.identifier, direction)
            || matches!((direction, self.identifier), (PcoDirection::Uplink, 0x003a))
            || self.is_well_formed(direction)
    }
}

/// Protocol configuration options value: the configuration protocol and
/// the units that follow it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Pco {
    /// Configuration protocol (octet 3, bits 3-1). 0 is PPP; the receiver
    /// interprets every other value as PPP.
    pub configuration_protocol: u8,
    /// Protocol and container units in wire order.
    pub entries: Vec<PcoEntry>,
}

/// Whether a container uses a two-octet length (NOTE to Table 10.5.154).
pub(crate) fn pco_two_octet_length(identifier: u16, direction: PcoDirection) -> bool {
    match direction {
        PcoDirection::Uplink => matches!(identifier, 0x0041 | 0x0051 | 0x0056),
        PcoDirection::Downlink => matches!(
            identifier,
            0x0023 | 0x0024 | 0x0030 | 0x0031 | 0x0032 | 0x0041 | 0x0051 | 0x0056
        ),
    }
}

impl Pco {
    fn parse(value: &[u8], direction: PcoDirection, reject_invalid: bool) -> Option<Self> {
        let (&first, mut remaining) = value.split_first()?;
        let mut entries = Vec::new();
        while !remaining.is_empty() {
            let (identifier, rest) = remaining.split_first_chunk::<2>()?;
            let identifier = u16::from_be_bytes(*identifier);
            let (length, rest) = if pco_two_octet_length(identifier, direction) {
                let (length, rest) = rest.split_first_chunk::<2>()?;
                (usize::from(u16::from_be_bytes(*length)), rest)
            } else {
                let (length, rest) = rest.split_first()?;
                (usize::from(*length), rest)
            };
            if rest.len() < length {
                return None;
            }
            let entry = PcoEntry {
                identifier,
                contents: rest[..length].to_vec(),
            };
            let usable = if reject_invalid {
                entry.is_well_formed(direction)
            } else {
                entry.is_receiver_usable(direction)
            };
            if usable {
                entries.push(entry);
            } else if reject_invalid {
                return None;
            }
            remaining = &rest[length..];
        }
        Some(Self {
            configuration_protocol: first & 0x07,
            entries,
        })
    }

    /// Parse a value sent in `direction`. The extension and spare bits of
    /// octet 3 are ignored; a truncated unit returns `None`. A framed unit
    /// whose container-specific length or value is invalid is skipped while
    /// the other units remain usable, as required by TS 24.008 §10.5.6.3.
    pub fn from_bytes(value: &[u8], direction: PcoDirection) -> Option<Self> {
        Self::parse(value, direction, false)
    }

    /// Parse as [`Self::from_bytes`], also requiring the extension bit set
    /// and the spare bits clear.
    pub fn from_bytes_strict(value: &[u8], direction: PcoDirection) -> Option<Self> {
        (value.first()? & 0xf8 == 0x80)
            .then(|| Self::parse(value, direction, true))
            .flatten()
    }

    /// Encode for `direction`; `None` unless the configuration protocol is
    /// PPP and every unit is valid for sending and fits its length field.
    pub fn to_bytes(&self, direction: PcoDirection) -> Option<Vec<u8>> {
        if self.configuration_protocol != 0 {
            return None;
        }
        let mut value = vec![0x80];
        for entry in &self.entries {
            if !entry.is_well_formed(direction) {
                return None;
            }
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

    /// First receiver-usable unit with the given protocol or container ID.
    pub fn entry(&self, identifier: u16) -> Option<&PcoEntry> {
        self.entries
            .iter()
            .find(|entry| entry.identifier == identifier)
    }
}

/// Protocol configuration options (TS 24.008 §10.5.6.3), at most 251 value
/// octets.
macro_rules! protocol_configuration_options_ie {
    ($name:ident) => {
        impl $name {
            /// Parse the value sent in `direction` (receiver rules).
            pub fn pco(&self, direction: PcoDirection) -> Option<Pco> {
                Pco::from_bytes(&self.value, direction)
            }

            /// Build from typed units; `None` if the value exceeds 251 octets.
            pub fn from_pco(pco: &Pco, direction: PcoDirection) -> Option<Self> {
                let value = pco.to_bytes(direction)?;
                (value.len() <= 251).then(|| Self::new(value))
            }

            /// Sender check for `direction`: at most 251 octets, octet 3 coded
            /// as PPP with the extension bit set, and complete units without
            /// a two-octet length, which needs ePCO (NOTE 2 to Table
            /// 10.5.154).
            pub fn is_well_formed(&self, direction: PcoDirection) -> bool {
                self.value.len() <= 251
                    && Pco::from_bytes_strict(&self.value, direction).is_some_and(|pco| {
                        pco.configuration_protocol == 0
                            && !pco.entries.iter().any(|entry| {
                                crate::common::ts24008::pco_two_octet_length(
                                    entry.identifier,
                                    direction,
                                )
                            })
                    })
            }
        }
    };
}

/// Extended protocol configuration options (TS 24.008 §10.5.6.3A), coded
/// as octet 3 onwards of the PCO IE.
macro_rules! extended_protocol_configuration_options_ie {
    ($name:ident) => {
        impl $name {
            /// Raw ePCO value octets.
            pub fn epco_data(&self) -> &[u8] {
                &self.value
            }

            /// Build from raw ePCO value octets.
            pub fn from_epco_data(data: Vec<u8>) -> Self {
                Self::new(data)
            }

            /// Replace the raw ePCO value and its declared length.
            pub fn set_epco_data(&mut self, data: Vec<u8>) -> &mut Self {
                self.length = data.len() as u16;
                self.value = data;
                self
            }

            /// Builder form of [`Self::set_epco_data`].
            pub fn with_epco_data(mut self, data: Vec<u8>) -> Self {
                self.set_epco_data(data);
                self
            }

            /// Parse the value sent in `direction` (receiver rules).
            pub fn pco(&self, direction: PcoDirection) -> Option<Pco> {
                Pco::from_bytes(&self.value, direction)
            }

            /// Build from typed units; `None` if the value exceeds 65535 octets.
            pub fn from_pco(pco: &Pco, direction: PcoDirection) -> Option<Self> {
                let value = pco.to_bytes(direction)?;
                (value.len() <= usize::from(u16::MAX)).then(|| Self::new(value))
            }

            /// Sender check for `direction`: octet 3 coded as PPP with the
            /// extension bit set, and complete units.
            pub fn is_well_formed(&self, direction: PcoDirection) -> bool {
                Pco::from_bytes_strict(&self.value, direction)
                    .is_some_and(|pco| pco.configuration_protocol == 0)
            }
        }
    };
}

// ── Network name, time zone, and emergency numbers (§10.5.3) ───────────────

/// Network name coding scheme (TS 24.008 Table 10.5.94).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum NetworkNameCodingScheme {
    /// GSM 7-bit default alphabet (TS 23.038).
    Gsm7Bit = 0x00,
    /// UCS2 (16 bit).
    Ucs2 = 0x01,
}

impl NetworkNameCodingScheme {
    /// Decode bits 3-1 of the argument; reserved codes return `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x07 {
            0x00 => Some(Self::Gsm7Bit),
            0x01 => Some(Self::Ucs2),
            _ => None,
        }
    }
}

/// Network name (TS 24.008 §10.5.3.5a): a header octet with the coding
/// scheme, the "Add CI" flag, and the number of spare bits in the last
/// octet, then the text string.
macro_rules! network_name_ie {
    ($name:ident) => {
        impl $name {
            /// Coding scheme; reserved codes return `None`.
            pub fn coding_scheme(&self) -> Option<NetworkNameCodingScheme> {
                NetworkNameCodingScheme::from_u8(self.coding_scheme_raw())
            }

            /// Raw coding scheme (bits 7-5 of the header octet).
            pub fn coding_scheme_raw(&self) -> u8 {
                self.value.first().map_or(0, |octet| (octet >> 4) & 0x07)
            }

            /// Whether the MS should add the country's initials (bit 4).
            pub fn add_ci(&self) -> bool {
                self.value.first().is_some_and(|octet| octet & 0x08 != 0)
            }

            /// Number of spare bits in the last octet (bits 3-1); 0 carries
            /// no information.
            pub fn spare_bits(&self) -> u8 {
                self.value.first().map_or(0, |octet| octet & 0x07)
            }

            /// Encoded text string after the header octet.
            pub fn name_data(&self) -> &[u8] {
                self.value.get(1..).unwrap_or_default()
            }

            /// Decoded text. For UCS2 the spare-bit count carries no
            /// information; for GSM 7-bit a count of 0 means the text fills
            /// the octets, less a padding carriage return (TS 23.038
            /// §6.1.2.3.1).
            pub fn name(&self) -> Option<String> {
                let data = self.name_data();
                match self.coding_scheme()? {
                    NetworkNameCodingScheme::Gsm7Bit => {
                        let septets = match self.spare_bits() {
                            0 => crate::common::gsm7::unpack_padded_septets(data),
                            spare => {
                                let bits = (data.len() * 8).checked_sub(usize::from(spare))?;
                                crate::common::gsm7::unpack_septets(data, bits / 7)?
                            }
                        };
                        Some(crate::common::gsm7::decode_septets(&septets))
                    }
                    NetworkNameCodingScheme::Ucs2 => char::decode_utf16(
                        data.chunks_exact(2)
                            .map(|pair| u16::from_be_bytes([pair[0], pair[1]])),
                    )
                    .collect::<std::result::Result<String, _>>()
                    .ok(),
                }
            }

            /// Encode text with the GSM 7-bit default alphabet when every
            /// character is in it, otherwise as UCS2.
            pub fn from_name(name: &str, add_ci: bool) -> Self {
                let ci = u8::from(add_ci) << 3;
                let value = match crate::common::gsm7::encode_septets(name) {
                    Some(septets) => {
                        let spare = ((8 - septets.len() * 7 % 8) % 8) as u8;
                        let mut value = vec![0x80 | ci | spare];
                        value.extend(crate::common::gsm7::pack_septets(&septets));
                        value
                    }
                    None => {
                        let mut value =
                            vec![0x80 | (NetworkNameCodingScheme::Ucs2 as u8) << 4 | ci];
                        value.extend(name.encode_utf16().flat_map(u16::to_be_bytes));
                        value
                    }
                };
                Self::new(value)
            }

            fn update_header(&mut self, mask: u8, bits: u8) -> &mut Self {
                if self.value.is_empty() {
                    self.value.push(0x80);
                    self.length = self.value.len() as _;
                }
                self.value[0] = (self.value[0] & !mask) | (bits & mask);
                self
            }

            /// Set the coding scheme; UCS2 also clears the spare-bit count.
            pub fn set_coding_scheme(&mut self, scheme: NetworkNameCodingScheme) -> &mut Self {
                self.update_header(0x70, (scheme as u8) << 4);
                if scheme == NetworkNameCodingScheme::Ucs2 {
                    self.update_header(0x07, 0);
                }
                self
            }

            /// Builder form of [`Self::set_coding_scheme`].
            pub fn with_coding_scheme(mut self, scheme: NetworkNameCodingScheme) -> Self {
                self.set_coding_scheme(scheme);
                self
            }

            /// Set the "Add CI" flag.
            pub fn set_add_ci(&mut self, add_ci: bool) -> &mut Self {
                self.update_header(0x08, u8::from(add_ci) << 3)
            }

            /// Builder form of [`Self::set_add_ci`].
            pub fn with_add_ci(mut self, add_ci: bool) -> Self {
                self.set_add_ci(add_ci);
                self
            }

            /// Set the spare-bit count; it stays 0 with UCS2.
            pub fn set_spare_bits(&mut self, count: u8) -> &mut Self {
                let count = if self.coding_scheme() == Some(NetworkNameCodingScheme::Ucs2) {
                    0
                } else {
                    count
                };
                self.update_header(0x07, count)
            }

            /// Builder form of [`Self::set_spare_bits`].
            pub fn with_spare_bits(mut self, count: u8) -> Self {
                self.set_spare_bits(count);
                self
            }

            /// Replace the encoded text string.
            pub fn set_name_data(&mut self, data: &[u8]) -> &mut Self {
                self.update_header(0, 0);
                self.value.truncate(1);
                self.value.extend_from_slice(data);
                self.length = self.value.len() as _;
                self
            }

            /// Builder form of [`Self::set_name_data`].
            pub fn with_name_data(mut self, data: &[u8]) -> Self {
                self.set_name_data(data);
                self
            }

            /// Sender check: the extension bit set and a defined coding scheme.
            pub fn is_well_formed(&self) -> bool {
                self.value.first().is_some_and(|octet| octet & 0x80 != 0)
                    && self.coding_scheme().is_some()
            }
        }
    };
}

/// Time zone (TS 24.008 §10.5.3.8): quarter hours as two swapped BCD
/// digits, with the sign in bit 4.
macro_rules! time_zone_ie {
    ($name:ident) => {
        impl $name {
            /// Raw time zone octet.
            pub fn raw(&self) -> u8 {
                self.value
            }

            /// Signed offset from GMT in quarter hours.
            pub fn quarter_hours(&self) -> i8 {
                crate::common::ts24008::time_zone_quarter_hours(self.value)
            }

            /// Build from a signed offset; `None` beyond ±79 quarter hours.
            pub fn from_quarter_hours(quarter_hours: i8) -> Option<Self> {
                crate::common::ts24008::time_zone_octet(quarter_hours).map(Self::new)
            }

            /// Sender check: the units digit is BCD.
            pub fn is_well_formed(&self) -> bool {
                crate::common::ts24008::time_zone_octet_is_bcd(self.value)
            }
        }
    };
}

/// Whether the units digit of a time zone octet (bits 8-5) is BCD; the
/// tens digit has three bits and cannot exceed 7.
pub(crate) fn time_zone_octet_is_bcd(octet: u8) -> bool {
    octet >> 4 <= 9
}

pub(crate) fn time_zone_quarter_hours(octet: u8) -> i8 {
    let magnitude = (octet & 0x07) as i8 * 10 + (octet >> 4) as i8;
    if octet & 0x08 != 0 {
        -magnitude
    } else {
        magnitude
    }
}

pub(crate) fn time_zone_octet(quarter_hours: i8) -> Option<u8> {
    let magnitude = quarter_hours.unsigned_abs();
    (magnitude <= 79).then_some(
        ((magnitude % 10) << 4) | (magnitude / 10) | if quarter_hours < 0 { 0x08 } else { 0 },
    )
}

/// Time zone and time (TS 24.008 §10.5.3.9): year, month, day, hour,
/// minute, and second as swapped BCD digits, then the time zone.
macro_rules! time_zone_and_time_ie {
    ($name:ident) => {
        paste::paste! {
            impl $name {
                crate::common::ts24008::time_zone_and_time_ie!(@field $name year 0 "Year within the century");
                crate::common::ts24008::time_zone_and_time_ie!(@field $name month 1 "Month");
                crate::common::ts24008::time_zone_and_time_ie!(@field $name day 2 "Day of the month");
                crate::common::ts24008::time_zone_and_time_ie!(@field $name hour 3 "Hour");
                crate::common::ts24008::time_zone_and_time_ie!(@field $name minute 4 "Minute");
                crate::common::ts24008::time_zone_and_time_ie!(@field $name second 5 "Second");

                /// Time zone in signed quarter hours.
                pub fn timezone_quarter_hours(&self) -> i8 {
                    crate::common::ts24008::time_zone_quarter_hours(
                        self.value.get(6).copied().unwrap_or(0),
                    )
                }

                /// Set the time zone; `None` beyond ±79 quarter hours.
                pub fn set_timezone_quarter_hours(&mut self, quarter_hours: i8) -> Option<&mut Self> {
                    let octet = crate::common::ts24008::time_zone_octet(quarter_hours)?;
                    self.value.resize(self.value.len().max(7), 0);
                    self.value[6] = octet;
                    Some(self)
                }

                /// Builder form of [`Self::set_timezone_quarter_hours`].
                pub fn with_timezone_quarter_hours(mut self, quarter_hours: i8) -> Option<Self> {
                    self.set_timezone_quarter_hours(quarter_hours)?;
                    Some(self)
                }

                /// Sender check: seven octets of BCD digits with a month of 1
                /// to 12, a day of 1 to 31, and a time of day within range
                /// (TS 23.040 §9.2.3.11).
                pub fn is_well_formed(&self) -> bool {
                    let Ok(octets) = <[u8; 7]>::try_from(self.value.as_slice()) else {
                        return false;
                    };
                    octets[..6].iter().all(|octet| octet & 0x0f <= 9 && octet >> 4 <= 9)
                        && crate::common::ts24008::time_zone_octet_is_bcd(octets[6])
                        && (1..=12).contains(&self.month())
                        && (1..=31).contains(&self.day())
                        && self.hour() <= 23
                        && self.minute() <= 59
                        && self.second() <= 59
                }
            }
        }
    };
    (@field $name:ident $field:ident $index:literal $doc:literal) => {
        paste::paste! {
            #[doc = concat!($doc, " (value octet ", $index, "), or 0 if missing.")]
            pub fn $field(&self) -> u8 {
                crate::common::ts24008::swapped_bcd_value(self.value.get($index).copied().unwrap_or(0))
            }

            #[doc = concat!("Set [`Self::", stringify!($field), "`] from a value below 100.")]
            pub fn [<set_ $field>](&mut self, value: u8) -> &mut Self {
                self.value.resize(self.value.len().max(7), 0);
                self.value[$index] = crate::common::ts24008::to_swapped_bcd_value(value);
                self
            }

            #[doc = concat!("Builder form of [`Self::set_", stringify!($field), "`].")]
            pub fn [<with_ $field>](mut self, value: u8) -> Self {
                self.[<set_ $field>](value);
                self
            }
        }
    };
}

/// Decode two swapped BCD digits: the tens digit is in the low nibble.
pub(crate) fn swapped_bcd_value(octet: u8) -> u8 {
    (octet & 0x0f) * 10 + (octet >> 4)
}

/// Encode a value below 100 as two swapped BCD digits.
pub(crate) fn to_swapped_bcd_value(value: u8) -> u8 {
    ((value % 10) << 4) | ((value / 10) % 10)
}

/// Daylight saving time adjustment (TS 24.008 Table 10.5.97a).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum DaylightSavingAdjustment {
    /// No adjustment for daylight saving time.
    NoAdjustment = 0,
    /// +1 hour adjustment.
    PlusOneHour = 1,
    /// +2 hours adjustment.
    PlusTwoHours = 2,
}

impl DaylightSavingAdjustment {
    /// Decode bits 2-1; the reserved value 3 returns `None`.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value & 0x03 {
            0 => Some(Self::NoAdjustment),
            1 => Some(Self::PlusOneHour),
            2 => Some(Self::PlusTwoHours),
            _ => None,
        }
    }
}

/// Daylight saving time (TS 24.008 §10.5.3.12).
macro_rules! daylight_saving_time_ie {
    ($name:ident) => {
        impl $name {
            /// Adjustment; spare bits are ignored and the reserved value is `None`.
            pub fn adjustment(&self) -> Option<DaylightSavingAdjustment> {
                DaylightSavingAdjustment::from_u8(*self.value.first()?)
            }

            /// Raw adjustment (bits 2-1), or 0 if the value is empty.
            pub fn adjustment_raw(&self) -> u8 {
                self.value.first().map_or(0, |octet| octet & 0x03)
            }

            /// Build from an adjustment with the spare bits clear.
            pub fn from_adjustment(adjustment: DaylightSavingAdjustment) -> Self {
                Self::new(vec![adjustment as u8])
            }

            /// Sender check: one octet with a defined value and spare bits clear.
            pub fn is_well_formed(&self) -> bool {
                matches!(self.value.as_slice(), [octet] if *octet <= 2)
            }
        }
    };
}

/// One local emergency number (TS 24.008 §10.5.3.13).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EmergencyNumber {
    /// Emergency service category bits 1 to 5 (§10.5.4.33): police,
    /// ambulance, fire brigade, marine guard, and mountain rescue.
    pub categories: u8,
    /// Number digits: `0`-`9`, `*`, `#`, `a`, `b`, and `c`.
    pub digits: String,
}

const CALLED_PARTY_DIGITS: &[u8; 15] = b"0123456789*#abc";

/// Decode number digits of TS 24.008 Table 10.5.118, first digit in the
/// low nibble. An end mark (0xF) ends the number.
pub(crate) fn decode_number_digits(octets: &[u8]) -> String {
    let mut digits = String::with_capacity(octets.len() * 2);
    for nibble in octets.iter().flat_map(|octet| [octet & 0x0f, octet >> 4]) {
        let Some(&digit) = CALLED_PARTY_DIGITS.get(usize::from(nibble)) else {
            break;
        };
        digits.push(char::from(digit));
    }
    digits
}

/// Encode number digits, adding an end mark after an odd count; `None`
/// for an empty number or a character outside Table 10.5.118.
pub(crate) fn encode_number_digits(digits: &str) -> Option<Vec<u8>> {
    let nibbles = digits
        .bytes()
        .map(|digit| {
            CALLED_PARTY_DIGITS
                .iter()
                .position(|&d| d == digit)
                .map(|n| n as u8)
        })
        .collect::<Option<Vec<_>>>()?;
    (!nibbles.is_empty()).then(|| {
        nibbles
            .chunks(2)
            .map(|pair| pair[0] | pair.get(1).copied().unwrap_or(0x0f) << 4)
            .collect()
    })
}

/// Whether number digits are canonical: an end mark only in the high nibble
/// of the last octet.
pub(crate) fn number_digits_are_well_formed(octets: &[u8]) -> bool {
    encode_number_digits(&decode_number_digits(octets)).as_deref() == Some(octets)
}

/// Emergency number list (TS 24.008 §10.5.3.13), 3 to 48 value octets.
macro_rules! emergency_number_list_ie {
    ($name:ident) => {
        impl $name {
            /// Emergency numbers in wire order; spare bits are ignored.
            /// `None` if an entry overruns the value or is empty.
            pub fn numbers(&self) -> Option<Vec<EmergencyNumber>> {
                let mut numbers = Vec::new();
                let mut remaining = self.value.as_slice();
                while let Some((&length, rest)) = remaining.split_first() {
                    let entry = rest.get(..usize::from(length))?;
                    let (&categories, digits) = entry.split_first()?;
                    numbers.push(EmergencyNumber {
                        categories: categories & 0x1f,
                        digits: crate::common::ts24008::decode_number_digits(digits),
                    });
                    remaining = &rest[entry.len()..];
                }
                Some(numbers)
            }

            /// Build from emergency numbers; `None` for invalid digits or
            /// categories, or a value outside 3 to 48 octets.
            pub fn from_numbers(numbers: &[EmergencyNumber]) -> Option<Self> {
                let mut value = Vec::new();
                for number in numbers {
                    let digits = crate::common::ts24008::encode_number_digits(&number.digits)?;
                    if number.categories > 0x1f {
                        return None;
                    }
                    value.push(u8::try_from(digits.len() + 1).ok()?);
                    value.push(number.categories);
                    value.extend(digits);
                }
                (3..=48).contains(&value.len()).then(|| Self::new(value))
            }

            /// Sender check: 3 to 48 octets of complete entries with spare
            /// bits clear, at least one digit, and canonical digits.
            pub fn is_well_formed(&self) -> bool {
                let mut remaining = self.value.as_slice();
                if !(3..=48).contains(&remaining.len()) {
                    return false;
                }
                while let Some((&length, rest)) = remaining.split_first() {
                    let Some(entry) = rest.get(..usize::from(length)) else {
                        return false;
                    };
                    let [categories, digits @ ..] = entry else {
                        return false;
                    };
                    if categories & 0xe0 != 0
                        || !crate::common::ts24008::number_digits_are_well_formed(digits)
                    {
                        return false;
                    }
                    remaining = &rest[entry.len()..];
                }
                true
            }
        }
    };
}

// ── Extended DRX parameters (§10.5.5.32) and supported codecs (§10.5.4.32) ──

/// E-UTRA bandwidth mode for reading extended DRX parameters in S1 mode or
/// in N1 mode over E-UTRA (TS 24.008 Table 10.5.5.32).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EutraMode {
    /// WB-S1 or WB-N1 mode.
    Wideband,
    /// NB-S1 or NB-N1 mode.
    Narrowband,
}

/// Extended DRX parameters (TS 24.008 §10.5.5.32): Paging Time Window and
/// eDRX value in octet 3, and the NR Extended Paging Time Window in octet 4.
macro_rules! extended_drx_parameters_ie {
    ($name:ident) => {
        impl $name {
            /// Paging Time Window code (octet 3, bits 8-5).
            pub fn paging_time_window(&self) -> u8 {
                self.value.first().map_or(0, |octet| octet >> 4)
            }

            /// Set the Paging Time Window code, keeping the eDRX value.
            pub fn set_paging_time_window(&mut self, ptw: u8) -> &mut Self {
                if self.value.is_empty() {
                    self.value.push(0);
                    self.length = self.value.len() as _;
                }
                self.value[0] = (self.value[0] & 0x0f) | ((ptw & 0x0f) << 4);
                self
            }

            /// Builder form of [`Self::set_paging_time_window`].
            pub fn with_paging_time_window(mut self, ptw: u8) -> Self {
                self.set_paging_time_window(ptw);
                self
            }

            /// eDRX value code (octet 3, bits 4-1).
            pub fn edrx_value(&self) -> u8 {
                self.value.first().map_or(0, |octet| octet & 0x0f)
            }

            /// Set the eDRX value code, keeping the Paging Time Window.
            pub fn set_edrx_value(&mut self, value: u8) -> &mut Self {
                if self.value.is_empty() {
                    self.value.push(0);
                    self.length = self.value.len() as _;
                }
                self.value[0] = (self.value[0] & 0xf0) | (value & 0x0f);
                self
            }

            /// Builder form of [`Self::set_edrx_value`].
            pub fn with_edrx_value(mut self, value: u8) -> Self {
                self.set_edrx_value(value);
                self
            }

            /// Extended Paging Time Window (octet 4), used in NR.
            pub fn extended_paging_time_window(&self) -> Option<u8> {
                self.value.get(1).copied()
            }

            /// eDRX value as read in E-UTRA: 0000 and 0001 in narrowband
            /// mean the IE is treated as absent (`None`), 0100 and 0110 to
            /// 1000 in narrowband are read as 0010, and 1110 and 1111 in
            /// wideband are read as 1101 (NOTES 4 to 6).
            pub fn effective_eutra_edrx_value(&self, mode: EutraMode) -> Option<u8> {
                let value = self.edrx_value();
                Some(match (mode, value) {
                    (EutraMode::Narrowband, 0 | 1) => return None,
                    (EutraMode::Narrowband, 4 | 6..=8) => 2,
                    (EutraMode::Wideband, 14 | 15) => 13,
                    _ => value,
                })
            }

            /// E-UTRA eDRX cycle length in milliseconds, after
            /// [`Self::effective_eutra_edrx_value`].
            pub fn eutra_edrx_cycle_ms(&self, mode: EutraMode) -> Option<u32> {
                const CYCLES_MS: [u32; 16] = [
                    5_120, 10_240, 20_480, 40_960, 61_440, 81_920, 102_400, 122_880, 143_360,
                    163_840, 327_680, 655_360, 1_310_720, 2_621_440, 5_242_880, 10_485_760,
                ];
                Some(CYCLES_MS[usize::from(self.effective_eutra_edrx_value(mode)?)])
            }

            /// E-UTRA Paging Time Window in milliseconds: (n + 1) × 1.28 s in
            /// wideband and (n + 1) × 2.56 s in narrowband.
            pub fn eutra_paging_time_window_ms(&self, mode: EutraMode) -> u32 {
                let step = match mode {
                    EutraMode::Wideband => 1_280,
                    EutraMode::Narrowband => 2_560,
                };
                (u32::from(self.paging_time_window()) + 1) * step
            }

            /// Sender check: one or two octets.
            pub fn is_well_formed(&self) -> bool {
                matches!(self.value.len(), 1 | 2)
            }
        }
    };
}

/// Supported codec list (TS 24.008 §10.5.4.32): system identifications, each
/// followed by a codec bitmap (TS 26.103).
macro_rules! supported_codec_list_ie {
    ($name:ident) => {
        impl $name {
            /// System identifications and codec bitmaps; `None` if an entry
            /// overruns the value or has an empty bitmap.
            pub fn codec_bitmaps(&self) -> Option<Vec<(u8, Vec<u8>)>> {
                let mut remaining = self.value.as_slice();
                let mut bitmaps = Vec::new();
                while let Some((&system, rest)) = remaining.split_first() {
                    let (&length, rest) = rest.split_first()?;
                    let bitmap = rest
                        .get(..usize::from(length))
                        .filter(|bitmap| !bitmap.is_empty())?;
                    bitmaps.push((system, bitmap.to_vec()));
                    remaining = &rest[bitmap.len()..];
                }
                Some(bitmaps)
            }

            /// Build from system identifications and codec bitmaps.
            pub fn from_codec_bitmaps(bitmaps: &[(u8, Vec<u8>)]) -> Option<Self> {
                let mut value = Vec::new();
                for (system, bitmap) in bitmaps {
                    if bitmap.is_empty() {
                        return None;
                    }
                    value.push(*system);
                    value.push(u8::try_from(bitmap.len()).ok()?);
                    value.extend_from_slice(bitmap);
                }
                (value.len() >= 3).then(|| Self::new(value))
            }

            /// Sender check: at least one complete entry.
            pub fn is_well_formed(&self) -> bool {
                self.codec_bitmaps()
                    .is_some_and(|bitmaps| !bitmaps.is_empty())
            }
        }
    };
}

// ── PLMN list (§10.5.1.13) ────────────────────────────────────────────────────

/// PLMN list (TS 24.008 §10.5.1.13): one to fifteen PLMN identities.
macro_rules! plmn_list_ie {
    ($name:ident) => {
        crate::common::plmn_sequence_ie!($name, 1, 15);
    };
}

// ── Access point name (§10.5.6.1, TS 23.003 §9.1) ────────────────────────────

/// Access point name or DNN value: length-prefixed labels of at most 100
/// octets (TS 23.003 §9.1, TS 24.501 §9.11.2.1B).
macro_rules! access_point_name_ie {
    ($name:ident) => {
        impl $name {
            /// Decode to a dot-separated name; `None` unless every label
            /// follows the TS 23.003 character rules.
            pub fn as_string(&self) -> Option<String> {
                crate::common::decode_labels(&self.value)
            }

            /// Encode a dot-separated name. Returns `None` if a label is
            /// invalid or the encoding exceeds 100 octets, so the name is
            /// never silently truncated.
            pub fn from_string(name: &str) -> Option<Self> {
                Some(Self::new(crate::common::encode_labels(name, 100)?))
            }

            /// Split the label octets without checking their characters;
            /// `None` if a length octet overruns the value.
            pub fn labels(&self) -> Option<Vec<&[u8]>> {
                let mut labels = Vec::new();
                let mut remaining = self.value.as_slice();
                while let Some((&length, rest)) = remaining.split_first() {
                    let label = rest.get(..usize::from(length))?;
                    labels.push(label);
                    remaining = &rest[label.len()..];
                }
                Some(labels)
            }

            /// Sender check: valid labels of at most 100 octets in total.
            pub fn is_well_formed(&self) -> bool {
                self.as_string().is_some()
            }
        }
    };
}

pub(crate) use {
    access_point_name_ie, authentication_failure_parameter_ie, authentication_parameter_autn_ie,
    authentication_parameter_rand_ie, daylight_saving_time_ie, emergency_number_list_ie,
    extended_drx_parameters_ie, extended_protocol_configuration_options_ie, gprs_timer_2_ie,
    gprs_timer_3_ie, gprs_timer_ie, imeisv_request_ie, mobile_station_classmark_2_ie,
    network_name_ie, non_3gpp_nw_provided_policies_ie, plmn_list_ie,
    protocol_configuration_options_ie, supported_codec_list_ie, time_zone_and_time_ie,
    time_zone_ie,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nas_5gs::{
        NasAuthenticationParameterAutn, NasImeisvRequest as FgsImeisvRequest,
        NasMobileStationClassmark2 as FgsClassmark2, NasNon3GppNwProvidedPolicies,
    };
    use crate::nas_eps::{
        NasAuthenticationFailureParameter, NasAuthenticationParameterAutnEpsChallenge,
        NasAuthenticationParameterRandEpsChallenge, NasImeisvRequest, NasMobileStationClassmark2,
        NasNon3GppNwProvidedPolicies as EpsPolicies,
    };

    #[test]
    fn authentication_parameters_split_the_ts_33_102_fields() {
        // AUTN from capture packet 34 (TS 24.301 AUTHENTICATION REQUEST).
        let autn: [u8; 16] = hex::decode("2c05040b170d80002180b9f277ae4fb4")
            .unwrap()
            .try_into()
            .unwrap();
        let eps = NasAuthenticationParameterAutnEpsChallenge::from_autn(autn);
        assert_eq!(eps.sqn_xor_ak().unwrap(), &autn[..6]);
        assert_eq!(eps.amf_field(), Some([0x80, 0x00]));
        assert_eq!(eps.amf_separation_bit(), Some(true));
        assert_eq!(eps.mac_a().unwrap(), &autn[8..]);
        let mut longer = autn.to_vec();
        longer.push(0xff);
        assert_eq!(
            NasAuthenticationParameterAutn::new(longer).autn_array(),
            Some(autn)
        );

        let rand = NasAuthenticationParameterRandEpsChallenge::from_rand([7; 16]);
        assert_eq!(rand.rand_array(), Some([7; 16]));
        let auts = NasAuthenticationFailureParameter::from_auts([1; 14]);
        assert_eq!(auts.sqn_xor_aks().unwrap(), &[1; 6]);
        assert_eq!(auts.mac_s().unwrap(), &[1; 8]);
        assert!(
            NasAuthenticationFailureParameter::new(vec![1; 13])
                .mac_s()
                .is_none()
        );
    }

    #[test]
    fn imeisv_request_applies_table_10_5_143_fallback() {
        for value in 2..=7 {
            assert_eq!(
                NasImeisvRequest::new(value).request(),
                Some(ImeisvRequestValue::NotRequested)
            );
            assert_eq!(FgsImeisvRequest::new(value).request_strict(), None);
        }
        let request = NasImeisvRequest::new(0x09);
        assert!(request.is_requested());
        assert_eq!(
            request.with_request(ImeisvRequestValue::NotRequested).value,
            0
        );
    }

    #[test]
    fn non_3gpp_policies_and_classmark_2_share_both_codecs() {
        assert!(EpsPolicies::from_n3en(true).n3en());
        assert!(!NasNon3GppNwProvidedPolicies::new(0x0e).n3en());
        assert_eq!(EpsPolicies::new(0).with_n3en(true).value, 1);

        // Revision level R99, A5/1 not available, RF class 3 / PS, SS 01, SM /
        // CM3, UCS2, A5/3.
        let classmark = NasMobileStationClassmark2::new(vec![0x5b, 0x59, 0x92]);
        assert_eq!(
            classmark.revision_level(),
            Some(MsRevisionLevel::R99OrLater)
        );
        assert_eq!(classmark.a51_available(), Some(false));
        assert_eq!(classmark.rf_power_capability(), Some(3));
        assert!(classmark.ps_capability() && classmark.sm_capability());
        assert_eq!(classmark.ss_screening_indicator(), Some(1));
        assert!(classmark.cm3() && classmark.ucs2() && classmark.a53() && !classmark.a52());
        assert!(classmark.is_well_formed());
        let reserved = FgsClassmark2::new(vec![0x60, 0x80, 0x40]);
        assert_eq!(reserved.revision_level(), Some(MsRevisionLevel::R99OrLater));
        assert_eq!(reserved.revision_level_raw(), Some(3));
        assert!(!reserved.is_well_formed());
    }

    #[test]
    fn pco_units_follow_direction_and_receiver_rules() {
        use crate::nas_5gs::NasExtendedProtocolConfigurationOptions as FgsEpco;
        use crate::nas_eps::NasProtocolConfigurationOptions;

        // 0x000D DNS server IPv4 address request, then 0x0023 (QoS rules),
        // which has a two-octet length only from the network.
        let downlink = [0x80, 0x00, 0x0d, 0x00, 0x00, 0x23, 0x00, 0x01, 0xaa];
        let pco = Pco::from_bytes(&downlink, PcoDirection::Downlink).unwrap();
        assert!(pco.entry(0x000d).is_none());
        assert_eq!(pco.entry(0x0023).unwrap().contents, [0xaa]);
        assert_eq!(
            pco.to_bytes(PcoDirection::Downlink).unwrap(),
            [0x80, 0x00, 0x23, 0x00, 0x01, 0xaa]
        );
        let uplink = Pco::from_bytes(
            &[0x80, 0x00, 0x0d, 0x00, 0x00, 0x23, 0x01, 0xaa],
            PcoDirection::Uplink,
        )
        .unwrap();
        assert!(uplink.entry(0x000d).is_some());
        assert_eq!(uplink.entry(0x0023).unwrap().contents, [0xaa]);
        // Codec review O-3: such a container needs ePCO (NOTE 2 to Table
        // 10.5.154); in the ePCO IE it is fine.
        let pco_ie = NasProtocolConfigurationOptions::new(downlink.to_vec());
        assert!(pco_ie.pco(PcoDirection::Downlink).is_some());
        assert!(!pco_ie.is_well_formed(PcoDirection::Downlink));
        let epco_downlink = [0x80, 0x00, 0x23, 0x00, 0x01, 0xaa];
        assert!(FgsEpco::new(epco_downlink.to_vec()).is_well_formed(PcoDirection::Downlink));

        // Spare and extension bits are ignored on receipt, and every
        // configuration protocol is read as PPP by the caller.
        let received = NasProtocolConfigurationOptions::new(vec![0x7b, 0x00, 0x0d, 0x00]);
        let pco = received.pco(PcoDirection::Uplink).unwrap();
        assert_eq!((pco.configuration_protocol, pco.entries.len()), (3, 1));
        assert!(!received.is_well_formed(PcoDirection::Uplink));
        let nonempty_request =
            Pco::from_bytes(&[0x80, 0x00, 0x0d, 0x01, 0xaa], PcoDirection::Uplink).unwrap();
        assert_eq!(nonempty_request.entry(0x000d).unwrap().contents, [0xaa]);
        assert!(
            Pco::from_bytes_strict(&[0x80, 0x00, 0x0d, 0x01, 0xaa], PcoDirection::Uplink).is_none()
        );

        let epco = FgsEpco::from_pco(&pco_with_ppp(), PcoDirection::Uplink).unwrap();
        assert!(epco.is_well_formed(PcoDirection::Uplink));
        assert_eq!(epco.pco(PcoDirection::Uplink), Some(pco_with_ppp()));

        // V19.5 late-release containers have direction-specific rules.
        for entry in [
            PcoEntry {
                identifier: 0x0032,
                contents: vec![],
            },
            PcoEntry {
                identifier: 0x0039,
                contents: vec![1],
            },
            PcoEntry {
                identifier: 0x0039,
                contents: vec![2],
            },
            PcoEntry {
                identifier: 0x003a,
                contents: vec![],
            },
            PcoEntry {
                identifier: 0x003a,
                contents: vec![7],
            },
        ] {
            assert!(entry.is_well_formed(PcoDirection::Uplink), "{entry:?}");
        }
        for entry in [
            PcoEntry {
                identifier: 0x0032,
                contents: vec![0],
            },
            PcoEntry {
                identifier: 0x0039,
                contents: vec![],
            },
            PcoEntry {
                identifier: 0x0039,
                contents: vec![3],
            },
            PcoEntry {
                identifier: 0x003a,
                contents: vec![8],
            },
            PcoEntry {
                identifier: 0x003a,
                contents: vec![0, 0],
            },
        ] {
            assert!(!entry.is_well_formed(PcoDirection::Uplink), "{entry:?}");
        }
        for entry in [
            PcoEntry {
                identifier: 0x0027,
                contents: vec![b'a'],
            },
            PcoEntry {
                identifier: 0x0036,
                contents: vec![0; 4],
            },
            PcoEntry {
                identifier: 0x0036,
                contents: vec![0; 9],
            },
            PcoEntry {
                identifier: 0x003b,
                contents: vec![0; 8],
            },
            PcoEntry {
                identifier: 0x003c,
                contents: vec![0; 32],
            },
        ] {
            assert!(entry.is_well_formed(PcoDirection::Downlink), "{entry:?}");
        }
        for entry in [
            PcoEntry {
                identifier: 0x0027,
                contents: vec![],
            },
            PcoEntry {
                identifier: 0x0036,
                contents: vec![0; 3],
            },
            PcoEntry {
                identifier: 0x003b,
                contents: vec![0; 7],
            },
            PcoEntry {
                identifier: 0x003c,
                contents: vec![0; 31],
            },
        ] {
            assert!(!entry.is_well_formed(PcoDirection::Downlink), "{entry:?}");
        }

        // Receivers use the first EAS capability octet and ignore extras,
        // while the same unit is not a conforming sender encoding.
        let eas_extra = [0x80, 0x00, 0x3a, 0x02, 0xf8, 0xaa];
        assert_eq!(
            Pco::from_bytes(&eas_extra, PcoDirection::Uplink)
                .unwrap()
                .entry(0x003a)
                .unwrap()
                .contents,
            [0xf8, 0xaa]
        );
        assert!(Pco::from_bytes_strict(&eas_extra, PcoDirection::Uplink).is_none());

        // Reserved container identifiers are invalid for senders, while
        // receiver parsing keeps unsupported units opaque.
        for (direction, identifier) in [
            (PcoDirection::Uplink, 0x0006),
            (PcoDirection::Uplink, 0x003b),
            (PcoDirection::Downlink, 0x0039),
            (PcoDirection::Downlink, 0x0058),
        ] {
            let entry = PcoEntry {
                identifier,
                contents: vec![],
            };
            assert!(!entry.is_well_formed(direction));
        }
        assert!(
            PcoEntry {
                identifier: 0xff00,
                contents: vec![0xaa],
            }
            .is_well_formed(PcoDirection::Uplink)
        );

        // A downlink empty indicator also survives forbidden contents.
        let downlink_indicator = [0x80, 0x00, 0x0f, 0x01, 0xaa];
        assert!(
            Pco::from_bytes(&downlink_indicator, PcoDirection::Downlink)
                .unwrap()
                .entry(0x000f)
                .is_some()
        );
        assert!(Pco::from_bytes_strict(&downlink_indicator, PcoDirection::Downlink).is_none());
    }

    fn pco_with_ppp() -> Pco {
        Pco {
            configuration_protocol: 0,
            entries: vec![PcoEntry {
                identifier: 0x0056,
                contents: vec![0; 300],
            }],
        }
    }

    #[test]
    fn network_name_time_and_emergency_numbers_decode_in_both_protocols() {
        use crate::nas_5gs::{NasNetworkName as FgsName, NasTimeZoneAndTime};
        use crate::nas_eps::{
            NasEmergencyNumberList, NasExtendedEmergencyNumberList, NasNetworkName,
            NasUniversalTimeAndLocalTimeZone,
        };

        // "OxiRush": seven GSM 7-bit characters leave seven spare bits.
        let name = NasNetworkName::from_name("OxiRush", false);
        assert_eq!((name.value[0], name.value.len()), (0x87, 8));
        assert_eq!(name.name().as_deref(), Some("OxiRush"));
        assert!(name.is_well_formed());
        let ucs2 = FgsName::from_name("Réseau 東", true);
        assert_eq!(ucs2.coding_scheme(), Some(NetworkNameCodingScheme::Ucs2));
        assert!(ucs2.add_ci());
        assert_eq!(ucs2.name().as_deref(), Some("Réseau 東"));
        let mut edited = FgsName::new(vec![]);
        edited.set_add_ci(true).set_name_data(&[0xd4]);
        assert_eq!(
            (edited.length, edited.value.as_slice()),
            (2, [0x88, 0xd4].as_slice())
        );
        assert!(!NasNetworkName::new(vec![0x20]).is_well_formed());

        // 2026-09-26 13:45:07, UTC+2 (8 quarter hours).
        let time = NasUniversalTimeAndLocalTimeZone::new(vec![0; 7])
            .with_year(26)
            .with_month(9)
            .with_day(26)
            .with_hour(13)
            .with_minute(45)
            .with_second(7)
            .with_timezone_quarter_hours(8)
            .unwrap();
        assert_eq!(time.value, [0x62, 0x90, 0x62, 0x31, 0x54, 0x70, 0x80]);
        let fgs = NasTimeZoneAndTime::new(time.value.clone());
        assert_eq!(
            (fgs.year(), fgs.minute(), fgs.timezone_quarter_hours()),
            (26, 45, 8)
        );
        assert!(time.is_well_formed() && fgs.is_well_formed());
        // Codec review O-4: BCD digits and calendar ranges (TS 23.040
        // §9.2.3.11) are sender rules.
        for invalid in [
            [0x62, 0x31, 0x99, 0x99, 0x99, 0x99, 0xff],
            [0x62, 0x31, 0x62, 0x31, 0x54, 0x70, 0xa0],
            [0x62, 0x00, 0x62, 0x31, 0x54, 0x70, 0x80],
        ] {
            assert!(!NasUniversalTimeAndLocalTimeZone::new(invalid.to_vec()).is_well_formed());
        }
        assert!(crate::nas_eps::NasLocalTimeZone::new(0x80).is_well_formed());
        assert!(!crate::nas_eps::NasLocalTimeZone::new(0xa0).is_well_formed());
        assert!(!crate::nas_5gs::NasTimeZone::new(0xa0).is_well_formed());

        // TS 24.008 §10.5.3.13: 112 and 911 for police (bit 1) and fire (bit 3).
        let numbers = [
            EmergencyNumber {
                categories: 0x01,
                digits: "112".into(),
            },
            EmergencyNumber {
                categories: 0x04,
                digits: "911".into(),
            },
        ];
        let list = NasEmergencyNumberList::from_numbers(&numbers).unwrap();
        assert_eq!(list.value, [3, 0x01, 0x11, 0xf2, 3, 0x04, 0x19, 0xf1]);
        assert!(list.is_well_formed());
        assert_eq!(list.numbers().unwrap(), numbers);
        let spare = NasEmergencyNumberList::new(vec![2, 0xe1, 0x21]);
        assert_eq!(spare.numbers().unwrap()[0].categories, 1);
        assert!(!spare.is_well_formed());

        let extended = [crate::common::ts24301::ExtendedEmergencyNumber {
            digits: "1234".into(),
            sub_services: "police.municipal".into(),
        }];
        let list = NasExtendedEmergencyNumberList::from_numbers(true, &extended).unwrap();
        assert!(list.is_well_formed());
        assert_eq!(list.valid_only_in_plmn(), Some(true));
        assert_eq!(list.numbers().unwrap(), extended);
        assert!(!NasExtendedEmergencyNumberList::new(vec![0x02, 1, 0x21, 0]).is_well_formed());
    }

    #[test]
    fn extended_drx_and_codec_lists_are_shared() {
        use crate::nas_5gs::{NasExtendedDrxParameters as FgsEdrx, NasSupportedCodecList};
        use crate::nas_eps::{NasExtendedDrxParameters, NasSupportedCodecs};

        let mut edrx = FgsEdrx::new(vec![]);
        edrx.set_paging_time_window(3).set_edrx_value(0x05);
        assert_eq!((edrx.length, edrx.value.as_slice()), (1, [0x35].as_slice()));
        assert_eq!(edrx.eutra_edrx_cycle_ms(EutraMode::Wideband), Some(81_920));
        assert_eq!(
            edrx.eutra_paging_time_window_ms(EutraMode::Narrowband),
            10_240
        );
        // NOTES 4 to 6 of Table 10.5.5.32.
        let short = NasExtendedDrxParameters::new(vec![0x01]);
        assert_eq!(
            short.effective_eutra_edrx_value(EutraMode::Narrowband),
            None
        );
        assert_eq!(short.eutra_edrx_cycle_ms(EutraMode::Wideband), Some(10_240));
        assert_eq!(
            NasExtendedDrxParameters::new(vec![0x07])
                .effective_eutra_edrx_value(EutraMode::Narrowband),
            Some(2)
        );
        assert_eq!(
            NasExtendedDrxParameters::new(vec![0x0f]).eutra_edrx_cycle_ms(EutraMode::Wideband),
            Some(2_621_440)
        );
        assert_eq!(
            NasExtendedDrxParameters::new(vec![0x0f, 0x12]).extended_paging_time_window(),
            Some(0x12)
        );

        let codecs =
            NasSupportedCodecs::from_codec_bitmaps(&[(0x04, vec![0x60, 0x04]), (0x00, vec![0x1f])])
                .unwrap();
        assert_eq!(codecs.value, [0x04, 2, 0x60, 0x04, 0x00, 1, 0x1f]);
        assert!(codecs.is_well_formed());
        let fgs = NasSupportedCodecList::from_data(codecs.value.clone());
        assert_eq!(fgs.codec_bitmaps().unwrap().len(), 2);
        assert!(!NasSupportedCodecList::from_data(vec![0x04, 3, 0x60]).is_well_formed());
    }
}
