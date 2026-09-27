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

//! Value grammars defined in TS 24.501 and delegated to by TS 24.301.
//!
//! The macros here add one implementation of each grammar to the 5GS type
//! and its EPS counterpart. Typed getters follow the receiver rules of
//! TS 24.007 §11.1.4 and §11.4.2; `is_well_formed()` checks sender rules.

/// UE status (TS 24.501 §9.11.3.56; TS 24.301 §9.9.3.54).
macro_rules! ue_status_ie {
    ($name:ident) => {
        crate::common::nas_ie_flags!($name {
            /// S1 mode registration status: EMM-REGISTERED (octet 3, bit 1).
            s1_mode_reg: 0, 1;
            /// N1 mode registration status: 5GMM-REGISTERED (octet 3, bit 2).
            n1_mode_reg: 0, 2;
        });

        impl $name {
            /// Build from both registration states with the spare bits clear.
            pub fn from_status(n1_reg: bool, s1_reg: bool) -> Self {
                Self::new(vec![(u8::from(n1_reg) << 1) | u8::from(s1_reg)])
            }

            /// Sender check: one octet with bits 8 to 3 clear.
            pub fn is_well_formed(&self) -> bool {
                matches!(self.value.as_slice(), [octet] if octet & 0xfc == 0)
            }
        }
    };
}

/// An inclusive port range: the lowest then the highest port number, each
/// two octets (TS 24.501 §9.11.4.29, TS 24.301 §9.9.4.20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PortRange {
    /// Lowest port number.
    pub low: u16,
    /// Highest port number.
    pub high: u16,
}

/// List of PLMNs to be used in disaster condition (TS 24.501 §9.11.3.83;
/// TS 24.301 §9.9.3.76): up to 85 PLMN identities in decreasing priority.
macro_rules! disaster_plmn_list_ie {
    ($name:ident) => {
        crate::common::plmn_sequence_ie!($name, 0, 85);
    };
}

/// UE radio capability ID (TS 24.501 §9.11.3.68; TS 24.301 §9.9.3.60):
/// hexadecimal digits, first digit in the low nibble, with an 0xF filler
/// after an odd count.
macro_rules! ue_radio_capability_id_ie {
    ($name:ident) => {
        impl $name {
            /// Hexadecimal digits in lower case; the filler ends the ID.
            pub fn id_string(&self) -> Option<String> {
                let mut id = String::with_capacity(self.value.len() * 2);
                for (index, &octet) in self.value.iter().enumerate() {
                    id.push(char::from_digit(u32::from(octet & 0x0f), 16)?);
                    if index + 1 == self.value.len() && octet >> 4 == 0x0f {
                        break;
                    }
                    id.push(char::from_digit(u32::from(octet >> 4), 16)?);
                }
                (!id.is_empty()).then_some(id)
            }

            /// Build from hexadecimal digits; `None` for an empty ID or a
            /// non-hexadecimal character.
            pub fn from_id_string(id: &str) -> Option<Self> {
                let digits = id
                    .chars()
                    .map(|digit| digit.to_digit(16).map(|value| value as u8))
                    .collect::<Option<Vec<_>>>()?;
                (!digits.is_empty()).then(|| {
                    Self::new(
                        digits
                            .chunks(2)
                            .map(|pair| pair[0] | pair.get(1).copied().unwrap_or(0x0f) << 4)
                            .collect(),
                    )
                })
            }
        }
    };
}

/// UE radio capability ID deletion request (TS 24.501 Table 9.11.3.69.1).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RadioCapabilityIdDeletionRequest {
    /// UE radio capability ID deletion not requested.
    NotRequested = 0,
    /// Network-assigned UE radio capability IDs deletion requested.
    NetworkAssignedDeletion = 1,
}

impl RadioCapabilityIdDeletionRequest {
    /// Decode bits 3-1; unused values are read as "not requested" by the
    /// UE. Always returns `Some`.
    pub fn from_u8(value: u8) -> Option<Self> {
        Some(Self::from_u8_strict(value).unwrap_or(Self::NotRequested))
    }

    /// Decode only the defined values.
    pub fn from_u8_strict(value: u8) -> Option<Self> {
        match value & 0x07 {
            0 => Some(Self::NotRequested),
            1 => Some(Self::NetworkAssignedDeletion),
            _ => None,
        }
    }
}

/// UE radio capability ID deletion indication (TS 24.501 §9.11.3.69; TS
/// 24.301 §9.9.3.61), a type 1 IE.
macro_rules! ue_radio_capability_id_deletion_indication_ie {
    ($name:ident) => {
        impl $name {
            /// Deletion request with the UE receive fallback.
            pub fn deletion_request(&self) -> Option<RadioCapabilityIdDeletionRequest> {
                RadioCapabilityIdDeletionRequest::from_u8(self.value)
            }

            /// Raw deletion request (bits 3-1).
            pub fn deletion_request_raw(&self) -> u8 {
                self.value & 0x07
            }

            /// Build from a deletion request with the spare bit clear.
            pub fn from_deletion_request(request: RadioCapabilityIdDeletionRequest) -> Self {
                Self::new(request as u8)
            }

            /// Build from a raw three-bit value.
            pub fn from_deletion_request_raw(request: u8) -> Self {
                Self::new(request & 0x07)
            }
        }
    };
}

/// Registration wait range (TS 24.501 §9.11.3.84; TS 24.301 §9.9.3.75):
/// minimum and maximum wait times, each a GPRS timer octet.
macro_rules! registration_wait_range_ie {
    ($name:ident) => {
        impl $name {
            fn wait_seconds(octet: Option<&u8>) -> Option<u64> {
                let octet = *octet?;
                let unit = crate::common::ts24008::GprsTimerUnit::from_u8(octet >> 5)?;
                (unit != crate::common::ts24008::GprsTimerUnit::Deactivated)
                    .then(|| unit.seconds_multiplier() * u64::from(octet & 0x1f))
            }

            /// Minimum wait time in seconds; `None` if deactivated or missing.
            pub fn min_seconds(&self) -> Option<u64> {
                Self::wait_seconds(self.value.first())
            }

            /// Maximum wait time in seconds; `None` if deactivated or missing.
            pub fn max_seconds(&self) -> Option<u64> {
                Self::wait_seconds(self.value.get(1))
            }

            /// Build from wait times in seconds; `None` unless both are
            /// exactly representable as GPRS timer octets.
            pub fn from_range(min_seconds: u64, max_seconds: u64) -> Option<Self> {
                Some(Self::new(vec![
                    crate::common::ts24008::gprs_timer_octet_from_seconds(min_seconds)?,
                    crate::common::ts24008::gprs_timer_octet_from_seconds(max_seconds)?,
                ]))
            }

            /// Sender check: two octets with defined units and minimum not
            /// above maximum.
            pub fn is_well_formed(&self) -> bool {
                let defined = |octet: &u8| {
                    crate::common::ts24008::GprsTimerUnit::from_u8_strict(octet >> 5).is_some()
                };
                matches!(self.value.as_slice(), [min, max] if defined(min) && defined(max))
                    && self.min_seconds() <= self.max_seconds()
            }
        }
    };
}

/// PLMN identity (TS 24.501 §9.11.3.85; TS 24.301 §9.9.3.77): MCC and MNC
/// in three octets. Octets after the third are ignored.
macro_rules! plmn_identity_ie {
    ($name:ident) => {
        impl $name {
            /// The PLMN identity; `None` for fewer than three octets or a
            /// digit that does not decode.
            pub fn plmn(&self) -> Option<PlmnId> {
                PlmnId::from_tbcd(self.value.get(..3)?)
            }

            /// Build from a PLMN identity.
            pub fn from_plmn(plmn: &PlmnId) -> Self {
                Self::new(plmn.to_tbcd().to_vec())
            }

            /// Sender check: exactly three octets that decode.
            pub fn is_well_formed(&self) -> bool {
                self.value.len() == 3 && self.plmn().is_some()
            }
        }
    };
}

pub(crate) use {
    disaster_plmn_list_ie, plmn_identity_ie, registration_wait_range_ie,
    ue_radio_capability_id_deletion_indication_ie, ue_radio_capability_id_ie, ue_status_ie,
};

#[cfg(test)]
mod tests {
    #[test]
    fn radio_capability_and_wait_range_grammars_are_shared() {
        use super::RadioCapabilityIdDeletionRequest;
        use crate::nas_5gs::{self, NasRegistrationWaitRange};
        use crate::nas_eps::{self, NasDisasterReturnWaitRange};

        let id = nas_eps::NasUeRadioCapabilityId::from_id_string("1aB").unwrap();
        assert_eq!(id.value, [0xa1, 0xfb]);
        assert_eq!(id.id_string().as_deref(), Some("1ab"));
        assert!(nas_5gs::NasUeRadioCapabilityId::from_id_string("xyz").is_none());

        let deletion = nas_eps::NasUeRadioCapabilityIdDeletionIndication::new(0x0e);
        assert_eq!(
            deletion.deletion_request(),
            Some(RadioCapabilityIdDeletionRequest::NotRequested)
        );
        assert_eq!(
            RadioCapabilityIdDeletionRequest::from_u8_strict(deletion.value),
            None
        );

        let plmn = crate::common::PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0f],
        };
        let disaster = nas_eps::NasUeDeterminedPlmnWithDisasterCondition::from_plmn(&plmn);
        assert!(disaster.is_well_formed());
        assert_eq!(
            nas_5gs::NasPlmnIdentity::new(vec![0x02, 0xf8, 0x39, 0]).plmn(),
            Some(plmn)
        );

        let range = NasDisasterReturnWaitRange::from_range(120, 1_800).unwrap();
        assert_eq!(range.value, [0x22, 0x3e]);
        assert_eq!(
            (range.min_seconds(), range.max_seconds()),
            (Some(120), Some(1_800))
        );
        assert!(range.is_well_formed());
        // Unit 011 is read as minutes by the receiver but fails the sender check.
        let received = NasRegistrationWaitRange::new(vec![0x61, 0x62]);
        assert_eq!(received.min_seconds(), Some(60));
        assert!(!received.is_well_formed());
    }
}
