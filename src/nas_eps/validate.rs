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

//! Structural validation helpers for EPS NAS messages against TS 24.301.
//!
//! The [`Validate`] trait returns [`ValidationError`] findings with a
//! [`Severity`] of Error or Warning. Checks cover the byte lengths and spare
//! half octets specified by the chapter 8 message tables, plus sender-side
//! value rules. The decoder still accepts values with specified receiver
//! fallback behavior; these can yield validation findings.
//! An empty list means these implemented checks passed; it does not imply
//! complete procedure validation.
//!
//! # Example
//!
//! ```rust
//! use oxirush_nas::nas_eps::{Validate, decode_nas_eps_message};
//!
//! let message = decode_nas_eps_message(&[0x07, 0x60, 0x03]).unwrap();
//! assert!(message.validate().is_empty());
//! ```

use crate::common::{ReceiverSyntaxCheck, with_optional_ie_checks};
pub use crate::common::{Severity, Validate, ValidationError};
use crate::nas_eps::ie::*;
use crate::nas_eps::message_types::NasEpsSecurityHeaderType;
use crate::nas_eps::messages::*;
use crate::nas_eps::types::*;

// Receiver syntax is intentionally narrower than sender validation. In
// particular, TS 24.007 §11.4.2 says that extra value octets in type 4 and
// type 6 IEs are ignored, so the timer check accepts every non-empty value
// even though a sender emits exactly one octet.
impl ReceiverSyntaxCheck for NasGprsTimer2 {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

macro_rules! nonempty_gprs_timer_2_receiver {
    ($($name:ident),* $(,)?) => {
        $(
            impl ReceiverSyntaxCheck for $name {
                fn receiver_syntax_ok(&self) -> bool {
                    !self.value.is_empty()
                }
            }
        )*
    };
}

nonempty_gprs_timer_2_receiver!(NasT3346Value, NasT3324Value, NasT3448Value);

impl ReceiverSyntaxCheck for NasCli {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasAccessPointName {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasEpsMobileIdentity {
    fn receiver_syntax_ok(&self) -> bool {
        self.as_imsi().is_some() || self.as_imei().is_some() || self.as_guti().is_some()
    }
}

impl ReceiverSyntaxCheck for NasMobileIdentity {
    fn receiver_syntax_ok(&self) -> bool {
        self.as_imsi().is_some()
            || self.as_imei().is_some()
            || self.as_imeisv().is_some()
            || self.as_tmsi().is_some()
            || matches!(self.value.as_slice(), [0, 0, 0, ..])
    }
}

impl ReceiverSyntaxCheck for NasAuthenticationParameterAutnEpsChallenge {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 16
    }
}

impl ReceiverSyntaxCheck for NasAuthenticationResponseParameter {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 4
    }
}

impl ReceiverSyntaxCheck for NasAuthenticationFailureParameter {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 14
    }
}

impl ReceiverSyntaxCheck for NasEsmMessageContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 3
    }
}

impl ReceiverSyntaxCheck for NasMessageContainer {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 2
    }
}

impl ReceiverSyntaxCheck for NasNegotiatedQos {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasNewQos {
    fn receiver_syntax_ok(&self) -> bool {
        self.receiver_syntax_is_valid()
    }
}

impl ReceiverSyntaxCheck for NasRequiredTrafficFlowQos {
    fn receiver_syntax_ok(&self) -> bool {
        self.qos().is_some()
    }
}

// Errors inside a TFT are errors of the ESM procedure (TS 24.301 §6.4.2.4,
// §6.4.3.4, §6.5.3.4, §6.5.4.4), which the receiver answers with the ESM
// cause of parse_tft. Only an empty value is short of the message tables.
impl ReceiverSyntaxCheck for NasTft {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasTrafficFlowAggregate {
    fn receiver_syntax_ok(&self) -> bool {
        !self.value.is_empty()
    }
}

impl ReceiverSyntaxCheck for NasEpsQos {
    fn receiver_syntax_ok(&self) -> bool {
        self.qos().is_some()
    }
}

impl ReceiverSyntaxCheck for NasPdnAddress {
    fn receiver_syntax_ok(&self) -> bool {
        self.pdn_address().is_some()
    }
}

impl ReceiverSyntaxCheck for NasReplayedUeSecurityCapabilities {
    fn receiver_syntax_ok(&self) -> bool {
        matches!(self.value.len(), 2 | 4..)
    }
}

impl ReceiverSyntaxCheck for NasTaiList {
    fn receiver_syntax_ok(&self) -> bool {
        self.tai_list().is_some()
    }
}

impl ReceiverSyntaxCheck for NasUeNetworkCapability {
    fn receiver_syntax_ok(&self) -> bool {
        self.value.len() >= 2
    }
}

// BEGIN TS24301 VALIDATE
// TS 24.301 V19.8.0 chapter 8/9 table definitions.

impl Validate for NasAttachAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "eps_attach_result",
            self.eps_attach_result.value as usize,
            0,
            Some(7),
        );
        check_eps_ie_one_of(
            &mut errors,
            "eps_attach_result",
            self.eps_attach_result.value as usize,
            &[1, 2],
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        check_eps_declared_length(
            &mut errors,
            "tai_list",
            self.tai_list.length as usize,
            self.tai_list.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "tai_list",
            self.tai_list.value.len() + 1,
            7,
            Some(97),
        );
        check_eps_ie_valid(&mut errors, "tai_list", self.tai_list.is_well_formed());
        check_eps_declared_length(
            &mut errors,
            "esm_message_container",
            self.esm_message_container.length as usize,
            self.esm_message_container.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "esm_message_container",
            self.esm_message_container.value.len() + 2,
            5,
            None,
        );
        if let Some(ie) = &self.guti {
            check_eps_declared_length(&mut errors, "guti", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "guti", ie.value.len() + 2, 13, Some(13));
            check_eps_ie_valid(
                &mut errors,
                "guti",
                ie.as_guti().is_some() && ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.location_area_identification {
            check_eps_ie(
                &mut errors,
                "location_area_identification",
                ie.value.len() + 1,
                6,
                Some(6),
            );
        }
        if let Some(ie) = &self.ms_identity {
            check_eps_declared_length(
                &mut errors,
                "ms_identity",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "ms_identity", ie.value.len() + 2, 7, Some(10));
        }
        if let Some(ie) = &self.equivalent_plmns {
            check_eps_declared_length(
                &mut errors,
                "equivalent_plmns",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "equivalent_plmns",
                ie.value.len() + 2,
                5,
                Some(47),
            );
            check_eps_ie_valid(&mut errors, "equivalent_plmns", ie.is_well_formed());
        }
        if let Some(ie) = &self.emergency_number_list {
            check_eps_declared_length(
                &mut errors,
                "emergency_number_list",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "emergency_number_list",
                ie.value.len() + 2,
                5,
                Some(50),
            );
            check_eps_ie_valid(&mut errors, "emergency_number_list", ie.is_well_formed());
        }
        if let Some(ie) = &self.eps_network_feature_support {
            check_eps_declared_length(
                &mut errors,
                "eps_network_feature_support",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_network_feature_support",
                ie.value.len() + 2,
                3,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_network_feature_support",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.additional_update_result {
            check_eps_ie_one_of(
                &mut errors,
                "additional_update_result",
                ie.value as usize,
                &[0, 1, 2],
            );
        }
        if let Some(ie) = &self.t3412_extended_value {
            check_eps_declared_length(
                &mut errors,
                "t3412_extended_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "t3412_extended_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "t3412_extended_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.t3324_value {
            check_eps_declared_length(
                &mut errors,
                "t3324_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3324_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3324_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_drx_parameters {
            check_eps_declared_length(
                &mut errors,
                "extended_drx_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_drx_parameters",
                ie.value.len() + 2,
                3,
                Some(3),
            );
        }
        if let Some(ie) = &self.dcn_id {
            check_eps_declared_length(&mut errors, "dcn_id", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "dcn_id", ie.value.len() + 2, 4, Some(4));
        }
        if let Some(ie) = &self.sms_services_status {
            check_eps_ie_one_of(
                &mut errors,
                "sms_services_status",
                ie.value as usize,
                &[0, 1, 2, 3],
            );
        }
        if let Some(ie) = &self.non_3gpp_nw_provided_policies {
            check_eps_ie_one_of(
                &mut errors,
                "non_3gpp_nw_provided_policies",
                ie.value as usize,
                &[0, 1],
            );
        }
        if let Some(ie) = &self.t3448_value {
            check_eps_declared_length(
                &mut errors,
                "t3448_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3448_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3448_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.network_policy {
            check_eps_ie_one_of(&mut errors, "network_policy", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.t3447_value {
            check_eps_declared_length(
                &mut errors,
                "t3447_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3447_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3447_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_emergency_number_list {
            check_eps_declared_length(
                &mut errors,
                "extended_emergency_number_list",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_emergency_number_list",
                ie.value.len() + 3,
                7,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_emergency_number_list",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.ciphering_key_data {
            check_eps_declared_length(
                &mut errors,
                "ciphering_key_data",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ciphering_key_data",
                ie.value.len() + 3,
                35,
                Some(2291),
            );
            check_eps_ie_valid(&mut errors, "ciphering_key_data", ie.is_well_formed());
        }
        if let Some(ie) = &self.ue_radio_capability_id {
            check_eps_declared_length(
                &mut errors,
                "ue_radio_capability_id",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id",
                ie.value.len() + 2,
                3,
                None,
            );
        }
        if let Some(ie) = &self.ue_radio_capability_id_deletion_indication {
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id_deletion_indication",
                ie.value as usize,
                0,
                Some(15),
            );
        }
        if let Some(ie) = &self.negotiated_wus_assistance_information {
            check_eps_declared_length(
                &mut errors,
                "negotiated_wus_assistance_information",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "negotiated_wus_assistance_information",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "negotiated_wus_assistance_information",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.negotiated_drx_parameter_in_nb_s1_mode {
            check_eps_declared_length(
                &mut errors,
                "negotiated_drx_parameter_in_nb_s1_mode",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "negotiated_drx_parameter_in_nb_s1_mode",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "negotiated_drx_parameter_in_nb_s1_mode",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.negotiated_imsi_offset {
            check_eps_declared_length(
                &mut errors,
                "negotiated_imsi_offset",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "negotiated_imsi_offset",
                ie.value.len() + 2,
                4,
                Some(4),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming
        {
            check_eps_declared_length(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.value.len() + 2,
                8,
                Some(98),
            );
            check_eps_ie_valid(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service {
            check_eps_declared_length(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.is_well_formed());
        }
        if let Some(ie) = &self.unavailability_configuration {
            check_eps_declared_length(
                &mut errors,
                "unavailability_configuration",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "unavailability_configuration",
                ie.value.len() + 2,
                3,
                Some(9),
            );
            check_eps_ie_valid(
                &mut errors,
                "unavailability_configuration",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.access_technology_utilization_control {
            check_eps_declared_length(
                &mut errors,
                "access_technology_utilization_control",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_technology_utilization_control",
                ie.value.len() + 2,
                2,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "access_technology_utilization_control",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.s_and_f_satellite_operation_parameters {
            check_eps_declared_length(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.disaster_roaming_wait_range {
            check_eps_declared_length(
                &mut errors,
                "disaster_roaming_wait_range",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "disaster_roaming_wait_range",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "disaster_roaming_wait_range",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.disaster_return_wait_range {
            check_eps_declared_length(
                &mut errors,
                "disaster_return_wait_range",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "disaster_return_wait_range",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "disaster_return_wait_range",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.list_of_plmns_to_be_used_in_disaster_condition {
            check_eps_declared_length(
                &mut errors,
                "list_of_plmns_to_be_used_in_disaster_condition",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "list_of_plmns_to_be_used_in_disaster_condition",
                ie.value.len() + 2,
                2,
                None,
            );
            check_eps_ie_valid(
                &mut errors,
                "list_of_plmns_to_be_used_in_disaster_condition",
                ie.is_well_formed(),
            );
        }
        check_esm_message_container(
            &mut errors,
            &self.esm_message_container.value,
            Severity::Warning,
        );
        errors
    }
}

impl Validate for NasAttachComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "esm_message_container",
            self.esm_message_container.length as usize,
            self.esm_message_container.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "esm_message_container",
            self.esm_message_container.value.len() + 2,
            5,
            None,
        );
        check_esm_message_container(
            &mut errors,
            &self.esm_message_container.value,
            Severity::Warning,
        );
        errors
    }
}

impl Validate for NasAttachReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.esm_message_container {
            check_eps_declared_length(
                &mut errors,
                "esm_message_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "esm_message_container",
                ie.value.len() + 3,
                6,
                None,
            );
        }
        if let Some(ie) = &self.t3346_value {
            check_eps_declared_length(
                &mut errors,
                "t3346_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3346_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3346_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.t3402_value {
            check_eps_declared_length(
                &mut errors,
                "t3402_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3402_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3402_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_emm_cause {
            check_eps_ie(
                &mut errors,
                "extended_emm_cause",
                ie.value as usize,
                0,
                Some(15),
            );
        }
        if let Some(ie) = &self.lower_bound_timer_value {
            check_eps_declared_length(
                &mut errors,
                "lower_bound_timer_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "lower_bound_timer_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "lower_bound_timer_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming
        {
            check_eps_declared_length(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.value.len() + 2,
                8,
                Some(98),
            );
            check_eps_ie_valid(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service {
            check_eps_declared_length(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.is_well_formed());
        }
        if let Some(ie) = &self.access_technology_utilization_control {
            check_eps_declared_length(
                &mut errors,
                "access_technology_utilization_control",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_technology_utilization_control",
                ie.value.len() + 2,
                2,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "access_technology_utilization_control",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.s_and_f_satellite_operation_parameters {
            check_eps_declared_length(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.esm_message_container {
            check_esm_message_container(&mut errors, &ie.value, Severity::Error);
        }
        errors
    }
}

impl Validate for NasAttachRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "eps_attach_type",
            self.eps_attach_type.value as usize,
            0,
            Some(7),
        );
        check_eps_ie_one_of(
            &mut errors,
            "eps_attach_type",
            self.eps_attach_type.value as usize,
            &[1, 2, 3, 6, 7],
        );
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier",
            self.nas_key_set_identifier.value as usize,
            0,
            Some(15),
        );
        check_eps_declared_length(
            &mut errors,
            "eps_mobile_identity",
            self.eps_mobile_identity.length as usize,
            self.eps_mobile_identity.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "eps_mobile_identity",
            self.eps_mobile_identity.value.len() + 1,
            5,
            Some(12),
        );
        check_eps_ie_valid(
            &mut errors,
            "eps_mobile_identity",
            self.eps_mobile_identity.is_well_formed(),
        );
        check_eps_declared_length(
            &mut errors,
            "ue_network_capability",
            self.ue_network_capability.length as usize,
            self.ue_network_capability.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "ue_network_capability",
            self.ue_network_capability.value.len() + 1,
            3,
            Some(14),
        );
        check_eps_ie_valid(
            &mut errors,
            "ue_network_capability",
            self.ue_network_capability.is_well_formed(),
        );
        check_eps_declared_length(
            &mut errors,
            "esm_message_container",
            self.esm_message_container.length as usize,
            self.esm_message_container.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "esm_message_container",
            self.esm_message_container.value.len() + 2,
            5,
            None,
        );
        if let Some(ie) = &self.old_p_tmsi_signature {
            check_eps_ie(
                &mut errors,
                "old_p_tmsi_signature",
                ie.value.len() + 1,
                4,
                Some(4),
            );
        }
        if let Some(ie) = &self.additional_guti {
            check_eps_declared_length(
                &mut errors,
                "additional_guti",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "additional_guti",
                ie.value.len() + 2,
                13,
                Some(13),
            );
            check_eps_ie_valid(
                &mut errors,
                "additional_guti",
                ie.as_guti().is_some() && ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.last_visited_registered_tai {
            check_eps_ie(
                &mut errors,
                "last_visited_registered_tai",
                ie.value.len() + 1,
                6,
                Some(6),
            );
        }
        if let Some(ie) = &self.drx_parameter {
            check_eps_ie(&mut errors, "drx_parameter", ie.value.len() + 1, 3, Some(3));
            check_eps_ie_valid(&mut errors, "drx_parameter", ie.is_well_formed());
        }
        if let Some(ie) = &self.ms_network_capability {
            check_eps_declared_length(
                &mut errors,
                "ms_network_capability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ms_network_capability",
                ie.value.len() + 2,
                4,
                Some(10),
            );
            check_eps_ie_valid(&mut errors, "ms_network_capability", ie.is_well_formed());
        }
        if let Some(ie) = &self.old_location_area_identification {
            check_eps_ie(
                &mut errors,
                "old_location_area_identification",
                ie.value.len() + 1,
                6,
                Some(6),
            );
        }
        if let Some(ie) = &self.tmsi_status {
            check_eps_ie_one_of(&mut errors, "tmsi_status", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.mobile_station_classmark_2 {
            check_eps_declared_length(
                &mut errors,
                "mobile_station_classmark_2",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "mobile_station_classmark_2",
                ie.value.len() + 2,
                5,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "mobile_station_classmark_2",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.mobile_station_classmark_3 {
            check_eps_declared_length(
                &mut errors,
                "mobile_station_classmark_3",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "mobile_station_classmark_3",
                ie.value.len() + 2,
                2,
                Some(34),
            );
            check_eps_ie_valid(
                &mut errors,
                "mobile_station_classmark_3",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.supported_codecs {
            check_eps_declared_length(
                &mut errors,
                "supported_codecs",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "supported_codecs", ie.value.len() + 2, 5, None);
            check_eps_ie_valid(&mut errors, "supported_codecs", ie.is_well_formed());
        }
        if let Some(ie) = &self.additional_update_type {
            check_eps_ie_valid(
                &mut errors,
                "additional_update_type",
                ie.value & 0x0c != 0x0c,
            );
        }
        if let Some(ie) = &self.voice_domain_preference_and_ue_usage_setting {
            check_eps_declared_length(
                &mut errors,
                "voice_domain_preference_and_ue_usage_setting",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "voice_domain_preference_and_ue_usage_setting",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "voice_domain_preference_and_ue_usage_setting",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.device_properties {
            check_eps_ie_one_of(&mut errors, "device_properties", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.old_guti_type {
            check_eps_ie_one_of(&mut errors, "old_guti_type", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.ms_network_feature_support {
            check_eps_ie_one_of(
                &mut errors,
                "ms_network_feature_support",
                ie.value as usize,
                &[0, 1],
            );
        }
        if let Some(ie) = &self.tmsi_based_nri_container {
            check_eps_declared_length(
                &mut errors,
                "tmsi_based_nri_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "tmsi_based_nri_container",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(&mut errors, "tmsi_based_nri_container", ie.is_well_formed());
        }
        if let Some(ie) = &self.t3324_value {
            check_eps_declared_length(
                &mut errors,
                "t3324_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3324_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3324_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.t3412_extended_value {
            check_eps_declared_length(
                &mut errors,
                "t3412_extended_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "t3412_extended_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "t3412_extended_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_drx_parameters {
            check_eps_declared_length(
                &mut errors,
                "extended_drx_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_drx_parameters",
                ie.value.len() + 2,
                3,
                Some(3),
            );
        }
        if let Some(ie) = &self.ue_additional_security_capability {
            check_eps_declared_length(
                &mut errors,
                "ue_additional_security_capability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_additional_security_capability",
                ie.value.len() + 2,
                6,
                Some(6),
            );
            check_eps_ie_valid(
                &mut errors,
                "ue_additional_security_capability",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.ue_status {
            check_eps_declared_length(&mut errors, "ue_status", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "ue_status", ie.value.len() + 2, 3, Some(3));
        }
        if let Some(ie) = &self.additional_information_requested {
            check_eps_ie_valid(
                &mut errors,
                "additional_information_requested",
                ie.value <= 1,
            );
        }
        if let Some(ie) = &self.n1_ue_network_capability {
            check_eps_declared_length(
                &mut errors,
                "n1_ue_network_capability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "n1_ue_network_capability",
                ie.value.len() + 2,
                3,
                Some(15),
            );
            check_eps_ie_valid(&mut errors, "n1_ue_network_capability", ie.is_well_formed());
        }
        if let Some(ie) = &self.ue_radio_capability_id_availability {
            check_eps_declared_length(
                &mut errors,
                "ue_radio_capability_id_availability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id_availability",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "ue_radio_capability_id_availability",
                ie.value.as_slice().first().is_some_and(|octet| *octet <= 1),
            );
        }
        if let Some(ie) = &self.requested_wus_assistance_information {
            check_eps_declared_length(
                &mut errors,
                "requested_wus_assistance_information",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "requested_wus_assistance_information",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "requested_wus_assistance_information",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.drx_parameter_in_nb_s1_mode {
            check_eps_declared_length(
                &mut errors,
                "drx_parameter_in_nb_s1_mode",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "drx_parameter_in_nb_s1_mode",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "drx_parameter_in_nb_s1_mode",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.requested_imsi_offset {
            check_eps_declared_length(
                &mut errors,
                "requested_imsi_offset",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "requested_imsi_offset",
                ie.value.len() + 2,
                4,
                Some(4),
            );
        }
        if let Some(ie) = &self.ue_determined_plmn_with_disaster_condition {
            check_eps_declared_length(
                &mut errors,
                "ue_determined_plmn_with_disaster_condition",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_determined_plmn_with_disaster_condition",
                ie.value.len() + 2,
                5,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "ue_determined_plmn_with_disaster_condition",
                ie.is_well_formed(),
            );
        }
        check_esm_message_container(
            &mut errors,
            &self.esm_message_container.value,
            Severity::Warning,
        );
        if self.t3412_extended_value.is_some() && self.t3324_value.is_none() {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "t3412_extended_value",
                message: "Extended T3412 requires T3324".into(),
            });
        }
        if self.ue_determined_plmn_with_disaster_condition.is_some()
            && self.eps_attach_type.value & 0x07 != 7
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "ue_determined_plmn_with_disaster_condition",
                message: "Disaster condition PLMN requires disaster roaming request type".into(),
            });
        }
        if self.eps_mobile_identity.identity_type() == Some(MobileIdentityType::Guti)
            && self.old_guti_type.is_none()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "old_guti_type",
                message: "Old GUTI type is required when ATTACH REQUEST uses a GUTI".into(),
            });
        }
        if let Ok(NasEpsMessage::Esm(_, NasEsmMessage::PdnConnectivityRequest(request))) =
            decode_nas_eps_message(&self.esm_message_container.value)
            && request.access_point_name.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "esm_message_container",
                message: "APN is forbidden in an ATTACH REQUEST PDN container".into(),
            });
        }
        errors
    }
}

impl Validate for NasAuthenticationFailure {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.authentication_failure_parameter {
            check_eps_declared_length(
                &mut errors,
                "authentication_failure_parameter",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "authentication_failure_parameter",
                ie.value.len() + 2,
                16,
                Some(16),
            );
        }
        if (self.emm_cause.value == 0x15) != self.authentication_failure_parameter.is_some() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "authentication_failure_parameter",
                message: "AUTS is required exactly for synchronization failure".into(),
            });
        }
        errors
    }
}

impl Validate for NasAuthenticationReject {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasAuthenticationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier_asme",
            self.nas_key_set_identifier_asme.value as usize,
            0,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        check_eps_ie(
            &mut errors,
            "authentication_parameter_rand_eps_challenge",
            self.authentication_parameter_rand_eps_challenge.value.len(),
            16,
            Some(16),
        );
        check_eps_declared_length(
            &mut errors,
            "authentication_parameter_autn_eps_challenge",
            self.authentication_parameter_autn_eps_challenge.length as usize,
            self.authentication_parameter_autn_eps_challenge.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "authentication_parameter_autn_eps_challenge",
            self.authentication_parameter_autn_eps_challenge.value.len() + 1,
            17,
            Some(17),
        );
        check_eps_ie_valid(
            &mut errors,
            "nas_key_set_identifier_asme",
            self.nas_key_set_identifier_asme.value <= 6,
        );
        errors
    }
}

impl Validate for NasAuthenticationResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "authentication_response_parameter",
            self.authentication_response_parameter.length as usize,
            self.authentication_response_parameter.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "authentication_response_parameter",
            self.authentication_response_parameter.value.len() + 1,
            5,
            Some(17),
        );
        errors
    }
}

impl Validate for NasCsServiceNotification {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie_valid(
            &mut errors,
            "paging_identity",
            self.paging_identity.value <= 1,
        );
        if let Some(ie) = &self.cli {
            check_eps_declared_length(&mut errors, "cli", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "cli", ie.value.len() + 2, 3, Some(14));
            check_eps_ie_valid(&mut errors, "cli", ie.is_well_formed());
        }
        if let Some(ie) = &self.lcs_client_identity {
            check_eps_declared_length(
                &mut errors,
                "lcs_client_identity",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "lcs_client_identity",
                ie.value.len() + 2,
                3,
                Some(257),
            );
        }
        errors
    }
}

impl Validate for NasDetachAccept {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasDetachRequestFromUe {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "detach_type",
            self.detach_type.value as usize,
            0,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier",
            self.nas_key_set_identifier.value as usize,
            0,
            Some(15),
        );
        check_eps_declared_length(
            &mut errors,
            "eps_mobile_identity",
            self.eps_mobile_identity.length as usize,
            self.eps_mobile_identity.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "eps_mobile_identity",
            self.eps_mobile_identity.value.len() + 1,
            5,
            Some(12),
        );
        check_eps_ie_valid(
            &mut errors,
            "eps_mobile_identity",
            self.eps_mobile_identity.is_well_formed(),
        );
        check_eps_ie_valid(
            &mut errors,
            "detach_type",
            matches!(self.detach_type.value & 0x07, 1..=3),
        );
        errors
    }
}

impl Validate for NasDetachRequestToUe {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "detach_type",
            self.detach_type.value as usize,
            0,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        if let Some(ie) = &self.lower_bound_timer_value {
            check_eps_declared_length(
                &mut errors,
                "lower_bound_timer_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "lower_bound_timer_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "lower_bound_timer_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming
        {
            check_eps_declared_length(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.value.len() + 2,
                8,
                Some(98),
            );
            check_eps_ie_valid(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service {
            check_eps_declared_length(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.is_well_formed());
        }
        if let Some(ie) = &self.access_technology_utilization_control {
            check_eps_declared_length(
                &mut errors,
                "access_technology_utilization_control",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_technology_utilization_control",
                ie.value.len() + 2,
                2,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "access_technology_utilization_control",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.s_and_f_satellite_operation_parameters {
            check_eps_declared_length(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.disaster_return_wait_range {
            check_eps_declared_length(
                &mut errors,
                "disaster_return_wait_range",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "disaster_return_wait_range",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "disaster_return_wait_range",
                ie.is_well_formed(),
            );
        }
        check_eps_ie_valid(
            &mut errors,
            "detach_type",
            matches!(self.detach_type.value & 0x07, 1..=3),
        );
        check_eps_ie_valid(
            &mut errors,
            "detach_type",
            self.detach_type.value & 0x08 == 0,
        );
        errors
    }
}

impl Validate for NasDownlinkNasTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "nas_message_container",
            self.nas_message_container.length as usize,
            self.nas_message_container.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "nas_message_container",
            self.nas_message_container.value.len() + 1,
            3,
            Some(252),
        );
        errors
    }
}

impl Validate for NasEmmInformation {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.full_name_for_network {
            check_eps_declared_length(
                &mut errors,
                "full_name_for_network",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "full_name_for_network",
                ie.value.len() + 2,
                3,
                None,
            );
            check_eps_ie_valid(&mut errors, "full_name_for_network", ie.is_well_formed());
        }
        if let Some(ie) = &self.short_name_for_network {
            check_eps_declared_length(
                &mut errors,
                "short_name_for_network",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "short_name_for_network",
                ie.value.len() + 2,
                3,
                None,
            );
            check_eps_ie_valid(&mut errors, "short_name_for_network", ie.is_well_formed());
        }
        if let Some(ie) = &self.universal_time_and_local_time_zone {
            check_eps_ie(
                &mut errors,
                "universal_time_and_local_time_zone",
                ie.value.len() + 1,
                8,
                Some(8),
            );
            check_eps_ie_valid(
                &mut errors,
                "universal_time_and_local_time_zone",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.network_daylight_saving_time {
            check_eps_declared_length(
                &mut errors,
                "network_daylight_saving_time",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "network_daylight_saving_time",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "network_daylight_saving_time",
                ie.is_well_formed(),
            );
        }
        errors
    }
}

impl Validate for NasEmmStatus {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasExtendedServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "service_type",
            self.service_type.value as usize,
            0,
            Some(15),
        );
        check_eps_ie_one_of(
            &mut errors,
            "service_type",
            self.service_type.value as usize,
            &[0, 1, 2, 8],
        );
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier",
            self.nas_key_set_identifier.value as usize,
            0,
            Some(15),
        );
        check_eps_declared_length(
            &mut errors,
            "m_tmsi",
            self.m_tmsi.length as usize,
            self.m_tmsi.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "m_tmsi",
            self.m_tmsi.value.len() + 1,
            6,
            Some(6),
        );
        check_eps_ie_valid(
            &mut errors,
            "m_tmsi",
            self.m_tmsi.as_tmsi().is_some() && self.m_tmsi.is_well_formed(),
        );
        if let Some(ie) = &self.csfb_response {
            check_eps_ie_one_of(&mut errors, "csfb_response", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.eps_bearer_context_status {
            check_eps_declared_length(
                &mut errors,
                "eps_bearer_context_status",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_bearer_context_status",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_bearer_context_status",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.device_properties {
            check_eps_ie_one_of(&mut errors, "device_properties", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.ue_request_type {
            check_eps_declared_length(
                &mut errors,
                "ue_request_type",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_request_type",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "ue_request_type", ie.is_well_formed());
        }
        if let Some(ie) = &self.paging_restriction {
            check_eps_declared_length(
                &mut errors,
                "paging_restriction",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "paging_restriction",
                ie.value.len() + 2,
                3,
                Some(5),
            );
            check_eps_ie_valid(&mut errors, "paging_restriction", ie.is_well_formed());
        }
        if self.csfb_response.is_some() && self.service_type.value & 0x0f != 1 {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "csfb_response",
                message: "CSFB response requires mobile terminating CS fallback service".into(),
            });
        }
        if self.paging_restriction.is_some()
            && self
                .ue_request_type
                .as_ref()
                .and_then(|ie| ie.request_type())
                .is_none()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "paging_restriction",
                message: "Paging restriction requires a UE request type (8.2.15.6, 8.2.33.7)"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasGutiReallocationCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "guti",
            self.guti.length as usize,
            self.guti.value.len(),
        );
        check_eps_ie(&mut errors, "guti", self.guti.value.len() + 1, 12, Some(12));
        check_eps_ie_valid(
            &mut errors,
            "guti",
            self.guti.as_guti().is_some() && self.guti.is_well_formed(),
        );
        if let Some(ie) = &self.tai_list {
            check_eps_declared_length(&mut errors, "tai_list", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "tai_list", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "tai_list", ie.is_well_formed());
        }
        if let Some(ie) = &self.dcn_id {
            check_eps_declared_length(&mut errors, "dcn_id", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "dcn_id", ie.value.len() + 2, 4, Some(4));
        }
        if let Some(ie) = &self.ue_radio_capability_id {
            check_eps_declared_length(
                &mut errors,
                "ue_radio_capability_id",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id",
                ie.value.len() + 2,
                3,
                None,
            );
        }
        if let Some(ie) = &self.ue_radio_capability_id_deletion_indication {
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id_deletion_indication",
                ie.value as usize,
                0,
                Some(15),
            );
        }
        if let Some(ie) = &self.access_technology_utilization_control {
            check_eps_declared_length(
                &mut errors,
                "access_technology_utilization_control",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_technology_utilization_control",
                ie.value.len() + 2,
                2,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "access_technology_utilization_control",
                ie.is_well_formed(),
            );
        }
        errors
    }
}

impl Validate for NasGutiReallocationComplete {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasIdentityRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "identity_type",
            self.identity_type.value as usize,
            0,
            Some(15),
        );
        check_eps_ie_one_of(
            &mut errors,
            "identity_type",
            self.identity_type.value as usize,
            &[1, 2, 3, 4],
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        errors
    }
}

impl Validate for NasIdentityResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "mobile_identity",
            self.mobile_identity.length as usize,
            self.mobile_identity.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "mobile_identity",
            self.mobile_identity.value.len() + 1,
            4,
            Some(10),
        );
        check_eps_ie_valid(
            &mut errors,
            "mobile_identity",
            self.mobile_identity.is_well_formed(),
        );
        errors
    }
}

impl Validate for NasSecurityModeCommand {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie_valid(
            &mut errors,
            "selected_nas_security_algorithms",
            self.selected_nas_security_algorithms.is_well_formed(),
        );
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier",
            self.nas_key_set_identifier.value as usize,
            0,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        check_eps_declared_length(
            &mut errors,
            "replayed_ue_security_capabilities",
            self.replayed_ue_security_capabilities.length as usize,
            self.replayed_ue_security_capabilities.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "replayed_ue_security_capabilities",
            self.replayed_ue_security_capabilities.value.len() + 1,
            3,
            Some(6),
        );
        check_eps_ie_valid(
            &mut errors,
            "replayed_ue_security_capabilities",
            self.replayed_ue_security_capabilities.is_well_formed(),
        );
        if let Some(ie) = &self.imeisv_request {
            check_eps_ie_one_of(&mut errors, "imeisv_request", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.replayed_nonce_ue {
            check_eps_ie(
                &mut errors,
                "replayed_nonce_ue",
                ie.value.len() + 1,
                5,
                Some(5),
            );
        }
        if let Some(ie) = &self.nonce_mme {
            check_eps_ie(&mut errors, "nonce_mme", ie.value.len() + 1, 5, Some(5));
        }
        if let Some(ie) = &self.hash_mme {
            check_eps_declared_length(&mut errors, "hash_mme", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "hash_mme", ie.value.len() + 2, 10, Some(10));
            check_eps_ie_valid(&mut errors, "hash_mme", ie.is_well_formed());
        }
        if let Some(ie) = &self.replayed_ue_additional_security_capability {
            check_eps_declared_length(
                &mut errors,
                "replayed_ue_additional_security_capability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "replayed_ue_additional_security_capability",
                ie.value.len() + 2,
                6,
                Some(6),
            );
            check_eps_ie_valid(
                &mut errors,
                "replayed_ue_additional_security_capability",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.ue_radio_capability_id_request {
            check_eps_declared_length(
                &mut errors,
                "ue_radio_capability_id_request",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id_request",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "ue_radio_capability_id_request",
                ie.value.as_slice().first().is_some_and(|octet| *octet <= 1),
            );
        }
        if let Some(ie) = &self.ue_coarse_location_information_request {
            check_eps_ie_one_of(
                &mut errors,
                "ue_coarse_location_information_request",
                ie.value as usize,
                &[0, 1],
            );
        }
        check_eps_ie_valid(
            &mut errors,
            "nas_key_set_identifier",
            !self.nas_key_set_identifier.no_key_available(),
        );
        let algorithms = &self.selected_nas_security_algorithms;
        if algorithms.ciphering_raw() > 3 || algorithms.integrity_raw() > 3 {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "selected_nas_security_algorithms",
                message: "Selected EPS algorithm is not specified in TS 33.401".into(),
            });
        }
        if algorithms.integrity_raw() == 0 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "selected_nas_security_algorithms",
                message: "EIA0 is only used for unauthenticated emergency or RLOS sessions".into(),
            });
        }
        errors
    }
}

impl Validate for NasSecurityModeComplete {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.imeisv {
            check_eps_declared_length(&mut errors, "imeisv", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "imeisv", ie.value.len() + 2, 11, Some(11));
            check_eps_ie_valid(&mut errors, "imeisv", ie.as_imeisv().is_some());
        }
        if let Some(ie) = &self.replayed_nas_message_container {
            check_eps_declared_length(
                &mut errors,
                "replayed_nas_message_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "replayed_nas_message_container",
                ie.value.len() + 3,
                3,
                None,
            );
        }
        if let Some(ie) = &self.ue_radio_capability_id {
            check_eps_declared_length(
                &mut errors,
                "ue_radio_capability_id",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id",
                ie.value.len() + 2,
                3,
                None,
            );
        }
        if let Some(ie) = &self.ue_coarse_location_information {
            check_eps_declared_length(
                &mut errors,
                "ue_coarse_location_information",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_coarse_location_information",
                ie.value.len() + 2,
                8,
                Some(8),
            );
        }
        errors
    }
}

impl Validate for NasSecurityModeReject {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasServiceReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.t3346_value {
            check_eps_declared_length(
                &mut errors,
                "t3346_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3346_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3346_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.t3448_value {
            check_eps_declared_length(
                &mut errors,
                "t3448_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3448_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3448_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.lower_bound_timer_value {
            check_eps_declared_length(
                &mut errors,
                "lower_bound_timer_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "lower_bound_timer_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "lower_bound_timer_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming
        {
            check_eps_declared_length(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.value.len() + 2,
                8,
                Some(98),
            );
            check_eps_ie_valid(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service {
            check_eps_declared_length(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.is_well_formed());
        }
        if let Some(ie) = &self.access_technology_utilization_control {
            check_eps_declared_length(
                &mut errors,
                "access_technology_utilization_control",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_technology_utilization_control",
                ie.value.len() + 2,
                2,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "access_technology_utilization_control",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.s_and_f_satellite_operation_parameters {
            check_eps_declared_length(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.disaster_return_wait_range {
            check_eps_declared_length(
                &mut errors,
                "disaster_return_wait_range",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "disaster_return_wait_range",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "disaster_return_wait_range",
                ie.is_well_formed(),
            );
        }
        if self.emm_cause.value == 0x27 && self.t3442_value.is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "t3442_value",
                message: "T3442 is required for CS service temporarily not available".into(),
            });
        }
        errors
    }
}

impl Validate for NasTrackingAreaUpdateAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "eps_update_result",
            self.eps_update_result.value as usize,
            0,
            Some(7),
        );
        check_eps_ie_one_of(
            &mut errors,
            "eps_update_result",
            self.eps_update_result.value as usize,
            &[0, 1, 4, 5],
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        if let Some(ie) = &self.guti {
            check_eps_declared_length(&mut errors, "guti", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "guti", ie.value.len() + 2, 13, Some(13));
            check_eps_ie_valid(
                &mut errors,
                "guti",
                ie.as_guti().is_some() && ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.tai_list {
            check_eps_declared_length(&mut errors, "tai_list", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "tai_list", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "tai_list", ie.is_well_formed());
        }
        if let Some(ie) = &self.eps_bearer_context_status {
            check_eps_declared_length(
                &mut errors,
                "eps_bearer_context_status",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_bearer_context_status",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_bearer_context_status",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.location_area_identification {
            check_eps_ie(
                &mut errors,
                "location_area_identification",
                ie.value.len() + 1,
                6,
                Some(6),
            );
        }
        if let Some(ie) = &self.ms_identity {
            check_eps_declared_length(
                &mut errors,
                "ms_identity",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "ms_identity", ie.value.len() + 2, 7, Some(10));
        }
        if let Some(ie) = &self.equivalent_plmns {
            check_eps_declared_length(
                &mut errors,
                "equivalent_plmns",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "equivalent_plmns",
                ie.value.len() + 2,
                5,
                Some(47),
            );
            check_eps_ie_valid(&mut errors, "equivalent_plmns", ie.is_well_formed());
        }
        if let Some(ie) = &self.emergency_number_list {
            check_eps_declared_length(
                &mut errors,
                "emergency_number_list",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "emergency_number_list",
                ie.value.len() + 2,
                5,
                Some(50),
            );
            check_eps_ie_valid(&mut errors, "emergency_number_list", ie.is_well_formed());
        }
        if let Some(ie) = &self.eps_network_feature_support {
            check_eps_declared_length(
                &mut errors,
                "eps_network_feature_support",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_network_feature_support",
                ie.value.len() + 2,
                3,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_network_feature_support",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.additional_update_result {
            check_eps_ie_one_of(
                &mut errors,
                "additional_update_result",
                ie.value as usize,
                &[0, 1, 2],
            );
        }
        if let Some(ie) = &self.t3412_extended_value {
            check_eps_declared_length(
                &mut errors,
                "t3412_extended_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "t3412_extended_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "t3412_extended_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.t3324_value {
            check_eps_declared_length(
                &mut errors,
                "t3324_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3324_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3324_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_drx_parameters {
            check_eps_declared_length(
                &mut errors,
                "extended_drx_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_drx_parameters",
                ie.value.len() + 2,
                3,
                Some(3),
            );
        }
        if let Some(ie) = &self.header_compression_configuration_status {
            check_eps_declared_length(
                &mut errors,
                "header_compression_configuration_status",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "header_compression_configuration_status",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "header_compression_configuration_status",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.dcn_id {
            check_eps_declared_length(&mut errors, "dcn_id", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "dcn_id", ie.value.len() + 2, 4, Some(4));
        }
        if let Some(ie) = &self.sms_services_status {
            check_eps_ie_one_of(
                &mut errors,
                "sms_services_status",
                ie.value as usize,
                &[0, 1, 2, 3],
            );
        }
        if let Some(ie) = &self.non_3gpp_nw_policies {
            check_eps_ie_one_of(
                &mut errors,
                "non_3gpp_nw_policies",
                ie.value as usize,
                &[0, 1],
            );
        }
        if let Some(ie) = &self.t3448_value {
            check_eps_declared_length(
                &mut errors,
                "t3448_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3448_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3448_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.network_policy {
            check_eps_ie_one_of(&mut errors, "network_policy", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.t3447_value {
            check_eps_declared_length(
                &mut errors,
                "t3447_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3447_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3447_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_emergency_number_list {
            check_eps_declared_length(
                &mut errors,
                "extended_emergency_number_list",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_emergency_number_list",
                ie.value.len() + 3,
                7,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_emergency_number_list",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.ciphering_key_data {
            check_eps_declared_length(
                &mut errors,
                "ciphering_key_data",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ciphering_key_data",
                ie.value.len() + 3,
                35,
                Some(2291),
            );
            check_eps_ie_valid(&mut errors, "ciphering_key_data", ie.is_well_formed());
        }
        if let Some(ie) = &self.ue_radio_capability_id {
            check_eps_declared_length(
                &mut errors,
                "ue_radio_capability_id",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id",
                ie.value.len() + 2,
                3,
                None,
            );
        }
        if let Some(ie) = &self.ue_radio_capability_id_deletion_indication {
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id_deletion_indication",
                ie.value as usize,
                0,
                Some(15),
            );
        }
        if let Some(ie) = &self.negotiated_wus_assistance_information {
            check_eps_declared_length(
                &mut errors,
                "negotiated_wus_assistance_information",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "negotiated_wus_assistance_information",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "negotiated_wus_assistance_information",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.negotiated_drx_parameter_in_nb_s1_mode {
            check_eps_declared_length(
                &mut errors,
                "negotiated_drx_parameter_in_nb_s1_mode",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "negotiated_drx_parameter_in_nb_s1_mode",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "negotiated_drx_parameter_in_nb_s1_mode",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.negotiated_imsi_offset {
            check_eps_declared_length(
                &mut errors,
                "negotiated_imsi_offset",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "negotiated_imsi_offset",
                ie.value.len() + 2,
                4,
                Some(4),
            );
        }
        if let Some(ie) = &self.eps_additional_request_result {
            check_eps_declared_length(
                &mut errors,
                "eps_additional_request_result",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_additional_request_result",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_additional_request_result",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming
        {
            check_eps_declared_length(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.value.len() + 2,
                8,
                Some(98),
            );
            check_eps_ie_valid(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service {
            check_eps_declared_length(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.is_well_formed());
        }
        if let Some(ie) = &self.maximum_time_offset {
            check_eps_declared_length(
                &mut errors,
                "maximum_time_offset",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "maximum_time_offset",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "maximum_time_offset", ie.is_well_formed());
        }
        if let Some(ie) = &self.unavailability_configuration {
            check_eps_declared_length(
                &mut errors,
                "unavailability_configuration",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "unavailability_configuration",
                ie.value.len() + 2,
                3,
                Some(9),
            );
            check_eps_ie_valid(
                &mut errors,
                "unavailability_configuration",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.access_technology_utilization_control {
            check_eps_declared_length(
                &mut errors,
                "access_technology_utilization_control",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_technology_utilization_control",
                ie.value.len() + 2,
                2,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "access_technology_utilization_control",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.s_and_f_satellite_operation_parameters {
            check_eps_declared_length(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.disaster_roaming_wait_range {
            check_eps_declared_length(
                &mut errors,
                "disaster_roaming_wait_range",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "disaster_roaming_wait_range",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "disaster_roaming_wait_range",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.disaster_return_wait_range {
            check_eps_declared_length(
                &mut errors,
                "disaster_return_wait_range",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "disaster_return_wait_range",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "disaster_return_wait_range",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.list_of_plmns_to_be_used_in_disaster_condition {
            check_eps_declared_length(
                &mut errors,
                "list_of_plmns_to_be_used_in_disaster_condition",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "list_of_plmns_to_be_used_in_disaster_condition",
                ie.value.len() + 2,
                2,
                None,
            );
            check_eps_ie_valid(
                &mut errors,
                "list_of_plmns_to_be_used_in_disaster_condition",
                ie.is_well_formed(),
            );
        }
        check_eps_ie_valid(
            &mut errors,
            "eps_update_result",
            matches!(self.eps_update_result.value, 0 | 1 | 4 | 5),
        );
        if self.t3412_extended_value.is_some() && self.t3412_value.is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "t3412_value",
                message: "T3412 value is required with extended T3412".into(),
            });
        }
        errors
    }
}

impl Validate for NasTrackingAreaUpdateComplete {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasTrackingAreaUpdateReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.t3346_value {
            check_eps_declared_length(
                &mut errors,
                "t3346_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3346_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3346_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_emm_cause {
            check_eps_ie(
                &mut errors,
                "extended_emm_cause",
                ie.value as usize,
                0,
                Some(15),
            );
        }
        if let Some(ie) = &self.lower_bound_timer_value {
            check_eps_declared_length(
                &mut errors,
                "lower_bound_timer_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "lower_bound_timer_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "lower_bound_timer_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming
        {
            check_eps_declared_length(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.value.len() + 2,
                8,
                Some(98),
            );
            check_eps_ie_valid(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service {
            check_eps_declared_length(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.is_well_formed());
        }
        if let Some(ie) = &self.access_technology_utilization_control {
            check_eps_declared_length(
                &mut errors,
                "access_technology_utilization_control",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_technology_utilization_control",
                ie.value.len() + 2,
                2,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "access_technology_utilization_control",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.s_and_f_satellite_operation_parameters {
            check_eps_declared_length(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.disaster_return_wait_range {
            check_eps_declared_length(
                &mut errors,
                "disaster_return_wait_range",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "disaster_return_wait_range",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "disaster_return_wait_range",
                ie.is_well_formed(),
            );
        }
        errors
    }
}

impl Validate for NasTrackingAreaUpdateRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "eps_update_type",
            self.eps_update_type.value as usize,
            0,
            Some(15),
        );
        check_eps_ie_one_of(
            &mut errors,
            "eps_update_type",
            (self.eps_update_type.value & 0x07) as usize,
            &[0, 1, 2, 3, 6],
        );
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier",
            self.nas_key_set_identifier.value as usize,
            0,
            Some(15),
        );
        check_eps_declared_length(
            &mut errors,
            "old_guti",
            self.old_guti.length as usize,
            self.old_guti.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "old_guti",
            self.old_guti.value.len() + 1,
            12,
            Some(12),
        );
        check_eps_ie_valid(
            &mut errors,
            "old_guti",
            self.old_guti.as_guti().is_some() && self.old_guti.is_well_formed(),
        );
        if let Some(ie) = &self.non_current_native_nas_key_set_identifier {
            check_eps_ie_valid(
                &mut errors,
                "non_current_native_nas_key_set_identifier",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.gprs_ciphering_key_sequence_number {
            check_eps_ie_one_of(
                &mut errors,
                "gprs_ciphering_key_sequence_number",
                ie.value as usize,
                &[0, 1, 2, 3, 4, 5, 6, 7],
            );
        }
        if let Some(ie) = &self.old_p_tmsi_signature {
            check_eps_ie(
                &mut errors,
                "old_p_tmsi_signature",
                ie.value.len() + 1,
                4,
                Some(4),
            );
        }
        if let Some(ie) = &self.additional_guti {
            check_eps_declared_length(
                &mut errors,
                "additional_guti",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "additional_guti",
                ie.value.len() + 2,
                13,
                Some(13),
            );
            check_eps_ie_valid(
                &mut errors,
                "additional_guti",
                ie.as_guti().is_some() && ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.nonce_ue {
            check_eps_ie(&mut errors, "nonce_ue", ie.value.len() + 1, 5, Some(5));
        }
        if let Some(ie) = &self.ue_network_capability {
            check_eps_declared_length(
                &mut errors,
                "ue_network_capability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_network_capability",
                ie.value.len() + 2,
                4,
                Some(15),
            );
            check_eps_ie_valid(&mut errors, "ue_network_capability", ie.is_well_formed());
        }
        if let Some(ie) = &self.last_visited_registered_tai {
            check_eps_ie(
                &mut errors,
                "last_visited_registered_tai",
                ie.value.len() + 1,
                6,
                Some(6),
            );
        }
        if let Some(ie) = &self.drx_parameter {
            check_eps_ie(&mut errors, "drx_parameter", ie.value.len() + 1, 3, Some(3));
            check_eps_ie_valid(&mut errors, "drx_parameter", ie.is_well_formed());
        }
        if let Some(ie) = &self.ue_radio_capability_information_update_needed {
            check_eps_ie_one_of(
                &mut errors,
                "ue_radio_capability_information_update_needed",
                ie.value as usize,
                &[0, 1],
            );
        }
        if let Some(ie) = &self.eps_bearer_context_status {
            check_eps_declared_length(
                &mut errors,
                "eps_bearer_context_status",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_bearer_context_status",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_bearer_context_status",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.ms_network_capability {
            check_eps_declared_length(
                &mut errors,
                "ms_network_capability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ms_network_capability",
                ie.value.len() + 2,
                4,
                Some(10),
            );
            check_eps_ie_valid(&mut errors, "ms_network_capability", ie.is_well_formed());
        }
        if let Some(ie) = &self.old_location_area_identification {
            check_eps_ie(
                &mut errors,
                "old_location_area_identification",
                ie.value.len() + 1,
                6,
                Some(6),
            );
        }
        if let Some(ie) = &self.tmsi_status {
            check_eps_ie_one_of(&mut errors, "tmsi_status", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.mobile_station_classmark_2 {
            check_eps_declared_length(
                &mut errors,
                "mobile_station_classmark_2",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "mobile_station_classmark_2",
                ie.value.len() + 2,
                5,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "mobile_station_classmark_2",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.mobile_station_classmark_3 {
            check_eps_declared_length(
                &mut errors,
                "mobile_station_classmark_3",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "mobile_station_classmark_3",
                ie.value.len() + 2,
                2,
                Some(34),
            );
            check_eps_ie_valid(
                &mut errors,
                "mobile_station_classmark_3",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.supported_codecs {
            check_eps_declared_length(
                &mut errors,
                "supported_codecs",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "supported_codecs", ie.value.len() + 2, 5, None);
            check_eps_ie_valid(&mut errors, "supported_codecs", ie.is_well_formed());
        }
        if let Some(ie) = &self.additional_update_type {
            check_eps_ie_valid(
                &mut errors,
                "additional_update_type",
                ie.value & 0x0c != 0x0c,
            );
        }
        if let Some(ie) = &self.voice_domain_preference_and_ue_usage_setting {
            check_eps_declared_length(
                &mut errors,
                "voice_domain_preference_and_ue_usage_setting",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "voice_domain_preference_and_ue_usage_setting",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "voice_domain_preference_and_ue_usage_setting",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.old_guti_type {
            check_eps_ie_one_of(&mut errors, "old_guti_type", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.device_properties {
            check_eps_ie_one_of(&mut errors, "device_properties", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.ms_network_feature_support {
            check_eps_ie_one_of(
                &mut errors,
                "ms_network_feature_support",
                ie.value as usize,
                &[0, 1],
            );
        }
        if let Some(ie) = &self.tmsi_based_nri_container {
            check_eps_declared_length(
                &mut errors,
                "tmsi_based_nri_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "tmsi_based_nri_container",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(&mut errors, "tmsi_based_nri_container", ie.is_well_formed());
        }
        if let Some(ie) = &self.t3324_value {
            check_eps_declared_length(
                &mut errors,
                "t3324_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3324_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3324_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.t3412_extended_value {
            check_eps_declared_length(
                &mut errors,
                "t3412_extended_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "t3412_extended_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "t3412_extended_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_drx_parameters {
            check_eps_declared_length(
                &mut errors,
                "extended_drx_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_drx_parameters",
                ie.value.len() + 2,
                3,
                Some(3),
            );
        }
        if let Some(ie) = &self.ue_additional_security_capability {
            check_eps_declared_length(
                &mut errors,
                "ue_additional_security_capability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_additional_security_capability",
                ie.value.len() + 2,
                6,
                Some(6),
            );
            check_eps_ie_valid(
                &mut errors,
                "ue_additional_security_capability",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.ue_status {
            check_eps_declared_length(&mut errors, "ue_status", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "ue_status", ie.value.len() + 2, 3, Some(3));
        }
        if let Some(ie) = &self.additional_information_requested {
            check_eps_ie_valid(
                &mut errors,
                "additional_information_requested",
                ie.value <= 1,
            );
        }
        if let Some(ie) = &self.n1_ue_network_capability {
            check_eps_declared_length(
                &mut errors,
                "n1_ue_network_capability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "n1_ue_network_capability",
                ie.value.len() + 2,
                3,
                Some(15),
            );
            check_eps_ie_valid(&mut errors, "n1_ue_network_capability", ie.is_well_formed());
        }
        if let Some(ie) = &self.ue_radio_capability_id_availability {
            check_eps_declared_length(
                &mut errors,
                "ue_radio_capability_id_availability",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_radio_capability_id_availability",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "ue_radio_capability_id_availability",
                ie.value.as_slice().first().is_some_and(|octet| *octet <= 1),
            );
        }
        if let Some(ie) = &self.requested_wus_assistance_information {
            check_eps_declared_length(
                &mut errors,
                "requested_wus_assistance_information",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "requested_wus_assistance_information",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "requested_wus_assistance_information",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.drx_parameter_in_nb_s1_mode {
            check_eps_declared_length(
                &mut errors,
                "drx_parameter_in_nb_s1_mode",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "drx_parameter_in_nb_s1_mode",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "drx_parameter_in_nb_s1_mode",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.requested_imsi_offset {
            check_eps_declared_length(
                &mut errors,
                "requested_imsi_offset",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "requested_imsi_offset",
                ie.value.len() + 2,
                4,
                Some(4),
            );
        }
        if let Some(ie) = &self.ue_request_type {
            check_eps_declared_length(
                &mut errors,
                "ue_request_type",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_request_type",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "ue_request_type", ie.is_well_formed());
        }
        if let Some(ie) = &self.paging_restriction {
            check_eps_declared_length(
                &mut errors,
                "paging_restriction",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "paging_restriction",
                ie.value.len() + 2,
                3,
                Some(5),
            );
            check_eps_ie_valid(&mut errors, "paging_restriction", ie.is_well_formed());
        }
        if let Some(ie) = &self.unavailability_information {
            check_eps_declared_length(
                &mut errors,
                "unavailability_information",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "unavailability_information",
                ie.value.len() + 2,
                3,
                Some(9),
            );
            check_eps_ie_valid(
                &mut errors,
                "unavailability_information",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.ue_determined_plmn_with_disaster_condition {
            check_eps_declared_length(
                &mut errors,
                "ue_determined_plmn_with_disaster_condition",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_determined_plmn_with_disaster_condition",
                ie.value.len() + 2,
                5,
                Some(5),
            );
            check_eps_ie_valid(
                &mut errors,
                "ue_determined_plmn_with_disaster_condition",
                ie.is_well_formed(),
            );
        }
        if self.old_guti_type.is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "old_guti_type",
                message: "Old GUTI type is required in TRACKING AREA UPDATE REQUEST".into(),
            });
        }
        if self.eps_update_type.value & 0x07 != 3 && self.ue_network_capability.is_none() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "ue_network_capability",
                message: "UE network capability is required for nonperiodic TAU".into(),
            });
        }
        if self.t3412_extended_value.is_some() && self.t3324_value.is_none() {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "t3412_extended_value",
                message: "Extended T3412 requires T3324".into(),
            });
        }
        if self.ue_determined_plmn_with_disaster_condition.is_some()
            && self.eps_update_type.value & 0x07 != 6
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "ue_determined_plmn_with_disaster_condition",
                message: "Disaster condition PLMN requires disaster roaming request type".into(),
            });
        }
        if self.ue_request_type.as_ref().is_some_and(|ie| {
            ie.request_type() != Some(UeRequestType::NasSignallingConnectionRelease)
        }) {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "ue_request_type",
                message: "TAU REQUEST carries only NAS signalling connection release (8.2.29.35)"
                    .into(),
            });
        }
        if self.paging_restriction.is_some()
            && self
                .ue_request_type
                .as_ref()
                .and_then(|ie| ie.request_type())
                != Some(UeRequestType::NasSignallingConnectionRelease)
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "paging_restriction",
                message: "Paging restriction requires UE request type NAS signalling connection release (8.2.29.36)".into(),
            });
        }
        if self.drx_parameter_in_nb_s1_mode.is_some() && self.eps_update_type.value & 0x07 == 3 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "drx_parameter_in_nb_s1_mode",
                message: "NB-S1 DRX parameter is not sent in periodic TAU (8.2.29.32)".into(),
            });
        }
        errors
    }
}

impl Validate for NasUplinkNasTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "nas_message_container",
            self.nas_message_container.length as usize,
            self.nas_message_container.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "nas_message_container",
            self.nas_message_container.value.len() + 1,
            3,
            Some(252),
        );
        errors
    }
}

impl Validate for NasDownlinkGenericNasTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie_one_of(
            &mut errors,
            "generic_message_container_type",
            self.generic_message_container_type.value as usize,
            &[1, 2],
        );
        check_eps_declared_length(
            &mut errors,
            "generic_message_container",
            self.generic_message_container.length as usize,
            self.generic_message_container.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "generic_message_container",
            self.generic_message_container.value.len() + 2,
            3,
            None,
        );
        if let Some(ie) = &self.additional_information {
            check_eps_declared_length(
                &mut errors,
                "additional_information",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "additional_information",
                ie.value.len() + 2,
                3,
                None,
            );
        }
        errors
    }
}

impl Validate for NasUplinkGenericNasTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie_one_of(
            &mut errors,
            "generic_message_container_type",
            self.generic_message_container_type.value as usize,
            &[1, 2],
        );
        check_eps_declared_length(
            &mut errors,
            "generic_message_container",
            self.generic_message_container.length as usize,
            self.generic_message_container.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "generic_message_container",
            self.generic_message_container.value.len() + 2,
            3,
            None,
        );
        if let Some(ie) = &self.additional_information {
            check_eps_declared_length(
                &mut errors,
                "additional_information",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "additional_information",
                ie.value.len() + 2,
                3,
                None,
            );
        }
        errors
    }
}

impl Validate for NasControlPlaneServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "control_plane_service_type",
            self.control_plane_service_type.value as usize,
            0,
            Some(15),
        );
        check_eps_ie_one_of(
            &mut errors,
            "control_plane_service_type",
            (self.control_plane_service_type.value & 0x07) as usize,
            &[0, 1],
        );
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier",
            self.nas_key_set_identifier.value as usize,
            0,
            Some(15),
        );
        if let Some(ie) = &self.esm_message_container {
            check_eps_declared_length(
                &mut errors,
                "esm_message_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "esm_message_container",
                ie.value.len() + 3,
                3,
                None,
            );
        }
        if let Some(ie) = &self.nas_message_container {
            check_eps_declared_length(
                &mut errors,
                "nas_message_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nas_message_container",
                ie.value.len() + 2,
                4,
                Some(253),
            );
        }
        if let Some(ie) = &self.eps_bearer_context_status {
            check_eps_declared_length(
                &mut errors,
                "eps_bearer_context_status",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_bearer_context_status",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_bearer_context_status",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.device_properties {
            check_eps_ie_one_of(&mut errors, "device_properties", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.ue_request_type {
            check_eps_declared_length(
                &mut errors,
                "ue_request_type",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "ue_request_type",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "ue_request_type", ie.is_well_formed());
        }
        if let Some(ie) = &self.paging_restriction {
            check_eps_declared_length(
                &mut errors,
                "paging_restriction",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "paging_restriction",
                ie.value.len() + 2,
                3,
                Some(5),
            );
            check_eps_ie_valid(&mut errors, "paging_restriction", ie.is_well_formed());
        }
        if let Some(ie) = &self.esm_message_container {
            check_esm_message_container(&mut errors, &ie.value, Severity::Warning);
        }
        if self.paging_restriction.is_some()
            && self
                .ue_request_type
                .as_ref()
                .and_then(|ie| ie.request_type())
                .is_none()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "paging_restriction",
                message: "Paging restriction requires a UE request type (8.2.15.6, 8.2.33.7)"
                    .into(),
            });
        }
        errors
    }
}

impl Validate for NasServiceAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.eps_bearer_context_status {
            check_eps_declared_length(
                &mut errors,
                "eps_bearer_context_status",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_bearer_context_status",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_bearer_context_status",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.t3448_value {
            check_eps_declared_length(
                &mut errors,
                "t3448_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3448_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3448_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.eps_additional_request_result {
            check_eps_declared_length(
                &mut errors,
                "eps_additional_request_result",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "eps_additional_request_result",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(
                &mut errors,
                "eps_additional_request_result",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming
        {
            check_eps_declared_length(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.value.len() + 2,
                8,
                Some(98),
            );
            check_eps_ie_valid(
                &mut errors,
                "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_roaming",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service {
            check_eps_declared_length(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.value.len() + 2, 8, Some(98));
            check_eps_ie_valid(&mut errors, "forbidden_tais_for_the_list_of_forbidden_tracking_areas_for_regional_provision_of_service", ie.is_well_formed());
        }
        if let Some(ie) = &self.s_and_f_satellite_operation_parameters {
            check_eps_declared_length(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "s_and_f_satellite_operation_parameters",
                ie.is_well_formed(),
            );
        }
        errors
    }
}

impl Validate for NasActivateDedicatedEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::UeToNetwork),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasActivateDedicatedEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::UeToNetwork),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasActivateDedicatedEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "linked_eps_bearer_identity",
            self.linked_eps_bearer_identity.value as usize,
            0,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "linked_eps_bearer_identity",
            self.linked_eps_bearer_identity.value as usize,
            1,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        check_eps_declared_length(
            &mut errors,
            "eps_qos",
            self.eps_qos.length as usize,
            self.eps_qos.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "eps_qos",
            self.eps_qos.value.len() + 1,
            2,
            Some(14),
        );
        check_eps_ie_valid(&mut errors, "eps_qos", self.eps_qos.is_well_formed());
        check_eps_ie_valid(
            &mut errors,
            "eps_qos",
            self.eps_qos
                .qos()
                .is_some_and(|qos| qos.qci_is_network_valid()),
        );
        check_eps_ie_valid(
            &mut errors,
            "eps_qos",
            self.eps_qos.value.len() < 5 || self.eps_qos.value[1..5].iter().all(|&rate| rate != 0),
        );
        check_eps_ie_valid(
            &mut errors,
            "eps_qos",
            !self.eps_qos.has_zero_maximum_bit_rates(),
        );
        check_eps_declared_length(
            &mut errors,
            "tft",
            self.tft.length as usize,
            self.tft.value.len(),
        );
        check_eps_ie(&mut errors, "tft", self.tft.value.len() + 1, 2, Some(256));
        check_eps_ie_valid(&mut errors, "tft", self.tft.is_well_formed());
        if let Some(ie) = &self.transaction_identifier {
            check_eps_declared_length(
                &mut errors,
                "transaction_identifier",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "transaction_identifier",
                ie.value.len() + 2,
                3,
                Some(4),
            );
            check_eps_ie_valid(&mut errors, "transaction_identifier", ie.is_well_formed());
        }
        if let Some(ie) = &self.negotiated_qos {
            check_eps_declared_length(
                &mut errors,
                "negotiated_qos",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "negotiated_qos",
                ie.value.len() + 2,
                14,
                Some(22),
            );
            check_eps_ie_valid(&mut errors, "negotiated_qos", ie.is_well_formed());
        }
        if let Some(ie) = &self.negotiated_llc_sapi {
            check_eps_ie_one_of(
                &mut errors,
                "negotiated_llc_sapi",
                ie.value as usize,
                &[0, 3, 5, 9, 11],
            );
        }
        if let Some(ie) = &self.radio_priority {
            check_eps_ie_one_of(
                &mut errors,
                "radio_priority",
                ie.value as usize,
                &[1, 2, 3, 4],
            );
        }
        if let Some(ie) = &self.packet_flow_identifier {
            check_eps_declared_length(
                &mut errors,
                "packet_flow_identifier",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "packet_flow_identifier",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "packet_flow_identifier", ie.is_well_formed());
        }
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.wlan_offload_indication {
            check_eps_ie_one_of(
                &mut errors,
                "wlan_offload_indication",
                ie.value as usize,
                &[0, 1, 2, 3],
            );
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::NetworkToUe),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.extended_eps_qos {
            check_eps_declared_length(
                &mut errors,
                "extended_eps_qos",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_eps_qos",
                ie.value.len() + 2,
                12,
                Some(12),
            );
            check_eps_ie_valid(&mut errors, "extended_eps_qos", ie.is_well_formed());
        }
        if self.extended_eps_qos.is_some() && self.eps_qos.value.len() < 13 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_eps_qos",
                message: "Extended EPS QoS needs EPS QoS at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasActivateDefaultEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasActivateDefaultEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasActivateDefaultEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "eps_qos",
            self.eps_qos.length as usize,
            self.eps_qos.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "eps_qos",
            self.eps_qos.value.len() + 1,
            2,
            Some(14),
        );
        check_eps_ie_valid(&mut errors, "eps_qos", self.eps_qos.is_well_formed());
        check_eps_ie_valid(
            &mut errors,
            "eps_qos",
            self.eps_qos
                .qos()
                .is_some_and(|qos| qos.qci_is_network_valid()),
        );
        check_eps_ie_valid(
            &mut errors,
            "eps_qos",
            self.eps_qos.value.len() < 5 || self.eps_qos.value[1..5].iter().all(|&rate| rate != 0),
        );
        check_eps_ie_valid(
            &mut errors,
            "eps_qos",
            !self.eps_qos.has_zero_maximum_bit_rates(),
        );
        check_eps_declared_length(
            &mut errors,
            "access_point_name",
            self.access_point_name.length as usize,
            self.access_point_name.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "access_point_name",
            self.access_point_name.value.len() + 1,
            2,
            Some(101),
        );
        check_eps_ie_valid(
            &mut errors,
            "access_point_name",
            self.access_point_name.is_well_formed(),
        );
        check_eps_declared_length(
            &mut errors,
            "pdn_address",
            self.pdn_address.length as usize,
            self.pdn_address.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "pdn_address",
            self.pdn_address.value.len() + 1,
            6,
            Some(14),
        );
        check_eps_ie_valid(
            &mut errors,
            "pdn_address",
            self.pdn_address.is_well_formed(),
        );
        if let Some(ie) = &self.transaction_identifier {
            check_eps_declared_length(
                &mut errors,
                "transaction_identifier",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "transaction_identifier",
                ie.value.len() + 2,
                3,
                Some(4),
            );
            check_eps_ie_valid(&mut errors, "transaction_identifier", ie.is_well_formed());
        }
        if let Some(ie) = &self.negotiated_qos {
            check_eps_declared_length(
                &mut errors,
                "negotiated_qos",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "negotiated_qos",
                ie.value.len() + 2,
                14,
                Some(22),
            );
            check_eps_ie_valid(&mut errors, "negotiated_qos", ie.is_well_formed());
        }
        if let Some(ie) = &self.negotiated_llc_sapi {
            check_eps_ie_one_of(
                &mut errors,
                "negotiated_llc_sapi",
                ie.value as usize,
                &[0, 3, 5, 9, 11],
            );
        }
        if let Some(ie) = &self.radio_priority {
            check_eps_ie_one_of(
                &mut errors,
                "radio_priority",
                ie.value as usize,
                &[1, 2, 3, 4],
            );
        }
        if let Some(ie) = &self.packet_flow_identifier {
            check_eps_declared_length(
                &mut errors,
                "packet_flow_identifier",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "packet_flow_identifier",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "packet_flow_identifier", ie.is_well_formed());
        }
        if let Some(ie) = &self.apn_ambr {
            check_eps_declared_length(&mut errors, "apn_ambr", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "apn_ambr", ie.value.len() + 2, 4, Some(8));
            check_eps_ie_valid(&mut errors, "apn_ambr", ie.is_well_formed());
        }
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.connectivity_type {
            check_eps_ie_one_of(&mut errors, "connectivity_type", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.wlan_offload_indication {
            check_eps_ie_one_of(
                &mut errors,
                "wlan_offload_indication",
                ie.value as usize,
                &[0, 1, 2, 3],
            );
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::NetworkToUe),
            );
        }
        if let Some(ie) = &self.header_compression_configuration {
            check_eps_declared_length(
                &mut errors,
                "header_compression_configuration",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "header_compression_configuration",
                ie.value.len() + 2,
                5,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "header_compression_configuration",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.control_plane_only_indication {
            check_eps_ie_one_of(
                &mut errors,
                "control_plane_only_indication",
                ie.value as usize,
                &[1],
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.serving_plmn_rate_control {
            check_eps_declared_length(
                &mut errors,
                "serving_plmn_rate_control",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "serving_plmn_rate_control",
                ie.value.len() + 2,
                4,
                Some(4),
            );
            check_eps_ie_valid(
                &mut errors,
                "serving_plmn_rate_control",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.extended_apn_ambr {
            check_eps_declared_length(
                &mut errors,
                "extended_apn_ambr",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_apn_ambr",
                ie.value.len() + 2,
                8,
                Some(8),
            );
            check_eps_ie_valid(&mut errors, "extended_apn_ambr", ie.is_well_formed());
        }
        if self.extended_apn_ambr.is_some()
            && self.apn_ambr.as_ref().is_none_or(|ie| ie.value.len() < 6)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_apn_ambr",
                message: "Extended APN-AMBR needs APN-AMBR at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasBearerResourceAllocationReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.back_off_timer_value {
            check_eps_declared_length(
                &mut errors,
                "back_off_timer_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "back_off_timer_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "back_off_timer_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.re_attempt_indicator {
            check_eps_declared_length(
                &mut errors,
                "re_attempt_indicator",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "re_attempt_indicator",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "re_attempt_indicator", ie.is_well_formed());
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::NetworkToUe),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if self.re_attempt_indicator.is_some()
            && (self.esm_cause.value == 26 || self.back_off_timer_value.is_none())
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "re_attempt_indicator",
                message: "Re-attempt indicator is not allowed for this cause and timer combination"
                    .into(),
            });
        }
        if self.back_off_timer_value.is_some() && self.esm_cause.value == 65 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "back_off_timer_value",
                message: "Back-off timer is not sent with ESM cause #65 (8.3.7.3)".into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasBearerResourceAllocationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "linked_eps_bearer_identity",
            self.linked_eps_bearer_identity.value as usize,
            0,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "linked_eps_bearer_identity",
            self.linked_eps_bearer_identity.value as usize,
            1,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        check_eps_declared_length(
            &mut errors,
            "traffic_flow_aggregate",
            self.traffic_flow_aggregate.length as usize,
            self.traffic_flow_aggregate.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "traffic_flow_aggregate",
            self.traffic_flow_aggregate.value.len() + 1,
            2,
            Some(256),
        );
        check_eps_ie_valid(
            &mut errors,
            "traffic_flow_aggregate",
            self.traffic_flow_aggregate.is_well_formed(),
        );
        check_eps_declared_length(
            &mut errors,
            "required_traffic_flow_qos",
            self.required_traffic_flow_qos.length as usize,
            self.required_traffic_flow_qos.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "required_traffic_flow_qos",
            self.required_traffic_flow_qos.value.len() + 1,
            2,
            Some(14),
        );
        check_eps_ie_valid(
            &mut errors,
            "required_traffic_flow_qos",
            self.required_traffic_flow_qos.is_well_formed(),
        );
        check_eps_ie_valid(
            &mut errors,
            "required_traffic_flow_qos",
            !self.required_traffic_flow_qos.has_zero_maximum_bit_rates(),
        );
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.device_properties {
            check_eps_ie_one_of(&mut errors, "device_properties", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::UeToNetwork),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.extended_eps_qos {
            check_eps_declared_length(
                &mut errors,
                "extended_eps_qos",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_eps_qos",
                ie.value.len() + 2,
                12,
                Some(12),
            );
            check_eps_ie_valid(&mut errors, "extended_eps_qos", ie.is_well_formed());
        }
        if self.extended_eps_qos.is_some() && self.required_traffic_flow_qos.value.len() < 13 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_eps_qos",
                message: "Extended EPS QoS needs EPS QoS at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasBearerResourceModificationReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.back_off_timer_value {
            check_eps_declared_length(
                &mut errors,
                "back_off_timer_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "back_off_timer_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "back_off_timer_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.re_attempt_indicator {
            check_eps_declared_length(
                &mut errors,
                "re_attempt_indicator",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "re_attempt_indicator",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "re_attempt_indicator", ie.is_well_formed());
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::NetworkToUe),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if self.re_attempt_indicator.is_some()
            && (self.esm_cause.value == 26 || self.back_off_timer_value.is_none())
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "re_attempt_indicator",
                message: "Re-attempt indicator is not allowed for this cause and timer combination"
                    .into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasBearerResourceModificationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "eps_bearer_identity_for_packet_filter",
            self.eps_bearer_identity_for_packet_filter.value as usize,
            0,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "eps_bearer_identity_for_packet_filter",
            self.eps_bearer_identity_for_packet_filter.value as usize,
            1,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        check_eps_declared_length(
            &mut errors,
            "traffic_flow_aggregate",
            self.traffic_flow_aggregate.length as usize,
            self.traffic_flow_aggregate.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "traffic_flow_aggregate",
            self.traffic_flow_aggregate.value.len() + 1,
            2,
            Some(256),
        );
        check_eps_ie_valid(
            &mut errors,
            "traffic_flow_aggregate",
            self.traffic_flow_aggregate.is_well_formed(),
        );
        if let Some(ie) = &self.required_traffic_flow_qos {
            check_eps_declared_length(
                &mut errors,
                "required_traffic_flow_qos",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "required_traffic_flow_qos",
                ie.value.len() + 2,
                3,
                Some(15),
            );
            check_eps_ie_valid(
                &mut errors,
                "required_traffic_flow_qos",
                ie.is_well_formed(),
            );
            check_eps_ie_valid(
                &mut errors,
                "required_traffic_flow_qos",
                !ie.has_zero_maximum_bit_rates(),
            );
        }
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.device_properties {
            check_eps_ie_one_of(&mut errors, "device_properties", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::UeToNetwork),
            );
        }
        if let Some(ie) = &self.header_compression_configuration {
            check_eps_declared_length(
                &mut errors,
                "header_compression_configuration",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "header_compression_configuration",
                ie.value.len() + 2,
                5,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "header_compression_configuration",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.extended_eps_qos {
            check_eps_declared_length(
                &mut errors,
                "extended_eps_qos",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_eps_qos",
                ie.value.len() + 2,
                12,
                Some(12),
            );
            check_eps_ie_valid(&mut errors, "extended_eps_qos", ie.is_well_formed());
        }
        if self.extended_eps_qos.is_some()
            && self
                .required_traffic_flow_qos
                .as_ref()
                .is_none_or(|ie| ie.value.len() < 13)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_eps_qos",
                message: "Extended EPS QoS needs EPS QoS at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasDeactivateEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasDeactivateEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.t3396_value {
            check_eps_declared_length(
                &mut errors,
                "t3396_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "t3396_value", ie.value.len() + 2, 3, Some(3));
            check_eps_ie_valid(&mut errors, "t3396_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.wlan_offload_indication {
            check_eps_ie_one_of(
                &mut errors,
                "wlan_offload_indication",
                ie.value as usize,
                &[0, 1, 2, 3],
            );
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::NetworkToUe),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if self.t3396_value.is_some() && self.esm_cause.value != 26 {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "t3396_value",
                message: "T3396 is sent with ESM cause #26 (8.3.12.3)".into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasEsmDummyMessage {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasEsmInformationRequest {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasEsmInformationResponse {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.access_point_name {
            check_eps_declared_length(
                &mut errors,
                "access_point_name",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_point_name",
                ie.value.len() + 2,
                3,
                Some(102),
            );
            check_eps_ie_valid(&mut errors, "access_point_name", ie.is_well_formed());
        }
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "protocol_configuration_options",
                message: "PCO and extended PCO are mutually exclusive".into(),
            });
        }
        errors
    }
}

impl Validate for NasEsmStatus {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasModifyEpsBearerContextAccept {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::UeToNetwork),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasModifyEpsBearerContextReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::UeToNetwork),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasModifyEpsBearerContextRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.new_eps_qos {
            check_eps_declared_length(
                &mut errors,
                "new_eps_qos",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(&mut errors, "new_eps_qos", ie.value.len() + 2, 3, Some(15));
            check_eps_ie_valid(&mut errors, "new_eps_qos", ie.is_well_formed());
            check_eps_ie_valid(
                &mut errors,
                "new_eps_qos",
                ie.qos().is_some_and(|qos| qos.qci_is_network_valid()),
            );
            check_eps_ie_valid(
                &mut errors,
                "new_eps_qos",
                ie.value.len() < 5 || ie.value[1..5].iter().all(|&rate| rate != 0),
            );
            check_eps_ie_valid(&mut errors, "new_eps_qos", !ie.has_zero_maximum_bit_rates());
        }
        if let Some(ie) = &self.tft {
            check_eps_declared_length(&mut errors, "tft", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "tft", ie.value.len() + 2, 3, Some(257));
            check_eps_ie_valid(&mut errors, "tft", ie.is_well_formed());
        }
        if let Some(ie) = &self.new_qos {
            check_eps_declared_length(&mut errors, "new_qos", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "new_qos", ie.value.len() + 2, 14, Some(22));
            check_eps_ie_valid(&mut errors, "new_qos", ie.is_well_formed());
        }
        if let Some(ie) = &self.negotiated_llc_sapi {
            check_eps_ie_one_of(
                &mut errors,
                "negotiated_llc_sapi",
                ie.value as usize,
                &[0, 3, 5, 9, 11],
            );
        }
        if let Some(ie) = &self.radio_priority {
            check_eps_ie_one_of(
                &mut errors,
                "radio_priority",
                ie.value as usize,
                &[1, 2, 3, 4],
            );
        }
        if let Some(ie) = &self.packet_flow_identifier {
            check_eps_declared_length(
                &mut errors,
                "packet_flow_identifier",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "packet_flow_identifier",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "packet_flow_identifier", ie.is_well_formed());
        }
        if let Some(ie) = &self.apn_ambr {
            check_eps_declared_length(&mut errors, "apn_ambr", ie.length as usize, ie.value.len());
            check_eps_ie(&mut errors, "apn_ambr", ie.value.len() + 2, 4, Some(8));
            check_eps_ie_valid(&mut errors, "apn_ambr", ie.is_well_formed());
        }
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.wlan_offload_indication {
            check_eps_ie_one_of(
                &mut errors,
                "wlan_offload_indication",
                ie.value as usize,
                &[0, 1, 2, 3],
            );
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::NetworkToUe),
            );
        }
        if let Some(ie) = &self.header_compression_configuration {
            check_eps_declared_length(
                &mut errors,
                "header_compression_configuration",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "header_compression_configuration",
                ie.value.len() + 2,
                5,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "header_compression_configuration",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.extended_apn_ambr {
            check_eps_declared_length(
                &mut errors,
                "extended_apn_ambr",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_apn_ambr",
                ie.value.len() + 2,
                8,
                Some(8),
            );
            check_eps_ie_valid(&mut errors, "extended_apn_ambr", ie.is_well_formed());
        }
        if let Some(ie) = &self.extended_eps_qos {
            check_eps_declared_length(
                &mut errors,
                "extended_eps_qos",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_eps_qos",
                ie.value.len() + 2,
                12,
                Some(12),
            );
            check_eps_ie_valid(&mut errors, "extended_eps_qos", ie.is_well_formed());
        }
        if self.extended_eps_qos.is_some()
            && self
                .new_eps_qos
                .as_ref()
                .is_none_or(|ie| ie.value.len() < 13)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_eps_qos",
                message: "Extended EPS QoS needs EPS QoS at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        if self.extended_apn_ambr.is_some()
            && self.apn_ambr.as_ref().is_none_or(|ie| ie.value.len() < 6)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_apn_ambr",
                message: "Extended APN-AMBR needs APN-AMBR at its maximum, with extended-2 octets"
                    .into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasNotification {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "notification_indicator",
            self.notification_indicator.length as usize,
            self.notification_indicator.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "notification_indicator",
            self.notification_indicator.value.len() + 1,
            2,
            Some(2),
        );
        check_eps_ie_valid(
            &mut errors,
            "notification_indicator",
            self.notification_indicator.value.as_slice() == [1],
        );
        errors
    }
}

impl Validate for NasPdnConnectivityReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.back_off_timer_value {
            check_eps_declared_length(
                &mut errors,
                "back_off_timer_value",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "back_off_timer_value",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "back_off_timer_value", ie.is_well_formed());
        }
        if let Some(ie) = &self.re_attempt_indicator {
            check_eps_declared_length(
                &mut errors,
                "re_attempt_indicator",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "re_attempt_indicator",
                ie.value.len() + 2,
                3,
                Some(3),
            );
            check_eps_ie_valid(&mut errors, "re_attempt_indicator", ie.is_well_formed());
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::NetworkToUe),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if self.re_attempt_indicator.is_some()
            && (self.esm_cause.value == 26
                || (self.back_off_timer_value.is_none()
                    && ![28, 50, 51, 57, 58, 61, 66].contains(&self.esm_cause.value)))
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "re_attempt_indicator",
                message: "Re-attempt indicator is not allowed for this cause and timer combination"
                    .into(),
            });
        }
        if self.back_off_timer_value.is_some()
            && [28, 50, 51, 54, 57, 58, 61, 65].contains(&self.esm_cause.value)
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "back_off_timer_value",
                message: "Back-off timer is not sent with this ESM cause (8.3.19.3)".into(),
            });
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasPdnConnectivityRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "request_type",
            self.request_type.value as usize,
            0,
            Some(15),
        );
        check_eps_ie_one_of(
            &mut errors,
            "request_type",
            self.request_type.value as usize,
            &[1, 2, 3, 4, 6],
        );
        check_eps_ie(
            &mut errors,
            "pdn_type",
            self.pdn_type.value as usize,
            0,
            Some(7),
        );
        check_eps_ie_one_of(
            &mut errors,
            "pdn_type",
            self.pdn_type.value as usize,
            &[1, 2, 3, 5, 6],
        );
        if let Some(ie) = &self.esm_information_transfer_flag {
            check_eps_ie_one_of(
                &mut errors,
                "esm_information_transfer_flag",
                ie.value as usize,
                &[0, 1],
            );
        }
        if let Some(ie) = &self.access_point_name {
            check_eps_declared_length(
                &mut errors,
                "access_point_name",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "access_point_name",
                ie.value.len() + 2,
                3,
                Some(102),
            );
            check_eps_ie_valid(&mut errors, "access_point_name", ie.is_well_formed());
        }
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.device_properties {
            check_eps_ie_one_of(&mut errors, "device_properties", ie.value as usize, &[0, 1]);
        }
        if let Some(ie) = &self.nbifom_container {
            check_eps_declared_length(
                &mut errors,
                "nbifom_container",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "nbifom_container",
                ie.value.len() + 2,
                3,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "nbifom_container",
                ie.is_well_formed_for(NbifomDirection::UeToNetwork),
            );
        }
        if let Some(ie) = &self.header_compression_configuration {
            check_eps_declared_length(
                &mut errors,
                "header_compression_configuration",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "header_compression_configuration",
                ie.value.len() + 2,
                5,
                Some(257),
            );
            check_eps_ie_valid(
                &mut errors,
                "header_compression_configuration",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "protocol_configuration_options",
                message: "PCO and extended PCO are mutually exclusive".into(),
            });
        }
        if matches!(self.request_type.value, 3 | 4 | 6) && self.access_point_name.is_some() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "access_point_name",
                message: "APN is forbidden for RLOS and emergency PDN requests".into(),
            });
        }
        errors
    }
}

impl Validate for NasPdnDisconnectReject {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Downlink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasPdnDisconnectRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "linked_eps_bearer_identity",
            self.linked_eps_bearer_identity.value as usize,
            0,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "linked_eps_bearer_identity",
            self.linked_eps_bearer_identity.value as usize,
            1,
            Some(15),
        );
        check_eps_ie(
            &mut errors,
            "spare_half_octet",
            self.spare_half_octet.value as usize,
            0,
            Some(0),
        );
        if let Some(ie) = &self.protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "protocol_configuration_options",
                ie.value.len() + 2,
                3,
                Some(253),
            );
            check_eps_ie_valid(
                &mut errors,
                "protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if let Some(ie) = &self.extended_protocol_configuration_options {
            check_eps_declared_length(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.value.len() + 3,
                4,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "extended_protocol_configuration_options",
                ie.is_well_formed(PcoDirection::Uplink),
            );
        }
        if self.protocol_configuration_options.is_some()
            && self.extended_protocol_configuration_options.is_some()
        {
            errors.push(ValidationError {
                severity: Severity::Warning,
                field: "extended_protocol_configuration_options",
                message: "PCO and ePCO apply to exclusive end-to-end support cases".into(),
            });
        }
        errors
    }
}

impl Validate for NasRemoteUeReport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if let Some(ie) = &self.remote_ue_context_connected {
            check_eps_declared_length(
                &mut errors,
                "remote_ue_context_connected",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "remote_ue_context_connected",
                ie.value.len() + 3,
                5,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "remote_ue_context_connected",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.remote_ue_context_disconnected {
            check_eps_declared_length(
                &mut errors,
                "remote_ue_context_disconnected",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "remote_ue_context_disconnected",
                ie.value.len() + 3,
                5,
                Some(65538),
            );
            check_eps_ie_valid(
                &mut errors,
                "remote_ue_context_disconnected",
                ie.is_well_formed(),
            );
        }
        if let Some(ie) = &self.prose_key_management_function_address {
            check_eps_declared_length(
                &mut errors,
                "prose_key_management_function_address",
                ie.length as usize,
                ie.value.len(),
            );
            check_eps_ie(
                &mut errors,
                "prose_key_management_function_address",
                ie.value.len() + 2,
                3,
                Some(19),
            );
            check_eps_ie_valid(
                &mut errors,
                "prose_key_management_function_address",
                ie.is_well_formed(),
            );
        }
        errors
    }
}

impl Validate for NasRemoteUeReportResponse {
    fn validate(&self) -> Vec<ValidationError> {
        Vec::new()
    }
}

impl Validate for NasEsmDataTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_declared_length(
            &mut errors,
            "user_data_container",
            self.user_data_container.length as usize,
            self.user_data_container.value.len(),
        );
        check_eps_ie(
            &mut errors,
            "user_data_container",
            self.user_data_container.value.len() + 2,
            2,
            None,
        );
        if let Some(ie) = &self.release_assistance_indication {
            check_eps_ie_one_of(
                &mut errors,
                "release_assistance_indication",
                ie.value as usize,
                &[0, 1, 2],
            );
        }
        errors
    }
}

impl Validate for NasEmmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        match self {
            Self::AttachAccept(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::AttachComplete(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::AttachReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::AttachRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::AuthenticationFailure(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::AuthenticationReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::AuthenticationRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::AuthenticationResponse(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::CsServiceNotification(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::DetachAccept(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::DetachRequestFromUe(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::DetachRequestToUe(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::DownlinkNasTransport(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::EmmInformation(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::EmmStatus(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ExtendedServiceRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::GutiReallocationCommand(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::GutiReallocationComplete(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::IdentityRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::IdentityResponse(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::SecurityModeCommand(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::SecurityModeComplete(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::SecurityModeReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ServiceReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::TrackingAreaUpdateAccept(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::TrackingAreaUpdateComplete(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::TrackingAreaUpdateReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::TrackingAreaUpdateRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::UplinkNasTransport(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::DownlinkGenericNasTransport(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::UplinkGenericNasTransport(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ControlPlaneServiceRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ServiceAccept(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
        }
    }
}

impl Validate for NasEsmMessage {
    fn validate(&self) -> Vec<ValidationError> {
        match self {
            Self::ActivateDedicatedEpsBearerContextAccept(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ActivateDedicatedEpsBearerContextReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ActivateDedicatedEpsBearerContextRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ActivateDefaultEpsBearerContextAccept(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ActivateDefaultEpsBearerContextReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ActivateDefaultEpsBearerContextRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::BearerResourceAllocationReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::BearerResourceAllocationRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::BearerResourceModificationReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::BearerResourceModificationRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::DeactivateEpsBearerContextAccept(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::DeactivateEpsBearerContextRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::EsmDummyMessage(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::EsmInformationRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::EsmInformationResponse(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::EsmStatus(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ModifyEpsBearerContextAccept(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ModifyEpsBearerContextReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::ModifyEpsBearerContextRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::Notification(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::PdnConnectivityReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::PdnConnectivityRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::PdnDisconnectReject(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::PdnDisconnectRequest(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::RemoteUeReport(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::RemoteUeReportResponse(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
            Self::EsmDataTransport(message) => with_optional_ie_checks(
                message.validate(),
                &message.unknown_ies,
                message.ie_order_findings(),
            ),
        }
    }
}

// END TS24301 VALIDATE

fn check_esm_message_container(
    errors: &mut Vec<ValidationError>,
    value: &[u8],
    severity: Severity,
) {
    if !matches!(decode_nas_eps_message(value), Ok(NasEpsMessage::Esm(..))) {
        errors.push(ValidationError {
            severity,
            field: "esm_message_container",
            message: "ESM message container does not hold one complete ESM PDU".into(),
        });
    }
}

fn check_eps_ie(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    actual: usize,
    minimum: usize,
    maximum: Option<usize>,
) {
    if actual < minimum || maximum.is_some_and(|maximum| actual > maximum) {
        errors.push(ValidationError {
            severity: Severity::Error,
            field,
            message: format!(
                "EPS IE length/value {actual} is outside the TS 24.301 range {minimum}..{maximum:?}"
            ),
        });
    }
}

fn check_eps_declared_length(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    declared: usize,
    actual: usize,
) {
    if declared != actual {
        errors.push(ValidationError {
            severity: Severity::Error,
            field,
            message: format!("EPS IE declares {declared} bytes but contains {actual}"),
        });
    }
}

fn check_eps_ie_one_of(
    errors: &mut Vec<ValidationError>,
    field: &'static str,
    actual: usize,
    allowed: &[usize],
) {
    if !allowed.contains(&actual) {
        errors.push(ValidationError {
            severity: Severity::Error,
            field,
            message: format!("EPS IE length {actual} is not one of {allowed:?}"),
        });
    }
}

fn check_eps_ie_valid(errors: &mut Vec<ValidationError>, field: &'static str, valid: bool) {
    if !valid {
        errors.push(ValidationError {
            severity: Severity::Error,
            field,
            message: "EPS IE has invalid value or structure".into(),
        });
    }
}

impl Validate for NasEmmTransport {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        if self.security_header.security_header_type != NasEpsSecurityHeaderType::EmmTransport {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "security_header_type",
                message: "EMM TRANSPORT requires its security header type".into(),
            });
        }
        if self.data_container.is_some() && self.protected_payload.is_some() {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "protected_payload",
                message: "EMM TRANSPORT cannot contain clear and opaque payloads together".into(),
            });
        }
        if let Some(data) = &self.data_container {
            check_eps_ie(&mut errors, "data_container", data.len() + 1, 2, None);
            check_eps_ie_valid(
                &mut errors,
                "data_container",
                valid_emm_data_container(data, false),
            );
        }
        // Table 8.2.35.1.1: the data container has at least two octets, and
        // ciphering keeps the length.
        if self
            .protected_payload
            .as_ref()
            .is_some_and(|payload| payload.len() < 2)
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "protected_payload",
                message: "EMM TRANSPORT data container is shorter than two octets".into(),
            });
        }
        errors
    }
}

impl NasEmmTransport {
    /// [`Validate::validate`] with the direction-dependent rule of Table
    /// 9.9.3.74.1: from the network, the DDX bits are spare and zero.
    pub fn validate_with_direction(
        &self,
        direction: crate::common::Direction,
    ) -> Vec<ValidationError> {
        let mut errors = self.validate();
        if direction == crate::common::Direction::Downlink
            && let Some(data) = &self.data_container
            && !valid_emm_data_container(data, true)
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "data_container",
                message: "Downlink EMM TRANSPORT data container has non-zero DDX bits".into(),
            });
        }
        errors
    }
}

impl Validate for NasEpsMessage {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = match self {
            Self::Emm(_, message) => message.validate(),
            Self::Esm(_, message) => message.validate(),
            Self::SecurityProtected(header, inner) => {
                let mut errors = inner.validate();
                if check_protected_inner(header.security_header_type, inner).is_err() {
                    errors.push(ValidationError {
                        severity: Severity::Error,
                        field: "security_header_type",
                        message: "Security header type does not match the protected message".into(),
                    });
                }
                errors
            }
            Self::ServiceRequest(message) => message.validate(),
            Self::EmmTransport(message) => message.validate(),
            _ => Vec::new(),
        };
        if let Self::Esm(header, message) = self {
            let transaction = matches!(
                message,
                NasEsmMessage::BearerResourceAllocationRequest(_)
                    | NasEsmMessage::EsmDummyMessage(_)
                    | NasEsmMessage::BearerResourceAllocationReject(_)
                    | NasEsmMessage::BearerResourceModificationRequest(_)
                    | NasEsmMessage::BearerResourceModificationReject(_)
                    | NasEsmMessage::EsmInformationRequest(_)
                    | NasEsmMessage::EsmInformationResponse(_)
                    | NasEsmMessage::PdnConnectivityRequest(_)
                    | NasEsmMessage::PdnConnectivityReject(_)
                    | NasEsmMessage::PdnDisconnectRequest(_)
                    | NasEsmMessage::PdnDisconnectReject(_)
            );
            let bearer_response = matches!(
                message,
                NasEsmMessage::ActivateDedicatedEpsBearerContextAccept(_)
                    | NasEsmMessage::ActivateDedicatedEpsBearerContextReject(_)
                    | NasEsmMessage::ActivateDefaultEpsBearerContextAccept(_)
                    | NasEsmMessage::ActivateDefaultEpsBearerContextReject(_)
                    | NasEsmMessage::ModifyEpsBearerContextAccept(_)
                    | NasEsmMessage::ModifyEpsBearerContextReject(_)
                    | NasEsmMessage::DeactivateEpsBearerContextAccept(_)
            );
            let bearer_request = matches!(
                message,
                NasEsmMessage::ActivateDedicatedEpsBearerContextRequest(_)
                    | NasEsmMessage::ActivateDefaultEpsBearerContextRequest(_)
                    | NasEsmMessage::ModifyEpsBearerContextRequest(_)
                    | NasEsmMessage::DeactivateEpsBearerContextRequest(_)
            );
            let remote_report = matches!(
                message,
                NasEsmMessage::RemoteUeReport(_) | NasEsmMessage::RemoteUeReportResponse(_)
            );
            let esm_data_transport = matches!(message, NasEsmMessage::EsmDataTransport(_));
            let unassigned_notification = matches!(message, NasEsmMessage::Notification(_))
                && header.eps_bearer_identity == 0
                && header.procedure_transaction_identity == 0;
            if transaction && header.eps_bearer_identity != 0
                || (bearer_response || bearer_request || remote_report || esm_data_transport)
                    && header.eps_bearer_identity == 0
                || unassigned_notification
            {
                errors.push(ValidationError {
                    severity: Severity::Error,
                    field: "eps_bearer_identity",
                    message: "EPS bearer identity does not match the ESM procedure".into(),
                });
            }
            let pti = header.procedure_transaction_identity;
            let invalid_pti = if pti == 255 {
                true
            } else if transaction || remote_report {
                pti == 0
            } else if bearer_response || esm_data_transport {
                pti != 0
            } else {
                false
            };
            if invalid_pti {
                errors.push(ValidationError {
                    severity: Severity::Error,
                    field: "procedure_transaction_identity",
                    message: "Procedure transaction identity does not match the ESM procedure"
                        .into(),
                });
            }
        }
        if !matches!(self, Self::EmmTransport(_))
            && let Err(error) = self.to_bytes()
        {
            errors.push(ValidationError {
                severity: Severity::Error,
                field: "EPS NAS header",
                message: error.to_string(),
            });
        }
        errors
    }
}

impl Validate for NasServiceRequest {
    fn validate(&self) -> Vec<ValidationError> {
        let mut errors = Vec::new();
        check_eps_ie(
            &mut errors,
            "security_header_type",
            self.security_header_type as usize,
            12,
            Some(12),
        );
        check_eps_ie(
            &mut errors,
            "nas_key_set_identifier",
            (self.ksi_and_sequence_number >> 5) as usize,
            0,
            Some(6),
        );
        errors
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(errors: &[ValidationError]) -> Vec<&'static str> {
        errors.iter().map(|error| error.field).collect()
    }

    fn attach_request(ue_network_capability: Vec<u8>) -> NasAttachRequest {
        NasAttachRequest::new(
            NasEpsAttachType::new(1),
            NasKeySetIdentifier::new(7),
            NasEpsMobileIdentity::from_imsi("001010123456789").unwrap(),
            NasUeNetworkCapability::new(ue_network_capability),
            NasEsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
        )
    }

    #[test]
    fn non_sat_lsp_is_a_defined_ue_network_capability_bit() {
        // TS 24.301 V19.8.0 defines octet 12 bit 1; other octet 12-15 bits are spare.
        let mut capability = vec![0xe0, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0x01];
        assert!(attach_request(capability.clone()).validate().is_empty());
        capability[9] = 0x02;
        assert_eq!(
            fields(&attach_request(capability).validate()),
            ["ue_network_capability"]
        );
    }

    #[test]
    fn one_tai_forbidden_list_meets_the_ie_minimum() {
        // §9.9.3.33 allows 8 octets; Table 8.2.24.1 says 9.
        let bytes = [
            0x07, 0x4e, 0x0f, 0x1d, 0x06, 0x00, 0x02, 0xf8, 0x39, 0x00, 0x01,
        ];
        let message = crate::nas_eps::decode_nas_eps_message(&bytes).unwrap();
        assert!(message.validate().is_empty());
    }

    #[test]
    fn longer_n1_ue_network_capability_is_valid() {
        let request = attach_request(vec![0xe0, 0xe0])
            .set_n1_ue_network_capability(NasN1UeNetworkCapability::new(vec![0x7f, 0, 0]));
        assert!(request.validate().is_empty());
        let spare = attach_request(vec![0xe0, 0xe0])
            .set_n1_ue_network_capability(NasN1UeNetworkCapability::new(vec![0x80]));
        assert_eq!(fields(&spare.validate()), ["n1_ue_network_capability"]);
    }

    /// TFT errors are answered by the ESM procedure with the cause of
    /// `parse_tft` (TS 24.301 §6.4.2.4, §6.4.3.4), so they neither fail the
    /// message with #96 nor drop an optional TFT.
    #[test]
    fn tft_errors_are_left_to_the_esm_procedure() {
        let semantic_error = vec![
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x01, 0xaa, 0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ];
        for receiver_ok in [
            ReceiverSyntaxCheck::receiver_syntax_ok(&NasTft::new(semantic_error.clone())),
            ReceiverSyntaxCheck::receiver_syntax_ok(&NasTrafficFlowAggregate::new(semantic_error)),
        ] {
            assert!(receiver_ok);
        }

        // "Create new TFT" without packet filters.
        assert!(ReceiverSyntaxCheck::receiver_syntax_ok(&NasTft::new(vec![
            0x20
        ])));
        assert!(ReceiverSyntaxCheck::receiver_syntax_ok(
            &NasTrafficFlowAggregate::new(vec![0x20])
        ));
        assert!(!ReceiverSyntaxCheck::receiver_syntax_ok(&NasTft::new(
            vec![]
        )));
        let syntax_error =
            decode_nas_eps_message(&[0x52, 0x01, 0xc5, 0x05, 0x01, 0x00, 0x01, 0x20]).unwrap();
        let NasEpsMessage::Esm(_, NasEsmMessage::ActivateDedicatedEpsBearerContextRequest(request)) =
            syntax_error
        else {
            panic!("wrong mandatory-TFT message");
        };
        assert_eq!(
            request.tft.parse_tft().map_err(TftError::esm_cause),
            Err(EsmCause::SyntacticalErrorInTheTftOperation)
        );

        let mut mandatory_wire = vec![0x52, 0x01, 0xc5, 0x05, 0x01, 0x00, 0x19];
        mandatory_wire.extend_from_slice(&[
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x01, 0xaa, 0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ]);
        let NasEpsMessage::Esm(_, NasEsmMessage::ActivateDedicatedEpsBearerContextRequest(request)) =
            decode_nas_eps_message(&mandatory_wire).unwrap()
        else {
            panic!("wrong mandatory-TFT message");
        };
        assert_eq!(request.tft.parse_tft(), Err(TftError::SemanticTftOperation));

        let mut optional_wire = vec![0x52, 0x01, 0xc9, 0x36, 0x19];
        optional_wire.extend_from_slice(&[
            0x31, 0x31, 0x00, 0x09, 0x10, 0x0a, 0x00, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0x01,
            0x01, 0xaa, 0x01, 0x01, 0xbb, 0x02, 0x04, 0x00, 0x01, 0x00, 0x02,
        ]);
        let NasEpsMessage::Esm(_, NasEsmMessage::ModifyEpsBearerContextRequest(request)) =
            decode_nas_eps_message(&optional_wire).unwrap()
        else {
            panic!("wrong optional-TFT message");
        };
        assert_eq!(
            request.tft.unwrap().parse_tft(),
            Err(TftError::SemanticTftOperation)
        );
    }

    #[test]
    fn security_mode_command_rejects_reserved_ksi_and_spare_algorithm_bits() {
        let command = |ksi: u8, algorithms: u8| {
            NasSecurityModeCommand::new(
                NasSelectedNasSecurityAlgorithms::new(algorithms),
                NasKeySetIdentifier::new(ksi),
                NasSpareHalfOctet::new(0),
                NasReplayedUeSecurityCapabilities::new(vec![0xe0, 0xe0]),
            )
        };
        assert!(command(0, 0x02).validate().is_empty());
        let null_integrity = command(0, 0x00).validate();
        assert_eq!(
            fields(&null_integrity),
            ["selected_nas_security_algorithms"]
        );
        assert_eq!(null_integrity[0].severity, Severity::Warning);
        let unspecified = command(0, 0x42).validate();
        assert_eq!(fields(&unspecified), ["selected_nas_security_algorithms"]);
        assert_eq!(unspecified[0].severity, Severity::Error);
        assert_eq!(
            fields(&command(7, 0x02).validate()),
            ["nas_key_set_identifier"]
        );
        assert_eq!(
            fields(&command(0, 0x82).validate()),
            ["selected_nas_security_algorithms"]
        );
        let bad_replay = NasSecurityModeCommand::new(
            NasSelectedNasSecurityAlgorithms::new(0x02),
            NasKeySetIdentifier::new(0),
            NasSpareHalfOctet::new(0),
            NasReplayedUeSecurityCapabilities::new(vec![0xe0, 0xe0, 0, 0]),
        );
        assert_eq!(
            fields(&bad_replay.validate()),
            ["replayed_ue_security_capabilities"]
        );
    }
}
