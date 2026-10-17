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

//! An IE type that one NAS specification defines and the other reuses is one
//! type, with the rules of its clause in both protocols.

use oxirush_nas::nas_5gs::{self, Nas5gsMessage};
use oxirush_nas::nas_eps::{self, NasEpsMessage};
use oxirush_nas::{Validate, ValidationError};

fn fields(errors: Vec<ValidationError>) -> Vec<&'static str> {
    errors.iter().map(|error| error.field).collect()
}

#[test]
fn a_reused_ie_type_is_one_type_in_both_protocols() {
    // The T3346 value of TS 24.501 and of TS 24.301 is a GPRS timer 2.
    let timer = nas_5gs::NasGprsTimer2::from_seconds(600).unwrap();
    let reject = nas_eps::NasAttachReject::new(nas_eps::NasEmmCause::new(22))
        .with_t3346_value(timer.clone());
    assert_eq!(reject.t3346_value, Some(timer));
}

#[test]
fn the_sender_rules_of_a_reused_type_hold_in_both_protocols() {
    // UE status (TS 24.501 §9.11.3.56): bits 8 to 3 are spare, in EPS too.
    let update = nas_eps::NasTrackingAreaUpdateRequest::new(
        nas_eps::NasEpsUpdateType::new(0),
        nas_eps::NasKeySetIdentifier::new(0),
        nas_eps::NasEpsMobileIdentity::new(vec![0xf6, 0x02, 0xf8, 0x39, 0, 1, 1, 0, 0, 0, 1]),
    )
    .with_old_guti_type(nas_eps::NasGutiType::new(1))
    .with_ue_network_capability(nas_eps::NasUeNetworkCapability::new(vec![0xe0, 0xe0]));
    assert_eq!(fields(update.validate()), Vec::<&str>::new());
    let spare = update.with_ue_status(nas_eps::NasUeStatus::new(vec![0xff]));
    let octets = NasEpsMessage::new_emm(spare).encode().unwrap();
    let message = NasEpsMessage::decode(&octets).unwrap();
    assert_eq!(fields(message.validate()), ["ue_status"]);

    // IMEISV request (TS 24.008 §10.5.5.10): 0 or 1, in 5GS too.
    let command = nas_5gs::NasSecurityModeCommand::new(
        nas_5gs::NasSecurityAlgorithms::new(0x22),
        nas_5gs::NasKeySetIdentifier::new(0),
        nas_5gs::NasUeSecurityCapability::new(vec![0xe0, 0xe0]),
    );
    let requested = command
        .clone()
        .with_imeisv_request(nas_5gs::NasImeisvRequest::new(1));
    let reserved = command.with_imeisv_request(nas_5gs::NasImeisvRequest::new(2));
    for (command, expected) in [(requested, vec![]), (reserved, vec!["imeisv_request"])] {
        let octets = Nas5gsMessage::new_5gmm(command).encode().unwrap();
        let message = Nas5gsMessage::decode(&octets).unwrap();
        assert_eq!(fields(message.validate()), expected);
    }
}

#[test]
fn the_paging_restriction_ies_of_both_systems_have_one_interface() {
    // TS 24.501 §9.11.3.77 and TS 24.301 §9.9.3.66: a type, then a bitmap
    // of the sessions or connections for which paging is not restricted.
    let sessions = nas_5gs::PagingRestrictionType::AllRestrictedExceptSpecifiedPduSessions;
    let connections = nas_eps::PagingRestrictionType::AllRestrictedExceptSpecifiedPdnConnections;
    let five = nas_5gs::NasPagingRestriction::from_restriction(sessions, &[5, 15]).unwrap();
    let eps = nas_eps::NasPagingRestriction::from_restriction(connections, &[5, 15]).unwrap();
    assert_eq!(five.value, eps.value);
    assert_eq!(five.unrestricted_psis(), Some(vec![5, 15]));
    assert_eq!(eps.unrestricted_ebis(), Some(vec![5, 15]));
    assert!(five.is_well_formed() && eps.is_well_formed());
    let reserved = nas_5gs::NasPagingRestriction::new(vec![0]);
    assert_eq!(
        (reserved.restriction_type(), reserved.is_well_formed()),
        (None, false)
    );

    // The paging restriction decision of the additional request result is
    // one type (TS 24.501 Table 9.11.3.81.1, TS 24.301 Table 9.9.3.67.1).
    let accepted = nas_5gs::PagingRestrictionDecision::PagingRestrictionIsAccepted;
    let result = nas_5gs::NasFGsAdditionalRequestResult::from_paging_restriction_decision(accepted);
    let eps_result = nas_eps::NasEpsAdditionalRequestResult::new(result.value.clone());
    assert_eq!(eps_result.paging_restriction_decision(), Some(accepted));
    assert_eq!(result.paging_restriction_decision(), Some(accepted));
    assert!(!nas_eps::NasEpsAdditionalRequestResult::new(vec![3]).is_well_formed());
}

#[test]
fn a_key_set_identifier_is_displayed_alike_in_both_systems() {
    // TS 24.501 §9.11.3.32 and TS 24.301 §9.9.3.21 code it alike.
    let mapped = nas_5gs::NasKeySetIdentifier::new(0x0b);
    let command = nas_5gs::NasSecurityModeCommand::new(
        nas_5gs::NasSecurityAlgorithms::new(0x22),
        mapped,
        nas_5gs::NasUeSecurityCapability::new(vec![0xe0, 0xe0]),
    );
    assert!(
        command.to_string().ends_with("ngKSI=mapped 3)"),
        "{command}"
    );
    let eps = nas_eps::NasSecurityModeCommand::new(
        nas_eps::NasSecurityAlgorithms::new(0x22),
        nas_eps::NasKeySetIdentifier::new(0x07),
        nas_eps::NasUeSecurityCapability::new(vec![0xe0, 0xe0]),
    );
    assert!(eps.to_string().contains("KSI=no key"), "{eps}");
}

#[test]
fn an_address_of_a_session_is_built_alike_in_both_systems() {
    // TS 24.501 §9.11.4.10 and TS 24.301 §9.9.4.9: a type, then the address.
    let five = nas_5gs::NasPduAddress::from_ipv4v6([0, 0, 0, 0, 0, 0, 0, 1], [10, 0, 0, 1]);
    let eps = nas_eps::NasPdnAddress::from_ipv4v6([0, 0, 0, 0, 0, 0, 0, 1], [10, 0, 0, 1]);
    assert_eq!(five.value, eps.value);
    assert_eq!(
        nas_eps::NasPdnAddress::from_ipv4([10, 0, 0, 1]).ipv4(),
        Some([10, 0, 0, 1])
    );
    let iid = [1, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(
        nas_eps::NasPdnAddress::from_ipv6_iid(iid).ipv6_interface_id(),
        Some(iid)
    );
}
