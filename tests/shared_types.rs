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
