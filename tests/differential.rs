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

//! What comparing the crate with another decoder of the same octets found:
//! each test is a message on which the two read a field differently, and
//! what the clause says of it. `tests/wireshark.rs` runs the comparison.

use oxirush_nas::nas_5gs::*;

fn message_5gs(octets: &str) -> Message {
    Message::decode(&hex::decode(octets).unwrap()).unwrap()
}

/// TS 24.501 §9.11.3.1: bit 6 of octet 3 of the 5GMM capability is "N3
/// data", and 0 means "N3 data transfer supported". The flag as sent is
/// named for what a 1 means, and `n3_data()` is the capability, as those of
/// the 5GS network feature support (§9.11.3.5) are.
#[test]
fn n3_data_of_a_5gmm_capability_is_supported_when_its_bit_is_0() {
    // REGISTRATION REQUEST with a 5GMM capability of S1 mode, HO attach and LPP
    let request = "7e004101000d0102f8390000000021436587f9100107";
    let Message::Gmm(_, GmmMessage::RegistrationRequest(request)) = message_5gs(request) else {
        panic!("a REGISTRATION REQUEST")
    };
    let capability = request.fgmm_capability.unwrap();
    assert!(capability.n3_data());
    assert!(!capability.n3_data_not_supported());
    let not_supported = capability.clone().with_n3_data(false);
    assert_eq!(not_supported.value, [0x27]);
    assert!(not_supported.n3_data_not_supported());
    assert_eq!(not_supported.with_n3_data(true).value, [0x07]);
}

#[cfg(feature = "tree")]
#[test]
fn a_view_names_the_n3_data_bit_for_what_a_1_means() {
    for (octets, not_supported) in [
        ("7e004101000d0102f8390000000021436587f9100107", false),
        ("7e004101000d0102f8390000000021436587f9100127", true),
    ] {
        let view = message_5gs(octets).to_view();
        let flags = &view["5gmm-capability"]["value"];
        assert_eq!(
            flags["n3-data-not-supported"],
            oxirush_nas::tree!(not_supported),
            "{octets}"
        );
        assert!(flags.get("n3-data").is_none(), "{octets}");
    }
    // The N1 UE network capability of EPS (TS 24.301 §9.9.3.57), bit 2
    use oxirush_nas::nas_eps::*;
    for (value, not_supported) in [(0x00, false), (0x02, true)] {
        let capability = N1UeNetworkCapability::new(vec![value]);
        assert_eq!(capability.n3_data_not_supported(), not_supported);
        assert_eq!(capability.n3_data_transfer_supported(), !not_supported);
    }
}

/// TS 24.501 §9.11.3.40, Table 9.11.3.40.1: payload container type 8 is
/// "CIoT user data container". A view prints the names of the crate in
/// lower case with hyphens, and an acronym such as CIoT is one word.
#[cfg(feature = "tree")]
#[test]
fn a_ciot_user_data_container_is_named_as_one_word() {
    // CONTROL PLANE SERVICE REQUEST with a CIoT user data container
    let request = "7e004f01887b00144500001400000000400100000a0000010a0000021201";
    let view = message_5gs(request).to_view();
    assert_eq!(
        view["payload-container-type"]["value"],
        oxirush_nas::tree!("ciot")
    );
    let edited = message_5gs(request).with_view(view).unwrap();
    assert_eq!(edited, message_5gs(request));
}
