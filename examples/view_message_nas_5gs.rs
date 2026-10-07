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

//! Read and edit a 5GS REGISTRATION REQUEST through its view: each IE by
//! its name, with its value as a reader writes it and its octets.

use oxirush_nas::nas_5gs::Nas5gsMessage;
use serde_json::json;

fn main() {
    // Initial registration with a SUCI of PLMN 208/93, a security
    // capability and a requested NSSAI.
    let bytes = hex::decode(
        "7e004179000d0102f8390000000000000010022e02e0e02f05040101020352\
         02f839000001",
    )
    .expect("hex");
    let message = Nas5gsMessage::from_bytes(&bytes).expect("decode failed");

    // The message to its tree.
    let mut view = message.to_view();
    println!("{view:#}");

    // A coded value reads by the name the specification gives it.
    let registration_type = &view["5gs-registration-type"];
    assert_eq!(
        registration_type["value"]["registration-type"],
        "initial-registration"
    );
    assert_eq!(registration_type["value"]["follow-on-request"], true);
    assert_eq!(registration_type["octets"], "79");

    // A structured IE is matched through its value, in the usual notation.
    let suci = &view["5gs-mobile-identity"]["value"]["suci"]["imsi"];
    assert_eq!(suci["plmn"], "208-93");
    assert_eq!(suci["msin"], "0000000120");
    assert_eq!(view["requested-nssai"]["value"][0]["sst"], 1);
    assert_eq!(view["requested-nssai"]["value"][0]["sd"], "010203");
    assert_eq!(
        view["last-visited-registered-tai"]["value"],
        json!({"plmn": "208-93", "tac": 1})
    );
    assert_eq!(
        view["ue-security-capability"]["value"]["ea"],
        json!([0, 1, 2])
    );

    // The same members are written, in any case and with a number also in
    // hexadecimal. The octets of an IE are written to say them as they are.
    view["5gs-registration-type"]["value"]["registration-type"] =
        json!("Mobility Registration Update");
    view["5gs-mobile-identity"]["value"]["suci"]["imsi"]["msin"] = json!("0000000121");
    view["requested-nssai"]["value"] = json!([{"sst": 1}, {"sst": 2, "sd": "0000ff"}]);
    view["last-visited-registered-tai"]["value"]["tac"] = json!("0x2a");
    view["ue-security-capability"]["octets"] = json!("ffff");

    // An optional IE that the message does not have is null in the view,
    // and is added by its value or its octets.
    assert!(view["mico-indication"].is_null());
    view["mico-indication"] = json!({"value": {"raai": true}});

    // And back to octets: each IE is encoded from what was written.
    let edited = message
        .with_view(view.clone())
        .expect("the view is a message");
    let edited_bytes = edited.to_bytes().expect("encode failed");
    println!("\n{}\n{}", hex::encode(&bytes), hex::encode(&edited_bytes));
    assert_eq!(
        hex::encode(&edited_bytes),
        "7e00417a000d0102f8390000000000000010122e02ffff2f07010104020000\
         ff5202f83900002ab1"
    );

    // Nothing that a view says is ignored: a name that does not exist is an
    // error, and so are octets and a value that disagree.
    view["5gs-registration-type"]["value"]["registration-type"] = json!("mobility");
    println!("\n{}", message.with_view(view).unwrap_err());
}
