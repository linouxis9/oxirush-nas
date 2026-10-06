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

//! Read and edit an EPS ATTACH REQUEST through its view: each IE by its
//! name, with its value as a reader writes it and its octets.

use oxirush_nas::nas_eps::NasEpsMessage;
use serde_json::json;

fn main() {
    // EPS attach with an IMSI of PLMN 208/93 and a PDN CONNECTIVITY REQUEST.
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").expect("hex");
    let message = NasEpsMessage::from_bytes(&bytes).expect("decode failed");

    // The message to its tree.
    let mut view = message.to_view();
    println!("{view:#}");

    // A coded value reads by the name the specification gives it.
    assert_eq!(
        view["eps-attach-type"],
        json!({"value": "eps-attach", "octets": "01"})
    );
    assert_eq!(
        view["nas-key-set-identifier"]["value"],
        json!({"native": 0})
    );

    // A structured IE is matched through its value, in the usual notation,
    // and a container through the view of the message it carries.
    assert_eq!(
        view["eps-mobile-identity"]["value"],
        json!({"imsi": "208930000000001"})
    );
    assert_eq!(
        view["ue-network-capability"]["value"]["eea"],
        json!([0, 1, 2])
    );
    let request = &view["esm-message-container"]["value"];
    assert_eq!(request["message-type"]["value"], "pdn-connectivity-request");
    assert_eq!(request["procedure-transaction-identity"]["value"], 1);
    assert_eq!(request["pdn-type"]["value"], "ipv4v6");

    // The same members are written, in any case.
    view["eps-attach-type"]["value"] = json!("Combined EPS IMSI attach");
    view["eps-mobile-identity"]["value"]["imsi"] = json!("208930000000002");
    view["ue-network-capability"]["value"]["eea"] = json!([0]);
    view["esm-message-container"]["value"]["pdn-type"]["value"] = json!("ipv6");

    // And back to octets: each IE is encoded from what was written.
    let edited = message
        .with_view(view.clone())
        .expect("the view is a message");
    let edited_bytes = edited.to_bytes().expect("encode failed");
    println!("\n{}\n{}", hex::encode(&bytes), hex::encode(&edited_bytes));
    assert_eq!(
        hex::encode(&edited_bytes),
        "0741020829803900000000200280e000040201d021"
    );

    // Nothing that a view says is ignored: a name that does not exist is an
    // error, and so are octets and a value that disagree.
    view["eps-attach-type"]["value"] = json!("combined");
    println!("\n{}", message.with_view(view).unwrap_err());
}
