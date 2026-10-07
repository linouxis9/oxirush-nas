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
//! name, with its value as a reader writes it and its octets, at the paths
//! of the `view` module.

use oxirush_nas::{nas_eps::NasEpsMessage, view};
use serde_json::json;

fn main() -> Result<(), String> {
    // EPS attach with an IMSI of PLMN 208/93 and a PDN CONNECTIVITY REQUEST.
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").expect("hex");
    let message = NasEpsMessage::from_bytes(&bytes).expect("decode failed");

    // The message to its view, and each value with the path that selects it.
    let mut tree = message.to_view();
    for (path, value) in view::paths(&tree) {
        println!("{path} = {value}");
    }

    // A coded value reads by the name the specification gives it.
    let select = |path| view::select(&tree, path);
    assert_eq!(
        select("/nas/eps-attach-type")?,
        [&json!({"value": "eps-attach", "octets": "01"})]
    );
    assert_eq!(
        select("/nas/nas-key-set-identifier/value")?,
        [&json!({"native": 0})]
    );

    // A structured IE is matched through its value, in the usual notation,
    // and a container through the view of the message it carries.
    assert_eq!(
        select("/nas/eps-mobile-identity/value/imsi")?,
        [&json!("208930000000001")]
    );
    assert_eq!(
        select("/nas/ue-network-capability/value/eea")?,
        [&json!([0, 1, 2])]
    );
    let request = "/nas/esm-message-container/value";
    let kind = view::select(&tree, &format!("{request}/message-type/value"))?;
    assert_eq!(kind, [&json!("pdn-connectivity-request")]);
    let pdn_type = format!("{request}/pdn-type/value");
    assert_eq!(view::select(&tree, &pdn_type)?, [&json!("ipv4v6")]);

    // The same members are written, in any case.
    let attach_type = "/nas/EPS attach type/value";
    view::set(&mut tree, attach_type, json!("Combined EPS IMSI attach"))?;
    let imsi = "/nas/eps-mobile-identity/value/imsi";
    view::set(&mut tree, imsi, json!("208930000000002"))?;
    view::set(
        &mut tree,
        "/nas/ue-network-capability/value/eea",
        json!([0]),
    )?;
    view::set(&mut tree, &pdn_type, json!("ipv6"))?;

    // And back to octets: each IE is encoded from what was written.
    let edited = message
        .with_view(tree.clone())
        .expect("the view is a message");
    let edited_bytes = edited.to_bytes().expect("encode failed");
    println!("\n{}\n{}", hex::encode(&bytes), hex::encode(&edited_bytes));
    assert_eq!(
        hex::encode(&edited_bytes),
        "0741020829803900000000200280e000040201d021"
    );

    // Nothing that a view says is ignored: a name that does not exist is an
    // error, and so are octets and a value that disagree.
    view::set(&mut tree, attach_type, json!("combined"))?;
    println!("\n{}", message.with_view(tree).unwrap_err());
    Ok(())
}
