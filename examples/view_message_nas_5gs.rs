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
//! its name, with its value as a reader writes it and its octets, at the
//! paths of the `view` module.

use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
use serde_json::json;

fn main() -> Result<(), String> {
    // Initial registration with a SUCI of PLMN 208/93, a security
    // capability and a requested NSSAI.
    let bytes = hex::decode(
        "7e004179000d0102f8390000000000000010022e02e0e02f05040101020352\
         02f839000001",
    )
    .expect("hex");
    let message = Nas5gsMessage::from_bytes(&bytes).expect("decode failed");

    // The message to its view, and each value with the path that selects it.
    let mut tree = message.to_view();
    for (path, value) in view::paths(&tree) {
        println!("{path} = {value}");
    }

    // A coded value reads by the name the specification gives it.
    let registration_type = "/nas/5gs-registration-type";
    let kind = format!("{registration_type}/value/registration-type");
    assert_eq!(
        view::select(&tree, &kind)?,
        [&json!("initial-registration")]
    );
    let octets = view::select(&tree, &format!("{registration_type}/octets"))?;
    assert_eq!(octets, [&json!("79")]);

    // A structured IE is matched through its value, in the usual notation.
    let select = |path| view::select(&tree, path);
    let suci = select("/nas/5gs-mobile-identity/value/suci/imsi")?;
    assert_eq!(suci[0]["plmn"], "208-93");
    assert_eq!(suci[0]["msin"], "0000000120");
    assert_eq!(select("/nas/requested-nssai/value/*/sst")?, [&json!(1)]);
    assert_eq!(
        select("/nas/last-visited-registered-tai/value")?,
        [&json!({"plmn": "208-93", "tac": 1})]
    );
    assert_eq!(
        select("/nas/ue-security-capability/value/ea")?,
        [&json!([0, 1, 2])]
    );

    // The same members are written, in any case and with a number also in
    // hexadecimal. The octets of an IE are written to say them as they are.
    view::set(&mut tree, &kind, json!("Mobility Registration Update"))?;
    let msin = "/nas/5gs-mobile-identity/value/suci/imsi/msin";
    view::set(&mut tree, msin, json!("0000000121"))?;
    let slices = "/nas/requested-nssai/value";
    view::remove(&mut tree, &format!("{slices}/0/sd"))?;
    view::insert(
        &mut tree,
        &format!("{slices}/-"),
        json!({"sst": 2, "sd": "0000ff"}),
    )?;
    view::set(
        &mut tree,
        "/nas/Last Visited Registered TAI/value/tac",
        json!("0x2a"),
    )?;
    view::set(
        &mut tree,
        "/nas/ue-security-capability/octets",
        json!("ffff"),
    )?;

    // An optional IE that the message does not have selects nothing, and is
    // added by its value or its octets.
    assert!(view::select(&tree, "/nas/mico-indication/value")?.is_empty());
    view::set(
        &mut tree,
        "/nas/mico-indication/value",
        json!({"raai": true}),
    )?;

    // And back to octets: each IE is encoded from what was written.
    let edited = message
        .with_view(tree.clone())
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
    view::set(&mut tree, &kind, json!("mobility"))?;
    println!("\n{}", message.with_view(tree).unwrap_err());
    Ok(())
}
