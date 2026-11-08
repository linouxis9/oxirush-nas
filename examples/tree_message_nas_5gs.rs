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

//! Read and edit a 5GS REGISTRATION REQUEST through its tree: each IE by its
//! name, with its value as a reader writes it, at the paths of the `paths`
//! module.

use oxirush_nas::{nas_5gs::Message, paths, tree};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initial registration with a SUCI of PLMN 208-93, a security
    // capability and a requested NSSAI.
    let bytes = hex::decode(
        "7e004179000d0102f8390000000000000010022e02e0e02f05040101020352\
         02f839000001",
    )
    .expect("hex");
    let message = Message::decode(&bytes).expect("decode failed");

    // The message to its tree, and each value with the path that selects it.
    let mut tree = message.to_tree();
    for (path, value) in paths::paths(&tree) {
        println!("{path} = {value}");
    }

    // A coded value reads by the name the specification gives it.
    let kind = "/nas/5gs-registration-type/registration-type";
    assert_eq!(
        paths::select(&tree, kind)?,
        [&tree!("initial-registration")]
    );

    // A structured IE is matched through its value, in the usual notation:
    // an identity by its parts,
    let select = |path| paths::select(&tree, path);
    let suci = select("/nas/5gs-mobile-identity/suci/imsi")?;
    assert_eq!(suci[0]["plmn"], tree!("208-93"));
    assert_eq!(suci[0]["msin"], tree!("0000000120"));

    // each entry of a list (`*`),
    let sst = select("/nas/requested-nssai/*/sst")?;
    assert_eq!(sst, [&tree!(1)]);

    // a whole value, and the algorithms of a capability.
    let tai = select("/nas/last-visited-registered-tai")?;
    assert_eq!(tai, [&tree!({"plmn": "208-93", "tac": 1})]);
    let ea = select("/nas/ue-security-capability/ea")?;
    assert_eq!(ea, [&tree!([0, 1, 2])]);

    // The same members are written, in any case.
    paths::set(&mut tree, kind, tree!("Mobility Registration Updating"))?;
    let msin = "/nas/5gs-mobile-identity/suci/imsi/msin";
    paths::set(&mut tree, msin, tree!("0000000121"))?;

    // A list loses a member of an entry, and takes an entry at its end (`-`).
    paths::remove(&mut tree, "/nas/requested-nssai/0/sd")?;
    let slice = tree!({"sst": 2, "sd": "0000ff"});
    paths::insert(&mut tree, "/nas/requested-nssai/-", slice)?;

    // A number is also written in hexadecimal.
    let tac = "/nas/Last Visited Registered TAI/tac";
    paths::set(&mut tree, tac, tree!("0x2a"))?;

    // The octets of an IE are written to say them as they are.
    let capability = "/nas/ue-security-capability";
    paths::set(&mut tree, capability, tree!({"octets": "ffff"}))?;

    // An optional IE that the message does not have selects nothing, and is
    // added by its value or its octets.
    let mico = "/nas/mico-indication";
    assert!(paths::select(&tree, mico)?.is_empty());
    paths::set(&mut tree, mico, tree!({"raai": true}))?;

    // And back to octets: each IE that changed is encoded from what was
    // written, and the others keep their octets.
    let edited = message
        .with_tree(tree.clone())
        .expect("the tree is a message");
    let edited_bytes = edited.encode().expect("encode failed");

    // The octets before and after.
    println!("\n{}\n{}", hex::encode(&bytes), hex::encode(&edited_bytes));
    assert_eq!(
        hex::encode(&edited_bytes),
        "7e00417a000d0102f8390000000000000010122e02ffff2f07010104020000\
         ff5202f83900002ab1"
    );

    // Nothing that a tree says is ignored: a name that does not exist is an
    // error.
    paths::set(&mut tree, kind, tree!("mobility"))?;
    let error = message.with_tree(tree).unwrap_err();
    println!("\n{error}");

    Ok(())
}
