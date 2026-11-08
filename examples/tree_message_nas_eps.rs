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

//! Read and edit an EPS ATTACH REQUEST through its tree: each IE by its name,
//! with its value as a reader writes it, at the paths of the `paths` module.

use oxirush_nas::{nas_eps::Message, paths, tree};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // EPS attach with an IMSI of PLMN 208-93 and a PDN CONNECTIVITY REQUEST.
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").expect("hex");
    let message = Message::decode(&bytes).expect("decode failed");

    // The message to its tree, and each value with the path that selects it.
    let mut tree = message.to_tree();
    for (path, value) in paths::paths(&tree) {
        println!("{path} = {value}");
    }

    // A coded value reads by the name the specification gives it.
    let select = |path| paths::select(&tree, path);
    assert_eq!(select("/nas/eps-attach-type")?, [&tree!("eps-attach")]);
    let key_set = select("/nas/nas-key-set-identifier")?;
    assert_eq!(key_set, [&tree!({"native": 0})]);

    // A structured IE is matched through its value, in the usual notation,
    let identity = select("/nas/eps-mobile-identity/imsi")?;
    assert_eq!(identity, [&tree!("208930000000001")]);
    let algorithms = select("/nas/ue-network-capability/eea")?;
    assert_eq!(algorithms, [&tree!([0, 1, 2])]);

    // and a container through the tree of the message it carries.
    let request = "/nas/esm-message-container";
    let kind = paths::select(&tree, &format!("{request}/message-type"))?;
    assert_eq!(kind, [&tree!("pdn-connectivity-request")]);
    let pdn_type = format!("{request}/pdn-type");
    assert_eq!(paths::select(&tree, &pdn_type)?, [&tree!("ipv4v6")]);

    // The same members are written, in any case.
    let attach_type = "/nas/EPS attach type";
    paths::set(&mut tree, attach_type, tree!("Combined EPS IMSI attach"))?;
    let imsi = "/nas/eps-mobile-identity/imsi";
    paths::set(&mut tree, imsi, tree!("208930000000002"))?;
    let eea = "/nas/ue-network-capability/eea";
    paths::set(&mut tree, eea, tree!([0]))?;
    paths::set(&mut tree, &pdn_type, tree!("ipv6"))?;

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
        "0741020829803900000000200280e000040201d021"
    );

    // Nothing that a tree says is ignored: a name that does not exist is an
    // error.
    paths::set(&mut tree, attach_type, tree!("combined"))?;
    let error = message.with_tree(tree).unwrap_err();
    println!("\n{error}");

    Ok(())
}
