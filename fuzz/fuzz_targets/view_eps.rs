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

#![no_main]
//! The JSON forms of a decoded message, whatever octets it was decoded from.
//!
//! A view that changes nothing gives the message back, a tree is one that a
//! message is written from, and the message that is written from it has the
//! same tree. The serde form is read back to the same message.

use libfuzzer_sys::fuzz_target;
use oxirush_nas::nas_eps::NasEpsMessage;

fuzz_target!(|octets: &[u8]| {
    let Ok(message) = NasEpsMessage::decode(octets) else {
        return;
    };
    let view = message.to_view();
    match message.with_view(view) {
        Ok(same) => assert_eq!(same, message),
        Err(error) => panic!("the view of a message is refused: {error}: {message:?}"),
    }

    let tree = message.to_tree();
    match NasEpsMessage::from_tree(tree.clone()) {
        Ok(written) => assert_eq!(written.to_tree(), tree, "{message:?}"),
        Err(error) => panic!("the tree of a message is refused: {error}: {tree}"),
    }

    let document = serde_json::to_value(&message).unwrap();
    let restored: NasEpsMessage = serde_json::from_value(document).unwrap();
    assert_eq!(restored, message);
});
