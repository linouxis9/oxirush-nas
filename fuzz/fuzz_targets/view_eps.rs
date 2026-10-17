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
//! A view that changes nothing gives the message back. A tree is one that a
//! message is written from, the message that is written from it has the
//! same tree, and it means what the message means: two messages may have
//! one tree and not mean the same, where a tree does not show all that the
//! octets say, so the two are compared below their trees, IE by IE. The
//! serde form is the tree, and is read back to a message that means the
//! same.

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
        Ok(written) => {
            assert_eq!(written.to_tree(), tree, "{message:?}");
            assert!(
                written.means_the_same(&message),
                "the tree {tree} of {message:?} writes {written:?}"
            );
            // What means the same is read as the same by a receiver
            if let Ok(octets) = written.encode() {
                let read = NasEpsMessage::decode(&octets);
                assert!(
                    read.is_ok_and(|read| read.means_the_same(&message)),
                    "{tree}"
                );
            }
        }
        Err(error) => panic!("the tree of a message is refused: {error}: {tree}"),
    }

    let document = serde_json::to_value(&message).unwrap();
    assert_eq!(document, tree);
    let restored: NasEpsMessage = serde_json::from_value(document).unwrap();
    assert!(restored.means_the_same(&message));
});
