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

//! A message as JSON: its tree, its view, and the paths of their values.
//!
//! With the `serde` feature a message is a `serde_json::Value` in two forms,
//! which [`Nas5gsMessage`](crate::nas_5gs::Nas5gsMessage) and
//! [`NasEpsMessage`](crate::nas_eps::NasEpsMessage) have alike. A tree is
//! the compact form, in which a message is shown and written; a view edits
//! a message and keeps what it does not touch.
//!
//! | | Tree | View |
//! |---|------|------|
//! | From a message | [`to_tree()`] | [`to_view()`] |
//! | An IE is | its value, or `{"octets": "…"}` when it has no readable one | its `value` and its `octets` |
//! | It has | the `message-type` and the IEs that the message has | the fields of the header and every IE that the message can have, `null` for one that it has not |
//! | Back to a message | [`from_tree()`]: a message written from the tree alone | [`with_view()`]: this message, edited; [`from_view()`]: a message written from the view alone |
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//!
//! // 5GMM STATUS, cause #22
//! let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//!
//! // Its tree, then its view
//! println!("{}", status.to_tree());
//! println!("{:#}", status.to_view());
//! ```
//!
//! ```json
//! {"5gmm-cause":"congestion","message-type":"5gmm-status"}
//! ```
//!
//! ```json
//! {
//!   "5gmm-cause": {
//!     "octets": "16",
//!     "value": "congestion"
//!   },
//!   "extended-protocol-discriminator": {
//!     "value": 126
//!   },
//!   "message-type": {
//!     "value": "5gmm-status"
//!   },
//!   "security-header-type": {
//!     "value": "plain-nas-message"
//!   },
//!   "spare-half-octet": {
//!     "value": 0
//!   }
//! }
//! ```
//!
//! This page has a [cookbook](#cookbook) of the two forms, the
//! [paths](#paths) that the functions of this module take, the
//! [rules](#rules) of the forms, the [notation](#values) of each kind of
//! value, the [IE types that have a value](#ie-types-that-have-a-value) and
//! the [units](#units-of-the-protocol-configuration-options) of the protocol
//! configuration options.
//!
//! # Cookbook
//!
//! ## Read an IE
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//!
//! // REGISTRATION ACCEPT with a 5G-GUTI, the temporary identity that the network
//! // gives the UE, and an allowed NSSAI, the network slices that it may use
//! let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
//! let accept = Nas5gsMessage::decode(&bytes).unwrap();
//! let view = accept.to_view();
//!
//! // An IE with its value and its octets
//! println!("{:#}", view["5g-guti"]);
//!
//! // A member of a value, and of an entry of a list
//! assert_eq!(view["5g-guti"]["value"]["guti"]["plmn"], "208-93");
//! assert_eq!(view["allowed-nssai"]["value"][0]["sst"], 1);
//!
//! // An optional IE that the message does not have
//! assert!(view["t3512-value"].is_null());
//! ```
//!
//! ```json
//! {
//!   "octets": "f202f83901004211223344",
//!   "value": {
//!     "guti": {
//!       "amf-pointer": 2,
//!       "amf-region-id": 1,
//!       "amf-set-id": 1,
//!       "plmn": "208-93",
//!       "tmsi": 287454020
//!     }
//!   }
//! }
//! ```
//!
//! ## Change a value
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//! use serde_json::json;
//!
//! // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
//! let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
//! let accept = Nas5gsMessage::decode(&bytes).unwrap();
//! println!("{}", accept.to_view()["allowed-nssai"]);
//!
//! // The slice gets an SD, and the 5G-GUTI another TMSI
//! let mut view = accept.to_view();
//! view["allowed-nssai"]["value"][0]["sd"] = json!("010203");
//! view["5g-guti"]["value"]["guti"]["tmsi"] = json!("0xdeadbeef");
//! let edited = accept.with_view(view).unwrap();
//!
//! // The allowed NSSAI and the octets of the edited message
//! println!("{}", edited.to_view()["allowed-nssai"]);
//! assert_eq!(
//!     hex::encode(edited.encode().unwrap()),
//!     "7e0042010177000bf202f839010042deadbeef15050401010203"
//! );
//! ```
//!
//! ```json
//! {"octets":"0101","value":[{"mapped-sd":null,"mapped-sst":null,"sd":null,"sst":1}]}
//! {"octets":"0401010203","value":[{"mapped-sd":null,"mapped-sst":null,"sd":"010203","sst":1}]}
//! ```
//!
//! An IE whose value changed is encoded from it, and the rest of the message
//! keeps its octets.
//!
//! ## Add or remove an IE
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//! use serde_json::json;
//!
//! // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
//! let bytes = hex::decode("7e0044165f012a").unwrap();
//! let reject = Nas5gsMessage::decode(&bytes).unwrap();
//! println!("{}", reject.to_tree());
//!
//! // One optional IE comes in, another goes out
//! let mut view = reject.to_view();
//! view["t3502-value"] = json!({"value": 720}); // added by its value, or by its octets
//! view["t3346-value"] = json!(null); // taken out
//! let edited = reject.with_view(view).unwrap();
//!
//! // The tree and the octets of the edited message
//! println!("{}", edited.to_tree());
//! assert_eq!(hex::encode(edited.encode().unwrap()), "7e00441616012c");
//! ```
//!
//! ```json
//! {"5gmm-cause":"congestion","message-type":"registration-reject","t3346-value":600}
//! {"5gmm-cause":"congestion","message-type":"registration-reject","t3502-value":720}
//! ```
//!
//! A mandatory IE stays: taking `5gmm-cause` out is an error.
//!
//! ## Send octets as they are
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//! use serde_json::json;
//!
//! // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
//! let bytes = hex::decode("7e0044165f012a").unwrap();
//! let reject = Nas5gsMessage::decode(&bytes).unwrap();
//! println!("{}", reject.to_view()["t3346-value"]);
//!
//! // A T3346 value of two octets, where the specification has one
//! let mut view = reject.to_view();
//! view["t3346-value"]["octets"] = json!("2a2b");
//! let edited = reject.with_view(view).unwrap();
//!
//! // The IE and the octets of the edited message
//! println!("{}", edited.to_view()["t3346-value"]);
//! assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044165f022a2b");
//!
//! // The 5GMM cause has no length: it is one octet
//! let mut view = reject.to_view();
//! view["5gmm-cause"]["octets"] = json!("ffff");
//! println!("{}", reject.with_view(view).unwrap_err());
//! ```
//!
//! ```json
//! {"octets":"2a","value":600}
//! {"octets":"2a2b","value":600}
//! ```
//!
//! ```text
//! cannot encode: 5gmm-cause: "ffff" is not 1 octets
//! ```
//!
//! The length of the IE follows its octets. In a tree, `{"octets": "2a2b"}`
//! takes the place of the value.
//!
//! ## Write a message from its name
//!
//! ```rust
//! use oxirush_nas::nas_5gs::{Nas5gmmMessageType, Nas5gsMessage};
//! use serde_json::json;
//!
//! // A REGISTRATION REJECT by the name of its type and of its IEs
//! let reject = Nas5gsMessage::from_tree(json!({
//!     "message-type": "registration-reject",
//!     "5gmm-cause": "congestion",
//!     "t3346-value": 600,
//! }))
//! .unwrap();
//! assert_eq!(hex::encode(reject.encode().unwrap()), "7e0044165f012a");
//!
//! // A 5GSM message writes the fields of its header that its type does not decide
//! let complete = Nas5gsMessage::from_tree(json!({
//!     "message-type": "pdu-session-release-complete",
//!     "pdu-session-identity": 5,
//!     "procedure-transaction-identity": 1,
//! }))
//! .unwrap();
//! assert_eq!(hex::encode(complete.encode().unwrap()), "2e0501d4");
//!
//! // A mandatory IE that is left out is an error
//! let tree = json!({"message-type": "registration-reject"});
//! println!("{}", Nas5gsMessage::from_tree(tree).unwrap_err());
//!
//! // What a message of a type can have, in the order of the message
//! println!("{:?}", Nas5gmmMessageType::AuthenticationFailure.view_names());
//! ```
//!
//! ```text
//! cannot encode: `5gmm-cause` is not written
//! ["extended-protocol-discriminator", "security-header-type", "spare-half-octet", "message-type", "5gmm-cause", "authentication-failure-parameter"]
//! ```
//!
//! [`blank_view()`] of a message type is the view to fill: an object for each
//! entry that a view has to write, and `null` for each optional IE.
//!
//! ## The message in a container
//!
//! ```rust
//! use oxirush_nas::nas_eps::NasEpsMessage;
//! use serde_json::json;
//!
//! // ATTACH REQUEST with a PDN CONNECTIVITY REQUEST in its ESM message container
//! let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
//! let attach = NasEpsMessage::decode(&bytes).unwrap();
//! println!("{:#}", attach.to_tree()["esm-message-container"]);
//!
//! // In a view, the value of the container is the view of its message
//! let mut view = attach.to_view();
//! view["esm-message-container"]["value"]["pdn-type"]["value"] = json!("ipv6");
//! let edited = attach.with_view(view).unwrap();
//!
//! // The PDN type and the octets of the edited message
//! println!("{}", edited.to_tree()["esm-message-container"]["pdn-type"]);
//! assert_eq!(
//!     hex::encode(edited.encode().unwrap()),
//!     "07410108298039000000001002e0e000040201d021"
//! );
//! ```
//!
//! ```json
//! {
//!   "eps-bearer-identity": 0,
//!   "message-type": "pdn-connectivity-request",
//!   "pdn-type": "ipv4v6",
//!   "procedure-transaction-identity": 1,
//!   "request-type": "initial"
//! }
//! ```
//!
//! ```json
//! "ipv6"
//! ```
//!
//! ## A protected message
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//! use serde_json::json;
//!
//! // 5GMM STATUS under an integrity protected header
//! let bytes = hex::decode("7e01e73b901b007e006416").unwrap();
//! let protected = Nas5gsMessage::decode(&bytes).unwrap();
//! println!("{:#}", protected.to_tree());
//!
//! // An edit that leaves the old MAC in the security header is refused
//! let mut view = protected.to_view();
//! view["5gmm-cause"]["value"] = json!("illegal-ue");
//! println!("{}", protected.with_view(view.clone()).unwrap_err());
//!
//! // The view writes the code of the edited message
//! view["security-header"]["value"]["message-authentication-code"] = json!("0x01020304");
//! let edited = protected.with_view(view).unwrap();
//! assert_eq!(hex::encode(edited.encode().unwrap()), "7e0101020304007e006403");
//!
//! // A message that is ciphered has its octets
//! let bytes = hex::decode("7e024b708bc300026ff75c").unwrap();
//! let ciphered = Nas5gsMessage::decode(&bytes).unwrap();
//! println!("{}", ciphered.to_tree()["ciphered-message"]);
//! ```
//!
//! ```json
//! {
//!   "5gmm-cause": "congestion",
//!   "message-type": "5gmm-status",
//!   "security-header": {
//!     "extended-protocol-discriminator": 126,
//!     "message-authentication-code": 3879440411,
//!     "security-header-type": "integrity-protected",
//!     "sequence-number": 0,
//!     "spare-half-octet": 0
//!   }
//! }
//! ```
//!
//! ```text
//! cannot encode: the message authentication code of `security-header` is that of the message as it was: write the code of the edited message, or edit the plain message
//! ```
//!
//! ```json
//! {"octets":"026ff75c"}
//! ```
//!
//! A view computes no code and ciphers nothing: a
//! [security context](crate::nas_5gs::security) does.
//! `from_tree()` writes the message of a tree with a `security-header` under
//! that header, with the code that the tree has; `from_view()` writes plain
//! messages.
//!
//! ## Select by path
//!
//! [`paths`], [`select`], [`set`], [`insert`] and [`remove`] read and edit a
//! view by paths, in which `/nas` stands for the view and an IE goes by its
//! name.
//!
//! ```rust
//! use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
//! use serde_json::json;
//!
//! // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
//! let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
//! let accept = Nas5gsMessage::decode(&bytes).unwrap();
//! let tree = accept.to_view();
//!
//! // Each value with the path that selects it
//! for (path, value) in view::paths(&tree) {
//!     println!("{path} = {value}");
//! }
//!
//! // A coded value by its name, an identity by its parts, and the octets beside
//! let select = |path| view::select(&tree, path).unwrap();
//! assert_eq!(select("/nas/message-type/value"), [&json!("registration-accept")]);
//! assert_eq!(select("/nas/5gs-registration-result/value/result"), [&json!("3gpp-access")]);
//! assert_eq!(select("/nas/5g-guti/value/guti/tmsi"), [&json!(0x1122_3344)]);
//! assert_eq!(select("/nas/allowed-nssai/octets"), [&json!("0101")]);
//!
//! // A name in any case, and `*` for each entry of a list
//! assert_eq!(select("/NAS/Allowed NSSAI/value/*/SST"), [&json!(1)]);
//!
//! // An optional IE that the message does not have selects nothing
//! assert!(select("/nas/t3512-value/value").is_empty());
//!
//! // A name that the message does not have is an error
//! assert!(view::select(&tree, "/nas/t3512/value").is_err());
//! ```
//!
//! ```text
//! /nas/5g-guti/octets = "f202f83901004211223344"
//! /nas/5g-guti/value/guti/amf-pointer = 2
//! /nas/5g-guti/value/guti/amf-region-id = 1
//! /nas/5g-guti/value/guti/amf-set-id = 1
//! /nas/5g-guti/value/guti/plmn = "208-93"
//! /nas/5g-guti/value/guti/tmsi = 287454020
//! /nas/5gs-registration-result/octets = "01"
//! /nas/5gs-registration-result/value/disaster-roaming = false
//! /nas/5gs-registration-result/value/emergency-registered = false
//! /nas/5gs-registration-result/value/nssaa-performed = false
//! /nas/5gs-registration-result/value/result = "3gpp-access"
//! /nas/5gs-registration-result/value/sms-allowed = false
//! /nas/allowed-nssai/octets = "0101"
//! /nas/allowed-nssai/value/0/sst = 1
//! /nas/extended-protocol-discriminator/value = 126
//! /nas/message-type/value = "registration-accept"
//! /nas/security-header-type/value = "plain-nas-message"
//! /nas/spare-half-octet/value = 0
//! ```
//!
//! The message in a container is under the `value` of the container, as in
//! `/nas/esm-message-container/value/pdn-type/value`.
//!
//! ## Edit by path
//!
//! [`set`], [`insert`] and [`remove`] write at the same paths, and
//! [`with_view()`] gives the message of the edited view.
//!
//! ```rust
//! use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
//! use serde_json::json;
//!
//! // The same REGISTRATION ACCEPT
//! let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
//! let accept = Nas5gsMessage::decode(&bytes).unwrap();
//!
//! // A value is set at its path
//! let mut tree = accept.to_view();
//! view::set(&mut tree, "/nas/5g-guti/value/guti/tmsi", json!("0xdeadbeef")).unwrap();
//! view::set(&mut tree, "/nas/allowed-nssai/value/0/sd", json!("010203")).unwrap();
//!
//! // An optional IE that the message does not have is added by its value
//! view::set(&mut tree, "/nas/t3512-value/value", json!(3600)).unwrap();
//!
//! // The message of the edited view
//! let edited = accept.with_view(tree).unwrap();
//! assert_eq!(
//!     hex::encode(edited.encode().unwrap()),
//!     "7e0042010177000bf202f839010042deadbeef150504010102035e0106"
//! );
//!
//! // A list takes an entry before a position or at its end (`-`), and loses one
//! let mut tree = accept.to_view();
//! let slice = json!({"sst": 2, "sd": "0000ff"});
//! view::insert(&mut tree, "/nas/allowed-nssai/value/-", slice).unwrap();
//! view::remove(&mut tree, "/nas/allowed-nssai/value/0").unwrap();
//!
//! let edited = accept.with_view(tree).unwrap();
//! assert_eq!(edited.to_view()["allowed-nssai"]["octets"], "04020000ff");
//! ```
//!
//! ## The serde form
//!
//! `Serialize` and `Deserialize` give a message with the fields of the codec. A
//! document re-encodes to the octets that were decoded, unknown IEs included.
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Nas5gsMessage;
//!
//! // 5GMM STATUS, cause #22, as a document
//! let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//! let document = serde_json::to_value(&status).unwrap();
//! println!("{document}");
//!
//! // The document back to a message, and to its octets
//! let restored: Nas5gsMessage = serde_json::from_value(document).unwrap();
//! assert_eq!(restored.encode().unwrap(), [0x7e, 0x00, 0x64, 0x16]);
//! ```
//!
//! ```json
//! {"Gmm":[{"extended_protocol_discriminator":126,"message_type":"FGmmStatus","security_header_type":"PlainNasMessage","spare_half_octet":0},{"FGmmStatus":{"fgmm_cause":{"value":22},"optional_ie_order":[],"unknown_ies":[]}}]}
//! ```
//!
//! # Paths
//!
//! [`paths`] gives each value of a view with the path that selects it,
//! [`select`] the values at a path, and [`set`], [`remove`] and [`insert`]
//! edit a view at a path. `/nas` stands for the view, and the segment
//! after it is the name of an IE or of a field of the header:
//!
//! ```text
//! /nas/message-type/value = "registration-accept"
//! /nas/5g-guti/octets = "f202f839cafe0011223344"
//! /nas/5g-guti/value/guti/plmn = "208-93"
//! /nas/allowed-nssai/value/0/sst = 1
//! ```
//!
//! A path is a JSON pointer. A name is its letters and its digits, whatever
//! their case and whatever is between them, as a view takes it: `/nas/5GMM
//! cause/value` and `/NAS/5gmm_cause/Value` are one path. A list selects by
//! position, a number as decimal writes it, and `*` is each entry of a list
//! or each member of a value. The message in a container is under the
//! `value` of the container, with the names of its own IEs.
//!
//! What is not there selects nothing: an optional IE that the message does
//! not have, which a view has as `null`, anything under it, and an optional
//! member that a value has as `null`. [`paths`] lists none of them. A name
//! that a view or a value does not have is an error, so a name that is
//! written wrong is not taken for an IE that is absent.
//!
//! ```
//! use oxirush_nas::{Nas5gsMessage, view};
//! use serde_json::json;
//!
//! // 5GMM STATUS, cause #22 "congestion".
//! let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//! let mut tree = status.to_view();
//! assert_eq!(view::select(&tree, "/nas/5gmm-cause/value")?, [&json!("congestion")]);
//!
//! view::set(&mut tree, "/nas/5gmm-cause/value", json!("illegal-ue"))?;
//! let edited = status.with_view(tree).unwrap();
//! assert_eq!(edited.encode().unwrap(), [0x7e, 0x00, 0x64, 0x03]);
//! # Ok::<(), String>(())
//! ```
//!
//! # Rules
//!
//! These are the rules of the two JSON forms of a message, its view and its
//! tree, which [`to_view()`](crate::nas_5gs::Nas5gsMessage::to_view),
//! [`with_view()`](crate::nas_5gs::Nas5gsMessage::with_view),
//! [`from_view()`](crate::nas_5gs::Nas5gsMessage::from_view),
//! [`to_tree()`](crate::nas_5gs::Nas5gsMessage::to_tree) and
//! [`from_tree()`](crate::nas_5gs::Nas5gsMessage::from_tree) read and write;
//! [`NasEpsMessage`](crate::nas_eps::NasEpsMessage) has the same methods.
//!
//! | Subject | Rule |
//! |---------|------|
//! | Names | The name that the specification gives an IE, in lower case with hyphens; `fg` of the codec reads `5g`, as in `5gs-registration-result`. A name is read by its letters and its digits, whatever their case and whatever is between them: `5GMM cause` and `5gmm_cause` are `5gmm-cause`. |
//! | `value` | What the IE means, in the notation of [Values](#values). A code is its name or its number. A number is also read as a `"0x…"` string, except in `message-type` and `security-header-type`, where a string is a name. |
//! | `octets` | The value part of the IE in hexadecimal. Octets that are written are sent whatever they are, and the length of the IE follows them. |
//! | Header | Each field is an entry with a `value` alone. A tree leaves out what its `message-type` decides: the protocol discriminator, and in a 5GMM message a plain security header type and a spare half octet of zero. A view that is written alone may leave out the `spare-half-octet`, which is then zero. |
//! | An IE that is not there | `null` in a view, left out of a tree. It selects nothing, and [`paths`] does not list it. |
//! | Unknown IEs | In neither form. `with_view()` keeps them; a message written alone has none. |
//! | Order | `serde_json` sorts the members of an object by name; with its `preserve_order` feature they are in the order of the message, header first. `view_names()` has that order either way. |
//! | Errors | Nothing that is written is ignored. These are errors: a name that the message or a value does not have; a value that its IE cannot carry, or that the crate reads and does not encode; a `value` and `octets` that were both changed and disagree; a mandatory IE that is taken out or not written; octets of a length that the message does not give the IE; a `message-type` that the IEs are not those of; an edit under a `security-header` that keeps its code. |
//! | Not checked | The rules of a sender: `validate()` has them. |
//! | Octets after `with_view()` | Only what was edited changes, and a view that changes nothing gives the message back. |
//! | Octets after a tree | The message means the same and may have other octets: where a value does not decide its coding (the unit of a timer or of a bit rate, the length of a capability, the type of a partial tracking area identity list), where an IE had more octets than its value, and without the unknown IEs. The `octets` of an IE are the way to choose them. |
//! | EPS SERVICE REQUEST | A short header, no IEs and no `message-type` (TS 24.301 §8.2.25). Its view has the fields of that header: `protocol-discriminator`, `security-header-type`, `ksi-and-sequence-number`, whose value is a `ksi` and a `sequence-number`, and the two `octets` of `message-authentication-code`. [`NasServiceRequest::from_view()`](crate::nas_eps::NasServiceRequest::from_view) writes one alone. |
//!
//! # Values
//!
//! | What | Notation |
//! |------|----------|
//! | coded value (cause, type, mode, result, algorithm) | its name, `"congestion"`, `"initial-registration"`, `"nea2"`; its number where the specification names none, and for a reserved code that a receiver takes as another |
//! | PLMN identity | `"208-93"`, `"310-410"` |
//! | IMSI, IMEI, IMEISV, MSIN, routing indicator | a string of digits |
//! | TMSI, TAC, LAC, AMF region, set and pointer, SST, QFI, PDU session and bearer identities | a number |
//! | timer | its seconds, or `"deactivated"` |
//! | DNN, APN, network name | text |
//! | IP address | text, `"10.0.0.1"`, `"fe80::1"` |
//! | flags of a capability or an indication | `true` or `false` by the name of the flag |
//! | container of a NAS message | the view of that message, or its tree in a tree |
//! | protocol configuration options | the list of their [units](#units-of-the-protocol-configuration-options) |
//! | SD, MAC address, EUI-64, key, interface identifier, raw contents | hexadecimal |
//!
//! # IE types that have a value
//!
//! | | 5GS | EPS |
//! |---|-----|-----|
//! | IE types | 169 | 153 |
//! | with a `value` | 156 | 134 |
//! | of which read only | 3 | 2 |
//! | with `octets` alone | 13 | 19 |
//!
//! A value that is read only is one that the crate parses and has no
//! constructor of: the PDU session reactivation result error cause and the
//! SOR transparent container of 5GS, the calling party number of EPS, and
//! the extended emergency number list of both. Their octets are written,
//! and a tree shows them by their octets.
//!
//! The 32 types with octets alone:
//!
//! | Kind | Types |
//! |------|-------|
//! | Octet strings | RAND, AUTN, AUTS, RES, ABBA, nonces, HashMME |
//! | Payloads of other protocols and of upper layers | EAP message, SMS, LPP and user data containers, ATSSS and port management containers, additional information |
//! | Getters and no constructor in the crate, or neither | ECS address, classmark 3, the A/Gb and Iu mode QoS, LCS client identity, UE coarse location information |
//! | Typed accessors and constructors that a view does not use | non-3GPP device information, whose constructor takes the type of the PDU session; negotiated LLC SAPI |
//! | No content | spare half octet |
//! | No NAS message has them as an IE | the two N1 mode NAS transparent containers |
//!
//! # Units of the protocol configuration options
//!
//! The value of the protocol configuration options and of the extended
//! protocol configuration options is the list of their units, in their
//! order (TS 24.008 §10.5.6.3). An identifier means one thing in a message
//! of the UE and another in a message of the network, so a unit is read by
//! the type of its message, and a name of the other direction is refused.
//! A unit that has a name is written by it, and not as a `container`.
//!
//! | Identifier | In a message of the UE | In a message of the network |
//! |------------|------------------------|-----------------------------|
//! | C021H, C023H, C223H, 8021H | `{"lcp": "01010004"}`, `{"pap": …}`, `{"chap": …}`, `{"ipcp": …}`: the packet of the configuration protocol in hexadecimal | the same |
//! | 0001H | `"p-cscf-ipv6-address-request"` | `{"p-cscf-ipv6-address": "2001:db8::1"}` |
//! | 0002H | `"im-cn-subsystem-signalling-flag"` | the same |
//! | 0003H | `"dns-server-ipv6-address-request"` | `{"dns-server-ipv6-address": "2001:db8::53"}` |
//! | 0005H | `"ms-support-of-network-requested-bearer-control"` | `{"selected-bearer-control-mode": "ms-only"}`, or `"ms-nw"` |
//! | 000AH | `"ip-address-allocation-via-nas-signalling"` | |
//! | 000BH | `"ipv4-address-allocation-via-dhcpv4"` | |
//! | 000CH | `"p-cscf-ipv4-address-request"` | `{"p-cscf-ipv4-address": "10.0.0.2"}` |
//! | 000DH | `"dns-server-ipv4-address-request"` | `{"dns-server-ipv4-address": "8.8.8.8"}` |
//! | 000EH | `"msisdn-request"` | |
//! | 0010H | `"ipv4-link-mtu-request"` | `{"ipv4-link-mtu": 1400}` |
//! | 0011H | `"ms-support-of-local-address-in-tft"` | `"network-support-of-local-address-in-tft"` |
//! | 0012H | `"p-cscf-reselection-support"` | |
//! | 0015H | `"non-ip-link-mtu-request"` | `{"non-ip-link-mtu": 1358}` |
//! | any other | `{"container": {"identifier": 65280, "contents": "01"}}`: the number of the identifier and the contents in hexadecimal | the same |
//!
//! The options have a value where the units give their octets back: not
//! with a spare bit of the first octet set, not with a configuration
//! protocol other than PPP, and not with a unit that the specification
//! lets a receiver ignore (an address of another length). Those have their
//! `octets`, which are written as they are.
//!
//! [`to_tree()`]: crate::nas_5gs::Nas5gsMessage::to_tree
//! [`from_tree()`]: crate::nas_5gs::Nas5gsMessage::from_tree
//! [`to_view()`]: crate::nas_5gs::Nas5gsMessage::to_view
//! [`with_view()`]: crate::nas_5gs::Nas5gsMessage::with_view
//! [`from_view()`]: crate::nas_5gs::Nas5gsMessage::from_view
//! [`blank_view()`]: crate::nas_5gs::Nas5gmmMessageType::blank_view

use crate::common::readable::{named, same_name};
use serde_json::{Map, Value};

/// The first segment of a path.
const ROOT: &str = "nas";
/// The most occurrences that a path selects.
const OCCURRENCES: usize = 4096;

/// The segments of a path after its root: those of a JSON pointer.
fn segments(path: &str) -> Result<Vec<String>, String> {
    if path.len() > 4096 || !path.starts_with('/') {
        return Err("IE path must start with / and be at most 4096 bytes".into());
    }
    let mut parts = path[1..]
        .split('/')
        .map(|part| {
            let mut decoded = String::new();
            let mut chars = part.chars();
            while let Some(c) = chars.next() {
                decoded.push(if c == '~' {
                    match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err("invalid JSON-pointer escape".into()),
                    }
                } else {
                    c
                });
            }
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, String>>()?;
    if parts.len() > 64 {
        return Err("IE path nesting exceeds 64".into());
    }
    if !same_name(&parts.remove(0), ROOT) {
        return Err(format!(
            "{path} is not a path of a view: it starts with /{ROOT}"
        ));
    }
    Ok(parts)
}

/// The position that a segment is: a number as decimal writes it, without a
/// sign and without a zero before it.
fn position(part: &str) -> Option<usize> {
    let plain = !part.is_empty()
        && part.bytes().all(|digit| digit.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'));
    part.parse().ok().filter(|_| plain)
}

/// The name that `members` has for `name`, however it is written.
fn key<'a>(members: &'a Map<String, Value>, name: &str) -> Option<&'a String> {
    let names: Vec<_> = members.keys().collect();
    named(&names, name).copied()
}

/// The values at `path` in `view`, in the order of the view. An IE that the
/// message does not have and an optional member that a value does not have
/// select nothing, whether the path ends at them or goes on; a name that the
/// view or a value does not have is an error.
pub fn select<'a>(view: &'a Value, path: &str) -> Result<Vec<&'a Value>, String> {
    let mut selected = vec![view];
    for part in segments(path)? {
        let mut next = Vec::new();
        for value in selected {
            match value {
                Value::Null => {}
                Value::Array(entries) if part == "*" => next.extend(entries),
                Value::Object(members) if part == "*" => next.extend(members.values()),
                Value::Object(members) => match key(members, &part) {
                    Some(name) => next.push(&members[name]),
                    None => {
                        return Err(format!(
                            "unknown or unavailable decoded field {part:?} at {path}"
                        ));
                    }
                },
                Value::Array(entries) => {
                    let index = position(&part)
                        .ok_or_else(|| format!("array index must be numeric at {path}"))?;
                    next.extend(entries.get(index));
                }
                _ if part == "*" => {
                    return Err(format!("wildcard cannot traverse a scalar at {path}"));
                }
                _ => return Err(format!("decoded path traverses a scalar at {path}")),
            }
            if next.len() > OCCURRENCES {
                return Err(format!("IE selection exceeds {OCCURRENCES} occurrences"));
            }
        }
        selected = next;
    }
    selected.retain(|value| !value.is_null());
    Ok(selected)
}

/// Each value of `view` with the path that selects it, in the order of the
/// view. A list of plain values is one value, and an IE that the message
/// does not have has no path.
pub fn paths(view: &Value) -> Vec<(String, Value)> {
    let mut found = Vec::new();
    walk(view, &mut format!("/{ROOT}"), &mut found);
    found
}

fn walk(value: &Value, path: &mut String, found: &mut Vec<(String, Value)>) {
    let step = |segment: &str, child: &Value, path: &mut String, found: &mut _| {
        let length = path.len();
        path.push('/');
        path.push_str(&segment.replace('~', "~0").replace('/', "~1"));
        walk(child, path, found);
        path.truncate(length);
    };
    match value {
        Value::Object(members) if !members.is_empty() => {
            for (name, member) in members.iter().filter(|(_, member)| !member.is_null()) {
                step(name, member, path, found);
            }
        }
        Value::Array(entries) if entries.iter().any(|e| e.is_object() || e.is_array()) => {
            for (index, entry) in entries.iter().enumerate() {
                step(&index.to_string(), entry, path, found);
            }
        }
        plain => found.push((path.clone(), plain.clone())),
    }
}

/// What an edit does at its path.
enum Edit {
    Set(Value),
    Remove,
    Insert(Value),
}

/// Give the IE, the member or the list entry at `path` the value `value`.
/// An optional IE that the message does not have is added by its `value`
/// or its `octets`, and `null` takes an optional IE or member out.
///
/// A path that selects nothing is an error, and the view is then as it
/// was. So is the name of an IE that the message cannot have, in a view
/// whose `message-type` names the message; in a view that does not say what
/// it is of, `with_view` or `from_view` refuses the name.
pub fn set(view: &mut Value, path: &str, value: Value) -> Result<(), String> {
    edit(view, path, Edit::Set(value))
}

/// Take the IE, the member or the list entries at `path` out of `view`. An
/// optional IE that is taken out is `null`, as one that the message does
/// not have. A path that selects nothing is an error.
pub fn remove(view: &mut Value, path: &str) -> Result<(), String> {
    edit(view, path, Edit::Remove)
}

/// Add `value` to a list of `view`: before each entry that `path` selects,
/// or at the end for a path that ends with `-`.
pub fn insert(view: &mut Value, path: &str, value: Value) -> Result<(), String> {
    edit(view, path, Edit::Insert(value))
}

fn edit(view: &mut Value, path: &str, operation: Edit) -> Result<(), String> {
    let parts = segments(path)?;
    let (last, ie) = parts.split_last().ok_or("empty edit path")?;
    let of_an_ie = ["value", "octets"].iter().any(|name| same_name(name, last));
    let removes = matches!(&operation, Edit::Remove | Edit::Set(Value::Null));
    if removes && of_an_ie {
        return Err("an IE is removed, not its value or its octets".into());
    }
    let nothing = || format!("IE edit selected no field: {path}");
    if let Some(name) = parts.first() {
        known(view, name)?;
    }
    let mut edited = view.clone();
    // An IE that the message does not have becomes an entry when its value
    // or its octets are set, and is no IE to take out.
    if of_an_ie && let Some(absent @ Value::Null) = at(&mut edited, ie) {
        *absent = Map::new().into();
    }
    if removes && matches!(at(&mut edited, &parts), Some(Value::Null)) {
        return Err(nothing());
    }
    // The view keeps the name of an IE that is taken out.
    let operation = match operation {
        Edit::Remove if ie.is_empty() => Edit::Set(Value::Null),
        operation => operation,
    };
    if apply(&mut edited, &parts, &operation)? == 0 {
        return Err(nothing());
    }
    *view = edited;
    Ok(())
}

/// Whether `view` can have the entry `name`: it has it, it does not say what
/// message it is of, or a message of the type that it names has that IE.
fn known(view: &Value, name: &str) -> Result<(), String> {
    use crate::common::view::names;
    use crate::{nas_5gs, nas_eps};
    let Some(members) = view.as_object() else {
        return Ok(());
    };
    let kind = key(members, "message-type")
        .and_then(|entry| members[entry].get("value")?.as_str())
        .filter(|_| key(members, name).is_none());
    let Some(kind) = kind else {
        return Ok(());
    };
    // The protocols have types of the same name, with other IEs.
    let of_the_type = [
        names::<nas_5gs::messages::Nas5gmmHeader, nas_5gs::Nas5gmmMessage>(&[kind]),
        names::<nas_5gs::messages::Nas5gsmHeader, nas_5gs::Nas5gsmMessage>(&[kind]),
        names::<nas_eps::messages::NasEmmHeader, nas_eps::NasEmmMessage>(&[kind]),
        names::<nas_eps::messages::NasEsmHeader, nas_eps::NasEsmMessage>(&[kind]),
    ]
    .concat();
    if of_the_type.is_empty() || named(&of_the_type, name).is_some() {
        return Ok(());
    }
    Err(format!("`{name}` is no IE of a message `{kind}`"))
}

/// The one value at `parts` under `value`, if the names and the positions
/// of `parts` lead to one.
fn at<'a>(value: &'a mut Value, parts: &[String]) -> Option<&'a mut Value> {
    let Some((part, rest)) = parts.split_first() else {
        return Some(value);
    };
    let child = match value {
        Value::Object(members) => {
            let name = key(members, part)?.clone();
            members.get_mut(&name)?
        }
        Value::Array(entries) => entries.get_mut(position(part)?)?,
        _ => return None,
    };
    at(child, rest)
}

/// Apply `operation` at `parts` under `value`; the number of places that it
/// changed.
fn apply(value: &mut Value, parts: &[String], operation: &Edit) -> Result<usize, String> {
    let (part, rest) = parts.split_first().ok_or("empty edit path")?;
    if let Some(members) = value.as_object_mut() {
        if part == "*" {
            return Err("array selection used on an object".into());
        }
        let name = key(members, part).cloned();
        if rest.is_empty() {
            return match (operation, name) {
                // Null removes a member: one that is not there is not selected.
                (Edit::Set(Value::Null), None) => Ok(0),
                (Edit::Set(value), name) => {
                    members.insert(name.unwrap_or_else(|| part.clone()), value.clone());
                    Ok(1)
                }
                (Edit::Remove, name) => Ok(usize::from(
                    name.is_some_and(|name| members.remove(&name).is_some()),
                )),
                (Edit::Insert(_), _) => Err("insert adds to a list".into()),
            };
        }
        let child = name.and_then(|name| members.get_mut(&name));
        return child.map_or(Ok(0), |child| apply(child, rest, operation));
    }
    let Some(entries) = value.as_array_mut() else {
        return Ok(0);
    };
    if let (Edit::Insert(value), "-", []) = (operation, part.as_str(), rest) {
        entries.push(value.clone());
        return Ok(1);
    }
    let indexes: Vec<_> = match part.as_str() {
        "*" => (0..entries.len()).collect(),
        part => vec![position(part).ok_or("array index must be numeric")?],
    };
    if indexes.len() > OCCURRENCES {
        return Err(format!(
            "IE edit selects more than {OCCURRENCES} occurrences"
        ));
    }
    let mut changed = 0;
    for index in indexes.into_iter().rev() {
        if index >= entries.len() {
            continue;
        }
        if rest.is_empty() {
            match operation {
                Edit::Set(value) => entries[index] = value.clone(),
                Edit::Remove => {
                    entries.remove(index);
                }
                Edit::Insert(value) => entries.insert(index, value.clone()),
            }
            changed += 1;
        } else {
            changed += apply(&mut entries[index], rest, operation)?;
        }
    }
    Ok(changed)
}
