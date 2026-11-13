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

//! A message as JSON: its tree, and the paths of its values.
//!
//! With the `tree` feature a message is a [`tree::Value`]:
//! [`to_tree()`] shows it, [`from_tree()`] writes a message from a tree alone,
//! and [`with_tree()`] edits a message, keeping the octets of every IE that
//! the edit leaves as it was. [`Message`](crate::nas_eps::Message) has the same
//! methods. Its `Serialize` and `Deserialize` are those of the tree.
//!
//! The tree has every value of the message, its keys included, so that it
//! gives the message back: RES and RES\*, the ciphering keys of positioning,
//! an MSK and K_NR_ProSe. It is no form for a log, which is what `Display` is;
//! neither it nor `Debug` prints a key.
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Message;
//!
//! // 5GMM STATUS, cause #22
//! let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
//! println!("{}", status.to_tree());
//! ```
//!
//! ```text
//! {"message-type":"5gmm-status","5gmm-cause":"congestion"}
//! ```
//!
//! The [README](https://github.com/linouxis9/oxirush-nas#a-message-as-json)
//! edits a message as JSON and by path, and serializes it. This page has
//! [examples](#examples) of the other tasks, the [paths](#paths) that the
//! functions of this module take, the [rules](#rules) of the tree, the
//! [notation](#values) of each kind of value, the
//! [IE types that have a value](#ie-types-that-have-a-value) and the
//! [units](#units-of-the-protocol-configuration-options) of the protocol
//! configuration options.
//!
//! # Examples
//!
//! ## Send octets as they are
//!
//! `{"octets": "2a2b"}` takes the place of the value of an IE, and the length
//! of the IE follows its octets.
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Message;
//! use oxirush_nas::tree;
//!
//! // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
//! let bytes = hex::decode("7e0044165f012a").unwrap();
//! let reject = Message::decode(&bytes).unwrap();
//!
//! // A T3346 value of two octets, where the specification has one
//! let mut tree = reject.to_tree();
//! tree["t3346-value"] = tree!({"octets": "2a2b"});
//! let edited = reject.with_tree(tree).unwrap();
//! assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044165f022a2b");
//!
//! // The 5GMM cause has no length: it is one octet
//! let mut tree = reject.to_tree();
//! tree["5gmm-cause"] = tree!({"octets": "ffff"});
//! println!("{}", reject.with_tree(tree).unwrap_err());
//! ```
//!
//! ```text
//! cannot encode: 5gmm-cause: "ffff" is not one octet
//! ```
//!
//! ## Write a message from its name
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Message;
//! use oxirush_nas::tree;
//!
//! // A REGISTRATION REJECT by the name of its type and of its IEs
//! let reject = Message::from_tree(tree!({
//!     "message-type": "registration-reject",
//!     "5gmm-cause": "congestion",
//!     "t3346-value": 600,
//! }))
//! .unwrap();
//! assert_eq!(hex::encode(reject.encode().unwrap()), "7e0044165f012a");
//!
//! // A 5GSM message writes the fields of its header that its type does not decide
//! let complete = Message::from_tree(tree!({
//!     "message-type": "pdu-session-release-complete",
//!     "pdu-session-identity": 5,
//!     "procedure-transaction-identity": 1,
//! }))
//! .unwrap();
//! assert_eq!(hex::encode(complete.encode().unwrap()), "2e0501d4");
//!
//! // A mandatory IE that is left out is an error
//! let tree = tree!({"message-type": "registration-reject"});
//! println!("{}", Message::from_tree(tree).unwrap_err());
//!
//! // A value that its IE cannot carry says the member and the limit
//! let tree = tree!({"message-type": "service-accept", "pdu-session-status": [5, 16]});
//! println!("{}", Message::from_tree(tree).unwrap_err());
//! ```
//!
//! ```text
//! cannot encode: `5gmm-cause` is not written
//! cannot encode: pdu-session-status: entry 1: `pdu-session-identity` is 16, and must be 1 to 15
//! ```
//!
//! ## The message in a container
//!
//! ```rust
//! use oxirush_nas::nas_eps::Message;
//! use oxirush_nas::tree;
//!
//! // ATTACH REQUEST with a PDN CONNECTIVITY REQUEST in its ESM message container
//! let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
//! let attach = Message::decode(&bytes).unwrap();
//! println!("{:#}", attach.to_tree()["esm-message-container"]);
//!
//! // The value of the container is the tree of its message
//! let mut tree = attach.to_tree();
//! tree["esm-message-container"]["pdn-type"] = tree!("ipv6");
//! let edited = attach.with_tree(tree).unwrap();
//! assert_eq!(
//!     hex::encode(edited.encode().unwrap()),
//!     "07410108298039000000001002e0e000040201d021"
//! );
//! ```
//!
//! ```text
//! {
//!   "eps-bearer-identity": 0,
//!   "procedure-transaction-identity": 1,
//!   "message-type": "pdn-connectivity-request",
//!   "request-type": "initial",
//!   "pdn-type": "ipv4v6"
//! }
//! ```
//!
//! ## One IE alone
//!
//! An IE type is a [`tree::Tree`]: `to_tree()` gives the tree of one IE
//! outside a message, which is the one that the tree of a message shows of it,
//! and [`tree::from_value`] the IE that a tree writes, or `{"octets": "…"}`.
//! The octets of an IE are its value, without an IEI or a length, as an NGAP
//! or S1AP IE carries a NAS IE.
//!
//! ```rust
//! use oxirush_nas::nas_5gs::{MessageContainer, S1ModeToN1ModeNasTransparentContainer};
//! use oxirush_nas::tree;
//! use oxirush_nas::tree::Tree;
//!
//! // The NASC of an NGAP HANDOVER REQUEST from EPS
//! let octets = hex::decode("0102030422290000").unwrap();
//! let nasc = S1ModeToN1ModeNasTransparentContainer::new(octets);
//! println!("{}", nasc.to_tree());
//!
//! // The container that its tree writes, with another NCC
//! let mut fields = nasc.to_tree();
//! fields["ncc"] = tree!(3);
//! let written: S1ModeToN1ModeNasTransparentContainer = tree::from_value(&fields).unwrap();
//! println!("{}", hex::encode(&written.value));
//!
//! // A container of a message is the tree of its message
//! let container = MessageContainer::new(vec![0x7e, 0x00, 0x64, 0x16]);
//! println!("{}", container.to_tree());
//! ```
//!
//! ```text
//! {"message-authentication-code":16909060,"selected-nas-security-algorithms":{"ciphering":"nea2","integrity":"nia2"},"ncc":2,"ngksi":{"mapped":1}}
//! 0102030422390000
//! {"message-type":"5gmm-status","5gmm-cause":"congestion"}
//! ```
//!
//! ## The protocol configuration options
//!
//! The value is the list of units. A unit is named by what it is in the
//! message that has it: a request from a UE, an answer from the network
//! ([the names](#units-of-the-protocol-configuration-options)).
//!
//! ```rust
//! use oxirush_nas::nas_eps::Message;
//! use oxirush_nas::tree;
//!
//! // PDN CONNECTIVITY REQUEST with a request for the address of a DNS
//! // server, and the packet of PAP with its credentials in a container
//! let request = Message::from_tree(tree!({
//!     "message-type": "pdn-connectivity-request",
//!     "eps-bearer-identity": 0,
//!     "procedure-transaction-identity": 1,
//!     "pdn-type": "ipv4",
//!     "request-type": "initial",
//!     "protocol-configuration-options": [
//!         {"container": {"identifier": 0xc023, "contents": "01010010047573657206736563726574"}},
//!         "dns-server-ipv4-address-request",
//!     ],
//! }))
//! .unwrap();
//! assert_eq!(
//!     hex::encode(request.encode().unwrap()),
//!     "0201d011271780c0231001010010047573657206736563726574000d00"
//! );
//!
//! // The network answers in an ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST
//! let bytes = hex::decode(
//!     "5201c101090908696e7465726e657405010a000001271080c023050201000500000d0408080808"
//! ).unwrap();
//! let answer = Message::decode(&bytes).unwrap();
//! println!("{:#}", answer.to_tree()["protocol-configuration-options"]);
//! ```
//!
//! ```text
//! [
//!   {
//!     "container": {
//!       "identifier": 49187,
//!       "contents": "0201000500"
//!     }
//!   },
//!   {
//!     "dns-server-ipv4-address": "8.8.8.8"
//!   }
//! ]
//! ```
//!
//! ## Edit a list
//!
//! ```rust
//! use oxirush_nas::{nas_5gs::Message, paths, tree};
//!
//! // REGISTRATION ACCEPT with an extended emergency number list: 112
//! let bytes = hex::decode("7e004201017a0005000211f200").unwrap();
//! let accept = Message::decode(&bytes).unwrap();
//! let mut tree = accept.to_tree();
//! println!("{}", tree["extended-emergency-number-list"]);
//!
//! // A number of the police is added at the end of the list
//! let police = tree!({"digits": "17", "sub-services": "police"});
//! let numbers = "/nas/extended-emergency-number-list/numbers/-";
//! paths::insert(&mut tree, numbers, police).unwrap();
//! let edited = accept.with_tree(tree).unwrap();
//! assert_eq!(
//!     hex::encode(edited.encode().unwrap()),
//!     "7e004201017a000e000211f200017106f0373b3d2e03"
//! );
//! ```
//!
//! ```text
//! {"valid-only-in-plmn":false,"numbers":[{"digits":"112","sub-services":""}]}
//! ```
//!
//! ## A protected message
//!
//! A tree computes no MAC and ciphers nothing: a
//! [security context](crate::nas_5gs::SecurityContext) does.
//!
//! ```rust
//! use oxirush_nas::nas_5gs::Message;
//! use oxirush_nas::tree;
//!
//! // 5GMM STATUS under an integrity protected header
//! let bytes = hex::decode("7e01e73b901b007e006416").unwrap();
//! let protected = Message::decode(&bytes).unwrap();
//! println!("{:#}", protected.to_tree());
//!
//! // An edit that leaves the old MAC in the security header is refused
//! let mut tree = protected.to_tree();
//! tree["5gmm-cause"] = tree!("illegal-ue");
//! println!("{}", protected.with_tree(tree.clone()).unwrap_err());
//!
//! // The tree writes the code of the edited message
//! tree["security-header"]["message-authentication-code"] = tree!("0x01020304");
//! let edited = protected.with_tree(tree).unwrap();
//! assert_eq!(hex::encode(edited.encode().unwrap()), "7e0101020304007e006403");
//!
//! // A message that is ciphered has its octets
//! let bytes = hex::decode("7e024b708bc300026ff75c").unwrap();
//! let ciphered = Message::decode(&bytes).unwrap();
//! println!("{}", ciphered.to_tree()["ciphered-message"]);
//! ```
//!
//! ```text
//! {
//!   "security-header": {
//!     "security-header-type": "integrity-protected",
//!     "message-authentication-code": 3879440411,
//!     "sequence-number": 0
//!   },
//!   "message-type": "5gmm-status",
//!   "5gmm-cause": "congestion"
//! }
//! cannot encode: the message authentication code of `security-header` is that of the message as it was: write the code of the edited message, or edit the plain message
//! {"octets":"026ff75c"}
//! ```
//!
//! `from_tree()` writes a message under the `security-header` of its tree, with
//! the MAC that the tree has.
//!
//! ## Every path of a message
//!
//! ```rust
//! use oxirush_nas::{nas_5gs::Message, paths, tree};
//!
//! // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
//! let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
//! let accept = Message::decode(&bytes).unwrap();
//! let tree = accept.to_tree();
//!
//! // Each value with the path that selects it
//! for (path, value) in paths::paths(&tree) {
//!     println!("{path} = {value}");
//! }
//!
//! // A coded value by its name and an identity by its parts
//! let select = |path| paths::select(&tree, path).unwrap();
//! assert_eq!(select("/nas/message-type"), [&tree!("registration-accept")]);
//! assert_eq!(select("/nas/5gs-registration-result/result"), [&tree!("3gpp-access")]);
//! assert_eq!(select("/nas/5g-guti/guti/tmsi"), [&tree!(0x1122_3344)]);
//!
//! // A name in any case, and `*` for each entry of a list
//! assert_eq!(select("/NAS/Allowed NSSAI/*/SST"), [&tree!(1)]);
//!
//! // An optional IE that the message does not have selects nothing
//! assert!(select("/nas/t3512-value").is_empty());
//!
//! // A name that the message cannot have is an error
//! assert!(paths::select(&tree, "/nas/t3512").is_err());
//! ```
//!
//! ```text
//! /nas/message-type = "registration-accept"
//! /nas/5gs-registration-result/result = "3gpp-access"
//! /nas/5gs-registration-result/sms-allowed = false
//! /nas/5gs-registration-result/nssaa-performed = false
//! /nas/5gs-registration-result/emergency-registered = false
//! /nas/5gs-registration-result/disaster-roaming = false
//! /nas/5g-guti/guti/plmn = "208-93"
//! /nas/5g-guti/guti/amf-region-id = 1
//! /nas/5g-guti/guti/amf-set-id = 1
//! /nas/5g-guti/guti/amf-pointer = 2
//! /nas/5g-guti/guti/tmsi = 287454020
//! /nas/allowed-nssai/0/sst = 1
//! ```
//!
//! # Paths
//!
//! [`paths`] gives each value of a tree with the path that selects it,
//! [`select`] the values at a path, and [`set`], [`remove`] and [`insert`]
//! edit a tree at a path. `/nas` stands for the tree, and the segment after it
//! is the name of an IE or of a field of the header:
//!
//! ```text
//! /nas/message-type = "registration-accept"
//! /nas/5g-guti/guti/plmn = "208-93"
//! /nas/allowed-nssai/0/sst = 1
//! /nas/t3346-value/octets = "2a2b"
//! ```
//!
//! A path is a JSON pointer. A name is its letters and its digits, whatever
//! their case and whatever is between them: `/nas/5GMM cause` and
//! `/NAS/5gmm_cause` are one path. A list selects by position, a number as
//! decimal writes it, `-` is the end of a list where [`insert`] adds, and `*`
//! is each entry of a list or each member of a value. The message in a
//! container is under the name of the container, with the names of its own
//! IEs: `/nas/esm-message-container/pdn-type`.
//!
//! A path is the names of the tree joined: after the name of an IE or of a
//! field of the header, the next name is a member of its value. `octets` there
//! is the octets of the IE: a tree has them where the value does not write
//! them back, and [`set`] writes the IE by them, in the place of its value;
//! the message has them for each IE, and its `select()`
//! ([`nas_5gs::Message::select`](crate::nas_5gs::Message::select),
//! [`nas_eps::Message::select`](crate::nas_eps::Message::select)) gives them.
//! `value` after the name of an IE, which no tree has, is an error that says the
//! path without it: ``a path is the tree's names joined: write
//! `/nas/5g-guti/guti/tmsi`, at /nas/5g-guti/value/guti/tmsi``.
//!
//! An optional IE that the message does not have selects nothing, and so does
//! anything under it; [`set`] adds it. Inside a value, a path names what the
//! value has, as the tree shows it: a member that it does not have is an error,
//! and [`set`] adds it. A name that a message cannot have is an error, so a
//! name that is written wrong is not taken for an IE that is absent.
//!
//! # Rules
//!
//! These are the rules of the tree of a message, which
//! [`to_tree()`], [`from_tree()`] and [`with_tree()`] read and write.
//!
//! | Subject | Rule |
//! |---------|------|
//! | Names | The name that the specification gives an IE, in lower case with hyphens, as in `5gs-registration-result`. A name is read by its letters and its digits, whatever their case and whatever is between them: `5GMM cause` and `5gmm_cause` are `5gmm-cause`. |
//! | An IE | Its value, in the notation of [Values](#values), or `{"octets": "…"}`: the value part of the IE in hexadecimal, which is sent whatever it is, and the length of the IE follows it. An IE whose value does not write it back is shown by its octets. A code is its name or its number. A number is also read as a `"0x…"` string, except in `message-type` and `security-header-type`, where a string is a name. |
//! | Header | Each field by its value. A tree leaves out what its `message-type` decides: the protocol discriminator, and in a 5GMM message a plain security header type and a spare half octet of zero. |
//! | An IE that is not there | Left out. It selects nothing, and [`paths`] does not list it. |
//! | Unknown IEs | `unknown-ies` is the IEs that the table of the message has no place for, as one text: each by its octets in hexadecimal, its IEI first, with a space between two of them, in the order they came in: an IEI that the table does not have, and what a receiver ignores of one that it has (a repetition, an IE out of sequence, one whose value is not one of its type). A message that is written has them after its other IEs; `with_tree()` keeps their places when the member is as it was. |
//! | Order | The order of the message: the header first, then the IEs in the order of the message table, and in a value its members in the order of the clause. A tree that is written may have them in any order. |
//! | Errors | Nothing that is written is ignored. These are errors: a name that the message or a value does not have; a value that its IE cannot carry, with the member and the limit that it breaks as the constructor of the IE says them (``pdu-session-status: entry 1: `pdu-session-identity` is 16, and must be 1 to 15``); a mandatory IE that is taken out or not written; octets of a length that the message does not give the IE; a `message-type` that the IEs are not those of; an edit under a `security-header` that keeps its code. |
//! | Not checked | The rules of a sender: `validate()` has them. |
//! | Octets that a message came with | A tree has the value of an IE, and its octets where the value does not write them back. [`select()`] of the message gives the octets of an IE as the message has them, by the path of the IE and `octets`: `/nas/nas-message-container/5gmm-capability/octets`. |
//! | Octets after `with_tree()` | Only what was edited changes: an IE that the tree leaves as it was keeps its octets, and a tree that changes nothing gives the message back. |
//! | Octets after `from_tree()` | The message means the same ([`means_the_same()`]) and may have other octets, in three cases: its optional IEs are in the order of the message table, with the unknown IEs after them; and a value that says all that its octets mean without deciding them is written in one form (the unit of a timer of one octet and of the rates of a session AMBR, octets of zeros at the end of the flags of a capability, the partial lists of an EPS tracking area identity list). Octets are the way to choose them. |
//! | EPS SERVICE REQUEST | A short header, no IEs and no `message-type` (TS 24.301 §8.2.25). Its tree has `ksi-and-sequence-number`, whose value is a `ksi` and a `sequence-number`, and the two octets of `message-authentication-code`; the protocol discriminator, and a security header type of 12, are left out as the other headers leave out what their type decides. |
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
//! | container of a NAS message | the tree of that message |
//! | protocol configuration options | the list of their [units](#units-of-the-protocol-configuration-options) |
//! | SD, MAC address, EUI-64, key, interface identifier, raw contents | hexadecimal |
//!
//! # IE types that have a value
//!
//! | | 5GS | EPS |
//! |---|-----|-----|
//! | IE types | 169 | 153 |
//! | with a `value` | 158 | 134 |
//! | with `octets` alone | 11 | 19 |
//!
//! A value is read and written: octets that the crate reads and would not
//! write back to the same value have no value, and are shown by their
//! `octets`.
//!
//! The 30 types with octets alone:
//!
//! | Kind | Types |
//! |------|-------|
//! | Octet strings | RAND, AUTN, AUTS, RES, ABBA, nonces, HashMME |
//! | Payloads of other protocols and of upper layers | EAP message, SMS, LPP and user data containers, ATSSS and port management containers, additional information |
//! | Getters and no constructor in the crate, or neither | ECS address, classmark 3, the A/Gb and Iu mode QoS, LCS client identity, UE coarse location information |
//! | Typed accessors and constructors that a tree does not use | non-3GPP device information, whose constructor takes the type of the PDU session; negotiated LLC SAPI |
//! | No content | spare half octet |
//!
//! # Units of the protocol configuration options
//!
//! The value of the protocol configuration options and of the extended
//! protocol configuration options is the list of their units, in their
//! order (TS 24.008 §10.5.6.3). An identifier means one thing in a message
//! of the UE and another in a message of the network, so a unit is read by
//! the type of its message. A name of the other direction is refused, with
//! the unit that this direction has for the same identifier. A unit that
//! has a name is written by it, and not as a `container`.
//!
//! | Identifier | In a message of the UE | In a message of the network |
//! |------------|------------------------|-----------------------------|
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
//! | 001AH | `{"pdu-session-id": 5}` | |
//! | 001BH | | `{"s-nssai": {"sst": 1, "sd": "010203", "plmn": "208-93"}}`: the S-NSSAI and its PLMN |
//! | 001CH | | `{"qos-rules": […]}`: the value of the QoS rules IE |
//! | 001DH | | `{"session-ambr": {"dl-kbps": 100000, "ul-kbps": 50000}}` |
//! | 001FH | | `{"qos-flow-descriptions": […]}`: the value of the QoS flow descriptions IE |
//! | 0022H | `{"5gsm-cause": "insufficient-resources"}` | |
//! | any other, and the packets of LCP (C021H), PAP (C023H), CHAP (C223H) and IPCP (8021H) | `{"container": {"identifier": 65280, "contents": "01"}}`: the number of the identifier and the contents in hexadecimal | the same |
//!
//! Where a cell is empty, the identifier has no name in that direction. It
//! is a `container` if the specification has it there, as the MSISDN that
//! the network gives under 000EH, and the options have their octets alone
//! if it does not.
//!
//! 001AH to 0022H are the units of a PDU session in a PDN connection (TS
//! 23.502 §4.11.1.5), each the value part of the IE of TS 24.501 of its name.
//! Each has its name where it writes its contents back, so that an edit of
//! the options changes no other unit: a session AMBR where each rate is in
//! the largest unit that holds it, as the crate writes it. Other contents are
//! a `container`.
//!
//! The options have a value where the units give their octets back: not
//! with a spare bit of the first octet set, not with a configuration
//! protocol other than PPP, and not with a unit that the specification
//! lets a receiver ignore (an address of another length). Those have their
//! `octets`, which are written as they are.
//!
//! [`to_tree()`]: crate::nas_5gs::Message::to_tree
//! [`means_the_same()`]: crate::nas_5gs::Message::means_the_same
//! [`from_tree()`]: crate::nas_5gs::Message::from_tree
//! [`with_tree()`]: crate::nas_5gs::Message::with_tree
//! [`select()`]: crate::nas_5gs::Message::select

use crate::prelude::*;
use alloc::rc::Rc;
use core::cell::Cell;
use oxirush_utils::tree::Value;
use oxirush_utils::tree::{
    self, Absent, Edit, Error, ErrorKind, Family, Key, Next, Place, Root, Step,
};

/// The name after an IE that is its octets.
const OCTETS: &str = "octets";
/// The name that a path may write after the name of an IE for its value, which no tree
/// has there.
const VALUE: &str = "value";

/// What a path knows of a place of a tree.
#[derive(Clone, Default)]
enum Shape {
    /// The tree of a message, with the `message-type` that it writes by name.
    Message(Option<String>),
    /// The value of an IE or of a field of the header of a message: the name after it is
    /// a member of the value, or `octets`, the octets of the IE. `message` is the type
    /// of the message that the value is, for a container; `at` the path of the IE, where
    /// a message gives the octets of each IE.
    Ie {
        message: Option<String>,
        at: Option<Rc<str>>,
    },
    /// The octets of an IE that the tree has by its value: those that the message has
    /// for the IE at `at`, and for `set`, the octets that take the place of the value.
    Octets(Option<Rc<str>>),
    /// A value, which the plain rules walk.
    #[default]
    Value,
}

/// The `message-type` that `tree` writes by name, if it is the tree of a message.
fn kind_of(tree: &Value) -> Option<String> {
    let kind = tree::member(tree.as_object()?, "message-type")?.1;
    Some(kind.as_str()?.to_owned())
}

/// The trees of the NAS messages of both systems, as the paths of oxirush-utils walk
/// them: `/nas` stands for the tree, and the segment after it names an IE or a field of
/// the header.
#[derive(Default)]
struct Trees {
    /// Whether the paths are those of a message, which has the octets of each IE.
    message: bool,
    /// Where the path has `value` after the name of an IE, which the walk refused: the
    /// position of that segment in the path as it is written.
    joined: Cell<Option<usize>>,
}

impl Trees {
    /// The paths of a message, whose places keep the paths of their IEs.
    fn of_message() -> Self {
        Self {
            message: true,
            ..Self::default()
        }
    }

    /// `done`, the end of a walk of `path` in `tree`, or the error that says the path of
    /// the names of the tree where the path has `value` after the name of an IE: without
    /// it, and without each `value` after another IE that a walk of that path meets. An
    /// edit that refused the path for another reason, as an IE that is not there, says
    /// this, which a walk of `tree` that selects finds.
    fn joined<T>(&self, done: Result<T, Error>, tree: &Value, path: &str) -> Result<T, Error> {
        let walked = |path: &str| {
            let again = Trees::default();
            let _ = tree::places_in(&again, tree, path);
            again.joined.get()
        };
        let index = match self.joined.get() {
            None if done.is_err() => walked(path),
            index => index,
        };
        let Some(mut index) = index else {
            return done;
        };
        let mut parts = tree::segments(path)?;
        let written = loop {
            parts.remove(index);
            let written: String = parts
                .iter()
                .map(|part| format!("/{}", tree::escape(part)))
                .collect();
            match walked(&written) {
                Some(again) => index = again,
                None => break written,
            }
        };
        let reason = format!("a path is the tree's names joined: write `{written}`");
        Err(Error::new(ErrorKind::NoSuchMember, path, reason))
    }

    /// What `octets` after the name of the IE at `at` selects at `place`, where the tree
    /// has no member of that name there: the IE has its value, or the message does not
    /// have it.
    fn octets<'v>(
        &self,
        place: &Place<'v, Shape>,
        at: &Option<Rc<str>>,
        next: &mut Next<'v, Shape>,
    ) -> Result<(), Error> {
        let there = place.value().is_some_and(|value| !value.is_null());
        match next.edit() {
            // The IE is written by its octets, in the place of its value.
            Some(Edit::Set) if next.is_last() => next.stay(place, Shape::Octets(None)),
            // An IE that the message does not have has no octets.
            None if !there => {}
            // A message has the octets of each IE.
            None if self.message => next.absent(OCTETS, Shape::Octets(at.clone())),
            _ => {
                let reason =
                    "the tree has the value of this IE and not its octets, which the message has";
                return Err(Error::new(ErrorKind::NoSuchMember, "", reason));
            }
        }
        Ok(())
    }
}

impl Family for Trees {
    type Shape = Shape;

    fn root(&self) -> Root<'_> {
        Root::new("nas", &[], true)
    }

    fn start(&self, tree: &Value, _rooted: bool) -> Shape {
        Shape::Message(kind_of(tree))
    }

    fn step<'v>(
        &self,
        place: &Place<'v, Shape>,
        segment: &str,
        next: &mut Next<'v, Shape>,
    ) -> Result<Step<Shape>, Error> {
        let Shape::Ie { at, .. } = place.shape() else {
            return Ok(Step::Plain);
        };
        // A member of the value that has the name is that member.
        let members = place.value().and_then(Value::as_object);
        let has = |name: &str| members.is_some_and(|members| tree::member(members, name).is_some());
        // No IE of the two systems has a value with a member `value`.
        if tree::same_name(segment, VALUE) && !has(VALUE) {
            self.joined.set(next.index());
            let reason = "a path is the tree's names joined";
            return Err(Error::new(ErrorKind::Refused, "", reason));
        }
        if !tree::same_name(segment, OCTETS) || has(OCTETS) {
            return Ok(Step::Plain);
        }
        self.octets(place, at, next)?;
        Ok(Step::Taken)
    }

    fn member(&self, shape: &Shape, name: &str, value: Option<&Value>) -> Shape {
        // The members of a message, and of the message in a container, are its IEs.
        let held = match shape {
            Shape::Message(_) => None,
            Shape::Ie {
                message: Some(_),
                at,
            } => at.as_deref(),
            _ => return Shape::Value,
        };
        let at = self.message.then(|| {
            let held = held.unwrap_or("/nas");
            Rc::from(format!("{held}/{}", tree::escape(name)))
        });
        Shape::Ie {
            message: value.and_then(kind_of),
            at,
        }
    }

    fn absent(&self, shape: &Shape, name: &str) -> Absent<Shape> {
        let (Shape::Message(Some(kind))
        | Shape::Ie {
            message: Some(kind),
            ..
        }) = shape
        else {
            return Absent::Unknown;
        };
        match can_have(kind, name) {
            true => Absent::Optional(self.member(shape, name, None)),
            false => Absent::Refused(Error::new(
                ErrorKind::NoSuchMember,
                "",
                format!("`{name}` is no IE of a message `{kind}`"),
            )),
        }
    }

    fn edited(&self, tree: &mut Value, at: &[Key], shape: &Shape, edit: Edit) {
        // The octets that are set take the place of the value of the IE.
        if !matches!((shape, edit), (Shape::Octets(_), Edit::Set)) {
            return;
        }
        let mut place = Some(tree);
        for key in at {
            place = match (key, place) {
                (Key::Name(name), Some(Value::Object(members))) => members.get_mut(name.as_str()),
                _ => None,
            };
        }
        if let Some(place) = place {
            let octets = core::mem::take(place);
            *place = oxirush_utils::tree!({ "octets": octets });
        }
    }
}

/// Whether a message of the type `kind` can have the IE `name`: one of the messages of
/// that name has it, or no message has that name.
fn can_have(kind: &str, name: &str) -> bool {
    use crate::common::view::names;
    use crate::{nas_5gs, nas_eps};
    // The protocols have types of the same name, with other IEs.
    let of_the_type = [
        names(
            &nas_5gs::view::GMM_HEADER,
            &[kind],
            nas_5gs::GmmMessage::fields_named,
        ),
        names(
            &nas_5gs::view::GSM_HEADER,
            &[kind],
            nas_5gs::GsmMessage::fields_named,
        ),
        names(
            &nas_eps::view::EMM_HEADER,
            &[kind],
            nas_eps::EmmMessage::fields_named,
        ),
        names(
            &nas_eps::view::ESM_HEADER,
            &[kind],
            nas_eps::EsmMessage::fields_named,
        ),
    ]
    .concat();
    of_the_type.is_empty() || tree::named(&of_the_type, name).is_some()
}

/// The values at `path` in the tree of a message, in the order of the tree. An IE that
/// the message does not have selects nothing, whether the path ends at it or goes on; a
/// name that the message cannot have, or that a value does not have, is an error.
///
/// # Errors
///
/// The errors of [`tree::select_in`]: a path that is none, more than 4096 values, a
/// name that the value at its place does not have, a segment that is no position in a
/// list, a path that goes on into a number or a string, and the name of an IE that the
/// message of the tree cannot have; `value` after the name of an IE, with the path that
/// the names of the tree write, and `octets` after an IE that the tree has by its value.
///
/// ```
/// use oxirush_nas::{nas_5gs::Message, paths, tree};
///
/// // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
/// let octets = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
/// let tree = Message::decode(&octets).unwrap().to_tree();
/// assert_eq!(paths::select(&tree, "/nas/5g-guti/guti/plmn")?, [&tree!("208-93")]);
/// assert_eq!(paths::select(&tree, "/NAS/Allowed NSSAI/*/SST")?, [&tree!(1)]);
///
/// // An IE that the message does not have selects nothing, and one that it cannot have is an error
/// assert!(paths::select(&tree, "/nas/t3512-value")?.is_empty());
/// assert!(paths::select(&tree, "/nas/t3512").is_err());
/// # Ok::<(), tree::Error>(())
/// ```
pub fn select<'a>(tree: &'a Value, path: &str) -> Result<Vec<&'a Value>, Error> {
    let trees = Trees::default();
    trees.joined(tree::select_in(&trees, tree, path), tree, path)
}

/// Each value of the tree of a message with the path that selects it, in the order of
/// the tree: the members of an object, the entries of a list, down to a number, a
/// string, a boolean, `null` or an empty object or list.
pub fn paths(tree: &Value) -> Vec<(String, Value)> {
    tree::paths_in(&Trees::default(), tree)
}

/// Set the value at `path` in the tree of a message to `value`, adding an optional IE
/// that the message does not have, and the members of a value on the way to it. At
/// `octets` after the name of an IE, the IE has those octets in the place of its value.
///
/// # Errors
///
/// The errors of [`tree::set_in`], the name of an IE that the message cannot have, and
/// `value` after the name of an IE, with the path that the names of the tree write.
///
/// ```
/// use oxirush_nas::{nas_5gs::Message, paths, tree};
///
/// // 5GMM STATUS, cause #22 "congestion"
/// let status = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
/// let mut tree = status.to_tree();
/// paths::set(&mut tree, "/nas/5gmm-cause", tree!("illegal-ue"))?;
/// let edited = status.with_tree(tree).unwrap();
/// assert_eq!(edited.encode().unwrap(), [0x7e, 0x00, 0x64, 0x03]);
/// # Ok::<(), tree::Error>(())
/// ```
pub fn set(tree: &mut Value, path: &str, value: Value) -> Result<(), Error> {
    let trees = Trees::default();
    let done = tree::set_in(&trees, tree, path, value);
    trees.joined(done, tree, path)
}

/// Take out the value at `path` in the tree of a message: an IE, a member of a value or
/// an entry of a list. A path that selects nothing takes out nothing.
///
/// # Errors
///
/// The errors of [`tree::remove_in`], and the name of an IE that the message cannot have.
pub fn remove(tree: &mut Value, path: &str) -> Result<(), Error> {
    let trees = Trees::default();
    let done = tree::remove_in(&trees, tree, path);
    trees.joined(done, tree, path)
}

/// Insert `value` into a list of the tree of a message: at the position that the last
/// segment of `path` gives, or at its end where it is `-`.
///
/// # Errors
///
/// The errors of [`tree::insert_in`], and the name of an IE that the message cannot
/// have.
pub fn insert(tree: &mut Value, path: &str, value: Value) -> Result<(), Error> {
    let trees = Trees::default();
    let done = tree::insert_in(&trees, tree, path, value);
    trees.joined(done, tree, path)
}

/// The values at `path` in `tree`, the tree of a message, as [`select`] gives them, and
/// the octets of each IE that the tree has by its value, which `octets` after its name
/// selects: `ie_octets` gives those that the message has, by the path of the IE.
pub(crate) fn of_message(
    tree: &Value,
    path: &str,
    ie_octets: impl Fn(&str) -> Result<Option<Vec<u8>>, Error>,
) -> Result<Vec<Value>, Error> {
    let trees = Trees::of_message();
    let places = trees.joined(tree::places_in(&trees, tree, path), tree, path)?;
    let mut selected = Vec::new();
    for place in places {
        match (place.value(), place.shape()) {
            (None, Shape::Octets(Some(ie))) => {
                let octets = ie_octets(ie)
                    .map_err(|error| Error::new(error.kind(), path, error.reason()))?;
                selected.extend(octets.map(|octets| tree::octets(&octets)));
            }
            (Some(value), _) if !value.is_null() => selected.push(value.clone()),
            _ => {}
        }
    }
    Ok(selected)
}
