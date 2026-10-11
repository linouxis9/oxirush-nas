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

//! What the benchmarks of oxirush-nas measure: the inputs, and the
//! operations on each. The three programs of `benches/` share them:
//!
//! - `codec` times each operation with criterion, and profiles it with
//!   pprof;
//! - `allocations` counts the allocations of one call of each;
//! - `heap` says where the allocations of an operation are made.
//!
//! The inputs are the fixtures of the crate, `tests/fixtures`, as one input
//! for the 5GS messages and one for the EPS messages, and a few messages
//! that are large or hostile, each an input of its own.
//!
//! With the `security` feature of this package, `protect` and `unprotect`
//! are measured too, on the plain messages of an input that a security
//! context protects, with 128-NIA2 and 128-NEA2.

use oxirush_nas::common::Direction;
use oxirush_nas::nas_5gs::{Nas5gsMessage, Validate as _};
use oxirush_nas::nas_eps::NasEpsMessage;
use std::hint::black_box;

// ── The codec, as the benchmarks call it ────────────────────────────────────

fn decode_5gs(octets: &[u8]) -> Nas5gsMessage {
    Nas5gsMessage::from_bytes(octets).unwrap()
}

fn decode_eps(octets: &[u8], direction: Direction) -> NasEpsMessage {
    NasEpsMessage::from_bytes_with_direction(octets, direction).unwrap()
}

fn encode_5gs(message: &Nas5gsMessage) -> Vec<u8> {
    message.to_bytes().unwrap()
}

fn encode_eps(message: &NasEpsMessage) -> Vec<u8> {
    message.to_bytes().unwrap()
}

#[cfg(feature = "security")]
mod security;

// ── Inputs ──────────────────────────────────────────────────────────────────

/// The messages of an input, as octets and decoded.
enum Messages {
    FiveGs(Vec<(Vec<u8>, Nas5gsMessage)>),
    Eps(Vec<(Vec<u8>, Direction, NasEpsMessage)>),
}

/// One or several messages that the operations are measured on.
pub struct Input {
    /// The name of the input, without spaces: `5gs-fixtures`.
    pub name: &'static str,
    /// What the input is.
    pub description: String,
    messages: Messages,
    /// The messages of the input that a security context protects.
    #[cfg(feature = "security")]
    protected: security::Protected,
}

impl Input {
    fn new(name: &'static str, description: String, messages: Messages) -> Self {
        Self {
            name,
            description,
            #[cfg(feature = "security")]
            protected: security::Protected::of(&messages),
            messages,
        }
    }
}

/// One call of an operation, with what it needs already made.
pub type Call<'a> = Box<dyn FnOnce() + 'a>;

/// How an operation is called on the message `index` of its input.
pub enum Run<'a> {
    /// The operation needs the message alone.
    Direct(Box<dyn Fn(usize) + 'a>),
    /// The operation is given something that is made first and is no part
    /// of it, such as the view that `with-view` reads: this makes it, and
    /// returns the call.
    Prepared(Box<dyn Fn(usize) -> Call<'a> + 'a>),
}

/// An operation on the messages of an input. What a call returns is dropped
/// in it.
pub struct Operation<'a> {
    /// The name of the operation: `decode`.
    pub name: &'static str,
    /// How many messages the input has.
    pub messages: usize,
    /// How the operation is called.
    pub run: Run<'a>,
}

impl Operation<'_> {
    /// The calls of the operation on every message of the input, each with
    /// what it needs already made.
    pub fn calls(&self) -> Vec<Call<'_>> {
        let call = |index| -> Call<'_> {
            match &self.run {
                Run::Direct(call) => Box::new(move || call(index)),
                Run::Prepared(prepare) => prepare(index),
            }
        };
        (0..self.messages).map(call).collect()
    }
}

/// The messages of a fixture file: the name and the octets of each.
fn fixtures(file: &str) -> Vec<(&str, Vec<u8>)> {
    file.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split_once('\t').unwrap())
        .map(|(name, octets)| (name, hex::decode(octets).unwrap()))
        .collect()
}

/// Octets written in hexadecimal, with spaces between the IEs.
fn octets(hexadecimal: &str) -> Vec<u8> {
    hex::decode(hexadecimal.replace(' ', "")).unwrap()
}

/// `count` S-NSSAIs with an SD, as the value of an NSSAI IE.
fn nssai(count: u8) -> Vec<u8> {
    (1..=count).flat_map(|sd| [4, 1, 0, 0, sd]).collect()
}

/// A REGISTRATION ACCEPT with what a network sends a smartphone: a 5G-GUTI,
/// equivalent PLMNs, a TAI list of sixteen areas, three NSSAIs, the network
/// feature support, timers and an emergency number list.
fn registration_accept() -> Vec<u8> {
    let mut message = octets("7e0042 0101 77000b f202f83901004211223344");
    // Equivalent PLMNs
    message.extend(octets("4a09 02f810 02f820 02f830"));
    // TAI list: sixteen tracking areas of one PLMN
    message.extend(octets("5434 0f 02f839"));
    message.extend((1..=16).flat_map(|tac| [0, 0, tac]));
    // Allowed, rejected and configured NSSAI
    let (allowed, configured) = (nssai(8), nssai(16));
    message.extend([0x15, allowed.len() as u8]);
    message.extend(&allowed);
    message.extend(octets("1102 1102"));
    message.extend([0x31, configured.len() as u8]);
    message.extend(&configured);
    // 5GS network feature support, PDU session status and reactivation result
    message.extend(octets("2102 0301  5002 2000  2602 2000"));
    // T3512, non-3GPP de-registration timer, T3502
    message.extend(octets("5e01 06  5d01 01  1601 2c"));
    // Emergency number list: 112 and 911
    message.extend(octets("3408 03 01 11f2 03 01 19f1"));
    // NSSAI inclusion mode, negotiated DRX parameters
    message.extend(octets("a1  5101 01"));
    message
}

/// A PDU SESSION ESTABLISHMENT ACCEPT with four QoS rules, their flow
/// descriptions, protocol configuration options and a DNN, in the payload
/// container of a DL NAS TRANSPORT under an integrity protected header.
fn dl_nas_transport() -> Vec<u8> {
    let mut accept = octets("2e 05 01 c2 11");
    // Authorized QoS rules: four rules of one packet filter each
    let rule = |id: u8| {
        let mut rule = vec![id, 0, 0, 0x21 | u8::from(id == 1) << 4];
        // A local IPv4 address, a remote port and the protocol
        rule.extend(octets("31 0e  11 ac100a0a ffffffff  50 1388  30 11"));
        rule.extend([id, id]);
        let length = (rule.len() - 3) as u16;
        rule[1..3].copy_from_slice(&length.to_be_bytes());
        rule
    };
    let rules: Vec<u8> = (1..=4).flat_map(rule).collect();
    accept.extend((rules.len() as u16).to_be_bytes());
    accept.extend(&rules);
    // Session-AMBR, 5GSM cause, PDU address, S-NSSAI
    accept.extend(octets(
        "06 06 0100 06 0100  59 24  2905 01 0a2d0001  2204 01 010203",
    ));
    // Authorized QoS flow descriptions: four flows with a 5QI and bit rates
    let flow = |qfi: u8| {
        let mut flow = vec![qfi, 0x20, 0x45];
        flow.extend(octets(
            "0101 01  0203 06 0100  0303 06 0100  0403 06 0100  0503 06 0100",
        ));
        flow
    };
    let flows: Vec<u8> = (1..=4).flat_map(flow).collect();
    accept.push(0x79);
    accept.extend((flows.len() as u16).to_be_bytes());
    accept.extend(&flows);
    // Extended protocol configuration options: two DNS servers and an MTU
    accept.extend(octets(
        "7b0014 80 000d 04 08080808 000d 04 08080404 0010 02 0578",
    ));
    // DNN "internet.mnc093.mcc208.gprs"
    accept.extend(octets(
        "251c 08 696e7465726e6574 06 6d6e63303933 06 6d6363323038 04 67707273",
    ));

    let mut message = octets("7e 01 deadbeef 07  7e0068 01");
    message.extend((accept.len() as u16).to_be_bytes());
    message.extend(&accept);
    message.extend(octets("1205"));
    message
}

/// A REGISTRATION REQUEST in the NAS message container of another, `depth`
/// times: what a peer can send to make a reader of containers call itself.
fn nested(depth: usize) -> Vec<u8> {
    let seed = octets("7e004101000d0102f8390000000021436587f9");
    let mut message = seed.clone();
    for _ in 0..depth {
        let mut outer = seed.clone();
        outer.push(0x71);
        outer.extend((message.len() as u16).to_be_bytes());
        outer.extend(&message);
        message = outer;
    }
    message
}

/// A PDU SESSION MODIFICATION COMMAND REJECT followed by `count` unknown IEs
/// of one octet each.
fn unknown_ies(count: usize) -> Vec<u8> {
    let mut message = octets("2e0101cc 7b000180");
    message.resize(message.len() + count, 0x80);
    message
}

/// The inputs: the fixtures of 5GS and of EPS, then the single messages.
pub fn inputs() -> Vec<Input> {
    let single = |name, what: &str, message: Vec<u8>| {
        Input::new(
            name,
            format!("{what}, {} octets", message.len()),
            five_gs(name, vec![message]),
        )
    };
    let fixtures_5gs = fixtures(include_str!("../../tests/fixtures/nas-5gs.tsv"));
    let fixtures_eps = fixtures(include_str!("../../tests/fixtures/nas-eps.tsv"));
    let eps: Vec<_> = (fixtures_eps.into_iter())
        .map(|(name, message)| {
            let direction = match name.starts_with("DetachRequestToUe") {
                true => Direction::Downlink,
                false => Direction::Uplink,
            };
            let decoded = decode_eps(&message, direction);
            assert_eq!(encode_eps(&decoded), message, "{name}");
            (message, direction, decoded)
        })
        .collect();
    vec![
        Input::new(
            "5gs-fixtures",
            format!("the {} messages of nas-5gs.tsv", fixtures_5gs.len()),
            five_gs(
                "5gs-fixtures",
                fixtures_5gs.into_iter().map(|(_, octets)| octets).collect(),
            ),
        ),
        Input::new(
            "eps-fixtures",
            format!("the {} messages of nas-eps.tsv", eps.len()),
            Messages::Eps(eps),
        ),
        single(
            "registration-accept",
            "REGISTRATION ACCEPT with 16 optional IEs",
            registration_accept(),
        ),
        single(
            "dl-nas-transport",
            "protected DL NAS TRANSPORT of a PDU SESSION ESTABLISHMENT ACCEPT",
            dl_nas_transport(),
        ),
        single("containers-8", "a NAS message container 8 deep", nested(8)),
        single(
            "containers-100",
            "a NAS message container 100 deep",
            nested(100),
        ),
        single(
            "unknown-ies-1000",
            "a message with 1,000 unknown IEs",
            unknown_ies(1_000),
        ),
        single(
            "unknown-ies-68227",
            "a message with 68,227 unknown IEs",
            unknown_ies(68_227),
        ),
    ]
}

/// 5GS messages as an input: each is one that the codec gives back.
fn five_gs(name: &str, messages: Vec<Vec<u8>>) -> Messages {
    let decoded = |message: Vec<u8>| {
        let decoded = Nas5gsMessage::from_bytes(&message)
            .unwrap_or_else(|error| panic!("{name}: {error}: {}", hex::encode(&message)));
        assert_eq!(encode_5gs(&decoded), message, "{name}");
        (message, decoded)
    };
    Messages::FiveGs(messages.into_iter().map(decoded).collect())
}

/// What an operation returns, used and dropped.
fn done<T>(result: T) {
    drop(black_box(result));
}

/// The operation `name` on the `messages` messages of an input: `call` on
/// the message `index`.
fn operation<'a>(name: &'static str, messages: usize, call: impl Fn(usize) + 'a) -> Operation<'a> {
    Operation {
        name,
        messages,
        run: Run::Direct(Box::new(call)),
    }
}

/// The operation `name` on the `messages` messages of an input: `prepare`
/// makes what the call on the message `index` needs, and returns the call.
fn prepared<'a, C: FnOnce() + 'a>(
    name: &'static str,
    messages: usize,
    prepare: impl Fn(usize) -> C + 'a,
) -> Operation<'a> {
    Operation {
        name,
        messages,
        run: Run::Prepared(Box::new(move |index| Box::new(prepare(index)))),
    }
}

impl Input {
    /// The operations on this input, in the order of the reports.
    pub fn operations(&self) -> Vec<Operation<'_>> {
        #[allow(unused_mut)]
        let mut operations = self.codec_operations();
        #[cfg(feature = "security")]
        operations.extend(self.protected.operations(&self.messages));
        operations
    }

    /// The operations of the codec and of its JSON forms.
    fn codec_operations(&self) -> Vec<Operation<'_>> {
        match &self.messages {
            Messages::FiveGs(messages) => {
                let count = messages.len();
                let octets = |at: usize| black_box(&messages[at].0);
                let message = |at: usize| black_box(&messages[at].1);
                vec![
                    operation("decode", count, move |at| done(decode_5gs(octets(at)))),
                    operation("encode", count, move |at| done(encode_5gs(message(at)))),
                    operation("validate", count, move |at| done(message(at).validate())),
                    operation("display", count, move |at| done(message(at).to_string())),
                    operation("clone", count, move |at| done(message(at).clone())),
                    operation("tree", count, move |at| done(message(at).to_tree())),
                    prepared("from-tree", count, move |at| {
                        let tree = message(at).to_tree();
                        move || done(Nas5gsMessage::from_tree(tree))
                    }),
                    operation("view", count, move |at| done(message(at).to_view())),
                    prepared("with-view", count, move |at| {
                        let view = message(at).to_view();
                        move || done(message(at).with_view(view))
                    }),
                    operation("to-json", count, move |at| {
                        done(serde_json::to_string(message(at)))
                    }),
                    prepared("from-json", count, move |at| {
                        let document = serde_json::to_string(message(at)).unwrap();
                        move || done(serde_json::from_str::<Nas5gsMessage>(&document))
                    }),
                ]
            }
            Messages::Eps(messages) => {
                let count = messages.len();
                let octets = |at: usize| black_box(&messages[at].0);
                let message = |at: usize| black_box(&messages[at].2);
                vec![
                    operation("decode", count, move |at| {
                        done(decode_eps(octets(at), messages[at].1))
                    }),
                    operation("encode", count, move |at| done(encode_eps(message(at)))),
                    operation("validate", count, move |at| done(message(at).validate())),
                    operation("display", count, move |at| done(message(at).to_string())),
                    operation("clone", count, move |at| done(message(at).clone())),
                    operation("tree", count, move |at| done(message(at).to_tree())),
                    prepared("from-tree", count, move |at| {
                        let tree = message(at).to_tree();
                        move || done(NasEpsMessage::from_tree(tree))
                    }),
                    operation("view", count, move |at| done(message(at).to_view())),
                    prepared("with-view", count, move |at| {
                        let view = message(at).to_view();
                        move || done(message(at).with_view(view))
                    }),
                    operation("to-json", count, move |at| {
                        done(serde_json::to_string(message(at)))
                    }),
                    prepared("from-json", count, move |at| {
                        let document = serde_json::to_string(message(at)).unwrap();
                        move || done(serde_json::from_str::<NasEpsMessage>(&document))
                    }),
                ]
            }
        }
    }
}

/// Whether the benchmark `operation` on `input` is one that `filter` asks
/// for: one of the words of the filter is in its name `operation/input`, or
/// the filter has no word.
pub fn selected(filter: &[String], operation: &str, input: &str) -> bool {
    let name = format!("{operation}/{input}");
    filter.is_empty() || filter.iter().any(|word| name.contains(word.as_str()))
}

/// The arguments of a benchmark program that are no options of cargo or of
/// the program: the words of a filter.
pub fn filter() -> Vec<String> {
    (std::env::args().skip(1))
        .filter(|argument| !argument.starts_with("--"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxirush_nas::common::Severity;
    use oxirush_nas::nas_5gs::Nas5gmmMessage;

    /// The messages that stand for what a network sends are ones that a
    /// network may send: `validate()` finds no error in them.
    #[test]
    fn the_realistic_messages_are_valid() {
        let errors = |message: &Nas5gsMessage| -> Vec<String> {
            (message.validate().iter())
                .filter(|finding| finding.severity == Severity::Error)
                .map(|finding| finding.to_string())
                .collect()
        };
        let accept = decode_5gs(&registration_accept());
        assert_eq!(errors(&accept), [""; 0]);

        let transport = decode_5gs(&dl_nas_transport());
        assert_eq!(errors(&transport), [""; 0]);
        let Nas5gsMessage::SecurityProtected(_, inner) = &transport else {
            panic!("{transport:?}");
        };
        let Nas5gsMessage::Gmm(_, Nas5gmmMessage::DlNasTransport(transport)) = inner.as_ref()
        else {
            panic!("{inner:?}");
        };
        let session = (transport.payload_container.decode_as_n1_sm_message()).unwrap();
        assert_eq!(errors(&session), [""; 0]);
        // Every IE of the REGISTRATION ACCEPT has a value in a tree.
        let tree = accept.to_tree().to_string();
        assert!(!tree.contains("octets"), "{tree}");
    }
}
