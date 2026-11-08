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

//! The messages of `tests/wireshark/corpus.tsv` as Wireshark reads them and
//! as this crate reads them, compared field by field.
//!
//! The crate's reading of each message is its view, the internal form under
//! its tree that has the octets of each IE beside its value, written here as one
//! line of JSON; `tests/wireshark/compare.py` has tshark dissect the same
//! octets and compares the two along `tests/wireshark/mapping.tsv`. A
//! difference that `tests/wireshark/known.tsv` does not explain fails the
//! test. Without tshark, or without Python 3, the test says that it is
//! skipped and passes; with a tshark other than the one that known.tsv was
//! triaged with, compare.py says so and passes.
//!
//! Other messages are compared with `NAS_WIRESHARK_CORPUS=<rows>`, rows as
//! those of the corpus (`tests/wireshark/extract.py` collects them from
//! captures and other files), and `NAS_WIRESHARK_OUTPUT=<directory>` keeps
//! the report: `cargo test --features tree wireshark`.

use crate::prelude::*;
use std::eprintln;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::nas_5gs;
use crate::nas_eps;
use serde_json::{Value, json};

fn found(program: &str, argument: &str) -> bool {
    Command::new(program)
        .arg(argument)
        .output()
        .is_ok_and(|output| output.status.success())
}

/// The codes of the headers of a 5GS message, the outer one first.
fn codes_5gs(message: &nas_5gs::Message) -> Vec<Value> {
    match message {
        nas_5gs::Message::Gmm(header, body) => vec![json!({
            "extended-protocol-discriminator": header.extended_protocol_discriminator,
            "security-header-type": header.security_header_type as u8,
            "spare-half-octet": header.spare_half_octet,
            "message-type": u8::from(body.message_type()),
        })],
        nas_5gs::Message::Gsm(header, _) => vec![json!({
            "extended-protocol-discriminator": header.extended_protocol_discriminator,
            "pdu-session-identity": header.pdu_session_identity,
            "procedure-transaction-identity": header.procedure_transaction_identity,
            "message-type": u8::from(header.message_type),
        })],
        nas_5gs::Message::SecurityProtected(header, inner) => {
            let mut codes = vec![json!({
                "extended-protocol-discriminator": header.extended_protocol_discriminator,
                "security-header-type": header.security_header_type as u8,
                "spare-half-octet": header.spare_half_octet,
                "message-authentication-code": header.message_authentication_code,
                "sequence-number": header.sequence_number,
            })];
            codes.extend(codes_5gs(inner));
            codes
        }
        nas_5gs::Message::Opaque(_) => vec![json!({"ciphered": true})],
    }
}

/// The codes of the headers of an EPS message, the outer one first.
fn codes_eps(message: &nas_eps::Message) -> Vec<Value> {
    match message {
        nas_eps::Message::Emm(header, _) => vec![json!({
            "protocol-discriminator": header.protocol_discriminator,
            "security-header-type": header.security_header_type as u8,
            "message-type": u8::from(header.message_type),
        })],
        nas_eps::Message::Esm(header, _) => vec![json!({
            "protocol-discriminator": header.protocol_discriminator,
            "eps-bearer-identity": header.eps_bearer_identity,
            "procedure-transaction-identity": header.procedure_transaction_identity,
            "message-type": u8::from(header.message_type),
        })],
        nas_eps::Message::SecurityProtected(header, inner) => {
            let mut codes = vec![json!({
                "security-header-type": header.security_header_type as u8,
                "message-authentication-code": header.message_authentication_code,
                "sequence-number": header.sequence_number,
            })];
            codes.extend(codes_eps(inner));
            codes
        }
        nas_eps::Message::ServiceRequest(request) => vec![json!({
            "security-header-type": request.security_header_type,
            "ksi-and-sequence-number": request.ksi_and_sequence_number,
            "short-mac": request.message_authentication_code,
        })],
        nas_eps::Message::EmmTransport(_) => vec![json!({"emm-transport": true})],
        nas_eps::Message::Opaque(_) => vec![json!({"ciphered": true})],
    }
}

/// What the crate reads of `octets`, as one object of JSON.
fn reading(system: &str, octets: &[u8]) -> Value {
    let mut entry = json!({"system": system, "octets": hex::encode(octets)});
    let unknown = |ies: &crate::UnknownIes| -> Value {
        ies.iter()
            .map(|ie| json!({"iei": ie.iei, "data": hex::encode(ie.data)}))
            .collect()
    };
    let read = if system == "5gs" {
        match nas_5gs::Message::decode(octets) {
            Ok(message) => Ok((
                message.to_view(),
                codes_5gs(&message),
                unknown(message.unknown_ies()),
            )),
            Err(error) => Err((
                error.to_string(),
                nas_5gs::Message::decode_lenient(octets)
                    .ok()
                    .map(|(message, faults)| {
                        (
                            message.to_view(),
                            faults.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        )
                    }),
            )),
        }
    } else {
        match nas_eps::Message::decode(octets) {
            Ok(message) => Ok((
                message.to_view(),
                codes_eps(&message),
                unknown(message.unknown_ies()),
            )),
            Err(error) => Err((
                error.to_string(),
                nas_eps::Message::decode_lenient(octets)
                    .ok()
                    .map(|(message, faults)| {
                        (
                            message.to_view(),
                            faults.iter().map(ToString::to_string).collect::<Vec<_>>(),
                        )
                    }),
            )),
        }
    };
    match read {
        Ok((view, codes, unknown)) => {
            entry["view"] = serde_json::to_value(view).expect("a view is JSON");
            entry["codes"] = json!(codes);
            entry["unknown"] = unknown;
        }
        Err((error, lenient)) => {
            entry["error"] = json!(error);
            if let Some((view, faults)) = lenient {
                entry["lenient"] = json!({
                    "view": serde_json::to_value(view).expect("a view is JSON"),
                    "faults": faults,
                });
            }
        }
    }
    entry
}

#[test]
fn wireshark_reads_the_messages_as_the_crate_does() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/wireshark");
    if !found("tshark", "--version") {
        eprintln!(
            "skipped: tshark is not installed, so the messages are not compared with Wireshark"
        );
        return;
    }
    if !found("python3", "--version") {
        eprintln!("skipped: python3 is not installed, which compares the messages with Wireshark");
        return;
    }
    let corpus = std::env::var_os("NAS_WIRESHARK_CORPUS")
        .map_or_else(|| here.join("corpus.tsv"), PathBuf::from);
    let output = std::env::var_os("NAS_WIRESHARK_OUTPUT").map_or_else(
        // Beside the test program, in the target directory
        || {
            let program = std::env::current_exe().expect("the test program");
            program.parent().expect("its directory").join("wireshark")
        },
        PathBuf::from,
    );
    std::fs::create_dir_all(&output).expect("the output directory");

    let rows = std::fs::read_to_string(&corpus).expect("the corpus");
    let mut lines = String::new();
    for row in rows
        .lines()
        .filter(|row| !row.is_empty() && !row.starts_with('#'))
    {
        let columns: Vec<&str> = row.split('\t').collect();
        let (system, octets) = (columns[0], columns[columns.len() - 1]);
        let octets = hex::decode(octets).unwrap_or_else(|error| panic!("{row}: {error}"));
        writeln!(lines, "{}", reading(system, &octets)).expect("a line");
    }
    let readings = output.join("crate.jsonl");
    std::fs::write(&readings, lines).expect("the crate's readings");

    let status = Command::new("python3")
        .arg("-I")
        .arg(here.join("compare.py"))
        .arg("--corpus")
        .arg(&corpus)
        .arg("--crate")
        .arg(&readings)
        .arg("--mapping")
        .arg(here.join("mapping.tsv"))
        .arg("--known")
        .arg(here.join("known.tsv"))
        .arg("--output")
        .arg(&output)
        // A standard input of its own: tshark reads each capture from its
        // standard input, which a descriptor 0 left closed would take
        .stdin(Stdio::null())
        .status()
        .expect("python3 runs");
    assert!(
        status.success(),
        "Wireshark and the crate differ: {}",
        output.display()
    );
}
