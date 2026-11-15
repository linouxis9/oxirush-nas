//! The dictionaries of the fuzz targets that read octets, fuzz/nas-5gs.dict and
//! fuzz/nas-eps.dict, written from the message tables of the crate: the header of each
//! message type, and each optional IE of the tables whole (its IEI, the length
//! indicator of its format and the least value of its row, of zeros, or its IEI and
//! length indicator alone where that value is long). The fuzzer inserts them, so that
//! it writes IEs that a decoder reads from their first octet.
//!
//! The test fails where a committed dictionary is not the one that the tables write;
//! `NAS_WRITE_DICTIONARIES=1 cargo test --lib dictionaries` writes them.

extern crate std;

use crate::prelude::*;
use alloc::format;

type Ies = &'static [&'static [(
    &'static [&'static str],
    &'static str,
    &'static str,
    Option<&'static str>,
)]];

/// The dictionary of `system`: the headers of its message types, then its IEs.
fn dictionary(system: &str, headers: &[(&str, &[(&str, u8)])], ies: &[Ies]) -> String {
    let mut out = format!(
        "# The message types and IEs of the tables of src/nas_{system}: written by the test \
         `dictionaries` of src/dictionary_tests.rs.\n"
    );
    for (prefix, types) in headers {
        for (name, code) in *types {
            out.push_str(&format!("{name}=\"{prefix}\\x{code:02x}\"\n"));
        }
    }
    // Each optional IE once by its IEI and field, in the order of the octets of the IEI
    // and then of the name; the first row of a pair in the order of the tables.
    let mut rows: Vec<(String, &str, &str, usize)> = Vec::new();
    for table in ies.iter().flat_map(|messages| messages.iter()) {
        for (ieis, field, format, least) in table.iter() {
            let Some(least) = least.and_then(|least| least.parse::<usize>().ok()) else {
                continue;
            };
            for iei in ieis.iter() {
                let Some(hex) = iei.strip_prefix("0x").filter(|hex| hex.len() == 2) else {
                    continue;
                };
                rows.push((hex.to_ascii_lowercase(), field, format, least));
            }
        }
    }
    rows.sort_by(|a, b| (format!("{} {}", a.0, a.1)).cmp(&format!("{} {}", b.0, b.1)));
    rows.dedup_by(|b, a| a.0 == b.0 && a.1 == b.1);
    for (iei, field, format, least) in rows {
        let (header, indicator) = match format {
            "lve" => (
                3,
                format!("\\x{:02x}\\x{:02x}", (least - 3) / 256, (least - 3) % 256),
            ),
            "lv" => (2, format!("\\x{:02x}", least - 2)),
            _ => (1, String::new()),
        };
        let value = least - header;
        let zeros = match value {
            1..=16 => "\\x00".repeat(value),
            _ => String::new(),
        };
        out.push_str(&format!("{field}=\"\\x{iei}{indicator}{zeros}\"\n"));
    }
    out
}

fn check(path: &str, written: &str, committed: &str) {
    if std::env::var_os("NAS_WRITE_DICTIONARIES").is_some() {
        std::fs::write(path, written).unwrap();
        return;
    }
    assert!(
        written == committed,
        "{path} is not the dictionary that the tables write; \
         NAS_WRITE_DICTIONARIES=1 cargo test --lib dictionaries writes it"
    );
}

#[test]
fn dictionaries() {
    use crate::nas_5gs::{GmmMessage, GsmMessage};
    use crate::nas_eps::{EmmMessage, EsmMessage};
    let fgs = dictionary(
        "5gs",
        &[
            ("\\x7e\\x00", GmmMessage::DICTIONARY.0),
            ("\\x2e\\x05\\x01", GsmMessage::DICTIONARY.0),
        ],
        &[GmmMessage::DICTIONARY.1, GsmMessage::DICTIONARY.1],
    );
    let eps = dictionary(
        "eps",
        &[
            ("\\x07", EmmMessage::DICTIONARY.0),
            ("\\x52\\x01", EsmMessage::DICTIONARY.0),
        ],
        &[EmmMessage::DICTIONARY.1, EsmMessage::DICTIONARY.1],
    );
    let root = env!("CARGO_MANIFEST_DIR");
    check(
        &format!("{root}/fuzz/nas-5gs.dict"),
        &fgs,
        include_str!("../fuzz/nas-5gs.dict"),
    );
    check(
        &format!("{root}/fuzz/nas-eps.dict"),
        &eps,
        include_str!("../fuzz/nas-eps.dict"),
    );
}
