//! The trees of the fixtures, as `tests/fixtures/trees.tsv` records them: for
//! each message, its tree, the octets of the message that the tree writes,
//! and whether the tree, given back to the message, leaves it as it is. A
//! change of how a message becomes a tree, or a tree a message, keeps every
//! line. `OXIRUSH_BLESS=1 cargo test --features tree --test trees` writes the
//! file again from the code.
#![cfg(feature = "tree")]

use oxirush_nas::tree::Takes;
use oxirush_nas::{DecodeOptions, Direction, nas_5gs, nas_eps};

/// Each message of the fixtures: its name, its system and direction, and its
/// octets.
fn messages() -> Vec<(String, bool, Direction, Vec<u8>)> {
    let mut messages = Vec::new();
    let lines = |text: &'static str| {
        text.lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split('\t').collect::<Vec<_>>())
    };
    for columns in lines(include_str!("fixtures/nas-5gs.tsv")) {
        let octets = hex::decode(columns[1]).unwrap();
        messages.push((
            format!("nas-5gs/{}", columns[0]),
            true,
            Direction::Downlink,
            octets,
        ));
    }
    for columns in lines(include_str!("fixtures/nas-eps.tsv")) {
        let direction = match columns[0].starts_with("DetachRequestUeTerminated") {
            true => Direction::Downlink,
            false => Direction::Uplink,
        };
        let octets = hex::decode(columns[1]).unwrap();
        messages.push((format!("nas-eps/{}", columns[0]), false, direction, octets));
    }
    for (at, columns) in lines(include_str!("fixtures/captured.tsv")).enumerate() {
        let five_gs = columns[0] == "5gs";
        let direction = match columns[2] {
            "downlink" => Direction::Downlink,
            _ => Direction::Uplink,
        };
        for (kind, column) in [("wire", 8), ("plain", 9)] {
            if let Some(octets) = columns.get(column).filter(|hex| !hex.is_empty()) {
                let name = format!("captured/{}/{}/{kind}", at + 1, columns[3]);
                messages.push((name, five_gs, direction, hex::decode(octets).unwrap()));
            }
        }
    }
    messages
}

/// What the tree of `message` is and writes, as a line of the file.
fn line<M>(
    name: &str,
    message: &M,
    to_tree: fn(&M) -> oxirush_nas::tree::Value,
    from_tree: fn(oxirush_nas::tree::Value) -> oxirush_nas::Result<M>,
    with_tree: fn(&M, oxirush_nas::tree::Value) -> oxirush_nas::Result<M>,
    encode: fn(&M) -> oxirush_nas::Result<Vec<u8>>,
) -> String
where
    M: PartialEq,
{
    let tree = to_tree(message);
    let written = match from_tree(tree.clone()).and_then(|written| encode(&written)) {
        Ok(octets) => hex::encode(octets),
        Err(error) => format!("error: {error}"),
    };
    let kept = match with_tree(message, tree.clone()) {
        Ok(edited) => (edited == *message).to_string(),
        Err(error) => format!("error: {error}"),
    };
    format!("{name}\t{tree}\t{written}\t{kept}")
}

fn lines() -> Vec<String> {
    let mut lines = Vec::new();
    for (name, five_gs, direction, octets) in messages() {
        let options = DecodeOptions::STRICT.with_direction(direction);
        if five_gs {
            match nas_5gs::Message::decode(&octets) {
                Ok(message) => lines.push(line(
                    &name,
                    &message,
                    nas_5gs::Message::to_tree,
                    nas_5gs::Message::from_tree,
                    nas_5gs::Message::with_tree,
                    nas_5gs::Message::encode,
                )),
                Err(error) => lines.push(format!("{name}\tdecode: {error}")),
            }
        } else {
            match nas_eps::Message::decode_with(&octets, options) {
                Ok(message) => lines.push(line(
                    &name,
                    &message,
                    nas_eps::Message::to_tree,
                    nas_eps::Message::from_tree,
                    nas_eps::Message::with_tree,
                    nas_eps::Message::encode,
                )),
                Err(error) => lines.push(format!("{name}\tdecode: {error}")),
            }
        }
    }
    lines
}

/// Every fixture has the tree, the written octets and the edit that the
/// file records.
#[test]
fn the_trees_of_the_fixtures_are_those_recorded() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/trees.tsv");
    let made = lines();
    if std::env::var_os("OXIRUSH_BLESS").is_some() {
        let header =
            "# name\ttree\toctets that the tree writes\twith_tree(to_tree) leaves it as it is\n";
        std::fs::write(path, header.to_owned() + &made.join("\n") + "\n").unwrap();
        return;
    }
    let recorded = std::fs::read_to_string(path).unwrap();
    let recorded: Vec<&str> = recorded
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert_eq!(recorded.len(), made.len(), "the number of fixtures");
    for (recorded, made) in recorded.iter().zip(&made) {
        assert_eq!(recorded, made);
    }
}

/// Whether `value` is one that `takes` says: each member of an object one of
/// its members, a name one of its names, a number up to its largest.
fn fits(value: &oxirush_nas::tree::Value, takes: &Takes) -> bool {
    use oxirush_nas::tree::{Value, same_name};
    match (takes, value) {
        (Takes::Flag, Value::Bool(_)) => true,
        (Takes::Number(most), Value::Number(number)) => number.as_u64().is_some_and(|n| n <= *most),
        (Takes::Signed(least, most), Value::Number(number)) => number
            .as_i64()
            .is_some_and(|n| (*least..=*most).contains(&n)),
        (Takes::Named(names), Value::String(name)) => {
            names.iter().any(|known| same_name(known, name))
        }
        (Takes::Octets(_), Value::String(_) | Value::Array(_) | Value::Number(_)) => true,
        (
            Takes::Text | Takes::Name | Takes::Digits | Takes::Ipv4 | Takes::Ipv6 | Takes::Plmn,
            Value::String(_),
        ) => true,
        (Takes::Message, Value::Object(message)) => message.contains_key("message-type"),
        (Takes::List(entry), Value::Array(entries)) => {
            entries.iter().all(|value| fits(value, entry))
        }
        (Takes::Members(_, members), Value::Object(written)) => {
            written.iter().all(|(name, value)| {
                (members.iter())
                    .find(|(member, _)| same_name(member, name))
                    .is_some_and(|(_, takes)| value.is_null() || fits(value, takes))
            })
        }
        (Takes::Members(Some(alone), members), value) => (members.iter())
            .find(|(member, _)| member == alone)
            .is_some_and(|(_, takes)| fits(value, takes)),
        (Takes::OneOf(forms), value) => forms.iter().any(|form| fits(value, form)),
        _ => false,
    }
}

/// Each IE of the tree of each message of the fixtures is a row of the table
/// of its message, and its value is one that the row says that it takes, or
/// its octets.
#[test]
fn each_ie_of_the_fixtures_takes_what_its_row_says() {
    use oxirush_nas::IeRow;
    let mut checked = 0;
    let mut messages = messages();
    // An UL NAS TRANSPORT of multiple payloads: a 5GSM message and an SMS.
    let multiple = hex::decode("7e00670f001602000e211201058001012e0501c1ffff910003020102").unwrap();
    messages.push((
        "multiple-payloads".into(),
        true,
        Direction::Uplink,
        multiple,
    ));
    let mut entries = 0;
    for (name, five_gs, direction, octets) in messages {
        let (rows, tree): (Vec<IeRow>, _) = match five_gs {
            true => match nas_5gs::Message::decode(&octets) {
                Ok(message @ nas_5gs::Message::Gmm(..))
                | Ok(message @ nas_5gs::Message::Gsm(..)) => {
                    let rows = match &message {
                        nas_5gs::Message::Gmm(header, _) => header.message_type.ies(),
                        nas_5gs::Message::Gsm(header, _) => header.message_type.ies(),
                        _ => unreachable!(),
                    };
                    (rows, message.to_tree())
                }
                _ => continue,
            },
            false => {
                let options = DecodeOptions::STRICT.with_direction(direction);
                match nas_eps::Message::decode_with(&octets, options) {
                    Ok(message @ nas_eps::Message::Emm(..))
                    | Ok(message @ nas_eps::Message::Esm(..)) => {
                        let rows = match &message {
                            nas_eps::Message::Emm(header, _) => header.message_type.ies(),
                            nas_eps::Message::Esm(header, _) => header.message_type.ies(),
                            _ => unreachable!(),
                        };
                        (rows, message.to_tree())
                    }
                    _ => continue,
                }
            }
        };
        let oxirush_nas::tree::Value::Object(members) = tree else {
            panic!("{name}")
        };
        for (ie, value) in &members {
            let Some(row) = rows.iter().find(|row| row.name == ie) else {
                continue;
            };
            let octets = value.get("octets").is_some();
            assert!(
                octets || fits(value, row.takes),
                "{name}: {ie} = {value} is not {:?}",
                row.takes
            );
            checked += 1;
            entries += usize::from(ie == "payload-container" && value.get("entries").is_some());
        }
    }
    assert_eq!(
        entries, 1,
        "the entries of a container of multiple payloads"
    );
    assert!(checked > 500, "{checked}");
}
