//! The trees of the fixtures, as `tests/fixtures/trees.tsv` records them: for
//! each message, its tree, the octets of the message that the tree writes,
//! and whether the tree, given back to the message, leaves it as it is. A
//! change of how a message becomes a tree, or a tree a message, keeps every
//! line. `OXIRUSH_BLESS=1 cargo test --features tree --test trees` writes the
//! file again from the code.
#![cfg(feature = "tree")]

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
