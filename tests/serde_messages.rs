//! Inspection must retain every decoded field and wire-order bookkeeping.
#![cfg(feature = "serde")]

use oxirush_nas::{nas_5gs as f, nas_eps as e};

#[test]
fn all_5gs_fixtures_survive_json_without_wire_changes() {
    for line in include_str!("fixtures/nas-5gs.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let wire = hex::decode(hex).unwrap();
        let message = f::Nas5gsMessage::from_bytes(&wire).unwrap();
        let inspected = serde_json::to_value(&message).unwrap();
        let restored: f::Nas5gsMessage = serde_json::from_value(inspected).unwrap();
        assert_eq!(restored.to_bytes().unwrap(), wire, "{name}");
    }
}

#[test]
fn all_eps_fixtures_survive_json_without_wire_changes() {
    for line in include_str!("fixtures/nas-eps.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let wire = hex::decode(hex).unwrap();
        let direction = if name.starts_with("DetachRequestToUe") {
            e::Direction::Downlink
        } else {
            e::Direction::Uplink
        };
        let message = e::NasEpsMessage::from_bytes_with_direction(&wire, direction).unwrap();
        let inspected = serde_json::to_value(&message).unwrap();
        let restored: e::NasEpsMessage = serde_json::from_value(inspected).unwrap();
        assert_eq!(restored.to_bytes().unwrap(), wire, "{name}");
    }
}

#[test]
fn ignored_repeated_and_unknown_ie_order_survives_json() {
    // Service Accept: a retained known IE, an unknown IE, and an ignored repetition.
    let wire = hex::decode("7e004e500202006902123450020400").unwrap();
    let message = f::Nas5gsMessage::from_bytes(&wire).unwrap();
    assert_eq!(message.to_bytes().unwrap(), wire);
    let restored: f::Nas5gsMessage =
        serde_json::from_value(serde_json::to_value(message).unwrap()).unwrap();
    assert_eq!(restored.to_bytes().unwrap(), wire);
}

#[test]
fn a_document_may_omit_the_decode_bookkeeping() {
    fn strip(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                object.remove("unknown_ies");
                object.remove("optional_ie_order");
                object.values_mut().for_each(strip);
            }
            serde_json::Value::Array(array) => array.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let wire = hex::decode("7e004e").unwrap();
    let message = f::Nas5gsMessage::from_bytes(&wire).unwrap();
    let mut document = serde_json::to_value(message).unwrap();
    strip(&mut document);
    let restored: f::Nas5gsMessage = serde_json::from_value(document).unwrap();
    assert_eq!(restored.to_bytes().unwrap(), wire);
}
