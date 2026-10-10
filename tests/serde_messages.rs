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

/// An IE reads as a derived struct of its name does: errors name the IE
/// type, unknown fields are ignored and a sequence of the fields is accepted.
#[test]
fn an_ie_deserializes_as_a_struct_of_its_name() {
    use serde_json::{from_str, from_value, json};
    let error = |document| {
        from_value::<f::NasGprsTimer2>(document)
            .unwrap_err()
            .to_string()
    };
    assert_eq!(
        error(json!(5)),
        "invalid type: integer `5`, expected struct NasGprsTimer2"
    );
    assert_eq!(
        error(json!([0, 1])),
        "invalid length 2, expected struct NasGprsTimer2 with 3 elements"
    );
    assert_eq!(
        error(json!({"type_field": 0, "length": 1})),
        "missing field `value`"
    );
    assert_eq!(
        from_str::<e::NasEmmCause>(r#"{"value": 3, "value": 4}"#)
            .unwrap_err()
            .to_string(),
        "duplicate field `value` at line 1 column 20"
    );
    assert_eq!(
        error(json!("x")),
        "invalid type: string \"x\", expected struct NasGprsTimer2"
    );
    let timer: f::NasGprsTimer2 =
        from_value(json!({"type_field": 0, "length": 1, "value": [9], "other": 2})).unwrap();
    assert_eq!(timer, from_value(json!([0, 1, [9]])).unwrap());
    assert_eq!(timer, f::NasGprsTimer2::new(vec![9]));
}

/// A message that is written from the tree of a fixture is one of the same
/// tree: it means what the fixture means. Most are the same octets too; the
/// others have a value that does not decide its coding.
#[test]
fn every_fixture_is_shown_as_a_tree_and_written_from_it() {
    let (mut all, mut same_octets) = (0, 0);
    for line in include_str!("fixtures/nas-5gs.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let wire = hex::decode(hex).unwrap();
        let tree = f::Nas5gsMessage::from_bytes(&wire).unwrap().to_tree();
        let back = f::Nas5gsMessage::from_tree(tree.clone());
        let back = back.unwrap_or_else(|error| panic!("{name}: {error} from {tree}"));
        assert_eq!(back.to_tree(), tree, "{name}");
        all += 1;
        same_octets += usize::from(back.to_bytes().unwrap() == wire);
    }
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
        let tree = message.to_tree();
        let back = e::NasEpsMessage::from_tree(tree.clone());
        let back = back.unwrap_or_else(|error| panic!("{name}: {error} from {tree}"));
        assert_eq!(back.to_tree(), tree, "{name}");
        all += 1;
        same_octets += usize::from(back.to_bytes().unwrap() == wire);
    }
    assert!(
        all > 180 && same_octets * 10 >= all * 8,
        "{same_octets} of {all}"
    );
}
