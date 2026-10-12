//! Inspection must retain every decoded field and wire-order bookkeeping.
#![cfg(feature = "serde")]

use oxirush_nas::{nas_5gs as f, nas_eps as e};
use serde_json::json;

#[test]
fn all_5gs_fixtures_survive_json_without_wire_changes() {
    for line in include_str!("fixtures/nas-5gs.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let wire = hex::decode(hex).unwrap();
        let message = f::Nas5gsMessage::decode(&wire).unwrap();
        let inspected = serde_json::to_value(&message).unwrap();
        let restored: f::Nas5gsMessage = serde_json::from_value(inspected).unwrap();
        assert_eq!(restored.encode().unwrap(), wire, "{name}");
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
        let message = e::NasEpsMessage::decode_with_direction(&wire, direction).unwrap();
        let inspected = serde_json::to_value(&message).unwrap();
        let restored: e::NasEpsMessage = serde_json::from_value(inspected).unwrap();
        assert_eq!(restored.encode().unwrap(), wire, "{name}");
    }
}

#[test]
fn ignored_repeated_and_unknown_ie_order_survives_json() {
    // Service Accept: a retained known IE, an unknown IE, and an ignored repetition.
    let wire = hex::decode("7e004e500202006902123450020400").unwrap();
    let message = f::Nas5gsMessage::decode(&wire).unwrap();
    assert_eq!(message.encode().unwrap(), wire);
    let restored: f::Nas5gsMessage =
        serde_json::from_value(serde_json::to_value(message).unwrap()).unwrap();
    assert_eq!(restored.encode().unwrap(), wire);
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
    let message = f::Nas5gsMessage::decode(&wire).unwrap();
    let mut document = serde_json::to_value(message).unwrap();
    strip(&mut document);
    let restored: f::Nas5gsMessage = serde_json::from_value(document).unwrap();
    assert_eq!(restored.encode().unwrap(), wire);
}

/// An IE reads as a derived struct of its name does: errors name the IE
/// type, unknown fields are ignored and a sequence of the fields is accepted.
#[test]
fn an_ie_deserializes_as_a_struct_of_its_name() {
    use serde_json::{from_str, from_value};
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
        error(json!([])),
        "invalid length 0, expected struct NasGprsTimer2 with 1 element"
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
    assert_eq!(timer, from_value(json!([[9]])).unwrap());
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
        let tree = f::Nas5gsMessage::decode(&wire).unwrap().to_tree();
        let back = f::Nas5gsMessage::from_tree(tree.clone());
        let back = back.unwrap_or_else(|error| panic!("{name}: {error} from {tree}"));
        assert_eq!(back.to_tree(), tree, "{name}");
        all += 1;
        same_octets += usize::from(back.encode().unwrap() == wire);
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
        let message = e::NasEpsMessage::decode_with_direction(&wire, direction).unwrap();
        let tree = message.to_tree();
        let back = e::NasEpsMessage::from_tree(tree.clone());
        let back = back.unwrap_or_else(|error| panic!("{name}: {error} from {tree}"));
        assert_eq!(back.to_tree(), tree, "{name}");
        all += 1;
        same_octets += usize::from(back.encode().unwrap() == wire);
    }
    assert!(
        all > 180 && same_octets * 10 >= all * 8,
        "{same_octets} of {all}"
    );
}

/// A tree is one that a message is written from, whatever the message: one
/// under a security header, and one that is ciphered.
#[test]
fn the_tree_of_a_protected_message_writes_it() {
    // 5GMM STATUS under an integrity header, then ciphered octets
    for wire in ["7e0101020304007e006416", "7e02010203040512345678"] {
        let message = f::Nas5gsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
        let tree = message.to_tree();
        assert!(tree.get("security-header").is_some(), "{tree}");
        let written = f::Nas5gsMessage::from_tree(tree.clone())
            .unwrap_or_else(|error| panic!("{error}: {tree}"));
        assert_eq!(written, message);
        assert_eq!(hex::encode(written.encode().unwrap()), wire);
    }
    // EMM STATUS under an integrity header, then ciphered octets
    for wire in ["17010203040007600f", "270102030405123456"] {
        let message = e::NasEpsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
        let tree = message.to_tree();
        assert!(tree.get("security-header").is_some(), "{tree}");
        let written = e::NasEpsMessage::from_tree(tree.clone())
            .unwrap_or_else(|error| panic!("{error}: {tree}"));
        assert_eq!(written, message);
        assert_eq!(hex::encode(written.encode().unwrap()), wire);
    }
    // The header is written whole, and a ciphered message by its octets
    // alone.
    let tree = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap();
    for refused in [
        r#"{"ciphered-message": {"octets": "1234"}}"#,
        r#"{"security-header": {"sequence-number": 0}, "message-type": "5gmm-status",
            "5gmm-cause": 22}"#,
        r#"{"security-header": {"extended-protocol-discriminator": 126,
            "security-header-type": "integrity-protected-and-ciphered", "spare-half-octet": 0,
            "message-authentication-code": 1, "sequence-number": 0},
            "ciphered-message": {"octets": "1234"}, "5gmm-cause": 22}"#,
    ] {
        assert!(
            f::Nas5gsMessage::from_tree(tree(refused)).is_err(),
            "{refused}"
        );
    }
}

/// The message that a tree writes has that tree, also where a value does
/// not say all of its octets: found by the `view_5gs` fuzz target. This
/// SECURITY MODE COMPLETE carries a REGISTRATION REQUEST whose mobile
/// identity is "no identity" with twelve more octets. The identity that
/// its value writes has one octet, which no REGISTRATION REQUEST has, so
/// the container is shown by its octets.
#[test]
fn a_container_whose_message_is_not_written_back_is_shown_by_its_octets() {
    let wire = hex::decode(
        "7e005e770009001532147698103254f67100137e004101000d300102f8390000000221436587f978\
         00084b09512430325701",
    )
    .unwrap();
    let message = f::Nas5gsMessage::decode(&wire).unwrap();
    let tree = message.to_tree();
    assert_eq!(
        tree["nas-message-container"],
        json!({"octets": "7e004101000d300102f8390000000221436587"})
    );
    let written = f::Nas5gsMessage::from_tree(tree.clone()).unwrap();
    assert_eq!(written.to_tree(), tree);
}

/// An EMM TRANSPORT has a view and a tree, which write it: found by the
/// `view_eps` fuzz target, which had `{}` for it.
#[test]
fn an_emm_transport_is_shown_and_written() {
    // Security header type 11, a code, a sequence number and two octets of
    // a container that is ciphered
    let wire = hex::decode("b7ffc3124100abcd").unwrap();
    let message = e::NasEpsMessage::decode(&wire).unwrap();
    let tree = message.to_tree();
    assert_eq!(
        tree,
        json!({
            "security-header": {
                "security-header-type": "emm-transport",
                "message-authentication-code": 0xffc3_1241_u32,
                "sequence-number": 0,
            },
            "ciphered-message": {"octets": "abcd"},
        })
    );
    assert_eq!(e::NasEpsMessage::from_tree(tree).unwrap(), message);
    assert_eq!(message.with_view(message.to_view()).unwrap(), message);
    assert_eq!(
        e::NasEpsMessage::from_view(message.to_view()).unwrap(),
        message
    );

    // Without a container, and with one that was deciphered
    let empty = e::NasEpsMessage::decode(&wire[..6]).unwrap();
    assert_eq!(e::NasEpsMessage::from_tree(empty.to_tree()).unwrap(), empty);
    let e::NasEpsMessage::EmmTransport(transport) = empty.clone() else {
        panic!("{empty:?}");
    };
    let plain = e::NasEpsMessage::EmmTransport(transport.set_data_container(vec![1, 2]));
    let tree = plain.to_tree();
    assert_eq!(tree["data-container"], json!({"octets": "0102"}));
    assert_eq!(e::NasEpsMessage::from_tree(tree).unwrap(), plain);
}
