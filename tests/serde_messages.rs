//! The serde form of a message is its tree, and that of an IE what the tree
//! of a message shows of it.
#![cfg(feature = "serde")]

use oxirush_nas::tree;
use oxirush_nas::tree::Value;
use oxirush_nas::{nas_5gs as f, nas_eps as e};

/// Each fixture is its tree as a document, and the message that the
/// document gives back means what the fixture means.
#[test]
fn the_serde_form_of_each_fixture_is_its_tree() {
    for line in include_str!("fixtures/nas-5gs.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let message = f::Nas5gsMessage::decode(&hex::decode(hex).unwrap()).unwrap();
        let document = serde_json::to_value(&message).unwrap();
        assert_eq!(document, message.to_tree(), "{name}");
        let restored: f::Nas5gsMessage = serde_json::from_value(document).unwrap();
        assert!(restored.means_the_same(&message), "{name}");
    }
    for line in include_str!("fixtures/nas-eps.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let direction = if name.starts_with("DetachRequestUeTerminated") {
            e::Direction::Downlink
        } else {
            e::Direction::Uplink
        };
        let wire = hex::decode(hex).unwrap();
        let message = e::NasEpsMessage::decode_with_direction(&wire, direction).unwrap();
        let document = serde_json::to_value(&message).unwrap();
        assert_eq!(document, message.to_tree(), "{name}");
        let restored: e::NasEpsMessage = serde_json::from_value(document).unwrap();
        assert!(restored.means_the_same(&message), "{name}");
    }
}

/// The IEs that the table has no place for, a repetition and their order
/// are in the tree, and so in the document.
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

/// What a document cannot write is refused with the words of the tree, and
/// the name of the type.
#[test]
fn a_document_that_is_no_message_is_refused() {
    let error =
        serde_json::from_value::<f::Nas5gsMessage>(serde_json::json!({"message-type": "nope"}))
            .unwrap_err()
            .to_string();
    assert!(
        error.starts_with("this is not a value of Nas5gsMessage: "),
        "{error}"
    );
    assert!(error.contains("no message `nope`"), "{error}");
}

/// An IE is what the tree of a message shows of it: its value, where that
/// writes it back, or its octets; and a document of either writes it.
#[test]
fn the_serde_form_of_an_ie_is_its_value_in_a_tree() {
    use serde_json::from_value;
    // T3346 value of a 5GMM STATUS-like message: a GPRS timer 2 of 9 units
    // of 2 seconds.
    let timer = f::NasGprsTimer2::new(vec![9]);
    let reject =
        f::NasRegistrationReject::new(f::NasFGmmCause::new(22)).with_t3346_value(timer.clone());
    let tree = f::Nas5gsMessage::new_5gmm(reject).to_tree();
    assert_eq!(serde_json::to_value(&timer).unwrap(), tree["t3346-value"]);
    assert_eq!(
        from_value::<f::NasGprsTimer2>(tree["t3346-value"].clone().into()).unwrap(),
        timer
    );
    assert_eq!(
        from_value::<f::NasGprsTimer2>(serde_json::json!({"octets": "09"})).unwrap(),
        timer
    );
    // A cause by its name, an IE of one octet by its octet.
    let cause: f::NasFGmmCause = from_value(serde_json::json!("congestion")).unwrap();
    assert_eq!(cause.value, 22);
    assert_eq!(
        from_value::<f::NasFGmmCause>(serde_json::json!({"octets": "16"})).unwrap(),
        cause
    );
    // What the IE cannot be is refused, with the name of its type.
    let error = from_value::<f::NasFGmmCause>(serde_json::json!({"octets": "1617"}))
        .unwrap_err()
        .to_string();
    assert!(
        error.starts_with("this is not a value of NasFGmmCause: "),
        "{error}"
    );
    // A value of the types of the IEs is its form in a tree too.
    assert_eq!(
        serde_json::to_value(f::GmmCause::Congestion).unwrap(),
        tree!("congestion")
    );
    let value = serde_json::to_value(oxirush_nas::nas_eps::KeySetIdentifier::Native(3)).unwrap();
    assert_eq!(value, tree!({"native": 3}));
}

/// A message that is written from the tree of a fixture is one of the same
/// tree, and means what the fixture means: the two are compared below
/// their trees, IE by IE. Most are the same octets too; the others have a
/// value that says all that its octets mean and does not decide them.
#[test]
fn every_fixture_is_shown_as_a_tree_and_written_from_it() {
    let (mut all, mut same_octets) = (0, 0);
    for line in include_str!("fixtures/nas-5gs.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let wire = hex::decode(hex).unwrap();
        let message = f::Nas5gsMessage::decode(&wire).unwrap();
        let tree = message.to_tree();
        let back = f::Nas5gsMessage::from_tree(tree.clone());
        let back = back.unwrap_or_else(|error| panic!("{name}: {error} from {tree}"));
        assert_eq!(back.to_tree(), tree, "{name}");
        assert!(back.means_the_same(&message), "{name}: {tree}");
        all += 1;
        same_octets += usize::from(back.encode().unwrap() == wire);
    }
    for line in include_str!("fixtures/nas-eps.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let wire = hex::decode(hex).unwrap();
        let direction = if name.starts_with("DetachRequestUeTerminated") {
            e::Direction::Downlink
        } else {
            e::Direction::Uplink
        };
        let message = e::NasEpsMessage::decode_with_direction(&wire, direction).unwrap();
        let tree = message.to_tree();
        let back = e::NasEpsMessage::from_tree(tree.clone());
        let back = back.unwrap_or_else(|error| panic!("{name}: {error} from {tree}"));
        assert_eq!(back.to_tree(), tree, "{name}");
        assert!(back.means_the_same(&message), "{name}: {tree}");
        all += 1;
        same_octets += usize::from(back.encode().unwrap() == wire);
    }
    // The numbers that the front page of the documentation gives.
    assert_eq!((same_octets, all), (174, 191));
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
    let tree = |text: &str| text.parse::<Value>().unwrap();
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
/// its value writes has one octet, so the identity is shown by its octets,
/// in the tree of the message that the container carries.
#[test]
fn an_ie_that_its_value_does_not_write_back_is_shown_by_its_octets_in_a_container_too() {
    let wire = hex::decode(
        "7e005e770009001532147698103254f67100137e004101000d300102f8390000000221436587f978\
         00084b09512430325701",
    )
    .unwrap();
    let message = f::Nas5gsMessage::decode(&wire).unwrap();
    let tree = message.to_tree();
    assert_eq!(
        tree["nas-message-container"],
        tree!({
            "message-type": "registration-request",
            "5gs-registration-type": {
                "registration-type": "initial-registration",
                "follow-on-request": false,
            },
            "ngksi": {"native": 0},
            "5gs-mobile-identity": {"octets": "300102f8390000000221436587"},
        })
    );
    let written = f::Nas5gsMessage::from_tree(tree.clone()).unwrap();
    assert_eq!(written.to_tree(), tree);
    assert!(written.means_the_same(&message));
}

/// The second review's messages: each lost something through its tree. The
/// UMTS algorithms of the two capabilities are members of their values,
/// and an IE that has more than its value says is shown by its octets: a
/// capability with bits that the crate has no name for, a container with a
/// parameter that it does not read.
#[test]
fn a_tree_gives_back_what_the_review_saw_it_lose() {
    // ATTACH REQUEST whose UE network capability has UEA0, UEA1 and UIA1
    let wire = "0741710801101021436587f904e0e0c04000040201d011";
    let message = e::NasEpsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    let tree = message.to_tree();
    let capability = &tree["ue-network-capability"];
    assert_eq!(
        (&capability["eea"], &capability["eia"]),
        (&tree!([0, 1, 2]), &tree!([0, 1, 2]))
    );
    assert_eq!(
        (&capability["uea"], &capability["uia"]),
        (&tree!([0, 1]), &tree!([1]))
    );
    let written = e::NasEpsMessage::from_tree(tree).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);

    // The same capability in a REGISTRATION REQUEST of 5GS
    let wire = "7e004179000d0102f839f0ff000021436587f91704e0e0c040";
    let message = f::Nas5gsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    let tree = message.to_tree();
    let capability = &tree["s1-ue-network-capability"];
    assert_eq!(
        (&capability["uea"], &capability["uia"]),
        (&tree!([0, 1]), &tree!([1]))
    );
    let written = f::Nas5gsMessage::from_tree(tree).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);

    // Every bit of a capability set: the octets, which say them all
    for (wire, ie, octets) in [
        (
            "7e004179000d0102f839f0ff000021436587f9170dffffffffffffffffffffffffff",
            "s1-ue-network-capability",
            "ffffffffffffffffffffffffff",
        ),
        (
            "7e004179000d0102f839f0ff000021436587f9100dffffffffffffffffffffffffff",
            "5gmm-capability",
            "ffffffffffffffffffffffffff",
        ),
        (
            "7e004179000d0102f839f0ff000021436587f92e08ffffffffffffffff",
            "ue-security-capability",
            "ffffffffffffffff",
        ),
        (
            "7e004201012104ffffffff",
            "5gs-network-feature-support",
            "ffffffff",
        ),
        ("2e0101c1ffff2803ffffff", "5gsm-capability", "ffffff"),
        // A service-level-AA container with a parameter of a type that
        // the crate does not read
        ("2e0101d80003010131", "service-level-aa-container", "010131"),
        ("2e0101d80003feffff", "service-level-aa-container", "feffff"),
    ] {
        let message = f::Nas5gsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
        let tree = message.to_tree();
        assert_eq!(tree[ie], tree!({ "octets": octets }), "{wire}");
        let written = f::Nas5gsMessage::from_tree(tree).unwrap();
        assert_eq!(hex::encode(written.encode().unwrap()), wire);
    }
    for (wire, ie, octets) in [
        (
            "0741710801101021436587f90dffffffffffffffffffffffffff00040201d011",
            "ue-network-capability",
            "ffffffffffffffffffffffffff",
        ),
        // The replayed capability of the review: bit 8 of the octet of
        // the UMTS integrity algorithms is spare, and is set
        (
            "075d020005f0f0c0c07f",
            "replayed-ue-security-capabilities",
            "f0f0c0c07f",
        ),
    ] {
        let message = e::NasEpsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
        let tree = message.to_tree();
        assert_eq!(tree[ie], tree!({ "octets": octets }), "{wire}");
        let written = e::NasEpsMessage::from_tree(tree).unwrap();
        assert_eq!(hex::encode(written.encode().unwrap()), wire);
    }
    // Without that bit, each algorithm is in the value
    let wire = "075d020005f0f0c0607f";
    let message = e::NasEpsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    let tree = message.to_tree();
    let capability = &tree["replayed-ue-security-capabilities"];
    assert_eq!(
        (&capability["uea"], &capability["uia"], &capability["gea"]),
        (
            &tree!([0, 1]),
            &tree!([1, 2]),
            &tree!([1, 2, 3, 4, 5, 6, 7])
        )
    );
    let written = e::NasEpsMessage::from_tree(tree).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);
}

/// The members of the two capabilities of TS 24.301 are the bits of
/// Figures 9.9.3.34.1 and 9.9.3.36.1, each at its place: a value that sets
/// one member writes that bit alone, in an IE that ends with its octet.
#[test]
fn each_bit_of_the_capabilities_of_ts_24_301_has_its_member() {
    // The octets of the value, each with its bits 8 to 1
    let network: [[&str; 8]; 10] = [
        [
            "eea 0", "eea 1", "eea 2", "eea 3", "eea 4", "eea 5", "eea 6", "eea 7",
        ],
        [
            "eia 0", "eia 1", "eia 2", "eia 3", "eia 4", "eia 5", "eia 6", "eps-upip",
        ],
        [
            "uea 0", "uea 1", "uea 2", "uea 3", "uea 4", "uea 5", "uea 6", "uea 7",
        ],
        [
            "ucs2", "uia 1", "uia 2", "uia 3", "uia 4", "uia 5", "uia 6", "uia 7",
        ],
        [
            "prose-dd", "prose", "h245-ash", "acc-csfb", "lpp", "lcs", "srvcc-1x", "nf",
        ],
        [
            "epco",
            "hc-cp-ciot",
            "erw-opdn",
            "s1u-data",
            "up-ciot",
            "cp-ciot",
            "prose-relay",
            "prose-dc",
        ],
        [
            "fifteen-bearers",
            "sgc",
            "n1-mode",
            "dcnr",
            "cp-backoff",
            "restrict-ec",
            "v2x-pc5",
            "multiple-drb",
        ],
        [
            "rpr",
            "piv",
            "ncr",
            "v2x-nr-pc5",
            "up-mt-edt",
            "cp-mt-edt",
            "wusa",
            "racs",
        ],
        [
            "mint-eps",
            "ohr-cp-ciot",
            "sfso",
            "atuc",
            "rclin",
            "edc",
            "ptcc",
            "pr",
        ],
        ["", "", "", "", "", "", "", "non-sat-lsp"],
    ];
    let security: [[&str; 8]; 5] = [
        network[0],
        network[1],
        network[2],
        [
            "", "uia 1", "uia 2", "uia 3", "uia 4", "uia 5", "uia 6", "uia 7",
        ],
        [
            "", "gea 1", "gea 2", "gea 3", "gea 4", "gea 5", "gea 6", "gea 7",
        ],
    ];
    // The value that sets the member `member` alone
    let value = |member: &str| match member.split_once(' ') {
        Some((list, algorithm)) => tree!({ list: [algorithm.parse::<u8>().unwrap()] }),
        None => tree!({ member: true }),
    };
    // The octets that have the bit alone, in an IE of `least` octets or more
    let expected = |octet: usize, bit: usize, least: usize| {
        let mut octets = vec![0u8; (octet + 1).max(least)];
        octets[octet] = 0x80 >> bit;
        hex::encode(octets)
    };
    let mut names = 0;

    // ATTACH REQUEST and SECURITY MODE COMMAND of EPS
    let attach = eps("0741710801101021436587f902e0e000040201d011").to_tree();
    let command = eps("075d020002e0e0").to_tree();
    for (octet, bits) in network.iter().enumerate() {
        for (bit, member) in bits
            .iter()
            .enumerate()
            .filter(|(_, member)| !member.is_empty())
        {
            let mut tree = attach.clone();
            tree["ue-network-capability"] = value(member);
            let written = e::NasEpsMessage::from_tree(tree).unwrap();
            let octets = &written.to_view()["ue-network-capability"]["octets"];
            assert_eq!(*octets, tree!(expected(octet, bit, 2)), "{member}");
            assert_eq!(
                written.to_tree()["ue-network-capability"][member.split(' ').next().unwrap()],
                value(member)[member.split(' ').next().unwrap()]
            );
            names += 1;
        }
    }
    assert_eq!(names, 73);
    for (octet, bits) in security.iter().enumerate() {
        for (bit, member) in bits
            .iter()
            .enumerate()
            .filter(|(_, member)| !member.is_empty())
        {
            let mut tree = command.clone();
            tree["replayed-ue-security-capabilities"] = value(member);
            let written = e::NasEpsMessage::from_tree(tree).unwrap();
            let octets = &written.to_view()["replayed-ue-security-capabilities"]["octets"];
            // Octets 5 and 6 come together (§9.9.3.36)
            let least = if octet >= 2 { 4 } else { 2 };
            assert_eq!(*octets, tree!(expected(octet, bit, least)), "{member}");
        }
    }

    // The same two types in 5GS: REGISTRATION REQUEST and SECURITY MODE
    // COMMAND
    let request = fgs("7e004179000d0102f839f0ff000021436587f91702e0e0").to_tree();
    for (octet, bit, member) in [
        (2, 0, "uea 0"),
        (3, 7, "uia 7"),
        (3, 0, "ucs2"),
        (9, 7, "non-sat-lsp"),
    ] {
        let mut tree = request.clone();
        tree["s1-ue-network-capability"] = value(member);
        let written = f::Nas5gsMessage::from_tree(tree).unwrap();
        let octets = &written.to_view()["s1-ue-network-capability"]["octets"];
        assert_eq!(*octets, tree!(expected(octet, bit, 2)), "{member}");
    }
    let command = fgs("7e005d020002e0e01902e0e0").to_tree();
    for (octet, bit, member) in [(2, 7, "uea 7"), (3, 1, "uia 1"), (4, 7, "gea 7")] {
        let mut tree = command.clone();
        tree["replayed-s1-ue-security-capabilities"] = value(member);
        let written = f::Nas5gsMessage::from_tree(tree).unwrap();
        let octets = &written.to_view()["replayed-s1-ue-security-capabilities"]["octets"];
        assert_eq!(*octets, tree!(expected(octet, bit, 4)), "{member}");
    }
}

fn fgs(hex: &str) -> f::Nas5gsMessage {
    f::Nas5gsMessage::decode(&hex::decode(hex).unwrap()).unwrap()
}

fn eps(hex: &str) -> e::NasEpsMessage {
    e::NasEpsMessage::decode(&hex::decode(hex).unwrap()).unwrap()
}

/// What a value says all of and does not decide is written in one form,
/// and the message means the same: the unit of a timer of one octet and of
/// the rates of a session AMBR, the octets of zeros at the end of flags,
/// the partial lists of an EPS TAI list.
#[test]
fn a_value_that_does_not_decide_its_octets_is_written_in_one_form() {
    let fgs = |wire: &str| f::Nas5gsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    for (wire, ie, value, written) in [
        // T3346 of ten minutes counted in decihours, and written in minutes
        (
            "7e0044165f0141",
            "t3346-value",
            tree!(360),
            "7e0044165f0126",
        ),
        // A deactivated timer whose count is not zero
        (
            "7e0044165f01e5",
            "t3346-value",
            tree!("deactivated"),
            "7e0044165f01e0",
        ),
        // IMS voice over PS in an octet that a second octet of zeros follows
        (
            "7e0042010121020100",
            "5gs-network-feature-support",
            Value::Null,
            "7e00420101210101",
        ),
    ] {
        let message = fgs(wire);
        let tree = message.to_tree();
        if !value.is_null() {
            assert_eq!(tree[ie], value, "{wire}");
        }
        assert!(tree[ie].get("octets").is_none(), "{wire}: {tree}");
        let back = f::Nas5gsMessage::from_tree(tree).unwrap();
        assert_eq!(hex::encode(back.encode().unwrap()), written, "{wire}");
        assert!(back.means_the_same(&message) && back != message, "{wire}");
    }
    // PDU SESSION ESTABLISHMENT ACCEPT with a session AMBR of 100 Mbit/s
    // and 50 Mbit/s, counted in Mbit/s and written in units of 4 Mbit/s
    // and of 1 Mbit/s
    let wire = "2e0101c211000901000631310101ff0106060064060032";
    let message = fgs(wire);
    let tree = message.to_tree();
    assert_eq!(
        tree["session-ambr"],
        tree!({"dl-kbps": 100_000, "ul-kbps": 50_000})
    );
    let back = f::Nas5gsMessage::from_tree(tree).unwrap();
    assert_eq!(
        hex::encode(back.encode().unwrap()),
        wire.replace("060064060032", "070019060032")
    );
    assert!(back.means_the_same(&message) && back != message);
    // A unit that the table does not have is not one that a rate says
    let odd = fgs(&wire.replace("060064060032", "ff0064060032"));
    assert_eq!(
        odd.to_tree()["session-ambr"],
        tree!({"octets": "ff0064060032"})
    );

    // An EPS TAI list has its partial lists, as one of 5GS has them, and
    // gives back its octets
    let wire = "07490054060002f8390001";
    let message = e::NasEpsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    let tree = message.to_tree();
    assert_eq!(
        tree["tai-list"],
        tree!([{"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1]}}])
    );
    let back = e::NasEpsMessage::from_tree(tree).unwrap();
    assert_eq!(hex::encode(back.encode().unwrap()), wire);

    // What means another thing is another message
    let reject = fgs("7e0044165f0141");
    for other in [
        "7e0044165f0142",
        "7e0044165f01e0",
        "7e0044165f024100",
        "7e0044165f01",
    ] {
        let Ok(other) = f::Nas5gsMessage::decode(&hex::decode(other).unwrap()) else {
            continue;
        };
        assert!(!reject.means_the_same(&other), "{other:?}");
    }
    assert!(!fgs("7e0042010121020100").means_the_same(&fgs("7e0042010121020101")));
}

/// The IEs that the table of a message has no place for are in its tree,
/// by their octets and in their order, and are written after the others.
#[test]
fn the_ies_that_a_table_has_no_place_for_are_in_the_tree() {
    // SERVICE ACCEPT: a PDU session status, an IE that the table does not
    // have, and the status a second time
    let wire = "7e004e500202006902123450020400";
    let message = f::Nas5gsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    let tree = message.to_tree();
    assert_eq!(
        tree,
        tree!({
            "message-type": "service-accept",
            "pdu-session-status": [1],
            "unknown-ies": "69021234 50020400",
        })
    );
    assert_eq!(
        message.to_view()["unknown-ies"],
        tree!({"value": "69021234 50020400"})
    );
    let written = f::Nas5gsMessage::from_tree(tree.clone()).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);

    // The unknown IE before the status: it is written after it, and a
    // receiver reads the same
    let wire = "7e004e6902123450020200";
    let message = f::Nas5gsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    let written = f::Nas5gsMessage::from_tree(message.to_tree()).unwrap();
    assert_eq!(
        hex::encode(written.encode().unwrap()),
        "7e004e5002020069021234"
    );
    assert!(written.means_the_same(&message));
    let read = f::Nas5gsMessage::decode(&written.encode().unwrap()).unwrap();
    assert!(read.means_the_same(&message));
    // Another IE, or another order of two of them, is another message
    let other = f::Nas5gsMessage::decode(&hex::decode("7e004e6902123550020200").unwrap()).unwrap();
    assert!(!other.means_the_same(&message));

    // Written by hand, in a tree and in a view
    let mut tree = tree!({"message-type": "registration-complete", "unknown-ies": "c0 6a0101"});
    let complete = f::Nas5gsMessage::from_tree(tree.clone()).unwrap();
    assert_eq!(hex::encode(complete.encode().unwrap()), "7e0043c06a0101");
    let plain = f::Nas5gsMessage::decode(&[0x7e, 0x00, 0x43]).unwrap();
    let mut view = plain.to_view();
    view["unknown-ies"] = tree!({"value": "c0"});
    let edited = plain.with_view(view).unwrap();
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e0043c0");
    // A view that leaves the entry as it is keeps the order that was received
    let message = f::Nas5gsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    assert_eq!(message.with_view(message.to_view()).unwrap(), message);

    // What is no list of octets is refused
    for refused in [
        tree!(["c0"]),
        tree!("zz"),
        tree!("c0  c1"),
        tree!("c"),
        tree!(12),
        tree!({"octets": "c0"}),
    ] {
        tree["unknown-ies"] = refused.clone();
        assert_eq!(
            f::Nas5gsMessage::from_tree(tree.clone())
                .unwrap_err()
                .to_string(),
            "cannot encode: `unknown-ies` is the IEs by their octets in hexadecimal, each with \
             its IEI first, with a space between two of them",
            "{refused}"
        );
    }
    // EPS has the same entry
    let wire = "07446f6a0101";
    let message = e::NasEpsMessage::decode(&hex::decode(wire).unwrap()).unwrap();
    let tree = message.to_tree();
    assert_eq!(tree["unknown-ies"], tree!("6a0101"));
    let written = e::NasEpsMessage::from_tree(tree).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);
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
        tree!({
            "security-header": {
                "security-header-type": "security-header-for-the-emm-transport-message",
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
    assert_eq!(tree["data-container"], tree!({"octets": "0102"}));
    assert_eq!(e::NasEpsMessage::from_tree(tree).unwrap(), plain);
}
