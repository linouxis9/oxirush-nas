//! The tree of a message: each IE by its name, with its value or its octets,
//! and the messages that trees write.

use crate::prelude::*;
use crate::tree;
use crate::tree::Value;
use crate::{nas_5gs as f, nas_eps as e};

/// The part of `value` that the JSON pointer `pointer` names.
fn pointer<'v>(value: &'v Value, pointer: &str) -> Option<&'v Value> {
    pointer
        .split('/')
        .skip(1)
        .try_fold(value, |value, part| match value {
            Value::Object(members) => members.get(part),
            Value::Array(items) => items.get(part.parse::<usize>().ok()?),
            _ => None,
        })
}

/// The part of `value` that the JSON pointer `pointer` names, to change it.
fn pointer_mut<'v>(value: &'v mut Value, pointer: &str) -> Option<&'v mut Value> {
    pointer
        .split('/')
        .skip(1)
        .try_fold(value, |value, part| match value {
            Value::Object(members) => members.get_mut(part),
            Value::Array(items) => items.get_mut(part.parse::<usize>().ok()?),
            _ => None,
        })
}

fn fgs(hex: &str) -> f::Message {
    f::Message::decode(&hex::decode(hex).unwrap()).unwrap()
}

fn eps(hex: &str) -> e::Message {
    e::Message::decode(&hex::decode(hex).unwrap()).unwrap()
}

/// The octets of the 5GS message of an edited tree.
fn fgs_edited(message: &f::Message, edit: impl FnOnce(&mut Value)) -> Result<String, String> {
    let mut tree = message.to_tree();
    edit(&mut tree);
    let edited = message.with_tree(tree).map_err(|error| error.to_string())?;
    Ok(hex::encode(edited.encode().unwrap()))
}

fn eps_edited(message: &e::Message, edit: impl FnOnce(&mut Value)) -> Result<String, String> {
    let mut tree = message.to_tree();
    edit(&mut tree);
    let edited = message.with_tree(tree).map_err(|error| error.to_string())?;
    Ok(hex::encode(edited.encode().unwrap()))
}

/// A message of either system, as the tests read it.
trait Read {
    fn tree(&self) -> Value;
    fn octets(&self, name: &str) -> Option<Vec<Value>>;
}

impl Read for f::Message {
    fn tree(&self) -> Value {
        self.to_tree()
    }

    fn octets(&self, name: &str) -> Option<Vec<Value>> {
        self.select(&format!("/nas/{name}/octets")).ok()
    }
}

impl Read for e::Message {
    fn tree(&self) -> Value {
        self.to_tree()
    }

    fn octets(&self, name: &str) -> Option<Vec<Value>> {
        self.select(&format!("/nas/{name}/octets")).ok()
    }
}

/// What the tree of `message` has of the IE `name`: `{"value": …}` where
/// the tree has the value of the IE, with the octets that the message has of
/// it, or the `{"octets": …}` of the tree.
fn ie(message: &impl Read, name: &str) -> Value {
    let member = message.tree()[name].clone();
    if member.is_null() || member.get("octets").is_some() {
        return member;
    }
    match message.octets(name).as_deref() {
        Some([octets]) => tree!({"value": member, "octets": octets}),
        _ => tree!({ "value": member }),
    }
}

fn fixtures(file: &str) -> impl Iterator<Item = (&str, Vec<u8>)> {
    file.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split_once('\t').unwrap())
        .map(|(name, hex)| (name, hex::decode(hex).unwrap()))
}

fn eps_fixture(name: &str, wire: &[u8]) -> e::Message {
    let direction = if name.starts_with("DetachRequestUeTerminated") {
        crate::Direction::Downlink
    } else {
        crate::Direction::Uplink
    };
    e::Message::decode_with(wire, crate::DecodeOptions::STRICT.with_direction(direction)).unwrap()
}

#[test]
fn a_coded_value_reads_and_writes_by_its_name() {
    // 5GMM STATUS, cause #22.
    let status = fgs("7e006416");
    assert_eq!(
        status.to_tree(),
        tree!({"message-type": "5gmm-status", "5gmm-cause": "congestion"})
    );
    assert_eq!(
        ie(&status, "5gmm-cause"),
        tree!({"value": "congestion", "octets": "16"})
    );
    let named = |name: Value| fgs_edited(&status, |tree| tree["5gmm-cause"] = name);
    assert_eq!(named(tree!("illegal-ue")).unwrap(), "7e006403");
    // A name is read in any case, with hyphens, underscores or spaces.
    for name in ["Illegal UE", "ILLEGAL_UE", "IllegalUe"] {
        assert_eq!(named(tree!(name)).unwrap(), "7e006403", "{name}");
    }
    // A value the specification does not name is a number, read and written,
    // also in hexadecimal.
    assert_eq!(named(tree!(200)).unwrap(), "7e0064c8");
    assert_eq!(named(tree!("0xc8")).unwrap(), "7e0064c8");
    assert_eq!(
        ie(&fgs("7e0064c8"), "5gmm-cause"),
        tree!({"value": 200, "octets": "c8"})
    );
    // A name that does not exist is an error that lists those that do.
    let error = named(tree!("congestio")).unwrap_err();
    assert!(
        error.contains("5gmm-cause: no name `congestio`; the nearest of its 50 is congestion"),
        "{error}"
    );
    // The number of a cause that has a name is that cause.
    assert_eq!(named(tree!(22)).unwrap(), "7e006416");
    assert_eq!(named(tree!(3)).unwrap(), "7e006403");
    // Nothing else is a cause.
    for value in [tree!(256), tree!({"cause": "illegal-ue"}), tree!(true)] {
        assert!(named(value.clone()).is_err(), "{value}");
    }
}

#[test]
fn the_octets_of_an_ie_are_written_as_they_are() {
    let status = fgs("7e006416");
    let edit = |ie: Value| fgs_edited(&status, |tree| tree["5gmm-cause"] = ie);
    assert_eq!(edit(tree!({"octets": "03"})).unwrap(), "7e006403");
    for ie in [
        tree!({"octets": "0304"}),
        tree!({"octets": "3"}),
        tree!({"octets": [3]}),
        tree!({"octets": null}),
    ] {
        assert!(edit(ie.clone()).is_err(), "{ie}");
    }

    // REGISTRATION ACCEPT with a 5G-GUTI: any octets, and the length follows.
    let accept = fgs("7e0042010177000bf202f83901004211223344");
    let mut tree = accept.to_tree();
    tree["5g-guti"] = tree!({"octets": "f2ffffff"});
    let odd = accept.with_tree(tree).unwrap();
    assert_eq!(
        hex::encode(odd.encode().unwrap()),
        "7e00420101770004f2ffffff"
    );
    // Octets that are no identity have no value, and can be given one.
    assert_eq!(odd.to_tree()["5g-guti"], tree!({"octets": "f2ffffff"}));
    let imei = |digits: &str| fgs_edited(&odd, |tree| tree["5g-guti"] = tree!({"imei": digits}));
    assert_eq!(
        imei("356938035643809").unwrap(),
        "7e004201017700083b65390853468390"
    );
    assert!(imei("1").is_err());

    // PDU SESSION ESTABLISHMENT REQUEST, whose integrity protection maximum data
    // rate is two octets
    let establishment = fgs("2e0501c1ffff");
    let rate = |octets: &str| {
        fgs_edited(&establishment, |tree| {
            tree["integrity-protection-maximum-data-rate"] = tree!({"octets": octets});
        })
    };
    assert_eq!(rate("0101"), Ok("2e0501c10101".into()));
    let error = rate("010203").unwrap_err();
    assert!(error.contains("is not two octets"), "{error}");
}

#[test]
fn the_fields_of_an_octet_read_and_write_by_name() {
    // REGISTRATION REQUEST: initial registration, follow-on request, no key.
    let request = fgs("7e004179000d0102f8390000000000000010022e08a020000000000000");
    assert_eq!(
        ie(&request, "5gs-registration-type"),
        tree!({"octets": "09", "value": {
            "registration-type": "initial-registration",
            "follow-on-request": true,
        }})
    );
    // The ngKSI is the other half of the octet, an IE of its own.
    assert_eq!(
        ie(&request, "ngksi"),
        tree!({"octets": "07", "value": "no-key"})
    );
    let edited = fgs_edited(&request, |tree| {
        let value = &mut tree["5gs-registration-type"];
        value["registration-type"] = tree!("mobility-registration-updating");
        value["follow-on-request"] = tree!(false);
    });
    assert_eq!(&edited.unwrap()[..8], "7e004172");
    // The members that are written are set, the others stay.
    let edited = fgs_edited(&request, |tree| {
        tree["5gs-registration-type"] = tree!({"Registration Type": "emergency registration"});
    });
    assert_eq!(&edited.unwrap()[..8], "7e00417c");
    // The number of a type that has a name is that type.
    let edited = fgs_edited(&request, |tree| {
        tree["5gs-registration-type"]["registration-type"] = tree!(2);
    });
    assert_eq!(&edited.unwrap()[6..8], "7a");
    for (member, value) in [
        ("registration-type", tree!("mobility")),
        ("registration-type", tree!(8)),
        ("follow-on-request", tree!(1)),
        ("follow-on", tree!(true)),
        ("ngksi", tree!(8)),
    ] {
        let edited = fgs_edited(&request, |tree| {
            tree["5gs-registration-type"][member] = value;
        });
        assert!(edited.is_err(), "{member}");
    }
}

#[test]
fn the_service_type_of_a_service_request_is_beside_the_ngksi() {
    // SERVICE REQUEST: signalling, native ngKSI 1.
    let request = fgs("7e004c010007f4004211223344");
    assert_eq!(
        ie(&request, "ngksi"),
        tree!({"octets": "01", "value": {"native": 1}})
    );
    assert_eq!(
        ie(&request, "service-type"),
        tree!({"octets": "00", "value": "signalling"})
    );
    assert_eq!(
        request.to_tree()["5g-s-tmsi"],
        tree!({"s-tmsi": {"amf-set-id": 1, "amf-pointer": 2, "tmsi": 0x1122_3344}})
    );
    let edited = fgs_edited(&request, |tree| {
        tree["service-type"] = tree!("data");
        tree["ngksi"] = tree!("no-key");
    });
    assert_eq!(edited.unwrap(), "7e004c170007f4004211223344");
    // Service type 7 has no name: it is its number, or the octets.
    assert_eq!(
        fgs("7e004c710007f4004211223344").to_tree()["service-type"],
        tree!(7)
    );
    let numbered = |number: u8| fgs_edited(&request, |tree| tree["service-type"] = tree!(number));
    assert_eq!(numbered(7).unwrap(), "7e004c710007f4004211223344");
    // The number of a type that has a name is that type.
    assert_eq!(numbered(1).unwrap(), "7e004c110007f4004211223344");
    let error = numbered(16).unwrap_err();
    assert!(error.contains("service"), "{error}");
    assert_eq!(
        fgs_edited(&request, |tree| tree["service-type"] =
            tree!({"octets": "07"}))
        .unwrap(),
        "7e004c710007f4004211223344"
    );
    // The ngKSI is the same IE in the other messages.
    assert_eq!(
        fgs("7e005d220102f070").to_tree()["ngksi"],
        tree!({"native": 1})
    );
}

#[test]
fn a_structured_ie_reads_and_writes_in_its_usual_notation() {
    // REGISTRATION ACCEPT with a 5G-GUTI, a TAI list, an allowed NSSAI and
    // T3512.
    let accept = fgs("7e0042010177000bf202f8390100421122334454070002f839000001150201015e0121");
    let tree = accept.to_tree();
    assert_eq!(
        tree["5gs-registration-result"]["result"],
        tree!("3gpp-access")
    );
    assert_eq!(
        ie(&accept, "5g-guti"),
        tree!({"octets": "f202f83901004211223344", "value": {"guti": {
            "plmn": "208-93",
            "amf-region-id": 1,
            "amf-set-id": 1,
            "amf-pointer": 2,
            "tmsi": 0x1122_3344,
        }}})
    );
    assert_eq!(
        tree["tai-list"],
        tree!([{"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1]}}])
    );
    assert_eq!(
        ie(&accept, "allowed-nssai"),
        tree!({"octets": "0101", "value": [{"sst": 1}]})
    );
    // One hour, in seconds.
    assert_eq!(
        ie(&accept, "t3512-value"),
        tree!({"octets": "21", "value": 3600})
    );

    let edited = fgs_edited(&accept, |tree| {
        tree["5g-guti"]["guti"]["plmn"] = tree!("001-01");
        tree["5g-guti"]["guti"]["tmsi"] = tree!("0xdeadbeef");
        tree["tai-list"] = tree!([{"one-plmn-consecutive":
            {"plmn": "310-410", "first-tac": 42, "count": 3}}]);
        tree["allowed-nssai"] = tree!([{"sst": 1, "sd": "010203"}, {"SST": 2}]);
        tree["t3512-value"] = tree!("deactivated");
    });
    assert_eq!(
        edited.unwrap(),
        "7e0042010177000bf200f110010042deadbeef540722130014\
         00002a150704010102030102\
         5e01e0"
    );
    // A member that a value does not have is not ignored, nor a value that
    // its IE cannot carry, nor a notation that is not the one of the value.
    for (pointer, value) in [
        ("/5g-guti/guti/tmsy", tree!(1)),
        ("/5g-guti/guti/amf-set-id", tree!(5000)),
        ("/5g-guti/guti/plmn", tree!("20893")),
        (
            "/5g-guti/guti/plmn",
            tree!({"mcc": [2, 0, 8], "mnc": [9, 3, 15]}),
        ),
        ("/allowed-nssai/0/sd", tree!("0102")),
        ("/allowed-nssai", tree!([])),
        ("/t3512-value", tree!(7)),
        ("/t3512-value", tree!("stopped")),
        ("/tai-list/0/one-plmn-non-consecutive/tacs", tree!([])),
    ] {
        let mut tree = accept.to_tree();
        match pointer_mut(&mut tree, pointer) {
            Some(member) => *member = value,
            None => {
                let (parent, member) = pointer.rsplit_once('/').unwrap();
                pointer_mut(&mut tree, parent).unwrap()[member] = value;
            }
        }
        assert!(accept.with_tree(tree).is_err(), "{pointer}");
    }
}

#[test]
fn a_container_of_a_message_reads_and_writes_as_its_tree() {
    // UL NAS TRANSPORT with a PDU SESSION ESTABLISHMENT REQUEST for the DNN
    // "internet".
    let transport = fgs(
        "7e00670100152e0101c1ffff91a12801007b000780000a00000d00120181220101250908696e7465726e6574",
    );
    let tree = transport.to_tree();
    assert_eq!(tree["payload-container-type"], tree!("n1-sm-information"));
    assert_eq!(
        ie(&transport, "dnn"),
        tree!({"octets": "08696e7465726e6574", "value": "internet"})
    );
    let request = &tree["payload-container"];
    assert_eq!(
        request["message-type"],
        tree!("pdu-session-establishment-request")
    );
    assert_eq!(request["pdu-session-identity"], tree!(1));
    assert_eq!(request["pdu-session-type"], tree!("ipv4"));
    assert_eq!(request["ssc-mode"], tree!("ssc1"));
    assert_eq!(
        request["integrity-protection-maximum-data-rate"],
        tree!({"ul": "full-rate", "dl": "full-rate"})
    );
    let edited = fgs_edited(&transport, |tree| {
        let request = &mut tree["payload-container"];
        request["pdu-session-identity"] = tree!(5);
        request["pdu-session-type"] = tree!("IPv4v6");
        request.as_object_mut().unwrap().shift_remove("ssc-mode");
        tree["dnn"] = tree!("ims.example");
    });
    assert_eq!(
        edited.unwrap(),
        "7e00670100142e0501c1ffff932801007b000780000a00000d0012018122010125\
         0c03696d73076578616d706c65"
    );
    let error = fgs_edited(&transport, |tree| {
        tree["payload-container"]["pdu-session-type"] = tree!("ipv5");
    });
    assert!(
        error
            .unwrap_err()
            .contains("payload-container: pdu-session-type: no name `ipv5`")
    );
    // A payload of another type, and a ciphered message, have octets alone.
    let lpp = fgs("7e00670300020102");
    assert_eq!(
        lpp.to_tree()["payload-container"],
        tree!({"octets": "0102"})
    );
    let complete = fgs("7e005e7100087e02000000000102");
    assert_eq!(
        complete.to_tree()["nas-message-container"],
        tree!({"octets": "7e02000000000102"})
    );
    // SECURITY MODE COMPLETE with the REGISTRATION REQUEST it replays.
    let complete = fgs("7e005e7100137e004101000d0102f8390000000021436587f9");
    let replayed = &complete.to_tree()["nas-message-container"];
    assert_eq!(replayed["message-type"], tree!("registration-request"));
    assert_eq!(
        replayed["5gs-mobile-identity"]["suci"]["imsi"]["msin"],
        tree!("123456789")
    );
}

#[test]
fn an_ie_is_taken_out_and_none_is_made_up() {
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let remove = |name: &str| {
        fgs_edited(&accept, |tree| {
            tree.as_object_mut().unwrap().shift_remove(name).unwrap();
        })
    };
    assert_eq!(
        remove("allowed-nssai").unwrap(),
        "7e0042010177000bf202f83901004211223344"
    );
    assert_eq!(
        remove("5g-guti").unwrap(),
        "7e00420101150201 01".replace(' ', "")
    );
    // A mandatory IE and a field of the header stay.
    let error = remove("5gs-registration-result").unwrap_err();
    assert!(
        error.contains("`5gs-registration-result` is mandatory"),
        "{error}"
    );
    let error = remove("message-type").unwrap_err();
    assert!(error.contains("`message-type` is the header"), "{error}");
    // A name is the one of an IE that the message has.
    let add = |name: &str, ie: Value| fgs_edited(&accept, |tree| tree[name] = ie);
    let error = add("allowed-nsai", tree!({"octets": "0101"})).unwrap_err();
    assert!(
        error.contains("no IE `allowed-nsai`; the nearest of its 64 is allowed-nssai"),
        "{error}"
    );
    let mut twice = accept.to_tree();
    twice["Allowed NSSAI"] = tree!({"octets": "0101"});
    let error = f::Message::from_tree(twice).unwrap_err().to_string();
    assert!(error.contains("named twice"), "{error}");
    // An IE is named in any case, and by the name of its field in the codec.
    for name in ["Allowed NSSAI", "allowed_nssai", "ALLOWED-NSSAI", "5G_GUTI"] {
        let mut tree = accept.to_tree();
        let known = (tree.as_object().unwrap().keys())
            .find(|known| crate::common::readable::same_name(known, name))
            .cloned()
            .unwrap();
        let ie = tree.as_object_mut().unwrap().shift_remove(&known).unwrap();
        tree[name] = ie;
        assert_eq!(accept.with_tree(tree.clone()).unwrap(), accept, "{name}");
        assert_eq!(f::Message::from_tree(tree).unwrap(), accept, "{name}");
    }
    // The fields of the header are written by their value.
    let request = fgs("2e0101c1ffff91");
    let edited = fgs_edited(&request, |tree| {
        tree["pdu-session-identity"] = tree!(15);
        tree["procedure-transaction-identity"] = tree!("0x2a");
    });
    assert_eq!(edited.unwrap(), "2e0f2ac1ffff91");
    assert!(
        fgs_edited(&request, |tree| tree["message-type"] =
            tree!({"octets": "c1"}))
        .is_err()
    );
}

#[test]
fn a_tree_is_read_through_a_security_header_which_it_shows() {
    // Integrity protected 5GMM STATUS.
    let protected = fgs("7e01aabbccdd057e006416");
    let tree = protected.to_tree();
    assert_eq!(tree["message-type"], tree!("5gmm-status"));
    assert_eq!(tree["5gmm-cause"], tree!("congestion"));
    // The header that protects the message is beside it, without what the
    // system decides.
    assert_eq!(
        tree["security-header"],
        tree!({
            "security-header-type": "integrity-protected",
            "message-authentication-code": 0xaabb_ccdd_u32,
            "sequence-number": 5,
        })
    );
    assert_eq!(protected.with_tree(tree).unwrap(), protected);
    // The code is that of the message as it was: an edit of the message
    // writes another, and the header is edited as any other value.
    let cause = |tree: &mut Value| tree["5gmm-cause"] = tree!("illegal-ue");
    let error = fgs_edited(&protected, cause).unwrap_err();
    assert!(error.contains("message authentication code"), "{error}");
    let edited = fgs_edited(&protected, |tree| {
        cause(tree);
        tree["security-header"]["message-authentication-code"] = tree!("0x01020304");
    });
    assert_eq!(edited.unwrap(), "7e0101020304057e006403");
    let edited = fgs_edited(&protected, |tree| {
        tree["security-header"]["sequence-number"] = tree!(6);
    });
    assert_eq!(edited.unwrap(), "7e01aabbccdd067e006416");
    let error = fgs_edited(&protected, |tree| {
        tree.as_object_mut()
            .unwrap()
            .shift_remove("security-header");
    });
    assert!(error.unwrap_err().contains("security-header: "));
    // A ciphered message has its octets, and no IE to show.
    let ciphered = fgs("7e0200000000001234");
    let tree = ciphered.to_tree();
    assert_eq!(tree["ciphered-message"], tree!({"octets": "1234"}));
    assert_eq!(
        tree["security-header"]["security-header-type"],
        tree!("integrity-protected-and-ciphered")
    );
    assert_eq!(tree.as_object().unwrap().len(), 2);
    assert_eq!(ciphered.with_tree(tree).unwrap(), ciphered);
    let octets = |tree: &mut Value| tree["ciphered-message"] = tree!({"octets": "5678"});
    let error = fgs_edited(&ciphered, octets).unwrap_err();
    assert!(error.contains("message authentication code"), "{error}");
    let edited = fgs_edited(&ciphered, |tree| {
        octets(tree);
        tree["security-header"]["message-authentication-code"] = tree!(1);
    });
    assert_eq!(edited.unwrap(), "7e0200000001005678");
    // A tree that says nothing is not one of this message.
    assert!(ciphered.with_tree(tree!({})).is_err());
    let added = fgs_edited(&ciphered, |tree| {
        tree["5gmm-cause"] = tree!({"octets": "03"})
    });
    assert!(added.unwrap_err().contains("no IE `"));
    assert!(ciphered.with_tree(tree!([])).is_err());
    // The same for EPS.
    let protected = eps("17aabbccdd05074403");
    let tree = protected.to_tree();
    assert_eq!(tree["emm-cause"], tree!("illegal-ue"));
    assert_eq!(
        tree["security-header"]["security-header-type"],
        tree!("integrity-protected")
    );
    assert_eq!(protected.with_tree(tree).unwrap(), protected);
    let error = eps_edited(&protected, |tree| tree["emm-cause"] = tree!("congestion"));
    assert!(error.unwrap_err().contains("message authentication code"));
    // An EPS SERVICE REQUEST has a short header and no IEs: a tree that
    // leaves out what it has keeps it.
    let request = eps("c7200000");
    assert_eq!(request.with_tree(tree!({})).unwrap(), request);
    assert_eq!(request.with_tree(request.to_tree()).unwrap(), request);
}

#[test]
fn an_ie_that_a_tree_writes_has_the_octets_of_what_is_written() {
    let accept = |result: Value| {
        let tree = tree!({
            "message-type": "registration-accept",
            "5gs-registration-result": result,
        });
        let accept = f::Message::from_tree(tree);
        accept.map(|accept| hex::encode(accept.encode().unwrap()))
    };
    // Members that are zero are written as any other.
    let zeros = tree!({
        "result": 0, "sms-allowed": false, "nssaa-performed": false,
        "emergency-registered": false, "disaster-roaming": false,
    });
    assert_eq!(accept(zeros).unwrap(), "7e00420100");
    assert_eq!(accept(tree!({"result": 0})).unwrap(), "7e00420100");
    assert_eq!(accept(tree!({"sms-allowed": false})).unwrap(), "7e00420100");
    // A code is written by its number, whether it has a name or not.
    assert_eq!(accept(tree!({"result": 7})).unwrap(), "7e00420107");
    assert_eq!(accept(tree!({"result": 1})).unwrap(), "7e00420101");
    assert_eq!(
        accept(tree!({"result": "3gpp-access"})).unwrap(),
        "7e00420101"
    );
    let error = accept(tree!({"result": 8})).unwrap_err().to_string();
    assert!(error.contains("result cannot be 8"), "{error}");
    let request = |name: &str, value: Value| {
        let mut tree = tree!({
            "message-type": "registration-request",
            "5gs-registration-type": {"octets": "09"},
            "ngksi": {"octets": "07"},
            "5gs-mobile-identity": {"octets": "0199f907000000000000001002"},
        });
        tree[name] = value;
        let request = f::Message::from_tree(tree);
        hex::encode(request.unwrap().encode().unwrap())
    };
    let drx = |window: u8| tree!({"paging-time-window": window, "edrx-value": 0});
    let written = request("requested-extended-drx-parameters", drx(0));
    assert!(written.ends_with("6e0100"), "{written}");
    let written = request("requested-extended-drx-parameters", drx(1));
    assert!(written.ends_with("6e0110"), "{written}");
    // The algorithms of a command, of which the integrity one is reserved.
    let command = f::Message::from_tree(tree!({
        "message-type": "security-mode-command",
        "selected-nas-security-algorithms": {"ciphering": "nea2", "integrity": 8},
        "ngksi": {"octets": "01"},
        "replayed-ue-security-capabilities": {"octets": "f0f0"},
    }));
    assert_eq!(
        hex::encode(command.unwrap().encode().unwrap()),
        "7e005d280102f0f0"
    );
    // The header takes the number of a type that it has a name for.
    let status = f::Message::from_tree(tree!({
        "message-type": "5gmm-status",
        "security-header-type": 0,
        "5gmm-cause": "congestion",
    }));
    assert_eq!(status.unwrap().encode().unwrap(), [0x7e, 0, 0x64, 0x16]);
}

/// The tree of an IE is its value where that writes the IE back, and its octets where
/// it does not.
#[test]
fn the_tree_of_an_ie_is_its_value_where_that_writes_it_back() {
    use crate::tree::Tree;
    let timer = |octets: &[u8]| e::GprsTimer2::new(octets.to_vec()).to_tree();
    assert_eq!(timer(&[0x21, 0x99]), tree!({"octets": "2199"}));
    assert_ne!(timer(&[0x21]), tree!({"octets": "21"}));
    // The fields of a 5GSM header are numbers
    let release = fgs("2e0f01d4");
    assert_eq!(release.to_tree()["pdu-session-identity"], tree!(15));
}

/// The tree of a message has the message of a container as its own tree.
#[test]
fn the_tree_of_a_container_is_the_tree_of_its_message() {
    let attach = eps("07411108298039103254769802f07000040201d011");
    let tree = attach.to_tree();
    let inner = &tree["esm-message-container"];
    assert_eq!(inner["message-type"], tree!("pdn-connectivity-request"));
    assert!(inner["pdn-type"].get("value").is_none(), "{inner}");
    assert_eq!(e::Message::from_tree(tree.clone()).unwrap(), attach);
}

/// What a tree writes of a header, of the header that protects a message and of its
/// ciphered octets is refused with what is wrong with it.
#[test]
fn a_header_that_a_tree_writes_wrong_is_refused_with_why() {
    let protected = fgs("7e01aabbccdd057e006416");
    let error = fgs_edited(&protected, |tree| tree["security-header"] = tree!(5)).unwrap_err();
    assert!(error.contains("expected struct SecurityHeader"), "{error}");
    let error = fgs_edited(&protected, |tree| tree["message-type"] = tree!(5)).unwrap_err();
    assert!(error.contains("5 is not a name"), "{error}");
    let ciphered = fgs("7e0200000000001234");
    let error = fgs_edited(&ciphered, |tree| {
        tree["ciphered-message"] = tree!({"octets": "zz"});
    })
    .unwrap_err();
    assert!(error.contains("it has `octets` alone"), "{error}");
}

/// The unknown IEs that a tree writes are those of the message that it writes.
#[test]
fn the_unknown_ies_that_a_tree_writes_are_kept() {
    let status = fgs("7e006416");
    let edited = fgs_edited(&status, |tree| tree["unknown-ies"] = tree!("700101"));
    assert_eq!(edited, Ok("7e006416700101".into()));
    // A ciphered message has no IEs to show, and keeps none
    let ciphered = fgs("7e0200000000001234");
    let error = fgs_edited(&ciphered, |tree| tree["unknown-ies"] = tree!("700101")).unwrap_err();
    assert!(
        error.contains("`unknown-ies` are IEs of a message"),
        "{error}"
    );
}

#[test]
fn what_a_tree_shows_is_what_it_takes() {
    // A CONFIGURATION UPDATE COMMAND with an IE of flags that has no octets:
    // the IE is written as it came.
    let command = fgs("7e00546300");
    assert_eq!(
        ie(&command, "access-technology-utilization-control")["octets"],
        tree!("")
    );
    // Its tree writes the IE of the fewest octets of its clause, which means
    // what no octets mean.
    let alone = f::Message::from_tree(command.to_tree()).unwrap();
    assert_eq!(hex::encode(alone.encode().unwrap()), "7e005463020000");
    assert!(alone.means_the_same(&command));
    // A reserved PDU session type is a number, not the name of the type that
    // a receiver takes it for, and the octet is written as it came.
    let accept = "2e0101c211000901000631310101ff0106060064060032";
    for (octet, kind, mode) in [
        ("11", tree!("ipv4"), tree!("ssc1")),
        ("10", tree!(0), tree!("ssc1")),
        ("16", tree!(6), tree!("ssc1")),
        ("41", tree!("ipv4"), tree!(4)),
        ("1f", tree!(15), tree!("ssc1")),
    ] {
        let wire = accept.replacen("c211", &format!("c2{octet}"), 1);
        let message = fgs(&wire);
        let tree = message.to_tree();
        assert_eq!(tree["selected-pdu-session-type"], kind, "{octet}");
        assert_eq!(tree["selected-ssc-mode"], mode, "{octet}");
        let alone = f::Message::from_tree(tree).unwrap();
        assert!(alone.means_the_same(&message), "{octet}");
    }
    // A value that the crate reads and cannot write back is not shown: the
    // identity 0 of a linked bearer is reserved.
    let request = eps("6201c5000109062131ff0b3011");
    assert_eq!(
        ie(&request, "linked-eps-bearer-identity"),
        tree!({"octets": "00"})
    );
    let request = eps("6201c5050109062131ff0b3011");
    assert_eq!(
        ie(&request, "linked-eps-bearer-identity"),
        tree!({"octets": "05", "value": 5})
    );
}

#[test]
fn every_message_of_a_tree_alone_is_the_fixture_it_was_read_from() {
    // Each one- or two-octet change of a fixture that still decodes: the
    // tree describes the message alone, with the same tree.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut seen = 0;
    for (_, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        for _ in 0..40 {
            let mut bytes = wire.clone();
            let at = next() as usize % bytes.len();
            bytes[at] = next() as u8;
            let Ok(message @ (f::Message::Gmm(..) | f::Message::Gsm(..))) =
                f::Message::decode(&bytes)
            else {
                continue;
            };
            let tree = message.to_tree();
            let alone = f::Message::from_tree(tree.clone())
                .unwrap_or_else(|error| panic!("{}: {error}", hex::encode(&bytes)));
            assert_eq!(alone.to_tree(), tree, "{}", hex::encode(&bytes));
            seen += 1;
        }
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        for _ in 0..40 {
            let mut bytes = wire.clone();
            let at = next() as usize % bytes.len();
            bytes[at] = next() as u8;
            let direction = if name.starts_with("DetachRequestUeTerminated") {
                crate::Direction::Downlink
            } else {
                crate::Direction::Uplink
            };
            let Ok(message @ (e::Message::Emm(..) | e::Message::Esm(..))) = e::Message::decode_with(
                &bytes,
                crate::DecodeOptions::STRICT.with_direction(direction),
            ) else {
                continue;
            };
            let tree = message.to_tree();
            let alone = e::Message::from_tree(tree.clone())
                .unwrap_or_else(|error| panic!("{}: {error}", hex::encode(&bytes)));
            assert_eq!(alone.to_tree(), tree, "{}", hex::encode(&bytes));
            seen += 1;
        }
    }
    assert!(seen > 2000, "{seen}");
}

#[test]
fn a_list_is_written_by_its_value_and_octets_have_none() {
    // REGISTRATION ACCEPT with a service area list: TAC 1 of PLMN 208-93.
    // The crate builds the list, so its value is written.
    let accept = fgs("7e0042010127070002f839000001");
    assert_eq!(
        accept.to_tree()["service-area-list"],
        tree!([{"one-plmn-non-consecutive": {
            "allowed": "allowed", "plmn": "208-93", "tacs": [1],
        }}])
    );
    let edited = fgs_edited(&accept, |tree| {
        tree["service-area-list"][0]["one-plmn-non-consecutive"]["tacs"] = tree!([2]);
    });
    assert_eq!(edited.unwrap(), "7e0042010127070002f839000002");
    let edited = fgs_edited(&accept, |tree| {
        tree["service-area-list"] = tree!({"octets": "0002f839000003"});
    });
    assert_eq!(edited.unwrap(), "7e0042010127070002f839000003");
    // What a list cannot be is refused: a TAC has three octets.
    let error = fgs_edited(&accept, |tree| {
        tree["service-area-list"][0]["one-plmn-non-consecutive"]["tacs"] = tree!([1_u64 << 24]);
    });
    assert!(error.is_err(), "{error:?}");

    // REGISTRATION ACCEPT with a PDU session reactivation result error
    // cause: a PDU session identity and its cause, for each session.
    let accept = fgs("7e004201017200020516");
    let cause = "pdu-session-reactivation-result-error-cause";
    assert_eq!(accept.to_tree()[cause], tree!([[5, "congestion"]]));
    let edited = fgs_edited(&accept, |tree| {
        tree[cause] = tree!([[6, "congestion"], [7, "illegal-ue"]]);
    });
    assert_eq!(edited.unwrap(), "7e0042010172000406160703");
    // A session has one cause
    let error = fgs_edited(&accept, |tree| {
        tree[cause] = tree!([[5, "congestion"], [5, "illegal-ue"]]);
    });
    assert!(error.is_err(), "{error:?}");
    // Its tree writes it
    let written = f::Message::from_tree(accept.to_tree()).unwrap();
    assert_eq!(
        hex::encode(written.encode().unwrap()),
        "7e004201017200020516"
    );
    // Octets are written as they are
    let edited = fgs_edited(&accept, |tree| tree[cause] = tree!({"octets": "0616"}));
    assert_eq!(edited.unwrap(), "7e004201017200020616");
    // AUTHENTICATION REQUEST: the RAND and the AUTN are octets, as is the ABBA.
    let request =
        fgs("7e0056010200002111111111111111111111111111111111201022222222222222222222222222222222");
    let tree = request.to_tree();
    assert_eq!(tree["abba"], tree!({"octets": "0000"}));
    assert_eq!(
        tree["authentication-parameter-rand"],
        tree!({"octets": "11111111111111111111111111111111"})
    );
    let error = fgs_edited(&request, |tree| tree["abba"] = tree!("0000"));
    assert!(
        error
            .unwrap_err()
            .contains("abba: this IE has octets and no value")
    );
}

#[test]
fn eps_values_read_and_write_by_name() {
    // ATTACH REQUEST with an IMSI and a PDN CONNECTIVITY REQUEST.
    let request = eps("07410108298039000000001002e0e000040201d031");
    let tree = request.to_tree();
    assert_eq!(tree["message-type"], tree!("attach-request"));
    assert_eq!(
        ie(&request, "eps-attach-type"),
        tree!({"value": "eps-attach", "octets": "01"})
    );
    assert_eq!(tree["nas-key-set-identifier"], tree!({"native": 0}));
    assert_eq!(
        tree["eps-mobile-identity"],
        tree!({"imsi": "208930000000001"})
    );
    assert_eq!(tree["ue-network-capability"]["eea"], tree!([0, 1, 2]));
    assert_eq!(tree["ue-network-capability"]["eps-upip"], tree!(false));
    let inner = &tree["esm-message-container"];
    assert_eq!(inner["message-type"], tree!("pdn-connectivity-request"));
    assert_eq!(inner["request-type"], tree!("initial"));
    let edited = eps_edited(&request, |tree| {
        tree["eps-attach-type"] = tree!("combined-eps-imsi-attach");
        tree["eps-mobile-identity"]["imsi"] = tree!("208930000000002");
        tree["nas-key-set-identifier"] = tree!("no-key");
        tree["ue-network-capability"]["eps-upip"] = tree!(true);
        tree["esm-message-container"]["pdn-type"] = tree!("ipv6");
    });
    assert_eq!(
        edited.unwrap(),
        "07417208298039000000002002e0e100040201d021"
    );
    // ATTACH REJECT, EMM cause #3.
    let reject = eps("074403");
    assert_eq!(
        ie(&reject, "emm-cause"),
        tree!({"value": "illegal-ue", "octets": "03"})
    );
    let named = |name: Value| eps_edited(&reject, |tree| tree["emm-cause"] = name);
    assert_eq!(named(tree!("congestion")).unwrap(), "074416");
    assert_eq!(named(tree!(200)).unwrap(), "0744c8");
    assert!(named(tree!({"unknown": 200})).is_err());
    assert!(named(tree!("congestio")).is_err());
    // ATTACH ACCEPT: T3412 of one minute, a TAI list, an ACTIVATE DEFAULT
    // EPS BEARER CONTEXT REQUEST, a GUTI and a TMSI.
    let accept = eps(
        "07420121060002f839000100155201c101090908696e7465726e657405010a000001\
         500bf602f839000102112233442305f411223344530317016b0101",
    );
    let tree = accept.to_tree();
    assert_eq!(
        ie(&accept, "t3412-value"),
        tree!({"octets": "21", "value": 60})
    );
    assert_eq!(
        tree["tai-list"],
        tree!([{"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1]}}])
    );
    assert_eq!(
        tree["guti"],
        tree!({"guti": {"plmn": "208-93", "mme-group-id": 1, "mme-code": 2,
            "m-tmsi": 0x1122_3344}})
    );
    assert_eq!(tree["ms-identity"], tree!({"tmsi": 0x1122_3344}));
    let bearer = &tree["esm-message-container"];
    assert_eq!(bearer["eps-bearer-identity"], tree!(5));
    assert_eq!(bearer["access-point-name"], tree!("internet"));
    assert_eq!(bearer["pdn-address"], tree!({"ipv4": "10.0.0.1"}));
    let edited = eps_edited(&accept, |tree| {
        tree["tai-list"] = tree!([{"different-plmns": [{"plmn": "208-93", "tac": 1},
            {"plmn": "001-01", "tac": "0x10"}]}]);
        tree["guti"]["guti"]["m-tmsi"] = tree!(1);
        let bearer = &mut tree["esm-message-container"];
        bearer["access-point-name"] = tree!("ims");
        bearer["pdn-address"]["ipv4"] = tree!("192.168.0.7");
    });
    assert_eq!(
        edited.unwrap(),
        "074201210b4102f839000100f110001000105201c101090403696d730501c0a80007\
         500bf602f839000102000000012305f411223344530317016b0101"
    );
}

#[test]
fn an_optional_ie_that_the_message_does_not_have_is_added() {
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let tree = accept.to_tree();
    assert_eq!(tree.get("configured-nssai"), None);
    // The names of a message type are those that its tree can have.
    let names = f::GmmMessageType::RegistrationAccept.names();
    assert!(
        tree.as_object()
            .unwrap()
            .keys()
            .all(|entry| names.contains(entry))
    );
    assert_eq!(
        names[..5],
        [
            "extended-protocol-discriminator",
            "security-header-type",
            "spare-half-octet",
            "message-type",
            "5gs-registration-result"
        ]
    );
    // From its octets, and from its value.
    let add = |name: &str, ie: Value| fgs_edited(&accept, |tree| tree[name] = ie);
    let with = |ies: &str| format!("7e0042010177000bf202f8390100421122334415020101{ies}");
    assert_eq!(
        add("configured-nssai", tree!({"octets": "0101"})).unwrap(),
        with("31020101")
    );
    assert_eq!(
        add("configured-nssai", tree!([{"sst": 1, "sd": "010203"}])).unwrap(),
        with("31050401010203")
    );
    // Under another spelling of its name.
    assert_eq!(
        add("Configured NSSAI", tree!({"octets": "0101"})).unwrap(),
        with("31020101")
    );
    assert_eq!(add("t3512-value", tree!(3600)).unwrap(), with("5e0106"));
    assert_eq!(
        add("mico-indication", tree!({"raai": true})).unwrap(),
        with("b1")
    );
    assert_eq!(
        add("mico-indication", tree!({"octets": "00"})).unwrap(),
        with("b0")
    );
    // A value is encoded, also when it is the one of no octets.
    let tnan = fgs_edited(&fgs("7e00440b"), |tree| {
        tree["tnan-information"] = tree!({"tngf-id": null, "ssid": null})
    });
    assert_eq!(tnan.unwrap(), "7e00440b4d0100");
    // Two at once take their places in the message.
    let both = fgs_edited(&accept, |tree| {
        tree["t3512-value"] = tree!("deactivated");
        tree["configured-nssai"] = tree!({"octets": ""});
    });
    assert_eq!(both.unwrap(), with("31005e01e0"));
    // What is added is said: `null` is nothing, and an IE that a message of
    // this type does not have is none.
    for nothing in [Value::Null, tree!({"octets": null})] {
        let error = add("configured-nssai", nothing).unwrap_err();
        assert!(
            error.contains("configured-nssai: an IE is written with a `value` or `octets`"),
            "{error}"
        );
    }
    let error = add("t3512-value", tree!("soon")).unwrap_err();
    assert!(error.contains("t3512-value: "), "{error}");
    let error = add("5gmm-cause", tree!("congestion")).unwrap_err();
    assert!(error.contains("no IE `5gmm-cause`"), "{error}");
    // Inside the message of a container: SECURITY MODE COMPLETE with the
    // REGISTRATION REQUEST it replays.
    let complete = fgs("7e005e7100137e004101000d0102f8390000000021436587f9");
    let edited = fgs_edited(&complete, |tree| {
        let replayed = &mut tree["nas-message-container"];
        assert_eq!(replayed.get("requested-nssai"), None);
        replayed["requested-nssai"] = tree!([{"sst": 1}]);
    });
    assert_eq!(
        edited.unwrap(),
        "7e005e7100177e004101000d0102f8390000000021436587f92f020101"
    );
    // EPS: ATTACH REJECT with EMM cause #3.
    let reject = eps("074403");
    assert_eq!(reject.to_tree().get("t3402-value"), None);
    let edited = eps_edited(&reject, |tree| {
        tree["t3402-value"] = tree!(720);
        tree["extended-emm-cause"] = tree!({"octets": "01"});
    });
    assert_eq!(edited.unwrap(), "07440316012ca1");
}

/// Every optional IE that a fixture does not have is added to it from
/// octets, and the message then has it with them.
#[test]
fn every_optional_ie_is_added_from_its_octets() {
    use crate::common::view::Viewed;
    /// The optional IEs that `message` does not have.
    fn absent(message: &impl Viewed) -> Vec<&'static str> {
        let mut absent = Vec::new();
        if let Some(body) = message.body() {
            body.absent(&mut |name, _| absent.push(name));
        }
        absent
    }
    fn check(absent: Vec<&str>, added: impl Fn(&str, &str) -> bool) -> usize {
        for name in &absent {
            // An IE has the octets of a length that its message encodes.
            let mut lengths = (1..=32).map(|length| "00".repeat(length));
            assert!(lengths.any(|octets| added(name, &octets)), "{name}");
        }
        absent.len()
    }
    let mut added = 0;
    for (_, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        let message = f::Message::decode(&wire).unwrap();
        let tree = message.to_tree();
        added += check(absent(&message), |name, octets| {
            let mut tree = tree.clone();
            tree[name] = tree!({ "octets": octets });
            let edited = message.with_tree(tree).ok();
            let selected = edited.map(|edited| edited.select(&format!("/nas/{name}/octets")));
            selected == Some(Ok(vec![tree!(octets)]))
        });
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        let tree = message.to_tree();
        added += check(absent(&message), |name, octets| {
            let mut tree = tree.clone();
            tree[name] = tree!({ "octets": octets });
            let edited = message.with_tree(tree).ok();
            let selected = edited.map(|edited| edited.select(&format!("/nas/{name}/octets")));
            selected == Some(Ok(vec![tree!(octets)]))
        });
    }
    assert!(added > 500, "{added}");
}

/// The names of every message type that the crate has a message of are the
/// members that its tree can have, in the order of the message.
#[test]
fn the_names_of_a_message_type_are_the_members_of_its_tree() {
    let check = |tree: Value, names: Vec<String>, name: &str| {
        let members: Vec<_> = tree.as_object().unwrap().keys().collect();
        assert!(!members.is_empty(), "{name}");
        // In the order of the message: the header, then the table
        let places: Vec<_> = (members.iter())
            .map(|member| names.iter().position(|known| known == *member))
            .collect();
        assert!(places.iter().all(Option::is_some), "{name}: {members:?}");
        assert!(places.is_sorted(), "{name}: {members:?}");
    };
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        let message = f::Message::decode(&wire).unwrap();
        let names = match &message {
            f::Message::Gmm(header, _) => header.message_type.names(),
            f::Message::Gsm(header, _) => header.message_type.names(),
            _ => panic!("{name}"),
        };
        check(message.to_tree(), names, name);
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        let names = match &message {
            e::Message::Emm(header, _) => header.message_type.names(),
            e::Message::Esm(header, _) => header.message_type.names(),
            _ => panic!("{name}"),
        };
        check(message.to_tree(), names, name);
    }
    let detach = e::EmmMessageType::DetachRequest.names();
    assert!(detach.contains(&"eps-mobile-identity".to_string()));
    assert!(detach.contains(&"emm-cause".to_string()));
    // A type that the crate has no message of.
    assert!(f::GmmMessageType::Unknown(0).names().is_empty());
}

#[test]
fn the_parts_of_a_configuration_or_a_restriction_read_and_write_by_name() {
    // REGISTRATION REJECT with a TNAN information, SERVICE REQUEST with a
    // paging restriction.
    let reject = fgs("7e00440b4d060301aa026162");
    assert_eq!(
        reject.to_tree()["tnan-information"],
        tree!({"tngf-id": "aa", "ssid": "ab"})
    );
    let edited = fgs_edited(&reject, |tree| {
        tree["tnan-information"] = tree!({"tngf-id": null, "ssid": "home"})
    });
    assert_eq!(edited.unwrap(), "7e00440b4d060204686f6d65");
    let request = fgs("7e004c010007f4004211223344280303a202");
    assert_eq!(
        request.to_tree()["paging-restriction"],
        tree!({
            "restriction-type": "all-restricted-except-specified-pdu-sessions",
            "unrestricted-psis": [1, 5, 7, 9],
        })
    );
    let edited = fgs_edited(&request, |tree| {
        tree["paging-restriction"]["unrestricted-psis"] = tree!([2, 15])
    });
    assert_eq!(edited.unwrap(), "7e004c010007f40042112233442803030480");
    // What the type of restriction has no place for is refused.
    let error = fgs_edited(&request, |tree| {
        tree["paging-restriction"] = tree!({
            "restriction-type": "all-restricted",
            "unrestricted-psis": [2],
        })
    });
    assert!(error.unwrap_err().ends_with(
        "`unrestricted-psis` are written with a restriction type that has their bitmap"
    ));
    // EPS: a SERVICE REJECT is given S&F satellite operation parameters.
    let reject = eps("074e0a");
    let edited = eps_edited(&reject, |tree| {
        tree["s-and-f-satellite-operation-parameters"] = tree!({
            "wait-time": 10,
            "uplink-delivery-time": 60,
            "monitoring-list": {"present": "0102"},
        })
    });
    assert_eq!(edited.unwrap(), "074e0a21090b000a00003c020102");
}

/// The example of the README.
#[test]
fn the_readme_example_holds() {
    use crate::paths;
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = f::Message::decode(&bytes).unwrap();
    let mut tree = accept.to_tree();
    let paths = paths::paths(&tree);
    for line in [
        ("/nas/message-type", tree!("registration-accept")),
        ("/nas/5g-guti/guti/plmn", tree!("208-93")),
        ("/nas/allowed-nssai/0/sst", tree!(1)),
    ] {
        assert!(
            paths
                .iter()
                .any(|(path, value)| (path.as_str(), value) == (line.0, &line.1))
        );
    }
    let select = |path| paths::select(&tree, path).unwrap();
    assert_eq!(select("/nas/message-type"), [&tree!("registration-accept")]);
    assert_eq!(
        select("/nas/5gs-registration-result/result"),
        [&tree!("3gpp-access")]
    );
    assert_eq!(select("/nas/5g-guti/guti/tmsi"), [&tree!(0x1122_3344)]);
    assert!(select("/nas/t3512-value").is_empty());
    paths::set(&mut tree, "/nas/5g-guti/guti/tmsi", tree!("0xdeadbeef")).unwrap();
    paths::set(&mut tree, "/nas/allowed-nssai/0/sd", tree!("010203")).unwrap();
    paths::set(&mut tree, "/nas/t3512-value", tree!(3600)).unwrap();
    let edited = accept.with_tree(tree).unwrap();
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "7e0042010177000bf202f839010042deadbeef150504010102035e0106"
    );
}

/// Every value of every fixture has a path that selects it alone.
#[test]
fn every_path_of_every_fixture_selects_its_value() {
    use crate::paths;
    let check = |name: &str, tree: Value| {
        let paths = paths::paths(&tree);
        assert!(!paths.is_empty(), "{name}");
        for (path, value) in paths {
            assert!(path.starts_with("/nas/"), "{name} {path}");
            assert_eq!(
                paths::select(&tree, &path),
                Ok(vec![&value]),
                "{name} {path}"
            );
        }
    };
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        check(name, f::Message::decode(&wire).unwrap().to_tree());
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        check(name, eps_fixture(name, &wire).to_tree());
    }
}

#[test]
fn a_path_names_an_ie_however_it_is_written_and_what_is_not_there_is_nothing() {
    use crate::paths;
    // REGISTRATION REQUEST with a requested NSSAI of one slice.
    let request = fgs("7e004179000d0102f8390000000000000010022e02e0e02f020101");
    let tree = request.to_tree();
    for path in [
        "/nas/5gs-mobile-identity/suci/imsi/msin",
        "/nas/5GS Mobile Identity/SUCI/IMSI/MSIN",
        "/nas/5gs_mobile_identity/suci/imsi/msin",
    ] {
        let msin = paths::select(&tree, path);
        assert_eq!(msin, Ok(vec![&tree!("0000000120")]), "{path}");
    }
    // The name of the field of the codec is no name of the specification
    let codec = paths::select(&tree, "/nas/fgs_mobile_identity").unwrap_err();
    assert_eq!(codec.kind(), tree::ErrorKind::NoSuchMember);
    let slices = paths::select(&tree, "/nas/requested-nssai/*/sst").unwrap();
    assert_eq!(slices, [&tree!(1)]);
    assert_eq!(paths::select(&tree, "/nas").unwrap(), [&tree]);
    // An optional IE that the message does not have, and an entry past the end.
    assert_eq!(
        paths::select(&tree, "/nas/5gmm-capability/s1-mode"),
        Ok(vec![])
    );
    assert_eq!(
        paths::select(&tree, "/nas/requested-nssai/1/sst"),
        Ok(vec![])
    );
    // The IE itself selects nothing either; a member that a slice does not
    // have is no member of the tree: no path of them is listed.
    assert_eq!(paths::select(&tree, "/nas/5gmm-capability"), Ok(vec![]));
    let sd = paths::select(&tree, "/nas/requested-nssai/0/sd").unwrap_err();
    assert_eq!(sd.kind(), tree::ErrorKind::NoSuchMember);
    assert!(
        !paths::paths(&tree)
            .iter()
            .any(|(path, _)| path.contains("5gmm-capability") || path.ends_with("/sd"))
    );
    // A view says what message it is of: the name of an IE that the message
    // cannot have is refused when it is set, and the view is as it was.
    let mut edited = tree.clone();
    let timer = tree!({"value": 60});
    let error = paths::set(&mut edited, "/nas/t3512-value", timer.clone()).unwrap_err();
    assert_eq!(error.kind(), tree::ErrorKind::NoSuchMember);
    assert!(
        error
            .to_string()
            .contains("`t3512-value` is no IE of a message"),
        "{error}"
    );
    assert_eq!(edited, tree);
    paths::set(&mut edited, "/nas/5gmm-capability", tree!({"octets": "00"})).unwrap();
    // One that does not say is refused when it is taken.
    let mut alone = tree!({});
    paths::set(&mut alone, "/nas/t3512-value", timer).unwrap();
    assert!(request.with_tree(alone).is_err());
    use tree::ErrorKind::{NoSuchMember, NotAList, Path, Scalar};
    for (path, kind, reason) in [
        (
            "/nas/no-such-ie",
            NoSuchMember,
            "`no-such-ie` is no IE of a message `registration-request`",
        ),
        (
            "/nas/requested-nssai/0/misspelled",
            NoSuchMember,
            "\"misspelled\" is not a member of this value",
        ),
        (
            "/nas/requested-nssai/first",
            NotAList,
            "\"first\" is no position in a list",
        ),
        (
            "/nas/requested-nssai/0/sst/deeper",
            Scalar,
            "\"deeper\" is not a member of this value, which has none",
        ),
        ("/message/requested_nssai", Path, "it starts with /nas"),
        ("nas/requested-nssai", Path, "a path starts with \"/\""),
    ] {
        let error = paths::select(&tree, path).unwrap_err();
        assert_eq!(error.kind(), kind, "{path}: {error}");
        assert!(error.to_string().contains(reason), "{path}: {error}");
    }
}

/// A path is the names of the tree joined: the name after an IE is a member of its
/// value. `value` there, which no tree has, is refused with the path that the names of
/// the tree write, without each such `value`, whether the message has the IE or not, by
/// each function that takes a path; the tree is as it was.
#[test]
fn a_path_is_the_names_of_the_tree() {
    use crate::paths;
    let joined = |written: &str, path: &str| {
        format!("a path is the tree's names joined: write `{written}`, at {path}")
    };
    // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101").to_tree();
    // UL NAS TRANSPORT with a PDU SESSION RELEASE REQUEST, cause #36
    let transport = fgs("7e00670100062e0501d159241205").to_tree();
    // ATTACH REQUEST with a PDN CONNECTIVITY REQUEST
    let attach = eps("07410108298039000000001002e0e000040201d031").to_tree();
    // 5GMM STATUS under an integrity protected header
    let protected = fgs("7e01e73b901b007e006416").to_tree();
    for (tree, path, written, value) in [
        (
            &accept,
            "/nas/5g-guti/value/guti/tmsi",
            "/nas/5g-guti/guti/tmsi",
            Some(tree!(0x1122_3344)),
        ),
        (
            &accept,
            "/nas/allowed-nssai/value/*/sst",
            "/nas/allowed-nssai/*/sst",
            Some(tree!(1)),
        ),
        (
            &accept,
            "/nas/message-type/value",
            "/nas/message-type",
            Some(tree!("registration-accept")),
        ),
        (
            &accept,
            "/nas/MESSAGE TYPE/Value",
            "/nas/MESSAGE TYPE",
            Some(tree!("registration-accept")),
        ),
        (&accept, "/nas/*/value", "/nas/*", None),
        // An IE that the message does not have
        (&accept, "/nas/t3512-value/value", "/nas/t3512-value", None),
        // The message of a container, each of whose IEs has its own `value`
        (
            &transport,
            "/nas/payload-container/value/5gsm-cause/value",
            "/nas/payload-container/5gsm-cause",
            Some(tree!("regular-deactivation")),
        ),
        (
            &attach,
            "/nas/esm-message-container/value/pdn-type",
            "/nas/esm-message-container/pdn-type",
            Some(tree!("ipv4v6")),
        ),
        (
            &protected,
            "/nas/security-header/value/sequence-number",
            "/nas/security-header/sequence-number",
            Some(tree!(0)),
        ),
    ] {
        let error = paths::select(tree, path).unwrap_err();
        assert_eq!(error.kind(), tree::ErrorKind::NoSuchMember, "{path}");
        assert_eq!(error.to_string(), joined(written, path));
        let selected = paths::select(tree, written).unwrap();
        if let Some(value) = value {
            assert_eq!(selected, [&value], "{written}");
        }
        let mut edited = tree.clone();
        for refused in [
            paths::set(&mut edited, path, tree!(1)),
            paths::remove(&mut edited, path),
            paths::insert(&mut edited, path, tree!(1)),
        ] {
            let refused = refused.map_err(|error| error.to_string());
            assert_eq!(refused, Err(joined(written, path)));
        }
        assert_eq!(&edited, tree, "{path}");
    }
}

/// `octets` after the name of an IE is its octets: a tree has those of an IE that its
/// value does not write back, the message has those of each IE, and an IE that is set
/// by its octets has them in the place of its value.
#[test]
fn octets_after_the_name_of_an_ie_are_its_octets() {
    use crate::paths;
    // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let mut tree = accept.to_tree();
    let guti = "/nas/5g-guti/octets";
    assert_eq!(
        accept.select(guti),
        Ok(vec![tree!("f202f83901004211223344")])
    );
    assert_eq!(
        accept.select("/nas/5g-guti/guti/tmsi"),
        Ok(vec![tree!(0x1122_3344)])
    );
    assert_eq!(accept.select("/nas/t3512-value/octets"), Ok(vec![]));
    // The tree has the value of the 5G-GUTI, and not its octets
    let error = paths::select(&tree, guti).unwrap_err();
    assert_eq!(error.kind(), tree::ErrorKind::NoSuchMember);
    assert_eq!(
        error.to_string(),
        "the tree has the value of this IE and not its octets, which the message has, at \
         /nas/5g-guti/octets"
    );
    assert_eq!(paths::select(&tree, "/nas/t3512-value/octets"), Ok(vec![]));
    // An IE set by its octets, which the message did not have or had by its value
    paths::set(&mut tree, guti, tree!("f202f83901004211223355")).unwrap();
    paths::set(&mut tree, "/nas/t3512-value/octets", tree!("21")).unwrap();
    assert_eq!(tree["5g-guti"], tree!({"octets": "f202f83901004211223355"}));
    assert_eq!(
        paths::select(&tree, guti),
        Ok(vec![&tree!("f202f83901004211223355")])
    );
    let edited = accept.with_tree(tree).unwrap();
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "7e0042010177000bf202f83901004211223355150201015e0121"
    );
    // A container and an IE of its message
    let transport = fgs("7e00670100062e0501d159241205");
    let container = "/nas/payload-container/octets";
    assert_eq!(transport.select(container), Ok(vec![tree!("2e0501d15924")]));
    let cause = "/nas/payload-container/5gsm-cause/octets";
    assert_eq!(transport.select(cause), Ok(vec![tree!("24")]));
    let attach = eps("07410108298039000000001002e0e000040201d031");
    let pdn = "/nas/esm-message-container/pdn-type/octets";
    assert_eq!(attach.select(pdn).map(|octets| octets.len()), Ok(1));
    // A field of a header has no octets of its own
    let header = accept.select("/nas/message-type/octets").unwrap_err();
    assert_eq!(header.kind(), tree::ErrorKind::Refused);
}

/// An IE that a view does not name at all is one that its message may have, or is
/// refused; a view of a message that no type names may have any. An IE taken out keeps
/// its name, as `null`.
#[test]
fn an_ie_that_a_tree_does_not_name_is_one_that_its_message_may_have() {
    use crate::paths;
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let mut tree = accept.to_tree();
    assert!(tree.get("t3512-value").is_none());
    assert_eq!(paths::select(&tree, "/nas/t3512-value"), Ok(vec![]));
    let error = paths::select(&tree, "/nas/no-such-ie").unwrap_err();
    assert_eq!(error.kind(), tree::ErrorKind::NoSuchMember);
    let unknown = tree!({"message-type": "no-such-message"});
    assert_eq!(paths::select(&unknown, "/nas/any-ie"), Ok(vec![]));
    paths::remove(&mut tree, "/nas/allowed-nssai").unwrap();
    assert!(tree.get("allowed-nssai").is_none());
}

#[test]
fn a_tree_is_edited_at_its_paths() {
    use crate::paths;
    let request = fgs("7e004179000d0102f8390000000000000010022e02e0e02f020101");
    let edited = |edit: &dyn Fn(&mut Value) -> Result<(), tree::Error>| {
        let mut tree = request.to_tree();
        edit(&mut tree).map_err(|error| error.to_string())?;
        let message = request.with_tree(tree).map_err(|error| error.to_string())?;
        Ok::<_, String>(hex::encode(message.encode().unwrap()))
    };
    let head = "7e004179000d0102f839000000000000001002";
    // A member of a value, an entry of a list, and the octets of an IE.
    let wire = edited(&|tree| {
        paths::set(tree, "/nas/Requested NSSAI/0/sst", tree!(2))?;
        paths::insert(
            tree,
            "/nas/requested-nssai/-",
            tree!({"sst": 3, "sd": "0000ff"}),
        )?;
        paths::insert(tree, "/nas/requested-nssai/0", tree!({"sst": 1}))?;
        paths::set(
            tree,
            "/nas/ue-security-capability",
            tree!({"octets": "f0f0"}),
        )
    });
    assert_eq!(
        wire.unwrap(),
        format!("{head}2e02f0f02f09010101020403{}", "0000ff")
    );
    // An optional IE is added by its value or its octets, and one is taken out.
    let wire = edited(&|tree| {
        paths::set(tree, "/nas/mico-indication", tree!({"raai": true}))?;
        paths::set(tree, "/nas/5gmm-capability", tree!({"octets": "01"}))?;
        paths::remove(tree, "/nas/requested-nssai")?;
        paths::remove(tree, "/nas/ue-security-capability")
    });
    assert_eq!(wire.unwrap(), format!("{head}100101b1"));
    // An IE that was taken out is added again.
    let mut tree = request.to_tree();
    paths::remove(&mut tree, "/nas/requested-nssai").unwrap();
    assert!(tree.get("requested-nssai").is_none());
    paths::set(&mut tree, "/nas/requested-nssai", tree!([{"sst": 5}])).unwrap();
    assert_eq!(tree["requested-nssai"], tree!([{"sst": 5}]));
    // What selects nothing is refused, and the tree is as it was.
    let mut tree = request.to_tree();
    for (edit, reason) in [
        (
            paths::set(&mut tree, "/nas/no-such-ie", tree!(1)),
            "`no-such-ie` is no IE of a message `registration-request`",
        ),
        (
            paths::set(&mut tree, "/nas/requested-nssai/4/sst", tree!(1)),
            "the path selects nothing",
        ),
        (
            paths::remove(&mut tree, "/nas/mico-indication"),
            "the path selects nothing",
        ),
        (
            paths::insert(&mut tree, "/nas/requested-nssai", tree!(1)),
            "insert adds to a list",
        ),
    ] {
        let error = edit.unwrap_err().to_string();
        assert!(error.contains(reason), "{error}");
    }
    assert_eq!(tree, request.to_tree());
    // A mandatory IE stays: the message says so.
    let error = edited(&|tree| paths::remove(tree, "/nas/5gs-mobile-identity")).unwrap_err();
    assert!(
        error.contains("`5gs-mobile-identity` is mandatory"),
        "{error}"
    );
}

/// The message of a container has the paths of a tree: an optional IE that
/// it has not is added at its path, as at the top of a message, and a name
/// that it cannot have is refused by the name of its message.
#[test]
fn a_path_into_the_message_of_a_container_adds_an_ie_that_it_has_not() {
    use crate::paths;
    // REGISTRATION REQUEST without a requested NSSAI, alone and replayed in
    // the NAS message container of a SECURITY MODE COMPLETE.
    let request = "7e004101000d0102f8390000000021436587f9";
    let complete = format!("7e005e710013{request}");
    let fgs_set = |octets: &str, path: &str, value: Value| -> Result<String, String> {
        let message = fgs(octets);
        let mut tree = message.to_tree();
        paths::set(&mut tree, path, value).map_err(|error| error.to_string())?;
        let edited = message.with_tree(tree).map_err(|error| error.to_string())?;
        Ok(hex::encode(edited.encode().unwrap()))
    };
    let nssai = || tree!([{"sst": 1}]);
    assert_eq!(
        fgs_set(request, "/nas/requested-nssai", nssai()).unwrap(),
        format!("{request}2f020101")
    );
    let path = "/nas/nas-message-container/requested-nssai";
    let replayed = format!("7e005e710017{request}2f020101");
    assert_eq!(fgs_set(&complete, path, nssai()).unwrap(), replayed);
    assert_eq!(
        fgs_set(&complete, path, tree!({"octets": "0101"})).unwrap(),
        replayed
    );
    // An IE that the inner message has
    let path = "/nas/nas-message-container/5gs-registration-type/follow-on-request";
    assert_eq!(
        fgs_set(&complete, path, tree!(true)).unwrap(),
        complete.replace("7e004101", "7e004109")
    );
    // The 5GSM message of a payload container: a PDU SESSION ESTABLISHMENT
    // REQUEST without a PDU session type.
    let transport = "7e00670100062e0101c1ffff1201";
    let path = "/nas/payload-container/pdu-session-type";
    assert_eq!(
        fgs_set(transport, path, tree!("ipv4")).unwrap(),
        "7e00670100072e0101c1ffff911201"
    );
    // The ESM message container of an ATTACH REQUEST: a PDN CONNECTIVITY
    // REQUEST without an access point name.
    let attach = eps("07410108298039000000001002e0e000040201d031");
    let mut tree = attach.to_tree();
    let path = "/nas/esm-message-container/access-point-name";
    paths::set(&mut tree, path, tree!("internet")).unwrap();
    let edited = attach.with_tree(tree).unwrap();
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "07410108298039000000001002e0e0000f0201d031280908696e7465726e6574"
    );
    // A name that the inner message cannot have is refused by its name, and
    // an inner IE is taken out by its name.
    let mut tree = fgs(&complete).to_tree();
    let error = paths::set(&mut tree, "/nas/nas-message-container/no-such-ie", tree!(1));
    let error = error.unwrap_err().to_string();
    assert!(
        error.contains("`no-such-ie` is no IE of a message `registration-request`"),
        "{error}"
    );
    let mut tree = fgs(&replayed).to_tree();
    paths::remove(&mut tree, "/nas/nas-message-container/requested-nssai").unwrap();
    assert!(
        tree["nas-message-container"]
            .get("requested-nssai")
            .is_none()
    );
}

/// The pointers to every part of the members of a tree.
fn values(tree: &Value, path: String, found: &mut Vec<String>) {
    if !path.is_empty() {
        found.push(path.clone());
    }
    match tree {
        Value::Object(object) => {
            (object.iter()).for_each(|(key, value)| values(value, format!("{path}/{key}"), found))
        }
        Value::Array(array) => (array.iter().enumerate())
            .for_each(|(index, value)| values(value, format!("{path}/{index}"), found)),
        _ => {}
    }
}

/// Every fixture has a tree that is the message, and whatever a value of it
/// is given, the answer is a message that has it or an error: nothing is
/// taken unchecked into an encoder.
#[test]
fn a_tree_is_the_message_and_takes_nothing_unchecked() {
    let parts = [
        tree!(255),
        tree!(65_536),
        tree!(-1),
        tree!("x"),
        tree!("0x7fffffffffff"),
        tree!("999-999"),
        tree!([]),
        tree!([300, 300, 300]),
        tree!({}),
        tree!(true),
    ];
    fn check<M: PartialEq + std::fmt::Debug>(
        message: &M,
        tree: impl Fn(&M) -> Value,
        with_tree: impl Fn(&M, Value) -> Option<M>,
        parts: &[Value],
        counts: &mut [usize; 2],
    ) {
        let whole = tree(message);
        assert_eq!(with_tree(message, whole.clone()).as_ref(), Some(message));
        let mut pointers = Vec::new();
        values(&whole, String::new(), &mut pointers);
        // A sample of the parts of a message with many, such as capabilities.
        let step = pointers.len().div_ceil(16).max(1);
        let pointers = pointers.iter().step_by(step);
        for (pointer, part) in pointers.flat_map(|p| parts.iter().map(move |v| (p, v))) {
            let mut edited = whole.clone();
            *pointer_mut(&mut edited, pointer).unwrap() = part.clone();
            counts[0] += 1;
            if let Some(message) = with_tree(message, edited) {
                tree(&message);
                counts[1] += 1;
            }
        }
    }
    let mut counts = [0; 2];
    for (_, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        let message = f::Message::decode(&wire).unwrap();
        check(
            &message,
            f::Message::to_tree,
            |message, tree| message.with_tree(tree).ok().inspect(|m| drop(m.encode())),
            &parts,
            &mut counts,
        );
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        check(
            &message,
            e::Message::to_tree,
            |message, tree| message.with_tree(tree).ok().inspect(|m| drop(m.encode())),
            &parts,
            &mut counts,
        );
    }
    assert!(counts[0] > 4_000 && counts[1] > 100, "{counts:?}");
}

#[test]
fn a_code_is_written_by_its_name_or_by_its_number() {
    // 5GMM STATUS, cause #22: one coded value.
    let status = fgs("7e006416");
    let cause = |value: Value| fgs_edited(&status, |tree| tree["5gmm-cause"] = value);
    assert_eq!(cause(tree!("illegal-ue")).unwrap(), "7e006403");
    assert_eq!(cause(tree!(3)).unwrap(), "7e006403");
    assert_eq!(cause(tree!("0x03")).unwrap(), "7e006403");
    assert_eq!(cause(tree!(22)).unwrap(), "7e006416");
    // The fields of an octet: REGISTRATION ACCEPT, 3GPP access.
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let result = |value: Value| {
        fgs_edited(&accept, |tree| {
            tree["5gs-registration-result"]["result"] = value
        })
    };
    let named = result(tree!("non-3gpp-access")).unwrap();
    assert_eq!(&named[..10], "7e00420102");
    assert_eq!(result(tree!(2)).unwrap(), named);
    assert_eq!(
        result(tree!(1)).unwrap(),
        hex::encode(accept.encode().unwrap())
    );
    // A number that the field cannot hold is refused.
    assert!(result(tree!(9)).unwrap_err().contains("result"));
    // The two values of one octet: PDU SESSION ESTABLISHMENT ACCEPT.
    let accept = fgs("2e0101c211000901000631310101ff0106060064060032");
    let selected = |kind: Value, mode: Value| {
        fgs_edited(&accept, |tree| {
            tree["selected-pdu-session-type"] = kind;
            tree["selected-ssc-mode"] = mode;
        })
    };
    let named = selected(tree!("ipv6"), tree!("ssc2")).unwrap();
    assert_eq!(&named[..10], "2e0101c222");
    assert_eq!(selected(tree!(2), tree!(2)).unwrap(), named);
    // A half octet has four bits.
    assert!(selected(tree!(16), tree!(2)).is_err());
    // EPS: ATTACH REJECT, cause #3.
    let reject = eps("074403");
    let cause = |value: Value| eps_edited(&reject, |tree| tree["emm-cause"] = value);
    assert_eq!(cause(tree!("congestion")).unwrap(), "074416");
    assert_eq!(cause(tree!(22)).unwrap(), "074416");
}

#[test]
fn the_spare_half_octet_of_a_5gmm_header_is_read_and_written() {
    // REGISTRATION COMPLETE, received with a spare half octet of 15
    let complete = fgs("7ef043");
    assert_eq!(
        complete.to_tree(),
        tree!({"message-type": "registration-complete", "spare-half-octet": 15})
    );

    // A tree writes it, and a tree that leaves it out writes zero
    let written = |tree: Value| {
        let message = f::Message::from_tree(tree).unwrap();
        hex::encode(message.encode().unwrap())
    };
    let zero = tree!({"message-type": "registration-complete"});
    assert_eq!(written(complete.to_tree()), "7ef043");
    assert_eq!(written(zero.clone()), "7e0043");
    assert_eq!(fgs("7e0043").to_tree(), zero);

    // An edit writes it, and an edit that leaves it out keeps it
    let edited = fgs_edited(&complete, |tree| tree["spare-half-octet"] = tree!(5));
    assert_eq!(edited.unwrap(), "7e5043");
    let kept = fgs_edited(&complete, |tree| {
        tree.as_object_mut()
            .unwrap()
            .shift_remove("spare-half-octet");
    });
    assert_eq!(kept.unwrap(), "7ef043");

    // It has four bits
    let wide = fgs_edited(&complete, |tree| tree["spare-half-octet"] = tree!(16));
    assert!(wide.is_err());

    // The header that protects a message has its own
    let protected = fgs("7ea1aabbccdd057ef043");
    let tree = protected.to_tree();
    assert_eq!(tree["security-header"]["spare-half-octet"], tree!(10));
    assert_eq!(tree["spare-half-octet"], tree!(15));
    assert_eq!(
        hex::encode(protected.encode().unwrap()),
        "7ea1aabbccdd057ef043"
    );
}

#[test]
fn a_message_in_many_containers_is_read_to_a_depth_and_is_octets_further_in() {
    // Three containers are three trees, down to a message without one.
    let message = fgs(&hex::encode(nested_registration_requests(3)));
    assert_eq!(containers_read_in_tree(&message.to_tree()), 3);

    // Octets of a peer may nest as deep as a message is long: a tree reads
    // eight containers and has the octets of the ninth, where it called
    // itself until the stack ran out.
    let wire = nested_registration_requests(2000);
    let message = fgs(&hex::encode(&wire));
    let tree = message.to_tree();
    assert_eq!(containers_read_in_tree(&tree), 8);
    let mut innermost = &tree;
    for _ in 0..8 {
        innermost = &innermost["nas-message-container"];
    }
    assert!(innermost["nas-message-container"]["octets"].is_string());

    // An edit is of the same depth, and the message is whole.
    assert_eq!(message.with_tree(tree.clone()).unwrap(), message);
    let mut edited = tree;
    edited["nas-message-container"]["5gs-registration-type"]["follow-on-request"] = tree!(true);
    let edited = message.with_tree(edited).unwrap().encode().unwrap();
    assert_eq!(edited.len(), wire.len());
    assert_ne!(edited, wire);

    // A tree that is written nests as deep and no deeper.
    let request = fgs("7e004101000d0102f8390000000021436587f9").to_tree();
    let written = |depth: usize| {
        let mut tree = request.clone();
        for _ in 0..depth {
            let mut outer = request.clone();
            outer["nas-message-container"] = tree;
            tree = outer;
        }
        f::Message::from_tree(tree)
    };
    assert_eq!(
        written(8).unwrap().encode().unwrap(),
        nested_registration_requests(8)
    );
    let error = written(9).unwrap_err().to_string();
    assert!(error.contains("more containers than are read"), "{error}");
}

#[test]
fn every_fixture_is_the_message_of_its_tree_alone() {
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        let message = f::Message::decode(&wire).unwrap();
        let alone = f::Message::from_tree(message.to_tree());
        let alone = alone.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(alone.means_the_same(&message), "{name}");
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        if matches!(message, e::Message::EmmTransport(_)) {
            continue;
        }
        let alone = e::Message::from_tree(message.to_tree());
        let alone = alone.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert!(alone.means_the_same(&message), "{name}");
    }
}

/// What a value has not is left out of its tree, as an IE that the message
/// has not is: a tree has no `null`, and a path selects nothing there.
#[test]
fn a_tree_leaves_out_what_a_value_has_not() {
    let mut found = Vec::new();
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        let message = f::Message::decode(&wire).unwrap();
        nulls(&message.to_tree(), format!("{name}: "), &mut found);
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        nulls(&message.to_tree(), format!("{name}: "), &mut found);
    }
    assert!(found.is_empty(), "{found:#?}");

    // An S-NSSAI of an SST alone, which the tree writes back
    let request = fgs("7e004179000d0102f839f0ff000021436587f92f020101");
    let tree = request.to_tree();
    assert_eq!(tree["requested-nssai"], tree!([{"sst": 1}]));
    assert_eq!(f::Message::from_tree(tree.clone()).unwrap(), request);
    // which has no SD: a path to it is to no member
    let sd = crate::paths::select(&tree, "/nas/requested-nssai/0/sd").unwrap_err();
    assert_eq!(sd.kind(), tree::ErrorKind::NoSuchMember);
}

#[test]
fn a_tree_gives_a_message_that_has_octets() {
    // A type that the IEs are not those of: the message had no octets, and
    // came back all the same.
    let status = fgs("7e006416");
    let error = fgs_edited(&status, |tree| {
        tree["message-type"] = tree!("registration-complete")
    });
    assert!(error.is_err(), "{error:?}");
    let reject = eps("074403");
    let error = eps_edited(&reject, |tree| {
        tree["message-type"] = tree!("attach-complete")
    });
    assert!(error.is_err(), "{error:?}");
    // A tree that changes nothing gives the message back as it is.
    assert_eq!(status.with_tree(status.to_tree()).unwrap(), status);
}

#[test]
fn one_value_of_an_octet_is_edited_and_the_other_stays() {
    // PDU SESSION ESTABLISHMENT ACCEPT whose selected type is the reserved 0,
    // with SSC mode 1: the type is its number, and stays when the mode changes.
    let accept = fgs("2e0101c210000901000631310101ff0106060064060032");
    let tree = accept.to_tree();
    assert_eq!(tree["selected-pdu-session-type"], tree!(0));
    assert_eq!(tree["selected-ssc-mode"], tree!("ssc1"));
    let edited = fgs_edited(&accept, |tree| tree["selected-ssc-mode"] = tree!("ssc2"));
    assert_eq!(&edited.unwrap()[..10], "2e0101c220");
    // And the mode stays when the type changes.
    let edited = fgs_edited(&accept, |tree| {
        tree["selected-pdu-session-type"] = tree!("ipv4")
    });
    assert_eq!(&edited.unwrap()[..10], "2e0101c211");
}

#[test]
fn an_optional_ie_that_is_added_with_zeros_has_its_octets() {
    // REGISTRATION REQUEST without extended DRX parameters: the IE that a
    // tree adds has its octet, of zeros as of anything else.
    let request = fgs("7e004101000d0102f8390000000021436587f9");
    let added = |window: u8, value: u8| {
        fgs_edited(&request, |tree| {
            tree["requested-extended-drx-parameters"] =
                tree!({"paging-time-window": window, "edrx-value": value});
        })
    };
    let wire = hex::encode(request.encode().unwrap());
    assert_eq!(added(0, 0).unwrap(), format!("{wire}6e0100"));
    assert_eq!(added(1, 0).unwrap(), format!("{wire}6e0110"));
    // Flags that are all false too.
    let flags = fgs_edited(&request, |tree| {
        tree["ue-status"] = tree!({"s1-mode-reg": false, "n1-mode-reg": false});
    });
    assert_eq!(flags.unwrap(), format!("{wire}2b0100"));
}

#[test]
fn a_time_whose_digits_are_no_digits_has_its_octets_alone() {
    let command = |time: &str| fgs(&format!("7e005447{time}"));
    let shown = command("62017151406380").to_tree();
    let time = &shown["universal-time-and-local-time-zone"];
    assert_eq!(time["year"], tree!(26), "{time}");
    assert_eq!(time["month"], tree!(10));
    // A year of the digits A and 0: no year writes these octets.
    for octets in ["0a017151406380", "a0017151406380", "620171514063f0"] {
        let shown = command(octets).to_tree();
        let time = &shown["universal-time-and-local-time-zone"];
        assert_eq!(time, &tree!({"octets": octets}), "{octets}");
        // The tree is still that of the message.
        let message = command(octets);
        assert_eq!(message.with_tree(shown).unwrap(), message);
    }
}

#[test]
fn a_service_request_reads_and_writes_its_short_header() {
    use crate::paths;
    // KSI 1, sequence number 5 and a short MAC.
    let request = eps("c725abcd");
    let tree = request.to_tree();
    assert_eq!(
        tree,
        tree!({
            "ksi-and-sequence-number": {"ksi": 1, "sequence-number": 5},
            "message-authentication-code": {"octets": "abcd"},
        })
    );
    let sequence = "/nas/ksi-and-sequence-number/sequence-number";
    assert_eq!(paths::select(&tree, sequence), Ok(vec![&tree!(5)]));
    let edited = |edit: &dyn Fn(&mut Value) -> Result<(), tree::Error>| {
        let mut tree = request.to_tree();
        edit(&mut tree).map_err(|error| error.to_string())?;
        let message = request.with_tree(tree).map_err(|error| error.to_string())?;
        Ok::<_, String>(hex::encode(message.encode().unwrap()))
    };
    let set = |path: &str, value: Value| edited(&|tree| paths::set(tree, path, value.clone()));
    assert_eq!(set(sequence, tree!(6)).unwrap(), "c726abcd");
    let ksi = "/nas/KSI and sequence number/ksi";
    assert_eq!(set(ksi, tree!(7)).unwrap(), "c7e5abcd");
    let octets = "/nas/ksi-and-sequence-number";
    assert_eq!(set(octets, tree!({"octets": "47"})).unwrap(), "c747abcd");
    let mac = "/nas/message-authentication-code";
    assert_eq!(set(mac, tree!({"octets": "0102"})).unwrap(), "c7250102");
    let header_type = "/nas/security-header-type";
    assert_eq!(set(header_type, tree!(13)).unwrap(), "d725abcd");
    // The message that a tree writes alone.
    assert_eq!(e::Message::from_tree(tree.clone()).unwrap(), request);
    let mut partial = tree.clone();
    paths::remove(&mut partial, "/nas/message-authentication-code").unwrap();
    let error = e::Message::from_tree(partial).unwrap_err().to_string();
    assert!(
        error.contains("`message-authentication-code` is not written"),
        "{error}"
    );
    // Nothing that the tree says is ignored.
    for (path, value, reason) in [
        (ksi, tree!(8), "a ksi is 0 to 7"),
        (
            "/nas/ksi-and-sequence-number/typo",
            tree!(1),
            "no member `typo`",
        ),
        (
            octets,
            tree!({"octets": "0102"}),
            "its octets are one octet",
        ),
        (mac, tree!({"octets": "01"}), "its octets are two octets"),
        (mac, tree!(1), "it has its `octets` alone"),
        (header_type, tree!(2), "is not service-request, or 12 to 15"),
        ("/nas/protocol-discriminator", tree!(2), "is not 7"),
    ] {
        let error = set(path, value).unwrap_err();
        assert!(error.contains(reason), "{path}: {error}");
    }
    let error = edited(&|tree| {
        tree["emm-cause"] = tree!("congestion");
        Ok(())
    });
    let error = error.unwrap_err();
    assert!(
        error.contains("no IE `emm-cause`, expected one of protocol-discriminator"),
        "{error}"
    );
}

#[test]
fn a_tree_names_its_message_by_its_name_or_by_its_number() {
    // 5GMM STATUS, cause #22
    let status = fgs("7e006416");
    for kind in [tree!("5gmm-status"), tree!(0x64)] {
        let tree = tree!({"message-type": &kind, "5gmm-cause": "congestion"});
        assert_eq!(f::Message::from_tree(tree).unwrap(), status, "{kind}");
    }

    // A 5GSM message, and the 5GSM message in the container of a 5GMM one
    let by_name = fgs("2e0101c211000901000631310101ff0106060064060032").to_tree();
    let mut by_number = by_name.clone();
    by_number["message-type"] = tree!(0xc2);
    assert_eq!(
        f::Message::from_tree(by_number).unwrap(),
        f::Message::from_tree(by_name).unwrap()
    );

    let transport = "7e00670100082e0101c1ffff91a11201";
    let by_name = fgs(transport).to_tree();
    assert_eq!(
        by_name["payload-container"]["message-type"],
        tree!("pdu-session-establishment-request")
    );
    let mut by_number = by_name.clone();
    by_number["message-type"] = tree!(0x67);
    by_number["payload-container"]["message-type"] = tree!(0xc1);
    let written = f::Message::from_tree(by_number).unwrap();
    assert_eq!(written, f::Message::from_tree(by_name).unwrap());
    assert_eq!(hex::encode(written.encode().unwrap()), transport);

    // An EMM message and an ESM one
    for (wire, number) in [("074403", 0x44), ("0209da280908696e7465726e6574", 0xda)] {
        let by_name = eps(wire).to_tree();
        let mut by_number = by_name.clone();
        by_number["message-type"] = tree!(number);
        let written = e::Message::from_tree(by_number).unwrap();
        assert_eq!(written, e::Message::from_tree(by_name).unwrap());
        assert_eq!(hex::encode(written.encode().unwrap()), wire);
    }

    // A number that no message has, and what is neither a name nor a number
    let error = |tree: Value| f::Message::from_tree(tree).unwrap_err().to_string();
    let no_message = error(tree!({"message-type": 0xff}));
    assert!(no_message.contains("no message `255`"), "{no_message}");
    let no_type = error(tree!({"message-type": true}));
    assert!(
        no_type.contains("is a name or the number of one"),
        "{no_type}"
    );

    let error = e::Message::from_tree(tree!({"message-type": 0xff})).unwrap_err();
    assert!(error.to_string().contains("no message `255`"), "{error}");
    let error = e::Message::from_tree(tree!({})).unwrap_err().to_string();
    assert!(error.contains("names the message"), "{error}");
}

/// A REGISTRATION REQUEST whose NAS message container holds another one,
/// `depth` times.
fn nested_registration_requests(depth: usize) -> Vec<u8> {
    let request = hex::decode("7e004101000d0102f8390000000021436587f9").unwrap();
    let mut message = request.clone();
    for _ in 0..depth {
        let mut outer = request.clone();
        outer.push(0x71);
        outer.extend_from_slice(&(message.len() as u16).to_be_bytes());
        outer.extend_from_slice(&message);
        message = outer;
    }
    message
}

/// The containers of `tree` that have the tree of a message, one inside
/// another.
fn containers_read_in_tree(tree: &Value) -> usize {
    let (mut read, mut message) = (0, tree);
    while let Some(inner) = message.get("nas-message-container") {
        if inner.get("message-type").is_none() {
            break;
        }
        read += 1;
        message = inner;
    }
    read
}

/// The places of `value` that are `null`, from `path`.
fn nulls(value: &Value, path: String, found: &mut Vec<String>) {
    match value {
        Value::Null => found.push(path),
        Value::Object(members) => {
            (members.iter()).for_each(|(name, value)| nulls(value, format!("{path}/{name}"), found))
        }
        Value::Array(items) => (items.iter().enumerate())
            .for_each(|(at, value)| nulls(value, format!("{path}/{at}"), found)),
        _ => {}
    }
}

#[test]
fn a_path_takes_a_name_by_its_letters_and_a_position_as_decimal_writes_it() {
    use crate::paths;
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let tree = accept.to_tree();
    let sst = paths::select(&tree, "/nas/allowed-nssai/0/sst").unwrap();
    for path in [
        "/NAS/Allowed NSSAI/0/SST",
        "/nas/allowed_nssai/0/sst",
        "/nas/allowednssai/0/sst",
        "/nas/allowed.nssai/0/sst",
    ] {
        assert_eq!(paths::select(&tree, path).unwrap(), sst, "{path}");
    }
    for path in ["/nas/allowed-nssai/+0/sst", "/nas/allowed-nssai/00/sst"] {
        let error = paths::select(&tree, path).unwrap_err();
        assert_eq!(error.kind(), tree::ErrorKind::NotAList, "{path}: {error}");
    }
}

/// The protocol configuration options are shown and written by their units.
/// A unit is read by the direction of its message, which the options alone
/// do not say: the same identifier is a request of the UE and an answer of
/// the network.
///
/// tshark 4.6.4 is the reference of what the octets below mean:
/// `text2pcap -l 147`, then `tshark -V` with the user DLT 147 as
/// `nas-eps_plain` or `nas-5gs`.
#[test]
fn protocol_configuration_options_are_units_by_the_direction_of_their_message() {
    // Uplink: the ATTACH REQUEST of an attach that was captured (packet 33
    // of the EPS corpus of the crate, under its security header), whose ESM
    // message container is a PDN CONNECTIVITY REQUEST. tshark: "PPP IP
    // Control Protocol, Code: Configuration Request (1), Identifier: 0,
    // Primary DNS Address: 0.0.0.0, Secondary DNS Address: 0.0.0.0", "IP
    // address allocation via NAS signalling (0x000a)", "DNS Server IPv4
    // Address Request (0x000d)", "IPv4 Link MTU Request (0x0010)".
    let wire = "0243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0";
    let options = tree!({
        "octets": "8080211001000010810600000000830600000000000a00000d00001000",
        "value": [
            {"ipcp": {
                "code": "configure-request",
                "identifier": 0,
                "options": [
                    {"primary-dns-server-address": "0.0.0.0"},
                    {"secondary-dns-server-address": "0.0.0.0"},
                ],
            }},
            "ip-address-allocation-via-nas-signalling",
            "dns-server-ipv4-address-request",
            "ipv4-link-mtu-request",
        ],
    });
    let attach = eps(&format!(
        "07410108991007000020160605e0e00000000025{wire}d0c1"
    ));
    let container = &attach.to_tree()["esm-message-container"];
    assert_eq!(
        container["protocol-configuration-options"],
        options["value"]
    );
    // The request alone
    let request = eps(wire);
    assert_eq!(ie(&request, "protocol-configuration-options"), options);
    // A unit is added, by its name, and the octets follow
    let edited = eps_edited(&request, |tree| {
        let units = tree["protocol-configuration-options"]
            .as_array_mut()
            .unwrap();
        units.push(tree!("p-cscf-ipv4-address-request"));
    });
    assert_eq!(
        edited.unwrap(),
        wire.replace("271d", "2720")
            .replace("1000c0", "1000000c00c0")
    );
    // The tree has the units, and writes the message back
    let tree = request.to_tree();
    assert_eq!(
        tree["protocol-configuration-options"][2],
        tree!("dns-server-ipv4-address-request")
    );
    let written = e::Message::from_tree(tree).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);

    // Downlink: ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST. tshark: IPCP
    // Configuration Nak with the DNS addresses 8.8.8.8 and 8.8.4.4, "DNS
    // Server IPv6 Address (0x0003) IPv6: 2001:4860::8888", "IPv4 Link MTU
    // (0x0010) IPv4 link MTU size: 1400 octets", "DNS Server IPv4 Address
    // (0x000d) IPv4: 8.8.8.8", "P-CSCF IPv4 Address (0x000c) IPv4:
    // 10.0.0.2", "Selected Bearer Control Mode: MS only (1)".
    let options = "8080211003000010810608080808830608080404\
                   00031020014860000000000000000000008888\
                   0010020578000d0408080808000c040a00000200050101";
    let units = tree!([
        {"ipcp": {
            "code": "configure-nak",
            "identifier": 0,
            "options": [
                {"primary-dns-server-address": "8.8.8.8"},
                {"secondary-dns-server-address": "8.8.4.4"},
            ],
        }},
        {"dns-server-ipv6-address": "2001:4860::8888"},
        {"ipv4-link-mtu": 1400},
        {"dns-server-ipv4-address": "8.8.8.8"},
        {"p-cscf-ipv4-address": "10.0.0.2"},
        {"selected-bearer-control-mode": "ms-only"},
    ]);
    let wire = format!("5201c101090908696e7465726e657405010a000001273e{options}");
    let request = eps(&wire);
    assert_eq!(
        ie(&request, "protocol-configuration-options"),
        tree!({"octets": options, "value": &units})
    );
    let edited = eps_edited(&request, |tree| {
        tree["protocol-configuration-options"][2]["ipv4-link-mtu"] = tree!(1500);
    });
    assert_eq!(edited.unwrap(), wire.replace("0010020578", "00100205dc"));
    let written = e::Message::from_tree(request.to_tree()).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);

    // The same units in the extended options of 5GS: PDU SESSION
    // ESTABLISHMENT ACCEPT, which tshark reads the same.
    let wire = format!("2e0101c211000901000631310101ff01060600640600327b003e{options}");
    let accept = fgs(&wire);
    assert_eq!(
        accept.to_tree()["extended-protocol-configuration-options"],
        units
    );
    // The tree writes the options back to their octets. The bit rates of
    // the session AMBR are values that do not say their unit, so the whole
    // message is not compared.
    let written = f::Message::from_tree(accept.to_tree()).unwrap();
    assert_eq!(
        ie(&written, "extended-protocol-configuration-options")["octets"],
        tree!(options)
    );
    // Uplink, the units of the same identifiers are requests: PDU SESSION
    // ESTABLISHMENT REQUEST
    let request = fgs("2e0101c1ffff7b000780000a00000d00");
    assert_eq!(
        request.to_tree()["extended-protocol-configuration-options"],
        tree!([
            "ip-address-allocation-via-nas-signalling",
            "dns-server-ipv4-address-request"
        ])
    );
    // A unit of the other direction is refused
    let error = fgs_edited(&request, |tree| {
        tree["extended-protocol-configuration-options"] =
            tree!([{"dns-server-ipv4-address": "8.8.8.8"}]);
    });
    assert!(error.is_err(), "{error:?}");
    // and so is the identifier of a unit that has a name
    let error = fgs_edited(&request, |tree| {
        tree["extended-protocol-configuration-options"] =
            tree!([{"container": {"identifier": 13, "contents": ""}}]);
    });
    let error = error.unwrap_err();
    assert!(error.contains("dns-server-ipv4-address-request"), "{error}");

    // A container that the crate has no name for is its identifier and its
    // octets, read and written
    let request = fgs("2e0101c1ffff7b000680f00002abcd");
    assert_eq!(
        request.to_tree()["extended-protocol-configuration-options"],
        tree!([{"container": {"identifier": 0xf000, "contents": "abcd"}}])
    );
    let edited = fgs_edited(&request, |tree| {
        tree["extended-protocol-configuration-options"][0]["container"]["contents"] =
            tree!("0102ff");
    });
    assert_eq!(edited.unwrap(), "2e0101c1ffff7b000780f000030102ff");

    // Octets that the units do not give back have no value: here the octet
    // of the configuration protocol has a spare bit
    let request = fgs("2e0101c1ffff7b000488000a00");
    let options = &ie(&request, "extended-protocol-configuration-options");
    assert_eq!(options, &tree!({"octets": "88000a00"}));
    // a configuration protocol that is not PPP
    let request = fgs("2e0101c1ffff7b000481000a00");
    let options = &ie(&request, "extended-protocol-configuration-options");
    assert_eq!(options, &tree!({"octets": "81000a00"}));
    // and a unit that a receiver ignores: the address of a DNS server in
    // three octets, in a message of the network
    let accept = fgs("2e0101c211000901000631310101ff01060600640600327b000780000d03080808");
    let options = &ie(&accept, "extended-protocol-configuration-options");
    assert_eq!(options, &tree!({"octets": "80000d03080808"}));
}

/// Each unit that the reference of the `view` module lists is written by
/// its name to its identifier, and read back by that name.
#[test]
fn each_unit_of_the_configuration_options_has_its_name() {
    let written = |message: &f::Message, units: &[(Value, &str)]| {
        let names: Vec<Value> = units.iter().map(|(unit, _)| unit.clone()).collect();
        let octets: String = units.iter().map(|(_, octets)| *octets).collect();
        let edited = fgs_edited(message, |tree| {
            tree["extended-protocol-configuration-options"] = tree!(names.as_slice());
        })
        .unwrap();
        let options = &ie(&fgs(&edited), "extended-protocol-configuration-options");
        assert_eq!(
            options,
            &tree!({"octets": format!("80{octets}"), "value": names})
        );
    };
    // In a message of the UE: PDU SESSION ESTABLISHMENT REQUEST
    written(
        &fgs("2e0101c1ffff7b000180"),
        &[
            (
                tree!({"lcp": {"code": "configure-request", "identifier": 1, "options": []}}),
                "c0210401010004",
            ),
            (
                tree!({"pap": {
                    "code": "authenticate-request",
                    "identifier": 1,
                    "peer-id": "abc",
                    "password": "zyx",
                }}),
                "c0230c0101000c03616263037a7978",
            ),
            // A response without the size of its value is no packet of CHAP
            (tree!({"chap": "02010004"}), "c2230402010004"),
            (
                tree!({"ipcp": {"code": "configure-ack", "identifier": 7, "options": []}}),
                "80210402070004",
            ),
            (tree!("p-cscf-ipv6-address-request"), "000100"),
            (tree!("im-cn-subsystem-signalling-flag"), "000200"),
            (tree!("dns-server-ipv6-address-request"), "000300"),
            (
                tree!("ms-support-of-network-requested-bearer-control"),
                "000500",
            ),
            (tree!("ip-address-allocation-via-nas-signalling"), "000a00"),
            (tree!("ipv4-address-allocation-via-dhcpv4"), "000b00"),
            (tree!("p-cscf-ipv4-address-request"), "000c00"),
            (tree!("dns-server-ipv4-address-request"), "000d00"),
            (tree!("msisdn-request"), "000e00"),
            (tree!("ipv4-link-mtu-request"), "001000"),
            (tree!("ms-support-of-local-address-in-tft"), "001100"),
            (tree!("p-cscf-reselection-support"), "001200"),
            (tree!("non-ip-link-mtu-request"), "001500"),
            (
                tree!({"container": {"identifier": 0xff00, "contents": "01"}}),
                "ff000101",
            ),
        ],
    );
    // In a message of the network: PDU SESSION ESTABLISHMENT ACCEPT
    written(
        &fgs("2e0101c211000901000631310101ff01060600640600327b000180"),
        &[
            (
                tree!({"p-cscf-ipv6-address": "2001:db8::1"}),
                "00011020010db8000000000000000000000001",
            ),
            (tree!("im-cn-subsystem-signalling-flag"), "000200"),
            (
                tree!({"dns-server-ipv6-address": "2001:db8::53"}),
                "00031020010db8000000000000000000000053",
            ),
            (tree!({"selected-bearer-control-mode": "ms-nw"}), "00050102"),
            (tree!({"p-cscf-ipv4-address": "10.0.0.2"}), "000c040a000002"),
            (
                tree!({"dns-server-ipv4-address": "8.8.4.4"}),
                "000d0408080404",
            ),
            (tree!({"ipv4-link-mtu": 1500}), "00100205dc"),
            (tree!("network-support-of-local-address-in-tft"), "001100"),
            (tree!({"non-ip-link-mtu": 1358}), "001502054e"),
            // 000EH is a request of the UE, and the MSISDN from the network
            (
                tree!({"container": {"identifier": 14, "contents": "9133"}}),
                "000e029133",
            ),
            (
                tree!({"container": {"identifier": 0xff00, "contents": "01"}}),
                "ff000101",
            ),
        ],
    );
    // 000AH is of the UE alone: from the network, the options have no value
    let accept = fgs("2e0101c211000901000631310101ff01060600640600327b000480000a00");
    let options = &ie(&accept, "extended-protocol-configuration-options");
    assert_eq!(options, &tree!({"octets": "80000a00"}));
}

/// TS 24.008 Table 10.5.154 and TS 23.502 §4.11.1.5: in a PDN connection that
/// a PDU session can move to, the UE gives the identity of the session that it
/// allocated (001AH) and a 5GSM cause (0022H), and the network gives the
/// parameters of the session: the S-NSSAI with its PLMN (001BH), the QoS rules
/// (001CH), the session AMBR (001DH) and the QoS flow descriptions (001FH), each
/// the value part of the IE of TS 24.501 of its name. Each unit is read and
/// written by its name in the direction of its message, as the IE of that name
/// is.
#[test]
fn the_units_of_a_pdu_session_in_a_pdn_connection_have_their_names() {
    // PDN CONNECTIVITY REQUEST, and its options of a PDU session: identity 5,
    // and the 5GSM cause #26 "insufficient resources"
    let request = |units: &str| {
        let options = format!("80{units}");
        eps(&format!("0243d011d127{:02x}{options}", options.len() / 2))
    };
    let units = tree!([{"pdu-session-id": 5}, {"5gsm-cause": "insufficient-resources"}]);
    let sent = request("001a01050022011a");
    assert_eq!(sent.to_tree()["protocol-configuration-options"], units);
    let written = e::Message::from_tree(sent.to_tree()).unwrap();
    assert_eq!(written.encode().unwrap(), sent.encode().unwrap());

    // ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST, and the parameters of the
    // session that the PDN connection maps to. They are the values of the IEs
    // of a PDU SESSION ESTABLISHMENT ACCEPT: the same octets, and for the
    // session AMBR the same rates, 100 Mbps down and 50 Mbps up, which the
    // unit has in the largest unit that holds each, 25 times 4 Mbps.
    let (rules, ambr, flows) = ("01000631310101ff01", "060064060032", "012041010109");
    let accept = fgs(&format!("2e0101c2110009{rules}06{ambr}790006{flows}"));
    let accept = accept.to_tree();
    let activate = |units: &str| {
        let options = format!("80{units}");
        let length = options.len() / 2;
        eps(&format!(
            "5201c101090908696e7465726e657405010a00000127{length:02x}{options}"
        ))
    };
    let units = tree!([
        {"s-nssai": {"sst": 1, "sd": "010203", "plmn": "208-93"}},
        {"qos-rules": &accept["authorized-qos-rules"]},
        {"session-ambr": &accept["session-ambr"]},
        {"qos-flow-descriptions": &accept["authorized-qos-flow-descriptions"]},
    ]);
    let octets = format!("001b070101020302f839001c09{rules}001d06070019060032001f06{flows}");
    let sent = activate(&octets);
    assert_eq!(
        ie(&sent, "protocol-configuration-options"),
        tree!({"octets": format!("80{octets}"), "value": &units})
    );
    let written = e::Message::from_tree(sent.to_tree()).unwrap();
    assert_eq!(written.encode().unwrap(), sent.encode().unwrap());
    // A unit that is edited by its value writes its octets
    let edited = eps_edited(&sent, |tree| {
        tree["protocol-configuration-options"][0]["s-nssai"] = tree!({"sst": 2, "plmn": "001-01"});
    });
    let expected = activate(&octets.replace("001b070101020302f839", "001b040200f110"));
    assert_eq!(edited.unwrap(), hex::encode(expected.encode().unwrap()));

    // Each is a unit of one direction: the identifier is reserved in the
    // other, where the options have their octets alone
    let reserved = activate("001a0105");
    let options = &ie(&reserved, "protocol-configuration-options");
    assert_eq!(options, &tree!({"octets": "80001a0105"}));
    let reserved = request("001b070101020302f839");
    let options = &ie(&reserved, "protocol-configuration-options");
    assert_eq!(options, &tree!({"octets": "80001b070101020302f839"}));
    // a name of the other direction is refused, and so is a unit that has a
    // name written as a container
    let error = eps_edited(&sent, |tree| {
        tree["protocol-configuration-options"] = tree!([{"pdu-session-id": 5}]);
    });
    let error = error.unwrap_err();
    assert!(
        error.contains("`pdu-session-id` is a unit of the direction UE to network"),
        "{error}"
    );
    let error = eps_edited(&request("001a0105"), |tree| {
        tree["protocol-configuration-options"] =
            tree!([{"container": {"identifier": 0x001a, "contents": "05"}}]);
    });
    let error = error.unwrap_err();
    assert!(error.contains("pdu-session-id"), "{error}");
    // and so is a value that the IE of its name cannot have
    let error = eps_edited(&sent, |tree| {
        tree["protocol-configuration-options"][0]["s-nssai"] =
            tree!({"sst": 1, "mapped-sd": "010203", "plmn": "208-93"});
    });
    let error = error.unwrap_err();
    assert!(
        error.contains("`s-nssai`") && error.contains("mapped-sd"),
        "{error}"
    );
    let error = eps_edited(&request("001a0105"), |tree| {
        tree["protocol-configuration-options"][0]["pdu-session-id"] = tree!(16);
    });
    assert!(error.unwrap_err().contains("0x001a"));

    // Contents that the unit would not write back are a container, which an
    // edit of the options keeps as it is: a session AMBR of 100 times 1 Mbps,
    // and an identity that is no PDU session identity
    let other = activate("001d06060064060032");
    assert_eq!(
        other.to_tree()["protocol-configuration-options"],
        tree!([{"container": {"identifier": 0x001d, "contents": "060064060032"}}])
    );
    let other = request("001a0100");
    let options = &ie(&other, "protocol-configuration-options");
    assert_eq!(options, &tree!({"octets": "80001a0100"}));
}

/// The SOR transparent container, the CLI and the extended emergency number
/// list are written by their value, with the constructors of the crate.
#[test]
fn a_container_that_a_constructor_builds_is_written() {
    let mac = "000102030405060708090a0b0c0d0e0f";

    // REGISTRATION COMPLETE with a SOR transparent container: the
    // acknowledgement of the UE
    let wire = format!("7e004373001101{mac}");
    let complete = fgs(&wire);
    assert_eq!(
        complete.to_tree()["sor-transparent-container"],
        tree!({"acknowledgement": {
            "mssi": false, "mssnpnsi": false, "msssnpnsils": false, "sor-mac-iue": mac,
        }})
    );
    let edited = fgs_edited(&complete, |tree| {
        tree["sor-transparent-container"]["acknowledgement"]["mssi"] = tree!(true);
    });
    assert_eq!(edited.unwrap(), wire.replace("001101", "001103"));
    let written = f::Message::from_tree(complete.to_tree()).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);

    // REGISTRATION ACCEPT with the information of the network: a list of
    // one PLMN with its access technologies, to be acknowledged
    let wire = format!("7e004201017300180e{mac}000102f8398000");
    let accept = fgs(&wire);
    assert_eq!(
        accept.to_tree()["sor-transparent-container"],
        tree!({"information": {
            "list-indication": true,
            "list-type": "plmn-access-technology-list",
            "acknowledgement-requested": true,
            "additional-parameters": false,
            "sor-mac-iausf": mac,
            "counter-sor": 1,
            "body": "02f8398000",
        }})
    );
    let edited = fgs_edited(&accept, |tree| {
        tree["sor-transparent-container"]["information"]["counter-sor"] = tree!(2);
    });
    assert_eq!(edited.unwrap(), wire.replace("000102f839", "000202f839"));
    let written = f::Message::from_tree(accept.to_tree()).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);
    // A list that is not one of PLMNs with their access technologies is
    // refused
    let error = fgs_edited(&accept, |tree| {
        tree["sor-transparent-container"]["information"]["body"] = tree!("02f839");
    });
    assert!(error.is_err(), "{error:?}");

    // CS SERVICE NOTIFICATION with a CLI: the number of the calling party
    let wire = "0764016006118121436587";
    let notification = eps(wire);
    assert_eq!(
        ie(&notification, "cli"),
        tree!({
            "octets": "118121436587",
            "value": {
                "type-of-number": "international",
                "numbering-plan": "isdn",
                "presentation": "allowed",
                "screening": "user-provided-verified-passed",
                "digits": "12345678",
            },
        })
    );
    let edited = eps_edited(&notification, |tree| {
        tree["cli"]["presentation"] = tree!("restricted");
        tree["cli"]["digits"] = tree!("123");
    });
    assert_eq!(edited.unwrap(), "076401600411a121f3");
    let written = e::Message::from_tree(notification.to_tree()).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);
    // The two indicators are one octet: one without the other is refused
    let error = eps_edited(&notification, |tree| {
        tree["cli"]["screening"] = tree!(null);
    });
    assert!(error.is_err(), "{error:?}");
    // Without them, the number has no octet 3a
    let edited = eps_edited(&notification, |tree| {
        tree["cli"]["presentation"] = tree!(null);
        tree["cli"]["screening"] = tree!(null);
    });
    assert_eq!(edited.unwrap(), "07640160059121436587");

    // REGISTRATION ACCEPT with an extended emergency number list: 112, for
    // the whole country
    let wire = "7e004201017a0005000211f200";
    let accept = fgs(wire);
    assert_eq!(
        accept.to_tree()["extended-emergency-number-list"],
        tree!({
            "valid-only-in-plmn": false,
            "numbers": [{"digits": "112", "sub-services": ""}],
        })
    );
    // The list becomes that of the PLMN, with a number of the police
    let edited = fgs_edited(&accept, |tree| {
        let list = &mut tree["extended-emergency-number-list"];
        list["valid-only-in-plmn"] = tree!(true);
        list["numbers"]
            .as_array_mut()
            .unwrap()
            .push(tree!({"digits": "17", "sub-services": "police"}));
    });
    let edited = fgs(&edited.unwrap());
    assert_eq!(
        ie(&edited, "extended-emergency-number-list"),
        tree!({
            // "police" in the 7-bit alphabet of TS 23.038, packed
            "octets": "010211f200017106f0373b3d2e03",
            "value": {
                "valid-only-in-plmn": true,
                "numbers": [
                    {"digits": "112", "sub-services": ""},
                    {"digits": "17", "sub-services": "police"},
                ],
            },
        })
    );
    let written = f::Message::from_tree(accept.to_tree()).unwrap();
    assert_eq!(hex::encode(written.encode().unwrap()), wire);
    // EPS has the same list: ATTACH ACCEPT
    let wire = "07420121060002f839000100155201c101090908696e7465726e657405010a000001\
                7a0005000211f200";
    let accept = eps(wire);
    assert_eq!(
        accept.to_tree()["extended-emergency-number-list"],
        tree!({
            "valid-only-in-plmn": false,
            "numbers": [{"digits": "112", "sub-services": ""}],
        })
    );
    let edited = eps_edited(&accept, |tree| {
        tree["extended-emergency-number-list"]["valid-only-in-plmn"] = tree!(true);
    });
    assert_eq!(edited.unwrap(), wire.replace("7a000500", "7a000501"));
}

/// The packet of a configuration protocol is shown and written by the names
/// of its protocol: its code, its identifier, and its options or its
/// fields (RFC 1661, RFC 1332 and RFC 1877, RFC 1334, RFC 1994). A packet
/// that those names would not write back has its octets.
///
/// tshark 4.6.4 reads the same in the octets of each message below.
#[test]
fn the_packets_of_the_configuration_protocols_have_their_names() {
    let units = |message: &e::Message| message.to_tree()["protocol-configuration-options"].clone();
    // The messages are written back from their trees to the same octets
    let written = |wire: &str| {
        let message = e::Message::from_tree(eps(wire).to_tree()).unwrap();
        assert_eq!(hex::encode(message.encode().unwrap()), wire);
    };

    // ESM INFORMATION RESPONSE with the credentials of PAP and a request of
    // IPCP. tshark: "PPP Password Authentication Protocol, Code:
    // Authenticate-Request (1), Identifier: 1, Peer-ID: user, Password:
    // secret", "PPP IP Control Protocol, Code: Configuration Request (1),
    // IP Address: 0.0.0.0, Primary DNS Address: 0.0.0.0, Secondary DNS
    // Address: 0.0.0.0".
    let wire = "0201da280908696e7465726e6574272d80\
                c0231001010010047573657206736563726574\
                80211601000016030600000000810600000000830600000000";
    let response = eps(wire);
    assert_eq!(
        units(&response),
        tree!([
            {"pap": {
                "code": "authenticate-request",
                "identifier": 1,
                "peer-id": "user",
                "password": "secret",
            }},
            {"ipcp": {
                "code": "configure-request",
                "identifier": 0,
                "options": [
                    {"ip-address": "0.0.0.0"},
                    {"primary-dns-server-address": "0.0.0.0"},
                    {"secondary-dns-server-address": "0.0.0.0"},
                ],
            }},
        ])
    );
    written(wire);
    // Another password: the lengths follow
    let edited = eps_edited(&response, |tree| {
        tree["protocol-configuration-options"][0]["pap"]["password"] = tree!("hunter2");
    });
    assert_eq!(
        eps(&edited.unwrap())
            .select("/nas/protocol-configuration-options/octets")
            .unwrap()[0],
        tree!(
            "80c023110101001104757365720768756e74657232\
         80211601000016030600000000810600000000830600000000"
        )
    );

    // ESM INFORMATION RESPONSE with a challenge of CHAP and its response.
    // tshark: "Code: Challenge (1), Identifier: 1, Value:
    // 101112131415161718191a1b1c1d1e1f, Name: gw", "Code: Response (2),
    // Identifier: 1, Value: a0a1a2a3a4a5a6a7a8a9aaabacadaeaf, Name: user".
    let wire = "0201da280908696e7465726e6574273780\
                c223170101001710101112131415161718191a1b1c1d1e1f6777\
                c223190201001910a0a1a2a3a4a5a6a7a8a9aaabacadaeaf75736572";
    assert_eq!(
        units(&eps(wire)),
        tree!([
            {"chap": {
                "code": "challenge",
                "identifier": 1,
                "value": "101112131415161718191a1b1c1d1e1f",
                "name": "gw",
            }},
            {"chap": {
                "code": "response",
                "identifier": 1,
                "value": "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                "name": "user",
            }},
        ])
    );
    written(wire);

    // PDN CONNECTIVITY REQUEST with a request of LCP. tshark: "PPP Link
    // Control Protocol, Code: Configuration Request (1), Identifier: 2,
    // Maximum Receive Unit: 1500, Authentication Protocol: Challenge
    // Handshake Authentication Protocol (0xc223), Algorithm: CHAP with MD5
    // (5), Magic Number: 0x12345678, Protocol Field Compression, Address
    // and Control Field Compression".
    let wire = "0201d011271b80c0211701020017010405dc0305c2230505061234567807020802";
    assert_eq!(
        units(&eps(wire)),
        tree!([{"lcp": {
            "code": "configure-request",
            "identifier": 2,
            "options": [
                {"maximum-receive-unit": 1500},
                {"authentication-protocol": "chap-md5"},
                {"magic-number": 0x1234_5678},
                "protocol-field-compression",
                "address-and-control-field-compression",
            ],
        }}])
    );
    written(wire);

    // ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST with the answers of the
    // network. tshark: "Code: Authenticate-Ack (2), Message: welcome",
    // "Code: Authenticate-Nak (3), Message: no", "Code: Success (3),
    // Message: ok", "Code: Failure (4), Message: bad".
    let wire = "5201c101090908696e7465726e657405010a000001272d80\
                c0230c0201000c0777656c636f6d65c0230703010007026e6f\
                c22306030100066f6bc2230704010007626164";
    let answer =
        |code: &str, message: &str| tree!({"code": code, "identifier": 1, "message": message});
    let outcome =
        |code: &str, message: &str| tree!({"code": code, "identifier": 1, "message": message});
    assert_eq!(
        units(&eps(wire)),
        tree!([
            {"pap": answer("authenticate-ack", "welcome")},
            {"pap": answer("authenticate-nak", "no")},
            {"chap": outcome("success", "ok")},
            {"chap": outcome("failure", "bad")},
        ])
    );
    written(wire);

    // A message is written with its credentials by their names
    let request = e::Message::from_tree(tree!({
        "message-type": "pdn-connectivity-request",
        "eps-bearer-identity": 0,
        "procedure-transaction-identity": 1,
        "pdn-type": "ipv4",
        "request-type": "initial",
        "protocol-configuration-options": [
            {"pap": {
                "code": "authenticate-request",
                "identifier": 1,
                "peer-id": "user",
                "password": "secret",
            }},
            "dns-server-ipv4-address-request",
        ],
    }))
    .unwrap();
    assert_eq!(
        hex::encode(request.encode().unwrap()),
        "0201d011271780c0231001010010047573657206736563726574000d00"
    );
}

/// A packet that the names of its protocol would not write back to the
/// same octets has its octets, and nothing of it is lost. What has names
/// is written by them.
#[test]
fn a_packet_that_its_names_do_not_write_back_has_its_octets() {
    let options = |wire: &str| ie(&fgs(wire), "extended-protocol-configuration-options").clone();
    // A length that is not that of the packet
    assert_eq!(
        options("2e0101c1ffff7b00088080210401000005")["value"],
        tree!([{"ipcp": "01000005"}])
    );
    // octets after the packet
    assert_eq!(
        options("2e0101c1ffff7b0009808021050100000400")["value"],
        tree!([{"ipcp": "0100000400"}])
    );
    // a code that has no name here: Terminate-Request
    assert_eq!(
        options("2e0101c1ffff7b00088080210405000004")["value"],
        tree!([{"ipcp": "05000004"}])
    );
    // a password of PAP that is no text
    assert_eq!(
        options("2e0101c1ffff7b000b80c02307010100070001ff")["value"],
        tree!([{"pap": "010100070001ff"}])
    );
    // An option that has no name is its type and its data: here the IP
    // compression protocol of RFC 1332, and a DNS server address of three
    // octets
    let unknown = "2e0101c1ffff7b000c80802108010000080204002d";
    assert_eq!(
        options(unknown)["value"],
        tree!([{"ipcp": {
            "code": "configure-request",
            "identifier": 0,
            "options": [{"option": {"type": 2, "data": "002d"}}],
        }}])
    );
    assert_eq!(
        options("2e0101c1ffff7b000d80802109010000098105080808")["value"][0]["ipcp"]["options"],
        tree!([{"option": {"type": 129, "data": "080808"}}])
    );
    // Each is written back as it is
    for wire in [
        "2e0101c1ffff7b00088080210401000005",
        "2e0101c1ffff7b0009808021050100000400",
        "2e0101c1ffff7b00088080210405000004",
        "2e0101c1ffff7b000b80c02307010100070001ff",
        unknown,
        "2e0101c1ffff7b000d80802109010000098105080808",
    ] {
        let message = f::Message::from_tree(fgs(wire).to_tree()).unwrap();
        assert_eq!(hex::encode(message.encode().unwrap()), wire);
    }

    // What has names is written by them: the octets of a packet that has
    // them are refused, and so is the type of an option that has a name
    let request = fgs("2e0101c1ffff7b00088080210401000004");
    let refused = |units: Value| {
        fgs_edited(&request, |tree| {
            tree["extended-protocol-configuration-options"] = units;
        })
        .unwrap_err()
    };
    let error = refused(tree!([{"ipcp": "01000004"}]));
    assert!(error.contains("configure-request"), "{error}");
    let error = refused(tree!([{"ipcp": {
        "code": "configure-request",
        "identifier": 0,
        "options": [{"option": {"type": 129, "data": "08080808"}}],
    }}]));
    assert!(error.contains("primary-dns-server-address"), "{error}");
    // A member that the code of a packet does not have is refused, and so
    // is a packet without one that it has
    refused(tree!([{"pap": {
        "code": "authenticate-request", "identifier": 1,
        "peer-id": "u", "password": "p", "message": "x",
    }}]));
    refused(tree!([{"pap": {"code": "authenticate-request", "identifier": 1, "peer-id": "u"}}]));
    refused(tree!([{"chap": {"code": "success", "identifier": 1, "name": "u", "message": ""}}]));
    // and so is a name that the packet does not have
    let error =
        refused(tree!([{"ipcp": {"code": "configure-request", "identifier": 0, "option": []}}]));
    assert!(error.contains("option"), "{error}");
}

/// A unit that the direction of the message does not have is refused with
/// its own direction, and with the unit that this direction has for the
/// same identifier, as a name that is written wrong is refused with those
/// that exist.
#[test]
fn a_unit_of_the_other_direction_is_refused_with_the_unit_of_this_one() {
    // PDU SESSION ESTABLISHMENT REQUEST, UE to network: the address of a DNS
    // server is what the network gives
    let request = fgs("2e0101c1ffff7b000780000a00000d00");
    let refused = |units: Value| {
        fgs_edited(&request, |tree| {
            tree["extended-protocol-configuration-options"] = units;
        })
        .unwrap_err()
    };
    assert_eq!(
        refused(tree!([{"dns-server-ipv4-address": "8.8.8.8"}])),
        "cannot encode: extended-protocol-configuration-options: `dns-server-ipv4-address` is a \
         unit of the direction network to UE, and this message is sent in the direction UE to \
         network: expected `dns-server-ipv4-address-request`, the unit of the same identifier \
         (0x000d)"
    );
    // The two names of an identifier need not be alike
    let error = refused(tree!([{"selected-bearer-control-mode": "ms-only"}]));
    assert!(
        error.ends_with(
            "expected `ms-support-of-network-requested-bearer-control`, the unit of the same \
             identifier (0x0005)"
        ),
        "{error}"
    );
    // The tree of a message is refused in the same words
    let mut tree = request.to_tree();
    tree["extended-protocol-configuration-options"] = tree!([{"ipv4-link-mtu": 1400}]);
    let error = f::Message::from_tree(tree).unwrap_err().to_string();
    assert!(
        error.ends_with(
            "`ipv4-link-mtu` is a unit of the direction network to UE, and this message is sent \
             in the direction UE to network: expected `ipv4-link-mtu-request`, the unit of the \
             same identifier (0x0010)"
        ),
        "{error}"
    );

    // ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST, network to UE: the plain
    // options of EPS, and a request of the UE
    let activate = eps("5201c101090908696e7465726e657405010a0000012705800010020578");
    let refused = |units: Value| {
        eps_edited(&activate, |tree| {
            tree["protocol-configuration-options"] = units;
        })
        .unwrap_err()
    };
    assert_eq!(
        refused(tree!(["dns-server-ipv4-address-request"])),
        "cannot encode: protocol-configuration-options: `dns-server-ipv4-address-request` is a \
         unit of the direction UE to network, and this message is sent in the direction network \
         to UE: expected `dns-server-ipv4-address`, the unit of the same identifier (0x000d)"
    );
    // An identifier that the network has no unit of
    assert_eq!(
        refused(tree!(["ip-address-allocation-via-nas-signalling"])),
        "cannot encode: protocol-configuration-options: \
         `ip-address-allocation-via-nas-signalling` is a unit of the direction UE to network, and \
         this message is sent in the direction network to UE, which has no unit of the same \
         identifier (0x000a)"
    );
    // A name that no direction has is refused with the names that exist
    let error = refused(tree!(["dns-server-ipv4-adress-request"]));
    assert!(
        error.contains(
            "no name `dns-server-ipv4-adress-request`; the nearest of its 32 are \
             dns-server-ipv4-address-request, dns-server-ipv6-address-request"
        ),
        "{error}"
    );
}

/// What a value cannot be says why, where the crate knows: the members of a
/// packet, the contents of a container, the length of the options.
#[test]
fn a_value_that_is_refused_says_what_was_expected() {
    let request = fgs("2e0101c1ffff7b000780000a00000d00");
    let refused = |units: Value| {
        fgs_edited(&request, |tree| {
            tree["extended-protocol-configuration-options"] = units;
        })
        .unwrap_err()
    };
    // The members of a packet are those of its code
    let error = refused(tree!([{"pap": {
        "code": "authenticate-request", "identifier": 1,
        "peer-id": "u", "password": "p", "message": "x",
    }}]));
    assert!(
        error.ends_with(
            "`pap`: a packet with the code `authenticate-request` has `peer-id` and `password`, \
             and no `message`"
        ),
        "{error}"
    );
    let error =
        refused(tree!([{"pap": {"code": "authenticate-ack", "identifier": 1, "peer-id": "u"}}]));
    assert!(
        error.ends_with(
            "`pap`: a packet with the code `authenticate-ack` may have a `message`, and has no \
             `peer-id` and no `password`"
        ),
        "{error}"
    );
    let error = refused(tree!([{"chap": {"code": "response", "identifier": 1, "name": "u"}}]));
    assert!(
        error.ends_with(
            "`chap`: a packet with the code `response` has `value` and `name`, and no `message`"
        ),
        "{error}"
    );
    let error = refused(
        tree!([{"chap": {"code": "success", "identifier": 1, "name": "u", "message": ""}}]),
    );
    assert!(
        error.ends_with(
            "`chap`: a packet with the code `success` has `message`, and no `value` and no `name`"
        ),
        "{error}"
    );
    // The contents of a container are those of its identifier in the
    // direction: 000DH from the UE is a request, which has none
    let error = refused(tree!([{"container": {"identifier": 13, "contents": "08080808"}}]));
    assert!(
        error.ends_with(
            "the container of the identifier 0x000d cannot have the contents `08080808` in the \
             direction UE to network"
        ),
        "{error}"
    );

    // The options together fit their IE: 251 octets, with one of the octet
    // that says the configuration protocol
    let request = eps("0201d011");
    let error = eps_edited(&request, |tree| {
        let unit = tree!({"container": {"identifier": 0xff00, "contents": "00".repeat(248)}});
        tree["protocol-configuration-options"] = tree!([unit]);
    })
    .unwrap_err();
    assert_eq!(
        error,
        "cannot encode: protocol-configuration-options: `protocol-configuration-options` has 252 \
         octets, and must have 1 to 251"
    );
}

/// What the constructor of an IE refuses says the member, what it was given
/// and the limit that it breaks, after the path of the IE: a number outside
/// its range, octets or digits outside their length, entries outside their
/// number, and members that do not go together, in a tree and in a view of
/// each protocol.
#[test]
fn a_value_that_its_constructor_refuses_says_the_member_and_the_limit() {
    let fgs_tree = |tree: Value| f::Message::from_tree(tree).unwrap_err().to_string();
    let eps_tree = |tree: Value| e::Message::from_tree(tree).unwrap_err().to_string();
    let plmns = |count: usize| vec!["208-93"; count];

    // A number outside its range, with the entry of the list that it is in
    assert_eq!(
        fgs_tree(tree!({"message-type": "service-accept", "pdu-session-status": [5, 16]})),
        "cannot encode: pdu-session-status: entry 1: `pdu-session-identity` is 16, and must be 1 to 15"
    );
    assert_eq!(
        eps_tree(tree!({"message-type": "emm-information", "local-time-zone": -80})),
        "cannot encode: local-time-zone: `time-zone` is -80, and must be -79 to 79"
    );

    // Digits and octets outside their length
    assert_eq!(
        fgs_tree(tree!({"message-type": "identity-response", "mobile-identity": {"imei": "1234"}})),
        "cannot encode: mobile-identity: `imei` has 4 digits, and must have 15"
    );
    assert_eq!(
        eps_tree(tree!({
            "message-type": "pdn-connectivity-request",
            "eps-bearer-identity": 0,
            "procedure-transaction-identity": 1,
            "pdn-type": "ipv4",
            "request-type": "initial",
            "access-point-name": "internet..mnc093",
        })),
        "cannot encode: access-point-name: `access-point-name` has 0 octets in a label, and must \
         have 1 to 63"
    );

    // Entries outside their number
    assert_eq!(
        fgs_tree(tree!({
            "message-type": "registration-accept",
            "5gs-registration-result": {"result": "3gpp-access"},
            "equivalent-plmns": plmns(16),
        })),
        "cannot encode: equivalent-plmns: `plmns` has 16 entries, and must have 1 to 15"
    );
    assert_eq!(
        eps_tree(tree!({
            "message-type": "tracking-area-update-accept",
            "eps-update-result": "ta-updated",
            "equivalent-plmns": plmns(16),
        })),
        "cannot encode: equivalent-plmns: `plmns` has 16 entries, and must have 1 to 15"
    );

    // Members that do not go together
    assert_eq!(
        fgs_tree(tree!({
            "message-type": "configuration-update-command",
            "allowed-nssai": [{"sst": 1}, {"sst": 1, "mapped-sd": "000001"}],
        })),
        "cannot encode: allowed-nssai: entry 1: `mapped-sd` is written with `mapped-sst`"
    );
    assert_eq!(
        eps_tree(tree!({
            "message-type": "pdn-connectivity-request",
            "eps-bearer-identity": 0,
            "procedure-transaction-identity": 1,
            "pdn-type": "ipv4",
            "request-type": "initial",
            "header-compression-configuration": {
                "profiles": {
                    "p0002": true, "p0003": false, "p0004": false, "p0006": false,
                    "p0102": false, "p0103": false, "p0104": false,
                },
                "max-cid": 15,
                "additional-setup-container": "00",
            },
        })),
        "cannot encode: header-compression-configuration: `additional-setup-container` is written \
         with `additional-setup-type`"
    );

    // A value that is there twice, a character that the member does not
    // have, and a number that it cannot be
    let accept = fgs("7e004201017200020516");
    let error = fgs_edited(&accept, |tree| {
        tree["pdu-session-reactivation-result-error-cause"] =
            tree!([[5, "congestion"], [5, "illegal-ue"]]);
    })
    .unwrap_err();
    assert_eq!(
        error,
        "cannot encode: pdu-session-reactivation-result-error-cause: entry 1: \
         `pdu-session-identity` has 5 twice"
    );
    assert_eq!(
        eps_tree(tree!({
            "message-type": "identity-response",
            "mobile-identity": {"imei": "35609204079301x"},
        })),
        "cannot encode: mobile-identity: `imei` has the character `x`, and must have decimal digits"
    );
    assert_eq!(
        fgs_tree(tree!({"message-type": "service-accept", "t3448-value": 100_000})),
        "cannot encode: t3448-value: `seconds` is 100000, and must be up to 31 times 2 seconds, 1 \
         minute or 6 minutes"
    );

    // An edited tree and a tree alone are told what a tree is: the fields
    // of an octet, and an IE that is added
    let command = fgs("7e0054");
    let error = fgs_edited(&command, |tree| {
        tree["universal-time-and-local-time-zone"] = tree!({
            "year": 26, "month": 10, "day": 12, "hour": 1, "minute": 2, "second": 3,
            "time-zone-quarter-hours": 80,
        });
    })
    .unwrap_err();
    assert_eq!(
        error,
        "cannot encode: universal-time-and-local-time-zone: `time-zone-quarter-hours` is 80, and \
         must be -79 to 79"
    );
    let mut tree = eps("0761").to_tree();
    tree["local-time-zone"] = tree!(80);
    assert_eq!(
        e::Message::from_tree(tree).unwrap_err().to_string(),
        "cannot encode: local-time-zone: `time-zone` is 80, and must be -79 to 79"
    );
    let mut tree = accept.to_tree();
    tree["pdu-session-status"] = tree!([0]);
    assert_eq!(
        f::Message::from_tree(tree).unwrap_err().to_string(),
        "cannot encode: pdu-session-status: entry 0: `pdu-session-identity` is 0, and must be 1 to 15"
    );

    // The message of a container says why it does not encode: the PDN
    // CONNECTIVITY REQUEST of an ATTACH REQUEST
    let request = eps("07411108298039103254769802f07000040201d011");
    let error = eps_edited(&request, |tree| {
        tree["esm-message-container"]["eps-bearer-identity"] = tree!(16);
    })
    .unwrap_err();
    assert_eq!(
        error,
        "cannot encode: esm-message-container: an ESM header has the protocol discriminator 2 \
         and an EPS bearer identity of 0 to 15"
    );
}

/// The messages that a tree of `tree` writes when one of its values is
/// replaced by one that says nothing: an object or a list without anything
/// in it, a text without a character.
fn emptied(tree: &Value, written: &mut Vec<(String, Value)>) {
    fn at(value: &mut Value, path: &str, root: &Value, written: &mut Vec<(String, Value)>) {
        for nothing in [tree!({}), tree!([]), tree!("")] {
            if *value != nothing && path != "/message-type" {
                let kept = core::mem::replace(value, nothing);
                written.push((path.to_string(), root_with(root, path, value)));
                *value = kept;
            }
        }
        match value {
            Value::Object(members) => {
                for (name, member) in members.iter_mut() {
                    at(member, &format!("{path}/{name}"), root, written);
                }
            }
            Value::Array(items) => {
                for (place, item) in items.iter_mut().enumerate() {
                    at(item, &format!("{path}/{place}"), root, written);
                }
            }
            _ => {}
        }
    }
    fn root_with(root: &Value, path: &str, value: &Value) -> Value {
        let mut tree = root.clone();
        *pointer_mut(&mut tree, path).unwrap() = value.clone();
        tree
    }
    let mut walked = tree.clone();
    let Value::Object(members) = &mut walked else {
        return;
    };
    for (name, member) in members.iter_mut() {
        at(member, &format!("/{name}"), tree, written);
    }
}

/// A tree is refused, or it writes a message that has octets which are
/// read: a value that says nothing wrote an IE without octets, which the
/// receiver of the message refuses. Every value of every fixture is
/// replaced in turn by one that says nothing. The `octets` of an IE are
/// what they are written as, and are not a value.
#[test]
fn a_value_that_says_nothing_writes_no_message() {
    let mut trees = 0;
    let mut unread = Vec::new();
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        let tree = f::Message::decode(&wire).unwrap().to_tree();
        let mut written = Vec::new();
        emptied(&tree, &mut written);
        for (path, tree) in written {
            if path.ends_with("/octets") {
                continue;
            }
            trees += 1;
            let Ok(message) = f::Message::from_tree(tree.clone()) else {
                continue;
            };
            // A message under a header that says it is ciphered has no
            // octets before a context ciphers it
            let Ok(octets) = message.encode() else {
                assert!(
                    tree.get("security-header").is_some(),
                    "{name} {path}: {tree}"
                );
                continue;
            };
            match f::Message::decode(&octets) {
                Err(error) => unread.push(format!(
                    "{name} {path} = {}: {error}",
                    pointer(&tree, &path).unwrap()
                )),
                Ok(read) if read.to_tree() != message.to_tree() => unread.push(format!(
                    "{name} {path} = {}: read as another",
                    pointer(&tree, &path).unwrap()
                )),
                Ok(_) => {}
            }
        }
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        let tree = eps_fixture(name, &wire).to_tree();
        let mut written = Vec::new();
        emptied(&tree, &mut written);
        for (path, tree) in written {
            if path.ends_with("/octets") {
                continue;
            }
            trees += 1;
            let Ok(message) = e::Message::from_tree(tree.clone()) else {
                continue;
            };
            let Ok(octets) = message.encode() else {
                assert!(
                    tree.get("security-header").is_some(),
                    "{name} {path}: {tree}"
                );
                continue;
            };
            let direction = match name.starts_with("DetachRequestUeTerminated") {
                true => crate::Direction::Downlink,
                false => crate::Direction::Uplink,
            };
            match e::Message::decode_with(
                &octets,
                crate::DecodeOptions::STRICT.with_direction(direction),
            ) {
                Err(error) => unread.push(format!(
                    "{name} {path} = {}: {error}",
                    pointer(&tree, &path).unwrap()
                )),
                Ok(read) if read.to_tree() != message.to_tree() => unread.push(format!(
                    "{name} {path} = {}: read as another",
                    pointer(&tree, &path).unwrap()
                )),
                Ok(_) => {}
            }
        }
    }
    assert!(unread.is_empty(), "{}", unread.join("\n"));
    assert!(trees > 3000, "{trees}");
}

/// What a tree or a view writes is taken as it is written or is refused:
/// octets of another length than their value, a value that writes nothing
/// of its IE, and a header that the message is not sent with.
#[test]
fn nothing_that_is_written_is_cut_or_made_up() {
    let fgs_tree = |tree: Value| f::Message::from_tree(tree).map_err(|e| e.to_string());
    let eps_tree = |tree: Value| e::Message::from_tree(tree).map_err(|e| e.to_string());
    fn refused<T>(error: &str) -> Result<T, String> {
        Err(format!("cannot encode: {error}"))
    }

    // An SD of three octets, written with four: the last was left out.
    // Through a view, through a tree and through serde
    let accept = fgs("7e0042010115020101");
    let edited = |sd: &str| fgs_edited(&accept, |tree| tree["allowed-nssai"][0]["sd"] = tree!(sd));
    assert_eq!(edited("010203").unwrap(), "7e0042010115050401010203");
    assert_eq!(
        edited("01020304"),
        refused("allowed-nssai: \"01020304\" is not 3 octets")
    );
    assert_eq!(
        edited("0102"),
        refused("allowed-nssai: \"0102\" is not 3 octets")
    );
    let tree = |sd: Value| {
        fgs_tree(tree!({
            "message-type": "registration-accept",
            "5gs-registration-result": {"result": "3gpp-access"},
            "allowed-nssai": [{"sst": 1, "sd": sd}],
        }))
        .map(|message| hex::encode(message.encode().unwrap()))
    };
    assert_eq!(tree(tree!("010203")).unwrap(), "7e0042010115050401010203");
    assert_eq!(
        tree(tree!("01020304")),
        refused("allowed-nssai: \"01020304\" is not 3 octets")
    );
    assert_eq!(
        tree(tree!([1, 2, 3, 4])),
        refused("allowed-nssai: [1,2,3,4] is not a list of 3")
    );
    let contents = |sd: Value| {
        serde_json::from_value::<f::SNssaiContents>(
            tree!({"sst": 1, "sd": sd, "mapped_sst": null, "mapped_sd": null}).into(),
        )
    };
    assert_eq!(contents(tree!([1, 2, 3])).unwrap().sd, Some([1, 2, 3]));
    assert!(contents(tree!([1, 2, 3, 4])).is_err());
    assert!(contents(tree!([1, 2])).is_err());

    // The other lengths that a value has: an address of 4 octets and one
    // of 16, a MAC address of 6, an interface identifier of 8
    let address = |address: Value| {
        eps_tree(tree!({
            "message-type": "activate-default-eps-bearer-context-request",
            "eps-bearer-identity": 5,
            "procedure-transaction-identity": 1,
            "eps-qos": {"octets": "09"},
            "access-point-name": "internet",
            "pdn-address": {"ipv4": address},
        }))
        .map(|message| hex::encode(message.encode().unwrap()))
    };
    assert!(
        address(tree!("10.0.0.1"))
            .unwrap()
            .ends_with("05010a000001")
    );
    assert!(
        address(tree!("0a000001"))
            .unwrap()
            .ends_with("05010a000001")
    );
    assert_eq!(
        address(tree!("0a00000102")),
        refused("pdn-address: \"0a00000102\" is not 4 octets")
    );
    assert_eq!(
        address(tree!("0a0000")),
        refused("pdn-address: \"0a0000\" is not 4 octets")
    );
    let identity = |mac: &str| {
        fgs_tree(tree!({
            "message-type": "identity-response",
            "mobile-identity": {"mac-address": {"address": mac, "mauri": false}},
        }))
        .map(|message| hex::encode(message.encode().unwrap()))
    };
    assert_eq!(
        identity("010203040506").unwrap(),
        "7e005c000706010203040506"
    );
    let error = "mobile-identity: \"01020304050607\" is not 6 octets";
    assert_eq!(identity("01020304050607"), refused(error));

    // A value that writes no member of its IE: the IE had no octets, and
    // the message was one that its receiver refuses
    let accept = |result: Value| {
        fgs_tree(tree!({"message-type": "registration-accept", "5gs-registration-result": result}))
            .map(|message| hex::encode(message.encode().unwrap()))
    };
    assert_eq!(
        accept(tree!({"result": "3gpp-access"})).unwrap(),
        "7e00420101"
    );
    assert_eq!(accept(tree!({"sms-allowed": true})).unwrap(), "7e00420108");
    let error = "5gs-registration-result: {} writes no member of the IE";
    assert_eq!(accept(tree!({})), refused(error));
    let attach = eps("07411108298039103254769802f07000040201d011");
    let mut tree = attach.to_tree();
    tree["ue-network-capability"] = tree!({});
    assert_eq!(
        eps_tree(tree).map(|_| ()),
        refused("ue-network-capability: {} writes no member of the IE")
    );
    // A list without an entry, of an IE that has one at least
    let mut tree = fgs("2e0101c211000901000631310101ff0106060064060032").to_tree();
    tree["authorized-qos-rules"] = tree!([]);
    assert_eq!(
        fgs_tree(tree).map(|_| ()),
        refused("authorized-qos-rules: `qos-rules` has 0 entries, and must have 1 at least")
    );

    // A header that the message is not sent with: the tree was taken, and
    // the message had no octets
    let reject = |member: &str, written: Value| {
        let mut tree = tree!({"message-type": "registration-reject", "5gmm-cause": "congestion"});
        tree[member] = written;
        fgs_tree(tree).map(|message| hex::encode(message.encode().unwrap()))
    };
    assert_eq!(reject("spare-half-octet", tree!(15)).unwrap(), "7ef04416");
    assert_eq!(
        reject("spare-half-octet", tree!(16)),
        refused("`spare-half-octet` is 16, and must be 0 to 15")
    );
    assert_eq!(
        reject("security-header-type", tree!("integrity-protected")),
        refused(
            "`security-header-type` is \"integrity-protected\", and that of a plain message is \
             \"plain-5gs-nas-message-not-security-protected\": the header that protects a message is its `security-header`"
        )
    );
    assert_eq!(
        reject("extended-protocol-discriminator", tree!(46)),
        refused("`extended-protocol-discriminator` is 46, and that of a 5GMM message is 126")
    );
    let release = |member: &str, written: Value| {
        let mut tree = tree!({
            "message-type": "pdu-session-release-complete",
            "pdu-session-identity": 5,
            "procedure-transaction-identity": 1,
        });
        tree[member] = written;
        fgs_tree(tree).map(|message| hex::encode(message.encode().unwrap()))
    };
    assert_eq!(
        release("pdu-session-identity", tree!(6)).unwrap(),
        "2e0601d4"
    );
    assert_eq!(
        release("extended-protocol-discriminator", tree!(126)),
        refused("`extended-protocol-discriminator` is 126, and that of a 5GSM message is 46")
    );
    let information = |member: &str, written: Value| {
        let mut tree = tree!({"message-type": "esm-information-request"});
        tree["eps-bearer-identity"] = tree!(5);
        tree["procedure-transaction-identity"] = tree!(1);
        tree[member] = written;
        eps_tree(tree).map(|message| hex::encode(message.encode().unwrap()))
    };
    assert_eq!(
        information("eps-bearer-identity", tree!(15)).unwrap(),
        "f201d9"
    );
    assert_eq!(
        information("eps-bearer-identity", tree!(16)),
        refused("`eps-bearer-identity` is 16, and must be 0 to 15")
    );
    assert_eq!(
        information("protocol-discriminator", tree!(7)),
        refused("`protocol-discriminator` is 7, and that of an ESM message is 2")
    );
    let reject = |member: &str, written: Value| {
        let mut tree = tree!({"message-type": "attach-reject", "emm-cause": "congestion"});
        tree[member] = written;
        eps_tree(tree).map(|message| hex::encode(message.encode().unwrap()))
    };
    assert_eq!(
        reject("protocol-discriminator", tree!(2)),
        refused("`protocol-discriminator` is 2, and that of an EMM message is 7")
    );
    assert_eq!(
        reject("security-header-type", tree!("integrity-protected")),
        refused(
            "`security-header-type` is \"integrity-protected\", and that of a plain message is \
             \"plain-nas-message-not-security-protected\": the header that protects a message is its `security-header`"
        )
    );
    // A tree alone gives a message that has octets, as an edited one does
    let mut tree = fgs("7e004416").to_tree();
    tree["spare-half-octet"] = tree!(16);
    assert_eq!(
        f::Message::from_tree(tree).map_err(|e| e.to_string()),
        refused("`spare-half-octet` is 16, and must be 0 to 15")
    );
}

/// A tree gives a message that has octets, with two exceptions that are
/// named here so that there is no third: a plain message under a security
/// header whose type says that it is ciphered, and an EMM TRANSPORT with
/// its data container. Both are what a security context deciphered, and a
/// tree of them is written back as it is; a context ciphers them again.
#[test]
fn the_trees_without_octets_are_what_a_context_deciphered() {
    /// What a tree writes: a message with octets, one without, or nothing.
    #[derive(Debug, PartialEq)]
    enum Written {
        Octets,
        NoOctets,
        Refused,
    }
    let fgs = |header_type: &str| {
        let tree = tree!({
            "security-header": {
                "extended-protocol-discriminator": 126,
                "security-header-type": header_type,
                "spare-half-octet": 0,
                "message-authentication-code": 1,
                "sequence-number": 0,
            },
            "message-type": "registration-reject",
            "5gmm-cause": "congestion",
        });
        match f::Message::from_tree(tree.clone()) {
            Err(_) => Written::Refused,
            Ok(message) => {
                // The tree of the message is the one it was written from
                assert_eq!(f::Message::from_tree(message.to_tree()).unwrap(), message);
                match message.encode() {
                    Ok(_) => Written::Octets,
                    Err(_) => Written::NoOctets,
                }
            }
        }
    };
    assert_eq!(
        fgs("plain-5gs-nas-message-not-security-protected"),
        Written::Refused
    );
    assert_eq!(fgs("integrity-protected"), Written::Octets);
    assert_eq!(fgs("integrity-protected-and-ciphered"), Written::NoOctets);
    // Which message goes under which header is a rule of a sender, which
    // `validate()` has: the message has octets
    assert_eq!(
        fgs("integrity-protected-with-new-5g-nas-security-context"),
        Written::Octets
    );
    assert_eq!(
        fgs("integrity-protected-and-ciphered-with-new-5g-nas-security-context"),
        Written::NoOctets
    );

    let eps = |header_type: &str, message: Value| {
        let mut tree = message;
        tree["security-header"] = tree!({
            "security-header-type": header_type,
            "message-authentication-code": 1,
            "sequence-number": 0,
        });
        match e::Message::from_tree(tree) {
            Err(_) => Written::Refused,
            Ok(message) => {
                assert_eq!(e::Message::from_tree(message.to_tree()).unwrap(), message);
                match message.encode() {
                    Ok(_) => Written::Octets,
                    Err(_) => Written::NoOctets,
                }
            }
        }
    };
    let reject = || tree!({"message-type": "attach-reject", "emm-cause": "congestion"});
    assert_eq!(
        eps("plain-nas-message-not-security-protected", reject()),
        Written::Refused
    );
    assert_eq!(eps("integrity-protected", reject()), Written::Octets);
    assert_eq!(
        eps("integrity-protected-and-ciphered", reject()),
        Written::NoOctets
    );
    assert_eq!(
        eps(
            "integrity-protected-with-new-eps-security-context",
            reject()
        ),
        Written::Octets
    );
    assert_eq!(
        eps(
            "integrity-protected-and-ciphered-with-new-eps-security-context",
            reject()
        ),
        Written::NoOctets
    );
    assert_eq!(
        eps(
            "integrity-protected-and-partially-ciphered-nas-message",
            reject()
        ),
        Written::NoOctets
    );
    // An EMM TRANSPORT: without a container and with one that is ciphered
    // it has octets, and with a data container it waits for its ciphering
    assert_eq!(
        eps("security-header-for-the-emm-transport-message", tree!({})),
        Written::Octets
    );
    let ciphered = tree!({"ciphered-message": {"octets": "abcd"}});
    assert_eq!(
        eps("security-header-for-the-emm-transport-message", ciphered),
        Written::Octets
    );
    let deciphered = tree!({"data-container": {"octets": "0102"}});
    assert_eq!(
        eps("security-header-for-the-emm-transport-message", deciphered),
        Written::NoOctets
    );

    // The message under the header is still one that is sent: what its own
    // header cannot have is refused under a header of any type
    let tree = tree!({
        "security-header": {
            "extended-protocol-discriminator": 126,
            "security-header-type": "integrity-protected-and-ciphered",
            "spare-half-octet": 0,
            "message-authentication-code": 1,
            "sequence-number": 0,
        },
        "message-type": "registration-reject",
        "5gmm-cause": "congestion",
        "spare-half-octet": 16,
    });
    assert_eq!(
        f::Message::from_tree(tree).unwrap_err().to_string(),
        "cannot encode: `spare-half-octet` is 16, and must be 0 to 15"
    );
    // And a plain message has octets or is refused: every fixture
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-5gs.tsv")) {
        let message = f::Message::decode(&wire).unwrap();
        let written = f::Message::from_tree(message.to_tree()).unwrap();
        assert!(written.encode().is_ok(), "{name}");
    }
    for (name, wire) in fixtures(include_str!("../tests/fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        let written = e::Message::from_tree(message.to_tree()).unwrap();
        assert!(written.encode().is_ok(), "{name}");
    }
}

#[test]
fn an_ie_that_both_systems_code_alike_has_one_tree() {
    // The control plane only indication (TS 24.501 §9.11.4.23, TS 24.301
    // §9.9.4.23): its CPOI by the name of its table, in both trees.
    let accept = f::PduSessionEstablishmentAccept::new(
        f::PduSessionType::new(1),
        f::SscMode::new(1),
        f::QosRules::new(vec![]),
        f::SessionAmbr::new(vec![6, 0, 1, 6, 0, 1]),
    )
    .with_control_plane_only_indication(f::ControlPlaneOnlyIndication::control_plane_only());
    let five = f::Message::new_5gsm(accept, 1, 1).to_tree();
    let request = e::ActivateDefaultEpsBearerContextRequest::new(
        e::EpsQualityOfService::new(vec![9]),
        e::AccessPointName::new(vec![8, b'i', b'n', b't', b'e', b'r', b'n', b'e', b't']),
        e::PdnAddress::new(vec![1, 10, 0, 0, 1]),
    )
    .with_control_plane_only_indication(e::ControlPlaneOnlyIndication::control_plane_only());
    let eps = e::Message::new_esm(request, 5, 1).to_tree();
    assert_eq!(five["control-plane-only-indication"], tree!({"cpoi": true}));
    assert_eq!(eps["control-plane-only-indication"], tree!({"cpoi": true}));
}

#[test]
fn a_security_header_leaves_out_what_the_system_decides() {
    // A security protected 5GS NAS message is one of 5GMM (TS 24.501
    // §9.1.1): its tree says neither the discriminator nor a spare half
    // octet of zero, as the tree of a plain message does not, and the EPS
    // header has neither.
    let protected = fgs("7e01e73b901b007e006416");
    let header = &protected.to_tree()["security-header"];
    assert_eq!(
        *header,
        tree!({
            "security-header-type": "integrity-protected",
            "message-authentication-code": 3879440411u32,
            "sequence-number": 0,
        })
    );
    assert_eq!(
        f::Message::from_tree(protected.to_tree()).unwrap(),
        protected
    );
    // A spare half octet that is set is shown, and written back.
    let spare = fgs("7e31e73b901b007e006416");
    assert_eq!(
        spare.to_tree()["security-header"]["spare-half-octet"],
        tree!(3)
    );
    assert_eq!(f::Message::from_tree(spare.to_tree()).unwrap(), spare);
}

#[test]
fn the_paging_identity_is_named_by_its_table() {
    // TS 24.301 Table 9.9.3.25A.1: bit 1 is 0 for IMSI and 1 for TMSI.
    let notification = e::Message::new_emm(e::CsServiceNotification::new(
        e::PagingIdentity::from_paging_identity(e::PagingIdentityValue::Tmsi),
    ));
    assert_eq!(notification.to_tree()["paging-identity"], tree!("tmsi"));
    let tree = tree!({"message-type": "cs-service-notification", "paging-identity": "imsi"});
    let written = e::Message::from_tree(tree).unwrap();
    assert_eq!(written.encode().unwrap(), [0x07, 0x64, 0x00]);
}

#[test]
fn a_value_that_holds_an_ie_shows_it_as_the_tree_of_that_ie() {
    // LADN information of a REGISTRATION ACCEPT (TS 24.501 §9.11.3.30): the
    // DNN and the TAI list of each LADN as their trees, not their octets.
    let plmn = crate::identity::Plmn::new("208", "93").unwrap();
    let tais = f::TrackingAreaIdentityList::from_plmn_tacs(&plmn, &[1, 2]).unwrap();
    let dnn = f::Dnn::from_string("internet").unwrap();
    let entry = f::LadnInfoEntry {
        dnn: dnn.value.to_vec(),
        tai_list: tais.value.to_vec(),
    };
    let ladn = f::LadnInformation::from_entries(&[entry]).unwrap();
    let accept =
        f::RegistrationAccept::new(f::RegistrationResult::new(vec![1])).with_ladn_information(ladn);
    let message = f::Message::new_5gmm(accept);
    let tree = message.to_tree();
    assert_eq!(tree["ladn-information"][0]["dnn"], tree!("internet"));
    assert_eq!(
        tree["ladn-information"][0]["tai-list"],
        tree!([{"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1, 2]}}])
    );
    let written = f::Message::from_tree(tree).unwrap();
    assert_eq!(written.encode().unwrap(), message.encode().unwrap());

    // An EPS packet filter (TS 24.008 §10.5.6.12): its direction by name,
    // and its components, as those of a 5GS QoS rule.
    let request = eps("6201c5050109062131ff023011");
    let filter = &request.to_tree()["tft"]["packet-filters"][0];
    assert_eq!(filter["direction"], tree!("bidirectional"));
    assert_eq!(
        filter["components"],
        tree!([{"protocol-identifier-next-header": 17}])
    );
}

#[test]
fn a_member_that_a_tree_leaves_out_is_read_back_as_absent() {
    // The input of the fuzz target tree_eps that CI found: an ATTACH REJECT
    // whose S&F satellite operation parameters indicate no wait time
    // (TS 24.301 §9.9.3.73), between unknown IEs
    let message = eps("0744380000160113210100010020");
    let tree = message.to_tree();
    assert_eq!(
        tree["s-and-f-satellite-operation-parameters"],
        tree!({"monitoring-list": "not-present"})
    );
    let written = e::Message::from_tree(tree.clone()).unwrap();
    assert_eq!(written.to_tree(), tree);
    assert!(written.means_the_same(&message));

    // Written alone, the IE has what is written, and lacks what is not
    let reject = |parameters: Value| {
        e::Message::from_tree(tree!({
            "message-type": "attach-reject",
            "emm-cause": "congestion",
            "s-and-f-satellite-operation-parameters": parameters,
        }))
        .map(|message| hex::encode(message.encode().unwrap()))
        .map_err(|error| error.to_string())
    };
    assert_eq!(
        reject(tree!({"monitoring-list": "delete"})),
        Ok("074416210104".into())
    );
    assert_eq!(
        reject(tree!({"wait-time": 600, "monitoring-list": "not-present"})),
        Ok("0744162103010258".into())
    );
}

/// A container of a NAS TRANSPORT is a 5GSM message when its type says so, and can be
/// written as one only when its octets are one.
#[test]
fn a_transport_container_is_a_message_when_its_type_says_so() {
    // UL and DL NAS TRANSPORT of SMS whose octets read as a 5GSM message
    for hex in ["7e00670200072e0101c1ffff91", "7e006802000 72e0101c1ffff91"] {
        let transport = fgs(&hex.replace(' ', ""));
        let container = &ie(&transport, "payload-container");
        assert_eq!(container, &tree!({"octets": "2e0101c1ffff91"}), "{hex}");
    }
    // An N1 SM container whose octets are no 5GSM message
    let transport = fgs("7e00670100020102");
    let message = fgs("2e0101c1ffff91").to_tree();
    let error = fgs_edited(&transport, |tree| tree["payload-container"] = message).unwrap_err();
    assert!(
        error.contains("the octets are not a 5GSM message"),
        "{error}"
    );
}

/// A message is written back from its tree with what it was received with: its IEs out
/// of sequence and its unknown IEs, also under a security header.
#[test]
fn a_message_is_written_back_with_what_it_was_received_with() {
    for hex in ["2e0101c1ffffa191", "7e01aabbccdd057e006416700101"] {
        let message = fgs(hex);
        let written = message.with_tree(message.to_tree()).unwrap();
        assert_eq!(hex::encode(written.encode().unwrap()), hex);
    }
}

/// A message means what another means as their trees do, and a message without a tree
/// what an equal one means.
#[test]
fn a_ciphered_message_means_what_an_equal_one_means() {
    let ciphered = fgs("7e0200000000001234");
    assert!(ciphered.means_the_same(&ciphered.clone()));
    assert!(!ciphered.means_the_same(&fgs("7e0200000000005678")));
}

/// A message type that is not one is refused with the nearest names.
#[test]
fn a_message_type_that_is_not_one_is_refused_with_the_nearest() {
    let error = f::Message::from_tree(tree!({"message-type": "registration-acept"}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("registration-accept"), "{error}");
}

/// The protection scheme of a SUCI is shown by its name where it has one, and a SUCI is
/// written with an MSIN with the null scheme alone.
#[test]
fn the_protection_scheme_of_a_suci_is_shown_by_its_name() {
    use crate::tree::Tree;
    let output = "11".repeat(32) + "2222222222" + &"33".repeat(8);
    for (scheme, name) in [
        ("00", tree!("null")),
        ("01", tree!("profile-a")),
        ("02", tree!("profile-b")),
        ("0c", tree!(12)),
    ] {
        let (key, body) = match scheme {
            "00" => ("00", "0000000010".to_string()),
            _ => ("01", output.clone()),
        };
        let identity = hex::decode(format!("0102f839f0ff{scheme}{key}{body}")).unwrap();
        let tree = f::MobileIdentity::new(identity).to_tree();
        assert_eq!(tree["suci"]["imsi"]["protection-scheme"], name, "{scheme}");
    }
    let written = tree!({"suci": {"imsi": {"plmn": "208-93", "routing-indicator": "0",
        "protection-scheme": "profile-a", "home-network-public-key-id": 1, "msin": "0000000001"}}});
    let error = tree::from_value::<f::MobileIdentity>(&written)
        .unwrap_err()
        .to_string();
    assert!(error.contains("is written with the null scheme"), "{error}");
}

/// An algorithm of a UE security capability that a value lists twice is refused, as
/// the IE that it would be has it once.
#[test]
fn an_algorithm_listed_twice_is_refused_as_the_ie_has_it_once() {
    let capability = tree!({"ea": [1, 1, 2], "ia": [2]});
    let error = tree::from_value::<f::UeSecurityCapability>(&capability)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(r#"the IE would be {"ea":[1,2],"ia":[2]"#),
        "{error}"
    );
}

/// An EPS message is written back from its tree with what it was received with, also
/// under a security header; a ciphered one means what an equal one means.
#[test]
fn an_eps_message_is_written_back_with_what_it_was_received_with() {
    // ATTACH REJECT and ESM INFORMATION REQUEST with an unknown IE, the reject under an
    // integrity protection header too
    for hex in ["074403700101", "5201d9700101", "17aabbccdd05074403700101"] {
        let message = eps(hex);
        let written = message.with_tree(message.to_tree()).unwrap();
        assert_eq!(hex::encode(written.encode().unwrap()), hex);
    }
    let ciphered = eps("2700000000051234");
    assert!(ciphered.means_the_same(&ciphered.clone()));
    assert!(!ciphered.means_the_same(&eps("2700000000055678")));
}

/// The fields of an EPS tree that read as names are written by their numbers too, and
/// those of a SERVICE REQUEST within their bits.
#[test]
fn the_fields_of_an_eps_tree_are_written_by_their_numbers() {
    let reject = eps("074403");
    let edited = eps_edited(&reject, |tree| tree["security-header-type"] = tree!(0));
    assert_eq!(edited, Ok("074403".into()));
    let request = eps("c7200000");
    let written = |sequence: u8| {
        eps_edited(&request, |tree| {
            tree["ksi-and-sequence-number"] = tree!({"ksi": 1, "sequence-number": sequence});
        })
    };
    assert_eq!(written(31), Ok("c73f0000".into()));
    assert!(written(32).is_err());
}

/// An EMM TRANSPORT has its security header and its octets, and no other entry.
#[test]
fn an_emm_transport_has_no_other_entry() {
    let transport = eps("b70000000000abcd");
    for entry in [tree!(1), tree!({"octets": "01"})] {
        let error = eps_edited(&transport, |tree| tree["other"] = entry).unwrap_err();
        assert!(
            error.contains("`other` is no entry of an EMM TRANSPORT"),
            "{error}"
        );
    }
}

/// The EPS bearers of an IE are written by their identities.
#[test]
fn eps_bearers_are_written_by_their_identities() {
    use crate::tree::Tree;
    let status = tree::from_value::<e::HeaderCompressionConfigurationStatus>(&tree!([5, 6]));
    assert_eq!(status.unwrap().to_tree(), tree!([5, 6]));
}

/// A value that a setter does not write is refused: the S1 UE network capability has no
/// EIA7, whose bit is EPS-UPIP; and a field of a 5GS registration result with a spare bit
/// set is shown by its octets.
#[test]
fn a_value_that_a_setter_does_not_write_is_refused() {
    let written = tree!({"eea": [0], "eia": [1, 7]});
    let error = tree::from_value::<f::S1UeNetworkCapability>(&written)
        .unwrap_err()
        .to_string();
    assert!(error.contains("eia cannot be [1,7]"), "{error}");
    let accept = fgs("7e00420181");
    assert_eq!(
        accept.to_tree()["5gs-registration-result"],
        tree!({"octets": "81"})
    );
}

/// A container without octets is written from the tree of the message that it names.
#[test]
fn a_container_without_octets_is_written_from_its_message() {
    let tree = tree!({
        "message-type": "ul-nas-transport",
        "payload-container-type": {"octets": "01"},
        "payload-container": fgs("2e0101c1ffff91").to_tree(),
    });
    let transport = f::Message::from_tree(tree).unwrap();
    assert_eq!(
        hex::encode(transport.encode().unwrap()),
        "7e00670100072e0101c1ffff91"
    );
}

/// A code that has no name is written by its number in the bits of its field, in the
/// octets that the IE has.
#[test]
fn a_code_without_a_name_is_written_in_the_octets_that_the_ie_has() {
    let accept = fgs("7e0042010177000bf202f8390100421122334421020100");
    let edited = fgs_edited(&accept, |tree| {
        tree["5gs-network-feature-support"]["emc"] = tree!(1);
    });
    assert_eq!(
        edited,
        Ok("7e0042010177000bf202f8390100421122334421020500".into())
    );
}

/// An IE of one octet has its octet before a value writes a member of it: a value that
/// writes none leaves it as it is, where an IE of octets that has none yet is refused.
#[test]
fn an_ie_of_one_octet_is_written_from_a_value_without_members() {
    let kind = tree::from_value::<f::RegistrationType>(&tree!({})).unwrap();
    assert_eq!(kind.value, 0);
    assert!(tree::from_value::<f::RegistrationResult>(&tree!({})).is_err());
}

/// An IE of octets alone, the ABBA, is written and shown by its octets.
#[test]
fn an_ie_of_octets_alone_is_written_and_shown_by_its_octets() {
    use crate::tree::Tree;
    let abba = tree::from_value::<f::Abba>(&tree!({"octets": "0102"})).unwrap();
    assert_eq!(abba.value[..], [1, 2]);
    assert_eq!(abba.to_tree(), tree!({"octets": "0102"}));
}

#[test]
fn the_octets_of_an_ie_are_those_that_the_message_came_with() {
    use crate::tree::ErrorKind;
    // SECURITY MODE COMPLETE with the REGISTRATION REQUEST it replays
    let complete = fgs("7e005e7100137e004101000d0102f8390000000021436587f9");
    let octets = |path| complete.select(path);
    let replayed = tree!("7e004101000d0102f8390000000021436587f9");
    assert_eq!(
        octets("/nas/nas-message-container/octets"),
        Ok(vec![replayed])
    );
    // An IE of the message in a container, by a name written in any case
    let identity = tree!("0102f8390000000021436587f9");
    let path = "/nas/NAS message container/5GS mobile identity/Octets";
    assert_eq!(octets(path), Ok(vec![identity]));
    // An optional IE that the message does not have
    assert_eq!(octets("/nas/imeisv/octets"), Ok(vec![]));
    // What is no IE
    for (path, kind) in [
        ("/nas/message-type/octets", ErrorKind::Refused),
        (
            "/nas/nas-message-container/5gs-mobile-identity/suci/octets",
            ErrorKind::NoSuchMember,
        ),
        (
            "/nas/nas-message-container/5gmm-cause/octets",
            ErrorKind::NoSuchMember,
        ),
        ("/nas/5gs-mobile-identity/octets", ErrorKind::NoSuchMember),
        ("/nas/octets", ErrorKind::NoSuchMember),
        ("/ngap/Cause/octets", ErrorKind::Path),
    ] {
        assert_eq!(
            octets(path).map_err(|error| error.kind()),
            Err(kind),
            "{path}"
        );
    }
    // ATTACH REJECT with EMM cause #3
    let reject = eps("074403");
    assert_eq!(
        reject.select("/nas/emm-cause/octets"),
        Ok(vec![tree!("03")])
    );
}

/// A tree leaves out the fields of a security header that the system decides,
/// and an edit of the header by its tree writes them all the same.
#[test]
fn an_edit_of_a_security_header_by_its_tree_keeps_what_the_system_decides() {
    let protected = fgs("7e01aabbccdd057e006416");
    let mut tree = protected.to_tree();
    let header = &tree["security-header"];
    assert!(
        header.get("extended-protocol-discriminator").is_none(),
        "{header}"
    );
    crate::paths::set(&mut tree, "/nas/security-header/sequence-number", tree!(6)).unwrap();
    let edited = protected.with_tree(tree).unwrap();
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "7e01aabbccdd067e006416"
    );
}
