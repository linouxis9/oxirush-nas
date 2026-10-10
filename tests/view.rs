//! The view of a message: each IE by its name, with its value and octets.
#![cfg(feature = "serde")]

use oxirush_nas::{nas_5gs as f, nas_eps as e};
use serde_json::{Value, json};

fn fgs(hex: &str) -> f::Nas5gsMessage {
    f::Nas5gsMessage::from_bytes(&hex::decode(hex).unwrap()).unwrap()
}

fn eps(hex: &str) -> e::NasEpsMessage {
    e::NasEpsMessage::from_bytes(&hex::decode(hex).unwrap()).unwrap()
}

/// The octets of the 5GS message of an edited view.
fn fgs_edited(message: &f::Nas5gsMessage, edit: impl FnOnce(&mut Value)) -> Result<String, String> {
    let mut view = message.to_view();
    edit(&mut view);
    let edited = message.with_view(view).map_err(|error| error.to_string())?;
    Ok(hex::encode(edited.to_bytes().unwrap()))
}

fn eps_edited(message: &e::NasEpsMessage, edit: impl FnOnce(&mut Value)) -> Result<String, String> {
    let mut view = message.to_view();
    edit(&mut view);
    let edited = message.with_view(view).map_err(|error| error.to_string())?;
    Ok(hex::encode(edited.to_bytes().unwrap()))
}

fn fixtures(file: &str) -> impl Iterator<Item = (&str, Vec<u8>)> {
    file.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split_once('\t').unwrap())
        .map(|(name, hex)| (name, hex::decode(hex).unwrap()))
}

fn eps_fixture(name: &str, wire: &[u8]) -> e::NasEpsMessage {
    let direction = if name.starts_with("DetachRequestToUe") {
        e::Direction::Downlink
    } else {
        e::Direction::Uplink
    };
    e::NasEpsMessage::from_bytes_with_direction(wire, direction).unwrap()
}

#[test]
fn a_coded_value_reads_and_writes_by_its_name() {
    // 5GMM STATUS, cause #22.
    let status = fgs("7e006416");
    let view = status.to_view();
    assert_eq!(
        view,
        json!({
            "extended-protocol-discriminator": {"value": 126},
            "security-header-type": {"value": "plain-nas-message"},
            "message-type": {"value": "5gmm-status"},
            "5gmm-cause": {"value": "congestion", "octets": "16"},
        })
    );
    let named = |name: Value| fgs_edited(&status, |view| view["5gmm-cause"]["value"] = name);
    assert_eq!(named(json!("illegal-ue")).unwrap(), "7e006403");
    // A name is read in any case, with hyphens, underscores or spaces.
    for name in ["Illegal UE", "ILLEGAL_UE", "IllegalUe"] {
        assert_eq!(named(json!(name)).unwrap(), "7e006403", "{name}");
    }
    // A value the specification does not name is a number, read and written,
    // also in hexadecimal.
    assert_eq!(named(json!(200)).unwrap(), "7e0064c8");
    assert_eq!(named(json!("0xc8")).unwrap(), "7e0064c8");
    assert_eq!(
        fgs("7e0064c8").to_view()["5gmm-cause"],
        json!({"value": 200, "octets": "c8"})
    );
    // A name that does not exist is an error that lists those that do.
    let error = named(json!("congestio")).unwrap_err();
    assert!(error.contains("5gmm-cause: no name `congestio`, expected one of illegal-ue, "));
    // The number of a cause that has a name is that cause.
    assert_eq!(named(json!(22)).unwrap(), "7e006416");
    assert_eq!(named(json!(3)).unwrap(), "7e006403");
    // Nothing else is a cause.
    for value in [json!(256), json!({"cause": "illegal-ue"}), json!(true)] {
        assert!(named(value.clone()).is_err(), "{value}");
    }
}

#[test]
fn the_octets_of_an_ie_are_written_as_they_are() {
    let status = fgs("7e006416");
    let edit = |ie: Value| fgs_edited(&status, |view| view["5gmm-cause"] = ie);
    assert_eq!(edit(json!({"octets": "03"})).unwrap(), "7e006403");
    // A value left as it was follows the octets.
    assert_eq!(
        edit(json!({"octets": "03", "value": "congestion"})).unwrap(),
        "7e006403"
    );
    // Both written: they have to say the same.
    assert_eq!(
        edit(json!({"octets": "03", "value": "illegal-ue"})).unwrap(),
        "7e006403"
    );
    let error = edit(json!({"octets": "03", "value": "plmn-not-allowed"})).unwrap_err();
    assert!(
        error.contains("5gmm-cause: the octets and the value"),
        "{error}"
    );
    for ie in [
        json!({"octets": "0304"}),
        json!({"octets": "3"}),
        json!({"octets": [3]}),
    ] {
        assert!(edit(ie.clone()).is_err(), "{ie}");
    }
    assert!(
        edit(json!({"octets": "03", "length": 1}))
            .unwrap_err()
            .contains("`length`")
    );

    // REGISTRATION ACCEPT with a 5G-GUTI: any octets, and the length follows.
    let accept = fgs("7e0042010177000bf202f83901004211223344");
    let mut view = accept.to_view();
    view["5g-guti"]["octets"] = json!("f2ffffff");
    let odd = accept.with_view(view).unwrap();
    assert_eq!(
        hex::encode(odd.to_bytes().unwrap()),
        "7e00420101770004f2ffffff"
    );
    // Octets that are no identity have no value, and can be given one.
    assert_eq!(odd.to_view()["5g-guti"], json!({"octets": "f2ffffff"}));
    let imei = |digits: &str| {
        fgs_edited(&odd, |view| {
            view["5g-guti"]["value"] = json!({"imei": digits})
        })
    };
    assert_eq!(
        imei("356938035643809").unwrap(),
        "7e004201017700083b65390853468390"
    );
    assert!(imei("1").is_err());
}

#[test]
fn the_fields_of_an_octet_read_and_write_by_name() {
    // REGISTRATION REQUEST: initial registration, follow-on request, no key.
    let request = fgs("7e004179000d0102f8390000000000000010022e08a020000000000000");
    assert_eq!(
        request.to_view()["5gs-registration-type"],
        json!({"octets": "79", "value": {
            "registration-type": "initial-registration",
            "follow-on-request": true,
            "ngksi": 7,
            "tsc": false,
        }})
    );
    let edited = fgs_edited(&request, |view| {
        let value = &mut view["5gs-registration-type"]["value"];
        value["registration-type"] = json!("mobility-registration-update");
        value["follow-on-request"] = json!(false);
    });
    assert_eq!(&edited.unwrap()[..8], "7e004172");
    // The members that are written are set, the others stay.
    let edited = fgs_edited(&request, |view| {
        view["5gs-registration-type"]["value"] =
            json!({"Registration Type": "emergency registration"});
    });
    assert_eq!(&edited.unwrap()[..8], "7e00417c");
    // The number of a type that has a name is that type.
    let edited = fgs_edited(&request, |view| {
        view["5gs-registration-type"]["value"]["registration-type"] = json!(2);
    });
    assert_eq!(&edited.unwrap()[6..8], "7a");
    for (member, value) in [
        ("registration-type", json!("mobility")),
        ("registration-type", json!(8)),
        ("follow-on-request", json!(1)),
        ("follow-on", json!(true)),
        ("ngksi", json!(8)),
    ] {
        let edited = fgs_edited(&request, |view| {
            view["5gs-registration-type"]["value"][member] = value;
        });
        assert!(edited.is_err(), "{member}");
    }
}

#[test]
fn the_service_type_of_a_service_request_reads_beside_the_ngksi() {
    // SERVICE REQUEST: signalling, native ngKSI 1.
    let request = fgs("7e004c010007f4004211223344");
    let view = request.to_view();
    assert_eq!(
        view["ngksi"],
        json!({"octets": "01", "value": {
            "service-type": "signalling",
            "key-set-identifier": {"native": 1},
        }})
    );
    assert_eq!(
        view["5g-s-tmsi"]["value"],
        json!({"s-tmsi": {"amf-set-id": 1, "amf-pointer": 2, "tmsi": 0x1122_3344}})
    );
    let edited = fgs_edited(&request, |view| {
        view["ngksi"]["value"]["service-type"] = json!("data");
        view["ngksi"]["value"]["key-set-identifier"] = json!("no-key");
    });
    assert_eq!(edited.unwrap(), "7e004c170007f4004211223344");
    // Service type 7 has no name: it is its number, or the octets.
    assert_eq!(
        fgs("7e004c710007f4004211223344").to_view()["ngksi"]["value"]["service-type"],
        7
    );
    let numbered = |number: u8| {
        fgs_edited(&request, |view| {
            view["ngksi"]["value"]["service-type"] = json!(number)
        })
    };
    assert_eq!(numbered(7).unwrap(), "7e004c710007f4004211223344");
    // The number of a type that has a name is that type.
    assert_eq!(numbered(1).unwrap(), "7e004c110007f4004211223344");
    assert!(numbered(16).unwrap_err().contains("ngksi"));
    assert_eq!(
        fgs_edited(&request, |view| view["ngksi"]["octets"] = json!("71")).unwrap(),
        "7e004c710007f4004211223344"
    );
    // In another message the same field is the ngKSI alone.
    assert_eq!(
        fgs("7e005d220102f070").to_view()["ngksi"]["value"],
        json!({"native": 1})
    );
}

#[test]
fn a_structured_ie_reads_and_writes_in_its_usual_notation() {
    // REGISTRATION ACCEPT with a 5G-GUTI, a TAI list, an allowed NSSAI and
    // T3512.
    let accept = fgs("7e0042010177000bf202f8390100421122334454070002f839000001150201015e0121");
    let view = accept.to_view();
    assert_eq!(
        view["5gs-registration-result"]["value"]["result"],
        "3gpp-access"
    );
    assert_eq!(
        view["5g-guti"],
        json!({"octets": "f202f83901004211223344", "value": {"guti": {
            "plmn": "208-93",
            "amf-region-id": 1,
            "amf-set-id": 1,
            "amf-pointer": 2,
            "tmsi": 0x1122_3344,
        }}})
    );
    assert_eq!(
        view["tai-list"]["value"],
        json!([{"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1]}}])
    );
    assert_eq!(
        view["allowed-nssai"],
        json!({"octets": "0101", "value": [
            {"sst": 1, "sd": null, "mapped-sst": null, "mapped-sd": null},
        ]})
    );
    // One hour, in seconds.
    assert_eq!(view["t3512-value"], json!({"octets": "21", "value": 3600}));

    let edited = fgs_edited(&accept, |view| {
        view["5g-guti"]["value"]["guti"]["plmn"] = json!("001-01");
        view["5g-guti"]["value"]["guti"]["tmsi"] = json!("0xdeadbeef");
        view["tai-list"]["value"] = json!([{"one-plmn-consecutive":
            {"plmn": "310-410", "first-tac": 42, "count": 3}}]);
        view["allowed-nssai"]["value"] = json!([{"sst": 1, "sd": "010203"}, {"SST": 2}]);
        view["t3512-value"]["value"] = json!("deactivated");
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
        ("/5g-guti/value/guti/tmsy", json!(1)),
        ("/5g-guti/value/guti/amf-set-id", json!(5000)),
        ("/5g-guti/value/guti/plmn", json!("20893")),
        (
            "/5g-guti/value/guti/plmn",
            json!({"mcc": [2, 0, 8], "mnc": [9, 3, 15]}),
        ),
        ("/allowed-nssai/value/0/sd", json!("0102")),
        ("/allowed-nssai/value", json!([])),
        ("/t3512-value/value", json!(7)),
        ("/t3512-value/value", json!("stopped")),
        ("/tai-list/value/0/one-plmn-non-consecutive/tacs", json!([])),
    ] {
        let mut view = accept.to_view();
        match view.pointer_mut(pointer) {
            Some(member) => *member = value,
            None => {
                let (parent, member) = pointer.rsplit_once('/').unwrap();
                view.pointer_mut(parent).unwrap()[member] = value;
            }
        }
        assert!(accept.with_view(view).is_err(), "{pointer}");
    }
}

#[test]
fn a_container_of_a_message_reads_and_writes_as_its_view() {
    // UL NAS TRANSPORT with a PDU SESSION ESTABLISHMENT REQUEST for the DNN
    // "internet".
    let transport = fgs(
        "7e00670100152e0101c1ffff91a12801007b000780000a00000d00120181220101250908696e7465726e6574",
    );
    let view = transport.to_view();
    assert_eq!(view["payload-container-type"]["value"], "n1-sm-information");
    assert_eq!(
        view["dnn"],
        json!({"octets": "08696e7465726e6574", "value": "internet"})
    );
    let request = &view["payload-container"]["value"];
    assert_eq!(
        request["message-type"]["value"],
        "pdu-session-establishment-request"
    );
    assert_eq!(request["pdu-session-identity"]["value"], 1);
    assert_eq!(request["pdu-session-type"]["value"], "ipv4");
    assert_eq!(request["ssc-mode"]["value"], "ssc1");
    assert_eq!(
        request["integrity-protection-maximum-data-rate"]["value"],
        json!({"ul": "full-rate", "dl": "full-rate"})
    );
    let edited = fgs_edited(&transport, |view| {
        let request = &mut view["payload-container"]["value"];
        request["pdu-session-identity"]["value"] = json!(5);
        request["pdu-session-type"]["value"] = json!("IPv4v6");
        request["ssc-mode"] = Value::Null;
        view["dnn"]["value"] = json!("ims.example");
    });
    assert_eq!(
        edited.unwrap(),
        "7e00670100142e0501c1ffff932801007b000780000a00000d0012018122010125\
         0c03696d73076578616d706c65"
    );
    let error = fgs_edited(&transport, |view| {
        view["payload-container"]["value"]["pdu-session-type"]["value"] = json!("ipv5");
    });
    assert!(
        error
            .unwrap_err()
            .contains("payload-container: pdu-session-type: no name `ipv5`")
    );
    // A payload of another type, and a ciphered message, have octets alone.
    let lpp = fgs("7e00670300020102");
    assert_eq!(
        lpp.to_view()["payload-container"],
        json!({"octets": "0102"})
    );
    let complete = fgs("7e005e7100087e02000000000102");
    assert_eq!(
        complete.to_view()["nas-message-container"],
        json!({"octets": "7e02000000000102"})
    );
    // SECURITY MODE COMPLETE with the REGISTRATION REQUEST it replays.
    let complete = fgs("7e005e7100137e004101000d0102f8390000000021436587f9");
    let replayed = &complete.to_view()["nas-message-container"]["value"];
    assert_eq!(replayed["message-type"]["value"], "registration-request");
    assert_eq!(
        replayed["5gs-mobile-identity"]["value"]["suci"]["imsi"]["msin"],
        "123456789"
    );
}

#[test]
fn an_ie_is_taken_out_and_none_is_made_up() {
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let remove = |name: &str| {
        fgs_edited(&accept, |view| {
            view.as_object_mut().unwrap().remove(name).unwrap();
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
    let add = |name: &str, ie: Value| fgs_edited(&accept, |view| view[name] = ie);
    let error = add("allowed-nsai", json!({"octets": "0101"})).unwrap_err();
    assert!(
        error.contains("`allowed-nsai` is no IE of the message"),
        "{error}"
    );
    let error = add("Allowed NSSAI", json!({"octets": "0101"})).unwrap_err();
    assert!(error.contains("named twice"), "{error}");
    // An IE is named in any case, and by the name of its field in the codec.
    for name in ["Allowed NSSAI", "allowed_nssai", "ALLOWED-NSSAI"] {
        let mut view = accept.to_view();
        let ie = view
            .as_object_mut()
            .unwrap()
            .remove("allowed-nssai")
            .unwrap();
        view[name] = ie;
        assert_eq!(accept.with_view(view).unwrap(), accept, "{name}");
    }
    let mut view = accept.to_view();
    let guti = view.as_object_mut().unwrap().remove("5g-guti").unwrap();
    view["fg_guti"] = guti;
    assert_eq!(accept.with_view(view).unwrap(), accept);
    // The fields of the header are written by their value.
    let request = fgs("2e0101c1ffff91");
    let edited = fgs_edited(&request, |view| {
        view["pdu-session-identity"]["value"] = json!(15);
        view["procedure-transaction-identity"]["value"] = json!("0x2a");
    });
    assert_eq!(edited.unwrap(), "2e0f2ac1ffff91");
    assert!(
        fgs_edited(&request, |view| view["message-type"]["octets"] =
            json!("c1"))
        .is_err()
    );
}

#[test]
fn a_view_is_read_through_a_security_header_which_it_shows() {
    // Integrity protected 5GMM STATUS.
    let protected = fgs("7e01aabbccdd057e006416");
    let view = protected.to_view();
    assert_eq!(view["message-type"]["value"], "5gmm-status");
    assert_eq!(view["5gmm-cause"]["value"], "congestion");
    // The header of the plain message is plain, and the one that protects
    // it is beside it.
    assert_eq!(view["security-header-type"]["value"], "plain-nas-message");
    assert_eq!(
        view["security-header"],
        json!({"value": {
            "extended-protocol-discriminator": 126,
            "security-header-type": "integrity-protected",
            "message-authentication-code": 0xaabb_ccdd_u32,
            "sequence-number": 5,
        }})
    );
    assert_eq!(protected.with_view(view.clone()).unwrap(), protected);
    // The code is that of the message as it was: an edit of the message
    // writes another, and the header is edited as any other value.
    let cause = |view: &mut Value| view["5gmm-cause"]["value"] = json!("illegal-ue");
    let error = fgs_edited(&protected, cause).unwrap_err();
    assert!(error.contains("message authentication code"), "{error}");
    let edited = fgs_edited(&protected, |view| {
        cause(view);
        view["security-header"]["value"]["message-authentication-code"] = json!("0x01020304");
    });
    assert_eq!(edited.unwrap(), "7e0101020304057e006403");
    let edited = fgs_edited(&protected, |view| {
        view["security-header"]["value"]["sequence-number"] = json!(6);
    });
    assert_eq!(edited.unwrap(), "7e01aabbccdd067e006416");
    let error = fgs_edited(&protected, |view| {
        view.as_object_mut().unwrap().remove("security-header");
    });
    assert!(
        error
            .unwrap_err()
            .contains("`security-header` is the header")
    );
    // A ciphered message has its octets, and no IE to show.
    let ciphered = fgs("7e0200000000001234");
    let view = ciphered.to_view();
    assert_eq!(view["ciphered-message"], json!({"octets": "1234"}));
    assert_eq!(
        view["security-header"]["value"]["security-header-type"],
        "integrity-protected-and-ciphered"
    );
    assert_eq!(view.as_object().unwrap().len(), 2);
    assert_eq!(ciphered.with_view(view).unwrap(), ciphered);
    let octets = |view: &mut Value| view["ciphered-message"]["octets"] = json!("5678");
    let error = fgs_edited(&ciphered, octets).unwrap_err();
    assert!(error.contains("message authentication code"), "{error}");
    let edited = fgs_edited(&ciphered, |view| {
        octets(view);
        view["security-header"]["value"]["message-authentication-code"] = json!(1);
    });
    assert_eq!(edited.unwrap(), "7e0200000001005678");
    // A view that says nothing is not one of this message.
    assert!(ciphered.with_view(json!({})).is_err());
    let added = fgs_edited(&ciphered, |view| {
        view["5gmm-cause"] = json!({"octets": "03"})
    });
    assert!(added.unwrap_err().contains("is no IE of the message"));
    assert!(ciphered.with_view(json!([])).is_err());
    // The same for EPS.
    let protected = eps("17aabbccdd05074403");
    let view = protected.to_view();
    assert_eq!(view["emm-cause"]["value"], "illegal-ue");
    assert_eq!(
        view["security-header"]["value"]["security-header-type"],
        "integrity-protected"
    );
    assert_eq!(protected.with_view(view).unwrap(), protected);
    let error = eps_edited(&protected, |view| {
        view["emm-cause"]["value"] = json!("congestion")
    });
    assert!(error.unwrap_err().contains("message authentication code"));
    // An EPS SERVICE REQUEST has a short header and no IEs: a view that says
    // nothing leaves it as it is.
    let request = eps("c7200000");
    assert_eq!(request.with_view(json!({})).unwrap(), request);
    assert_eq!(request.with_view(request.to_view()).unwrap(), request);
}

#[test]
fn an_ie_that_a_view_writes_has_the_octets_of_what_is_written() {
    let header = |kind: &str| {
        json!({
            "extended-protocol-discriminator": {"value": 126},
            "security-header-type": {"value": "plain-nas-message"},
            "message-type": {"value": kind},
        })
    };
    let accept = |result: Value| {
        let mut view = header("registration-accept");
        view["5gs-registration-result"] = json!({"value": result});
        let accept = f::Nas5gmmMessageType::RegistrationAccept.from_view(view);
        accept.map(|accept| hex::encode(accept.to_bytes().unwrap()))
    };
    // Members that are zero are written as any other.
    let zeros = json!({
        "result": 0, "sms-allowed": false, "nssaa-performed": false,
        "emergency-registered": false, "disaster-roaming": false,
    });
    assert_eq!(accept(zeros).unwrap(), "7e00420100");
    assert_eq!(accept(json!({"result": 0})).unwrap(), "7e00420100");
    assert_eq!(accept(json!({"sms-allowed": false})).unwrap(), "7e00420100");
    // A code is written by its number, whether it has a name or not.
    assert_eq!(accept(json!({"result": 7})).unwrap(), "7e00420107");
    assert_eq!(accept(json!({"result": 1})).unwrap(), "7e00420101");
    assert_eq!(
        accept(json!({"result": "3gpp-access"})).unwrap(),
        "7e00420101"
    );
    let error = accept(json!({"result": 8})).unwrap_err().to_string();
    assert!(error.contains("result cannot be 8"), "{error}");
    let request = |name: &str, value: Value| {
        let mut view = header("registration-request");
        view["5gs-registration-type"] = json!({"octets": "79"});
        view["5gs-mobile-identity"] = json!({"octets": "0199f907000000000000001002"});
        view[name] = json!({"value": value});
        let request = f::Nas5gmmMessageType::RegistrationRequest.from_view(view);
        hex::encode(request.unwrap().to_bytes().unwrap())
    };
    let drx = |window: u8| json!({"paging-time-window": window, "edrx-value": 0});
    let written = request("requested-extended-drx-parameters", drx(0));
    assert!(written.ends_with("6e0100"), "{written}");
    let written = request("requested-extended-drx-parameters", drx(1));
    assert!(written.ends_with("6e0110"), "{written}");
    // The algorithms of a command, of which the integrity one is reserved.
    let command = f::Nas5gmmMessageType::SecurityModeCommand.from_view({
        let mut view = header("security-mode-command");
        view["selected-nas-security-algorithms"] =
            json!({"value": {"ciphering": "nea2", "integrity": 8}});
        view["ngksi"] = json!({"octets": "01"});
        view["replayed-ue-security-capabilities"] = json!({"octets": "f0f0"});
        view
    });
    assert_eq!(
        hex::encode(command.unwrap().to_bytes().unwrap()),
        "7e005d280102f0f0"
    );
    // The header takes the number of a type that it has a name for.
    let mut view = header("5gmm-status");
    view["security-header-type"] = json!({"value": 0});
    view["5gmm-cause"] = json!({"value": "congestion"});
    let status = f::Nas5gmmMessageType::FGmmStatus.from_view(view.clone());
    assert_eq!(status.unwrap().to_bytes().unwrap(), [0x7e, 0, 0x64, 0x16]);
    // The type that the header names is the one of the message.
    let error = f::Nas5gmmMessageType::RegistrationReject
        .from_view(view)
        .unwrap_err()
        .to_string();
    assert!(error.contains("`message-type` is 5gmm-status"), "{error}");
}

#[test]
fn what_a_view_shows_is_what_it_takes() {
    // A CONFIGURATION UPDATE COMMAND with an IE of flags that has no octets:
    // its flags read false, and the IE is written as it came.
    let command = fgs("7e00546300");
    let view = command.to_view();
    let control = &view["access-technology-utilization-control"];
    assert_eq!(control["octets"], "");
    assert!(
        control["value"]
            .as_object()
            .unwrap()
            .values()
            .all(|flag| flag == false)
    );
    let alone = f::Nas5gmmMessageType::ConfigurationUpdateCommand.from_view(view);
    assert_eq!(
        hex::encode(alone.unwrap().to_bytes().unwrap()),
        "7e00546300"
    );
    // A reserved PDU session type is a number, not the name of the type that
    // a receiver takes it for, and the octet is written as it came.
    let accept = "2e0101c211000901000631310101ff0106060064060032";
    for (octet, kind, mode) in [
        ("11", json!("ipv4"), json!("ssc1")),
        ("10", json!(0), json!("ssc1")),
        ("16", json!(6), json!("ssc1")),
        ("41", json!("ipv4"), json!(4)),
        ("1f", json!(7), json!("ssc1")),
    ] {
        let wire = accept.replacen("c211", &format!("c2{octet}"), 1);
        let message = fgs(&wire);
        let view = message.to_view();
        let shown = &view["selected-pdu-session-type"];
        assert_eq!(shown["value"]["pdu-session-type"], kind, "{octet}");
        assert_eq!(shown["value"]["ssc-mode"], mode, "{octet}");
        let alone = f::Nas5gsmMessageType::PduSessionEstablishmentAccept.from_view(view);
        assert_eq!(hex::encode(alone.unwrap().to_bytes().unwrap()), wire);
    }
    // A value that the crate reads and cannot write back is not shown: the
    // identity 0 of a linked bearer is reserved.
    let request = eps("6201c5000109062131ff0b3011");
    assert_eq!(
        request.to_view()["linked-eps-bearer-identity"],
        json!({"octets": "00"})
    );
    let request = eps("6201c5050109062131ff0b3011");
    assert_eq!(
        request.to_view()["linked-eps-bearer-identity"],
        json!({"octets": "05", "value": 5})
    );
}

#[test]
fn every_message_of_a_view_alone_is_the_fixture_it_was_viewed_from() {
    // Each one- or two-octet change of a fixture that still decodes: the
    // view describes the message alone, with the same view.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut seen = 0;
    for (_, wire) in fixtures(include_str!("fixtures/nas-5gs.tsv")) {
        for _ in 0..40 {
            let mut bytes = wire.clone();
            let at = next() as usize % bytes.len();
            bytes[at] = next() as u8;
            let Ok(message) = f::Nas5gsMessage::from_bytes(&bytes) else {
                continue;
            };
            let view = message.to_view();
            let alone = match &message {
                f::Nas5gsMessage::Gmm(_, body) => body.message_type().from_view(view.clone()),
                f::Nas5gsMessage::Gsm(_, body) => body.message_type().from_view(view.clone()),
                _ => continue,
            };
            let alone = alone.unwrap_or_else(|error| panic!("{}: {error}", hex::encode(&bytes)));
            assert_eq!(alone.to_view(), view, "{}", hex::encode(&bytes));
            seen += 1;
        }
    }
    for (name, wire) in fixtures(include_str!("fixtures/nas-eps.tsv")) {
        for _ in 0..40 {
            let mut bytes = wire.clone();
            let at = next() as usize % bytes.len();
            bytes[at] = next() as u8;
            let direction = if name.starts_with("DetachRequestToUe") {
                e::Direction::Downlink
            } else {
                e::Direction::Uplink
            };
            let Ok(message) = e::NasEpsMessage::from_bytes_with_direction(&bytes, direction) else {
                continue;
            };
            let view = message.to_view();
            let alone = match &message {
                e::NasEpsMessage::Emm(_, body) => body.message_type().from_view(view.clone()),
                e::NasEpsMessage::Esm(_, body) => body.message_type().from_view(view.clone()),
                _ => continue,
            };
            let alone = alone.unwrap_or_else(|error| panic!("{}: {error}", hex::encode(&bytes)));
            assert_eq!(alone.to_view(), view, "{}", hex::encode(&bytes));
            seen += 1;
        }
    }
    assert!(seen > 2000, "{seen}");
}

#[test]
fn a_value_that_the_crate_does_not_encode_is_read_only() {
    // REGISTRATION ACCEPT with a service area list: TAC 1 of PLMN 208/93.
    let accept = fgs("7e0042010127070002f839000001");
    let view = accept.to_view();
    assert_eq!(
        view["service-area-list"]["value"],
        json!([{"one-plmn-non-consecutive": {
            "allowed": "allowed", "plmn": "208-93", "tacs": [1],
        }}])
    );
    let error = fgs_edited(&accept, |view| {
        view["service-area-list"]["value"][0]["one-plmn-non-consecutive"]["tacs"] = json!([2]);
    });
    assert!(
        error
            .unwrap_err()
            .contains("service-area-list: the crate reads this value")
    );
    let edited = fgs_edited(&accept, |view| {
        view["service-area-list"]["octets"] = json!("0002f839000002");
    });
    assert_eq!(edited.unwrap(), "7e0042010127070002f839000002");
    // AUTHENTICATION REQUEST: the RAND and the AUTN are octets, as is the ABBA.
    let request =
        fgs("7e0056010200002111111111111111111111111111111111201022222222222222222222222222222222");
    let view = request.to_view();
    assert_eq!(view["abba"], json!({"octets": "0000"}));
    assert_eq!(
        view["authentication-parameter-rand"],
        json!({"octets": "11111111111111111111111111111111"})
    );
    let error = fgs_edited(&request, |view| view["abba"]["value"] = json!("0000"));
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
    let view = request.to_view();
    assert_eq!(view["message-type"]["value"], "attach-request");
    assert_eq!(
        view["eps-attach-type"],
        json!({"value": "eps-attach", "octets": "01"})
    );
    assert_eq!(
        view["nas-key-set-identifier"]["value"],
        json!({"native": 0})
    );
    assert_eq!(
        view["eps-mobile-identity"]["value"],
        json!({"imsi": "208930000000001"})
    );
    assert_eq!(
        view["ue-network-capability"]["value"]["eea"],
        json!([0, 1, 2])
    );
    assert_eq!(view["ue-network-capability"]["value"]["eps-upip"], false);
    let inner = &view["esm-message-container"]["value"];
    assert_eq!(inner["message-type"]["value"], "pdn-connectivity-request");
    assert_eq!(inner["request-type"]["value"], "initial");
    let edited = eps_edited(&request, |view| {
        view["eps-attach-type"]["value"] = json!("combined-eps-imsi-attach");
        view["eps-mobile-identity"]["value"]["imsi"] = json!("208930000000002");
        view["nas-key-set-identifier"]["value"] = json!("no-key");
        view["ue-network-capability"]["value"]["eps-upip"] = json!(true);
        view["esm-message-container"]["value"]["pdn-type"]["value"] = json!("ipv6");
    });
    assert_eq!(
        edited.unwrap(),
        "07417208298039000000002002e0e100040201d021"
    );
    // ATTACH REJECT, EMM cause #3.
    let reject = eps("074403");
    assert_eq!(
        reject.to_view()["emm-cause"],
        json!({"value": "illegal-ue", "octets": "03"})
    );
    let named = |name: Value| eps_edited(&reject, |view| view["emm-cause"]["value"] = name);
    assert_eq!(named(json!("congestion")).unwrap(), "074416");
    assert_eq!(named(json!(200)).unwrap(), "0744c8");
    assert!(named(json!({"unknown": 200})).is_err());
    assert!(named(json!("congestio")).is_err());
    // ATTACH ACCEPT: T3412 of one minute, a TAI list, an ACTIVATE DEFAULT
    // EPS BEARER CONTEXT REQUEST, a GUTI and a TMSI.
    let accept = eps(
        "07420121060002f839000100155201c101090908696e7465726e657405010a000001\
         500bf602f839000102112233442305f411223344530317016b0101",
    );
    let view = accept.to_view();
    assert_eq!(view["t3412-value"], json!({"octets": "21", "value": 60}));
    assert_eq!(
        view["tai-list"]["value"],
        json!([{"plmn": "208-93", "tac": 1}])
    );
    assert_eq!(
        view["guti"]["value"],
        json!({"guti": {"plmn": "208-93", "mme-group-id": 1, "mme-code": 2,
            "m-tmsi": 0x1122_3344}})
    );
    assert_eq!(view["ms-identity"]["value"], json!({"tmsi": 0x1122_3344}));
    let bearer = &view["esm-message-container"]["value"];
    assert_eq!(bearer["eps-bearer-identity"]["value"], 5);
    assert_eq!(bearer["access-point-name"]["value"], "internet");
    assert_eq!(bearer["pdn-address"]["value"], json!({"ipv4": "10.0.0.1"}));
    let edited = eps_edited(&accept, |view| {
        view["tai-list"]["value"] = json!([{"plmn": "208-93", "tac": 1},
            {"plmn": "001-01", "tac": "0x10"}]);
        view["guti"]["value"]["guti"]["m-tmsi"] = json!(1);
        let bearer = &mut view["esm-message-container"]["value"];
        bearer["access-point-name"]["value"] = json!("ims");
        bearer["pdn-address"]["value"]["ipv4"] = json!("192.168.0.7");
    });
    assert_eq!(
        edited.unwrap(),
        "074201210b4102f839000100f110001000105201c101090403696d730501c0a80007\
         500bf602f839000102000000012305f411223344530317016b0101"
    );
}

#[test]
fn an_optional_ie_that_the_message_does_not_have_is_null_and_is_added() {
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let view = accept.to_view();
    assert_eq!(view["configured-nssai"], Value::Null);
    assert_eq!(view["t3512-value"], Value::Null);
    assert_eq!(view.get("5gmm-cause"), None);
    // The view of a message names what a message of its type can have.
    let names = f::Nas5gmmMessageType::RegistrationAccept.view_names();
    let entries: Vec<_> = view.as_object().unwrap().keys().collect();
    assert_eq!(names.len(), entries.len());
    assert!(entries.iter().all(|entry| names.contains(entry)));
    assert_eq!(
        names[..4],
        [
            "extended-protocol-discriminator",
            "security-header-type",
            "message-type",
            "5gs-registration-result"
        ]
    );
    // From its octets, from its value, and from both.
    let add = |name: &str, ie: Value| fgs_edited(&accept, |view| view[name] = ie);
    let with = |ies: &str| format!("7e0042010177000bf202f8390100421122334415020101{ies}");
    assert_eq!(
        add("configured-nssai", json!({"octets": "0101"})).unwrap(),
        with("31020101")
    );
    assert_eq!(
        add(
            "configured-nssai",
            json!({"value": [{"sst": 1, "sd": "010203"}]})
        )
        .unwrap(),
        with("31050401010203")
    );
    // Under another spelling of its name, in the place of the entry.
    let other = fgs_edited(&accept, |view| {
        view.as_object_mut().unwrap().remove("configured-nssai");
        view["Configured NSSAI"] = json!({"Octets": "0101"});
    });
    assert_eq!(other.unwrap(), with("31020101"));
    let error = add("Configured NSSAI", json!({"octets": "0101"})).unwrap_err();
    assert!(error.contains("named twice"), "{error}");
    assert_eq!(
        add("t3512-value", json!({"value": 3600})).unwrap(),
        with("5e0106")
    );
    assert_eq!(
        add("t3512-value", json!({"value": 3600, "octets": "21"})).unwrap(),
        with("5e0121")
    );
    assert_eq!(
        add("mico-indication", json!({"value": {"raai": true}})).unwrap(),
        with("b1")
    );
    assert_eq!(
        add("mico-indication", json!({"octets": "00"})).unwrap(),
        with("b0")
    );
    // A value is encoded, also when it is the one of no octets.
    let tnan = fgs_edited(&fgs("7e00440b"), |view| {
        view["tnan-information"] = json!({"value": {"tngf-id": null, "ssid": null}})
    });
    assert_eq!(tnan.unwrap(), "7e00440b4d0100");
    // Two at once take their places in the message.
    let both = fgs_edited(&accept, |view| {
        view["t3512-value"] = json!({"value": "deactivated"});
        view["configured-nssai"] = json!({"octets": ""});
    });
    assert_eq!(both.unwrap(), with("31005e01e0"));
    // What is added is said: an entry with nothing is none, and neither is
    // an IE that a message of this type does not have.
    for nothing in [json!({}), json!({"value": null}), json!("0101")] {
        let error = add("configured-nssai", nothing).unwrap_err();
        assert!(error.contains("configured-nssai: "), "{error}");
        assert!(error.contains("with a `value` or `octets`"), "{error}");
    }
    let error = add("allowed-nssai", json!({})).unwrap_err();
    assert!(
        error.contains("allowed-nssai: an IE is written with a `value` or `octets`"),
        "{error}"
    );
    let error = add("t3512-value", json!({"value": 3600, "octets": "22"})).unwrap_err();
    assert!(error.contains("disagree"), "{error}");
    let error = add("t3512-value", json!({"value": "soon"})).unwrap_err();
    assert!(error.contains("t3512-value: "), "{error}");
    let error = add("5gmm-cause", json!({"value": "congestion"})).unwrap_err();
    assert!(
        error.contains("`5gmm-cause` is no IE of the message"),
        "{error}"
    );
    assert_eq!(add("configured-nssai", Value::Null).unwrap(), with(""));
    // Inside the message of a container: SECURITY MODE COMPLETE with the
    // REGISTRATION REQUEST it replays.
    let complete = fgs("7e005e7100137e004101000d0102f8390000000021436587f9");
    let edited = fgs_edited(&complete, |view| {
        let replayed = &mut view["nas-message-container"]["value"];
        assert_eq!(replayed["requested-nssai"], Value::Null);
        replayed["requested-nssai"] = json!({"value": [{"sst": 1}]});
    });
    assert_eq!(
        edited.unwrap(),
        "7e005e7100177e004101000d0102f8390000000021436587f92f020101"
    );
    // EPS: ATTACH REJECT with EMM cause #3.
    let reject = eps("074403");
    assert_eq!(reject.to_view()["t3402-value"], Value::Null);
    let edited = eps_edited(&reject, |view| {
        view["t3402-value"] = json!({"value": 720});
        view["extended-emm-cause"] = json!({"octets": "01"});
    });
    assert_eq!(edited.unwrap(), "07440316012ca1");
    assert_eq!(
        e::NasEmmMessageType::AttachReject.view_names().len(),
        reject.to_view().as_object().unwrap().len()
    );
}

/// Every optional IE that a fixture does not have is added to it from
/// octets, and the view then has it with them.
#[test]
fn every_optional_ie_is_added_from_its_octets() {
    fn check(view: Value, with_view: impl Fn(Value) -> Option<Value>) -> usize {
        let absent = view.as_object().unwrap().iter();
        let absent = absent.filter(|(_, ie)| ie.is_null()).map(|(name, _)| name);
        absent
            .map(|name| {
                // An IE has the octets of a length that its message encodes.
                let added = (1..=32)
                    .map(|length| "00".repeat(length))
                    .find_map(|octets| {
                        let mut view = view.clone();
                        view[name] = json!({ "octets": octets });
                        with_view(view).filter(|view| view[name]["octets"] == octets)
                    });
                assert!(added.is_some(), "{name}");
            })
            .count()
    }
    let mut added = 0;
    for (_, wire) in fixtures(include_str!("fixtures/nas-5gs.tsv")) {
        let message = f::Nas5gsMessage::from_bytes(&wire).unwrap();
        added += check(message.to_view(), |view| {
            Some(message.with_view(view).ok()?.to_view())
        });
    }
    for (name, wire) in fixtures(include_str!("fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        added += check(message.to_view(), |view| {
            Some(message.with_view(view).ok()?.to_view())
        });
    }
    assert!(added > 500, "{added}");
}

/// The names of every message type that the crate has a message of are the
/// entries of the view of that message.
#[test]
fn the_names_of_a_message_type_are_the_entries_of_its_view() {
    let check = |view: Value, mut names: Vec<String>, name: &str| {
        let entries: Vec<_> = view.as_object().unwrap().keys().collect();
        assert!(entries.len() > 2, "{name}");
        // An EPS DETACH REQUEST is one message from the UE and another to it.
        if name.starts_with("DetachRequest") {
            names.retain(|name| entries.contains(&name));
        }
        names.sort();
        assert_eq!(entries, names.iter().collect::<Vec<_>>(), "{name}");
    };
    for (name, wire) in fixtures(include_str!("fixtures/nas-5gs.tsv")) {
        let message = f::Nas5gsMessage::from_bytes(&wire).unwrap();
        let names = match &message {
            f::Nas5gsMessage::Gmm(header, _) => header.message_type.view_names(),
            f::Nas5gsMessage::Gsm(header, _) => header.message_type.view_names(),
            _ => panic!("{name}"),
        };
        check(message.to_view(), names, name);
    }
    for (name, wire) in fixtures(include_str!("fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        let names = match &message {
            e::NasEpsMessage::Emm(header, _) => header.message_type.view_names(),
            e::NasEpsMessage::Esm(header, _) => header.message_type.view_names(),
            _ => panic!("{name}"),
        };
        check(message.to_view(), names, name);
    }
    let detach = e::NasEmmMessageType::DetachRequest.view_names();
    assert!(detach.contains(&"eps-mobile-identity".to_string()));
    assert!(detach.contains(&"emm-cause".to_string()));
    // A type that the crate has no message of.
    assert!(f::Nas5gmmMessageType::Unknown(0).view_names().is_empty());
}

/// The view with nothing written has the names of `view_names`, the fields
/// of the header with a value, each mandatory IE with its octets and each
/// optional IE as `null`: writing over it what a message has gives that
/// message.
#[test]
fn a_blank_view_is_what_from_view_fills() {
    let names_of = |view: &Value| -> Vec<String> {
        let mut names: Vec<_> = view.as_object().unwrap().keys().cloned().collect();
        names.sort();
        names
    };
    let sorted = |mut names: Vec<String>| {
        names.sort();
        names
    };
    for (name, wire) in fixtures(include_str!("fixtures/nas-5gs.tsv")) {
        let message = f::Nas5gsMessage::from_bytes(&wire).unwrap();
        let (blank, names, built) = match &message {
            f::Nas5gsMessage::Gmm(header, _) => {
                let kind = header.message_type;
                let blank = kind.blank_view().unwrap();
                let mut filled = blank.clone();
                (filled.as_object_mut().unwrap())
                    .extend(message.to_view().as_object().unwrap().clone());
                (blank, kind.view_names(), kind.from_view(filled))
            }
            f::Nas5gsMessage::Gsm(header, _) => {
                let kind = header.message_type;
                let blank = kind.blank_view().unwrap();
                let mut filled = blank.clone();
                (filled.as_object_mut().unwrap())
                    .extend(message.to_view().as_object().unwrap().clone());
                (blank, kind.view_names(), kind.from_view(filled))
            }
            _ => panic!("{name}"),
        };
        assert_eq!(names_of(&blank), sorted(names), "{name}");
        assert_eq!(built.unwrap().to_view(), message.to_view(), "{name}");
        // A mandatory IE has its octets, and is written over them.
        for (entry, written) in blank.as_object().unwrap() {
            assert!(
                written.is_null()
                    || written.get("value").is_some()
                    || written["octets"].is_string(),
                "{name}: {entry} is {written}"
            );
        }
    }
    let status = e::NasEmmMessageType::EmmStatus.blank_view().unwrap();
    assert_eq!(status["message-type"]["value"], "emm-status");
    assert_eq!(status["emm-cause"]["octets"], "00");
    let detach = e::NasEmmMessageType::DetachRequest.blank_view().unwrap();
    assert!(detach["eps-mobile-identity"].is_object() && detach.get("emm-cause").is_none());
    let response = e::NasEsmMessageType::EsmInformationResponse
        .blank_view()
        .unwrap();
    assert!(response["access-point-name"].is_null());
    assert!(
        f::Nas5gsmMessageType::PduSessionReleaseComplete
            .blank_view()
            .is_some()
    );
    assert!(f::Nas5gmmMessageType::Unknown(0).blank_view().is_none());
}

#[test]
fn the_parts_of_a_configuration_or_a_restriction_read_and_write_by_name() {
    // REGISTRATION REJECT with a TNAN information, SERVICE REQUEST with a
    // paging restriction.
    let reject = fgs("7e00440b4d060301aa026162");
    assert_eq!(
        reject.to_view()["tnan-information"]["value"],
        json!({"tngf-id": "aa", "ssid": "ab"})
    );
    let edited = fgs_edited(&reject, |view| {
        view["tnan-information"]["value"] = json!({"tngf-id": null, "ssid": "home"})
    });
    assert_eq!(edited.unwrap(), "7e00440b4d060204686f6d65");
    let request = fgs("7e004c010007f4004211223344280303a202");
    assert_eq!(
        request.to_view()["paging-restriction"]["value"],
        json!({
            "restriction-type": "all-restricted-except-specified-pdu-sessions",
            "unrestricted-psi-list": [1, 5, 7, 9],
        })
    );
    let edited = fgs_edited(&request, |view| {
        view["paging-restriction"]["value"]["unrestricted-psi-list"] = json!([2, 15])
    });
    assert_eq!(edited.unwrap(), "7e004c010007f40042112233442803030480");
    // What the type of restriction has no place for is refused.
    let error = fgs_edited(&request, |view| {
        view["paging-restriction"]["value"] = json!({
            "restriction-type": "all-restricted",
            "unrestricted-psi-list": [2],
        })
    });
    assert!(error.unwrap_err().contains("cannot be encoded"));
    // EPS: a SERVICE REJECT is given S&F satellite operation parameters.
    let reject = eps("074e0a");
    let edited = eps_edited(&reject, |view| {
        view["s-and-f-satellite-operation-parameters"] = json!({"value": {
            "wait-time": 10,
            "uplink-delivery-time": 60,
            "monitoring-list": {"present": "0102"},
        }})
    });
    assert_eq!(edited.unwrap(), "074e0a21090b000a00003c020102");
}

/// The example of the README.
#[test]
fn the_readme_example_holds() {
    use oxirush_nas::view;
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = f::Nas5gsMessage::from_bytes(&bytes).unwrap();
    let mut tree = accept.to_view();
    let paths = view::paths(&tree);
    for line in [
        ("/nas/message-type/value", json!("registration-accept")),
        ("/nas/5g-guti/value/guti/plmn", json!("208-93")),
        ("/nas/allowed-nssai/value/0/sst", json!(1)),
    ] {
        assert!(
            paths
                .iter()
                .any(|(path, value)| (path.as_str(), value) == (line.0, &line.1))
        );
    }
    let select = |path| view::select(&tree, path).unwrap();
    assert_eq!(
        select("/nas/message-type/value"),
        [&json!("registration-accept")]
    );
    assert_eq!(
        select("/nas/5gs-registration-result/value/result"),
        [&json!("3gpp-access")]
    );
    assert_eq!(
        select("/nas/5g-guti/value/guti/tmsi"),
        [&json!(0x1122_3344)]
    );
    assert_eq!(select("/nas/allowed-nssai/octets"), [&json!("0101")]);
    assert!(select("/nas/t3512-value/value").is_empty());
    view::set(
        &mut tree,
        "/nas/5g-guti/value/guti/tmsi",
        json!("0xdeadbeef"),
    )
    .unwrap();
    view::set(&mut tree, "/nas/allowed-nssai/value/0/sd", json!("010203")).unwrap();
    view::set(&mut tree, "/nas/t3512-value/value", json!(3600)).unwrap();
    let edited = accept.with_view(tree).unwrap();
    assert_eq!(
        hex::encode(edited.to_bytes().unwrap()),
        "7e0042010177000bf202f839010042deadbeef150504010102035e0106"
    );
}

/// Every value of every fixture has a path that selects it alone.
#[test]
fn every_path_of_every_fixture_selects_its_value() {
    use oxirush_nas::view;
    let check = |name: &str, tree: Value| {
        let paths = view::paths(&tree);
        assert!(!paths.is_empty(), "{name}");
        for (path, value) in paths {
            assert!(path.starts_with("/nas/"), "{name} {path}");
            assert_eq!(
                view::select(&tree, &path),
                Ok(vec![&value]),
                "{name} {path}"
            );
        }
    };
    for (name, wire) in fixtures(include_str!("fixtures/nas-5gs.tsv")) {
        check(name, f::Nas5gsMessage::from_bytes(&wire).unwrap().to_view());
    }
    for (name, wire) in fixtures(include_str!("fixtures/nas-eps.tsv")) {
        check(name, eps_fixture(name, &wire).to_view());
    }
}

#[test]
fn a_path_names_an_ie_however_it_is_written_and_what_is_not_there_is_nothing() {
    use oxirush_nas::view;
    // REGISTRATION REQUEST with a requested NSSAI of one slice.
    let request = fgs("7e004179000d0102f8390000000000000010022e02e0e02f020101");
    let tree = request.to_view();
    for path in [
        "/nas/5gs-mobile-identity/value/suci/imsi/msin",
        "/nas/5GS Mobile Identity/value/SUCI/IMSI/MSIN",
        "/nas/fgs_mobile_identity/value/suci/imsi/msin",
    ] {
        let msin = view::select(&tree, path);
        assert_eq!(msin, Ok(vec![&json!("0000000120")]), "{path}");
    }
    let slices = view::select(&tree, "/nas/requested-nssai/value/*/sst").unwrap();
    assert_eq!(slices, [&json!(1)]);
    assert_eq!(view::select(&tree, "/nas").unwrap(), [&tree]);
    // An optional IE that the message does not have, and an entry past the end.
    assert_eq!(
        view::select(&tree, "/nas/5gmm-capability/value/s1-mode"),
        Ok(vec![])
    );
    assert_eq!(
        view::select(&tree, "/nas/requested-nssai/value/1/sst"),
        Ok(vec![])
    );
    // The IE itself, and a member that a slice does not have, select
    // nothing either: no path of them is listed.
    assert_eq!(view::select(&tree, "/nas/5gmm-capability"), Ok(vec![]));
    assert_eq!(
        view::select(&tree, "/nas/requested-nssai/value/0/sd"),
        Ok(vec![])
    );
    assert!(
        !view::paths(&tree)
            .iter()
            .any(|(path, _)| path.contains("5gmm-capability") || path.ends_with("/sd"))
    );
    // A view says what message it is of: the name of an IE that the message
    // cannot have is refused when it is set, and the view is as it was.
    let mut edited = tree.clone();
    let timer = json!({"value": 60});
    let error = view::set(&mut edited, "/nas/t3512-value", timer.clone()).unwrap_err();
    assert!(
        error.contains("`t3512-value` is no IE of a message"),
        "{error}"
    );
    assert_eq!(edited, tree);
    view::set(&mut edited, "/nas/5gmm-capability", json!({"octets": "00"})).unwrap();
    // One that does not say is refused when it is taken.
    let mut alone = json!({});
    view::set(&mut alone, "/nas/t3512-value", timer).unwrap();
    assert!(request.with_view(alone).is_err());
    for (path, reason) in [
        (
            "/nas/no-such-ie/value",
            "unknown or unavailable decoded field \"no-such-ie\"",
        ),
        (
            "/nas/requested-nssai/value/0/misspelled",
            "unknown or unavailable decoded field",
        ),
        (
            "/nas/requested-nssai/value/first",
            "array index must be numeric",
        ),
        ("/nas/requested-nssai/octets/deeper", "traverses a scalar"),
        ("/message/requested_nssai", "is not a path of a view"),
        ("nas/requested-nssai", "must start with /"),
    ] {
        let error = view::select(&tree, path).unwrap_err();
        assert!(error.contains(reason), "{path}: {error}");
    }
}

#[test]
fn a_view_is_edited_at_its_paths() {
    use oxirush_nas::view;
    let request = fgs("7e004179000d0102f8390000000000000010022e02e0e02f020101");
    let edited = |edit: &dyn Fn(&mut Value) -> Result<(), String>| {
        let mut tree = request.to_view();
        edit(&mut tree)?;
        let message = request.with_view(tree).map_err(|error| error.to_string())?;
        Ok::<_, String>(hex::encode(message.to_bytes().unwrap()))
    };
    let head = "7e004179000d0102f839000000000000001002";
    // A member of a value, an entry of a list, and the octets of an IE.
    let wire = edited(&|tree| {
        view::set(tree, "/nas/Requested NSSAI/value/0/sst", json!(2))?;
        view::insert(
            tree,
            "/nas/requested-nssai/value/-",
            json!({"sst": 3, "sd": "0000ff"}),
        )?;
        view::insert(tree, "/nas/requested-nssai/value/0", json!({"sst": 1}))?;
        view::set(tree, "/nas/ue-security-capability/octets", json!("f0f0"))
    });
    assert_eq!(
        wire.unwrap(),
        format!("{head}2e02f0f02f09010101020403{}", "0000ff")
    );
    // An optional IE is added by its value or its octets, and one is taken out.
    let wire = edited(&|tree| {
        view::set(tree, "/nas/mico-indication/value", json!({"raai": true}))?;
        view::set(tree, "/nas/5gmm-capability/octets", json!("01"))?;
        view::remove(tree, "/nas/requested-nssai")?;
        view::remove(tree, "/nas/ue-security-capability")
    });
    assert_eq!(wire.unwrap(), format!("{head}100101b1"));
    // The view still names the IE that was taken out, which is added again.
    let mut tree = request.to_view();
    view::remove(&mut tree, "/nas/requested-nssai").unwrap();
    assert!(tree["requested-nssai"].is_null());
    view::set(&mut tree, "/nas/requested-nssai/value", json!([{"sst": 5}])).unwrap();
    assert_eq!(tree["requested-nssai"], json!({"value": [{"sst": 5}]}));
    // What selects nothing is refused, and the view is as it was.
    let mut tree = request.to_view();
    for (edit, reason) in [
        (
            view::set(&mut tree, "/nas/no-such-ie/value", json!(1)),
            "`no-such-ie` is no IE of a message `registration-request`",
        ),
        (
            view::set(&mut tree, "/nas/requested-nssai/value/4/sst", json!(1)),
            "selected no field",
        ),
        (
            view::set(&mut tree, "/nas/requested-nssai/value", Value::Null),
            "an IE is removed",
        ),
        (
            view::remove(&mut tree, "/nas/requested-nssai/octets"),
            "an IE is removed",
        ),
        (
            view::remove(&mut tree, "/nas/mico-indication"),
            "selected no field",
        ),
        (
            view::insert(&mut tree, "/nas/requested-nssai", json!(1)),
            "insert adds to a list",
        ),
    ] {
        let error = edit.unwrap_err();
        assert!(error.contains(reason), "{error}");
    }
    assert_eq!(tree, request.to_view());
    // A mandatory IE stays: the message says so.
    let error = edited(&|tree| view::remove(tree, "/nas/5gs-mobile-identity")).unwrap_err();
    assert!(
        error.contains("`5gs-mobile-identity` is mandatory"),
        "{error}"
    );
}

/// The pointers to every part of the values of a view.
fn values(view: &Value, path: String, inside: bool, found: &mut Vec<String>) {
    if inside {
        found.push(path.clone());
    }
    match view {
        Value::Object(object) => object.iter().for_each(|(key, value)| {
            values(
                value,
                format!("{path}/{key}"),
                inside || key == "value",
                found,
            )
        }),
        Value::Array(array) => array
            .iter()
            .enumerate()
            .for_each(|(index, value)| values(value, format!("{path}/{index}"), inside, found)),
        _ => {}
    }
}

/// Every fixture has a view that is the message, and whatever a value of it
/// is given, the answer is a message that has it or an error: nothing is
/// taken unchecked into an encoder.
#[test]
fn a_view_is_the_message_and_takes_nothing_unchecked() {
    let parts = [
        json!(255),
        json!(65_536),
        json!(-1),
        json!("x"),
        json!("0x7fffffffffff"),
        json!("999-999"),
        json!([]),
        json!([300, 300, 300]),
        json!({}),
        json!(true),
    ];
    fn check<M: PartialEq + std::fmt::Debug>(
        message: &M,
        view: impl Fn(&M) -> Value,
        with_view: impl Fn(&M, Value) -> Option<M>,
        parts: &[Value],
        counts: &mut [usize; 2],
    ) {
        let whole = view(message);
        assert_eq!(with_view(message, whole.clone()).as_ref(), Some(message));
        let mut pointers = Vec::new();
        values(&whole, String::new(), false, &mut pointers);
        // A sample of the parts of a message with many, such as capabilities.
        let step = pointers.len().div_ceil(16).max(1);
        let pointers = pointers.iter().step_by(step);
        for (pointer, part) in pointers.flat_map(|p| parts.iter().map(move |v| (p, v))) {
            let mut edited = whole.clone();
            *edited.pointer_mut(pointer).unwrap() = part.clone();
            counts[0] += 1;
            if let Some(message) = with_view(message, edited) {
                view(&message);
                counts[1] += 1;
            }
        }
    }
    let mut counts = [0; 2];
    for (_, wire) in fixtures(include_str!("fixtures/nas-5gs.tsv")) {
        let message = f::Nas5gsMessage::from_bytes(&wire).unwrap();
        check(
            &message,
            f::Nas5gsMessage::to_view,
            |message, view| message.with_view(view).ok().inspect(|m| drop(m.to_bytes())),
            &parts,
            &mut counts,
        );
    }
    for (name, wire) in fixtures(include_str!("fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        check(
            &message,
            e::NasEpsMessage::to_view,
            |message, view| message.with_view(view).ok().inspect(|m| drop(m.to_bytes())),
            &parts,
            &mut counts,
        );
    }
    assert!(counts[0] > 4_000 && counts[1] > 100, "{counts:?}");
}

/// A SERVICE REQUEST has the fields of its short header (TS 24.301 §8.2.25).
#[test]
fn a_service_request_reads_and_writes_its_short_header() {
    use oxirush_nas::view;
    // KSI 1, sequence number 5 and a short MAC.
    let request = eps("c725abcd");
    let tree = request.to_view();
    assert_eq!(
        tree,
        json!({
            "protocol-discriminator": {"value": 7},
            "security-header-type": {"value": "service-request"},
            "ksi-and-sequence-number": {
                "value": {"ksi": 1, "sequence-number": 5},
                "octets": "25",
            },
            "message-authentication-code": {"octets": "abcd"},
        })
    );
    let sequence = "/nas/ksi-and-sequence-number/value/sequence-number";
    assert_eq!(view::select(&tree, sequence), Ok(vec![&json!(5)]));
    let edited = |edit: &dyn Fn(&mut Value) -> Result<(), String>| {
        let mut tree = request.to_view();
        edit(&mut tree)?;
        let message = request.with_view(tree).map_err(|error| error.to_string())?;
        Ok::<_, String>(hex::encode(message.to_bytes().unwrap()))
    };
    let set = |path: &str, value: Value| edited(&|tree| view::set(tree, path, value.clone()));
    assert_eq!(set(sequence, json!(6)).unwrap(), "c726abcd");
    let ksi = "/nas/KSI and sequence number/value/ksi";
    assert_eq!(set(ksi, json!(7)).unwrap(), "c7e5abcd");
    let octets = "/nas/ksi-and-sequence-number/octets";
    assert_eq!(set(octets, json!("47")).unwrap(), "c747abcd");
    let mac = "/nas/message-authentication-code/octets";
    assert_eq!(set(mac, json!("0102")).unwrap(), "c7250102");
    let header_type = "/nas/security-header-type/value";
    assert_eq!(set(header_type, json!(13)).unwrap(), "d725abcd");
    // The message that a view describes alone.
    let alone = e::NasServiceRequest::from_view(tree.clone()).unwrap();
    assert_eq!(alone, request);
    let mut partial = tree.clone();
    view::remove(&mut partial, "/nas/message-authentication-code").unwrap();
    let error = e::NasServiceRequest::from_view(partial).unwrap_err();
    let error = error.to_string();
    assert!(
        error.contains("`message-authentication-code` is not written"),
        "{error}"
    );
    // Nothing that the view says is ignored.
    for (path, value, reason) in [
        (ksi, json!(8), "a ksi is 0 to 7"),
        (
            "/nas/ksi-and-sequence-number/value/typo",
            json!(1),
            "no member `typo`",
        ),
        (octets, json!("0102"), "its octets are one octet"),
        (mac, json!("01"), "its octets are two octets"),
        (
            "/nas/message-authentication-code/value",
            json!(1),
            "it has its `octets` alone",
        ),
        (header_type, json!(2), "is not service-request, or 12 to 15"),
        ("/nas/protocol-discriminator/value", json!(2), "is not 7"),
    ] {
        let error = set(path, value).unwrap_err();
        assert!(error.contains(reason), "{path}: {error}");
    }
    let error = edited(&|tree| {
        tree["emm-cause"] = json!({"value": "congestion"});
        Ok(())
    });
    let error = error.unwrap_err();
    assert!(
        error.contains("`emm-cause` is no IE of the message"),
        "{error}"
    );
    let error = edited(&|tree| {
        tree["ksi-and-sequence-number"] = json!({"value": {"ksi": 3}, "octets": "47"});
        Ok(())
    });
    assert!(error.unwrap_err().contains("disagree"));
}

#[test]
fn a_code_is_written_by_its_name_or_by_its_number() {
    // 5GMM STATUS, cause #22: one coded value.
    let status = fgs("7e006416");
    let cause = |value: Value| fgs_edited(&status, |view| view["5gmm-cause"]["value"] = value);
    assert_eq!(cause(json!("illegal-ue")).unwrap(), "7e006403");
    assert_eq!(cause(json!(3)).unwrap(), "7e006403");
    assert_eq!(cause(json!("0x03")).unwrap(), "7e006403");
    assert_eq!(cause(json!(22)).unwrap(), "7e006416");
    // The fields of an octet: REGISTRATION ACCEPT, 3GPP access.
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let result = |value: Value| {
        fgs_edited(&accept, |view| {
            view["5gs-registration-result"]["value"]["result"] = value
        })
    };
    let named = result(json!("non-3gpp-access")).unwrap();
    assert_eq!(&named[..10], "7e00420102");
    assert_eq!(result(json!(2)).unwrap(), named);
    assert_eq!(
        result(json!(1)).unwrap(),
        hex::encode(accept.to_bytes().unwrap())
    );
    // A number that the field cannot hold is refused.
    assert!(result(json!(9)).unwrap_err().contains("result"));
    // The two values of one octet: PDU SESSION ESTABLISHMENT ACCEPT.
    let accept = fgs("2e0101c211000901000631310101ff0106060064060032");
    let selected = |value: Value| {
        fgs_edited(&accept, |view| {
            view["selected-pdu-session-type"]["value"] = value
        })
    };
    let named = selected(json!({"pdu-session-type": "ipv6", "ssc-mode": "ssc2"})).unwrap();
    assert_eq!(&named[..10], "2e0101c222");
    assert_eq!(
        selected(json!({"pdu-session-type": 2, "ssc-mode": 2})).unwrap(),
        named
    );
    assert!(selected(json!({"pdu-session-type": 9, "ssc-mode": 2})).is_err());
    // EPS: ATTACH REJECT, cause #3.
    let reject = eps("074403");
    let cause = |value: Value| eps_edited(&reject, |view| view["emm-cause"]["value"] = value);
    assert_eq!(cause(json!("congestion")).unwrap(), "074416");
    assert_eq!(cause(json!(22)).unwrap(), "074416");
}

#[test]
fn the_type_of_a_message_is_written_by_its_name_or_by_its_number() {
    let status = |kind: Value| {
        json!({
            "extended-protocol-discriminator": {"value": 126},
            "security-header-type": {"value": 0},
            "message-type": {"value": kind},
            "5gmm-cause": {"value": "congestion"},
        })
    };
    let kind = f::Nas5gmmMessageType::FGmmStatus;
    for written in [json!("5gmm-status"), json!(0x64)] {
        let message = kind.from_view(status(written.clone())).unwrap();
        assert_eq!(
            message.to_bytes().unwrap(),
            [0x7e, 0x00, 0x64, 0x16],
            "{written}"
        );
        // The view says what message it is of: the type is not needed twice.
        let alone = f::Nas5gsMessage::from_view(status(written)).unwrap();
        assert_eq!(alone, message);
    }
    // The number of another type is the name of another type.
    let other = f::Nas5gmmMessageType::RegistrationComplete.from_view(status(json!(0x64)));
    let error = other.unwrap_err().to_string();
    assert!(error.contains("`message-type` is 5gmm-status"), "{error}");
    for (view, reason) in [
        (
            json!({"5gmm-cause": {"value": "congestion"}}),
            "names the message",
        ),
        (
            status(json!("no-such-message")),
            "no message `no-such-message`",
        ),
        (status(json!(0xff)), "names the message"),
    ] {
        let error = f::Nas5gsMessage::from_view(view).unwrap_err().to_string();
        assert!(error.contains(reason), "{error}");
    }
    // A 5GSM message, an EMM and an ESM one, and the short SERVICE REQUEST.
    let accept = fgs("2e0101c211000901000631310101ff0106060064060032");
    assert_eq!(
        f::Nas5gsMessage::from_view(accept.to_view()).unwrap(),
        accept
    );
    for wire in ["074403", "0209da280908696e7465726e6574", "c725abcd"] {
        let message = eps(wire);
        let alone = e::NasEpsMessage::from_view(message.to_view()).unwrap();
        assert_eq!(hex::encode(alone.to_bytes().unwrap()), wire);
    }
    let mut reject = eps("074403").to_view();
    reject["message-type"]["value"] = json!(0x44);
    let alone = e::NasEpsMessage::from_view(reject).unwrap();
    assert_eq!(alone.to_bytes().unwrap(), [0x07, 0x44, 0x03]);
    let error = e::NasEpsMessage::from_view(json!({}))
        .unwrap_err()
        .to_string();
    assert!(error.contains("names the message"), "{error}");
}

#[test]
fn every_fixture_is_the_message_of_its_view_alone() {
    for (name, wire) in fixtures(include_str!("fixtures/nas-5gs.tsv")) {
        let message = f::Nas5gsMessage::from_bytes(&wire).unwrap();
        if !matches!(
            message,
            f::Nas5gsMessage::Gmm(..) | f::Nas5gsMessage::Gsm(..)
        ) {
            continue;
        }
        let alone = f::Nas5gsMessage::from_view(message.to_view());
        let alone = alone.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(alone.to_bytes().unwrap(), wire, "{name}");
    }
    for (name, wire) in fixtures(include_str!("fixtures/nas-eps.tsv")) {
        let message = eps_fixture(name, &wire);
        if matches!(
            message,
            e::NasEpsMessage::SecurityProtected(..)
                | e::NasEpsMessage::EmmTransport(_)
                | e::NasEpsMessage::Opaque(_)
        ) {
            continue;
        }
        let alone = e::NasEpsMessage::from_view(message.to_view());
        let alone = alone.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(alone.to_bytes().unwrap(), wire, "{name}");
    }
}

#[test]
fn a_view_gives_a_message_that_has_octets() {
    // A type that the IEs are not those of: the message had no octets, and
    // came back all the same.
    let status = fgs("7e006416");
    let error = fgs_edited(&status, |view| {
        view["message-type"]["value"] = json!("registration-complete")
    });
    assert!(error.is_err(), "{error:?}");
    let reject = eps("074403");
    let error = eps_edited(&reject, |view| {
        view["message-type"]["value"] = json!("attach-complete")
    });
    assert!(error.is_err(), "{error:?}");
    // A view that changes nothing gives the message back as it is.
    assert_eq!(status.with_view(status.to_view()).unwrap(), status);
}

#[test]
fn one_value_of_an_octet_is_edited_and_the_other_stays() {
    // PDU SESSION ESTABLISHMENT ACCEPT whose selected type is the reserved 0,
    // with SSC mode 1: the type is its number, and stays when the mode changes.
    let accept = fgs("2e0101c210000901000631310101ff0106060064060032");
    assert_eq!(
        accept.to_view()["selected-pdu-session-type"]["value"],
        json!({"pdu-session-type": 0, "ssc-mode": "ssc1"})
    );
    let edited = fgs_edited(&accept, |view| {
        view["selected-pdu-session-type"]["value"]["ssc-mode"] = json!("ssc2")
    });
    assert_eq!(&edited.unwrap()[..10], "2e0101c220");
    // And the mode stays when the type changes.
    let edited = fgs_edited(&accept, |view| {
        view["selected-pdu-session-type"]["value"]["pdu-session-type"] = json!("ipv4")
    });
    assert_eq!(&edited.unwrap()[..10], "2e0101c211");
}

#[test]
fn an_optional_ie_that_is_added_with_zeros_has_its_octets() {
    // REGISTRATION REQUEST without extended DRX parameters: the IE that a
    // view adds has its octet, of zeros as of anything else.
    let request = fgs("7e004101000d0102f8390000000021436587f9");
    let added = |window: u8, value: u8| {
        fgs_edited(&request, |view| {
            view["requested-extended-drx-parameters"] =
                json!({"value": {"paging-time-window": window, "edrx-value": value}});
        })
    };
    let wire = hex::encode(request.to_bytes().unwrap());
    assert_eq!(added(0, 0).unwrap(), format!("{wire}6e0100"));
    assert_eq!(added(1, 0).unwrap(), format!("{wire}6e0110"));
    // Flags that are all false too.
    let flags = fgs_edited(&request, |view| {
        view["ue-status"] = json!({"value": {"s1-mode-reg": false, "n1-mode-reg": false}});
    });
    assert_eq!(flags.unwrap(), format!("{wire}2b0100"));
}

#[test]
fn a_time_whose_digits_are_no_digits_has_its_octets_alone() {
    let command = |time: &str| fgs(&format!("7e005447{time}"));
    let shown = command("62017151406380").to_view();
    let time = &shown["universal-time-and-local-time-zone"];
    assert_eq!(time["value"]["year"], json!(26), "{time}");
    assert_eq!(time["value"]["month"], json!(10));
    // A year of the digits A and 0: no year writes these octets.
    for octets in ["0a017151406380", "a0017151406380", "620171514063f0"] {
        let shown = command(octets).to_view();
        let time = &shown["universal-time-and-local-time-zone"];
        assert_eq!(time, &json!({"octets": octets}), "{octets}");
        // The view is still that of the message.
        let message = command(octets);
        assert_eq!(message.with_view(shown).unwrap(), message);
    }
}

#[test]
fn a_path_takes_a_name_by_its_letters_and_a_position_as_decimal_writes_it() {
    use oxirush_nas::view;
    let accept = fgs("7e0042010177000bf202f8390100421122334415020101");
    let tree = accept.to_view();
    let sst = view::select(&tree, "/nas/allowed-nssai/value/0/sst").unwrap();
    for path in [
        "/NAS/Allowed NSSAI/Value/0/SST",
        "/nas/allowed_nssai/value/0/sst",
        "/nas/allowednssai/value/0/sst",
        "/nas/allowed.nssai/value/0/sst",
    ] {
        assert_eq!(view::select(&tree, path).unwrap(), sst, "{path}");
    }
    for path in [
        "/nas/allowed-nssai/value/+0/sst",
        "/nas/allowed-nssai/value/00/sst",
    ] {
        let error = view::select(&tree, path).unwrap_err();
        assert!(
            error.contains("array index must be numeric"),
            "{path}: {error}"
        );
    }
}
