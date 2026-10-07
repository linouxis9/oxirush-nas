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
    // A named value is written by its name, and nothing else is a cause.
    for value in [
        json!(22),
        json!(256),
        json!({"cause": "illegal-ue"}),
        json!(true),
    ] {
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
    for (member, value) in [
        ("registration-type", json!("mobility")),
        ("registration-type", json!(2)),
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
    // Service type 7 has no name: it is written through the octets.
    assert_eq!(
        fgs("7e004c710007f4004211223344").to_view()["ngksi"]["value"]["service-type"],
        7
    );
    let numbered = fgs_edited(&request, |view| {
        view["ngksi"]["value"]["service-type"] = json!(7)
    });
    assert!(numbered.unwrap_err().contains("ngksi"));
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
fn a_view_is_read_through_a_security_header() {
    // Integrity protected 5GMM STATUS.
    let protected = fgs("7e0100000000007e006416");
    let view = protected.to_view();
    assert_eq!(view["message-type"]["value"], "5gmm-status");
    assert_eq!(view["5gmm-cause"]["value"], "congestion");
    let edited = fgs_edited(&protected, |view| {
        view["5gmm-cause"]["value"] = json!("illegal-ue")
    });
    assert_eq!(edited.unwrap(), "7e0100000000007e006403");
    // A ciphered message and an EPS SERVICE REQUEST have no IEs to show.
    let ciphered = fgs("7e0200000000001234");
    assert_eq!(ciphered.to_view(), json!({}));
    assert_eq!(ciphered.with_view(json!({})).unwrap(), ciphered);
    assert!(
        ciphered
            .with_view(json!({"5gmm-cause": {"octets": "03"}}))
            .is_err()
    );
    assert!(ciphered.with_view(json!([])).is_err());
    let request = eps("c7200000");
    assert_eq!(request.to_view(), json!({}));
    assert_eq!(request.with_view(json!({})).unwrap(), request);
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
                // An IE whose value is a number has its size, one octet or two.
                let added = ["00", "0000"].into_iter().find_map(|octets| {
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

/// The example of the README.
#[test]
fn the_readme_example_holds() {
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = f::Nas5gsMessage::from_bytes(&bytes).unwrap();
    let mut view = accept.to_view();
    assert_eq!(view["message-type"]["value"], "registration-accept");
    assert_eq!(
        view["5gs-registration-result"]["value"]["result"],
        "3gpp-access"
    );
    assert_eq!(view["5g-guti"]["value"]["guti"]["plmn"], "208-93");
    assert_eq!(view["5g-guti"]["value"]["guti"]["tmsi"], 0x1122_3344);
    assert_eq!(view["allowed-nssai"]["value"][0]["sst"], 1);
    assert_eq!(view["allowed-nssai"]["octets"], "0101");
    view["5g-guti"]["value"]["guti"]["tmsi"] = json!("0xdeadbeef");
    view["allowed-nssai"]["value"] = json!([{"sst": 1, "sd": "010203"}]);
    assert!(view["t3512-value"].is_null());
    view["t3512-value"] = json!({"value": 3600});
    let edited = accept.with_view(view).unwrap();
    assert_eq!(
        hex::encode(edited.to_bytes().unwrap()),
        "7e0042010177000bf202f839010042deadbeef150504010102035e0106"
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
