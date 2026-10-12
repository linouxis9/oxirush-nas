// The Rust blocks of README.md, each as a function. `tests/readme.rs` writes
// this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what the README shows.
macro_rules! println {
    () => {
        PRINTED.with(|printed| printed.borrow_mut().push('\n'))
    };
    ($($argument:tt)*) => {
        PRINTED.with(|printed| {
            let line = format!($($argument)*);
            let mut printed = printed.borrow_mut();
            printed.push_str(&line);
            printed.push('\n');
        })
    };
}

/// What `block` prints.
pub fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

pub const BLOCKS: &[fn()] = &[
    block_1,
    block_2,
    block_3,
    block_4,
    block_5,
    block_6,
    block_7,
    block_8,
    block_9,
    block_10,
    block_11,
    block_12,
    block_13,
    block_14,
    block_15,
    block_16,
    block_17,
    block_18,
];

/// The Rust block 1 of README.md.
fn block_1() {
    use oxirush_nas::nas_5gs::*;

    // Decode a REGISTRATION REQUEST
    let bytes = hex::decode(
        "7e004179000d0102f8390000000000000010022e08a020000000000000"
    ).unwrap();
    let msg = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{msg}");

    // Read its IEs through typed accessors
    if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationRequest(reg)) = &msg {
        let kind = reg.fgs_registration_type.registration_type();
        assert_eq!(kind, Some(RegistrationType::InitialRegistration));

        let identity = &reg.fgs_mobile_identity;
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Suci));

        // The PLMN identity names the network: a country code and a network code
        let plmn = identity.plmn().unwrap();
        println!("MCC={}, MNC={}", plmn.mcc_string(), plmn.mnc_string());
    }

    // It passes every check that can be made on a single message, and encodes
    // to the octets that were decoded
    assert!(msg.validate().is_empty());
    assert_eq!(bytes, msg.encode().unwrap());

    // Build the answer, a REGISTRATION REJECT with cause #22 and a T3346 value
    // of ten minutes: `new()` takes the mandatory IEs, `set_*()` adds the others
    let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
    let t3346 = NasGprsTimer2::from_seconds(600).unwrap();
    let reject = NasRegistrationReject::new(cause).set_t3346_value(t3346);
    let answer = Nas5gsMessage::new_5gmm(reject);

    // Encode it
    let octets = answer.encode().unwrap();
    assert_eq!(hex::encode(octets), "7e0044165f012a");
}

/// The Rust block 2 of README.md.
fn block_2() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use serde_json::json;

    // Decode the REGISTRATION REJECT
    let bytes = hex::decode("7e0044165f012a").unwrap();
    let reject = Nas5gsMessage::decode(&bytes).unwrap();

    // Show it as a tree
    let mut tree = reject.to_tree();
    println!("{tree:#}");

    // Change a value, and encode the message that the tree writes
    tree["t3346-value"] = json!(1200);
    let edited = Nas5gsMessage::from_tree(tree).unwrap();
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044165f0134");
}

/// The Rust block 3 of README.md.
fn block_3() {
    use oxirush_nas::nas_5gs::*;

    // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
    let bytes = hex::decode("7e0044165f012a").unwrap();
    let mut msg = Nas5gsMessage::decode(&bytes).unwrap();

    if let Nas5gsMessage::Gmm(_, Nas5gmmMessage::RegistrationReject(reject)) = &mut msg {
        // Read a mandatory IE, an optional IE that is there and one that is not
        assert_eq!(reject.fgmm_cause.cause(), Some(GmmCause::Congestion));
        let t3346 = reject.t3346_value.as_ref().unwrap();
        assert_eq!(t3346.to_seconds(), Some(600));
        assert!(!reject.has_t3502_value());

        // Another cause, T3346 taken out and T3502 added
        reject.fgmm_cause = NasFGmmCause::from_cause(GmmCause::IllegalUe);
        reject.clear_t3346_value();
        reject.set_t3502_value_mut(NasGprsTimer2::from_seconds(720).unwrap());
    }

    assert_eq!(hex::encode(msg.encode().unwrap()), "7e00440316012c");
}

/// The Rust block 4 of README.md.
fn block_4() {
    use oxirush_nas::nas_eps::*;

    // Decode an ATTACH REQUEST with an IMSI and a PDN CONNECTIVITY REQUEST
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
    let msg = NasEpsMessage::decode(&bytes).unwrap();
    println!("{msg}");
    assert!(msg.validate().is_empty());

    // Read its IEs, and the ESM message in its container
    if let NasEpsMessage::Emm(_, NasEmmMessage::AttachRequest(request)) = &msg {
        let imsi = request.eps_mobile_identity.as_imsi();
        assert_eq!(imsi.as_deref(), Some("208930000000001"));
        assert!(request.ue_network_capability.supports_eea(2));

        let esm = request.esm_message_container.decode_as_esm_message().unwrap();
        println!("{esm}");
    }

    // It encodes to the octets that were decoded
    assert_eq!(bytes, msg.encode().unwrap());

    // Build an ATTACH REJECT, cause #3, and encode it
    let cause = NasEmmCause::from_cause(EmmCause::IllegalUe);
    let reject = NasAttachReject::new(cause);
    let answer = NasEpsMessage::new_emm(reject);
    assert_eq!(answer.encode().unwrap(), [0x07, 0x44, 0x03]);
}

/// The Rust block 5 of README.md.
fn block_5() {
    use oxirush_nas::nas_5gs::{Nas5gsMessage, Validate};

    // REGISTRATION REJECT whose T3346 value is there twice, then an unknown IE
    // that is encoded as "comprehension required"
    let bytes = hex::decode("7e0044165f012a5f012a0400").unwrap();
    let msg = Nas5gsMessage::decode(&bytes).unwrap();

    // What `validate()` finds
    for finding in msg.validate() {
        println!("{finding}");
    }

    // Both are kept as they came, and go out again
    assert_eq!(msg.unknown_ies().len(), 2);
    assert!(msg.unknown_ies()[1].is_comprehension_required());
    assert_eq!(bytes, msg.encode().unwrap());
}

/// The Rust block 6 of README.md.
fn block_6() {
    use oxirush_nas::nas_5gs::ie::{CipheringAlgorithm, IntegrityAlgorithm};
    use oxirush_nas::nas_5gs::{
        Direction, Nas5gsMessage, Nas5gsSecurityHeaderType, NasSecurityContext,
    };

    // REGISTRATION REJECT, cause #3
    let msg = Nas5gsMessage::decode(&[0x7e, 0x00, 0x44, 0x03]).unwrap();

    // The two ends of one link: the same keys and the same algorithms
    let (knas_int, knas_enc) = ([0u8; 16], [0u8; 16]);
    let (nia, nea) = (IntegrityAlgorithm::NIA2, CipheringAlgorithm::NEA2);
    let mut tx = NasSecurityContext::from_fresh_keys(knas_int, knas_enc, nia, nea).unwrap();
    let mut rx = NasSecurityContext::from_fresh_keys(knas_int, knas_enc, nia, nea).unwrap();

    // Protect outbound: integrity and ciphering
    let sht = Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered;
    let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();

    // Unprotect inbound: MAC check, deciphering and decoding
    let (decoded, header_type) = rx.unprotect(&protected, Direction::Downlink).unwrap();
    assert_eq!((decoded, header_type), (msg, sht));
}

/// The Rust block 7 of README.md.
fn block_7() {
    use oxirush_nas::nas_eps::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, NasEpsMessage,
        NasEpsSecurityHeaderType, NasSecurityContext,
    };

    // ATTACH REJECT, cause #3
    let msg = NasEpsMessage::decode(&[0x07, 0x44, 0x03]).unwrap();

    // The two ends of one link: the same KASME and the same algorithms
    let kasme = [0x11; 32];
    let (eia, eea) = (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2);
    let mut tx = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
    let mut rx = NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();

    // Protect outbound: integrity and ciphering
    let sht = NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered;
    let protected = tx.protect(&msg, sht, Direction::Downlink).unwrap();

    // Unprotect inbound: MAC check, deciphering and decoding
    let (decoded, header_type) = rx.unprotect(&protected, Direction::Downlink).unwrap();
    assert_eq!((decoded, header_type), (msg, sht));
}

/// The Rust block 8 of README.md.
fn block_8() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;

    // 5GMM STATUS, cause #22
    let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();

    // Its tree, then its view
    println!("{}", status.to_tree());
    println!("{:#}", status.to_view());
}

/// The Rust block 9 of README.md.
fn block_9() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;

    // REGISTRATION ACCEPT with a 5G-GUTI, the temporary identity that the network
    // gives the UE, and an allowed NSSAI, the network slices that it may use
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = Nas5gsMessage::decode(&bytes).unwrap();
    let view = accept.to_view();

    // An IE with its value and its octets
    println!("{:#}", view["5g-guti"]);

    // A member of a value, and of an entry of a list
    assert_eq!(view["5g-guti"]["value"]["guti"]["plmn"], "208-93");
    assert_eq!(view["allowed-nssai"]["value"][0]["sst"], 1);

    // An optional IE that the message does not have
    assert!(view["t3512-value"].is_null());
}

/// The Rust block 10 of README.md.
fn block_10() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use serde_json::json;

    // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{}", accept.to_view()["allowed-nssai"]);

    // The slice gets an SD, and the 5G-GUTI another TMSI
    let mut view = accept.to_view();
    view["allowed-nssai"]["value"][0]["sd"] = json!("010203");
    view["5g-guti"]["value"]["guti"]["tmsi"] = json!("0xdeadbeef");
    let edited = accept.with_view(view).unwrap();

    // The allowed NSSAI and the octets of the edited message
    println!("{}", edited.to_view()["allowed-nssai"]);
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "7e0042010177000bf202f839010042deadbeef15050401010203"
    );
}

/// The Rust block 11 of README.md.
fn block_11() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use serde_json::json;

    // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
    let bytes = hex::decode("7e0044165f012a").unwrap();
    let reject = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{}", reject.to_tree());

    // One optional IE comes in, another goes out
    let mut view = reject.to_view();
    view["t3502-value"] = json!({"value": 720}); // added by its value, or by its octets
    view["t3346-value"] = json!(null); // taken out
    let edited = reject.with_view(view).unwrap();

    // The tree and the octets of the edited message
    println!("{}", edited.to_tree());
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e00441616012c");
}

/// The Rust block 12 of README.md.
fn block_12() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use serde_json::json;

    // REGISTRATION REJECT: cause #22 and a T3346 value of ten minutes
    let bytes = hex::decode("7e0044165f012a").unwrap();
    let reject = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{}", reject.to_view()["t3346-value"]);

    // A T3346 value of two octets, where the specification has one
    let mut view = reject.to_view();
    view["t3346-value"]["octets"] = json!("2a2b");
    let edited = reject.with_view(view).unwrap();

    // The IE and the octets of the edited message
    println!("{}", edited.to_view()["t3346-value"]);
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e0044165f022a2b");

    // The 5GMM cause has no length: it is one octet
    let mut view = reject.to_view();
    view["5gmm-cause"]["octets"] = json!("ffff");
    println!("{}", reject.with_view(view).unwrap_err());
}

/// The Rust block 13 of README.md.
fn block_13() {
    use oxirush_nas::nas_5gs::{Nas5gmmMessageType, Nas5gsMessage};
    use serde_json::json;

    // A REGISTRATION REJECT by the name of its type and of its IEs
    let reject = Nas5gsMessage::from_tree(json!({
        "message-type": "registration-reject",
        "5gmm-cause": "congestion",
        "t3346-value": 600,
    }))
    .unwrap();
    assert_eq!(hex::encode(reject.encode().unwrap()), "7e0044165f012a");

    // A 5GSM message writes the fields of its header that its type does not decide
    let complete = Nas5gsMessage::from_tree(json!({
        "message-type": "pdu-session-release-complete",
        "pdu-session-identity": 5,
        "procedure-transaction-identity": 1,
    }))
    .unwrap();
    assert_eq!(hex::encode(complete.encode().unwrap()), "2e0501d4");

    // A mandatory IE that is left out is an error
    let tree = json!({"message-type": "registration-reject"});
    println!("{}", Nas5gsMessage::from_tree(tree).unwrap_err());

    // What a message of a type can have, in the order of the message
    println!("{:?}", Nas5gmmMessageType::AuthenticationFailure.view_names());
}

/// The Rust block 14 of README.md.
fn block_14() {
    use oxirush_nas::nas_eps::NasEpsMessage;
    use serde_json::json;

    // ATTACH REQUEST with a PDN CONNECTIVITY REQUEST in its ESM message container
    let bytes = hex::decode("07410108298039000000001002e0e000040201d031").unwrap();
    let attach = NasEpsMessage::decode(&bytes).unwrap();
    println!("{:#}", attach.to_tree()["esm-message-container"]);

    // In a view, the value of the container is the view of its message
    let mut view = attach.to_view();
    view["esm-message-container"]["value"]["pdn-type"]["value"] = json!("ipv6");
    let edited = attach.with_view(view).unwrap();

    // The PDN type and the octets of the edited message
    println!("{}", edited.to_tree()["esm-message-container"]["pdn-type"]);
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "07410108298039000000001002e0e000040201d021"
    );
}

/// The Rust block 15 of README.md.
fn block_15() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;
    use serde_json::json;

    // 5GMM STATUS under an integrity protected header
    let bytes = hex::decode("7e01e73b901b007e006416").unwrap();
    let protected = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{:#}", protected.to_tree());

    // An edit that leaves the old MAC in the security header is refused
    let mut view = protected.to_view();
    view["5gmm-cause"]["value"] = json!("illegal-ue");
    println!("{}", protected.with_view(view.clone()).unwrap_err());

    // The view writes the code of the edited message
    view["security-header"]["value"]["message-authentication-code"] = json!("0x01020304");
    let edited = protected.with_view(view).unwrap();
    assert_eq!(hex::encode(edited.encode().unwrap()), "7e0101020304007e006403");

    // A message that is ciphered has its octets
    let bytes = hex::decode("7e024b708bc300026ff75c").unwrap();
    let ciphered = Nas5gsMessage::decode(&bytes).unwrap();
    println!("{}", ciphered.to_tree()["ciphered-message"]);
}

/// The Rust block 16 of README.md.
fn block_16() {
    use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
    use serde_json::json;

    // REGISTRATION ACCEPT with a 5G-GUTI and an allowed NSSAI
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = Nas5gsMessage::decode(&bytes).unwrap();
    let tree = accept.to_view();

    // Each value with the path that selects it
    for (path, value) in view::paths(&tree) {
        println!("{path} = {value}");
    }

    // A coded value by its name, an identity by its parts, and the octets beside
    let select = |path| view::select(&tree, path).unwrap();
    assert_eq!(select("/nas/message-type/value"), [&json!("registration-accept")]);
    assert_eq!(select("/nas/5gs-registration-result/value/result"), [&json!("3gpp-access")]);
    assert_eq!(select("/nas/5g-guti/value/guti/tmsi"), [&json!(0x1122_3344)]);
    assert_eq!(select("/nas/allowed-nssai/octets"), [&json!("0101")]);

    // A name in any case, and `*` for each entry of a list
    assert_eq!(select("/NAS/Allowed NSSAI/value/*/SST"), [&json!(1)]);

    // An optional IE that the message does not have selects nothing
    assert!(select("/nas/t3512-value/value").is_empty());

    // A name that the message does not have is an error
    assert!(view::select(&tree, "/nas/t3512/value").is_err());
}

/// The Rust block 17 of README.md.
fn block_17() {
    use oxirush_nas::{nas_5gs::Nas5gsMessage, view};
    use serde_json::json;

    // The same REGISTRATION ACCEPT
    let bytes = hex::decode("7e0042010177000bf202f8390100421122334415020101").unwrap();
    let accept = Nas5gsMessage::decode(&bytes).unwrap();

    // A value is set at its path
    let mut tree = accept.to_view();
    view::set(&mut tree, "/nas/5g-guti/value/guti/tmsi", json!("0xdeadbeef")).unwrap();
    view::set(&mut tree, "/nas/allowed-nssai/value/0/sd", json!("010203")).unwrap();

    // An optional IE that the message does not have is added by its value
    view::set(&mut tree, "/nas/t3512-value/value", json!(3600)).unwrap();

    // The message of the edited view
    let edited = accept.with_view(tree).unwrap();
    assert_eq!(
        hex::encode(edited.encode().unwrap()),
        "7e0042010177000bf202f839010042deadbeef150504010102035e0106"
    );

    // A list takes an entry before a position or at its end (`-`), and loses one
    let mut tree = accept.to_view();
    let slice = json!({"sst": 2, "sd": "0000ff"});
    view::insert(&mut tree, "/nas/allowed-nssai/value/-", slice).unwrap();
    view::remove(&mut tree, "/nas/allowed-nssai/value/0").unwrap();

    let edited = accept.with_view(tree).unwrap();
    assert_eq!(edited.to_view()["allowed-nssai"]["octets"], "04020000ff");
}

/// The Rust block 18 of README.md.
fn block_18() {
    use oxirush_nas::nas_5gs::Nas5gsMessage;

    // 5GMM STATUS, cause #22, as a document
    let status = Nas5gsMessage::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    let document = serde_json::to_value(&status).unwrap();
    println!("{document}");

    // The document back to a message, and to its octets
    let restored: Nas5gsMessage = serde_json::from_value(document).unwrap();
    assert_eq!(restored.encode().unwrap(), [0x7e, 0x00, 0x64, 0x16]);
}
