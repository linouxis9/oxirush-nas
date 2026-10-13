//! Messages that other implementations sent: `tests/fixtures/captured.tsv`
//! says where each comes from and how it was captured. The crate reads each
//! as the dissector of its capture named it, writes it back to its octets,
//! and with the `security` feature verifies and deciphers what was on the
//! wire with the keys and the NAS COUNT that are recorded beside it.
use oxirush_nas::{Validate, nas_5gs as f, nas_eps as e};

/// One line of the fixture.
struct Captured<'a> {
    line: usize,
    system: &'a str,
    sender: &'a str,
    downlink: bool,
    /// The name that pycrate 0.8.1 gives the plain message.
    name: &'a str,
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    security_header_type: u8,
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    count: Option<u32>,
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    keys: Option<([u8; 16], [u8; 16])>,
    #[cfg_attr(not(feature = "security"), allow(dead_code))]
    wire: Vec<u8>,
    plain: Vec<u8>,
}

fn captured() -> Vec<Captured<'static>> {
    let key = |text: &str| -> [u8; 16] { hex::decode(text).unwrap().try_into().unwrap() };
    include_str!("fixtures/captured.tsv")
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.starts_with('#') && !line.is_empty())
        .map(|(at, line)| {
            let columns: Vec<&str> = line.split('\t').collect();
            let [
                system,
                sender,
                direction,
                name,
                header,
                count,
                integrity,
                ciphering,
                wire,
                plain,
            ] = columns[..]
            else {
                panic!("line {}: {} columns", at + 1, columns.len());
            };
            Captured {
                line: at + 1,
                system,
                sender,
                downlink: match direction {
                    "downlink" => true,
                    "uplink" => false,
                    other => panic!("line {}: direction {other}", at + 1),
                },
                name,
                security_header_type: header.parse().unwrap(),
                count: (!count.is_empty()).then(|| count.parse().unwrap()),
                keys: (!integrity.is_empty()).then(|| (key(integrity), key(ciphering))),
                wire: hex::decode(wire).unwrap(),
                plain: hex::decode(plain).unwrap(),
            }
        })
        .collect()
}

/// The name of pycrate for a message type of the crate, as its `Debug`
/// writes it: the same words but for the prefix of the protocol, and for
/// the four that pycrate names by who starts the procedure or abbreviates.
fn named_by_pycrate(protocol: &str, kind: &str) -> String {
    let words = match kind {
        "DeregistrationRequestFromUe" => "MODeregistrationRequest",
        "DeregistrationAcceptFromUe" => "MODeregistrationAccept",
        "DlNasTransport" => "DLNASTransport",
        "UlNasTransport" => "ULNASTransport",
        "FGmmStatus" => "Status",
        "EmmInformation" => "Information",
        "EsmInformationRequest" => "InformationRequest",
        "PdnConnectivityReject" => "PDNConnectivityReject",
        other => other,
    };
    format!("{protocol}{words}")
}

/// The fixture is what its head says: 170 messages of four senders.
#[test]
fn the_captured_messages_are_those_of_four_senders() {
    let all = captured();
    let of = |sender: &str, system: &str| {
        (all.iter())
            .filter(|message| message.sender.starts_with(sender) && message.system == system)
            .count()
    };
    assert_eq!(all.len(), 170);
    assert_eq!(of("Open5GS v2.8.0", "5gs"), 58);
    assert_eq!(of("Open5GS v2.8.0", "eps"), 52);
    assert_eq!(of("free5GC v4.2.3", "5gs"), 52);
    assert_eq!(of("PacketRusher 20250225", "5gs"), 8);
    // What it is not: no uplink message of EPS
    assert!(
        all.iter()
            .all(|message| message.system == "5gs" || message.downlink)
    );
}

/// Each plain message decodes to the message that the dissector of the
/// capture names, has no finding of `validate()`, and encodes back to its
/// octets.
#[test]
fn each_captured_message_is_read_as_its_dissector_names_it_and_written_back() {
    for message in captured() {
        let at = format!("line {} ({})", message.line, message.name);
        let (name, findings, encoded) = match message.system {
            "5gs" => {
                let decoded = f::Nas5gsMessage::decode(&message.plain)
                    .unwrap_or_else(|error| panic!("{at}: {error}"));
                let name = match &decoded {
                    f::Nas5gsMessage::Gmm(_, gmm) => {
                        named_by_pycrate("5GMM", &format!("{:?}", gmm.message_type()))
                    }
                    f::Nas5gsMessage::Gsm(_, gsm) => {
                        named_by_pycrate("5GSM", &format!("{:?}", gsm.message_type()))
                    }
                    other => panic!("{at}: {other:?}"),
                };
                (name, decoded.validate(), decoded.encode().unwrap())
            }
            _ => {
                let direction = match message.downlink {
                    true => e::Direction::Downlink,
                    false => e::Direction::Uplink,
                };
                let decoded = e::NasEpsMessage::decode_with_direction(&message.plain, direction)
                    .unwrap_or_else(|error| panic!("{at}: {error}"));
                let name = match &decoded {
                    e::NasEpsMessage::Emm(_, emm) => {
                        named_by_pycrate("EMM", &format!("{:?}", emm.message_type()))
                    }
                    e::NasEpsMessage::Esm(_, esm) => {
                        named_by_pycrate("ESM", &format!("{:?}", esm.message_type()))
                    }
                    other => panic!("{at}: {other:?}"),
                };
                (name, decoded.validate(), decoded.encode().unwrap())
            }
        };
        assert_eq!(name, message.name, "{at}");
        assert_eq!(encoded, message.plain, "{at}");
        // One message has a finding: the next test is about it.
        let fields: Vec<_> = findings.iter().map(|finding| finding.field).collect();
        match message.name == "5GMMSecurityModeComplete" {
            true => assert_eq!(fields, ["imeisv"], "{at}"),
            false => assert!(fields.is_empty(), "{at}: {findings:?}"),
        }
    }
}

/// The IMEISV of the SECURITY MODE COMPLETE that PacketRusher sent has 0000
/// in the half octet after its 16 digits, where TS 24.501 §9.11.3.4 has a
/// sender write 1111. The digits are read, since an IMEISV has no other
/// number of them, and `validate()` reports the IE.
#[test]
fn an_imeisv_with_zeros_after_its_digits_is_read_and_reported() {
    let all = captured();
    let complete = (all.iter())
        .find(|message| message.name == "5GMMSecurityModeComplete")
        .unwrap();
    assert!(complete.sender.starts_with("PacketRusher"));
    let decoded = f::Nas5gsMessage::decode(&complete.plain).unwrap();
    let f::Nas5gsMessage::Gmm(_, f::Nas5gmmMessage::SecurityModeComplete(body)) = &decoded else {
        panic!("{decoded:?}");
    };
    let imeisv = body.imeisv.as_ref().unwrap();
    assert_eq!(hex::encode(&imeisv.value), "151100000000000000");
    assert_eq!(imeisv.as_imeisv().as_deref(), Some("1110000000000000"));
    assert!(!imeisv.is_well_formed());
    // As a sender writes the same digits
    let written = f::NasFGsMobileIdentity::from_imeisv("1110000000000000").unwrap();
    assert_eq!(hex::encode(&written.value), "1511000000000000f0");
    assert!(written.is_well_formed());

    // The same in an IDENTITY RESPONSE, where the identity is mandatory:
    // the message is read, and reported
    let response = hex::decode("7e005c0009151100000000000000").unwrap();
    let decoded = f::Nas5gsMessage::decode(&response).unwrap();
    let fields: Vec<_> = decoded
        .validate()
        .iter()
        .map(|finding| finding.field)
        .collect();
    assert_eq!(fields, ["mobile_identity"]);
    // and in EPS, whose IMEISV has the type 3
    let identity = e::NasMobileIdentity::new(hex::decode("131100000000000000").unwrap());
    assert_eq!(identity.as_imeisv().as_deref(), Some("1110000000000000"));
    assert!(!identity.is_well_formed());

    // A digit that is no digit is still refused, and so is an IMSI whose
    // odd/even bit does not agree with its digits: nothing else says how
    // many it has.
    let identity = e::NasMobileIdentity::new(hex::decode("13110000000000a000").unwrap());
    assert_eq!(identity.as_imeisv(), None);
    let imsi = e::NasMobileIdentity::new(hex::decode("21436500").unwrap());
    assert_eq!(imsi.as_imsi(), None);
}

/// With the keys and the NAS COUNT of its line, a context of the crate
/// verifies each protected message as it was on the wire and deciphers it
/// to the plain message of the line; and it writes the same octets when it
/// protects that plain message with that COUNT.
#[cfg(feature = "security")]
#[test]
fn each_protected_captured_message_is_verified_and_deciphered_with_its_keys() {
    let mut protected = 0;
    for message in captured() {
        let (Some(count), Some((integrity, ciphering))) = (message.count, message.keys) else {
            assert_eq!(message.wire, message.plain, "line {}", message.line);
            continue;
        };
        protected += 1;
        let at = format!("line {} ({})", message.line, message.name);
        if message.system == "5gs" {
            use f::{CipheringAlgorithm, IntegrityAlgorithm, KNasEnc, KNasInt, NasSecurityContext};
            let direction = match message.downlink {
                true => f::Direction::Downlink,
                false => f::Direction::Uplink,
            };
            let context = || {
                NasSecurityContext::from_fresh_keys(
                    &KNasInt::new(&integrity),
                    &KNasEnc::new(&ciphering),
                    IntegrityAlgorithm::NIA2,
                    CipheringAlgorithm::NEA2,
                )
                .unwrap()
            };
            let verified = context()
                .unprotect(&message.wire, direction)
                .unwrap_or_else(|error| panic!("{at}: {error}"));
            assert_eq!(u32::from(verified.count), count, "{at}");
            assert_eq!(
                verified.security_header_type as u8, message.security_header_type,
                "{at}"
            );
            let plain = f::Nas5gsMessage::decode(&message.plain).unwrap();
            assert_eq!(
                verified.sent.as_ref().unwrap_or(&verified.message),
                &plain,
                "{at}"
            );
        } else {
            use e::{CipheringAlgorithm, IntegrityAlgorithm, KNasEnc, KNasInt, NasSecurityContext};
            let mut context = NasSecurityContext::from_fresh_keys(
                &KNasInt::new(&integrity),
                &KNasEnc::new(&ciphering),
                IntegrityAlgorithm::EIA2,
                CipheringAlgorithm::EEA2,
            )
            .unwrap();
            let verified = context
                .unprotect(&message.wire, e::Direction::Downlink)
                .unwrap_or_else(|error| panic!("{at}: {error}"));
            assert_eq!(u32::from(verified.count), count, "{at}");
            assert_eq!(
                verified.security_header_type as u8, message.security_header_type,
                "{at}"
            );
            let plain =
                e::NasEpsMessage::decode_with_direction(&message.plain, e::Direction::Downlink);
            assert_eq!(verified.message, plain.unwrap(), "{at}");
        }
    }
    // 81 of 5GS and 33 of EPS
    assert_eq!(protected, 114);
}
