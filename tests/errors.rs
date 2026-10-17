//! What an error says to someone who has the octets and not the
//! specification open.
use oxirush_nas::common::{Decode, IeFault, NasError};
use oxirush_nas::{nas_5gs as f, nas_eps as e};

fn text<T: std::fmt::Debug>(result: Result<T, NasError>) -> String {
    result.unwrap_err().to_string()
}

#[test]
fn a_message_of_the_other_system_names_the_decoder_that_reads_it() {
    // REGISTRATION COMPLETE of 5GS, given to the decoder of EPS
    let error = e::NasEpsMessage::decode(&[0x7e, 0x00, 0x43]).unwrap_err();
    assert_eq!(error, NasError::UnknownProtocolDiscriminator(0x7e));
    assert_eq!(
        error.to_string(),
        "unknown protocol discriminator: the first octet is 0x7e, the extended protocol \
         discriminator of a 5GMM message: decode it with `nas_5gs`"
    );

    // PDU SESSION RELEASE COMPLETE of 5GS
    assert_eq!(
        text(e::NasEpsMessage::decode(&[0x2e, 0x05, 0x01, 0xd4])),
        "unknown protocol discriminator: the first octet is 0x2e, the extended protocol \
         discriminator of a 5GSM message: decode it with `nas_5gs`"
    );

    // ATTACH COMPLETE of EPS, plain and in a security header, given to the
    // decoder of 5GS
    for first in [0x07, 0x27] {
        assert_eq!(
            text(f::Nas5gsMessage::decode(&[first, 0x43, 0x00, 0x00])),
            format!(
                "unknown protocol discriminator: the first octet is {first:#04x}, which has the \
                 protocol discriminator of an EMM message: decode it with `nas_eps`"
            )
        );
    }

    // An ESM message, with its EPS bearer identity in the first octet
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[0x52, 0x01, 0xd0, 0x11])),
        "unknown protocol discriminator: the first octet is 0x52, which has the protocol \
         discriminator of an ESM message: decode it with `nas_eps`"
    );

    // Neither
    assert_eq!(
        text(e::NasEpsMessage::decode(&[0x05, 0x41])),
        "unknown protocol discriminator: the first octet is 0x05"
    );
}

#[test]
fn a_mandatory_ie_says_whether_it_is_missing_cut_short_or_wrong() {
    // REGISTRATION REQUEST that ends after its header
    let error = f::Nas5gsMessage::decode(&[0x7e, 0x00, 0x41]).unwrap_err();
    assert_eq!(
        error,
        NasError::InvalidMandatoryIe {
            ie: "fgs_registration_type",
            fault: IeFault::Missing
        }
    );
    assert_eq!(
        error.to_string(),
        "mandatory IE `5gs-registration-type` is missing: the message ends before it"
    );

    // The mobile identity says 13 octets and the message has two of them
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[
            0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x99
        ])),
        "mandatory IE `5gs-mobile-identity` is cut short: the message ends inside it"
    );

    // AUTHENTICATION RESPONSE of EPS whose parameter has three octets:
    // Table 8.2.8.1 has four or more
    assert_eq!(
        text(e::NasEpsMessage::decode(&[0x07, 0x53, 0x03, 0, 0, 0])),
        "mandatory IE `authentication-response-parameter` is shorter than its message allows"
    );

    // A 5GS mobile identity whose type of identity is reserved
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[
            0x7e, 0x00, 0x5c, 0x00, 0x01, 0x07
        ])),
        "mandatory IE `mobile-identity` has a value that is syntactically incorrect"
    );

    // An unknown IE that is "comprehension required" (IEI 0x0f), cut short
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[
            0x7e, 0x00, 0x44, 0x16, 0x0f, 0x05, 0xaa
        ])),
        "an unknown IE that is encoded as \"comprehension required\" is cut short"
    );
}

#[test]
fn the_other_errors_say_what_was_read() {
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[])),
        "the message is too short: it ends inside its header"
    );
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[0x7e, 0x00, 0x01])),
        "unknown message type 0x01"
    );
    // An IE alone: a cause is one octet
    assert_eq!(
        text(f::NasFGmmCause::decode(&[0x16, 0x00])),
        "cannot decode: 1 octet after the end"
    );
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[0x7e, 0x05, 0x43])),
        "reserved security header type 5"
    );
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[0x2e, 0x05, 0x01, 0x01])),
        "unknown session management message type 0x01 (identity 5, PTI 1)"
    );
    assert_eq!(
        text(f::Nas5gsMessage::decode(&[0x2e, 0x10, 0x01, 0xd4])),
        "reserved PDU session identity 16 (PTI 1, message type 0xd4)"
    );
    // An IE alone: the octets of an NSSAI that says four octets and has two
    assert_eq!(
        text(f::NasNssai::decode(&[0x04, 0x01, 0x01])),
        "the octets end before the value does"
    );
}

/// An error is no larger than a `String` and a tag: the result of every
/// decode carries one.
#[test]
fn an_error_is_four_words() {
    assert!(std::mem::size_of::<NasError>() <= 4 * std::mem::size_of::<usize>());
    // The two that a security context has for what a caller acts on
    let exhausted = NasError::NasCountExhausted;
    assert_eq!(
        exhausted.to_string(),
        "every NAS COUNT of the direction was used with these keys"
    );
    let refused = NasError::AuthenticMessageRefused {
        error: Box::new(NasError::UnknownMessageType(0xff)),
        plain: [0x7e, 0x00, 0xff].into(),
    };
    assert_eq!(
        refused.to_string(),
        "the message is authentic and is refused: unknown message type 0xff"
    );
    let inside = std::error::Error::source(&refused).map(|inside| inside.to_string());
    assert_eq!(inside.as_deref(), Some("unknown message type 0xff"));
}

/// The REGISTRATION REQUEST of the review: its SUCI is a network specific
/// identifier whose realm has one label, `operator`.
const REALM_OF_ONE_LABEL: &str = "7e004179002a1174797065312e7269643637382e7363686964302e7573\
                                  6572696475736572313740\
                                  6f70657261746f72";

/// A mandatory IE that has its octets and is not one of its type refuses
/// the message, and `decode_lenient` gives the message with the refusal:
/// the receiver reads what it rejects (TS 24.501 and TS 24.301 §7.5.1).
#[test]
fn a_message_with_a_faulty_mandatory_ie_is_read_with_its_fault() {
    let octets = hex::decode(REALM_OF_ONE_LABEL).unwrap();
    let fault = NasError::InvalidMandatoryIe {
        ie: "fgs_mobile_identity",
        fault: IeFault::Syntax,
    };
    assert_eq!(f::Nas5gsMessage::decode(&octets).unwrap_err(), fault);
    let (message, faults) = f::Nas5gsMessage::decode_lenient(&octets).unwrap();
    assert_eq!(faults, vec![fault.clone()]);
    // The IEs that are sound, and the octets of the one that is not
    let f::Nas5gsMessage::Gmm(_, f::Nas5gmmMessage::RegistrationRequest(request)) = &message else {
        panic!("{message:?}");
    };
    assert_eq!(request.fgs_registration_type.value, 0x09);
    assert!(request.ngksi.no_key_available());
    assert_eq!(
        hex::encode(&request.fgs_mobile_identity.value),
        REALM_OF_ONE_LABEL[12..]
    );
    // The message is the one that was received: it encodes to its octets
    assert_eq!(message.encode().unwrap(), octets);

    // Through `Decode`, for a message struct alone
    let mut faults = Vec::new();
    let mut body = &octets[3..];
    let request = f::NasRegistrationRequest::decode_lenient_from(&mut body, &mut faults).unwrap();
    assert_eq!((faults, body.len()), (vec![fault.clone()], 0));
    assert_eq!(request.fgs_registration_type.value, 0x09);

    // Under a security header, as an AMF receives it after `unprotect`
    let protected = [&[0x7e, 0x01, 1, 2, 3, 4, 0][..], &octets].concat();
    assert_eq!(f::Nas5gsMessage::decode(&protected).unwrap_err(), fault);
    let (message, faults) = f::Nas5gsMessage::decode_lenient(&protected).unwrap();
    assert_eq!(faults, [fault]);
    assert_eq!(message.encode().unwrap(), protected);
}

/// A message that `decode` reads has no fault, and is that message; what
/// has no message to give is the error of `decode`.
#[test]
fn a_lenient_decode_is_the_decode_of_a_sound_message_and_its_errors() {
    for line in include_str!("fixtures/nas-5gs.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let octets = hex::decode(hex).unwrap();
        let (message, faults) = f::Nas5gsMessage::decode_lenient(&octets).unwrap();
        assert_eq!(faults, [], "{name}");
        assert_eq!(
            message,
            f::Nas5gsMessage::decode(&octets).unwrap(),
            "{name}"
        );
    }
    for line in include_str!("fixtures/nas-eps.tsv")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let (name, hex) = line.split_once('\t').unwrap();
        let octets = hex::decode(hex).unwrap();
        let direction = match name.starts_with("DetachRequestUeTerminated") {
            true => e::Direction::Downlink,
            false => e::Direction::Uplink,
        };
        let (message, faults) =
            e::NasEpsMessage::decode_lenient_with_direction(&octets, direction).unwrap();
        assert_eq!(faults, [], "{name}");
        let strict = e::NasEpsMessage::decode_with_direction(&octets, direction).unwrap();
        assert_eq!(message, strict, "{name}");
    }

    // A mandatory IE that is missing or cut short leaves no message
    for octets in [
        &[0x7e, 0x00, 0x41][..],
        &[0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x99],
        &[],
        &[0x7e, 0x00, 0x01],
        // REGISTRATION COMPLETE and an octet after it... which is an IE that is cut short
        &[0x7e, 0x05, 0x43],
    ] {
        assert_eq!(
            f::Nas5gsMessage::decode_lenient(octets).unwrap_err(),
            f::Nas5gsMessage::decode(octets).unwrap_err(),
            "{octets:02x?}"
        );
    }
    for octets in [&[0x07, 0x41][..], &[0x07, 0x53, 0x03, 0, 0], &[0x05, 0x41]] {
        assert_eq!(
            e::NasEpsMessage::decode_lenient(octets).unwrap_err(),
            e::NasEpsMessage::decode(octets).unwrap_err(),
            "{octets:02x?}"
        );
    }
}

/// Each mandatory IE that is refused is in the list, in the order of the
/// message, with the reason that `decode` gives the first of them.
#[test]
fn each_faulty_mandatory_ie_is_listed() {
    // AUTHENTICATION RESPONSE of EPS whose parameter has three octets:
    // Table 8.2.8.1 has four or more
    let octets = [0x07, 0x53, 0x03, 1, 2, 3];
    let short = NasError::InvalidMandatoryIe {
        ie: "authentication_response_parameter",
        fault: IeFault::TooShort,
    };
    assert_eq!(e::NasEpsMessage::decode(&octets).unwrap_err(), short);
    let (message, faults) = e::NasEpsMessage::decode_lenient(&octets).unwrap();
    assert_eq!(faults, [short]);
    let e::NasEpsMessage::Emm(_, e::NasEmmMessage::AuthenticationResponse(response)) = &message
    else {
        panic!("{message:?}");
    };
    assert_eq!(
        response.authentication_response_parameter.value[..],
        [1, 2, 3]
    );
    assert_eq!(message.encode().unwrap(), octets);

    // IDENTITY RESPONSE of 5GS whose identity has a reserved type
    let octets = [0x7e, 0x00, 0x5c, 0x00, 0x01, 0x07];
    let (message, faults) = f::Nas5gsMessage::decode_lenient(&octets).unwrap();
    assert_eq!(
        faults,
        [NasError::InvalidMandatoryIe {
            ie: "mobile_identity",
            fault: IeFault::Syntax
        }]
    );
    assert_eq!(message.encode().unwrap(), octets);

    // DETACH REQUEST of EPS from the network, whose direction the caller
    // says: its detach type is reserved
    let octets = [0x07, 0x45, 0x07];
    let strict = e::NasEpsMessage::decode_with_direction(&octets, e::Direction::Downlink);
    let lenient = e::NasEpsMessage::decode_lenient_with_direction(&octets, e::Direction::Downlink);
    match strict {
        // The type is one that a receiver takes: nothing to list
        Ok(message) => assert_eq!(lenient.unwrap(), (message, vec![])),
        Err(fault) => {
            let (message, faults) = lenient.unwrap();
            assert_eq!(faults, [fault]);
            assert_eq!(message.encode().unwrap(), octets);
        }
    }
}

/// The answer of clause 7 to octets that `decode` refuses, for each of its
/// rows, by the octets of the answer.
#[test]
fn a_refused_message_has_the_answer_of_clause_7() {
    use e::Direction::{Downlink, Uplink};
    let fgs = |octets: &[u8], direction| {
        let error = f::Nas5gsMessage::decode(octets).unwrap_err();
        let answer = f::Nas5gsMessage::answer_to_refused(octets, &error, direction);
        answer.map(|answer| hex::encode(answer.encode().unwrap()))
    };
    let answered = |answer: &str| Some(answer.to_owned());
    // §7.2.1: too short to have a message type
    assert_eq!(fgs(&[0x7e, 0x00], Uplink), None);
    // §7.4: 5GMM STATUS and 5GSM STATUS, cause #97
    assert_eq!(fgs(&[0x7e, 0x00, 0x01], Uplink), answered("7e006461"));
    assert_eq!(
        fgs(&[0x2e, 0x05, 0x01, 0x01], Downlink),
        answered("2e0501d661")
    );
    // §7.5.1: 5GMM STATUS, cause #96, for a REGISTRATION REQUEST that ends
    // after its header and for one whose identity is cut short
    assert_eq!(fgs(&[0x7e, 0x00, 0x41], Uplink), answered("7e006460"));
    let cut = [0x7e, 0x00, 0x41, 0x79, 0x00, 0x0d, 0x01, 0x99];
    assert_eq!(fgs(&cut, Uplink), answered("7e006460"));
    // §7.5.3, to a network: the reject of the three requests
    for (request, reject) in [(0xc1, "c3"), (0xc9, "ca"), (0xd1, "d2")] {
        let octets = [0x2e, 0x05, 0x01, request, 0x59];
        match f::Nas5gsMessage::decode(&octets) {
            // A request without a mandatory IE decodes: nothing to answer
            Ok(_) => continue,
            Err(_) => assert_eq!(
                fgs(&octets, Uplink),
                answered(&format!("2e0501{reject}60")),
                "{request:#x}"
            ),
        }
    }
    assert_eq!(
        fgs(&[0x2e, 0x05, 0x01, 0xc1], Uplink),
        answered("2e0501c360")
    );
    // to a UE: PDU SESSION RELEASE REQUEST for an ESTABLISHMENT ACCEPT, and
    // 5GSM STATUS for a message that §7.5.3 does not name
    assert_eq!(
        fgs(&[0x2e, 0x05, 0x01, 0xc2], Downlink),
        answered("2e0501d15960")
    );
    assert_eq!(
        fgs(&[0x2e, 0x05, 0x01, 0xc3], Downlink),
        answered("2e0501d660")
    );
    // §7.3.2: a reserved PDU session identity, from a UE and to a UE
    assert_eq!(
        fgs(&[0x2e, 0x10, 0x01, 0xc9], Uplink),
        answered("2e1001ca2b")
    );
    assert_eq!(
        fgs(&[0x2e, 0x10, 0x01, 0xd1], Uplink),
        answered("2e1001d22b")
    );
    assert_eq!(fgs(&[0x2e, 0x10, 0x01, 0xc1], Uplink), None);
    assert_eq!(fgs(&[0x2e, 0x10, 0x01, 0xc9], Downlink), None);
    // An error that is not of received octets has no answer
    let exhausted = NasError::NasCountExhausted;
    assert!(f::Nas5gsMessage::answer_to_refused(&[0x7e, 0x00, 0x43], &exhausted, Uplink).is_none());
    // Under an integrity header, and for the refusal of an authentic message
    let protected = [0x7e, 0x01, 1, 2, 3, 4, 0, 0x7e, 0x00, 0x41];
    assert_eq!(fgs(&protected, Uplink), answered("7e006460"));
    let refused = NasError::AuthenticMessageRefused {
        error: Box::new(NasError::UnknownMessageType(1)),
        plain: [0x7e, 0x00, 0x01].into(),
    };
    let answer = f::Nas5gsMessage::answer_to_refused(&protected, &refused, Uplink);
    assert_eq!(answer.unwrap().encode().unwrap(), [0x7e, 0x00, 0x64, 0x61]);

    let eps = |octets: &[u8], direction| {
        let error = e::NasEpsMessage::decode_with_direction(octets, direction).unwrap_err();
        let answer = e::NasEpsMessage::answer_to_refused(octets, &error, direction);
        answer.map(|answer| hex::encode(answer.encode().unwrap()))
    };
    // EMM STATUS with #97 and with #96, ESM STATUS with #97
    assert_eq!(eps(&[0x07, 0x01], Uplink), answered("076061"));
    assert_eq!(eps(&[0x07, 0x41], Uplink), answered("076060"));
    assert_eq!(eps(&[0x52, 0x01, 0x01], Downlink), answered("5201e861"));
    // §7.5.3, to a network: PDN CONNECTIVITY REJECT; to a UE: the reject of
    // an ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST and the accept of a
    // DEACTIVATE EPS BEARER CONTEXT REQUEST
    assert_eq!(eps(&[0x02, 0x01, 0xd0], Uplink), answered("0201d160"));
    assert_eq!(eps(&[0x52, 0x01, 0xc1], Downlink), answered("5201c360"));
    assert_eq!(eps(&[0x52, 0x01, 0xcd], Downlink), answered("5201ce"));
    assert_eq!(eps(&[0x07], Uplink), None);
}

/// A finding of `validate()` on an IE says the sender rule that the IE
/// breaks, where it said that the IE had an invalid value or structure.
#[test]
fn a_finding_on_an_ie_says_the_rule_that_it_breaks() {
    use oxirush_nas::Validate;
    let rule = |findings: Vec<oxirush_nas::ValidationError>, field: &str| {
        let finding = findings.into_iter().find(|finding| finding.field == field);
        finding.map(|finding| finding.message).unwrap_or_default()
    };
    // REGISTRATION REQUEST with a 5G-GUTI whose spare bits are 0000, which
    // a receiver reads and a sender sets to 1111
    let request = f::Nas5gsMessage::decode(
        &hex::decode("7e004179000b0202f839cafe00112233442e02a020").unwrap(),
    )
    .unwrap();
    let message = rule(request.validate(), "fgs_mobile_identity");
    assert!(
        message.starts_with(
            "IE breaks a sender rule: an identity of its type as TS 24.501 §9.11.3.4 writes it"
        ),
        "{message}"
    );
    // ATTACH REQUEST with a DRX parameter whose split PG cycle code is 99
    let attach = e::NasEpsMessage::decode_with_direction(
        &hex::decode("07410108298039000000001002e0e000040201d0315c6300").unwrap(),
        oxirush_nas::common::Direction::Uplink,
    )
    .unwrap();
    let message = rule(attach.validate(), "drx_parameter");
    assert_eq!(
        message,
        "IE breaks a sender rule: two octets: a split PG cycle code of at most 98, and an S1 \
         mode DRX value of 0 or 6 to 9 (TS 24.008 §10.5.5.6)"
    );
}

/// One call answers a received message whatever was wrong with it: an
/// error of decode, or an unknown IE encoded as "comprehension required"
/// in a message that decoded (TS 24.501 and TS 24.301 §7.6.1, TS 24.007
/// §11.2.5), which has the answer of a faulty mandatory IE.
#[test]
fn a_received_message_is_answered_whatever_was_wrong() {
    use oxirush_nas::common::Direction::{Downlink, Uplink};
    let fgs = |octets: &str, direction| {
        let octets = hex::decode(octets).unwrap();
        let received = f::Nas5gsMessage::decode(&octets);
        let answer = f::Nas5gsMessage::answer_to(&octets, &received, direction);
        answer.map(|answer| hex::encode(answer.encode().unwrap()))
    };
    // REGISTRATION COMPLETE with an unknown IE 0x03, comprehension required
    assert_eq!(fgs("7e0043030100", Uplink).as_deref(), Some("7e006460"));
    // The same under an integrity header, which decode reads unverified
    assert_eq!(
        fgs("7e01000000000a7e0043030100", Uplink).as_deref(),
        Some("7e006460")
    );
    // PDU SESSION ESTABLISHMENT REQUEST with one: the reject of §7.5.3
    assert_eq!(
        fgs("2e0501c1ffff0f0100", Uplink).as_deref(),
        Some("2e0501c360")
    );
    // An unknown IE that is not marked so is ignored, and a sound message
    // is not answered
    assert_eq!(fgs("7e00436a0100", Uplink), None);
    assert_eq!(fgs("7e0043", Uplink), None);
    // An error has the answer of answer_to_refused
    assert_eq!(fgs("7e0001", Downlink).as_deref(), Some("7e006461"));

    let eps = |octets: &str| {
        let octets = hex::decode(octets).unwrap();
        let received = e::NasEpsMessage::decode_with_direction(&octets, Uplink);
        let answer = e::NasEpsMessage::answer_to(&octets, &received, Uplink);
        answer.map(|answer| hex::encode(answer.encode().unwrap()))
    };
    // ATTACH COMPLETE with an unknown IE 0x05, comprehension required, and
    // one 0x6a that is not
    assert_eq!(eps("074300035201c2050100").as_deref(), Some("076060"));
    assert_eq!(eps("074300035201c26a0100"), None);
    // PDN CONNECTIVITY REQUEST with one: PDN CONNECTIVITY REJECT #96
    assert_eq!(eps("0201d031050100").as_deref(), Some("0201d160"));
    assert_eq!(eps("0701").as_deref(), Some("076061"));
}

/// A message whose code verifies and whose plain message is refused is
/// answered as the plain message would be, ciphered or not (TS 24.501 and
/// TS 24.301 §7.4, §7.5, and §7.5.3 for 5GSM): the refusal has the plain
/// octets, which a receiver logs and answers.
#[cfg(feature = "security")]
#[test]
fn an_authentic_message_that_is_refused_is_answered_from_its_plain_octets() {
    use oxirush_nas::common::Direction::Uplink;
    let (nia, nea) = (f::IntegrityAlgorithm::NIA2, f::CipheringAlgorithm::NEA2);
    let kamf = f::KAmf::new(&[0x11; 32]);
    let fresh = || f::NasSecurityContext::from_fresh_kamf(&kamf, nia, nea).unwrap();
    let (mut ue, mut amf) = (fresh(), fresh());
    for (inner, answer) in [
        // An unknown 5GMM message type: 5GMM STATUS #97
        ("7e0001", "7e006461"),
        // A REGISTRATION REQUEST cut short, an AUTHENTICATION REQUEST
        // without its ABBA: 5GMM STATUS #96
        ("7e00417900030102", "7e006460"),
        ("7e005600", "7e006460"),
        // A PDU SESSION ESTABLISHMENT REQUEST without its integrity
        // protection maximum data rate: the reject with #96 (§7.5.3)
        ("2e0501c1", "2e0501c360"),
    ] {
        for header in [
            f::Nas5gsSecurityHeaderType::IntegrityProtectedAndCiphered,
            f::Nas5gsSecurityHeaderType::IntegrityProtected,
        ] {
            let plain = hex::decode(inner).unwrap();
            let sent = ue
                .protect_opaque_payload(plain.clone(), header, Uplink)
                .unwrap();
            let error = amf.unprotect(&sent, Uplink).unwrap_err();
            let NasError::AuthenticMessageRefused { plain: refused, .. } = &error else {
                panic!("{error:?}");
            };
            assert_eq!(**refused, plain, "{inner} {header:?}");
            let answered = f::Nas5gsMessage::answer_to_refused(&sent, &error, Uplink);
            let answered = answered.map(|answer| hex::encode(answer.encode().unwrap()));
            assert_eq!(answered.as_deref(), Some(answer), "{inner} {header:?}");
        }
    }
    let (eia, eea) = (e::IntegrityAlgorithm::EIA2, e::CipheringAlgorithm::EEA2);
    let kasme = e::KAsme::new(&[0x22; 32]);
    let fresh = || e::NasSecurityContext::from_fresh_kasme(&kasme, eia, eea).unwrap();
    let (mut ue, mut mme) = (fresh(), fresh());
    for (inner, answer) in [
        // An unknown EMM message type: EMM STATUS #97; an ATTACH REQUEST
        // cut short: EMM STATUS #96
        ("0701", "076061"),
        ("07417108", "076060"),
    ] {
        for header in [
            e::NasEpsSecurityHeaderType::IntegrityProtectedAndCiphered,
            e::NasEpsSecurityHeaderType::IntegrityProtected,
        ] {
            let plain = hex::decode(inner).unwrap();
            let sent = ue
                .protect_opaque_payload(plain.clone(), header, Uplink)
                .unwrap();
            let error = mme.unprotect(&sent, Uplink).unwrap_err();
            let NasError::AuthenticMessageRefused { plain: refused, .. } = &error else {
                panic!("{error:?}");
            };
            assert_eq!(**refused, plain, "{inner} {header:?}");
            let answered = e::NasEpsMessage::answer_to_refused(&sent, &error, Uplink);
            let answered = answered.map(|answer| hex::encode(answer.encode().unwrap()));
            assert_eq!(answered.as_deref(), Some(answer), "{inner} {header:?}");
        }
    }
}

/// The typed constructor of a registration result.
#[test]
fn a_registration_result_is_built_from_its_value() {
    let result = f::NasFGsRegistrationResult::from_result(f::RegistrationResult::Non3GppAccess);
    assert_eq!(result.value, [0x02]);
    assert_eq!(
        result.result_value(),
        Some(f::RegistrationResult::Non3GppAccess)
    );
    assert!(result.is_well_formed());
}
