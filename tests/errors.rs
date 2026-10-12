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
    let refused = NasError::AuthenticMessageRefused(Box::new(NasError::UnknownMessageType(0xff)));
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
    assert_eq!(request.fgs_registration_type.value, 0x79);
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
    assert_eq!(request.fgs_registration_type.value, 0x79);

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
        let direction = match name.starts_with("DetachRequestToUe") {
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
