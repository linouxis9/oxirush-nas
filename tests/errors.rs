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
