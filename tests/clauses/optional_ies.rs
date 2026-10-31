//! A receiver treats an optional IE whose value is syntactically incorrect as not
//! present (TS 24.501 §7.7.3.1), and takes one whose value is of its clause.

use oxirush_nas::nas_5gs::{
    Nas5gmmMessage as Gmm, Nas5gsMessage as Message, Nas5gsmMessage as Gsm,
    NasPduSessionEstablishmentRequest, NasRegistrationAccept, NasRegistrationRequest,
    NasUlNasTransport,
};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// The message of `base` followed by the optional IE `ie`.
fn decode(base: &str, ie: &str) -> Message {
    Message::decode(&octets(&format!("{base} {ie}"))).unwrap()
}

/// A REGISTRATION REQUEST for an initial registration of a SUCI, and `ie`.
fn registration_request(ie: &str) -> Box<NasRegistrationRequest> {
    let base = "7e0041 01 000d 0102f8390000000021436587f9";
    let Message::Gmm(_, Gmm::RegistrationRequest(message)) = decode(base, ie) else {
        unreachable!()
    };
    message
}

/// A REGISTRATION ACCEPT of 3GPP access, and `ie`.
fn registration_accept(ie: &str) -> Box<NasRegistrationAccept> {
    let Message::Gmm(_, Gmm::RegistrationAccept(message)) = decode("7e0042 0101", ie) else {
        unreachable!()
    };
    message
}

/// An UL NAS TRANSPORT of a PDU SESSION ESTABLISHMENT REQUEST of PDU session 1,
/// and `ie`.
fn ul_nas_transport(ie: &str) -> Box<NasUlNasTransport> {
    let base = "7e0067 01 0008 2e0101c1ffff91a1 1201";
    let Message::Gmm(_, Gmm::UlNasTransport(message)) = decode(base, ie) else {
        unreachable!()
    };
    message
}

/// A PDU SESSION ESTABLISHMENT REQUEST, and `ie`.
fn establishment_request(ie: &str) -> Box<NasPduSessionEstablishmentRequest> {
    let Message::Gsm(_, Gsm::PduSessionEstablishmentRequest(message)) = decode("2e0101c1 ffff", ie)
    else {
        unreachable!()
    };
    message
}

#[test]
fn an_nssai_is_s_nssais_of_their_length() {
    // Allowed NSSAI (§9.11.3.37): an S-NSSAI of one octet, then one of two octets
    // of which one is there
    assert!(registration_accept("15 02 0101").allowed_nssai.is_some());
    assert!(registration_accept("15 02 0201").allowed_nssai.is_none());
    // Rejected NSSAI (§9.11.3.46): the length of the S-NSSAI in bits 8 to 5, the
    // cause in bits 4 to 1
    assert!(registration_accept("11 02 1001").rejected_nssai.is_some());
    assert!(registration_accept("11 02 2001").rejected_nssai.is_none());
    // S-NSSAI (§9.11.2.8): an SST, with an SD, mapped values, of 1, 2, 4, 5 or 8
    // octets
    assert!(ul_nas_transport("22 01 01").s_nssai.is_some());
    assert!(ul_nas_transport("22 03 010000").s_nssai.is_none());
}

#[test]
fn access_category_definitions_are_definitions_of_their_criteria() {
    // §9.11.3.38: a criterion of one S-NSSAI of an SST, then one of an SST and a
    // mapped SST, which a criterion does not have
    let valid = "76 0008 07 01 02 04 02 01 01 01";
    let invalid = "76 0009 08 01 02 05 02 01 02 0102";
    let field = |ie| registration_accept(ie).operator_defined_access_category_definitions;
    assert!(field(valid).is_some());
    assert!(field(invalid).is_none());
}

#[test]
fn an_ladn_indication_is_dnns_or_nothing() {
    // §9.11.3.29: no DNN, a DNN of its labels, and a length beyond the value
    assert!(registration_request("74 0000").ladn_indication.is_some());
    let internet = "74 000a 09 08696e7465726e6574";
    assert!(registration_request(internet).ladn_indication.is_some());
    assert!(
        registration_request("74 0002 0501")
            .ladn_indication
            .is_none()
    );
}

#[test]
fn a_maximum_number_of_packet_filters_is_17_to_1024() {
    // §9.11.4.9: 11 bits, 64 then 16
    let field = |ie| establishment_request(ie).maximum_number_of_supported_packet_filters;
    assert!(field("55 0800").is_some());
    assert!(field("55 0200").is_none());
    // UE-DS-TT residence time (§9.11.4.26): 8 octets
    let residence = establishment_request("6f 08 0000000000000001");
    assert!(residence.ue_ds_tt_residence_time.is_some());
}
