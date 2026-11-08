//! The protocol description (TS 24.501 §9.11.4.39): entries after their length of two
//! octets, each a QRI alone, which deletes the description, or a QRI, the transport
//! protocol in bits 4 to 1 of the next octet with the presence of the RTP header
//! extension in bit 5 and of the RTP payload information list in bit 6, the type and
//! the identifier of the extension, and the list after its length of two octets: a
//! payload format, the number of payload types and the types, of 127 at most.

use oxirush_nas::nas_5gs::{
    ProtocolDescription, ProtocolDescriptionEntry as Entry,
    ProtocolDescriptionRtpHeaderExtensionType as Extension,
    ProtocolDescriptionRtpPayloadFormat as Format,
    ProtocolDescriptionRtpPayloadInformation as Payload,
    ProtocolDescriptionTransportProtocol as Transport,
};

fn description(octets: &str) -> ProtocolDescription {
    ProtocolDescription::new(hex::decode(octets.split_whitespace().collect::<String>()).unwrap())
}

#[test]
fn the_transport_protocol_is_its_four_bits() {
    for (protocol, code) in [
        (Transport::Rtp, 1),
        (Transport::Srtp, 2),
        (Transport::Unknown(5), 5),
    ] {
        assert_eq!(protocol.as_u8(), code);
        assert_eq!(Transport::from_u8(code), protocol);
        let strict = Transport::from_u8_strict(code);
        assert_eq!(strict, (code != 5).then_some(protocol));
    }
    assert_eq!(Extension::PduSetMarking.as_u8(), 1);
    assert_eq!(Extension::Unknown(5).as_u8(), 5);
}

#[test]
fn an_entry_has_what_its_flags_say() {
    let payload = |format, types: &[u8]| Payload::new(format, types.to_vec());
    let entries = vec![
        Entry::Delete { qri: 1 },
        Entry::Description {
            qri: 2,
            transport_protocol: Transport::Srtp,
            rtp_header_extension: Some((Extension::PduSetMarking, 3)),
            rtp_payload_information_list: vec![
                payload(Format::H264Avc, &[96, 127]),
                payload(Format::H265Hevc, &[]),
            ],
        },
        Entry::Description {
            qri: 4,
            transport_protocol: Transport::Rtp,
            rtp_header_extension: Some((Extension::PduSetMarking, 1)),
            rtp_payload_information_list: vec![],
        },
        Entry::Description {
            qri: 5,
            transport_protocol: Transport::Rtp,
            rtp_header_extension: None,
            rtp_payload_information_list: vec![payload(Format::H264Avc, &[100])],
        },
    ];
    let octets = "0001 01  000c 02 32 0103 0006 0102607f 0200  0004 04 11 0101  \
                  0007 05 21 0003 010164";
    let received = description(octets);
    assert_eq!(received.entries(), entries);
    assert!(received.is_well_formed());
    let written = ProtocolDescription::from_entries(&entries).unwrap();
    assert_eq!(written.value, received.value);
}

#[test]
fn an_entry_cut_short_is_not_read() {
    let delete = Entry::Delete { qri: 1 };
    for octets in [
        // An entry longer than the IE, with the RTP header extension
        "0001 01  0009 02 11",
        // An RTP header extension and a list length, cut at the end of the IE
        "0001 01  0002 02 11",
        "0001 01  0002 02 21",
        // A list longer than the IE
        "0001 01  0006 02 21 0009 0101",
    ] {
        let received = description(octets);
        assert_eq!(
            received.entries(),
            std::slice::from_ref(&delete),
            "{octets}"
        );
        assert!(!received.is_well_formed(), "{octets}");
    }
    // A payload information of one octet, and payload types beyond the list: the
    // reader keeps the entry without them, which a sender does not write
    let without = Entry::Description {
        qri: 2,
        transport_protocol: Transport::Rtp,
        rtp_header_extension: None,
        rtp_payload_information_list: vec![],
    };
    for octets in [
        "0001 01  0005 02 21 0001 01",
        "0001 01  0006 02 21 0002 0109",
        // An empty list
        "0001 01  0004 02 21 0000",
    ] {
        let received = description(octets);
        assert_eq!(
            received.entries(),
            [delete.clone(), without.clone()],
            "{octets}"
        );
        assert!(!received.is_well_formed(), "{octets}");
    }
    assert!(!description("").is_well_formed());
}

#[test]
fn a_sender_writes_named_types_and_payload_types_of_127_at_most() {
    let written = |extension, types: Vec<u8>| {
        let entry = Entry::Description {
            qri: 1,
            transport_protocol: Transport::Rtp,
            rtp_header_extension: Some(extension),
            rtp_payload_information_list: vec![Payload::new(Format::H264Avc, types)],
        };
        ProtocolDescription::from_entries(&[entry]).is_ok()
    };
    assert!(written((Extension::PduSetMarking, 1), vec![0, 127]));
    assert!(!written((Extension::PduSetMarking, 0), vec![]));
    assert!(!written((Extension::PduSetMarking, 1), vec![128]));
}
