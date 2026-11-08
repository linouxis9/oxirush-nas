//! `Debug` prints no octet of a key, as `Display` prints none. Of RES and RES\*, the
//! ciphering keys of the positioning SIBs, the MSK of an MBS session and K_NR_ProSe it
//! shows the length, and so does it of the octets of an IE that holds one. Of an EAP
//! message it shows the header, without the attributes, where an EAP-AKA' response
//! has RES. A tree is the data of a message, and has the keys.

use oxirush_nas::nas_5gs::*;
use oxirush_nas::nas_eps;

/// A key of which every octet is `5a`, and one of which every octet is `a5`.
const KEY: [u8; 16] = [0x5a; 16];
const RES: [u8; 16] = [0xa5; 16];

/// What `Debug` printed has no four octets of either key in hexadecimal, in either
/// case, nor as numbers.
fn has_no_key(printed: &str) -> bool {
    let lower = printed.to_ascii_lowercase();
    !["5a5a5a5a", "a5a5a5a5", "90, 90, 90", "165, 165, 165"]
        .iter()
        .any(|key| lower.contains(key))
}

#[test]
fn debug_of_a_5gs_authentication_response_shows_the_length_of_res_star_and_no_eap_attribute()
-> Result<(), Box<dyn std::error::Error>> {
    // AUTHENTICATION RESPONSE with RES*, and an EAP-AKA' Response/AKA'-Challenge whose
    // AT_RES holds a RES of 8 octets (RFC 4187 §10.8, RFC 5448 §3)
    let eap = hex::decode("020100143201000003030040a5a5a5a5a5a5a5a5")?;
    let octets = [
        &hex::decode("7e00572d10")?[..],
        &RES,
        &[0x78, 0x00, 0x14],
        &eap,
    ]
    .concat();
    let message = Message::decode(&octets)?;

    let printed = format!("{message:?}");
    assert!(has_no_key(&printed), "{printed}");
    assert!(
        printed.contains("AuthenticationResponseParameter { value: hidden (16 octets) }"),
        "{printed}"
    );
    assert!(
        printed.contains(
            "EapMessage { code: Response, identifier: 1, type: 50, subtype: 1, length: 20, .. }"
        ),
        "{printed}"
    );
    let printed = message.to_string();
    assert!(has_no_key(&printed), "{printed}");
    assert_eq!(
        printed,
        "5GMM AuthenticationResponse (RES*=hidden (16 octets), EAP=Response)"
    );

    // The message keeps the octets, which encode back
    assert_eq!(message.encode()?, octets);
    let Message::Gmm(_, GmmMessage::AuthenticationResponse(response)) = &message else {
        unreachable!()
    };
    let parameter = response.authentication_response_parameter.as_ref();
    assert_eq!(
        parameter.and_then(|parameter| parameter.res_star()),
        Some(&RES)
    );
    Ok(())
}

#[test]
fn debug_of_an_eps_authentication_response_shows_the_length_of_res()
-> Result<(), Box<dyn std::error::Error>> {
    let octets = [&hex::decode("075308")?[..], &RES[..8]].concat();
    let message = nas_eps::Message::decode(&octets)?;
    let printed = format!("{message:?}");
    assert!(has_no_key(&printed), "{printed}");
    assert!(
        printed.contains("AuthenticationResponseParameter { value: hidden (8 octets) }"),
        "{printed}"
    );
    assert!(has_no_key(&message.to_string()), "{message}");
    Ok(())
}

#[test]
fn debug_of_the_ciphering_keys_of_positioning_shows_their_length()
-> Result<(), Box<dyn std::error::Error>> {
    // 5GS: a set of a REGISTRATION ACCEPT
    let set = CipheringDataSet::new(
        1,
        KEY,
        vec![],
        vec![0x80],
        vec![0x80],
        [0x26, 0x01, 0x42, 0x01, 0x00],
        60,
        vec![],
    );
    let printed = format!("{set:?}");
    assert!(has_no_key(&printed), "{printed}");
    assert!(
        printed.contains("ciphering_key: hidden (16 octets)"),
        "{printed}"
    );
    let data = CipheringKeyData::from_data_sets(&[set])?;
    let result = RegistrationResult::from_result(RegistrationResultValue::ThreeGppAccess);
    let accept = Message::new_5gmm(RegistrationAccept::new(result).with_ciphering_key_data(data));
    let octets = accept.encode()?;
    assert!(hex::encode(&octets).contains(&"5a".repeat(16)));
    let printed = format!("{:?}", Message::decode(&octets)?);
    assert!(has_no_key(&printed), "{printed}");
    assert!(
        printed.contains("CipheringKeyData { value: hidden ("),
        "{printed}"
    );

    // EPS: a set of a TRACKING AREA UPDATE ACCEPT
    let set = nas_eps::CipheringDataSet::new(
        1,
        KEY,
        vec![0x01],
        [0x80, 0, 0, 0],
        [0x26, 0x01, 0x42, 0x01, 0x00],
        60,
        vec![],
    );
    let printed = format!("{set:?}");
    assert!(has_no_key(&printed), "{printed}");
    assert!(
        printed.contains("ciphering_key: hidden (16 octets)"),
        "{printed}"
    );
    let data = nas_eps::CipheringKeyData::from_data_sets(&[set])?;
    let accept = nas_eps::TrackingAreaUpdateAccept::new(nas_eps::EpsUpdateResult::new(0))
        .with_ciphering_key_data(data);
    let octets = nas_eps::Message::new_emm(accept).encode()?;
    assert!(hex::encode(&octets).contains(&"5a".repeat(16)));
    let printed = format!("{:?}", nas_eps::Message::decode(&octets)?);
    assert!(has_no_key(&printed), "{printed}");
    assert!(
        printed.contains("CipheringKeyData { value: hidden ("),
        "{printed}"
    );
    Ok(())
}

#[test]
fn debug_of_an_msk_and_of_k_nr_prose_shows_their_length() {
    let keys = MbsSecurityKeySet::new([1, 2, 3], [0, 0, 0, 1], KEY, Some([0, 1]), Some(RES));
    let printed = format!("{keys:?}");
    assert!(printed.contains("msk: hidden (16 octets)"), "{printed}");
    assert!(!printed.contains("90, 90, 90"), "{printed}");
    assert_eq!(
        format!("{:?}", ReceivedMbsContainer::new(KEY.to_vec())),
        "ReceivedMbsContainer { value: hidden (16 octets) }"
    );

    let parameters = RelayKeyResponseParametersValue::new([0x5a; 32], [0x11; 16], vec![0x22; 4]);
    let printed = format!("{parameters:?}");
    assert!(has_no_key(&printed), "{printed}");
    assert!(
        printed.contains("key_knr_prose: hidden (32 octets)"),
        "{printed}"
    );
    let parameters = RelayKeyResponseParameters::new([0x5a; 52].to_vec());
    assert_eq!(
        format!("{parameters:?}"),
        "RelayKeyResponseParameters { value: hidden (52 octets) }"
    );
}

#[test]
fn debug_of_an_eap_message_is_its_header() {
    // EAP-Success, and a packet too short for a header
    let success = EapMessage::new(vec![0x03, 0x07, 0x00, 0x04]);
    assert_eq!(
        format!("{success:?}"),
        "EapMessage { code: Success, identifier: 7, length: 4, .. }"
    );
    let short = EapMessage::new(vec![0x09]);
    assert_eq!(
        format!("{short:?}"),
        "EapMessage { code: 9, length: 1, .. }"
    );
}

#[test]
fn debug_of_an_ie_kept_unread_shows_its_length() -> Result<(), Box<dyn std::error::Error>> {
    // AUTHENTICATION RESPONSE whose RES* has 15 octets: the decoder keeps the IE
    // unread, with the octets it came with
    let octets = [&hex::decode("7e00572d0f")?[..], &RES[..15]].concat();
    let message = Message::decode(&octets)?;
    assert_eq!(
        message
            .unknown_ies()
            .iter()
            .map(|ie| ie.data.len())
            .sum::<usize>(),
        16
    );
    let printed = format!("{message:?}");
    assert!(has_no_key(&printed), "{printed}");
    assert!(
        printed.contains("UnknownIe { iei: 0x2d, data: 16 octets }"),
        "{printed}"
    );
    assert_eq!(message.encode()?, octets);
    Ok(())
}
