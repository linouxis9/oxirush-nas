//! The 5GS mobile identity (TS 24.501 §9.11.3.4): no identity, a 5G-GUTI, a
//! 5G-S-TMSI, an IMEI, an IMEISV, a MAC address with its MAURI bit, and an EUI-64,
//! each of its type and its length; a receiver says why it does not read one.

use oxirush_nas::nas_5gs::{Nas5gsMessage, NasFGsMobileIdentity as Identity};

/// `text` with its spaces taken out, as octets.
fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// The IDENTITY RESPONSE whose mobile identity is `value`.
fn identity_response(value: &[u8]) -> Vec<u8> {
    let mut message = vec![0x7e, 0x00, 0x5c];
    message.extend_from_slice(&(value.len() as u16).to_be_bytes());
    message.extend_from_slice(value);
    message
}

#[test]
fn no_identity_is_its_one_octet() {
    assert!(Identity::from_no_identity().is_well_formed());
    assert!(!Identity::new(vec![0x00, 0x00]).is_well_formed());
}

#[test]
fn a_5g_guti_has_its_plmn_and_its_5g_tmsi() {
    let guti = Identity::new(octets("f2 02f839 ca fe00 11223344"));
    assert_eq!(guti.tmsi(), Some(0x1122_3344));
    assert_eq!(
        guti.plmn().map(|plmn| plmn.to_string()),
        Some("208-93".into())
    );
    // Of another type than a MAC address, it has no MAC address nor MAURI bit
    assert_eq!(guti.as_mac_address(), None);
    assert_eq!(guti.mauri(), None);
    assert!(guti.clone().with_mauri(true).is_err());
}

#[test]
fn a_mac_address_has_six_octets_and_its_mauri_bit() {
    let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    // Bit 4 of the first octet is MAURI, bits 8 to 5 are spare
    let identity = Identity::from_mac_address_with_mauri(mac, true);
    assert_eq!(identity.value, octets("0e aabbccddeeff"));
    assert_eq!(identity.as_mac_address(), Some(mac));
    assert_eq!(identity.mauri(), Some(true));
    assert!(identity.is_well_formed());
    assert!(Identity::from_mac_address(mac).is_well_formed());
    assert!(!Identity::new(octets("16 aabbccddeeff")).is_well_formed());
    assert!(!Identity::new(octets("06 aabbccddeeff00")).is_well_formed());
    // Three octets are no MAC address
    assert_eq!(Identity::new(octets("06 aabb")).as_mac_address(), None);
}

#[test]
fn an_eui_64_has_eight_octets() {
    let id = [1, 2, 3, 4, 5, 6, 7, 8];
    let identity = Identity::from_eui64(id);
    assert_eq!(identity.value, octets("07 0102030405060708"));
    assert_eq!(identity.as_eui64(), Some(id));
    assert!(identity.is_well_formed());
    assert!(!Identity::new(octets("17 0102030405060708")).is_well_formed());
    assert!(!Identity::new(octets("07 010203040506070809")).is_well_formed());
    // A SUCI, whose type is 001, is none
    let suci = Identity::new(octets("01 02f839 f0ff 00 00 0000000001"));
    assert_eq!(suci.as_eui64(), None);
}

#[test]
fn a_receiver_reads_a_mac_address_and_an_eui_64() {
    for value in [octets("0e aabbccddeeff"), octets("07 0102030405060708")] {
        let message = Nas5gsMessage::decode(&identity_response(&value));
        assert!(message.is_ok(), "{value:02x?}: {message:?}");
    }
}

#[test]
fn a_receiver_says_why_an_identity_is_not_one_of_its_type() {
    for (value, reason) in [
        ("f4 0102", "`5g-s-tmsi` has 3 octets, and must have 7"),
        ("4b 09", "`imei` has 3 digits, and must have 15"),
        ("45 09", "`imeisv` has 2 digits, and must have 16"),
        (
            "06 aabb",
            "`mac-address` has 3 octets, and must have 7 at least",
        ),
    ] {
        let error = Nas5gsMessage::decode(&identity_response(&octets(value))).unwrap_err();
        assert!(error.to_string().contains(reason), "{value}: {error}");
    }
}
