//! The fields of the 5GS IEs of a few octets that later features added (TS 24.501
//! §9.11.3): each reader takes the bits of its field, each code is read as its table
//! says, and a code that a table leaves to the receiver is read as it says.

use oxirush_nas::nas_5gs::{
    Aun3DeviceSecurityKeyType as KeyType, CiotSmallDataDownlinkDataExpected as Ddx,
    DsTtCorrectionField, EcsAddressType, EcsSpatialValidityType, FeatureAuthMbsraiValue as Mbsrai,
    N3iwfAddress, N3iwfIdentifierType, NasAdditionalInformationRequested, NasAun3DeviceSecurityKey,
    NasAun3Indication, NasEcsAddress, NasEthernetHeaderCompressionConfiguration,
    NasExtendedFGmmCause, NasFeatureAuthorizationIndication as FeatureAuthorization,
    NasLpWusStatus, NasLpWuspsAssistanceInformation as LpWusps, NasN3iwfIdentifier,
    NasNbN1ModeDrxParameters, NasNon3GppAccessPathSwitchingIndication,
    NasNon3GppPathSwitchingInformation, NasNssrgInformation, NasPayloadContainerInformation,
    NasPeipsAssistanceInformation, NasProseRelayTransactionIdentity, NasRelayKeyRequestParameters,
    NasSnpnList, NasTnanInformation, NasTruncatedFGSTmsiConfiguration, NasUeDsTtResidenceTime,
    NasUrspRuleEnforcementReports, PagingRestrictionType, PeipsAssistanceInformationEntry,
    UeParametersUpdateDataSetType,
};

#[test]
fn a_truncated_5g_s_tmsi_configuration_has_two_lengths() {
    // The truncated AMF set ID length in bits 8 to 5, 1 to 10, and the truncated AMF
    // pointer length in bits 4 to 1, 1 to 6; another code is read as the largest
    // (TS 24.501 §9.11.3.70)
    for octet in 0..=u8::MAX {
        let configuration = NasTruncatedFGSTmsiConfiguration::new(vec![octet]);
        let (set_id, pointer) = (octet >> 4, octet & 0x0f);
        let set_id = if (1..=10).contains(&set_id) {
            set_id
        } else {
            10
        };
        let pointer = if (1..=6).contains(&pointer) {
            pointer
        } else {
            6
        };
        assert_eq!(
            configuration.effective_amf_set_id_length(),
            Some(set_id),
            "{octet}"
        );
        assert_eq!(
            configuration.effective_amf_pointer_length(),
            Some(pointer),
            "{octet}"
        );
    }
    // Eight bits at least in both
    let written = NasTruncatedFGSTmsiConfiguration::try_from_lengths(2, 6).unwrap();
    assert_eq!(written.value, [0x26]);
    assert!(written.is_well_formed());
    assert!(NasTruncatedFGSTmsiConfiguration::try_from_lengths(1, 6).is_err());
    assert!(!NasTruncatedFGSTmsiConfiguration::new(vec![0x11]).is_well_formed());
    assert!(!NasTruncatedFGSTmsiConfiguration::new(vec![0x26, 0x00]).is_well_formed());
    let mut pointer = NasTruncatedFGSTmsiConfiguration::new(vec![0xa1]);
    pointer.set_pointer_length(6).unwrap();
    assert_eq!(pointer.value, [0xa6]);
}

#[test]
fn a_residence_time_overflows_at_its_largest_value() {
    // All the octets of the correction field set but the sign bit (§9.11.4.26)
    let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
    assert!(DsTtCorrectionField::from_wire_bytes(overflow).is_overflow());
    assert!(NasUeDsTtResidenceTime::new(overflow.to_vec()).is_overflow());
    for at in 0..8 {
        let mut value = overflow;
        value[at] = 0x00;
        assert!(
            !DsTtCorrectionField::from_wire_bytes(value).is_overflow(),
            "{at}"
        );
        assert!(
            !NasUeDsTtResidenceTime::new(value.to_vec()).is_overflow(),
            "{at}"
        );
    }
    assert!(NasUeDsTtResidenceTime::new(overflow.to_vec()).is_well_formed());
    assert!(!NasUeDsTtResidenceTime::new(overflow[..7].to_vec()).is_well_formed());
}

#[test]
fn the_codes_of_the_later_fields_are_those_of_their_tables() {
    let restrictions = [
        PagingRestrictionType::AllRestricted,
        PagingRestrictionType::AllRestrictedExceptVoice,
        PagingRestrictionType::AllRestrictedExceptSpecifiedPduSessions,
        PagingRestrictionType::AllRestrictedExceptVoiceAndSpecifiedPduSessions,
    ];
    for (code, restriction) in (1..).zip(restrictions) {
        assert_eq!(PagingRestrictionType::from_u8(code), Some(restriction));
    }
    let addresses = [
        (0x00, EcsAddressType::Ipv4),
        (0x01, EcsAddressType::Ipv6),
        (0x02, EcsAddressType::Fqdn),
        (0x0f, EcsAddressType::Unspecified),
    ];
    for (code, address) in addresses {
        assert_eq!(EcsAddressType::from_u8(code), Some(address));
    }
    let validities = [
        EcsSpatialValidityType::None,
        EcsSpatialValidityType::GeographicalServiceArea,
        EcsSpatialValidityType::TrackingArea,
        EcsSpatialValidityType::CountryWide,
    ];
    for (code, validity) in (0..).zip(validities) {
        assert_eq!(EcsSpatialValidityType::from_u8(code), Some(validity));
    }
    // The spatial validity in bits 8 to 5 of the first octet of an ECS address, the
    // type of address in bits 4 to 1
    let address = NasEcsAddress::new(vec![0x21, 10, 0, 0, 1]);
    assert_eq!(
        address.spatial_validity_type(),
        Some(EcsSpatialValidityType::TrackingArea)
    );
    assert_eq!(address.address_type(), Some(EcsAddressType::Ipv6));
    assert_eq!(Mbsrai::from_u8(0), Some(Mbsrai::NoInformation));
    assert_eq!(
        Mbsrai::from_u8(1),
        Some(Mbsrai::NotAuthorizedAsMbsrAllowedAsUe)
    );
    assert_eq!(
        N3iwfIdentifierType::from_u8(2),
        Some(N3iwfIdentifierType::Ipv6)
    );
    assert_eq!(Ddx::from_u8(0), Ddx::NoInformationAvailable);
    assert_eq!(UeParametersUpdateDataSetType::Unknown(9).as_u8(), 9);
    for (code, key) in [
        (0, Some(KeyType::MasterSessionKey)),
        (1, Some(KeyType::KWagfKey)),
        (2, None),
    ] {
        assert_eq!(KeyType::from_u8_strict(code), key, "{code}");
    }
}

#[test]
fn a_flag_or_a_short_field_of_a_later_ie_is_its_bits() {
    for octet in [0x00, 0xfe, 0x01] {
        let set = octet & 0x01 != 0;
        let naps = NasNon3GppAccessPathSwitchingIndication::new(vec![octet]).naps();
        let nsonr = NasNon3GppPathSwitchingInformation::new(vec![octet]).nsonr();
        let aun3reg = NasAun3Indication::new(vec![octet]).aun3reg();
        assert_eq!((naps, nsonr, aun3reg), (set, set, set), "{octet}");
        assert_eq!(NasPayloadContainerInformation::new(octet).pru(), set);
        assert_eq!(NasLpWusStatus::new(octet).lp_wus_disabled(), set);
        let cause = NasExtendedFGmmCause::new(vec![octet]);
        assert_eq!(
            (
                cause.satellite_nr_not_allowed(),
                cause.satellite_nr_allowed()
            ),
            (set, !set)
        );
    }
    // The CID length in bits 2 and 1, and the DRX value of NB-N1 mode in bits 4 to 1
    let compression = NasEthernetHeaderCompressionConfiguration::new(vec![0xfe]);
    assert_eq!(compression.cid_length_raw(), 0x02);
    assert_eq!(
        NasEthernetHeaderCompressionConfiguration::new(vec![]).cid_length_raw(),
        0
    );
    assert_eq!(
        NasNbN1ModeDrxParameters::new(vec![0xf5]).drx_value_raw(),
        Some(5)
    );
    assert_eq!(NasNbN1ModeDrxParameters::new(vec![]).drx_value_raw(), None);
    assert_eq!(NasProseRelayTransactionIdentity::new(5).identity_raw(), 5);
    // The UE paging probability information of PEIPS: type 001 in bits 8 to 6
    let entry = PeipsAssistanceInformationEntry::UePagingProbabilityInformation(20);
    assert_eq!(
        NasPeipsAssistanceInformation::from_entry(entry)
            .unwrap()
            .value,
        [0x34]
    );
}

#[test]
fn the_feature_authorization_indication_has_hpase_in_bit_3() {
    // HPASE in bit 3, 1 when high priority access is not exempted, and MBSRAI in bits
    // 2 and 1 (§9.11.3.105)
    let not_exempt = FeatureAuthorization::new(vec![0x04]);
    assert!(not_exempt.high_priority_access_not_exempt() && !not_exempt.hpase());
    assert!(FeatureAuthorization::new(vec![0x03]).hpase());
    let written = FeatureAuthorization::from_flags(false, Mbsrai::AuthorizedAsMbsr);
    assert_eq!(written.value, [0x06]);
    let written =
        FeatureAuthorization::from_high_priority_access_not_exempt(true, Mbsrai::AuthorizedAsMbsr);
    assert_eq!(written.value, [0x06]);
}

#[test]
fn the_lp_wusps_assistance_information_has_its_type_in_bits_8_to_6() {
    // Type 001, a UE paging probability information of 5, of 20 at most
    let probability = LpWusps::new(vec![0x25]);
    assert_eq!(probability.info_type_raw(), 1);
    assert_eq!(probability.ue_paging_probability_information(), Some(5));
    assert_eq!(
        LpWusps::new(vec![0x3f]).ue_paging_probability_information(),
        Some(20)
    );
    assert_eq!(probability.reserved_bits(), None);
    assert_eq!(LpWusps::new(vec![0x05]).info_type_raw(), 0);
    // A reserved type keeps the five bits after it
    let reserved = LpWusps::new(vec![0x47]);
    assert_eq!(
        (reserved.info_type_raw(), reserved.reserved_bits()),
        (2, Some(7))
    );
}

#[test]
fn the_lists_of_a_few_octets_end_where_their_lengths_say() {
    // URSP rule enforcement reports, each its number of identifiers and the
    // identifiers (§9.11.4.38)
    let reports = |octets: &[u8]| NasUrspRuleEnforcementReports::new(octets.to_vec()).reports();
    let read = reports(&[0x01, 0x07, 0x02, 0x08, 0x09]);
    let identifiers: Vec<_> = read
        .iter()
        .map(|r| r.connection_capability_identifiers.clone())
        .collect();
    assert_eq!(identifiers, [vec![0x07], vec![0x08, 0x09]]);
    assert!(reports(&[0x00]).is_empty());
    assert!(reports(&[0x02, 0x01]).is_empty());
    // The SSID of a TNAN information, of 32 octets at most, after the TNGF ID
    // (§9.11.3.94), and its spare bits
    let tnan = |octets: &[u8]| NasTnanInformation::new(octets.to_vec());
    assert_eq!(
        tnan(&[0x03, 0x01, 0xaa, 0x02, 0x61, 0x62]).ssid(),
        Some(&b"ab"[..])
    );
    assert_eq!(tnan(&[0x02, 0x00]).ssid(), Some(&b""[..]));
    assert_eq!(tnan(&[0x02, 0x01, 0x61, 0xff]).ssid(), Some(&b"a"[..]));
    assert_eq!(tnan(&[0x02]).ssid(), None);
    let ssid = |length: usize| tnan(&[&[0x02, length as u8][..], &vec![0x61; length]].concat());
    assert_eq!(ssid(32).ssid().map(<[u8]>::len), Some(32));
    assert_eq!(ssid(33).ssid(), None);
    assert!(!tnan(&[0x04]).spare_bits_are_zero());
    // The key of an AUN3 device security key, after its length; octets after it are
    // ignored
    let key = NasAun3DeviceSecurityKey::new(vec![0x00, 0x02, 0x01, 0x02, 0xff]);
    assert_eq!(key.key(), Some(&[0x01, 0x02][..]));
    // An N3IWF identifier of an IPv6 address
    let mut ipv6 = vec![0x02];
    ipv6.extend([0x20; 16]);
    let address = NasN3iwfIdentifier::new(ipv6).address();
    assert_eq!(address, Some(N3iwfAddress::Ipv6([0x20; 16])));
    // NSSRG information: sixteen entries at most, of an S-NSSAI and its NSSRG values
    let entry = [0x03, 0x01, 0x01, 0x05];
    let seventeen = NasNssrgInformation::new(entry.repeat(17));
    assert_eq!(seventeen.entries().len(), 16);
    assert!(NasNssrgInformation::new(entry.repeat(16)).is_well_formed());
    assert!(!NasNssrgInformation::new(vec![]).is_well_formed());
}

#[test]
fn the_requests_and_the_lists_of_fixed_entries_are_their_octets() {
    // CipherKey in bit 1 of the additional information requested (§9.11.3.12A)
    for (octet, requested) in [(0x01, true), (0xfe, false)] {
        let information = NasAdditionalInformationRequested::new(vec![octet]);
        assert_eq!(
            information.cipher_key_data_requested(),
            requested,
            "{octet}"
        );
    }
    assert!(!NasAdditionalInformationRequested::new(vec![]).cipher_key_data_requested());
    let mut information = NasAdditionalInformationRequested::new(vec![0xfe]);
    information.set_cipher_key_data_requested(true);
    assert_eq!(information.value, [0xff]);
    information.set_cipher_key_data_requested(false);
    assert_eq!(information.value, [0xfe]);
    // An SNPN list of entries of nine octets, a PLMN and a NID (§9.11.3.92)
    let snpns = NasSnpnList::new(hex_octets("02f839 0102030405f6  130014 0a0b0c0d0ef6"));
    let entries = snpns.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].nid, [0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0xf6]);
    // The relay key request parameters: the relay service code, nonce 1, UIT and the
    // UE identity, which may be empty (§9.11.3.89)
    let mut value = vec![0x00, 0x00, 0x2a];
    value.extend([0x11; 16]);
    value.push(0x01);
    let parameters = NasRelayKeyRequestParameters::new(value).parse().unwrap();
    assert_eq!((parameters.relay_service_code, parameters.uit), (42, true));
    assert!(parameters.ue_id.is_empty());
}

fn hex_octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}
