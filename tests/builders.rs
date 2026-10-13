/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! A builder refuses what its IE cannot carry, and does not panic: each of
//! these calls panicked in 0.4.0.

use oxirush_nas::common::PlmnId;
use oxirush_nas::nas_5gs::*;
use oxirush_nas::nas_eps;

#[test]
fn a_plmn_identity_has_decimal_digits() {
    assert!(PlmnId::new("208", "93").is_ok());
    assert!(PlmnId::new("310", "410").is_ok());
    for (mcc, mnc) in [
        ("20", "93"),
        ("2080", "93"),
        ("208", "9"),
        ("208", "9300"),
        ("2a8", "93"),
    ] {
        assert!(PlmnId::new(mcc, mnc).is_err(), "{mcc}-{mnc}");
    }
    assert!(PlmnId::from_digits([10, 0, 8], [9, 3, 0x0f]).is_err());
    assert!(PlmnId::from_digits([2, 0, 8], [9, 0x0f, 0x0f]).is_err());
    assert!("208-93".parse::<PlmnId>().is_ok());
    assert!("20893".parse::<PlmnId>().is_err());
    // TS 24.008 §10.5.1.3: MCC digit 2 | MCC digit 1, MNC digit 3 | MCC
    // digit 3, MNC digit 2 | MNC digit 1.
    assert_eq!(
        PlmnId::new("208", "93").unwrap().to_tbcd(),
        [0x02, 0xf8, 0x39]
    );
    assert_eq!(
        PlmnId::new("310", "410").unwrap().to_tbcd(),
        [0x13, 0x00, 0x14]
    );
}

#[test]
fn identities_refuse_fields_that_are_out_of_range() {
    let plmn = PlmnId::new("208", "93").unwrap();
    let guti = |amf_set_id, amf_pointer| Guti {
        plmn,
        amf_region_id: 1,
        amf_set_id,
        amf_pointer,
        tmsi: 1,
    };
    // An AMF set identifier of ten bits and an AMF pointer of six.
    assert!(NasFGsMobileIdentity::from_guti(&guti(0x3ff, 0x3f)).is_ok());
    assert!(NasFGsMobileIdentity::from_guti(&guti(0x400, 0)).is_err());
    assert!(NasFGsMobileIdentity::from_guti(&guti(0, 0x40)).is_err());
    let s_tmsi = |amf_set_id, amf_pointer| STmsi {
        amf_set_id,
        amf_pointer,
        tmsi: 1,
    };
    assert!(NasFGsMobileIdentity::from_s_tmsi(&s_tmsi(0x3ff, 0x3f)).is_ok());
    assert!(NasFGsMobileIdentity::from_s_tmsi(&s_tmsi(0x400, 0)).is_err());
    assert!(NasFGsMobileIdentity::from_s_tmsi(&s_tmsi(0, 0x40)).is_err());
    // An IMEI of 15 digits and an IMEISV of 16.
    assert!(NasFGsMobileIdentity::from_imei("490154203237518").is_ok());
    assert!(NasFGsMobileIdentity::from_imei("49015420323751").is_err());
    assert!(NasFGsMobileIdentity::from_imeisv("4901542032375181").is_ok());
    assert!(NasFGsMobileIdentity::from_imeisv("49015420323751x1").is_err());
    assert!(nas_eps::NasEpsMobileIdentity::from_imei("490154203237518").is_ok());
    assert!(nas_eps::NasEpsMobileIdentity::from_imei("12345").is_err());
    assert!(ProtectionScheme::Reserved(0x12).to_u8().is_err());
    assert_eq!(ProtectionScheme::ProfileA.to_u8(), Ok(1));
}

#[test]
fn lists_refuse_counts_that_are_out_of_range() {
    let plmn = PlmnId::new("208", "93").unwrap();
    assert!(NasNssai::from_snssais(&[]).is_err());
    // A TAC that is reserved for a deleted TAI.
    assert!(NasFGsTrackingAreaIdentity::from_plmn_tac(&plmn, [0, 0, 1]).is_ok());
    assert!(NasFGsTrackingAreaIdentity::from_plmn_tac(&plmn, [0xff, 0xff, 0xfe]).is_err());
    // One to sixteen tracking areas.
    type TaiList = NasFGsTrackingAreaIdentityList;
    assert!(TaiList::from_plmn_tacs(&plmn, &[[0, 0, 1]; 16]).is_ok());
    assert!(TaiList::from_plmn_tacs(&plmn, &[]).is_err());
    assert!(TaiList::from_plmn_tacs(&plmn, &[[0, 0, 1]; 17]).is_err());
    assert!(TaiList::from_tai_list(&[]).is_err());
    assert!(TaiList::from_consecutive_tacs(&plmn, [0, 0, 1], 16).is_ok());
    assert!(TaiList::from_consecutive_tacs(&plmn, [0, 0, 1], 0).is_err());
    assert!(TaiList::from_consecutive_tacs(&plmn, [0, 0, 1], 17).is_err());
    assert!(TaiList::from_consecutive_tacs(&plmn, [0xff, 0xff, 0xff], 2).is_err());
    assert!(TaiList::from_entries(&[]).is_err());
    // What a constructor refuses is of what it was given: a list of tracking
    // areas has no entry of a list of partial lists, which the caller did
    // not write, and a list of partial lists says which of them.
    let tai = TrackingAreaIdentity {
        plmn,
        tac: [0, 0, 1],
    };
    let refused = |list: Result<TaiList, ValueError>| list.unwrap_err().to_string();
    assert_eq!(
        refused(TaiList::from_tai_list(&[tai; 17])),
        "`tais` has 17 entries, and has 1 to 16"
    );
    assert_eq!(
        refused(TaiList::from_plmn_tacs(&plmn, &[[0, 0, 1]; 17])),
        "`tacs` has 17 entries, and has 1 to 16"
    );
    assert_eq!(
        refused(TaiList::from_consecutive_tacs(&plmn, [0, 0, 1], 17)),
        "`count` is 17, and is 1 to 16"
    );
    let partial = TaiListEntry::DifferentPlmns(vec![tai; 17]);
    let one = TaiListEntry::DifferentPlmns(vec![tai]);
    assert_eq!(
        refused(TaiList::from_entries(&[one, partial])),
        "entry 1: `tais` has 17 entries, and has 1 to 16"
    );
    assert!(NasServiceAreaList::from_entries(&[]).is_err());
    let refused = |list: Result<NasServiceAreaList, ValueError>| list.unwrap_err().to_string();
    let allowed = ServiceAreaListAllowedType::Allowed;
    assert_eq!(
        refused(NasServiceAreaList::from_different_plmns(
            allowed, &[tai; 17]
        )),
        "`tais` has 17 entries, and has 1 to 16"
    );
    let allowed = ServiceAreaListAllowedType::Allowed;
    assert!(NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[[0, 0, 1]; 16]).is_ok());
    assert!(NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[]).is_err());
    assert!(NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[[0, 0, 1]; 17]).is_err());
    assert!(NasServiceAreaList::from_consecutive_tacs(allowed, &plmn, [0, 0, 1], 17).is_err());
    assert!(NasServiceAreaList::from_different_plmns(allowed, &[]).is_err());
    // A list of every tracking area of a PLMN is an allowed one.
    let non_allowed = ServiceAreaListAllowedType::NonAllowed;
    assert!(NasServiceAreaList::from_plmn_only(allowed, &plmn).is_ok());
    assert!(NasServiceAreaList::from_plmn_only(non_allowed, &plmn).is_err());
}

#[test]
fn values_refuse_what_their_field_cannot_hold() {
    assert!(NasSessionAmbr::from_kbps(1000, 1000).is_ok());
    assert!(NasSessionAmbr::from_kbps(u64::MAX, 1000).is_err());
    assert!(QosFlowBitRate::from_kbps(u64::MAX).is_err());
    // The control plane only indication is sent when it is set.
    assert!(NasControlPlaneOnlyIndication::from_cpoi(true).is_ok());
    assert_eq!(
        NasControlPlaneOnlyIndication::from_cpoi(false)
            .unwrap_err()
            .to_string(),
        "`cpoi` is true in an IE that is sent: a message without the IE says false"
    );
    // 17 to 1024 packet filters.
    assert!(NasMaximumNumberOfSupportedPacketFilters::from_max_filters(17).is_ok());
    assert!(NasMaximumNumberOfSupportedPacketFilters::from_max_filters(16).is_err());
    assert!(NasMaximumNumberOfSupportedPacketFilters::from_max_filters(1025).is_err());
    assert!(NasFGmmCapability::from_octets(vec![0]).is_ok());
    assert!(NasFGmmCapability::from_octets(vec![]).is_err());
    assert!(NasFGmmCapability::from_octets(vec![0; 14]).is_err());
    // A paging subgroup ID up to 7 and paging probability information up to 20.
    type Peips = NasPeipsAssistanceInformation;
    assert!(Peips::from_paging_subgroup_id(7).is_ok());
    assert!(Peips::from_paging_subgroup_id(8).is_err());
    assert!(Peips::from_ue_paging_probability_information(21).is_err());
    assert!(Peips::from_entries(&[]).is_err());
    type LpWusps = NasLpWuspsAssistanceInformation;
    assert!(LpWusps::from_paging_subgroup_id(30).is_ok());
    assert!(LpWusps::from_paging_subgroup_id(31).is_err());
    assert!(LpWusps::from_ue_paging_probability_information(21).is_err());
    // A TNGF identifier of 255 octets and an SSID of 32.
    assert!(NasTnanInformation::from_tngf_id(&[0; 255]).is_ok());
    assert!(NasTnanInformation::from_tngf_id(&[0; 256]).is_err());
    assert!(NasTnanInformation::from_ssid(&[0; 33]).is_err());
    let mut tnan = NasTnanInformation::from_ssid(b"ssid").unwrap();
    assert!(tnan.set_ssid(Some(&[0; 33])).is_err());
    assert_eq!(tnan.ssid(), Some(&b"ssid"[..]));
    // A setter that refuses leaves the IE as it was.
    let mut truncated = NasTruncatedFGSTmsiConfiguration::new(vec![0x45]);
    assert!(truncated.set_set_id_length(11).is_err());
    assert!(truncated.set_set_id_length(0).is_err());
    assert!(truncated.set_pointer_length(7).is_err());
    assert_eq!(truncated.value, [0x45]);
    assert!(truncated.set_set_id_length(10).is_ok());
    assert_eq!(truncated.value, [0xa5]);
    let algorithms =
        NasSecurityAlgorithms::from_algorithms(CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
    let ksi = NasKeySetIdentifier::new(1);
    type S1ToN1 = NasS1ModeToN1ModeNasTransparentContainer;
    assert!(S1ToN1::from_fields(1, algorithms, 7, ksi).is_ok());
    assert!(S1ToN1::from_fields(1, algorithms, 8, ksi).is_err());
}

/// A setter or a constructor that takes a number wider than its field
/// refuses what the field cannot hold: each of these kept the low bits, or
/// left out an entry, without a word.
#[test]
fn nothing_keeps_the_low_bits_of_what_it_is_given() {
    use oxirush_nas::common::ValueError;
    fn text<T>(refused: Result<T, ValueError>) -> String {
        refused
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| "accepted".into())
    }

    // The GPRS timers: 40 hours were 8 hours
    let hours = NasGprsTimer3::from_unit_value(GprsTimer3Unit::OneHour, 31).unwrap();
    assert_eq!(hours.to_seconds(), Some(31 * 3600));
    let refused = "`timer-value` is 40, and is 0 to 31";
    assert_eq!(
        text(NasGprsTimer3::from_unit_value(GprsTimer3Unit::OneHour, 40)),
        refused
    );
    let refused = "`timer-value` is 200, and is 0 to 31";
    assert_eq!(
        text(NasGprsTimer2::from_unit_value(
            GprsTimerUnit::OneMinute,
            200
        )),
        refused
    );
    assert_eq!(
        text(NasGprsTimer::from_unit_value(GprsTimerUnit::OneMinute, 200)),
        refused
    );
    let extended = nas_eps::NasT3412ExtendedValue::from_unit_value;
    let refused = "`timer-value` is 33, and is 0 to 31";
    assert_eq!(text(extended(GprsTimer3Unit::TenHours, 33)), refused);
    // A constructor from a unit and a value is what `timer()` reads
    let deactivated = NasGprsTimer3::from_unit_value(GprsTimer3Unit::Deactivated, 5).unwrap();
    assert_eq!(deactivated.timer(), Some((GprsTimer3Unit::Deactivated, 5)));

    // The key set identifiers, in each octet that has one
    let refused = "`ngksi` is 9, and is 0 to 7";
    let mut registration = NasFGsRegistrationType::new(0x01);
    assert_eq!(text(registration.set_ngksi(9).map(|_| ())), refused);
    assert_eq!(registration.value, 0x01);
    assert_eq!(text(registration.with_ngksi(9)), refused);
    assert_eq!(registration.set_ngksi(7).unwrap().value, 0x71);
    assert_eq!(text(NasDeRegistrationType::new(0).with_ngksi(9)), refused);
    assert_eq!(
        text(NasControlPlaneServiceType::new(0).with_ngksi(9)),
        refused
    );
    assert_eq!(text(NasKeySetIdentifier::new(0).with_ngksi(9)), refused);
    let refused = "`ksi` is 12, and is 0 to 7";
    let mut identifier = NasKeySetIdentifier::new(0);
    assert_eq!(text(identifier.set_ksi(12).map(|_| ())), refused);
    assert_eq!(identifier.value, 0);
    assert_eq!(
        text(nas_eps::NasKeySetIdentifier::new(0).with_ksi(12)),
        refused
    );

    // The fields of two bits and of four
    let mut support = NasFGsNetworkFeatureSupport::new(vec![0, 0]);
    assert_eq!(
        text(support.set_emc(7).map(|_| ())),
        "`emc` is 7, and is 0 to 3"
    );
    assert_eq!(
        text(support.set_emf(4).map(|_| ())),
        "`emf` is 4, and is 0 to 3"
    );
    let refused = "`restrict-ec` is 5, and is 0 to 3";
    assert_eq!(text(support.set_restrict_ec(5).map(|_| ())), refused);
    assert_eq!(support.value, [0, 0]);
    assert_eq!(support.set_emc(3).unwrap().value, [0x0c, 0]);
    let mut update = NasFGsUpdateType::new(vec![0]);
    assert_eq!(
        text(update.set_pnb_ciot(6).map(|_| ())),
        "`pnb-ciot` is 6, and is 0 to 3"
    );
    let refused = "`eps-pnb-ciot` is 4, and is 0 to 3";
    assert_eq!(text(update.set_eps_pnb_ciot(4).map(|_| ())), refused);
    assert_eq!(update.value, [0]);
    let mut drx = NasExtendedDrxParameters::new(vec![0]);
    let refused = "`paging-time-window` is 20, and is 0 to 15";
    assert_eq!(text(drx.set_paging_time_window(20).map(|_| ())), refused);
    let refused = "`edrx-value` is 31, and is 0 to 15";
    assert_eq!(text(drx.set_edrx_value(31).map(|_| ())), refused);
    assert_eq!(drx.value, [0]);
    assert_eq!(
        drx.set_paging_time_window(15)
            .unwrap()
            .set_edrx_value(15)
            .unwrap()
            .value,
        [0xff]
    );
    let refused = "`assignment-mode` is 16, and is 0 to 15";
    assert_eq!(
        text(NasNid::new(vec![0; 6]).with_assignment_mode_raw(16)),
        refused
    );
    let deletion = NasUeRadioCapabilityIdDeletionIndication::from_deletion_request_raw;
    assert_eq!(text(deletion(8)), "`deletion-request` is 8, and is 0 to 7");
    assert_eq!(deletion(1).unwrap().value, 1);

    // The lists of PDU sessions: 16 and 200 were left out, and 0 is spare
    let refused = "entry 1: `pdu-session-identity` is 16, and is 1 to 15";
    assert_eq!(
        text(NasPduSessionStatus::from_sessions(&[5, 16, 200])),
        refused
    );
    assert_eq!(
        text(NasAllowedPduSessionStatus::from_sessions(&[5, 16])),
        refused
    );
    assert_eq!(text(NasUplinkDataStatus::from_sessions(&[5, 16])), refused);
    assert_eq!(
        text(NasPduSessionReactivationResult::from_failed_sessions(&[
            5, 16
        ])),
        refused
    );
    let refused = "entry 0: `pdu-session-identity` is 0, and is 1 to 15";
    assert_eq!(text(NasPduSessionStatus::from_sessions(&[0])), refused);
    assert_eq!(
        NasPduSessionStatus::from_sessions(&[5, 15]).unwrap().value,
        [0x20, 0x80]
    );
    let with_sessions = PagingRestrictionType::AllRestrictedExceptSpecifiedPduSessions;
    let restriction = NasPagingRestriction::from_restriction_type_with_unrestricted_psis;
    assert_eq!(
        text(restriction(with_sessions, &[5, 16])),
        refused.replace("0:", "1:").replace("is 0", "is 16")
    );
    assert_eq!(
        restriction(with_sessions, &[5]).unwrap().value,
        [3, 0x20, 0]
    );
    // Sessions with a type that has none were left out
    let refused = "`unrestricted-psi-list` is written with a restriction type that has a PDU \
                   session bitmap";
    assert_eq!(
        text(restriction(PagingRestrictionType::AllRestricted, &[5])),
        refused
    );
    let mut all = NasPagingRestriction::from_restriction_type(PagingRestrictionType::AllRestricted);
    assert_eq!(
        text(all.set_unrestricted_psi_list(&[5]).map(|_| ())),
        refused
    );
    assert_eq!(all.value, [1]);

    // The algorithms of the capabilities: one above the last was ignored
    let mut capability = nas_eps::NasUeNetworkCapability::new(vec![0, 0]);
    assert_eq!(
        text(capability.set_eea(8, true).map(|_| ())),
        "`eea` is 8, and is 0 to 7"
    );
    // Bit 1 of the octet of the EIAs is EPS-UPIP
    assert_eq!(
        text(capability.set_eia(7, true).map(|_| ())),
        "`eia` is 7, and is 0 to 6"
    );
    assert_eq!(capability.value, [0, 0]);
    let mut additional = nas_eps::NasUeAdditionalSecurityCapability::new(vec![0; 4]);
    assert_eq!(
        text(additional.set_ea(16, true).map(|_| ())),
        "`5g-ea` is 16, and is 0 to 15"
    );
    assert_eq!(
        text(additional.set_ia(16, true).map(|_| ())),
        "`5g-ia` is 16, and is 0 to 15"
    );
    // Bit 8 of the octets of UIA and of GEA is spare, and was cleared
    let replayed = nas_eps::NasReplayedUeSecurityCapabilities::from_algorithms;
    assert_eq!(
        text(replayed(0xe0, 0xe0, Some((0xc0, 0xc0)), None)),
        "`uia` is 192, and is 0 to 127"
    );
    assert_eq!(
        text(replayed(0xe0, 0xe0, None, Some(0x80))),
        "`gea` is 128, and is 0 to 127"
    );
    assert_eq!(
        replayed(0xe0, 0xe0, Some((0xc0, 0x40)), None)
            .unwrap()
            .value,
        [0xe0, 0xe0, 0xc0, 0x40]
    );

    // A value that was written as another, or not at all
    let refused = "`type-of-identity` is a type of identity that is asked for, and `no-identity` \
                   is none";
    assert_eq!(
        text(NasFGsIdentityType::from_identity_type(
            MobileIdentityType::NoIdentity
        )),
        refused
    );
    let mut asked = NasFGsIdentityType::from_identity_type(MobileIdentityType::Imei).unwrap();
    assert_eq!(
        text(
            asked
                .set_identity_type(MobileIdentityType::NoIdentity)
                .map(|_| ())
        ),
        refused
    );
    assert_eq!(asked.identity_type(), Some(MobileIdentityType::Imei));
    let mut imei = NasFGsMobileIdentity::from_imei("356092040793011").unwrap();
    let refused = "`mauri` is a bit of a MAC address, and the identity is of another type";
    assert_eq!(text(imei.set_mauri(true).map(|_| ())), refused);
    let mut mac = NasFGsMobileIdentity::from_mac_address([1, 2, 3, 4, 5, 6]);
    assert_eq!(mac.set_mauri(true).unwrap().mauri(), Some(true));
    let identity = NasProseRelayTransactionIdentity::from_identity;
    let refused = "`assigned` is 0, and is 1 to 254";
    assert_eq!(
        text(identity(ProseRelayTransactionIdentityValue::Assigned(0))),
        refused
    );
    assert_eq!(
        identity(ProseRelayTransactionIdentityValue::Assigned(254))
            .unwrap()
            .value,
        254
    );
    let parameters = RelayKeyRequestParameters::new(0x0100_0000, [0; 16], false, vec![1]);
    let refused = "`relay-service-code` is 16777216, and is 0 to 16777215";
    assert_eq!(
        text(NasRelayKeyRequestParameters::from_parsed(&parameters)),
        refused
    );
    let name = NasNetworkName::from_name("net", false);
    assert_eq!(
        text(name.clone().with_spare_bits(8)),
        "`spare-bits` is 8, and is 0 to 7"
    );
    let ucs2 = name.with_coding_scheme(NetworkNameCodingScheme::Ucs2);
    let refused = "`spare-bits` is 0 with the UCS2 coding scheme";
    assert_eq!(text(ucs2.with_spare_bits(3)), refused);
}

/// A refusal is one error type for every constructor and setter: the member
/// by its name, the entry of the list that it is in, what it was given and
/// the limit that this breaks.
#[test]
fn a_refusal_says_the_member_what_it_was_given_and_the_limit() {
    use oxirush_nas::common::{ValueError, ValueFault};

    // `?` carries the refusal of any constructor.
    fn identities(mcc: &str, imei: &str) -> Result<(PlmnId, NasFGsMobileIdentity), ValueError> {
        Ok((
            PlmnId::new(mcc, "93")?,
            NasFGsMobileIdentity::from_imei(imei)?,
        ))
    }
    assert!(identities("208", "356092040793011").is_ok());

    // Digits outside their length, and a character that is no digit
    let error = identities("20", "356092040793011").unwrap_err();
    let fault = ValueFault::Length {
        given: 2,
        min: 3,
        max: 3,
        unit: "digits",
    };
    assert_eq!(
        (error.member, error.entry, error.fault),
        ("mcc", None, fault)
    );
    assert_eq!(error.to_string(), "`mcc` has 2 digits, and has 3");
    let error = identities("208", "35609204079301x").unwrap_err();
    let fault = ValueFault::Character {
        given: 'x',
        expected: "decimal digits",
    };
    assert_eq!((error.member, error.fault), ("imei", fault));
    assert_eq!(
        error.to_string(),
        "`imei` has the character `x`, and has decimal digits"
    );

    // A number outside its range, in a constructor and in a setter
    let error = NasTimeZone::from_quarter_hours(80).unwrap_err();
    let fault = ValueFault::Range {
        given: 80,
        min: -79,
        max: 79,
    };
    assert_eq!((error.member, error.fault), ("time-zone", fault));
    assert_eq!(error.to_string(), "`time-zone` is 80, and is -79 to 79");
    let mut identifier = nas_eps::NasKeySetIdentifier::new(0);
    let error =
        (identifier.set_key_set_identifier(nas_eps::KeySetIdentifier::Mapped(7))).unwrap_err();
    assert_eq!(error.to_string(), "`mapped` is 7, and is 0 to 6");
    assert_eq!(identifier.value, 0);

    // Entries outside their number, and the entry that a member is in
    let plmn = PlmnId::new("208", "93").unwrap();
    let error = nas_eps::NasEquivalentPlmns::from_plmns(&[plmn; 16]).unwrap_err();
    let fault = ValueFault::Count {
        given: 16,
        min: 1,
        max: 15,
    };
    assert_eq!((error.member, error.fault), ("plmns", fault));
    assert_eq!(error.to_string(), "`plmns` has 16 entries, and has 1 to 15");
    let error = nas_eps::NasEpsBearerContextStatus::from_bearers(&[5, 16]).unwrap_err();
    assert_eq!(
        (error.member, error.entry),
        ("eps-bearer-identity", Some(1))
    );
    assert_eq!(
        error.to_string(),
        "entry 1: `eps-bearer-identity` is 16, and is 1 to 15"
    );

    // A value that is there twice
    let causes = [(5, GmmCause::Congestion), (5, GmmCause::IllegalUe)];
    let error = NasPduSessionReactivationResultErrorCause::from_entries(&causes).unwrap_err();
    assert_eq!(error.fault, ValueFault::Repeated { given: 5 });
    assert_eq!(
        error.to_string(),
        "entry 1: `pdu-session-identity` has 5 twice"
    );

    // Members that do not go together
    let mut contents = NasSNssai::new(vec![1]).parse().unwrap();
    contents.mapped_sd = Some([0, 0, 1]);
    let error = contents.to_snssai().unwrap_err();
    let fault = ValueFault::Combination {
        rule: "is written with `mapped-sst`",
    };
    assert_eq!((error.member, error.fault), ("mapped-sd", fault));
    assert_eq!(
        error.to_string(),
        "`mapped-sd` is written with `mapped-sst`"
    );
    let error = (nas_eps::NasPagingRestriction::from_restriction(
        nas_eps::EpsPagingRestrictionType::AllRestricted,
        &[5],
    ))
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "`unrestricted-ebis` are written with a restriction type that has a bearer bitmap"
    );

    // A number that the member cannot be
    let error = NasGprsTimer3::from_seconds(100_000_000).unwrap_err();
    assert!(matches!(
        error.fault,
        ValueFault::Value {
            given: 100_000_000,
            ..
        }
    ));

    // An error is one of `core::error::Error`, and is copied
    let boxed: Box<dyn core::error::Error + Send + Sync> = Box::new(error);
    assert_eq!(boxed.to_string(), error.to_string());
}
