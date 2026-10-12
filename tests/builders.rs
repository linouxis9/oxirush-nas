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
    assert!(NasServiceAreaList::from_entries(&[]).is_err());
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
    assert!(S1ToN1::from_fields(1, algorithms.clone(), 7, ksi.clone()).is_ok());
    assert!(S1ToN1::from_fields(1, algorithms, 8, ksi).is_err());
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
