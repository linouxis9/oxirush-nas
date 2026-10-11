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
    assert!(PlmnId::new("208", "93").is_some());
    assert!(PlmnId::new("310", "410").is_some());
    for (mcc, mnc) in [
        ("20", "93"),
        ("2080", "93"),
        ("208", "9"),
        ("208", "9300"),
        ("2a8", "93"),
    ] {
        assert_eq!(PlmnId::new(mcc, mnc), None, "{mcc}-{mnc}");
    }
    assert_eq!(PlmnId::from_digits([10, 0, 8], [9, 3, 0x0f]), None);
    assert_eq!(PlmnId::from_digits([2, 0, 8], [9, 0x0f, 0x0f]), None);
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
    assert!(NasFGsMobileIdentity::from_guti(&guti(0x3ff, 0x3f)).is_some());
    assert!(NasFGsMobileIdentity::from_guti(&guti(0x400, 0)).is_none());
    assert!(NasFGsMobileIdentity::from_guti(&guti(0, 0x40)).is_none());
    let s_tmsi = |amf_set_id, amf_pointer| STmsi {
        amf_set_id,
        amf_pointer,
        tmsi: 1,
    };
    assert!(NasFGsMobileIdentity::from_s_tmsi(&s_tmsi(0x3ff, 0x3f)).is_some());
    assert!(NasFGsMobileIdentity::from_s_tmsi(&s_tmsi(0x400, 0)).is_none());
    assert!(NasFGsMobileIdentity::from_s_tmsi(&s_tmsi(0, 0x40)).is_none());
    // An IMEI of 15 digits and an IMEISV of 16.
    assert!(NasFGsMobileIdentity::from_imei("490154203237518").is_some());
    assert!(NasFGsMobileIdentity::from_imei("49015420323751").is_none());
    assert!(NasFGsMobileIdentity::from_imeisv("4901542032375181").is_some());
    assert!(NasFGsMobileIdentity::from_imeisv("49015420323751x1").is_none());
    assert!(nas_eps::NasEpsMobileIdentity::from_imei("490154203237518").is_some());
    assert!(nas_eps::NasEpsMobileIdentity::from_imei("12345").is_none());
    assert_eq!(ProtectionScheme::Reserved(0x12).to_u8(), None);
    assert_eq!(ProtectionScheme::ProfileA.to_u8(), Some(1));
}

#[test]
fn lists_refuse_counts_that_are_out_of_range() {
    let plmn = PlmnId::new("208", "93").unwrap();
    assert!(NasNssai::from_snssais(&[]).is_none());
    // A TAC that is reserved for a deleted TAI.
    assert!(NasFGsTrackingAreaIdentity::from_plmn_tac(&plmn, [0, 0, 1]).is_some());
    assert!(NasFGsTrackingAreaIdentity::from_plmn_tac(&plmn, [0xff, 0xff, 0xfe]).is_none());
    // One to sixteen tracking areas.
    type TaiList = NasFGsTrackingAreaIdentityList;
    assert!(TaiList::from_plmn_tacs(&plmn, &[[0, 0, 1]; 16]).is_some());
    assert!(TaiList::from_plmn_tacs(&plmn, &[]).is_none());
    assert!(TaiList::from_plmn_tacs(&plmn, &[[0, 0, 1]; 17]).is_none());
    assert!(TaiList::from_tai_list(&[]).is_none());
    assert!(TaiList::from_consecutive_tacs(&plmn, [0, 0, 1], 16).is_some());
    assert!(TaiList::from_consecutive_tacs(&plmn, [0, 0, 1], 0).is_none());
    assert!(TaiList::from_consecutive_tacs(&plmn, [0, 0, 1], 17).is_none());
    assert!(TaiList::from_consecutive_tacs(&plmn, [0xff, 0xff, 0xff], 2).is_none());
    assert!(TaiList::from_entries(&[]).is_none());
    assert!(NasServiceAreaList::from_entries(&[]).is_none());
    let allowed = ServiceAreaListAllowedType::Allowed;
    assert!(NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[[0, 0, 1]; 16]).is_some());
    assert!(NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[]).is_none());
    assert!(NasServiceAreaList::from_plmn_tacs(allowed, &plmn, &[[0, 0, 1]; 17]).is_none());
    assert!(NasServiceAreaList::from_consecutive_tacs(allowed, &plmn, [0, 0, 1], 17).is_none());
    assert!(NasServiceAreaList::from_different_plmns(allowed, &[]).is_none());
    // A list of every tracking area of a PLMN is an allowed one.
    let non_allowed = ServiceAreaListAllowedType::NonAllowed;
    assert!(NasServiceAreaList::from_plmn_only(allowed, &plmn).is_some());
    assert!(NasServiceAreaList::from_plmn_only(non_allowed, &plmn).is_none());
}

#[test]
fn values_refuse_what_their_field_cannot_hold() {
    assert!(NasSessionAmbr::from_kbps(1000, 1000).is_some());
    assert!(NasSessionAmbr::from_kbps(u64::MAX, 1000).is_none());
    assert!(QosFlowBitRate::from_kbps(u64::MAX).is_none());
    // The control plane only indication is sent when it is set.
    assert!(NasControlPlaneOnlyIndication::from_cpoi(true).is_some());
    assert!(NasControlPlaneOnlyIndication::from_cpoi(false).is_none());
    // 17 to 1024 packet filters.
    assert!(NasMaximumNumberOfSupportedPacketFilters::from_max_filters(17).is_some());
    assert!(NasMaximumNumberOfSupportedPacketFilters::from_max_filters(16).is_none());
    assert!(NasMaximumNumberOfSupportedPacketFilters::from_max_filters(1025).is_none());
    assert!(NasFGmmCapability::from_octets(vec![0]).is_some());
    assert!(NasFGmmCapability::from_octets(vec![]).is_none());
    assert!(NasFGmmCapability::from_octets(vec![0; 14]).is_none());
    // A paging subgroup ID up to 7 and paging probability information up to 20.
    type Peips = NasPeipsAssistanceInformation;
    assert!(Peips::from_paging_subgroup_id(7).is_some());
    assert!(Peips::from_paging_subgroup_id(8).is_none());
    assert!(Peips::from_ue_paging_probability_information(21).is_none());
    assert!(Peips::from_entries(&[]).is_none());
    type LpWusps = NasLpWuspsAssistanceInformation;
    assert!(LpWusps::from_paging_subgroup_id(30).is_ok());
    assert!(LpWusps::from_paging_subgroup_id(31).is_err());
    assert!(LpWusps::from_ue_paging_probability_information(21).is_err());
    // A TNGF identifier of 255 octets and an SSID of 32.
    assert!(NasTnanInformation::from_tngf_id(&[0; 255]).is_some());
    assert!(NasTnanInformation::from_tngf_id(&[0; 256]).is_none());
    assert!(NasTnanInformation::from_ssid(&[0; 33]).is_none());
    let mut tnan = NasTnanInformation::from_ssid(b"ssid").unwrap();
    assert!(tnan.set_ssid(Some(&[0; 33])).is_none());
    assert_eq!(tnan.ssid(), Some(&b"ssid"[..]));
    // A setter that refuses leaves the IE as it was.
    let mut truncated = NasTruncatedFGSTmsiConfiguration::new(vec![0x45]);
    assert!(truncated.set_set_id_length(11).is_none());
    assert!(truncated.set_set_id_length(0).is_none());
    assert!(truncated.set_pointer_length(7).is_none());
    assert_eq!(truncated.value, [0x45]);
    assert!(truncated.set_set_id_length(10).is_some());
    assert_eq!(truncated.value, [0xa5]);
    let algorithms =
        NasSecurityAlgorithms::from_algorithms(CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
    let ksi = NasKeySetIdentifier::new(1);
    type S1ToN1 = NasS1ModeToN1ModeNasTransparentContainer;
    assert!(S1ToN1::from_fields(1, algorithms.clone(), 7, ksi.clone()).is_some());
    assert!(S1ToN1::from_fields(1, algorithms, 8, ksi).is_none());
}
