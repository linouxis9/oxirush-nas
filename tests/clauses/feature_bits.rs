//! IEs of indications, each in its bits: the 5GS network feature support (TS
//! 24.501 §9.11.3.5, figure 9.11.3.5.1), whose value has up to four octets, the
//! 5GSM capability (§9.11.4.1), the 5GS registration result (§9.11.3.6), the
//! de-registration type (§9.11.3.20) and the 5GS update type (§9.11.3.9A).

use oxirush_nas::nas_5gs::{
    AccessTypeValue, AtsssLowLayerFunctionality, AtsssSteeringFunctionality,
    DeregistrationAccessType, EmergencyFallbackSupport, EmergencyServiceSupport,
    NasDeRegistrationType, NasFGsNetworkFeatureSupport as Support, NasFGsRegistrationResult,
    NasFGsUpdateType, NasFGsmCapability as Capability, PreferredCiotBehavior, RegistrationResult,
    RestrictionOnEnhancedCoverage,
};

type With = fn(Support, bool) -> Support;
type Read = fn(&Support) -> bool;

/// Each indication of one bit, with the octet of the value and the bit that
/// carry it: octet 3 of the IE is the octet 0 of its value.
const INDICATIONS: [(&str, With, Read, usize, u8); 24] = [
    (
        "IMS-VoPS-3GPP",
        Support::with_ims_vops_3gpp,
        Support::ims_vops_3gpp,
        0,
        0x01,
    ),
    (
        "IMS-VoPS-N3GPP",
        Support::with_ims_vops_n3gpp,
        Support::ims_vops_n3gpp,
        0,
        0x02,
    ),
    ("IWK N26", Support::with_iwk_n26, Support::iwk_n26, 0, 0x40),
    ("MPSI", Support::with_mpsi, Support::mpsi, 0, 0x80),
    ("EMCN3", Support::with_emcn3, Support::emcn3, 1, 0x01),
    ("MCSI", Support::with_mcsi, Support::mcsi, 1, 0x02),
    (
        "5G-CP CIoT",
        Support::with_cp_ciot,
        Support::cp_ciot,
        1,
        0x10,
    ),
    (
        "N3 data",
        Support::with_n3_data_not_supported,
        Support::n3_data_not_supported,
        1,
        0x20,
    ),
    (
        "5G-IPHC-CP CIoT",
        Support::with_iphc_cp_ciot,
        Support::iphc_cp_ciot,
        1,
        0x40,
    ),
    (
        "5G-UP CIoT",
        Support::with_up_ciot,
        Support::up_ciot,
        1,
        0x80,
    ),
    ("5G-LCS", Support::with_lcs_5g, Support::lcs_5g, 2, 0x01),
    ("ATS-IND", Support::with_ats_ind, Support::ats_ind, 2, 0x02),
    (
        "5G-EHC-CP CIoT",
        Support::with_ehc_cp_ciot,
        Support::ehc_cp_ciot,
        2,
        0x04,
    ),
    ("NCR", Support::with_ncr, Support::ncr, 2, 0x08),
    ("PIV", Support::with_piv, Support::piv, 2, 0x10),
    ("RPR", Support::with_rpr, Support::rpr, 2, 0x20),
    ("PR", Support::with_pr, Support::pr, 2, 0x40),
    ("UN-PER", Support::with_un_per, Support::un_per, 2, 0x80),
    ("NAPS", Support::with_naps, Support::naps, 3, 0x01),
    ("LCS-UPP", Support::with_lcs_upp, Support::lcs_upp, 3, 0x02),
    ("SUPL", Support::with_supl, Support::supl, 3, 0x04),
    ("RSLP", Support::with_rslp, Support::rslp, 3, 0x08),
    ("MLCSUP", Support::with_mlcsup, Support::mlcsup, 3, 0x10),
    ("EF5L", Support::with_ef5l, Support::ef5l, 3, 0x20),
];

#[test]
fn each_indication_of_the_5gs_network_feature_support_is_its_own_bit() {
    for (name, with, read, octet, bit) in INDICATIONS {
        // Set on four octets of zeros, the indication is its bit alone; set on
        // four octets of ones and cleared, every other bit stays
        let set = with(Support::new(vec![0; 4]), true);
        let mut expected = [0; 4];
        expected[octet] = bit;
        assert_eq!(set.value, expected, "{name}");
        assert!(read(&set), "{name}");
        assert_eq!(set.octet(octet + 1), bit, "{name}");
        let cleared = with(Support::new(vec![0xff; 4]), false);
        let mut expected = [0xff; 4];
        expected[octet] = !bit;
        assert_eq!(cleared.value, expected, "{name}");
        assert!(!read(&cleared), "{name}");
        // Read on the other bits alone, it is not set
        let others = Support::new(vec![0xff; 4]);
        let mut others = others.value.to_vec();
        others[octet] = !bit;
        assert!(!read(&Support::new(others)), "{name}");
        // A value that is short of its octet does not have it, and gets it
        assert!(!read(&Support::new(vec![0xff; octet])), "{name}");
        assert_eq!(
            with(Support::new(vec![]), true).value.len(),
            octet + 1,
            "{name}"
        );
    }
    assert_eq!(Support::new(vec![1, 2, 3, 4]).octet(0), 0);
    assert_eq!(Support::new(vec![1, 2, 3, 4]).octet(5), 0);
}

#[test]
fn n3_data_transfer_is_supported_when_its_bit_is_0() {
    let supported = Support::new(vec![0; 2]).with_n3_data(true);
    assert_eq!(supported.value, [0, 0]);
    assert!(supported.n3_data());
    let not_supported = Support::new(vec![0; 2]).with_n3_data(false);
    assert_eq!(not_supported.value, [0, 0x20]);
    assert!(!not_supported.n3_data());
}

#[test]
fn the_codes_of_two_bits_are_in_their_bits() {
    // EMC in the bits 4 and 3 of octet 3, EMF in the bits 6 and 5, and
    // RestrictEC in the bits 4 and 3 of octet 4
    let support = Support::new(vec![0xff, 0xff])
        .with_emc_value(EmergencyServiceSupport::NrOnly)
        .with_emf_value(EmergencyFallbackSupport::EutraOnly)
        .with_restrict_ec_value(RestrictionOnEnhancedCoverage::CeModeBRestricted);
    assert_eq!(
        support.value,
        [0xc3 | 0x01 << 2 | 0x02 << 4, 0xf3 | 0x02 << 2]
    );
    assert_eq!(support.emc(), 1);
    assert_eq!(support.emc_value(), Some(EmergencyServiceSupport::NrOnly));
    assert_eq!(support.emf(), 2);
    assert_eq!(
        support.emf_value(),
        Some(EmergencyFallbackSupport::EutraOnly)
    );
    assert_eq!(support.restrict_ec(), 2);
    assert_eq!(
        support.restrict_ec_value(),
        Some(RestrictionOnEnhancedCoverage::CeModeBRestricted)
    );
    let codes = Support::new(vec![])
        .with_emc(3)
        .unwrap()
        .with_emf(1)
        .unwrap()
        .with_restrict_ec(3)
        .unwrap();
    assert_eq!(codes.value, [0x1c, 0x0c]);
    assert!(Support::new(vec![]).with_emc(4).is_err());
    assert!(Support::new(vec![]).with_emf(4).is_err());
    assert!(Support::new(vec![]).with_restrict_ec(4).is_err());
}

#[test]
fn from_features_writes_octet_3_and_octet_4_when_it_has_an_indication() {
    let support = Support::from_features(
        true,
        false,
        EmergencyServiceSupport::NrAndEutra,
        EmergencyFallbackSupport::NrOnly,
        false,
        true,
        false,
        false,
    );
    assert_eq!(support.value, [0x01 | 0x0c | 0x10 | 0x80]);
    assert!(support.access_identity_1_valid());
    assert!(!support.access_identity_2_valid());
    let both = Support::from_features(
        false,
        true,
        EmergencyServiceSupport::NotSupported,
        EmergencyFallbackSupport::NotSupported,
        true,
        false,
        true,
        true,
    );
    assert_eq!(both.value, [0x42, 0x03]);
    assert!(both.access_identity_2_valid());
}

type WithCapability = fn(Capability, bool) -> Capability;
type ReadCapability = fn(&Capability) -> bool;

/// Each indication of the 5GSM capability of one bit, with the octet of the
/// value and the bit that carry it (figure 9.11.4.1.1).
const CAPABILITIES: [(&str, WithCapability, ReadCapability, usize, u8); 12] = [
    ("RQoS", Capability::with_rqos, Capability::rqos, 0, 0x01),
    (
        "MH6-PDU",
        Capability::with_mh6_pdu,
        Capability::mh6_pdu,
        0,
        0x02,
    ),
    (
        "EPT-S1",
        Capability::with_ept_s1,
        Capability::ept_s1,
        0,
        0x04,
    ),
    ("TPMIC", Capability::with_tpmic, Capability::tpmic, 0, 0x80),
    ("APMQF", Capability::with_apmqf, Capability::apmqf, 1, 0x01),
    (
        "SDNAEPC",
        Capability::with_sdnaepc,
        Capability::sdnaepc,
        1,
        0x02,
    ),
    (
        "RTPMMII",
        Capability::with_rtpmmii,
        Capability::rtpmmii,
        1,
        0x04,
    ),
    ("MPTCP", Capability::with_mptcp, Capability::mptcp, 1, 0x20),
    (
        "MPQUIC-UDP",
        Capability::with_mpquic_udp,
        Capability::mpquic_udp,
        1,
        0x40,
    ),
    (
        "MPQUIC-IP",
        Capability::with_mpquic_ip,
        Capability::mpquic_ip,
        1,
        0x80,
    ),
    (
        "MPQUIC-E",
        Capability::with_mpquic_e,
        Capability::mpquic_e,
        2,
        0x01,
    ),
    (
        "E8PCPDEI",
        Capability::with_e8pcpdei,
        Capability::e8pcpdei,
        2,
        0x02,
    ),
];

#[test]
fn each_indication_of_the_5gsm_capability_is_its_own_bit() {
    for (name, with, read, octet, bit) in CAPABILITIES {
        let set = with(Capability::new(vec![0; 3]), true);
        let mut expected = [0; 3];
        expected[octet] = bit;
        assert_eq!(set.value, expected, "{name}");
        assert!(read(&set), "{name}");
        assert_eq!(set.octet(octet + 1), bit, "{name}");
        let mut others = [0xff; 3];
        others[octet] = !bit;
        assert!(!read(&Capability::new(others.to_vec())), "{name}");
        assert!(!read(&Capability::new(vec![0xff; octet])), "{name}");
    }
    // The spare bits of octet 5, and the octets 6 to 15, are cleared by a
    // setter of octet 5 and are zero in a capability that is well formed
    let spare = Capability::new(vec![0, 0, 0xfc, 1]).with_mpquic_e(true);
    assert_eq!(spare.value, [0, 0, 0x01, 0]);
    assert!(spare.spare_bits_are_zero());
    assert!(!Capability::new(vec![0, 0, 0x04]).spare_bits_are_zero());
    assert!(!Capability::new(vec![0, 0, 0, 1]).spare_bits_are_zero());
    assert!(Capability::new(vec![0xff, 0xff, 0x03]).spare_bits_are_zero());
    assert_eq!(Capability::new(vec![1, 2]).octet(0), 0);
    assert_eq!(Capability::new(vec![1, 2]).octet(3), 0);
}

#[test]
fn the_steering_functionalities_of_the_5gsm_capability_are_in_their_bits() {
    // ATSSS-ST in the bits 7 to 4 of octet 3, ATSSS-LL in the bits 5 and 4
    // of octet 4
    let capability = Capability::new(vec![0xff, 0xff])
        .with_atsss_st_value(AtsssSteeringFunctionality::MptcpAnyAndLowLayerActiveStandby)
        .with_atsss_ll_value(AtsssLowLayerFunctionality::AnySteering);
    assert_eq!(capability.value, [0x87 | 0x02 << 3, 0xe7 | 0x02 << 3]);
    assert_eq!(capability.atsss_st(), 2);
    assert_eq!(capability.atsss_ll(), 2);
    let flags = Capability::from_flags(
        true,
        AtsssSteeringFunctionality::LowLayerAnySteering,
        false,
        true,
        false,
    );
    assert_eq!(flags.value, [0x80 | 0x01 << 3 | 0x02]);
    let flags = Capability::from_flags(
        false,
        AtsssSteeringFunctionality::NotSupported,
        true,
        false,
        true,
    );
    assert_eq!(flags.value, [0x05]);
    // Contents of 1 to 13 octets, of defined functionalities and spare bits
    // that are zero
    assert!(Capability::from_octets(vec![0x01, 0x08, 0x03]).is_ok());
    for refused in [
        vec![],
        vec![0; 14],
        vec![0x78],
        vec![0, 0x18],
        vec![0, 0, 0x04],
        vec![0, 0, 0, 1],
    ] {
        assert!(
            Capability::from_octets(refused.clone()).is_err(),
            "{refused:?}"
        );
    }
}

#[test]
fn the_registration_result_has_its_value_and_four_indications() {
    // The value in the bits 3 to 1, SMS allowed in the bit 4, NSSAA performed
    // in the bit 5, emergency registered in the bit 6 and the disaster
    // roaming registration result in the bit 7
    let result = NasFGsRegistrationResult::from_result(RegistrationResult::Non3GppAccess);
    assert_eq!(result.value, [0x02]);
    let all = result
        .clone()
        .with_sms_allowed(true)
        .with_nssaa_performed(true)
        .with_emergency_registered(true)
        .with_disaster_roaming(true);
    assert_eq!(all.value, [0x7a]);
    assert!(all.sms_allowed() && all.nssaa_performed());
    assert!(all.emergency_registered() && all.disaster_roaming());
    let with = |set: fn(NasFGsRegistrationResult, bool) -> NasFGsRegistrationResult| {
        (
            set(result.clone(), true).value[0],
            set(all.clone(), false).value[0],
        )
    };
    assert_eq!(
        with(NasFGsRegistrationResult::with_sms_allowed),
        (0x0a, 0x72)
    );
    assert_eq!(
        with(NasFGsRegistrationResult::with_nssaa_performed),
        (0x12, 0x6a)
    );
    assert_eq!(
        with(NasFGsRegistrationResult::with_emergency_registered),
        (0x22, 0x5a)
    );
    assert_eq!(
        with(NasFGsRegistrationResult::with_disaster_roaming),
        (0x42, 0x3a)
    );
    let mut changed = all.clone();
    changed.set_sms_allowed(false);
    changed.set_nssaa_performed(false);
    changed.set_emergency_registered(false);
    changed.set_disaster_roaming(false);
    changed.set_result_value(RegistrationResult::ThreeGppAccessAndNon3GppAccess);
    assert_eq!(changed.value, [0x03]);
    let changed = all.with_result_value(RegistrationResult::ThreeGppAccess);
    assert_eq!(changed.value, [0x79]);
    assert_eq!(
        changed.result_value(),
        Some(RegistrationResult::ThreeGppAccess)
    );
    assert_eq!(changed.result_value_raw(), 1);
}

#[test]
fn the_deregistration_type_has_switch_off_re_registration_and_the_access_type() {
    // Switch off in the bit 4, re-registration required in the bit 3 and the
    // access type in the bits 2 and 1
    let deregistration = NasDeRegistrationType::new(0)
        .with_switch_off(true)
        .with_access_type(AccessTypeValue::Non3GppAccess);
    assert_eq!(deregistration.value, 0x0a);
    assert!(deregistration.switch_off());
    assert!(!deregistration.re_registration_required());
    assert_eq!(
        deregistration.access_type(),
        Some(AccessTypeValue::Non3GppAccess)
    );
    let required = NasDeRegistrationType::new(0x0f)
        .with_switch_off(false)
        .with_re_registration_required(true)
        .with_deregistration_access_type(DeregistrationAccessType::ThreeGppAccess);
    assert_eq!(required.value, 0x05);
    assert!(required.re_registration_required());
    assert_eq!(required.access_type_raw(), 1);
    let mut changed = required;
    changed.set_re_registration_required(false);
    changed.set_switch_off(true);
    changed.set_access_type(AccessTypeValue::Non3GppAccess);
    assert_eq!(changed.value, 0x0a);
    changed.set_switch_off(false);
    changed
        .set_deregistration_access_type(DeregistrationAccessType::ThreeGppAccessAndNon3GppAccess);
    assert_eq!(changed.value, 0x03);
    assert_eq!(
        changed.deregistration_access_type(),
        Some(DeregistrationAccessType::ThreeGppAccessAndNon3GppAccess)
    );
    assert_eq!(
        NasDeRegistrationType::new(0x07)
            .with_re_registration_required(false)
            .value,
        0x03
    );
}

#[test]
fn the_update_type_has_its_requests_and_the_preferred_behaviours() {
    // SMS requested in the bit 1, NG-RAN-RCU in the bit 2, 5GS-PNB-CIoT in the
    // bits 4 and 3 and EPS-PNB-CIoT in the bits 6 and 5
    let update = NasFGsUpdateType::new(vec![0])
        .with_sms_requested(true)
        .with_ng_ran_rcu(true)
        .with_pnb_ciot(PreferredCiotBehavior::UserPlane)
        .with_eps_pnb_ciot(PreferredCiotBehavior::ControlPlane);
    let pnb = PreferredCiotBehavior::UserPlane as u8;
    let eps = PreferredCiotBehavior::ControlPlane as u8;
    assert_eq!(update.value, [0x03 | pnb << 2 | eps << 4]);
    assert!(update.sms_requested() && update.ng_ran_rcu());
    assert_eq!(update.pnb_ciot(), Some(PreferredCiotBehavior::UserPlane));
    assert_eq!(
        update.eps_pnb_ciot(),
        Some(PreferredCiotBehavior::ControlPlane)
    );
    assert_eq!(update.pnb_ciot_raw(), pnb);
    assert_eq!(update.eps_pnb_ciot_raw(), eps);
    let cleared = update.with_sms_requested(false).with_ng_ran_rcu(false);
    assert_eq!(cleared.value, [pnb << 2 | eps << 4]);
    let mut changed = NasFGsUpdateType::new(vec![0x3f]);
    changed.set_ng_ran_rcu(false);
    assert_eq!(changed.value, [0x3d]);
    changed.set_sms_requested(false);
    assert_eq!(changed.value, [0x3c]);
}
