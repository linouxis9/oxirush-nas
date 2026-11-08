//! The fields of the 5GS IEs of a few octets (TS 24.501 §9.11): each reader takes the
//! bits of its field and no other, each setter writes them and leaves the others, and
//! each constructor of flags sets the bit of each flag.

use oxirush_nas::identity::MobileIdentityType5gs;
use oxirush_nas::nas_5gs::{
    Abba, AccessType, Additional5gSecurityInformation, AdditionalConfigurationIndication,
    AllowedSscMode, AlwaysOnPduSessionIndication, AlwaysOnPduSessionRequested,
    ConfigurationUpdateIndication, ControlPlaneServiceType, ControlPlaneServiceTypeValue,
    DeRegistrationType, DrxParameters, GmmCapability, GmmCause, GprsTimer3Unit, GprsTimerValue,
    GsmCause, GsmCongestionReAttemptIndicator, GsmNetworkFeatureSupport, IdentityType,
    IntegrityProtectionMaximumDataRate, MaPduSessionInfoValue, MaPduSessionInformation,
    MaxDataRate, MaximumNumberOfSupportedPacketFilters, MicoIndication, N5gcIndication,
    NetworkFeatureSupport, NetworkSlicingIndication, NssaiInclusionMode, NssaiInclusionModeValue,
    PayloadContainerKind, PayloadContainerType, PduSessionType, PriorityIndicator,
    ReAttemptIndicator, RegistrationType, RegistrationTypeValue, RequestType, Rsn, SmsIndication,
    SscMode, T3512Value, UeSecurityCapability, UeUsageSetting,
};

/// Whether bit `bit` (1 to 8) of `octet` is set.
fn bit(octet: u8, bit: u8) -> bool {
    octet >> (bit - 1) & 1 == 1
}

#[test]
fn a_flag_of_a_type_1_or_type_3_ie_is_its_bit() {
    for octet in 0..=u8::MAX {
        // Bit 1 alone: SCMR, SSC1, APSI, APSR, ACK, RAAI, N5GC, NSSCI, MPSI, SAI
        assert_eq!(
            AdditionalConfigurationIndication::new(octet).scmr(),
            bit(octet, 1)
        );
        assert_eq!(
            AlwaysOnPduSessionIndication::new(octet).apsi(),
            bit(octet, 1)
        );
        assert_eq!(
            AlwaysOnPduSessionRequested::new(octet).apsr(),
            bit(octet, 1)
        );
        assert_eq!(
            ConfigurationUpdateIndication::new(octet).ack(),
            bit(octet, 1)
        );
        assert_eq!(MicoIndication::new(octet).raai(), bit(octet, 1));
        assert_eq!(N5gcIndication::new(octet).n5gc(), bit(octet, 1));
        assert_eq!(SmsIndication::new(octet).sai(), bit(octet, 1));
        let modes = AllowedSscMode::new(octet);
        let read = (modes.ssc1(), modes.ssc2(), modes.ssc3());
        assert_eq!(
            read,
            (bit(octet, 1), bit(octet, 2), bit(octet, 3)),
            "{octet}"
        );
        let slicing = NetworkSlicingIndication::new(octet);
        assert_eq!(
            (slicing.nssci(), slicing.dcni()),
            (bit(octet, 1), bit(octet, 2))
        );
        let priority = PriorityIndicator::new(octet);
        assert_eq!(
            (priority.mpsi(), priority.mcsi()),
            (bit(octet, 1), bit(octet, 2))
        );
        let valid = (
            priority.access_identity_1_valid(),
            priority.access_identity_2_valid(),
        );
        assert_eq!(valid, (bit(octet, 1), bit(octet, 2)));
        // A value of octets: its first octet, and none without it
        let usage = UeUsageSetting::new(vec![octet]);
        assert_eq!(usage.data_centric(), bit(octet, 1));
        let security = Additional5gSecurityInformation::new(vec![octet]);
        assert_eq!(
            (security.hdp(), security.rinmr()),
            (bit(octet, 1), bit(octet, 2))
        );
        let congestion = GsmCongestionReAttemptIndicator::new(vec![octet]);
        assert_eq!(
            (congestion.abo(), congestion.catbo()),
            (bit(octet, 1), bit(octet, 2))
        );
        let support = GsmNetworkFeatureSupport::new(vec![octet]);
        assert_eq!(
            (support.ept_s1(), support.naps()),
            (bit(octet, 1), bit(octet, 2))
        );
    }
    assert!(!UeUsageSetting::new(vec![]).data_centric());
    let security = Additional5gSecurityInformation::new(vec![]);
    assert!(!security.hdp() && !security.rinmr());
    let congestion = GsmCongestionReAttemptIndicator::new(vec![]);
    assert!(!congestion.abo() && !congestion.catbo());
    let support = GsmNetworkFeatureSupport::new(vec![]);
    assert!(!support.ept_s1() && !support.naps());
}

#[test]
fn a_field_of_a_few_bits_is_read_from_its_bits() {
    for octet in 0..=u8::MAX {
        assert_eq!(SscMode::new(octet).mode_raw(), octet & 0x07);
        assert_eq!(PduSessionType::new(octet).session_type_raw(), octet & 0x07);
        assert_eq!(AccessType::new(octet).access_type_raw(), octet & 0x03);
        let service = ControlPlaneServiceType::new(octet);
        assert_eq!(service.service_type_raw(), octet & 0x07);
        assert_eq!(MaPduSessionInformation::new(octet).info_raw(), octet & 0x0f);
        let mode = NssaiInclusionMode::new(octet).mode();
        assert_eq!(mode, NssaiInclusionModeValue::received(octet & 0x03));
        let drx = DrxParameters::new(vec![octet]);
        assert_eq!(drx.drx_value_raw(), Some(octet & 0x0f));
        assert_eq!(Rsn::new(vec![octet]).rsn_raw(), octet);
        assert_eq!(GmmCause::new(octet).value, octet);
        assert_eq!(GsmCause::new(octet).value, octet);
        // The request type, of three bits (Table 9.11.4.6.1)
        let request = RequestType::new(octet);
        let value = octet & 0x07;
        assert_eq!(request.is_initial(), value <= 1, "{octet}");
        assert_eq!(request.is_existing(), value == 2, "{octet}");
        assert_eq!(request.is_emergency(), matches!(value, 3 | 4), "{octet}");
        // The type of identity asked for, of which 000 is none
        let asked = IdentityType::new(octet).identity_type_strict();
        assert_eq!(
            asked.map(|kind| kind as u8),
            (value != 0).then_some(value),
            "{octet}"
        );
        // A payload container type of a defined value, with its spare bits 8 to 5
        // clear (TS 24.501 §9.11.3.40)
        let defined =
            octet & 0xf0 == 0 && PayloadContainerKind::try_from(octet & 0x0F).ok().is_some();
        let container = PayloadContainerType::new(octet);
        assert_eq!(container.is_well_formed(), defined, "{octet}");
    }
    assert_eq!(DrxParameters::new(vec![]).drx_value_raw(), None);
    assert_eq!(Rsn::new(vec![]).rsn_raw(), 0);
    let abba = Abba::new(vec![0x00, 0x00, 0x01]);
    assert_eq!(abba.abba(), [0x00, 0x00, 0x01]);
}

#[test]
fn a_setter_writes_the_bits_of_its_field_and_leaves_the_others() {
    for octet in 0..=u8::MAX {
        for kind in [
            PayloadContainerKind::N1SmInformation,
            PayloadContainerKind::Sms,
        ] {
            let mut container = PayloadContainerType::new(octet);
            container.set_kind(kind);
            assert_eq!(container.value, octet & 0xf0 | kind as u8, "{octet}");
        }
        for info in [
            MaPduSessionInfoValue::NoAdditionalInformation,
            MaPduSessionInfoValue::NetworkUpgradeAllowed,
        ] {
            let mut information = MaPduSessionInformation::new(octet);
            information.set_info(info);
            assert_eq!(information.value, octet & 0xf0 | info as u8, "{octet}");
        }
        for mode in [NssaiInclusionModeValue::A, NssaiInclusionModeValue::D] {
            let mut inclusion = NssaiInclusionMode::new(octet);
            inclusion.set_mode(mode);
            assert_eq!(inclusion.value, octet & 0xfc | mode as u8, "{octet}");
        }
        for service in [
            ControlPlaneServiceTypeValue::MobileOriginatingRequest,
            ControlPlaneServiceTypeValue::EmergencyServicesFallback,
        ] {
            let mut written = ControlPlaneServiceType::new(octet);
            written.set_service_type(service);
            assert_eq!(written.value, octet & 0xf8 | service as u8, "{octet}");
        }
        for asked in [MobileIdentityType5gs::Suci, MobileIdentityType5gs::Imeisv] {
            let mut written = IdentityType::new(octet);
            written.set_identity_type(asked).unwrap();
            assert_eq!(written.value, octet & 0xf8 | asked as u8, "{octet}");
        }
    }
    let n1 = PayloadContainerType::new(0x01);
    assert!(n1.is_n1_sm() && !PayloadContainerType::new(0x02).is_n1_sm());
}

#[test]
fn a_constructor_of_flags_sets_the_bit_of_each() {
    // 5GMM capability, octet 3: SGC, 5G-IPHC-CP CIoT, N3 data, 5G-CP CIoT, RestrictEC,
    // LPP, HO attach and S1 mode, from bit 8 to bit 1
    for (at, octet) in [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01]
        .into_iter()
        .enumerate()
    {
        let flags: Vec<bool> = (0..8).map(|flag| flag == at).collect();
        let capability = GmmCapability::from_flags(
            flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], flags[6], flags[7],
        );
        assert_eq!(capability.value, [octet], "{at}");
    }
    let all = GmmCapability::from_flags(true, true, true, true, true, true, true, true);
    assert_eq!(all.value, [0xff]);
    // Re-attempt indicator: EPLMNC in bit 2 and RATC in bit 1
    assert_eq!(ReAttemptIndicator::from_flags(true, false).value, [0x02]);
    assert_eq!(ReAttemptIndicator::from_flags(false, true).value, [0x01]);
    assert_eq!(ReAttemptIndicator::from_flags(true, true).value, [0x03]);
    // Priority indicator: MPSI in bit 1 and MCSI in bit 2
    assert_eq!(PriorityIndicator::from_flags(true, true).value, 0x03);
    assert_eq!(PriorityIndicator::from_flags(false, true).value, 0x02);
    // Allowed SSC mode: SSC1 to SSC3 in bits 1 to 3
    assert_eq!(AllowedSscMode::from_modes(true, true, true).value, 0x07);
    assert_eq!(AllowedSscMode::from_modes(false, true, false).value, 0x02);
    assert_eq!(AllowedSscMode::from_modes(false, false, true).value, 0x04);
}

#[test]
fn a_t3512_value_is_a_unit_and_a_number_of_it() {
    // GPRS timer 3 (TS 24.008 §10.5.7.4a): the unit in bits 8 to 6, the value in bits
    // 5 to 1; the network reads unit 110 as 1 hour (Table 10.5.163a NOTE 1)
    let seconds = [600, 3_600, 36_000, 2, 30, 60, 3_600];
    for octet in 0..=u8::MAX {
        let t3512 = T3512Value::new(vec![octet]);
        let (unit, value) = (octet >> 5, octet & 0x1f);
        assert_eq!(
            t3512.unit(),
            Some(GprsTimer3Unit::received(unit & 0x07)),
            "{octet}"
        );
        assert_eq!(t3512.timer_value(), Some(value), "{octet}");
        let read = match seconds.get(usize::from(unit)) {
            Some(step) => GprsTimerValue::Seconds(step * u64::from(value)),
            None => GprsTimerValue::Deactivated,
        };
        assert_eq!(t3512.value_for_network(), Some(read), "{octet}");
        assert!(t3512.is_well_formed());
    }
    let none = T3512Value::new(vec![]);
    assert_eq!(
        (none.unit(), none.timer_value(), none.value_for_network()),
        (None, None, None)
    );
    assert!(!none.is_well_formed() && !T3512Value::new(vec![0x21, 0x00]).is_well_formed());
    // A duration that no other unit codes takes units of 320 hours, up to 31 of them
    let long = 320 * 3_600;
    assert_eq!(T3512Value::from_seconds(long).unwrap().value, [0xc1]);
    assert_eq!(T3512Value::from_seconds(31 * long).unwrap().value, [0xdf]);
    assert!(T3512Value::from_seconds(long + 1).is_err());
    let error = T3512Value::from_seconds(32 * long).unwrap_err();
    assert_eq!(error.member, "seconds");
}

#[test]
fn a_ue_security_capability_supports_the_algorithm_of_each_bit() {
    // 5G-EA0 to 5G-EA7 in bits 8 to 1 of octet 3, 5G-IA in octet 4, EEA in octet 5
    // and EIA in octet 6 (TS 24.501 §9.11.3.54)
    for algorithm in 0..8 {
        let bit = 0x80 >> algorithm;
        let only = UeSecurityCapability::new(vec![bit, bit, bit, bit]);
        let all_but = UeSecurityCapability::new(vec![!bit, !bit, !bit, !bit]);
        for (capability, supported) in [(only, true), (all_but, false)] {
            assert_eq!(capability.supports_ea(algorithm), supported, "{algorithm}");
            assert_eq!(capability.supports_ia(algorithm), supported, "{algorithm}");
            assert_eq!(capability.supports_eea(algorithm), supported, "{algorithm}");
            assert_eq!(capability.supports_eia(algorithm), supported, "{algorithm}");
        }
    }
    // There is no algorithm 8, and the EPS octets are there or not
    let all = UeSecurityCapability::new(vec![0xff; 4]);
    assert!(!all.supports_ea(8) && !all.supports_ia(8));
    assert!(!all.supports_eea(8) && !all.supports_eia(8));
    assert!(all.has_eps_algorithms());
    assert!(!UeSecurityCapability::new(vec![0xff; 2]).has_eps_algorithms());
}

#[test]
fn the_rates_and_the_number_of_packet_filters_are_their_octets() {
    // Integrity protection maximum data rate (TS 24.501 §9.11.4.7): uplink in octet
    // 2, downlink in octet 3, and a reserved code read as 64 kbps
    for (ul, dl) in [
        (MaxDataRate::Null, MaxDataRate::FullRate),
        (MaxDataRate::FullRate, MaxDataRate::Null),
        (MaxDataRate::Kbps64, MaxDataRate::Null),
    ] {
        let rate = IntegrityProtectionMaximumDataRate::from_rates(ul, dl);
        assert_eq!(rate.value, u16::from(ul as u8) << 8 | u16::from(dl as u8));
        assert_eq!((rate.ul(), rate.dl()), (Some(ul), Some(dl)));
    }
    let reserved = IntegrityProtectionMaximumDataRate::new(0x02fe);
    let kbps64 = Some(MaxDataRate::Kbps64);
    assert_eq!((reserved.ul(), reserved.dl()), (kbps64, kbps64));
    assert_eq!(
        Some(MaxDataRate::received(0xff)),
        Some(MaxDataRate::FullRate)
    );
    // Maximum number of supported packet filters (§9.11.4.9): eleven bits from bit 8
    // of octet 3, 17 to 1024
    for count in [17, 18, 255, 1023, 1024] {
        let filters = MaximumNumberOfSupportedPacketFilters::from_max_filters(count).unwrap();
        assert_eq!(
            filters.value,
            [(count >> 3) as u8, ((count & 0x07) << 5) as u8]
        );
        assert_eq!(filters.max_filters(), count);
        assert!(filters.is_well_formed());
    }
    assert_eq!(
        MaximumNumberOfSupportedPacketFilters::new(vec![0x02]).max_filters(),
        0
    );
}

#[test]
fn the_5gs_network_feature_support_has_one_to_four_octets() {
    // Access identity 1 valid: MPSI, bit 8 of octet 3; access identity 2 valid: MCSI,
    // bit 2 of octet 4 (TS 24.501 §9.11.3.5)
    for octet in 0..=u8::MAX {
        let support = NetworkFeatureSupport::new(vec![octet, octet]);
        let valid = (
            support.access_identity_1_valid(),
            support.access_identity_2_valid(),
        );
        assert_eq!(valid, (bit(octet, 8), bit(octet, 2)), "{octet}");
    }
    for length in 0..=5 {
        let support = NetworkFeatureSupport::new(vec![0x00; length]);
        assert_eq!(
            support.is_well_formed(),
            (1..=4).contains(&length),
            "{length}"
        );
    }
}

#[test]
fn a_registration_type_and_a_de_registration_type_write_their_bits() {
    // 5GS registration type (TS 24.501 §9.11.3.7): FOR in bit 4, the type in bits 3
    // to 1; de-registration type (§9.11.3.20): switch off in bit 4, re-registration
    // required in bit 3, the access type in bits 2 to 1
    for octet in 0..=u8::MAX {
        let registration = RegistrationType::new(octet);
        let mut written = registration;
        written.set_registration_type(RegistrationTypeValue::EmergencyRegistration);
        assert_eq!(written.value, octet & 0xf8 | 0x04, "{octet}");
        let mut follow_on = registration;
        follow_on.set_follow_on_request(true);
        assert_eq!(follow_on.value, octet | 0x08);
        let mut no_follow_on = registration;
        no_follow_on.set_follow_on_request(false);
        assert_eq!(no_follow_on.value, octet & !0x08);
        let deregistration = DeRegistrationType::new(octet);
        assert_eq!(deregistration.access_type_raw(), octet & 0x03, "{octet}");
        let mut required = deregistration;
        required.set_re_registration_required(true);
        assert_eq!(required.value, octet | 0x04, "{octet}");
        let mut not_required = deregistration;
        not_required.set_re_registration_required(false);
        assert_eq!(not_required.value, octet & !0x04, "{octet}");
    }
}
