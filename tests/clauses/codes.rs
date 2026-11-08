//! The codes of a field of a few bits, as their tables give them (TS 24.501): a
//! receiver reads a value that the table leaves unused as the clause says, and the
//! strict reader, which a sender's check takes, refuses it.

use oxirush_nas::nas_5gs::{
    AtsssLowLayerFunctionality, ControlPlaneServiceType, DeregistrationAccessType, DrxValue,
    EapCode, EmergencyFallbackSupport, EmergencyServiceSupport, EthHdrCompCidLen,
    MaPduSessionInfoValue, MaxDataRate, NasNid, NbN1DrxValue, NssaiInclusionModeValue,
    PayloadContainerKind, PduSessionTypeValue, QosFlowOpCode, QosPacketFilterDirection,
    QosRuleOpCode, RegistrationResult, RegistrationType, RejectedNssaiCause, RequestTypeValue,
    RestrictionOnEnhancedCoverage, RsnValue, ServiceLevelAaResponseC2AuthorizationResult,
    ServiceLevelAaResponseResult, ServiceLevelAaServerAddressType, ServiceType, SessionAmbrUnit,
    SscModeValue,
};

#[test]
fn a_unit_of_the_session_ambr_is_one_of_the_25_steps_of_table_9_11_4_14_1() {
    let units = [
        SessionAmbrUnit::NotUsed,
        SessionAmbrUnit::Kbps1,
        SessionAmbrUnit::Kbps4,
        SessionAmbrUnit::Kbps16,
        SessionAmbrUnit::Kbps64,
        SessionAmbrUnit::Kbps256,
        SessionAmbrUnit::Mbps1,
        SessionAmbrUnit::Mbps4,
        SessionAmbrUnit::Mbps16,
        SessionAmbrUnit::Mbps64,
        SessionAmbrUnit::Mbps256,
        SessionAmbrUnit::Gbps1,
        SessionAmbrUnit::Gbps4,
        SessionAmbrUnit::Gbps16,
        SessionAmbrUnit::Gbps64,
        SessionAmbrUnit::Gbps256,
        SessionAmbrUnit::Tbps1,
        SessionAmbrUnit::Tbps4,
        SessionAmbrUnit::Tbps16,
        SessionAmbrUnit::Tbps64,
        SessionAmbrUnit::Tbps256,
        SessionAmbrUnit::Pbps1,
        SessionAmbrUnit::Pbps4,
        SessionAmbrUnit::Pbps16,
        SessionAmbrUnit::Pbps64,
        SessionAmbrUnit::Pbps256,
    ];
    for (code, unit) in units.into_iter().enumerate() {
        assert_eq!(
            SessionAmbrUnit::try_from(code as u8).ok(),
            Some(unit),
            "{code}"
        );
    }
    // "Other values shall be interpreted as multiples of 256 Pbps"
    for code in [0x1a, 0x80, 0xff] {
        assert_eq!(SessionAmbrUnit::try_from(code).ok(), None, "{code}");
        assert_eq!(
            SessionAmbrUnit::received(code),
            Some(SessionAmbrUnit::Pbps256)
        );
    }
}

#[test]
fn a_drx_value_is_a_cycle_of_its_table_or_not_specified() {
    // Table 9.11.3.2A.1: the cycles 32 to 256, the other codes not specified
    let cycles = [
        DrxValue::NotSpecified,
        DrxValue::Cycle32,
        DrxValue::Cycle64,
        DrxValue::Cycle128,
        DrxValue::Cycle256,
    ];
    for (code, cycle) in cycles.into_iter().enumerate() {
        assert_eq!(
            DrxValue::try_from((code as u8) & 0x0F).ok(),
            Some(cycle),
            "{code}"
        );
    }
    for code in 5..16 {
        assert_eq!(DrxValue::try_from(code & 0x0F).ok(), None, "{code}");
        assert_eq!(
            Some(DrxValue::received(code & 0x0F)),
            Some(DrxValue::NotSpecified),
            "{code}"
        );
    }
    // Table 9.11.3.73.1: T of 32 to 512 and 1024, with 0110 among the other codes
    let cycles = [
        (0x0, NbN1DrxValue::NotSpecified),
        (0x1, NbN1DrxValue::T32),
        (0x2, NbN1DrxValue::T64),
        (0x3, NbN1DrxValue::T128),
        (0x4, NbN1DrxValue::T256),
        (0x5, NbN1DrxValue::T512),
        (0x7, NbN1DrxValue::T1024),
    ];
    for (code, cycle) in cycles {
        assert_eq!(
            NbN1DrxValue::try_from(code & 0x0F).ok(),
            Some(cycle),
            "{code}"
        );
        assert_eq!(
            Some(NbN1DrxValue::received(code & 0x0F)),
            Some(cycle),
            "{code}"
        );
    }
    for code in [0x6, 0x8, 0xf] {
        assert_eq!(NbN1DrxValue::try_from(code & 0x0F).ok(), None, "{code}");
        assert_eq!(
            Some(NbN1DrxValue::received(code & 0x0F)),
            Some(NbN1DrxValue::NotSpecified)
        );
    }
}

#[test]
fn a_cid_length_of_11_is_read_as_7_bits() {
    // Figure 9.11.4.28.1: CID Length in the bits 2 and 1
    let lengths = [
        (0, EthHdrCompCidLen::NotUsed),
        (1, EthHdrCompCidLen::SevenBits),
        (2, EthHdrCompCidLen::FifteenBits),
    ];
    for (code, length) in lengths {
        assert_eq!(
            EthHdrCompCidLen::try_from(code & 0x03).ok(),
            Some(length),
            "{code}"
        );
        assert_eq!(
            Some(EthHdrCompCidLen::received(code & 0x03)),
            Some(length),
            "{code}"
        );
    }
    assert_eq!(EthHdrCompCidLen::try_from(3).ok(), None);
    assert_eq!(
        Some(EthHdrCompCidLen::received(3)),
        Some(EthHdrCompCidLen::SevenBits)
    );
}

#[test]
fn a_pdu_session_type_is_a_value_of_table_9_11_4_11_1() {
    for code in 0..=u8::MAX {
        let value = code & 0x07;
        let strict = PduSessionTypeValue::try_from(code & 0x07)
            .ok()
            .map(|kind| kind as u8);
        assert_eq!(strict, (1..=5).contains(&value).then_some(value), "{code}");
        // "All other values are unused and shall be interpreted as IPv4v6", 111 reserved
        let received = PduSessionTypeValue::received(code & 0x07).map(|kind| kind as u8);
        let expected = match value {
            0 | 6 => Some(3),
            7 => None,
            value => Some(value),
        };
        assert_eq!(received, expected, "{code}");
    }
    let names = [
        (PduSessionTypeValue::Ipv4, "IPV4"),
        (PduSessionTypeValue::Ipv6, "IPV6"),
        (PduSessionTypeValue::Ipv4v6, "IPV4V6"),
        (PduSessionTypeValue::Unstructured, "UNSTRUCTURED"),
        (PduSessionTypeValue::Ethernet, "ETHERNET"),
    ];
    for (kind, name) in names {
        assert_eq!(kind.sbi_str(), name);
    }
}

#[test]
fn a_service_type_is_a_value_of_table_9_11_3_50_1() {
    for code in 0..=u8::MAX {
        let value = code & 0x0f;
        let strict = ServiceType::try_from(code & 0x0f)
            .ok()
            .map(|kind| kind as u8);
        assert_eq!(strict, (value <= 6).then_some(value), "{code}");
        // 0111 and 1000 are read as signalling, 1001 to 1011 as data, by the network
        let received = ServiceType::received(code & 0x0f).map(|kind| kind as u8);
        let expected = match value {
            0..=6 => Some(value),
            7 | 8 => Some(0),
            9..=11 => Some(1),
            _ => None,
        };
        assert_eq!(received, expected, "{code}");
        let control = ControlPlaneServiceType::try_from(code & 0x07)
            .ok()
            .map(|kind| kind as u8);
        assert_eq!(control, (code & 0x07 <= 3).then_some(code & 0x07), "{code}");
    }
}

#[test]
fn the_codes_of_eap_and_of_the_qos_operations_are_their_values() {
    for code in 0..=u8::MAX {
        // RFC 3748 and RFC 6696: request to finish
        let eap = EapCode::try_from(code).ok().map(|kind| kind as u8);
        assert_eq!(eap, (1..=6).contains(&code).then_some(code), "{code}");
        // Tables 9.11.4.13.1 and 9.11.4.12.1
        assert_eq!(
            QosRuleOpCode::received(code & 0x07) as u8,
            code & 0x07,
            "{code}"
        );
        let direction = QosPacketFilterDirection::received(code & 0x03) as u8;
        assert_eq!(direction, code & 0x03, "{code}");
        let flow = QosFlowOpCode::received(code) as u8;
        assert_eq!(
            flow,
            if (1..=3).contains(&code) { code } else { 0 },
            "{code}"
        );
    }
}

#[test]
fn a_nid_is_written_in_hexadecimal_digits_of_either_case() {
    let lower = NasNid::from_nid_value("0123456789ab").unwrap();
    let upper = NasNid::from_nid_value("0123456789AB").unwrap();
    assert_eq!(lower, upper);
    assert_eq!(upper.value, [0x10, 0x32, 0x54, 0x76, 0x98, 0xba]);
    assert_eq!(upper.nid_value(), "0123456789ab");
    assert!(NasNid::from_nid_value("0123456789ag").is_err());
}

/// Each code of a field of `mask` reads as the value at its place in `table`.
fn masked<T: PartialEq + core::fmt::Debug>(read: fn(u8) -> T, mask: u8, table: &[T]) {
    for code in 0..=mask {
        assert_eq!(read(code), table[usize::from(code)], "{code}");
    }
}

/// Each code that `table` has reads as its value, and any other as `other`.
fn listed<T: PartialEq + core::fmt::Debug>(read: fn(u8) -> T, table: &[(u8, T)], other: T) {
    for code in 0..=u8::MAX {
        let expected = table.iter().find(|(listed, _)| *listed == code);
        assert_eq!(
            &read(code),
            expected.map_or(&other, |(_, value)| value),
            "{code}"
        );
    }
}

/// The codes of the fields of the 5GS IEs, as their tables give them: the strict reader
/// takes the values of the table alone, and the receiver reads the others as the clause
/// says.
#[test]
fn each_code_of_a_5gs_field_reads_as_its_table_says() {
    masked(
        |code| PayloadContainerKind::try_from(code).ok(),
        0x0f,
        &[
            None,
            Some(PayloadContainerKind::N1SmInformation),
            Some(PayloadContainerKind::Sms),
            Some(PayloadContainerKind::LtePp),
            Some(PayloadContainerKind::SorTransparentContainer),
            Some(PayloadContainerKind::UePolicy),
            Some(PayloadContainerKind::UeParametersUpdate),
            Some(PayloadContainerKind::LocationServices),
            Some(PayloadContainerKind::CIoT),
            Some(PayloadContainerKind::ServiceLevelAaContainer),
            Some(PayloadContainerKind::EventNotification),
            Some(PayloadContainerKind::UppCmiContainer),
            Some(PayloadContainerKind::SlppMessageContainer),
            None,
            None,
            Some(PayloadContainerKind::MultiplePayloads),
        ],
    );
    masked(
        RequestTypeValue::received,
        0x07,
        &[
            Some(RequestTypeValue::InitialRequest),
            Some(RequestTypeValue::InitialRequest),
            Some(RequestTypeValue::ExistingPduSession),
            Some(RequestTypeValue::InitialEmergencyRequest),
            Some(RequestTypeValue::ExistingEmergencyPduSession),
            Some(RequestTypeValue::ModificationRequest),
            Some(RequestTypeValue::MaPduRequest),
            None,
        ],
    );
    masked(
        |code| RequestTypeValue::try_from(code).ok(),
        0x07,
        &[
            None,
            Some(RequestTypeValue::InitialRequest),
            Some(RequestTypeValue::ExistingPduSession),
            Some(RequestTypeValue::InitialEmergencyRequest),
            Some(RequestTypeValue::ExistingEmergencyPduSession),
            Some(RequestTypeValue::ModificationRequest),
            Some(RequestTypeValue::MaPduRequest),
            None,
        ],
    );
    masked(
        SscModeValue::received,
        0x07,
        &[
            None,
            Some(SscModeValue::Ssc1),
            Some(SscModeValue::Ssc2),
            Some(SscModeValue::Ssc3),
            Some(SscModeValue::Ssc1),
            Some(SscModeValue::Ssc2),
            Some(SscModeValue::Ssc3),
            None,
        ],
    );
    masked(
        |code| SscModeValue::try_from(code).ok(),
        0x07,
        &[
            None,
            Some(SscModeValue::Ssc1),
            Some(SscModeValue::Ssc2),
            Some(SscModeValue::Ssc3),
            None,
            None,
            None,
            None,
        ],
    );
    masked(
        NssaiInclusionModeValue::received,
        0x03,
        &[
            NssaiInclusionModeValue::A,
            NssaiInclusionModeValue::B,
            NssaiInclusionModeValue::C,
            NssaiInclusionModeValue::D,
        ],
    );
    masked(
        RegistrationResult::received,
        0x07,
        &[
            Some(RegistrationResult::ThreeGppAccess),
            Some(RegistrationResult::ThreeGppAccess),
            Some(RegistrationResult::Non3GppAccess),
            Some(RegistrationResult::ThreeGppAccessAndNon3GppAccess),
            Some(RegistrationResult::ThreeGppAccess),
            Some(RegistrationResult::ThreeGppAccess),
            Some(RegistrationResult::ThreeGppAccess),
            None,
        ],
    );
    masked(
        |code| RegistrationResult::try_from(code).ok(),
        0x07,
        &[
            None,
            Some(RegistrationResult::ThreeGppAccess),
            Some(RegistrationResult::Non3GppAccess),
            Some(RegistrationResult::ThreeGppAccessAndNon3GppAccess),
            None,
            None,
            None,
            None,
        ],
    );
    listed(
        |code| MaxDataRate::try_from(code).ok(),
        &[
            (0x00, Some(MaxDataRate::Kbps64)),
            (0x01, Some(MaxDataRate::Null)),
            (0xff, Some(MaxDataRate::FullRate)),
        ],
        None,
    );
    masked(
        |code| DeregistrationAccessType::try_from(code).ok(),
        0x03,
        &[
            None,
            Some(DeregistrationAccessType::ThreeGppAccess),
            Some(DeregistrationAccessType::Non3GppAccess),
            Some(DeregistrationAccessType::ThreeGppAccessAndNon3GppAccess),
        ],
    );
    masked(
        |code| EmergencyServiceSupport::try_from(code).ok(),
        0x03,
        &[
            Some(EmergencyServiceSupport::NotSupported),
            Some(EmergencyServiceSupport::NrOnly),
            Some(EmergencyServiceSupport::EutraOnly),
            Some(EmergencyServiceSupport::NrAndEutra),
        ],
    );
    masked(
        |code| EmergencyFallbackSupport::try_from(code).ok(),
        0x03,
        &[
            Some(EmergencyFallbackSupport::NotSupported),
            Some(EmergencyFallbackSupport::NrOnly),
            Some(EmergencyFallbackSupport::EutraOnly),
            Some(EmergencyFallbackSupport::NrAndEutra),
        ],
    );
    masked(
        |code| RestrictionOnEnhancedCoverage::try_from(code).ok(),
        0x03,
        &[
            Some(RestrictionOnEnhancedCoverage::NotRestricted),
            Some(RestrictionOnEnhancedCoverage::Restricted),
            Some(RestrictionOnEnhancedCoverage::CeModeBRestricted),
            Some(RestrictionOnEnhancedCoverage::Reserved),
        ],
    );
    masked(
        |code| MaPduSessionInfoValue::try_from(code).ok(),
        0x0f,
        &[
            Some(MaPduSessionInfoValue::NoAdditionalInformation),
            Some(MaPduSessionInfoValue::NetworkUpgradeAllowed),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ],
    );
    masked(
        |code| Some(DrxValue::received(code)),
        0x0f,
        &[
            Some(DrxValue::NotSpecified),
            Some(DrxValue::Cycle32),
            Some(DrxValue::Cycle64),
            Some(DrxValue::Cycle128),
            Some(DrxValue::Cycle256),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
            Some(DrxValue::NotSpecified),
        ],
    );
    masked(
        |code| DrxValue::try_from(code).ok(),
        0x0f,
        &[
            Some(DrxValue::NotSpecified),
            Some(DrxValue::Cycle32),
            Some(DrxValue::Cycle64),
            Some(DrxValue::Cycle128),
            Some(DrxValue::Cycle256),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ],
    );
    listed(
        |code| AtsssLowLayerFunctionality::try_from(code).ok(),
        &[
            (0x00, Some(AtsssLowLayerFunctionality::NotSupported)),
            (0x01, Some(AtsssLowLayerFunctionality::ActiveStandbyOnly)),
            (0x02, Some(AtsssLowLayerFunctionality::AnySteering)),
        ],
        None,
    );
    listed(
        RegistrationType::received,
        &[
            (0x00, Some(RegistrationType::InitialRegistration)),
            (0x01, Some(RegistrationType::InitialRegistration)),
            (0x02, Some(RegistrationType::MobilityRegistrationUpdating)),
            (0x03, Some(RegistrationType::PeriodicRegistrationUpdating)),
            (0x04, Some(RegistrationType::EmergencyRegistration)),
            (0x05, Some(RegistrationType::SnpnOnboardingRegistration)),
            (
                0x06,
                Some(RegistrationType::DisasterRoamingMobilityRegistrationUpdating),
            ),
            (
                0x07,
                Some(RegistrationType::DisasterRoamingInitialRegistration),
            ),
        ],
        None,
    );
    listed(
        |code| RegistrationType::try_from(code).ok(),
        &[
            (0x01, Some(RegistrationType::InitialRegistration)),
            (0x02, Some(RegistrationType::MobilityRegistrationUpdating)),
            (0x03, Some(RegistrationType::PeriodicRegistrationUpdating)),
            (0x04, Some(RegistrationType::EmergencyRegistration)),
            (0x05, Some(RegistrationType::SnpnOnboardingRegistration)),
            (
                0x06,
                Some(RegistrationType::DisasterRoamingMobilityRegistrationUpdating),
            ),
            (
                0x07,
                Some(RegistrationType::DisasterRoamingInitialRegistration),
            ),
        ],
        None,
    );
    listed(
        |code| RejectedNssaiCause::try_from(code).ok(),
        &[
            (0x00, Some(RejectedNssaiCause::NotAvailableInPlmnOrSnpn)),
            (
                0x01,
                Some(RejectedNssaiCause::NotAvailableInRegistrationArea),
            ),
            (
                0x02,
                Some(RejectedNssaiCause::AuthenticationOrAuthorizationFailedOrRevoked),
            ),
        ],
        None,
    );
    listed(
        |code| RsnValue::try_from(code).ok(),
        &[(0x00, Some(RsnValue::V1)), (0x01, Some(RsnValue::V2))],
        None,
    );
    listed(
        |code| ServiceLevelAaServerAddressType::try_from(code).ok(),
        &[
            (0x01, Some(ServiceLevelAaServerAddressType::Ipv4)),
            (0x02, Some(ServiceLevelAaServerAddressType::Ipv6)),
            (0x03, Some(ServiceLevelAaServerAddressType::Ipv4v6)),
            (0x04, Some(ServiceLevelAaServerAddressType::Fqdn)),
        ],
        None,
    );
    masked(
        ServiceLevelAaResponseResult::received,
        0x03,
        &[
            ServiceLevelAaResponseResult::NoInformation,
            ServiceLevelAaResponseResult::Successful,
            ServiceLevelAaResponseResult::NotSuccessfulOrRevoked,
            ServiceLevelAaResponseResult::Reserved,
        ],
    );
    masked(
        ServiceLevelAaResponseC2AuthorizationResult::received,
        0x03,
        &[
            ServiceLevelAaResponseC2AuthorizationResult::NoInformation,
            ServiceLevelAaResponseC2AuthorizationResult::Successful,
            ServiceLevelAaResponseC2AuthorizationResult::NotSuccessfulOrRevoked,
            ServiceLevelAaResponseC2AuthorizationResult::Reserved,
        ],
    );
    // A rate that the table does not have is read as 64 kbps
    for code in 0..=u8::MAX {
        let rate = MaxDataRate::try_from(code)
            .ok()
            .unwrap_or(MaxDataRate::Kbps64);
        assert_eq!(Some(MaxDataRate::received(code)), Some(rate), "{code}");
    }
}
