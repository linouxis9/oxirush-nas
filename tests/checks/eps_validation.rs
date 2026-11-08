//! The findings of `validate()` for the EPS messages: each rule of a message
//! of TS 24.301 chapter 8, and of its IE types, with the IEs that a receiver
//! takes or ignores.

use oxirush_nas::Direction;
use oxirush_nas::Severity;
use oxirush_nas::nas_eps::*;
use oxirush_nas::{Error, Validate, ValidationError};

fn octets(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

/// The fields that a list of findings names.
fn fields(errors: &[ValidationError]) -> Vec<&'static str> {
    errors.iter().map(|error| error.field).collect()
}

/// Whether a finding names `field`.
fn names(errors: &[ValidationError], field: &str) -> bool {
    errors.iter().any(|error| error.field == field)
}

/// The message of the finding that names `field`.
fn message(errors: &[ValidationError], field: &str) -> String {
    let finding = errors.iter().find(|error| error.field == field);
    finding
        .map(|error| error.message.clone())
        .unwrap_or_default()
}

/// A TFT that creates one filter of TCP, identifier 1, both directions.
fn tft() -> Vec<u8> {
    vec![0x21, 0x31, 0x00, 0x02, 0x30, 0x06]
}

/// A traffic flow aggregate that creates one filter of TCP, both directions.
fn tfa() -> Vec<u8> {
    vec![0x21, 0x30, 0x00, 0x02, 0x30, 0x06]
}

/// ATTACH REQUEST of an IMSI, EEA0 to EEA2 and EIA0 to EIA2, and a PDN
/// CONNECTIVITY REQUEST.
fn attach_request() -> AttachRequest {
    AttachRequest::new(
        EpsAttachType::new(1),
        KeySetIdentifier::new(7),
        EpsMobileIdentity::from_imsi("001010123456789").unwrap(),
        UeNetworkCapability::new(vec![0xe0, 0xe0]),
        EsmMessageContainer::new(vec![0x02, 0x01, 0xd0, 0x11]),
    )
}

/// SECURITY MODE COMMAND of the algorithms `algorithms`, KSI 0.
fn security_mode_command(algorithms: u8) -> SecurityModeCommand {
    SecurityModeCommand::new(
        SecurityAlgorithms::new(algorithms),
        KeySetIdentifier::new(0),
        UeSecurityCapability::new(vec![0xe0, 0xe0]),
    )
}

fn syntax_error(error: Error) -> bool {
    matches!(error, Error::InvalidMandatoryIe { .. })
}

#[test]
fn a_mobile_identity_of_a_type_that_a_receiver_does_not_read_is_refused() {
    // IDENTITY RESPONSE with a TMSI, and with a TMGI, which TS 24.301 does
    // not use (TS 24.008 §10.5.1.4)
    assert!(Message::decode(&octets("075605f4c0000001")).is_ok());
    let tmgi = Message::decode(&octets("075603f50000")).unwrap_err();
    assert!(syntax_error(tmgi));
}

#[test]
fn the_esm_message_container_of_a_control_plane_service_request_is_read_by_its_length() {
    // Table 8.2.33.1 gives the ESM message container of a CONTROL PLANE
    // SERVICE REQUEST 3-n octets, no contents at least, and §7.5.2 has a
    // receiver diagnose nothing of it but its presence and its length:
    // contents that are no ESM message are read, as those of an ATTACH
    // COMPLETE are, and a sender is warned of them
    for contents in ["", "02", "0201", "0201d6"] {
        let length = format!("{:04x}", contents.len() / 2);
        let wire = octets(&format!("074d0078{length}{contents}"));
        let message = Message::decode(&wire).unwrap();
        let Message::Emm(_, EmmMessage::ControlPlaneServiceRequest(request)) = &message else {
            panic!("{message:?}")
        };
        let container = request.esm_message_container.as_ref();
        let value = container.map(|container| container.value.to_vec());
        assert_eq!(value, Some(octets(contents)));
        assert_eq!(message.encode().unwrap(), wire);
        let findings = message.validate();
        assert!(
            findings
                .iter()
                .all(|finding| finding.field == "esm_message_container"
                    && finding.severity == Severity::Warning),
            "{contents}: {findings:?}"
        );
    }
}

#[test]
fn the_ms_identity_of_an_accept_is_a_tmsi_or_the_imsi() {
    // §8.2.1.4 and §8.2.26.7: the MS identity of an ATTACH ACCEPT and of a
    // TRACKING AREA UPDATE ACCEPT assigns a new TMSI, or unassigns it with
    // the IMSI (TS 24.008 §10.5.1.4). An identity that a receiver ignores,
    // as an IMEISV of five octets or "no identity" with octets that are not
    // zeros, is one that a sender does not write, and nor is another type
    // of identity
    let attach = octets("07420121060002f839000100155201c101090908696e7465726e657405010a000001");
    let Ok(Message::Emm(_, EmmMessage::AttachAccept(attach))) = Message::decode(&attach) else {
        panic!("an ATTACH ACCEPT")
    };
    let update = TrackingAreaUpdateAccept::new(EpsUpdateResult::new(0));
    for (identity, sound) in [
        (MobileIdentity::from_tmsi(0x1234_5678), true),
        (MobileIdentity::from_imsi("001010123456789").unwrap(), true),
        (MobileIdentity::new(octets("93ffffff1e")), false),
        (MobileIdentity::new(octets("00ef2cefeffbef")), false),
        (
            MobileIdentity::from_imeisv("4901542032375183").unwrap(),
            false,
        ),
        // A TMSI whose spare half octet is not 1111
        (MobileIdentity::new(octets("0412345678")), false),
    ] {
        let attach = attach.clone().with_ms_identity(identity.clone()).validate();
        let update = update.clone().with_ms_identity(identity.clone()).validate();
        for errors in [attach, update] {
            assert_eq!(
                !names(&errors, "ms_identity"),
                sound,
                "{identity:?}: {errors:?}"
            );
        }
    }
}

/// ACTIVATE DEFAULT EPS BEARER CONTEXT REQUEST of EBI 5, PTI 1, QCI 9, the APN
/// "internet" and the PDN address `pdn`, then `optional`.
fn activate_default(pdn: &str, optional: &str) -> Result<Message, Error> {
    Message::decode(&octets(&format!(
        "5201c101090908696e7465726e6574{pdn}{optional}"
    )))
}

#[test]
fn a_pdn_address_has_the_octets_of_its_type() {
    // §9.9.4.9: an IPv4 address after the type 001, an interface identifier
    // of eight octets after the type 010
    assert!(activate_default("05010a000001", "").is_ok());
    assert!(activate_default("0902000000000000000a", "").is_ok());
    assert!(syntax_error(
        activate_default("05020a000001", "").unwrap_err()
    ));
}

#[test]
fn a_negotiated_qos_of_a_length_that_ts_24_008_does_not_give_is_ignored() {
    let negotiated = |optional: &str| {
        let message = activate_default("05010a000001", optional).unwrap();
        let Message::Esm(_, EsmMessage::ActivateDefaultEpsBearerContextRequest(request)) = message
        else {
            panic!()
        };
        request.negotiated_qos
    };
    // TS 24.008 §10.5.6.5: 3, 11, 12, 14, 16, 18 or 20 value octets
    assert!(negotiated("300c1b921f73964040734a404010").is_some());
    assert_eq!(negotiated("30041b921f73"), None);
}

#[test]
fn replayed_ue_security_capabilities_have_two_octets_or_four_and_more() {
    // §9.9.3.36: octets 3 and 4, then the UMTS and GPRS octets 5 to 7
    assert!(Message::decode(&octets("075d020002e0e0")).is_ok());
    assert!(Message::decode(&octets("075d020004e0e0c040")).is_ok());
    assert!(syntax_error(
        Message::decode(&octets("075d020003e0e0c0")).unwrap_err()
    ));
}

#[test]
fn a_tai_list_of_a_reserved_type_is_refused() {
    // §9.9.3.33: the type of list 11 is reserved
    let accept = |tai_list: &str| {
        Message::decode(&octets(&format!(
            "07420121{tai_list}00155201c101090908696e7465726e657405010a000001"
        )))
    };
    assert!(accept("060002f8390001").is_ok());
    assert!(syntax_error(accept("066002f8390001").unwrap_err()));
}

#[test]
fn a_sender_writes_the_values_that_an_ie_type_has() {
    // §9.9.4.7A: the notification indicator 0x01, "paging for CS fallback"
    let notification = Notification::new(NotificationIndicator::new(vec![2]));
    assert_eq!(
        message(&notification.validate(), "notification_indicator"),
        "IE breaks a sender rule: the one octet 0x01, \"paging for CS fallback\""
    );
    assert!(
        Notification::new(NotificationIndicator::new(vec![1]))
            .validate()
            .is_empty()
    );
    // §9.9.3.58 and §9.9.3.59: the UE radio capability ID availability and request,
    // 0 or 1
    let mut request = attach_request();
    request.ue_radio_capability_id_availability =
        Some(UeRadioCapabilityIdAvailability::new(vec![1]));
    assert!(request.validate().is_empty(), "{:?}", request.validate());
    request.ue_radio_capability_id_availability =
        Some(UeRadioCapabilityIdAvailability::new(vec![2]));
    assert_eq!(
        message(&request.validate(), "ue_radio_capability_id_availability"),
        "IE breaks a sender rule: a first octet of 0 or 1"
    );
    let mut command = security_mode_command(0x02);
    command.ue_radio_capability_id_request = Some(UeRadioCapabilityIdRequest::new(vec![1]));
    assert!(!names(
        &command.validate(),
        "ue_radio_capability_id_request"
    ));
    command.ue_radio_capability_id_request = Some(UeRadioCapabilityIdRequest::new(vec![2]));
    assert_eq!(
        message(&command.validate(), "ue_radio_capability_id_request"),
        "IE breaks a sender rule: a first octet of 0 or 1"
    );
}

#[test]
fn an_eps_qos_has_maximum_bit_rates_that_are_not_both_zero() {
    // §9.9.4.3: 0 kbps in both maximum bit rates is a syntactical error
    let request = |eps_qos: Vec<u8>| {
        BearerResourceAllocationRequest::new(
            LinkedEpsBearerIdentity::new(5),
            TrafficFlowAggregateDescription::new(tfa()),
            EpsQualityOfService::new(eps_qos),
        )
        .validate()
    };
    assert_eq!(
        message(
            &request(vec![1, 0xff, 0xff, 0x40, 0x40]),
            "required_traffic_flow_qos"
        ),
        "IE breaks a sender rule: maximum bit rates that are not zero (TS 24.301 §9.9.4.3)"
    );
    assert!(
        message(
            &request(vec![1, 0x40, 0x40, 0x40]),
            "required_traffic_flow_qos"
        )
        .starts_with("IE breaks a sender rule: bit rates with extensions")
    );
}

#[test]
fn the_eps_qos_from_the_network_has_no_reserved_bit_rate() {
    // §9.9.4.3: octets 4 to 7 of 00000000 are reserved from the network
    let request = |eps_qos: Vec<u8>| {
        ActivateDedicatedEpsBearerContextRequest::new(
            LinkedEpsBearerIdentity::new(5),
            EpsQualityOfService::new(eps_qos),
            TrafficFlowTemplate::new(tft()),
        )
        .validate()
    };
    assert!(!names(&request(vec![1, 0x40, 0x40, 0x40, 0x40]), "eps_qos"));
    assert!(names(&request(vec![1, 0x40, 0x00, 0x40, 0x40]), "eps_qos"));
}

#[test]
fn a_disaster_plmn_goes_with_the_disaster_roaming_attach_alone() {
    // §8.2.4.29: the UE-determined PLMN with disaster condition is sent with
    // the EPS attach type "disaster roaming attach", 111
    let mut request = attach_request();
    request.ue_determined_plmn_with_disaster_condition =
        Some(PlmnIdentity::new(vec![0x02, 0xf8, 0x39]));
    let field = "ue_determined_plmn_with_disaster_condition";
    request.eps_attach_type = EpsAttachType::new(7);
    assert!(!names(&request.validate(), field));
    request.eps_attach_type = EpsAttachType::new(1);
    assert!(names(&request.validate(), field));
}

#[test]
fn an_auts_goes_with_the_synch_failure_alone() {
    // §8.2.5.2: the authentication failure parameter with cause #21
    let failure = AuthenticationFailure::new(EmmCause::new(21));
    assert!(names(
        &failure.validate(),
        "authentication_failure_parameter"
    ));
    let mut synch = failure.clone();
    synch.authentication_failure_parameter = Some(AuthenticationFailureParameter::new(vec![0; 14]));
    assert!(synch.validate().is_empty());
}

#[test]
fn a_detach_type_from_the_network_has_bit_4_spare() {
    // §9.9.3.7: bit 4 is the switch off of the UE alone
    let detach = DetachRequestUeTerminated::new(DetachType::new(0x09));
    assert!(names(&detach.validate(), "detach_type"));
    let detach = DetachRequestUeTerminated::new(DetachType::new(0x01));
    assert!(detach.validate().is_empty());
}

#[test]
fn an_extended_service_request_has_an_m_tmsi_and_a_csfb_response_to_a_terminating_call() {
    let request = |service_type: u8, m_tmsi: Vec<u8>| {
        ExtendedServiceRequest::new(
            ServiceType::new(service_type),
            KeySetIdentifier::new(0),
            MobileIdentity::new(m_tmsi),
        )
    };
    let tmsi = vec![0xf4, 1, 2, 3, 4];
    assert!(request(0, tmsi.clone()).validate().is_empty());
    // The M-TMSI as TS 24.008 §10.5.1.4 writes it, its first octet f4
    assert!(names(
        &request(0, vec![0x04, 1, 2, 3, 4]).validate(),
        "m_tmsi"
    ));
    // §8.2.15.2: a CSFB response answers a mobile terminating CS fallback
    let mut terminating = request(1, tmsi.clone());
    terminating.csfb_response = Some(CsfbResponse::new(1));
    assert!(!names(&terminating.validate(), "csfb_response"));
    let mut originating = request(0, tmsi);
    originating.csfb_response = Some(CsfbResponse::new(1));
    assert!(names(&originating.validate(), "csfb_response"));
}

#[test]
fn a_guti_reallocation_command_has_a_guti() {
    let guti = EpsMobileIdentity::new(octets("f602f839800110fedcba98"));
    assert!(GutiReallocationCommand::new(guti).validate().is_empty());
    // Eleven octets of the type of identity IMSI
    let imsi = EpsMobileIdentity::new(octets("f102f839800110fedcba98"));
    assert!(names(
        &GutiReallocationCommand::new(imsi).validate(),
        "guti"
    ));
}

#[test]
fn the_selected_algorithms_are_those_of_ts_33_401() {
    // EEA0 to EEA3 and EIA0 to EIA3 (TS 33.401 §5.1.3, §5.1.4)
    let field = "selected_nas_security_algorithms";
    let errors = |algorithms: u8| {
        security_mode_command(algorithms)
            .validate()
            .into_iter()
            .filter(|error| error.field == field)
            .map(|error| error.message)
            .collect::<Vec<_>>()
    };
    assert!(errors(0x33).is_empty());
    assert_eq!(
        errors(0x34),
        ["Selected EPS algorithm is not specified in TS 33.401"]
    );
    assert_eq!(
        errors(0x42),
        ["Selected EPS algorithm is not specified in TS 33.401"]
    );
}

#[test]
fn a_service_reject_for_cause_39_has_t3442() {
    // §8.2.24.2: T3442 with cause #39, CS service temporarily not available
    let reject = ServiceReject::new(EmmCause::new(39));
    assert!(names(&reject.validate(), "t3442_value"));
    let mut timed = reject.clone();
    timed.t3442_value = Some(GprsTimer::new(0x21));
    assert!(timed.validate().is_empty());
}

fn tracking_area_update_request(update_type: u8) -> TrackingAreaUpdateRequest {
    let mut request = TrackingAreaUpdateRequest::new(
        EpsUpdateType::new(update_type),
        KeySetIdentifier::new(0),
        EpsMobileIdentity::new(octets("f602f839800110fedcba98")),
    );
    request.old_guti_type = Some(GutiType::new(0));
    request
}

#[test]
fn a_tau_request_that_is_not_periodic_has_a_ue_network_capability() {
    // §8.2.29.7: the UE network capability is sent in a TAU that is not
    // periodic
    let field = "ue_network_capability";
    assert!(!names(&tracking_area_update_request(3).validate(), field));
    assert!(names(&tracking_area_update_request(0).validate(), field));
    let mut request = tracking_area_update_request(0);
    request.ue_network_capability = Some(UeNetworkCapability::new(vec![0xe0, 0xe0]));
    assert!(!names(&request.validate(), field));
}

#[test]
fn a_disaster_plmn_goes_with_the_disaster_roaming_update_alone() {
    let field = "ue_determined_plmn_with_disaster_condition";
    let plmn = Some(PlmnIdentity::new(vec![0x02, 0xf8, 0x39]));
    let mut disaster = tracking_area_update_request(6);
    disaster.ue_determined_plmn_with_disaster_condition = plmn.clone();
    assert!(!names(&disaster.validate(), field));
    let mut other = tracking_area_update_request(3);
    other.ue_determined_plmn_with_disaster_condition = plmn;
    assert!(names(&other.validate(), field));
}

#[test]
fn an_nb_s1_drx_parameter_is_not_sent_in_a_periodic_tau() {
    // §8.2.29.32
    let field = "drx_parameter_in_nb_s1_mode";
    assert!(!names(&tracking_area_update_request(3).validate(), field));
    let mut request = tracking_area_update_request(0);
    request.ue_network_capability = Some(UeNetworkCapability::new(vec![0xe0, 0xe0]));
    request.drx_parameter_in_nb_s1_mode = Some(NbS1DrxParameter::new(vec![0x01]));
    assert!(!names(&request.validate(), field));
    let mut periodic = tracking_area_update_request(3);
    periodic.drx_parameter_in_nb_s1_mode = Some(NbS1DrxParameter::new(vec![0x01]));
    assert!(names(&periodic.validate(), field));
}

/// The findings of an ESM message `$message` that has a PCO and an ePCO, each
/// of no configuration option, which TS 24.301 §9.9.4.26 gives one use alone.
macro_rules! with_both_options {
    ($message:expr) => {{
        let mut message = $message;
        message.protocol_configuration_options =
            Some(ProtocolConfigurationOptions::new(vec![0x80]));
        message.extended_protocol_configuration_options =
            Some(ExtendedProtocolConfigurationOptions::new(vec![0x80]));
        message.validate()
    }};
}

#[test]
fn an_esm_message_has_a_pco_or_an_epco() {
    let both = "extended_protocol_configuration_options";
    let cause = || EsmCause::new(31);
    assert!(names(
        &with_both_options!(ActivateDedicatedEpsBearerContextReject::new(cause())),
        both
    ));
    assert!(names(
        &with_both_options!(ActivateDefaultEpsBearerContextAccept::new()),
        both
    ));
    assert!(names(
        &with_both_options!(ActivateDefaultEpsBearerContextReject::new(cause())),
        both
    ));
    assert!(names(
        &with_both_options!(DeactivateEpsBearerContextAccept::new()),
        both
    ));
    assert!(names(
        &with_both_options!(ModifyEpsBearerContextAccept::new()),
        both
    ));
    assert!(names(
        &with_both_options!(ModifyEpsBearerContextReject::new(cause())),
        both
    ));
    assert!(names(
        &with_both_options!(PdnDisconnectReject::new(cause())),
        both
    ));
    assert!(names(
        &with_both_options!(PdnDisconnectRequest::new(LinkedEpsBearerIdentity::new(5))),
        both
    ));
    // and an ESM INFORMATION RESPONSE has one or the other (§8.3.14)
    let response = with_both_options!(EsmInformationResponse::new());
    assert_eq!(
        message(&response, "protocol_configuration_options"),
        "PCO and extended PCO are mutually exclusive"
    );
}

#[test]
fn an_extended_eps_qos_follows_an_eps_qos_at_its_maximum() {
    // §8.3.3.11, §8.3.8.6, §8.3.10.9, §8.3.18.15: the extended EPS QoS carries a
    // rate above those of an EPS QoS of 13 octets, its extended-2 octets
    let field = "extended_eps_qos";
    let extended = || {
        Some(ExtendedQualityOfService::new(vec![
            1, 0, 1, 0, 1, 1, 0, 1, 0, 1,
        ]))
    };
    let full = vec![
        1, 0xfe, 0xfe, 0xfe, 0xfe, 0xfa, 0xfa, 0xfa, 0xfa, 0xf6, 0xf6, 0xf6, 0xf6,
    ];
    let dedicated = |eps_qos: Vec<u8>, with: bool| {
        let mut request = ActivateDedicatedEpsBearerContextRequest::new(
            LinkedEpsBearerIdentity::new(5),
            EpsQualityOfService::new(eps_qos),
            TrafficFlowTemplate::new(tft()),
        );
        request.extended_eps_qos = if with { extended() } else { None };
        names(&request.validate(), field)
    };
    assert!(!dedicated(full.clone(), true));
    assert!(dedicated(vec![1], true));
    assert!(!dedicated(vec![1], false));
    let allocation = |eps_qos: Vec<u8>, with: bool| {
        let mut request = BearerResourceAllocationRequest::new(
            LinkedEpsBearerIdentity::new(5),
            TrafficFlowAggregateDescription::new(tfa()),
            EpsQualityOfService::new(eps_qos),
        );
        request.extended_eps_qos = if with { extended() } else { None };
        names(&request.validate(), field)
    };
    assert!(!allocation(full.clone(), true));
    assert!(allocation(vec![1], true));
    let modification = |eps_qos: Option<Vec<u8>>, with: bool| {
        let mut request = BearerResourceModificationRequest::new(
            LinkedEpsBearerIdentity::new(5),
            TrafficFlowAggregateDescription::new(tfa()),
        );
        request.required_traffic_flow_qos = eps_qos.map(EpsQualityOfService::new);
        request.extended_eps_qos = if with { extended() } else { None };
        names(&request.validate(), field)
    };
    assert!(!modification(Some(full.clone()), true));
    assert!(modification(Some(vec![1]), true));
    assert!(modification(None, true));
    assert!(!modification(None, false));
    let modify = |eps_qos: Option<Vec<u8>>, with: bool| {
        let mut request = ModifyEpsBearerContextRequest::new();
        request.new_eps_qos = eps_qos.map(EpsQualityOfService::new);
        request.extended_eps_qos = if with { extended() } else { None };
        names(&request.validate(), field)
    };
    assert!(!modify(Some(full), true));
    assert!(modify(Some(vec![1]), true));
    assert!(!modify(None, false));
}

#[test]
fn an_extended_apn_ambr_follows_an_apn_ambr_at_its_maximum() {
    // §8.3.6.17, §8.3.18.14: the extended APN-AMBR carries a rate above those
    // of an APN-AMBR of six octets, its extended-2 octets
    let field = "extended_apn_ambr";
    let extended = || {
        Some(ExtendedApnAggregateMaximumBitRate::new(vec![
            3, 0, 1, 3, 0, 1,
        ]))
    };
    let full = vec![0xfe, 0xfe, 0xfa, 0xfa, 0xfe, 0xfe];
    let default = |apn_ambr: Option<Vec<u8>>, with: bool| {
        let mut request = ActivateDefaultEpsBearerContextRequest::new(
            EpsQualityOfService::new(vec![9]),
            AccessPointName::new(octets("08696e7465726e6574")),
            PdnAddress::new(vec![1, 10, 0, 0, 1]),
        );
        request.apn_ambr = apn_ambr.map(ApnAggregateMaximumBitRate::new);
        request.extended_apn_ambr = if with { extended() } else { None };
        names(&request.validate(), field)
    };
    assert!(!default(Some(full.clone()), true));
    assert!(default(Some(vec![0x40, 0x40]), true));
    assert!(default(None, true));
    assert!(!default(None, false));
    let modify = |apn_ambr: Option<Vec<u8>>, with: bool| {
        let mut request = ModifyEpsBearerContextRequest::new();
        request.apn_ambr = apn_ambr.map(ApnAggregateMaximumBitRate::new);
        request.extended_apn_ambr = if with { extended() } else { None };
        names(&request.validate(), field)
    };
    assert!(!modify(Some(full), true));
    assert!(modify(Some(vec![0x40, 0x40]), true));
    assert!(!modify(None, false));
}

#[test]
fn a_re_attempt_indicator_goes_with_a_back_off_timer_and_not_with_cause_26() {
    // §8.3.7.4, §8.3.9.4, §8.3.19.4
    let field = "re_attempt_indicator";
    let indicator = || Some(ReAttemptIndicator::new(vec![0]));
    let timer = || Some(GprsTimer3::new(vec![0x21]));
    let allocation = |cause: u8| {
        let mut reject = BearerResourceAllocationReject::new(EsmCause::new(cause));
        reject.re_attempt_indicator = indicator();
        reject.back_off_timer_value = timer();
        names(&reject.validate(), field)
    };
    assert!(!allocation(30));
    assert!(allocation(26));
    let modification = |cause: u8| {
        let mut reject = BearerResourceModificationReject::new(EsmCause::new(cause));
        reject.re_attempt_indicator = indicator();
        reject.back_off_timer_value = timer();
        names(&reject.validate(), field)
    };
    assert!(!modification(30));
    assert!(modification(26));
    let connectivity = |cause: u8, with_timer: bool| {
        let mut reject = PdnConnectivityReject::new(EsmCause::new(cause));
        reject.re_attempt_indicator = indicator();
        reject.back_off_timer_value = if with_timer { timer() } else { None };
        names(&reject.validate(), field)
    };
    assert!(!connectivity(30, true));
    assert!(connectivity(26, true));
    assert!(connectivity(30, false));
    // Without a timer, for the causes of §6.5.1.4.3 that it is sent with
    assert!(!connectivity(50, false));
}

#[test]
fn a_back_off_timer_is_not_sent_with_cause_65() {
    // §8.3.7.3
    let field = "back_off_timer_value";
    let reject = |cause: u8, with_timer: bool| {
        let mut reject = BearerResourceAllocationReject::new(EsmCause::new(cause));
        reject.back_off_timer_value = with_timer.then(|| GprsTimer3::new(vec![0x21]));
        names(&reject.validate(), field)
    };
    assert!(reject(65, true));
    assert!(!reject(65, false));
    assert!(!reject(30, true));
}

#[test]
fn t3396_is_sent_with_cause_26() {
    // §8.3.12.3
    let field = "t3396_value";
    let request = |cause: u8, with_timer: bool| {
        let mut request = DeactivateEpsBearerContextRequest::new(EsmCause::new(cause));
        request.t3396_value = with_timer.then(|| GprsTimer3::new(vec![0x21]));
        names(&request.validate(), field)
    };
    assert!(!request(26, true));
    assert!(request(36, true));
    assert!(!request(36, false));
}

#[test]
fn a_service_request_has_its_security_header_type_and_a_native_ksi() {
    // §8.2.25: the security header type 1100 and a KSI of 0 to 6 in bits 8
    // to 6 of octet 2
    assert!(ServiceRequest::new(0x21, 0x1234).validate().is_empty());
    assert!(ServiceRequest::new(0xc1, 0x1234).validate().is_empty());
    assert_eq!(
        fields(&ServiceRequest::new(0xe1, 0x1234).validate()),
        ["nas_key_set_identifier"]
    );
    let mut other = ServiceRequest::new(0x21, 0x1234);
    other.security_header_type = 13;
    assert_eq!(fields(&other.validate()), ["security_header_type"]);
}

fn emm_transport(data: Option<Vec<u8>>, payload: Option<Vec<u8>>) -> EmmTransport {
    let mut transport = EmmTransport::new(0x0102_0304, 7);
    transport.data_container = data;
    transport.protected_payload = payload;
    transport
}

#[test]
fn an_emm_transport_has_one_data_container_of_two_octets_at_least() {
    // §8.2.35: control plane user data of EBI 5 and one octet
    let data = vec![0x05, 0xaa];
    assert!(
        emm_transport(Some(data.clone()), None)
            .validate()
            .is_empty()
    );
    assert!(emm_transport(None, Some(vec![1, 2])).validate().is_empty());
    assert_eq!(
        fields(&emm_transport(None, Some(vec![1])).validate()),
        ["protected_payload"]
    );
    assert_eq!(
        fields(&emm_transport(Some(data.clone()), Some(vec![1, 2])).validate()),
        ["protected_payload"]
    );
    // An empty data container is short of the table, with its length octet,
    // and one of one octet short of its type
    let empty = emm_transport(Some(Vec::new()), None).validate();
    assert_eq!(fields(&empty), ["data_container", "data_container"]);
    assert!(
        empty[0].message.starts_with("EPS IE length/value 1 "),
        "{empty:?}"
    );
    let short = emm_transport(Some(vec![0x05]), None).validate();
    assert_eq!(fields(&short), ["data_container"]);
    assert!(
        short[0].message.starts_with("IE breaks a sender rule"),
        "{short:?}"
    );
    let mut other = emm_transport(Some(data), None);
    other.security_header.security_header_type = SecurityHeaderType::IntegrityProtected;
    assert_eq!(fields(&other.validate()), ["security_header_type"]);
}

#[test]
fn the_ddx_bits_of_an_emm_transport_from_the_network_are_spare() {
    // Table 9.9.3.74.1: from the network, bits 5 and 4 are spare
    let uplink = emm_transport(Some(vec![0x0d, 0xaa]), None);
    assert!(uplink.validate_with_direction(Direction::Uplink).is_empty());
    assert_eq!(
        fields(&uplink.validate_with_direction(Direction::Downlink)),
        ["data_container"]
    );
    let plain = emm_transport(Some(vec![0x05, 0xaa]), None);
    assert!(
        plain
            .validate_with_direction(Direction::Downlink)
            .is_empty()
    );
}

#[test]
fn the_eps_bearer_identity_and_the_pti_of_an_esm_message_match_its_procedure() {
    let field = "eps_bearer_identity";
    let pti_field = "procedure_transaction_identity";
    let connectivity = || PdnConnectivityRequest::new(RequestType::new(1), PdnType::new(1));
    // §6.1.2: a transaction related procedure has a PTI and no EBI
    assert!(Message::new_esm(connectivity(), 0, 1).validate().is_empty());
    assert!(names(
        &Message::new_esm(connectivity(), 5, 1).validate(),
        field
    ));
    assert!(names(
        &Message::new_esm(connectivity(), 0, 0).validate(),
        pti_field
    ));
    // A response to a bearer request has an EBI and no PTI
    let accept = || ActivateDefaultEpsBearerContextAccept::new();
    assert!(Message::new_esm(accept(), 5, 0).validate().is_empty());
    assert!(names(&Message::new_esm(accept(), 0, 0).validate(), field));
    assert!(names(
        &Message::new_esm(accept(), 5, 1).validate(),
        pti_field
    ));
    // A bearer request of the network, a REMOTE UE REPORT and an ESM DATA
    // TRANSPORT have an EBI, and the latter no PTI
    let request = || {
        ActivateDefaultEpsBearerContextRequest::new(
            EpsQualityOfService::new(vec![9]),
            AccessPointName::new(octets("08696e7465726e6574")),
            PdnAddress::new(vec![1, 10, 0, 0, 1]),
        )
    };
    assert!(!names(&Message::new_esm(request(), 5, 1).validate(), field));
    assert!(names(&Message::new_esm(request(), 0, 1).validate(), field));
    let report = || RemoteUeReport::new();
    assert!(!names(&Message::new_esm(report(), 5, 1).validate(), field));
    assert!(names(&Message::new_esm(report(), 0, 1).validate(), field));
    let data = || EsmDataTransport::new(UserDataContainer::new(vec![0xaa]));
    assert!(Message::new_esm(data(), 5, 0).validate().is_empty());
    assert!(names(&Message::new_esm(data(), 0, 0).validate(), field));
    assert!(names(&Message::new_esm(data(), 5, 1).validate(), pti_field));
    // and a NOTIFICATION has one or the other
    let notification = || Notification::new(NotificationIndicator::new(vec![1]));
    assert!(Message::new_esm(notification(), 5, 0).validate().is_empty());
    assert!(names(
        &Message::new_esm(notification(), 0, 0).validate(),
        field
    ));
}

#[test]
fn a_message_that_does_not_encode_is_a_finding() {
    // A half octet of five bits
    let detach = DetachRequestUeOriginating::new(
        DetachType::new(0x11),
        KeySetIdentifier::new(0),
        EpsMobileIdentity::from_imsi("001010123456789").unwrap(),
    );
    let message = Message::new_emm(detach);
    assert!(
        names(&message.validate(), "EPS NAS header"),
        "{:?}",
        message.validate()
    );
}

#[test]
fn an_unknown_ie_is_one_ie_of_its_format() {
    // TS 24.007 §11.2.4, as TS 24.301 has it: an IEI with bit 8 set is an IE
    // of one octet, one of 78 to 7F has two octets of length and the others
    // one. A receiver reads the octets of an unknown IE by that rule, and a
    // sender writes each as one IE of its format, or the receiver reads
    // other IEs
    for (iei, data, sound) in [
        (0x21, vec![2, 0xaa, 0xbb], true),
        (0x72, vec![1, 0xaa], true),
        (0x7a, vec![0, 1, 0xaa], true),
        (0xd0, vec![], true),
        (0x21, vec![3, 0xaa, 0xbb], false),
        (0x72, vec![0, 1, 0xaa], false),
        (0x7a, vec![1, 0xaa], false),
        (0xdf, vec![0x21, 0], false),
    ] {
        let mut status = EmmStatus::new(EmmCause::new(0x60));
        status.unknown_ies.push(iei, &data);
        let errors = Message::new_emm(status).validate();
        let fault = names(&errors, "unknown_ies");
        assert_eq!(!fault, sound, "{iei:#04x} {data:02x?}: {errors:?}");
    }
}
