//! The findings of `validate()` for the 5GS messages: the headers of TS 24.501
//! §9.1 and §9.3, the rules of single messages, and the IEs that a receiver
//! takes or ignores.

use oxirush_nas::common::{Validate, ValidationError};
use oxirush_nas::nas_5gs::*;

/// Whether a finding names `field`.
fn names(errors: &[ValidationError], field: &str) -> bool {
    errors.iter().any(|error| error.field == field)
}

/// Whether a finding names `field` with `message`.
fn says(errors: &[ValidationError], field: &str, message: &str) -> bool {
    errors
        .iter()
        .any(|error| error.field == field && error.message == message)
}

/// A message in an envelope of the security header type `kind`.
fn protected(kind: Nas5gsSecurityHeaderType, inner: Nas5gsMessage) -> Nas5gsMessage {
    Nas5gsMessage::SecurityProtected(
        Nas5gsSecurityHeader {
            extended_protocol_discriminator: 0x7e,
            security_header_type: kind,
            spare_half_octet: 0,
            message_authentication_code: 0x0102_0304,
            sequence_number: 1,
        },
        Box::new(inner),
    )
}

fn security_mode_command() -> NasSecurityModeCommand {
    NasSecurityModeCommand::new(
        NasSecurityAlgorithms::new(0x22),
        NasKeySetIdentifier::new(0),
        NasUeSecurityCapability::new(vec![0xe0, 0xe0]),
    )
}

#[test]
fn a_security_header_type_with_a_new_context_goes_with_the_security_mode_messages_alone() {
    use Nas5gsSecurityHeaderType as Kind;
    // TS 24.501 §9.3, Table 9.3.1: 0011 for the SECURITY MODE COMMAND, 0100
    // for the SECURITY MODE COMPLETE
    let command = || Nas5gsMessage::new_5gmm(security_mode_command());
    let complete = || Nas5gsMessage::new_5gmm(NasSecurityModeComplete::new());
    let other = || Nas5gsMessage::new_5gmm(NasRegistrationComplete::new());
    let header = |message: &Nas5gsMessage| names(&message.validate(), "security_header_type");
    assert!(!header(&protected(
        Kind::IntegrityProtectedWithNewFiveGNasSecurityContext,
        command()
    )));
    assert!(header(&protected(Kind::IntegrityProtected, command())));
    assert!(header(&protected(
        Kind::IntegrityProtectedWithNewFiveGNasSecurityContext,
        other()
    )));
    assert!(header(&protected(
        Kind::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
        other()
    )));
    assert!(!header(&protected(Kind::IntegrityProtected, other())));
    // A SECURITY MODE COMPLETE is ciphered, so it is opaque in an envelope
    // that a message is not decoded from; written in clear, its header says
    // that it is ciphered, and the envelope carries cleartext
    let clear = protected(
        Kind::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
        complete(),
    );
    assert!(!header(&clear), "{:?}", clear.validate());
    assert!(names(&clear.validate(), "plain_fgs_nas_message"));
    assert!(header(&protected(Kind::IntegrityProtected, complete())));
    // The outer header has the EPD of 5GMM and a security header type
    let plain = protected(Kind::IntegrityProtected, other());
    assert!(plain.validate().is_empty(), "{:?}", plain.validate());
    let mut wrapper = plain.clone();
    if let Nas5gsMessage::SecurityProtected(header, _) = &mut wrapper {
        header.security_header_type = Kind::PlainFiveGsNasMessageNotSecurityProtected;
    }
    assert!(names(&wrapper.validate(), "security_header_type"));
    let mut epd = plain;
    if let Nas5gsMessage::SecurityProtected(header, _) = &mut epd {
        header.extended_protocol_discriminator = 0x2e;
    }
    assert!(names(&epd.validate(), "extended_protocol_discriminator"));
}

#[test]
fn the_inner_message_of_an_envelope_is_a_plain_5gmm_message() {
    use Nas5gsSecurityHeaderType as Kind;
    let field = "plain_fgs_nas_message";
    // Ciphertext goes under a ciphered header type, and is not empty
    let opaque = |kind, octets: Vec<u8>| protected(kind, Nas5gsMessage::Opaque(octets));
    assert!(!names(
        &opaque(Kind::IntegrityProtectedAndCiphered, vec![1, 2]).validate(),
        field
    ));
    assert!(names(
        &opaque(Kind::IntegrityProtected, vec![1, 2]).validate(),
        field
    ));
    assert!(names(
        &opaque(Kind::IntegrityProtectedAndCiphered, Vec::new()).validate(),
        field
    ));
    // The inner header has the EPD of 5GMM and no security header type
    let mut inner = Nas5gsMessage::new_5gmm(NasRegistrationComplete::new());
    if let Nas5gsMessage::Gmm(header, _) = &mut inner {
        header.extended_protocol_discriminator = 0x2e;
    }
    let message = protected(Kind::IntegrityProtected, inner);
    assert!(names(
        &message.validate(),
        "plain_fgs_nas_message.extended_protocol_discriminator"
    ));
    let mut inner = Nas5gsMessage::new_5gmm(NasRegistrationComplete::new());
    if let Nas5gsMessage::Gmm(header, _) = &mut inner {
        header.security_header_type = Kind::IntegrityProtected;
    }
    let message = protected(Kind::IntegrityProtected, inner);
    assert!(names(
        &message.validate(),
        "plain_fgs_nas_message.security_header_type"
    ));
}

#[test]
fn a_5gsm_message_has_a_pdu_session_identity_of_1_to_15_and_a_pti_for_a_ue_request() {
    // §9.4: PDU session identity values 1 to 15; §9.6: the PTI of a request
    // of the UE is assigned, and 255 is reserved
    let release =
        |psi, pti| Nas5gsMessage::new_5gsm(NasPduSessionReleaseRequest::new(), psi, pti).validate();
    assert!(release(15, 1).is_empty(), "{:?}", release(15, 1));
    assert!(names(&release(0, 1), "pdu_session_identity"));
    assert!(names(&release(16, 1), "pdu_session_identity"));
    assert!(names(&release(5, 0), "procedure_transaction_identity"));
    assert!(names(&release(5, 255), "procedure_transaction_identity"));
    let command = Nas5gsMessage::new_5gsm(
        NasPduSessionReleaseCommand::new(NasFGsmCause::new(36)),
        5,
        0,
    );
    assert!(!names(
        &command.validate(),
        "procedure_transaction_identity"
    ));
}

#[test]
fn an_identity_request_asks_for_one_of_the_seven_identities() {
    // §9.11.3.3: 001 SUCI to 111 EUI-64; a sender does not write the unused
    // 000, nor the spare bit 4
    let request = |value| NasIdentityRequest::new(NasFGsIdentityType::new(value)).validate();
    assert!(request(1).is_empty());
    assert!(request(7).is_empty());
    assert!(names(&request(0), "identity_type"));
    assert!(names(&request(0x09), "identity_type"));
}

#[test]
fn an_authentication_request_has_rand_and_autn_or_an_eap_message() {
    // §8.2.1.1
    let mut request =
        NasAuthenticationRequest::new(NasKeySetIdentifier::new(0), NasAbba::new(vec![0, 0]));
    request.authentication_parameter_rand = Some(NasAuthenticationParameterRand::new(vec![0; 16]));
    let errors = request.validate();
    assert!(names(&errors, "authentication_parameter_rand"));
    assert!(names(&errors, "eap_message"));
    request.authentication_parameter_autn = Some(NasAuthenticationParameterAutn::new(vec![0; 16]));
    assert!(request.validate().is_empty(), "{:?}", request.validate());
}

#[test]
fn replayed_ue_security_capabilities_have_two_octets_at_least() {
    let mut command = security_mode_command();
    command.replayed_ue_security_capabilities =
        NasUeSecurityCapability::new(vec![0xe0, 0xe0, 0xe0, 0xe0]);
    assert!(!names(
        &command.validate(),
        "replayed_ue_security_capabilities"
    ));
    command.replayed_ue_security_capabilities = NasUeSecurityCapability::new(vec![0xe0]);
    assert!(names(
        &command.validate(),
        "replayed_ue_security_capabilities"
    ));
}

#[test]
fn a_ciot_small_data_container_goes_alone() {
    // §8.2.30.1 NOTE: the CIoT small data container is sent without the other
    // optional IEs
    let field = "ciot_small_data_container";
    let mut request = NasControlPlaneServiceRequest::new(
        NasControlPlaneServiceType::new(0),
        NasKeySetIdentifier::new(0),
    );
    request.ciot_small_data_container = Some(NasCiotSmallDataContainer::new(vec![0x01, 0xaa]));
    assert!(
        !names(&request.validate(), field),
        "{:?}",
        request.validate()
    );
    request.pdu_session_id = Some(NasPduSessionIdentity2::new(1));
    assert!(names(&request.validate(), field));
}

#[test]
fn a_deregistration_request_has_an_access_type() {
    // §9.11.3.20: access types 01, 10 and 11
    let originating = |value| {
        NasDeregistrationRequestUeOriginating::new(
            NasDeRegistrationType::new(value),
            NasKeySetIdentifier::new(0),
            NasFGsMobileIdentity::new(vec![
                0xf2, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x11, 0x22, 0x33, 0x44,
            ]),
        )
        .validate()
    };
    assert!(originating(0x01).is_empty(), "{:?}", originating(0x01));
    assert!(names(&originating(0x00), "de_registration_type"));
    let terminated = |value| {
        NasDeregistrationRequestUeTerminated::new(NasDeRegistrationType::new(value)).validate()
    };
    assert!(terminated(0x01).is_empty());
    assert!(names(&terminated(0x00), "de_registration_type"));
}

#[test]
fn a_cause_that_is_none_of_its_table_is_a_warning() {
    let reject = NasRegistrationReject::new(NasFGmmCause::new(0xfe));
    assert!(names(&reject.validate(), "fgmm_cause"));
    let reject = NasPduSessionEstablishmentReject::new(NasFGsmCause::new(0xfe));
    assert!(names(&reject.validate(), "fgsm_cause"));
}

#[test]
fn an_epco_of_a_5gsm_message_has_its_first_octet() {
    // §9.11.4.6: an ePCO has its configuration protocol octet
    let field = "extended_protocol_configuration_options";
    let empty = || Some(NasExtendedProtocolConfigurationOptions::new(Vec::new()));
    let mut command = NasPduSessionModificationCommand::new();
    command.extended_protocol_configuration_options = empty();
    assert!(names(&command.validate(), field));
    let mut release = NasPduSessionReleaseCommand::new(NasFGsmCause::new(36));
    release.extended_protocol_configuration_options = empty();
    assert!(names(&release.validate(), field));
}

#[test]
fn a_service_level_aa_container_of_an_authentication_message_has_three_octets_at_least() {
    // §8.3.17 and §8.3.18, SERVICE-LEVEL AUTHENTICATION COMMAND and COMPLETE: the
    // service-level-AA container is a type 6 IE of 5 octets at least
    let field = "service_level_aa_container";
    let short = "Mandatory container must contain at least 3 octets";
    let container = NasServiceLevelAaContainer::new(vec![0x10, 0x02, 0x00, 0x01]);
    let command = NasServiceLevelAuthenticationCommand::new(container.clone()).validate();
    assert!(!says(&command, field, short), "{command:?}");
    let complete = NasServiceLevelAuthenticationComplete::new(container).validate();
    assert!(!says(&complete, field, short), "{complete:?}");
    let two = NasServiceLevelAaContainer::new(vec![0x10, 0x00]);
    assert!(says(
        &NasServiceLevelAuthenticationCommand::new(two.clone()).validate(),
        field,
        short
    ));
    assert!(says(
        &NasServiceLevelAuthenticationComplete::new(two).validate(),
        field,
        short
    ));
}

#[test]
fn a_remote_ue_context_list_of_a_report_has_thirteen_octets_at_least() {
    let field = "remote_ue_context_connected";
    let report = |octets: usize| {
        let mut report = NasRemoteUeReport::new();
        report.remote_ue_context_connected = Some(NasRemoteUeContextList::new(vec![0; octets]));
        names(&report.validate(), field)
    };
    assert!(!report(13));
    assert!(report(12));
}

#[test]
fn an_sor_container_of_a_registration_complete_is_one_from_the_ue() {
    // §9.11.3.51: the SOR data type 1, acknowledgement, from the UE
    let field = "sor_transparent_container";
    let mut complete = NasRegistrationComplete::new();
    complete.sor_transparent_container = Some(NasSorTransparentContainer::from_ack(
        false, false, false, [0; 16],
    ));
    assert!(!names(&complete.validate(), field));
    complete.sor_transparent_container = Some(NasSorTransparentContainer::new(vec![0x00; 19]));
    assert!(names(&complete.validate(), field));
}

/// A multiple payloads container of one entry of the type `kind` with the
/// contents `contents` (§9.11.3.39, Figure 9.11.3.39.2).
fn multiple_payloads(kind: u8, contents: &[u8]) -> Vec<u8> {
    let mut entry = vec![kind];
    entry.extend_from_slice(contents);
    let mut value = vec![1];
    value.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    value.extend_from_slice(&entry);
    value
}

#[test]
fn an_sor_container_of_a_nas_transport_is_one_of_its_direction() {
    let field = "sor_transparent_container";
    let ack: Vec<u8> = NasSorTransparentContainer::from_ack(false, false, false, [0; 16])
        .value
        .into();
    let uplink = NasUlNasTransport::new(
        NasPayloadContainerType::new(4),
        NasPayloadContainer::new(ack.clone()),
    );
    assert!(!names(&uplink.validate(), field));
    let downlink = |kind: u8, payload: Vec<u8>| {
        NasDlNasTransport::new(
            NasPayloadContainerType::new(kind),
            NasPayloadContainer::new(payload),
        )
        .validate()
    };
    assert!(names(&downlink(4, ack.clone()), field));
    // and of each SOR entry of multiple payloads (type 1111)
    assert!(names(&downlink(0x0f, multiple_payloads(4, &ack)), field));
    assert!(!names(
        &downlink(0x0f, multiple_payloads(2, &[0x01, 0x02])),
        field
    ));
}

#[test]
fn a_registration_request_carries_a_ue_policy_payload_alone() {
    // §8.2.6.1: the payload container of a REGISTRATION REQUEST is a UE
    // policy container
    let field = "payload_container_type";
    let mut request = NasRegistrationRequest::new(
        NasFGsRegistrationType::new(0x09),
        NasKeySetIdentifier::new(7),
        NasFGsMobileIdentity::new(vec![
            0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]),
    );
    request.payload_container_type = Some(NasPayloadContainerType::new(5));
    request.payload_container = Some(NasPayloadContainer::new(vec![0x01, 0x04]));
    assert!(
        !names(&request.validate(), field),
        "{:?}",
        request.validate()
    );
    request.payload_container_type = Some(NasPayloadContainerType::new(2));
    assert!(names(&request.validate(), field));
}

/// The message `$message` with `$field` set to `$value`, encoded and decoded
/// back as the variant `$variant` of 5GMM (`Gmm`) or of 5GSM (`Gsm`): whether
/// the receiver took the IE.
macro_rules! taken {
    (Gmm $variant:ident, $message:expr, $field:ident, $value:expr) => {{
        let mut message = $message;
        message.$field = Some($value);
        let octets = Nas5gsMessage::new_5gmm(message).encode().unwrap();
        match Nas5gsMessage::decode(&octets).unwrap() {
            Nas5gsMessage::Gmm(_, Nas5gmmMessage::$variant(message)) => message.$field.is_some(),
            other => panic!("{other:?}"),
        }
    }};
    (Gsm $variant:ident, $message:expr, $field:ident, $value:expr) => {{
        let mut message = $message;
        message.$field = Some($value);
        let octets = Nas5gsMessage::new_5gsm(message, 5, 1).encode().unwrap();
        match Nas5gsMessage::decode(&octets).unwrap() {
            Nas5gsMessage::Gsm(_, Nas5gsmMessage::$variant(message)) => message.$field.is_some(),
            other => panic!("{other:?}"),
        }
    }};
}

fn registration_accept() -> NasRegistrationAccept {
    NasRegistrationAccept::new(NasFGsRegistrationResult::new(vec![0x01]))
}

#[test]
fn a_receiver_ignores_an_optional_list_that_it_cannot_read() {
    // TS 24.501 §7.7.1: a syntactically incorrect optional IE is absent.
    // Each value below is as long as its table allows, and its type refuses it
    let bad = vec![0x05, 0x01, 0x00, 0x00, 0x00, 0x00];
    assert!(NasCagInformationList::new(bad.clone()).entries().is_empty());
    assert!(
        !taken!(Gmm RegistrationAccept, registration_accept(), cag_information_list, NasCagInformationList::new(bad.clone()))
    );
    assert!(
        NasExtendedCagInformationList::new(bad.clone())
            .entries()
            .is_empty()
    );
    assert!(
        !taken!(Gmm RegistrationAccept, registration_accept(), extended_cag_information_list, NasExtendedCagInformationList::new(bad.clone()))
    );
    assert!(NasLadnInformation::new(bad.clone()).entries().is_empty());
    assert!(
        !taken!(Gmm ConfigurationUpdateCommand, NasConfigurationUpdateCommand::new(), ladn_information, NasLadnInformation::new(bad.clone()))
    );
    assert!(NasNsagInformation::new(bad.clone()).entries().is_empty());
    assert!(
        !taken!(Gmm RegistrationAccept, registration_accept(), nsag_information, NasNsagInformation::new(bad.clone()))
    );
    let rejected = vec![0xff; 3];
    assert!(!NasExtendedRejectedNssai::new(rejected.clone()).receiver_syntax_is_valid());
    assert!(
        !taken!(Gmm RegistrationAccept, registration_accept(), extended_rejected_nssai, NasExtendedRejectedNssai::new(rejected))
    );
    let contexts = vec![0x51, 0x00, 0xff, 0xff];
    assert!(!NasMappedEpsBearerContexts::new(contexts.clone()).receiver_syntax_is_valid());
    assert!(
        !taken!(Gsm PduSessionModificationCommand, NasPduSessionModificationCommand::new(), mapped_eps_bearer_contexts, NasMappedEpsBearerContexts::new(contexts))
    );
    let received = vec![0xff; 6];
    assert!(
        NasReceivedMbsContainer::new(received.clone())
            .try_sessions()
            .is_none()
    );
    assert!(
        !taken!(Gsm PduSessionModificationCommand, NasPduSessionModificationCommand::new(), received_mbs_container, NasReceivedMbsContainer::new(received))
    );
    let requested = vec![0xff; 5];
    assert!(
        NasRequestedMbsContainer::new(requested.clone())
            .try_sessions()
            .is_none()
    );
    assert!(
        !taken!(Gsm PduSessionModificationRequest, NasPduSessionModificationRequest::new(), requested_mbs_container, NasRequestedMbsContainer::new(requested))
    );
}

#[test]
fn a_receiver_ignores_ciphering_key_data_of_no_complete_set() {
    // §9.11.3.18C: a c0 of 17 octets is none that a set has
    let mut set = vec![0x00, 0x01];
    set.extend_from_slice(&[0x5a; 16]);
    set.push(17);
    set.extend_from_slice(&[0xc0; 17]);
    set.extend_from_slice(&[0x80, 0, 0, 0x20, 1, 2, 3, 4, 5, 0, 0x3c, 0]);
    assert!(NasCipheringKeyData::new(set.clone()).data_sets().is_empty());
    assert!(
        !taken!(Gmm RegistrationAccept, registration_accept(), ciphering_key_data, NasCipheringKeyData::new(set))
    );
}

#[test]
fn a_receiver_takes_the_nssrg_information_that_it_reads() {
    // §9.11.3.82: an entry of its length, the S-NSSAI and its NSSRG values
    let valid = vec![0x03, 0x01, 0x01, 0x05];
    assert_eq!(NasNssrgInformation::new(valid.clone()).entries().len(), 1);
    assert!(
        taken!(Gmm RegistrationAccept, registration_accept(), nssrg_information, NasNssrgInformation::new(valid))
    );
    let invalid = vec![0x02, 0x01, 0x01, 0x00];
    assert!(
        NasNssrgInformation::new(invalid.clone())
            .entries()
            .is_empty()
    );
    assert!(
        !taken!(Gmm RegistrationAccept, registration_accept(), nssrg_information, NasNssrgInformation::new(invalid))
    );
}

#[test]
fn a_receiver_takes_the_mapped_nssai_and_the_n3qai_that_it_reads() {
    let request = || {
        NasRegistrationRequest::new(
            NasFGsRegistrationType::new(0x09),
            NasKeySetIdentifier::new(7),
            NasFGsMobileIdentity::new(vec![
                0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            ]),
        )
    };
    let mapped = NasMappedNssai::from_snssais(&[NasSNssai::new(vec![1])]).unwrap();
    assert!(taken!(Gmm RegistrationRequest, request(), requested_mapped_nssai, mapped));
    let overrun = NasMappedNssai::new(vec![0x05, 0x01]);
    assert!(overrun.try_parse_all().is_none());
    assert!(!taken!(Gmm RegistrationRequest, request(), requested_mapped_nssai, overrun));
    // §9.11.4.36: two N3QAI entries of one QFI and no parameter
    let n3qai = NasN3Qai::new(vec![1, 1, 0, 1, 2, 0]);
    assert!(n3qai.try_entries().is_some());
    assert!(
        taken!(Gsm PduSessionModificationCommand, NasPduSessionModificationCommand::new(), n3_qai, n3qai)
    );
}

#[test]
fn a_configuration_update_command_has_an_lp_wus_status_of_its_values() {
    // §9.11.3.112: the LP-WUS status in bit 1 alone
    let mut command = NasConfigurationUpdateCommand::new();
    command.lp_wus_status = Some(NasLpWusStatus::new(0x02));
    assert!(names(&command.validate(), "lp_wus_status"));
    command.lp_wus_status = Some(NasLpWusStatus::from_disabled(true));
    assert!(command.validate().is_empty(), "{:?}", command.validate());
}

#[test]
fn a_pdu_address_has_the_octets_of_its_pdu_session_type() {
    // §9.11.4.10
    let mut request =
        NasPduSessionEstablishmentRequest::new(NasIntegrityProtectionMaximumDataRate::new(0xffff));
    request.suggested_interface_identifier =
        Some(NasPduAddress::from_ipv6_iid([1, 2, 3, 4, 5, 6, 7, 8]));
    assert!(
        !names(&request.validate(), "suggested_interface_identifier"),
        "{:?}",
        request.validate()
    );
    request.suggested_interface_identifier = Some(NasPduAddress::new(vec![0x02, 1, 2, 3]));
    assert!(names(&request.validate(), "suggested_interface_identifier"));
    let mut accept = NasPduSessionEstablishmentAccept::new(
        NasPduSessionType::new(1),
        NasSscMode::new(1),
        NasQosRules::new(vec![0x01, 0x00, 0x06, 0x31, 0x01, 0x01, 0xff, 0x01, 0x01]),
        NasSessionAmbr::new(vec![0x06, 0x00, 0x01, 0x06, 0x00, 0x01]),
    );
    accept.pdu_address = Some(NasPduAddress::from_ipv4([10, 0, 0, 1]));
    assert!(
        !names(&accept.validate(), "pdu_address"),
        "{:?}",
        accept.validate()
    );
    accept.pdu_address = Some(NasPduAddress::new(vec![0x01, 10, 0]));
    assert!(names(&accept.validate(), "pdu_address"));
}

#[test]
fn an_unknown_ie_is_one_ie_of_its_format() {
    // TS 24.007 §11.2.4: an IEI with bit 8 set is an IE of one octet, one of
    // 70 to 7F has two octets of length and the others one. A receiver reads
    // the octets of an unknown IE by that rule, and a sender writes each as
    // one IE of its format, or the receiver reads other IEs
    for (iei, data, sound) in [
        (0x21, vec![2, 0xaa, 0xbb], true),
        (0x72, vec![0, 1, 0xaa], true),
        (0xd0, vec![], true),
        (0x21, vec![3, 0xaa, 0xbb], false),
        (0x72, vec![1, 0xaa], false),
        (0xdf, vec![0x21, 0], false),
    ] {
        let mut complete = NasRegistrationComplete::new();
        complete.unknown_ies.push(iei, &data);
        let errors = Nas5gsMessage::new_5gmm(complete).validate();
        let fault = names(&errors, "unknown_ies");
        assert_eq!(!fault, sound, "{iei:#04x} {data:02x?}: {errors:?}");
    }
}
