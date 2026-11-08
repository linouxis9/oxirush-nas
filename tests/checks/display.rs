//! The words of `Display`: an IE whose octets read shows its value, one that
//! does not shows its type and its octets, and a message its IEs.

use oxirush_nas::nas_5gs as f;
use oxirush_nas::nas_eps as e;

fn octets(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

#[test]
fn an_eps_identity_that_does_not_read_shows_its_type_and_its_octets() {
    assert_eq!(
        e::EsmMessageType::PdnConnectivityRequest.to_string(),
        "PdnConnectivityRequest"
    );
    let identity = |hex: &str| e::EpsMobileIdentity::new(octets(hex)).to_string();
    assert_eq!(identity("f602f8398001"), "GUTI (f602f8398001)");
    assert_eq!(identity("2980390a00"), "IMSI (2980390a00)");
    assert_eq!(identity("4b0951"), "IMEI (4b0951)");
    let identity = |hex: &str| e::MobileIdentity::new(octets(hex)).to_string();
    assert_eq!(identity("1980"), "IMSI (1980)");
    assert_eq!(identity("2a09"), "IMEI (2a09)");
    assert_eq!(identity("3b0951"), "IMEISV (3b0951)");
    assert_eq!(identity("f4c000"), "TMSI (f4c000)");
    assert_eq!(identity("f50000"), "TMGI (f50000)");
}

#[test]
fn the_values_of_eps_ies_and_messages_are_shown() {
    assert_eq!(
        e::TrackingAreaIdentity::new(octets("02f8390001")).to_string(),
        "208-93-0001"
    );
    assert_eq!(
        e::TrackingAreaIdentity::new(octets("02f839")).to_string(),
        "02f839"
    );
    assert_eq!(e::T3412ExtendedValue::new(octets("21")).to_string(), "1 h");
    assert_eq!(
        e::ServiceRequest::new(0x21, 0x1234).to_string(),
        "ServiceRequest (KSI=1, SN=1, short-MAC=0x1234)"
    );
    let mut transport = e::EmmTransport::new(1, 7);
    transport.data_container = Some(vec![5, 0xaa]);
    assert_eq!(transport.to_string(), "Transport (SN=7, container=05aa)");
    // A replayed NAS message container shows the message that it carries,
    // or its octets
    let mut complete = e::SecurityModeComplete::new();
    complete.replayed_nas_message_container = Some(e::ReplayedNasMessageContainer::new(octets(
        "07410108298039000000001002e0e000040201d031",
    )));
    assert!(
        e::Message::new_emm(complete.clone())
            .to_string()
            .starts_with(
                "EMM SecurityModeComplete (Replayed-NAS=EMM AttachRequest (type=EpsAttach"
            )
    );
    complete.replayed_nas_message_container =
        Some(e::ReplayedNasMessageContainer::new(octets("0741")));
    assert_eq!(
        e::Message::new_emm(complete).to_string(),
        "EMM SecurityModeComplete (Replayed-NAS=0741)"
    );
}

#[test]
fn the_values_of_5gs_ies_are_shown() {
    assert_eq!(
        f::EpsNasSecurityAlgorithms::new(0x22).to_string(),
        "EEA2 EIA2"
    );
    assert_eq!(
        f::MobileIdentity::new(vec![0x00]).to_string(),
        "no identity"
    );
    let tai = |hex: &str| f::TrackingAreaIdentity::new(octets(hex)).to_string();
    assert_eq!(tai("02f839000001"), "208-93-000001");
    assert_eq!(tai("ffffffffffff"), "deleted");
    assert_eq!(tai("02f8"), "02f8");
    assert_eq!(
        f::RejectedNssai::new(octets("1001")).to_string(),
        "[1 NotAvailableInPlmnOrSnpn]"
    );
    assert_eq!(
        f::PduAddress::from_ipv4([10, 45, 0, 2]).to_string(),
        "IPv4 10.45.0.2"
    );
}

#[test]
fn an_identity_request_shows_the_identity_by_its_name() {
    let names = [
        "SUCI",
        "SUCI",
        "5G-GUTI",
        "IMEI",
        "5G-S-TMSI",
        "IMEISV",
        "MAC address",
        "EUI-64",
    ];
    for (value, name) in names.into_iter().enumerate() {
        let request = f::IdentityRequest::new(f::IdentityType::new(value as u8));
        assert_eq!(
            f::Message::new_5gmm(request).to_string(),
            format!("5GMM IdentityRequest (type={name})")
        );
    }
}

#[test]
fn a_5gs_message_shows_its_payload_its_rules_and_its_flags() {
    let downlink = f::DlNasTransport::new(
        f::PayloadContainerType::new(5),
        f::PayloadContainer::new(octets("0102")),
    );
    assert_eq!(
        f::Message::new_5gmm(downlink).to_string(),
        "5GMM DlNasTransport (type=UePolicy, payload=UPDS (PTI=0x01 (UE-initiated), type=0x02) ManageUePolicyComplete)"
    );
    // QoS rules that do not read, or none, show their octets
    let accept = |rules: Vec<u8>| {
        f::Message::new_5gsm(
            f::PduSessionEstablishmentAccept::new(
                f::PduSessionType::new(1),
                f::SscMode::new(1),
                f::QosRules::new(rules),
                f::SessionAmbr::new(vec![0x06, 0x00, 0x01, 0x06, 0x00, 0x01]),
            ),
            5,
            1,
        )
        .to_string()
    };
    assert!(
        accept(octets("01000631")).contains("QoS-rules=01000631"),
        "{}",
        accept(octets("01000631"))
    );
    assert!(accept(Vec::new()).contains("QoS-rules=empty"));
    let request = |requested: u8| {
        let mut request = f::PduSessionEstablishmentRequest::new(
            f::IntegrityProtectionMaximumDataRate::new(0xffff),
        );
        request.always_on_pdu_session_requested =
            Some(f::AlwaysOnPduSessionRequested::new(requested));
        f::Message::new_5gsm(request, 5, 1).to_string()
    };
    assert_eq!(
        request(1),
        "5GSM (PSI=5, PTI=1) PduSessionEstablishmentRequest (always-on requested)"
    );
    assert_eq!(
        request(0),
        "5GSM (PSI=5, PTI=1) PduSessionEstablishmentRequest"
    );
}
