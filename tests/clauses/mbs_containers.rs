//! The MBS containers: the requested MBS container (TS 24.501 §9.11.4.30), each
//! session its operation in bits 4 and 3 of a control octet and the type of its ID in
//! bits 2 and 1, then a TMGI, or source and destination IPv4 or IPv6 addresses; and
//! the received MBS container (§9.11.4.31), each session the decision of the
//! network, the kind of its service area and the rejection cause in its first octet,
//! the flags of what follows in the second, the TMGI, the addresses, the service area,
//! the timer and the security keys.

use oxirush_nas::identity::Plmn;
use oxirush_nas::nas_5gs::{
    MbsDecision as Decision, MbsNrCgi, MbsRejectionCause as Cause, MbsSecurityKeySet,
    MbsServiceArea as Area, MbsTimer, MbsTmgi, ReceivedMbsContainer, ReceivedMbsSession,
    RequestedMbsContainer, RequestedMbsOperation as Operation, RequestedMbsSession,
    RequestedMbsSessionId as SessionId, TaiListEntry,
};

fn plmn() -> Plmn {
    Plmn::new("208", "93").unwrap()
}

fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

#[test]
fn a_requested_session_has_its_operation_and_its_id() {
    let tmgi = MbsTmgi {
        service_id: [1, 2, 3],
        plmn: Some(plmn()),
    };
    let sessions = vec![
        RequestedMbsSession::new(Operation::Join, SessionId::Tmgi(tmgi)),
        RequestedMbsSession::new(
            Operation::Leave,
            SessionId::Ipv4 {
                source: [10, 0, 0, 1],
                destination: [232, 0, 0, 1],
            },
        ),
        RequestedMbsSession::new(
            Operation::Join,
            SessionId::Ipv6 {
                source: [0x20; 16],
                destination: [0xff; 16],
            },
        ),
        RequestedMbsSession::new(
            Operation::Leave,
            SessionId::Ipv4 {
                source: [10, 0, 0, 2],
                destination: [232, 0, 0, 2],
            },
        ),
    ];
    let value = octets(&format!(
        "05 06 010203 02f839  0a 0a000001 e8000001  07 {} {}  0a 0a000002 e8000002",
        "20".repeat(16),
        "ff".repeat(16)
    ));
    let received = RequestedMbsContainer::new(value.clone());
    assert_eq!(received.try_sessions(), Some(sessions.clone()));
    let written = RequestedMbsContainer::try_from_sessions(&sessions).unwrap();
    assert_eq!(written.value, value);
}

/// A received session of `decision`, of the TMGI 010203 without a PLMN, that the
/// other members complete.
fn session(decision: Decision, cause: Option<Cause>) -> ReceivedMbsSession {
    let tmgi = MbsTmgi {
        service_id: [1, 2, 3],
        plmn: None,
    };
    ReceivedMbsSession::new(decision, cause, tmgi, None, None, None, None, vec![])
}

#[test]
fn a_received_session_has_what_its_flags_say() {
    let plmn = plmn();
    let tais = vec![TaiListEntry::OnePlmnNonConsecutive {
        plmn,
        tacs: vec![1],
    }];
    let cgis = vec![MbsNrCgi {
        nr_cell_id: 0x1_2345_6789,
        plmn,
    }];
    let with_mtk = MbsSecurityKeySet::new([1; 3], [2; 4], [3; 16], Some([4; 2]), Some([5; 16]));
    let without_mtk = MbsSecurityKeySet::new([6; 3], [7; 4], [8; 16], None, None);
    let mut update = session(Decision::ServiceAreaUpdate, None);
    update.service_area = Some(Area::TaiList(tais.clone()));
    let mut accepted = session(Decision::JoinAccepted, None);
    accepted.tmgi = MbsTmgi {
        service_id: [4, 5, 6],
        plmn: Some(plmn),
    };
    accepted.ipv4 = Some(([10, 0, 0, 1], [232, 0, 0, 1]));
    accepted.service_area = Some(Area::NrCgiList(cgis.clone()));
    accepted.timer = Some(MbsTimer::StartTime([0x62, 0x01, 0x71, 0x21, 0x03, 0x00]));
    accepted.security_keys = vec![with_mtk, without_mtk.clone()];
    let mut rejected = session(Decision::JoinRejected, Some(Cause::NotAuthorized));
    rejected.timer = Some(MbsTimer::Backoff(5));
    let mut removed = session(Decision::RemoveUe, Some(Cause::SessionReleased));
    removed.service_area = Some(Area::TaiAndNrCgi {
        tais,
        nr_cgis: cgis,
    });
    let mut keys = session(Decision::SecurityInformationUpdate, None);
    keys.ipv6 = Some(([0x20; 16], [0xff; 16]));
    keys.security_keys = vec![without_mtk];
    let mut sessions = vec![update, accepted, rejected, removed, keys];
    // Each rejection cause, in bits 8 to 6 of the first octet
    for cause in [
        Cause::NoAdditionalInformation,
        Cause::InsufficientResources,
        Cause::NotAuthorized,
        Cause::SessionNotStarted,
        Cause::OutsideServiceArea,
        Cause::ContextNotFound,
        Cause::SessionReleased,
    ] {
        sessions.push(session(Decision::JoinRejected, Some(cause)));
    }
    let written = ReceivedMbsContainer::try_from_sessions(&sessions).unwrap();
    assert_eq!(written.value[..2], [0x09, 0x00]);
    assert_eq!(written.try_sessions(), Some(sessions.clone()));
    assert_eq!(written.sessions(), sessions);
    assert!(written.is_well_formed());
    // The decision in bits 3 to 1 and the kind of service area in bits 5 and 4; the
    // flags of the IP addresses (bit 1, and bit 5 for IPv6), of the timer (bits 3 and
    // 2) and of the security keys (bit 4)
    let rejected = ReceivedMbsContainer::try_from_sessions(&[session(
        Decision::JoinRejected,
        Some(Cause::SessionReleased),
    )])
    .unwrap();
    assert_eq!(rejected.value[..2], [0xc3, 0x00]);
    let ipv6 = ReceivedMbsContainer::try_from_sessions(&sessions[4..5]).unwrap();
    assert_eq!(ipv6.value[..2], [0x05, 0x19]);
}

#[test]
fn an_nr_cgi_list_has_entries_of_eight_octets() {
    // A session of the service area of NR CGIs (kind 2) whose list has no octet, then
    // nine octets: not read
    for list in ["00", "09 123456789002f839ff"] {
        let value = format!("12 00 03 010203 {list}");
        let received = ReceivedMbsContainer::new(octets(&value));
        assert_eq!(received.try_sessions(), None, "{list}");
    }
}
