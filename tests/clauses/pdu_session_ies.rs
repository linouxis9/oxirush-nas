//! The PDU address (TS 24.501 §9.11.4.10): the PDU session type value in bits 3 to 1
//! of octet 3 and SI6LLA in bit 4, then the address of the type, and after it the
//! SMF's IPv6 link local address when SI6LLA is set; and the PDU session
//! reactivation result (§9.11.3.42), a bit for each PDU session identity.

use oxirush_nas::nas_5gs::{PduAddress, PduSessionReactivationResult};

const IPV4: [u8; 4] = [10, 45, 0, 2];
const INTERFACE_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const LINK_LOCAL: [u8; 16] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

#[test]
fn a_pdu_address_has_the_address_of_its_type_then_the_smf_link_local_address() {
    let address = |octets: &[&[u8]]| PduAddress::new(octets.concat());
    let ipv4 = address(&[&[0x09], &IPV4, &LINK_LOCAL]);
    assert!(ipv4.smf_ipv6_ll_indicator());
    let read = (
        ipv4.ipv4(),
        ipv4.ipv6_interface_id(),
        ipv4.smf_ipv6_link_local_address(),
    );
    assert_eq!(read, (Some(IPV4), None, Some(LINK_LOCAL)));
    let ipv6 = address(&[&[0x0a], &INTERFACE_ID, &LINK_LOCAL]);
    let read = (
        ipv6.ipv4(),
        ipv6.ipv6_interface_id(),
        ipv6.smf_ipv6_link_local_address(),
    );
    assert_eq!(read, (None, Some(INTERFACE_ID), Some(LINK_LOCAL)));
    let ipv4v6 = address(&[&[0x0b], &INTERFACE_ID, &IPV4, &LINK_LOCAL]);
    let read = (
        ipv4v6.ipv4(),
        ipv4v6.ipv6_interface_id(),
        ipv4v6.smf_ipv6_link_local_address(),
    );
    assert_eq!(read, (Some(IPV4), Some(INTERFACE_ID), Some(LINK_LOCAL)));
    // Without SI6LLA, the octets after the address are not a link local address
    let without = address(&[&[0x01], &IPV4, &LINK_LOCAL]);
    assert!(!without.smf_ipv6_ll_indicator());
    assert_eq!(without.smf_ipv6_link_local_address(), None);
    // A value cut short has no address
    assert_eq!(address(&[&[0x01], &IPV4[..3]]).ipv4(), None);
    assert_eq!(address(&[&[0x03], &INTERFACE_ID, &IPV4[..1]]).ipv4(), None);
    assert_eq!(
        address(&[&[0x02], &INTERFACE_ID[..7]]).ipv6_interface_id(),
        None
    );
    for (kind, before) in [(0x09, &IPV4[..]), (0x0a, &INTERFACE_ID), (0x0b, &[0; 12])] {
        let short = address(&[&[kind], before, &LINK_LOCAL[..15]]);
        assert_eq!(short.smf_ipv6_link_local_address(), None, "{kind}");
    }
}

#[test]
fn a_reactivation_result_has_the_bit_of_each_session_that_failed() {
    for sessions in [vec![], vec![1, 5, 15]] {
        let result = PduSessionReactivationResult::from_failed_sessions(&sessions).unwrap();
        assert_eq!(result.failed_sessions(), sessions);
        for session in 0..16 {
            let failed = sessions.contains(&session);
            assert_eq!(result.reactivation_failed(session), failed, "{session}");
        }
    }
}
