//! The causes of EMM (TS 24.301 table 9.9.3.9.1), of 5GMM (TS 24.501 table 9.11.3.2.1)
//! and of 5GSM (table 9.11.4.2.1): each value of its table is the cause that the table
//! names, and a receiver treats any other value as #111 "protocol error, unspecified",
//! or a UE any other 5GSM cause as #31 "request rejected, unspecified".

use oxirush_nas::nas_5gs::{GmmCause, GsmCause};
use oxirush_nas::nas_eps::EmmCause;

/// Table 9.9.3.9.1 of TS 24.301
const EMM: [(u8, &str); 41] = [
    (0x02, "IMSI unknown in HSS"),
    (0x03, "Illegal UE"),
    (0x05, "IMEI not accepted"),
    (0x06, "Illegal ME"),
    (0x07, "EPS services not allowed"),
    (0x08, "EPS services and non-EPS services not allowed"),
    (0x09, "UE identity cannot be derived by the network"),
    (0x0a, "Implicitly detached"),
    (0x0b, "PLMN not allowed"),
    (0x0c, "Tracking Area not allowed"),
    (0x0d, "Roaming not allowed in this tracking area"),
    (0x0e, "EPS services not allowed in this PLMN"),
    (0x0f, "No Suitable Cells In tracking area"),
    (0x10, "MSC temporarily not reachable"),
    (0x11, "Network failure"),
    (0x12, "CS domain not available"),
    (0x13, "ESM failure"),
    (0x14, "MAC failure"),
    (0x15, "Synch failure"),
    (0x16, "Congestion"),
    (0x17, "UE security capabilities mismatch"),
    (0x18, "Security mode rejected, unspecified"),
    (0x19, "Not authorized for this CSG"),
    (0x1a, "Non-EPS authentication unacceptable"),
    (0x1f, "Redirection to 5GCN required"),
    (0x23, "Requested service option not authorized in this PLMN"),
    (0x24, "IAB-node operation not authorized"),
    (0x27, "CS service temporarily not available"),
    (0x28, "No EPS bearer context activated"),
    (0x2a, "Severe network failure"),
    (
        0x4e,
        "PLMN not allowed to operate at the present UE location",
    ),
    (
        0x50,
        "Disaster roaming for the determined PLMN with disaster condition not allowed",
    ),
    (
        0x53,
        "Procedure cannot be completed due to unavailable feeder link while MME is operating in S&F mode",
    ),
    (0x5f, "Semantically incorrect message"),
    (0x60, "Invalid mandatory information"),
    (0x61, "Message type non-existent or not implemented"),
    (0x62, "Message type not compatible with the protocol state"),
    (0x63, "Information element non-existent or not implemented"),
    (0x64, "Conditional IE error"),
    (0x65, "Message not compatible with the protocol state"),
    (0x6f, "Protocol error, unspecified"),
];

/// Table 9.11.3.2.1 of TS 24.501
const GMM: [(u8, &str); 50] = [
    (0x03, "Illegal UE"),
    (0x05, "PEI not accepted"),
    (0x06, "Illegal ME"),
    (0x07, "5GS services not allowed"),
    (0x09, "UE identity cannot be derived by the network"),
    (0x0a, "Implicitly de-registered"),
    (0x0b, "PLMN not allowed"),
    (0x0c, "Tracking area not allowed"),
    (0x0d, "Roaming not allowed in this tracking area"),
    (0x0f, "No suitable cells in tracking area"),
    (0x14, "MAC failure"),
    (0x15, "Synch failure"),
    (0x16, "Congestion"),
    (0x17, "UE security capabilities mismatch"),
    (0x18, "Security mode rejected, unspecified"),
    (0x1a, "Non-5G authentication unacceptable"),
    (0x1b, "N1 mode not allowed"),
    (0x1c, "Restricted service area"),
    (0x1f, "Redirection to EPC required"),
    (0x24, "IAB-node operation not authorized"),
    (0x2b, "LADN not available"),
    (0x3e, "No network slices available"),
    (0x41, "Maximum number of PDU sessions reached"),
    (0x43, "Insufficient resources for specific slice and DNN"),
    (0x45, "Insufficient resources for specific slice"),
    (0x47, "ngKSI already in use"),
    (0x48, "Non-3GPP access to 5GCN not allowed"),
    (0x49, "Serving network not authorized"),
    (0x4a, "Temporarily not authorized for this SNPN"),
    (0x4b, "Permanently not authorized for this SNPN"),
    (
        0x4c,
        "Not authorized for this CAG or authorized for CAG cells only",
    ),
    (0x4d, "Wireline access area not allowed"),
    (
        0x4e,
        "PLMN not allowed to operate at the present UE location",
    ),
    (0x4f, "UAS services not allowed"),
    (
        0x50,
        "Disaster roaming for the determined PLMN with disaster condition not allowed",
    ),
    (
        0x51,
        "Selected N3IWF is not compatible with the allowed NSSAI",
    ),
    (
        0x52,
        "Selected TNGF is not compatible with the allowed NSSAI",
    ),
    (0x5a, "Payload was not forwarded"),
    (0x5b, "DNN not supported or not subscribed in the slice"),
    (
        0x5c,
        "Insufficient user-plane resources for the PDU session",
    ),
    (0x5d, "Onboarding services terminated"),
    (0x5e, "User plane positioning not authorized"),
    (0x5f, "Semantically incorrect message"),
    (0x60, "Invalid mandatory information"),
    (0x61, "Message type non-existent or not implemented"),
    (0x62, "Message type not compatible with the protocol state"),
    (0x63, "Information element non-existent or not implemented"),
    (0x64, "Conditional IE error"),
    (0x65, "Message not compatible with the protocol state"),
    (0x6f, "Protocol error, unspecified"),
];

/// The name that `table` gives `value`.
fn named(table: &[(u8, &'static str)], value: u8) -> Option<&'static str> {
    table
        .iter()
        .find(|(code, _)| *code == value)
        .map(|(_, name)| *name)
}

#[test]
fn an_emm_cause_is_a_value_of_table_9_9_3_9_1() {
    for value in 0..=u8::MAX {
        let cause = EmmCause::from_u8(value);
        match named(&EMM, value) {
            Some(name) => {
                let cause = cause.unwrap_or_else(|| panic!("{value}"));
                assert_eq!(cause.as_u8(), value);
                assert!(
                    cause.description().eq_ignore_ascii_case(name),
                    "{value}: {cause:?}"
                );
                assert_eq!(EmmCause::from_u8_received(value), cause);
            }
            None => {
                assert_eq!(cause, None, "{value}");
                assert_eq!(
                    EmmCause::from_u8_received(value),
                    EmmCause::ProtocolErrorUnspecified
                );
            }
        }
    }
}

#[test]
fn a_5gmm_cause_is_a_value_of_table_9_11_3_2_1() {
    for value in 0..=u8::MAX {
        let cause = GmmCause::from_u8(value);
        match named(&GMM, value) {
            Some(name) => {
                let cause = cause.unwrap_or_else(|| panic!("{value}"));
                assert_eq!(cause.as_u8(), value);
                assert!(
                    cause.description().eq_ignore_ascii_case(name),
                    "{value}: {cause:?}"
                );
                assert_eq!(GmmCause::from_u8_received(value), cause);
            }
            None => {
                assert_eq!(cause, None, "{value}");
                assert_eq!(
                    GmmCause::from_u8_received(value),
                    GmmCause::ProtocolErrorUnspecified
                );
            }
        }
    }
}

/// Table 9.11.4.2.1 of TS 24.501
const GSM: [(u8, &str); 46] = [
    (0x08, "Operator determined barring"),
    (0x1a, "Insufficient resources"),
    (0x1b, "Missing or unknown DNN"),
    (0x1c, "Unknown PDU session type"),
    (0x1d, "User authentication or authorization failed"),
    (0x1f, "Request rejected, unspecified"),
    (0x20, "Service option not supported"),
    (0x21, "Requested service option not subscribed"),
    (0x23, "PTI already in use"),
    (0x24, "Regular deactivation"),
    (0x25, "5GS QoS not accepted"),
    (0x26, "Network failure"),
    (0x27, "Reactivation requested"),
    (0x29, "Semantic error in the TFT operation"),
    (0x2a, "Syntactical error in the TFT operation"),
    (0x2b, "Invalid PDU session identity"),
    (0x2c, "Semantic errors in packet filter(s)"),
    (0x2d, "Syntactical error in packet filter(s)"),
    (0x2e, "Out of LADN service area"),
    (0x2f, "PTI mismatch"),
    (0x32, "PDU session type IPv4 only allowed"),
    (0x33, "PDU session type IPv6 only allowed"),
    (0x36, "PDU session does not exist"),
    (0x39, "PDU session type IPv4v6 only allowed"),
    (0x3a, "PDU session type Unstructured only allowed"),
    (0x3b, "Unsupported 5QI value"),
    (0x3d, "PDU session type Ethernet only allowed"),
    (0x43, "Insufficient resources for specific slice and DNN"),
    (0x44, "Not supported SSC mode"),
    (0x45, "Insufficient resources for specific slice"),
    (0x46, "Missing or unknown DNN in a slice"),
    (0x51, "Invalid PTI value"),
    (
        0x52,
        "Maximum data rate per UE for user-plane integrity protection is too low",
    ),
    (0x53, "Semantic error in the QoS operation"),
    (0x54, "Syntactical error in the QoS operation"),
    (0x55, "Invalid mapped EPS bearer identity"),
    (0x56, "UAS services not allowed"),
    (
        0x57,
        "QoS differentiation for non-3GPP device identifier(s) not available",
    ),
    (0x5f, "Semantically incorrect message"),
    (0x60, "Invalid mandatory information"),
    (0x61, "Message type non-existent or not implemented"),
    (0x62, "Message type not compatible with the protocol state"),
    (0x63, "Information element non-existent or not implemented"),
    (0x64, "Conditional IE error"),
    (0x65, "Message not compatible with the protocol state"),
    (0x6f, "Protocol error, unspecified"),
];

#[test]
fn a_5gsm_cause_is_a_value_of_table_9_11_4_2_1() {
    for value in 0..=u8::MAX {
        let cause = GsmCause::from_u8(value);
        match named(&GSM, value) {
            Some(name) => {
                let cause = cause.unwrap_or_else(|| panic!("{value}"));
                assert_eq!(cause.as_u8(), value);
                assert!(
                    cause.description().eq_ignore_ascii_case(name),
                    "{value}: {cause:?}"
                );
                assert_eq!(GsmCause::from_u8_for_ue(value), cause);
                assert_eq!(GsmCause::from_u8_for_network(value), cause);
            }
            None => {
                assert_eq!(cause, None, "{value}");
                assert_eq!(
                    GsmCause::from_u8_for_ue(value),
                    GsmCause::RequestRejectedUnspecified
                );
                assert_eq!(
                    GsmCause::from_u8_for_network(value),
                    GsmCause::ProtocolErrorUnspecified
                );
            }
        }
    }
}
