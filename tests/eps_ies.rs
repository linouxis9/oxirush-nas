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

//! The typed accessors of the EPS IEs, each against the table of its clause in
//! TS 24.301, or of TS 24.008 and TS 24.161 where TS 24.301 takes the IE from
//! them: every value that a table lists, the field that a value is read from,
//! and what a sender may write.

use oxirush_nas::nas_eps::*;

#[test]
fn an_esm_cause_is_one_of_table_9_9_4_4_1() {
    let causes = [
        (0x08, EsmCauseValue::OperatorDeterminedBarring),
        (0x1A, EsmCauseValue::InsufficientResources),
        (0x1B, EsmCauseValue::MissingOrUnknownApn),
        (0x1C, EsmCauseValue::UnknownPdnType),
        (0x1D, EsmCauseValue::UserAuthenticationOrAuthorizationFailed),
        (0x1E, EsmCauseValue::RequestRejectedByServingGwOrPdnGw),
        (0x1F, EsmCauseValue::RequestRejectedUnspecified),
        (0x20, EsmCauseValue::ServiceOptionNotSupported),
        (0x21, EsmCauseValue::RequestedServiceOptionNotSubscribed),
        (0x22, EsmCauseValue::ServiceOptionTemporarilyOutOfOrder),
        (0x23, EsmCauseValue::PtiAlreadyInUse),
        (0x24, EsmCauseValue::RegularDeactivation),
        (0x25, EsmCauseValue::EpsQosNotAccepted),
        (0x26, EsmCauseValue::NetworkFailure),
        (0x27, EsmCauseValue::ReactivationRequested),
        (0x29, EsmCauseValue::SemanticErrorInTheTftOperation),
        (0x2A, EsmCauseValue::SyntacticalErrorInTheTftOperation),
        (0x2B, EsmCauseValue::InvalidEpsBearerIdentity),
        (0x2C, EsmCauseValue::SemanticErrorsInPacketFilters),
        (0x2D, EsmCauseValue::SyntacticalErrorsInPacketFilters),
        (0x2F, EsmCauseValue::PtiMismatch),
        (0x31, EsmCauseValue::LastPdnDisconnectionNotAllowed),
        (0x32, EsmCauseValue::PdnTypeIpv4OnlyAllowed),
        (0x33, EsmCauseValue::PdnTypeIpv6OnlyAllowed),
        (0x34, EsmCauseValue::SingleAddressBearersOnlyAllowed),
        (0x35, EsmCauseValue::EsmInformationNotReceived),
        (0x36, EsmCauseValue::PdnConnectionDoesNotExist),
        (
            0x37,
            EsmCauseValue::MultiplePdnConnectionsForAGivenApnNotAllowed,
        ),
        (0x38, EsmCauseValue::CollisionWithNetworkInitiatedRequest),
        (0x39, EsmCauseValue::PdnTypeIpv4v6OnlyAllowed),
        (0x3A, EsmCauseValue::PdnTypeNonIpOnlyAllowed),
        (0x3B, EsmCauseValue::UnsupportedQciValue),
        (0x3C, EsmCauseValue::BearerHandlingNotSupported),
        (0x3D, EsmCauseValue::PdnTypeEthernetOnlyAllowed),
        (0x41, EsmCauseValue::MaximumNumberOfEpsBearersReached),
        (
            0x42,
            EsmCauseValue::RequestedApnNotSupportedInCurrentRatAndPlmnCombination,
        ),
        (0x51, EsmCauseValue::InvalidPtiValue),
        (0x5F, EsmCauseValue::SemanticallyIncorrectMessage),
        (0x60, EsmCauseValue::InvalidMandatoryInformation),
        (0x61, EsmCauseValue::MessageTypeNonExistentOrNotImplemented),
        (
            0x62,
            EsmCauseValue::MessageTypeNotCompatibleWithTheProtocolState,
        ),
        (
            0x63,
            EsmCauseValue::InformationElementNonExistentOrNotImplemented,
        ),
        (0x64, EsmCauseValue::ConditionalIeError),
        (
            0x65,
            EsmCauseValue::MessageNotCompatibleWithTheProtocolState,
        ),
        (0x6F, EsmCauseValue::ProtocolErrorUnspecified),
        (
            0x70,
            EsmCauseValue::ApnRestrictionValueIncompatibleWithActiveEpsBearerContext,
        ),
        (
            0x71,
            EsmCauseValue::MultipleAccessesToAPdnConnectionNotAllowed,
        ),
    ];
    for (value, cause) in causes {
        assert_eq!(
            EsmCauseValue::try_from(value).ok(),
            Some(cause),
            "{value:#04x}"
        );
        assert_eq!(u8::from(cause), value);
        assert_eq!(EsmCause::new(value).cause(), Some(cause));
    }
    // #46 is unused (NOTE 2), and any other value is none of the table
    for value in (0..=255u8).filter(|value| causes.iter().all(|(listed, _)| listed != value)) {
        assert_eq!(EsmCauseValue::try_from(value).ok(), None, "{value:#04x}");
    }
}

#[test]
fn an_esm_cause_ie_has_its_raw_value_and_the_text_of_its_cause() {
    let cause = EsmCause::new(0x1A);
    assert_eq!(cause.cause_raw(), 0x1A);
    assert_eq!(cause.description(), "Insufficient resources");
    let unknown = EsmCause::new(0x2E);
    assert_eq!(unknown.cause_raw(), 0x2E);
    assert_eq!(unknown.description(), "Unknown ESM cause 0x2e");
    // Any other value is read as #34 by the UE and as #111 by the network
    assert_eq!(
        unknown.cause_for_ue(),
        EsmCauseValue::ServiceOptionTemporarilyOutOfOrder
    );
    assert_eq!(
        unknown.cause_for_network(),
        EsmCauseValue::ProtocolErrorUnspecified
    );
}

#[test]
fn a_paging_restriction_type_is_one_of_four() {
    // §9.9.3.66: bits 4 to 1 of octet 3, 0 and 5 to 15 reserved
    let types = [
        (1, PagingRestrictionType::AllRestricted),
        (2, PagingRestrictionType::AllRestrictedExceptVoice),
        (
            3,
            PagingRestrictionType::AllRestrictedExceptSpecifiedPdnConnections,
        ),
        (
            4,
            PagingRestrictionType::AllRestrictedExceptVoiceAndSpecifiedPdnConnections,
        ),
    ];
    for (value, restriction) in types {
        assert_eq!(
            PagingRestrictionType::try_from(value & 0x0f).ok(),
            Some(restriction)
        );
        // The spare bits 8 to 5 are not read
        assert_eq!(
            PagingRestrictionType::try_from((0xf0 | value) & 0x0f).ok(),
            Some(restriction)
        );
    }
    assert_eq!(PagingRestrictionType::try_from(0).ok(), None);
    assert_eq!(PagingRestrictionType::try_from(5).ok(), None);
}

#[test]
fn an_s1_drx_value_is_not_specified_or_t_32_to_256() {
    // TS 24.008 Table 10.5.139: DRX value for S1 mode, bits 8 to 5 of octet 4
    let values = [
        (0, S1DrxValue::NotSpecified),
        (6, S1DrxValue::T32),
        (7, S1DrxValue::T64),
        (8, S1DrxValue::T128),
        (9, S1DrxValue::T256),
    ];
    for (value, drx) in values {
        assert_eq!(
            S1DrxValue::try_from(value & 0x0f).ok(),
            Some(drx),
            "{value}"
        );
        assert_eq!(S1DrxValue::try_from((0x10 | value) & 0x0f).ok(), Some(drx));
    }
    for value in [1, 5, 10, 15] {
        assert_eq!(S1DrxValue::try_from(value & 0x0f).ok(), None, "{value}");
        assert_eq!(S1DrxValue::received(value & 0x0f), S1DrxValue::NotSpecified);
    }
}

#[test]
fn a_drx_parameter_has_a_split_pg_cycle_and_the_fields_of_octet_4() {
    // TS 24.008 §10.5.5.6: the split PG cycle code, then the S1 DRX value in
    // bits 8 to 5, SPLIT on CCCH in bit 4 and the non-DRX timer in bits 3 to 1
    let drx = DrxParameter::new(vec![5, 0x7b]);
    assert_eq!(drx.split_pg_cycle(), Some(5));
    assert_eq!(drx.s1_drx_value(), Some(S1DrxValue::T64));
    assert_eq!(drx.s1_drx_value_raw(), Some(7));
    assert_eq!(drx.split_on_ccch(), Some(true));
    assert_eq!(drx.non_drx_timer(), Some(3));
    let other = DrxParameter::new(vec![64, 0x93]);
    assert_eq!(other.split_pg_cycle(), Some(64));
    assert_eq!(other.s1_drx_value(), Some(S1DrxValue::T256));
    assert_eq!(other.s1_drx_value_raw(), Some(9));
    assert_eq!(other.split_on_ccch(), Some(false));
    // Code 0 is 704, codes 65 to 98 those of the table, and the others 1
    assert_eq!(DrxParameter::new(vec![0, 0]).split_pg_cycle(), Some(704));
    assert_eq!(DrxParameter::new(vec![65, 0]).split_pg_cycle(), Some(71));
    assert_eq!(DrxParameter::new(vec![98, 0]).split_pg_cycle(), Some(352));
    assert_eq!(DrxParameter::new(vec![99, 0]).split_pg_cycle(), Some(1));
    let short = DrxParameter::new(vec![5]);
    assert_eq!(short.s1_drx_value_raw(), None);
    assert_eq!(short.split_on_ccch(), None);
}

#[test]
fn the_voice_domain_preference_is_bits_2_to_1_and_the_usage_setting_bit_3() {
    // TS 24.008 §10.5.5.28
    let preferences = [
        VoiceDomainPreference::CsVoiceOnly,
        VoiceDomainPreference::ImsPsVoiceOnly,
        VoiceDomainPreference::CsVoicePreferred,
        VoiceDomainPreference::ImsPsVoicePreferred,
    ];
    for (value, preference) in preferences.into_iter().enumerate() {
        for usage in [0, 0x04] {
            let ie = VoiceDomainPreferenceAndUeUsageSetting::new(vec![usage | value as u8]);
            assert_eq!(ie.voice_domain_preference(), Some(preference));
            assert_eq!(ie.data_centric(), Some(usage != 0));
            assert_eq!(
                VoiceDomainPreferenceAndUeUsageSetting::from_fields(preference, usage != 0),
                ie
            );
        }
    }
    let empty = VoiceDomainPreferenceAndUeUsageSetting::new(Vec::new());
    assert_eq!(empty.voice_domain_preference(), None);
    assert_eq!(empty.data_centric(), None);
}

#[test]
fn an_nbifom_status_is_one_of_table_6_1_3_1() {
    // TS 24.161 Table 6.1.3-1
    let statuses = [
        (0x00, NbifomStatus::Accepted),
        (0x1a, NbifomStatus::InsufficientResources),
        (0x22, NbifomStatus::ServiceOptionTemporarilyOutOfOrder),
        (0x25, NbifomStatus::RequestedServiceOptionNotSubscribed),
        (0x3f, NbifomStatus::RequestRejectedUnspecified),
        (
            0x39,
            NbifomStatus::IncorrectIndicationInRoutingRuleOperation,
        ),
        (0x3a, NbifomStatus::UnknownInformationInIpFlowFilters),
        (0x6f, NbifomStatus::ProtocolErrorUnspecified),
        (0x82, NbifomStatus::UnknownRoutingAccessInformation),
    ];
    for (value, status) in statuses {
        assert_eq!(NbifomStatus::try_from(value).ok(), Some(status));
        assert_eq!(NbifomStatus::received(value), status);
    }
    // All other values are read as "protocol error, unspecified"
    assert_eq!(NbifomStatus::try_from(0x01).ok(), None);
    assert_eq!(
        NbifomStatus::received(0x01),
        NbifomStatus::ProtocolErrorUnspecified
    );
}

/// An NBIFOM container of one routing rules parameter with one rule: the
/// identifier, the routing access and operation code, the priority, and the
/// routing filter.
fn routing_rule(rule: &[u8]) -> NbifomContainer {
    let mut contents = vec![rule.len() as u8];
    contents.extend_from_slice(rule);
    let mut value = vec![NbifomParameterId::RoutingRules as u8, contents.len() as u8];
    value.extend_from_slice(&contents);
    NbifomContainer::new(value)
}

/// A rule of 3GPP access to create, with the four flag octets of its filter and
/// the fields that they indicate.
fn rule_with(flags: [u8; 4], fields: &[u8]) -> NbifomContainer {
    let mut rule = vec![1, 0x41, 7];
    rule.extend_from_slice(&flags);
    rule.extend_from_slice(fields);
    routing_rule(&rule)
}

fn sent(container: &NbifomContainer) -> bool {
    container.is_well_formed_for(NbifomDirection::NetworkToUe)
}

#[test]
fn a_routing_rule_has_the_fields_that_its_filter_flags_indicate() {
    // TS 24.161 §6.1.4: octet 1 of the filter is H G F E D C B A and octet 2
    // Z Z N M L K J I; each flag set adds its field
    assert!(sent(&rule_with([0, 0, 0, 0], &[])));
    // A, the source IPv4 address
    assert!(sent(&rule_with([0x01, 0, 0, 0], &[10, 0, 0, 1])));
    // D, the destination IPv6 address
    assert!(sent(&rule_with([0x08, 0, 0, 0], &[0x20; 16])));
    // H, G, F, E, B and A: 1 + 4 + 1 + 1 + 4 + 4 octets
    assert!(sent(&rule_with([0xf3, 0, 0, 0], &[0; 15])));
    assert!(!sent(&rule_with([0xf3, 0, 0, 0], &[0; 14])));
    // I and J, the source port range
    assert!(sent(&rule_with([0, 0x03, 0, 0], &[0xff; 8])));
    // K and L, the destination port range
    assert!(sent(&rule_with([0, 0x0c, 0, 0], &[0; 8])));
    // M, the type of service
    assert!(sent(&rule_with([0, 0x10, 0, 0], &[0xb8])));
    // N, the flow label, octets m to m+3 of figure 6.1.4-2, bits 8 to 5 of
    // its first octet spare
    assert!(sent(&rule_with([0, 0x20, 0, 0], &[0x0f, 0x0f, 0xff, 0xff])));
    assert!(!sent(&rule_with(
        [0, 0x20, 0, 0],
        &[0x1f, 0x0f, 0xff, 0xff]
    )));
    // A field more or less than the flags say
    assert!(!sent(&rule_with([0x01, 0, 0, 0], &[10, 0, 0, 1, 0])));
    assert!(!sent(&rule_with([0x01, 0, 0, 0], &[10, 0, 0])));
    // A rule has at least its identifier, operation, priority and flags
    assert!(!sent(&routing_rule(&[1, 0x41, 7, 0, 0, 0])));
}

#[test]
fn a_routing_rule_has_a_routing_access_an_operation_and_coherent_flags() {
    // TS 24.161 Table 6.1.4-1: the access 01 or 10, the spare bits clear and
    // the operation 1 to 3
    assert!(sent(&routing_rule(&[1, 0x81, 7, 0, 0, 0, 0])));
    assert!(sent(&routing_rule(&[1, 0x43, 7, 0, 0, 0, 0])));
    assert!(!sent(&routing_rule(&[1, 0x01, 7, 0, 0, 0, 0])));
    assert!(!sent(&routing_rule(&[1, 0xc1, 7, 0, 0, 0, 0])));
    assert!(!sent(&routing_rule(&[1, 0x49, 7, 0, 0, 0, 0])));
    assert!(!sent(&routing_rule(&[1, 0x40, 7, 0, 0, 0, 0])));
    assert!(!sent(&routing_rule(&[1, 0x44, 7, 0, 0, 0, 0])));
    // The sender sets the Z flags to zero (Table 6.1.4-2)
    assert!(!sent(&routing_rule(&[1, 0x41, 7, 0, 0x40, 0, 0])));
    assert!(!sent(&routing_rule(&[1, 0x41, 7, 0, 0, 1, 0])));
    assert!(!sent(&routing_rule(&[1, 0x41, 7, 0, 0, 0, 1])));
    // No IPv4 address with an IPv6 one
    assert!(!sent(&rule_with([0x05, 0, 0, 0], &[0; 20])));
    // An end of a port range only with its start
    assert!(!sent(&rule_with([0, 0x02, 0, 0], &[0; 4])));
    assert!(!sent(&rule_with([0, 0x08, 0, 0], &[0; 4])));
}

#[test]
fn an_nbifom_parameter_is_one_of_its_direction_with_its_contents() {
    let container = |identifier: u8, contents: &[u8]| {
        let mut value = vec![identifier, contents.len() as u8];
        value.extend_from_slice(contents);
        NbifomContainer::new(value)
    };
    let both = |container: &NbifomContainer| {
        (
            container.is_well_formed_for(NbifomDirection::UeToNetwork),
            container.is_well_formed_for(NbifomDirection::NetworkToUe),
            container.is_well_formed(),
        )
    };
    // TS 24.161 §6.1.3: a status of the table, in both directions
    assert_eq!(both(&container(3, &[0x00])), (true, true, true));
    assert_eq!(both(&container(3, &[0x82])), (true, true, true));
    assert_eq!(both(&container(3, &[0x01])), (false, false, false));
    // §6.1.6: the RAN rules handling, network to MS alone
    assert_eq!(both(&container(6, &[2])), (false, true, true));
    // §6.1.7: the access stratum status, MS to network alone, 1 to 3
    assert_eq!(both(&container(7, &[3])), (true, false, true));
    assert_eq!(both(&container(7, &[4])), (false, false, false));
    // §6.1.8: the access usability indication, MS to network alone, neither
    // field 11 and bits 8 to 5 spare
    assert_eq!(both(&container(8, &[0x09])), (true, false, true));
    assert_eq!(both(&container(8, &[0x03])), (false, false, false));
    assert_eq!(both(&container(8, &[0x0c])), (false, false, false));
    assert_eq!(both(&container(8, &[0x11])), (false, false, false));
}

/// A ciphering data set of §9.9.3.56 with a c0 of `c0` octets and a TAI list
/// of `tai` octets.
fn ciphering_data_set(c0: usize, tai: &[u8]) -> Vec<u8> {
    let mut set = vec![0x00, 0x01];
    set.extend_from_slice(&[0x5a; 16]);
    set.push(c0 as u8);
    set.extend(vec![0xc0; c0]);
    // The positioning SIB types, bits 5 to 1 of the fourth octet spare
    set.extend_from_slice(&[0x80, 0, 0, 0x20]);
    set.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x00, 0x3c]);
    set.push(tai.len() as u8);
    set.extend_from_slice(tai);
    set
}

#[test]
fn ciphering_key_data_is_1_to_16_complete_sets() {
    // §9.9.3.56: a set has 31 octets at least, a c0 of 16 octets at most, and
    // the IE 16 sets at most
    let shortest = ciphering_data_set(0, &[]);
    assert_eq!(shortest.len(), 31);
    assert!(CipheringKeyData::new(shortest.clone()).is_well_formed());
    assert!(CipheringKeyData::new(ciphering_data_set(16, &[])).is_well_formed());
    assert!(!CipheringKeyData::new(ciphering_data_set(17, &[])).is_well_formed());
    assert!(!CipheringKeyData::new(Vec::new()).is_well_formed());
    assert!(!CipheringKeyData::new(shortest[..30].to_vec()).is_well_formed());
    let two = [shortest.clone(), ciphering_data_set(2, &[])].concat();
    assert!(CipheringKeyData::new(two.clone()).is_well_formed());
    assert!(!CipheringKeyData::new(two[..two.len() - 1].to_vec()).is_well_formed());
    let sixteen = shortest.repeat(16);
    assert!(CipheringKeyData::new(sixteen.clone()).is_well_formed());
    assert!(!CipheringKeyData::new(shortest.repeat(17)).is_well_formed());
    // The receiver keeps the first 16 sets and ignores the octets after them
    let ie = CipheringKeyData::new(shortest.repeat(17));
    assert_eq!(ie.data_sets().len(), 16);
    assert_eq!(CipheringKeyData::new(sixteen).data_sets().len(), 16);
}

#[test]
fn a_ciphering_data_set_has_a_c0_of_16_octets_at_most() {
    let sets = CipheringKeyData::new(ciphering_data_set(16, &[])).data_sets();
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].c0, vec![0xc0; 16]);
    assert_eq!(sets[0].validity_duration, 0x3c);
    // A c0 longer than 16 octets ends the decoding
    assert!(
        CipheringKeyData::new(ciphering_data_set(17, &[]))
            .data_sets()
            .is_empty()
    );
}

#[test]
fn the_s_and_f_parameters_have_the_fields_that_their_flags_indicate() {
    // §9.9.3.73: SFWTPI (bit 1), ESFUDTPI (bit 2) and SFMLI (bits 4 and 3),
    // then the fields in that order
    let wait = SAndFSatelliteOperationParameters::new(vec![0x01, 0x01, 0x2c]);
    assert_eq!(wait.wait_time(), Some(300));
    assert_eq!(wait.uplink_delivery_time(), None);
    let uplink = SAndFSatelliteOperationParameters::new(vec![0x02, 0x00, 0x0e, 0x10]);
    assert_eq!(uplink.wait_time(), None);
    assert_eq!(uplink.uplink_delivery_time(), Some(3600));
    let list = SAndFSatelliteOperationParameters::new(vec![0x08, 2, 7, 9]);
    assert_eq!(
        list.monitoring_list(),
        Some(SAndFMonitoringList::Present(vec![7, 9]))
    );
    // The wait time and the list, and no uplink delivery time
    let wait_and_list = SAndFSatelliteOperationParameters::new(vec![0x09, 0x00, 0x3c, 3, 1, 2, 3]);
    assert_eq!(wait_and_list.wait_time(), Some(60));
    assert_eq!(wait_and_list.uplink_delivery_time(), None);
    assert_eq!(
        wait_and_list.monitoring_list(),
        Some(SAndFMonitoringList::Present(vec![1, 2, 3]))
    );
    let all =
        SAndFSatelliteOperationParameters::new(vec![0x0b, 0x00, 0x3c, 0x00, 0x00, 0x78, 1, 4]);
    assert_eq!(all.wait_time(), Some(60));
    assert_eq!(all.uplink_delivery_time(), Some(120));
    assert_eq!(
        all.monitoring_list(),
        Some(SAndFMonitoringList::Present(vec![4]))
    );
    let uplink_and_list =
        SAndFSatelliteOperationParameters::new(vec![0x0a, 0x00, 0x00, 0x78, 1, 4]);
    assert_eq!(
        uplink_and_list.monitoring_list(),
        Some(SAndFMonitoringList::Present(vec![4]))
    );
    assert_eq!(
        SAndFSatelliteOperationParameters::new(vec![0x04]).monitoring_list(),
        Some(SAndFMonitoringList::Delete)
    );
    // A sender writes bits 8 to 5 clear and no SFMLI 11
    assert!(SAndFSatelliteOperationParameters::new(vec![0x04]).is_well_formed());
    assert!(!SAndFSatelliteOperationParameters::new(vec![0x0c]).is_well_formed());
    assert!(!SAndFSatelliteOperationParameters::new(vec![0x10]).is_well_formed());
}

#[test]
fn a_remote_ue_user_identity_is_one_of_five_types() {
    // §9.9.4.20, Table 9.9.4.20.2: the type of user identity in bits 3 to 1
    let types = [
        (1, RemoteUeIdentityType::EncryptedImsi),
        (2, RemoteUeIdentityType::Imsi),
        (3, RemoteUeIdentityType::Msisdn),
        (4, RemoteUeIdentityType::Imei),
        (5, RemoteUeIdentityType::Imeisv),
    ];
    for (value, identity_type) in types {
        let identity = RemoteUeUserIdentity {
            octets: vec![value, 0x21],
        };
        assert_eq!(identity.identity_type(), Some(identity_type));
    }
    for value in [0, 6, 7] {
        let identity = RemoteUeUserIdentity {
            octets: vec![value, 0x21],
        };
        assert_eq!(identity.identity_type(), None);
    }
}

#[test]
fn a_remote_ue_user_identity_has_the_digits_of_its_type() {
    let imsi =
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imsi, "208930000000001").unwrap();
    assert_eq!(imsi.digits().as_deref(), Some("208930000000001"));
    assert!(imsi.is_well_formed());
    let msisdn =
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Msisdn, "33612345678").unwrap();
    assert!(msisdn.is_well_formed());
    // An IMEI has 15 digits, the last the spare digit 0 (TS 23.003 §6.2.1)
    let imei =
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imei, "490154203237510").unwrap();
    assert_eq!(imei.digits().as_deref(), Some("490154203237510"));
    assert!(imei.is_well_formed());
    assert!(
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imei, "490154203237518").is_err()
    );
    assert!(
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imei, "49015420323750").is_err()
    );
    // An IMEISV has 16 digits, and no software version 99
    let imeisv =
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imeisv, "4901542032375101")
            .unwrap();
    assert_eq!(imeisv.digits().as_deref(), Some("4901542032375101"));
    assert!(imeisv.is_well_formed());
    assert!(
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imeisv, "4901542032375199")
            .is_err()
    );
    // An encrypted IMSI is a string of 128 bits, which has no digits
    assert!(
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::EncryptedImsi, "1234").is_err()
    );
    let encrypted = RemoteUeUserIdentity::from_encrypted_imsi([0x12; 16]);
    assert_eq!(encrypted.digits(), None);
    assert!(encrypted.is_well_formed());
    let short_encrypted = RemoteUeUserIdentity {
        octets: vec![0x09, 0x21],
    };
    assert_eq!(short_encrypted.digits(), None);
    assert!(!short_encrypted.is_well_formed());
    // Bits 5 to 8 of the type octet of an encrypted IMSI are coded as zero
    let mut flagged = encrypted.clone();
    flagged.octets[0] = 0x11;
    assert!(!flagged.is_well_formed());
    let mut long = encrypted.clone();
    long.octets.push(0);
    assert!(!long.is_well_formed());
    // An identity of one digit is no IMSI
    let one = RemoteUeUserIdentity { octets: vec![0x1a] };
    assert_eq!(one.digits(), None);
}

/// A remote UE context of one IMSI and an IPv4 address with the NAT port
/// 5000.
fn remote_ue_context(udp: Option<PortRange>, tcp: Option<PortRange>) -> RemoteUeContext {
    let imsi =
        RemoteUeUserIdentity::from_digits(RemoteUeIdentityType::Imsi, "208930000000001").unwrap();
    RemoteUeContext::new(
        vec![imsi],
        RemoteUeAddress::Ipv4 {
            address: [10, 0, 0, 2],
            port: 5000,
            udp_port_range: udp,
            tcp_port_range: tcp,
        },
    )
}

#[test]
fn a_remote_ue_context_has_an_address_of_its_type() {
    // Table 9.9.4.20.2: UPRI4I (bit 5), TPRI4I (bit 4) and the address type
    // (bits 3 to 1) of octet j
    let range = PortRange {
        low: 4000,
        high: 6000,
    };
    let context = remote_ue_context(None, Some(range));
    let octets = context.to_bytes().unwrap();
    let flags = octets[octets.len() - 11];
    assert_eq!(flags, 0x09);
    assert_eq!(RemoteUeContext::from_bytes(&octets), Some(context.clone()));
    let both = remote_ue_context(Some(range), Some(range));
    let octets = both.to_bytes().unwrap();
    assert_eq!(octets[octets.len() - 15], 0x19);
    assert_eq!(RemoteUeContext::from_bytes(&octets), Some(both));
    // A reserved address type is kept in its three bits
    let unknown = RemoteUeContext::new(
        Vec::new(),
        RemoteUeAddress::Unknown {
            address_type: 3,
            octets: vec![1, 2],
        },
    );
    assert_eq!(unknown.to_bytes().unwrap(), [0, 3, 1, 2]);
    assert!(!unknown.is_well_formed());
    assert_eq!(
        RemoteUeContext::from_bytes(&[0, 2, 1, 2, 3, 4, 5, 6, 7, 8]).map(|context| context.address),
        Some(RemoteUeAddress::Ipv6Prefix([1, 2, 3, 4, 5, 6, 7, 8]))
    );
}

#[test]
fn the_nat_port_of_a_remote_ue_is_in_its_port_ranges() {
    let around = PortRange {
        low: 4000,
        high: 6000,
    };
    assert!(remote_ue_context(Some(around), Some(around)).is_well_formed());
    let above = PortRange {
        low: 6000,
        high: 7000,
    };
    let below = PortRange {
        low: 1000,
        high: 4000,
    };
    assert!(!remote_ue_context(Some(above), None).is_well_formed());
    assert!(!remote_ue_context(None, Some(below)).is_well_formed());
}

#[test]
fn a_pkmf_address_is_an_ipv4_or_an_ipv6_address() {
    // §9.9.4.21: the address type in bits 3 to 1 of octet 3
    let ipv4 = PkmfAddress::from_address("10.0.0.1".parse().unwrap());
    assert_eq!(ipv4.address_type_raw(), Some(1));
    assert_eq!(ipv4.address_type(), Some(PkmfAddressType::Ipv4));
    assert!(ipv4.is_well_formed());
    let ipv6 = PkmfAddress::from_address("2001:db8::1".parse().unwrap());
    assert_eq!(ipv6.address_type_raw(), Some(2));
    assert_eq!(ipv6.address_type(), Some(PkmfAddressType::Ipv6));
    assert_eq!(ipv6.address(), Some("2001:db8::1".parse().unwrap()));
    assert!(ipv6.is_well_formed());
    assert_eq!(PkmfAddress::new(vec![3, 0, 0, 0, 0]).address_type(), None);
}

#[test]
fn an_eps_attach_type_is_one_of_table_9_9_3_11_1() {
    let types = [
        (1, AttachType::EpsAttach),
        (2, AttachType::CombinedEpsImsiAttach),
        (3, AttachType::EpsRlosAttach),
        (6, AttachType::EpsEmergencyAttach),
        (7, AttachType::DisasterRoamingAttach),
    ];
    for (value, attach_type) in types {
        assert_eq!(AttachType::try_from(value & 0x07).ok(), Some(attach_type));
        assert_eq!(AttachType::received(value & 0x07), attach_type);
    }
    // The unused values are read as EPS attach by the network
    for value in [0, 4, 5] {
        assert_eq!(AttachType::try_from(value & 0x07).ok(), None);
        assert_eq!(AttachType::received(value & 0x07), AttachType::EpsAttach);
    }
    // Bit 4 is spare
    let ie = EpsAttachType::new(0x0a);
    assert_eq!(ie.attach_type_raw(), 2);
    assert_eq!(
        ie.attach_type_strict(),
        Some(AttachType::CombinedEpsImsiAttach)
    );
}

#[test]
fn a_service_type_is_one_of_table_9_9_3_27_1() {
    let types = [
        (
            0,
            ServiceTypeValue::MobileOriginatingCsFallbackOr1xCsFallback,
        ),
        (
            1,
            ServiceTypeValue::MobileTerminatingCsFallbackOr1xCsFallback,
        ),
        (
            2,
            ServiceTypeValue::MobileOriginatingCsFallbackEmergencyCallOr1xCsFallbackEmergencyCall,
        ),
        (8, ServiceTypeValue::PacketServicesViaS1),
    ];
    for (value, service_type) in types {
        assert_eq!(
            ServiceTypeValue::try_from(value & 0x0f).ok(),
            Some(service_type)
        );
        assert_eq!(ServiceTypeValue::received(value & 0x0f), Some(service_type));
        assert_eq!(
            ServiceType::new(value).service_type_strict(),
            Some(service_type)
        );
    }
    // 3 and 4 are read as mobile originating CS fallback, 9 to 11 as packet
    // services via S1, by the network
    assert_eq!(ServiceTypeValue::try_from(3).ok(), None);
    assert_eq!(
        ServiceTypeValue::received(4),
        Some(ServiceTypeValue::MobileOriginatingCsFallbackOr1xCsFallback)
    );
    assert_eq!(
        ServiceTypeValue::received(11),
        Some(ServiceTypeValue::PacketServicesViaS1)
    );
    assert_eq!(ServiceTypeValue::received(12), None);
}

#[test]
fn a_control_plane_service_type_has_its_type_and_the_active_flag() {
    // Table 9.9.3.47.1: the type in bits 3 to 1, "active" in bit 4
    let active = ControlPlaneServiceType::new(0x09);
    assert_eq!(active.service_type_raw(), 1);
    assert!(active.is_active());
    let mut ie = ControlPlaneServiceType::new(0x08);
    ie.set_service_type(ControlPlaneServiceTypeValue::MobileTerminatingRequest);
    assert_eq!(ie.value, 0x09);
    let mut idle = ControlPlaneServiceType::new(0x00);
    idle.set_service_type(ControlPlaneServiceTypeValue::MobileTerminatingRequest);
    assert_eq!(idle.value, 0x01);
    idle.set_active(true);
    assert_eq!(idle.value, 0x09);
}

#[test]
fn a_pdn_type_is_one_of_table_9_9_4_10_1() {
    let types = [
        (1, PdnTypeValue::Ipv4),
        (2, PdnTypeValue::Ipv6),
        (3, PdnTypeValue::Ipv4v6),
        (5, PdnTypeValue::NonIp),
        (6, PdnTypeValue::Ethernet),
    ];
    for (value, pdn_type) in types {
        assert_eq!(PdnTypeValue::try_from(value & 0x07).ok(), Some(pdn_type));
        assert_eq!(PdnTypeValue::received(value & 0x07), Some(pdn_type));
    }
    // 4 is read as IPv6 by the network
    assert_eq!(PdnTypeValue::try_from(4).ok(), None);
    assert_eq!(PdnTypeValue::received(4), Some(PdnTypeValue::Ipv6));
    assert_eq!(PdnTypeValue::received(7), None);
}

#[test]
fn an_eps_attach_result_is_eps_only_or_combined() {
    // Table 9.9.3.10.1, bit 4 spare
    assert_eq!(AttachResult::try_from(1).ok(), Some(AttachResult::EpsOnly));
    assert_eq!(
        AttachResult::try_from(2).ok(),
        Some(AttachResult::CombinedEpsImsiAttach)
    );
    assert_eq!(AttachResult::try_from(3).ok(), None);
    let ie = EpsAttachResult::new(0x0a);
    assert_eq!(ie.attach_result_raw(), 2);
    assert_eq!(
        ie.attach_result(),
        Some(AttachResult::CombinedEpsImsiAttach)
    );
}

#[test]
fn an_eps_update_type_has_its_type_and_the_active_flag() {
    // Table 9.9.3.14.1
    let types = [
        (0, UpdateType::TaUpdating),
        (1, UpdateType::CombinedTaLaUpdating),
        (2, UpdateType::CombinedTaLaUpdatingWithImsiAttach),
        (3, UpdateType::PeriodicUpdating),
        (6, UpdateType::DisasterRoamingUpdate),
    ];
    for (value, update_type) in types {
        assert_eq!(UpdateType::try_from(value & 0x07).ok(), Some(update_type));
        assert_eq!(UpdateType::received(value & 0x07), Some(update_type));
        assert_eq!(
            EpsUpdateType::new(0x08 | value).update_type_strict(),
            Some(update_type)
        );
    }
    // 4 and 5 are read as TA updating by the network, 7 is reserved
    assert_eq!(UpdateType::try_from(5).ok(), None);
    assert_eq!(UpdateType::received(5), Some(UpdateType::TaUpdating));
    assert_eq!(UpdateType::received(7), None);
    let ie = EpsUpdateType::new(0x09);
    assert_eq!(ie.update_type_raw(), 1);
    assert!(ie.is_active());
}

#[test]
fn an_eps_update_result_is_one_of_table_9_9_3_13_1() {
    let results = [
        (0, UpdateResult::TaUpdated),
        (1, UpdateResult::CombinedTaLaUpdated),
        (4, UpdateResult::TaUpdatedAndIsrActivated),
        (5, UpdateResult::CombinedTaLaUpdatedAndIsrActivated),
    ];
    for (value, result) in results {
        assert_eq!(UpdateResult::try_from(value & 0x07).ok(), Some(result));
    }
    assert_eq!(UpdateResult::try_from(2).ok(), None);
    let ie = EpsUpdateResult::new(0x0d);
    assert_eq!(ie.update_result_raw(), 5);
    assert_eq!(
        ie.update_result(),
        Some(UpdateResult::CombinedTaLaUpdatedAndIsrActivated)
    );
}

/// The error of an ATTACH REQUEST whose EPS mobile identity is `identity`, a
/// length and its value.
fn attach_request_error(identity: &str) -> String {
    let octets = hex::decode(format!("074101{identity}02e0e000040201d031")).unwrap();
    Message::decode(&octets).unwrap_err().to_string()
}

#[test]
fn an_eps_mobile_identity_that_a_receiver_refuses_says_why() {
    // §9.9.3.12: an IMSI with a half octet that is no digit
    assert_eq!(
        attach_request_error("082980390a00000010"),
        "mandatory IE `eps-mobile-identity` has a value that is syntactically incorrect: \
         `imsi` has the half octet 0xa where a digit is, and a digit is 0 to 9"
    );
    // An IMSI of 16 digits, which no beginning of it reads as one of 15 at
    // most (TS 23.003 §2.2)
    assert_eq!(
        attach_request_error("09218039000000000000f1"),
        "mandatory IE `eps-mobile-identity` has a value that is syntactically incorrect: \
         `imsi` has 16 digits, and must have 6 to 15"
    );
    // An IMEI of 13 digits
    assert_eq!(
        attach_request_error("074b095124303257"),
        "mandatory IE `eps-mobile-identity` has a value that is syntactically incorrect: \
         `imei` has 13 digits, and must have 15"
    );
}

#[test]
fn an_eps_mobile_identity_has_the_odd_even_indication_in_bit_4() {
    let imsi = EpsMobileIdentity::from_imsi("208930000000001").unwrap();
    assert_eq!(imsi.is_odd_digits(), Some(true));
    let even = EpsMobileIdentity::from_imsi("20893000000001").unwrap();
    assert_eq!(even.is_odd_digits(), Some(false));
    assert_eq!(EpsMobileIdentity::new(Vec::new()).is_odd_digits(), None);
}

#[test]
fn an_eps_mobile_identity_of_an_imei_is_sent_with_the_spare_digit_0() {
    // TS 23.003 §6.2.1: an IMEI is sent with the spare digit 0
    let imei = EpsMobileIdentity::from_imei_tac_snr("49015420323751").unwrap();
    assert!(imei.is_well_formed());
    let spare_8 = EpsMobileIdentity::new(vec![0x4b, 0x09, 0x51, 0x24, 0x30, 0x32, 0x57, 0x81]);
    assert!(spare_8.as_imei().is_some());
    assert!(!spare_8.is_well_formed());
}

#[test]
fn a_detach_type_is_one_of_table_9_9_3_7_1_in_each_direction() {
    let ue = [
        (1, UeDetachKind::EpsDetach),
        (2, UeDetachKind::ImsiDetach),
        (3, UeDetachKind::CombinedEpsImsiDetach),
    ];
    for (value, kind) in ue {
        assert_eq!(UeDetachKind::try_from(value & 0x07).ok(), Some(kind));
        assert_eq!(
            UeDetachKind::try_from((0x08 | value) & 0x07).ok(),
            Some(kind)
        );
    }
    assert_eq!(UeDetachKind::try_from(4).ok(), None);
    // Other values are read as combined EPS/IMSI detach by the network
    assert_eq!(
        UeDetachKind::received(4),
        UeDetachKind::CombinedEpsImsiDetach
    );
    let network = [
        (1, NetworkDetachKind::ReattachRequired),
        (2, NetworkDetachKind::ReattachNotRequired),
        (3, NetworkDetachKind::ImsiDetach),
    ];
    for (value, kind) in network {
        assert_eq!(NetworkDetachKind::try_from(value & 0x07).ok(), Some(kind));
    }
    assert_eq!(NetworkDetachKind::try_from(0).ok(), None);
    // and as "re-attach not required" by the UE
    assert_eq!(
        NetworkDetachKind::received(0),
        NetworkDetachKind::ReattachNotRequired
    );
    let switch_off = DetachType::from_ue_detach_kind(UeDetachKind::ImsiDetach, true);
    assert_eq!(switch_off.value, 0x0a);
    assert!(switch_off.is_switch_off());
}

#[test]
fn an_apn_ambr_base_octet_of_0_is_reserved_unless_its_extension_replaces_it() {
    // §9.9.4.2, Table 9.9.4.2.1: 00000000 is reserved in octets 3 and 4
    assert_eq!(ApnAmbr::from_bytes(&[0x00, 0x08]), None);
    assert_eq!(ApnAmbr::from_bytes(&[0x08, 0x00]), None);
    assert!(ApnAmbr::from_bytes(&[0x08, 0x08]).is_some());
    let replaced = ApnAmbr::from_bytes(&[0x00, 0x08, 0x01, 0x00]).unwrap();
    assert_eq!(replaced.downlink_kbps(), Some(8_700));
}

#[test]
fn an_apn_ambr_is_coded_in_as_few_octets_as_its_rates_need() {
    // Up to 8640 kbps in octets 3 and 4, up to 256 Mbps with octets 5 and 6,
    // and up to 65280 Mbps with octets 7 and 8
    assert_eq!(
        ApnAmbr::from_kbps(8, 64).unwrap().to_bytes().unwrap(),
        [0x08, 0x40]
    );
    assert_eq!(
        ApnAmbr::from_kbps(100_000, 8).unwrap().to_bytes().unwrap(),
        [0xfe, 0x08, 0x9e, 0x00]
    );
    assert_eq!(
        ApnAmbr::from_kbps(8, 100_000).unwrap().to_bytes().unwrap(),
        [0x08, 0xfe, 0x00, 0x9e]
    );
    let extended2 = ApnAmbr::from_kbps(300_000, 8).unwrap();
    assert_eq!(extended2.extension2, Some([0x01, 0x00]));
    assert_eq!(extended2.downlink_kbps(), Some(300_000));
    let uplink2 = ApnAmbr::from_kbps(8, 300_000).unwrap();
    assert_eq!(uplink2.extension2, Some([0x00, 0x01]));
    assert_eq!(uplink2.uplink_kbps(), Some(300_000));
}

#[test]
fn an_extended_apn_ambr_replaces_the_rate_above_65280_mbps_alone() {
    // §9.9.4.29: 65280 Mbps is 16320 times the unit of 4 Mbps (3)
    let ambr = ApnAggregateMaximumBitRate::from_kbps(8, 8).unwrap();
    let at_limit = ExtendedApnAggregateMaximumBitRate::from_kbps(65_280_000, 65_280_000).unwrap();
    assert_eq!(at_limit.value.as_slice(), [3, 0x3f, 0xc0, 3, 0x3f, 0xc0]);
    assert_eq!(at_limit.uplink_kbps(), Some(65_280_000));
    assert!(at_limit.is_well_formed());
    assert_eq!(
        ambr.effective_kbps(Some(&at_limit)),
        Some(ApnAmbrValue {
            dl_kbps: 8,
            ul_kbps: 8,
        })
    );
    let above = ExtendedApnAggregateMaximumBitRate::from_kbps(65_284_000, 65_284_000).unwrap();
    assert_eq!(
        ambr.effective_kbps(Some(&above)),
        Some(ApnAmbrValue {
            dl_kbps: 65_284_000,
            ul_kbps: 65_284_000,
        })
    );
    let uplink_above =
        ExtendedApnAggregateMaximumBitRate::from_kbps(65_280_000, 65_284_000).unwrap();
    assert_eq!(
        ambr.effective_kbps(Some(&uplink_above)),
        Some(ApnAmbrValue {
            dl_kbps: 8,
            ul_kbps: 65_284_000,
        })
    );
    // Units 0 to 2 are not used by a sender
    assert!(!ExtendedApnAggregateMaximumBitRate::new(vec![2, 0, 1, 3, 0, 1]).is_well_formed());
}

#[test]
fn an_eps_qos_is_coded_in_as_few_octets_as_its_rates_need() {
    // §9.9.4.3: up to 8640 kbps in octets 4 to 7, up to 256 Mbps with octets 8
    // to 11, and up to 10 Gbps with octets 12 to 15
    let plain = EpsQos::from_kbps(1, [64, 64, 8, 8]).unwrap();
    assert_eq!(plain.bit_rates, Some([0x40, 0x40, 0x08, 0x08]));
    assert_eq!(plain.extension, None);
    assert_eq!(plain.extension2, None);
    let extended = EpsQos::from_kbps(1, [64, 64, 8, 100_000]).unwrap();
    assert_eq!(extended.bit_rates, Some([0x40, 0x40, 0x08, 0xfe]));
    assert_eq!(extended.extension, Some([0, 0, 0, 0x9e]));
    assert_eq!(extended.extension2, None);
    let extended2 = EpsQos::from_kbps(1, [64, 64, 8, 1_000_000]).unwrap();
    assert_eq!(extended2.extension, Some([0, 0, 0, 0xfa]));
    assert!(extended2.extension2.is_some_and(|group| group[3] != 0));
    assert_eq!(extended2.gbr_dl(), Some(EpsBitRate::Kbps(1_000_000)));
    let first = EpsQos::from_kbps(1, [1_000_000, 64, 8, 8]).unwrap();
    assert_eq!(first.extension, Some([0xfa, 0, 0, 0]));
    assert_eq!(first.mbr_ul(), Some(EpsBitRate::Kbps(1_000_000)));
}

#[test]
fn the_gbr_qcis_are_those_of_ts_23_203() {
    // TS 23.203 Table 6.1.7: QCI 1 to 4, 65 to 67, 71 to 76 and 82 to 85
    for qci in [1, 4, 65, 67, 71, 76, 82, 85] {
        assert!(EpsQos::new(qci, None, None, None).is_gbr(), "{qci}");
    }
    for qci in [5, 9, 69, 70, 79, 80, 128] {
        assert!(!EpsQos::new(qci, None, None, None).is_gbr(), "{qci}");
    }
}

/// A quality of service of TS 24.008 §10.5.6.5 of twelve value octets
/// (octets 3 to 14) whose fields have defined codes.
fn qos_of_24008() -> Vec<u8> {
    vec![
        0x1b, // delay class 3, reliability class 3
        0x92, // peak throughput 9, precedence 2
        0x1f, // mean throughput best effort
        0x73, // interactive class, without delivery order, erroneous SDUs not delivered
        0x96, // maximum SDU size 1500 octets
        0x40, 0x40, // maximum bit rates 64 kbps
        0x73, // residual BER 7, SDU error ratio 3
        0x4a, // transfer delay 18, traffic handling priority 2
        0x40, 0x40, // guaranteed bit rates 64 kbps
        0x10, // signalling indication
    ]
}

#[test]
fn a_quality_of_service_of_ts_24_008_has_its_fields_in_their_octets() {
    let qos = QualityOfService::new(qos_of_24008());
    assert_eq!(qos.delay_class(), Some(3));
    assert_eq!(qos.reliability_class(), Some(3));
    assert_eq!(qos.peak_throughput(), Some(9));
    assert_eq!(qos.precedence_class(), Some(2));
    assert_eq!(qos.mean_throughput(), Some(31));
    assert_eq!(qos.traffic_class_raw(), Some(3));
    assert_eq!(qos.delivery_order_raw(), Some(2));
    assert_eq!(qos.delivery_of_erroneous_sdu_raw(), Some(3));
    assert_eq!(qos.maximum_sdu_size_raw(), Some(0x96));
    assert_eq!(qos.residual_ber_raw(), Some(7));
    assert_eq!(qos.sdu_error_ratio_raw(), Some(3));
    assert_eq!(qos.transfer_delay_raw(), Some(18));
    assert_eq!(qos.traffic_handling_priority_raw(), Some(2));
    assert_eq!(qos.signalling_indication(), Some(true));
    let mut octets = qos_of_24008();
    octets[11] = 0x01;
    assert_eq!(
        QualityOfService::new(octets).signalling_indication(),
        Some(false)
    );
    let short = QualityOfService::new(vec![0x1b, 0x92, 0x1f]);
    assert_eq!(short.delivery_order_raw(), None);
    assert_eq!(short.delivery_of_erroneous_sdu_raw(), None);
    assert_eq!(short.maximum_sdu_size_raw(), None);
    assert_eq!(short.residual_ber_raw(), None);
    assert_eq!(short.sdu_error_ratio_raw(), None);
    assert_eq!(short.traffic_handling_priority_raw(), None);
}

#[test]
fn the_classes_of_a_quality_of_service_are_read_with_the_receiver_rules() {
    let with = |index: usize, octet: u8| {
        let mut octets = qos_of_24008();
        octets[index] = octet;
        QualityOfService::new(octets)
    };
    // Table 10.5.156: delay classes 1 to 4, the others read as 4 but 0 and 7
    for (class, read) in [
        (0, None),
        (1, Some(1)),
        (4, Some(4)),
        (5, Some(4)),
        (7, None),
    ] {
        assert_eq!(with(0, class << 3 | 3).delay_class(), read, "{class}");
    }
    // reliability class 001 is read as 010, 110 as 011
    for (class, read) in [
        (0, None),
        (1, Some(2)),
        (2, Some(2)),
        (5, Some(5)),
        (6, Some(3)),
        (7, None),
    ] {
        assert_eq!(with(0, 0x08 | class).reliability_class(), read, "{class}");
    }
    // peak throughput classes 1 to 9, the others read as 1 but 0 and 15
    for (class, read) in [
        (0, None),
        (1, Some(1)),
        (9, Some(9)),
        (10, Some(1)),
        (15, None),
    ] {
        assert_eq!(with(1, class << 4 | 2).peak_throughput(), read, "{class}");
    }
    // precedence classes 1 to 3, the others read as 2 but 0 and 7
    for (class, read) in [
        (0, None),
        (1, Some(1)),
        (3, Some(3)),
        (4, Some(2)),
        (7, None),
    ] {
        assert_eq!(with(1, 0x90 | class).precedence_class(), read, "{class}");
    }
    // mean throughput classes 1 to 18 and 31, the others read as 31 but 0 and 30
    for (class, read) in [
        (0, None),
        (1, Some(1)),
        (18, Some(18)),
        (19, Some(31)),
        (30, None),
    ] {
        assert_eq!(with(2, class).mean_throughput(), read, "{class}");
    }
}

#[test]
fn a_quality_of_service_of_ts_24_008_has_the_lengths_of_its_extensions() {
    // §10.5.6.5: the three- and eleven-octet values of earlier versions, and
    // each pair of extension octets after the twelve
    for length in [3, 11, 12, 14, 16, 18, 20] {
        assert!(QualityOfService::new(vec![0x1b; length]).receiver_syntax_is_valid());
    }
    for length in [0, 5, 13, 21] {
        assert!(!QualityOfService::new(vec![0x1b; length]).receiver_syntax_is_valid());
    }
}

#[test]
fn a_sender_writes_a_quality_of_service_of_defined_codes() {
    assert!(QualityOfService::new(qos_of_24008()).is_well_formed());
    // Bits 8 to 6 of octet 14 and its source statistics descriptor are not
    // written by the network
    let mut octets = qos_of_24008();
    octets[11] = 0x11;
    assert!(!QualityOfService::new(octets).is_well_formed());
    let mut reserved_delay = qos_of_24008();
    reserved_delay[0] = 0x3b;
    assert!(!QualityOfService::new(reserved_delay).is_well_formed());
}

#[test]
fn an_extension_of_a_quality_of_service_follows_a_full_base_octet() {
    // Octets 15 and 16 (value 12, 13) extend octets 9 and 13 (value 6, 10),
    // 17 and 18 (14, 15) octets 8 and 12 (5, 9), and 19 to 22 (16 to 19)
    // octets 15 to 18; an extension is used after 11111110, an extension-2
    // after 11111010
    let with = |extension: &[(usize, u8)]| {
        let mut octets = qos_of_24008();
        let length = extension
            .iter()
            .map(|(index, _)| index + 1)
            .max()
            .unwrap_or(12);
        octets.resize(length.max(12) + length % 2, 0);
        for &(index, octet) in extension {
            octets[index] = octet;
        }
        QualityOfService::new(octets).is_well_formed()
    };
    assert!(with(&[(13, 0)]));
    assert!(with(&[(6, 0xfe), (12, 0x10), (13, 0)]));
    assert!(!with(&[(12, 0x10), (13, 0)]));
    assert!(!with(&[(6, 0xfe), (12, 0xfb), (13, 0)]));
    assert!(!with(&[(10, 0xfe), (13, 0xfb)]));
    assert!(with(&[(5, 0xfe), (14, 0x10), (15, 0)]));
    assert!(!with(&[(5, 0xfe), (14, 0xfb), (15, 0)]));
    assert!(!with(&[(9, 0xfe), (14, 0), (15, 0xfb)]));
    assert!(with(&[(6, 0xfe), (12, 0xfa), (16, 0x10), (17, 0)]));
    assert!(!with(&[(6, 0xfe), (12, 0xfa), (16, 0xf7), (17, 0)]));
    assert!(!with(&[(10, 0xfe), (13, 0xfa), (16, 0), (17, 0xf7)]));
    assert!(with(&[(5, 0xfe), (14, 0xfa), (18, 0x10), (19, 0)]));
    assert!(!with(&[(5, 0xfe), (14, 0xfa), (18, 0xf7), (19, 0)]));
    assert!(!with(&[(9, 0xfe), (15, 0xfa), (18, 0), (19, 0xf7)]));
}

#[test]
fn an_extended_eps_qos_carries_the_rates_above_10_gbps() {
    // §9.9.4.30: a rate of 10 Gbps or less is carried by the EPS QoS IE, and
    // read as none here; unit 1 is 200 kbps
    let at_limit = ExtendedEpsQos {
        mbr_unit: 1,
        mbr_ul: 50_000,
        mbr_dl: 50_001,
        gbr_unit: 1,
        gbr_ul: 50_001,
        gbr_dl: 0,
    };
    assert_eq!(at_limit.mbr_ul_kbps(), None);
    assert_eq!(at_limit.mbr_dl_kbps(), Some(10_000_200));
    assert_eq!(at_limit.gbr_ul_kbps(), Some(10_000_200));
    assert_eq!(at_limit.gbr_dl_kbps(), None);
    let sent = ExtendedEpsQos::from_kbps(10_000_000, 10_000_200, 0, 20_000_000).unwrap();
    assert_eq!((sent.mbr_ul, sent.mbr_dl), (0, 50_001));
    assert_eq!(sent.gbr_ul_kbps(), None);
    assert_eq!(sent.gbr_dl_kbps(), Some(20_000_000));
    // A sender writes ten octets and units from 1
    assert!(ExtendedQualityOfService::from_qos(sent).is_well_formed());
    assert!(!ExtendedQualityOfService::new(vec![0; 10]).is_well_formed());
    assert!(!ExtendedQualityOfService::new(vec![1; 9]).is_well_formed());
}

#[test]
fn a_tft_operation_is_one_of_table_10_5_162() {
    let operations = [
        TftOperation::Ignore,
        TftOperation::Create,
        TftOperation::Delete,
        TftOperation::AddFilters,
        TftOperation::ReplaceFilters,
        TftOperation::DeleteFilters,
        TftOperation::NoOperation,
    ];
    for (value, operation) in operations.into_iter().enumerate() {
        assert_eq!(TftOperation::try_from(value as u8).ok(), Some(operation));
    }
    assert_eq!(TftOperation::try_from(7).ok(), None);
}

#[test]
fn a_flow_label_and_a_pcp_dei_component_have_spare_bits_that_a_sender_clears() {
    // TS 24.008 Table 10.5.162: bits 8 to 5 of the first octet of a flow
    // label are spare, ignored by a receiver
    let received = TftPacketFilter::new(1, 3, Some(9), vec![0x80, 0xf1, 0x23, 0x45]);
    assert_eq!(
        received.components(),
        Some(vec![TftPacketFilterComponent::FlowLabel(0x12345)])
    );
    // A PCP of three bits in bits 4 to 2 and the DEI in bit 1, the four high bits
    // spare
    let tag =
        |kind: u8, octet: u8| TftPacketFilter::new(1, 3, Some(9), vec![kind, octet]).components();
    assert_eq!(
        tag(0x85, 0x0a),
        Some(vec![TftPacketFilterComponent::CTagPcpDei {
            pcp: 5,
            dei: false
        }])
    );
    assert_eq!(
        tag(0x85, 0xf3),
        Some(vec![TftPacketFilterComponent::CTagPcpDei {
            pcp: 1,
            dei: true
        }])
    );
    assert_eq!(
        tag(0x86, 0x0b),
        Some(vec![TftPacketFilterComponent::STagPcpDei {
            pcp: 5,
            dei: true
        }])
    );
    // and not written by a sender
    let tft = |contents: Vec<u8>| {
        Tft::new(
            TftOperation::Create,
            vec![TftPacketFilter::new(1, 3, Some(9), contents)],
            Vec::new(),
        )
        .to_bytes()
    };
    assert!(tft(vec![0x80, 0x01, 0x23, 0x45]).is_ok());
    assert!(tft(vec![0x80, 0xf1, 0x23, 0x45]).is_err());
}

#[cfg(feature = "tree")]
#[test]
fn a_packet_filter_of_no_contents_shows_none() {
    let deleted = serde_json::to_value(TftPacketFilter::new(3, 0, None, Vec::new())).unwrap();
    let members = deleted.as_object().unwrap();
    assert!(!members.contains_key("components"), "{deleted}");
    assert!(!members.contains_key("contents"), "{deleted}");
    // A direction may be written as its number
    let read: TftPacketFilter = serde_json::from_value(serde_json::json!({
        "identifier": 1,
        "direction": 2,
        "precedence": 5,
        "contents": "3006",
    }))
    .unwrap();
    assert_eq!(read, TftPacketFilter::new(1, 2, Some(5), vec![0x30, 0x06]));
}

#[test]
fn the_cs_lcs_field_is_bits_5_and_4_of_octet_3() {
    // §9.9.3.12A: setting CS-LCS keeps the other flags
    let mut support = EpsNetworkFeatureSupport::new(vec![0x11]);
    support.set_cs_lcs(CsLcsSupport::Supported);
    assert_eq!(support.value.as_slice(), [0x09]);
    assert_eq!(support.cs_lcs(), Some(CsLcsSupport::Supported));
}

#[test]
fn s1_u_data_and_overhead_reduction_depend_on_cp_ciot() {
    // §9.9.3.12A: S1-U data transfer is supported when CP CIoT is not
    // indicated, and OHR is ignored when CP CIoT is not indicated
    let none = EpsNetworkFeatureSupport::new(vec![0x00, 0x00]);
    assert!(none.s1u_data_supported());
    assert!(!none.ohr_cp_ciot_supported());
    let cp_ciot = EpsNetworkFeatureSupport::new(vec![0x80, 0x00]);
    assert!(!cp_ciot.s1u_data_supported());
    let cp_ciot_and_s1u = EpsNetworkFeatureSupport::new(vec![0x80, 0x02]);
    assert!(cp_ciot_and_s1u.s1u_data_supported());
    let with_ohr = EpsNetworkFeatureSupport::new(vec![0x80, 0x00])
        .with_cp_ciot(true)
        .with_ohr_cp_ciot(true);
    assert!(with_ohr.ohr_cp_ciot_supported());
    let ohr_alone = EpsNetworkFeatureSupport::new(vec![0x00, 0x00]).with_ohr_cp_ciot(true);
    assert!(!ohr_alone.ohr_cp_ciot_supported());
}

#[test]
fn a_header_compression_configuration_status_has_two_octets_and_ebi_0_spare() {
    // §9.9.4.27
    let status = HeaderCompressionConfigurationStatus::from_not_used_ebis(&[5, 15]).unwrap();
    assert_eq!(status.value.as_slice(), [0x20, 0x80]);
    assert!(status.is_well_formed());
    assert!(!HeaderCompressionConfigurationStatus::new(vec![0x21, 0x80]).is_well_formed());
    assert!(!HeaderCompressionConfigurationStatus::new(vec![0x20]).is_well_formed());
}

#[test]
fn an_additional_update_result_is_one_of_table_9_9_3_0a_1() {
    let results = [
        (0, AdditionalUpdateResultValue::NoAdditionalInformation),
        (1, AdditionalUpdateResultValue::CsFallbackNotPreferred),
        (2, AdditionalUpdateResultValue::SmsOnly),
    ];
    for (value, result) in results {
        assert_eq!(
            AdditionalUpdateResultValue::try_from(value & 0x03).ok(),
            Some(result)
        );
    }
    assert_eq!(AdditionalUpdateResultValue::try_from(3).ok(), None);
    let ie = AdditionalUpdateResult::new(0x06);
    assert_eq!(ie.result_raw(), 2);
    assert_eq!(ie.result(), Some(AdditionalUpdateResultValue::SmsOnly));
}

#[test]
fn a_radio_priority_is_level_1_to_4() {
    // TS 24.008 §10.5.7.2: other values are read as level 4
    let levels = [
        (1, RadioPriorityLevel::One),
        (2, RadioPriorityLevel::Two),
        (3, RadioPriorityLevel::Three),
        (4, RadioPriorityLevel::Four),
    ];
    for (value, level) in levels {
        assert_eq!(RadioPriorityLevel::try_from(value & 0x07).ok(), Some(level));
    }
    assert_eq!(RadioPriorityLevel::try_from(0).ok(), None);
    assert_eq!(RadioPriorityLevel::received(5), RadioPriorityLevel::Four);
    let ie = RadioPriority::new(0x0a);
    assert_eq!(ie.priority_level_raw(), 2);
    assert_eq!(ie.priority_level(), RadioPriorityLevel::Two);
}

#[test]
fn the_fields_of_a_calling_party_number_are_those_of_ts_24_008() {
    // TS 24.008 Table 10.5.118: the type of number and the numbering plan
    let types = [
        CallingPartyTypeOfNumber::Unknown,
        CallingPartyTypeOfNumber::International,
        CallingPartyTypeOfNumber::National,
        CallingPartyTypeOfNumber::NetworkSpecific,
        CallingPartyTypeOfNumber::DedicatedAccessShortCode,
    ];
    for (value, kind) in types.into_iter().enumerate() {
        assert_eq!(
            CallingPartyTypeOfNumber::try_from(value as u8).ok(),
            Some(kind)
        );
    }
    assert_eq!(CallingPartyTypeOfNumber::try_from(5).ok(), None);
    let plans = [
        (0, CallingPartyNumberingPlan::Unknown),
        (1, CallingPartyNumberingPlan::Isdn),
        (3, CallingPartyNumberingPlan::Data),
        (4, CallingPartyNumberingPlan::Telex),
        (8, CallingPartyNumberingPlan::National),
        (9, CallingPartyNumberingPlan::Private),
    ];
    for (value, plan) in plans {
        assert_eq!(CallingPartyNumberingPlan::try_from(value).ok(), Some(plan));
    }
    assert_eq!(CallingPartyNumberingPlan::try_from(2).ok(), None);
    // Table 10.5.120: the presentation and the screening indicators
    let presentations = [
        CallingPartyPresentation::Allowed,
        CallingPartyPresentation::Restricted,
        CallingPartyPresentation::Unavailable,
    ];
    for (value, presentation) in presentations.into_iter().enumerate() {
        assert_eq!(
            CallingPartyPresentation::try_from(value as u8).ok(),
            Some(presentation)
        );
    }
    assert_eq!(CallingPartyPresentation::try_from(3).ok(), None);
    let screenings = [
        CallingPartyScreening::UserProvidedNotScreened,
        CallingPartyScreening::UserProvidedVerifiedPassed,
        CallingPartyScreening::UserProvidedVerifiedFailed,
        CallingPartyScreening::NetworkProvided,
    ];
    for (value, screening) in screenings.into_iter().enumerate() {
        assert_eq!(
            CallingPartyScreening::try_from(value as u8).ok(),
            Some(screening)
        );
    }
    assert_eq!(CallingPartyScreening::try_from(4).ok(), None);
}

#[test]
fn a_cli_has_a_type_of_number_and_a_numbering_plan_of_the_tables() {
    // §9.9.3.38: octets 3 to 14 of the calling party BCD number of TS 24.008
    // §10.5.4.9, octet 3a after octet 3 when bit 8 of octet 3 is 0
    let cli = |octets: &[u8]| Cli::new(octets.to_vec());
    assert!(cli(&[0x91, 0x21, 0x43]).receiver_syntax_is_valid());
    // Type of number 111 and numbering plan 0010 are none of the tables
    assert!(!cli(&[0xf1, 0x21]).receiver_syntax_is_valid());
    assert!(!cli(&[0x92, 0x21]).receiver_syntax_is_valid());
    // Octet 3a has bit 8 set, and a presentation of the table
    assert!(cli(&[0x11, 0x80, 0x21]).receiver_syntax_is_valid());
    assert!(cli(&[0x11, 0xa3, 0x21]).receiver_syntax_is_valid());
    assert!(!cli(&[0x11, 0x00, 0x21]).receiver_syntax_is_valid());
    assert!(!cli(&[0x11, 0xe0, 0x21]).receiver_syntax_is_valid());
}

#[test]
fn a_sender_writes_a_cli_of_12_octets_at_most_with_its_spare_bits_clear() {
    let cli = |octets: &[u8]| Cli::new(octets.to_vec());
    assert!(cli(&[0x91, 0x54, 0x76]).is_well_formed());
    assert!(cli(&[0x11, 0x80, 0x54]).is_well_formed());
    // Bits 5 to 3 of octet 3a are spare
    assert!(!cli(&[0x11, 0x84, 0x54]).is_well_formed());
    // Twelve octets, and not thirteen
    let twelve = [&[0x91][..], &[0x21; 11]].concat();
    assert!(cli(&twelve).is_well_formed());
    let thirteen = [&[0x91][..], &[0x21; 12]].concat();
    assert!(!cli(&thirteen).is_well_formed());
    assert!(!cli(&[0xf1, 0x21]).is_well_formed());
    // An international or national number has decimal digits, the others the
    // signs of Table 10.5.118 too
    let unknown = CallingPartyNumber::new(0, 1, None, "*12#".to_string());
    let unknown = Cli::from_number(&unknown).unwrap();
    assert!(unknown.is_well_formed());
    let national = Cli::new(vec![0xa1, 0x21, 0xfa]);
    assert!(!national.is_well_formed());
    let international = CallingPartyNumber::new(1, 1, Some((1, 3)), "33612".to_string());
    let international = Cli::from_number(&international).unwrap();
    assert_eq!(international.value.as_slice()[..2], [0x11, 0xa3]);
    assert!(international.is_well_formed());
}

#[test]
fn an_nb_s1_drx_value_is_one_of_table_9_9_3_63_1() {
    let values = [
        NbS1DrxValue::NotSpecified,
        NbS1DrxValue::T32,
        NbS1DrxValue::T64,
        NbS1DrxValue::T128,
        NbS1DrxValue::T256,
        NbS1DrxValue::T512,
        NbS1DrxValue::T1024,
    ];
    for (value, drx) in values.into_iter().enumerate() {
        assert_eq!(NbS1DrxValue::try_from((value as u8) & 0x0f).ok(), Some(drx));
        assert_eq!(NbS1DrxValue::received((value as u8) & 0x0f), drx);
    }
    // Other values are read as "not specified"
    assert_eq!(NbS1DrxValue::try_from(7).ok(), None);
    assert_eq!(NbS1DrxValue::received(7), NbS1DrxValue::NotSpecified);
}

#[test]
fn a_packet_flow_identifier_has_seven_bits_and_a_spare_bit() {
    // TS 24.008 §10.5.6.11: values 4 to 7 reserved, bit 8 spare
    let dynamic = PacketFlowIdentifier::new(vec![0x08]);
    assert_eq!(dynamic.pfi_raw(), Some(8));
    assert!(dynamic.is_well_formed());
    let spare = PacketFlowIdentifier::new(vec![0x88]);
    assert_eq!(spare.pfi_raw(), Some(8));
    assert!(!spare.is_well_formed());
    assert!(!PacketFlowIdentifier::new(vec![0x04]).is_well_formed());
    assert_eq!(PacketFlowIdentifier::new(Vec::new()).pfi_raw(), None);
}

#[test]
fn the_ue_radio_capability_id_flags_are_their_low_bits() {
    // §9.9.3.58: the UE radio capability ID availability in bits 3 to 1, 001
    // available
    let available = UeRadioCapabilityIdAvailability::new(vec![0x01]);
    assert_eq!(available.is_available(), Some(true));
    assert_eq!(
        UeRadioCapabilityIdAvailability::new(vec![0x09]).is_available(),
        Some(true)
    );
    assert_eq!(
        UeRadioCapabilityIdAvailability::new(vec![0x00]).is_available(),
        Some(false)
    );
    // UE radio capability ID request: bit 1
    assert_eq!(
        UeRadioCapabilityIdRequest::new(vec![0x00]).is_requested(),
        Some(false)
    );
    assert_eq!(
        UeRadioCapabilityIdRequest::new(vec![0x02]).is_requested(),
        Some(false)
    );
    assert_eq!(
        UeRadioCapabilityIdRequest::new(vec![0x01]).is_requested(),
        Some(true)
    );
}

#[test]
fn a_nonce_is_set_to_its_four_octets() {
    let mut nonce = Nonce::from_nonce(1);
    nonce.set_nonce(0x0102_0304);
    assert_eq!(nonce.value.as_slice(), [1, 2, 3, 4]);
    assert_eq!(nonce.nonce(), Some(0x0102_0304));
}

#[test]
fn a_hash_mme_has_eight_octets_and_an_additional_security_capability_four() {
    // §9.9.3.50 and §9.9.3.53
    assert!(HashMme::new(vec![0; 8]).is_well_formed());
    assert!(!HashMme::new(vec![0; 7]).is_well_formed());
    assert!(UeAdditionalSecurityCapability::new(vec![0; 4]).is_well_formed());
    assert!(!UeAdditionalSecurityCapability::new(vec![0; 3]).is_well_formed());
}

#[test]
fn the_gprs_algorithms_of_an_ms_network_capability_are_in_octets_4_and_6() {
    // TS 24.008 §10.5.5.12: the SS screening indicator in bits 4 and 3 of
    // octet 3; GIA/4 to GIA/7 in bits 7 to 4 of octet 6, between the user
    // plane integrity bit (bit 8) and ePCO (bit 3)
    let capability = MsNetworkCapability::new(vec![0x08, 0x00, 0x00, 0x50]);
    assert_eq!(capability.ss_screening_indicator(), Some(2));
    assert!(capability.supports_gia(4));
    assert!(!capability.supports_gia(5));
    assert!(capability.supports_gia(6));
    assert!(!capability.supports_gia(7));
    let gia5 = MsNetworkCapability::new(vec![0x00, 0x00, 0x00, 0x20]);
    assert!(gia5.supports_gia(5));
    assert!(!gia5.supports_gia(4));
    let gia7 = MsNetworkCapability::new(vec![0x00, 0x00, 0x00, 0x08]);
    assert!(gia7.supports_gia(7));
    // The bits around them are no GIA
    let others = MsNetworkCapability::new(vec![0x00, 0x00, 0x00, 0x87]);
    for algo in 2..=8 {
        assert!(!others.supports_gia(algo), "{algo}");
    }
    assert!(!MsNetworkCapability::new(vec![0x00, 0x00, 0x00]).supports_gia(4));
}

#[test]
fn a_sender_writes_an_ms_network_capability_of_2_to_8_octets_and_spare_octets_zero() {
    assert!(MsNetworkCapability::new(vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_well_formed());
    assert!(!MsNetworkCapability::new(vec![0x00, 0x00, 0x00, 0x00, 0x01]).is_well_formed());
    // and a mobile station classmark 3 of 32 octets at most
    assert!(MobileStationClassmark3::new(vec![0; 32]).is_well_formed());
    assert!(!MobileStationClassmark3::new(vec![0; 33]).is_well_formed());
}

#[test]
fn the_half_octet_flags_of_emm_are_their_bits() {
    // §9.9.3.0B: SMS only (bit 1) and "signalling active" (bit 2)
    assert!(AdditionalUpdateType::new(0x01).sms_only());
    assert!(!AdditionalUpdateType::new(0x02).sms_only());
    assert!(AdditionalUpdateType::new(0x02).signalling_active());
    assert!(!AdditionalUpdateType::new(0x01).signalling_active());
    // The additional information requested has bits 2 to 4 spare
    assert!(AdditionalInformationRequested::new(0x01).is_well_formed());
    assert!(!AdditionalInformationRequested::new(0x02).is_well_formed());
    // §9.9.3.5: CS fallback rejected (000) or accepted (001) by the UE
    assert_eq!(CsfbResponse::new(0).accepted(), Some(false));
    assert_eq!(CsfbResponse::new(1).accepted(), Some(true));
    assert_eq!(CsfbResponse::new(2).accepted(), None);
    // TS 24.008 §10.5.6.19: the connectivity type in bits 4 to 1
    assert_eq!(ConnectivityType::new(0x12).connectivity_type_raw(), 2);
    // TS 24.008 §10.5.6.20: S1 mode offload (bit 1) and Iu mode (bit 2)
    assert_eq!(
        WlanOffloadAcceptability::from_acceptability(true, false).value,
        1
    );
    assert_eq!(
        WlanOffloadAcceptability::from_acceptability(false, true).value,
        2
    );
}

#[test]
fn an_extended_emm_cause_has_four_flags() {
    // §9.9.3.26A: E-UTRAN (bit 1), EPS optimization (bit 2), NB-IoT (bit 3)
    // and satellite E-UTRAN (bit 4)
    let none = ExtendedEmmCause::new(0);
    assert!(!none.eutran_not_allowed());
    assert!(!none.nb_iot_not_allowed());
    for (bit, cause) in [0x01, 0x02, 0x04, 0x08].map(|bit| (bit, ExtendedEmmCause::new(bit))) {
        assert_eq!(cause.eutran_not_allowed(), bit == 0x01);
        assert_eq!(cause.eps_optimization_not_supported(), bit == 0x02);
        assert_eq!(cause.nb_iot_not_allowed(), bit == 0x04);
        assert_eq!(cause.satellite_eutran_not_allowed(), bit == 0x08);
    }
    assert_eq!(
        ExtendedEmmCause::from_flags(false, true, false, false).value,
        0x02
    );
    assert_eq!(
        ExtendedEmmCause::from_flags(false, false, true, false).value,
        0x04
    );
    assert_eq!(
        ExtendedEmmCause::from_flags(false, false, false, true).value,
        0x08
    );
}

#[test]
fn the_values_of_a_generic_container_type_lcs_and_sms_services_are_those_of_their_tables() {
    // §9.9.3.42: LPP (1) and LCS (2)
    assert_eq!(
        GenericMessageContainerTypeValue::try_from(1).ok(),
        Some(GenericMessageContainerTypeValue::Lpp)
    );
    assert_eq!(
        GenericMessageContainerTypeValue::try_from(2).ok(),
        Some(GenericMessageContainerTypeValue::Lcs)
    );
    // §9.9.3.40: MT-LR (1), the others "normal, unspecified"
    assert!(LcsIndicator::new(1).is_mt_lr());
    assert!(!LcsIndicator::new(0).is_mt_lr());
    // §9.9.3.4B: the SMS services status in bits 3 to 1
    let statuses = [
        SmsServicesStatusValue::Unavailable,
        SmsServicesStatusValue::UnavailableInPlmn,
        SmsServicesStatusValue::NetworkFailure,
        SmsServicesStatusValue::Congestion,
    ];
    for (value, status) in statuses.into_iter().enumerate() {
        assert_eq!(
            SmsServicesStatusValue::try_from((value as u8) & 0x07).ok(),
            Some(status)
        );
        assert_eq!(
            SmsServicesStatusValue::try_from((0x08 | value as u8) & 0x07).ok(),
            Some(status)
        );
        assert_eq!(SmsServicesStatus::new(value as u8).status(), Some(status));
    }
    assert_eq!(SmsServicesStatusValue::try_from(4).ok(), None);
}

#[test]
fn the_one_bit_requests_of_emm_are_bit_1() {
    // §9.9.3.71 and §9.9.3.35: the UE information request and the UE radio
    // capability information update needed
    assert!(UeInformationRequest::new(1).requested());
    assert!(!UeInformationRequest::new(0).requested());
    assert!(!UeInformationRequest::new(2).requested());
    assert!(UeRadioCapabilityInformationUpdateNeeded::new(1).update_needed());
    assert!(!UeRadioCapabilityInformationUpdateNeeded::new(0).update_needed());
    assert!(!UeRadioCapabilityInformationUpdateNeeded::new(2).update_needed());
    // TS 24.008 §10.5.1.2: a ciphering key sequence number of 111 is "no key
    // is available"
    assert!(CipheringKeySequenceNumber::new(7).no_key_available());
    assert!(!CipheringKeySequenceNumber::new(3).no_key_available());
}

#[test]
fn an_llc_sapi_is_one_of_ts_24_008_section_10_5_6_9() {
    let sapis = [
        (0, LlcSapi::NotAssigned),
        (3, LlcSapi::Sapi3),
        (5, LlcSapi::Sapi5),
        (9, LlcSapi::Sapi9),
        (11, LlcSapi::Sapi11),
    ];
    for (value, sapi) in sapis {
        assert_eq!(LlcSapi::try_from(value & 0x0f).ok(), Some(sapi));
    }
    assert_eq!(LlcSapi::try_from(1).ok(), None);
    let ie = LlcServiceAccessPointIdentifier::new(0x05);
    assert_eq!(ie.sapi_raw(), 5);
    assert_eq!(LlcServiceAccessPointIdentifier::new(0x39).sapi_raw(), 9);
}
