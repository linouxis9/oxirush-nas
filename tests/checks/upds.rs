//! The UE policy delivery service of TS 24.501 Annex D: the IEs of its
//! messages, each read as its clause of D.6 codes it and refused where it
//! overruns, the messages in their envelope, and what `validate()` finds.

use oxirush_nas::identity::Plmn;
use oxirush_nas::nas_5gs::*;
use oxirush_nas::{Encode, NasError, Validate};

fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

fn plmn(mcc: &str, mnc: &str) -> Plmn {
    Plmn::new(mcc, mnc).unwrap()
}

#[test]
fn the_flags_of_the_ue_policy_classmarks_are_their_bits() {
    // D.6.5: SupportANDSP (bit 1), EPSURSP (bit 2), SVPSU (bit 3) and
    // SupportRURE (bit 4)
    let flags = |octet: u8| {
        let classmark = NasUePolicyClassmark::new(vec![octet]);
        [
            classmark.support_andsp(),
            classmark.eps_ursp(),
            classmark.svpsu(),
            classmark.support_rure(),
        ]
    };
    assert_eq!(flags(0x00), [false; 4]);
    assert_eq!(flags(0x01), [true, false, false, false]);
    assert_eq!(flags(0x02), [false, true, false, false]);
    assert_eq!(flags(0x04), [false, false, true, false]);
    assert_eq!(flags(0x08), [false, false, false, true]);
    assert_eq!(flags(0xf0), [false; 4]);
    assert_eq!(
        NasUePolicyClassmark::from_flags(false, true, false, false).value,
        [0x02]
    );
    assert_eq!(
        NasUePolicyClassmark::from_flags(true, true, true, true).value,
        [0x0f]
    );
    // D.6.7: NSSUI (bit 1)
    assert!(NasUePolicyNetworkClassmark::new(vec![0x01]).nssui());
    assert!(!NasUePolicyNetworkClassmark::new(vec![0x00]).nssui());
    // D.6.6: OS Ids of sixteen octets
    let os_id = NasUeOsId::from_os_ids(&[[1; 16], [2; 16]]).unwrap();
    assert_eq!(os_id.os_ids(), vec![[1; 16], [2; 16]]);
}

#[test]
fn an_unknown_ie_is_comprehension_required_as_ts_24_007_codes_it() {
    // TS 24.007 §11.2.5: a type 4 IEI of 0000 in bits 8 to 5, a type 6 IEI of
    // 0111111x
    let required = |iei| {
        UpdsUnknownIe {
            iei,
            data: Vec::new(),
        }
        .is_comprehension_required()
    };
    assert!(required(0x05));
    assert!(required(0x0f));
    assert!(!required(0x10));
    assert!(required(0x7e));
    assert!(required(0x7f));
    assert!(!required(0x7c));
}

#[test]
fn the_codes_of_the_upds_values_are_those_of_their_tables() {
    // Table D.6.2.1: the UE policy part types; Table D.6.3.1: the cause #111;
    // Figure D.6.8.1: the replacement types
    assert_eq!(UePolicyPartType::Andsp.as_u8(), 2);
    assert_eq!(UePolicyPartType::Unknown(9).as_u8(), 9);
    assert_eq!(
        UePolicySectionManagementResultCause::ProtocolErrorUnspecified.as_u8(),
        0x6f
    );
    assert_eq!(VpsUrspReplacementType::Reserved(0).as_u8(), 0);
    assert_eq!(VpsUrspReplacementType::Reserved(3).as_u8(), 3);
    assert_eq!(UpdsEventNotificationIndicatorType::Unknown(5).as_u8(), 5);
}

fn part(part_type: UePolicyPartType, contents: &[u8]) -> UePolicyPart {
    UePolicyPart {
        part_type,
        contents: contents.to_vec(),
    }
}

/// Two sublists: 208-93 with two instructions, the first of a URSP part and
/// of an ANDSP part of no contents, the second of no part; and 310-410 with
/// one instruction of one URSP part.
fn sublists() -> Vec<UePolicySectionManagementSublist> {
    vec![
        UePolicySectionManagementSublist::new(
            plmn("208", "93"),
            vec![
                UePolicySectionManagementInstruction::new(
                    0x0102,
                    vec![
                        part(UePolicyPartType::Ursp, &[0xaa]),
                        part(UePolicyPartType::Andsp, &[]),
                    ],
                ),
                UePolicySectionManagementInstruction::new(0x0304, vec![]),
            ],
        ),
        UePolicySectionManagementSublist::new(
            plmn("310", "410"),
            vec![UePolicySectionManagementInstruction::new(
                0x0506,
                vec![part(UePolicyPartType::Ursp, &[1, 2])],
            )],
        ),
    ]
}

#[test]
fn a_ue_policy_section_management_list_is_read_as_figures_d_6_2_3_to_d_6_2_7_code_it() {
    let list = NasUePolicySectionManagementList::from_sublists(&sublists()).unwrap();
    assert_eq!(
        list.value,
        octets(
            "0012 02f839 0009 0102 0002 01aa 0001 02 0002 0304 \
             000c 130014 0007 0506 0003 010102"
        )
    );
    assert_eq!(list.try_sublists(), Some(sublists()));
    assert_eq!(list.sublists(), sublists());
    assert!(list.is_well_formed());
    // Each list cut short is one that ends in a sublist, or none
    for end in 0..list.value.len() {
        let cut = NasUePolicySectionManagementList::new(list.value[..end].to_vec());
        let read = cut.try_sublists();
        assert!(read.is_none() || end == 20, "{end}: {read:?}");
        assert!(!cut.is_well_formed() || end == 20, "{end}");
    }
}

#[test]
fn a_ue_policy_section_management_list_that_overruns_is_none() {
    let none = |text: &str| {
        let list = NasUePolicySectionManagementList::new(octets(text));
        assert_eq!(list.try_sublists(), None, "{text}");
        assert_eq!(list.sublists(), Vec::new());
    };
    // A sublist longer than the list
    none("0020 02f839 0002 0001");
    // An instruction of no UPSC, and one longer than its sublist
    none("0009 02f839 0000 0001 0000");
    none("0007 02f839 0010 0001");
    // An instruction cut short after a complete one
    none("0008 02f839 0002 0001 00");
    // A UE policy part of no type, longer than its instruction, or cut short
    none("000a 02f839 0005 0001 0000 05");
    none("000a 02f839 0005 0001 0009 01");
    none("0008 02f839 0003 0001 00");
}

/// Two subresults: 208-93 with two results, and 310-410 with one.
fn subresults() -> Vec<UePolicySectionManagementSubresult> {
    let result = |upsc, order| {
        UePolicySectionManagementResultEntry::new(
            upsc,
            order,
            UePolicySectionManagementResultCause::ProtocolErrorUnspecified,
        )
    };
    vec![
        UePolicySectionManagementSubresult::new(
            plmn("208", "93"),
            vec![result(0x0102, 0x0304), result(0x0506, 0x0708)],
        ),
        UePolicySectionManagementSubresult::new(plmn("310", "410"), vec![result(0x090a, 1)]),
    ]
}

#[test]
fn a_ue_policy_section_management_result_is_read_as_figures_d_6_3_3_to_d_6_3_5_code_it() {
    let result = NasUePolicySectionManagementResult::from_subresults(&subresults()).unwrap();
    assert_eq!(
        result.value,
        octets("02 02f839 0102 0304 6f 0506 0708 6f  01 130014 090a 0001 6f")
    );
    assert_eq!(result.try_subresults(), Some(subresults()));
    assert_eq!(result.subresults(), subresults());
    assert!(result.is_well_formed());
    // A result of another cause than #111 is not sent
    let mut other = subresults();
    other[1].results[0].cause = UePolicySectionManagementResultCause::Other(0x22);
    assert!(NasUePolicySectionManagementResult::from_subresults(&other).is_err());
    // A subresult cut short after a complete one, or of more results than
    // the octets hold
    let mut cut = result.value.as_slice()[..14].to_vec();
    cut.extend_from_slice(&[0x01, 0x13]);
    assert_eq!(
        NasUePolicySectionManagementResult::new(cut).try_subresults(),
        None
    );
    let overrun = octets("03 02f839 0102 0304 6f 0506 0708 6f");
    assert_eq!(
        NasUePolicySectionManagementResult::new(overrun).try_subresults(),
        None
    );
}

#[test]
fn a_upsi_list_is_read_as_figure_d_6_4_2_codes_it() {
    let lists = vec![
        UpsiSublist::new(plmn("208", "93"), vec![0x0102]),
        UpsiSublist::new(plmn("310", "410"), vec![0x0304, 0x0506]),
    ];
    let list = NasUpsiList::from_sublists(&lists).unwrap();
    assert_eq!(
        list.value,
        octets("0005 02f839 0102  0007 130014 0304 0506")
    );
    assert_eq!(list.try_sublists(), Some(lists.clone()));
    assert_eq!(list.sublists(), lists);
    assert!(list.is_well_formed());
    assert!(!NasUpsiList::new(vec![0x00]).is_well_formed());
    let none = |text: &str| {
        assert_eq!(
            NasUpsiList::new(octets(text)).try_sublists(),
            None,
            "{text}"
        )
    };
    // A sublist of no UPSC, of half a UPSC, longer than the list, or cut short
    none("0003 02f839");
    none("0006 02f839 0102 01");
    none("0007 02f839 0102");
    none("0005 02f839 0102 00");
    // The value of the IE has 65529 octets at most
    let upscs = vec![0x0101; 32762];
    let longest =
        NasUpsiList::from_sublists(&[UpsiSublist::new(plmn("208", "93"), upscs)]).unwrap();
    assert_eq!(longest.value.len(), 65529);
    assert!(longest.try_sublists().is_some());
    // Two sublists of one octet more are none
    let mut over = longest.value.as_slice().to_vec();
    over.truncate(65523);
    over[0..2].copy_from_slice(&65521u16.to_be_bytes());
    over.extend_from_slice(&octets("0005 02f839 0102"));
    assert_eq!(over.len(), 65530);
    assert_eq!(NasUpsiList::new(over).try_sublists(), None);
}

#[test]
fn a_vps_ursp_configuration_is_read_as_figures_d_6_8_2_to_d_6_8_9_code_it() {
    use VpsUrspNetworkDescriptorEntry as Entry;
    let contents = VpsUrspConfigurationContents::new(
        VpsUrspReplacementType::FullListOfTuples,
        vec![
            VpsUrspTuple::new(
                7,
                vec![Entry::OneOrMoreVplmns(vec![plmn("208", "93")])],
                vec![0x0102],
            ),
            VpsUrspTuple::new(
                9,
                vec![Entry::OneOrMoreVplmns(vec![plmn("310", "410")])],
                vec![],
            ),
            VpsUrspTuple::new(
                8,
                vec![Entry::OneOrMoreMccs(vec![[2, 0, 9], [9, 0, 1], [9, 9, 9]])],
                vec![0x0304],
            ),
        ],
    );
    let ie = NasVpsUrspConfiguration::from_parsed(&contents).unwrap();
    assert_eq!(
        NasVpsUrspConfiguration::new(ie.value.clone()).parse(),
        Some(contents)
    );
    let none = |text: &str| {
        assert_eq!(
            NasVpsUrspConfiguration::new(octets(text)).parse(),
            None,
            "{text}"
        );
    };
    // A tuple cut short to one octet
    none("02 00");
    // A descriptor of more entries than its tuple holds, before the next tuple
    none("02 0003 07 02 03 03");
    // More VPLMNs than the tuple holds
    none("02 0007 07 01 01 02 02f839");
    // Two MCCs in two octets
    none("02 0006 07 01 02 02 0209");
}

#[test]
fn an_event_notification_container_has_each_indicator_with_its_length() {
    // TS 24.501 §9.11.3.39, Figure 9.11.3.39.1B: the event notification indicators,
    // each a type, a length and a value
    let two = UpdsEventNotificationContainer::decode(&octets("02 05 01 aa 00 00")).unwrap();
    assert_eq!(
        two.indicators,
        vec![
            UpdsEventNotificationIndicator {
                indicator_type: UpdsEventNotificationIndicatorType::Unknown(5),
                value: vec![0xaa],
            },
            UpdsEventNotificationIndicator {
                indicator_type:
                    UpdsEventNotificationIndicatorType::SrvccHandoverCancelledImsSessionReEstablishmentRequired,
                value: vec![],
            },
        ]
    );
    assert_eq!(two.encode().unwrap(), octets("02 05 01 aa 00 00"));
    assert!(UpdsEventNotificationContainer::decode(&octets("01 05")).is_err());
    assert!(UpdsEventNotificationContainer::decode(&octets("01 05 02 aa")).is_err());
}

#[test]
fn a_multiple_payload_container_has_each_entry_with_its_length() {
    // §9.11.3.39: the number of entries, then each with its length, its
    // number of optional IEs and its payload container type, its optional
    // IEs and its contents
    let decoded =
        UpdsMultiplePayloadContainer::decode(&octets("03  0001 05  0003 18 1200  0004 1f 1201 aa"))
            .unwrap();
    assert_eq!(decoded.entries.len(), 3);
    assert_eq!(decoded.entries[0].payload_container_type.value, 5);
    assert!(decoded.entries[0].optional_ies.is_empty());
    assert_eq!(decoded.entries[1].payload_container_type.value, 8);
    assert_eq!(decoded.entries[1].optional_ies.len(), 1);
    assert!(decoded.entries[1].contents.is_empty());
    assert_eq!(decoded.entries[2].payload_container_type.value, 0x0f);
    assert_eq!(decoded.entries[2].optional_ies[0].iei(), 0x12);
    assert_eq!(decoded.entries[2].optional_ies[0].value(), [0xaa]);
    assert!(decoded.entries[2].contents.is_empty());
    assert_eq!(
        decoded.encode().unwrap(),
        octets("03  0001 05  0003 18 1200  0004 1f 1201 aa")
    );
    let one = UpdsMultiplePayloadContainer::decode(&octets("01 0001 05")).unwrap();
    assert_eq!(one.entries.len(), 1);
    // An entry longer than the octets, and an optional IE longer than its entry
    assert!(UpdsMultiplePayloadContainer::decode(&octets("01 0005 05 aa")).is_err());
    assert!(UpdsMultiplePayloadContainer::decode(&octets("01 0003 15 1202")).is_err());
    // Fifteen optional IEs at most, and a type of four bits
    let entry = |optional_ies: usize, kind: u8| {
        UpdsMultiplePayloadContainer::new(vec![UpdsMultiplePayloadEntry::new(
            NasPayloadContainerType::new(kind),
            vec![MultiplePayloadOptionalIe::from_raw(0x12, vec![1]); optional_ies],
            vec![],
        )])
        .encode()
    };
    assert!(entry(15, 1).is_ok());
    assert!(entry(16, 1).is_err());
    assert!(entry(0, 0x0f).is_ok());
    assert!(entry(0, 0x10).is_err());
}

fn command() -> NasManageUePolicyCommand {
    NasManageUePolicyCommand::new(
        NasUePolicySectionManagementList::from_sublists(&sublists()).unwrap(),
    )
}

#[test]
fn two_messages_are_equal_when_each_of_their_ies_is() {
    let classmark = NasUePolicyNetworkClassmark::from_nssui(true);
    let configuration = NasVpsUrspConfiguration::new(octets("01"));
    let base = command();
    assert_eq!(base, command());
    let mut other_list = command();
    other_list.ue_policy_section_management_list =
        NasUePolicySectionManagementList::from_sublists(&sublists()[1..]).unwrap();
    assert_ne!(base, other_list);
    let mut with_classmark = command();
    with_classmark.set_ue_policy_network_classmark(classmark.clone());
    assert_eq!(with_classmark.ue_policy_network_classmark, Some(classmark));
    assert_ne!(base, with_classmark);
    let mut with_configuration = command();
    with_configuration.set_vps_ursp_configuration(configuration.clone());
    assert_eq!(
        with_configuration.vps_ursp_configuration,
        Some(configuration)
    );
    assert_ne!(base, with_configuration);
    let mut with_unknown = command();
    with_unknown.unknown_ies.push(UpdsUnknownIe {
        iei: 0x30,
        data: vec![0x01, 0xaa],
    });
    assert_ne!(base, with_unknown);

    let indication = || {
        NasUeStateIndication::new(
            NasUpsiList::new(octets("0005 02f839 0102")),
            NasUePolicyClassmark::new(vec![0x01]),
        )
    };
    let state = indication();
    assert_eq!(state, indication());
    let mut other_upsi = indication();
    other_upsi.upsi_list = NasUpsiList::new(Vec::new());
    assert_ne!(state, other_upsi);
    let mut other_classmark = indication();
    other_classmark.ue_policy_classmark = NasUePolicyClassmark::new(vec![0x02]);
    assert_ne!(state, other_classmark);
    let mut with_os_id = indication();
    let os_id = NasUeOsId::from_os_ids(&[[7; 16]]).unwrap();
    with_os_id.set_ue_os_id(os_id.clone());
    assert_eq!(with_os_id.ue_os_id, Some(os_id));
    assert_ne!(state, with_os_id);
    let mut with_unknown = indication();
    with_unknown.unknown_ies.push(UpdsUnknownIe {
        iei: 0x30,
        data: vec![0x01, 0xaa],
    });
    assert_ne!(state, with_unknown);
}

fn envelope(message: NasUpdsMessage) -> NasUpdsEnvelope {
    NasUpdsEnvelope::new(0x01, message)
}

#[test]
fn a_message_is_read_back_from_its_octets_with_its_optional_ies_once() {
    // D.5.4: UE STATE INDICATION with a UE OS Id of one OS Id
    let mut indication = NasUeStateIndication::new(
        NasUpsiList::new(octets("0005 02f839 0102")),
        NasUePolicyClassmark::new(vec![0x01]),
    );
    indication.set_ue_os_id(NasUeOsId::from_os_ids(&[[7; 16]]).unwrap());
    let octets = envelope(NasUpdsMessage::UeStateIndication(indication))
        .encode()
        .unwrap();
    let decoded = NasUpdsEnvelope::decode(&octets).unwrap();
    let NasUpdsMessage::UeStateIndication(read) = &decoded.message else {
        panic!("{decoded:?}")
    };
    assert_eq!(
        read.ue_os_id.as_ref().map(NasUeOsId::os_ids),
        Some(vec![[7; 16]])
    );
    assert_eq!(decoded.encode().unwrap(), octets);
    assert_eq!(
        decoded.message.semantics(),
        Some(NasUpdsMessageType::UeStateIndication.semantics())
    );
}

#[test]
fn a_repeated_or_malformed_optional_ie_is_kept_in_its_octets() {
    // TS 24.501 §7.6.3: an IE that is repeated is ignored after the first,
    // and kept as it came
    let list = NasUePolicySectionManagementList::from_sublists(&sublists()).unwrap();
    let mut wire = vec![0x01, 0x01];
    wire.extend_from_slice(&(list.value.len() as u16).to_be_bytes());
    wire.extend_from_slice(&list.value);
    wire.extend_from_slice(&octets(
        "42 01 01  42 01 00  70 0001 01  70 0001 02  30 01 aa",
    ));
    let decoded = NasUpdsEnvelope::decode(&wire).unwrap();
    let NasUpdsMessage::ManageUePolicyCommand(command) = &decoded.message else {
        panic!("{decoded:?}")
    };
    assert_eq!(
        command
            .ue_policy_network_classmark
            .as_ref()
            .map(|ie| ie.value.clone()),
        Some(vec![0x01])
    );
    assert_eq!(
        command
            .vps_ursp_configuration
            .as_ref()
            .map(|ie| ie.value.clone()),
        Some(vec![0x01])
    );
    assert_eq!(
        command.unknown_ies,
        vec![
            UpdsUnknownIe {
                iei: 0x42,
                data: vec![0x01, 0x00]
            },
            UpdsUnknownIe {
                iei: 0x70,
                data: vec![0x00, 0x01, 0x02]
            },
            UpdsUnknownIe {
                iei: 0x30,
                data: vec![0x01, 0xaa]
            },
        ]
    );
    assert_eq!(decoded.encode().unwrap(), wire);
    // An OS Id of sixteen octets is one, of fifteen none
    let state = |os_id: &str| {
        let wire = octets(&format!("01 04 0007 0005 02f839 0102 01 01 {os_id}"));
        let decoded = NasUpdsEnvelope::decode(&wire).unwrap();
        let NasUpdsMessage::UeStateIndication(indication) = decoded.message else {
            panic!()
        };
        (indication.ue_os_id.is_some(), indication.unknown_ies.len())
    };
    assert_eq!(state(&format!("41 10 {}", "07".repeat(16))), (true, 0));
    assert_eq!(
        state(&format!("41 0f {}  30 01 aa", "07".repeat(15))),
        (false, 2)
    );
    assert_eq!(
        state(&format!(
            "41 10 {}  41 10 {}  30 01 aa",
            "07".repeat(16),
            "08".repeat(16)
        )),
        (true, 2)
    );
}

#[test]
fn unknown_ies_are_written_back() {
    let mut complete = NasManageUePolicyComplete::new();
    complete.unknown_ies.push(UpdsUnknownIe {
        iei: 0x30,
        data: vec![0x01, 0xaa],
    });
    let octets_of_complete = envelope(NasUpdsMessage::ManageUePolicyComplete(complete))
        .encode()
        .unwrap();
    assert_eq!(octets_of_complete, octets("01 02 30 01 aa"));
    // An unknown IE set after decoding goes after the known ones
    let mut built = command();
    built.unknown_ies.push(UpdsUnknownIe {
        iei: 0x30,
        data: vec![0x01, 0xaa],
    });
    let wire = envelope(NasUpdsMessage::ManageUePolicyCommand(built))
        .encode()
        .unwrap();
    assert!(wire.ends_with(&octets("30 01 aa")), "{wire:02x?}");
}

#[test]
fn a_upds_message_has_65535_octets_at_most() {
    // §9.11.3.39: the payload of a UE policy container, of a length of two octets
    let request = |octets: usize| {
        envelope(NasUpdsMessage::UePolicyProvisioningRequest(
            NasUePolicyProvisioningRequest::new(vec![0x55; octets]),
        ))
    };
    let longest = request(65533).encode().unwrap();
    assert_eq!(longest.len(), 65535);
    assert!(NasUpdsEnvelope::decode(&longest).is_ok());
    assert!(request(65534).encode().is_err());
    let mut over = longest.clone();
    over.push(0x55);
    assert!(NasUpdsEnvelope::decode(&over).is_err());
    // The limit is of the message, wherever it is written
    let mut buffer = vec![0; 70_000];
    request(10).encode_into(&mut buffer).unwrap();
    assert_eq!(buffer.len(), 70_012);
}

#[test]
fn a_mandatory_ie_of_no_octet_is_refused_as_its_own() {
    // D.5.4: a UE policy classmark of no octet; D.5.3: a UE policy section
    // management result of no octet
    let refused = |text: &str| match NasUpdsEnvelope::decode(&octets(text)).unwrap_err() {
        NasError::InvalidMandatoryIe { ie, .. } => ie.field().to_string(),
        other => format!("{other:?}"),
    };
    assert_eq!(
        refused("01 04 0007 0005 02f839 0102 00"),
        "ue_policy_classmark"
    );
    assert_eq!(refused("01 03 0000"), "ue_policy_section_management_result");
}

fn names(errors: &[oxirush_nas::ValidationError], field: &str) -> bool {
    errors.iter().any(|error| error.field == field)
}

#[test]
fn a_manage_ue_policy_command_has_classmark_and_configuration_of_their_clauses() {
    // D.6.7: the UE policy network classmark of 1 to 3 octets, its spare
    // bits clear
    let field = "ue_policy_network_classmark";
    let with = |octets: Vec<u8>| {
        let mut message = command();
        message.ue_policy_network_classmark = Some(NasUePolicyNetworkClassmark::new(octets));
        message.validate()
    };
    assert!(with(vec![0x01]).is_empty(), "{:?}", with(vec![0x01]));
    assert!(with(vec![0x01, 0x00]).is_empty());
    assert!(names(&with(vec![0x02]), field));
    assert!(names(&with(vec![0x01, 0x01]), field));
    assert!(names(&with(vec![0x01, 0, 0, 0]), field));
    // D.6.8: a VPS URSP configuration that it reads
    let mut message = command();
    message.vps_ursp_configuration = Some(NasVpsUrspConfiguration::new(octets("01")));
    assert!(message.validate().is_empty(), "{:?}", message.validate());
    message.vps_ursp_configuration = Some(NasVpsUrspConfiguration::new(octets("03")));
    assert!(names(&message.validate(), "vps_ursp_configuration"));
}

#[test]
fn an_ignored_or_comprehension_required_ie_of_a_upds_message_is_a_finding() {
    let mut complete = NasManageUePolicyComplete::new();
    assert!(complete.validate().is_empty());
    complete.unknown_ies.push(UpdsUnknownIe {
        iei: 0x05,
        data: vec![0x00],
    });
    assert!(names(&complete.validate(), "unknown_ies"));
    // A command reject has a result of its clause
    let reject = NasManageUePolicyCommandReject::new(
        NasUePolicySectionManagementResult::from_subresults(&subresults()).unwrap(),
    );
    assert!(reject.validate().is_empty());
    let reject =
        NasManageUePolicyCommandReject::new(NasUePolicySectionManagementResult::new(vec![0x00]));
    assert!(names(
        &reject.validate(),
        "ue_policy_section_management_result"
    ));
}

#[test]
fn a_ue_state_indication_has_a_classmark_and_os_ids_of_their_clauses() {
    let indication = |upsi: &str, classmark: Vec<u8>| {
        NasUeStateIndication::new(
            NasUpsiList::new(octets(upsi)),
            NasUePolicyClassmark::new(classmark),
        )
    };
    let valid = indication("0005 02f839 0102", vec![0x01]);
    assert!(valid.validate().is_empty(), "{:?}", valid.validate());
    assert!(names(
        &indication("0003 02f839", vec![0x01]).validate(),
        "upsi_list"
    ));
    // D.6.5: 1 to 3 octets, bits 8 to 6 of octet 3 and octets 4 and 5 spare
    assert!(names(
        &indication("", vec![0x10]).validate(),
        "ue_policy_classmark"
    ));
    assert!(names(
        &indication("", vec![0x01, 0x01]).validate(),
        "ue_policy_classmark"
    ));
    assert!(!names(
        &indication("", vec![0x01, 0x00]).validate(),
        "ue_policy_classmark"
    ));
    // D.6.6: 1 to 15 OS Ids of sixteen octets
    let with_os_id = |octets: Vec<u8>| {
        let mut message = indication("", vec![0x01]);
        message.ue_os_id = Some(NasUeOsId::new(octets));
        names(&message.validate(), "ue_os_id")
    };
    assert!(!with_os_id(vec![7; 16]));
    assert!(with_os_id(vec![7; 17]));
    assert!(with_os_id(vec![7; 15]));
}

#[test]
fn a_provisioning_message_has_65533_octets_of_payload_at_most() {
    let request =
        |octets: usize| NasUePolicyProvisioningRequest::new(vec![0x55; octets]).validate();
    assert!(request(65533).is_empty());
    assert!(names(&request(65534), "payload"));
    let reject = |octets: usize| NasUePolicyProvisioningReject::new(vec![0x55; octets]).validate();
    assert!(reject(65533).is_empty());
    assert!(names(&reject(65534), "payload"));
    assert!(names(&reject(0), "payload"));
}
