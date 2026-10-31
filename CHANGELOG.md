# Changelog

All notable changes to `oxirush-nas` are recorded here.

## Unreleased

- A packet filter of a QoS rule decodes when a component follows its (S)RTP
  multiplexed media identification information (TS 24.501 §9.11.4.13): the
  number of the entries and the length of each say where it ends, and the
  decoder took it to end the packet filter. Such a rule, which `from_rules`
  encodes, was refused as a syntactical error in packet filters.
- The keywords take `eps` in the place of `telecom`, and the description says 5G (5GS) and 4G LTE (EPS), as those who look for the crate search.

## 0.5.0 - 2026-10-24

This release brings the receivers closer to TS 24.501 and TS 24.301
V19.8.0 (Release 19). Two items follow TS 24.501 V20.1.0 (Release 20)
instead, as the entries below and the documentation say: the VLAN ID of the
non-3GPP device information, and the NSSAA-EPC and AIoTUR bits of the 5GMM
capability. It is not source compatible with 0.4.0.

### Breaking changes relative to 0.4.0

- Each IE of a message has two setters, `set_<ie>(&mut self, value)`
  and `with_<ie>(self, value)`, and an optional one `clear_<ie>()`; the
  fields of a message are public, and are how an IE is read. A mandatory
  IE had four methods and has two, an optional IE seven and has three.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `set_<ie>_value(&mut self, ..)`, `with_<ie>_value(self, ..)` of a mandatory IE | `set_<ie>`, `with_<ie>` |
  | `set_<ie>(self, ..) -> Self` of an optional IE | `with_<ie>` |
  | `set_<ie>_mut(&mut self, ..)` of an optional IE | `set_<ie>` |
  | `get_<ie>()`, `get_<ie>_mut()` | `&message.<ie>`, `&mut message.<ie>`; `.as_ref()`, `.as_mut()` of an optional one |
  | `has_<ie>()` | `message.<ie>.is_some()` |
  | the field and the methods of `ms_determined_plmn_with_disaster_condition` of a REGISTRATION REQUEST, and those of `ue_determined_plmn_with_disaster_condition`, a second name of its IE | those of `ue_determined_plmn_with_disaster_condition`, the name of its table (TS 24.501 replaced MS by UE in V18.7.0) |
  | `NasPduSessionEstablishmentAccept::set_selected_ssc_mode(SscModeValue)`, `selected_ssc_mode()`, `selected_ssc_mode_value()`, and the same for the PDU session type | the IEs: `accept.selected_ssc_mode.mode()`, `accept.set_selected_ssc_mode(NasSscMode::new(..).with_mode(mode))` |

- An EPS IE type is named after the IE type of its clause 9.9 of TS 24.301,
  and is one type for every IE of that type: `NasGprsTimer3` for the
  back-off timer value, T3396, T3447, the lower bound timer value and the
  maximum time offset, as the 5GS types were named. The member of a
  message keeps the name of the IE of the message's table
  (`back_off_timer_value`), and `Debug` prints the type's new name. T3412
  value and T3412 extended value keep types of their own: a GPRS timer
  whose value 0 deactivates it (§9.9.3.16), and a GPRS timer 3 whose
  receiver reads it with T3324 (TS 24.008 Table 10.5.163a).

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `NasApnAmbr` | `NasApnAggregateMaximumBitRate` |
  | `NasAuthenticationParameterAutnEpsChallenge` | `NasAuthenticationParameterAutn` |
  | `NasAuthenticationParameterRandEpsChallenge` | `NasAuthenticationParameterRand` |
  | `NasGprsCipheringKeySequenceNumber` | `NasCipheringKeySequenceNumber` |
  | `NasNetworkDaylightSavingTime` | `NasDaylightSavingTime` |
  | `NasEpsQos`, `NasNewEpsQos`, `NasRequiredTrafficFlowQos` | `NasEpsQualityOfService` |
  | `NasExtendedApnAmbr` | `NasExtendedApnAggregateMaximumBitRate` |
  | `NasExtendedEpsQos` | `NasExtendedQualityOfService` |
  | `NasT3402Value`, `NasT3423Value`, `NasT3442Value` | `NasGprsTimer` |
  | `NasT3324Value`, `NasT3346Value`, `NasT3448Value` | `NasGprsTimer2` |
  | `NasBackOffTimerValue`, `NasLowerBoundTimerValue`, `NasMaximumTimeOffset`, `NasT3396Value`, `NasT3447Value` | `NasGprsTimer3` |
  | `NasOldGutiType` | `NasGutiType` |
  | `NasIdentityType` | `NasIdentityType2` |
  | `NasNegotiatedImsiOffset`, `NasRequestedImsiOffset` | `NasImsiOffset` |
  | `NasNonCurrentNativeNasKeySetIdentifier` | `NasKeySetIdentifier` |
  | `NasNegotiatedLlcSapi` | `NasLlcServiceAccessPointIdentifier` |
  | `NasDrxParameterInNbS1Mode`, `NasNegotiatedDrxParameterInNbS1Mode` | `NasNbS1DrxParameter` |
  | `NasTmsiBasedNriContainer` | `NasNetworkResourceIdentifierContainer` |
  | `NasNonceMme`, `NasNonceUe`, `NasReplayedNonceUe` | `NasNonce` |
  | `NasOldPTmsiSignature` | `NasPTmsiSignature` |
  | `NasProseKeyManagementFunctionAddress` | `NasPkmfAddress` |
  | `NasUeDeterminedPlmnWithDisasterCondition` | `NasPlmnIdentity` |
  | `NasEquivalentPlmns` | `NasPlmnList` |
  | `NasNegotiatedQos`, `NasNewQos` | `NasQualityOfService` |
  | `NasDisasterReturnWaitRange`, `NasDisasterRoamingWaitRange` | `NasRegistrationWaitRange` |
  | `NasRemoteUeContextConnected`, `NasRemoteUeContextDisconnected` | `NasRemoteUeContextList` |
  | `NasSelectedNasSecurityAlgorithms` | `NasSecurityAlgorithms` |
  | `NasSupportedCodecs` | `NasSupportedCodecList` |
  | `NasLocalTimeZone` | `NasTimeZone` |
  | `NasUniversalTimeAndLocalTimeZone` | `NasTimeZoneAndTime` |
  | `NasLastVisitedRegisteredTai` | `NasTrackingAreaIdentity` |
  | `NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRegionalProvisionOfService`, `NasForbiddenTaisForTheListOfForbiddenTrackingAreasForRoaming`, `NasTaiList` | `NasTrackingAreaIdentityList` |
  | `NasTrafficFlowAggregate` | `NasTrafficFlowAggregateDescription` |
  | `NasTft` | `NasTrafficFlowTemplate` |
  | `NasUeCoarseLocationInformationRequest` | `NasUeInformationRequest` |
  | `NasReplayedUeSecurityCapabilities` | `NasUeSecurityCapability` |
  | `NasWlanOffloadIndication` | `NasWlanOffloadAcceptability` |
  | `NasNegotiatedWusAssistanceInformation`, `NasRequestedWusAssistanceInformation` | `NasWusAssistanceInformation` |

  `NasKeySetIdentifier::from_key_set_identifier` builds any key set
  identifier; that of the non-current native one refused a mapped one and
  "no key". That rule, and the one of the EPS QoS that the network assigns
  (a QCI of TS 23.203, no reserved bit rate octet), are now findings of the
  messages that carry them: `validate()` of TRACKING AREA UPDATE REQUEST
  for `non_current_native_nas_key_set_identifier`, and of ACTIVATE DEFAULT
  and ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST and MODIFY EPS BEARER
  CONTEXT REQUEST for their EPS QoS.

- `Display` of a message says its protocol once, its type, and what a log
  needs of its IEs, in the order of the message and each in the form of its
  IE type, one form for the IEs of both systems: each IE type that a
  message shows has a `Display` of its own. In both systems:

  | IE | 0.4.0 | 0.5.0 |
  |---|---|---|
  | a cause | `cause=0x16 (Congestion)` | `cause=#22 (Congestion)`, by the name of its table; `#4` for a value the table does not have |
  | RAND, AUTN | 5GS `RAND=23553cbe...`, no AUTN; EPS `RAND=16B, AUTN=16B` | both whole: `RAND=23553cbe9637a89d218ae64dae47bf35, AUTN=...` |
  | AUTS | 5GS `[AUTS present]`, EPS `AUTS=14B` | whole |
  | RES, RES\* | `RES*=16B`, `RES=8B` | `RES*=hidden (16 octets)`: a key is not printed |
  | a timer | absent, or `T3412=60` | `T3346=10 min`, `T3512=1 h`, `T3412=9 min`, `deactivated`: T3346, T3502, T3512, T3412 and the others where a message has them |
  | an identity | `SUCI (PLMN=208-93, routing-indicator=0000, ...)`, `5G-GUTI (PLMN=208-93, AMF=202/1022/0, TMSI=0x11223344)`, `GUTI (PLMN=..., MMEGI=0x0002, ...)`, `IMSI 2089...`, `TMSI 0xC0000001` | as the service based interfaces write it, by the `Display` of oxirush-utils: `suci-0-208-93-0000-0-0-0000000120`, `5g-guti-20893caff8011223344`, `4g-guti-...`, `5g-s-tmsi-...`, `imsi-...`, `imei-...`, `imeisv-...`, `tmsi-c0000001`, `mac-01-02-03-04-05-06`, `eui-...` |
  | a list of TAIs, an NSSAI | `TAI-list=10B`, `TAIs=1`, `Allowed-NSSAI=7B` | `TAI-list=[208-93-000001, 208-93-000002]`, `Allowed-NSSAI=[1, 1/010203]`; a list of more than four entries shows three and how many more |
  | a container | `ESM=4B`, `8B`, `[NAS container present]` | the message that it carries: `payload=5GSM (PSI=1, PTI=1) PduSessionEstablishmentRequest (...)`, `ESM-container=ESM (...)`, `NAS-container=5GMM ...` |
  | other octets | `container=2B` | whole up to sixteen octets, then their count |
  | a bit of a type | `switch_off=0`, `re_reg=0`, `FOR=1`, `access_type=Some(ThreeGppAccess)` | a word when it is set: `switch off`, `re-registration required`, `FOR`; `access=ThreeGppAccess` |

  A message that shows no IE has no empty `()`. The SECURITY MODE COMMAND
  of 5GS shows `IMEISV requested` and the replayed UE security capability
  as that of EPS does, the 5G-S-TMSI of a SERVICE REQUEST is the one of
  oxirush-utils, a PDU address and a PDN address print alike
  (`IPv4 10.45.0.2`), and a session-AMBR and an APN-AMBR as
  `DL 1 Gbps UL 1 Gbps`. The module `display` of each system lists the
  forms. Hexadecimal is in lower case in every `Display`, `Debug` and
  error of the crate: `IEI 0x5f was ignored as repeated`, a PCO identifier
  `0x000d` where it was `000DH`.
- `Debug` prints no key, as `Display` prints none. Of RES and RES\*
  (`NasAuthenticationResponseParameter`), the ciphering keys of the
  positioning SIBs (`NasCipheringKeyData` and `CipheringDataSet` of both
  systems), the MSK of an MBS session (`NasReceivedMbsContainer`,
  `MbsSecurityKeySet`) and K_NR_ProSe (`NasRelayKeyResponseParameters`,
  `RelayKeyResponseParameters`) it shows the length,
  `NasAuthenticationResponseParameter { value: hidden (16 octets) }`, where
  0.4.0 printed the octets. Of an `UnknownIe` it shows the IEI and the
  length of the data, `UnknownIe { iei: 0x2d, data: 16 octets }`: an IE
  whose length its type refuses is kept unread, and may hold a key. Of a
  `NasEapMessage` it shows the header of the packet, `NasEapMessage { code:
  Response, identifier: 1, type: 50, subtype: 1, length: 20, .. }`, without
  the attributes, where an EAP-AKA' response has RES (RFC 4187 §9.4). The
  fields keep every octet.

- `NasError::InvalidMandatoryIe` names its IE by an `IeName`, whose
  `Display` and `Debug` both print the name of the table,
  `5gs-mobile-identity`, and whose `field()` is the field of the message
  struct; `ie` was the field as a `&str`, which `Debug` printed while
  `Display` printed the name. A value that is syntactically incorrect has
  the reason that it is not one of its type in `reason`, boxed so that an
  error stays four words: the error of oxirush-utils for an identity,
  "`5g-guti` has 10 octets, and must have 11". `NasError::SecurityRefused` is
  what a security context refuses, NIA0 or EIA0 with another algorithm than
  the null one, a reserved algorithm and a header type that does not
  protect, where it was an `EncodingError` ("cannot encode: 5GS NIA0
  requires NEA0"). A number of a tree out of the range of its member is
  "300 is not a number from 0 to 255", where serde's words were "invalid
  value: integer `300`, expected u8", and an IE of one octet "is not one
  octet". A value that its IE cannot carry says what its member must have or
  be, in the words of the errors of oxirush-utils: "`mcc` has 2 digits, and
  must have 3", "`mnc` has 1 digit, and must have 2 or 3", "`res` has 2
  octets, and must have 4 at least", "`pdu-session-identity` is 16, and must
  be 1 to 15".

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `NasError::InvalidMandatoryIe { ie: "fgs_mobile_identity", fault }` | `NasError::InvalidMandatoryIe { ie: IeName::of("fgs_mobile_identity"), fault, reason }` |
  | `rand() -> &[u8]`, `rand_array() -> Option<[u8; 16]>` | `rand() -> Option<&[u8; 16]>`, which a `Rand` of oxirush-security takes |
  | `autn()`, `autn_array()`; `auts()`, `auts_array()` | `autn() -> Option<&[u8; 16]>`, `auts() -> Option<&[u8; 14]>` |
  | `res_star() -> &[u8]`, `res_star_array()` | `res_star() -> Option<&[u8; 16]>`; `res()` keeps its 4 to 16 octets |

- A tracking area identity list has one form in both systems, that of
  5GS: its partial lists, `TaiListEntry`, of one PLMN and its TACs, of one
  PLMN and a range of TACs, or of tracking areas of different PLMNs, and a
  TAC is a number, of 24 bits in 5GS and of 16 in EPS. One macro writes
  both. The tree of an EPS list has its partial lists, as the one of 5GS
  has, and a list written from a tree has the octets it was read from,
  where an EPS list was written again as tracking areas of different
  PLMNs. The TACs of the 5GS service area list and TAI are numbers too.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `nas_eps::TaiList(Vec<Tai>)`, `TaiList::from_bytes`, `from_bytes_strict`, `to_bytes` | `NasTrackingAreaIdentityList::entries()`, `tais()`, `receiver_syntax_is_valid()`, `is_well_formed()`, `from_entries` |
  | `NasTrackingAreaIdentityList::tai_list() -> Option<TaiList>`, `from_tai_list(&TaiList)` | `tais() -> Vec<Tai>`, `entries()`, `from_tais(&[Tai])`, `from_plmn_tacs`, `from_consecutive_tacs`, `from_entries` |
  | `NasFGsTrackingAreaIdentityList::parse()`, `from_tai_list(&[Tai])` | `entries()`, `from_tais(&[Tai])`, and `tais()` |
  | `TaiListEntry::OnePlmnNonConsecutive { tacs: Vec<[u8; 3]> }`, `OnePlmnConsecutive { first_tac: [u8; 3] }`, `tacs() -> Vec<[u8; 3]>`, `from_plmn_tacs(&plmn, &[[u8; 3]])`, `from_consecutive_tacs(&plmn, [u8; 3], count)` (5GS) | `u32`; in EPS `u16` |
  | `ServiceAreaListEntry` TACs `[u8; 3]`, and those of `NasServiceAreaList::from_plmn_tacs`, `from_consecutive_tacs` | `u32` |
  | `NasFGsTrackingAreaIdentity::parse()`, `from_plmn_tac(&plmn, [u8; 3])`, `ReceivedTrackingAreaIdentity::Deleted { tac: [u8; 3] }` | `tai()`, as in EPS; `from_plmn_tac(&plmn, u32)`; `tac: u32` |
  | `TaiListType` (5GS) | one type of both systems |
  | `nas_eps::CipheringDataSet::tai_list_value() -> Option<TaiList>` | `-> Option<NasTrackingAreaIdentityList>`, and the same in 5GS |

- The `field` of a finding of `validate()` of a 5GS message is the name
  of the member that it is about, as in EPS (`"fgs_registration_type"`,
  where it was `"5GS registration type"`); a member of an inner message is
  written after the one that has it (`"plain_fgs_nas_message.security_header_type"`).
  The findings are the same, and their messages, but for the two that
  named a security header type by a name it no longer has
  (`IntegrityProtectedWithNewContext is only valid for SecurityModeCommand`
  is `IntegrityProtectedWithNewFiveGNasSecurityContext is ...`, and the
  same for the ciphered one, in the findings and in the decode errors).

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `"ABBA"` | `"abba"` |
  | `"Access type"` | `"access_type"` |
  | `"Additional information"` | `"additional_information"` |
  | `"Authentication failure parameter"` | `"authentication_failure_parameter"` |
  | `"AUTN"` | `"authentication_parameter_autn"` |
  | `"RAND"`, `"RAND/AUTN"` | `"authentication_parameter_rand"` |
  | `"Authorized QoS rules"` | `"authorized_qos_rules"` |
  | `"CIoT small data container"` | `"ciot_small_data_container"` |
  | `"Connected remote UE context list"` | `"remote_ue_context_connected"` |
  | `"De-registration type"` | `"de_registration_type"` |
  | `"Disconnected remote UE context list"` | `"remote_ue_context_disconnected"` |
  | `"Authentication mechanism"`, `"EAP message"` | `"eap_message"` |
  | `"Extended 5GMM cause"` | `"extended_5gmm_cause"` |
  | `"Extended protocol configuration options"` | `"extended_protocol_configuration_options"` |
  | `"EPD"` | `"extended_protocol_discriminator"` |
  | `"5G-S-TMSI"` | `"fg_s_tmsi"` |
  | `"5GMM capability"` | `"fgmm_capability"` |
  | `"5GMM cause"` | `"fgmm_cause"` |
  | `"5GS mobile identity"` | `"fgs_mobile_identity"` |
  | `"5GS registration result"` | `"fgs_registration_result"` |
  | `"5GS registration type"` | `"fgs_registration_type"` |
  | `"5GSM cause"` | `"fgsm_cause"` |
  | `"Identity type"` | `"identity_type"` |
  | `"IMEISV"` | `"imeisv"` |
  | `"Integrity protection maximum data rate"` | `"integrity_protection_maximum_data_rate"` |
  | `"LP-WUS status"` | `"lp_wus_status"` |
  | `"Maximum number of supported packet filters"` | `"maximum_number_of_supported_packet_filters"` |
  | `"5GS NAS header"` | `"message"` |
  | `"UPDS message type"` | `"message_type"` |
  | `"Mobile identity"` | `"mobile_identity"` |
  | `"Non-3GPP device information"` | `"non_3gpp_device_information"` |
  | `"Non-current native NAS key set identifier"` | `"non_current_native_nas_key_set_identifier"` |
  | `"Non-IMEISV PEI"` | `"non_imeisv_pei"` |
  | `"Payload container"` | `"payload_container"` |
  | `"Payload container type"` | `"payload_container_type"` |
  | `"PDU address"` | `"pdu_address"` |
  | `"PDU session ID"` | `"pdu_session_id"` |
  | `"PDU Session ID"` | `"pdu_session_identity"` |
  | `"PDU session status"` | `"pdu_session_status"` |
  | `"PDU session type"` | `"pdu_session_type"` |
  | `"Plain NAS message"`, `"Protected payload"` | `"plain_fgs_nas_message"` |
  | `"Inner EPD"` | `"plain_fgs_nas_message.extended_protocol_discriminator"` |
  | `"Inner SHT"` | `"plain_fgs_nas_message.security_header_type"` |
  | `"Port management information container"` | `"port_management_information_container"` |
  | `"Procedure Transaction ID"`, `"UPDS PTI"` | `"procedure_transaction_identity"` |
  | `"Relay key request parameters"` | `"relay_key_request_parameters"` |
  | `"Relay key response parameters"` | `"relay_key_response_parameters"` |
  | `"Replayed UE security capabilities"` | `"replayed_ue_security_capabilities"` |
  | `"Request type"` | `"request_type"` |
  | `"Requested QoS flow descriptions"` | `"requested_qos_flow_descriptions"` |
  | `"Requested QoS rules"` | `"requested_qos_rules"` |
  | `"S-NSSAI"` | `"s_nssai"` |
  | `"SHT"` | `"security_header_type"` |
  | `"Selected NAS security algorithms"` | `"selected_nas_security_algorithms"` |
  | `"Selected PDU session type"` | `"selected_pdu_session_type"` |
  | `"Selected SSC mode"` | `"selected_ssc_mode"` |
  | `"Service-level-AA container"` | `"service_level_aa_container"` |
  | `"Service type"` | `"service_type"` |
  | `"Session-AMBR"` | `"session_ambr"` |
  | `"SOR transparent container"` | `"sor_transparent_container"` |
  | `"Spare half octet"` | `"spare_half_octet"` |
  | `"SSC mode"` | `"ssc_mode"` |
  | `"Suggested interface identifier"` | `"suggested_interface_identifier"` |
  | `"UE OS Id"` | `"ue_os_id"` |
  | `"UE policy classmark"` | `"ue_policy_classmark"` |
  | `"UE policy network classmark"` | `"ue_policy_network_classmark"` |
  | `"UE policy section management list"` | `"ue_policy_section_management_list"` |
  | `"UE policy section management result"` | `"ue_policy_section_management_result"` |
  | `"UE security capability"` | `"ue_security_capability"` |
  | `"UPDS optional IEs"` | `"unknown_ies"` |
  | `"UPSI list"` | `"upsi_list"` |
  | `"VPS URSP configuration"` | `"vps_ursp_configuration"` |

- A member of a message has the name of its IE in the table of the
  message, and an IE type the name of the IE type of its clause, where
  they had another. The tree of a message names its IEs by the same words.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `NasEcnMarkingL4sIndication`, member `ecn_marking_l4s_indication` (5GS PDU SESSION ESTABLISHMENT ACCEPT, MODIFICATION COMMAND), `"ecn-marking-l4s-indication"` | `NasEcnMarkingForL4sIndication`, `ecn_marking_for_l4s_indication`, `"ecn-marking-for-l4s-indication"` |
  | `discontinuous_coverage_max_time_offset` (REGISTRATION ACCEPT, CONFIGURATION UPDATE COMMAND) | `discontinuous_coverage_maximum_time_offset` |
  | `forbidden_tai_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming`, `..._for_regional_provision_of_service` (5 messages) | `forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming`, `..._for_regional_provision_of_service`: "Forbidden TAI(s)" |
  | `type_6_ie_container` (REGISTRATION ACCEPT) | `registration_accept_type_6_ie_container` |
  | `connected_remote_ue_context_list`, `disconnected_remote_ue_context_list` (5GS REMOTE UE REPORT) | `remote_ue_context_connected`, `remote_ue_context_disconnected`, as in EPS |
  | `authentication_parameter_rand_eps_challenge`, `authentication_parameter_autn_eps_challenge` (EPS AUTHENTICATION REQUEST) | `authentication_parameter_rand`, `authentication_parameter_autn`, as in 5GS |

  The setters follow the members (`with_registration_accept_type_6_ie_container`).

- The paging restriction and the additional request result of the two
  systems have one interface, which one macro writes for both: the
  sessions or connections for which paging is not restricted, and one
  `PagingRestrictionDecision`, by the words of its table.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `nas_eps::EpsPagingRestrictionType` | `nas_eps::PagingRestrictionType`, as in 5GS |
  | `nas_5gs::PagingRestrictionType::Reserved` | none: `restriction_type()` is `None` for a reserved code, as in EPS |
  | `NasPagingRestriction::from_restriction_type(kind)`, `from_restriction_type_with_unrestricted_psis(kind, &psis)` (5GS) | `from_restriction(kind, &psis)`, as in EPS |
  | `unrestricted_psi_list() -> Vec<u8>`, `restricted_psi_list()`, `unrestricted_psi_bitmap()`, `restricted_psi_bitmap()`, `set_unrestricted_psi_list`, `with_unrestricted_psi_list`, `set_restriction_type`, `with_restriction_type`, `data`, `from_data` (5GS) | `unrestricted_psis() -> Option<Vec<u8>>`, as `unrestricted_ebis()` of EPS; `from_restriction`; `value`, `new` |
  | tree member `"unrestricted-psi-list"` (5GS) | `"unrestricted-psis"`, as `"unrestricted-ebis"` of EPS |
  | the refusals "is written with a restriction type that has a PDU session bitmap", "are written with a restriction type that has a bearer bitmap" | "are written with a restriction type that has their bitmap" |
  | `nas_5gs::PagingRestrictionDecision::{NoAdditionalInfo, PagingRestrictionAccepted, PagingRestrictionRejected}`, `nas_eps::PagingRestrictionDecision::{NoAdditionalInformation, Accepted, Rejected}` | one type, `{NoAdditionalInformation, PagingRestrictionIsAccepted, PagingRestrictionIsRejected}`; in a tree `"no-additional-information"`, `"paging-restriction-is-accepted"`, `"paging-restriction-is-rejected"` |
  | `NasFGsAdditionalRequestResult::prd()`, `prd_raw() -> u8`, `from_prd` | `paging_restriction_decision()`, `paging_restriction_decision_raw() -> Option<u8>`, `from_paging_restriction_decision`, and `is_well_formed()`, as in EPS |

- The octets of an IE have one spelling: its `value`, which `new(value)`
  writes. The 438 methods that only read or wrote the whole value under
  another name are gone, and an IE type has the same way to its octets in
  both systems, where some had them and others not.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `ie.data()` (100 IE types), `ie.octets()` (5GS network feature support, 5GMM and 5GSM capabilities), `ie.capability_bytes()` (UE security capabilities) | `ie.value` (`ie.value.as_slice()` for a `&[u8]`) |
  | `Ie::from_data(v)` (100), `from_capability_bytes(v)`, `NasAbba::from_bytes(&abba)` | `Ie::new(v)` |
  | `ie.set_data(v)`, `ie.with_data(v)` (81) | `ie.value = v.into()`, `Ie::new(v)` |
  | the same four under the name of the content: `container_data` (8 containers), `epco_data`, `eap_data`, `eps_nas_data`, `rules_data`, `descriptions_data`, `contexts_data`, `address_data`, `budget_data`, `device_information_data`, `qai_data`, `description_data`, `context_list_data`, `report_data` | `value`, `new` |

  A getter that gives the value of a fixed IE by what it carries stays
  (`rand()`, `autn()`, `auts()`, `res()`, `res_star()`, `abba()`), with its
  constructor of a typed array (`from_rand([u8; 16])`).

- Three IEs that the two specifications code alike have one interface:

  | 0.4.0 | 0.5.0 |
  |---|---|
  | control plane only indication: `cpoi()`, `is_control_plane_only()` (an alias), `from_cpoi`, `control_plane_only()`, `is_well_formed()` in 5GS; `is_control_plane_only()`, `control_plane_only()` in EPS; tree `{"cpoi": true}` in 5GS and `{"is-control-plane-only": true}` in EPS | `cpoi()`, `from_cpoi`, `control_plane_only()`, `is_well_formed()` in both, from one macro; `{"cpoi": true}` in both trees, the name of the table |
  | `nas_eps::NasAdditionalInformationRequested::spare_bits_are_zero()` | `is_well_formed()`, as in 5GS |
  | `nas_eps::EpsRemoteUeContext` | `nas_eps::RemoteUeContext`, as the 5GS one is named |

- The `security-header` of the tree of a 5GS message leaves out what the
  system decides, as the tree of a plain message does and as that of EPS
  has it: the extended protocol discriminator, which is that of 5GMM, and
  a spare half octet of zero. `from_tree` reads a header without them, and
  one that has them; the view keeps every field.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `"security-header": {"extended-protocol-discriminator": 126, "security-header-type": "integrity-protected", "spare-half-octet": 0, "message-authentication-code": …, "sequence-number": 0}` | `"security-header": {"security-header-type": "integrity-protected", "message-authentication-code": …, "sequence-number": 0}` |

- A constructor of one name takes one kind of argument:
  `NasPagingIdentity::from_tmsi(bool)` took a flag where
  `NasMobileIdentity::from_tmsi(u32)` takes a TMSI. The paging identity is
  a `PagingIdentityValue`, by the words of its table.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `NasPagingIdentity::is_tmsi() -> bool`, `from_tmsi(bool)` | `paging_identity() -> PagingIdentityValue`, `from_paging_identity(PagingIdentityValue::Tmsi)` |
  | tree `"paging-identity": {"is-tmsi": true}` | `"paging-identity": "tmsi"` (or `"imsi"`) |

- `Serialize` and `Deserialize` go through the trees, and no type derives
  them: a message is its tree (`to_tree`, `from_tree`), an IE what the tree
  of a message shows of it (its value where that writes it back, or
  `{"octets": ".."}`), and a value of an IE, a header or a cause, its form
  there. The trees no longer go through serde either: the macros of the
  messages and of the IEs, and one macro for each struct and enum of the
  values, write them, and the forms of the trees and views are those of
  before. The feature `serde` takes oxirush-utils' `serde` in place of the
  crate `serde`, and is `no_std` as it was.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `serde_json::to_value(&message)`: `{"Gmm":[{"extended_protocol_discriminator":126,...},{"FiveGmmStatus":{"fgmm_cause":{"value":22},"unknown_ies":[],"optional_ie_order":[]}}]}` | `{"message-type":"5gmm-status","5gmm-cause":"congestion"}`, its tree; the message read back means the same (`means_the_same`), with its octets where the values decide them |
  | `serde_json::to_value(&ie)`: `{"value": [22]}` | `"congestion"`, or `{"octets": "16"}` for an IE whose value does not write it back |
  | `serde_json::to_value(&GmmCause::Congestion)`: `"Congestion"` | `"congestion"`, and every value of an IE in the form of its tree (`{"native": 3}` for a key set identifier) |
  | `Serialize`/`Deserialize` of a message struct (`NasRegistrationRequest`) and of the enums of one protocol (`Nas5gmmMessage`, `NasEmmMessage`...) | none: a message is serialized as a `Nas5gsMessage` or a `NasEpsMessage` |
  | the error of a document that is no value: serde's (`missing field \`value\``) | that of the tree, with the name of the type: `this is not a value of NasFGmmCause: ...` |
  | dependency `serde` | `serde_core`, through oxirush-utils, and `spin` 0.10, whose locks keep the names that the trees print, with or without `std` |

- A tree and a view are a `tree::Value`, the tree of oxirush-utils, which
  the crate re-exports as `oxirush_nas::tree` with `tree!`: JSON whose
  objects keep their members in the order in which they are written, the
  order of the message, whatever the features of `serde_json` in a build.
  It converts to and from a `serde_json::Value` and compares equal to one.
  The crate depends on `serde_json` no more, and oxirush-utils no longer
  turns on `serde_json/preserve_order`, which changed the `serde_json::Map`
  of every program that used the crate.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `to_tree()`, `to_view()`, `from_tree`, `from_view`, `with_view`, `view::select`, `paths`, `set`, `insert`, `remove`, `blank_view()`: `serde_json::Value` | `oxirush_nas::tree::Value`; `Value::from(json)` and `serde_json::Value::from(tree)` convert |
  | `serde_json::json!({...})` | `oxirush_nas::tree!({...})`, which takes a variable that holds a tree by value: `&name` keeps it |
  | `serde_json::Map<String, Value>` of an object of a tree | `tree::Map` |
  | `serde_json::to_value(&message)` printed the members in the order of the message, `preserve_order` being on | in the order of a `serde_json::Map` of the program; `serde_json::to_string(&message)` writes them in the order of the message |
  | dependency `serde_json` with the feature `serde` | none; `serde_json` 1 through oxirush-utils |

- A tree leaves out a member that a value has not, as it leaves out an IE
  that the message has not, where it showed `null`. A view keeps `null`
  for both, at which a path selects nothing. `null` is absent wherever it
  is written, as the paths of oxirush-utils read it: no value of NAS is
  the NULL of ASN.1.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `"requested-nssai": [{"sst": 1, "sd": null, "mapped-sst": null, "mapped-sd": null}]` | `[{"sst": 1}]` |
  | `"eps-qos": {"qci": 9, "bit-rates": null, "extension": null, "extension2": null}` | `{"qci": 9}` |
  | `{"pap": {"code": "authenticate-ack", "identifier": 1, "peer-id": null, "password": null, "message": ""}}` | `{"pap": {"code": "authenticate-ack", "identifier": 1, "message": ""}}` |
  | `"suci": {"imsi": {..., "msin": "123456789", "scheme-output": null}}` | without `scheme-output` |

- A value that holds an IE, or the octets of one, shows it in a tree as
  the tree of a message shows that IE, where it showed its octets: the DNN
  and the TAI list of a LADN, the S-NSSAIs and TAI lists of the NSSAI, NSAG
  and NSSRG entries, the TAI list of a ciphering data set, the IEs of a
  type 6 IE container and of the optional IEs of a UPDS payload. An EPS
  packet filter has its direction by name and its components, as the
  packet filters of a 5GS QoS rule have.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `"ladn-information": [{"dnn": "08696e7465726e6574", "tai-list": "0002f839000001"}]` | `[{"dnn": "internet", "tai-list": [{"one-plmn-non-consecutive": {"plmn": "208-93", "tacs": [1]}}]}]` |
  | `"s-nssai": "0101"` in an entry | `"s-nssai": {"sst": 1, ...}` |
  | `"dnn": {"value": "..."}`, `"s-nssai": {"value": "..."}` of an extended LADN entry, and the IEs of a type 6 IE container | the trees of those IEs |
  | `"packet-filters": [{"identifier": 1, "direction": 3, "precedence": 255, "contents": "3011"}]` | `[{"identifier": 1, "direction": "bidirectional", "precedence": 255, "components": [{"protocol-identifier-next-header": 17}]}]`; `contents` in hexadecimal where the components do not write them back, and either is read |

- A tree or a view that names a member or a value that does not exist is
  refused with the nearest names that do where the type has more than
  eight (`no name \`congestio\`; the nearest of the 50 is congestion`, where
  the 50 causes were listed), and a member that is not written by its name
  as a tree writes it (`\`message-authentication-code\` is not written`,
  where it was `missing field \`message_authentication_code\``).

- The names that a first program tripped on.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `Suci::as_imsi() -> Option<&ImsiSuci>`, `Suci::as_nai() -> Option<&NaiSuci>` | `as_imsi_suci()`, `as_nai_suci()`: `as_imsi()` of an EPS mobile identity gives an `Imsi` |
  | `PduSessionTypeValue::IPv4`, `IPv6`, `IPv4v6`, and those of `PduAddressTypeValue` | `Ipv4`, `Ipv6`, `Ipv4v6`, as `PdnType` of EPS and every other enum of both systems; the trees write `ipv4` as before |
  | `QosRule::new(rule_id, op_code, dqr, packet_filters, precedence, qfi, segregation)` | `QosRule::new(rule_id, op_code)` with `with_default_rule`, `with_packet_filters`, `with_precedence`, `with_qfi` and `with_segregation` |
  | `NasT3512Value::to_seconds_with_integrity(true)` alone | `to_seconds()` too, as the other timers have it |
  | `Display` of a PDU SESSION ESTABLISHMENT REQUEST or ACCEPT: `type=0x1` | `type=Ipv4`, the code where it has no name |

- A method of one name gives the same kind of value in both systems.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `NasFGsUpdateType::pnb_ciot() -> u8`, `set_pnb_ciot(u8) -> Result`, and the same of `eps_pnb_ciot` | `-> Option<PreferredCiotBehavior>`, `pnb_ciot_raw() -> u8`, `set_pnb_ciot(PreferredCiotBehavior) -> &mut Self`, as `NasN1UeNetworkCapability` of EPS has them; `PreferredCiotBehavior` is one type of both systems |
  | `NasN1UeNetworkCapability::set_pnb_ciot` returned `()` | `&mut Self` |
  | `NasFGsDrxParameters::drx_value_raw() -> u8`, `NasNbN1ModeDrxParameters::drx_value_raw() -> u8`, `NasPagingRestriction::restriction_type_raw() -> u8` (5GS), 0 for an empty value | `-> Option<u8>`, as in EPS |
  | `NasPduAddress::ipv6_interface_id() -> Option<&[u8]>` | `-> Option<[u8; 8]>`, as `NasPdnAddress` has it |
  | `NasMappedEpsBearerContexts::contexts() -> Vec`, empty for a value that does not parse, and `try_contexts() -> Option<Vec>` | `contexts() -> Option<Vec>` |
  | `NasRemoteUeContextList::contexts() -> Vec` (5GS), empty for a value that does not parse | `-> Option<Vec>`, as in EPS |
  | `ControlPlaneServiceTypeValue` (5GS); `from_u8(code) -> Option<Self>`, never `None`; `NasControlPlaneServiceType::service_type() -> Option` | `ControlPlaneServiceType`, as in EPS; `from_u8(code) -> Self` with the receive rule, `from_u8_strict`; `service_type()` with the rule and `service_type_strict()` |
  | `NasMessageContainer::decode_plain_inner()`, `from_plain_message` | `decode_as_nas_message()`, `from_nas_message`, as `decode_as_esm_message` of the ESM message container |
  | `NasPayloadContainer::decode_plain_nas_message()`, `from_plain_nas_message`, the same as `decode_as_n1_sm_message`, `from_n1_sm_message` | `decode_as_n1_sm_message`, `from_n1_sm_message` |

  The tree of a 5GS update type names its preferred CIoT behaviours
  (`"pnb-ciot": "control-plane"`), where it gave their codes.

- The four cause enums have one form, that of the 5GS ones: each variant
  is its code (`#[repr(u8)]`), `from_u8` gives the cause of a listed code,
  the receiver rules give one for every code, `as_u8` the code and
  `description(self)` the words of the table. The IEs of a cause have
  the same methods in both systems: `cause()` is the listed cause or
  `None`, the IE keeping the code that it has.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `EmmCause::Unknown(code)`, `EsmCause::Unknown(code)` | none: `NasEmmCause::cause()` is `None`, and `cause_raw()` the code |
  | `NasEmmCause::cause() -> EmmCause`, `NasEsmCause::cause() -> EsmCause` | `-> Option<EmmCause>`, `-> Option<EsmCause>`, as in 5GS |
  | `EmmCause::from_u8(code) -> EmmCause`, `from_u8_strict(code) -> Option`; the same for `EsmCause` | `from_u8(code) -> Option<Self>` |
  | `GmmCause::from_u8_strict`, `GsmCause::from_u8_strict` (the same as `from_u8`) | `from_u8` |
  | `GmmCause::description(&self)`, `GsmCause::description(&self)` | `description(self)` |
  | `cause as u8` alone in 5GS | also `cause.as_u8()`, as in EPS |
  | `NasFGmmCause`, `NasFGsmCause` without `set_cause`, `with_cause` | `set_cause(&mut self, cause) -> &mut Self`, `with_cause(self, cause)` |

- The variants of the code enums are the words of their tables, as the
  EPS causes already were: the causes of 5GMM and of 5GSM
  (`MessageTypeNonExistentOrNotImplemented` for #97), the message types,
  the security header types, the registration, update and attach types and
  results, the service types, the control plane service types, the access
  types and the detach types, compared mechanically with the tables of
  TS 24.501 and TS 24.301. A leading number is spelled (`FiveGmmStatus`,
  `ThreeGppAccess`), and so is 5G (`NonFiveGAuthenticationUnacceptable`),
  which a view prints back as `5g`; `5gcn` and `1x` print as words. The
  messages of a direction are named after it as Table 9.7.1 names them,
  in both systems. The trees and views print the new names, and read no
  other: the table gives each name as printed.

  | 0.4.0 | 0.5.0 | printed |
  |---|---|---|
  | `nas_5gs::GmmCause::FiveGSServicesNotAllowed` | `FiveGsServicesNotAllowed` | `5gs-services-not-allowed` |
  | `nas_5gs::GmmCause::UeIdentityCannotBeDerived` | `UeIdentityCannotBeDerivedByTheNetwork` | `ue-identity-cannot-be-derived-by-the-network` |
  | `nas_5gs::GmmCause::RoamingNotAllowedInTa` | `RoamingNotAllowedInThisTrackingArea` | `roaming-not-allowed-in-this-tracking-area` |
  | `nas_5gs::GmmCause::NoCellsInTa` | `NoSuitableCellsInTrackingArea` | `no-suitable-cells-in-tracking-area` |
  | `nas_5gs::GmmCause::UeSecurityCapMismatch` | `UeSecurityCapabilitiesMismatch` | `ue-security-capabilities-mismatch` |
  | `nas_5gs::GmmCause::SecurityModeRejected` | `SecurityModeRejectedUnspecified` | `security-mode-rejected-unspecified` |
  | `nas_5gs::GmmCause::Non5GAuthUnacceptable` | `NonFiveGAuthenticationUnacceptable` | `non-5g-authentication-unacceptable` |
  | `nas_5gs::GmmCause::MaxPduSessionsReached` | `MaximumNumberOfPduSessionsReached` | `maximum-number-of-pdu-sessions-reached` |
  | `nas_5gs::GmmCause::InsufficientResourcesForSliceDnn` | `InsufficientResourcesForSpecificSliceAndDnn` | `insufficient-resources-for-specific-slice-and-dnn` |
  | `nas_5gs::GmmCause::InsufficientResourcesForSlice` | `InsufficientResourcesForSpecificSlice` | `insufficient-resources-for-specific-slice` |
  | `nas_5gs::GmmCause::TemporarilyNotAuthorizedForSnpn` | `TemporarilyNotAuthorizedForThisSnpn` | `temporarily-not-authorized-for-this-snpn` |
  | `nas_5gs::GmmCause::PermanentlyNotAuthorizedForSnpn` | `PermanentlyNotAuthorizedForThisSnpn` | `permanently-not-authorized-for-this-snpn` |
  | `nas_5gs::GmmCause::NotAuthorizedForCag` | `NotAuthorizedForThisCagOrAuthorizedForCagCellsOnly` | `not-authorized-for-this-cag-or-authorized-for-cag-cells-only` |
  | `nas_5gs::GmmCause::PlmnNotAllowedAtUeLocation` | `PlmnNotAllowedToOperateAtThePresentUeLocation` | `plmn-not-allowed-to-operate-at-the-present-ue-location` |
  | `nas_5gs::GmmCause::DisasterRoamingNotAllowed` | `DisasterRoamingForTheDeterminedPlmnWithDisasterConditionNotAllowed` | `disaster-roaming-for-the-determined-plmn-with-disaster-condition-not-allowed` |
  | `nas_5gs::GmmCause::N3iwfNotCompatibleWithNssai` | `SelectedN3iwfIsNotCompatibleWithTheAllowedNssai` | `selected-n3iwf-is-not-compatible-with-the-allowed-nssai` |
  | `nas_5gs::GmmCause::TngfNotCompatibleWithNssai` | `SelectedTngfIsNotCompatibleWithTheAllowedNssai` | `selected-tngf-is-not-compatible-with-the-allowed-nssai` |
  | `nas_5gs::GmmCause::DnnNotSupportedInSlice` | `DnnNotSupportedOrNotSubscribedInTheSlice` | `dnn-not-supported-or-not-subscribed-in-the-slice` |
  | `nas_5gs::GmmCause::InsufficientUserPlaneResources` | `InsufficientUserPlaneResourcesForThePduSession` | `insufficient-user-plane-resources-for-the-pdu-session` |
  | `nas_5gs::GmmCause::MessageTypeNotExistent` | `MessageTypeNonExistentOrNotImplemented` | `message-type-non-existent-or-not-implemented` |
  | `nas_5gs::GmmCause::MessageTypeNotCompatible` | `MessageTypeNotCompatibleWithTheProtocolState` | `message-type-not-compatible-with-the-protocol-state` |
  | `nas_5gs::GmmCause::InformationElementNotExistent` | `InformationElementNonExistentOrNotImplemented` | `information-element-non-existent-or-not-implemented` |
  | `nas_5gs::GmmCause::MessageNotCompatible` | `MessageNotCompatibleWithTheProtocolState` | `message-not-compatible-with-the-protocol-state` |
  | `nas_5gs::GmmCause::Non3GppAccessTo5GcnNotAllowed` | `Non3GppAccessToFiveGcnNotAllowed` | `non-3gpp-access-to-5gcn-not-allowed` |
  | `nas_5gs::GsmCause::UserAuthFailed` | `UserAuthenticationOrAuthorizationFailed` | `user-authentication-or-authorization-failed` |
  | `nas_5gs::GsmCause::ServiceOptionNotSubscribed` | `RequestedServiceOptionNotSubscribed` | `requested-service-option-not-subscribed` |
  | `nas_5gs::GsmCause::SemanticErrorInTft` | `SemanticErrorInTheTftOperation` | `semantic-error-in-the-tft-operation` |
  | `nas_5gs::GsmCause::SyntacticalErrorInTft` | `SyntacticalErrorInTheTftOperation` | `syntactical-error-in-the-tft-operation` |
  | `nas_5gs::GsmCause::SemanticErrorInPacketFilter` | `SemanticErrorsInPacketFilters` | `semantic-errors-in-packet-filters` |
  | `nas_5gs::GsmCause::SyntacticalErrorInPacketFilter` | `SyntacticalErrorInPacketFilters` | `syntactical-error-in-packet-filters` |
  | `nas_5gs::GsmCause::PduSessionTypeIpv4Only` | `PduSessionTypeIpv4OnlyAllowed` | `pdu-session-type-ipv4-only-allowed` |
  | `nas_5gs::GsmCause::PduSessionTypeIpv6Only` | `PduSessionTypeIpv6OnlyAllowed` | `pdu-session-type-ipv6-only-allowed` |
  | `nas_5gs::GsmCause::PduSessionTypeIpv4v6Only` | `PduSessionTypeIpv4v6OnlyAllowed` | `pdu-session-type-ipv4v6-only-allowed` |
  | `nas_5gs::GsmCause::PduSessionTypeUnstructuredOnly` | `PduSessionTypeUnstructuredOnlyAllowed` | `pdu-session-type-unstructured-only-allowed` |
  | `nas_5gs::GsmCause::PduSessionTypeEthernetOnly` | `PduSessionTypeEthernetOnlyAllowed` | `pdu-session-type-ethernet-only-allowed` |
  | `nas_5gs::GsmCause::InsufficientResourcesForSliceDnn` | `InsufficientResourcesForSpecificSliceAndDnn` | `insufficient-resources-for-specific-slice-and-dnn` |
  | `nas_5gs::GsmCause::InsufficientResourcesForSlice` | `InsufficientResourcesForSpecificSlice` | `insufficient-resources-for-specific-slice` |
  | `nas_5gs::GsmCause::MissingOrUnknownDnnInSlice` | `MissingOrUnknownDnnInASlice` | `missing-or-unknown-dnn-in-a-slice` |
  | `nas_5gs::GsmCause::MaxDataRateForUpIpTooLow` | `MaximumDataRatePerUeForUserPlaneIntegrityProtectionIsTooLow` | `maximum-data-rate-per-ue-for-user-plane-integrity-protection-is-too-low` |
  | `nas_5gs::GsmCause::SemanticErrorInQosOperation` | `SemanticErrorInTheQosOperation` | `semantic-error-in-the-qos-operation` |
  | `nas_5gs::GsmCause::SyntacticalErrorInQosOperation` | `SyntacticalErrorInTheQosOperation` | `syntactical-error-in-the-qos-operation` |
  | `nas_5gs::GsmCause::QosDiffNon3gppDeviceIdNotAvailable` | `QosDifferentiationForNon3GppDeviceIdentifiersNotAvailable` | `qos-differentiation-for-non-3gpp-device-identifiers-not-available` |
  | `nas_5gs::GsmCause::MessageTypeNotExistent` | `MessageTypeNonExistentOrNotImplemented` | `message-type-non-existent-or-not-implemented` |
  | `nas_5gs::GsmCause::MessageTypeNotCompatible` | `MessageTypeNotCompatibleWithTheProtocolState` | `message-type-not-compatible-with-the-protocol-state` |
  | `nas_5gs::GsmCause::InformationElementNotExistent` | `InformationElementNonExistentOrNotImplemented` | `information-element-non-existent-or-not-implemented` |
  | `nas_5gs::GsmCause::MessageNotCompatible` | `MessageNotCompatibleWithTheProtocolState` | `message-not-compatible-with-the-protocol-state` |
  | `nas_eps::EmmCause::RedirectionTo5gcnRequired` | `RedirectionToFiveGcnRequired` | `redirection-to-5gcn-required` |
  | `nas_5gs::Nas5gmmMessageType::DeregistrationRequestFromUe` | `DeregistrationRequestUeOriginating` | `deregistration-request-ue-originating` |
  | `nas_5gs::Nas5gmmMessageType::DeregistrationAcceptFromUe` | `DeregistrationAcceptUeOriginating` | `deregistration-accept-ue-originating` |
  | `nas_5gs::Nas5gmmMessageType::DeregistrationRequestToUe` | `DeregistrationRequestUeTerminated` | `deregistration-request-ue-terminated` |
  | `nas_5gs::Nas5gmmMessageType::DeregistrationAcceptToUe` | `DeregistrationAcceptUeTerminated` | `deregistration-accept-ue-terminated` |
  | `nas_5gs::Nas5gmmMessageType::FGmmStatus` | `FiveGmmStatus` | `5gmm-status` |
  | `nas_5gs::Nas5gsmMessageType::FGsmStatus` | `FiveGsmStatus` | `5gsm-status` |
  | `nas_5gs::Nas5gsSecurityHeaderType::PlainNasMessage` | `PlainFiveGsNasMessageNotSecurityProtected` | `plain-5gs-nas-message-not-security-protected` |
  | `nas_5gs::Nas5gsSecurityHeaderType::IntegrityProtectedWithNewContext` | `IntegrityProtectedWithNewFiveGNasSecurityContext` | `integrity-protected-with-new-5g-nas-security-context` |
  | `nas_5gs::Nas5gsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext` | `IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext` | `integrity-protected-and-ciphered-with-new-5g-nas-security-context` |
  | `nas_eps::NasEpsSecurityHeaderType::PlainNasMessage` | `PlainNasMessageNotSecurityProtected` | `plain-nas-message-not-security-protected` |
  | `nas_eps::NasEpsSecurityHeaderType::IntegrityProtectedWithNewContext` | `IntegrityProtectedWithNewEpsSecurityContext` | `integrity-protected-with-new-eps-security-context` |
  | `nas_eps::NasEpsSecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext` | `IntegrityProtectedAndCipheredWithNewEpsSecurityContext` | `integrity-protected-and-ciphered-with-new-eps-security-context` |
  | `nas_eps::NasEpsSecurityHeaderType::IntegrityProtectedAndPartiallyCiphered` | `IntegrityProtectedAndPartiallyCipheredNasMessage` | `integrity-protected-and-partially-ciphered-nas-message` |
  | `nas_eps::NasEpsSecurityHeaderType::EmmTransport` | `SecurityHeaderForTheEmmTransportMessage` | `security-header-for-the-emm-transport-message` |
  | `nas_eps::NasEpsSecurityHeaderType::ServiceRequest` | `SecurityHeaderForTheServiceRequestMessage` | `security-header-for-the-service-request-message` |
  | `nas_5gs::RegistrationType::MobilityRegistrationUpdate` | `MobilityRegistrationUpdating` | `mobility-registration-updating` |
  | `nas_5gs::RegistrationType::PeriodicRegistrationUpdate` | `PeriodicRegistrationUpdating` | `periodic-registration-updating` |
  | `nas_5gs::RegistrationType::SnpnOnboarding` | `SnpnOnboardingRegistration` | `snpn-onboarding-registration` |
  | `nas_5gs::RegistrationType::DisasterRoamingMobility` | `DisasterRoamingMobilityRegistrationUpdating` | `disaster-roaming-mobility-registration-updating` |
  | `nas_5gs::RegistrationType::DisasterRoamingInitial` | `DisasterRoamingInitialRegistration` | `disaster-roaming-initial-registration` |
  | `nas_eps::AttachResult::CombinedEpsImsi` | `CombinedEpsImsiAttach` | `combined-eps-imsi-attach` |
  | `nas_eps::UpdateResult::TaUpdatedWithIsr` | `TaUpdatedAndIsrActivated` | `ta-updated-and-isr-activated` |
  | `nas_eps::UpdateResult::CombinedTaLaUpdatedWithIsr` | `CombinedTaLaUpdatedAndIsrActivated` | `combined-ta-la-updated-and-isr-activated` |
  | `nas_5gs::RegistrationResult::ThreeGppAndNon3Gpp` | `ThreeGppAccessAndNon3GppAccess` | `3gpp-access-and-non-3gpp-access` |
  | `nas_eps::ServiceType::MobileOriginatingCsFallback` | `MobileOriginatingCsFallbackOr1xCsFallback` | `mobile-originating-cs-fallback-or1x-cs-fallback` |
  | `nas_eps::ServiceType::MobileTerminatingCsFallback` | `MobileTerminatingCsFallbackOr1xCsFallback` | `mobile-terminating-cs-fallback-or1x-cs-fallback` |
  | `nas_eps::ServiceType::MobileOriginatingEmergencyCsFallback` | `MobileOriginatingCsFallbackEmergencyCallOr1xCsFallbackEmergencyCall` | `mobile-originating-cs-fallback-emergency-call-or1x-cs-fallback-emergency-call` |
  | `nas_eps::ServiceType::PacketServices` | `PacketServicesViaS1` | `packet-services-via-s1` |
  | `nas_5gs::DeregistrationAccessType::ThreeGpp` | `ThreeGppAccess` | `3gpp-access` |
  | `nas_5gs::DeregistrationAccessType::Non3Gpp` | `Non3GppAccess` | `non-3gpp-access` |
  | `nas_5gs::DeregistrationAccessType::ThreeGppAndNon3Gpp` | `ThreeGppAccessAndNon3GppAccess` | `3gpp-access-and-non-3gpp-access` |
  | `nas_5gs::AccessTypeValue::ThreeGpp` | `ThreeGppAccess` | `3gpp-access` |
  | `nas_5gs::AccessTypeValue::Non3Gpp` | `Non3GppAccess` | `non-3gpp-access` |
  | `nas_eps::UeDetachKind::Eps` | `EpsDetach` | `eps-detach` |
  | `nas_eps::UeDetachKind::Imsi` | `ImsiDetach` | `imsi-detach` |
  | `nas_eps::UeDetachKind::CombinedEpsImsi` | `CombinedEpsImsiDetach` | `combined-eps-imsi-detach` |
  | `nas_eps::NetworkDetachKind::Imsi` | `ImsiDetach` | `imsi-detach` |
  | `nas_eps::ControlPlaneServiceType::MobileOriginating` | `MobileOriginatingRequest` | `mobile-originating-request` |
  | `nas_eps::ControlPlaneServiceType::MobileTerminating` | `MobileTerminatingRequest` | `mobile-terminating-request` |
  | `nas_5gs::` Nas5gmmMessage::FGmmStatus, Nas5gsmMessage::FGsmStatus | FiveGmmStatus, FiveGsmStatus | 5gmm-status, 5gsm-status (as before) |
  | `nas_5gs::` NasDeregistrationRequestFromUe, NasDeregistrationAcceptFromUe, NasDeregistrationRequestToUe, NasDeregistrationAcceptToUe, and the variants of Nas5gmmMessage and Nas5gmmMessageType of these names | NasDeregistrationRequestUeOriginating, NasDeregistrationAcceptUeOriginating, NasDeregistrationRequestUeTerminated, NasDeregistrationAcceptUeTerminated | deregistration-request-ue-originating, ... |
  | `nas_eps::` NasDetachRequestFromUe, NasDetachRequestToUe, and the variants of NasEmmMessage | NasDetachRequestUeOriginating, NasDetachRequestUeTerminated | (the message type stays detach-request) |

- Two IEs that share an octet are two members of the message, in both
  systems, as the EPS messages had them: the ngKSI of a 5GS REGISTRATION
  REQUEST, DEREGISTRATION REQUEST from the UE and CONTROL PLANE SERVICE
  REQUEST is `ngksi` beside the registration, de-registration or control
  plane service type, and a SERVICE REQUEST has `ngksi` and `service_type`
  (`NasServiceType`, §9.11.3.50). Each is in its own entry of a view and a
  tree, `"ngksi": {"native": 0}` as in the other messages. A spare half
  octet is no member: the IE beside it has the whole octet, as the 5GS
  messages had it, so that `new()` takes no spare half octet in EPS either
  and no tree has a `spare-half-octet` member but the one of a header. A
  spare bit that is set is in the octets of its IE, which a tree then
  shows, and `validate()` reports it at that IE.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `NasRegistrationRequest::new(NasFGsRegistrationType::new(0x79), identity)` | `NasRegistrationRequest::new(NasFGsRegistrationType::new(0x09), NasKeySetIdentifier::new(7), identity)` |
  | `NasDeregistrationRequestFromUe::new(kind, identity)`, `NasControlPlaneServiceRequest::new(kind)` | `new(kind, ngksi, identity)`, `new(kind, ngksi)` |
  | `NasServiceRequest::new(ngksi_and_service_type, s_tmsi)`, `request.service_type()`, `service_type_raw()`, `set_service_type`, `with_service_type` | `NasServiceRequest::new(ngksi, service_type, s_tmsi)`, `request.service_type.service_type()`, and so on |
  | `ngksi()`, `set_ngksi`, `with_ngksi`, `tsc()`, `set_tsc`, `with_tsc` of `NasFGsRegistrationType`, `NasDeRegistrationType` and `NasControlPlaneServiceType`, and of the two messages | those of the `ngksi` member: `ksi()`, `set_ksi`, `tsc()`, `key_set_identifier()` |
  | `NasKeySetIdentifier::ngksi()`, `set_ngksi`, `with_ngksi` (5GS) | `ksi()`, `set_ksi`, `with_ksi`, as in EPS |
  | `nas_key_set_identifier()`, `set_nas_key_set_identifier`, `with_nas_key_set_identifier` of a DEREGISTRATION REQUEST from the UE and a CONTROL PLANE SERVICE REQUEST | the member `ngksi` |
  | `NasSpareHalfOctet` (EPS), the member `spare_half_octet` of ten EPS messages and its argument of their `new()` | none: the IE beside it has the octet |
  | the default of `NasFGsRegistrationType`, `NasDeRegistrationType`, `NasControlPlaneServiceType`: ngKSI 7 in bits 8 to 5 | the type alone; `NasKeySetIdentifier::default()` is "no key" |
  | `NasControlPlaneServiceType::set_service_type` returned `()` | `&mut Self` |

- An IE type that one NAS specification defines and the other reuses is
  one type for both protocols, which `nas_5gs` and `nas_eps` re-export, so
  that a value of one is a value of the other: the T3346 value of a 5GS
  REGISTRATION REJECT is that of an EPS ATTACH REJECT. These are 34 types,
  by the specification that defines them:

  TS 24.008: `NasAuthenticationFailureParameter`,
  `NasAuthenticationParameterAutn`, `NasAuthenticationParameterRand`,
  `NasDaylightSavingTime`, `NasEmergencyNumberList`,
  `NasExtendedDrxParameters`, `NasExtendedProtocolConfigurationOptions`,
  `NasGprsTimer`, `NasGprsTimer2`, `NasGprsTimer3`, `NasImeisvRequest`,
  `NasMobileStationClassmark2`, `NasNetworkName`,
  `NasNon3GppNwProvidedPolicies`, `NasPlmnList`, `NasSupportedCodecList`,
  `NasTimeZone`, `NasTimeZoneAndTime`.
  TS 24.301: `NasAccessTechnologyUtilizationControl`,
  `NasAuthenticationResponseParameter`, `NasEpsBearerContextStatus`,
  `NasExtendedEmergencyNumberList`, `NasReleaseAssistanceIndication`,
  `NasServingPlmnRateControl`, `NasUeRequestType`,
  `NasUnavailabilityConfiguration`, `NasUnavailabilityInformation`,
  `NasWusAssistanceInformation`.
  TS 24.501: `NasListOfPlmnsToBeUsedInDisasterCondition`, `NasPlmnIdentity`,
  `NasRegistrationWaitRange`, `NasUeRadioCapabilityId`,
  `NasUeRadioCapabilityIdDeletionIndication`, `NasUeStatus`.

  Each has the methods and the rules that its two types had. `validate()`
  of an EPS message now reports a UE status, extended DRX parameters or a
  time zone that a sender may not send, and that of a 5GS message an IMEISV
  request, non-3GPP NW provided policies or a release assistance indication
  of a reserved value. The value lengths of a type are those of its clause
  in both protocols: in 5GS, the authentication response parameter has 4
  to 16 octets and the unavailability configuration 1 to 7, as TS 24.301
  defines them, and the message tables keep 16 and 1 to 4. Decoding, the
  octets, the findings of every other message and the trees are those of
  before, over the fixtures and the fuzzing corpus. Three IE types are
  reused under another name, and stay a type of each protocol, named after
  its clause, with one grammar: the NAS security algorithms, the UE
  security capability and the UE network capability of TS 24.301 are the
  EPS NAS security algorithms, the S1 UE security capability and the S1 UE
  network capability of TS 24.501, which has a NAS security algorithms and
  a UE security capability of its own.

- The crate root has what the two systems share, and no longer the 5GS
  API: `oxirush_nas::Nas5gsMessage` is `oxirush_nas::nas_5gs::Nas5gsMessage`,
  as `nas_eps::NasEpsMessage` is for EPS, and so for every item of one
  system. The root has `Decode`, `Encode`, `NasError`, `Result`, `IeFault`,
  `MAX_IE_VALUE_LENGTH`, `Direction`, `Octets`, `Validate`,
  `ValidationError`, `Severity`, `ValueError`, `ValueFault`, `UnknownIe`,
  `UnknownIes` and `UnknownIesIter`, `Plmn` and the module `identity` of
  oxirush-utils, the modules `common`, `nas_5gs`, `nas_eps` and `view`,
  and `VERSION`.

- Decoding and encoding have one spelling, that of the other OxiRush
  crates: `Nas5gsMessage::decode(&octets)` and `message.encode()`.

  | 0.4.0 | Now |
  |---|---|
  | `decode_nas_5gs_message(&octets)`, `Nas5gsMessage::from_bytes(&octets)` | `Nas5gsMessage::decode(&octets)` |
  | `encode_nas_5gs_message(&message)`, `message.to_bytes()` | `message.encode()` |
  | `decode_nas_eps_message(&octets)`, `NasEpsMessage::from_bytes(&octets)` | `NasEpsMessage::decode(&octets)` |
  | `decode_nas_eps_message_with_direction(&octets, direction)`, `NasEpsMessage::from_bytes_with_direction` | `NasEpsMessage::decode_with_direction(&octets, direction)` |
  | `encode_nas_eps_message(&message)`, `message.to_bytes()` | `message.encode()` |
  | `NasUpdsEnvelope::decode_from_slice`, `encode_to_vec`, and those of `UpdsEventNotificationContainer` and `UpdsMultiplePayloadContainer` | `decode`, `encode` |

- The codec reads slices and writes vectors, and the `bytes` crate is no
  longer a dependency. The traits `Encode` and `Decode` have two methods
  each: `encode_into(&self, &mut Vec<u8>)` appends, and `encode(&self)`
  returns the octets; `decode_from(&mut &[u8])` reads from the front of a
  slice and leaves it at what follows, and `decode(&[u8])` reads a value
  that is all of the octets. An implementation writes `encode_into` and
  `decode_from`. In 0.4.0 `encode` took a `&mut BytesMut` and `decode` a
  `&mut Bytes`: `ie.encode(&mut buffer)` is `ie.encode_into(&mut buffer)`
  and `Ie::decode(&mut buffer)` is `Ie::decode_from(&mut buffer)`. Mind
  that `Ie::decode(&mut buffer)` still compiles for a buffer that is a
  slice: it reads all of it, does not move it, and octets after the value
  are an error. `Nas5gmmMessage`, `Nas5gsmMessage`, `NasEmmMessage` and
  `NasEsmMessage` are `TryFrom<(message type, &mut &[u8])>`. The module
  `helpers` (`be16_to_u16`, `u16_to_be16`, `encode_optional_type`) is
  removed.
- An IE type is the value of its IE. It no longer has a `type_field` and a
  `length`: an IE struct has the one field `value`, and encodes as the IE is
  in a message without its IEI (a length indicator, if its format has one,
  and the value). The IEI is that of the place the IE has in a message,
  which the message writes and reads, so that a type is the same whether
  its field is mandatory or optional.
  - `ie.type_field` is gone: the IEI of an optional IE is in the table of
    its message. `ie.length` is `ie.value.len()`, and a length that differs
    from the value, which `encode` refused, cannot be written any more.
  - An IE alone encodes without an IEI. `NasNssai::new(vec![1, 1]).encode()`
    is `[2, 1, 1]`, where 0.4.0 wrote `[0, 2, 1, 1]`, and `NasNssai::decode`
    reads the same. A type that 0.4.0 defined with an IEI octet, such as
    `NasGprsTimer`, is one octet. A half octet IE such as
    `NasMicoIndication` is an octet with the half octet in bits 4 to 1.
  - `NasFGsmCause::decode_value_only` and
    `NasProseRelayTransactionIdentity::decode_value_only` are removed:
    `decode` reads the octet.
  - The value of a variable IE is an `Octets`, and no longer a `Vec<u8>`.
    It reads as a slice and is written as a vector is (`push`,
    `extend_from_slice`, `resize`, `truncate`, `clear`, indexing), compares
    with slices, arrays and vectors, and is made `from` any of them:
    `ie.value = vec![1, 2].into()`. A value of up to 22 octets is kept in
    the `Octets` itself, without an allocation: an `Octets` is 24 octets on
    every target, the size of a `Vec<u8>` on 64 bits and twice it on 32,
    where the continuous integration runs the tests too
    (`i686-unknown-linux-musl`). `new`, `from_data`,
    `set_data` and `with_data` take anything that is `Into<Octets>`: a
    vector as before, a slice or an array. Where a `Vec<u8>` is needed,
    `ie.value.to_vec()`. `UnknownIe::data` is an `Octets` too.
- PDU SESSION ESTABLISHMENT ACCEPT has its two half octets as two fields,
  as Table 8.3.2.1.1 has two IEs: `selected_pdu_session_type` and
  `selected_ssc_mode`, a `NasSscMode`. 0.4.0 kept the SSC mode in the
  `type_field` of the PDU session type.
  `NasPduSessionEstablishmentAccept::new` takes it second, and a view and a
  tree have the two entries `selected-pdu-session-type` (`"ipv4"`) and
  `selected-ssc-mode` (`"ssc1"`) where they had one entry with the two
  members `pdu-session-type` and `ssc-mode`. The accessors
  `selected_ssc_mode()`, `set_selected_ssc_mode()` and their kin are as
  they were.
- NOTIFICATION keeps the spare half octet beside its access type in bits 8
  to 5 of `access_type.value`, where 0.4.0 had it in `type_field`.
  `NasAccessType::access_type()` reads the half octet of the IE.
- `NasError::InvalidMandatoryIe` says what is wrong with the IE:
  `InvalidMandatoryIe { ie, fault }`, with `fault` an `IeFault` that is
  `Missing`, `Truncated`, `TooShort` or `Syntax`. It was a tuple variant of
  the field name. The receiver answers all four alike, with cause #96.
- `NasError::UnknownProtocolDiscriminator` keeps the first octet of the
  message, for both systems: `nas_eps` gave bits 4 to 1 alone.
- The texts of the errors changed, and a text is no part of the interface:
  match the variant. A message of the other system says which decoder
  reads it (`unknown protocol discriminator: the first octet is 0x7e, the
  extended protocol discriminator of a 5GMM message: decode it with
  `nas_5gs``), a mandatory IE is named as the specification names it and
  with its fault (`mandatory IE `5gs-mobile-identity` is cut short: the
  message ends inside it`), and octets after a value are counted (`cannot
  decode: 1 octet after the end`).
- A constructor or a setter that refuses what it is given says why, and
  all of them in one error type. Every `from_*`, `with_*`, `set_*` and
  `to_bytes` of a typed value that can refuse returns
  `Result<_, ValueError>`: more than 300 functions on some 190 types of
  `common`, `nas_5gs` and `nas_eps`. In 0.4.0 most of them returned an
  `Option`, some a `NasError`, some panicked, and some wrote another value
  than the one they were given. A `ValueError` has the member by the
  name that the specification and a view give it, the entry of the list
  that the member is in, and a `ValueFault`: what it was given and the
  range, the length, the number of entries or the combination that this
  breaks. It is `Copy` and a `core::error::Error`, `common`, `nas_5gs` and
  `nas_eps` export it, and it is the same without `std`. A `NasError` is
  made `From` one, so that `?` also works in a function that builds a
  message and encodes it.

  ```rust
  let error = NasPlmnList::from_plmns(&[plmn; 16]).unwrap_err();
  assert_eq!(error.member, "plmns");
  assert_eq!(error.fault, ValueFault::Count { given: 16, min: 1, max: 15 });
  assert_eq!(error.to_string(), "`plmns` has 16 entries, and must have 1 to 15");
  ```

  | 0.4.0 | Now |
  |---|---|
  | `X::from_y(..).ok_or(MyError::Invalid)?` | `X::from_y(..)?` with `impl From<ValueError> for MyError`, or `.map_err(..)?`: the `ok_or` goes |
  | `X::from_y(..)?` in a function that returns an `Option` | `X::from_y(..).ok()?` |
  | `if let Some(x) = X::from_y(..)`, a `match` on `Some` and `None` | `if let Ok(x)`, `Ok` and `Err(error)` |
  | `.is_some()`, `.is_none()`, `.is_some_and(..)` | `.is_ok()`, `.is_err()`, `.is_ok_and(..)` |
  | `.unwrap()`, `.expect(..)`, `.map(..)`, `.unwrap_or(..)` | the same |
  | `message.set_x(X::from_y(..))` where `set_x` takes an `Option` | `X::from_y(..).ok()` |
  | `ie.set_y(..);` | `ie.set_y(..)?;`: the compiler warns of a refusal that is not looked at |
  | `X::try_from_y(..)?` into a `NasError` | `X::from_y(..)?` into a `ValueError` |

  - No public function panics on its arguments any more. A builder that
    panicked had a checked twin, `try_from_x`: the checked one now has the
    name, `from_x`, and the other is gone. Add `?` or `.unwrap()` where
    `from_x` was called, and drop the `try_` where `try_from_x` was. They
    are `NasFGsMobileIdentity::from_guti`, `from_s_tmsi`, `from_suci`,
    `from_imei` and `from_imeisv`, `nas_eps::NasEpsMobileIdentity::from_imei`,
    `NasNssai::from_snssais`, `NasFGsTrackingAreaIdentity::from_plmn_tac`,
    `NasFGsTrackingAreaIdentityList::from_plmn_tacs`, `from_tai_list`,
    `from_consecutive_tacs` and `from_entries`, `NasSessionAmbr::from_kbps`,
    `QosFlowBitRate::from_kbps`, `NasControlPlaneOnlyIndication::from_cpoi`,
    `NasMaximumNumberOfSupportedPacketFilters::from_max_filters`,
    `NasFGmmCapability::from_octets`, `NasQosRules::from_rules`,
    `NasQosFlowDescriptions::from_descriptions`,
    `NasExtendedRejectedNssai::from_partial_lists`,
    `NasOperatorDefinedAccessCategoryDefinitions::from_definitions`,
    `NasAun3DeviceSecurityKey::from_typed`,
    `NasLpWuspsAssistanceInformation::from_paging_subgroup_id` and
    `from_ue_paging_probability_information`, and `from_entries` of
    `NasOnDemandNssai`, `NasPartialNssai` and `NasAlternativeNssai`.
  - These had no checked twin, and refuse now what they panicked on:
    `NasServiceAreaList::from_entries`, `from_plmn_tacs`,
    `from_consecutive_tacs`, `from_different_plmns` and `from_plmn_only`;
    `NasPeipsAssistanceInformation::from_entries`, `from_entry`,
    `from_paging_subgroup_id` and `from_ue_paging_probability_information`;
    `NasTnanInformation::from_tngf_id`, `from_ssid`, `set_tngf_id`,
    `with_tngf_id`, `set_ssid` and `with_ssid`;
    `NasS1ModeToN1ModeNasTransparentContainer::from_fields`, `set_ncc` and
    `with_ncc`; `NasTruncatedFGSTmsiConfiguration::set_set_id_length`,
    `with_set_id_length`, `set_pointer_length` and `with_pointer_length`. A
    setter that refuses leaves the IE as it was.
  - These returned an `Option` in 0.4.0, and the others like them: the
    `from_seconds` of the timers, `from_quarter_hours` and the time zone
    setters, `NasDnn::from_string` and
    `nas_eps::NasAccessPointName::from_string`, `from_plmns`,
    `from_numbers`, `from_bearers`, `from_pco` and `Pco::to_bytes`,
    `from_res`, `NasSNssai::from_value` and `SNssaiContents::to_snssai`,
    the `from_entries`, `from_contexts`, `from_parsed` and `from_fields` of
    the lists and the containers, the EPS identities `from_imsi`,
    `from_imei` and `from_imeisv`, `from_kbps`, `from_qos`, `from_tft` and
    the `to_bytes` of `nas_eps::EpsQos`, `ApnAmbr`, `Tft`, `TaiList`,
    `TftPacketFilterComponent` and `EpsRemoteUeContext`.
  - These returned a `NasError`: `KeySetIdentifier::as_u8`, and
    `from_key_set_identifier`, `set_key_set_identifier` and
    `with_key_set_identifier` of `NasKeySetIdentifier` and of
    `nas_eps::NasNonCurrentNativeNasKeySetIdentifier`;
    `NasEcnMarkingForL4sIndication::try_from_qri_values`.
  - `NasRelayKeyResponseParameters::from_parsed` returned the IE, and
    returns a `Result` like the others: see under Fixed.
  - The functions that read a code or octets (`from_u8`, `from_u8_strict`,
    `from_bytes`, `from_bytes_strict`) and the getters
    return an `Option` as they did: `None` is a code that is not defined,
    or octets that are no value. The constructors that encode a
    message into a container (`NasMessageContainer::from_plain_message`,
    `NasPayloadContainer::from_n1_sm_message` and the like) return the
    `NasError` of the encoder, and the security contexts theirs.
  - Nothing writes another value than the one it is given. These took a
    number that their field cannot hold and kept its low bits, left out
    the entries of a list that were out of range, or wrote something else,
    and returned nothing: `NasGprsTimer3::from_unit_value(OneHour, 40)` was
    8 hours. They return a `Result` and refuse it, and a setter that
    refuses leaves the IE as it was: add `?` or `.unwrap()`.
    - `from_unit_value` of the GPRS timers (`NasGprsTimer`,
      `NasGprsTimer2`, `NasGprsTimer3` and the EPS timers of these types)
      and of `nas_eps::NasT3412ExtendedValue`: a timer value of 0 to 31. It
      no longer clears the value of a timer whose unit says that it is
      deactivated: the IE is the unit and the value that `timer()` reads,
      and `deactivated()` is the timer with a value of 0.
    - The key set identifiers: `set_ksi` and `with_ksi` of
      `NasKeySetIdentifier` in both systems, `set_ngksi` and `with_ngksi`
      of `NasKeySetIdentifier`, `NasFGsRegistrationType`,
      `NasDeRegistrationType`, `NasControlPlaneServiceType`,
      `NasDeregistrationRequestFromUe` and `NasControlPlaneServiceRequest`:
      0 to 7.
    - `NasFGsNetworkFeatureSupport::set_emc`, `set_emf` and
      `set_restrict_ec`, `NasFGsUpdateType::set_pnb_ciot` and
      `set_eps_pnb_ciot`, each with its `with_` form: 0 to 3.
      `NasFGsNetworkFeatureSupport::from_features` takes an
      `EmergencyServiceSupport` and an `EmergencyFallbackSupport` where it
      took two numbers.
    - `NasExtendedDrxParameters::set_paging_time_window` and
      `set_edrx_value` with their `with_` forms, and
      `NasNid::set_assignment_mode_raw` and `with_assignment_mode_raw`: 0
      to 15. `NasUeRadioCapabilityIdDeletionIndication::from_deletion_request_raw`:
      0 to 7. `set_spare_bits` and `with_spare_bits` of a network name: 0
      to 7, and 0 with UCS2.
    - The lists of PDU sessions: `from_sessions` of `NasPduSessionStatus`,
      `NasAllowedPduSessionStatus` and `NasUplinkDataStatus`,
      `NasPduSessionReactivationResult::from_failed_sessions`, and
      `NasPagingRestriction::from_restriction_type_with_unrestricted_psis`,
      `set_unrestricted_psi_list` and `with_unrestricted_psi_list`: each
      identity is 1 to 15, PSI(0) being spare (TS 24.501 §9.11.3.44), and
      the paging restriction refuses sessions with a type that has no
      bitmap for them, where it left them out.
    - The algorithms of the capabilities: `set_eea` (0 to 7) and `set_eia`
      (0 to 6, bit 1 of the octet being EPS-UPIP) of the UE network
      capability and of the UE security capability in both systems,
      `set_ea` and `set_ia` of `nas_eps::NasUeAdditionalSecurityCapability`
      (0 to 15), which ignored an algorithm above the last; and
      `from_algorithms` of the UE security capabilities, which cleared the
      spare bit 8 of the UIA and GEA octets.
    - `NasFGsIdentityType::from_identity_type`, `set_identity_type` and
      `with_identity_type` wrote "SUCI" for `MobileIdentityType::NoIdentity`,
      which is no identity that is asked for (TS 24.501 Table 9.11.3.3.1).
      `NasFGsMobileIdentity::set_mauri` and `with_mauri` did nothing to an
      identity that is no MAC address.
      `NasProseRelayTransactionIdentity::from_identity` wrote
      `Assigned(0)` and `Assigned(255)`, which read as "unassigned" and
      "reserved". `NasRelayKeyRequestParameters::from_parsed` kept 24 bits
      of a relay service code.
    - Removed, each a second name of a function above or one that kept the
      first octet of several: `NasPagingRestriction::set_restricted_psi_list`,
      `with_restricted_psi_list` and `from_restriction_type_with_psis`
      (the `unrestricted` ones), and
      `NasProseRelayTransactionIdentity::from_data` (`new`).
    - The setters that take a number return `Result<&mut Self, _>`, so that
      they chain with `?`: `drx.set_paging_time_window(3)?.set_edrx_value(5)?`.
  - `NasFGsmCapability::set_atsss_st`, `with_atsss_st`, `set_atsss_ll` and
    `with_atsss_ll`, which took a number and panicked for one that is no
    code, are removed: `set_atsss_st_value`, `with_atsss_st_value`,
    `set_atsss_ll_value` and `with_atsss_ll_value` take the enums.
    `NasFGsmCapability::from_flags` takes an `AtsssSteeringFunctionality`.
- The crate no longer depends on `idna` and `unicode-normalization` unless
  the new `idna` feature asks for them, which is the feature `idna` of
  oxirush-utils: 9 crates are built with the default features where there
  were 36, 24 with `security` where there were 51.
  The realm and the username of the NAI of a SUCI are checked by the
  grammar of RFC 7542 §2.2, and a realm also by the lengths of a domain
  name, 63 octets in a label and 253 in all. With `idna` they are also
  checked as internationalized names, as 0.4.0 did: a text that is not in
  Unicode normalization form C, a label above ASCII that IDNA does not
  allow or writes otherwise (capitals, fullwidth letters, a joiner), a
  label that begins with `xn--` and is not the ASCII form of one, and
  hyphens in the third and fourth places of a label are refused with the
  feature, and taken without it. A program that needs those checks writes
  `features = ["idna"]`.
- The identities are the values of oxirush-utils, which the OxiRush
  crates share: the PLMN, the IMSI, the IMEI and the IMEISV, the GUTI and
  the S-TMSI of each system, the TAI of each system, the types of identity,
  the SUPI type, the protection scheme, the routing indicator and the SUCI
  of an IMSI or of a NAI. Each is checked when it is made, has its parts
  through accessors, and has the text of the service based interfaces as
  `Display` (`5g-guti-20893caff8112345678`); a message prints them as
  before. `nas_5gs` and `nas_eps` name them as their system does:
  `nas_5gs::Guti` is `Guti5g` and `nas_eps::Guti` is `GutiEps`, and so are
  `STmsi`, `Tai` and `MobileIdentityType`.

  | 0.4.0 | 0.5.0 |
  |---|---|
  | `common::PlmnId` | `common::Plmn`, also at `nas_5gs::Plmn` and `nas_eps::Plmn` |
  | `PlmnId { mcc: [2, 0, 8], mnc: [9, 3, 0x0F] }` | `Plmn::new("208", "93")`, `"208-93".parse()` or `Plmn::from_digits([2, 0, 8], &[9, 3])` |
  | `PlmnId::from_tbcd(&octets) -> Option<PlmnId>` | `Plmn::from_nas_octets([u8; 3]) -> Result<Plmn, identity::Error>` |
  | `plmn.to_tbcd()`, `plmn.mcc` and `plmn.mnc` | `plmn.to_nas_octets()`, `plmn.mcc()` and `plmn.mnc()`, which are text |
  | `nas_5gs::Guti { plmn, amf_region_id, amf_set_id, amf_pointer, tmsi }`, `STmsi { .. }` | `Guti::new(plmn, region, set, pointer, tmsi)?`, `STmsi::new(set, pointer, tmsi)?`, with an accessor for each part |
  | `NasFGsMobileIdentity::from_guti(&guti)?`, `from_s_tmsi(&s_tmsi)?` | `from_guti(guti)`, `from_s_tmsi(s_tmsi)`: the value is checked already |
  | `nas_eps::Guti { plmn, mme_group_id, mme_code, m_tmsi }`, `Guti::from_bytes`, `to_bytes` | `Guti::new(plmn, group, code, m_tmsi)`, `Guti::from_nas_octets`, `to_nas_octets` |
  | `nas_5gs::TrackingAreaIdentity { plmn, tac: [u8; 3] }` | `nas_5gs::Tai::new(plmn, tac)?`, `tai.plmn()`, `tai.tac()`, a number of 24 bits |
  | `nas_eps::Tai { plmn, tac }`, `Tai::from_bytes`, `to_bytes` | `Tai::new(plmn, tac)`, `Tai::from_nas_octets([u8; 5])`, `to_nas_octets` |
  | `as_imsi()`, `as_imei()`, `as_imeisv()` returning a `String` | the same returning an `Imsi`, an `Imei`, an `Imeisv`: `as_str()` and `to_string()` give the digits |
  | `MobileIdentityType::from_u8(bits)`, `MacAddr` | `MobileIdentityType::of(first_octet)` and `try_from(bits)`, `MacAddress` |
  | `SupiFormat`, `identity.supi_format()` | `SupiType`, with `nas_format()` and `from_nas_format()`, and `identity.supi_type()` |
  | `ProtectionScheme::{Null, ProfileA, ProfileB, Reserved(n), HplmnDefined(n)}`, `to_u8()` | `ProtectionScheme::NULL`, `PROFILE_A`, `PROFILE_B`, `ProtectionScheme::new(n)?` for one of the operator, `identifier()`: a reserved scheme is none |
  | `ImsiSuci { plmn_id, routing_indicator, protection_scheme, home_nw_public_key_id, scheme_output }` | `ImsiSuci::null(plmn, routing_indicator, msin)?`, `ImsiSuci::concealed(plmn, routing_indicator, scheme, key, output)?`, and `RoutingIndicator::new("678")?` |
  | `Suci::Utf8 { supi_format, nai }`, `suci.nai()`, `suci.to_nai_string()` | `Suci::Nai(NaiSuci)`, `suci.as_nai()`, `suci.to_string()` |
  | `NasFGsMobileIdentity::from_suci_nai(SupiFormat::NetworkSpecific, nai)` | `from_suci_nai(nai)`: the NAI says its type |
  | `nas_eps::IdentityTypeValue`, `NasIdentityType::from_identity_type(kind) -> Self` | `IdentityType`, and `from_identity_type(kind)?`, which refuses no identity and a TMGI |

  A refusal of oxirush-utils converts into a `ValueError` with `?`, with
  the fault of this crate where it has one and `ValueFault::Identity`
  otherwise. The identities have no `Serialize` and `Deserialize` of their
  own: a view and a tree write them as before, and their text is their
  `Display` and `FromStr`.

  Three readings change. A SUCI that a scheme conceals with the key
  identifier 0 is no SUCI, by TS 23.003 §2.2B ("set to the value 0 if and
  only if null protection scheme is used"), as Open5GS (1 to 254) and the
  UDM of free5GC (1 and above) read it; a REGISTRATION REQUEST with one is
  refused for a mandatory IE that is syntactically incorrect, where it was
  read. A sender that writes a SUPI format of 4 to 7 writes no
  well-formed identity: it is still read as that of an IMSI. An IMSI has 6
  to 15 digits, where 2 were read. The text of a SUCI of an IMSI writes its
  scheme as one hexadecimal digit, as `SupiOrSuci` of TS 29.571 has it:
  `suci-0-208-93-0-c-1-ab` for the first scheme of the operator.
- A PLMN identity is displayed `208-93`, as a view and a tree write it, and
  no longer `208/93`: `Display` of `Plmn`, and of the messages that show
  one.
- `Nas5gsMessage`, `Nas5gmmMessage`, `Nas5gsmMessage`, `NasUpdsMessage`,
  `NasEpsMessage`, `NasEmmMessage` and `NasEsmMessage` are
  `#[non_exhaustive]`: they get a variant with each message that a release
  of the specifications adds, and a `match` on one needs a `_` arm. So are
  the enums of the parameters that grow the same way:
  `QosPacketFilterComponent`, `QosFlowParameter`, `ServiceLevelAaParameter`,
  `ServiceLevelAaServerAddress`, `OperatorAccessCategoryCriterion`,
  `PeipsAssistanceInformationEntry`, `UeParametersUpdateDataSet`,
  `UeParametersUpdateTransparentContainerContents`,
  `Non3GppDeviceConnectionInformation`, `RemoteUeIdentifier`,
  `RemoteUeProtocolInformation`, `ProtocolDescriptionEntry`,
  `CiotSmallDataContainerContents`, `Type6IeContainerEntry`, `N3iwfAddress`
  and `VpsUrspNetworkDescriptorEntry`.
- The variants of `Nas5gmmMessage`, `Nas5gsmMessage`, `NasEmmMessage` and
  `NasEsmMessage` hold their message struct in a `Box`:
  `Nas5gmmMessage::RegistrationReject(Box<NasRegistrationReject>)`. A
  `Nas5gsMessage` was as large as its largest message, 1,936 octets, and is
  32 now; a `NasEpsMessage` is 56 where it was 1,080. A pattern that binds
  the struct by reference reads its fields as before. Where a variant is
  built, give the struct to the constructor instead, which takes anything
  that is `Into` the enum: `Nas5gsMessage::new_5gmm(reject)`,
  `new_5gsm(request, psi, pti)`, `NasEpsMessage::new_emm(reject)`,
  `new_esm(request, ebi, pti)`. `Nas5gmmMessage::from(reject)` and
  `Box::new(reject)` are the two other ways.
- `Nas5gsMessage::from_5gmm` and `from_5gsm`, `NasEpsMessage::from_emm` and
  `from_esm`, and `get_message_type` of the four message enums were second
  names of `new_5gmm`, `new_5gsm`, `new_emm`, `new_esm` and `message_type`,
  and are removed.
- The IEs that the table of a message has no place for are an
  `UnknownIes`, where they were a `Vec<UnknownIe>`: the field
  `unknown_ies` of each message struct and what `unknown_ies()` returns.
  It keeps them in one buffer, each after its length, and the order of the
  optional IEs in one or two octets an IE: a message of 68,235 octets made
  of IEs of one octet took 6,292 kB to decode and takes 393 kB, and the
  message of an ordinary decode is the size it was. `iter()` gives each as
  an `UnknownIe { iei, data }` whose `data` is a slice, `get(at)` the one
  at a place, `len()` their number, `push(iei, &data)` adds one, and a
  `Vec<UnknownIe>` is `collect()`ed from it; indexing (`unknown_ies()[1]`)
  is `unknown_ies().get(1)`.
- `validate()` lists the first 32 findings of a kind about such IEs and
  one more that counts the others (`967 more findings of this kind are not
  listed`), where a message of 67,002 octets gave 66,999 findings in
  12 MB.
- In a view and a tree, `unknown-ies` is one text, the octets of each IE
  in hexadecimal with a space between two IEs (`"c0 6a0101"`), where the
  first form of this entry, earlier in this release, was a list of texts:
  a list has a value for each of tens of thousands of IEs.
- The structs and enums of values that a later release of the
  specifications can add a member or a variant to are `#[non_exhaustive]`:
  59 structs, which code outside the crate builds with their `new(..)` in
  the order of their members instead of a struct expression, and the enums
  `TaiListType` and `TaiListEntry`, which a `match` outside the crate gives
  a wildcard arm. The headers, the pairs of an identifier and its
  contents, and the values whose layout their clause closes stay as they
  were. [`RELEASING.md`](RELEASING.md) lists both groups.
- With the `security` feature, the security contexts take and return the
  types of oxirush-security 0.3.0 where an array stood for a key and a
  number for a NAS COUNT or for a NAS connection, and refuse an algorithm
  that is none when a context is made. `nas_5gs` and `nas_eps` export those
  types beside their context, at that one path: `nas_5gs::{KAmf, KNasInt,
  KNasEnc, NasCount, NasConnection, SecurityError}` and `nas_eps::{KAsme,
  KNasInt, KNasEnc, Nh, NasCount, SecurityError}`.

  | 0.4.0 | Now |
  |---|---|
  | `from_fresh_kamf(&[u8; 32], ..)`, `restore_from_kamf(&[u8; 32], ..)`, `reselect_algorithms(&[u8; 32], ..)` | `&KAmf`: `KAmf::new(&octets)`, or `KAmf::from_slice(&octets)?` |
  | `from_fresh_kasme(&[u8; 32], ..)`, `restore_from_kasme`, `reselect_algorithms` of EPS | `&KAsme` |
  | `from_fresh_keys([u8; 16], [u8; 16], ..)` | `from_fresh_keys(&KNasInt, &KNasEnc, ..)`, of `nas_5gs` or of `nas_eps` |
  | `from_mapped_kamf_idle(&[u8; 32], ..)`, `from_mapped_kamf_handover(&[u8; 32], &[u8; 32], ..)` | `(&nas_eps::KAsme, ..)`, `(&nas_eps::KAsme, &nas_eps::Nh, ..)` |
  | `from_mapped_kasme_idle(&[u8; 32], ..)`, `from_mapped_kasme_handover(&[u8; 32], ..)` | `(&nas_5gs::KAmf, ..)` |
  | `let (message, header_type) = context.unprotect(..)?` | `let verified = context.unprotect(..)?`: `verified.message`, `verified.security_header_type`, `verified.count` |
  | `unprotect_raw(..)? -> (Vec<u8>, header type)` | `Verified<Vec<u8>>`, with the same three fields |
  | `unprotect_service_request(..)? -> ()` | `-> NasCount` |
  | `protect_eps_message(..)? -> Vec<u8>`, `unprotect_eps_message(..)? -> Vec<u8>` | `-> (Vec<u8>, NasCount)` |
  | `nas_5gs::security::{NasCountAccessType, ..}` | `nas_5gs::NasConnection` |

  - A key is a type of oxirush-security that is wiped when it is dropped,
    is neither `Copy` nor printed by `Debug`, and is compared in constant
    time. It is made from a reference to its octets, `KAmf::new(&octets)`,
    so that no copy of them is left in the frame of the caller. A context
    has its two NAS keys in one place of the heap from their derivation on,
    so that a context that is moved leaves no copy of them, and clears the
    stack that their derivation used. A context has `Debug`: its algorithms
    and its COUNTs.
  - oxirush-security clears the stack that it used and the vector registers
    after each operation that computes with a key, and `tests/key_wiping.rs`
    finds no key in the memory of a process once its contexts are dropped,
    for both systems, the three algorithms and six sequences of steps, with
    no exception. A message pays for it: one of 64 octets with 128-NIA2 and
    128-NEA2 takes 352 ns to protect and 348 ns to verify and decipher,
    where it took 309 ns and 308 ns without the clearing, about 40 ns a
    message; with SNOW 3G and ZUC it takes 2 to 6 % more, and a message of
    1500 octets 1 to 2 % more. A program that would rather not pay builds
    with `RUSTFLAGS="--cfg oxirush_security_unwiped"`, which is a setting of
    oxirush-security.
  - `unprotect` and its kin return a `Verified`: the message, its security
    header type, and the NAS COUNT that it was verified with, which K_gNB
    and K_eNB are derived with for a message that starts the access
    stratum security (TS 33.501 Annex A.9, TS 33.401 Annex A.3).
  - The 5GS context reads the initial NAS message of a UE that has a
    security context (TS 24.501 §4.4.6). Such a REGISTRATION REQUEST,
    DEREGISTRATION REQUEST, SERVICE REQUEST or CONTROL PLANE SERVICE
    REQUEST comes integrity protected with its cleartext IEs alone, and the
    complete message ciphered in its NAS message container. `unprotect`
    deciphers the container with the NAS COUNT of the message and gives
    the complete message as `verified.message`, which is the one to act on,
    with the message as it came in `verified.sent`; the CIoT small data
    container of a CONTROL PLANE SERVICE REQUEST is deciphered likewise.
    0.4.0 gave the message with the cleartext IEs, and the container could
    not be read without a second copy of the key. A container that was
    sent in clear under a context that ciphers no longer reads as its
    message: it is refused, as one that does not decipher is, and the AMF
    asks for the message again in the SECURITY MODE COMMAND.
  - `NasSecurityContext::from_fresh_keys`, `from_fresh_kamf` and
    `from_mapped_kamf_handover` of 5GS, and `from_fresh_keys` and
    `from_fresh_kasme` of EPS, return `Result<Self, NasError>`. A reserved
    algorithm (the codes 4 to 7) and NIA0 or EIA0 with another cipher than
    NEA0 or EEA0 are errors there; 0.4.0 made the context and failed at the
    first message. `reselect_algorithms` leaves the context as it was when
    it refuses the new ones.
  - A NAS COUNT is a `NasCount`: 24 bits, checked when it is made
    (`NasCount::new(5)?`, `count.get()`). The next COUNT of a context is an
    `Option<NasCount>`, `None` once every COUNT of the direction was used,
    where 0.4.0 had `0x0100_0000`. 5GS: `nas_count()` returns
    `Option<NasCount>`, `restore_from_kamf` takes two
    `(Option<NasCount>, Option<NasCount>)`, and `from_mapped_kamf_idle` a
    `NasCount`. EPS: `nas_count(direction)` returns `Option<NasCount>`,
    as that of 5GS without the access, where `uplink_count()` and
    `downlink_count()` were; `restore_from_kasme` takes one
    `(Option<NasCount>, Option<NasCount>)`, the uplink then the downlink
    COUNT, as `restore_from_kamf` takes one for each access; and
    `from_mapped_kasme_idle` and `from_mapped_kasme_handover` two
    `NasCount` each. A COUNT is estimated from the bits that a message
    carries by `NasCount::estimate`, `estimate_from_low_bits` and their
    `wrapping_` forms, and counted on by `next` and `wrapping_next`: the
    contexts use them, and this crate has no function of its own for it.
  - The contexts of the two systems are one core with two instances: the
    keys in one place of the heap, the two algorithms, the next COUNTs of
    each NAS connection (two in 5GS, one in EPS), and what TS 24.501 and
    TS 24.301 §4.4.3 do alike with them: the estimate of the COUNT of a
    received message, the code of the sequence number and of what follows
    it, its check in a constant time, the COUNT that advances once a
    message is made or its code verified, the null integrity algorithm
    whose COUNTs wrap around. Each system has its headers, its messages
    and its mapped contexts around it; a context is the size it was, 32
    octets in 5GS and 24 in EPS.
  - A context keeps its keys with the `IntegrityContext` and the
    `CipheringContext` of oxirush-security, which hold what 128-NIA2 and
    128-NEA2 compute from a key alone: a message does not expand the AES
    key and the subkeys of CMAC again. `protect` of a typed message checks
    it and does not decode again what it encoded. protect takes 58% less
    time and unprotect 19% less over the fixtures of both systems, and a
    new context 43% more (both revisions in one program, one core, load
    10.6); the place of the heap of a context is about 480 octets, where it
    was 32.
  - A context that has used every COUNT of a direction returns
    `NasError::NasCountExhausted`, where a text said so. A message whose
    code is right and that is then refused, because it does not decode or
    is not one that its header type or its direction protects, returns
    `NasError::AuthenticMessageRefused { error, plain }`, with that reason
    and the plain octets of the message, deciphered, which a receiver logs
    and `answer_to_refused` answers whether the message came ciphered or
    not: its COUNT is used, and no caller compares a text to know it.
  - `nas_5gs::security::NasCountAccessType` is replaced by
    `NasConnection` of oxirush-security, re-exported there, with the same
    two variants: `protect_for_access`, `unprotect_for_access` and their
    kin take it. `NasConnection::from(AccessTypeValue)` replaces the
    `TryFrom` that could not fail.
  - `Direction::as_u8` is removed. `oxirush_security::Direction` and
    `Direction` convert into each other with `From`.
  - The algorithm enums of `nas_5gs` and of `nas_eps` convert with
    `TryFrom` into `oxirush_security::IntegrityAlgorithm` and
    `CipheringAlgorithm`; a reserved code is an error.
- `Result` is no longer among what `oxirush_nas::*`, `nas_5gs::*` and
  `nas_eps::*` export: a glob import of any of them replaced the `Result` of
  the standard library with an alias that takes one type, so that
  `fn main() -> Result<(), Box<dyn Error>>` under the first line of the README
  did not compile. The alias is `oxirush_nas::common::Result`.
- `Nas5gmmHeader` and `Nas5gsSecurityHeader` have a `spare_half_octet`
  field: bits 5 to 8 of the octet of the security header type (TS 24.501
  §9.5, Figures 9.1.1.1 and 9.1.1.2). Decoding keeps the value received and
  encoding writes it, so `7ef043` is encoded as `7ef043`; 0.4.0 dropped these
  bits and encoded `7e0043`. A struct literal of either header names the new
  field; `Nas5gmmHeader::new` and `Nas5gsMessage::protect` set it to zero,
  and a value above 15 does not encode.
- `AtsssSteeringFunctionality` variants have the ATSSS-ST codes of TS
  24.501 Table 9.11.4.1.1 (1, 2 and 3 instead of 3, 12 and 15).
- `NasPayloadContainer::decode_as_ciot_user_data_container` returns the
  user data as `&[u8]`, and `from_ciot_user_data_container` takes it,
  instead of a `NasCiotSmallDataContainer`.
- `Non3GppDeviceConnectionInformation::Ethernet::vlan_tag_id` is the 12-bit
  VLAN identifier in the high bits of its two octets, as in TS 24.501
  V20.1.0 §9.11.4.41: a value above 4095 is refused, and 100 goes out as
  0x0640. 0.4.0 wrote the 16-bit field of V19.8.0. This follows Release 20
  on purpose: V19.8.0, the newest Release 19 version, still has the 16-bit
  VLAN tag ID, and a peer that follows it reads and writes the two octets
  differently.

### Added

- `NasPdnAddress::from_ipv4`, `from_ipv6_iid` and `from_ipv4v6` build an
  EPS PDN address as the constructors of one name build a 5GS PDU
  address, beside `from_pdn_address(PdnAddress)`.
- The replayed UE security capabilities of a SECURITY MODE COMMAND are
  made from what the UE sent, in both systems:
  `NasUeSecurityCapability::from_ue_network_capability(&capability)` in
  EPS and `NasS1UeSecurityCapability::from_ue_network_capability` in 5GS
  take its EPS and UMTS algorithms (TS 24.301 §5.4.3.2, TS 24.501
  §5.4.2.2), and the EPS `with_gea_of(&ms_network_capability)` its GPRS
  ones; `matches_ue_network_capability` checks the other way.
- `Nas5gsMessage::decode_lenient`, `NasEpsMessage::decode_lenient` and
  `decode_lenient_with_direction` read a message that `decode` refuses for
  a mandatory IE: one that has its octets and is shorter than its message
  allows, or is not an IE of its type. They return the message, with that
  IE as it came, and the list of the refusals, each the
  `NasError::InvalidMandatoryIe` that `decode` returns; a message that
  `decode` reads has an empty list. A receiver that rejects such a message
  (TS 24.501 and TS 24.301 §7.5.1) reads in it the type of the message,
  the IEs that are sound and the octets of the one that is not: a
  REGISTRATION REQUEST whose SUCI is refused still has its registration
  type and the octets of its identity. A mandatory IE that is missing or
  cut short leaves no message, and is the error of `decode`. `Decode` has
  the method `decode_lenient_from` for it, which a type without mandatory
  IEs does not implement. `decode` does the same work as before.
- `Nas5gsMessage::answer_to_refused(octets, &error, direction)` and
  `NasEpsMessage::answer_to_refused` give the message that clause 7 of
  TS 24.501 and of TS 24.301 has a receiver answer with, to octets that
  `decode` refused: 5GMM, 5GSM, EMM or ESM STATUS with cause #97 for a
  message type that does not exist, cause #96 for a mandatory IE that is
  missing or wrong, in the reject or the accept that §7.5.3 names for a
  session management request and in a status message otherwise, and the
  reject with cause #43 for a PDU session identity that is reserved; none
  where the clause has the message ignored. The mapping was prose on the
  front page. An authentic message that a security context refused is
  answered from the plain octets that its refusal has: a ciphered one was
  answered with nothing.
- A finding of `validate()` on an IE says the sender rule that it breaks,
  where every one said `IE has invalid value or structure`: `IE breaks a
  sender rule: two octets: a split PG cycle code of at most 98, and an S1
  mode DRX value of 0 or 6 to 9 (TS 24.008 §10.5.5.6)`, `IE breaks a
  sender rule: a value of 2 to 13 octets` for a length, `IE breaks a
  sender rule: a value that a sender sets: 0 | 1` for a code. Each IE
  type has its rule beside its `is_well_formed()`. The 5GS additional
  request result is checked as the EPS one is, and the EPS control plane
  only indication by its `is_well_formed()`, as in 5GS.
- `DecodeOptions`, and `Nas5gsMessage::decode_with(octets, options)` and
  `NasEpsMessage::decode_with(octets, direction, options)`: what a receiver
  takes beyond the rules of the specifications, from a peer that does not
  follow them. `DecodeOptions::STRICT.with_out_of_sequence()` takes a known
  optional IE that comes out of the order of its table, which §7.6.2 has a
  receiver ignore and Open5GS, free5GC and pycrate take; `validate()`
  reports it as out of the order of the table, and the message is encoded
  in the order it came.
- `Nas5gsMessage::answer_to(octets, &received, direction)` and
  `NasEpsMessage::answer_to` answer a received message whatever was wrong
  with it, from what `decode` or a security context returned: an error has
  the answer of `answer_to_refused`, and a message that decoded with an
  unknown IE encoded as "comprehension required" (§7.6.1) the answer of
  cause #96, which the caller built from `unknown_ies()`.
- `NasFGsRegistrationResult::from_result(RegistrationResult)` builds the
  IE that `new(vec![1])` built. An IE type whose value is one or two
  octets, and the TAIs, are `Copy`.
- `tests/fixtures/captured.tsv` has 170 messages that other
  implementations sent in a lab run, each with its source: Open5GS v2.8.0
  as AMF and as MME, free5GC v4.2.3, and PacketRusher as UE. The crate
  decodes each to the message that the dissector of the capture names and
  encodes it back to its octets, and with the `security` feature its
  contexts verify and decipher the 114 protected ones as they were on the
  wire, with the keys and the NAS COUNT that an independent program
  derived. The head of the file says how they were captured and what they
  are not: no commercial UE, RAN or core, 128-NIA2 and 128-NEA2 only.
- With the `security` feature, `NasSecurityContext::protect_initial` and
  `protect_initial_for_access` of 5GS send an initial NAS message as
  TS 24.501 §4.4.6 has a UE with a security context send it: given the
  complete REGISTRATION REQUEST, DEREGISTRATION REQUEST, SERVICE REQUEST or
  CONTROL PLANE SERVICE REQUEST, they keep its cleartext IEs, put the
  complete message in the NAS message container, cipher the value of the
  container with the uplink NAS COUNT of the message and integrity protect
  the whole. The container of a CONTROL PLANE SERVICE REQUEST has its
  non-cleartext IEs and not the complete message (§4.4.6 b) 2) ii),
  §9.11.3.33), and `unprotect` reads that container and one that has the
  complete message, as §5.4.2.3 has it in a SECURITY MODE COMPLETE: a
  container of IEs was refused. A message of cleartext IEs alone goes out
  without a container, and a CONTROL PLANE SERVICE REQUEST whose only
  other IE is the CIoT small data container has the value of that IE
  ciphered. `unprotect` is the other end. The vectors of `tests/fixtures/initial-nas.tsv` are
  computed without this crate and without oxirush-security, by the program
  beside them, for 128-NIA2 with 128-NEA2 and with 5G-EA0. In EPS the
  CONTROL PLANE SERVICE REQUEST was already ciphered and read by `protect`
  and `unprotect` under "integrity protected and partially ciphered".
- With the `serde` feature, `means_the_same` on `Nas5gsMessage` and
  `NasEpsMessage`: whether two messages have the same IEs with the same
  meaning, where they may differ in the order of their optional IEs and in
  the octets that a value does not decide (the unit of a timer of one
  octet, octets of zeros after the flags of a capability). The message
  that the tree of a message writes means the same as that message: the
  tests hold it for each fixture and the fuzz targets `view_5gs` and
  `view_eps` for any octets, also after the message is encoded and decoded
  again.
- A view and a tree have the entry `unknown-ies` for the IEs that the
  table of a message has no place for, each by its octets with its IEI
  first, in the order they came in: an IEI that the table does not have,
  and what a receiver ignores of one that it has. A message that is
  written from a tree or a view has them after its other IEs, so that a
  tree gives back a message with all its octets; 0.4.0 had no tree, and
  the view of this release left them out until now.
- The UE network capability and the UE security capability of TS 24.301,
  in both systems, have the setters `set_uea` and `set_uia`, and the UE
  security capability `set_gea`, beside `supports_uea`, `supports_uia` and
  `supports_gea`. Their values in a view and a tree have the members
  `uea`, `uia` and `gea`, the lists of the algorithms as `eea` and `eia`
  are.
- The crate builds without the standard library. A `std` feature is on by
  default; with `default-features = false` the crate is `no_std` and needs
  an allocator, and the codec, `validate()`, the builders and `Display` are
  the same. The `security` and `serde` features are `no_std` too: the JSON
  forms of a message (its tree, its view, the `view` module and the serde
  form) keep the names that they printed for the whole program behind the
  locks of `spin`, a dependency of `serde`. Without `std`, oxirush-security runs SNOW 3G and ZUC on the
  vector instructions that the build enables for the target, and on its
  scalar code otherwise; with `std` it asks the processor. The continuous
  integration builds for `thumbv7em-none-eabihf` and `aarch64-unknown-none`.
  The lowest versions that the manifest allows are those that build this
  way, `hex` 0.4.3 and `unicode-normalization` 0.1.13 where it said 0.4 and
  0.1, and the continuous integration tests and builds with them.
  No signature changes: an IP address of a value is the `core::net` type
  that `std::net` names, and the errors implement `core::error::Error`.
- With the `serde` feature, the protocol configuration options and the
  extended protocol configuration options have a value in a view and a
  tree, in each 5GSM and ESM message that carries them: the list of their
  units. A unit is read by the direction of its message, which its type
  says: in a PDN CONNECTIVITY REQUEST
  `["ip-address-allocation-via-nas-signalling", "dns-server-ipv4-address-request", "ipv4-link-mtu-request"]`,
  and in the request of the network that answers it
  `{"dns-server-ipv4-address": "8.8.8.8"}`, `{"ipv4-link-mtu": 1400}`,
  `{"p-cscf-ipv4-address": "10.0.0.2"}` or
  `{"selected-bearer-control-mode": "ms-only"}`. A container that has no
  name here is `{"container": {"identifier": 65280, "contents": "01"}}`.
  A unit of a configuration protocol is its packet by the names of its
  protocol, the code, the identifier and the options or the fields:
  `{"pap": {"code": "authenticate-request", "identifier": 1, "peer-id": "user", "password": "secret"}}`,
  `{"ipcp": {"code": "configure-nak", "identifier": 0, "options": [{"primary-dns-server-address": "8.8.8.8"}]}}`,
  and so for CHAP (`challenge`, `response`, `success`, `failure`) and for
  LCP. An option that has no name is its type and its data, and a packet
  that the names would not write back to the same octets is those octets
  in hexadecimal. The units that are written give the octets. A unit of
  the other direction is refused with the unit that this direction has for
  the same identifier, and a packet with a member that its code does not
  have is refused with the members that it has. Options that their units
  do not give back to the same octets have their octets alone. The rustdoc
  of the `view` module lists the units and the names of the packets.
- `from_tree()` writes the message of a tree that has a `security-header`:
  the plain message under that header, with the code that the tree has, or
  the octets of its `ciphered-message`. Every tree that `to_tree()` shows
  is now one that `from_tree()` reads.
- An EPS EMM TRANSPORT has a view and a tree: its `security-header`, and the
  `octets` of its `ciphered-message` or, once it is deciphered, of its
  `data-container`. `with_view()`, `from_view()` and `from_tree()` write
  it. It had the empty view `{}`.
- With the `serde` feature, the lists and containers that a constructor of
  the crate builds are read and written by their value, and no value is
  read only. In 5GS: NSAG, NSSRG, LADN, CAG and
  extended CAG information, the service area list, the extended rejected
  NSSAI, the operator-defined access category definitions, the mapped EPS
  bearer contexts, the received and requested MBS containers, the UE
  parameters update transparent container, the CIoT small data container,
  N3QAI, the protocol description, the type 6 IE container, the S-NSSAI
  location and time validity information, the relay key request and
  response parameters, the service-level-AA container, the N3IWF
  identifier, the alternative, on-demand and partial NSSAI, the extended
  LADN information, the non-3GPP delay budget, the remote UE context list,
  the URSP rule enforcement reports, the ciphering key data, the PEIPS
  assistance information, the SNPN list, the PDU session reactivation
  result error cause (`[[5, "congestion"]]`, a PDU session identity and its
  cause) and the SOR transparent container (its `acknowledgement` or its
  `information`). In EPS: the NBIFOM container, the ciphering key data, the
  two remote UE context lists and the calling party number of a CLI, with
  the names of its codes
  (`{"type-of-number": "international", "numbering-plan": "isdn", "presentation": "allowed", "screening": "network-provided", "digits": "33123456789"}`).
  In both: the extended emergency number list, with where it is valid
  (`{"valid-only-in-plmn": false, "numbers": [{"digits": "112", "sub-services": ""}]}`).
  A value that is written is built and read back, and one that the IE does
  not then have is refused: with the member and the limit that it breaks,
  as the constructor of the IE says them, after the name of the IE
  (``pdu-session-status: entry 1: `pdu-session-identity` is 16, and must be 1 to
  15``), or with what the IE would be. Octets that the crate reads and
  would not write back to the same value are shown by their `octets`.
- `nas_5gs` and `nas_eps` export `Severity` and `ValidationError`, the
  types of what `validate()` returns, beside `Validate`.
- Four fuzz targets in `fuzz/`, which the continuous integration runs for a
  minute each from the fixtures and from a few messages with protocol
  configuration options: `decode_5gs`, `decode_eps`, `view_5gs` and
  `view_eps`. They replace six targets that no workflow ran.
- With the `serde` feature, `to_view()` and `with_view()` on
  `Nas5gsMessage` and `NasEpsMessage`. A view is a `tree::Value` with
  each IE of the message by the name the specification gives it, in lower
  case with hyphens (`5gs-registration-type`, `tai-list`), its `value` as
  the typed accessors decode it and its `octets` in hexadecimal; a field of
  the header has a `value` alone. The entries are in the order of the
  message: the fields of the header first, then the IEs in the order of the
  message table. A value is in the notation a reader expects: a
  coded value is its name (`"congestion"`, `"initial-registration"`) or,
  where the specification names none, its number; a PLMN identity is
  `"208-93"`; an IMSI, an IMEI or an MSIN is its digits; a TMSI, a TAC or
  an SST is a number; a timer is its seconds; a DNN, an APN and an IP
  address are text; a capability is its flags by name; a container of a NAS
  message is the view of that message. `with_view` returns the message of
  an edited view: an IE is encoded from a `value` that was changed, takes
  the `octets` that were changed, and is taken out when the view leaves it
  out. An optional IE that the message does not have is `null` in the view,
  and is added from the `value` or the `octets` that an edited view gives
  it; `view_names()` of a message type gives the names that the view of such
  a message has, and `blank_view()` the view with nothing written yet, which
  says which entries are mandatory. Names are read in any case, with hyphens, underscores or
  spaces, and numbers also as `"0x…"` strings, except in the `message-type`
  and the `security-header-type` of a header, where a string is a name. A
  name that does not exist,
  a member that is not there, a value that an IE cannot carry, and octets
  and a value that disagree are errors. What a view shows, it takes: a code
  has the name that writes it and otherwise its number, which is written as
  a number, and a value that the crate cannot write back is not shown. A
  message under a security header has that header as `security-header`
  beside the entries of the plain message, and `with_view` refuses an edit
  that keeps the message authentication code of the message as it was; a
  ciphered one has its octets as `ciphered-message`. 156 of the 169 5GS IE types and 134
  of the 153 EPS types have a value, which is read and written. The
  feature takes the trees of oxirush-utils. Examples: `view_message_nas_5gs` and `view_message_nas_eps`.
- With the `serde` feature, a message as a tree, which is a view written
  shortly: `Nas5gsMessage::from_tree()` and `NasEpsMessage::from_tree()` make
  the message of `{"message-type": NAME, IE: VALUE, …}`, with what the type
  of the message decides of its header, and `to_tree()` shows a message in
  that form. An IE is its value, or `{"octets": "…"}`, and a value has the
  members that it has; the message in a container is its own tree. The
  type is written by its name or by its number, in a tree as in a view.
- A view and a tree read the messages of containers eight deep, and show a
  container further in by its octets: octets of a peer may nest one NAS
  message container in another as deep as a message is long.
- With the `serde` feature, `from_view()` on `Nas5gmmMessageType`,
  `Nas5gsmMessageType`, `NasEmmMessageType` and `NasEsmMessageType`: the
  message that a view describes alone. The view has every field of the
  header, every mandatory IE and the optional IEs that the message has; the
  message in a container is the view that is the `value` of the container,
  named by its `message-type`, which is the type of the message. An IE
  that a view builds has the octets of every member written, a zero or a
  flag that is not set too.
- With the `serde` feature, the `view` module: the values of a view by their
  paths. `view::paths` gives each value with the path that selects it,
  `view::select` the values at a path, and `view::set`, `remove` and `insert`
  edit a view at a path. `/nas` stands for the view and an IE goes by its
  name, as in `/nas/5g-guti/value/guti/plmn`. An IE or a member that is not
  there selects nothing, a name that cannot be there is an error, and
  `view::set` refuses the name of an IE that the message cannot have. The
  message in a container has the paths of a view: `view::set` adds an
  optional IE that it has not, as in
  `/nas/payload-container/value/pdu-session-type/value`. The
  paths are those of the feature `tree` of oxirush-utils, which the other
  OxiRush crates walk too, and their errors are its `view::Error`, with a
  kind (`view::ErrorKind`) to match and a reason that says where:
  `"no-such-ie" is no IE of a message `registration-request``,
  `"first" is no position in a list: …`, `the path selects nothing`, each
  with `, at <path>`. After `*`, a name that one place does not have is an
  error only when no place has it; `set` of `null` takes an entry of a list
  out, as `remove` does; `paths()` goes 64 levels deep, the most that a
  path has.
- With the `serde` feature, `Nas5gsMessage::from_view()` and
  `NasEpsMessage::from_view()`: the message that a view describes alone, of
  the type that its `message-type` names, so that the type is written once.
- `with_view()` returns a message that `encode()` encodes, as the one that
  was edited is: an edit that makes a message without octets, such as a type
  that the IEs are not those of or octets of a length that the message does
  not give the IE, was taken and is an error. `from_view()` gives what the
  view writes, and `encode()` says whether it has octets.
- In a view, a coded value is written by its name or by its number, which
  are two ways to write one code: `"congestion"` and `22` are one cause, in
  an IE that is one code, in the fields of an octet and in the
  `message-type` of the header. A number was refused for a code that has a
  name. A number that its field cannot hold is an error.
- A name of a view or of a path is its letters and its digits, whatever
  their case and whatever is between them, and so is the root of a path. A
  position of a path is a number as decimal writes it: `+1` and `01` are
  not.
- A time zone and time whose digits are no decimal digits has its `octets`
  alone in a view: it showed a year that no view could write.
- An EPS SERVICE REQUEST has a view: the fields of its short header, with
  the `ksi` and the `sequence-number` of its second octet and the octets of
  its short message authentication code. `with_view()` edits it, and
  `nas_eps::NasServiceRequest::from_view()` returns the one that a view
  describes alone. Its view was empty.
- The `selected-pdu-session-type` of a PDU SESSION ESTABLISHMENT ACCEPT has
  the two values of its octet in a view, `pdu-session-type` and `ssc-mode`.
- `NasNssai::parse_allowed`: the first 8 entries of an allowed NSSAI (TS
  24.501 §9.11.3.37).
- `unknown_ies()` on `Nas5gsMessage`, `Nas5gmmMessage`, `Nas5gsmMessage`,
  `NasEpsMessage`, `NasEmmMessage` and `NasEsmMessage`: the unknown and
  ignored IEs of a decoded message of any type, read through a security
  header. As in 0.4.0, decoding keeps a well-framed unknown IE encoded as
  "comprehension required", flagged by
  `UnknownIe::is_comprehension_required()` and reported by `validate()`; a
  receiver uses the accessor to answer it as TS 24.501 and TS 24.301 §7.5.1
  require.
- 5GMM capability octet 13 (TS 24.501 §9.11.3.1): `non_sat_lsp` (bit 1) and
  `lcscdl` (bit 4), which V19.8.0 defines, and `nssaa_epc` (bit 2) and
  `aiot_ue_reader` (bit 3), which only Release 20 defines (V20.1.0).
  V19.8.0 has bits 2 and 3 spare; `validate()` accepts them.
- `NasFGmmCapability::with_*` builders for every capability flag, beside
  the getters and setters, as the EPS UE network capability has them.
- With the `security` feature, `protect_opaque_payload`, and
  `protect_opaque_payload_for_access` in 5GS, cipher and integrity-protect
  inner octets as given under security header types 1 to 4, without
  decoding them, for negative tests. They keep the algorithm, bearer and
  COUNT checks and advance the COUNT once; `protect` and `protect_bytes`
  are unchanged and still validate the inner message.

### Changed

- Each Rust block of the README, and the sample of the front page, is a
  whole program, whose `main` returns a `Result` and takes `?`. The output
  of a block is one `text` block. docs.rs shows the feature that an item
  needs (`doc_cfg`). `key_wiping`, which holds in an optimized build alone,
  is no part of `cargo test`: `cargo test --release --features security
  --test key_wiping` runs it, as CI does. The comparison with the other
  implementations gives each time as `other / this crate`, and "about the
  same" within 10 %.

- The README starts with a sample and has an example of each task, each
  with the output that it prints. Its reference tables are in the
  documentation, which docs.rs shows: the paths, the rules, the notation
  of the values and the IE types that have a value in the `view` module;
  what the crate covers and does not, the versions of the specifications,
  the tests and the examples on the front page; the security contexts in
  `nas_5gs::security` and `nas_eps::security`; the commands of the
  benchmarks in `benches/src/lib.rs`. `tests/readme.rs` compares what each
  Rust block of the README and of those pages prints with the output under
  it. Its sections are those of the other OxiRush crates, and its
  performance has a comparison with free5GC's nas, Open5GS,
  packet-dissector and pycrate, which `benches/compare/compare.sh`
  measures, fetching each at a pinned version.
- The codec and the JSON forms are faster and allocate less. Measured with
  `benches/` on one core, a message of the 5GS fixtures, 0.5.0 before this
  work and now:

  | Operation | Before | Now | Allocations before | Now |
  |---|---|---|---|---|
  | `decode` | 269 ns | 115 ns | 4.7 | 1.2 |
  | `encode` | 134 ns | 49 ns | 3.4 | 1.0 |
  | `validate` | 412 ns | 234 ns | 8.3 | 3.3 |
  | `to_view` | 14.6 µs | 4.8 µs | 259 | 73 |
  | `with_view` | 78 µs | 18 µs | 1,251 | 146 |
  | `to_tree` | 689 µs | 18 µs | 18,606 | 299 |
  | `from_tree` | 581 µs | 38 µs | 11,805 | 380 |
  | `unprotect` (128-NIA2, 128-NEA2) | 913 ns | 609 ns | 12.1 | 2.4 |

  A message of 68,235 octets that is 68,227 unknown IEs of one octet is
  edited through its view with 3.3 MB allocated, where it took 128 MB: a
  view no longer has the message in its serde form, and `with_view` edits
  the form without the unknown IEs and gives them back to the message.
  `benches/src/lib.rs` says how to run the benchmarks and the profiler.

  The allocations of this table are those of the first call for a message
  type, which also fills the names that the JSON forms keep. The benchmark
  now counts a later call, as the times are those of later calls, and the
  README has those counts: 255 for `to_tree` and 407 for `from_tree`. Since
  this table was measured, `to_tree` also reads back what it writes, to
  show by its octets an IE whose value would not write it again, and takes
  21 µs.
- `decode` of a 5GS message was 10% slower than in the revision before the
  identities moved to oxirush-utils, and `validate` of an EPS message 3%:
  each IE that the reader took made the error it would return, and dropped
  it once the octets were there, through a drop of the error that its
  refused-message variant keeps from being inlined; the sender check of a
  tracking area identity list read the list, wrote it again and compared.
  The reader makes an error when it returns one, the list is checked in
  one pass over its octets (a test compares the two checks on 100,000
  lists of each system), and the findings on IEs out of order place each
  IE by the index of the table. Per message of the fixtures, in
  instructions, against that revision: 5GS `decode` 1,046 to 1,054 (it
  had become 1,151), EPS `decode` 922 to 847, EPS `validate` 1,449 to
  1,450 (1,494); `validate` of a message of 1,000 unknown IEs takes 4%
  less time where it took 30% more.
- A tree shows by its octets each IE whose value a message is not written
  from, also in a message under a security header; such a message kept the
  value, which `from_tree` then refused.
- The macros of the crate are written with `pastey`, the maintained
  successor of `paste` (RUSTSEC-2024-0436).
- `Plmn` implements `FromStr`, for `"208-93"`, and has `new`,
  `from_digits`, `mcc` and `mnc`.
- The `security` feature requires oxirush-security 0.3.0 without its
  default features, which are SUCI concealment and its NAI form, and no
  longer `zeroize` by itself: the feature adds 16 crates to the build where
  it added 34. That version wipes
  the hash state of the key derivations and the 128-EEA2 keystream blocks
  and reads the SNOW 3G and ZUC tables without secret-dependent indices.
- A security context compares a message authentication code in constant
  time, with `oxirush_security::constant_time_eq`.
- `validate()` of an EPS message takes the length of each field from its
  message table and the value rules of each IE type from one list of types,
  as 5GS does; each message had its own list of checks. The same messages
  get findings on the same fields with the same severity. The texts are
  those of 5GS: `message-table length is outside 7..=97` for a length
  outside the table or a declared length that differs from the value, and
  for a value rule the rule that the IE breaks, as below. The number of
  findings on one field and the order of the findings can differ. One
  finding is new: an additional update type above 15 in ATTACH REQUEST or
  TRACKING AREA UPDATE REQUEST, a half octet that cannot be encoded and
  that decoding does not produce, is reported on its field and not only
  as the failed encoding of the message.
- The names that an error gives for a misspelt name of an IE, a message or
  a value are those of oxirush-utils, `tree::nearest`, in its words: every
  name of up to 12, or the nearest of more ("the nearest of its 16 is
  t3346-value"), with those that start as the name is written, or else the
  first eight and how many more.
- An error says what to write instead. An unknown IE that is encoded as
  "comprehension required" and is cut short is
  `NasError::UnknownIeCutShort`, with its IEI and the octets from it to the
  end of the message, and is answered with cause #96 as before; it was
  `InvalidMandatoryIe` with the field `unknown_ies`. A tree with an IE that
  its message has not lists the IEs of the message, or the nearest of them;
  the name of a message of the other system names the module that reads
  it, and a misspelt one the nearest; a code written as a number in a text
  (`"#22"`) is to be written as the number. The texts of `EncodingError`
  and `DecodingError` start in lower case, after "cannot encode:".
- `unprotect` says what a context does with NIA0 and EIA0, which check no
  MAC and refuse no replay (TS 24.501 and TS 24.301 §4.4.3.2): a message
  received again is taken with a higher COUNT. It says which context
  verifies a SECURITY MODE COMMAND, whose header is "new security context"
  whatever context it takes into use: the one in use, one restored with
  new algorithms, or a fresh one after an authentication. Tests pin both.

### Fixed

- `from_tree` reads back the tree of an IE whose value is built from its
  members, such as the S&F satellite operation parameters of EPS without
  their wait time: a member that the tree leaves out, since the value has
  none, is absent, where it was refused as not written. The fuzz target
  `view_eps` found it in CI.
- A 5GS T3512 value may count in units of 320 hours, as TS 24.008 Table
  10.5.163a NOTE 1 says of it alone among the 5GS timers: `validate()`
  refused such a REGISTRATION ACCEPT, and its value read as `None`. The
  T3512 value and the requested T3512 value are `NasT3512Value`, a GPRS
  timer 3 of its own, as the EPS T3412 extended value is:
  `value_for_ue(integrity_protected)` reads the unit as the UE does, with
  the zero of §5.3.7, `value_for_network()` as the network does in N1
  mode, `value()` as in an integrity protected REGISTRATION ACCEPT, and
  `from_seconds` uses the unit of 320 hours where the others do not reach.
  `NasGprsTimer3::t3512_value_for_ue` is `NasT3512Value::value_for_ue`.
- `validate()` of a 5GS REGISTRATION REQUEST reports a non-current
  native ngKSI that is no native one of 0 to 6 (§8.2.6.2), as that of an
  EPS TRACKING AREA UPDATE REQUEST does (TS 24.301 §8.2.29.2).
- An IMEISV is read whatever the half octet after its 16 digits holds.
  TS 24.501 §9.11.3.4 and TS 24.008 §10.5.1.4 have a sender fill it with
  1111, and the SECURITY MODE COMPLETE of PacketRusher has 0000 there: the
  IE was ignored as malformed, and an IDENTITY RESPONSE with such an
  IMEISV was refused. An IMEISV has no other number of digits, so the
  half octet is no digit: `as_imeisv()` gives the 16 digits, in 5GS and in
  EPS, and `is_well_formed()` and `validate()` report the IE. An IMSI
  whose odd/even bit does not agree with its digits is still refused:
  nothing else says how many it has.
- Two lengths of EPS message tables. The access technology utilization
  control is 4 to 5 octets in ATTACH ACCEPT, ATTACH REJECT, DETACH REQUEST,
  SERVICE REJECT, TRACKING AREA UPDATE ACCEPT and TRACKING AREA UPDATE
  REJECT, where 2 octets were taken, and stays 2 to 5 in GUTI REALLOCATION
  COMMAND, whose IE without contents removes what the UE stored. The
  remote UE context lists of REMOTE UE REPORT are 3 octets or more, where
  one of 3 or 4 was ignored as malformed; `validate()` holds a sender to
  the 5 of §9.9.4.20. The two other ranges that the second review
  compared stay, each with a test: a negotiated QoS of 5 to 13 octets is
  one that TS 24.008 §10.5.6.5 has a receiver accept, and `validate()`
  holds a sender to the 14 of the table; forbidden TAIs of 8 octets are a
  list of one tracking area, the least that §9.9.3.33 has, where three of
  the six tables say 9.
- A constructor of a tracking area list or of a service area list from
  its tracking areas (`from_tai_list`, `from_plmn_tacs`,
  `from_consecutive_tacs`, `from_different_plmns`, `from_plmn_only`) says
  what it refuses without `entry 0:`, which was the place of a partial
  list that the caller did not write.
- `Display` shows an identity whole wherever it shows one. A SUCI of an
  IMSI was shown by its PLMN and its scheme: it has its routing indicator,
  its key identifier and its MSIN or scheme output too. The 5G-S-TMSI of a
  SERVICE REQUEST was shown by its TMSI, and has its AMF set and pointer;
  the line says `identity=` where it said `5G-S-TMSI=`. A MAC address and
  an EUI-64 were shown by their type and length (`MacAddr (7B)`), and an
  identity that does not read as one of its type by its length: they are
  shown by their value, and by their octets. An EPS identity of a type
  that the crate does not read has its octets beside the type. The
  SECURITY MODE COMPLETE of 5GS shows its IMEISV and its non-IMEISV PEI,
  as that of EPS showed its IMEISV. An identity is printed whole in every
  form, and what goes to a log is the caller's choice.
- The message that a tree writes means what the message of the tree means.
  A tree showed the value of an IE whenever that value wrote some IE, and
  what the value did not say was lost without an error: the UMTS
  algorithms of a UE network capability (`e0e0c040` came back as
  `e0e00000000000000000`), the bits of a capability that have no name, a
  parameter of a service-level-AA container that the crate does not read
  (the container came back empty), octets after the end of an IE, the
  unknown IEs. A tree now shows the value of an IE that the value writes
  back, and the `octets` of any other; a container is shown by the tree of
  its message, with the IEs of that message under the same rule. What a
  value says all of and does not decide is written in one form, which the
  documentation of `to_tree` lists with the reason of each: the unit of a
  timer of one octet and of the rates of a session AMBR, octets of zeros
  after the flags of a capability, the partial lists of an EPS tracking
  area identity list, and the order of the optional IEs. A capability that
  a tree writes has the fewest octets that carry its flags and that its
  clause gives it, where it had the most: a 5GMM capability with `s1-mode`
  alone is one octet, and was eleven. 173 of the 191 fixtures come back
  from their tree with the same octets, where 167 did, and each means the
  same.
- A view and a tree take what they are given or refuse it. A text or a
  list that is longer than a value of a fixed number of octets was read up
  to that number: an SD written `"01020304"` was `010203`. It is refused
  (`"01020304" is not 3 octets`), as one that is shorter was, for each of
  the values of 2 to 32 octets that an IE has.
- A value without a member, `{}`, wrote an IE without octets, and the
  message was one that its receiver refuses: `"5gs-registration-result":
  {}` encoded as `7e004200`. It is refused (`{} writes no member of the
  IE`). `NasQosRules::from_rules` and
  `NasServiceLevelAaContainer::from_parameters` refuse a list without an
  entry, which their IEs have no octets for.
- `from_tree` and `from_view` give a message that `encode()` encodes, as
  `with_view` did. A `security-header-type` or an
  `extended-protocol-discriminator` that a plain message is not sent with,
  and a `spare-half-octet` or an `eps-bearer-identity` above 15, were taken
  and the message then had no octets; they are refused by the name of the
  member, in a message and in the message of a container. A plain message
  under a header that says it is ciphered, and an EMM TRANSPORT with a
  `data-container`, are what a security context deciphered and stay as
  they are.
- `NasRelayKeyResponseParameters::from_parsed` built an IE of 48 octets
  from a CP-PRUK ID without octets, which `parse()` then read as nothing:
  TS 24.501 §9.11.3.90 has 49 octets at least. It refuses one, with
  `` `cp-pruk-id` has 0 octets, and must have 1 to 65487 ``.
- An optional IE of one octet in an entry of a multiple payload container
  (`MultiplePayloadOptionalIe::from_raw`) that came with another length
  was read as its first octet, or as 0 without one, and encoded back as
  one octet. It is kept as `Unknown` with the octets that it has. A
  payload container type above 15 in an entry is refused when it is
  encoded, where its low four bits were written.
- The encoder says what an EPS header has when it refuses one: `an ESM
  header has the protocol discriminator 2 and an EPS bearer identity of 0
  to 15`, where it said `Invalid EPS ESM header`, and so for a plain EMM
  header. A mandatory half octet that is given more than four bits is
  refused by the name of its field.
- A tree shows a container by its octets when the message that its values
  write is not the one that it carries: a value does not say every octet,
  and the octets that it writes can be those of no message of its type. A
  SECURITY MODE COMPLETE that carries a REGISTRATION REQUEST whose mobile
  identity is "no identity" with more octets had a tree whose message had
  another tree.
- 5GS QoS rules and QoS flow descriptions, and EPS TFTs and traffic flow
  aggregates, with an error in a rule, description, TFT operation, or
  packet filter were syntactically incorrect IEs: a PDU SESSION
  ESTABLISHMENT ACCEPT or ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST
  failed with an invalid mandatory IE (cause #96), and a PDU SESSION
  MODIFICATION COMMAND, MODIFY EPS BEARER CONTEXT REQUEST, or request of
  the UE lost the IE, so a receiver accepted it. TS 24.501 §6.3.2.4,
  §6.4.1.3, §6.4.2.4 and TS 24.301 §6.4.2.4, §6.4.3.4, §6.5.3.4, §6.5.4.4
  handle these errors in the procedure with causes #41 to #45, #83 and
  #84. Receivers keep the IEs (only an empty TFT or QoS flow description is
  short of the message tables), and new accessors report the errors:
  `NasQosRules::parse_rules` returns each rule or a `QosRuleError` with its
  identifier, DQR bit and `QosError` class (#84 or #45), and
  `NasQosFlowDescriptions::parse_descriptions` each description or a
  `QosFlowDescriptionError` (#84). EPS callers already had `parse_tft` and
  `TftError::esm_cause`.
- A 5GS extended CAG information list entry without the CAG-ID list length
  (LCI = 0) whose CAG-IDs were followed by one to three octets was dropped
  on receipt with every later entry, although TS 24.501 Table 9.11.3.86.1
  has a receiver ignore superfluous octets at the end of an entry.
- 5GS `NasPayloadContainer::decode_as_ciot_user_data_container` read the
  payload as a CIoT small data container (§9.11.3.18B), so user data whose
  first octet was not a valid small data header, or that was longer than
  255 octets, failed to decode. TS 24.501 §9.11.3.39 codes that payload as
  the contents of a TS 24.301 §9.9.4.24 user data container, which is user
  data without structure: the helper now returns the user data, and
  `from_ciot_user_data_container` takes it.
- A 5GSM message with a reserved PDU session identity (16 to 255) failed
  with a `DecodingError` that dropped its PTI and message type, which a
  network needs to answer a PDU SESSION MODIFICATION REQUEST or PDU SESSION
  RELEASE REQUEST with cause #43 (TS 24.501 §7.3.2). It now fails with
  `NasError::ReservedPduSessionIdentity`, which carries them.
- 5GS NSSAI and rejected NSSAI receivers parsed the whole value, so
  malformed octets after the S-NSSAIs a UE stores dropped the IE, although
  TS 24.501 §9.11.3.37 and §9.11.3.46 have it store the first 8 (allowed
  NSSAI, rejected NSSAI) or 16 (configured and pending NSSAI) and ignore the
  remaining octets. `NasNssai::parse_all` returns up to 16 S-NSSAIs and stops
  at malformed octets once 8 are read; `NasRejectedNssai::entries` reads the
  first 8. `try_parse_all` and `is_well_formed` still check the whole value.
- Received DNN and APN IEs had to follow the TS 23.003 §9.1 character rules
  (letters, digits and hyphens), so an APN such as "my_apn" made an ACTIVATE
  DEFAULT EPS BEARER CONTEXT REQUEST fail with an invalid mandatory IE and
  dropped an optional DNN or APN. A receiver now needs only labels of 1 to
  63 octets that fill at most 100 octets, also for the DNN criteria of the
  operator-defined access category definitions; `as_string`, the builders
  and `validate()` keep the character rules of a sender, and `labels()`
  returns the received labels.
- 5GS PDU session reactivation result error cause was dropped from SERVICE
  ACCEPT and REGISTRATION ACCEPT when one pair had a PDU session ID of 0 or a
  reserved one, or when a half pair trailed. A receiver keeps the IE and its
  getters return the pairs that name a PDU session (TS 24.501 §9.11.3.43,
  §9.4); `is_well_formed` still requires a canonical list of a sender.
- A truncated unknown IE encoded as "comprehension required" made decoding
  fail with `BufferTooShort`, the error of a message too short for its
  header (§7.2). It is invalid mandatory information (TS 24.501 §7.5.1 b),
  cause #96), so it now fails with `InvalidMandatoryIe("unknown_ies")`, in
  5GS and EPS messages.
- 5GS `SessionAmbrUnit::from_u8`, and so the Session-AMBR and QoS flow bit
  rate unit getters, returned `None` for the codes above 0x19, which TS
  24.501 §9.11.4.14 makes a receiver read as 256 Pbps; `downlink_kbps` and
  its kin already did. `SessionAmbrUnit::from_u8_strict` returns the defined
  codes only, and the QoS flow description and N3QAI builders keep refusing
  the others.
- EPS `Guti::from_bytes`, `NasEpsMobileIdentity::as_guti` and
  `NasMobileIdentity::as_tmsi` required the first octet to be exactly 0xF6 or
  0xF4, although their documentation says that only the type of identity is
  checked, as the 5GS receivers do; they now read bits 3 to 1 only. The
  sender checks still require the "1111" filler.
- 5GS SUCI with an ECIES or operator-specific protection scheme and home
  network public key identifier 0 was rejected, making a REGISTRATION REQUEST
  that carried it fail with an invalid mandatory IE (TS 24.501 Table
  9.11.3.4.1 defines PKI value 0; only the null scheme requires it).
- 5GS `NasSorTransparentContainer::secured_packet` panicked for a container
  shorter than 19 octets, such as the SOR acknowledgement a REGISTRATION
  COMPLETE carries; it returns `None`.
- 5GS multiple-payload container entries used the decimal reading of the
  hexadecimal optional IEIs of TS 24.501 Table 9.11.3.39.1 for 5GMM cause,
  back-off timer value, old PDU session ID, request type, S-NSSAI, and DNN
  (for example 0x19 instead of 0x25 for the DNN), on encode and decode.
- 5GS `NasSecurityAlgorithms` read each algorithm from three bits, so the
  reserved codes 8 to 15 of TS 24.501 Table 9.11.3.34.1 were returned as a
  real algorithm (0x88 as NEA0 and NIA0). The 5GS fields are four bits wide:
  `ciphering` and `integrity` return `None` for a reserved code, and the raw
  getters return it. The EPS algorithm IEs keep their spare bits 8 and 4.
- 5GS QoS rules with a packet filter identifier 0, or with QFI 0, were
  syntactically incorrect, so the Requested QoS rules of a PDU SESSION
  MODIFICATION REQUEST were dropped and `NasQosRules::from_rules`
  refused them. TS 24.501 Table 9.11.4.13.1 has the UE set new packet filter
  identifiers to 0, and QFI 0 is "no QoS flow identifier assigned".
- A 5GS QoS rule "modify existing QoS rule without modifying packet
  filters" that carried a precedence and QFI was syntactically incorrect,
  so the Authorized QoS rules of a PDU SESSION MODIFICATION COMMAND were
  dropped (and a PDU SESSION ESTABLISHMENT ACCEPT failed to decode); only
  "delete existing QoS rule" omits them.
- 5GS QoS rules with a spare bit set (the QFI octet, packet filter direction
  octet, deleted packet filter identifier, flow label, or 802.1Q VID or
  PCP/DEI) were syntactically incorrect on receipt: the IE was dropped, and
  a PDU SESSION ESTABLISHMENT ACCEPT failed to decode. Receivers ignore the
  spare bits; `validate()` still reports them. The flow label and VID
  getters no longer return the spare bits, and the builders refuse a VID
  above 4095.
- 5GS QoS flow descriptions with QFI 0 were syntactically incorrect, so the
  Requested QoS flow descriptions of a UE that creates a QoS flow
  (TS 24.501 §6.4.2.2) were dropped and could not be built.
- 5GS QoS flow descriptions with a spare bit set (octets 4 to 6 of a
  description, or bits 1 to 4 of the EPS bearer identity parameter) were
  dropped on receipt; receivers ignore the spare bits and `validate()`
  still reports them.
- 5GS `AtsssSteeringFunctionality` used the codes 3, 12 and 15 for the ATSSS
  steering functionalities that TS 24.501 Table 9.11.4.1.1 codes 1, 2 and 3,
  so the 5GSM capability getters misread received values and the setters
  wrote reserved codes. The variants now have the table values.
- 5GS `NasNon3GppDelayBudget::entries` searched for the end of each packet
  filter list by exponential backtracking with unbounded recursion, so a
  received IE of about 130 octets took tens of seconds to parse. It now
  parses in linear time with the same result.
- A 5GS tracking area identity list whose partial-list header had the spare
  bit 8 set was dropped on receipt (for example the TAI list of a
  REGISTRATION ACCEPT); the bit is ignored, as the EPS TAI list already did,
  and `validate()` reports it.
- 5GS NSAG information limited the S-NSSAI list of an NSAG to 8 S-NSSAIs
  instead of the 16 of the configured NSSAI, so a REGISTRATION ACCEPT or
  CONFIGURATION UPDATE COMMAND lost the IE and `from_entries` refused it.
- 5GS LADN information and NSAG information parsed their nested TAI lists
  with the canonical sender check, so a TAI list that a stand-alone TAI
  list IE accepts (spare bit set, more than 16 TAIs) made the receiver drop
  the IE or truncate its entries.
- 5GS receivers dropped these IEs when a spare bit was set: maximum number of
  supported packet filters, PDU address, mapped EPS bearer contexts,
  requested and received MBS containers, and the VPS URSP configuration of
  a MANAGE UE POLICY COMMAND. The spare bits are ignored on receipt and
  `validate()` still reports them.
- 5GS receivers dropped the extended rejected NSSAI, operator-defined access
  category definitions, and CAG information lists when a spare bit was set;
  the bits are ignored on receipt and `validate()` still reports them.
- 5GS `NasServiceLevelAaContainer` gave every unknown parameter a
  one-octet length, so an unknown type 1 parameter (IEI 0x80 and above) or
  type 6 parameter (0x71 to 0x7F) made `try_parameters` and
  `validate_strict` fail instead of skipping it.
- 5GS QoS flow descriptions applied a zero-MFBR rule that TS 24.501 does not
  have (a zero MFBR required a zero GFBR in the same direction) and missed
  the one it has: an MFBR of 0 kbps in both directions is a syntactical
  error. The builder, `is_well_formed`, and the receiver now apply the
  §9.11.4.12 rule.
- 5GS NSSRG information was limited to 8 S-NSSAIs instead of the 16 of the
  configured NSSAI: `entries()` stopped after the eighth, `from_entries`
  refused more, and `validate()` reported a valid IE.
- 5GS `NasProtocolDescription::entries` stopped at an entry with a spare bit
  of octet 7 set, losing it and every later entry.
- 5GS N3QAI averaging windows above 4095 could not be built and failed the
  sender check; TS 24.501 §9.11.4.36 codes the parameter as in Table
  9.11.4.12.1, two octets in milliseconds.
- A 5GS SOR acknowledgement longer than 17 octets was dropped on receipt,
  unlike the other type 6 IEs, whose extra octets receivers ignore.
- A 5GS service area list of type "11" was dropped on receipt unless its
  PLMN octets decoded, although TS 24.501 Table 9.11.3.49.1 lets receivers
  ignore them.
- The EPS CLI of a CS SERVICE NOTIFICATION was dropped on receipt when the
  spare bits 5 to 3 of octet 3a were set; they are ignored, and
  `validate()` still reports them.
- `validate()` reported an uplink data status with zero spare octets 5 to 34
  and an empty LADN information IE (which deletes the LADN information) as
  errors; TS 24.501 §9.11.3.57 and §9.11.3.30 allow both.
- Encoding a decoded 5GS or EPS message, which `validate()` also does, took
  time quadratic in the number of unknown IEs it carried: about 0.8 s in a
  release build for a 64 KB message of one-octet IEs. It is now linear.
- `from_plmns` of the PLMN list IEs (5GS PLMN list, EPS equivalent PLMNs
  and both lists of PLMNs to be used in disaster condition) panicked for a
  PLMN identity whose digits are not BCD. Such a `Plmn` can no longer be
  made.

## 0.4.0 - 2026-09-27

This release adds the EPS NAS codec and reorganizes the crate. It is not
source compatible with 0.2.0.

### Breaking changes relative to 0.2.0

- **5GS IE helpers that existed in 0.2.0:**
  - `TimerUnit` is replaced by `GprsTimerUnit` and `GprsTimer3Unit`;
    `seconds_multiplier` takes `self`. `NasGprsTimer3` shares the TS 24.008
    GPRS timer 3 grammar with EPS: `unit` returns `Option<GprsTimer3Unit>`,
    `timer_value` returns `Option<u8>`, and `to_seconds` returns
    `Option<u64>`, `None` when deactivated or when the 320-hour unit is used
    (read T3512 with `t3512_value_for_ue`); a zero value is `Some(0)`.
  - `NasFGsMobileIdentity::as_imei` and `as_imeisv` return `None` for a
    non-decimal digit or an odd/even indicator that does not match the digit
    count, instead of skipping the digit.
  - `NasSecurityAlgorithms::ciphering` and `integrity` ignore the spare bits
    8 and 4 instead of returning `None` when they are set.
  - `NasDeRegistrationType::access_type` returns `Option<AccessTypeValue>`.
  - `NasFGsRegistrationResult::result_value` returns
    `Option<RegistrationResult>`.
  - `NasDnn::from_string` returns `Option` and refuses names that are not
    valid labels or exceed 100 octets.
  - `NasFGsRegistrationType::from_parts` is replaced by
    `from_registration_type` with the `with_*` builders, and
    `NasKeySetIdentifier::from_parts` by `from_key_set_identifier` or `new`
    with `with_ngksi` and `with_tsc`.
  - `NasMessageContainer::decode_inner` is `decode_plain_inner`, and
    `NasPayloadContainer::decode_as_gsm` is `decode_as_n1_sm_message`.
- **NAS security context lifecycle.** EPS and 5GS key, algorithm, and COUNT
  fields are private and a live context is no longer `Clone` in production.
  `new`/`from_kasme`/`from_kamf` are replaced by explicit
  `from_fresh_keys`, `from_fresh_kasme`, and `from_fresh_kamf`; use
  `restore_from_*` for persisted next-count state and `reselect_algorithms`
  to change algorithms under the same root key without resetting COUNT.
  Read-only algorithm and COUNT accessors are provided.
- **Module layout.** The 5GS codec moved to `oxirush_nas::nas_5gs`; shared
  traits, errors, and macros moved to `oxirush_nas::common`. The crate root
  still re-exports the 5GS API.
- **`NasError`** is `#[non_exhaustive]`, derives `PartialEq` and `Eq`, and has
  new variants: `MessageTooShort`, `UnknownProtocolDiscriminator`,
  `ReservedSecurityHeaderType`, `UnknownSessionMessageType` (with the header
  identities a STATUS message echoes), `InvalidMandatoryIe`, and
  `IntegrityCheckFailed`. Decoders return these instead of `BufferTooShort`
  or `DecodingError` for the corresponding cases, and the security contexts
  return `IntegrityCheckFailed` for a MAC mismatch.
- **Receiver-tolerant decoding.** Repeated optional IEs keep the first
  occurrence. Syntactically incorrect optional IEs, repetitions, and
  out-of-sequence IEs are absent from typed fields and retained in raw form
  for inspection and round-trip encoding; registered mandatory syntax
  failures return `NasError::InvalidMandatoryIe`. An IE longer than its
  defined value keeps its octets, and typed getters ignore the extra ones.
  A security envelope whose header type does not match the protected message
  decodes. For a null-ciphered opaque payload, callers can reconstruct the
  decoded envelope so `validate()` reports the sender error.
- **Validation.** `validate()` reports repeated IEs (§9.1) and
  out-of-sequence IEs in both protocols, and runs the sender check
  (`is_well_formed()`) of every 5GS IE whose grammar EPS shares.
- **Encoder policy.** Decode followed by encode accepts every representable
  value: the reserved PTI 255 and SERVICE REQUEST header types 13 to 15 now
  encode. `validate()` reports them, and builders such as `protect()` still
  refuse invalid pairings.
- **Encoding order.** Optional IEs set after decoding are inserted at their
  message-table position relative to the decoded ones.
- **Shared IE grammars.** IEs that TS 24.501 delegates to TS 24.301 or
  TS 24.008 use one implementation for both protocols; EPS keeps a type per
  message-table field where 5GS has one type per IE. For 5GS helpers added
  after 0.2.0 this changes:
  - `NasGprsTimer` and `NasGprsTimer2` read a zero value as `Some(0)`, and
    `from_unit_value` clears the value of a deactivated timer.
  - `NasEpsNasSecurityAlgorithms` returns the EPS `CipheringAlgorithm` and
    `IntegrityAlgorithm` (EEA/EIA) of `nas_eps`.
  - `GmmCause::from_u8` and `GsmCause::from_u8` return `None` for an
    unlisted value again, as in 0.2.0; the receiver fallbacks are
    `GmmCause::from_u8_received`, `NasFGmmCause::cause_received`, and
    `NasFGsmCause::cause_for_ue`/`cause_for_network`.
  - `NasEpsBearerContextStatus` accepts EBIs 1 to 15; `from_bearers` returns
    `Option`, and `set_active` and `is_well_formed` are new.
  - `NasServingPlmnRateControl::rate` rejects values below 10.
  - `NasIpHeaderCompressionConfiguration::from_profiles` and
    `from_profiles_with_additional_setup` return `Option` instead of panicking,
    and `max_cid` returns 0 when truncated.
  - `NasPlmnList::plmns`, `from_plmns`, and the disaster PLMN list helpers
    skip undecodable entries on receipt; `from_plmns` returns `Option`.
  - `NasNetworkName`, `NasTimeZone`, `NasTimeZoneAndTime`, and
    `NasDaylightSavingTime` setters return `&mut Self` and keep the IE length
    in sync; `NasNetworkName::name` and `from_name` decode and encode the
    text.
  - `NasUeRequestType::request_type_raw` returns `Option<u8>`, and
    `from_request_type_raw` is replaced by `from_request_type`.
  - `NasRegistrationWaitRange::from_range` returns `Option` instead of
    panicking, and `min_seconds`/`max_seconds` return `Option<u64>`.
  - `NasExtendedDrxParameters` setters return `&mut Self` and keep the IE
    length in sync.
  - `NasDnn`, `NasUeRadioCapabilityId`, `NasUnavailabilityInformation`,
    `NasUnavailabilityConfiguration`, `NasAccessTechnologyUtilizationControl`,
    `NasWusAssistanceInformation`, `NasSupportedCodecList`, and the emergency
    number lists gained typed accessors.
- **5GS reserved PTI.** The 5GSM header encodes PTI 255; decoding still
  rejects it.
- **Display text.** PLMNs show as `MCC/MNC` (for example `208/93`); EPS
  messages use the `EMM`, `ESM`, `SecurityProtected`, and `Opaque` prefixes
  of 5GS; causes include their description.

### Added

- EPS NAS codec (`nas_eps`) for all TS 24.301 V19.8.0 chapter 8 messages and
  chapter 9 IEs, with typed accessors, validation, display, and the EPS NAS
  security context.
- EPS `NasSecurityContext::verify_re_establishment` performs the network-side
  five-bit COUNT estimate, UL_NAS_MAC verification and atomic commit, and
  returns DL_NAS_MAC per TS 33.401 §7.4.4.
- Complete typed EPS helpers and strict sender/receiver grammars for legacy
  GPRS QoS, CLI, Remote UE Context, NBIFOM, header compression, identities,
  timers, PCO/TFT, capabilities, flags, lists, and Release-19 scalar IEs.
- 5GS SOR transparent-container information/ACK types, flags, MACs,
  CounterSOR, list accessors, Rel-17 parameter framing, canonical builders,
  message-direction validation, and nested payload validation.
- 5GS: `NasSecurityContext::protect_eps_message` and `unprotect_eps_message`
  protect an EPS ATTACH REQUEST or TRACKING AREA UPDATE REQUEST with the 5G
  context (TS 33.501 §8.5.2); `estimate_nas_count` estimates a COUNT from its
  low bits.
- NAS keys in both security contexts are overwritten when the context drops,
  and derived or mapped key temporaries are wiped after use.
- EPS `NasSecurityContext::protect_re_establishment` computes the two
  TS 33.401 §7.4.4 MAC halves and consumes the uplink COUNT atomically.
- 5GS: `NasKeySetIdentifier` has the EPS `ksi`, `tsc`, and typed
  `KeySetIdentifier` accessors (`ngksi` remains); `NasSecurityAlgorithms`
  has `ciphering_raw`, `integrity_raw`, setters, and `is_well_formed`;
  `NasGprsTimer`, `NasGprsTimer2`, and `NasGprsTimer3` have `value`,
  `from_seconds`, `deactivated`, and `is_well_formed`; the cause IEs have
  `cause_raw` and receiver fallbacks; `MappedEpsBearerParam` decodes its EPS
  QoS, TFT, and APN-AMBR contents; and more IEs have raw `data` accessors.
- Display for `Nas5gmmMessageType` and `Nas5gsmMessageType`.

### Fixed

- EPS receiver bounds now accept defined legacy QoS lengths while sender
  validation still requires the modern grammar; Remote UE, CLI, NBIFOM, and
  header-compression sender rules reject reserved or non-canonical values.
- EPS and 5GS receivers commit authenticated COUNT before later inner-message
  or header validation, preventing reuse by an authenticated malformed PDU.
- 5GS SOR, UPU, CIoT, and Service-level-AA typed payload decoders reject
  malformed inner content; SOR information and ACK forms are checked against
  their enclosing NAS message direction.
- 5GS payload/registration/request/access type, PDU address, DNN, TAI and
  service-area list, PDU-session/SSC, and maximum-data-rate validation now
  keeps receiver fallbacks distinct from canonical sender checks.
- 5GS EPS bearer context status ignored EBIs 1 to 4.
- 5GS `NasSecurityContext::unprotect` rejected a PDU whose spare half octet
  of octet 2 was set; it is ignored (TS 24.501 Figure 9.1.1-2).
- 5GS serving PLMN rate control accepted rates 1 to 9.
- 5GS wire decoding now ignores the security-header spare half octet and
  leaves security-header/message pairing to `validate()`, matching EPS and
  separating receiver parsing from sender requirements.
- Every public 5GS IE and UPDS API now has rustdoc, and the crate denies
  missing public documentation.
