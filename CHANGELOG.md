# Changelog

All notable changes to `oxirush-nas` are recorded here.

## Unreleased (0.5.0)

This release brings the receivers closer to TS 24.501 and TS 24.301
V19.8.0 (Release 19). Two items follow TS 24.501 V20.1.0 (Release 20)
instead, as the entries below and the README say: the VLAN ID of the
non-3GPP device information, and the NSSAA-EPC and AIoTUR bits of the 5GMM
capability. It is not source compatible with 0.4.0.

### Breaking changes relative to 0.4.0

- `AtsssSteeringFunctionality` variants have the ATSSS-ST codes of TS
  24.501 Table 9.11.4.1.1 (1, 2 and 3 instead of 3, 12 and 15), so
  `NasFGsmCapability::from_flags` and `set_atsss_st` panic for the old
  codes.
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

- With the `serde` feature, message structs, the 5GS and EPS message enums,
  plain and security headers and the message type enums derive `Serialize`
  and `Deserialize`, not only the typed IE values. A serialized message
  carries its unknown IEs and the decoded optional IE order, so a JSON round
  trip re-encodes the octets that were received; both default to empty
  when a document omits them. The order is decode bookkeeping, not a stable
  format.
- With the `serde` feature, `to_view()` and `with_view()` on
  `Nas5gsMessage` and `NasEpsMessage`. A view is a `serde_json::Value` with
  each IE of the message by the name the specification gives it, in lower
  case with hyphens (`5gs-registration-type`, `tai-list`), its `value` as
  the typed accessors decode it and its `octets` in hexadecimal; the fields
  of the header come first. A value is in the notation a reader expects: a
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
  a message has. Names are read in any case, with hyphens, underscores or
  spaces, and numbers also as `"0x…"` strings. A name that does not exist,
  a member that is not there, a value that an IE cannot carry, and octets
  and a value that disagree are errors. 153 of the 169 5GS IE types and 132
  of the 153 EPS types have a value; 33 and 6 of them are read only. The
  serde form of a message is unchanged. The feature now depends on
  `serde_json`. Examples: `view_message_nas_5gs` and `view_message_nas_eps`.
- With the `serde` feature, `from_view()` on `Nas5gmmMessageType`,
  `Nas5gsmMessageType`, `NasEmmMessageType` and `NasEsmMessageType`: the
  message that a view describes alone. The view has every field of the
  header, every mandatory IE and the optional IEs that the message has; the
  message in a container is the view that is the `value` of the container,
  named by its `message-type`.
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

- The `security` feature requires oxirush-security 0.2.1, which wipes the
  hash state of the key derivations and the 128-EEA2 keystream blocks and
  reads the SNOW 3G and ZUC tables without secret-dependent indices.
- `validate()` of an EPS message takes the length of each field from its
  message table and the value rules of each IE type from one list of types,
  as 5GS does; each message had its own list of checks. The same messages
  get findings on the same fields with the same severity. The texts are
  those of 5GS: `message-table length is outside 7..=97` for a length
  outside the table or a declared length that differs from the value, and
  `IE has invalid value or structure` for a value rule. The number of
  findings on one field and the order of the findings can differ. One
  finding is new: an additional update type above 15 in ATTACH REQUEST or
  TRACKING AREA UPDATE REQUEST, a half octet that cannot be encoded and
  that decoding does not produce, is reported on its field and not only
  as the failed encoding of the message.

### Fixed

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
  MODIFICATION REQUEST were dropped and `NasQosRules::try_from_rules`
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
  `PlmnId` whose digits are not BCD; it returns `None`, as documented.

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
