# Changelog

All notable changes to `oxirush-nas` are recorded here.

## Unreleased (0.5.0)

This release brings the receivers closer to TS 24.501 and TS 24.301
V19.8.0 (Release 19). Two items follow TS 24.501 V20.1.0 (Release 20)
instead, as the entries below and the documentation say: the VLAN ID of the
non-3GPP device information, and the NSSAA-EPC and AIoTUR bits of the 5GMM
capability. It is not source compatible with 0.4.0.

### Breaking changes relative to 0.4.0

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
    the `Octets` itself, without an allocation. `new`, `from_data`,
    `set_data` and `with_data` take anything that is `Into<Octets>`: a
    vector as before, a slice or an array. Where a `Vec<u8>` is needed,
    `ie.value.to_vec()`. `UnknownIe::data` is an `Octets` too.
  - With `serde`, the form of an IE is `{"value": ..}`. A document of 0.4.0,
    which has `type_field` and `length` beside it, is still read.
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
  assert_eq!(error.to_string(), "`plmns` has 16 entries, and has 1 to 15");
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
    `NasEcnMarkingL4sIndication::try_from_qri_values`.
  - `NasRelayKeyResponseParameters::from_parsed` returned the IE, and
    returns a `Result` like the others: see under Fixed.
  - `ProtectionScheme::to_u8` returns `Result<u8, ValueError>`, where
    `try_to_u8` returned an `Option`.
  - The functions that read a code or octets (`from_u8`, `from_u8_strict`,
    `from_bytes`, `from_bytes_strict`, `PlmnId::from_tbcd`) and the getters
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
  the new `idna` feature asks for them: 9 crates are built with the default
  features where there were 36, 24 with `security` where there were 51.
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
- A `PlmnId` is valid: its digits are checked when it is made, so that
  `to_tbcd()` returns the three octets and cannot fail. Its fields are
  private. `PlmnId { mcc: [2, 0, 8], mnc: [9, 3, 0x0F] }` is
  `PlmnId::new("208", "93")`, `"208-93".parse()` or
  `PlmnId::from_digits([2, 0, 8], [9, 3, 0x0F])`, which return a
  `ValueError` for digits that are not 0 to 9; `plmn.mcc` and `plmn.mnc` are
  `plmn.mcc()` and `plmn.mnc()`. `try_to_tbcd` and `is_valid` are removed.
  With `serde`, a document with other digits is refused.
- A PLMN identity is displayed `208-93`, as a view and a tree write it, and
  no longer `208/93`: `Display` of `PlmnId`, and of the messages that show
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
  is `unknown_ies().get(1)`. The serde form of the field is the list of
  `{"iei", "data"}` that it was.
- `validate()` lists the first 32 findings of a kind about such IEs and
  one more that counts the others (`967 more findings of this kind are not
  listed`), where a message of 67,002 octets gave 66,999 findings in
  12 MB.
- In a view and a tree, `unknown-ies` is one text, the octets of each IE
  in hexadecimal with a space between two IEs (`"c0 6a0101"`), where the
  first form of this entry, earlier in this release, was a list of texts:
  a list has a value for each of tens of thousands of IEs.
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
    `NasCount`. EPS: `uplink_count()` and `downlink_count()` return
    `Option<NasCount>`, `restore_from_kasme` takes two `Option<NasCount>`,
    and `from_mapped_kasme_idle` and `from_mapped_kasme_handover` two
    `NasCount` each. A COUNT is estimated from the bits that a message
    carries by `NasCount::estimate`, `estimate_from_low_bits` and their
    `wrapping_` forms, and counted on by `next` and `wrapping_next`: the
    contexts use them, and this crate has no function of its own for it.
  - A context that has used every COUNT of a direction returns
    `NasError::NasCountExhausted`, where a text said so. A message whose
    code is right and that is then refused, because it does not decode or
    is not one that its header type or its direction protects, returns
    `NasError::AuthenticMessageRefused` with that reason inside: its COUNT
    is used, and no caller compares a text to know it.
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
  front page.
- `NasFGsRegistrationResult::from_result(RegistrationResult)` builds the
  IE that `new(vec![1])` built. An IE type whose value is one or two
  octets, and `TrackingAreaIdentity`, are `Copy`.
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
  the whole. A message of cleartext IEs alone goes out without a
  container, and a CONTROL PLANE SERVICE REQUEST whose only other IE is the
  CIoT small data container has the value of that IE ciphered. `unprotect`
  is the other end. The vectors of `tests/fixtures/initial-nas.tsv` are
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
  the same. The `security` feature is `no_std` too, as are `Serialize` and
  `Deserialize` of the `serde` feature. The JSON forms of a message (its
  tree, its view and the `view` module) need `serde` and `std`: they keep
  the names that they printed for the whole program and state for each
  thread. Without `std`, oxirush-security runs SNOW 3G and ZUC on the
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
  (``pdu-session-status: entry 1: `pdu-session-identity` is 16, and is 1 to
  15``), or with what the IE would be. Octets that the crate reads and
  would not write back to the same value are shown by their `octets`.
- `nas_5gs` and `nas_eps` export `Severity` and `ValidationError`, the
  types of what `validate()` returns, beside `Validate`.
- Four fuzz targets in `fuzz/`, which the continuous integration runs for a
  minute each from the fixtures and from a few messages with protocol
  configuration options: `decode_5gs`, `decode_eps`, `view_5gs` and
  `view_eps`. They replace six targets that no workflow ran.
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
  the typed accessors decode it and its `octets` in hexadecimal; a field of
  the header has a `value` alone. The entries are in the order that
  `serde_json` keeps the members of an object in: by name, or with its
  `preserve_order` feature the fields of the header first, then the IEs. A
  value is in the notation a reader expects: a
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
  serde form of a message is unchanged. The feature now depends on
  `serde_json`. Examples: `view_message_nas_5gs` and `view_message_nas_eps`.
- With the `serde` feature, a message as a tree, which is a view written
  shortly: `Nas5gsMessage::from_tree()` and `NasEpsMessage::from_tree()` make
  the message of `{"message-type": NAME, IE: VALUE, …}`, with what the type
  of the message decides of its header, and `to_tree()` shows a message in
  that form. An IE is its value, or `{"octets": "…"}`; the message in a
  container is its own tree. The type is written by its name or by its
  number, in a tree as in a view.
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
  `view::set` refuses the name of an IE that the message cannot have.
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

- The README starts with a sample and has an example of each task, each
  with the output that it prints. Its reference tables are in the
  documentation, which docs.rs shows: the paths, the rules, the notation
  of the values and the IE types that have a value in the `view` module;
  what the crate covers and does not, the versions of the specifications,
  the tests and the examples on the front page; the security contexts in
  `nas_5gs::security` and `nas_eps::security`; the commands of the
  benchmarks in `benches/src/lib.rs`. `tests/readme.rs` compares what each
  Rust block of the README and of those pages prints with the output under
  it.
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
- A tree shows by its octets each IE whose value a message is not written
  from, also in a message under a security header; such a message kept the
  value, which `from_tree` then refused.
- The macros of the crate are written with `pastey`, the maintained
  successor of `paste` (RUSTSEC-2024-0436).
- `PlmnId` implements `FromStr`, for `"208-93"`, and has `new`,
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
  `IE has invalid value or structure` for a value rule. The number of
  findings on one field and the order of the findings can differ. One
  finding is new: an additional update type above 15 in ATTACH REQUEST or
  TRACKING AREA UPDATE REQUEST, a half octet that cannot be encoded and
  that decoding does not produce, is reported on its field and not only
  as the failed encoding of the message.

### Fixed

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
  `` `cp-pruk-id` has 0 octets, and has 1 to 65487 ``.
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
  `PlmnId` whose digits are not BCD. Such a `PlmnId` can no longer be made.

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
