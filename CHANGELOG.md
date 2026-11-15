# Changelog

All notable changes to `oxirush-nas` are recorded here.

## Unreleased

### Added

- `cleartext_ies()` of `GmmMessageType`: the cleartext IEs of an initial NAS
  message of the type, by the names of its tree (TS 24.501 §4.4.6).
- `replayed_count()`: the NAS COUNT that a received message of a sequence
  number replays, the highest of the 256 below the receiver's next one that
  ends with it (TS 24.501 and TS 24.301 §4.4.3.2).
- `ies()` of each message type (`GmmMessageType`, `GsmMessageType`,
  `EmmMessageType`, `EsmMessageType`) gives the rows of the table of its
  message, `IeRow`: the name of each IE as the tree prints it, its IEI, whether
  it is mandatory, its length in the message, and what its value takes in the
  tree, as a `tree::Takes` of oxirush-utils: the names of a coded value, the
  seconds of a timer or `deactivated`, the entries of a list, the members of a
  value written by them, the tree of a carried message.
- `select_in()` of the 5GS and of the EPS `Message` selects in a tree of the
  message that the caller built already, as `select()` does in the one that
  it builds: several selections build the tree once.
- `set_nas_count()` of the 5GS and of the EPS `SecurityContext` sets the next
  COUNT of a direction and keeps the keys, where `restore_from_kamf()` and
  `restore_from_kasme()` derive them again.
- `protect_into()` of the 5GS and of the EPS `SecurityContext` appends the
  protected message to a buffer, which allocates nothing once a buffer that
  is used again is long enough: the message is encoded in its place and
  ciphered there. With AES, a REGISTRATION ACCEPT of 247 octets is protected
  in 420 ns, where `protect()` took 522 ns.
- A payload container of the type "multiple payloads" (TS 24.501
  §9.11.3.39) in a UL or DL NAS TRANSPORT has the tree of its `entries`,
  where it had its octets alone: the `payload-container-type` of each
  entry, its `optional-ies` where it has some, and its `contents`, which
  are the tree of its 5GSM message for an entry of N1 SM information and
  its `octets` otherwise. The tree writes the container, and an edit of
  the message of an entry edits that message. Octets that are no such
  container are shown by their octets.

### Changed

- The member `n3-data` of the N1 UE network capability of EPS (TS 24.301
  §9.9.3.57), which was `n3-data-not-supported`, is the "N3 data" bit as its
  figure has it: `n3_data()` and `set_n3_data()` read and write it, and
  `n3_data_transfer_supported()`, its negation, goes.
- The 5GS network feature support and the feature authorization indication
  come from their tables. The member `n3-data` of the 5GS network feature
  support and of the 5GMM capability, and `hpase` of the feature authorization
  indication, are the bit as its figure has it: `n3_data()` is true where the
  bit says "N3 data transfer not supported", and `hpase()` where it says "high
  priority access UEs are not exempt". The 5GMM capability's member was
  `n3-data-not-supported`; `n3_data_not_supported()`,
  `high_priority_access_not_exempt()` and
  `from_high_priority_access_not_exempt()` go, and `from_flags()` of both takes
  the bit. The two-bit fields of the 5GS network feature support are typed:
  `emc()`, `emf()` and `restrict_ec()` return their values, `_raw` their bits,
  where `emc_value()` and the others go.
- The setter of a field of more than one bit that a table writes refuses a
  value that the bits of the field do not hold, and writes nothing: it returns
  `Result<&mut Self, OutOfRange>` ("Paging Time Window: 20 is more than 15, the
  most that its bits hold"). The setter of bits (`_raw`) writes those of the
  value that the field has, as before.
- The tree of a message holds the names of its members and of the variants
  of its values without copying them, with oxirush-utils at 8f0b227.
- The EMM and ESM causes come from their tables: `cause()` returns the value
  of the octet, not an `Option` (`name()` says whether the table names it).
- The extended DRX parameters come from their table:
  `set_paging_time_window()` and `set_edrx_value()` return `&mut Self` and
  write the four bits of their value, where they refused a value over 15.
- Thirty IEs of one coded value (the 5GMM and 5GSM causes, the service,
  PDU session, SSC mode, access, payload container, request, attach, update
  and PDN types, the DRX values and the others) come from tables. Their getters
  return the value as the IE has it, not an `Option` (`name()` says whether the
  table names it, `effective()` reads it as a receiver does); the `_strict`
  getters go; setters keep the bits that they do not write.
- The EPS additional update type, voice domain preference and UE's usage
  setting, T3412 extended value, DRX parameter, UE radio capability ID request
  and the truncated 5G-S-TMSI configuration come from tables. Their getters
  return the field as the IE has it, not an `Option`, and a reserved value is
  shown in a tree by its number.
- Twenty-eight indications of one to four flags of TS 24.501 and TS 24.301
  (MICO indication, network slicing indication, priority indicator, extended
  EMM cause, and the others) come from tables: each flag has a setter that
  returns `&mut Self`, and each type `spare_bits_are_zero()`. A tree that edits
  one of them keeps the bits that it does not write.
- The 5GS de-registration type, registration result, update type and control
  plane service type, and the EPS update type, control plane service type and
  detach type come from the tables of their figures. `result()`,
  `result_raw()` and `set_result()` replace the `result_value` accessors;
  `DeRegistrationType::access_type()` is the `DeregistrationAccessType`
  (`deregistration_access_type()` goes); `active()` and `switch_off()` replace
  `is_active()` and `is_switch_off()`; the `_strict` getters go; getters of
  coded fields return the value as the IE has it. A tree that writes a number
  too wide for its field is refused with the width of the field.
- The 5GSM capability, the EPS network feature support and the N1 UE network
  capability come from the tables of their figures. `GsmCapability::atsss_st()`
  and `atsss_ll()` return the typed values (the bits are `atsss_st_raw()` and
  `atsss_ll_raw()`; the `_value` accessors go); `cs_lcs()` and `pnb_ciot()`
  return the value, not an `Option`; setters return `&mut Self` and keep the
  bits that they do not write.
- Thirteen IE types of flags alone (5GMM capability, UE status, the
  re-attempt indicators, non-3GPP NW provided policies, mobile station
  classmark 2, access technology utilization control, MS network capability,
  device properties, WLAN offload acceptability, network policy, MS network
  feature support, the EPS additional information requested) come from the
  tables of their figures: their setters return `&mut Self`, and each has
  `spare_bits_are_zero()`. `validate()` reports spare bits set in a 5GMM
  capability.
- Every table of values (102, of TS 24.501, TS 24.301 and TS 24.008) is a
  table of `named_values!` of oxirush-utils, as `RegistrationTypeValue` is:
  `Other(u8)`, `from_value()`, `named()`, `value()`, `name()`, `tree_name()`
  and `effective()`. `TryFrom<u8>` never fails (`named()` reads a code
  strictly), `received()` goes (`from_value(code).effective()`),
  `description()` is `name()`, and `u8::from(value)` is the code of a value.
  The getters that returned an `Option` of the value as a receiver reads it
  return the value that the IE has (`downlink_unit()`, `uplink_unit()`,
  `unit_value()`, `mode()`, `session_type()`, `request_type()`,
  `result_value()`, `service_type()`, `pdn_type()`, `update_type()`).
  `PduSessionTypeValue::sbi_str()` returns an `Option`; an access type gives
  its `NasConnection` by `TryFrom`. `IpHdrCompAdditionalSetupType::Other` is
  `OtherProfile`. The trees do not change.
- The accessors of the 5GS registration type (§9.11.3.7) come from the table
  of its figure, and so does its tree: `set_registration_type()` and
  `set_follow_on_request()` return `&mut Self`; `registration_type_raw()`,
  `set_registration_type_raw()` and `spare_bits_are_zero()` are new;
  `validate()` reports spare bits that are set; its tree takes a number up to
  7. The tree is decided from the masks of the fields, without writing the IE
  back.
- `RegistrationTypeValue` is a table of `named_values!` of oxirush-utils:
  it has `Other(u8)` for a value that the table does not name, `from_value()`,
  `value()`, `name()` (the words of the table), `tree_name()` and
  `effective()`, the value as a network reads it. `received()` goes, and
  `TryFrom<u8>` is that of `From<u8>`, which never fails.
  `RegistrationType::registration_type()` returns the `RegistrationTypeValue`
  that the IE has, where it returned an `Option` of the value as a network
  reads it: `effective()` reads it so.
- `protect()` is written on `protect_into()`, and has one allocation and
  one copy of the message fewer: 476 ns for that REGISTRATION ACCEPT, three
  allocations where it had four.

- `to_tree()`, `from_tree()`, `with_tree()`, `select()` and `means_the_same()`
  of a 5GS and of an EPS message are five to fifteen times as fast, with a
  fifth of the allocations or fewer: for a REGISTRATION ACCEPT, to_tree
  18.6 to 2.8 us, from_tree 51.7 to 5.8 us and with_tree 77 to 5.0 us. A
  tree is made straight from the IEs of the message, and written into the
  message itself, without the readable form of the whole message or a view
  under the tree; whether an IE shows its value is decided on typed values.
  The trees, the messages that they write and the errors are the same, but
  for the message of a container: an edit of its tree edits it as
  `with_tree` edits a message.
- Two errors no longer name the view that a tree stood under: a tree
  without a `message-type` is refused with "a message is written from a tree
  whose `message-type` names it", and a tree that gives an EMM TRANSPORT
  another security header with "an EMM TRANSPORT has the security header type
  `security-header-for-the-emm-transport-message`, and a message under
  another one is written with `from_tree`".
- The examples of the README and of the documentation show what they give
  with `assert_eq!`, which the documentation tests check, and the package of
  `readme/`, which compared what each printed with the text under it, goes.

### Removed

- The UE policy delivery service of TS 24.501 Annex D: its six messages,
  `UpdsEnvelope`, `UpdsMessage`, their IEs and their `validate()`, and
  `decode_as_ue_policy_message()` and `from_ue_policy_message()` of
  `PayloadContainer`. A payload container of the type "UE policy container"
  is its octets, which `Display` shows as such. The contents of the payload
  container types "event notification" and "multiple payloads" stay, named
  without `Upds`: `EventNotificationContainer`, `EventNotificationIndicator`,
  `EventNotificationIndicatorType`, `MultiplePayloadContainer` and
  `MultiplePayloadEntry`. The fuzz target `upds` goes with them.
- The packets of the configuration protocols in the protocol configuration
  options: a unit of LCP, PAP, CHAP or IPCP (C021H, C023H, C223H, 8021H) is
  a `container` of its identifier and its octets in a tree, as any unit
  without a name: `{"container": {"identifier": 49187, "contents": "0101"}}`
  where a tree had `{"pap": "0101"}`. A tree that names `lcp`, `pap`, `chap`
  or `ipcp` is refused.
- The aliases of the 5GS IEs kept for callers of earlier versions:
  `GsmCongestionReAttemptIndicator::from_abo(abo)`, which is
  `from_flags(abo, false)`; `GsmNetworkFeatureSupport::from_ept_s1(ept_s1)`,
  which is `from_flags(ept_s1, false)`; `QosFlowDescriptions::descriptions()`,
  which is `try_descriptions().unwrap_or_default()`; and the deprecated
  `is_active`, `active_sessions` and `from_sessions` of
  `PduSessionReactivationResult`, which are `reactivation_failed`,
  `failed_sessions` and `from_failed_sessions`.

### Fixed

- `validate()` of a DEREGISTRATION REQUEST no longer reports the access type
  11 of its de-registration type (§9.11.3.20), 3GPP access and non-3GPP
  access, as invalid.
- `validate()` of a 5GS message says once each of the lengths of the ABBA,
  RAND, AUTN, AUTS, the UE security capability, the replayed one and the
  session AMBR, which the message structs said a second time in words of
  their own ("ABBA must be at least 2 bytes"). The `validate()` of a 5GS
  message struct starts from the rules of the IEs of its fields, as an EPS
  one does, so the struct alone has those findings too.
- `validate()` says the length of an IE once. A value that the clause of
  its IE finds too short or too long had a second finding from the table of
  its message, the same range with the octets of the IEI and of the length:
  the table says the length only of an IE that its clause has not faulted.
- No finding prints `usize::MAX` for a length without an upper limit: "a
  value of at least 2 octets" and "message-table length is under 3", where
  the two read "2 to 18446744073709551615 octets" and
  "outside 3..=18446744073709551615".

## 0.7.1 - 2026-11-09

### Added

- `plain` of a 5GS and of an EPS `Verified`: the plain octets that its
  message was read from, deciphered, which `unprotect_raw` gives as its
  message. A receiver that decodes a message with `unprotect` has its octets
  too, from the one NAS COUNT that the message takes.

## 0.7.0 - 2026-11-09

A path is the names of the tree joined: `value` after the name of an IE is
refused, with the path to write, and `octets` after it is the octets of the IE,
which `select()` of a message gives. It is not source compatible with 0.6.0:
`ie_octets()` is `select()`, and the table below has the paths.

### Added

- `innermost()` of a 5GS and of an EPS `Message`: the message inside its
  security envelopes, the plain message of an integrity protected one and
  the ciphertext of a ciphered one.
- `select()` of a 5GS and of an EPS `Message`: the values at a path of its
  tree, and the octets of each IE as the message has them, which `octets`
  after the name of the IE selects in hexadecimal, `/nas/5g-guti/octets`,
  also where the tree has the value of the IE.
- The intra N1 mode and the S1 mode to N1 mode NAS transparent containers
  (TS 24.501 §9.11.2.6 and §9.11.2.9), the NASC of an NGAP HANDOVER REQUEST,
  have a tree of their fields, which had their octets alone:
  `message-authentication-code`, `selected-nas-security-algorithms` and
  `ngksi` as a SECURITY MODE COMMAND names them, and `k-amf-change-flag` and
  `sequence-number`, or `ncc`. One with a spare bit set, or of another
  length, is shown by its octets.
- One IE alone as a tree, as an NGAP or S1AP IE carries the value of a NAS
  IE: `to_tree()` of an IE type, which is a `tree::Tree`, is the tree that a
  message shows of the IE, and `tree::from_value` writes the IE back from it
  or from `{"octets": "…"}` (`paths`, "One IE alone"). A container of a
  message alone, its serde form, and the `Display` of an EPS NAS message
  container in a message, are the tree of the message, as the tree of a
  message has it: they were a form of their own, with the fields that a tree
  leaves out, or the octets.

### Changed

- A path is the names of the tree joined: after the name of an IE or of a
  field of the header, the next name is a member of its value. `value` there,
  which no tree has, is refused by `select`, `set`, `remove` and `insert` of
  `paths`, and by `select()` of a message, with the path that the names of the
  tree write, without it and without each such `value` after another IE:
  ``a path is the tree's names joined: write `/nas/5g-guti/guti/tmsi`, at
  /nas/5g-guti/value/guti/tmsi``. It was refused as a member that the value
  has not, and selected nothing where the message does not have the IE.
- `octets` after the name of an IE is its octets: `set` writes the IE by them,
  in the place of its value, and adds an optional IE so; it added `octets`
  beside the members of the value, which `with_tree()` refused. A path that
  selects the octets of an IE that the tree has by its value is refused, with
  why: the message has them, and its `select()` gives them.
- oxirush-utils 0.2.2, whose `Next::index` says where a segment is in the path,
  for the path that the refusal of `value` writes.

### Removed

- `ie_octets()` of a message, which is `select()` with `octets` after the name
  of the IE: `message.ie_octets("/nas/5g-guti")` gives `Some(octets)`, and
  `message.select("/nas/5g-guti/octets")` gives them in hexadecimal.

### Fixed

- The message of the ESM message container of an ATTACH REQUEST in the EPS
  NAS message container of a 5GS message is its tree, as in the ATTACH
  REQUEST alone: it had its octets, and a tree that wrote it was refused as
  no 5GS message.

### Migration from 0.6

| 0.6 | 0.7 |
|-----|-----|
| `paths::select(&tree, "/nas/5g-guti/value/guti")`, refused | `paths::select(&tree, "/nas/5g-guti/guti")` |
| `message.ie_octets("/nas/5g-guti")?`, `Some(vec![0xf2, ..])` | `message.select("/nas/5g-guti/octets")?`, `[tree!("f2..")]` |
| `tree["5g-guti"] = tree!({"octets": "f2.."})` | the same, or `paths::set(&mut tree, "/nas/5g-guti/octets", tree!("f2.."))` |

## 0.6.0 - 2026-11-08

A lighter crate: each item has one path and one name, a message has one
JSON form, its tree, and each thing is written once. It is not source
compatible with 0.5.0; the table below has the changes that a caller makes.

### Changed

- oxirush-utils 0.2 and oxirush-security 0.4. The algorithms of a security
  context and of the IEs are `identity::Algorithm` (`Null`, `Snow3g`, `Aes`,
  `Zuc`), and a SUCI is `identity::Suci`.
- Each item has one path. The submodules of `nas_5gs` and `nas_eps` are
  private and their items are `nas_5gs::X` and `nas_eps::X`; what both
  systems share is at the root (`Error`, `Decode`, `Encode`, `Direction`,
  `Validate`, `DecodeOptions`...); the identities are in `identity` alone.
- A type is named by its specification, without the prefix `Nas` and the
  spelling `FG`: `nas_5gs::RegistrationRequest`, `nas_5gs::MobileIdentity`,
  `GmmCause`, `nas_5gs::Message`, `Error`. An enum of values whose name its IE
  has takes `Value`: `GmmCauseValue`, `RegistrationTypeValue`.
- An enum of codes reads with `TryFrom<u8>` (`Err` with the code) and as a
  receiver with `received()`, and writes with `u8::from`; a message type is
  `From<u8>`, with `Unknown(code)`.
- The feature `serde` is `tree`, and takes `std`; the codec, `validate()` and
  the security contexts stay `no_std`.
- A message has one JSON form, its tree. `with_tree()` writes the message
  that an edited tree says and keeps the octets of every IE that it leaves
  as it was; the module `paths` reads and edits a tree by path, without
  `/value`; `ie_octets()` gives the octets that an IE came with;
  `names()` of a message type lists the members of its tree.
- The names of a tree are printed when the crate is compiled. A name is read
  as itself, written alike, or by its letters and digits; a name spelt as
  the identifier of the source is not (`fgs_mobile_identity`).
- An IE is changed by its setters (`set_x()`); a message keeps its builders.
- A 5GS security context has one method of each kind, which takes the
  `NasConnection` of its access: `protect`, `protect_initial`,
  `protect_opaque_payload`, `unprotect`, `unprotect_raw`.
- A message is decoded with `decode()`, `decode_with(octets, options)` or
  `decode_lenient(octets, options)`, in both systems; the direction that
  tells the two EPS DETACH REQUESTs apart is one of the `DecodeOptions`.
- `Display` of a message is written from its table: its name, then each IE
  that it has, by the name of its tree and as its type shows it, or else as
  its tree on one line (its octets without the feature `tree`). An IE that
  holds a key shows its length alone, the key of an AUN3 device too, whose
  `Debug` now hides it as well.
- `Error` writes its own text; `thiserror` is no dependency, and `hex` one of
  the tests alone. `validate()` takes the rules of each IE type from one table.
- The README blocks are checked by the package of `readme/`.

### Added

- The NAS transparent containers of a handover between 5GS and EPS (TS
  24.501 §4.4.2.2, §4.4.2.4) on the 5GS security context:
  `n1_to_s1_container`, `verify_n1_to_s1_container`, `s1_to_n1_container`
  and `verify_s1_to_n1_container`.
- The names of the units of the protocol configuration options that carry a
  PDU session in a PDN connection (TS 24.008 Table 10.5.154): `pdu-session-id`,
  `5gsm-cause`, `s-nssai`, `qos-rules`, `session-ambr` and
  `qos-flow-descriptions`.
- A replay window: `set_replay_window(size)` lets a security context take a
  message whose NAS COUNT is below the highest that it accepted, once (TS
  24.501 and TS 24.301 §4.4.3.1), up to `MAX_REPLAY_WINDOW` (64).
- `validate()` reports an unknown IE whose octets are not one IE of the
  format of its IEI (TS 24.007 §11.2.4), and holds the MS identity of an
  ATTACH ACCEPT and a TRACKING AREA UPDATE ACCEPT to a TMSI or the IMSI.
- Ten fuzz targets, which CI runs for a minute each at each commit.

### Fixed

- The N3 data flag of the 5GMM capability is `n3_data_not_supported` as
  sent, and `n3_data()` is the capability (TS 24.501 §9.11.3.1).
- Payload container type 8 prints as `ciot`, not `cio-t`.
- A CONTROL PLANE SERVICE REQUEST is read with an ESM message container of
  no octet to two (TS 24.301 §7.5.2).
- `ServiceAreaList::from_entries` refuses a first TAC that would overflow;
  `RemoteUeContextList::from_contexts` writes the HPLMN ID that Table
  9.11.4.29.2 asks for; `ServiceLevelAaContainer::from_parameters` writes the
  length of a parameter as its IEI has it.
- A packet filter of a QoS rule decodes a component after (S)RTP multiplexed
  media identification information; `from_rules` refuses the components
  that Table 9.11.4.13.1 does not allow with an ethertype, and an RTP SDES
  header extension id that is said to be there and is not.
- The SOR transparent container reads its PLMN list, SOR-CMCI rules and
  SOR-SNPN-SI-LS entries with the lengths of TS 24.501 §9.11.3.51.
- 5GMM cause #10 is "Implicitly de-registered".

### Migration from 0.5

| 0.5 | 0.6 |
|-----|-----|
| `oxirush_nas::nas_5gs::ie::X`, `messages::X`, `types::X`, `common::X` | `oxirush_nas::nas_5gs::X`, `oxirush_nas::X` |
| `nas_5gs::Guti`, `STmsi`, `Tai`, `oxirush_nas::Plmn` | `identity::Guti5g`, `STmsi5g`, `Tai5gs`, `identity::Plmn` |
| `NasRegistrationRequest`, `NasFGsMobileIdentity`, `NasFGmmCause` | `RegistrationRequest`, `nas_5gs::MobileIdentity`, `GmmCause` |
| `Nas5gsMessage`, `NasEpsMessage`, `NasError` | `nas_5gs::Message`, `nas_eps::Message`, `Error` |
| `GmmCause` (the enum), `RegistrationType` (the enum) | `GmmCauseValue`, `RegistrationTypeValue` |
| `CipheringAlgorithm::NEA2`, `IntegrityAlgorithm::EIA2` | `identity::Algorithm::Aes` |
| `X::from_u8(c)`, `from_u8_strict(c)`; `x.as_u8()` | `X::try_from(c)`, or `X::received(c)` as a receiver; `u8::from(x)` |
| `features = ["serde"]` | `features = ["tree"]` |
| `to_view()`, `with_view(view)`, `from_view(view)` | `to_tree()`, `with_tree(tree)`, `from_tree(tree)` |
| `view::select(&view, "/nas/5g-guti/value/guti")`, `set`, `insert` | `paths::select(&tree, "/nas/5g-guti/guti")`, `set`, `insert` |
| `view::select(&view, "/nas/5g-guti/octets")` | `message.ie_octets("/nas/5g-guti")` |
| `kind.view_names()` | `kind.names()` |
| `ie.with_x(v)` on an IE | `let mut ie = ..; ie.set_x(v);` |
| `cause.cause_raw()` | `cause.value` |
| `ctx.protect(&m, sht, dir)`, `protect_for_access(.., conn)` | `ctx.protect(&m, sht, dir, NasConnection::ThreeGpp)` |
| `ctx.unprotect(data, dir)`, `unprotect_raw`, `protect_initial(&m)` | the same with the `NasConnection` last |
| `ctx.protect_bytes(octets, sht, dir)` | `ctx.protect(&Message::decode(&octets)?, sht, dir, ..)` |
| `nas_eps::Message::decode_with_direction(octets, dir)` | `decode_with(octets, DecodeOptions::STRICT.with_direction(dir))` |
| `decode_lenient(octets)` | `decode_lenient(octets, DecodeOptions::STRICT)` |
| `5GMM RegistrationReject (cause=#22 (Congestion), T3346=10 min)` | `5GMM RegistrationReject (5gmm-cause: #22 (Congestion), t3346-value: 10 min)`: every IE, by the name of its tree |

## 0.5.0 - 2026-10-24

The receivers closer to TS 24.501 and TS 24.301 V19.8.0: each IE of a
message has `set_<ie>` and `with_<ie>`, and its field is public; a message
is read leniently with `decode_lenient`, answered by `answer_to` (clause 7),
and checked by `validate()` against the rules of a sender and of a receiver;
the views and trees of the messages, with paths; the security contexts of
both systems, with the keys of oxirush-security, the NAS COUNTs and the
initial NAS messages (TS 24.501 §4.4.6); the IEs of TS 24.501 V19 and V20 by
type, with their values. It was not source compatible with 0.4.0.

## 0.4.0 - 2026-09-27

The EPS NAS codec (TS 24.301), and the IEs that 5GS and EPS share in one
type. It was not source compatible with 0.2.0.
