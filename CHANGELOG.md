# Changelog

All notable changes to `oxirush-nas` are recorded here.

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
