# Releasing

What a release of `oxirush-nas` needs beside its changelog. Two things are
temporary in this repository until 0.5.0 is on crates.io, and this page says
where they are, so that the commit of the release removes each.

## Order

1. `oxirush-utils` 0.1.0 is published first, then `oxirush-security`
   0.3.0, which depends on it. This crate depends on both: on utils for its
   identities, and on security for its `security` feature, which Cargo
   resolves for the lockfile without the feature too. Until they are on
   crates.io, `cargo package`, `cargo publish` and a plain `cargo build` of
   a clone fail with `failed to select a version for the requirement`.
2. The temporary lines below are removed, in one commit.
3. `cargo publish --dry-run`, then the tag `v0.5.0` and `cargo publish`.

## What the commit of the release removes

Each is found by the text in the second column: the lines move.

| File | Text | What becomes of it |
|------|------|--------------------|
| `README.md`, under the first sample | `> This page describes 0.5.0, which is on \`master\` and unpublished.` and the line after it | removed |
| `README.md`, "Install" | from `Until 0.5.0 is published, depend on the repository.` to the end of the `[patch.crates-io]` block | removed: the `oxirush-nas = "0.5"` block above it is the whole of the section |
| `README.md`, "Tests and fuzzing" | `In a clone, \`--config\` takes oxirush-security and oxirush-utils from their repositories until they are on crates.io:`, the lines `SECURITY=...` and `UTILS=...`, and each `--config "$SECURITY" --config "$UTILS"` | the sentence and the two lines are removed, and the commands lose their `--config` |
| `README.md`, "Documentation" | `It has 0.4.0 until 0.5.0 is published; \`cargo doc\` in a clone builds this version.` | removed |
| `src/lib.rs`, "Tests" | `Until oxirush-security 0.3.0 and oxirush-utils 0.1.0 are on crates.io, these commands take the \`--config\` that the README gives.` | removed |
| `.github/workflows/ci.yml` | the comment `oxirush-security 0.3.0 and oxirush-utils 0.1.0 are not on crates.io yet` and the variable `UNPUBLISHED` | the variable is removed, and each `$UNPUBLISHED` of the steps with it |
| `benches/Cargo.toml`, `fuzz/Cargo.toml` | the comment `oxirush-security 0.3.0 and oxirush-utils 0.1.0 are not on crates.io yet` and the `[patch.crates-io]` section under it | removed |
| `CHANGELOG.md` | `## Unreleased (0.5.0)` | `## 0.5.0 - ` and the date |

`tests/readme.rs` holds the README to its blocks and to what they print: it
passes after the removal, since none of the removed lines is in a Rust
block.

## What a later version may add to

A struct or an enum of values is `#[non_exhaustive]` when a later release of
the specifications can add a member or a variant to what it stands for: an
entry of a list, the contents of a container, the flags of an octet with
spare bits, a message. Code outside the crate builds such a struct with its
`new(..)`, which takes its members in their order, and a later member is
then one that `new` leaves at its default: adding it is no breaking change.

- `nas_5gs`: `SNssaiContents`, `QosSrtpMultiplexedMediaIdentificationInformationEntry`, `QosRule`, `QosFlowDescription`, `ServiceLevelAaResponse`, `MappedEpsBearerContext`, `RequestedMbsSession`, `MbsSecurityKeySet`, `ReceivedMbsSession`, `ExtendedRejectedNssaiPartialList`, `NsagInfoEntry`, `OperatorAccessCategoryDefinition`, `CagInformationEntry`, `CagIdWithAdditionalInfo`, `CipheringDataSet`, `UeParametersUpdateProtectedHeaderInformation`, `UeParametersUpdateDisasterRoamingInformation`, `UeParametersUpdateListContents`, `UeParametersUpdateAcknowledgementContents`, `N3QaiEntry`, `Non3GppDeviceInformationEntry`, `RemoteUeContext`, `Non3GppDelayBudgetEntry`, `UrspRuleEnforcementReport`, `ProtocolDescriptionRtpPayloadInformation`, `ExtendedLadnInformationEntry`, `SNssaiLocationValidityEntry`, `SNssaiTimeWindow`, `SNssaiTimeValidityEntry`, `OnDemandNssaiEntry`, `RelayKeyRequestParameters`, `RelayKeyResponseParameters`, `UpdsMessageSemantics`, `UePolicySectionManagementInstruction`, `UePolicySectionManagementSublist`, `UePolicySectionManagementResultEntry`, `UePolicySectionManagementSubresult`, `UpsiSublist`, `VpsUrspTuple`, `VpsUrspConfigurationContents`, `UpdsEventNotificationContainer`, `UpdsMultiplePayloadEntry`, `UpdsMultiplePayloadContainer`, `NasManageUePolicyComplete`, `NasManageUePolicyCommandReject`, `NasUePolicyProvisioningRequest`, `NasUePolicyProvisioningReject`, `NasUnsupportedUpdsMessage`, `NasUpdsEnvelope`.
- `nas_eps`: `CipheringDataSet`, `EpsRemoteUeContext`, `ApnAmbr`, `EpsQos`, `TftPacketFilter`, `Tft`, `CallingPartyNumber`.
- `common`: `IpHdrCompProfiles`, `Pco`, `ValidationError`.
- The enums `TaiListType` and `TaiListEntry` of `nas_5gs`: the list type `11` has no meaning yet.

These stay as they are, because their clause closes them: the headers of a
message, a pair of an identifier and its contents, a value of two numbers
that its coding fixes, an identity of a network or of a cell.

- `nas_5gs`: `SessionAmbrValue`, `QosFlowBitRate`, `MappedEpsBearerParam`, `MbsTmgi`, `MbsNrCgi`, `ExtendedRejectedSNssai`, `NssrgInfoEntry`, `LadnInfoEntry`, `N3QaiParameter`, `SNssaiLocationValidityNrCgi`, `PartialNssaiEntry`, `AlternativeNssaiEntry`, `SnpnListEntry`, `UpdsUnknownIe`, `UePolicyPart`, `UpdsEventNotificationIndicator`, `Nas5gmmHeader`, `Nas5gsmHeader`, `Nas5gsSecurityHeader`.
- `nas_eps`: `NbifomParameter`, `RemoteUeUserIdentity`, `ApnAmbrValue`, `ExtendedApnAmbr`, `ExtendedEpsQos`, `TftParameter`, `NasEpsSecurityHeader`, `NasEmmHeader`, `NasEsmHeader`, `NasServiceRequest`, `NasEmmTransport`.
- `common`: `ExtendedEmergencyNumber`, `PortRange`, `UnknownIe`, `PcoEntry`, `EmergencyNumber`.
- The enums `Direction`, `PcoDirection`, `NbifomDirection`, `EutraMode`, `EpsBitRate`, `QosPacketFilter`,
  `ServiceAreaListEntry`, `Non3GppIpv6AddressInformation` and `ProseRelayTransactionIdentityValue`: each has
  every case of what it stands for.

The identities (`Guti` of both systems, `STmsi`, `Suci`, `ImsiSuci`,
`TrackingAreaIdentity`, `Tai`, `Lai`) are not decided here: they are to
move to a crate that the OxiRush crates share.

## Checks before the tag

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --no-default-features
cargo test --release --features security --test key_wiping
cargo build --target thumbv7em-none-eabihf --no-default-features --features serde,security
cargo publish --dry-run
```

The continuous integration runs these on every commit, with the lowest
versions of the dependencies and the four fuzz targets.
