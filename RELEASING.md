# Releasing

What a release of `oxirush-nas` needs beside its changelog.

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

The identities (`Guti` of both systems, `STmsi`, `ImsiSuci`, `NaiSuci`,
`Tai`) are the types of oxirush-utils, which decides what they may add to.

## Checks before the tag

```sh
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
