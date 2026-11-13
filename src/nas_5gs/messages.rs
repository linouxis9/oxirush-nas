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

//! NAS message structs, headers, and codec functions.
//!
//! This is **Layer 2** of the crate. Each NAS message is a struct defined by the
//! `nas_message!` macro with:
//!
//! - **Mandatory fields** — passed to `new()` and exposed via explicit getters
//!   plus `set_*_value()` / `with_*_value()` helpers.
//! - **Optional fields** — set via `set_*()` builder methods (e.g., `set_tai_list()`).
//! - **`Encode`/`Decode` implementations** — encode/decode with IEI-based dispatch.
//!
//! The top-level type is [`Message`], which wraps either a 5GMM or 5GSM message
//! (or a security-protected envelope). [`Message::decode`] and
//! [`Message::encode`] are the main entry points.

use crate::common::{Direction, Reader, Writer};
use crate::nas_5gs::*;
use crate::prelude::*;
use core::convert::TryFrom;

// TS 24.007 §11.2.4 assigns 0x70..=0x7f to 5GS TLV-E IEs.
pub(crate) const UNKNOWN_TLVE_START: u8 = 0x70;

/// PDU Session Identity value indicating "unassigned" (0x00).
pub const PDU_SESSION_IDENTITY_UNASSIGNED: u8 = 0;

pub(crate) use crate::common::UnknownIes;
use crate::common::{nas_message, nas_message_empty, nas_message_impl_default};

// ── Framework types ──────────────────────────────────────────────────────────

/// 5GMM message header (3 bytes on the wire).
///
/// Contains the Extended Protocol Discriminator (always 0x7E for 5GMM),
/// the spare half octet plus the Security Header Type (`§9.3`, Table `9.3.1`),
/// and the message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GmmHeader {
    /// Extended protocol discriminator (0x7E, 5GMM).
    pub extended_protocol_discriminator: u8,
    /// Security header type; plain for a plain message.
    pub security_header_type: SecurityHeaderType,
    /// Spare half octet: bits 5 to 8 of the octet of the security header
    /// type, which are spare bits set to zero (`§9.5`). Decoding takes any
    /// value and keeps it: a message is encoded with the one it was received
    /// with.
    pub spare_half_octet: u8,
    /// Message type.
    pub message_type: GmmMessageType,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct GmmHeader { extended_protocol_discriminator, security_header_type, spare_half_octet, message_type });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(GmmHeader);

impl GmmHeader {
    /// Build a plain 5GMM header.
    pub fn new(message_type: GmmMessageType) -> Self {
        Self {
            extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM,
            security_header_type: SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected,
            spare_half_octet: 0,
            message_type,
        }
    }
}

/// The octet of a security header type `security_header_type` with the spare
/// half octet `spare_half_octet` in its bits 5 to 8.
fn security_header_type_octet(
    security_header_type: SecurityHeaderType,
    spare_half_octet: u8,
) -> Result<u8> {
    if spare_half_octet > 0x0F {
        return Err(Error::EncodingError(format!(
            "A spare half octet has four bits, got 0x{spare_half_octet:02x}"
        )));
    }
    Ok((spare_half_octet << 4) | security_header_type as u8)
}

impl Encode for GmmHeader {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if self.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(Error::EncodingError(format!(
                "plain 5GMM header shall use EPD=0x7e, got 0x{:02x}",
                self.extended_protocol_discriminator
            )));
        }
        if self.security_header_type
            != SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected
        {
            return Err(Error::EncodingError(format!(
                "plain 5GMM header shall use SHT=PlainFiveGsNasMessageNotSecurityProtected, got {:?}",
                self.security_header_type
            )));
        }

        let security_header_type_octet =
            security_header_type_octet(self.security_header_type, self.spare_half_octet)?;

        buffer.put_u8(self.extended_protocol_discriminator);
        buffer.put_u8(security_header_type_octet);
        buffer.put_u8(u8::from(self.message_type));
        Ok(())
    }
}

impl Decode for GmmHeader {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        if buffer.remaining() < 3 {
            return Err(Error::MessageTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let security_header_type_octet = buffer.get_u8();
        let message_type_value = buffer.get_u8();

        let security_header_type = SecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;
        let message_type = GmmMessageType::from(message_type_value);

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(Error::DecodingError(format!(
                "plain 5GMM header shall use EPD=0x7e, got 0x{extended_protocol_discriminator:02x}"
            )));
        }
        if security_header_type != SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected {
            return Err(Error::DecodingError(format!(
                "plain 5GMM header shall use SHT=PlainFiveGsNasMessageNotSecurityProtected, got {security_header_type:?}"
            )));
        }

        Ok(Self {
            extended_protocol_discriminator,
            security_header_type,
            spare_half_octet: security_header_type_octet >> 4,
            message_type,
        })
    }
}

/// 5GSM message header (4 bytes on the wire).
///
/// Contains the Extended Protocol Discriminator (always 0x2E for 5GSM),
/// the PDU Session Identity, Procedure Transaction Identity, and message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GsmHeader {
    /// Extended protocol discriminator (0x2E, 5GSM).
    pub extended_protocol_discriminator: u8,
    /// PDU session identity.
    pub pdu_session_identity: u8,
    /// Procedure transaction identity.
    pub procedure_transaction_identity: u8,
    /// Message type.
    pub message_type: GsmMessageType,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct GsmHeader { extended_protocol_discriminator, pdu_session_identity, procedure_transaction_identity, message_type });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(GsmHeader);

impl GsmHeader {
    /// Build a 5GSM header.
    pub fn new(
        message_type: GsmMessageType,
        pdu_session_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        Self {
            extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM,
            pdu_session_identity,
            procedure_transaction_identity,
            message_type,
        }
    }
}

impl Encode for GsmHeader {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if self.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM {
            return Err(Error::EncodingError(format!(
                "5GSM header shall use EPD=0x2e, got 0x{:02x}",
                self.extended_protocol_discriminator
            )));
        }
        // The reserved PTI 255 is encodable for negative tests; receivers
        // reject it on decode.
        buffer.put_u8(self.extended_protocol_discriminator);
        buffer.put_u8(self.pdu_session_identity);
        buffer.put_u8(self.procedure_transaction_identity);
        buffer.put_u8(u8::from(self.message_type));
        Ok(())
    }
}

impl Decode for GsmHeader {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        if buffer.remaining() < 4 {
            return Err(Error::MessageTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let pdu_session_identity = buffer.get_u8();
        let procedure_transaction_identity = buffer.get_u8();
        let message_type_value = buffer.get_u8();

        let message_type = GsmMessageType::from(message_type_value);

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM {
            return Err(Error::DecodingError(format!(
                "5GSM header shall use EPD=0x2e, got 0x{extended_protocol_discriminator:02x}"
            )));
        }
        if pdu_session_identity > 15 {
            return Err(Error::ReservedPduSessionIdentity {
                identity: pdu_session_identity,
                pti: procedure_transaction_identity,
                message_type: message_type_value,
            });
        }
        if procedure_transaction_identity == 255 {
            return Err(Error::DecodingError(
                "reserved 5GSM procedure transaction identity".into(),
            ));
        }

        Ok(Self {
            extended_protocol_discriminator,
            pdu_session_identity,
            procedure_transaction_identity,
            message_type,
        })
    }
}

/// Check whether raw NAS PDU bytes are security-protected (integrity and/or ciphered).
///
/// Returns `true` if the PDU has a 5GMM EPD (0x7E) and a non-plain security header type.
/// Returns `false` for plain 5GMM, 5GSM messages, or truncated PDUs.
pub fn is_security_protected(pdu: &[u8]) -> bool {
    if pdu.len() < SECURITY_HEADER_LEN + 2 || pdu.first().copied() != Some(0x7E) {
        return false;
    }

    matches!(
        SecurityHeaderType::try_from(pdu[1] & 0x0F),
        Ok(sht) if sht != SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected
    )
}

/// NAS security header length in bytes (EPD + SHT + MAC + SN = 7).
pub const SECURITY_HEADER_LEN: usize = 7;

/// NAS security header (7 bytes on the wire).
///
/// Wraps a plain NAS message with integrity protection and optional ciphering.
/// Contains the MAC (4 bytes) and sequence number (1 byte) used for NAS COUNT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityHeader {
    /// Extended protocol discriminator (0x7E).
    pub extended_protocol_discriminator: u8,
    /// Security header type.
    pub security_header_type: SecurityHeaderType,
    /// Spare half octet: bits 5 to 8 of the octet of the security header
    /// type (Figure `9.1.1.2`), which are spare bits set to zero (`§9.5`)
    /// and are not covered by the message authentication code. Decoding
    /// takes any value and keeps it.
    pub spare_half_octet: u8,
    /// Message authentication code.
    pub message_authentication_code: u32,
    /// Sequence number: the eight least significant bits of the NAS COUNT.
    pub sequence_number: u8,
}

#[cfg(feature = "tree")]
crate::common::readable::readable!(struct SecurityHeader { extended_protocol_discriminator, security_header_type, spare_half_octet, message_authentication_code, sequence_number });
#[cfg(feature = "tree")]
crate::common::readable::serde_by_readable!(SecurityHeader);

impl Encode for SecurityHeader {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        if self.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(Error::EncodingError(format!(
                "security-protected outer header shall use EPD=0x7e, got 0x{:02x}",
                self.extended_protocol_discriminator
            )));
        }
        if self.security_header_type
            == SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected
        {
            return Err(Error::EncodingError(
                "security-protected outer header cannot use SHT=PlainFiveGsNasMessageNotSecurityProtected".into(),
            ));
        }

        let security_header_type_octet =
            security_header_type_octet(self.security_header_type, self.spare_half_octet)?;

        buffer.put_u8(self.extended_protocol_discriminator);
        buffer.put_u8(security_header_type_octet);
        buffer.put_u32(self.message_authentication_code);
        buffer.put_u8(self.sequence_number);
        Ok(())
    }
}

impl Decode for SecurityHeader {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        if buffer.remaining() < 7 {
            return Err(Error::MessageTooShort);
        }

        let extended_protocol_discriminator = buffer.get_u8();
        let security_header_type_octet = buffer.get_u8();
        let message_authentication_code = buffer.get_u32();
        let sequence_number = buffer.get_u8();

        let security_header_type = SecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;

        if extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
            return Err(Error::DecodingError(format!(
                "security-protected outer header shall use EPD=0x7e, got 0x{extended_protocol_discriminator:02x}"
            )));
        }
        if security_header_type == SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected {
            return Err(Error::DecodingError(
                "security-protected outer header cannot use SHT=PlainFiveGsNasMessageNotSecurityProtected".into(),
            ));
        }

        Ok(Self {
            extended_protocol_discriminator,
            security_header_type,
            spare_half_octet: security_header_type_octet >> 4,
            message_authentication_code,
            sequence_number,
        })
    }
}

// ── 5GMM Messages ──────────────────────────────────────────────────────────────

nas_message! {
    /// Registration Request (TS 24.501 §8.2.6).
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // An initial registration with the SUCI of the null scheme
    /// let octets = hex::decode("7e004179000d0102f8390000000000000010022e08a020000000000000");
    /// let Message::Gmm(_, GmmMessage::RegistrationRequest(request)) =
    ///     Message::decode(&octets.unwrap()).unwrap()
    /// else {
    ///     unreachable!()
    /// };
    /// let kind = request.fgs_registration_type.registration_type();
    /// assert_eq!(kind, Some(RegistrationTypeValue::InitialRegistration));
    /// assert_eq!(request.ngksi.to_string(), "no key");
    /// let identity = request.fgs_mobile_identity.to_string();
    /// assert_eq!(identity, "suci-0-208-93-0000-0-0-0000000120");
    /// assert!(request.requested_nssai.is_none());
    /// ```
    pub struct RegistrationRequest {
        mandatory {
            fgs_registration_type: RegistrationType [low_half_first],
            ngksi: KeySetIdentifier [high_half_last],
            fgs_mobile_identity: MobileIdentity {wire_len 6, usize::MAX}
        }
        optional {
            0xC0 => non_current_native_nas_key_set_identifier: KeySetIdentifier [tv1] {wire_len 1, 1},
            0x10 => fgmm_capability: GmmCapability {wire_len 3, 15},
            0x2E => ue_security_capability: UeSecurityCapability {wire_len 4, 10},
            0x2F => requested_nssai: Nssai {wire_len 4, 74},
            0x52 => last_visited_registered_tai: TrackingAreaIdentity {wire_len 7, 7},
            0x17 => s1_ue_network_capability: S1UeNetworkCapability {wire_len 4, 15},
            0x40 => uplink_data_status: UplinkDataStatus {wire_len 4, 34},
            0x50 => pdu_session_status: PduSessionStatus {wire_len 4, 34},
            0xB0 => mico_indication: MicoIndication [tv1] {wire_len 1, 1},
            0x2B => ue_status: UeStatus {wire_len 3, 3},
            0x77 => additional_guti: MobileIdentity {wire_len 14, 14},
            0x25 => allowed_pdu_session_status: AllowedPduSessionStatus {wire_len 4, 34},
            0x18 => ue_usage_setting: UeUsageSetting {wire_len 3, 3},
            0x51 => requested_drx_parameters: DrxParameters {wire_len 3, 3},
            0x70 => eps_nas_message_container: EpsNasMessageContainer {wire_len 4, usize::MAX},
            0x74 => ladn_indication: LadnIndication {wire_len 3, 811},
            0x80 => payload_container_type: PayloadContainerType [tv1] {wire_len 1, 1},
            0x7B => payload_container: PayloadContainer {wire_len 4, 65538},
            0x90 => network_slicing_indication: NetworkSlicingIndication [tv1] {wire_len 1, 1},
            0x53 => fgs_update_type: UpdateType {wire_len 3, 3},
            0x41 => mobile_station_classmark_2: MobileStationClassmark2 {wire_len 5, 5},
            0x42 => supported_codecs: SupportedCodecList {wire_len 5, usize::MAX},
            0x71 => nas_message_container: MessageContainer {wire_len 4, usize::MAX},
            0x60 => eps_bearer_context_status: EpsBearerContextStatus {wire_len 4, 4},
            0x6E => requested_extended_drx_parameters: ExtendedDrxParameters {wire_len 3, 4},
            0x6A => t3324_value: GprsTimer3 {wire_len 3, 3},
            0x67 => ue_radio_capability_id: UeRadioCapabilityId {wire_len 3, usize::MAX},
            0x35 => requested_mapped_nssai: MappedNssai {wire_len 3, 42},
            0x48 => additional_information_requested: AdditionalInformationRequested {wire_len 3, 3},
            0x1A => requested_wus_assistance_information: WusAssistanceInformation {wire_len 3, 3},
            0xA0 => n5gc_indication: N5gcIndication [tv1] {wire_len 1, 1},
            0x30 => requested_nb_n1_mode_drx_parameters: NbN1ModeDrxParameters {wire_len 3, 3},
            0x29 => ue_request_type: UeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: PagingRestriction {wire_len 3, 35},
            0x72 => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x32 => nid: Nid {wire_len 8, 8},
            0x16 => ue_determined_plmn_with_disaster_condition: PlmnIdentity {wire_len 5, 5},
            0x2A => requested_peips_assistance_information: PeipsAssistanceInformation {wire_len 3, 3},
            0x3B => requested_t3512_value: T3512Value {wire_len 3, 3},
            0x3C => unavailability_information: UnavailabilityInformation {wire_len 3, 9},
            0x3F => non_3gpp_path_switching_information: Non3GppPathSwitchingInformation {wire_len 3, 3},
            0x56 => aun3_indication: Aun3Indication {wire_len 3, 3},
            0x64 => requested_lp_wusps_assistance_information: LpWuspsAssistanceInformation {wire_len 3, 3}
        }
    }
}

nas_message! {
    /// Registration Accept (TS 24.501 §8.2.7).
    ///
    /// ```
    /// use oxirush_nas::identity::{Guti5g, Plmn};
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // An ACCEPT on 3GPP access, with the 5G-GUTI that the AMF assigns
    /// let plmn = Plmn::new("208", "93").unwrap();
    /// let guti = Guti5g::new(plmn, 0xca, 0x3fe, 0, 0x1122_3344).unwrap();
    /// let result = RegistrationResult::from_result(RegistrationResultValue::ThreeGppAccess);
    /// let accept = RegistrationAccept::new(result)
    ///     .with_fg_guti(MobileIdentity::from_guti(guti));
    /// let octets = Message::new_5gmm(accept).encode().unwrap();
    /// assert_eq!(hex::encode(octets), "7e0042010177000bf202f839caff8011223344");
    /// ```
    pub struct RegistrationAccept {
        mandatory {
            fgs_registration_result: RegistrationResult {wire_len 2, 2}
        }
        optional {
            0x77 => fg_guti: MobileIdentity {wire_len 14, 14},
            0x4A => equivalent_plmns: PlmnList {wire_len 5, 47},
            0x54 => tai_list: TrackingAreaIdentityList {wire_len 9, 114},
            0x15 => allowed_nssai: Nssai {wire_len 4, 74},
            0x11 => rejected_nssai: RejectedNssai {wire_len 4, 42},
            0x31 => configured_nssai: Nssai {wire_len 4, 146},
            0x21 => fgs_network_feature_support: NetworkFeatureSupport {wire_len 3, 6},
            0x50 => pdu_session_status: PduSessionStatus {wire_len 4, 34},
            0x26 => pdu_session_reactivation_result: PduSessionReactivationResult {wire_len 4, 34},
            0x72 => pdu_session_reactivation_result_error_cause: PduSessionReactivationResultErrorCause {wire_len 5, 515},
            0x79 => ladn_information: LadnInformation {wire_len 13, 1715},
            0xB0 => mico_indication: MicoIndication [tv1] {wire_len 1, 1},
            0x90 => network_slicing_indication: NetworkSlicingIndication [tv1] {wire_len 1, 1},
            0x27 => service_area_list: ServiceAreaList {wire_len 6, 114},
            0x5E => t3512_value: T3512Value {wire_len 3, 3},
            0x5D => non_3gpp_de_registration_timer_value: GprsTimer2 {wire_len 3, 3},
            0x16 => t3502_value: GprsTimer2 {wire_len 3, 3},
            0x34 => emergency_number_list: EmergencyNumberList {wire_len 5, 50},
            0x7A => extended_emergency_number_list: ExtendedEmergencyNumberList {wire_len 7, 65538},
            0x73 => sor_transparent_container: SorTransparentContainer {wire_len 20, usize::MAX},
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0xA0 => nssai_inclusion_mode: NssaiInclusionMode [tv1] {wire_len 1, 1},
            0x76 => operator_defined_access_category_definitions: OperatorDefinedAccessCategoryDefinitions {wire_len 3, 8323},
            0x51 => negotiated_drx_parameters: DrxParameters {wire_len 3, 3},
            0xD0 => non_3gpp_nw_policies: Non3GppNwProvidedPolicies [tv1] {wire_len 1, 1},
            0x60 => eps_bearer_context_status: EpsBearerContextStatus {wire_len 4, 4},
            0x6E => negotiated_extended_drx_parameters: ExtendedDrxParameters {wire_len 3, 4},
            0x6C => t3447_value: GprsTimer3 {wire_len 3, 3},
            0x6B => t3448_value: GprsTimer2 {wire_len 3, 3},
            0x6A => t3324_value: GprsTimer3 {wire_len 3, 3},
            0x67 => ue_radio_capability_id: UeRadioCapabilityId {wire_len 3, usize::MAX},
            0xE0 => ue_radio_capability_id_deletion_indication: UeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x39 => pending_nssai: Nssai {wire_len 4, 146},
            0x74 => ciphering_key_data: CipheringKeyData {wire_len 34, usize::MAX},
            0x75 => cag_information_list: CagInformationList {wire_len 3, usize::MAX},
            0x1B => truncated_fg_s_tmsi_configuration: Truncated5gSTmsiConfiguration {wire_len 3, 3},
            0x1C => negotiated_wus_assistance_information: WusAssistanceInformation {wire_len 3, 3},
            0x29 => negotiated_nb_n1_mode_drx_parameters: NbN1ModeDrxParameters {wire_len 3, 3},
            0x68 => extended_rejected_nssai: ExtendedRejectedNssai {wire_len 5, 90},
            0x7B => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x33 => negotiated_peips_assistance_information: PeipsAssistanceInformation {wire_len 3, 3},
            0x35 => fgs_additional_request_result: AdditionalRequestResult {wire_len 3, 3},
            0x70 => nssrg_information: NssrgInformation {wire_len 7, 4099},
            0x14 => disaster_roaming_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x2C => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x13 => list_of_plmns_to_be_used_in_disaster_condition: ListOfPlmnsToBeUsedInDisasterCondition {wire_len 2, usize::MAX},
            0x1D => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 9, 114},
            0x1E => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 9, 114},
            0x71 => extended_cag_information_list: ExtendedCagInformationList {wire_len 3, usize::MAX},
            0x7C => nsag_information: NsagInformation {wire_len 9, 3143},
            0x3D => equivalent_snpns: SnpnList {wire_len 11, 137},
            0x32 => nid: Nid {wire_len 8, 8},
            0x7D => registration_accept_type_6_ie_container: Type6IeContainer {wire_len 6, 65538},
            0x4B => ran_timing_synchronization: RanTimingSynchronization {wire_len 3, 3},
            0x4C => alternative_nssai: AlternativeNssai {wire_len 2, 146},
            0x4F => discontinuous_coverage_maximum_time_offset: GprsTimer3 {wire_len 3, 3},
            0x5B => s_nssai_time_validity_information: SNssaiTimeValidityInformation {wire_len 23, 257},
            0x3C => unavailability_configuration: UnavailabilityConfiguration {wire_len 3, 6},
            0x5C => feature_authorization_indication: FeatureAuthorizationIndication {wire_len 3, 257},
            0x61 => on_demand_nssai: OnDemandNssai {wire_len 5, 210},
            0x63 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5},
            0x64 => negotiated_lp_wusps_assistance_information: LpWuspsAssistanceInformation {wire_len 3, 3},
            0x80 => lp_wus_status: LpWusStatus [tv1] {wire_len 1, 1}
        }
    }
}

nas_message! {
    /// Registration Complete (TS 24.501 §8.2.8).
    pub struct RegistrationComplete {
        mandatory { }
        optional {
            0x73 => sor_transparent_container: SorTransparentContainer {wire_len 20, 20}
        }
    }
}

nas_message! {
    /// Registration Reject (TS 24.501 §8.2.9).
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // Cause #22, and a T3346 value of ten minutes
    /// let cause = GmmCause::from_cause(GmmCauseValue::Congestion);
    /// let reject = RegistrationReject::new(cause)
    ///     .with_t3346_value(GprsTimer2::from_seconds(600).unwrap());
    /// let reject = Message::new_5gmm(reject);
    /// assert_eq!(reject.encode().unwrap(), [0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x2a]);
    /// let shown = "5GMM RegistrationReject (5gmm-cause: #22 (Congestion), t3346-value: 10 min)";
    /// assert_eq!(reject.to_string(), shown);
    /// ```
    pub struct RegistrationReject {
        mandatory {
            fgmm_cause: GmmCause {wire_len 1, 1}
        }
        optional {
            0x5F => t3346_value: GprsTimer2 {wire_len 3, 3},
            0x16 => t3502_value: GprsTimer2 {wire_len 3, 3},
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0x69 => rejected_nssai: RejectedNssai {wire_len 4, 42},
            0x75 => cag_information_list: CagInformationList {wire_len 3, usize::MAX},
            0x68 => extended_rejected_nssai: ExtendedRejectedNssai {wire_len 5, 90},
            0x2C => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x71 => extended_cag_information_list: ExtendedCagInformationList {wire_len 3, usize::MAX},
            0x3A => lower_bound_timer_value: GprsTimer3 {wire_len 3, 3},
            0x1D | 0x3B => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 9, 114},
            0x1E | 0x3C => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 9, 114},
            0x3E => n3iwf_identifier: N3iwfIdentifier {wire_len 7, usize::MAX},
            0x4D => tnan_information: TnanInformation {wire_len 3, usize::MAX},
            0x62 => extended_5gmm_cause: ExtendedGmmCause {wire_len 3, 3},
            0x63 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5}
        }
    }
}

nas_message! {
    /// Deregistration Request from UE (TS 24.501 §8.2.12).
    pub struct DeregistrationRequestUeOriginating {
        mandatory {
            de_registration_type: DeRegistrationType [low_half_first],
            ngksi: KeySetIdentifier [high_half_last],
            fgs_mobile_identity: MobileIdentity {wire_len 6, usize::MAX}
        }
        optional {
            0x3C => unavailability_information: UnavailabilityInformation {wire_len 3, 9},
            0x71 => nas_message_container: MessageContainer {wire_len 4, usize::MAX}
        }
    }
}

nas_message! {
    /// Deregistration Request to UE (TS 24.501 §8.2.14).
    pub struct DeregistrationRequestUeTerminated {
        mandatory {
            de_registration_type: DeRegistrationType {wire_len 1, 1}
        }
        optional {
            0x58 => fgmm_cause: GmmCause {wire_len 2, 2},
            0x5F => t3346_value: GprsTimer2 {wire_len 3, 3},
            0x6D => rejected_nssai: RejectedNssai {wire_len 4, 42},
            0x75 => cag_information_list: CagInformationList {wire_len 3, usize::MAX},
            0x68 => extended_rejected_nssai: ExtendedRejectedNssai {wire_len 5, 90},
            0x2C => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x71 => extended_cag_information_list: ExtendedCagInformationList {wire_len 3, usize::MAX},
            0x3A => lower_bound_timer_value: GprsTimer3 {wire_len 3, 3},
            0x1D | 0x3B => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 9, 114},
            0x1E | 0x3C => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 9, 114},
            0x63 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5}
        }
    }
}

nas_message_empty!(
    /// Deregistration Accept from UE (TS 24.501 §8.2.13).
    DeregistrationAcceptUeOriginating
);
nas_message_empty!(
    /// Deregistration Accept to UE (TS 24.501 §8.2.15).
    DeregistrationAcceptUeTerminated
);
nas_message_empty!(
    /// Configuration Update Complete (TS 24.501 §8.2.20).
    ConfigurationUpdateComplete
);

nas_message! {
    /// Service Request (TS 24.501 §8.2.16).
    pub struct ServiceRequest {
        mandatory {
            ngksi: KeySetIdentifier [low_half_first],
            service_type: ServiceType [high_half_last],
            fg_s_tmsi: MobileIdentity {wire_len 9, 9}
        }
        optional {
            0x40 => uplink_data_status: UplinkDataStatus {wire_len 4, 34},
            0x50 => pdu_session_status: PduSessionStatus {wire_len 4, 34},
            0x25 => allowed_pdu_session_status: AllowedPduSessionStatus {wire_len 4, 34},
            0x71 => nas_message_container: MessageContainer {wire_len 4, usize::MAX},
            0x29 => ue_request_type: UeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: PagingRestriction {wire_len 3, 35}
        }
    }
}

nas_message! {
    /// Service Reject (TS 24.501 §8.2.18).
    pub struct ServiceReject {
        mandatory {
            fgmm_cause: GmmCause {wire_len 1, 1}
        }
        optional {
            0x50 => pdu_session_status: PduSessionStatus {wire_len 4, 34},
            0x5F => t3346_value: GprsTimer2 {wire_len 3, 3},
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0x6B => t3448_value: GprsTimer2 {wire_len 3, 3},
            0x75 => cag_information_list: CagInformationList {wire_len 3, usize::MAX},
            0x2C => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x71 => extended_cag_information_list: ExtendedCagInformationList {wire_len 3, usize::MAX},
            0x3A => lower_bound_timer_value: GprsTimer3 {wire_len 3, 3},
            0x1D | 0x3B => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 9, 114},
            0x1E | 0x3C => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 9, 114},
            0x63 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 4, 5}
        }
    }
}

nas_message! {
    /// Service Accept (TS 24.501 §8.2.17).
    pub struct ServiceAccept {
        mandatory { }
        optional {
            0x50 => pdu_session_status: PduSessionStatus {wire_len 4, 34},
            0x26 => pdu_session_reactivation_result: PduSessionReactivationResult {wire_len 4, 34},
            0x72 => pdu_session_reactivation_result_error_cause: PduSessionReactivationResultErrorCause {wire_len 5, 515},
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0x6B => t3448_value: GprsTimer2 {wire_len 3, 3},
            0x34 => fgs_additional_request_result: AdditionalRequestResult {wire_len 3, 3},
            0x1D => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_roaming: TrackingAreaIdentityList {wire_len 9, 114},
            0x1E => forbidden_tais_for_the_list_of_fgs_forbidden_tracking_areas_for_regional_provision_of_service: TrackingAreaIdentityList {wire_len 9, 114}
        }
    }
}

nas_message! {
    /// Configuration Update Command (TS 24.501 §8.2.19).
    pub struct ConfigurationUpdateCommand {
        mandatory { }
        optional {
            0xD0 => configuration_update_indication: ConfigurationUpdateIndication [tv1] {wire_len 1, 1},
            0x77 => fg_guti: MobileIdentity {wire_len 14, 14},
            0x54 => tai_list: TrackingAreaIdentityList {wire_len 9, 114},
            0x15 => allowed_nssai: Nssai {wire_len 4, 74},
            0x27 => service_area_list: ServiceAreaList {wire_len 6, 114},
            0x43 => full_name_for_network: NetworkName {wire_len 3, usize::MAX},
            0x45 => short_name_for_network: NetworkName {wire_len 3, usize::MAX},
            0x46 => local_time_zone: TimeZone {wire_len 2, 2},
            0x47 => universal_time_and_local_time_zone: TimeZoneAndTime {wire_len 8, 8},
            0x49 => network_daylight_saving_time: DaylightSavingTime {wire_len 3, 3},
            0x79 => ladn_information: LadnInformation {wire_len 3, 1715},
            0xB0 => mico_indication: MicoIndication [tv1] {wire_len 1, 1},
            0x90 => network_slicing_indication: NetworkSlicingIndication [tv1] {wire_len 1, 1},
            0x31 => configured_nssai: Nssai {wire_len 4, 146},
            0x11 => rejected_nssai: RejectedNssai {wire_len 4, 42},
            0x76 => operator_defined_access_category_definitions: OperatorDefinedAccessCategoryDefinitions {wire_len 3, 8323},
            0xF0 => sms_indication: SmsIndication [tv1] {wire_len 1, 1},
            0x6C => t3447_value: GprsTimer3 {wire_len 3, 3},
            0x75 => cag_information_list: CagInformationList {wire_len 3, usize::MAX},
            0x67 => ue_radio_capability_id: UeRadioCapabilityId {wire_len 3, usize::MAX},
            0xA0 => ue_radio_capability_id_deletion_indication: UeRadioCapabilityIdDeletionIndication [tv1] {wire_len 1, 1},
            0x44 => fgs_registration_result: RegistrationResult {wire_len 3, 3},
            0x1B => truncated_fg_s_tmsi_configuration: Truncated5gSTmsiConfiguration {wire_len 3, 3},
            0xC0 => additional_configuration_indication: AdditionalConfigurationIndication [tv1] {wire_len 1, 1},
            0x68 => extended_rejected_nssai: ExtendedRejectedNssai {wire_len 5, 90},
            0x72 => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x70 => nssrg_information: NssrgInformation {wire_len 7, 4099},
            0x14 => disaster_roaming_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x2C => disaster_return_wait_range: RegistrationWaitRange {wire_len 4, 4},
            0x13 => list_of_plmns_to_be_used_in_disaster_condition: ListOfPlmnsToBeUsedInDisasterCondition {wire_len 2, usize::MAX},
            0x71 => extended_cag_information_list: ExtendedCagInformationList {wire_len 3, usize::MAX},
            0x1F => updated_peips_assistance_information: PeipsAssistanceInformation {wire_len 3, 3},
            0x73 => nsag_information: NsagInformation {wire_len 9, 3143},
            0xE0 => priority_indicator: PriorityIndicator [tv1] {wire_len 1, 1},
            0x4B => ran_timing_synchronization: RanTimingSynchronization {wire_len 3, 3},
            0x78 => extended_ladn_information: ExtendedLadnInformation {wire_len 3, 1787},
            0x4C => alternative_nssai: AlternativeNssai {wire_len 2, 146},
            0x7B => s_nssai_location_validity_information: SNssaiLocationValidityInformation {wire_len 17, 38611},
            0x5B => s_nssai_time_validity_information: SNssaiTimeValidityInformation {wire_len 23, 257},
            0x4F => discontinuous_coverage_maximum_time_offset: GprsTimer3 {wire_len 3, 3},
            0x74 => partially_allowed_nssai: PartialNssai {wire_len 3, 808},
            0x7A => partially_rejected_nssai: PartialNssai {wire_len 3, 808},
            0x5C => feature_authorization_indication: FeatureAuthorizationIndication {wire_len 3, 257},
            0x61 => on_demand_nssai: OnDemandNssai {wire_len 5, 210},
            0x63 => access_technology_utilization_control: AccessTechnologyUtilizationControl {wire_len 2, 5},
            0x64 => updated_lp_wusps_assistance_information: LpWuspsAssistanceInformation {wire_len 2, 3},
            0x80 => lp_wus_status: LpWusStatus [tv1] {wire_len 1, 1}
        }
    }
}

nas_message! {
    /// Authentication Request (TS 24.501 §8.2.1).
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // A challenge of 5G AKA under ngKSI 0: the ABBA, RAND and AUTN
    /// let ngksi = KeySetIdentifierValue::Native(0);
    /// let ngksi = KeySetIdentifier::from_key_set_identifier(ngksi).unwrap();
    /// let request = AuthenticationRequest::new(ngksi, Abba::new(vec![0, 0]))
    ///     .with_authentication_parameter_rand(AuthenticationParameterRand::from_rand([0x23; 16]))
    ///     .with_authentication_parameter_autn(AuthenticationParameterAutn::from_autn([0x55; 16]));
    /// let octets = Message::new_5gmm(request).encode().unwrap();
    ///
    /// // The header, ngKSI, the ABBA, then RAND after its IEI and AUTN after its
    /// // IEI and length
    /// assert_eq!(hex::encode(&octets[..8]), "7e00560002000021");
    /// assert_eq!(hex::encode(&octets[24..26]), "2010");
    /// assert_eq!(octets.len(), 42);
    /// ```
    pub struct AuthenticationRequest {
        mandatory {
            ngksi: KeySetIdentifier {wire_len 1, 1},
            abba: Abba {wire_len 3, usize::MAX}
        }
        optional {
            0x21 => authentication_parameter_rand: AuthenticationParameterRand {wire_len 17, 17},
            0x20 => authentication_parameter_autn: AuthenticationParameterAutn {wire_len 18, 18},
            0x78 => eap_message: EapMessage {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Authentication Response (TS 24.501 §8.2.2).
    pub struct AuthenticationResponse {
        mandatory { }
        optional {
            0x2D => authentication_response_parameter: AuthenticationResponseParameter {wire_len 18, 18},
            0x78 => eap_message: EapMessage {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Authentication Reject (TS 24.501 §8.2.5).
    pub struct AuthenticationReject {
        mandatory { }
        optional {
            0x78 => eap_message: EapMessage {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Authentication Failure (TS 24.501 §8.2.4).
    pub struct AuthenticationFailure {
        mandatory {
            fgmm_cause: GmmCause {wire_len 1, 1}
        }
        optional {
            0x30 => authentication_failure_parameter: AuthenticationFailureParameter {wire_len 16, 16}
        }
    }
}

nas_message! {
    /// Authentication Result (TS 24.501 §8.2.3).
    pub struct AuthenticationResult {
        mandatory {
            ngksi: KeySetIdentifier {wire_len 1, 1},
            eap_message: EapMessage {wire_len 6, 1502}
        }
        optional {
            0x38 => abba: Abba {wire_len 4, usize::MAX},
            0x55 => aun3_device_security_key: Aun3DeviceSecurityKey {wire_len 36, usize::MAX}
        }
    }
}

nas_message! {
    /// Identity Request (TS 24.501 §8.2.21).
    pub struct IdentityRequest {
        mandatory {
            identity_type: IdentityType {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// Identity Response (TS 24.501 §8.2.22).
    pub struct IdentityResponse {
        mandatory {
            mobile_identity: MobileIdentity {wire_len 3, usize::MAX}
        }
        optional { }
    }
}

nas_message! {
    /// Security Mode Command (TS 24.501 §8.2.25).
    ///
    /// ```
    /// use oxirush_nas::identity::Algorithm;
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // NEA2 and NIA2 under ngKSI 0, and the UE security capability of the
    /// // REGISTRATION REQUEST replayed: EA0 and EA2, IA2
    /// let algorithms =
    ///     SecurityAlgorithms::from_algorithms(Algorithm::Aes, Algorithm::Aes);
    /// let ngksi = KeySetIdentifier::from_key_set_identifier(KeySetIdentifierValue::Native(0)).unwrap();
    /// let capability = UeSecurityCapability::new(vec![0xa0, 0x20]);
    /// let command = SecurityModeCommand::new(algorithms, ngksi, capability);
    ///
    /// // Plain here: SecurityContext::protect sends it integrity protected
    /// let octets = Message::new_5gmm(command).encode().unwrap();
    /// assert_eq!(hex::encode(octets), "7e005d220002a020");
    /// ```
    pub struct SecurityModeCommand {
        mandatory {
            selected_nas_security_algorithms: SecurityAlgorithms {wire_len 1, 1},
            ngksi: KeySetIdentifier {wire_len 1, 1},
            replayed_ue_security_capabilities: UeSecurityCapability {wire_len 3, 9}
        }
        optional {
            0xE0 => imeisv_request: ImeisvRequest [tv1] {wire_len 1, 1},
            0x57 => selected_eps_nas_security_algorithms: EpsNasSecurityAlgorithms {wire_len 2, 2},
            0x36 => additional_5g_security_information: Additional5gSecurityInformation {wire_len 3, 3},
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0x38 => abba: Abba {wire_len 4, usize::MAX},
            0x19 => replayed_s1_ue_security_capabilities: S1UeSecurityCapability {wire_len 4, 7},
            0x55 => aun3_device_security_key: Aun3DeviceSecurityKey {wire_len 36, 257}
        }
    }
}

nas_message! {
    /// Security Mode Complete (TS 24.501 §8.2.26).
    pub struct SecurityModeComplete {
        mandatory { }
        optional {
            0x77 => imeisv: MobileIdentity {wire_len 12, 12},
            0x71 => nas_message_container: MessageContainer {wire_len 4, usize::MAX},
            0x78 => non_imeisv_pei: MobileIdentity {wire_len 7, usize::MAX}
        }
    }
}

nas_message! {
    /// Security Mode Reject (TS 24.501 §8.2.27).
    pub struct SecurityModeReject {
        mandatory {
            fgmm_cause: GmmCause {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// 5GMM Status (TS 24.501 §8.2.29).
    pub struct GmmStatus {
        mandatory {
            fgmm_cause: GmmCause {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// Notification (TS 24.501 §8.2.23).
    pub struct Notification {
        mandatory {
            access_type: AccessType {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// Notification Response (TS 24.501 §8.2.24).
    pub struct NotificationResponse {
        mandatory { }
        optional {
            0x50 => pdu_session_status: PduSessionStatus {wire_len 4, 34}
        }
    }
}

nas_message! {
    /// UL NAS Transport (TS 24.501 §8.2.10).
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // A PDU SESSION ESTABLISHMENT REQUEST of PDU session 5 in the payload container
    /// let rate = IntegrityProtectionMaximumDataRate::new(0xffff);
    /// let request = Message::new_5gsm(PduSessionEstablishmentRequest::new(rate), 5, 1);
    /// let transport = UlNasTransport::new(
    ///     PayloadContainerType::from_kind(PayloadContainerKind::N1SmInformation),
    ///     PayloadContainer::from_n1_sm_message(&request).unwrap(),
    /// )
    /// .with_pdu_session_id(PduSessionIdentity2::from_pdu_session_id(5));
    /// let octets = Message::new_5gmm(transport).encode().unwrap();
    /// assert_eq!(hex::encode(octets), "7e00670100062e0501c1ffff1205");
    /// ```
    pub struct UlNasTransport {
        mandatory {
            payload_container_type: PayloadContainerType {wire_len 1, 1},
            payload_container: PayloadContainer {wire_len 3, 65537}
        }
        optional {
            0x12 => pdu_session_id: PduSessionIdentity2 {wire_len 2, 2},
            0x59 => old_pdu_session_id: PduSessionIdentity2 {wire_len 2, 2},
            0x80 => request_type: RequestType [tv1] {wire_len 1, 1},
            0x22 => s_nssai: SNssai {wire_len 3, 10},
            0x25 => dnn: Dnn {wire_len 3, 102},
            0x24 => additional_information: AdditionalInformation {wire_len 3, usize::MAX},
            0xA0 => ma_pdu_session_information: MaPduSessionInformation [tv1] {wire_len 1, 1},
            0xF0 => release_assistance_indication: ReleaseAssistanceIndication [tv1] {wire_len 1, 1},
            0x4E => non_3gpp_access_path_switching_indication: Non3GppAccessPathSwitchingIndication {wire_len 3, 3},
            0x5A => alternative_s_nssai: SNssai {wire_len 3, 10},
            0x90 => payload_container_information: PayloadContainerInformation [tv1] {wire_len 1, 1}
        }
    }
}

nas_message! {
    /// DL NAS Transport (TS 24.501 §8.2.11).
    pub struct DlNasTransport {
        mandatory {
            payload_container_type: PayloadContainerType {wire_len 1, 1},
            payload_container: PayloadContainer {wire_len 3, 65537}
        }
        optional {
            0x12 => pdu_session_id: PduSessionIdentity2 {wire_len 2, 2},
            0x24 => additional_information: AdditionalInformation {wire_len 3, usize::MAX},
            0x58 => fgmm_cause: GmmCause {wire_len 2, 2},
            0x37 => back_off_timer_value: GprsTimer3 {wire_len 3, 3},
            0x3A => lower_bound_timer_value: GprsTimer3 {wire_len 3, 3}
        }
    }
}

nas_message! {
    /// Control Plane Service Request (TS 24.501 §8.2.30).
    pub struct ControlPlaneServiceRequest {
        mandatory {
            control_plane_service_type: ControlPlaneServiceType [low_half_first],
            ngksi: KeySetIdentifier [high_half_last],
        }
        optional {
            0x6F => ciot_small_data_container: CiotSmallDataContainer {wire_len 4, 257},
            0x80 => payload_container_type: PayloadContainerType [tv1] {wire_len 1, 1},
            0x7B => payload_container: PayloadContainer {wire_len 4, 65538},
            0x12 => pdu_session_id: PduSessionIdentity2 {wire_len 2, 2},
            0x50 => pdu_session_status: PduSessionStatus {wire_len 4, 34},
            0xF0 => release_assistance_indication: ReleaseAssistanceIndication [tv1] {wire_len 1, 1},
            0x40 => uplink_data_status: UplinkDataStatus {wire_len 4, 34},
            0x71 => nas_message_container: MessageContainer {wire_len 4, usize::MAX},
            0x24 => additional_information: AdditionalInformation {wire_len 3, usize::MAX},
            0x25 => allowed_pdu_session_status: AllowedPduSessionStatus {wire_len 4, 34},
            0x29 => ue_request_type: UeRequestType {wire_len 3, 3},
            0x28 => paging_restriction: PagingRestriction {wire_len 3, 35}
        }
    }
}

impl ControlPlaneServiceRequest {
    /// Whether the message uses the CIoT small data container without any other optional IE.
    pub fn ciot_small_data_container_is_exclusive(&self) -> bool {
        self.ciot_small_data_container.is_none()
            || (self.payload_container_type.is_none()
                && self.payload_container.is_none()
                && self.pdu_session_id.is_none()
                && self.pdu_session_status.is_none()
                && self.release_assistance_indication.is_none()
                && self.uplink_data_status.is_none()
                && self.nas_message_container.is_none()
                && self.additional_information.is_none()
                && self.allowed_pdu_session_status.is_none()
                && self.ue_request_type.is_none()
                && self.paging_restriction.is_none())
    }
}

nas_message! {
    /// Network Slice-Specific Authentication Command (TS 24.501 §8.2.31).
    pub struct NetworkSliceSpecificAuthenticationCommand {
        mandatory {
            s_nssai: SNssai {wire_len 2, 5},
            eap_message: EapMessage {wire_len 6, 1502}
        }
        optional { }
    }
}

nas_message! {
    /// Network Slice-Specific Authentication Complete (TS 24.501 §8.2.32).
    pub struct NetworkSliceSpecificAuthenticationComplete {
        mandatory {
            s_nssai: SNssai {wire_len 2, 5},
            eap_message: EapMessage {wire_len 6, 1502}
        }
        optional { }
    }
}

nas_message! {
    /// Network Slice-Specific Authentication Result (TS 24.501 §8.2.33).
    pub struct NetworkSliceSpecificAuthenticationResult {
        mandatory {
            s_nssai: SNssai {wire_len 2, 5},
            eap_message: EapMessage {wire_len 6, 1502}
        }
        optional { }
    }
}

nas_message! {
    /// Relay Key Request (TS 24.501 §8.2.34).
    pub struct RelayKeyRequest {
        mandatory {
            prose_relay_transaction_identity: ProseRelayTransactionIdentity {wire_len 1, 1},
            relay_key_request_parameters: RelayKeyRequestParameters {wire_len 22, 65537}
        }
        optional { }
    }
}

nas_message! {
    /// Relay Key Accept (TS 24.501 §8.2.35).
    pub struct RelayKeyAccept {
        mandatory {
            prose_relay_transaction_identity: ProseRelayTransactionIdentity {wire_len 1, 1},
            relay_key_response_parameters: RelayKeyResponseParameters {wire_len 51, 65537}
        }
        optional {
            0x78 => eap_message: EapMessage {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Relay Key Reject (TS 24.501 §8.2.36).
    pub struct RelayKeyReject {
        mandatory {
            prose_relay_transaction_identity: ProseRelayTransactionIdentity {wire_len 1, 1}
        }
        optional {
            0x78 => eap_message: EapMessage {wire_len 7, 1503}
        }
    }
}

nas_message! {
    /// Relay Authentication Request (TS 24.501 §8.2.37).
    pub struct RelayAuthenticationRequest {
        mandatory {
            prose_relay_transaction_identity: ProseRelayTransactionIdentity {wire_len 1, 1},
            eap_message: EapMessage {wire_len 7, 1503}
        }
        optional { }
    }
}

nas_message! {
    /// Relay Authentication Response (TS 24.501 §8.2.38).
    pub struct RelayAuthenticationResponse {
        mandatory {
            prose_relay_transaction_identity: ProseRelayTransactionIdentity {wire_len 1, 1},
            eap_message: EapMessage {wire_len 6, 1502}
        }
        optional { }
    }
}

// ── 5GSM Messages ──────────────────────────────────────────────────────────────

nas_message! {
    /// PDU Session Establishment Request (TS 24.501 §8.3.1).
    pub struct PduSessionEstablishmentRequest {
        mandatory {
            integrity_protection_maximum_data_rate: IntegrityProtectionMaximumDataRate {wire_len 2, 2}
        }
        optional {
            0x90 => pdu_session_type: PduSessionType [tv1] {wire_len 1, 1},
            0xA0 => ssc_mode: SscMode [tv1] {wire_len 1, 1},
            0x28 => fgsm_capability: GsmCapability {wire_len 3, 15},
            0x55 => maximum_number_of_supported_packet_filters: MaximumNumberOfSupportedPacketFilters {wire_len 3, 3},
            0xB0 => always_on_pdu_session_requested: AlwaysOnPduSessionRequested [tv1] {wire_len 1, 1},
            0x39 => sm_pdu_dn_request_container: SmPduDnRequestContainer {wire_len 3, 255},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x66 => ip_header_compression_configuration: IpHeaderCompressionConfiguration {wire_len 5, 257},
            0x6E => ds_tt_ethernet_port_mac_address: DsTtEthernetPortMacAddress {wire_len 8, 8},
            0x6F => ue_ds_tt_residence_time: UeDsTtResidenceTime {wire_len 10, 10},
            0x74 => port_management_information_container: PortManagementInformationContainer {wire_len 8, 65538},
            0x1F => ethernet_header_compression_configuration: EthernetHeaderCompressionConfiguration {wire_len 3, 3},
            0x29 => suggested_interface_identifier: PduAddress {wire_len 11, 11},
            0x72 => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x70 => requested_mbs_container: RequestedMbsContainer {wire_len 8, 65538},
            0x34 => pdu_session_pair_id: PduSessionPairId {wire_len 3, 3},
            0x35 => rsn: Rsn {wire_len 3, 3},
            0x36 => ursp_rule_enforcement_reports: UrspRuleEnforcementReports {wire_len 4, usize::MAX}
        }
    }
}

nas_message! {
    /// PDU Session Establishment Accept (TS 24.501 §8.3.2).
    pub struct PduSessionEstablishmentAccept {
        mandatory {
            selected_pdu_session_type: PduSessionType [low_half_first],
            selected_ssc_mode: SscMode [high_half_last],
            authorized_qos_rules: QosRules {wire_len 6, 65538},
            session_ambr: SessionAmbr {wire_len 7, 7}
        }
        optional {
            0x59 => fgsm_cause: GsmCause {wire_len 2, 2},
            0x29 => pdu_address: PduAddress {wire_len 7, 31},
            0x56 => rq_timer_value: GprsTimer {wire_len 2, 2},
            0x22 => s_nssai: SNssai {wire_len 3, 10},
            0x80 => always_on_pdu_session_indication: AlwaysOnPduSessionIndication [tv1] {wire_len 1, 1},
            0x75 => mapped_eps_bearer_contexts: MappedEpsBearerContexts {wire_len 7, 65538},
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0x79 => authorized_qos_flow_descriptions: QosFlowDescriptions {wire_len 6, 65538},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x25 => dnn: Dnn {wire_len 3, 102},
            0x17 => fgsm_network_feature_support: GsmNetworkFeatureSupport {wire_len 3, 15},
            0x18 => serving_plmn_rate_control: ServingPlmnRateControl {wire_len 4, 4},
            0x77 => atsss_container: AtsssContainer {wire_len 3, 65538},
            0xC0 => control_plane_only_indication: ControlPlaneOnlyIndication [tv1] {wire_len 1, 1},
            0x66 => ip_header_compression_configuration: IpHeaderCompressionConfiguration {wire_len 5, 257},
            0x1F => ethernet_header_compression_configuration: EthernetHeaderCompressionConfiguration {wire_len 3, 3},
            0x72 => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x71 => received_mbs_container: ReceivedMbsContainer {wire_len 9, 65538},
            0x70 => n3_qai: N3Qai {wire_len 9, usize::MAX},
            0x73 => protocol_description: ProtocolDescription {wire_len 6, usize::MAX},
            0x38 => ecn_marking_for_l4s_indication: EcnMarkingForL4sIndication {wire_len 2, 257}
        }
    }
}

nas_message! {
    /// PDU Session Establishment Reject (TS 24.501 §8.3.3).
    pub struct PduSessionEstablishmentReject {
        mandatory {
            fgsm_cause: GsmCause {wire_len 1, 1}
        }
        optional {
            0x37 => back_off_timer_value: GprsTimer3 {wire_len 3, 3},
            0xF0 => allowed_ssc_mode: AllowedSscMode [tv1] {wire_len 1, 1},
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0x61 => fgsm_congestion_re_attempt_indicator: GsmCongestionReAttemptIndicator {wire_len 3, 3},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x1D => re_attempt_indicator: ReAttemptIndicator {wire_len 3, 3},
            0x72 => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x77 => atsss_container: AtsssContainer {wire_len 3, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Authentication Command (TS 24.501 §8.3.4).
    pub struct PduSessionAuthenticationCommand {
        mandatory {
            eap_message: EapMessage {wire_len 6, 1502}
        }
        optional {
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Authentication Complete (TS 24.501 §8.3.5).
    pub struct PduSessionAuthenticationComplete {
        mandatory {
            eap_message: EapMessage {wire_len 6, 1502}
        }
        optional {
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Authentication Result (TS 24.501 §8.3.6).
    pub struct PduSessionAuthenticationResult {
        mandatory { }
        optional {
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Modification Request (TS 24.501 §8.3.7).
    pub struct PduSessionModificationRequest {
        mandatory { }
        optional {
            0x28 => fgsm_capability: GsmCapability {wire_len 3, 15},
            0x59 => fgsm_cause: GsmCause {wire_len 2, 2},
            0x55 => maximum_number_of_supported_packet_filters: MaximumNumberOfSupportedPacketFilters {wire_len 3, 3},
            0xB0 => always_on_pdu_session_requested: AlwaysOnPduSessionRequested [tv1] {wire_len 1, 1},
            0x13 => integrity_protection_maximum_data_rate: IntegrityProtectionMaximumDataRate {wire_len 3, 3},
            0x7A => requested_qos_rules: QosRules {wire_len 7, 65538},
            0x79 => requested_qos_flow_descriptions: QosFlowDescriptions {wire_len 6, 65538},
            0x75 => mapped_eps_bearer_contexts: MappedEpsBearerContexts {wire_len 7, 65538},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x74 => port_management_information_container: PortManagementInformationContainer {wire_len 4, 65538},
            0x66 => ip_header_compression_configuration: IpHeaderCompressionConfiguration {wire_len 5, 257},
            0x1F => ethernet_header_compression_configuration: EthernetHeaderCompressionConfiguration {wire_len 3, 3},
            0x70 => requested_mbs_container: RequestedMbsContainer {wire_len 8, 65538},
            0x72 => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x73 => non_3gpp_delay_budget: Non3GppDelayBudget {wire_len 6, usize::MAX},
            0x36 => ursp_rule_enforcement_reports: UrspRuleEnforcementReports {wire_len 4, usize::MAX},
            0x7C => non_3gpp_device_information: Non3GppDeviceInformation {wire_len 7, usize::MAX}
        }
    }
}

nas_message! {
    /// PDU Session Modification Reject (TS 24.501 §8.3.8).
    pub struct PduSessionModificationReject {
        mandatory {
            fgsm_cause: GsmCause {wire_len 1, 1}
        }
        optional {
            0x37 => back_off_timer_value: GprsTimer3 {wire_len 3, 3},
            0x61 => fgsm_congestion_re_attempt_indicator: GsmCongestionReAttemptIndicator {wire_len 3, 3},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x1D => re_attempt_indicator: ReAttemptIndicator {wire_len 3, 3}
        }
    }
}

nas_message! {
    /// PDU Session Modification Command (TS 24.501 §8.3.9).
    pub struct PduSessionModificationCommand {
        mandatory { }
        optional {
            0x59 => fgsm_cause: GsmCause {wire_len 2, 2},
            0x2A => session_ambr: SessionAmbr {wire_len 8, 8},
            0x56 => rq_timer_value: GprsTimer {wire_len 2, 2},
            0x80 => always_on_pdu_session_indication: AlwaysOnPduSessionIndication [tv1] {wire_len 1, 1},
            0x7A => authorized_qos_rules: QosRules {wire_len 7, 65538},
            0x75 => mapped_eps_bearer_contexts: MappedEpsBearerContexts {wire_len 7, 65538},
            0x79 => authorized_qos_flow_descriptions: QosFlowDescriptions {wire_len 6, 65538},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x77 => atsss_container: AtsssContainer {wire_len 3, 65538},
            0x66 => ip_header_compression_configuration: IpHeaderCompressionConfiguration {wire_len 5, 257},
            0x74 => port_management_information_container: PortManagementInformationContainer {wire_len 4, 65538},
            0x1E => serving_plmn_rate_control: ServingPlmnRateControl {wire_len 4, 4},
            0x1F => ethernet_header_compression_configuration: EthernetHeaderCompressionConfiguration {wire_len 3, 3},
            0x71 => received_mbs_container: ReceivedMbsContainer {wire_len 9, 65538},
            0x72 => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x5A => alternative_s_nssai: SNssai {wire_len 3, 10},
            0x70 => n3_qai: N3Qai {wire_len 9, usize::MAX},
            0x73 => protocol_description: ProtocolDescription {wire_len 6, usize::MAX},
            0x38 => ecn_marking_for_l4s_indication: EcnMarkingForL4sIndication {wire_len 2, 257}
        }
    }
}

nas_message! {
    /// PDU Session Modification Complete (TS 24.501 §8.3.10).
    pub struct PduSessionModificationComplete {
        mandatory { }
        optional {
            0x59 => fgsm_cause: GsmCause,
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0x74 => port_management_information_container: PortManagementInformationContainer {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Modification Command Reject (TS 24.501 §8.3.11).
    pub struct PduSessionModificationCommandReject {
        mandatory {
            fgsm_cause: GsmCause {wire_len 1, 1}
        }
        optional {
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Release Request (TS 24.501 §8.3.12).
    pub struct PduSessionReleaseRequest {
        mandatory { }
        optional {
            0x59 => fgsm_cause: GsmCause {wire_len 2, 2},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Release Reject (TS 24.501 §8.3.13).
    pub struct PduSessionReleaseReject {
        mandatory {
            fgsm_cause: GsmCause {wire_len 1, 1}
        }
        optional {
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// PDU Session Release Command (TS 24.501 §8.3.14).
    pub struct PduSessionReleaseCommand {
        mandatory {
            fgsm_cause: GsmCause {wire_len 1, 1}
        }
        optional {
            0x37 => back_off_timer_value: GprsTimer3 {wire_len 3, 3},
            0x78 => eap_message: EapMessage {wire_len 7, 1503},
            0x61 => fgsm_congestion_re_attempt_indicator: GsmCongestionReAttemptIndicator {wire_len 3, 3},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538},
            0xD0 => access_type: AccessType [tv1] {wire_len 1, 1},
            0x72 => service_level_aa_container: ServiceLevelAaContainer {wire_len 4, 65538},
            0x5A => alternative_s_nssai: SNssai {wire_len 3, 10}
        }
    }
}

nas_message! {
    /// PDU Session Release Complete (TS 24.501 §8.3.15).
    pub struct PduSessionReleaseComplete {
        mandatory { }
        optional {
            0x59 => fgsm_cause: GsmCause {wire_len 2, 2},
            0x7B => extended_protocol_configuration_options: ExtendedProtocolConfigurationOptions {wire_len 4, 65538}
        }
    }
}

nas_message! {
    /// 5GSM Status (TS 24.501 §8.3.16).
    pub struct GsmStatus {
        mandatory {
            fgsm_cause: GsmCause {wire_len 1, 1}
        }
        optional { }
    }
}

nas_message! {
    /// Service-Level Authentication Command (TS 24.501 §8.3.17).
    pub struct ServiceLevelAuthenticationCommand {
        mandatory {
            service_level_aa_container: ServiceLevelAaContainer {wire_len 5, 65538}
        }
        optional { }
    }
}

nas_message! {
    /// Service-Level Authentication Complete (TS 24.501 §8.3.18).
    pub struct ServiceLevelAuthenticationComplete {
        mandatory {
            service_level_aa_container: ServiceLevelAaContainer {wire_len 5, 65538}
        }
        optional { }
    }
}

nas_message! {
    /// Remote UE Report (TS 24.501 §8.3.19).
    pub struct RemoteUeReport {
        mandatory { }
        optional {
            0x76 => remote_ue_context_connected: RemoteUeContextList {wire_len 16, 65538},
            0x70 => remote_ue_context_disconnected: RemoteUeContextList {wire_len 16, 65538}
        }
    }
}

nas_message_empty!(
    /// Remote UE Report Response (TS 24.501 §8.3.20).
    RemoteUeReportResponse
);

// ── Message enums and dispatch ───────────────────────────────────────────────

crate::common::nas_messages! {
    /// Enum over all 5G Mobility Management (5GMM) message types.
    ///
    /// Each variant wraps a message struct defined by the `nas_message!` macro.
    /// Pattern-match to access the inner message fields.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::{GmmCauseValue, GmmMessage, Message};
    ///
    /// // 5GMM STATUS, cause #22
    /// let message = Message::decode(&[0x7e, 0x00, 0x64, 0x16]).unwrap();
    /// let Message::Gmm(_, GmmMessage::FiveGmmStatus(status)) = &message else {
    ///     unreachable!()
    /// };
    /// assert_eq!(status.fgmm_cause.cause(), Some(GmmCauseValue::Congestion));
    /// ```
    pub enum GmmMessage;
    /// 5G Mobility Management (5GMM) message types per TS 24.501 §9.7.
    ///
    /// `u8::from` gives the message type octet, and `From<u8>` reads one: a code
    /// that the table does not have is `Unknown`.
    pub enum GmmMessageType;
    {
        /// Registration request (TS 24.501 §8.2.6).
        RegistrationRequest = 65 => RegistrationRequest,
        /// Registration accept (TS 24.501 §8.2.7).
        RegistrationAccept = 66 => RegistrationAccept,
        /// Registration complete (TS 24.501 §8.2.8).
        RegistrationComplete = 67 => RegistrationComplete,
        /// Registration reject (TS 24.501 §8.2.9).
        RegistrationReject = 68 => RegistrationReject,
        /// De-registration request (UE originating de-registration) (TS 24.501 §8.2.12).
        DeregistrationRequestUeOriginating = 69 => DeregistrationRequestUeOriginating,
        /// De-registration accept (UE originating de-registration) (TS 24.501 §8.2.13).
        DeregistrationAcceptUeOriginating = 70 => DeregistrationAcceptUeOriginating,
        /// De-registration request (UE terminated de-registration) (TS 24.501 §8.2.14).
        DeregistrationRequestUeTerminated = 71 => DeregistrationRequestUeTerminated,
        /// De-registration accept (UE terminated de-registration) (TS 24.501 §8.2.15).
        DeregistrationAcceptUeTerminated = 72 => DeregistrationAcceptUeTerminated,
        /// Service request (TS 24.501 §8.2.16).
        ServiceRequest = 76 => ServiceRequest,
        /// Service reject (TS 24.501 §8.2.18).
        ServiceReject = 77 => ServiceReject,
        /// Service accept (TS 24.501 §8.2.17).
        ServiceAccept = 78 => ServiceAccept,
        /// Control Plane Service request (TS 24.501 §8.2.30).
        ControlPlaneServiceRequest = 79 => ControlPlaneServiceRequest,
        /// Network slice-specific authentication command (TS 24.501 §8.2.31).
        NetworkSliceSpecificAuthenticationCommand = 80 => NetworkSliceSpecificAuthenticationCommand,
        /// Network slice-specific authentication complete (TS 24.501 §8.2.32).
        NetworkSliceSpecificAuthenticationComplete = 81 => NetworkSliceSpecificAuthenticationComplete,
        /// Network slice-specific authentication result (TS 24.501 §8.2.33).
        NetworkSliceSpecificAuthenticationResult = 82 => NetworkSliceSpecificAuthenticationResult,
        /// Configuration update command (TS 24.501 §8.2.19).
        ConfigurationUpdateCommand = 84 => ConfigurationUpdateCommand,
        /// Configuration update complete (TS 24.501 §8.2.20).
        ConfigurationUpdateComplete = 85 => ConfigurationUpdateComplete,
        /// Authentication request (TS 24.501 §8.2.1).
        AuthenticationRequest = 86 => AuthenticationRequest,
        /// Authentication response (TS 24.501 §8.2.2).
        AuthenticationResponse = 87 => AuthenticationResponse,
        /// Authentication reject (TS 24.501 §8.2.5).
        AuthenticationReject = 88 => AuthenticationReject,
        /// Authentication failure (TS 24.501 §8.2.4).
        AuthenticationFailure = 89 => AuthenticationFailure,
        /// Authentication result (TS 24.501 §8.2.3).
        AuthenticationResult = 90 => AuthenticationResult,
        /// Identity request (TS 24.501 §8.2.21).
        IdentityRequest = 91 => IdentityRequest,
        /// Identity response (TS 24.501 §8.2.22).
        IdentityResponse = 92 => IdentityResponse,
        /// Security mode command (TS 24.501 §8.2.25).
        SecurityModeCommand = 93 => SecurityModeCommand,
        /// Security mode complete (TS 24.501 §8.2.26).
        SecurityModeComplete = 94 => SecurityModeComplete,
        /// Security mode reject (TS 24.501 §8.2.27).
        SecurityModeReject = 95 => SecurityModeReject,
        /// 5GMM status (TS 24.501 §8.2.29).
        FiveGmmStatus = 100 => GmmStatus,
        /// Notification (TS 24.501 §8.2.23).
        Notification = 101 => Notification,
        /// Notification response (TS 24.501 §8.2.24).
        NotificationResponse = 102 => NotificationResponse,
        /// UL NAS transport (TS 24.501 §8.2.10).
        UlNasTransport = 103 => UlNasTransport,
        /// DL NAS transport (TS 24.501 §8.2.11).
        DlNasTransport = 104 => DlNasTransport,
        /// Relay key request (TS 24.501 §8.2.34).
        RelayKeyRequest = 105 => RelayKeyRequest,
        /// Relay key accept (TS 24.501 §8.2.35).
        RelayKeyAccept = 106 => RelayKeyAccept,
        /// Relay key reject (TS 24.501 §8.2.36).
        RelayKeyReject = 107 => RelayKeyReject,
        /// Relay authentication request (TS 24.501 §8.2.37).
        RelayAuthenticationRequest = 108 => RelayAuthenticationRequest,
        /// Relay authentication response (TS 24.501 §8.2.38).
        RelayAuthenticationResponse = 109 => RelayAuthenticationResponse,
    }
}

impl GmmMessage {
    /// IEs the decoder did not recognize in the message body, and known IEs
    /// it ignored. An unknown IE encoded as "comprehension required" is
    /// flagged by [`UnknownIe::is_comprehension_required`](crate::UnknownIe::is_comprehension_required): the receiver
    /// answers it as TS 24.501 §7.5.1 requires.
    pub fn unknown_ies(&self) -> &UnknownIes {
        self.body().unknown_ies()
    }
}

impl Encode for GmmMessage {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        self.body().encode_into(buffer)
    }
}

impl TryFrom<(GmmMessageType, &mut &[u8])> for GmmMessage {
    type Error = Error;

    fn try_from((message_type, buffer): (GmmMessageType, &mut &[u8])) -> Result<Self> {
        Self::decode_keeping(message_type, buffer, &mut crate::common::Reading::strict())
    }
}

crate::common::nas_messages! {
    /// Enum over all 5G Session Management (5GSM) message types.
    ///
    /// Each variant wraps a message struct defined by the `nas_message!` macro.
    pub enum GsmMessage;
    /// 5G Session Management (5GSM) message types per TS 24.501 §9.7.
    ///
    /// `u8::from` gives the message type octet, and `From<u8>` reads one: a code
    /// that the table does not have is `Unknown`.
    pub enum GsmMessageType;
    {
        /// PDU session establishment request (TS 24.501 §8.3.1).
        PduSessionEstablishmentRequest = 193 => PduSessionEstablishmentRequest,
        /// PDU session establishment accept (TS 24.501 §8.3.2).
        PduSessionEstablishmentAccept = 194 => PduSessionEstablishmentAccept,
        /// PDU session establishment reject (TS 24.501 §8.3.3).
        PduSessionEstablishmentReject = 195 => PduSessionEstablishmentReject,
        /// PDU session authentication command (TS 24.501 §8.3.4).
        PduSessionAuthenticationCommand = 197 => PduSessionAuthenticationCommand,
        /// PDU session authentication complete (TS 24.501 §8.3.5).
        PduSessionAuthenticationComplete = 198 => PduSessionAuthenticationComplete,
        /// PDU session authentication result (TS 24.501 §8.3.6).
        PduSessionAuthenticationResult = 199 => PduSessionAuthenticationResult,
        /// PDU session modification request (TS 24.501 §8.3.7).
        PduSessionModificationRequest = 201 => PduSessionModificationRequest,
        /// PDU session modification reject (TS 24.501 §8.3.8).
        PduSessionModificationReject = 202 => PduSessionModificationReject,
        /// PDU session modification command (TS 24.501 §8.3.9).
        PduSessionModificationCommand = 203 => PduSessionModificationCommand,
        /// PDU session modification complete (TS 24.501 §8.3.10).
        PduSessionModificationComplete = 204 => PduSessionModificationComplete,
        /// PDU session modification command reject (TS 24.501 §8.3.11).
        PduSessionModificationCommandReject = 205 => PduSessionModificationCommandReject,
        /// PDU session release request (TS 24.501 §8.3.12).
        PduSessionReleaseRequest = 209 => PduSessionReleaseRequest,
        /// PDU session release reject (TS 24.501 §8.3.13).
        PduSessionReleaseReject = 210 => PduSessionReleaseReject,
        /// PDU session release command (TS 24.501 §8.3.14).
        PduSessionReleaseCommand = 211 => PduSessionReleaseCommand,
        /// PDU session release complete (TS 24.501 §8.3.15).
        PduSessionReleaseComplete = 212 => PduSessionReleaseComplete,
        /// 5GSM status (TS 24.501 §8.3.16).
        FiveGsmStatus = 214 => GsmStatus,
        /// Service-level authentication command (TS 24.501 §8.3.17).
        ServiceLevelAuthenticationCommand = 216 => ServiceLevelAuthenticationCommand,
        /// Service-level authentication complete (TS 24.501 §8.3.18).
        ServiceLevelAuthenticationComplete = 217 => ServiceLevelAuthenticationComplete,
        /// Remote UE report (TS 24.501 §8.3.19).
        RemoteUeReport = 218 => RemoteUeReport,
        /// Remote UE report response (TS 24.501 §8.3.20).
        RemoteUeReportResponse = 219 => RemoteUeReportResponse,
    }
}

impl GsmMessage {
    /// IEs the decoder did not recognize in the message body, and known IEs
    /// it ignored. An unknown IE encoded as "comprehension required" is
    /// flagged by [`UnknownIe::is_comprehension_required`](crate::UnknownIe::is_comprehension_required): the receiver
    /// answers it as TS 24.501 §7.5.1 requires.
    pub fn unknown_ies(&self) -> &UnknownIes {
        self.body().unknown_ies()
    }
}

impl Encode for GsmMessage {
    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        self.body().encode_into(buffer)
    }
}

impl TryFrom<(GsmMessageType, &mut &[u8])> for GsmMessage {
    type Error = Error;

    fn try_from((message_type, buffer): (GsmMessageType, &mut &[u8])) -> Result<Self> {
        Self::decode_keeping(message_type, buffer, &mut crate::common::Reading::strict())
    }
}

/// Top-level 5G NAS message.
///
/// Every NAS PDU decodes into one of the following variants:
/// - [`Gmm`](Message::Gmm) — a 5G Mobility Management message (EPD 0x7E)
/// - [`Gsm`](Message::Gsm) — a 5G Session Management message (EPD 0x2E)
/// - [`SecurityProtected`](Message::SecurityProtected) — a security envelope wrapping an inner message
/// - [`Opaque`](Message::Opaque) — ciphertext inside a security envelope
///
/// # Examples
///
/// ```rust
/// use oxirush_nas::nas_5gs::{GmmMessage, Message};
///
/// let bytes = hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
/// let msg = Message::decode(&bytes).unwrap();
/// match msg {
///     Message::Gmm(hdr, GmmMessage::RegistrationRequest(reg)) => {
///         println!("Got registration request");
///     }
///     _ => {}
/// }
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    /// A 5G Mobility Management message (registration, authentication, security, etc.).
    Gmm(GmmHeader, GmmMessage),
    /// A 5G Session Management message (PDU session establishment, modification, release).
    Gsm(GsmHeader, GsmMessage),
    /// A security-protected envelope containing an inner plain 5GMM message.
    SecurityProtected(SecurityHeader, Box<Message>),
    /// Ciphertext carried by a security-protected 5GMM envelope.
    Opaque(Vec<u8>),
}

pub(crate) fn validate_security_protected_inner_message(
    message: &Message,
    security_header_type: SecurityHeaderType,
) -> Result<()> {
    if security_header_type == SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected {
        return Err(Error::EncodingError(
            "a security protected message has a security header type that protects, which the plain one does not".into(),
        ));
    }

    let (header, inner) = match message {
        Message::Gmm(header, inner) => (header, inner),
        Message::Gsm(_, _) => {
            return Err(Error::EncodingError(
                "security-protected 5GS NAS message shall carry a plain 5GMM message; 5GSM messages are protected only via the enclosing 5GMM message"
                    .into(),
            ));
        }
        Message::SecurityProtected(_, _) | Message::Opaque(_) => {
            return Err(Error::EncodingError(
                "security-protected 5GS NAS message shall carry a plain 5GMM message".into(),
            ));
        }
    };

    if header.extended_protocol_discriminator != EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM {
        return Err(Error::EncodingError(format!(
            "inner plain 5GMM message shall use EPD=0x7e, got 0x{:02x}",
            header.extended_protocol_discriminator
        )));
    }
    if header.security_header_type != SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected
    {
        return Err(Error::EncodingError(format!(
            "inner plain 5GMM message shall use SHT=PlainFiveGsNasMessageNotSecurityProtected, got {:?}",
            header.security_header_type
        )));
    }
    if header.message_type != inner.message_type() {
        return Err(Error::EncodingError(format!(
            "inner 5GMM header message type {:?} does not match payload {:?}",
            header.message_type,
            inner.message_type()
        )));
    }

    match security_header_type {
        _ if matches!(inner, GmmMessage::SecurityModeCommand(_))
            && security_header_type
                != SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext =>
        {
            Err(Error::EncodingError(
                "SecurityModeCommand requires integrity protection with new context".into(),
            ))
        }
        _ if matches!(inner, GmmMessage::SecurityModeComplete(_))
            && security_header_type
                != SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext =>
        {
            Err(Error::EncodingError(
                "SecurityModeComplete requires ciphering with new context".into(),
            ))
        }
        SecurityHeaderType::IntegrityProtectedWithNewFiveGNasSecurityContext
            if !matches!(inner, GmmMessage::SecurityModeCommand(_)) =>
        {
            Err(Error::EncodingError(
                "security header type IntegrityProtectedWithNewFiveGNasSecurityContext is only valid for SecurityModeCommand per TS 24.501 Table 9.3.1 note 1"
                    .into(),
            ))
        }
        SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
            if !matches!(inner, GmmMessage::SecurityModeComplete(_)) =>
        {
            Err(Error::EncodingError(
                "security header type IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext is only valid for SecurityModeComplete per TS 24.501 Table 9.3.1 note 2"
                    .into(),
            ))
        }
        _ => Ok(()),
    }
}

impl Message {
    /// Create a new 5GMM message.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // A plain 5GMM STATUS with cause #22
    /// let status = GmmStatus::new(GmmCause::from_cause(GmmCauseValue::Congestion));
    /// let message = Message::new_5gmm(status);
    /// assert_eq!(message.encode().unwrap(), [0x7e, 0x00, 0x64, 0x16]);
    /// ```
    pub fn new_5gmm(message: impl Into<GmmMessage>) -> Self {
        let message = message.into();
        let header = GmmHeader::new(message.message_type());
        Message::Gmm(header, message)
    }

    /// Decode the plain 5GMM message inside a security envelope that uses NEA0.
    ///
    /// NEA0 produces an all-zero keystream (TS 33.501 §D.2.1), so the
    /// ciphered payload is the plain 5GMM message. An integrity-only envelope
    /// returns its already decoded message. The MAC is not verified; use
    /// `SecurityContext` (feature `security`) when the
    /// NAS keys are known.
    pub fn decode_null_ciphered_payload(&self) -> Result<Message> {
        let Self::SecurityProtected(_, inner) = self else {
            return Err(Error::DecodingError(
                "5GS message has no security envelope".into(),
            ));
        };
        let Self::Opaque(payload) = inner.as_ref() else {
            return Ok(inner.as_ref().clone());
        };
        Message::decode(payload)
    }

    /// Create a new 5GSM message, of a PDU session and a procedure
    /// transaction.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // A PDU SESSION RELEASE COMPLETE of PDU session 5, PTI 1
    /// let complete = Message::new_5gsm(PduSessionReleaseComplete::new(), 5, 1);
    /// assert_eq!(complete.encode().unwrap(), [0x2e, 0x05, 0x01, 0xd4]);
    /// ```
    pub fn new_5gsm(
        message: impl Into<GsmMessage>,
        pdu_session_identity: u8,
        procedure_transaction_identity: u8,
    ) -> Self {
        let message = message.into();
        let header = GsmHeader::new(
            message.message_type(),
            pdu_session_identity,
            procedure_transaction_identity,
        );
        Message::Gsm(header, message)
    }

    /// Wrap a plain 5GMM message with security protection per TS 24.501 `§8.2.28` / `§9.9`.
    pub fn protect(
        message: Message,
        security_header_type: SecurityHeaderType,
        message_authentication_code: u32,
        sequence_number: u8,
    ) -> Result<Self> {
        if matches!(
            security_header_type,
            SecurityHeaderType::IntegrityProtectedAndCiphered
                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
        ) {
            return Err(Error::EncodingError(
                "use SecurityContext to cipher a 5GS NAS message".into(),
            ));
        }
        validate_security_protected_inner_message(&message, security_header_type)?;

        let security_header = SecurityHeader {
            // TS 24.501 §9.1.1 and §9.2 require the outer header of a
            // security-protected 5GS NAS message to use the 5GMM EPD.
            extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM,
            security_header_type,
            spare_half_octet: 0,
            message_authentication_code,
            sequence_number,
        };

        Ok(Message::SecurityProtected(
            security_header,
            Box::new(message),
        ))
    }

    fn decode_plain(buffer: &mut &[u8], faults: crate::common::Faults<'_, '_>) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(Error::MessageTooShort);
        }

        match buffer[0] {
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM => {
                if buffer.remaining() < 2 {
                    return Err(Error::MessageTooShort);
                }

                let security_header_type_octet = buffer[1];
                let security_header_type =
                    SecurityHeaderType::try_from(security_header_type_octet & 0x0F)?;
                if security_header_type
                    != SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected
                {
                    return Err(Error::DecodingError(format!(
                        "plain 5GS NAS message cannot carry security header type {security_header_type:?}"
                    )));
                }

                let header = GmmHeader::decode_from(buffer)?;
                let message = GmmMessage::decode_keeping(header.message_type, buffer, faults)?;

                Ok(Message::Gmm(header, message))
            }
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM => {
                let header = GsmHeader::decode_from(buffer)?;
                if let GsmMessageType::Unknown(message_type) = header.message_type {
                    return Err(Error::UnknownSessionMessageType {
                        identity: header.pdu_session_identity,
                        pti: header.procedure_transaction_identity,
                        message_type,
                    });
                }
                let message = GsmMessage::decode_keeping(header.message_type, buffer, faults)?;

                Ok(Message::Gsm(header, message))
            }
            epd => Err(Error::UnknownProtocolDiscriminator(epd)),
        }
    }
}

impl Message {
    /// Unknown and ignored IEs of the 5GMM or 5GSM message body, read
    /// through a security header: see [`GmmMessage::unknown_ies`].
    /// An opaque payload has none.
    pub fn unknown_ies(&self) -> &UnknownIes {
        match self {
            Self::Gmm(_, message) => message.unknown_ies(),
            Self::Gsm(_, message) => message.unknown_ies(),
            Self::SecurityProtected(_, inner) => inner.unknown_ies(),
            Self::Opaque(_) => &crate::common::NO_UNKNOWN_IES,
        }
    }

    /// The message inside the security envelopes: the plain message of an
    /// integrity protected one, the ciphertext ([`Self::Opaque`]) of a
    /// ciphered one, and the message itself when it has no security header.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // A REGISTRATION COMPLETE, integrity protected
    /// let message = Message::decode(&[0x7e, 0x01, 0, 0, 0, 0, 0, 0x7e, 0x00, 0x43]).unwrap();
    /// assert!(matches!(
    ///     message.innermost(),
    ///     Message::Gmm(_, GmmMessage::RegistrationComplete(_))
    /// ));
    /// ```
    pub fn innermost(&self) -> &Self {
        let mut message = self;
        while let Self::SecurityProtected(_, inner) = message {
            message = inner;
        }
        message
    }
}

impl Encode for Message {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::ENCODED);
        self.encode_into(&mut out)?;
        Ok(out)
    }

    fn encode_into(&self, buffer: &mut Vec<u8>) -> Result<()> {
        match self {
            Message::Gmm(header, message) => {
                if header.message_type != message.message_type() {
                    return Err(Error::EncodingError(format!(
                        "5GMM header message type {:?} does not match payload {:?}",
                        header.message_type,
                        message.message_type()
                    )));
                }
                header.encode_into(buffer)?;
                message.encode_into(buffer)?;
            }
            Message::Gsm(header, message) => {
                if header.message_type != message.message_type() {
                    return Err(Error::EncodingError(format!(
                        "5GSM header message type {:?} does not match payload {:?}",
                        header.message_type,
                        message.message_type()
                    )));
                }
                header.encode_into(buffer)?;
                message.encode_into(buffer)?;
            }
            Message::SecurityProtected(header, message) => {
                let ciphered = matches!(
                    header.security_header_type,
                    SecurityHeaderType::IntegrityProtectedAndCiphered
                        | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
                );
                match message.as_ref() {
                    Message::Opaque(data) if ciphered && !data.is_empty() => {}
                    Message::Opaque(_) => {
                        return Err(Error::EncodingError(
                            "opaque 5GS payload requires a ciphered security header and nonempty ciphertext".into(),
                        ));
                    }
                    _ if ciphered => {
                        return Err(Error::EncodingError(
                            "ciphered 5GS security envelope requires opaque ciphertext".into(),
                        ));
                    }
                    Message::SecurityProtected(_, _) => {
                        return Err(Error::EncodingError(
                            "security-protected 5GS NAS message cannot contain another security envelope"
                                .into(),
                        ));
                    }
                    Message::Gmm(_, _) | Message::Gsm(_, _) => {}
                }
                header.encode_into(buffer)?;
                message.encode_into(buffer)?;
            }
            Message::Opaque(data) => buffer.put_slice(data),
        }

        Ok(())
    }
}

impl Decode for Message {
    fn decode_from(buffer: &mut &[u8]) -> Result<Self> {
        Self::decode_keeping(buffer, &mut crate::common::Reading::strict())
    }

    fn decode_lenient_from(buffer: &mut &[u8], faults: &mut Vec<Error>) -> Result<Self> {
        Self::decode_keeping(
            buffer,
            &mut crate::common::Reading::keeping(faults, crate::common::DecodeOptions::STRICT),
        )
    }
}

impl Message {
    /// Decode a message with or without a security header, strictly or
    /// keeping the faults of its mandatory IEs.
    fn decode_keeping(buffer: &mut &[u8], faults: crate::common::Faults<'_, '_>) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(Error::MessageTooShort);
        }

        match buffer[0] {
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM => {
                if buffer.remaining() < 2 {
                    return Err(Error::MessageTooShort);
                }

                let security_header_type_octet = buffer[1];
                match SecurityHeaderType::try_from(security_header_type_octet & 0x0F)? {
                    SecurityHeaderType::PlainFiveGsNasMessageNotSecurityProtected => {
                        Self::decode_plain(buffer, faults)
                    }
                    sht => {
                        let security_header = SecurityHeader::decode_from(buffer)?;
                        let inner = if matches!(
                            sht,
                            SecurityHeaderType::IntegrityProtectedAndCiphered
                                | SecurityHeaderType::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext
                        ) {
                            if !buffer.has_remaining() {
                                return Err(Error::MessageTooShort);
                            }
                            Self::Opaque(buffer.split_to(buffer.remaining()).to_vec())
                        } else {
                            Self::decode_plain(buffer, faults)?
                        };

                        Ok(Message::SecurityProtected(security_header, Box::new(inner)))
                    }
                }
            }
            _ => Self::decode_plain(buffer, faults),
        }
    }
}

impl Message {
    /// The message that `octets` are: one whole NAS message, as it is
    /// carried in the NAS-PDU IE of an NGAP message.
    ///
    /// The first octet says what is decoded: the extended protocol
    /// discriminator of a 5GMM message (0x7E), with or without a security
    /// header, or that of a 5GSM message (0x2E). Octets after the message
    /// are an error.
    ///
    /// This is [`Decode::decode`], which needs no import here.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // A REGISTRATION REJECT, cause #22, and the message type of an EPS message
    /// let reject = Message::decode(&[0x7e, 0x00, 0x44, 0x16]).unwrap();
    /// assert_eq!(reject.to_string(), "5GMM RegistrationReject (5gmm-cause: #22 (Congestion))");
    /// assert!(Message::decode(&[0x07, 0x44, 0x03]).is_err());
    /// ```
    pub fn decode(octets: &[u8]) -> Result<Self> {
        <Self as Decode>::decode(octets)
    }

    /// The message that TS 24.501 clause 7 has a receiver answer with, to
    /// `octets` that [`Self::decode`] refused with `error`. `direction` is
    /// that of `octets`: `Uplink` for what a network received, `Downlink`
    /// for what a UE received. The answer is plain, for the caller to
    /// protect, and `None` where the clause has the message ignored.
    ///
    /// | `error` | Answer |
    /// |---------|--------|
    /// | `MessageTooShort` | None: the message is ignored (§7.2.1) |
    /// | `UnknownMessageType`, `UnknownSessionMessageType` | 5GMM STATUS, or 5GSM STATUS with the identities of the message, with cause #97 "message type non-existent or not implemented" (§7.4) |
    /// | `InvalidMandatoryIe`, `UnknownIeCutShort` | Cause #96 "invalid mandatory information" (§7.5): 5GMM STATUS for a 5GMM message; for a 5GSM message the answer of §7.5.3 where it names one, and 5GSM STATUS otherwise |
    /// | `ReservedPduSessionIdentity` | From a UE, PDU SESSION MODIFICATION REJECT or PDU SESSION RELEASE REJECT with cause #43 "invalid PDU session identity" for those two requests; none for another message, and none to a UE (§7.3.2) |
    /// | `AuthenticMessageRefused` | That of the error inside, for the plain octets that it has, ciphered or not |
    /// | any other | None |
    ///
    /// §7.5.3 has a network answer a PDU SESSION ESTABLISHMENT REQUEST, a
    /// PDU SESSION MODIFICATION REQUEST and a PDU SESSION RELEASE REQUEST
    /// with the reject of the procedure, and a UE answer a PDU SESSION
    /// ESTABLISHMENT ACCEPT with a PDU SESSION RELEASE REQUEST and a PDU
    /// SESSION RELEASE COMMAND with a PDU SESSION RELEASE COMPLETE.
    ///
    /// For a network the clause says "should" of a status message, lets it
    /// try to treat a message with a faulty mandatory IE instead
    /// ([`Self::decode_lenient`] reads one), and leaves to the
    /// implementation a state in which no message is foreseen: whether the
    /// answer is sent is the caller's decision. An unknown IE that is
    /// encoded as "comprehension required" is not an error of `decode`
    /// unless it is cut short: [`UnknownIe::is_comprehension_required`](crate::UnknownIe::is_comprehension_required)
    /// finds one in a decoded message, and it has the same cause #96.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Message;
    /// use oxirush_nas::Direction;
    ///
    /// // PDU SESSION ESTABLISHMENT REQUEST (PDU session 5, PTI 1) that ends
    /// // before its integrity protection maximum data rate
    /// let octets = [0x2e, 0x05, 0x01, 0xc1];
    /// let error = Message::decode(&octets).unwrap_err();
    /// let answer = Message::answer_to_refused(&octets, &error, Direction::Uplink).unwrap();
    /// // PDU SESSION ESTABLISHMENT REJECT, cause #96
    /// assert_eq!(answer.encode().unwrap(), [0x2e, 0x05, 0x01, 0xc3, 0x60]);
    ///
    /// // A 5GMM message type that does not exist
    /// let octets = [0x7e, 0x00, 0x01];
    /// let error = Message::decode(&octets).unwrap_err();
    /// let answer = Message::answer_to_refused(&octets, &error, Direction::Downlink).unwrap();
    /// // 5GMM STATUS, cause #97
    /// assert_eq!(answer.encode().unwrap(), [0x7e, 0x00, 0x64, 0x61]);
    /// ```
    pub fn answer_to_refused(octets: &[u8], error: &Error, direction: Direction) -> Option<Self> {
        use crate::nas_5gs::{GmmCauseValue, GsmCauseValue};
        use GsmMessageType as Type;
        // The plain message: the one that the refusal of an authentic
        // message has deciphered, or `octets`, under their security header
        // if they have one.
        let (error, plain) = match error {
            Error::AuthenticMessageRefused { error, plain } => (error.as_ref(), &plain[..]),
            error => match octets {
                [EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, header, ..] if header & 0x0f != 0 => {
                    (error, octets.get(7..)?)
                }
                plain => (error, plain),
            },
        };
        let status = |cause| Self::new_5gmm(GmmStatus::new(GmmCause::from_cause(cause)));
        let session = |cause| GsmCause::from_cause(cause);
        let from_ue = direction == Direction::Uplink;
        match (*plain.first()?, error) {
            (EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM, Error::UnknownMessageType(_)) => Some(status(
                GmmCauseValue::MessageTypeNonExistentOrNotImplemented,
            )),
            (_, Error::InvalidMandatoryIe { .. } | Error::UnknownIeCutShort { .. }) => {
                Self::invalid_mandatory(plain, direction)
            }
            (_, &Error::UnknownSessionMessageType { identity, pti, .. }) => {
                let cause = session(GsmCauseValue::MessageTypeNonExistentOrNotImplemented);
                Some(Self::new_5gsm(GsmStatus::new(cause), identity, pti))
            }
            (
                _,
                &Error::ReservedPduSessionIdentity {
                    identity,
                    pti,
                    message_type,
                },
            ) if from_ue => {
                let cause = session(GsmCauseValue::InvalidPduSessionIdentity);
                match Type::from(message_type) {
                    Type::PduSessionModificationRequest => {
                        let reject = PduSessionModificationReject::new(cause);
                        Some(Self::new_5gsm(reject, identity, pti))
                    }
                    Type::PduSessionReleaseRequest => {
                        let reject = PduSessionReleaseReject::new(cause);
                        Some(Self::new_5gsm(reject, identity, pti))
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// The message that TS 24.501 clause 7 has a receiver answer with, to
    /// `octets` that it read as `received`, whatever was wrong: for an
    /// error, the answer of [`Self::answer_to_refused`]; for a message that
    /// was read, cause #96 "invalid mandatory information" where it has an
    /// unknown IE that is encoded as "comprehension required" (§7.6.1,
    /// TS 24.007 §11.2.5), as for a faulty mandatory IE (§7.5). `None`
    /// where there is nothing to answer. `received` is what
    /// [`Self::decode`] returned, or a security context, with the message of
    /// its `Verified`.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::Message;
    /// use oxirush_nas::Direction;
    ///
    /// // REGISTRATION COMPLETE with an unknown IE 0x03, comprehension
    /// // required, which `decode` reads
    /// let octets = [0x7e, 0x00, 0x43, 0x03, 0x01, 0x00];
    /// let received = Message::decode(&octets);
    /// assert!(received.is_ok());
    /// let answer = Message::answer_to(&octets, &received, Direction::Uplink).unwrap();
    /// // 5GMM STATUS, cause #96
    /// assert_eq!(answer.encode().unwrap(), [0x7e, 0x00, 0x64, 0x60]);
    ///
    /// // A message type that does not exist, and a message without a fault
    /// let refused = [0x7e, 0x00, 0x01];
    /// let answer = Message::answer_to(&refused, &Message::decode(&refused), Direction::Uplink);
    /// assert_eq!(answer.unwrap().encode().unwrap(), [0x7e, 0x00, 0x64, 0x61]);
    /// let sound = [0x7e, 0x00, 0x43];
    /// assert!(Message::answer_to(&sound, &Message::decode(&sound), Direction::Uplink).is_none());
    /// ```
    pub fn answer_to(octets: &[u8], received: &Result<Self>, direction: Direction) -> Option<Self> {
        let message = match received {
            Err(error) => return Self::answer_to_refused(octets, error, direction),
            Ok(message) => message,
        };
        let required = (message.unknown_ies().iter()).any(|ie| ie.is_comprehension_required());
        // The plain message, whose header the answer to a 5GSM message has
        let plain = match message {
            Self::SecurityProtected(_, inner) => inner.as_ref(),
            plain => plain,
        };
        match required {
            true => Self::invalid_mandatory(&plain.encode().ok()?, direction),
            false => None,
        }
    }

    /// The answer of cause #96 "invalid mandatory information" to the plain
    /// message `plain` (TS 24.501 §7.5): 5GMM STATUS for a 5GMM message, and
    /// for a 5GSM message the answer of §7.5.3 where it names one, 5GSM
    /// STATUS otherwise.
    fn invalid_mandatory(plain: &[u8], direction: Direction) -> Option<Self> {
        use crate::nas_5gs::{GmmCauseValue, GsmCauseValue};
        use GsmMessageType as Type;
        let from_ue = direction == Direction::Uplink;
        match *plain.first()? {
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM => {
                let cause = GmmCause::from_cause(GmmCauseValue::InvalidMandatoryInformation);
                Some(Self::new_5gmm(GmmStatus::new(cause)))
            }
            EXTENDED_PROTOCOL_DISCRIMINATOR_5GSM => {
                let &[_, identity, pti, kind, ..] = plain else {
                    return None;
                };
                let cause = GsmCause::from_cause(GsmCauseValue::InvalidMandatoryInformation);
                let answer: GsmMessage = match (from_ue, Type::from(kind)) {
                    (true, Type::PduSessionEstablishmentRequest) => {
                        PduSessionEstablishmentReject::new(cause).into()
                    }
                    (true, Type::PduSessionModificationRequest) => {
                        PduSessionModificationReject::new(cause).into()
                    }
                    (true, Type::PduSessionReleaseRequest) => {
                        PduSessionReleaseReject::new(cause).into()
                    }
                    (false, Type::PduSessionEstablishmentAccept) => PduSessionReleaseRequest::new()
                        .with_fgsm_cause(cause)
                        .into(),
                    (false, Type::PduSessionReleaseCommand) => PduSessionReleaseComplete::new()
                        .with_fgsm_cause(cause)
                        .into(),
                    _ => GsmStatus::new(cause).into(),
                };
                Some(Self::new_5gsm(answer, identity, pti))
            }
            _ => None,
        }
    }

    /// The message that `octets` are, as [`Self::decode`] reads it, with
    /// what `decode` refuses of a mandatory IE: an IE that has its octets
    /// and is shorter than its message has it, or is not one of its type.
    /// The IE is in the message as it came, and each refusal is in the
    /// list, the [`Error::InvalidMandatoryIe`] that `decode` returns
    /// for it. A list without an error is a message that `decode` reads.
    ///
    /// A receiver rejects such a message (TS 24.501 §7.5.1), and this is how
    /// it reads what it rejects: its type, the IEs that are sound and the
    /// octets of the one that is not, to log them and to choose its answer.
    /// Every other error is one of `decode`: a mandatory IE that is missing
    /// or cut short leaves no message to read.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::{GmmCauseValue, GmmMessage, Message, GmmCause, GmmStatus, RegistrationTypeValue};
    /// use oxirush_nas::{IeFault, IeName, Error};
    ///
    /// // REGISTRATION REQUEST whose SUCI is a network specific identifier with
    /// // a realm of one label, `type1.rid678.schid0.useriduser17@operator`
    /// let octets = hex::decode(
    ///     "7e004179002a1174797065312e7269643637382e7363686964302e757365726964757365723137\
    ///      406f70657261746f72",
    /// )
    /// .unwrap();
    /// let refusal = Error::InvalidMandatoryIe {
    ///     ie: IeName::of("fgs_mobile_identity"),
    ///     fault: IeFault::Syntax,
    ///     reason: Some(Box::new(
    ///         "`realm` is written as a domain name of two labels at least, of letters, digits \
    ///          and hyphens, with no hyphen at either end and 63 octets at most each, as \
    ///          example.com"
    ///             .into(),
    ///     )),
    /// };
    /// assert_eq!(Message::decode(&octets), Err(refusal.clone()));
    ///
    /// // What the AMF reads of it, to log it and to choose its answer
    /// let (message, faults) = Message::decode_lenient(&octets, oxirush_nas::DecodeOptions::STRICT).unwrap();
    /// assert_eq!(faults, [refusal]);
    /// let Message::Gmm(_, GmmMessage::RegistrationRequest(request)) = &message else {
    ///     panic!("another message")
    /// };
    /// let registration = request.fgs_registration_type.registration_type();
    /// assert_eq!(registration, Some(RegistrationTypeValue::InitialRegistration));
    /// let identity = String::from_utf8_lossy(&request.fgs_mobile_identity.value[1..]);
    /// assert_eq!(identity, "type1.rid678.schid0.useriduser17@operator");
    ///
    /// // Its answer (§7.5.1): 5GMM STATUS with cause #96 "invalid mandatory information"
    /// let cause = GmmCause::from_cause(GmmCauseValue::InvalidMandatoryInformation);
    /// let status = Message::new_5gmm(GmmStatus::new(cause));
    /// assert_eq!(status.encode().unwrap(), [0x7e, 0x00, 0x64, 0x60]);
    /// ```
    pub fn decode_lenient(
        mut octets: &[u8],
        options: crate::common::DecodeOptions,
    ) -> Result<(Self, Vec<Error>)> {
        let mut faults = Vec::new();
        let mut reading = crate::common::Reading::keeping(&mut faults, options);
        let message = Self::decode_keeping(&mut octets, &mut reading)?;
        match octets.len() {
            0 => Ok((message, faults)),
            more => Err(crate::common::trailing(more)),
        }
    }

    /// The message that `octets` are, as [`Self::decode`] reads it, with
    /// what a receiver takes beyond the rules of TS 24.501 by `options`: a
    /// known optional IE out of the order of its table, which §7.6.2 has a
    /// receiver ignore and other implementations take.
    ///
    /// ```
    /// use oxirush_nas::DecodeOptions;
    /// use oxirush_nas::nas_5gs::{GmmMessage, Message};
    ///
    /// // UL NAS TRANSPORT whose PDU session ID comes after its MA PDU
    /// // session information, which its table places after it
    /// let octets = hex::decode("7e00670100082e0101c1ffff9181a11201").unwrap();
    /// let session = |message: &Message| match message {
    ///     Message::Gmm(_, GmmMessage::UlNasTransport(transport)) => {
    ///         transport.pdu_session_id.clone()
    ///     }
    ///     _ => None,
    /// };
    /// assert!(session(&Message::decode(&octets).unwrap()).is_none());
    /// let options = DecodeOptions::STRICT.with_out_of_sequence();
    /// let taken = Message::decode_with(&octets, options).unwrap();
    /// assert!(session(&taken).is_some());
    ///
    /// // It is encoded in the order it came, and validate() says so
    /// assert_eq!(taken.encode().unwrap(), octets);
    /// ```
    pub fn decode_with(mut octets: &[u8], options: crate::common::DecodeOptions) -> Result<Self> {
        let message =
            Self::decode_keeping(&mut octets, &mut crate::common::Reading::with(options))?;
        match octets.len() {
            0 => Ok(message),
            more => Err(crate::common::trailing(more)),
        }
    }

    /// The octets of the message, header first.
    ///
    /// This is [`Encode::encode`], which needs no import here.
    ///
    /// ```
    /// use oxirush_nas::nas_5gs::*;
    ///
    /// // A REGISTRATION REJECT with cause #22 and a T3346 value of ten minutes
    /// let cause = GmmCause::from_cause(GmmCauseValue::Congestion);
    /// let t3346 = GprsTimer2::from_seconds(600).unwrap();
    /// let reject = RegistrationReject::new(cause).with_t3346_value(t3346);
    /// let octets = Message::new_5gmm(reject).encode().unwrap();
    /// assert_eq!(octets, [0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x2a]);
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>> {
        <Self as Encode>::encode(self)
    }

    /// What a message is first given to be encoded in: most signalling
    /// messages are shorter, and one that is longer takes more.
    const ENCODED: usize = 64;
}

/// The system and the header of a message, then the message.
impl core::fmt::Display for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Message::Gmm(_hdr, msg) => {
                write!(f, "5GMM {msg}")
            }
            Message::Gsm(hdr, msg) => {
                write!(
                    f,
                    "5GSM (PSI={}, PTI={}) {}",
                    hdr.pdu_session_identity, hdr.procedure_transaction_identity, msg
                )
            }
            Message::SecurityProtected(hdr, inner) => {
                write!(
                    f,
                    "SecurityProtected (SHT={:?}, MAC={:#010x}, SN={}) {}",
                    hdr.security_header_type,
                    hdr.message_authentication_code,
                    hdr.sequence_number,
                    inner
                )
            }
            Message::Opaque(data) => write!(f, "Opaque ({} octets)", data.len()),
        }
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::*;
    use crate::common::{UnknownIe, Validate};

    #[test]
    fn spare_half_octets_of_the_headers_are_kept() {
        // A plain message, and the same one in a security header
        let plain = [0x7e, 0xf0, 0x43];
        let protected = [0x7e, 0xa1, 0, 0, 0, 0, 0, 0x7e, 0xf0, 0x43];

        let message = Message::decode(&plain).unwrap();
        let Message::Gmm(header, GmmMessage::RegistrationComplete(_)) = &message else {
            panic!("expected a REGISTRATION COMPLETE");
        };
        assert_eq!(header.spare_half_octet, 0x0f);
        assert_eq!(message.encode().unwrap(), plain);

        let message = Message::decode(&protected).unwrap();
        let Message::SecurityProtected(header, inner) = &message else {
            panic!("expected a security protected message");
        };
        assert_eq!(header.spare_half_octet, 0x0a);
        assert_eq!(inner.encode().unwrap(), plain);
        assert_eq!(message.encode().unwrap(), protected);
    }

    #[test]
    fn a_spare_half_octet_has_four_bits() {
        let mut header = GmmHeader::new(GmmMessageType::RegistrationComplete);
        header.spare_half_octet = 0x10;
        assert!(header.encode().is_err());

        header.spare_half_octet = 0x0f;
        let mut encoded = Vec::new();
        header.encode_into(&mut encoded).unwrap();
        assert_eq!(encoded[..], [0x7e, 0xf0, 0x43]);
    }

    #[test]
    fn security_header_pairing_is_validation_not_wire_decoding() {
        let mut wire = vec![0x7e, 0x01, 0, 0, 0, 0, 0];
        wire.extend_from_slice(&hex::decode("7e005d020002a020e1360102").unwrap());
        let message = Message::decode(&wire).unwrap();
        assert!(
            message.validate().iter().any(
                |finding| finding.field == "message" || finding.field == "security_header_type"
            )
        );
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn registration_request_carries_protected_eps_attach_request() {
        // TS 24.501 §8.2.6.16: the EPS NAS message container holds the complete
        // integrity protected ATTACH REQUEST. This one is packet 33 of the
        // S1AP capture used by the EPS tests.
        let attach = hex::decode(
            "17830224400307410108991007000020160605e0e000000000250243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1",
        )
        .unwrap();
        let mut wire =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        wire.push(0x70);
        wire.extend_from_slice(&(attach.len() as u16).to_be_bytes());
        wire.extend_from_slice(&attach);

        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
        let Message::Gmm(_, GmmMessage::RegistrationRequest(request)) = &message else {
            panic!("expected REGISTRATION REQUEST");
        };
        let container = request.eps_nas_message_container.as_ref().unwrap();
        let eps = container.decode_as_eps_message().unwrap();
        let crate::nas_eps::Message::SecurityProtected(header, inner) = &eps else {
            panic!("expected an integrity protected EPS message");
        };
        assert_eq!(header.sequence_number, 3);
        let crate::nas_eps::Message::Emm(
            _,
            crate::nas_eps::EmmMessage::AttachRequest(attach_request),
        ) = inner.as_ref()
        else {
            panic!("expected ATTACH REQUEST");
        };
        assert_eq!(
            attach_request
                .eps_mobile_identity
                .as_imsi()
                .map(|identity| identity.to_string())
                .as_deref(),
            Some("901700000026160")
        );
        assert_eq!(
            EpsNasMessageContainer::from_eps_message(&eps)
                .unwrap()
                .value,
            attach
        );

        let status = crate::nas_eps::Message::decode(&[0x07, 0x60, 0x03]).unwrap();
        assert!(EpsNasMessageContainer::from_eps_message(&status).is_err());
        assert!(
            EpsNasMessageContainer::new(vec![0x07, 0x60, 0x03])
                .decode_as_eps_message()
                .is_err()
        );
    }

    #[test]
    fn truncated_and_bit_flipped_pdus_never_panic() {
        // Every accepted mutation must also format, validate, and re-encode to
        // a canonical form that decodes to the same structure.
        fn check(wire: &[u8]) {
            let Ok(message) = Message::decode(wire) else {
                return;
            };
            let _ = message.to_string();
            let _ = message.validate();
            if let Ok(inner) = message.decode_null_ciphered_payload() {
                let _ = inner.to_string();
                let _ = inner.validate();
            }
            let bytes = message.encode().expect("decodable PDU re-encodes");
            let again = Message::decode(&bytes).expect("canonical PDU decodes");
            assert_eq!(again, message, "structural round trip of {wire:02x?}");
            assert_eq!(again.encode().unwrap(), bytes);
        }
        for hex in [
            "7e004179000d0199f9070000000000000010022e08a020000000000000",
            "7e0042010177000bf299f907020040c00002df54074099f90700000115020101210201005e01a9",
            "7e004509000bf299f907020040c00002df",
            "7e004c100007040040c00002df7100157e004c100007040040c00002df4002020050020200",
            "7e004e5002020026020000",
            "7e0054430f90004f00700065006e00350047005346004742306202647100490100",
            "7e00560002000021ab6f2a1cc5c5938d38cba14dfe26b0012010a820e67b8896800076a638e98eed4747",
            "7e005d020002a020e1360102",
            "7e005e7700091511000000000000007100207e004109000d0199f9070000000000000010021001072e08a020000000000000",
            "7e00670100142e0101c1ffff917b000a80000a00000d00000300120181220101250908696e7465726e6574",
            "7e006801006d2e0101c211000901000631310101ff010603f42403f4242905010a2d00bd2201017900060120410101097b003580000d0408080808000d04080804040003102001486048600000000000000000888800031020014860486000000000000000008844250908696e7465726e65741201",
            "7e02123456780b7e005d020002a020e1360102",
        ] {
            let wire = hex::decode(hex).unwrap();
            for length in 0..wire.len() {
                check(&wire[..length]);
            }
            for bit in 0..wire.len() * 8 {
                let mut mutated = wire.clone();
                mutated[bit / 8] ^= 0x80 >> (bit % 8);
                check(&mutated);
            }
        }
    }

    #[test]
    fn unknown_comprehension_required_ies_are_reported() {
        // TS 24.007 §11.2.5: type 4 IEIs 0x00-0x0F and type 6 IEIs 0x7E-0x7F.
        for (wire, flagged) in [
            (&[0x7e, 0x00, 0x44, 0x16, 0x49, 0x01, 0xaa][..], false),
            (&[0x7e, 0x00, 0x44, 0x16, 0x0f, 0x01, 0xaa][..], true),
            (&[0x7e, 0x00, 0x44, 0x16, 0x7f, 0x00, 0x01, 0xaa][..], true),
            (&[0x7e, 0x00, 0x44, 0x16, 0x7b, 0x00, 0x01, 0xaa][..], false),
        ] {
            // A well-framed one is kept: the receiver applies TS 24.501
            // §7.5.1 to the flag, and a tool can inspect the message.
            let message = Message::decode(wire).unwrap();
            assert_eq!(message.encode().unwrap(), wire);
            assert_eq!(
                message
                    .unknown_ies()
                    .iter()
                    .any(|ie| ie.is_comprehension_required()),
                flagged,
                "{wire:02x?}"
            );
            assert_eq!(
                message
                    .validate()
                    .iter()
                    .any(|error| error.field == "unknown_ies"),
                flagged,
                "{wire:02x?}"
            );
        }
    }

    #[test]
    fn truncated_unknown_comprehension_required_ies_are_invalid_mandatory_information() {
        // An unknown IE encoded as "comprehension required" that is cut
        // short has no boundary to keep it by. It is invalid mandatory
        // information (TS 24.501 §7.5.1 b), #96); the message itself is not
        // too short (§7.2).
        for wire in [
            &[0x7e, 0x00, 0x44, 0x16, 0x0f, 0x05, 0xaa][..],
            &[0x7e, 0x00, 0x44, 0x16, 0x7f, 0x00, 0x05, 0xaa][..],
            &[0x7e, 0x00, 0x44, 0x16, 0x0f][..],
        ] {
            assert!(
                matches!(
                    Message::decode(wire),
                    Err(Error::UnknownIeCutShort {
                        iei: 0x0f | 0x7f,
                        ..
                    })
                ),
                "{wire:02x?}"
            );
        }
        // A truncated IE that is not comprehension required is ignored.
        let wire = [0x7e, 0x00, 0x44, 0x16, 0x49, 0x05, 0xaa];
        assert_eq!(Message::decode(&wire).unwrap().encode().unwrap(), wire);
    }

    #[test]
    fn repeated_optional_ies_keep_first_occurrence() {
        // TS 24.501 §7.6.3: only the first repetition is handled. Later
        // repetitions are kept as ignored octets so relayed bytes are unchanged.
        let wire = [0x7e, 0x00, 0x44, 0x16, 0x5f, 0x01, 0x21, 0x5f, 0x01, 0x22];
        let message = Message::decode(&wire).unwrap();
        let Message::Gmm(_, GmmMessage::RegistrationReject(reject)) = &message else {
            panic!("expected REGISTRATION REJECT");
        };
        assert_eq!(reject.t3346_value.as_ref().unwrap().value, [0x21]);
        assert_eq!(
            reject.unknown_ies.iter().collect::<Vec<_>>(),
            [UnknownIe {
                iei: 0x5f,
                data: &[0x01, 0x22],
            }]
        );
        assert_eq!(message.encode().unwrap(), wire);

        let wire = [0x7e, 0x00, 0x44, 0x16, 0x5f, 0x00, 0x5f, 0x01, 0x21];
        let message = Message::decode(&wire).unwrap();
        let Message::Gmm(_, GmmMessage::RegistrationReject(reject)) = &message else {
            panic!("expected REGISTRATION REJECT");
        };
        assert!(reject.t3346_value.is_none());
        assert_eq!(reject.unknown_ies.len(), 2);
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn relay_key_parameters_use_mandatory_lve_wire_format() {
        for (kind, value_len) in [(0x69, 20usize), (0x6a, 49)] {
            let mut wire = vec![0x7e, 0x00, kind, 0x01];
            wire.extend_from_slice(&(value_len as u16).to_be_bytes());
            wire.extend_from_slice(&vec![0; value_len]);
            let decoded = Message::decode(&wire).unwrap();
            assert_eq!(decoded.encode().unwrap(), wire);
        }
    }

    #[test]
    fn shared_optional_ie_types_use_untagged_mandatory_wire_format() {
        let slice_auth = [
            0x7e, 0x00, 0x50, 0x01, 0x01, 0x00, 0x04, 0x03, 0x01, 0x00, 0x04,
        ];
        let service_auth = [0x2e, 0x01, 0x00, 0xd8, 0x00, 0x03, 0x00, 0x00, 0x00];
        for wire in [&slice_auth[..], &service_auth[..]] {
            let decoded = Message::decode(wire).unwrap();
            assert_eq!(decoded.encode().unwrap(), wire);
        }
    }

    #[test]
    fn interleaved_optional_ies_keep_original_order() {
        let wire = [
            0x7e, 0x00, 0x54, 0x40, 0x01, 0xaa, 0x49, 0x01, 0x00, 0x43, 0x01, 0x80,
        ];
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn malformed_n3qai_is_ignored_and_preserved_verbatim() {
        let wire = hex::decode("2e0101c211000901000631310101ff010603f42403f42470000601010101ff00")
            .unwrap();
        let message = Message::decode(&wire).unwrap();
        let Message::Gsm(_, GsmMessage::PduSessionEstablishmentAccept(accept)) = &message else {
            panic!("expected PDU SESSION ESTABLISHMENT ACCEPT");
        };
        assert!(accept.n3_qai.is_none());
        assert!(accept.unknown_ies.iter().any(|ie| ie.iei == 0x70));
        assert!(message.validate().iter().any(|finding| {
            finding.field == "unknown_ies" && finding.message.contains("malformed")
        }));
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn ciphered_envelope_round_trips_without_keys() {
        let wire = [0x7e, 0x02, 0, 0, 0, 0, 0, 0xff, 0xee];
        let message = Message::decode(&wire).unwrap();
        assert!(matches!(
            message,
            Message::SecurityProtected(_, ref inner)
                if matches!(inner.as_ref(), Message::Opaque(data) if data == &[0xff, 0xee])
        ));
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn ciphered_header_cannot_carry_cleartext() {
        let plain = Message::new_5gmm(DeregistrationAcceptUeOriginating::new());
        let sht = SecurityHeaderType::IntegrityProtectedAndCiphered;
        assert!(Message::protect(plain.clone(), sht, 0, 0).is_err());
        let wrapped = Message::SecurityProtected(
            SecurityHeader {
                extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM,
                security_header_type: sht,
                spare_half_octet: 0,
                message_authentication_code: 0,
                sequence_number: 0,
            },
            Box::new(plain),
        );
        assert!(wrapped.encode().is_err());
    }

    #[test]
    fn empty_message_preserves_unknown_optional_ie() {
        let wire = [0x7e, 0x00, 0x46, 0xff];
        let message = Message::decode(&wire).unwrap();
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn service_request_uses_all_four_service_type_bits() {
        let wire = hex::decode("7e004ca1000704000000000000").unwrap();
        let mut message = Message::decode(&wire).unwrap();
        let Message::Gmm(_, GmmMessage::ServiceRequest(request)) = &mut message else {
            panic!("expected SERVICE REQUEST");
        };
        assert_eq!(request.service_type.service_type_raw(), 0x0a);
        assert_eq!(
            request.service_type.service_type(),
            Some(crate::nas_5gs::ServiceTypeValue::Data)
        );
        assert_eq!(request.ngksi.value, 0x01);

        request
            .service_type
            .set_service_type(crate::nas_5gs::ServiceTypeValue::Data);
        assert_eq!(request.service_type.value, 0x01);
        let mut canonical = wire;
        canonical[3] = 0x11;
        assert_eq!(message.encode().unwrap(), canonical);
    }

    #[test]
    fn malformed_known_optional_ie_is_ignored_by_receiver() {
        let wire = hex::decode("7e004201015e00").unwrap();
        let message = Message::decode(&wire).unwrap();
        let Message::Gmm(_, GmmMessage::RegistrationAccept(accept)) = message else {
            panic!("expected REGISTRATION ACCEPT");
        };
        assert!(accept.t3512_value.is_none());
    }

    #[test]
    fn message_table_minimum_ignores_contextually_short_optional_ie() {
        // Access technology utilization control has a whole-IE minimum of 4
        // here, but the same type has a valid two-octet removal form elsewhere.
        let wire = hex::decode("7e004201016300").unwrap();
        let message = Message::decode(&wire).unwrap();
        let Message::Gmm(_, GmmMessage::RegistrationAccept(accept)) = message else {
            panic!("expected REGISTRATION ACCEPT");
        };
        assert!(accept.access_technology_utilization_control.is_none());
        assert!(accept.unknown_ies.iter().any(|ie| ie.iei == 0x63));
    }

    #[test]
    fn message_table_maximum_is_checked_per_occurrence() {
        let wire =
            hex::decode("7e004179000d0199f9070000000000000010022e08a020000000000000").unwrap();
        let mut message = Message::decode(&wire).unwrap();
        let Message::Gmm(_, GmmMessage::RegistrationRequest(request)) = &mut message else {
            panic!("expected REGISTRATION REQUEST");
        };
        // 37 valid length-one S-NSSAIs occupy 74 value octets. That fits the
        // type-wide configured-NSSAI maximum, but exceeds Requested NSSAI's
        // message-table maximum of 74 whole octets (72 value octets).
        request.requested_nssai = Some(Nssai::new([1, 1].repeat(37)));
        assert!(request.requested_nssai.as_ref().unwrap().is_well_formed());
        assert!(message.validate().iter().any(|finding| {
            finding.severity == crate::common::Severity::Error
                && finding.field == "requested_nssai"
                && finding.message.contains("message-table length")
        }));
    }

    #[test]
    fn malformed_mandatory_suci_is_rejected() {
        for wire in [
            // Reserved protection-scheme identifier 3.
            "7e00417900090102f839f0ff0301aa",
            // Network-specific SUCI with two at-signs in the NAI.
            "7e004179000b1162616440407265616c6d",
            // Null-scheme MSIN containing non-BCD nibbles.
            "7e00417900090102f839f0ff0000aa",
            // Binary NAS HNPKI 255, reserved by TS 24.501 table 9.11.3.4.1.
            "7e00417900090102f839f0ff01ff21",
        ] {
            assert!(matches!(
                Message::decode(&hex::decode(wire).unwrap()),
                Err(Error::InvalidMandatoryIe { .. })
            ));
        }
    }

    #[test]
    fn malformed_mandatory_registration_result_is_rejected() {
        let wire = hex::decode("7e004200").unwrap();
        assert!(matches!(
            Message::decode(&wire),
            Err(Error::InvalidMandatoryIe { .. })
        ));
    }

    #[test]
    fn sender_validation_rejects_excess_network_feature_support() {
        let wire = hex::decode("7e0042010121050000000000").unwrap();
        let message = Message::decode(&wire).unwrap();
        assert!(message.validate().iter().any(|finding| {
            finding.severity == crate::common::Severity::Error
                && finding.field == "fgs_network_feature_support"
        }));
    }

    #[test]
    fn mobile_originated_qos_flow_description_rejects_eps_bearer_identity() {
        let wire = hex::decode("2e0101c9790006012041070150").unwrap();
        let message = Message::decode(&wire).unwrap();
        assert!(message.validate().iter().any(|finding| {
            finding.field == "requested_qos_flow_descriptions"
                && finding.severity == crate::common::Severity::Error
        }));
        assert_eq!(message.encode().unwrap(), wire);
    }

    /// A QoS flow description with an error is an error of the procedure,
    /// which the SMF rejects with #84 (TS 24.501 §6.4.2.4), not of the IE.
    #[test]
    fn malformed_qos_flow_description_is_kept_for_the_5gsm_cause() {
        let wire = hex::decode("2e0101c979000701204101020900").unwrap();
        let message = Message::decode(&wire).unwrap();
        let Message::Gsm(_, GsmMessage::PduSessionModificationRequest(request)) = message else {
            panic!("expected PDU SESSION MODIFICATION REQUEST");
        };
        let descriptions = request.requested_qos_flow_descriptions.unwrap();
        assert_eq!(descriptions.try_descriptions(), None);
        let [Err(error)] = descriptions.parse_descriptions()[..] else {
            panic!("expected one QoS flow description error");
        };
        assert_eq!(error.qfi, 1);
        assert_eq!(
            error.gsm_cause(),
            crate::nas_5gs::GsmCauseValue::SyntacticalErrorInTheQosOperation
        );
    }

    /// The Authorized QoS rules of a PDU SESSION ESTABLISHMENT ACCEPT are
    /// mandatory, and their errors are handled per rule with #84 or #45
    /// (§6.4.1.3): the message decodes, and each rule reports its own error.
    #[test]
    fn qos_rule_errors_are_left_to_the_5gsm_procedure() {
        let rules = hex::decode(concat!(
            "010006", "31", "310101", "ff09", // default rule, match-all filter 1
            "020009", "23", "310101", "320101", "fe09", // three filters counted, two sent
            "030009", "22", "310101", "310101", "fd09", // filters 1 and 1
            "040007", "21", "31029901", "fc09", // reserved component type 0x99
        ))
        .unwrap();
        let mut wire = hex::decode("2e0501c211").unwrap();
        wire.extend_from_slice(&(rules.len() as u16).to_be_bytes());
        wire.extend_from_slice(&rules);
        wire.extend_from_slice(&hex::decode("06010101010101").unwrap());
        let message = Message::decode(&wire).unwrap();
        let Message::Gsm(_, GsmMessage::PduSessionEstablishmentAccept(accept)) = message else {
            panic!("expected PDU SESSION ESTABLISHMENT ACCEPT");
        };
        let parsed = accept.authorized_qos_rules.parse_rules();
        assert_eq!(parsed.len(), 4);
        assert!(
            parsed[0]
                .as_ref()
                .is_ok_and(|rule| rule.dqr && rule.qfi == Some(9))
        );
        let errors: Vec<_> = parsed[1..]
            .iter()
            .map(|rule| {
                let error = rule.as_ref().unwrap_err();
                (error.rule_id, error.dqr, error.error.gsm_cause())
            })
            .collect();
        assert_eq!(
            errors,
            [
                (
                    2,
                    Some(false),
                    crate::nas_5gs::GsmCauseValue::SyntacticalErrorInTheQosOperation
                ),
                (
                    3,
                    Some(false),
                    crate::nas_5gs::GsmCauseValue::SyntacticalErrorInPacketFilters
                ),
                (
                    4,
                    Some(false),
                    crate::nas_5gs::GsmCauseValue::SyntacticalErrorInPacketFilters
                ),
            ]
        );
        assert!(!accept.authorized_qos_rules.is_well_formed());
    }

    #[test]
    fn legacy_modification_complete_cause_is_receive_only() {
        let wire = hex::decode("2e0101cc591a").unwrap();
        let message = Message::decode(&wire).unwrap();
        assert!(message.validate().iter().any(|finding| {
            finding.severity == crate::common::Severity::Error && finding.field == "fgsm_cause"
        }));
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn reserved_service_type_is_receiver_fallback_but_sender_error() {
        let wire = hex::decode("7e004ca1000704000000000000").unwrap();
        let mut message = Message::decode(&wire).unwrap();
        let Message::Gmm(_, GmmMessage::ServiceRequest(request)) = &mut message else {
            panic!("expected SERVICE REQUEST");
        };
        request.service_type.value = 0x0c;
        assert_eq!(request.service_type.service_type(), None);
        assert!(message.validate().iter().any(|finding| {
            finding.severity == crate::common::Severity::Error && finding.field == "service_type"
        }));
    }

    #[test]
    fn reserved_5gsm_pti_is_encodable_but_rejected_on_receipt() {
        // Negative tests can send PTI 255; a receiver rejects it on decode.
        let header = GsmHeader::new(GsmMessageType::PduSessionEstablishmentRequest, 1, 255);
        let mut buffer = Vec::new();
        header.encode_into(&mut buffer).unwrap();
        assert_eq!(buffer, [0x2e, 1, 255, 193]);
        assert!(GsmHeader::decode(&[0x2e, 1, 255, 193]).is_err());
    }

    #[test]
    fn reserved_5gsm_pdu_session_identity_is_rejected_on_receipt() {
        let wire = hex::decode("2e1001d4").unwrap();
        // TS 24.501 §7.3.2: the network answers a PDU SESSION MODIFICATION
        // or RELEASE REQUEST with a reserved PDU session identity with cause
        // #43, which needs the PTI and the message type.
        assert_eq!(
            Message::decode(&wire),
            Err(Error::ReservedPduSessionIdentity {
                identity: 16,
                pti: 1,
                message_type: 0xd4,
            })
        );
        assert_eq!(
            Message::decode(&hex::decode("2eff05c9").unwrap()),
            Err(Error::ReservedPduSessionIdentity {
                identity: 255,
                pti: 5,
                message_type: 0xc9,
            })
        );

        let message = Message::Gsm(
            GsmHeader::new(GsmMessageType::PduSessionReleaseComplete, 16, 1),
            GsmMessage::PduSessionReleaseComplete(Box::default()),
        );
        assert_eq!(message.encode().unwrap(), wire);
    }

    #[test]
    fn unknown_ies_re_encode_in_linear_time() {
        // A REGISTRATION COMPLETE padded with 65000 one-octet unknown IEs
        // (TS 24.501 §7.6.1). Re-encoding it, as validate() does, must not
        // take time quadratic in the number of IEs.
        let mut wire = vec![0x7e, 0x00, 0x43];
        wire.resize(65003, 0x81);
        let message = Message::decode(&wire).unwrap();
        let start = std::time::Instant::now();
        assert_eq!(message.encode().unwrap(), wire);
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "re-encoding took {:?}",
            start.elapsed()
        );
    }

    /// A short message is refused by the first thing that it lacks, also under a
    /// security header.
    #[test]
    fn a_short_message_is_refused_by_what_it_lacks_first() {
        for (octets, refused) in [
            (&[0x00][..], Error::UnknownProtocolDiscriminator(0)),
            (&[0x7e], Error::MessageTooShort),
            (&[0x7e, 0x0f], Error::ReservedSecurityHeaderType(15)),
            (
                &[0x7e, 0x01, 1, 2, 3, 4, 0, 0x00],
                Error::UnknownProtocolDiscriminator(0),
            ),
            (&[0x7e, 0x01, 1, 2, 3, 4, 0, 0x7e], Error::MessageTooShort),
            (
                &[0x7e, 0x01, 1, 2, 3, 4, 0, 0x7e, 0x01],
                Error::DecodingError(
                    "plain 5GS NAS message cannot carry security header type IntegrityProtected"
                        .into(),
                ),
            ),
        ] {
            assert_eq!(Message::decode(octets), Err(refused), "{octets:02x?}");
        }
        // A security header is seven octets, and a protected message one more at least
        let header = SecurityHeader::decode(&[0x7e, 0x02, 1, 2, 3, 4, 9]).unwrap();
        assert_eq!(header.sequence_number, 9);
        assert!(is_security_protected(&[
            0x7e, 0x02, 1, 2, 3, 4, 0, 0x7e, 0x00
        ]));
        assert!(!is_security_protected(&[0x7e, 0x02, 1, 2, 3, 4, 0, 0x7e]));
        assert!(!is_security_protected(&[
            0x7e, 0x00, 0x43, 0, 0, 0, 0, 0, 0
        ]));
        assert!(!is_security_protected(&[
            0x2e, 0x02, 1, 2, 3, 4, 0, 0x7e, 0x00
        ]));
        // The PDU session identity 15 is one
        let release = [0x2e, 0x0f, 0x01, 0xd4];
        assert!(Message::decode(&release).is_ok());
    }

    /// A security header type says what a protected message may hold: new keys for
    /// the SECURITY MODE messages alone, and opaque ciphertext for a ciphered one.
    #[test]
    fn a_security_header_type_says_what_its_message_holds() {
        use SecurityHeaderType as Sht;
        let complete = Message::new_5gmm(RegistrationComplete::new());
        let refused = validate_security_protected_inner_message(
            &complete,
            Sht::IntegrityProtectedAndCipheredWithNewFiveGNasSecurityContext,
        );
        assert!(refused.is_err());
        assert!(
            validate_security_protected_inner_message(&complete, Sht::IntegrityProtected).is_ok()
        );
        let protected = |sht, inner| {
            let header = SecurityHeader {
                extended_protocol_discriminator: EXTENDED_PROTOCOL_DISCRIMINATOR_5GMM,
                security_header_type: sht,
                spare_half_octet: 0,
                message_authentication_code: 0,
                sequence_number: 0,
            };
            Message::SecurityProtected(header, Box::new(inner)).encode()
        };
        let ciphered = Sht::IntegrityProtectedAndCiphered;
        assert_eq!(
            protected(ciphered, Message::Opaque(vec![1])),
            Ok(vec![0x7e, 0x02, 0, 0, 0, 0, 0, 1])
        );
        assert!(protected(ciphered, Message::Opaque(Vec::new())).is_err());
        assert!(protected(Sht::IntegrityProtected, Message::Opaque(vec![1])).is_err());
    }

    /// A CONTROL PLANE SERVICE REQUEST without a small data container has it alone,
    /// whatever else it has.
    #[test]
    fn a_service_request_without_small_data_has_it_alone() {
        let mut request = ControlPlaneServiceRequest::new(
            ControlPlaneServiceType::new(0),
            KeySetIdentifier::new(0),
        );
        request.pdu_session_id = Some(PduSessionIdentity2::new(5));
        assert!(request.ciot_small_data_container_is_exclusive());
    }

    /// A refused message is answered from the plain message under its security header,
    /// and an invalid mandatory IE of a 5GSM request or command by its own answer.
    #[test]
    fn an_invalid_mandatory_ie_is_answered_by_the_message_that_answers_its_message() {
        let invalid = Error::InvalidMandatoryIe {
            ie: crate::common::IeName::of("x"),
            fault: crate::common::IeFault::Syntax,
            reason: None,
        };
        let answered = |octets: &[u8], direction| {
            Message::answer_to_refused(octets, &invalid, direction)
                .map(|answer| answer.encode().unwrap())
        };
        // PDU SESSION MODIFICATION REQUEST and RELEASE REQUEST: their REJECT, cause #96
        assert_eq!(
            answered(&[0x2e, 0x05, 0x01, 0xc9], Direction::Uplink),
            Some(vec![0x2e, 0x05, 0x01, 0xca, 0x60])
        );
        assert_eq!(
            answered(&[0x2e, 0x05, 0x01, 0xd1], Direction::Uplink),
            Some(vec![0x2e, 0x05, 0x01, 0xd2, 0x60])
        );
        // PDU SESSION RELEASE COMMAND: RELEASE COMPLETE, cause #96
        assert_eq!(
            answered(&[0x2e, 0x05, 0x01, 0xd3], Direction::Downlink),
            Some(vec![0x2e, 0x05, 0x01, 0xd4, 0x59, 0x60])
        );
        // The same request under a security header
        assert_eq!(
            answered(
                &[0x7e, 0x01, 1, 2, 3, 4, 0, 0x2e, 0x05, 0x01, 0xc9],
                Direction::Uplink
            ),
            Some(vec![0x2e, 0x05, 0x01, 0xca, 0x60])
        );
    }

    /// An IE that a message keeps among its unknown ones and that its table has a place
    /// for is a finding, a type 1 IE by the half octet of its IEI.
    #[test]
    fn an_unknown_ie_of_an_iei_of_the_table_is_a_finding() {
        let Message::Gmm(_, GmmMessage::RegistrationAccept(mut accept)) =
            Message::decode(&[0x7e, 0x00, 0x42, 0x01, 0x01]).unwrap()
        else {
            panic!("a REGISTRATION ACCEPT");
        };
        // A MICO indication, of the IEI 0xB-
        accept.unknown_ies.push(0xb1, &[]);
        accept
            .optional_ie_order
            .push(crate::common::Placed::Unknown);
        let findings = accept.ie_order_findings();
        let messages: Vec<&str> = findings
            .iter()
            .map(|finding| finding.message.as_str())
            .collect();
        assert_eq!(
            messages,
            ["IEI 0xb1 was ignored as malformed, repeated, or out of sequence"]
        );
    }

    /// An optional IE longer than a sender writes it is a finding of the message.
    #[test]
    fn an_ie_longer_than_a_sender_writes_it_is_a_finding() {
        // REGISTRATION REQUEST with a 5GMM capability of 14 octets: 13 at most
        let mut octets = hex::decode("7e004101000d0102f8390000000021436587f9").unwrap();
        octets.extend([0x10, 14]);
        octets.extend([0; 14]);
        let request = Message::decode(&octets).unwrap();
        let findings = request.validate();
        assert!(
            findings
                .iter()
                .any(|finding| finding.message.contains("a value of 1 to 13 octets")),
            "{findings:?}"
        );
    }

    /// An optional IE set after decoding is written at its place in the table, before
    /// the decoded IEs that come after it, in a message that keeps the order of its IEs.
    #[test]
    fn an_ie_set_after_decoding_is_written_at_its_place_in_the_table() {
        // PDU SESSION ESTABLISHMENT REQUEST with its SSC mode, then a PDU session type out
        // of sequence, which is ignored
        let decoded = Message::decode(&hex::decode("2e0101c1ffffa191").unwrap()).unwrap();
        let Message::Gsm(header, GsmMessage::PduSessionEstablishmentRequest(mut request)) = decoded
        else {
            panic!("a PDU SESSION ESTABLISHMENT REQUEST");
        };
        request.pdu_session_type = Some(PduSessionType::new(0x02));
        let message = Message::Gsm(header, GsmMessage::PduSessionEstablishmentRequest(request));
        assert_eq!(hex::encode(message.encode().unwrap()), "2e0101c1ffff92a191");
    }

    #[test]
    fn innermost_is_the_message_inside_the_security_envelopes() {
        // A REGISTRATION COMPLETE, plain and integrity protected
        let plain = Message::decode(&[0x7e, 0x00, 0x43]).unwrap();
        assert_eq!(plain.innermost(), &plain);
        let protected = Message::decode(&[0x7e, 0x01, 0, 0, 0, 0, 0, 0x7e, 0x00, 0x43]).unwrap();
        assert_eq!(protected.innermost(), &plain);

        // An envelope in an envelope, which a program can build
        let Message::SecurityProtected(header, _) = &protected else {
            panic!("expected a security protected message");
        };
        let nested = Message::SecurityProtected(header.clone(), Box::new(protected.clone()));
        assert_eq!(nested.innermost(), &plain);

        // A ciphered message: its ciphertext
        let ciphered = Message::decode(&[0x7e, 0x02, 0, 0, 0, 0, 0, 0xaa, 0xbb]).unwrap();
        assert_eq!(ciphered.innermost(), &Message::Opaque(vec![0xaa, 0xbb]));
    }
}
