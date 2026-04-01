/*
   OxiRush
   Copyright 2025 Valentin D'Emmanuele

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

//! Typed accessors for NAS Information Elements.
//!
//! This module provides zero-cost typed wrappers over the raw byte-level IE
//! structs defined in [`crate::types`]. The raw `.value` fields remain `pub`
//! for backward compatibility; these accessors add type-safe parsing without
//! heap allocation or copies.
//!
//! # Architecture
//!
//! ```text
//! Layer 3 — This module: typed enums, accessor methods, builder helpers
//! Layer 2 — messages.rs:  NAS message structs with IEI dispatch
//! Layer 1 — types.rs:     raw TLV/TV/V/LV wire codec
//! ```

use crate::types::*;

// ============================================================================
// TIER 1 — Eliminates all manual bit manipulation in consumers
// ============================================================================

// ---------------------------------------------------------------------------
// 5GS Mobile Identity (§9.11.3.4)
// ---------------------------------------------------------------------------

/// Mobile identity type, extracted from bits 1-3 of the first content byte.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum MobileIdentityType {
    /// No identity (TS 24.501 §9.11.3.4, type value 0).
    NoIdentity = 0x00,
    /// SUPI as SUCI
    Suci = 0x01,
    /// 5G-GUTI
    Guti = 0x02,
    /// IMEI
    Imei = 0x03,
    /// 5G-S-TMSI
    STmsi = 0x04,
    /// IMEISV
    Imeisv = 0x05,
    /// MAC address
    MacAddr = 0x06,
    /// EUI-64
    Eui64 = 0x07,
}

impl MobileIdentityType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NoIdentity),
            0x01 => Some(Self::Suci),
            0x02 => Some(Self::Guti),
            0x03 => Some(Self::Imei),
            0x04 => Some(Self::STmsi),
            0x05 => Some(Self::Imeisv),
            0x06 => Some(Self::MacAddr),
            0x07 => Some(Self::Eui64),
            _ => None,
        }
    }
}

/// Parsed 5G-GUTI (§9.11.3.4, Figure 9.11.3.4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Guti {
    pub mcc: [u8; 3],
    pub mnc: [u8; 3], // mnc[2] == 0x0F means 2-digit MNC
    pub amf_region_id: u8,
    pub amf_set_id: u16, // 10 bits
    pub amf_pointer: u8, // 6 bits
    pub tmsi: u32,
}

/// Parsed 5G-S-TMSI (§9.11.3.4, Figure 9.11.3.4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct STmsi {
    pub amf_set_id: u16, // 10 bits
    pub amf_pointer: u8, // 6 bits
    pub tmsi: u32,
}

/// Parsed SUCI (§9.11.3.4, Figure 9.11.3.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Suci {
    pub plmn_id: PlmnId,
    pub routing_indicator: Vec<u8>,
    pub protection_scheme: u8,
    pub home_nw_public_key_id: u8,
    pub scheme_output: Vec<u8>,
}

/// Decode BCD-encoded bytes into a digit string (low nibble first, skip 0xF padding).
fn bcd_to_string(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        let lo = b & 0x0F;
        let hi = (b >> 4) & 0x0F;
        if lo < 10 {
            s.push(char::from(b'0' + lo));
        }
        if hi < 10 {
            s.push(char::from(b'0' + hi));
        }
    }
    s
}

impl Suci {
    /// Format as SUCI NAI string per 3GPP TS 23.003 §28.7.3.
    ///
    /// Output: `suci-0-<MCC>-<MNC>-<RI>-<scheme>-<key_id>-<scheme_output>`
    pub fn to_string(&self) -> String {
        // Decode BCD routing indicator digits
        let ri = bcd_to_string(&self.routing_indicator);
        let scheme_output = if self.protection_scheme == 0 {
            // Null scheme: MSIN in BCD
            bcd_to_string(&self.scheme_output)
        } else {
            hex::encode(&self.scheme_output)
        };
        format!(
            "suci-0-{}-{}-{}-{}-{}-{}",
            self.plmn_id.mcc_string(),
            self.plmn_id.mnc_string(),
            ri,
            self.protection_scheme,
            self.home_nw_public_key_id,
            scheme_output
        )
    }
}

/// PLMN as raw TBCD-encoded 3 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PlmnId {
    pub mcc: [u8; 3],
    pub mnc: [u8; 3],
}

impl PlmnId {
    /// Filler value for 2-digit MNC (3GPP TBCD convention: 0x0F in mnc[2]).
    pub const MNC_2DIGIT_FILLER: u8 = 0x0F;

    /// Decode PLMN from 3 TBCD bytes.
    pub fn from_tbcd(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }
        let mcc = [bytes[0] & 0x0F, (bytes[0] >> 4) & 0x0F, bytes[1] & 0x0F];
        let mnc = [
            bytes[2] & 0x0F,
            (bytes[2] >> 4) & 0x0F,
            (bytes[1] >> 4) & 0x0F, // 0x0F means 2-digit MNC
        ];
        Some(PlmnId { mcc, mnc })
    }

    /// Encode PLMN to 3 TBCD bytes.
    pub fn to_tbcd(&self) -> [u8; 3] {
        [
            (self.mcc[1] << 4) | self.mcc[0],
            (self.mnc[2] << 4) | self.mcc[2],
            (self.mnc[1] << 4) | self.mnc[0],
        ]
    }

    /// MCC as a numeric string (e.g., "208").
    pub fn mcc_string(&self) -> String {
        format!("{}{}{}", self.mcc[0], self.mcc[1], self.mcc[2])
    }

    /// MNC as a numeric string (e.g., "93" or "093").
    pub fn mnc_string(&self) -> String {
        if self.mnc[2] == 0x0F {
            format!("{}{}", self.mnc[0], self.mnc[1])
        } else {
            format!("{}{}{}", self.mnc[0], self.mnc[1], self.mnc[2])
        }
    }
}

impl NasFGsMobileIdentity {
    /// Extract the identity type from bits 1-3 of the first byte.
    pub fn identity_type(&self) -> Option<MobileIdentityType> {
        self.value
            .first()
            .map(|b| MobileIdentityType::from_u8(b & 0x07))
            .flatten()
    }

    /// Parse as 5G-GUTI. Returns `None` if type is not GUTI or bytes are malformed.
    ///
    /// Wire format (13 bytes):
    ///   byte 0: 0xF2 (spare=1111, odd/even=0, type=010)
    ///   bytes 1-3: PLMN (TBCD)
    ///   byte 4: AMF Region ID
    ///   bytes 5-6: AMF Set ID (10 bits) + AMF Pointer (6 bits)
    ///   bytes 7-10: 5G-TMSI
    pub fn as_guti(&self) -> Option<Guti> {
        if self.value.len() < 11 || (self.value[0] & 0x07) != 0x02 {
            return None;
        }
        let plmn = PlmnId::from_tbcd(&self.value[1..4])?;
        let amf_region_id = self.value[4];
        let amf_set_id = ((self.value[5] as u16) << 2) | ((self.value[6] as u16) >> 6);
        let amf_pointer = self.value[6] & 0x3F;
        let tmsi =
            u32::from_be_bytes([self.value[7], self.value[8], self.value[9], self.value[10]]);
        Some(Guti {
            mcc: plmn.mcc,
            mnc: plmn.mnc,
            amf_region_id,
            amf_set_id,
            amf_pointer,
            tmsi,
        })
    }

    /// Parse as 5G-S-TMSI. Returns `None` if type is not S-TMSI.
    ///
    /// Wire format (7 bytes):
    ///   byte 0: spare (4 bits) + odd/even (1 bit) + type=100 (3 bits)
    ///   bytes 1-2: AMF Set ID (10 bits) + AMF Pointer (6 bits)
    ///   bytes 3-6: 5G-TMSI
    pub fn as_s_tmsi(&self) -> Option<STmsi> {
        if self.value.len() < 7 || (self.value[0] & 0x07) != 0x04 {
            return None;
        }
        let amf_set_id = ((self.value[1] as u16) << 2) | ((self.value[2] as u16) >> 6);
        let amf_pointer = self.value[2] & 0x3F;
        let tmsi = u32::from_be_bytes([self.value[3], self.value[4], self.value[5], self.value[6]]);
        Some(STmsi {
            amf_set_id,
            amf_pointer,
            tmsi,
        })
    }

    /// Parse as SUCI. Returns `None` if type is not SUCI.
    ///
    /// Wire format:
    ///   byte 0: spare (4 bits) + SUPI format (3 bits) + type=001 (3 bits)
    ///   bytes 1-3: PLMN (TBCD)
    ///   bytes 4-5: Routing indicator (BCD, 2 bytes)
    ///   byte 6: Protection scheme ID
    ///   byte 7: Home network public key identifier
    ///   bytes 8+: Scheme output
    pub fn as_suci(&self) -> Option<Suci> {
        if self.value.len() < 8 || (self.value[0] & 0x07) != 0x01 {
            return None;
        }
        let plmn = PlmnId::from_tbcd(&self.value[1..4])?;
        let routing_indicator = self.value[4..6].to_vec();
        let protection_scheme = self.value[6];
        let home_nw_public_key_id = self.value[7];
        let scheme_output = self.value[8..].to_vec();
        Some(Suci {
            plmn_id: plmn,
            routing_indicator,
            protection_scheme,
            home_nw_public_key_id,
            scheme_output,
        })
    }

    /// Parse as IMEI. Returns the 15-digit IMEI string.
    pub fn as_imei(&self) -> Option<String> {
        if self.value.is_empty() || (self.value[0] & 0x07) != 0x03 {
            return None;
        }
        Some(decode_bcd_identity(&self.value))
    }

    /// Parse as IMEISV. Returns the 16-digit IMEISV string.
    pub fn as_imeisv(&self) -> Option<String> {
        if self.value.is_empty() || (self.value[0] & 0x07) != 0x05 {
            return None;
        }
        Some(decode_bcd_identity(&self.value))
    }

    /// Extract the 5G-TMSI as a u32, regardless of whether the identity is
    /// a GUTI or S-TMSI.
    pub fn tmsi(&self) -> Option<u32> {
        match self.identity_type()? {
            MobileIdentityType::Guti => self.as_guti().map(|g| g.tmsi),
            MobileIdentityType::STmsi => self.as_s_tmsi().map(|t| t.tmsi),
            _ => None,
        }
    }

    /// Extract the PLMN from SUCI or GUTI identities.
    pub fn plmn(&self) -> Option<PlmnId> {
        match self.identity_type()? {
            MobileIdentityType::Suci | MobileIdentityType::Guti => {
                PlmnId::from_tbcd(&self.value[1..4])
            }
            _ => None,
        }
    }

    /// Construct a GUTI mobile identity from structured fields.
    pub fn from_guti(guti: &Guti) -> Self {
        let plmn = PlmnId {
            mcc: guti.mcc,
            mnc: guti.mnc,
        };
        let tbcd = plmn.to_tbcd();
        let set_ptr_hi = ((guti.amf_set_id >> 2) & 0xFF) as u8;
        let set_ptr_lo = (((guti.amf_set_id & 0x03) << 6) | (guti.amf_pointer as u16 & 0x3F)) as u8;
        let tmsi_bytes = guti.tmsi.to_be_bytes();

        let mut value = Vec::with_capacity(11);
        value.push(0xF2); // spare=1111, even, type=GUTI
        value.extend_from_slice(&tbcd);
        value.push(guti.amf_region_id);
        value.push(set_ptr_hi);
        value.push(set_ptr_lo);
        value.extend_from_slice(&tmsi_bytes);
        Self::new(value)
    }

    /// Construct an S-TMSI mobile identity from structured fields.
    pub fn from_s_tmsi(tmsi: &STmsi) -> Self {
        let set_ptr_hi = ((tmsi.amf_set_id >> 2) & 0xFF) as u8;
        let set_ptr_lo = (((tmsi.amf_set_id & 0x03) << 6) | (tmsi.amf_pointer as u16 & 0x3F)) as u8;
        let tmsi_bytes = tmsi.tmsi.to_be_bytes();

        let mut value = Vec::with_capacity(7);
        value.push(0xF4); // spare=1111, even, type=S-TMSI
        value.push(set_ptr_hi);
        value.push(set_ptr_lo);
        value.extend_from_slice(&tmsi_bytes);
        Self::new(value)
    }
}

/// Decode BCD-encoded IMEI/IMEISV from mobile identity bytes.
fn decode_bcd_identity(bytes: &[u8]) -> String {
    let mut digits = String::with_capacity(16);
    if bytes.is_empty() {
        return digits;
    }
    // First byte: digit1 (bits 5-8) | odd/even (bit 4) | type (bits 1-3)
    let first_digit = (bytes[0] >> 4) & 0x0F;
    if first_digit < 10 {
        digits.push((b'0' + first_digit) as char);
    }
    // Remaining bytes: two BCD digits each (low nibble first, then high nibble)
    for &byte in &bytes[1..] {
        let lo = byte & 0x0F;
        let hi = (byte >> 4) & 0x0F;
        if lo < 10 {
            digits.push((b'0' + lo) as char);
        }
        if hi < 10 {
            digits.push((b'0' + hi) as char);
        }
    }
    digits
}

// ---------------------------------------------------------------------------
// NAS Security Algorithms (§9.11.3.34)
// ---------------------------------------------------------------------------

/// 5G NAS ciphering algorithm (TS 33.501 &sect;5.5).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum CipheringAlgorithm {
    /// Null ciphering (no encryption).
    NEA0 = 0x00,
    /// 128-EEA1 (SNOW 3G).
    NEA1 = 0x01,
    /// 128-EEA2 (AES-128-CTR).
    NEA2 = 0x02,
    /// 128-EEA3 (ZUC).
    NEA3 = 0x03,
}

impl CipheringAlgorithm {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NEA0),
            0x01 => Some(Self::NEA1),
            0x02 => Some(Self::NEA2),
            0x03 => Some(Self::NEA3),
            _ => None,
        }
    }
}

/// 5G NAS integrity algorithm (TS 33.501 &sect;5.5).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum IntegrityAlgorithm {
    /// Null integrity (no protection). Must not be selected in production.
    NIA0 = 0x00,
    /// 128-EIA1 (SNOW 3G UIA2).
    NIA1 = 0x01,
    /// 128-EIA2 (AES-CMAC).
    NIA2 = 0x02,
    /// 128-EIA3 (ZUC MAC).
    NIA3 = 0x03,
}

impl IntegrityAlgorithm {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::NIA0),
            0x01 => Some(Self::NIA1),
            0x02 => Some(Self::NIA2),
            0x03 => Some(Self::NIA3),
            _ => None,
        }
    }
}

impl NasSecurityAlgorithms {
    /// Ciphering algorithm (upper nibble).
    pub fn ciphering(&self) -> Option<CipheringAlgorithm> {
        CipheringAlgorithm::from_u8((self.value >> 4) & 0x0F)
    }

    /// Integrity algorithm (lower nibble).
    pub fn integrity(&self) -> Option<IntegrityAlgorithm> {
        IntegrityAlgorithm::from_u8(self.value & 0x0F)
    }

    /// Construct from typed algorithms.
    pub fn from_algorithms(c: CipheringAlgorithm, i: IntegrityAlgorithm) -> Self {
        Self::new((c as u8) << 4 | (i as u8))
    }
}

// ---------------------------------------------------------------------------
// 5GS Registration Type (§9.11.3.7)
// ---------------------------------------------------------------------------

/// 5GS registration type values (TS 24.501 &sect;9.11.3.7, bits 1-3).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum RegistrationType {
    /// Initial registration (first attach to the network).
    InitialRegistration = 0x01,
    /// Mobility registration updating (TAU equivalent).
    MobilityRegistrationUpdate = 0x02,
    /// Periodic registration updating.
    PeriodicRegistrationUpdate = 0x03,
    /// Emergency registration.
    EmergencyRegistration = 0x04,
    /// SNPN onboarding registration.
    SnpnOnboarding = 0x05,
    /// Disaster roaming mobility registration updating.
    DisasterRoamingMobility = 0x06,
    /// Disaster roaming initial registration.
    DisasterRoamingInitial = 0x07,
}

impl RegistrationType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::InitialRegistration),
            0x02 => Some(Self::MobilityRegistrationUpdate),
            0x03 => Some(Self::PeriodicRegistrationUpdate),
            0x04 => Some(Self::EmergencyRegistration),
            0x05 => Some(Self::SnpnOnboarding),
            0x06 => Some(Self::DisasterRoamingMobility),
            0x07 => Some(Self::DisasterRoamingInitial),
            _ => None,
        }
    }
}

impl NasFGsRegistrationType {
    /// Registration type (bits 1-3 of the lower nibble).
    pub fn registration_type(&self) -> Option<RegistrationType> {
        RegistrationType::from_u8(self.value & 0x07)
    }

    /// Follow-on request indicator (bit 4 of the lower nibble).
    pub fn follow_on_request(&self) -> bool {
        (self.value >> 3) & 1 != 0
    }

    /// ngKSI value (bits 1-3 of the upper nibble).
    pub fn ngksi(&self) -> u8 {
        (self.value >> 4) & 0x07
    }

    /// TSC flag (bit 4 of the upper nibble).
    pub fn tsc(&self) -> bool {
        (self.value >> 7) & 1 != 0
    }

    /// Construct from typed fields. The byte packs ngKSI in the upper nibble
    /// and (FOR | registration_type) in the lower nibble.
    pub fn from_parts(reg_type: RegistrationType, for_flag: bool, ngksi: u8, tsc: bool) -> Self {
        let lower = (reg_type as u8) | ((for_flag as u8) << 3);
        let upper = (ngksi & 0x07) | ((tsc as u8) << 3);
        Self::new((upper << 4) | lower)
    }
}

// ---------------------------------------------------------------------------
// NAS Key Set Identifier (§9.11.3.32)
// ---------------------------------------------------------------------------

/// Special value indicating no NAS key is available.
pub const NAS_KSI_NO_KEY_AVAILABLE: u8 = 0x07;

impl NasKeySetIdentifier {
    /// NAS key set identifier (bits 1-3).
    pub fn ngksi(&self) -> u8 {
        self.value & 0x07
    }

    /// Type of security context (bit 4): false = native, true = mapped.
    pub fn tsc(&self) -> bool {
        (self.value >> 3) & 1 != 0
    }

    /// Whether no key is available (KSI = 111).
    pub fn no_key_available(&self) -> bool {
        self.ngksi() == NAS_KSI_NO_KEY_AVAILABLE
    }

    /// Construct from typed fields.
    pub fn from_parts(ngksi: u8, tsc: bool) -> Self {
        Self::new((ngksi & 0x07) | ((tsc as u8) << 3))
    }
}

// ---------------------------------------------------------------------------
// 5GS Identity Type (§9.11.3.3)
// ---------------------------------------------------------------------------

impl NasFGsIdentityType {
    /// Identity type (bits 1-3).
    pub fn identity_type(&self) -> Option<MobileIdentityType> {
        MobileIdentityType::from_u8(self.value & 0x07)
    }

    /// Construct from identity type.
    pub fn from_identity_type(t: MobileIdentityType) -> Self {
        Self::new(t as u8)
    }
}

// ============================================================================
// TIER 2 — Cause codes, timers, payload container type
// ============================================================================

// ---------------------------------------------------------------------------
// 5GMM Cause (§9.11.3.2, Table 9.11.3.2.1)
// ---------------------------------------------------------------------------

/// 5GMM cause values per TS 24.501 Table 9.11.3.2.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum GmmCause {
    IllegalUe = 0x03,
    PeiNotAccepted = 0x05,
    IllegalMe = 0x06,
    FiveGSServicesNotAllowed = 0x07,
    UeIdentityCannotBeDerived = 0x09,
    ImplicitlyDeregistered = 0x0A,
    PlmnNotAllowed = 0x0B,
    TrackingAreaNotAllowed = 0x0C,
    RoamingNotAllowedInTa = 0x0D,
    NoCellsInTa = 0x0F,
    N1ModeNotAllowed = 0x1B,
    MacFailure = 0x14,
    SynchFailure = 0x15,
    Congestion = 0x16,
    UeSecurityCapMismatch = 0x17,
    SecurityModeRejected = 0x18,
    Non5GAuthUnacceptable = 0x1A,
    RestrictedServiceArea = 0x1C,
    LadnNotAvailable = 0x2B,
    MaxPduSessionsReached = 0x41,
    InsufficientResourcesForSliceDnn = 0x43,
    NotAuthorizedForSlice = 0x44,
    InsufficientResourcesForSlice = 0x45,
    RequestRejectedUnspecified = 0x1F,
    InvalidMandatoryInformation = 0x60,
    MessageTypeNotExistent = 0x61,
    MessageTypeNotCompatible = 0x62,
    InformationElementNotExistent = 0x63,
    ConditionalIeError = 0x64,
    MessageNotCompatible = 0x65,
    ProtocolErrorUnspecified = 0x6F,
}

impl GmmCause {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x03 => Some(Self::IllegalUe),
            0x05 => Some(Self::PeiNotAccepted),
            0x06 => Some(Self::IllegalMe),
            0x07 => Some(Self::FiveGSServicesNotAllowed),
            0x09 => Some(Self::UeIdentityCannotBeDerived),
            0x0A => Some(Self::ImplicitlyDeregistered),
            0x0B => Some(Self::PlmnNotAllowed),
            0x0C => Some(Self::TrackingAreaNotAllowed),
            0x0D => Some(Self::RoamingNotAllowedInTa),
            0x0F => Some(Self::NoCellsInTa),
            0x14 => Some(Self::MacFailure),
            0x15 => Some(Self::SynchFailure),
            0x16 => Some(Self::Congestion),
            0x17 => Some(Self::UeSecurityCapMismatch),
            0x18 => Some(Self::SecurityModeRejected),
            0x1A => Some(Self::Non5GAuthUnacceptable),
            0x1B => Some(Self::N1ModeNotAllowed),
            0x1C => Some(Self::RestrictedServiceArea),
            0x1F => Some(Self::RequestRejectedUnspecified),
            0x2B => Some(Self::LadnNotAvailable),
            0x41 => Some(Self::MaxPduSessionsReached),
            0x43 => Some(Self::InsufficientResourcesForSliceDnn),
            0x44 => Some(Self::NotAuthorizedForSlice),
            0x45 => Some(Self::InsufficientResourcesForSlice),
            0x60 => Some(Self::InvalidMandatoryInformation),
            0x61 => Some(Self::MessageTypeNotExistent),
            0x62 => Some(Self::MessageTypeNotCompatible),
            0x63 => Some(Self::InformationElementNotExistent),
            0x64 => Some(Self::ConditionalIeError),
            0x65 => Some(Self::MessageNotCompatible),
            0x6F => Some(Self::ProtocolErrorUnspecified),
            _ => None,
        }
    }

    /// Human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::IllegalUe => "Illegal UE",
            Self::PeiNotAccepted => "PEI not accepted",
            Self::IllegalMe => "Illegal ME",
            Self::FiveGSServicesNotAllowed => "5GS services not allowed",
            Self::UeIdentityCannotBeDerived => "UE identity cannot be derived by the network",
            Self::ImplicitlyDeregistered => "Implicitly deregistered",
            Self::PlmnNotAllowed => "PLMN not allowed",
            Self::TrackingAreaNotAllowed => "Tracking area not allowed",
            Self::RoamingNotAllowedInTa => "Roaming not allowed in this tracking area",
            Self::NoCellsInTa => "No suitable cells in tracking area",
            Self::MacFailure => "MAC failure",
            Self::SynchFailure => "Synch failure",
            Self::Congestion => "Congestion",
            Self::UeSecurityCapMismatch => "UE security capabilities mismatch",
            Self::SecurityModeRejected => "Security mode rejected, unspecified",
            Self::Non5GAuthUnacceptable => "Non-5G authentication unacceptable",
            Self::N1ModeNotAllowed => "N1 mode not allowed",
            Self::RestrictedServiceArea => "Restricted service area",
            Self::RequestRejectedUnspecified => "Request rejected, unspecified",
            Self::LadnNotAvailable => "LADN not available",
            Self::MaxPduSessionsReached => "Maximum number of PDU sessions reached",
            Self::InsufficientResourcesForSliceDnn => {
                "Insufficient resources for specific slice and DNN"
            }
            Self::NotAuthorizedForSlice => "Not authorized for this network slice",
            Self::InsufficientResourcesForSlice => "Insufficient resources for specific slice",
            Self::InvalidMandatoryInformation => "Invalid mandatory information",
            Self::MessageTypeNotExistent => "Message type non-existent or not implemented",
            Self::MessageTypeNotCompatible => "Message type not compatible with protocol state",
            Self::InformationElementNotExistent => {
                "Information element non-existent or not implemented"
            }
            Self::ConditionalIeError => "Conditional IE error",
            Self::MessageNotCompatible => "Message not compatible with protocol state",
            Self::ProtocolErrorUnspecified => "Protocol error, unspecified",
        }
    }
}

impl NasFGmmCause {
    /// Parse as typed cause enum.
    pub fn cause(&self) -> Option<GmmCause> {
        GmmCause::from_u8(self.value)
    }

    /// Human-readable description (returns hex for unknown values).
    pub fn description(&self) -> String {
        match self.cause() {
            Some(c) => c.description().to_string(),
            None => format!("Unknown 5GMM cause 0x{:02X}", self.value),
        }
    }

    /// Construct from typed cause.
    pub fn from_cause(c: GmmCause) -> Self {
        Self::new(c as u8)
    }
}

// ---------------------------------------------------------------------------
// 5GSM Cause (§9.11.4.2, Table 9.11.4.2.1)
// ---------------------------------------------------------------------------

/// 5GSM cause values per TS 24.501 Table 9.11.4.2.1.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum GsmCause {
    OperatorDeterminedBarring = 0x08,
    InsufficientResources = 0x1A,
    MissingOrUnknownDnn = 0x1B,
    UnknownPduSessionType = 0x1C,
    UserAuthFailed = 0x1D,
    RequestRejectedUnspecified = 0x1F,
    ServiceOptionNotSupported = 0x20,
    ServiceOptionNotSubscribed = 0x21,
    PtiAlreadyInUse = 0x23,
    RegularDeactivation = 0x24,
    NetworkFailure = 0x26,
    ReactivationRequested = 0x27,
    InvalidPduSessionIdentity = 0x2B,
    SemanticErrorInTft = 0x29,
    SyntacticalErrorInTft = 0x2A,
    SemanticErrorInPacketFilter = 0x2C,
    SyntacticalErrorInPacketFilter = 0x2D,
    OutOfLadnServiceArea = 0x2E,
    PtiMismatch = 0x2F,
    PduSessionTypeIpv4Only = 0x32,
    PduSessionTypeIpv6Only = 0x33,
    PduSessionDoesNotExist = 0x36,
    InsufficientResourcesForSliceDnn = 0x43,
    NotSupportedSscMode = 0x44,
    InsufficientResourcesForSlice = 0x45,
    MissingOrUnknownDnnInSlice = 0x46,
    InvalidMandatoryInformation = 0x60,
    MessageTypeNotExistent = 0x61,
    MessageTypeNotCompatible = 0x62,
    InformationElementNotExistent = 0x63,
    ConditionalIeError = 0x64,
    MessageNotCompatible = 0x65,
    ProtocolErrorUnspecified = 0x6F,
}

impl GsmCause {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x08 => Some(Self::OperatorDeterminedBarring),
            0x1A => Some(Self::InsufficientResources),
            0x1B => Some(Self::MissingOrUnknownDnn),
            0x1C => Some(Self::UnknownPduSessionType),
            0x1D => Some(Self::UserAuthFailed),
            0x1F => Some(Self::RequestRejectedUnspecified),
            0x20 => Some(Self::ServiceOptionNotSupported),
            0x21 => Some(Self::ServiceOptionNotSubscribed),
            0x23 => Some(Self::PtiAlreadyInUse),
            0x24 => Some(Self::RegularDeactivation),
            0x26 => Some(Self::NetworkFailure),
            0x27 => Some(Self::ReactivationRequested),
            0x29 => Some(Self::SemanticErrorInTft),
            0x2A => Some(Self::SyntacticalErrorInTft),
            0x2B => Some(Self::InvalidPduSessionIdentity),
            0x2C => Some(Self::SemanticErrorInPacketFilter),
            0x2D => Some(Self::SyntacticalErrorInPacketFilter),
            0x2E => Some(Self::OutOfLadnServiceArea),
            0x2F => Some(Self::PtiMismatch),
            0x32 => Some(Self::PduSessionTypeIpv4Only),
            0x33 => Some(Self::PduSessionTypeIpv6Only),
            0x36 => Some(Self::PduSessionDoesNotExist),
            0x43 => Some(Self::InsufficientResourcesForSliceDnn),
            0x44 => Some(Self::NotSupportedSscMode),
            0x45 => Some(Self::InsufficientResourcesForSlice),
            0x46 => Some(Self::MissingOrUnknownDnnInSlice),
            0x60 => Some(Self::InvalidMandatoryInformation),
            0x61 => Some(Self::MessageTypeNotExistent),
            0x62 => Some(Self::MessageTypeNotCompatible),
            0x63 => Some(Self::InformationElementNotExistent),
            0x64 => Some(Self::ConditionalIeError),
            0x65 => Some(Self::MessageNotCompatible),
            0x6F => Some(Self::ProtocolErrorUnspecified),
            _ => None,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::OperatorDeterminedBarring => "Operator determined barring",
            Self::InsufficientResources => "Insufficient resources",
            Self::MissingOrUnknownDnn => "Missing or unknown DNN",
            Self::UnknownPduSessionType => "Unknown PDU session type",
            Self::UserAuthFailed => "User authentication or authorization failed",
            Self::RequestRejectedUnspecified => "Request rejected, unspecified",
            Self::ServiceOptionNotSupported => "Service option not supported",
            Self::ServiceOptionNotSubscribed => "Requested service option not subscribed",
            Self::PtiAlreadyInUse => "PTI already in use",
            Self::RegularDeactivation => "Regular deactivation",
            Self::NetworkFailure => "Network failure",
            Self::ReactivationRequested => "Reactivation requested",
            Self::SemanticErrorInTft => "Semantic error in the TFT operation",
            Self::SyntacticalErrorInTft => "Syntactical error in the TFT operation",
            Self::InvalidPduSessionIdentity => "Invalid PDU session identity",
            Self::SemanticErrorInPacketFilter => "Semantic errors in packet filter(s)",
            Self::SyntacticalErrorInPacketFilter => "Syntactical errors in packet filter(s)",
            Self::OutOfLadnServiceArea => "Out of LADN service area",
            Self::PtiMismatch => "PTI mismatch",
            Self::PduSessionTypeIpv4Only => "PDU session type IPv4 only allowed",
            Self::PduSessionTypeIpv6Only => "PDU session type IPv6 only allowed",
            Self::PduSessionDoesNotExist => "PDU session does not exist",
            Self::InsufficientResourcesForSliceDnn => {
                "Insufficient resources for specific slice and DNN"
            }
            Self::NotSupportedSscMode => "Not supported SSC mode",
            Self::InsufficientResourcesForSlice => "Insufficient resources for specific slice",
            Self::MissingOrUnknownDnnInSlice => "Missing or unknown DNN in a slice",
            Self::InvalidMandatoryInformation => "Invalid mandatory information",
            Self::MessageTypeNotExistent => "Message type non-existent or not implemented",
            Self::MessageTypeNotCompatible => "Message type not compatible with protocol state",
            Self::InformationElementNotExistent => {
                "Information element non-existent or not implemented"
            }
            Self::ConditionalIeError => "Conditional IE error",
            Self::MessageNotCompatible => "Message not compatible with protocol state",
            Self::ProtocolErrorUnspecified => "Protocol error, unspecified",
        }
    }
}

impl NasFGsmCause {
    /// Parse as typed cause enum.
    pub fn cause(&self) -> Option<GsmCause> {
        GsmCause::from_u8(self.value)
    }

    /// Human-readable description.
    pub fn description(&self) -> String {
        match self.cause() {
            Some(c) => c.description().to_string(),
            None => format!("Unknown 5GSM cause 0x{:02X}", self.value),
        }
    }

    /// Construct from typed cause.
    pub fn from_cause(c: GsmCause) -> Self {
        Self {
            type_field: 0,
            value: c as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// GPRS Timer 3 (§9.11.2.5)
// ---------------------------------------------------------------------------

/// Timer unit for GPRS Timer 3.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TimerUnit {
    /// Value is in multiples of 10 minutes
    TenMinutes,
    /// Value is in multiples of 1 hour
    OneHour,
    /// Value is in multiples of 10 hours
    TenHours,
    /// Value is in multiples of 2 seconds
    TwoSeconds,
    /// Value is in multiples of 30 seconds
    ThirtySeconds,
    /// Value is in multiples of 1 minute
    OneMinute,
    /// Value is in multiples of 320 hours
    ThreeHundredTwentyHours,
    /// Timer is deactivated
    Deactivated,
}

impl TimerUnit {
    pub fn from_u8(v: u8) -> Self {
        match v & 0x07 {
            0 => Self::TenMinutes,
            1 => Self::OneHour,
            2 => Self::TenHours,
            3 => Self::TwoSeconds,
            4 => Self::ThirtySeconds,
            5 => Self::OneMinute,
            6 => Self::ThreeHundredTwentyHours,
            _ => Self::Deactivated,
        }
    }

    /// Multiplier in seconds for this unit.
    pub fn seconds_multiplier(&self) -> u64 {
        match self {
            Self::TwoSeconds => 2,
            Self::ThirtySeconds => 30,
            Self::OneMinute => 60,
            Self::TenMinutes => 600,
            Self::OneHour => 3600,
            Self::TenHours => 36000,
            Self::ThreeHundredTwentyHours => 1_152_000,
            Self::Deactivated => 0,
        }
    }
}

impl NasGprsTimer3 {
    /// Timer unit (bits 6-8 of the value byte).
    pub fn unit(&self) -> TimerUnit {
        self.value
            .first()
            .map(|b| TimerUnit::from_u8(b >> 5))
            .unwrap_or(TimerUnit::Deactivated)
    }

    /// Timer value (bits 1-5 of the value byte).
    pub fn timer_value(&self) -> u8 {
        self.value.first().map(|b| b & 0x1F).unwrap_or(0)
    }

    /// Timer duration in seconds. Returns 0 if deactivated.
    pub fn to_seconds(&self) -> u64 {
        let unit = self.unit();
        unit.seconds_multiplier() * self.timer_value() as u64
    }
}

// ---------------------------------------------------------------------------
// GPRS Timer 2 (§10.5.7.4a — TS 24.008)
// ---------------------------------------------------------------------------

impl NasGprsTimer2 {
    /// Timer duration in seconds. Returns `None` if deactivated (unit 0b111).
    ///
    /// Units per TS 24.008 §10.5.7.4a:
    ///   0b000 = multiples of 2 seconds
    ///   0b001 = multiples of 1 minute
    ///   0b010 = multiples of 6 minutes (decihours)
    ///   0b011 = multiples of 1 second (Rel-17)
    ///   0b100 = multiples of 30 seconds (Rel-17)
    ///   0b111 = timer deactivated
    pub fn to_seconds(&self) -> Option<u64> {
        let byte = *self.value.first()?;
        let unit = (byte >> 5) & 0x07;
        let val = (byte & 0x1F) as u64;
        match unit {
            0b000 => Some(val * 2),
            0b001 => Some(val * 60),
            0b010 => Some(val * 360), // decihours (6 min)
            0b011 => Some(val),       // seconds (Rel-17)
            0b100 => Some(val * 30),  // 30s multiples (Rel-17)
            0b111 => None,            // deactivated
            _ => Some(val * 60),      // unknown unit → treat as minutes
        }
    }
}

// ---------------------------------------------------------------------------
// Payload Container Type (§9.11.3.40)
// ---------------------------------------------------------------------------

/// Payload container type values.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum PayloadContainerKind {
    N1SmInformation = 0x01,
    Sms = 0x02,
    LtePp = 0x03,
    SorTransparentContainer = 0x04,
    UePolicy = 0x05,
    UeParametersUpdate = 0x06,
    LocationServices = 0x07,
    CIoT = 0x08,
    MultiplePayloads = 0x0F,
}

impl PayloadContainerKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x0F {
            0x01 => Some(Self::N1SmInformation),
            0x02 => Some(Self::Sms),
            0x03 => Some(Self::LtePp),
            0x04 => Some(Self::SorTransparentContainer),
            0x05 => Some(Self::UePolicy),
            0x06 => Some(Self::UeParametersUpdate),
            0x07 => Some(Self::LocationServices),
            0x08 => Some(Self::CIoT),
            0x0F => Some(Self::MultiplePayloads),
            _ => None,
        }
    }
}

impl NasPayloadContainerType {
    /// Typed payload container kind.
    pub fn kind(&self) -> Option<PayloadContainerKind> {
        PayloadContainerKind::from_u8(self.value)
    }

    /// Whether this is N1 SM information (most common case).
    pub fn is_n1_sm(&self) -> bool {
        (self.value & 0x0F) == 0x01
    }
}

// ---------------------------------------------------------------------------
// PDU Session Type (§9.11.4.11)
// ---------------------------------------------------------------------------

impl NasPduSessionType {
    /// PDU session type value (lower 3 bits): 1=IPv4, 2=IPv6, 3=IPv4v6, etc.
    pub fn session_type(&self) -> u8 {
        self.value & 0x07
    }
}

// ============================================================================
// TIER 3 — Structured sub-IEs and status bitmasks
// ============================================================================

// ---------------------------------------------------------------------------
// UE Security Capability (§9.11.3.54)
// ---------------------------------------------------------------------------

impl NasUeSecurityCapability {
    /// 5GS encryption algorithms byte (EA0-EA7). Byte 0 of value.
    pub fn ea_byte(&self) -> u8 {
        self.value.first().copied().unwrap_or(0)
    }

    /// 5GS integrity algorithms byte (IA0-IA7). Byte 1 of value.
    pub fn ia_byte(&self) -> u8 {
        self.value.get(1).copied().unwrap_or(0)
    }

    /// Whether a specific 5GS encryption algorithm is supported (0=EA0, 1=EA1, etc).
    pub fn supports_ea(&self, algo: u8) -> bool {
        if algo > 7 {
            return false;
        }
        (self.ea_byte() >> (7 - algo)) & 1 != 0
    }

    /// Whether a specific 5GS integrity algorithm is supported.
    pub fn supports_ia(&self, algo: u8) -> bool {
        if algo > 7 {
            return false;
        }
        (self.ia_byte() >> (7 - algo)) & 1 != 0
    }

    /// Construct from EA and IA bytes.
    pub fn from_capabilities(ea: u8, ia: u8) -> Self {
        Self::new(vec![ea, ia])
    }
}

// ---------------------------------------------------------------------------
// PDU Session Status (§9.11.3.44)
// ---------------------------------------------------------------------------

impl NasPduSessionStatus {
    /// Whether a given PDU session ID (1-15) is active.
    pub fn is_active(&self, session_id: u8) -> bool {
        if session_id == 0 || session_id > 15 {
            return false;
        }
        let byte_idx = (session_id / 8) as usize;
        let bit_idx = session_id % 8;
        self.value
            .get(byte_idx)
            .map(|b| (b >> bit_idx) & 1 != 0)
            .unwrap_or(false)
    }

    /// List all active PDU session IDs.
    pub fn active_sessions(&self) -> Vec<u8> {
        (1..=15).filter(|&id| self.is_active(id)).collect()
    }

    /// Construct from a list of active session IDs.
    pub fn from_sessions(sessions: &[u8]) -> Self {
        let mut bytes = [0u8; 2];
        for &id in sessions {
            if id >= 1 && id <= 15 {
                let byte_idx = (id / 8) as usize;
                let bit_idx = id % 8;
                bytes[byte_idx] |= 1 << bit_idx;
            }
        }
        Self::new(bytes.to_vec())
    }
}

// ---------------------------------------------------------------------------
// S-NSSAI (§9.11.2.8)
// ---------------------------------------------------------------------------

/// Parsed S-NSSAI contents.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SNssaiContents {
    /// Slice/Service Type (mandatory, 1 byte).
    pub sst: u8,
    /// Slice Differentiator (optional, 3 bytes).
    pub sd: Option<[u8; 3]>,
    /// Mapped HPLMN SST (optional, 1 byte).
    pub mapped_sst: Option<u8>,
    /// Mapped HPLMN SD (optional, 3 bytes).
    pub mapped_sd: Option<[u8; 3]>,
}

impl NasSNssai {
    /// Parse the S-NSSAI value bytes into structured fields.
    pub fn parse(&self) -> Option<SNssaiContents> {
        if self.value.is_empty() {
            return None;
        }
        let sst = self.value[0];
        let mut sd = None;
        let mut mapped_sst = None;
        let mut mapped_sd = None;

        match self.value.len() {
            1 => {} // SST only
            4 => {
                // SST + SD
                sd = Some([self.value[1], self.value[2], self.value[3]]);
            }
            5 => {
                // SST + SD + mapped SST
                sd = Some([self.value[1], self.value[2], self.value[3]]);
                mapped_sst = Some(self.value[4]);
            }
            8 => {
                // SST + SD + mapped SST + mapped SD
                sd = Some([self.value[1], self.value[2], self.value[3]]);
                mapped_sst = Some(self.value[4]);
                mapped_sd = Some([self.value[5], self.value[6], self.value[7]]);
            }
            2 => {
                // SST + mapped SST (no SD)
                mapped_sst = Some(self.value[1]);
            }
            _ => {} // best-effort: return what we can parse
        }

        Some(SNssaiContents {
            sst,
            sd,
            mapped_sst,
            mapped_sd,
        })
    }

    /// Construct from SST and optional SD.
    pub fn from_sst_sd(sst: u8, sd: Option<[u8; 3]>) -> Self {
        let mut value = vec![sst];
        if let Some(sd) = sd {
            value.extend_from_slice(&sd);
        }
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// DNN (§9.11.2.1B)
// ---------------------------------------------------------------------------

impl NasDnn {
    /// Decode DNN from DNS label encoding to a dot-separated string.
    ///
    /// Wire format: length-prefixed labels (e.g., `\x08internet` → "internet").
    pub fn as_string(&self) -> Option<String> {
        if self.value.is_empty() {
            return None;
        }
        let mut result = String::new();
        let mut pos = 0;
        while pos < self.value.len() {
            let label_len = self.value[pos] as usize;
            pos += 1;
            if pos + label_len > self.value.len() {
                return None;
            }
            if !result.is_empty() {
                result.push('.');
            }
            result.push_str(std::str::from_utf8(&self.value[pos..pos + label_len]).ok()?);
            pos += label_len;
        }
        Some(result)
    }

    /// Encode a dot-separated DNN string to DNS label format.
    pub fn from_string(dnn: &str) -> Self {
        let mut value = Vec::new();
        for label in dnn.split('.') {
            value.push(label.len() as u8);
            value.extend_from_slice(label.as_bytes());
        }
        Self::new(value)
    }
}

// ---------------------------------------------------------------------------
// De-registration Type (§9.11.3.20)
// ---------------------------------------------------------------------------

impl NasDeRegistrationType {
    /// Switch off flag (bit 4).
    pub fn switch_off(&self) -> bool {
        (self.value >> 3) & 1 != 0
    }

    /// Re-registration required flag (bit 4, same position as switch_off but for network-originated).
    pub fn re_registration_required(&self) -> bool {
        (self.value >> 3) & 1 != 0
    }

    /// Access type (bits 1-2): 1 = 3GPP, 2 = non-3GPP, 3 = both.
    pub fn access_type(&self) -> u8 {
        self.value & 0x03
    }

    /// ngKSI (bits 5-7 of the upper nibble, when packed with KSI).
    pub fn ngksi(&self) -> u8 {
        (self.value >> 4) & 0x07
    }
}

// ---------------------------------------------------------------------------
// 5GS Registration Result (§9.11.3.6)
// ---------------------------------------------------------------------------

impl NasFGsRegistrationResult {
    /// Registration result value (bits 1-3 of first byte).
    pub fn result_value(&self) -> u8 {
        self.value.first().map(|b| b & 0x07).unwrap_or(0)
    }

    /// SMS over NAS allowed (bit 4).
    pub fn sms_allowed(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 3) & 1 != 0)
            .unwrap_or(false)
    }

    /// NSSAA to be performed (bit 5).
    pub fn nssaa_performed(&self) -> bool {
        self.value
            .first()
            .map(|b| (b >> 4) & 1 != 0)
            .unwrap_or(false)
    }
}

// ---------------------------------------------------------------------------
// Service type (§9.11.3.50) — upper nibble of ServiceRequest's first byte
// ---------------------------------------------------------------------------

/// Service type values per TS 24.501 §9.11.3.50.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(u8)]
pub enum ServiceType {
    Signalling = 0x00,
    Data = 0x01,
    MobileTerminatedServices = 0x02,
    EmergencyServices = 0x03,
    EmergencyServicesFallback = 0x04,
    HighPriorityAccess = 0x05,
    ElevatedSignalling = 0x06,
    UnusedOrReserved = 0x07,
}

impl ServiceType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v & 0x07 {
            0x00 => Some(Self::Signalling),
            0x01 => Some(Self::Data),
            0x02 => Some(Self::MobileTerminatedServices),
            0x03 => Some(Self::EmergencyServices),
            0x04 => Some(Self::EmergencyServicesFallback),
            0x05 => Some(Self::HighPriorityAccess),
            0x06 => Some(Self::ElevatedSignalling),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Access type (§9.11.2.1A)
// ---------------------------------------------------------------------------

impl NasAccessType {
    /// Access type value (lower nibble, bits 1-2).
    pub fn access_type(&self) -> u8 {
        self.value & 0x03
    }
}

// ---------------------------------------------------------------------------
// NAS Message Container (§9.11.3.33) — recursive decode
// ---------------------------------------------------------------------------

impl NasMessageContainer {
    /// Decode the inner NAS message from this container's raw bytes.
    ///
    /// The container holds a complete NAS message (including EPD + header).
    /// Returns the decoded message, or an error if the bytes are malformed.
    pub fn decode_inner(&self) -> crate::types::Result<crate::messages::Nas5gsMessage> {
        crate::messages::decode_nas_5gs_message(&self.value)
    }
}

// ---------------------------------------------------------------------------
// Payload Container — recursive decode for N1 SM
// ---------------------------------------------------------------------------

impl NasPayloadContainer {
    /// Decode the payload as a 5GSM message (when payload container type = N1 SM).
    ///
    /// The container holds a complete 5GSM NAS message (EPD=0x2E + header + body).
    pub fn decode_as_gsm(&self) -> crate::types::Result<crate::messages::Nas5gsMessage> {
        crate::messages::decode_nas_5gs_message(&self.value)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plmn_tbcd_roundtrip() {
        // MCC=208, MNC=93 (2-digit)
        let plmn = PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
        };
        let tbcd = plmn.to_tbcd();
        let parsed = PlmnId::from_tbcd(&tbcd).unwrap();
        assert_eq!(parsed.mcc, plmn.mcc);
        assert_eq!(parsed.mnc, plmn.mnc);
        assert_eq!(parsed.mcc_string(), "208");
        assert_eq!(parsed.mnc_string(), "93");
    }

    #[test]
    fn test_plmn_3digit_mnc() {
        // MCC=310, MNC=260
        let plmn = PlmnId {
            mcc: [3, 1, 0],
            mnc: [2, 6, 0],
        };
        let tbcd = plmn.to_tbcd();
        let parsed = PlmnId::from_tbcd(&tbcd).unwrap();
        assert_eq!(parsed.mcc_string(), "310");
        assert_eq!(parsed.mnc_string(), "260");
    }

    #[test]
    fn test_guti_roundtrip() {
        let guti = Guti {
            mcc: [2, 0, 8],
            mnc: [9, 3, 0x0F],
            amf_region_id: 0x02,
            amf_set_id: 0x40,  // 10 bits
            amf_pointer: 0x00, // 6 bits
            tmsi: 0xC00002DF,
        };
        let identity = NasFGsMobileIdentity::from_guti(&guti);
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::Guti));
        let parsed = identity.as_guti().unwrap();
        assert_eq!(parsed.mcc, guti.mcc);
        assert_eq!(parsed.mnc, guti.mnc);
        assert_eq!(parsed.amf_region_id, guti.amf_region_id);
        assert_eq!(parsed.amf_set_id, guti.amf_set_id);
        assert_eq!(parsed.amf_pointer, guti.amf_pointer);
        assert_eq!(parsed.tmsi, guti.tmsi);
    }

    #[test]
    fn test_s_tmsi_roundtrip() {
        let tmsi = STmsi {
            amf_set_id: 0x40,
            amf_pointer: 0x00,
            tmsi: 0xDEADBEEF,
        };
        let identity = NasFGsMobileIdentity::from_s_tmsi(&tmsi);
        assert_eq!(identity.identity_type(), Some(MobileIdentityType::STmsi));
        let parsed = identity.as_s_tmsi().unwrap();
        assert_eq!(parsed.amf_set_id, tmsi.amf_set_id);
        assert_eq!(parsed.amf_pointer, tmsi.amf_pointer);
        assert_eq!(parsed.tmsi, tmsi.tmsi);
    }

    #[test]
    fn test_security_algorithms() {
        let sa = NasSecurityAlgorithms::from_algorithms(
            CipheringAlgorithm::NEA2,
            IntegrityAlgorithm::NIA2,
        );
        assert_eq!(sa.value, 0x22);
        assert_eq!(sa.ciphering(), Some(CipheringAlgorithm::NEA2));
        assert_eq!(sa.integrity(), Some(IntegrityAlgorithm::NIA2));
    }

    #[test]
    fn test_registration_type() {
        let rt = NasFGsRegistrationType::from_parts(
            RegistrationType::InitialRegistration,
            true,  // FOR
            0x07,  // ngKSI = no key
            false, // TSC = native
        );
        assert_eq!(rt.value, 0x79); // 0111_1001
        assert_eq!(
            rt.registration_type(),
            Some(RegistrationType::InitialRegistration)
        );
        assert!(rt.follow_on_request());
        assert_eq!(rt.ngksi(), 0x07);
        assert!(!rt.tsc());
    }

    #[test]
    fn test_nas_ksi() {
        let ksi = NasKeySetIdentifier::from_parts(3, false);
        assert_eq!(ksi.value, 0x03);
        assert_eq!(ksi.ngksi(), 3);
        assert!(!ksi.tsc());
        assert!(!ksi.no_key_available());

        let no_key = NasKeySetIdentifier::from_parts(NAS_KSI_NO_KEY_AVAILABLE, false);
        assert!(no_key.no_key_available());
    }

    #[test]
    fn test_gmm_cause() {
        let cause = NasFGmmCause::from_cause(GmmCause::IllegalUe);
        assert_eq!(cause.value, 0x03);
        assert_eq!(cause.cause(), Some(GmmCause::IllegalUe));
        assert_eq!(cause.description(), "Illegal UE");
    }

    #[test]
    fn test_gsm_cause() {
        let cause = NasFGsmCause::from_cause(GsmCause::RegularDeactivation);
        assert_eq!(cause.value, 0x24);
        assert_eq!(cause.cause(), Some(GsmCause::RegularDeactivation));
    }

    #[test]
    fn test_gprs_timer3() {
        // 5 minutes = unit=OneMinute(5), value=5
        let timer = NasGprsTimer3::new(vec![(5 << 5) | 5]);
        assert_eq!(timer.unit(), TimerUnit::OneMinute);
        assert_eq!(timer.timer_value(), 5);
        assert_eq!(timer.to_seconds(), 300);
    }

    #[test]
    fn test_ue_security_capability() {
        // EA0=1, EA1=1, EA2=1; IA0=1, IA1=1, IA2=1
        let cap = NasUeSecurityCapability::from_capabilities(0xE0, 0xE0);
        assert!(cap.supports_ea(0)); // EA0
        assert!(cap.supports_ea(1)); // EA1
        assert!(cap.supports_ea(2)); // EA2
        assert!(!cap.supports_ea(3));
        assert!(cap.supports_ia(0));
        assert!(cap.supports_ia(1));
        assert!(cap.supports_ia(2));
        assert!(!cap.supports_ia(3));
    }

    #[test]
    fn test_pdu_session_status() {
        let status = NasPduSessionStatus::from_sessions(&[1, 5, 10]);
        assert!(status.is_active(1));
        assert!(!status.is_active(2));
        assert!(status.is_active(5));
        assert!(status.is_active(10));
        assert!(!status.is_active(0));
        assert_eq!(status.active_sessions(), vec![1, 5, 10]);
    }

    #[test]
    fn test_snssai_parse() {
        // SST=1, SD=0x010203
        let snssai = NasSNssai::from_sst_sd(1, Some([0x01, 0x02, 0x03]));
        let parsed = snssai.parse().unwrap();
        assert_eq!(parsed.sst, 1);
        assert_eq!(parsed.sd, Some([0x01, 0x02, 0x03]));
        assert_eq!(parsed.mapped_sst, None);
    }

    #[test]
    fn test_dnn_roundtrip() {
        let dnn = NasDnn::from_string("internet");
        assert_eq!(dnn.as_string(), Some("internet".to_string()));

        let dnn2 = NasDnn::from_string("ims.mnc093.mcc208.3gppnetwork.org");
        assert_eq!(
            dnn2.as_string(),
            Some("ims.mnc093.mcc208.3gppnetwork.org".to_string())
        );
    }

    #[test]
    fn test_bcd_imei_decode() {
        // Typical IMEI: type=3 (IMEI), odd flag set, then BCD digits
        // IMEI 123456789012345
        let digits = decode_bcd_identity(&[0x19, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54]);
        assert!(digits.starts_with("1"));
        assert!(digits.len() >= 14); // at least 14 IMEI digits
    }

    #[test]
    fn test_deregistration_type() {
        // switch_off=1, access_type=1 (3GPP) = 0b1001
        let dt = NasDeRegistrationType::new(0x09);
        assert!(dt.switch_off());
        // re_registration_required() reads the same bit as switch_off() (bit 4),
        // just named differently for network-originated vs UE-originated messages
        assert!(dt.re_registration_required());
        assert_eq!(dt.access_type(), 0x01);

        // access_type=1, no switch-off = 0b0001
        let dt2 = NasDeRegistrationType::new(0x01);
        assert!(!dt2.switch_off());
        assert!(!dt2.re_registration_required());
        assert_eq!(dt2.access_type(), 0x01);
    }

    #[test]
    fn test_registration_result() {
        let result = NasFGsRegistrationResult::new(vec![0x09]); // 3GPP access + SMS allowed
        assert_eq!(result.result_value(), 0x01); // 3GPP access
        assert!(result.sms_allowed());
    }

    #[test]
    fn test_payload_container_type() {
        let pct = NasPayloadContainerType::new(0x01);
        assert!(pct.is_n1_sm());
        assert_eq!(pct.kind(), Some(PayloadContainerKind::N1SmInformation));
    }
}
